Response:
### 功能概述
该eBPF程序用于**跟踪进程被唤醒的延迟时间**，统计线程在阻塞状态下的等待时长，并关联唤醒者（waker）的信息。适用于分析调度延迟、性能调优。

---

### 执行顺序（10步）
1. **挂载eBPF程序**：加载到内核，绑定`sched_switch`和`sched_wakeup`跟踪点。
2. **触发调度切换（sched_switch）**：内核发生进程切换时，触发`sched_switch`事件。
3. **记录被切换进程时间**：调用`offcpu_sched_switch`，记录被切换进程的TID和当前时间戳到`start`映射。
4. **触发唤醒事件（sched_wakeup）**：当某个进程被唤醒时，触发`sched_wakeup`事件。
5. **查找唤醒目标的时间戳**：在`wakeup`函数中，通过TID从`start`映射查找时间戳。
6. **计算阻塞时间**：用当前时间减去时间戳，得到阻塞时长（delta）。
7. **过滤时间范围**：根据`min_block_ns`和`max_block_ns`过滤无效数据。
8. **捕获堆栈和进程信息**：获取唤醒目标的进程名（`p->comm`）、唤醒者的进程名（`current->comm`）及堆栈跟踪。
9. **更新统计映射**：将阻塞时间累加到`counts`映射的对应键（含进程名、堆栈ID）。
10. **用户空间读取结果**：用户态工具读取`counts`映射并汇总输出。

---

### Hook点与关键信息
| Hook点                | 函数名         | 读取信息                                 | 信息说明                          |
|-----------------------|---------------|----------------------------------------|---------------------------------|
| `tp_btf/sched_switch` | `sched_switch`| `prev`任务的PID、TID、flags             | 被切换进程的元数据，判断是否为内核线程 |
| `tp_btf/sched_wakeup` | `sched_wakeup`| 被唤醒进程的`p->comm`、当前进程的`comm` | 目标进程名、唤醒者进程名            |

---

### 逻辑推理：输入与输出
- **输入假设**：进程A（PID=123）因读管道阻塞，进程B（PID=456）写入数据唤醒A。
- **输出结果**：`counts`映射中记录一条键为`{waker=B, target=A, w_k_stack_id=X}`，值为阻塞时间（B唤醒A的延迟）。

---

### 用户常见错误
1. **PID过滤无效**：设置`targ_pid=123`但进程不存在，导致无数据。
2. **时间范围错误**：`min_block_ns=1e6`（1ms）可能忽略微秒级阻塞。
3. **权限问题**：未以root运行或缺少CAP_BPF权限，程序加载失败。

---

### Syscall到Hook的调试线索
1. **进程阻塞**：例如`read()`系统调用进入等待队列（如等待I/O）。
2. **触发调度**：内核调用`schedule()`切换进程，触发`sched_switch`事件。
3. **唤醒事件**：另一个进程调用`write()`写入数据，调用`wake_up()`唤醒阻塞进程，触发`sched_wakeup`。
4. **eBPF捕获**：通过tracepoint捕获这两个事件，执行对应的处理函数。

---

### 代码关键点验证
- **`sched_wakeup`参数传递**：`BPF_PROG(sched_wakeup, struct task_struct *p)`正确接收被唤醒进程`p`，`ctx`由BCC隐式处理。
- **内核线程过滤**：通过`prev->flags & PF_KTHREAD`跳过内核线程，需确认`vmlinux.h`中`PF_KTHREAD`定义与内核一致。
Prompt: 
```
这是目录为bcc/libbpf-tools/wakeuptime.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-3.0
// Copyright (c) 2022 Nicolas Sterchele
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "wakeuptime.h"
#include "maps.bpf.h"

#define PF_KTHREAD		0x00200000	/* kernel thread */

const volatile pid_t targ_pid = 0;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 1;
const volatile bool user_threads_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key_t);
	__type(value, u64);
} counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

static int offcpu_sched_switch(struct task_struct *prev)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = (u32)pid_tgid;
	u64 ts;

	if (targ_pid && targ_pid != pid)
		return 0;

	if (user_threads_only && prev->flags & PF_KTHREAD)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
	return 0;
}

static int wakeup(void *ctx, struct task_struct *p)
{
	u32 pid = p->tgid;
	u32 tid = p->pid;
	u64 delta, *count_key, *tsp;
	static const u64 zero;
	struct key_t key = {};

	if (targ_pid && targ_pid != pid)
		return 0;
	tsp = bpf_map_lookup_elem(&start, &tid);
	if (tsp == 0)
		return 0;
	bpf_map_delete_elem(&start, &tid);

	delta = bpf_ktime_get_ns() - *tsp;
	if ((delta < min_block_ns) || (delta > max_block_ns))
		return 0;

	key.w_k_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	bpf_probe_read_kernel(&key.target, sizeof(key.target), p->comm);
	bpf_get_current_comm(&key.waker, sizeof(key.waker));

	count_key = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (count_key)
		__atomic_add_fetch(count_key, delta, __ATOMIC_RELAXED);

	return 0;
}


SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return offcpu_sched_switch(prev);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	return wakeup(ctx, p);
}

char LICENSE[] SEC("license") = "GPL";

"""

```