Response:
### 功能说明
该 eBPF 程序（`runqslower.bpf.c`）用于监控进程在调度器就绪队列中的等待时间。当进程被唤醒（加入就绪队列）但未立即获得 CPU 执行时，记录其等待时间，并通过 Perf 事件输出超过阈值（`min_us`）的延迟事件。核心功能包括：
1. **过滤目标进程**：通过 `targ_pid` 和 `targ_tgid` 过滤特定进程或线程组。
2. **延迟计算**：记录进程被唤醒到实际获得 CPU 的时间差。
3. **事件输出**：将延迟事件通过 Perf 环形缓冲区发送到用户态。

---

### 执行顺序（10 步）
1. **用户空间初始化**：用户态程序加载 eBPF 代码，设置 `min_us`、`targ_pid`、`targ_tgid` 参数。
2. **挂载 Tracepoint**：将 eBPF 程序附加到内核的 `sched_wakeup`、`sched_wakeup_new`、`sched_switch` 事件点。
3. **进程唤醒事件**：当进程被唤醒（`sched_wakeup` 或 `sched_wakeup_new` 事件），调用 `trace_enqueue` 记录时间戳。
4. **时间戳存储**：将当前进程的 PID 和纳秒级时间戳存入 `start` 哈希表。
5. **上下文切换事件**：当发生进程切换（`sched_switch` 事件），调用 `handle_switch`。
6. **检查前一个进程**：若前一个进程状态为 `TASK_RUNNING`，说明它是主动让出 CPU，需记录其入队时间。
7. **计算延迟**：从 `start` 表中查询当前进程的时间戳，计算与当前时间的差值（转换为微秒）。
8. **过滤短延迟**：若延迟未超过 `min_us`，跳过输出。
9. **构造事件数据**：填充 `event` 结构体（包含 PID、任务名、延迟等）。
10. **输出到用户态**：通过 `perf_event_output` 将事件发送到用户态，并清理 `start` 表中的条目。

---

### Hook 点与信息
| Hook 点                | 函数名               | 有效信息                                  | 信息说明                          |
|------------------------|---------------------|-----------------------------------------|----------------------------------|
| `tp_btf/sched_wakeup`  | `sched_wakeup`      | `p->tgid`, `p->pid`                     | 被唤醒进程的线程组 ID 和进程 ID    |
| `tp_btf/sched_wakeup_new` | `sched_wakeup_new` | `p->tgid`, `p->pid`                     | 新进程的线程组 ID 和进程 ID        |
| `tp_btf/sched_switch`  | `sched_switch`      | `prev->pid`, `next->pid`, `prev->comm`  | 切换前后的进程 PID 和任务名称       |
| `raw_tp/sched_wakeup`  | `handle_sched_wakeup` | `p->tgid`, `p->pid` (通过 `BPF_CORE_READ`) | 兼容旧内核的唤醒事件信息            |

---

### 逻辑推理示例
- **输入**：进程 A（PID=100）被唤醒（`sched_wakeup`），但等待 200μs 后才被调度（`sched_switch`）。
- **输出**：`event` 结构体包含 `pid=100`、`delta_us=200` 及任务名。
- **过滤**：若 `min_us=300`，则此事件因 `200 <= 300` 被过滤。

---

### 常见使用错误
1. **权限不足**：  
   **错误示例**：未以 root 权限运行，导致 eBPF 程序加载失败。  
   **解决**：使用 `sudo` 或赋予 `CAP_BPF` 权限。

2. **无效 PID 过滤**：  
   **错误示例**：设置 `targ_pid=9999`，但目标进程不存在，导致无输出。  
   **解决**：通过 `ps` 确认 PID 有效性。

3. **内核版本不兼容**：  
   **错误示例**：旧内核未支持 BTF（BPF Type Format），无法使用 `tp_btf`。  
   **解决**：回退到 `raw_tp` 版本（代码中已兼容处理）。

---

### Syscall 调试线索
1. **进程唤醒路径**：  
   - 系统调用（如 `read`）返回时，内核调用 `try_to_wake_up()` 触发 `sched_wakeup`。
   - eBPF 在 `sched_wakeup` 的 Tracepoint 捕获事件，记录时间戳。

2. **上下文切换路径**：  
   - 时钟中断或主动调用 `schedule()` 触发 `sched_switch`。  
   - eBPF 在 `sched_switch` 计算从唤醒到执行的时间差。

3. **调试技巧**：  
   - 使用 `bpftool prog show` 确认 eBPF 程序加载状态。  
   - 通过 `perf record` 捕获用户态输出，验证事件数据是否符合预期。
### 提示词
```
这是目录为bcc/libbpf-tools/runqslower.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。
```

### 源代码
```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "runqslower.h"
#include "core_fixes.bpf.h"

#define TASK_RUNNING	0

const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/* record enqueue timestamp */
static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;

	if (!pid)
		return 0;
	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

static int handle_switch(void *ctx, struct task_struct *prev, struct task_struct *next)
{
	struct event event = {};
	u64 *tsp, delta_us;
	u32 pid;

	/* ivcsw: treat like an enqueue event and store timestamp */
	if (get_task_state(prev) == TASK_RUNNING)
		trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

	pid = BPF_CORE_READ(next, pid);

	/* fetch timestamp and calculate delta */
	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;   /* missed enqueue */

	delta_us = (bpf_ktime_get_ns() - *tsp) / 1000;
	if (min_us && delta_us <= min_us)
		return 0;

	event.pid = pid;
	event.prev_pid = BPF_CORE_READ(prev, pid);
	event.delta_us = delta_us;
	bpf_probe_read_kernel_str(&event.task, sizeof(event.task), next->comm);
	bpf_probe_read_kernel_str(&event.prev_task, sizeof(event.prev_task), prev->comm);

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(ctx, prev, next);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(ctx, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
```