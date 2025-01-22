Response:
### 功能概述  
`offcputime.bpf.c` 是一个基于 eBPF 的 **Off-CPU 时间分析工具**，用于追踪进程在非运行状态（如等待 I/O、锁、调度延迟）的时间消耗。通过捕获进程调度事件和堆栈信息，帮助开发者定位性能瓶颈。

---

### 执行顺序（10 步骤）  
1. **挂载 Hook 点**  
   - 程序加载时，通过 `SEC("tp_btf/sched_switch")` 或 `SEC("raw_tp/sched_switch")` 注册到内核的 `sched_switch` 事件。

2. **触发调度事件**  
   - 当发生进程切换（如系统调用阻塞、时间片耗尽），内核触发 `sched_switch` 事件。

3. **处理被换出进程 (`prev`)**  
   - 调用 `handle_sched_switch`，检查 `prev` 进程是否符合记录条件（`allow_record`）。

4. **过滤条件检查**  
   - `allow_record` 验证进程的 TGID/PID、内核/用户线程标志、任务状态（如 `TASK_UNINTERRUPTIBLE`）。

5. **记录进程信息**  
   - 若允许记录，保存 `prev` 的 PID、TGID、时间戳、用户/内核堆栈 ID 到 `start` 和 `info` map。

6. **处理换入进程 (`next`)**  
   - 查找 `next` 进程在 `start` map 中的记录，计算其 Off-CPU 时间（`delta = 当前时间 - 开始时间`）。

7. **时间过滤与统计**  
   - 检查 `delta` 是否在 `min_block_ns` 和 `max_block_ns` 范围内，有效则累加到 `info` map 的 `val.delta`。

8. **清理临时数据**  
   - 删除 `start` map 中 `next` 进程的临时记录，避免内存泄漏。

9. **用户态数据聚合**  
   - 用户空间工具（如 `offcputime.py`）读取 `info` map，按进程/堆栈聚合 Off-CPU 时间。

10. **输出分析结果**  
    - 生成火焰图或文本报告，展示哪些代码路径导致了高 Off-CPU 时间。

---

### Hook 点与关键信息  
| **Hook 点**       | **函数名**          | **读取信息**                          | **信息含义**                     |
|--------------------|---------------------|---------------------------------------|----------------------------------|
| `sched_switch`     | `sched_switch`      | `prev->pid`, `prev->tgid`             | 被换出进程的 PID 和线程组 ID      |
|                    |                     | `prev->comm`                          | 进程名（如 `nginx`）              |
|                    |                     | `bpf_ktime_get_ns()`                  | 事件触发的纳秒级时间戳            |
|                    |                     | `bpf_get_stackid()`                   | 用户态/内核态堆栈 ID（用于火焰图） |

---

### 逻辑推理：输入与输出  
- **输入**  
  内核调度事件 `sched_switch`，携带 `prev` 和 `next` 进程的上下文。

- **输出**  
  包含进程 PID、TGID、堆栈 ID 和 Off-CPU 时间的 `info` map，例如：  
  ```c
  struct val_t { char comm[16]; u64 delta; }; // comm="java", delta=1200000 (ns)
  ```

---

### 常见使用错误  
1. **过滤条件冲突**  
   - 同时启用 `kernel_threads_only` 和 `user_threads_only`，导致无任何记录。
   
2. **时间范围错误**  
   - 设置 `min_block_ns=1000000`（1ms），漏掉短阻塞事件（如快速锁竞争）。

3. **PID/TGID 过滤未配置**  
   - 启用 `filter_by_tgid` 但未填充 `tgids` map，导致所有进程被过滤。

---

### Syscall 到达 Hook 的路径  
1. **用户进程执行系统调用**（如 `read()`）。  
2. **内核处理系统调用时发生阻塞**（如等待磁盘 I/O）。  
3. **触发进程调度**，内核调用 `schedule()` 函数。  
4. `schedule()` 触发 `sched_switch` 事件，执行 eBPF 程序。  

**调试线索**：  
- 检查 `sched_switch` 事件的 `prev->comm` 和堆栈，确认阻塞操作来源（如 `do_sys_read`）。  
- 结合 `info` map 中的 `delta` 时间，关联到具体系统调用或内核函数。
Prompt: 
```
这是目录为bcc/libbpf-tools/offcputime.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "offcputime.h"
#include "core_fixes.bpf.h"

#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define MAX_ENTRIES		10240

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile __u64 max_block_ns = -1;
const volatile __u64 min_block_ns = 1;
const volatile bool filter_by_tgid = false;
const volatile bool filter_by_pid = false;
const volatile long state = -1;

struct internal_key {
	u64 start_ts;
	struct key_t key;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct internal_key);
	__uint(max_entries, MAX_ENTRIES);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} pids SEC(".maps");

static bool allow_record(struct task_struct *t)
{
	u32 tgid = BPF_CORE_READ(t, tgid);
	u32 pid = BPF_CORE_READ(t, pid);

	if (filter_by_tgid && !bpf_map_lookup_elem(&tgids, &tgid))
		return false;
	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return false;
	if (user_threads_only && (BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	else if (kernel_threads_only && !(BPF_CORE_READ(t, flags) & PF_KTHREAD))
		return false;
	if (state != -1 && get_task_state(t) != state)
		return false;
	return true;
}

static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct internal_key *i_keyp, i_key;
	struct val_t *valp, val;
	s64 delta;
	u32 pid;

	if (allow_record(prev)) {
		pid = BPF_CORE_READ(prev, pid);
		/* To distinguish idle threads of different cores */
		if (!pid)
			pid = bpf_get_smp_processor_id();
		i_key.key.pid = pid;
		i_key.key.tgid = BPF_CORE_READ(prev, tgid);
		i_key.start_ts = bpf_ktime_get_ns();

		if (BPF_CORE_READ(prev, flags) & PF_KTHREAD)
			i_key.key.user_stack_id = -1;
		else
			i_key.key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		i_key.key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		bpf_map_update_elem(&start, &pid, &i_key, 0);
		bpf_probe_read_kernel_str(&val.comm, sizeof(prev->comm), BPF_CORE_READ(prev, comm));
		val.delta = 0;
		bpf_map_update_elem(&info, &i_key.key, &val, BPF_NOEXIST);
	}

	pid = BPF_CORE_READ(next, pid);
	i_keyp = bpf_map_lookup_elem(&start, &pid);
	if (!i_keyp)
		return 0;
	delta = (s64)(bpf_ktime_get_ns() - i_keyp->start_ts);
	if (delta < 0)
		goto cleanup;
	delta /= 1000U;
	if (delta < min_block_ns || delta > max_block_ns)
		goto cleanup;
	valp = bpf_map_lookup_elem(&info, &i_keyp->key);
	if (!valp)
		goto cleanup;
	__sync_fetch_and_add(&valp->delta, delta);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";

"""

```