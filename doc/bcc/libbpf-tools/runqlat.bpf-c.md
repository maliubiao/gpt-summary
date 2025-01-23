Response:
### 功能总结
该 eBPF 程序用于统计任务在 CPU 运行队列中的等待时间（调度延迟），生成延迟分布的直方图。核心功能如下：
- 跟踪任务被唤醒（`sched_wakeup`）和调度切换（`sched_switch`）事件。
- 记录任务进入运行队列的时间戳。
- 计算任务从入队到实际获得 CPU 执行的时间差（延迟）。
- 支持按进程、线程、PID 命名空间聚合统计。
- 支持过滤特定 CGroup 或进程组（TGID）。

---

### 执行顺序（10 步）
1. **加载程序**：用户通过 `runqlat` 工具加载此 eBPF 程序到内核。
2. **绑定跟踪点**：挂载到内核调度器事件 `sched_wakeup`、`sched_wakeup_new`、`sched_switch`。
3. **触发唤醒事件**：当任务被唤醒（如从睡眠变为可运行状态），执行 `sched_wakeup` 或 `sched_wakeup_new` 的 BPF 函数。
4. **记录入队时间**：调用 `trace_enqueue` 记录当前任务的 PID 和纳秒级时间戳到 `start` Map。
5. **触发调度切换**：当发生任务切换时，执行 `sched_switch` 的 BPF 函数。
6. **处理前一个任务**：若前一个任务状态为 `TASK_RUNNING`，说明它仍在运行队列，记录其入队时间。
7. **处理新任务**：查找新任务的 PID 在 `start` Map 中的时间戳，计算延迟时间。
8. **更新直方图**：根据延迟时间计算对应的直方图桶（Bucket），更新 `hists` Map。
9. **清理数据**：从 `start` Map 删除已处理的任务条目。
10. **用户输出**：用户空间工具读取 `hists` Map 并输出延迟统计结果。

---

### Hook 点与关键信息
| Hook 点                  | 函数名               | 有效信息                     | 信息说明                     |
|--------------------------|---------------------|-----------------------------|-----------------------------|
| `tp_btf/sched_wakeup`    | `BPF_PROG(sched_wakeup)` | `p->tgid`, `p->pid`         | 被唤醒进程的 TGID 和 PID     |
| `tp_btf/sched_wakeup_new`| `BPF_PROG(sched_wakeup_new)` | 同上                        | 新进程的 TGID 和 PID         |
| `tp_btf/sched_switch`    | `BPF_PROG(sched_switch)`     | `prev` 和 `next` 任务结构体 | 切换前后的任务状态和元数据   |
| `raw_tp/sched_wakeup`    | `BPF_PROG(handle_sched_wakeup)` | `p->tgid`, `p->pid`         | 兼容旧内核的唤醒事件处理     |
| `raw_tp/sched_switch`    | `BPF_PROG(handle_sched_switch)` | 同上                        | 兼容旧内核的调度切换处理     |

---

### 逻辑推理示例
- **输入假设**：一个 PID 为 123 的进程多次被唤醒和调度。
- **输出结果**：在 `hists` Map 中，PID 123 对应的直方图桶会增加，显示其在不同延迟区间的命中次数。
- **调试线索**：若某任务延迟异常高，可通过 `hists` Map 中的 `comm` 字段（进程名）定位具体进程。

---

### 常见使用错误
1. **权限不足**：未以 root 权限运行，导致加载 eBPF 程序失败。
   - 示例：普通用户执行 `runqlat` 报错 `Permission denied`。
2. **过滤条件错误**：误设 `targ_tgid` 或 `filter_cg`，导致无数据输出。
   - 示例：`targ_tgid=999` 但目标进程不存在。
3. **内核版本不兼容**：旧内核不支持 BTF，需使用 `raw_tp` 回退逻辑。
   - 示例：内核 4.x 未启用 BTF，导致 `tp_btf` 挂载失败。

---

### Syscall 路径追踪
1. **用户触发调度事件**：如进程调用 `sched_yield()` 或发生阻塞/唤醒。
2. **内核调度路径**：进入 `kernel/sched/core.c` 的调度逻辑。
3. **触发跟踪点**：内核执行 `trace_sched_wakeup()` 或 `trace_sched_switch()`。
4. **eBPF 程序执行**：挂载到跟踪点的 eBPF 函数被调用，记录时间戳或计算延迟。
5. **数据存储**：通过 `start` 和 `hists` Map 暂存中间数据及统计结果。

---

### 调试线索
1. **检查挂载点**：通过 `bpftool prog list` 确认程序是否加载成功。
2. **查看 Map 数据**：使用 `bpftool map dump` 检查 `start` 和 `hists` Map 内容。
3. **日志分析**：若程序失败，检查内核日志 `dmesg` 中的 eBPF 验证错误（如内存越界）。
### 提示词
```
这是目录为bcc/libbpf-tools/runqlat.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "runqlat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES	10240
#define TASK_RUNNING 	0

const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

static struct hist zero;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

static int trace_enqueue(u32 tgid, u32 pid)
{
	u64 ts;

	if (!pid)
		return 0;
	if (targ_tgid && targ_tgid != tgid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
	return 0;
}

static unsigned int pid_namespace(struct task_struct *task)
{
	struct pid *pid;
	unsigned int level;
	struct upid upid;
	unsigned int inum;

	/*  get the pid namespace by following task_active_pid_ns(),
	 *  pid->numbers[pid->level].ns
	 */
	pid = BPF_CORE_READ(task, thread_pid);
	level = BPF_CORE_READ(pid, level);
	bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
	inum = BPF_CORE_READ(upid.ns, ns.inum);

	return inum;
}

static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct hist *histp;
	u64 *tsp, slot;
	u32 pid, hkey;
	s64 delta;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (get_task_state(prev) == TASK_RUNNING)
		trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

	pid = BPF_CORE_READ(next, pid);

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;
	delta = bpf_ktime_get_ns() - *tsp;
	if (delta < 0)
		goto cleanup;

	if (targ_per_process)
		hkey = BPF_CORE_READ(next, tgid);
	else if (targ_per_thread)
		hkey = pid;
	else if (targ_per_pidns)
		hkey = pid_namespace(next);
	else
		hkey = -1;
	histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
	if (!histp)
		goto cleanup;
	if (!histp->comm[0])
		bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm),
					next->comm);
	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(p->tgid, p->pid);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	return handle_switch(preempt, prev, next);
}

char LICENSE[] SEC("license") = "GPL";
```