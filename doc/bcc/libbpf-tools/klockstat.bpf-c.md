Response:
### 功能概述
该 eBPF 程序 `klockstat.bpf.c` 是一个用于追踪和分析内核锁竞争状态的工具。它通过监控 **互斥锁（mutex）** 和 **读写信号量（rwsem）** 的操作，统计锁的争用时间（Contention Time）和持有时间（Hold Time），并记录最大延迟事件。主要功能包括：
1. **锁争用跟踪**：记录锁被争用的开始时间（尝试获取锁的时间）。
2. **锁获取跟踪**：记录成功获取锁的时间。
3. **锁释放跟踪**：记录锁释放时间，并计算持有时间。
4. **统计信息聚合**：按堆栈或线程聚合锁的争用次数、总时间、最大时间等。
5. **过滤机制**：支持按进程 ID、线程 ID、锁地址过滤事件。

---

### 执行顺序（10 步）
1. **用户态触发锁操作**：用户程序调用 `mutex_lock`、`down_read` 等内核函数。
2. **进入内核函数入口（fentry）**：eBPF 在 `mutex_lock` 入口调用 `lock_contended`，记录尝试时间。
3. **内核函数执行**：内核执行锁的获取逻辑（可能阻塞）。
4. **内核函数退出（fexit）**：若获取成功，调用 `lock_acquired` 记录获取时间。
5. **锁释放操作**：用户调用 `mutex_unlock`，触发 `lock_released`，记录释放时间。
6. **统计计算**：通过 `account()` 计算争用时间和持有时间，更新统计信息。
7. **堆栈跟踪收集**：使用 `bpf_get_stackid` 捕获调用堆栈，关联到锁操作。
8. **数据存储**：将统计结果写入 `stat_map`，堆栈信息存入 `stack_map`。
9. **用户态数据读取**：用户态工具（如 BCC 脚本）从 map 中读取数据。
10. **结果展示**：输出锁统计报告，包括最大延迟、平均时间等。

---

### Hook 点与关键信息
| Hook 类型          | 函数名                          | 读取信息                               | 信息说明                                     |
|--------------------|---------------------------------|---------------------------------------|--------------------------------------------|
| `fentry/mutex_lock` | `BPF_PROG(mutex_lock)`         | `struct mutex *lock`                  | 锁的内存地址，用于唯一标识锁。               |
| `fexit/mutex_lock`  | `BPF_PROG(mutex_lock_exit)`    | `long ret`                            | 返回值，判断锁是否成功获取。                 |
| `fentry/mutex_unlock` | `BPF_PROG(mutex_unlock)`       | `struct mutex *lock`                  | 锁地址，用于匹配锁的释放事件。               |
| `kprobe/down_read`  | `BPF_KPROBE(kprobe_down_read)` | `struct rw_semaphore *lock`           | 读写信号量的地址，标识具体锁实例。           |
| `kretprobe/down_read` | `BPF_KRETPROBE(...)`          | `long ret`                            | 返回值，判断读锁是否成功获取。               |
| **公共信息**        | `bpf_get_current_pid_tgid()`   | `task_id` (PID + TGID)                | 当前进程/线程的 ID，用于过滤和关联事件。     |
| **公共信息**        | `bpf_ktime_get_ns()`           | `try_at`, `acq_at`, `rel_at`          | 时间戳，用于计算争用和持有时间。             |

---

### 逻辑推理示例
**假设输入**：一个多线程程序频繁竞争同一互斥锁。
- **线程 A** 调用 `mutex_lock(lock1)`，因锁被占用进入争用。
- **线程 B** 释放 `lock1`，触发 `mutex_unlock`。
- **线程 A** 成功获取 `lock1`，随后释放。

**输出统计**：
- `stat_map` 中记录 `lock1` 的：
  - `acq_count`: 1（争用次数）
  - `acq_total_time`: 线程 A 的等待时间。
  - `hld_max_time`: 线程 A 持有锁的最长时间。

---

### 常见使用错误
1. **过滤条件错误**：
   - 错误示例：设置 `targ_tgid=123` 但实际进程 ID 为 `456`，导致无数据。
   - 解决：通过 `ps` 或 `/proc` 确认目标进程的 TGID/PID。

2. **递归锁误判**：
   - 错误示例：监控的锁是递归锁，但程序假设为非递归，导致统计重复事件。
   - 解决：结合锁类型（如 `mutex` 的 `owner` 字段）过滤递归调用。

3. **堆栈跳过帧数错误**：
   - 错误示例：`bpf_get_stackid` 的 `skip` 参数设置不当，导致堆栈信息不完整。
   - 解决：根据内核版本调整 `skip`（例如跳过 4 层框架）。

---

### Syscall 调试线索
1. **用户态调用**：应用程序调用 `pthread_mutex_lock()`，触发 `mutex_lock` 系统调用。
2. **内核路径**：
   - `mutex_lock()` → `__mutex_lock_slowpath()`（若锁被占用）。
3. **eBPF Hook 触发**：
   - `fentry/mutex_lock` → 记录 `try_at` 时间。
   - `fexit/mutex_lock` → 若 `ret == 0`，记录 `acq_at` 时间。
4. **锁释放路径**：
   - `mutex_unlock()` → `__mutex_unlock_slowpath()`。
   - `fentry/mutex_unlock` → 调用 `lock_released`，计算持有时间。

---

### 总结
该程序通过精细的 **锁生命周期跟踪** 和 **时间统计**，帮助开发者识别内核锁的性能瓶颈。调试时需关注过滤条件、锁类型和堆栈信息准确性，结合用户态工具解析 `stat_map` 数据定位问题。
Prompt: 
```
这是目录为bcc/libbpf-tools/klockstat.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Google LLC.
 *
 * Based on klockstat from BCC by Jiri Olsa and others
 * 2021-10-26   Barret Rhoden   Created this.
 */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "klockstat.h"
#include "bits.bpf.h"

const volatile pid_t targ_tgid = 0;
const volatile pid_t targ_pid = 0;
void *const volatile targ_lock = NULL;
const volatile int per_thread = 0;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
} stack_map SEC(".maps");

/*
 * Uniquely identifies a task grabbing a particular lock; a task can only hold
 * the same lock once (non-recursive mutexes).
 */
struct task_lock {
	u64 task_id;
	u64 lock_ptr;
};

struct lockholder_info {
	s32 stack_id;
	u64 task_id;
	u64 try_at;
	u64 acq_at;
	u64 rel_at;
	u64 lock_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct task_lock);
	__type(value, struct lockholder_info);
} lockholder_map SEC(".maps");

/*
 * Keyed by stack_id.
 *
 * Multiple call sites may have the same underlying lock, but we only know the
 * stats for a particular stack frame.  Multiple tasks may have the same
 * stackframe.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, s32);
	__type(value, struct lock_stat);
} stat_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, void *);
} locks SEC(".maps");

static bool tracing_task(u64 task_id)
{
	u32 tgid = task_id >> 32;
	u32 pid = task_id;

	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	return true;
}

static void lock_contended(void *ctx, void *lock)
{
	u64 task_id;
	struct lockholder_info li[1] = {0};
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;

	li->task_id = task_id;
	li->lock_ptr = (u64)lock;
	/*
	 * Skip 4 frames, e.g.:
	 *       __this_module+0x34ef
	 *       __this_module+0x34ef
	 *       __this_module+0x8c44
	 *             mutex_lock+0x5
	 *
	 * Note: if you make major changes to this bpf program, double check
	 * that you aren't skipping too many frames.
	 */
	li->stack_id = bpf_get_stackid(ctx, &stack_map, 4 | BPF_F_FAST_STACK_CMP);

	/* Legit failures include EEXIST */
	if (li->stack_id < 0)
		return;
	li->try_at = bpf_ktime_get_ns();

	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	bpf_map_update_elem(&lockholder_map, &tl, li, BPF_ANY);
}

static void lock_aborted(void *lock)
{
	u64 task_id;
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;
	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	bpf_map_delete_elem(&lockholder_map, &tl);
}

static void lock_acquired(void *lock)
{
	u64 task_id;
	struct lockholder_info *li;
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;

	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholder_map, &tl);
	if (!li)
		return;

	li->acq_at = bpf_ktime_get_ns();
}

static void account(struct lockholder_info *li)
{
	struct lock_stat *ls;
	u64 delta;
	u32 key = li->stack_id;

	if (per_thread)
		key = li->task_id;

	/*
	 * Multiple threads may have the same stack_id.  Even though we are
	 * holding the lock, dynamically allocated mutexes can have the same
	 * callgraph but represent different locks.  Also, a rwsem can be held
	 * by multiple readers at the same time.  They will be accounted as
	 * the same lock, which is what we want, but we need to use atomics to
	 * avoid corruption, especially for the total_time variables.
	 * But it should be ok for per-thread since it's not racy anymore.
	 */
	ls = bpf_map_lookup_elem(&stat_map, &key);
	if (!ls) {
		struct lock_stat fresh = {0};

		bpf_map_update_elem(&stat_map, &key, &fresh, BPF_ANY);
		ls = bpf_map_lookup_elem(&stat_map, &key);
		if (!ls)
			return;

		if (per_thread)
			bpf_get_current_comm(ls->acq_max_comm, TASK_COMM_LEN);
	}

	delta = li->acq_at - li->try_at;
	__sync_fetch_and_add(&ls->acq_count, 1);
	__sync_fetch_and_add(&ls->acq_total_time, delta);
	if (delta > READ_ONCE(ls->acq_max_time)) {
		WRITE_ONCE(ls->acq_max_time, delta);
		WRITE_ONCE(ls->acq_max_id, li->task_id);
		WRITE_ONCE(ls->acq_max_lock_ptr, li->lock_ptr);
		/*
		 * Potentially racy, if multiple threads think they are the max,
		 * so you may get a clobbered write.
		 */
		if (!per_thread)
			bpf_get_current_comm(ls->acq_max_comm, TASK_COMM_LEN);
	}

	delta = li->rel_at - li->acq_at;
	__sync_fetch_and_add(&ls->hld_count, 1);
	__sync_fetch_and_add(&ls->hld_total_time, delta);
	if (delta > READ_ONCE(ls->hld_max_time)) {
		WRITE_ONCE(ls->hld_max_time, delta);
		WRITE_ONCE(ls->hld_max_id, li->task_id);
		WRITE_ONCE(ls->hld_max_lock_ptr, li->lock_ptr);
		if (!per_thread)
			bpf_get_current_comm(ls->hld_max_comm, TASK_COMM_LEN);
	}
}

static void lock_released(void *lock)
{
	u64 task_id;
	struct lockholder_info *li;
	struct task_lock tl = {};

	if (targ_lock && targ_lock != lock)
		return;
	task_id = bpf_get_current_pid_tgid();
	if (!tracing_task(task_id))
		return;
	tl.task_id = task_id;
	tl.lock_ptr = (u64)lock;
	li = bpf_map_lookup_elem(&lockholder_map, &tl);
	if (!li)
		return;

	li->rel_at = bpf_ktime_get_ns();
	account(li);

	bpf_map_delete_elem(&lockholder_map, &tl);
}

SEC("fentry/mutex_lock")
int BPF_PROG(mutex_lock, struct mutex *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/mutex_lock")
int BPF_PROG(mutex_lock_exit, struct mutex *lock, long ret)
{
	lock_acquired(lock);
	return 0;
}

SEC("fexit/mutex_trylock")
int BPF_PROG(mutex_trylock_exit, struct mutex *lock, long ret)
{
	if (ret) {
		lock_contended(ctx, lock);
		lock_acquired(lock);
	}
	return 0;
}

SEC("fentry/mutex_lock_interruptible")
int BPF_PROG(mutex_lock_interruptible, struct mutex *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/mutex_lock_interruptible")
int BPF_PROG(mutex_lock_interruptible_exit, struct mutex *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/mutex_lock_killable")
int BPF_PROG(mutex_lock_killable, struct mutex *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/mutex_lock_killable")
int BPF_PROG(mutex_lock_killable_exit, struct mutex *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/mutex_unlock")
int BPF_PROG(mutex_unlock, struct mutex *lock)
{
	lock_released(lock);
	return 0;
}

SEC("fentry/down_read")
int BPF_PROG(down_read, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_read")
int BPF_PROG(down_read_exit, struct rw_semaphore *lock, long ret)
{
	lock_acquired(lock);
	return 0;
}

SEC("fexit/down_read_trylock")
int BPF_PROG(down_read_trylock_exit, struct rw_semaphore *lock, long ret)
{
	if (ret == 1) {
		lock_contended(ctx, lock);
		lock_acquired(lock);
	}
	return 0;
}

SEC("fentry/down_read_interruptible")
int BPF_PROG(down_read_interruptible, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_read_interruptible")
int BPF_PROG(down_read_interruptible_exit, struct rw_semaphore *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/down_read_killable")
int BPF_PROG(down_read_killable, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_read_killable")
int BPF_PROG(down_read_killable_exit, struct rw_semaphore *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/up_read")
int BPF_PROG(up_read, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("fentry/down_write")
int BPF_PROG(down_write, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_write")
int BPF_PROG(down_write_exit, struct rw_semaphore *lock, long ret)
{
	lock_acquired(lock);
	return 0;
}

SEC("fexit/down_write_trylock")
int BPF_PROG(down_write_trylock_exit, struct rw_semaphore *lock, long ret)
{
	if (ret == 1) {
		lock_contended(ctx, lock);
		lock_acquired(lock);
	}
	return 0;
}

SEC("fentry/down_write_killable")
int BPF_PROG(down_write_killable, struct rw_semaphore *lock)
{
	lock_contended(ctx, lock);
	return 0;
}

SEC("fexit/down_write_killable")
int BPF_PROG(down_write_killable_exit, struct rw_semaphore *lock, long ret)
{
	if (ret)
		lock_aborted(lock);
	else
		lock_acquired(lock);
	return 0;
}

SEC("fentry/up_write")
int BPF_PROG(up_write, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/mutex_lock")
int BPF_KPROBE(kprobe_mutex_lock, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/mutex_lock")
int BPF_KRETPROBE(kprobe_mutex_lock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);
	lock_acquired(*lock);
	return 0;
}

SEC("kprobe/mutex_trylock")
int BPF_KPROBE(kprobe_mutex_trylock, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	return 0;
}

SEC("kretprobe/mutex_trylock")
int BPF_KRETPROBE(kprobe_mutex_trylock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret) {
		lock_contended(ctx, *lock);
		lock_acquired(*lock);
	}
	return 0;
}

SEC("kprobe/mutex_lock_interruptible")
int BPF_KPROBE(kprobe_mutex_lock_interruptible, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/mutex_lock_interruptible")
int BPF_KRETPROBE(kprobe_mutex_lock_interruptible_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/mutex_lock_killable")
int BPF_KPROBE(kprobe_mutex_lock_killable, struct mutex *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/mutex_lock_killable")
int BPF_KRETPROBE(kprobe_mutex_lock_killable_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(kprobe_mutex_unlock, struct mutex *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/down_read")
int BPF_KPROBE(kprobe_down_read, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_read")
int BPF_KRETPROBE(kprobe_down_read_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	lock_acquired(*lock);
	return 0;
}

SEC("kprobe/down_read_trylock")
int BPF_KPROBE(kprobe_down_read_trylock, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	return 0;
}

SEC("kretprobe/down_read_trylock")
int BPF_KRETPROBE(kprobe_down_read_trylock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret == 1) {
		lock_contended(ctx, *lock);
		lock_acquired(*lock);
	}
	return 0;
}

SEC("kprobe/down_read_interruptible")
int BPF_KPROBE(kprobe_down_read_interruptible, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_read_interruptible")
int BPF_KRETPROBE(kprobe_down_read_interruptible_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/down_read_killable")
int BPF_KPROBE(kprobe_down_read_killable, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_read_killable")
int BPF_KRETPROBE(kprobe_down_read_killable_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/up_read")
int BPF_KPROBE(kprobe_up_read, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

SEC("kprobe/down_write")
int BPF_KPROBE(kprobe_down_write, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_write")
int BPF_KRETPROBE(kprobe_down_write_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	lock_acquired(*lock);
	return 0;
}

SEC("kprobe/down_write_trylock")
int BPF_KPROBE(kprobe_down_write_trylock, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	return 0;
}

SEC("kretprobe/down_write_trylock")
int BPF_KRETPROBE(kprobe_down_write_trylock_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret == 1) {
		lock_contended(ctx, *lock);
		lock_acquired(*lock);
	}
	return 0;
}

SEC("kprobe/down_write_killable")
int BPF_KPROBE(kprobe_down_write_killable, struct rw_semaphore *lock)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();

	bpf_map_update_elem(&locks, &tid, &lock, BPF_ANY);
	lock_contended(ctx, lock);
	return 0;
}

SEC("kretprobe/down_write_killable")
int BPF_KRETPROBE(kprobe_down_write_killable_exit, long ret)
{
	u32 tid = (u32)bpf_get_current_pid_tgid();
	void **lock;

	lock = bpf_map_lookup_elem(&locks, &tid);
	if (!lock)
		return 0;

	bpf_map_delete_elem(&locks, &tid);

	if (ret)
		lock_aborted(*lock);
	else
		lock_acquired(*lock);
	return 0;
}

SEC("kprobe/up_write")
int BPF_KPROBE(kprobe_up_write, struct rw_semaphore *lock)
{
	lock_released(lock);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

"""

```