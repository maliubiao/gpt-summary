Response:
### 功能概述
该eBPF程序用于监控和分析Linux系统中`futex(FUTEX_WAIT)`系统调用的性能特征，记录等待时间分布、竞争情况、最小/最大耗时等。支持按进程、线程、锁地址过滤，支持输出用户态堆栈跟踪或汇总统计。

---

### 执行顺序（分10步）

1. **挂钩`sys_enter_futex`入口**  
   - 当用户态程序调用`futex()`系统调用时，触发`tracepoint/syscalls/sys_enter_futex`钩子。

2. **过滤非`FUTEX_WAIT`操作**  
   - 检查`ctx->args[1]`参数，仅处理`FUTEX_WAIT`命令（忽略其他futex操作）。

3. **过滤进程/线程/锁地址**  
   - 通过`targ_pid`、`targ_tid`、`targ_lock`过滤不符合条件的调用，保留目标数据。

4. **记录起始时间戳和锁地址**  
   - 将当前时间戳和用户空间锁地址（`uaddr`）存入`start`哈希表，键为`pid_tgid`。

5. **挂钩`sys_exit_futex`出口**  
   - 当`futex()`系统调用返回时，触发`tracepoint/syscalls/sys_exit_futex`钩子。

6. **计算耗时`delta`**  
   - 从`start`表中获取入口时间戳，计算与出口时间的差值`delta`（纳秒级）。

7. **构建直方图键`hkey`**  
   - 根据`targ_summary`模式决定键内容：汇总模式用进程PID，否则包含用户态堆栈ID。

8. **更新直方图统计**  
   - 将`delta`转换为微秒或毫秒，统计到`hists`哈希表的对应分桶（`slots`），更新最小/最大耗时。

9. **记录进程名和竞争计数**  
   - 保存进程名称到`histp->comm`，递增`contended`计数器（表示锁竞争次数）。

10. **清理`start`表条目**  
    - 删除已处理的`pid_tgid`条目，避免内存泄漏。

---

### Hook点与有效信息

| Hook点名称                          | 函数名      | 读取信息                     | 信息说明                     |
|-------------------------------------|-------------|------------------------------|------------------------------|
| `tracepoint/syscalls/sys_enter_futex` | `futex_enter` | `ctx->args[0]`               | 用户空间锁地址 (`uaddr`)     |
|                                     |             | `pid_tgid`（通过`bpf_get_current_pid_tgid()`） | 进程PID（高32位）和线程TID（低32位） |
| `tracepoint/syscalls/sys_exit_futex`  | `futex_exit`  | `ctx->ret`                   | 系统调用返回值（错误码）     |
|                                     |             | `vp->ts`（来自`start`表）    | 入口时间戳（纳秒）           |
|                                     |             | `bpf_get_stackid()`          | 用户态堆栈ID（用于定位代码路径） |

---

### 假设输入与输出

- **输入**：  
  进程PID=1234的应用程序频繁调用`futex(uaddr, FUTEX_WAIT, ...)`，其中某个锁地址`0x7ffd1234`存在竞争。

- **输出**：  
  `hists`表中记录：
  - `hkey={pid=1234, uaddr=0x7ffd1234, user_stack_id=X}`  
  - `slots`显示耗时集中在100-200μs区间，`contended=50`次，`min=50μs`，`max=500μs`。

---

### 常见使用错误

1. **未过滤无关数据**  
   - 若未设置`targ_pid`或`targ_lock`，可能采集到全系统futex调用，导致性能开销剧增。

2. **时间单位混淆**  
   - 启用`targ_ms`时误以为统计单位是微秒（实际为毫秒），错误解读直方图。

3. **堆栈映射溢出**  
   - `stackmap`未设置足够大小（`MAX_ENTRIES`），频繁调用导致丢失堆栈跟踪。

---

### Syscall调试线索

1. 用户程序调用`futex(uaddr, FUTEX_WAIT, ...)` → 触发系统调用进入内核。
2. 内核执行`do_futex()` → 调用`futex_wait()`处理等待逻辑。
3. Tracepoint `sys_enter_futex`被触发 → eBPF程序记录入口时间戳。
4. 若锁未就绪，进程进入睡眠状态 → 等待唤醒事件（如`futex_wake`）。
5. 锁释放后，进程被唤醒 → 系统调用返回用户态。
6. Tracepoint `sys_exit_futex`被触发 → eBPF程序计算耗时并更新统计。

通过`hists`表中的`uaddr`和堆栈ID，可定位高延迟的锁地址及对应代码位置。
Prompt: 
```
这是目录为bcc/libbpf-tools/futexctn.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Wenbo Zhang */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "futexctn.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

#define FUTEX_WAIT		0
#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

const volatile bool targ_summary = false;
const volatile bool targ_ms = false;
const volatile __u64 targ_lock = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tid = 0;

struct val_t {
	u64 ts;
	u64 uaddr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct val_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist initial_hist = {};

SEC("tracepoint/syscalls/sys_enter_futex")
int futex_enter(struct syscall_trace_enter *ctx)
{
	struct val_t v = {};
	u64 pid_tgid;
	u32 tid;

	if (((int)ctx->args[1] & FUTEX_CMD_MASK) != FUTEX_WAIT)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;
	if (targ_pid && targ_pid != pid_tgid >> 32)
		return 0;
	if (targ_tid && targ_tid != tid)
		return 0;
	v.uaddr = ctx->args[0];
	if (targ_lock && targ_lock != v.uaddr)
		return 0;
	v.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start, &pid_tgid, &v, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_futex")
int futex_exit(struct syscall_trace_exit *ctx)
{
	u64 pid_tgid, slot, ts, min, max;
	struct hist_key hkey = {};
	struct hist *histp;
	struct val_t *vp;
	s64 delta;

	ts = bpf_ktime_get_ns();
	pid_tgid = bpf_get_current_pid_tgid();
	vp = bpf_map_lookup_elem(&start, &pid_tgid);
	if (!vp)
		return 0;
	if ((int)ctx->ret < 0)
		goto cleanup;

	delta = (s64)(ts - vp->ts);
	if (delta < 0)
		goto cleanup;

	hkey.pid_tgid = pid_tgid;
	hkey.uaddr = vp->uaddr;
	if (!targ_summary)
		hkey.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	else
		hkey.pid_tgid >>= 32;

	histp = bpf_map_lookup_or_try_init(&hists, &hkey, &initial_hist);
	if (!histp)
		goto cleanup;

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);
	__sync_fetch_and_add(&histp->contended, 1);
	__sync_fetch_and_add(&histp->total_elapsed, delta);
	min = __sync_fetch_and_add(&histp->min, 0);
	if (!min || min > delta)
		__sync_val_compare_and_swap(&histp->min, min, delta);
	max = __sync_fetch_and_add(&histp->max, 0);
	if (max < delta)
		__sync_val_compare_and_swap(&histp->max, max, delta);
	bpf_get_current_comm(&histp->comm, sizeof(histp->comm));

cleanup:
	bpf_map_delete_elem(&start, &pid_tgid);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

"""

```