Response:
### 功能概述
这是一个用于**测量块设备I/O请求延迟分布**的eBPF程序，通过跟踪块设备层的请求生命周期（插入队列、下发到硬件、完成），记录每个阶段的耗时，最终生成延迟直方图。支持按磁盘设备、请求标志分类统计，并可过滤特定CGroup或设备。

---

### 执行顺序（10步）
1. **用户空间初始化**：设置过滤参数（设备号、CGroup、统计维度）。
2. **加载eBPF程序**：将编译后的程序附加到指定的内核跟踪点。
3. **触发`block_rq_insert`事件**：当I/O请求被插入块设备队列时，记录起始时间戳。
4. **触发`block_rq_issue`事件**：当请求从队列下发到硬件设备时，记录实际下发时间（若启用`targ_queued`过滤则不记录队列等待时间）。
5. **过滤逻辑**：检查CGroup和设备号，不符合条件的请求被丢弃。
6. **触发`block_rq_complete`事件**：请求完成时，从`start`映射中查找对应的时间戳。
7. **计算延迟**：用完成时间减去起始时间，得到I/O延迟（纳秒级）。
8. **数据分类**：根据磁盘设备号（`targ_per_disk`）或请求标志（`targ_per_flag`）生成分类键。
9. **更新直方图**：将延迟按对数区间分桶，累加到对应的直方图槽位。
10. **用户空间读取**：周期性从`hists`映射中提取数据，输出延迟分布直方图。

---

### Hook点与关键信息
| Hook点                     | 函数名                  | 有效信息                           | 信息说明                          |
|---------------------------|-------------------------|----------------------------------|---------------------------------|
| `tp_btf/block_rq_insert`  | `block_rq_insert_btf`   | `struct request *rq`            | 块设备请求对象（含设备、队列信息）     |
| `raw_tp/block_rq_insert`  | `block_rq_insert`       | 同上                              | 兼容旧内核的原始跟踪点              |
| `tp_btf/block_rq_issue`   | `block_rq_issue_btf`    | `struct request *rq`            | 下发时的请求对象                    |
| `raw_tp/block_rq_issue`   | `block_rq_issue`        | 同上                              | 兼容旧内核的原始跟踪点              |
| `tp_btf/block_rq_complete`| `block_rq_complete_btf` | `struct request *rq`, `error`   | 完成的请求对象及错误码              |
| `raw_tp/block_rq_complete`| `block_rq_complete`     | 同上                              | 兼容旧内核的原始跟踪点              |

**关键数据提取**：
- **设备号**：通过`rq->q->disk`获取`gendisk`结构，计算主次设备号（`MKDEV`）。
- **进程PID**：`bpf_get_current_pid_tgid()`可获取发起I/O的进程ID（但此程序未显式记录）。
- **请求标志**：`rq->cmd_flags`包含读写方向（REQ_OP_READ/WRITE）等信息。

---

### 逻辑推理示例
**假设输入**：一个EXT4文件系统的写操作（对应`REQ_OP_WRITE`）。
1. **系统调用路径**：`write() -> vfs_write() -> ext4_file_write_iter() -> submit_bio() -> block层生成request`。
2. **Hook触发顺序**：
   - `block_rq_insert`：请求入队时记录时间`t1`。
   - `block_rq_issue`：请求下发到磁盘时记录时间`t2`（若启用队列过滤则跳过）。
   - `block_rq_complete`：请求完成时计算延迟`t3 - t1`。
3. **输出直方图**：显示该请求的延迟落在`[16ms, 32ms)`区间。

---

### 常见使用错误
1. **设备号过滤失效**：用户误输入十进制设备号（应使用`lsblk -d -o MAJ:MIN`获取十六进制值）。
   ```bash
   # 错误示例：直接使用设备名
   ./biolatency -D sda  # 应使用`-D 0x8:0`
   ```
2. **CGroup路径错误**：未正确绑定CGroup导致过滤无数据。
   ```bash
   # 错误示例：未挂载cgroup2或路径无效
   ./biolatency -c /invalid/cgroup/path
   ```
3. **内核版本兼容性**：旧内核无`tp_btf`支持，需回退到`raw_tp`。

---

### Syscall调试线索
1. **跟踪系统调用到块层**：
   - `write`/`read` -> `vfs_read`/`vfs_write` -> 文件系统层 -> `submit_bio` -> 块层生成`request`。
2. **请求生命周期事件**：
   - **插入队列**：`blk_mq_sched_insert_request()`触发`block_rq_insert`。
   - **下发到设备**：`scsi_dispatch_cmd()`触发`block_rq_issue`。
   - **完成中断**：`blk_mq_complete_request()`触发`block_rq_complete`。
3. **调试技巧**：结合`bpftrace`验证事件触发：
   ```bash
   bpftrace -e 'tracepoint:block:block_rq_* { printf("%s\n", probe); }'
   ```
### 提示词
```
这是目录为bcc/libbpf-tools/biolatency.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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

#include "biolatency.h"
#include "bits.bpf.h"
#include "core_fixes.bpf.h"

#define MAX_ENTRIES	10240

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile bool filter_cg = false;
const volatile bool targ_per_disk = false;
const volatile bool targ_per_flag = false;
const volatile bool targ_queued = false;
const volatile bool targ_ms = false;
const volatile bool filter_dev = false;
const volatile __u32 targ_dev = 0;
const volatile bool targ_single = true;

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct request *);
	__type(value, u64);
} start SEC(".maps");

static struct hist initial_hist;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct hist_key);
	__type(value, struct hist);
} hists SEC(".maps");

static int __always_inline trace_rq_start(struct request *rq, int issue)
{
	u64 ts;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	if (issue && targ_queued && BPF_CORE_READ(rq, q, elevator))
		return 0;

	ts = bpf_ktime_get_ns();

	if (filter_dev) {
		struct gendisk *disk = get_disk(rq);
		u32 dev;

		dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
				BPF_CORE_READ(disk, first_minor)) : 0;
		if (targ_dev != dev)
			return 0;
	}
	bpf_map_update_elem(&start, &rq, &ts, 0);
	return 0;
}

static int handle_block_rq_insert(__u64 *ctx)
{
	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (!targ_single)
		return trace_rq_start((void *)ctx[1], false);
	else
		return trace_rq_start((void *)ctx[0], false);
}

static int handle_block_rq_issue(__u64 *ctx)
{
	/**
	 * commit a54895fa (v5.11-rc1) changed tracepoint argument list
	 * from TP_PROTO(struct request_queue *q, struct request *rq)
	 * to TP_PROTO(struct request *rq)
	 */
	if (!targ_single)
		return trace_rq_start((void *)ctx[1], true);
	else
		return trace_rq_start((void *)ctx[0], true);
}

static int handle_block_rq_complete(struct request *rq, int error, unsigned int nr_bytes)
{
	u64 slot, *tsp, ts = bpf_ktime_get_ns();
	struct hist_key hkey = {};
	struct hist *histp;
	s64 delta;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	tsp = bpf_map_lookup_elem(&start, &rq);
	if (!tsp)
		return 0;

	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (targ_per_disk) {
		struct gendisk *disk = get_disk(rq);

		hkey.dev = disk ? MKDEV(BPF_CORE_READ(disk, major),
					BPF_CORE_READ(disk, first_minor)) : 0;
	}
	if (targ_per_flag)
		hkey.cmd_flags = BPF_CORE_READ(rq, cmd_flags);

	histp = bpf_map_lookup_elem(&hists, &hkey);
	if (!histp) {
		bpf_map_update_elem(&hists, &hkey, &initial_hist, 0);
		histp = bpf_map_lookup_elem(&hists, &hkey);
		if (!histp)
			goto cleanup;
	}

	if (targ_ms)
		delta /= 1000000U;
	else
		delta /= 1000U;
	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&histp->slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&start, &rq);
	return 0;
}

SEC("tp_btf/block_rq_insert")
int block_rq_insert_btf(u64 *ctx)
{
	return handle_block_rq_insert(ctx);
}

SEC("tp_btf/block_rq_issue")
int block_rq_issue_btf(u64 *ctx)
{
	return handle_block_rq_issue(ctx);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete_btf, struct request *rq, int error, unsigned int nr_bytes)
{
	return handle_block_rq_complete(rq, error, nr_bytes);
}

SEC("raw_tp/block_rq_insert")
int BPF_PROG(block_rq_insert)
{
	return handle_block_rq_insert(ctx);
}

SEC("raw_tp/block_rq_issue")
int BPF_PROG(block_rq_issue)
{
	return handle_block_rq_issue(ctx);
}

SEC("raw_tp/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error, unsigned int nr_bytes)
{
	return handle_block_rq_complete(rq, error, nr_bytes);
}

char LICENSE[] SEC("license") = "GPL";
```