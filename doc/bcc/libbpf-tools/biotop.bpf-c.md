Response:
### 功能概述
该 eBPF 程序用于监控块设备 I/O 操作，统计每个进程的 I/O 延迟、吞吐量、操作次数等信息。类似 `iotop` 工具，但基于 eBPF 实现，支持按设备、进程、读写类型聚合数据。

---

### 执行顺序（10 步骤）
1. **初始化映射**：加载 eBPF 程序时，初始化 `start`、`whobyreq`、`counts` 三个哈希表。
2. **Hook 块请求开始**：当内核调用 `blk_mq_start_request` 或相关函数时，记录请求的起始时间戳和数据长度到 `start` 映射。
3. **关联进程信息**：在 `blk_account_io_start` 或类似函数触发时，将当前进程的 PID 和名称关联到请求（存入 `whobyreq` 映射）。
4. **捕获请求完成**：当内核调用 `blk_account_io_done` 或相关函数时，触发 `trace_done` 逻辑。
5. **计算耗时**：从 `start` 映射中取出起始时间，计算 I/O 操作的微秒级耗时。
6. **提取设备信息**：通过请求的 `gendisk` 结构获取设备的主次设备号。
7. **判断读写类型**：根据 `cmd_flags` 判断是读（REQ_OP_READ）还是写（REQ_OP_WRITE）。
8. **聚合统计数据**：将耗时、字节数、I/O 次数按设备、进程、读写类型聚合到 `counts` 映射。
9. **清理临时数据**：删除 `start` 和 `whobyreq` 映射中已处理的请求条目。
10. **用户空间展示**：用户态程序（如 `biotop`）定期读取 `counts` 映射并格式化输出。

---

### Hook 点与有效信息
| Hook 类型          | 函数名                     | 触发时机                  | 读取信息                          | 信息说明                     |
|--------------------|---------------------------|--------------------------|---------------------------------|----------------------------|
| **Kprobe**         | `blk_mq_start_request`    | 块请求开始               | `struct request*` 指针          | 请求的唯一标识               |
| **Kprobe**         | `blk_account_io_start`    | 进程关联 I/O 开始        | 当前进程的 PID 和名称（`who_t`） | 进程上下文信息               |
| **Kprobe**         | `blk_account_io_done`     | 进程关联 I/O 完成        | `struct request*` 指针          | 用于关联 `start` 和 `whobyreq` |
| **Tracepoint**     | `block_io_start`          | 块 I/O 开始（通用事件）  | 同上                            | 兼容不同内核版本的替代方案    |
| **Tracepoint**     | `block_io_done`           | 块 I/O 完成（通用事件）  | 同上                            | 同上                        |

---

### 逻辑推理示例
**假设输入**：进程 PID=1234 写入 4KB 数据到 `/dev/sda`。  
**输出**：在 `counts` 映射中更新 `info_t{ major=8, minor=0, rwflag=1, pid=1234 }` 对应的 `val_t`，增加 `us=500`（耗时）、`bytes=4096`、`io=1`。

---

### 常见错误与调试
1. **Hook 点失效**  
   **原因**：内核版本差异导致函数名或参数变化（如 `blk_account_io_*` 的重命名）。  
   **调试**：通过 `/sys/kernel/debug/tracing/available_filter_functions` 检查目标函数是否存在。

2. **数据丢失**  
   **原因**：`start` 或 `whobyreq` 映射容量不足，导致请求信息被覆盖。  
   **解决**：增大 `max_entries` 或优化过滤条件（如 `target_pid`）。

3. **时间计算错误**  
   **现象**：`delta_us` 为负数。  
   **原因**：请求在 `start` 映射记录前已完成，导致 `startp` 为 `NULL`。

---

### Syscall 到 Hook 的路径
1. **用户态调用**：进程调用 `write()` 系统调用写入文件。
2. **文件系统层**：VFS 将写操作转发到文件系统（如 ext4）。
3. **块层提交请求**：文件系统通过 `submit_bio()` 提交 I/O 请求到块层。
4. **触发 Hook 点**：块层调用 `blk_mq_start_request` 或 `blk_account_io_start`，被 eBPF 程序捕获。
5. **请求完成回调**：设备驱动处理完 I/O 后，调用 `blk_account_io_done`，再次触发 eBPF 统计。

---

### 调试线索
1. **检查 Hook 点状态**：通过 `bpftool prog list` 确认 eBPF 程序已加载并绑定到目标函数。
2. **查看映射内容**：使用 `bpftool map dump` 检查 `counts` 映射是否累积数据。
3. **内核日志**：通过 `dmesg` 查找 eBPF 验证器错误（如类型不匹配）。
### 提示词
```
这是目录为bcc/libbpf-tools/biotop.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
// Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "biotop.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, struct start_req_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct request *);
	__type(value, struct who_t);
} whobyreq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct info_t);
	__type(value, struct val_t);
} counts SEC(".maps");

static __always_inline
int trace_start(struct request *req)
{
	struct who_t who = {};
	__u64 pid_tgid;
	__u32 pid;

	/* cache PID and comm by-req */
	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;

	if (target_pid && target_pid != pid)
		return 0;

	bpf_get_current_comm(&who.name, sizeof(who.name));
	who.pid = pid;
	bpf_map_update_elem(&whobyreq, &req, &who, 0);

	return 0;
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(blk_mq_start_request, struct request *req)
{
	/* time block I/O */
	struct start_req_t start_req;

	start_req.ts = bpf_ktime_get_ns();
	start_req.data_len = BPF_CORE_READ(req, __data_len);

	bpf_map_update_elem(&start, &req, &start_req, 0);
	return 0;
}

static __always_inline
int trace_done(struct request *req)
{
	struct val_t *valp, zero = {};
	struct info_t info = {};
	struct start_req_t *startp;
	unsigned int cmd_flags;
	struct gendisk *disk;
	struct who_t *whop;
	u64 delta_us;
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	if (target_pid && target_pid != pid)
		goto cleanup;

	/* fetch timestamp and calculate delta */
	startp = bpf_map_lookup_elem(&start, &req);
	if (!startp)
		goto cleanup;    /* missed tracing issue */

	delta_us = (bpf_ktime_get_ns() - startp->ts) / 1000;

	/* setup info_t key */
	cmd_flags = BPF_CORE_READ(req, cmd_flags);

	disk = get_disk(req);
	info.major = BPF_CORE_READ(disk, major);
	info.minor = BPF_CORE_READ(disk, first_minor);
	info.rwflag = !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);

	whop = bpf_map_lookup_elem(&whobyreq, &req);
	if (whop) {
		info.pid = whop->pid;
		__builtin_memcpy(&info.name, whop->name, sizeof(info.name));
	}

	valp = bpf_map_lookup_or_try_init(&counts, &info, &zero);

	if (valp) {
		/* save stats */
		valp->us += delta_us;
		valp->bytes += startp->data_len;
		valp->io++;
	}

cleanup:
	bpf_map_delete_elem(&start, &req);
	bpf_map_delete_elem(&whobyreq, &req);
	return 0;
}

SEC("kprobe/blk_account_io_start")
int BPF_KPROBE(blk_account_io_start, struct request *req)
{
	return trace_start(req);
}

SEC("kprobe/blk_account_io_done")
int BPF_KPROBE(blk_account_io_done, struct request *req)
{
	return trace_done(req);
}

SEC("kprobe/__blk_account_io_start")
int BPF_KPROBE(__blk_account_io_start, struct request *req)
{
	return trace_start(req);
}

SEC("kprobe/__blk_account_io_done")
int BPF_KPROBE(__blk_account_io_done, struct request *req)
{
	return trace_done(req);
}

SEC("tp_btf/block_io_start")
int BPF_PROG(block_io_start, struct request *req)
{
	return trace_start(req);
}

SEC("tp_btf/block_io_done")
int BPF_PROG(block_io_done, struct request *req)
{
	return trace_done(req);
}

char LICENSE[] SEC("license") = "GPL";
```