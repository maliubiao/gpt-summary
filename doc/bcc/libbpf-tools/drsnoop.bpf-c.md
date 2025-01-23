Response:
### 功能概述
该 eBPF 程序用于跟踪 Linux 内核中直接内存回收（Direct Memory Reclaim）事件，记录进程触发直接内存回收的耗时、回收页面数、系统空闲内存等信息。主要功能包括：
1. 捕获直接内存回收的**开始**和**结束**事件。
2. 统计回收耗时、回收页面数、进程信息。
3. 支持通过 PID/TGID 过滤目标进程。

---

### 执行顺序（10 步）
1. **用户空间配置**：设置过滤条件 `targ_pid`/`targ_tgid` 和 `vm_zone_stat_kaddr`。
2. **挂载 Hook 点**：加载 eBPF 程序到内核，绑定到 `mm_vmscan_direct_reclaim_begin` 和 `end` 事件。
3. **触发直接内存回收**：进程因内存不足触发回收逻辑。
4. **Begin 事件捕获**：内核调用 `handle_direct_reclaim_begin`，记录进程 PID、时间戳、空闲页数到 `start` Map。
5. **End 事件捕获**：内核调用 `handle_direct_reclaim_end`，从 Map 中查找 Begin 阶段的数据。
6. **计算耗时**：通过时间戳差值计算回收耗时 (`delta_ns`)。
7. **填充事件数据**：整合进程名、回收页面数 (`nr_reclaimed`)、空闲页数 (`nr_free_pages`)。
8. **输出到用户空间**：通过 `perf_event_array` 将事件发送到用户态。
9. **清理 Map**：删除 `start` Map 中的临时数据。
10. **用户态处理**：BCC 工具解析并打印事件信息。

---

### Hook 点与关键信息
| Hook 点类型          | 函数名                      | 触发时机                  | 读取的有效信息                          |
|----------------------|----------------------------|--------------------------|---------------------------------------|
| `tp_btf`/`raw_tp`    | `direct_reclaim_begin_btf` | 直接内存回收**开始**时   | 进程 PID、TGID、当前时间戳、系统空闲页数 |
| `tp_btf`/`raw_tp`    | `direct_reclaim_end_btf`   | 直接内存回收**结束**时   | 进程 PID、回收页面数 (`nr_reclaimed`)    |

---

### 逻辑推理：输入与输出
- **假设输入**：进程 PID=1234 触发直接内存回收，回收 5 个页面，耗时 1000ns，系统空闲页为 10000。
- **输出事件**：
  ```c
  struct event {
    .pid = 1234,
    .nr_reclaimed = 5,
    .delta_ns = 1000,
    .nr_free_pages = 10000,
    .task = "process_name"
  };
  ```

---

### 常见使用错误
1. **未正确设置 `vm_zone_stat_kaddr`**：
   - 错误现象：`nr_free_pages` 始终为 0。
   - 解决方法：需通过内核符号表获取 `vm_zone_stat[NR_FREE_PAGES]` 地址。
2. **过滤条件冲突**：
   - 错误现象：同时设置 `targ_pid` 和 `targ_tgid` 导致无事件输出。
   - 建议：仅使用一种过滤条件。
3. **权限不足**：
   - 错误现象：加载 eBPF 程序失败。
   - 解决：需要 `CAP_SYS_ADMIN` 权限或 root 用户。

---

### Syscall 调试线索
直接内存回收由内存压力触发（非直接由 Syscall 触发），典型场景：
1. **内存分配**：进程通过 `malloc()` 或 `mmap()` 申请内存。
2. **页面错误**：触发缺页中断 (`handle_mm_fault`)。
3. **内存不足**：Buddy 分配器无法分配页面，调用 `direct reclaim`。
4. **触发 Hook**：内核执行回收前后触发 `mm_vmscan_direct_reclaim_begin/end`。

---

### 总结
- **核心目的**：监控直接内存回收性能，定位内存瓶颈。
- **关键数据**：耗时、回收页面数、进程信息。
- **调试重点**：确保 Hook 点存在、地址正确、过滤条件合理。
### 提示词
```
这是目录为bcc/libbpf-tools/drsnoop.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
#include <bpf/bpf_tracing.h>
#include "drsnoop.h"

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile __u64 vm_zone_stat_kaddr = 0;

struct piddata {
	u64 ts;
	u64 nr_free_pages;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, struct piddata);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static int handle_direct_reclaim_begin()
{
	u64 *vm_zone_stat_kaddrp = (u64*)vm_zone_stat_kaddr;
	u64 id = bpf_get_current_pid_tgid();
	struct piddata piddata = {};
	u32 tgid = id >> 32;
	u32 pid = id;

	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	piddata.ts = bpf_ktime_get_ns();
	if (vm_zone_stat_kaddrp) {
		bpf_probe_read_kernel(&piddata.nr_free_pages,
				      sizeof(*vm_zone_stat_kaddrp),
				      &vm_zone_stat_kaddrp[NR_FREE_PAGES]);
	}

	bpf_map_update_elem(&start, &pid, &piddata, 0);
	return 0;
}

static int handle_direct_reclaim_end(void *ctx, unsigned long nr_reclaimed)
{
	u64 id = bpf_get_current_pid_tgid();
	struct piddata *piddatap;
	struct event event = {};
	u32 tgid = id >> 32;
	u32 pid = id;
	s64 delta_ns;

	if (targ_tgid && targ_tgid != tgid)
		return 0;
	if (targ_pid && targ_pid != pid)
		return 0;

	/* fetch timestamp and calculate delta */
	piddatap = bpf_map_lookup_elem(&start, &pid);
	if (!piddatap)
		return 0;   /* missed entry */

	delta_ns = bpf_ktime_get_ns() - piddatap->ts;
	if (delta_ns < 0)
		goto cleanup;

	event.pid = pid;
	event.nr_reclaimed = nr_reclaimed;
	event.delta_ns = delta_ns;
	event.nr_free_pages = piddatap->nr_free_pages;
	bpf_get_current_comm(&event.task, TASK_COMM_LEN);

	/* output */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tp_btf/mm_vmscan_direct_reclaim_begin")
int BPF_PROG(direct_reclaim_begin_btf)
{
	return handle_direct_reclaim_begin();
}

SEC("tp_btf/mm_vmscan_direct_reclaim_end")
int BPF_PROG(direct_reclaim_end_btf, unsigned long nr_reclaimed)
{
	return handle_direct_reclaim_end(ctx, nr_reclaimed);
}

SEC("raw_tp/mm_vmscan_direct_reclaim_begin")
int BPF_PROG(direct_reclaim_begin)
{
	return handle_direct_reclaim_begin();
}

SEC("raw_tp/mm_vmscan_direct_reclaim_end")
int BPF_PROG(direct_reclaim_end, unsigned long nr_reclaimed)
{
	return handle_direct_reclaim_end(ctx, nr_reclaimed);
}

char LICENSE[] SEC("license") = "GPL";
```