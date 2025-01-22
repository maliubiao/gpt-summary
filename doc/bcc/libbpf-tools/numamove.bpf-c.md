Response:
### 功能概述
该 eBPF 程序用于监控 Linux 内核中 NUMA（非统一内存访问）相关的内存页迁移函数（`migrate_misplaced_page` 和 `migrate_misplaced_folio`）的执行延迟，统计总延迟和调用次数，帮助诊断 NUMA 性能问题。

---

### 执行顺序（分10步）
1. **加载程序**：用户态通过 BCC 工具加载 eBPF 程序到内核。
2. **挂载入口探针**：将 `fentry` 或 `kprobe` 探针绑定到内核函数 `migrate_misplaced_page` 和 `migrate_misplaced_folio` 的入口。
3. **入口触发**：当内核执行上述函数时，触发入口处理函数（如 `BPF_PROG(fentry_migrate_misplaced_page)`）。
4. **记录开始时间**：在入口函数中获取当前进程 PID 和时间戳，存入哈希表 `start`。
5. **挂载出口探针**：将 `fexit` 或 `kretprobe` 探针绑定到上述内核函数的退出点。
6. **出口触发**：当内核函数执行完毕时，触发出口处理函数（如 `BPF_PROG(fexit_migrate_misplaced_page_exit)`）。
7. **计算延迟**：在出口函数中通过 PID 查找哈希表，计算函数执行时间差（单位：毫秒）。
8. **更新统计**：累加总延迟 `latency` 和调用次数 `num`。
9. **清理数据**：从哈希表中删除当前 PID 的记录。
10. **用户态读取**：用户态工具定期从全局变量 `latency` 和 `num` 读取数据并输出统计结果。

---

### Hook 点与关键信息
| Hook 类型         | 函数名                          | 有效信息                          | 信息说明                     |
|-------------------|--------------------------------|----------------------------------|----------------------------|
| `fentry`/`kprobe` | `migrate_misplaced_page`       | 当前进程 PID、入口时间戳（纳秒）   | 用于计算函数执行延迟         |
| `fentry`/`kprobe` | `migrate_misplaced_folio`      | 同上                             | 同上                       |
| `fexit`/`kretprobe`| `migrate_misplaced_page`       | 当前进程 PID、出口时间戳（纳秒）   | 结合入口时间计算延迟         |
| `fexit`/`kretprobe`| `migrate_misplaced_folio`      | 同上                             | 同上                       |

---

### 逻辑推理：输入与输出
- **输入**：内核触发内存页迁移事件（如 NUMA 平衡机制或进程访问远程内存）。
- **输出**：全局变量 `latency`（总延迟毫秒数）和 `num`（迁移次数）。
- **示例**：若发生 5 次迁移，每次耗时 2ms，则 `latency=10`，`num=5`。

---

### 常见使用错误
1. **内核版本不兼容**：  
   - 错误现象：加载失败，提示 `Failed to attach BPF program`。  
   - 原因：旧内核无 `migrate_misplaced_folio` 函数（该函数替代了 `migrate_misplaced_page`）。  
   - 解决：检查内核版本，注释掉不存在的函数探针。

2. **权限不足**：  
   - 错误现象：`Permission denied`。  
   - 原因：非 root 用户或缺少 `CAP_BPF` 权限。  
   - 解决：以 root 权限运行或授予权限。

---

### Syscall 触发路径（调试线索）
1. **触发场景**：进程在 NUMA 节点间访问内存，触发内核的 NUMA 平衡机制。
2. **系统调用路径**：  
   - 用户态调用 `malloc()` 或访问内存 → 触发缺页异常（Page Fault）。  
   - 内核检测到内存位于非最优 NUMA 节点 → 调用 `migrate_misplaced_page`/`folio`。  
   - eBPF 程序在函数入口/出口记录时间戳。  
3. **调试方法**：  
   - 使用 `bpftrace` 跟踪内核函数调用：  
     ```bash
     bpftrace -e 'kprobe:migrate_misplaced_page { printf("PID %d called\n", pid); }'
     ```
   - 结合 `numastat` 或 `perf` 分析 NUMA 迁移事件。
Prompt: 
```
这是目录为bcc/libbpf-tools/numamove.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

__u64 latency = 0;
__u64 num = 0;

static int __migrate_misplaced(void)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start, &pid, &ts, 0);
	return 0;
}

SEC("fentry/migrate_misplaced_page")
int BPF_PROG(fentry_migrate_misplaced_page)
{
	return __migrate_misplaced();
}

SEC("fentry/migrate_misplaced_folio")
int BPF_PROG(fentry_migrate_misplaced_folio)
{
	return __migrate_misplaced();
}

SEC("kprobe/migrate_misplaced_page")
int BPF_PROG(kprobe_migrate_misplaced_page)
{
	return __migrate_misplaced();
}

SEC("kprobe/migrate_misplaced_folio")
int BPF_PROG(kprobe_migrate_misplaced_folio)
{
	return __migrate_misplaced();
}

static int __migrate_misplaced_exit(void)
{
	u32 pid = bpf_get_current_pid_tgid();
	u64 *tsp, ts = bpf_ktime_get_ns();
	s64 delta;

	tsp = bpf_map_lookup_elem(&start, &pid);
	if (!tsp)
		return 0;
	delta = (s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;
	__sync_fetch_and_add(&latency, delta / 1000000U);
	__sync_fetch_and_add(&num, 1);

cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("fexit/migrate_misplaced_page")
int BPF_PROG(fexit_migrate_misplaced_page_exit)
{
	return __migrate_misplaced_exit();
}

SEC("fexit/migrate_misplaced_folio")
int BPF_PROG(fexit_migrate_misplaced_folio_exit)
{
	return __migrate_misplaced_exit();
}

SEC("kretprobe/migrate_misplaced_page")
int BPF_PROG(kretprobe_migrate_misplaced_page_exit)
{
	return __migrate_misplaced_exit();
}

SEC("kretprobe/migrate_misplaced_folio")
int BPF_PROG(kretprobe_migrate_misplaced_folio_exit)
{
	return __migrate_misplaced_exit();
}

char LICENSE[] SEC("license") = "GPL";

"""

```