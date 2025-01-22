Response:
### 功能说明
该 eBPF 程序用于统计系统页缓存（Page Cache）的状态，包括总缓存访问次数、未命中次数及脏页标记次数。通过分析这些指标，可评估系统缓存的效率和性能。

---

### 执行顺序（10 步）
1. **触发缓存未命中**：当内核因读取未命中调用 `add_to_page_cache_lru`，触发 `fentry/kprobe` 钩子，增加 `misses`。
2. **记录缓存访问**：访问缓存页时调用 `mark_page_accessed`，触发钩子增加 `total`。
3. **处理脏页标记**：标记页面为脏时调用 `mark_buffer_dirty`，减少 `total` 并增加 `mbd`。
4. **调整未命中计数**：调用 `account_page_dirtied` 或 `folio_account_dirtied` 时减少 `misses`。
5. **脏页写回事件**：通过 `writeback_dirty_folio/page` 的 Tracepoint 减少 `misses`。
6. **兼容性处理**：若内核不支持 `fentry`，回退到 `kprobe` 钩子重复上述操作。
7. **数据同步**：使用原子操作 `__sync_fetch_and_add` 确保并发安全。
8. **统计汇总**：全局变量 `total`、`misses`、`mbd` 实时更新。
9. **用户态读取**：用户态工具定期读取这些变量并计算命中率。
10. **输出结果**：展示缓存命中率、未命中率及脏页数量。

---

### Hook 点与有效信息
| **Hook 类型**         | **函数/Tracepoint**               | **有效信息**                     | **说明**                           |
|-----------------------|----------------------------------|----------------------------------|-----------------------------------|
| `fentry`/`kprobe`     | `add_to_page_cache_lru`         | 缓存未命中事件                    | 页面因未命中被加入 LRU 缓存          |
| `fentry`/`kprobe`     | `mark_page_accessed`            | 缓存访问事件                     | 页面被访问，总访问量增加              |
| `fentry`/`kprobe`     | `account_page_dirtied`          | 脏页调整事件                     | 页面被标记为脏，减少未命中计数         |
| `fentry`/`kprobe`     | `mark_buffer_dirty`             | 脏页标记事件                     | 缓存页被标记为脏，调整总访问和脏页计数 |
| `tracepoint`          | `writeback_dirty_folio/page`    | 脏页写回事件                     | 脏页写回磁盘，减少未命中计数          |

---

### 假设输入与输出
- **输入**：系统发生文件读写操作，触发页缓存访问、未命中及脏页标记。
- **输出**：
  ```plaintext
  TOTAL   MISSES  DIRTY   HIT%
  1000    200     50      80%
  ```
  表示：总访问 1000 次，未命中 200 次，脏页 50 个，命中率 80%。

---

### 常见使用错误
1. **重复计数**：同时启用 `fentry` 和 `kprobe` 钩子（内核支持时），导致统计翻倍。
   - **解决**：根据内核版本选择一种钩子类型。
2. **兼容性问题**：旧内核无 `folio_account_dirtied` 函数，`kprobe` 挂载失败。
   - **解决**：使用动态检测函数存在性。
3. **数据竞争**：用户态读取全局变量时未同步，导致值不准确。
   - **解决**：使用原子变量或映射（map）存储数据。

---

### Syscall 到 Hook 的调试线索
1. **用户进程调用 `read()`**：触发文件系统读取。
2. **内核检查页缓存**：若未命中，调用 `add_to_page_cache_lru`。
   - 触发 `fentry/kprobe` 钩子，`misses++`。
3. **缓存页被访问**：调用 `mark_page_accessed`。
   - 触发钩子，`total++`。
4. **进程修改数据**：调用 `mark_buffer_dirty` 标记脏页。
   - 触发钩子，`total--`、`mbd++`。
5. **写回脏页**：后台线程调用 `writeback_dirty_folio/page`。
   - 触发 Tracepoint，`misses--`。

---

### 总结
该程序通过监控内核函数和 Tracepoint，统计页缓存的访问、未命中及脏页状态，帮助诊断系统 I/O 性能问题。需注意钩子兼容性和数据同步问题。
Prompt: 
```
这是目录为bcc/libbpf-tools/cachestat.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
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
#include <bpf/bpf_tracing.h>

__s64 total = 0;	/* total cache accesses without counting dirties */
__s64 misses = 0;	/* total of add to lru because of read misses */
__u64 mbd = 0;  	/* total of mark_buffer_dirty events */

SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(fentry_add_to_page_cache_lru)
{
	__sync_fetch_and_add(&misses, 1);
	return 0;
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(fentry_mark_page_accessed)
{
	__sync_fetch_and_add(&total, 1);
	return 0;
}

SEC("fentry/account_page_dirtied")
int BPF_PROG(fentry_account_page_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("fentry/mark_buffer_dirty")
int BPF_PROG(fentry_mark_buffer_dirty)
{
	__sync_fetch_and_add(&total, -1);
	__sync_fetch_and_add(&mbd, 1);
	return 0;
}

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(kprobe_add_to_page_cache_lru)
{
	__sync_fetch_and_add(&misses, 1);
	return 0;
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(kprobe_mark_page_accessed)
{
	__sync_fetch_and_add(&total, 1);
	return 0;
}

SEC("kprobe/account_page_dirtied")
int BPF_KPROBE(kprobe_account_page_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("kprobe/folio_account_dirtied")
int BPF_KPROBE(kprobe_folio_account_dirtied)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(kprobe_mark_buffer_dirty)
{
	__sync_fetch_and_add(&total, -1);
	__sync_fetch_and_add(&mbd, 1);
	return 0;
}

SEC("tracepoint/writeback/writeback_dirty_folio")
int tracepoint__writeback_dirty_folio(struct trace_event_raw_sys_enter* ctx)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

SEC("tracepoint/writeback/writeback_dirty_page")
int tracepoint__writeback_dirty_page(struct trace_event_raw_sys_enter* ctx)
{
	__sync_fetch_and_add(&misses, -1);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

"""

```