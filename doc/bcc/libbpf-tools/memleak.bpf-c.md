Response:
### 功能总结
1. **内存分配跟踪**：监控用户态和内核态的内存分配（如 `malloc`、`calloc`、`mmap`、`kmalloc` 等）。
2. **内存释放跟踪**：记录释放操作（如 `free`、`munmap`、`kfree`）。
3. **调用栈记录**：通过堆栈 ID 关联内存操作的调用上下文。
4. **内存泄漏检测**：统计未释放的内存块，结合堆栈信息定位泄漏点。
5. **条件过滤**：支持按内存大小范围（`min_size`/`max_size`）、采样率（`sample_rate`）过滤事件。
6. **多场景支持**：处理特殊函数（如 `realloc` 先释放旧地址再分配新内存）。
7. **内核与用户态统一**：通过 `tracepoint` 和 `uprobe` 同时监控内核和用户空间的内存操作。
8. **统计聚合**：通过 `combined_allocs` 映射汇总每个调用栈的总内存和分配次数。
9. **兼容性处理**：适配不同内核版本的跟踪点差异（如 `kmem_alloc` vs `kmalloc`）。
10. **调试支持**：通过 `trace_all` 输出详细日志，辅助问题排查。

---

### 执行顺序（逻辑流程）
1. **用户态内存分配入口**（如 `malloc`）：
   - 触发 `uprobe`，调用 `gen_alloc_enter`，记录分配大小到 `sizes` 映射。
2. **用户态分配返回**（如 `malloc` 返回）：
   - 触发 `uretprobe`，调用 `gen_alloc_exit`，记录地址到 `allocs` 映射，更新 `combined_allocs` 统计。
3. **用户态释放入口**（如 `free`）：
   - 触发 `uprobe`，调用 `gen_free_enter`，从 `allocs` 删除记录，更新统计。
4. **内核态内存分配**（如 `kmalloc`）：
   - 触发 `tracepoint`，记录分配地址和大小，流程同用户态。
5. **内核态释放**（如 `kfree`）：
   - 触发 `tracepoint`，调用 `gen_free_enter`。
6. **特殊函数处理**（如 `realloc`）：
   - 先触发旧地址的 `gen_free_enter`，再记录新分配。
7. **堆栈信息捕获**：
   - 在分配退出时通过 `bpf_get_stackid` 保存调用栈。
8. **统计聚合**：
   - 每次分配/释放时更新 `combined_allocs` 中的总内存和次数。
9. **数据持久化**：
   - 用户态工具读取 `allocs` 和 `combined_allocs` 生成报告。
10. **异常处理**：
    - 处理未匹配的释放操作（如 `wa_missing_free` 应对内核缺失释放事件）。

---

### Hook 点与关键信息
| **Hook 类型**          | **函数/跟踪点**                  | **读取信息**                          | **信息含义**                      |
|------------------------|----------------------------------|---------------------------------------|-----------------------------------|
| `uprobe`               | `malloc_enter`                  | `size_t size`                         | 用户态分配请求的大小              |
| `uretprobe`            | `malloc_exit`                   | 返回值（地址）                        | 分配的内存地址                    |
| `uprobe`               | `free_enter`                    | `void *address`                       | 要释放的内存地址                  |
| `tracepoint/kmem/kmalloc` | `memleak__kmalloc`            | `ptr`（地址）、`bytes_alloc`（大小）  | 内核分配的内存地址和大小          |
| `tracepoint/kmem/kfree`   | `memleak__kfree`              | `ptr`（地址）                         | 内核释放的内存地址                |
| `uprobe`               | `posix_memalign_enter`          | `size_t size`、`void **memptr`        | 对齐分配的大小和返回指针地址      |
| `uretprobe`            | `posix_memalign_exit`           | 通过 `memptr` 读取实际地址            | 对齐分配的实际内存地址            |
| `tracepoint/kmem/mm_page_alloc` | `memleak__mm_page_alloc`  | `order`（页阶数）                     | 内核页分配的数量（`order` 决定）  |
| `tracepoint/percpu/percpu_alloc_percpu` | `memleak__percpu_alloc_percpu` | `bytes_alloc`（大小）                 | 内核 per-CPU 内存分配的大小       |

---

### 逻辑推理示例
#### 输入场景
- **程序行为**：用户程序调用 `malloc(1024)` 未释放。
- **Hook 触发**：
  1. `malloc_enter` 记录 `size=1024`。
  2. `malloc_exit` 记录返回地址 `0x1234`，存入 `allocs`。
  3. 无 `free_enter` 触发，`allocs` 中保留 `0x1234` 的条目。
- **输出结果**：
  - `allocs` 中存在未删除的 `0x1234`，`combined_allocs` 中对应堆栈的总内存增加 1024。
  - 用户态工具显示该地址和调用栈为内存泄漏。

---

### 常见使用错误
1. **采样率过高**：
   - 设置 `sample_rate=100` 时，可能漏掉 99% 的小内存泄漏。
   - **现象**：工具报告泄漏量远小于实际值。
2. **未追踪特殊函数**：
   - 使用 `memalign` 但未挂钩对应函数。
   - **现象**：对齐分配的内存泄漏未被检测。
3. **内核版本不兼容**：
   - 旧内核无 `kmem_alloc` 跟踪点，导致统计缺失。
   - **现象**：内核泄漏检测部分失效。
4. **地址误判**：
   - `realloc` 旧地址释放后，新地址未正确记录。
   - **现象**：错误标记旧地址为泄漏。

---

### Syscall 到 Hook 的路径
1. **用户态调用 `malloc`**：
   - `malloc` → `brk`/`mmap` 系统调用 → glibc 内存管理。
   - **Hook 点**：`uprobe` 直接挂钩 `malloc` 而非系统调用。
2. **内核 `kmalloc`**：
   - 应用通过系统调用（如 `write`）触发内核分配内存。
   - **路径**：系统调用 → 内核代码调用 `kmalloc` → 触发 `tracepoint/kmem/kmalloc`。
3. **`free` 调用**：
   - `free` → `munmap` 系统调用（大内存）→ glibc 释放逻辑。
   - **Hook 点**：`uprobe` 挂钩 `free` 函数入口。

---

### 调试线索
1. **未释放内存地址**：
   - 检查 `allocs` 映射中残留的地址，结合堆栈 ID 定位代码位置。
2. **统计不准确**：
   - 检查 `sample_rate` 和 `min_size`/`max_size` 是否过滤了关键事件。
3. **内核泄漏检测失败**：
   - 确认内核版本支持的跟踪点（如 `tracepoint/kmem/kmalloc` 是否存在）。
4. **误报/漏报**：
   - 检查 `wa_missing_free` 是否适配内核行为，验证 `trace_all` 日志。
Prompt: 
```
这是目录为bcc/libbpf-tools/memleak.bpf.cbcc BPF Compiler Collection的源代码文件， BCC is a toolkit for creating efficient kernel tracing and manipulation programs, and includes several useful tools and examples. It makes use of extended BPF (Berkeley Packet Filters), formally known as eBPF,
请列举一下它的功能, 给出执行顺序(不是行号顺序), 建议分10步,
如果这是一个ebpf程序，给出hook的点，函数名，从这个hook点读取到的有效信息，说明是什么信息，比如文件路径, 进程pid,
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明syscall是如何一步步的到达这里，作为调试线索，
请用中文回复。

"""
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "memleak.h"
#include "core_fixes.bpf.h"

const volatile size_t min_size = 0;
const volatile size_t max_size = -1;
const volatile size_t page_size = 4096;
const volatile __u64 sample_rate = 1;
const volatile bool trace_all = false;
const volatile __u64 stack_flags = 0;
const volatile bool wa_missing_free = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* stack id */
	__type(value, union combined_alloc_info);
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stack_traces SEC(".maps");

static union combined_alloc_info initial_cinfo;

static void update_statistics_add(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_or_try_init(&combined_allocs, &stack_id, &initial_cinfo);
	if (!existing_cinfo)
		return;

	const union combined_alloc_info incremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_add(&existing_cinfo->bits, incremental_cinfo.bits);
}

static void update_statistics_del(u64 stack_id, u64 sz)
{
	union combined_alloc_info *existing_cinfo;

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (!existing_cinfo) {
		bpf_printk("failed to lookup combined allocs\n");

		return;
	}

	const union combined_alloc_info decremental_cinfo = {
		.total_size = sz,
		.number_of_allocs = 1
	};

	__sync_fetch_and_sub(&existing_cinfo->bits, decremental_cinfo.bits);
}

static int gen_alloc_enter(size_t size)
{
	if (size < min_size || size > max_size)
		return 0;

	if (sample_rate > 1) {
		if (bpf_ktime_get_ns() % sample_rate != 0)
			return 0;
	}

	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);

	if (trace_all)
		bpf_printk("alloc entered, size = %lu\n", size);

	return 0;
}

static int gen_alloc_exit2(void *ctx, u64 address)
{
	const u32 tid = bpf_get_current_pid_tgid();
	struct alloc_info info;

	const u64* size = bpf_map_lookup_elem(&sizes, &tid);
	if (!size)
		return 0; // missed alloc entry

	__builtin_memset(&info, 0, sizeof(info));

	info.size = *size;
	bpf_map_delete_elem(&sizes, &tid);

	if (address != 0 && address != MAP_FAILED) {
		info.timestamp_ns = bpf_ktime_get_ns();

		info.stack_id = bpf_get_stackid(ctx, &stack_traces, stack_flags);

		bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);

		update_statistics_add(info.stack_id, info.size);
	}

	if (trace_all) {
		bpf_printk("alloc exited, size = %lu, result = %lx\n",
				info.size, address);
	}

	return 0;
}

static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static int gen_free_enter(const void *address)
{
	const u64 addr = (u64)address;

	const struct alloc_info *info = bpf_map_lookup_elem(&allocs, &addr);
	if (!info)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

	if (trace_all) {
		bpf_printk("free entered, address = %lx, size = %lu\n",
				address, info->size);
	}

	return 0;
}

SEC("uprobe")
int BPF_UPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(free_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_UPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_URETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_UPROBE(mremap_enter, void *old_address, size_t old_size, size_t new_size, int flags)
{
	gen_free_enter(old_address);

	return gen_alloc_enter(new_size);
}

SEC("uretprobe")
int BPF_URETPROBE(mremap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&memptrs, &tid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(posix_memalign_exit)
{
	u64 *memptr64;
	void *addr;
	const u32 tid = bpf_get_current_pid_tgid();

	memptr64 = bpf_map_lookup_elem(&memptrs, &tid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &tid);

	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe")
int BPF_UPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_UPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_URETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("tracepoint/kmem/kmalloc")
int memleak__kmalloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmalloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter(ptr);

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int memleak__kmalloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter(ptr);

		gen_alloc_enter( bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kfree")
int memleak__kfree(void *ctx)
{
	const void *ptr;

	if (has_kfree()) {
		struct trace_event_raw_kfree___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc")
int memleak__kmem_cache_alloc(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc()) {
		struct trace_event_raw_kmem_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	} else {
		struct trace_event_raw_kmem_cache_alloc___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);
	}

	if (wa_missing_free)
		gen_free_enter(ptr);

	gen_alloc_enter(bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int memleak__kmem_cache_alloc_node(void *ctx)
{
	const void *ptr;
	size_t bytes_alloc;

	if (has_kmem_alloc_node()) {
		struct trace_event_raw_kmem_alloc_node___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
		bytes_alloc = BPF_CORE_READ(args, bytes_alloc);

		if (wa_missing_free)
			gen_free_enter(ptr);

		gen_alloc_enter(bytes_alloc);

		return gen_alloc_exit2(ctx, (u64)ptr);
	} else {
		/* tracepoint is disabled if not exist, avoid compile warning */
		return 0;
	}
}

SEC("tracepoint/kmem/kmem_cache_free")
int memleak__kmem_cache_free(void *ctx)
{
	const void *ptr;

	if (has_kmem_cache_free()) {
		struct trace_event_raw_kmem_cache_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	} else {
		struct trace_event_raw_kmem_free___x *args = ctx;
		ptr = BPF_CORE_READ(args, ptr);
	}

	return gen_free_enter(ptr);
}

SEC("tracepoint/kmem/mm_page_alloc")
int memleak__mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
	gen_alloc_enter(page_size << ctx->order);

	return gen_alloc_exit2(ctx, ctx->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int memleak__mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
	return gen_free_enter((void *)ctx->pfn);
}

SEC("tracepoint/percpu/percpu_alloc_percpu")
int memleak__percpu_alloc_percpu(struct trace_event_raw_percpu_alloc_percpu *ctx)
{
	gen_alloc_enter(ctx->bytes_alloc);

	return gen_alloc_exit2(ctx, (u64)(ctx->ptr));
}

SEC("tracepoint/percpu/percpu_free_percpu")
int memleak__percpu_free_percpu(struct trace_event_raw_percpu_free_percpu *ctx)
{
	return gen_free_enter(ctx->ptr);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

"""

```