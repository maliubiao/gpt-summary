Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for a functional summary of the provided `mheap.go` code, specifically the first part. It also probes for deeper understanding like identifying Go features implemented, code reasoning examples, command-line argument handling, and common mistakes. Finally, it wants a concise summary of this first part.

2. **Initial Scan and Keyword Recognition:**  Quickly skim the code, looking for prominent keywords and structures:
    * `package runtime`:  Indicates this is part of the Go runtime.
    * `import`: Lists dependencies, hinting at functionalities like CPU information, architecture details, atomics, system calls, and unsafe operations.
    * `const`: Defines various constants related to page sizes, chunk sizes, and alignment, suggesting memory management.
    * `type mheap struct`:  This is the central data structure. Its fields will be key to understanding the code's purpose.
    * Fields in `mheap`: `lock`, `pages`, `allspans`, `central`, `spanalloc`, `cachealloc`, etc. These names strongly suggest memory management concepts.
    * `type heapArena struct`, `type mspan struct`, `type mSpanList struct`: These are supporting data structures, likely representing memory regions and their organization.
    * Functions like `recordspan`, `arenaIndex`, `spanOf`, `reclaim`, `reclaimChunk`, `init`. These indicate operations performed on the heap.

3. **Focus on the `mheap` Struct:**  This is the core. Analyze its fields:
    * `lock mutex`:  Concurrency control.
    * `pages pageAlloc`:  Allocation of pages, suggesting a lower-level memory manager.
    * `allspans []*mspan`: A collection of all memory spans, important for tracking allocated regions.
    * Proportional sweep fields (`pagesInUse`, `pagesSwept`, etc.): Relates to garbage collection and efficient memory reclamation.
    * Page reclaimer fields (`reclaimIndex`, `reclaimCredit`):  Mechanisms for freeing unused memory.
    * `arenas [1 << arenaL1Bits]*[1 << arenaL2Bits]*heapArena`: A multi-level map for storing metadata about memory regions (arenas). This is a crucial part of the heap's organization.
    * `central [numSpanClasses]struct { mcentral mcentral; pad ... }`: Centralized free lists for different object sizes, a common technique in allocators.
    * `spanalloc fixalloc`, `cachealloc fixalloc`, etc.: Dedicated allocators for specific runtime data structures, optimizing their allocation.
    * `userArena`:  Features related to user-managed memory arenas.

4. **Identify Key Functions and Their Roles:**
    * `recordspan`:  Registers newly created spans. This is important for tracking all allocated memory.
    * `arenaIndex`, `arenaBase`:  Functions for calculating indices and base addresses of arenas, essential for locating metadata.
    * `spanOf`, `spanOfHeap`:  Functions for finding the memory span associated with a given address, critical for memory lookups and garbage collection.
    * `reclaim`, `reclaimChunk`: The core logic of the page reclaimer, responsible for freeing unused memory pages.
    * `init`: Initializes the heap's data structures.

5. **Infer Go Feature Implementations:** Based on the identified structures and functions:
    * **Heap Allocation:** The very presence of `mheap`, `mspan`, and arenas points to the implementation of Go's dynamic memory allocation (the heap).
    * **Garbage Collection:** The "proportional sweep" fields, "page reclaimer," and `gcmarkBits` in `mspan` strongly indicate the implementation of Go's garbage collector, specifically the concurrent sweeper and marking mechanisms.
    * **Memory Management (Small Objects):** The `central` free lists suggest optimization for allocating small objects using size classes.
    * **Memory Management (Large Objects):** The mention of `largeType` in `mspan` hints at handling allocations larger than the standard size classes.
    * **Stack Allocation:** `spanAllocStack` and discussion of manual memory management in `mspan`'s state indicate how stacks are managed.
    * **User-Managed Memory Arenas:** The `userArena` field points to a feature allowing users to manage their own memory pools.

6. **Code Reasoning (Example - `spanOf`):**
    * **Input Assumption:** A memory address `p`.
    * **Process:** The function calculates an `arenaIndex` from the address. It then uses this index to look up the corresponding `heapArena` in the `mheap_.arenas` map. Finally, it calculates an offset within the `heapArena.spans` array to find the `mspan` associated with the page containing `p`.
    * **Output:** A pointer to the `mspan` if found, otherwise `nil`.
    * **Key Logic:**  The multi-level arena map is the core of this lookup. The modulo operation (`% pagesPerArena`) isolates the page within the arena.

7. **Command-Line Arguments:**  A quick scan reveals no explicit handling of command-line arguments *within this specific snippet*. However, understanding that this is part of the Go *runtime*, one can infer that some of the constants or behaviors *might* be influenced by environment variables or build-time flags, but the code itself doesn't directly process `os.Args`.

8. **Common Mistakes:** Look for potential pitfalls:
    * **Concurrency:** The use of `atomic` operations and `mutex` highlights the importance of thread safety. Forgetting to acquire locks or using non-atomic operations on shared data would be errors.
    * **Pointer Handling:** The code deals directly with memory addresses and `unsafe.Pointer`. Incorrect pointer arithmetic or dereferencing invalid pointers could lead to crashes.
    * **Assumptions about Memory Layout:**  The code makes assumptions about page sizes and arena organization. These assumptions are generally valid for the Go runtime's managed memory but could be problematic if interacting with external memory.

9. **Structure the Answer:** Organize the findings logically:
    * Start with a general summary of the file's purpose.
    * List the specific functionalities.
    * Provide a code reasoning example.
    * Discuss command-line arguments (or the lack thereof).
    * Point out potential user mistakes.
    * Conclude with a concise summary of the first part.

10. **Refine and Elaborate:** Review the generated answer for clarity, accuracy, and completeness. Add details where necessary to explain complex concepts. For instance, elaborate on the purpose of the arena map or the different states of an `mspan`. Ensure the language is clear and precise.
这是 `go/src/runtime/mheap.go` 文件的第一部分代码，它定义了 Go 运行时堆的核心数据结构 `mheap` 以及一些辅助结构和常量。从代码内容来看，其主要功能围绕着**管理 Go 程序的堆内存**。

以下是更具体的功能点：

1. **定义了堆的基本属性和配置：**
   - 定义了最小和最大物理页大小 (`minPhysPageSize`, `maxPhysPageSize`)，以及最大巨页大小 (`maxPhysHugePageSize`)。
   - 定义了页回收器一次扫描的页数 (`pagesPerReclaimerChunk`)。
   - 定义了 OpenBSD 系统中栈分配是否需要物理页对齐 (`physPageAlignedStacks`)。

2. **定义了主堆结构 `mheap`：**
   - `lock mutex`: 用于保护堆数据结构的互斥锁，确保并发安全。
   - `pages pageAlloc`: 用于管理页的分配和释放。
   - `sweepgen uint32`:  用于跟踪垃圾回收的 sweep 阶段。
   - `allspans []*mspan`:  存储所有已创建的 `mspan` 的切片。
   - **比例扫描 (Proportional Sweep) 相关字段:**  用于实现基于堆活跃度的动态扫描策略，控制垃圾回收的速度 (`pagesInUse`, `pagesSwept`, `pagesSweptBasis`, `sweepHeapLiveBasis`, `sweepPagesPerByte`)。
   - **页回收器 (Page Reclaimer) 相关字段:**  用于后台回收空闲页面的机制 (`reclaimIndex`, `reclaimCredit`)。
   - `arenas [1 << arenaL1Bits]*[1 << arenaL2Bits]*heapArena`:  堆的 arena 映射，用于快速查找给定地址的元数据。这是一个两级映射结构，可以有效地管理巨大的地址空间。
   - `heapArenaAlloc linearAlloc`, `arena linearAlloc`:  用于分配 `heapArena` 结构本身的内存。在 32 位系统上，这些是预留空间，避免与堆本身交错。
   - `arenaHints *arenaHint`:  用于提示堆 arena 扩展的地址。
   - `allArenas []arenaIdx`:  存储所有已映射 arena 的索引。
   - `sweepArenas []arenaIdx`, `markArenas []arenaIdx`:  在 sweep 和 mark 阶段开始时 `allArenas` 的快照。
   - `curArena struct { base, end uintptr }`:  当前堆正在增长到的 arena。
   - `central [numSpanClasses]struct { mcentral mcentral; pad ... }`:  用于小对象大小类的中心化空闲列表。使用 padding 来避免缓存行伪共享。
   - 一系列 `fixalloc`:  用于分配特定类型的运行时元数据的分配器，例如 `mspan`、`mcache` 等。
   - `speciallock mutex`:  用于保护特殊记录分配器的锁。
   - `userArena struct {...}`:  用于管理用户自定义的 arena。
   - `cleanupID uint64`:  用于生成唯一 cleanup 特殊记录的 ID。

3. **定义了 `heapArena` 结构：**
   - `spans [pagesPerArena]*mspan`:  映射 arena 内的虚拟地址页到 `mspan` 的指针。
   - `pageInUse [pagesPerArena / 8]uint8`:  位图，指示哪些 span 处于 `mSpanInUse` 状态。
   - `pageMarks [pagesPerArena / 8]uint8`:  位图，指示哪些 span 上有被标记的对象。
   - `pageSpecials [pagesPerArena / 8]uint8`:  位图，指示哪些 span 有特殊的记录（例如 finalizer）。
   - `checkmarks *checkmarksMap`:  用于调试的标记状态。
   - `zeroedBase uintptr`:  指示 arena 中尚未使用的、已置零的起始地址。

4. **定义了 `arenaHint` 结构：** 用于提示堆 arena 扩展的位置。

5. **定义了 `mspan` 结构：** 代表一段连续的页，是堆内存管理的基本单元。
   - `next *mspan`, `prev *mspan`, `list *mSpanList`:  用于将 `mspan` 链接成列表。
   - `startAddr uintptr`, `npages uintptr`:  `mspan` 的起始地址和页数。
   - `manualFreeList gclinkptr`:  用于 `mSpanManual` span 中空闲对象的链表。
   - `freeindex uint16`, `nelems uint16`, `freeIndexForScan uint16`:  用于管理 `mspan` 中空闲对象的索引和数量。
   - `allocCache uint64`:  `allocBits` 的缓存，用于加速空闲对象的查找。
   - `allocBits *gcBits`, `gcmarkBits *gcBits`, `pinnerBits *gcBits`:  指向分配位图、垃圾回收标记位图和 pinned 对象位图的指针。
   - `sweepgen uint32`:  用于跟踪 `mspan` 的 sweep 状态。
   - `divMul uint32`:  用于除以对象大小的乘数。
   - `allocCount uint16`:  已分配的对象数量。
   - `spanclass spanClass`:  大小类和 noscan 属性。
   - `state mSpanStateBox`:  `mspan` 的状态（例如 `mSpanInUse`，`mSpanManual`）。
   - `needzero uint8`:  指示在分配前是否需要清零。
   - `isUserArenaChunk bool`:  指示是否是用户 arena 的 chunk。
   - `elemsize uintptr`:  对象的大小。
   - `limit uintptr`:  `mspan` 中数据的末尾地址。
   - `speciallock mutex`:  用于保护 specials 列表和 `pinnerBits` 的锁。
   - `specials *special`:  特殊记录的链表。
   - `userArenaChunkFree addrRange`:  用于管理用户 arena chunk 的分配区间。
   - `largeType *_type`:  用于大对象的 malloc 头部信息。

6. **定义了 `mSpanList` 结构：**  `mspan` 的链表。

7. **定义了 `mSpanState` 和相关的常量和方法：** 表示 `mspan` 的状态（例如 `mSpanDead`, `mSpanInUse`, `mSpanManual`），并提供原子操作的方法。

8. **定义了 `spanClass` 和相关的常量和方法：** 表示 span 的大小类和是否包含指针。

9. **定义了一些辅助函数：**
   - `recordspan`:  用于将新分配的 `mspan` 添加到 `h.allspans` 中。
   - `arenaIndex`:  根据地址计算其所属 arena 的索引。
   - `arenaBase`:  根据 arena 索引计算 arena 的起始地址。
   - `inheap`, `inHeapOrStack`:  判断指针是否指向堆内存或栈内存。
   - `spanOf`, `spanOfUnchecked`, `spanOfHeap`:  根据地址查找对应的 `mspan`。
   - `pageIndexOf`:  根据地址返回 arena、页索引和页掩码。
   - `(h *mheap).init()`:  初始化 `mheap` 结构。
   - `(h *mheap).reclaim()`:  执行页回收操作。
   - `(h *mheap).reclaimChunk()`:  回收指定范围内的未标记 span。

**可以推理出它是 Go 语言堆内存分配和垃圾回收功能的实现的核心部分。**

**Go 代码举例说明 (假设)：**

虽然这部分代码本身不直接包含用户级别的分配代码，但它是 `new` 和 `make` 等操作的底层实现。

```go
package main

import "fmt"

func main() {
	// 使用 make 创建一个切片，这会在堆上分配内存
	s := make([]int, 10)
	fmt.Println(s)

	// 使用 new 创建一个指向 int 的指针，也会在堆上分配内存
	i := new(int)
	*i = 42
	fmt.Println(*i)
}
```

**代码推理 (假设输入与输出)：**

假设我们有一个地址 `p`，我们想知道它属于哪个 `mspan`。

**假设输入:** `p` 是一个有效的堆地址，例如 `0xc000010000`。

**处理过程 (基于 `spanOf` 函数):**

1. 计算 `arenaIndex(p)`:  假设 `arenaBaseOffset` 为 `0xc000000000`，`heapArenaBytes` 为 `67108864` (64MB)。
   `arenaIndex = (0xc000010000 - 0xc000000000) / 67108864 = 65536 / 67108864 = 0`
   假设 `arenaL1Bits` 为 0，则 `l1() = 0`, `l2() = 0`。

2. 获取 `heapArena`: `ha = mheap_.arenas[0][0]`

3. 计算页索引: `pageIndex = (p / pageSize) % pagesPerArena`。假设 `pageSize` 为 `8192`，`pagesPerArena` 为 `8192`。
   `pageIndex = (0xc000010000 / 8192) % 8192 = 16 % 8192 = 16`

4. 获取 `mspan`: `s = ha.spans[16]`

**假设输出:**  如果地址 `0xc000010000` 确实属于一个已分配的 `mspan`，那么 `spanOf(0xc000010000)` 将返回指向该 `mspan` 结构的指针。如果该地址未被分配或不属于堆，则返回 `nil`。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。与内存管理相关的命令行参数（例如，与垃圾回收相关的 GOGC 环境变量）是在 Go 运行时的其他部分处理的，而不是在 `mheap.go` 中。

**使用者易犯错的点：**

这段代码是 Go 运行时的一部分，普通 Go 开发者不会直接操作它。但是，理解其背后的概念有助于避免一些与内存相关的错误：

- **理解堆内存的分配方式:**  知道像 `make` 和 `new` 这样的操作会在堆上分配内存，有助于理解内存的生命周期和垃圾回收的重要性。
- **避免内存泄漏:**  理解垃圾回收机制有助于编写不会泄漏内存的代码。虽然 Go 会自动回收不再使用的内存，但在某些情况下（例如，持有指向不再需要的对象的引用），仍然可能发生逻辑上的内存泄漏。

**功能归纳 (第 1 部分):**

`go/src/runtime/mheap.go` 的第一部分主要定义了 Go 语言运行时堆的核心数据结构 (`mheap`, `heapArena`, `mspan`) 和相关的常量，以及一些用于查找和管理内存页面的基本函数。它为堆内存的分配、垃圾回收的跟踪和管理奠定了基础。这部分代码的核心职责是**组织和管理堆内存的元数据**，以便运行时可以有效地分配和回收内存。

Prompt: 
```
这是路径为go/src/runtime/mheap.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Page heap.
//
// See malloc.go for overview.

package runtime

import (
	"internal/cpu"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

const (
	// minPhysPageSize is a lower-bound on the physical page size. The
	// true physical page size may be larger than this. In contrast,
	// sys.PhysPageSize is an upper-bound on the physical page size.
	minPhysPageSize = 4096

	// maxPhysPageSize is the maximum page size the runtime supports.
	maxPhysPageSize = 512 << 10

	// maxPhysHugePageSize sets an upper-bound on the maximum huge page size
	// that the runtime supports.
	maxPhysHugePageSize = pallocChunkBytes

	// pagesPerReclaimerChunk indicates how many pages to scan from the
	// pageInUse bitmap at a time. Used by the page reclaimer.
	//
	// Higher values reduce contention on scanning indexes (such as
	// h.reclaimIndex), but increase the minimum latency of the
	// operation.
	//
	// The time required to scan this many pages can vary a lot depending
	// on how many spans are actually freed. Experimentally, it can
	// scan for pages at ~300 GB/ms on a 2.6GHz Core i7, but can only
	// free spans at ~32 MB/ms. Using 512 pages bounds this at
	// roughly 100µs.
	//
	// Must be a multiple of the pageInUse bitmap element size and
	// must also evenly divide pagesPerArena.
	pagesPerReclaimerChunk = 512

	// physPageAlignedStacks indicates whether stack allocations must be
	// physical page aligned. This is a requirement for MAP_STACK on
	// OpenBSD.
	physPageAlignedStacks = GOOS == "openbsd"
)

// Main malloc heap.
// The heap itself is the "free" and "scav" treaps,
// but all the other global data is here too.
//
// mheap must not be heap-allocated because it contains mSpanLists,
// which must not be heap-allocated.
type mheap struct {
	_ sys.NotInHeap

	// lock must only be acquired on the system stack, otherwise a g
	// could self-deadlock if its stack grows with the lock held.
	lock mutex

	pages pageAlloc // page allocation data structure

	sweepgen uint32 // sweep generation, see comment in mspan; written during STW

	// allspans is a slice of all mspans ever created. Each mspan
	// appears exactly once.
	//
	// The memory for allspans is manually managed and can be
	// reallocated and move as the heap grows.
	//
	// In general, allspans is protected by mheap_.lock, which
	// prevents concurrent access as well as freeing the backing
	// store. Accesses during STW might not hold the lock, but
	// must ensure that allocation cannot happen around the
	// access (since that may free the backing store).
	allspans []*mspan // all spans out there

	// Proportional sweep
	//
	// These parameters represent a linear function from gcController.heapLive
	// to page sweep count. The proportional sweep system works to
	// stay in the black by keeping the current page sweep count
	// above this line at the current gcController.heapLive.
	//
	// The line has slope sweepPagesPerByte and passes through a
	// basis point at (sweepHeapLiveBasis, pagesSweptBasis). At
	// any given time, the system is at (gcController.heapLive,
	// pagesSwept) in this space.
	//
	// It is important that the line pass through a point we
	// control rather than simply starting at a 0,0 origin
	// because that lets us adjust sweep pacing at any time while
	// accounting for current progress. If we could only adjust
	// the slope, it would create a discontinuity in debt if any
	// progress has already been made.
	pagesInUse         atomic.Uintptr // pages of spans in stats mSpanInUse
	pagesSwept         atomic.Uint64  // pages swept this cycle
	pagesSweptBasis    atomic.Uint64  // pagesSwept to use as the origin of the sweep ratio
	sweepHeapLiveBasis uint64         // value of gcController.heapLive to use as the origin of sweep ratio; written with lock, read without
	sweepPagesPerByte  float64        // proportional sweep ratio; written with lock, read without

	// Page reclaimer state

	// reclaimIndex is the page index in allArenas of next page to
	// reclaim. Specifically, it refers to page (i %
	// pagesPerArena) of arena allArenas[i / pagesPerArena].
	//
	// If this is >= 1<<63, the page reclaimer is done scanning
	// the page marks.
	reclaimIndex atomic.Uint64

	// reclaimCredit is spare credit for extra pages swept. Since
	// the page reclaimer works in large chunks, it may reclaim
	// more than requested. Any spare pages released go to this
	// credit pool.
	reclaimCredit atomic.Uintptr

	_ cpu.CacheLinePad // prevents false-sharing between arenas and preceding variables

	// arenas is the heap arena map. It points to the metadata for
	// the heap for every arena frame of the entire usable virtual
	// address space.
	//
	// Use arenaIndex to compute indexes into this array.
	//
	// For regions of the address space that are not backed by the
	// Go heap, the arena map contains nil.
	//
	// Modifications are protected by mheap_.lock. Reads can be
	// performed without locking; however, a given entry can
	// transition from nil to non-nil at any time when the lock
	// isn't held. (Entries never transitions back to nil.)
	//
	// In general, this is a two-level mapping consisting of an L1
	// map and possibly many L2 maps. This saves space when there
	// are a huge number of arena frames. However, on many
	// platforms (even 64-bit), arenaL1Bits is 0, making this
	// effectively a single-level map. In this case, arenas[0]
	// will never be nil.
	arenas [1 << arenaL1Bits]*[1 << arenaL2Bits]*heapArena

	// arenasHugePages indicates whether arenas' L2 entries are eligible
	// to be backed by huge pages.
	arenasHugePages bool

	// heapArenaAlloc is pre-reserved space for allocating heapArena
	// objects. This is only used on 32-bit, where we pre-reserve
	// this space to avoid interleaving it with the heap itself.
	heapArenaAlloc linearAlloc

	// arenaHints is a list of addresses at which to attempt to
	// add more heap arenas. This is initially populated with a
	// set of general hint addresses, and grown with the bounds of
	// actual heap arena ranges.
	arenaHints *arenaHint

	// arena is a pre-reserved space for allocating heap arenas
	// (the actual arenas). This is only used on 32-bit.
	arena linearAlloc

	// allArenas is the arenaIndex of every mapped arena. This can
	// be used to iterate through the address space.
	//
	// Access is protected by mheap_.lock. However, since this is
	// append-only and old backing arrays are never freed, it is
	// safe to acquire mheap_.lock, copy the slice header, and
	// then release mheap_.lock.
	allArenas []arenaIdx

	// sweepArenas is a snapshot of allArenas taken at the
	// beginning of the sweep cycle. This can be read safely by
	// simply blocking GC (by disabling preemption).
	sweepArenas []arenaIdx

	// markArenas is a snapshot of allArenas taken at the beginning
	// of the mark cycle. Because allArenas is append-only, neither
	// this slice nor its contents will change during the mark, so
	// it can be read safely.
	markArenas []arenaIdx

	// curArena is the arena that the heap is currently growing
	// into. This should always be physPageSize-aligned.
	curArena struct {
		base, end uintptr
	}

	// central free lists for small size classes.
	// the padding makes sure that the mcentrals are
	// spaced CacheLinePadSize bytes apart, so that each mcentral.lock
	// gets its own cache line.
	// central is indexed by spanClass.
	central [numSpanClasses]struct {
		mcentral mcentral
		pad      [(cpu.CacheLinePadSize - unsafe.Sizeof(mcentral{})%cpu.CacheLinePadSize) % cpu.CacheLinePadSize]byte
	}

	spanalloc              fixalloc // allocator for span*
	cachealloc             fixalloc // allocator for mcache*
	specialfinalizeralloc  fixalloc // allocator for specialfinalizer*
	specialCleanupAlloc    fixalloc // allocator for specialcleanup*
	specialprofilealloc    fixalloc // allocator for specialprofile*
	specialReachableAlloc  fixalloc // allocator for specialReachable
	specialPinCounterAlloc fixalloc // allocator for specialPinCounter
	specialWeakHandleAlloc fixalloc // allocator for specialWeakHandle
	speciallock            mutex    // lock for special record allocators.
	arenaHintAlloc         fixalloc // allocator for arenaHints

	// User arena state.
	//
	// Protected by mheap_.lock.
	userArena struct {
		// arenaHints is a list of addresses at which to attempt to
		// add more heap arenas for user arena chunks. This is initially
		// populated with a set of general hint addresses, and grown with
		// the bounds of actual heap arena ranges.
		arenaHints *arenaHint

		// quarantineList is a list of user arena spans that have been set to fault, but
		// are waiting for all pointers into them to go away. Sweeping handles
		// identifying when this is true, and moves the span to the ready list.
		quarantineList mSpanList

		// readyList is a list of empty user arena spans that are ready for reuse.
		readyList mSpanList
	}

	// cleanupID is a counter which is incremented each time a cleanup special is added
	// to a span. It's used to create globally unique identifiers for individual cleanup.
	// cleanupID is protected by mheap_.lock. It should only be incremented while holding
	// the lock.
	cleanupID uint64

	unused *specialfinalizer // never set, just here to force the specialfinalizer type into DWARF
}

var mheap_ mheap

// A heapArena stores metadata for a heap arena. heapArenas are stored
// outside of the Go heap and accessed via the mheap_.arenas index.
type heapArena struct {
	_ sys.NotInHeap

	// spans maps from virtual address page ID within this arena to *mspan.
	// For allocated spans, their pages map to the span itself.
	// For free spans, only the lowest and highest pages map to the span itself.
	// Internal pages map to an arbitrary span.
	// For pages that have never been allocated, spans entries are nil.
	//
	// Modifications are protected by mheap.lock. Reads can be
	// performed without locking, but ONLY from indexes that are
	// known to contain in-use or stack spans. This means there
	// must not be a safe-point between establishing that an
	// address is live and looking it up in the spans array.
	spans [pagesPerArena]*mspan

	// pageInUse is a bitmap that indicates which spans are in
	// state mSpanInUse. This bitmap is indexed by page number,
	// but only the bit corresponding to the first page in each
	// span is used.
	//
	// Reads and writes are atomic.
	pageInUse [pagesPerArena / 8]uint8

	// pageMarks is a bitmap that indicates which spans have any
	// marked objects on them. Like pageInUse, only the bit
	// corresponding to the first page in each span is used.
	//
	// Writes are done atomically during marking. Reads are
	// non-atomic and lock-free since they only occur during
	// sweeping (and hence never race with writes).
	//
	// This is used to quickly find whole spans that can be freed.
	//
	// TODO(austin): It would be nice if this was uint64 for
	// faster scanning, but we don't have 64-bit atomic bit
	// operations.
	pageMarks [pagesPerArena / 8]uint8

	// pageSpecials is a bitmap that indicates which spans have
	// specials (finalizers or other). Like pageInUse, only the bit
	// corresponding to the first page in each span is used.
	//
	// Writes are done atomically whenever a special is added to
	// a span and whenever the last special is removed from a span.
	// Reads are done atomically to find spans containing specials
	// during marking.
	pageSpecials [pagesPerArena / 8]uint8

	// checkmarks stores the debug.gccheckmark state. It is only
	// used if debug.gccheckmark > 0.
	checkmarks *checkmarksMap

	// zeroedBase marks the first byte of the first page in this
	// arena which hasn't been used yet and is therefore already
	// zero. zeroedBase is relative to the arena base.
	// Increases monotonically until it hits heapArenaBytes.
	//
	// This field is sufficient to determine if an allocation
	// needs to be zeroed because the page allocator follows an
	// address-ordered first-fit policy.
	//
	// Read atomically and written with an atomic CAS.
	zeroedBase uintptr
}

// arenaHint is a hint for where to grow the heap arenas. See
// mheap_.arenaHints.
type arenaHint struct {
	_    sys.NotInHeap
	addr uintptr
	down bool
	next *arenaHint
}

// An mspan is a run of pages.
//
// When a mspan is in the heap free treap, state == mSpanFree
// and heapmap(s->start) == span, heapmap(s->start+s->npages-1) == span.
// If the mspan is in the heap scav treap, then in addition to the
// above scavenged == true. scavenged == false in all other cases.
//
// When a mspan is allocated, state == mSpanInUse or mSpanManual
// and heapmap(i) == span for all s->start <= i < s->start+s->npages.

// Every mspan is in one doubly-linked list, either in the mheap's
// busy list or one of the mcentral's span lists.

// An mspan representing actual memory has state mSpanInUse,
// mSpanManual, or mSpanFree. Transitions between these states are
// constrained as follows:
//
//   - A span may transition from free to in-use or manual during any GC
//     phase.
//
//   - During sweeping (gcphase == _GCoff), a span may transition from
//     in-use to free (as a result of sweeping) or manual to free (as a
//     result of stacks being freed).
//
//   - During GC (gcphase != _GCoff), a span *must not* transition from
//     manual or in-use to free. Because concurrent GC may read a pointer
//     and then look up its span, the span state must be monotonic.
//
// Setting mspan.state to mSpanInUse or mSpanManual must be done
// atomically and only after all other span fields are valid.
// Likewise, if inspecting a span is contingent on it being
// mSpanInUse, the state should be loaded atomically and checked
// before depending on other fields. This allows the garbage collector
// to safely deal with potentially invalid pointers, since resolving
// such pointers may race with a span being allocated.
type mSpanState uint8

const (
	mSpanDead   mSpanState = iota
	mSpanInUse             // allocated for garbage collected heap
	mSpanManual            // allocated for manual management (e.g., stack allocator)
)

// mSpanStateNames are the names of the span states, indexed by
// mSpanState.
var mSpanStateNames = []string{
	"mSpanDead",
	"mSpanInUse",
	"mSpanManual",
}

// mSpanStateBox holds an atomic.Uint8 to provide atomic operations on
// an mSpanState. This is a separate type to disallow accidental comparison
// or assignment with mSpanState.
type mSpanStateBox struct {
	s atomic.Uint8
}

// It is nosplit to match get, below.

//go:nosplit
func (b *mSpanStateBox) set(s mSpanState) {
	b.s.Store(uint8(s))
}

// It is nosplit because it's called indirectly by typedmemclr,
// which must not be preempted.

//go:nosplit
func (b *mSpanStateBox) get() mSpanState {
	return mSpanState(b.s.Load())
}

// mSpanList heads a linked list of spans.
type mSpanList struct {
	_     sys.NotInHeap
	first *mspan // first span in list, or nil if none
	last  *mspan // last span in list, or nil if none
}

type mspan struct {
	_    sys.NotInHeap
	next *mspan     // next span in list, or nil if none
	prev *mspan     // previous span in list, or nil if none
	list *mSpanList // For debugging.

	startAddr uintptr // address of first byte of span aka s.base()
	npages    uintptr // number of pages in span

	manualFreeList gclinkptr // list of free objects in mSpanManual spans

	// freeindex is the slot index between 0 and nelems at which to begin scanning
	// for the next free object in this span.
	// Each allocation scans allocBits starting at freeindex until it encounters a 0
	// indicating a free object. freeindex is then adjusted so that subsequent scans begin
	// just past the newly discovered free object.
	//
	// If freeindex == nelem, this span has no free objects.
	//
	// allocBits is a bitmap of objects in this span.
	// If n >= freeindex and allocBits[n/8] & (1<<(n%8)) is 0
	// then object n is free;
	// otherwise, object n is allocated. Bits starting at nelem are
	// undefined and should never be referenced.
	//
	// Object n starts at address n*elemsize + (start << pageShift).
	freeindex uint16
	// TODO: Look up nelems from sizeclass and remove this field if it
	// helps performance.
	nelems uint16 // number of object in the span.
	// freeIndexForScan is like freeindex, except that freeindex is
	// used by the allocator whereas freeIndexForScan is used by the
	// GC scanner. They are two fields so that the GC sees the object
	// is allocated only when the object and the heap bits are
	// initialized (see also the assignment of freeIndexForScan in
	// mallocgc, and issue 54596).
	freeIndexForScan uint16

	// Cache of the allocBits at freeindex. allocCache is shifted
	// such that the lowest bit corresponds to the bit freeindex.
	// allocCache holds the complement of allocBits, thus allowing
	// ctz (count trailing zero) to use it directly.
	// allocCache may contain bits beyond s.nelems; the caller must ignore
	// these.
	allocCache uint64

	// allocBits and gcmarkBits hold pointers to a span's mark and
	// allocation bits. The pointers are 8 byte aligned.
	// There are three arenas where this data is held.
	// free: Dirty arenas that are no longer accessed
	//       and can be reused.
	// next: Holds information to be used in the next GC cycle.
	// current: Information being used during this GC cycle.
	// previous: Information being used during the last GC cycle.
	// A new GC cycle starts with the call to finishsweep_m.
	// finishsweep_m moves the previous arena to the free arena,
	// the current arena to the previous arena, and
	// the next arena to the current arena.
	// The next arena is populated as the spans request
	// memory to hold gcmarkBits for the next GC cycle as well
	// as allocBits for newly allocated spans.
	//
	// The pointer arithmetic is done "by hand" instead of using
	// arrays to avoid bounds checks along critical performance
	// paths.
	// The sweep will free the old allocBits and set allocBits to the
	// gcmarkBits. The gcmarkBits are replaced with a fresh zeroed
	// out memory.
	allocBits  *gcBits
	gcmarkBits *gcBits
	pinnerBits *gcBits // bitmap for pinned objects; accessed atomically

	// sweep generation:
	// if sweepgen == h->sweepgen - 2, the span needs sweeping
	// if sweepgen == h->sweepgen - 1, the span is currently being swept
	// if sweepgen == h->sweepgen, the span is swept and ready to use
	// if sweepgen == h->sweepgen + 1, the span was cached before sweep began and is still cached, and needs sweeping
	// if sweepgen == h->sweepgen + 3, the span was swept and then cached and is still cached
	// h->sweepgen is incremented by 2 after every GC

	sweepgen              uint32
	divMul                uint32        // for divide by elemsize
	allocCount            uint16        // number of allocated objects
	spanclass             spanClass     // size class and noscan (uint8)
	state                 mSpanStateBox // mSpanInUse etc; accessed atomically (get/set methods)
	needzero              uint8         // needs to be zeroed before allocation
	isUserArenaChunk      bool          // whether or not this span represents a user arena
	allocCountBeforeCache uint16        // a copy of allocCount that is stored just before this span is cached
	elemsize              uintptr       // computed from sizeclass or from npages
	limit                 uintptr       // end of data in span
	speciallock           mutex         // guards specials list and changes to pinnerBits
	specials              *special      // linked list of special records sorted by offset.
	userArenaChunkFree    addrRange     // interval for managing chunk allocation
	largeType             *_type        // malloc header for large objects.
}

func (s *mspan) base() uintptr {
	return s.startAddr
}

func (s *mspan) layout() (size, n, total uintptr) {
	total = s.npages << _PageShift
	size = s.elemsize
	if size > 0 {
		n = total / size
	}
	return
}

// recordspan adds a newly allocated span to h.allspans.
//
// This only happens the first time a span is allocated from
// mheap.spanalloc (it is not called when a span is reused).
//
// Write barriers are disallowed here because it can be called from
// gcWork when allocating new workbufs. However, because it's an
// indirect call from the fixalloc initializer, the compiler can't see
// this.
//
// The heap lock must be held.
//
//go:nowritebarrierrec
func recordspan(vh unsafe.Pointer, p unsafe.Pointer) {
	h := (*mheap)(vh)
	s := (*mspan)(p)

	assertLockHeld(&h.lock)

	if len(h.allspans) >= cap(h.allspans) {
		n := 64 * 1024 / goarch.PtrSize
		if n < cap(h.allspans)*3/2 {
			n = cap(h.allspans) * 3 / 2
		}
		var new []*mspan
		sp := (*slice)(unsafe.Pointer(&new))
		sp.array = sysAlloc(uintptr(n)*goarch.PtrSize, &memstats.other_sys)
		if sp.array == nil {
			throw("runtime: cannot allocate memory")
		}
		sp.len = len(h.allspans)
		sp.cap = n
		if len(h.allspans) > 0 {
			copy(new, h.allspans)
		}
		oldAllspans := h.allspans
		*(*notInHeapSlice)(unsafe.Pointer(&h.allspans)) = *(*notInHeapSlice)(unsafe.Pointer(&new))
		if len(oldAllspans) != 0 {
			sysFree(unsafe.Pointer(&oldAllspans[0]), uintptr(cap(oldAllspans))*unsafe.Sizeof(oldAllspans[0]), &memstats.other_sys)
		}
	}
	h.allspans = h.allspans[:len(h.allspans)+1]
	h.allspans[len(h.allspans)-1] = s
}

// A spanClass represents the size class and noscan-ness of a span.
//
// Each size class has a noscan spanClass and a scan spanClass. The
// noscan spanClass contains only noscan objects, which do not contain
// pointers and thus do not need to be scanned by the garbage
// collector.
type spanClass uint8

const (
	numSpanClasses = _NumSizeClasses << 1
	tinySpanClass  = spanClass(tinySizeClass<<1 | 1)
)

func makeSpanClass(sizeclass uint8, noscan bool) spanClass {
	return spanClass(sizeclass<<1) | spanClass(bool2int(noscan))
}

//go:nosplit
func (sc spanClass) sizeclass() int8 {
	return int8(sc >> 1)
}

//go:nosplit
func (sc spanClass) noscan() bool {
	return sc&1 != 0
}

// arenaIndex returns the index into mheap_.arenas of the arena
// containing metadata for p. This index combines of an index into the
// L1 map and an index into the L2 map and should be used as
// mheap_.arenas[ai.l1()][ai.l2()].
//
// If p is outside the range of valid heap addresses, either l1() or
// l2() will be out of bounds.
//
// It is nosplit because it's called by spanOf and several other
// nosplit functions.
//
//go:nosplit
func arenaIndex(p uintptr) arenaIdx {
	return arenaIdx((p - arenaBaseOffset) / heapArenaBytes)
}

// arenaBase returns the low address of the region covered by heap
// arena i.
func arenaBase(i arenaIdx) uintptr {
	return uintptr(i)*heapArenaBytes + arenaBaseOffset
}

type arenaIdx uint

// l1 returns the "l1" portion of an arenaIdx.
//
// Marked nosplit because it's called by spanOf and other nosplit
// functions.
//
//go:nosplit
func (i arenaIdx) l1() uint {
	if arenaL1Bits == 0 {
		// Let the compiler optimize this away if there's no
		// L1 map.
		return 0
	} else {
		return uint(i) >> arenaL1Shift
	}
}

// l2 returns the "l2" portion of an arenaIdx.
//
// Marked nosplit because it's called by spanOf and other nosplit funcs.
// functions.
//
//go:nosplit
func (i arenaIdx) l2() uint {
	if arenaL1Bits == 0 {
		return uint(i)
	} else {
		return uint(i) & (1<<arenaL2Bits - 1)
	}
}

// inheap reports whether b is a pointer into a (potentially dead) heap object.
// It returns false for pointers into mSpanManual spans.
// Non-preemptible because it is used by write barriers.
//
//go:nowritebarrier
//go:nosplit
func inheap(b uintptr) bool {
	return spanOfHeap(b) != nil
}

// inHeapOrStack is a variant of inheap that returns true for pointers
// into any allocated heap span.
//
//go:nowritebarrier
//go:nosplit
func inHeapOrStack(b uintptr) bool {
	s := spanOf(b)
	if s == nil || b < s.base() {
		return false
	}
	switch s.state.get() {
	case mSpanInUse, mSpanManual:
		return b < s.limit
	default:
		return false
	}
}

// spanOf returns the span of p. If p does not point into the heap
// arena or no span has ever contained p, spanOf returns nil.
//
// If p does not point to allocated memory, this may return a non-nil
// span that does *not* contain p. If this is a possibility, the
// caller should either call spanOfHeap or check the span bounds
// explicitly.
//
// Must be nosplit because it has callers that are nosplit.
//
//go:nosplit
func spanOf(p uintptr) *mspan {
	// This function looks big, but we use a lot of constant
	// folding around arenaL1Bits to get it under the inlining
	// budget. Also, many of the checks here are safety checks
	// that Go needs to do anyway, so the generated code is quite
	// short.
	ri := arenaIndex(p)
	if arenaL1Bits == 0 {
		// If there's no L1, then ri.l1() can't be out of bounds but ri.l2() can.
		if ri.l2() >= uint(len(mheap_.arenas[0])) {
			return nil
		}
	} else {
		// If there's an L1, then ri.l1() can be out of bounds but ri.l2() can't.
		if ri.l1() >= uint(len(mheap_.arenas)) {
			return nil
		}
	}
	l2 := mheap_.arenas[ri.l1()]
	if arenaL1Bits != 0 && l2 == nil { // Should never happen if there's no L1.
		return nil
	}
	ha := l2[ri.l2()]
	if ha == nil {
		return nil
	}
	return ha.spans[(p/pageSize)%pagesPerArena]
}

// spanOfUnchecked is equivalent to spanOf, but the caller must ensure
// that p points into an allocated heap arena.
//
// Must be nosplit because it has callers that are nosplit.
//
//go:nosplit
func spanOfUnchecked(p uintptr) *mspan {
	ai := arenaIndex(p)
	return mheap_.arenas[ai.l1()][ai.l2()].spans[(p/pageSize)%pagesPerArena]
}

// spanOfHeap is like spanOf, but returns nil if p does not point to a
// heap object.
//
// Must be nosplit because it has callers that are nosplit.
//
//go:nosplit
func spanOfHeap(p uintptr) *mspan {
	s := spanOf(p)
	// s is nil if it's never been allocated. Otherwise, we check
	// its state first because we don't trust this pointer, so we
	// have to synchronize with span initialization. Then, it's
	// still possible we picked up a stale span pointer, so we
	// have to check the span's bounds.
	if s == nil || s.state.get() != mSpanInUse || p < s.base() || p >= s.limit {
		return nil
	}
	return s
}

// pageIndexOf returns the arena, page index, and page mask for pointer p.
// The caller must ensure p is in the heap.
func pageIndexOf(p uintptr) (arena *heapArena, pageIdx uintptr, pageMask uint8) {
	ai := arenaIndex(p)
	arena = mheap_.arenas[ai.l1()][ai.l2()]
	pageIdx = ((p / pageSize) / 8) % uintptr(len(arena.pageInUse))
	pageMask = byte(1 << ((p / pageSize) % 8))
	return
}

// Initialize the heap.
func (h *mheap) init() {
	lockInit(&h.lock, lockRankMheap)
	lockInit(&h.speciallock, lockRankMheapSpecial)

	h.spanalloc.init(unsafe.Sizeof(mspan{}), recordspan, unsafe.Pointer(h), &memstats.mspan_sys)
	h.cachealloc.init(unsafe.Sizeof(mcache{}), nil, nil, &memstats.mcache_sys)
	h.specialfinalizeralloc.init(unsafe.Sizeof(specialfinalizer{}), nil, nil, &memstats.other_sys)
	h.specialCleanupAlloc.init(unsafe.Sizeof(specialCleanup{}), nil, nil, &memstats.other_sys)
	h.specialprofilealloc.init(unsafe.Sizeof(specialprofile{}), nil, nil, &memstats.other_sys)
	h.specialReachableAlloc.init(unsafe.Sizeof(specialReachable{}), nil, nil, &memstats.other_sys)
	h.specialPinCounterAlloc.init(unsafe.Sizeof(specialPinCounter{}), nil, nil, &memstats.other_sys)
	h.specialWeakHandleAlloc.init(unsafe.Sizeof(specialWeakHandle{}), nil, nil, &memstats.gcMiscSys)
	h.arenaHintAlloc.init(unsafe.Sizeof(arenaHint{}), nil, nil, &memstats.other_sys)

	// Don't zero mspan allocations. Background sweeping can
	// inspect a span concurrently with allocating it, so it's
	// important that the span's sweepgen survive across freeing
	// and re-allocating a span to prevent background sweeping
	// from improperly cas'ing it from 0.
	//
	// This is safe because mspan contains no heap pointers.
	h.spanalloc.zero = false

	// h->mapcache needs no init

	for i := range h.central {
		h.central[i].mcentral.init(spanClass(i))
	}

	h.pages.init(&h.lock, &memstats.gcMiscSys, false)
}

// reclaim sweeps and reclaims at least npage pages into the heap.
// It is called before allocating npage pages to keep growth in check.
//
// reclaim implements the page-reclaimer half of the sweeper.
//
// h.lock must NOT be held.
func (h *mheap) reclaim(npage uintptr) {
	// TODO(austin): Half of the time spent freeing spans is in
	// locking/unlocking the heap (even with low contention). We
	// could make the slow path here several times faster by
	// batching heap frees.

	// Bail early if there's no more reclaim work.
	if h.reclaimIndex.Load() >= 1<<63 {
		return
	}

	// Disable preemption so the GC can't start while we're
	// sweeping, so we can read h.sweepArenas, and so
	// traceGCSweepStart/Done pair on the P.
	mp := acquirem()

	trace := traceAcquire()
	if trace.ok() {
		trace.GCSweepStart()
		traceRelease(trace)
	}

	arenas := h.sweepArenas
	locked := false
	for npage > 0 {
		// Pull from accumulated credit first.
		if credit := h.reclaimCredit.Load(); credit > 0 {
			take := credit
			if take > npage {
				// Take only what we need.
				take = npage
			}
			if h.reclaimCredit.CompareAndSwap(credit, credit-take) {
				npage -= take
			}
			continue
		}

		// Claim a chunk of work.
		idx := uintptr(h.reclaimIndex.Add(pagesPerReclaimerChunk) - pagesPerReclaimerChunk)
		if idx/pagesPerArena >= uintptr(len(arenas)) {
			// Page reclaiming is done.
			h.reclaimIndex.Store(1 << 63)
			break
		}

		if !locked {
			// Lock the heap for reclaimChunk.
			lock(&h.lock)
			locked = true
		}

		// Scan this chunk.
		nfound := h.reclaimChunk(arenas, idx, pagesPerReclaimerChunk)
		if nfound <= npage {
			npage -= nfound
		} else {
			// Put spare pages toward global credit.
			h.reclaimCredit.Add(nfound - npage)
			npage = 0
		}
	}
	if locked {
		unlock(&h.lock)
	}

	trace = traceAcquire()
	if trace.ok() {
		trace.GCSweepDone()
		traceRelease(trace)
	}
	releasem(mp)
}

// reclaimChunk sweeps unmarked spans that start at page indexes [pageIdx, pageIdx+n).
// It returns the number of pages returned to the heap.
//
// h.lock must be held and the caller must be non-preemptible. Note: h.lock may be
// temporarily unlocked and re-locked in order to do sweeping or if tracing is
// enabled.
func (h *mheap) reclaimChunk(arenas []arenaIdx, pageIdx, n uintptr) uintptr {
	// The heap lock must be held because this accesses the
	// heapArena.spans arrays using potentially non-live pointers.
	// In particular, if a span were freed and merged concurrently
	// with this probing heapArena.spans, it would be possible to
	// observe arbitrary, stale span pointers.
	assertLockHeld(&h.lock)

	n0 := n
	var nFreed uintptr
	sl := sweep.active.begin()
	if !sl.valid {
		return 0
	}
	for n > 0 {
		ai := arenas[pageIdx/pagesPerArena]
		ha := h.arenas[ai.l1()][ai.l2()]

		// Get a chunk of the bitmap to work on.
		arenaPage := uint(pageIdx % pagesPerArena)
		inUse := ha.pageInUse[arenaPage/8:]
		marked := ha.pageMarks[arenaPage/8:]
		if uintptr(len(inUse)) > n/8 {
			inUse = inUse[:n/8]
			marked = marked[:n/8]
		}

		// Scan this bitmap chunk for spans that are in-use
		// but have no marked objects on them.
		for i := range inUse {
			inUseUnmarked := atomic.Load8(&inUse[i]) &^ marked[i]
			if inUseUnmarked == 0 {
				continue
			}

			for j := uint(0); j < 8; j++ {
				if inUseUnmarked&(1<<j) != 0 {
					s := ha.spans[arenaPage+uint(i)*8+j]
					if s, ok := sl.tryAcquire(s); ok {
						npages := s.npages
						unlock(&h.lock)
						if s.sweep(false) {
							nFreed += npages
						}
						lock(&h.lock)
						// Reload inUse. It's possible nearby
						// spans were freed when we dropped the
						// lock and we don't want to get stale
						// pointers from the spans array.
						inUseUnmarked = atomic.Load8(&inUse[i]) &^ marked[i]
					}
				}
			}
		}

		// Advance.
		pageIdx += uintptr(len(inUse) * 8)
		n -= uintptr(len(inUse) * 8)
	}
	sweep.active.end(sl)
	trace := traceAcquire()
	if trace.ok() {
		unlock(&h.lock)
		// Account for pages scanned but not reclaimed.
		trace.GCSweepSpan((n0 - nFreed) * pageSize)
		traceRelease(trace)
		lock(&h.lock)
	}

	assertLockHeld(&h.lock) // Must be locked on return.
	return nFreed
}

// spanAllocType represents the type of allocation to make, or
// the type of allocation to be freed.
type spanAllocType uint8

const (
	spanAllocHeap          spanAllocType = iota // heap span
	spanAllocStack                              // stack span
	spanAllocPtrScalarBits                      // unrolled GC prog bitmap span
	spanAllocWorkBuf                            // work buf span
)

// m
"""




```