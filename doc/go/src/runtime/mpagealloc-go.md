Response:
Let's break down the thought process for analyzing the provided Go code snippet. The goal is to understand its functionality and explain it in Chinese.

**1. Initial Scan and Identification of Key Terms:**

The first step is to quickly scan the code and identify recurring keywords and data structures. I see terms like:

* `page allocator`
* `mpagealloc.go`
* `bitmap`
* `chunks`
* `radix tree`
* `summaries`
* `free pages`
* `in-use`
* `allocation`
* `mheap`
* `pageSize`

These terms immediately suggest the code is about memory management at a low level, specifically dealing with pages and tracking their allocation status. The mention of "radix tree" and "summaries" points towards an efficient way of searching for free space.

**2. Understanding the Core Data Structures:**

Next, I focus on the major data structures defined in the code:

* **`pageAlloc` struct:** This is the central structure. I examine its fields to understand what information it holds. Key fields are `summary`, `chunks`, `searchAddr`, `inUse`, and `scav`.
    * `summary`:  The comments clearly explain this is the radix tree, storing summaries of free space at different granularities.
    * `chunks`:  This is the actual bitmap data, organized in a two-level structure for efficiency.
    * `searchAddr`:  An optimization hint for where to start searching for free space.
    * `inUse`:  Keeps track of the currently used memory ranges.
    * `scav`:  Related to memory scavenging (reclaiming unused memory).

* **`pallocSum`:** Though not explicitly shown in this snippet, the comments frequently mention it and its fields (`start`, `max`, `end`). I infer it stores the number of contiguous free pages at the beginning, the maximum contiguous free pages, and the number of contiguous free pages at the end of a region.

* **`chunkIdx`:**  Represents an index into the `chunks` structure.

**3. Tracing the Allocation Process (Conceptual):**

Based on the identified terms and data structures, I start to form a mental model of how allocation might work:

1. **Request for memory:**  The allocator needs to find a contiguous block of free pages.
2. **Radix Tree Search:** The `find` function likely traverses the `summary` radix tree to quickly locate regions with enough free space. The summaries help prune the search.
3. **Bitmap Check:** Once a promising region is found, the `chunks` bitmap is consulted to verify the availability of individual pages.
4. **Marking as Allocated:** If the pages are free, they are marked as "in-use" in the bitmap.
5. **Updating Summaries:**  The `update` function recalculates the summaries in the radix tree to reflect the allocation.

**4. Inferring Functionality from Function Names and Comments:**

I examine the functions and their associated comments:

* `init`: Initializes the `pageAlloc` structure.
* `grow`: Adds a new memory region to the allocator's management.
* `enableChunkHugePages`: Enables the use of huge pages for the bitmap.
* `update`:  Updates the radix tree summaries.
* `allocRange`: Marks a range of pages as allocated.
* `findMappedAddr`: Finds the start of a mapped memory region.
* `find`:  The core function for searching for free space.

The comments provide valuable insights into the purpose and logic of each function.

**5. Connecting the Pieces:**

I start connecting the functions and data structures. For example, `grow` adds new memory, which requires updating the `chunks` structure and the `summary` radix tree. `find` uses the `summary` to efficiently search before checking the `chunks`.

**6. Focusing on the Specific Request (Summarizing Part 1):**

The prompt asks for a summary of the functionality of this *part* of the code. It's important to focus on what's present in this specific snippet and avoid going too deep into aspects that might be in Part 2.

Based on the code and comments, I can identify the key functionalities in this part:

* **Initialization:** Setting up the page allocator and its data structures.
* **Memory Growth:** Handling the addition of new memory regions.
* **Bitmap Management:**  Organizing and accessing the page allocation bitmap using the `chunks` structure.
* **Radix Tree Representation:** Defining the structure and indexing of the radix tree using the `summary` array.
* **Address Space Management:**  Converting between linear addresses and indices within the radix tree and bitmap.
* **Basic Allocation Search (Conceptual):** The `find` function outlines the general search strategy using the radix tree.

**7. Structuring the Answer in Chinese:**

Finally, I structure my understanding into a clear and concise Chinese explanation, using the identified keywords and functionalities. I emphasize the role of the radix tree, bitmap, and the overall goal of managing page allocations. I also note the sparse array approach for managing the bitmap.

**Self-Correction/Refinement:**

During the process, I might realize I've made some assumptions or haven't fully grasped a concept. For example, initially, I might not fully understand the purpose of `searchAddr`. By rereading the comments and how it's used in `find`, I can refine my understanding. Similarly, understanding the two-level structure of `chunks` requires careful attention to the bit-shifting operations in the `l1()` and `l2()` methods. I would revisit these parts of the code and comments to solidify my understanding.
这段代码是 Go 语言运行时系统中的**页分配器 (Page Allocator)** 的实现的一部分。它的主要功能是管理进程的虚拟地址空间，用于分配和回收大小为 `pageSize` 的内存页。

更具体地说，这段代码实现了页分配器的核心数据结构和一些基本操作，用于高效地跟踪哪些页被使用，哪些页是空闲的，并快速找到连续的空闲页块来满足分配请求。

以下是这段代码的主要功能归纳：

**1. 管理页的位图 (Bitmap Management):**

*   使用位图来表示进程地址空间中的每个页的状态（已使用或空闲）。
*   将位图划分为更小的**块 (chunks)** 以提高管理效率。
*   使用两级稀疏数组 (`chunks`) 来存储这些位图块，避免一次性映射巨大的位图，节省内存。

**2. 使用基数树 (Radix Tree) 加速查找:**

*   构建了一个隐式的**基数树 (Radix Tree)** 结构的**摘要 (summaries)** 数组。
*   基数树的每个节点（摘要）概括了其所代表的地址空间区域的空闲页信息：起始和结尾的连续空闲页数量，以及区域内的最大连续空闲页数量。
*   通过遍历基数树，可以高效地定位到包含足够连续空闲页的区域，避免扫描整个位图。

**3. 地址空间划分和索引:**

*   定义了 `chunkIdx` 类型来表示位图块的全局索引。
*   提供了函数用于在地址、块索引和页索引之间进行转换 (`chunkIndex`, `chunkBase`, `chunkPageIndex`)。
*   提供了函数用于在地址和基数树各层级的索引之间进行转换 (`offAddrToLevelIndex`, `levelIndexToOffAddr`, `addrsToSummaryRange`, `blockAlignSummaryRange`)。

**4. 内存增长管理 (`grow` 函数):**

*   当需要向堆添加新的内存区域时，`grow` 函数负责更新页分配器的元数据。
*   它会扩展基数树的摘要信息，并在 `chunks` 数组中创建或更新相应的位图块。
*   新增长的内存区域会被标记为已扫描 (scavenged)。

**5. 查找空闲页 (`find` 函数):**

*   `find` 函数是查找连续空闲页的核心实现。
*   它使用基数树的摘要信息来快速定位可能包含足够空闲页的区域。
*   它从根节点开始，逐层向下搜索，利用摘要信息剪枝，避免不必要的扫描。
*   在找到可能包含空闲页的块后，会进一步检查该块的位图。

**6. 分配页范围 (`allocRange` 函数):**

*   `allocRange` 函数将指定地址范围内的页标记为已分配。
*   它会更新相应位图块中的位，并将分配信息同步到基数树的摘要中。
*   还会计算被分配区域内已扫描的内存量。

**7. 优化搜索起点 (`searchAddr`):**

*   维护一个 `searchAddr` 变量，用于记录上次找到空闲空间的地址附近。
*   在下次查找时，可以从 `searchAddr` 开始搜索，跳过已知已分配的地址空间，提高效率。

**8. 内存扫描状态管理 (`scav`):**

*   包含一个 `scav` 结构体，用于管理内存扫描相关的状态，包括一个用于高效查找可扫描页的索引。

**可以推理出这是 Go 语言** **堆内存分配 (Heap Memory Allocation)** **功能的一部分。**  更具体地说，它负责管理堆的底层物理内存页的分配和回收。

**Go 代码举例说明 (假设的简化版):**

```go
package main

import "fmt"
import "unsafe" // 实际使用中会更复杂，此处仅为示意

// 假设的 pageSize
const pageSize = 4096

// 假设的 pageAlloc 结构体 (简化)
type pageAlloc struct {
	// 假设的 chunks 位图数组 (简化)
	chunks map[uintptr][]bool // key: chunk 的起始地址, value: 该 chunk 的页状态 (true: 已使用, false: 空闲)
}

// 假设的分配函数 (简化)
func (pa *pageAlloc) alloc(npages uintptr) uintptr {
	for chunkBase, pages := range pa.chunks {
		contiguousFree := 0
		startPage := -1
		for i, used := range pages {
			if !used {
				if contiguousFree == 0 {
					startPage = i
				}
				contiguousFree++
				if uintptr(contiguousFree) == npages {
					// 找到足够的连续空闲页，标记为已使用
					addr := chunkBase + uintptr(startPage)*pageSize
					for i := startPage; i < startPage+int(npages); i++ {
						pages[i] = true
					}
					fmt.Printf("分配了 %d 个页，起始地址: 0x%x\n", npages, addr)
					return addr
				}
			} else {
				contiguousFree = 0
			}
		}
	}
	fmt.Println("找不到足够的连续空闲页")
	return 0
}

func main() {
	// 初始化 pageAlloc (实际初始化会更复杂)
	pa := pageAlloc{
		chunks: map[uintptr][]bool{
			0x10000000: make([]bool, 1024), // 假设一个 chunk 有 1024 个页
			0x20000000: make([]bool, 1024),
		},
	}

	// 分配 5 个页
	addr1 := pa.alloc(5)
	if addr1 != 0 {
		fmt.Printf("分配的地址: 0x%x\n", addr1)
	}

	// 分配 10 个页
	addr2 := pa.alloc(10)
	if addr2 != 0 {
		fmt.Printf("分配的地址: 0x%x\n", addr2)
	}
}
```

**假设的输入与输出:**

在这个简化的例子中：

*   **假设输入:**  `pa.alloc(5)` 和 `pa.alloc(10)`，分别请求分配 5 个和 10 个连续的内存页。
*   **可能的输出:**
    ```
    分配了 5 个页，起始地址: 0x10000000
    分配的地址: 0x10000000
    分配了 10 个页，起始地址: 0x10005000
    分配的地址: 0x10005000
    ```
    或者，如果第一个 chunk 中没有足够的连续空间，可能会分配到第二个 chunk。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。页分配器是 Go 运行时系统内部的核心组件，它的行为受到运行时系统的配置和内存管理策略的影响。

**使用者易犯错的点:**

这段代码是 Go 运行时系统的一部分，普通 Go 开发者不会直接操作或修改它。 因此，从使用者（Go 开发者）的角度来看，**不容易犯错**。

然而，如果开发者试图**绕过 Go 的内存管理机制**，例如使用 `unsafe` 包进行不当的内存操作，可能会导致与页分配器状态不一致，从而引发程序崩溃或其他未定义行为。但这并非直接由这段代码引起，而是滥用 `unsafe` 导致的。

**功能归纳 (针对提供的第 1 部分代码):**

提供的代码主要负责以下功能：

1. **定义了页分配器的数据结构:**  `pageAlloc` 结构体及其内部的 `summary` (基数树的摘要信息) 和 `chunks` (页位图)。
2. **实现了地址空间和索引的转换:** 提供了一系列函数用于在不同的地址表示和索引之间进行转换，这是高效管理和查找的基础。
3. **实现了内存增长的管理:**  `grow` 函数负责在堆内存扩展时更新页分配器的元数据。
4. **定义了基本的查找空闲页的框架:**  `find` 函数是查找连续空闲页的核心，虽然具体的位图扫描逻辑可能在其他部分实现。
5. **实现了分配页范围的功能:** `allocRange` 函数负责将指定的页范围标记为已分配并更新元数据。

总而言之，这段代码是 Go 语言运行时系统中负责底层内存页管理的关键组成部分，它利用位图和基数树等高效的数据结构和算法来实现快速的内存分配和回收。

### 提示词
```
这是路径为go/src/runtime/mpagealloc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Page allocator.
//
// The page allocator manages mapped pages (defined by pageSize, NOT
// physPageSize) for allocation and re-use. It is embedded into mheap.
//
// Pages are managed using a bitmap that is sharded into chunks.
// In the bitmap, 1 means in-use, and 0 means free. The bitmap spans the
// process's address space. Chunks are managed in a sparse-array-style structure
// similar to mheap.arenas, since the bitmap may be large on some systems.
//
// The bitmap is efficiently searched by using a radix tree in combination
// with fast bit-wise intrinsics. Allocation is performed using an address-ordered
// first-fit approach.
//
// Each entry in the radix tree is a summary that describes three properties of
// a particular region of the address space: the number of contiguous free pages
// at the start and end of the region it represents, and the maximum number of
// contiguous free pages found anywhere in that region.
//
// Each level of the radix tree is stored as one contiguous array, which represents
// a different granularity of subdivision of the processes' address space. Thus, this
// radix tree is actually implicit in these large arrays, as opposed to having explicit
// dynamically-allocated pointer-based node structures. Naturally, these arrays may be
// quite large for system with large address spaces, so in these cases they are mapped
// into memory as needed. The leaf summaries of the tree correspond to a bitmap chunk.
//
// The root level (referred to as L0 and index 0 in pageAlloc.summary) has each
// summary represent the largest section of address space (16 GiB on 64-bit systems),
// with each subsequent level representing successively smaller subsections until we
// reach the finest granularity at the leaves, a chunk.
//
// More specifically, each summary in each level (except for leaf summaries)
// represents some number of entries in the following level. For example, each
// summary in the root level may represent a 16 GiB region of address space,
// and in the next level there could be 8 corresponding entries which represent 2
// GiB subsections of that 16 GiB region, each of which could correspond to 8
// entries in the next level which each represent 256 MiB regions, and so on.
//
// Thus, this design only scales to heaps so large, but can always be extended to
// larger heaps by simply adding levels to the radix tree, which mostly costs
// additional virtual address space. The choice of managing large arrays also means
// that a large amount of virtual address space may be reserved by the runtime.

package runtime

import (
	"internal/runtime/atomic"
	"unsafe"
)

const (
	// The size of a bitmap chunk, i.e. the amount of bits (that is, pages) to consider
	// in the bitmap at once.
	pallocChunkPages    = 1 << logPallocChunkPages
	pallocChunkBytes    = pallocChunkPages * pageSize
	logPallocChunkPages = 9
	logPallocChunkBytes = logPallocChunkPages + pageShift

	// The number of radix bits for each level.
	//
	// The value of 3 is chosen such that the block of summaries we need to scan at
	// each level fits in 64 bytes (2^3 summaries * 8 bytes per summary), which is
	// close to the L1 cache line width on many systems. Also, a value of 3 fits 4 tree
	// levels perfectly into the 21-bit pallocBits summary field at the root level.
	//
	// The following equation explains how each of the constants relate:
	// summaryL0Bits + (summaryLevels-1)*summaryLevelBits + logPallocChunkBytes = heapAddrBits
	//
	// summaryLevels is an architecture-dependent value defined in mpagealloc_*.go.
	summaryLevelBits = 3
	summaryL0Bits    = heapAddrBits - logPallocChunkBytes - (summaryLevels-1)*summaryLevelBits

	// pallocChunksL2Bits is the number of bits of the chunk index number
	// covered by the second level of the chunks map.
	//
	// See (*pageAlloc).chunks for more details. Update the documentation
	// there should this change.
	pallocChunksL2Bits  = heapAddrBits - logPallocChunkBytes - pallocChunksL1Bits
	pallocChunksL1Shift = pallocChunksL2Bits
)

// maxSearchAddr returns the maximum searchAddr value, which indicates
// that the heap has no free space.
//
// This function exists just to make it clear that this is the maximum address
// for the page allocator's search space. See maxOffAddr for details.
//
// It's a function (rather than a variable) because it needs to be
// usable before package runtime's dynamic initialization is complete.
// See #51913 for details.
func maxSearchAddr() offAddr { return maxOffAddr }

// Global chunk index.
//
// Represents an index into the leaf level of the radix tree.
// Similar to arenaIndex, except instead of arenas, it divides the address
// space into chunks.
type chunkIdx uint

// chunkIndex returns the global index of the palloc chunk containing the
// pointer p.
func chunkIndex(p uintptr) chunkIdx {
	return chunkIdx((p - arenaBaseOffset) / pallocChunkBytes)
}

// chunkBase returns the base address of the palloc chunk at index ci.
func chunkBase(ci chunkIdx) uintptr {
	return uintptr(ci)*pallocChunkBytes + arenaBaseOffset
}

// chunkPageIndex computes the index of the page that contains p,
// relative to the chunk which contains p.
func chunkPageIndex(p uintptr) uint {
	return uint(p % pallocChunkBytes / pageSize)
}

// l1 returns the index into the first level of (*pageAlloc).chunks.
func (i chunkIdx) l1() uint {
	if pallocChunksL1Bits == 0 {
		// Let the compiler optimize this away if there's no
		// L1 map.
		return 0
	} else {
		return uint(i) >> pallocChunksL1Shift
	}
}

// l2 returns the index into the second level of (*pageAlloc).chunks.
func (i chunkIdx) l2() uint {
	if pallocChunksL1Bits == 0 {
		return uint(i)
	} else {
		return uint(i) & (1<<pallocChunksL2Bits - 1)
	}
}

// offAddrToLevelIndex converts an address in the offset address space
// to the index into summary[level] containing addr.
func offAddrToLevelIndex(level int, addr offAddr) int {
	return int((addr.a - arenaBaseOffset) >> levelShift[level])
}

// levelIndexToOffAddr converts an index into summary[level] into
// the corresponding address in the offset address space.
func levelIndexToOffAddr(level, idx int) offAddr {
	return offAddr{(uintptr(idx) << levelShift[level]) + arenaBaseOffset}
}

// addrsToSummaryRange converts base and limit pointers into a range
// of entries for the given summary level.
//
// The returned range is inclusive on the lower bound and exclusive on
// the upper bound.
func addrsToSummaryRange(level int, base, limit uintptr) (lo int, hi int) {
	// This is slightly more nuanced than just a shift for the exclusive
	// upper-bound. Note that the exclusive upper bound may be within a
	// summary at this level, meaning if we just do the obvious computation
	// hi will end up being an inclusive upper bound. Unfortunately, just
	// adding 1 to that is too broad since we might be on the very edge
	// of a summary's max page count boundary for this level
	// (1 << levelLogPages[level]). So, make limit an inclusive upper bound
	// then shift, then add 1, so we get an exclusive upper bound at the end.
	lo = int((base - arenaBaseOffset) >> levelShift[level])
	hi = int(((limit-1)-arenaBaseOffset)>>levelShift[level]) + 1
	return
}

// blockAlignSummaryRange aligns indices into the given level to that
// level's block width (1 << levelBits[level]). It assumes lo is inclusive
// and hi is exclusive, and so aligns them down and up respectively.
func blockAlignSummaryRange(level int, lo, hi int) (int, int) {
	e := uintptr(1) << levelBits[level]
	return int(alignDown(uintptr(lo), e)), int(alignUp(uintptr(hi), e))
}

type pageAlloc struct {
	// Radix tree of summaries.
	//
	// Each slice's cap represents the whole memory reservation.
	// Each slice's len reflects the allocator's maximum known
	// mapped heap address for that level.
	//
	// The backing store of each summary level is reserved in init
	// and may or may not be committed in grow (small address spaces
	// may commit all the memory in init).
	//
	// The purpose of keeping len <= cap is to enforce bounds checks
	// on the top end of the slice so that instead of an unknown
	// runtime segmentation fault, we get a much friendlier out-of-bounds
	// error.
	//
	// To iterate over a summary level, use inUse to determine which ranges
	// are currently available. Otherwise one might try to access
	// memory which is only Reserved which may result in a hard fault.
	//
	// We may still get segmentation faults < len since some of that
	// memory may not be committed yet.
	summary [summaryLevels][]pallocSum

	// chunks is a slice of bitmap chunks.
	//
	// The total size of chunks is quite large on most 64-bit platforms
	// (O(GiB) or more) if flattened, so rather than making one large mapping
	// (which has problems on some platforms, even when PROT_NONE) we use a
	// two-level sparse array approach similar to the arena index in mheap.
	//
	// To find the chunk containing a memory address `a`, do:
	//   chunkOf(chunkIndex(a))
	//
	// Below is a table describing the configuration for chunks for various
	// heapAddrBits supported by the runtime.
	//
	// heapAddrBits | L1 Bits | L2 Bits | L2 Entry Size
	// ------------------------------------------------
	// 32           | 0       | 10      | 128 KiB
	// 33 (iOS)     | 0       | 11      | 256 KiB
	// 48           | 13      | 13      | 1 MiB
	//
	// There's no reason to use the L1 part of chunks on 32-bit, the
	// address space is small so the L2 is small. For platforms with a
	// 48-bit address space, we pick the L1 such that the L2 is 1 MiB
	// in size, which is a good balance between low granularity without
	// making the impact on BSS too high (note the L1 is stored directly
	// in pageAlloc).
	//
	// To iterate over the bitmap, use inUse to determine which ranges
	// are currently available. Otherwise one might iterate over unused
	// ranges.
	//
	// Protected by mheapLock.
	//
	// TODO(mknyszek): Consider changing the definition of the bitmap
	// such that 1 means free and 0 means in-use so that summaries and
	// the bitmaps align better on zero-values.
	chunks [1 << pallocChunksL1Bits]*[1 << pallocChunksL2Bits]pallocData

	// The address to start an allocation search with. It must never
	// point to any memory that is not contained in inUse, i.e.
	// inUse.contains(searchAddr.addr()) must always be true. The one
	// exception to this rule is that it may take on the value of
	// maxOffAddr to indicate that the heap is exhausted.
	//
	// We guarantee that all valid heap addresses below this value
	// are allocated and not worth searching.
	searchAddr offAddr

	// start and end represent the chunk indices
	// which pageAlloc knows about. It assumes
	// chunks in the range [start, end) are
	// currently ready to use.
	start, end chunkIdx

	// inUse is a slice of ranges of address space which are
	// known by the page allocator to be currently in-use (passed
	// to grow).
	//
	// We care much more about having a contiguous heap in these cases
	// and take additional measures to ensure that, so in nearly all
	// cases this should have just 1 element.
	//
	// All access is protected by the mheapLock.
	inUse addrRanges

	// scav stores the scavenger state.
	scav struct {
		// index is an efficient index of chunks that have pages available to
		// scavenge.
		index scavengeIndex

		// releasedBg is the amount of memory released in the background this
		// scavenge cycle.
		releasedBg atomic.Uintptr

		// releasedEager is the amount of memory released eagerly this scavenge
		// cycle.
		releasedEager atomic.Uintptr
	}

	// mheap_.lock. This level of indirection makes it possible
	// to test pageAlloc independently of the runtime allocator.
	mheapLock *mutex

	// sysStat is the runtime memstat to update when new system
	// memory is committed by the pageAlloc for allocation metadata.
	sysStat *sysMemStat

	// summaryMappedReady is the number of bytes mapped in the Ready state
	// in the summary structure. Used only for testing currently.
	//
	// Protected by mheapLock.
	summaryMappedReady uintptr

	// chunkHugePages indicates whether page bitmap chunks should be backed
	// by huge pages.
	chunkHugePages bool

	// Whether or not this struct is being used in tests.
	test bool
}

func (p *pageAlloc) init(mheapLock *mutex, sysStat *sysMemStat, test bool) {
	if levelLogPages[0] > logMaxPackedValue {
		// We can't represent 1<<levelLogPages[0] pages, the maximum number
		// of pages we need to represent at the root level, in a summary, which
		// is a big problem. Throw.
		print("runtime: root level max pages = ", 1<<levelLogPages[0], "\n")
		print("runtime: summary max pages = ", maxPackedValue, "\n")
		throw("root level max pages doesn't fit in summary")
	}
	p.sysStat = sysStat

	// Initialize p.inUse.
	p.inUse.init(sysStat)

	// System-dependent initialization.
	p.sysInit(test)

	// Start with the searchAddr in a state indicating there's no free memory.
	p.searchAddr = maxSearchAddr()

	// Set the mheapLock.
	p.mheapLock = mheapLock

	// Initialize the scavenge index.
	p.summaryMappedReady += p.scav.index.init(test, sysStat)

	// Set if we're in a test.
	p.test = test
}

// tryChunkOf returns the bitmap data for the given chunk.
//
// Returns nil if the chunk data has not been mapped.
func (p *pageAlloc) tryChunkOf(ci chunkIdx) *pallocData {
	l2 := p.chunks[ci.l1()]
	if l2 == nil {
		return nil
	}
	return &l2[ci.l2()]
}

// chunkOf returns the chunk at the given chunk index.
//
// The chunk index must be valid or this method may throw.
func (p *pageAlloc) chunkOf(ci chunkIdx) *pallocData {
	return &p.chunks[ci.l1()][ci.l2()]
}

// grow sets up the metadata for the address range [base, base+size).
// It may allocate metadata, in which case *p.sysStat will be updated.
//
// p.mheapLock must be held.
func (p *pageAlloc) grow(base, size uintptr) {
	assertLockHeld(p.mheapLock)

	// Round up to chunks, since we can't deal with increments smaller
	// than chunks. Also, sysGrow expects aligned values.
	limit := alignUp(base+size, pallocChunkBytes)
	base = alignDown(base, pallocChunkBytes)

	// Grow the summary levels in a system-dependent manner.
	// We just update a bunch of additional metadata here.
	p.sysGrow(base, limit)

	// Grow the scavenge index.
	p.summaryMappedReady += p.scav.index.grow(base, limit, p.sysStat)

	// Update p.start and p.end.
	// If no growth happened yet, start == 0. This is generally
	// safe since the zero page is unmapped.
	firstGrowth := p.start == 0
	start, end := chunkIndex(base), chunkIndex(limit)
	if firstGrowth || start < p.start {
		p.start = start
	}
	if end > p.end {
		p.end = end
	}
	// Note that [base, limit) will never overlap with any existing
	// range inUse because grow only ever adds never-used memory
	// regions to the page allocator.
	p.inUse.add(makeAddrRange(base, limit))

	// A grow operation is a lot like a free operation, so if our
	// chunk ends up below p.searchAddr, update p.searchAddr to the
	// new address, just like in free.
	if b := (offAddr{base}); b.lessThan(p.searchAddr) {
		p.searchAddr = b
	}

	// Add entries into chunks, which is sparse, if needed. Then,
	// initialize the bitmap.
	//
	// Newly-grown memory is always considered scavenged.
	// Set all the bits in the scavenged bitmaps high.
	for c := chunkIndex(base); c < chunkIndex(limit); c++ {
		if p.chunks[c.l1()] == nil {
			// Create the necessary l2 entry.
			const l2Size = unsafe.Sizeof(*p.chunks[0])
			r := sysAlloc(l2Size, p.sysStat)
			if r == nil {
				throw("pageAlloc: out of memory")
			}
			if !p.test {
				// Make the chunk mapping eligible or ineligible
				// for huge pages, depending on what our current
				// state is.
				if p.chunkHugePages {
					sysHugePage(r, l2Size)
				} else {
					sysNoHugePage(r, l2Size)
				}
			}
			// Store the new chunk block but avoid a write barrier.
			// grow is used in call chains that disallow write barriers.
			*(*uintptr)(unsafe.Pointer(&p.chunks[c.l1()])) = uintptr(r)
		}
		p.chunkOf(c).scavenged.setRange(0, pallocChunkPages)
	}

	// Update summaries accordingly. The grow acts like a free, so
	// we need to ensure this newly-free memory is visible in the
	// summaries.
	p.update(base, size/pageSize, true, false)
}

// enableChunkHugePages enables huge pages for the chunk bitmap mappings (disabled by default).
//
// This function is idempotent.
//
// A note on latency: for sufficiently small heaps (<10s of GiB) this function will take constant
// time, but may take time proportional to the size of the mapped heap beyond that.
//
// The heap lock must not be held over this operation, since it will briefly acquire
// the heap lock.
//
// Must be called on the system stack because it acquires the heap lock.
//
//go:systemstack
func (p *pageAlloc) enableChunkHugePages() {
	// Grab the heap lock to turn on huge pages for new chunks and clone the current
	// heap address space ranges.
	//
	// After the lock is released, we can be sure that bitmaps for any new chunks may
	// be backed with huge pages, and we have the address space for the rest of the
	// chunks. At the end of this function, all chunk metadata should be backed by huge
	// pages.
	lock(&mheap_.lock)
	if p.chunkHugePages {
		unlock(&mheap_.lock)
		return
	}
	p.chunkHugePages = true
	var inUse addrRanges
	inUse.sysStat = p.sysStat
	p.inUse.cloneInto(&inUse)
	unlock(&mheap_.lock)

	// This might seem like a lot of work, but all these loops are for generality.
	//
	// For a 1 GiB contiguous heap, a 48-bit address space, 13 L1 bits, a palloc chunk size
	// of 4 MiB, and adherence to the default set of heap address hints, this will result in
	// exactly 1 call to sysHugePage.
	for _, r := range p.inUse.ranges {
		for i := chunkIndex(r.base.addr()).l1(); i < chunkIndex(r.limit.addr()-1).l1(); i++ {
			// N.B. We can assume that p.chunks[i] is non-nil and in a mapped part of p.chunks
			// because it's derived from inUse, which never shrinks.
			sysHugePage(unsafe.Pointer(p.chunks[i]), unsafe.Sizeof(*p.chunks[0]))
		}
	}
}

// update updates heap metadata. It must be called each time the bitmap
// is updated.
//
// If contig is true, update does some optimizations assuming that there was
// a contiguous allocation or free between addr and addr+npages. alloc indicates
// whether the operation performed was an allocation or a free.
//
// p.mheapLock must be held.
func (p *pageAlloc) update(base, npages uintptr, contig, alloc bool) {
	assertLockHeld(p.mheapLock)

	// base, limit, start, and end are inclusive.
	limit := base + npages*pageSize - 1
	sc, ec := chunkIndex(base), chunkIndex(limit)

	// Handle updating the lowest level first.
	if sc == ec {
		// Fast path: the allocation doesn't span more than one chunk,
		// so update this one and if the summary didn't change, return.
		x := p.summary[len(p.summary)-1][sc]
		y := p.chunkOf(sc).summarize()
		if x == y {
			return
		}
		p.summary[len(p.summary)-1][sc] = y
	} else if contig {
		// Slow contiguous path: the allocation spans more than one chunk
		// and at least one summary is guaranteed to change.
		summary := p.summary[len(p.summary)-1]

		// Update the summary for chunk sc.
		summary[sc] = p.chunkOf(sc).summarize()

		// Update the summaries for chunks in between, which are
		// either totally allocated or freed.
		whole := p.summary[len(p.summary)-1][sc+1 : ec]
		if alloc {
			clear(whole)
		} else {
			for i := range whole {
				whole[i] = freeChunkSum
			}
		}

		// Update the summary for chunk ec.
		summary[ec] = p.chunkOf(ec).summarize()
	} else {
		// Slow general path: the allocation spans more than one chunk
		// and at least one summary is guaranteed to change.
		//
		// We can't assume a contiguous allocation happened, so walk over
		// every chunk in the range and manually recompute the summary.
		summary := p.summary[len(p.summary)-1]
		for c := sc; c <= ec; c++ {
			summary[c] = p.chunkOf(c).summarize()
		}
	}

	// Walk up the radix tree and update the summaries appropriately.
	changed := true
	for l := len(p.summary) - 2; l >= 0 && changed; l-- {
		// Update summaries at level l from summaries at level l+1.
		changed = false

		// "Constants" for the previous level which we
		// need to compute the summary from that level.
		logEntriesPerBlock := levelBits[l+1]
		logMaxPages := levelLogPages[l+1]

		// lo and hi describe all the parts of the level we need to look at.
		lo, hi := addrsToSummaryRange(l, base, limit+1)

		// Iterate over each block, updating the corresponding summary in the less-granular level.
		for i := lo; i < hi; i++ {
			children := p.summary[l+1][i<<logEntriesPerBlock : (i+1)<<logEntriesPerBlock]
			sum := mergeSummaries(children, logMaxPages)
			old := p.summary[l][i]
			if old != sum {
				changed = true
				p.summary[l][i] = sum
			}
		}
	}
}

// allocRange marks the range of memory [base, base+npages*pageSize) as
// allocated. It also updates the summaries to reflect the newly-updated
// bitmap.
//
// Returns the amount of scavenged memory in bytes present in the
// allocated range.
//
// p.mheapLock must be held.
func (p *pageAlloc) allocRange(base, npages uintptr) uintptr {
	assertLockHeld(p.mheapLock)

	limit := base + npages*pageSize - 1
	sc, ec := chunkIndex(base), chunkIndex(limit)
	si, ei := chunkPageIndex(base), chunkPageIndex(limit)

	scav := uint(0)
	if sc == ec {
		// The range doesn't cross any chunk boundaries.
		chunk := p.chunkOf(sc)
		scav += chunk.scavenged.popcntRange(si, ei+1-si)
		chunk.allocRange(si, ei+1-si)
		p.scav.index.alloc(sc, ei+1-si)
	} else {
		// The range crosses at least one chunk boundary.
		chunk := p.chunkOf(sc)
		scav += chunk.scavenged.popcntRange(si, pallocChunkPages-si)
		chunk.allocRange(si, pallocChunkPages-si)
		p.scav.index.alloc(sc, pallocChunkPages-si)
		for c := sc + 1; c < ec; c++ {
			chunk := p.chunkOf(c)
			scav += chunk.scavenged.popcntRange(0, pallocChunkPages)
			chunk.allocAll()
			p.scav.index.alloc(c, pallocChunkPages)
		}
		chunk = p.chunkOf(ec)
		scav += chunk.scavenged.popcntRange(0, ei+1)
		chunk.allocRange(0, ei+1)
		p.scav.index.alloc(ec, ei+1)
	}
	p.update(base, npages, true, true)
	return uintptr(scav) * pageSize
}

// findMappedAddr returns the smallest mapped offAddr that is
// >= addr. That is, if addr refers to mapped memory, then it is
// returned. If addr is higher than any mapped region, then
// it returns maxOffAddr.
//
// p.mheapLock must be held.
func (p *pageAlloc) findMappedAddr(addr offAddr) offAddr {
	assertLockHeld(p.mheapLock)

	// If we're not in a test, validate first by checking mheap_.arenas.
	// This is a fast path which is only safe to use outside of testing.
	ai := arenaIndex(addr.addr())
	if p.test || mheap_.arenas[ai.l1()] == nil || mheap_.arenas[ai.l1()][ai.l2()] == nil {
		vAddr, ok := p.inUse.findAddrGreaterEqual(addr.addr())
		if ok {
			return offAddr{vAddr}
		} else {
			// The candidate search address is greater than any
			// known address, which means we definitely have no
			// free memory left.
			return maxOffAddr
		}
	}
	return addr
}

// find searches for the first (address-ordered) contiguous free region of
// npages in size and returns a base address for that region.
//
// It uses p.searchAddr to prune its search and assumes that no palloc chunks
// below chunkIndex(p.searchAddr) contain any free memory at all.
//
// find also computes and returns a candidate p.searchAddr, which may or
// may not prune more of the address space than p.searchAddr already does.
// This candidate is always a valid p.searchAddr.
//
// find represents the slow path and the full radix tree search.
//
// Returns a base address of 0 on failure, in which case the candidate
// searchAddr returned is invalid and must be ignored.
//
// p.mheapLock must be held.
func (p *pageAlloc) find(npages uintptr) (uintptr, offAddr) {
	assertLockHeld(p.mheapLock)

	// Search algorithm.
	//
	// This algorithm walks each level l of the radix tree from the root level
	// to the leaf level. It iterates over at most 1 << levelBits[l] of entries
	// in a given level in the radix tree, and uses the summary information to
	// find either:
	//  1) That a given subtree contains a large enough contiguous region, at
	//     which point it continues iterating on the next level, or
	//  2) That there are enough contiguous boundary-crossing bits to satisfy
	//     the allocation, at which point it knows exactly where to start
	//     allocating from.
	//
	// i tracks the index into the current level l's structure for the
	// contiguous 1 << levelBits[l] entries we're actually interested in.
	//
	// NOTE: Technically this search could allocate a region which crosses
	// the arenaBaseOffset boundary, which when arenaBaseOffset != 0, is
	// a discontinuity. However, the only way this could happen is if the
	// page at the zero address is mapped, and this is impossible on
	// every system we support where arenaBaseOffset != 0. So, the
	// discontinuity is already encoded in the fact that the OS will never
	// map the zero page for us, and this function doesn't try to handle
	// this case in any way.

	// i is the beginning of the block of entries we're searching at the
	// current level.
	i := 0

	// firstFree is the region of address space that we are certain to
	// find the first free page in the heap. base and bound are the inclusive
	// bounds of this window, and both are addresses in the linearized, contiguous
	// view of the address space (with arenaBaseOffset pre-added). At each level,
	// this window is narrowed as we find the memory region containing the
	// first free page of memory. To begin with, the range reflects the
	// full process address space.
	//
	// firstFree is updated by calling foundFree each time free space in the
	// heap is discovered.
	//
	// At the end of the search, base.addr() is the best new
	// searchAddr we could deduce in this search.
	firstFree := struct {
		base, bound offAddr
	}{
		base:  minOffAddr,
		bound: maxOffAddr,
	}
	// foundFree takes the given address range [addr, addr+size) and
	// updates firstFree if it is a narrower range. The input range must
	// either be fully contained within firstFree or not overlap with it
	// at all.
	//
	// This way, we'll record the first summary we find with any free
	// pages on the root level and narrow that down if we descend into
	// that summary. But as soon as we need to iterate beyond that summary
	// in a level to find a large enough range, we'll stop narrowing.
	foundFree := func(addr offAddr, size uintptr) {
		if firstFree.base.lessEqual(addr) && addr.add(size-1).lessEqual(firstFree.bound) {
			// This range fits within the current firstFree window, so narrow
			// down the firstFree window to the base and bound of this range.
			firstFree.base = addr
			firstFree.bound = addr.add(size - 1)
		} else if !(addr.add(size-1).lessThan(firstFree.base) || firstFree.bound.lessThan(addr)) {
			// This range only partially overlaps with the firstFree range,
			// so throw.
			print("runtime: addr = ", hex(addr.addr()), ", size = ", size, "\n")
			print("runtime: base = ", hex(firstFree.base.addr()), ", bound = ", hex(firstFree.bound.addr()), "\n")
			throw("range partially overlaps")
		}
	}

	// lastSum is the summary which we saw on the previous level that made us
	// move on to the next level. Used to print additional information in the
	// case of a catastrophic failure.
	// lastSumIdx is that summary's index in the previous level.
	lastSum := packPallocSum(0, 0, 0)
	lastSumIdx := -1

nextLevel:
	for l := 0; l < len(p.summary); l++ {
		// For the root level, entriesPerBlock is the whole level.
		entriesPerBlock := 1 << levelBits[l]
		logMaxPages := levelLogPages[l]

		// We've moved into a new level, so let's update i to our new
		// starting index. This is a no-op for level 0.
		i <<= levelBits[l]

		// Slice out the block of entries we care about.
		entries := p.summary[l][i : i+entriesPerBlock]

		// Determine j0, the first index we should start iterating from.
		// The searchAddr may help us eliminate iterations if we followed the
		// searchAddr on the previous level or we're on the root level, in which
		// case the searchAddr should be the same as i after levelShift.
		j0 := 0
		if searchIdx := offAddrToLevelIndex(l, p.searchAddr); searchIdx&^(entriesPerBlock-1) == i {
			j0 = searchIdx & (entriesPerBlock - 1)
		}

		// Run over the level entries looking for
		// a contiguous run of at least npages either
		// within an entry or across entries.
		//
		// base contains the page index (relative to
		// the first entry's first page) of the currently
		// considered run of consecutive pages.
		//
		// size contains the size of the currently considered
		// run of consecutive pages.
		var base, size uint
		for j := j0; j < len(entries); j++ {
			sum := entries[j]
			if sum == 0 {
				// A full entry means we broke any streak and
				// that we should skip it altogether.
				size = 0
				continue
			}

			// We've encountered a non-zero summary which means
			// free memory, so update firstFree.
			foundFree(levelIndexToOffAddr(l, i+j), (uintptr(1)<<logMaxPages)*pageSize)

			s := sum.start()
			if size+s >= uint(npages) {
				// If size == 0 we don't have a run yet,
				// which means base isn't valid. So, set
				// base to the first page in this block.
				if size == 0 {
					base = uint(j) << logMaxPages
				}
				// We hit npages; we're done!
				size += s
				break
			}
			if sum.max() >= uint(npages) {
				// The entry itself contains npages contiguous
				// free pages, so continue on the next level
				// to find that run.
				i += j
				lastSumIdx = i
				lastSum = sum
				continue nextLevel
			}
			if size == 0 || s < 1<<logMaxPages {
				// We either don't have a current run started, or this entry
				// isn't totally free (meaning we can't continue the current
				// one), so try to begin a new run by setting size and base
				// based on sum.end.
				size = sum.end()
				base = uint(j+1)<<logMaxPages - size
				continue
			}
			// The entry is completely free, so continue the run.
			size += 1 << logMaxPages
		}
		if size >= uint(npages) {
			// We found a sufficiently large run of free pages straddling
			// some boundary, so compute the address and return it.
			addr := levelIndexToOffAddr(l, i).add(uintptr(base) * pageSize).addr()
			return addr, p.findMappedAddr(firstFree.base)
		}
		if l == 0 {
			// We're at level zero, so that means we've exhausted our search.
			return 0, maxSearchAddr()
		}

		// We're not at level zero, and we exhausted the level we were looking in.
		// This means that either our calculations were wrong or the level above
		// lied to us. In either case, dump some useful state and throw.
		print("runtime: summary[", l-1, "][", lastSumIdx, "] = ", lastSum.start(), ", ", lastSum.max(), ", ", lastSum.end(), "\n")
		print("runtime: level = ", l, ", npages = ", npages, ", j0 = ", j0, "\n")
		print("runtime: p.searchAddr = ", hex(p.searchAddr.addr()), ", i = ", i, "\n")
		print("runtime: levelShift[level] = ", levelShift[l], ", levelBits[level] = ", levelBits[l], "\n")
		for j := 0; j < len(entries); j++ {
			sum := entries[j]
			print("runtime: summary[", l, "][", i+j, "] = (", sum.start(), ", ", sum.max(), ", ", sum.end(), ")\n")
		}
		throw("bad summary data")
	}

	// Since we've gotten to this point, that means we haven't found a
	// sufficiently-sized free region straddling some boundary (chunk or larger).
	// This means the last summary we inspected must have had a large enough "max"
	// value, so look inside the chunk to find a suitable run.
	//
	// After iterating over all levels, i must contain a chunk index which
	// is what the final level represents.
	ci := chunkIdx(i)
	j, searchIdx := p.chunkOf(ci).find(npages, 0)
	if j == ^uint(0) {
		// We couldn't find any space in this chunk despite the summaries telling
		// us it should be there. There's likely a bug, so dump some state and throw.
		sum := p.summary[len(p.summary)-1][i]
		print("runtime: summary[", len(p.summary)-1, "][", i, "] = (", sum.start(), ", ", sum.max(), ", ", sum.end(), ")\n")
		print("runtime: npages = ", npages, "\n")
		throw("bad summary data")
	}

	// Compute the address at which the free space starts.
	addr := chunkBase(ci) + uintptr(j)*pageSize

	// Since we actually searched the chunk, we may have
	// found an even narrower free window.
	searchAddr := chunkBase(ci) + uintptr(searchIdx)*pageSize
	foundFree(offAddr{searchAddr}, chunkBase(ci+1)-searchAddr)
	return addr, p.findMappedAddr(firstFree.base)
}

// alloc allocates npages worth of memory from the page heap, returning the base
// address for the
```