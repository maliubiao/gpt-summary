Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Reading and Keyword Spotting:**

The first step is to read through the code, even if you don't understand every line. Look for keywords and patterns that suggest functionality:

* **`mgcscavenge.go` in the path:**  This strongly suggests garbage collection (GC) scavenging related code.
* **`scavenge` and its variations (`scavengeIndex`, `scavChunkData`, `findScavengeCandidate`):**  Confirms the scavenging theme.
* **`pallocData`, `pallocBits`, `pallocChunkPages`:**  Likely related to page allocation. "palloc" probably stands for page allocation.
* **`atomic.Uintptr`, `atomicScavChunkData`:**  Indicates concurrency control and thread-safety.
* **`searchAddrBg`, `searchAddrForce`:** Hints at different scavenging strategies or priorities.
* **`gen` (generation counter):**  Very common in generational garbage collectors.
* **`freeHWM` (free high water mark):**  Suggests tracking free memory boundaries.
* **`piController`:**  A standard control theory component, likely used for regulating some process (like the rate of scavenging).
* **Comments like "TODO"**: Indicate areas of potential future development or known issues.

**2. Focusing on Key Structures and Functions:**

After the initial skim, focus on the main data structures and functions. Try to understand their purpose and how they interact.

* **`pallocData`:** Seems to represent a chunk of memory and track which parts are free and scavenged. `findScavengeCandidate` is the core function here, responsible for finding contiguous free and unscavenged regions. The logic involving `fillAligned` and bit manipulation is about efficiently searching these regions.
* **`scavengeIndex`:** This appears to be the central management structure for scavenging. It keeps track of which chunks are eligible for scavenging (`chunks`), the range of managed memory (`min`, `max`), and uses the `searchAddr` variables to guide the scavenging process. The `find`, `alloc`, and `free` methods suggest how the scavenger interacts with memory allocation and deallocation. The generation counter (`gen`) plays a role in determining scavenging eligibility.
* **`scavChunkData`:**  Holds metadata *per chunk*, like usage information (`inUse`, `lastInUse`) and a flag (`scavChunkFlags`) indicating availability for scavenging. The packing and unpacking functions are for efficient storage within the atomic wrapper.
* **`piController`:**  A separate component. Its methods (`next`, `reset`) and fields (`kp`, `ti`, `tt`) are characteristic of a PI controller.

**3. Inferring Functionality and Purpose:**

Based on the structures and functions, start inferring the broader purpose of the code:

* **Garbage Collection Scavenging:** The core function is to identify and reclaim memory that is no longer in use (garbage). "Scavenging" likely refers to a phase where large blocks of contiguous free memory are identified and potentially made available to the OS or used for other purposes.
* **Memory Management:** The code deals with how memory is divided into chunks and pages, and how the state of these units is tracked (free, allocated, scavenged).
* **Concurrency Control:** The use of `atomic` operations is essential for ensuring that the scavenging process is thread-safe and can operate concurrently with other parts of the runtime (like allocation).
* **Performance Optimization:** Techniques like bit manipulation (`fillAligned`) and the `searchAddr` hints are aimed at making the scavenging process efficient, avoiding unnecessary searching. The handling of huge pages suggests an optimization for large memory allocations.
* **Generational GC:** The `gen` counter and the `lastInUse` field in `scavChunkData` strongly point to a generational garbage collection strategy, where memory is divided into generations and older generations are scavenged less frequently.

**4. Reasoning about Specific Code Blocks (Example: `findScavengeCandidate`):**

For more complex functions, analyze them step by step:

* **Input Parameters:** Understand what the function takes as input (`searchIdx`, `minimum`, `max`).
* **Bit Manipulation:** Realize that the `fillAligned` function and the subsequent bitwise operations are a way to efficiently find contiguous sequences of zero bits (representing free and unscavenged pages).
* **Looping and Searching:** Understand how the backward search works and how it determines the start and end of a candidate region.
* **Huge Page Handling:** Recognize that the code specifically checks for and handles huge page boundaries to avoid breaking them.

**5. Connecting the Dots and Forming a Narrative:**

Once you have a good understanding of the individual components, try to connect them and form a coherent picture of how the scavenging process works. For example:

* The `scavengeIndex` is the brain, coordinating the scavenging.
* `find` finds chunks to scavenge.
* `findScavengeCandidate` within a chunk identifies specific free regions.
* `alloc` and `free` update the metadata, affecting future scavenging decisions.
* The `gen` counter and occupancy information in `scavChunkData` guide which chunks are eligible for scavenging in each GC cycle.
* The `piController` likely regulates the scavenging rate based on some feedback mechanism (though the specific input and output are not directly shown in this snippet).

**6. Addressing Specific Requirements of the Prompt:**

* **Function Listing:**  Straightforward once you understand the code.
* **Go Code Example:** Requires inferring how this code fits into the larger Go runtime. Focus on the likely interactions and the impact of scavenging.
* **Input/Output:**  For code reasoning, you need to make reasonable assumptions about inputs and then trace the code's execution to determine the outputs.
* **Command-Line Arguments:**  This snippet doesn't directly handle command-line arguments, so that part would be skipped.
* **Common Mistakes:** Think about potential race conditions or incorrect state updates that could occur if the concurrency control mechanisms were not in place or were used incorrectly.
* **Summary:**  Condense the key functionalities and the overall purpose of the code.

**Self-Correction/Refinement:**

During the analysis, you might encounter things you don't understand. Go back, reread the code, look up unfamiliar functions or concepts (like PI controllers), and refine your understanding. For example, initially, the exact purpose of `fillAligned` might not be clear, but by examining its implementation and usage, you can infer its role in efficient bitmasking.

This iterative process of reading, identifying key components, inferring functionality, analyzing details, and connecting the dots helps in understanding even complex code snippets.
这是 Go 语言运行时环境的垃圾回收（Garbage Collection，GC）机制中负责内存回收（Scavenging）部分的代码。更具体地说，它涉及到**释放不再使用的内存页，并将其归还给操作系统或供后续分配使用**。

以下是对代码功能的详细归纳：

**核心功能:**

1. **高效查找可回收内存块 (`findScavengeCandidate`)**:
   -  这个函数负责在一个 `pallocData` 结构中查找连续的、空闲且未被回收的内存页区域。
   -  它接收起始搜索索引 (`searchIdx`)、最小大小和对齐要求 (`minimum`) 以及期望的最大大小 (`max`) 作为输入。
   -  它通过高效的位运算（`fillAligned`）来快速跳过已被分配或回收的内存页。
   -  它会考虑最小大小和对齐要求，确保返回的内存块满足这些条件。
   -  它还会尝试避免拆分大页（huge pages），如果发现潜在的拆分，可能会扩大回收区域以包含整个大页。

2. **管理可回收内存块的索引 (`scavengeIndex`)**:
   -  `scavengeIndex` 是一个核心数据结构，用于管理哪些内存块（`palloc` chunk）有可供回收的内存页。
   -  它维护一个 `chunks` 数组，每个元素（`atomicScavChunkData`）记录了对应内存块的占用情况和状态。
   -  通过 `min` 和 `max` 记录了可以安全访问的内存块范围。
   -  使用 `searchAddrBg` 和 `searchAddrForce` 作为搜索的起始地址提示，以优化查找过程。`searchAddrBg` 用于后台回收，`searchAddrForce` 用于强制回收（例如 `debug.FreeOSMemory`）。
   -  `freeHWM` 记录了本轮 GC 中被释放的最高地址，用于指导下一次的回收。
   -  `gen` 是一个代龄计数器，用于区分不同 GC 周期，帮助判断内存块是否可以回收。

3. **跟踪内存块的回收状态 (`scavChunkData`)**:
   -  `scavChunkData` 结构体存储了每个内存块的回收相关信息。
   -  `inUse`：记录了当前内存块中已分配的页数。
   -  `lastInUse`：记录了上一个 GC 周期结束时内存块中已分配的页数。
   -  `gen`：记录了上次更新 `scavChunkData` 时的 GC 代龄。
   -  `scavChunkFlags`：包含一些标志位，例如 `scavChunkHasFree`，指示内存块是否还有空闲页可以回收。

4. **更新内存块状态 (`alloc`, `free`)**:
   -  `alloc` 函数在分配内存时更新 `scavengeIndex` 和 `scavChunkData`，标记内存块的使用情况。
   -  `free` 函数在释放内存时更新 `scavengeIndex` 和 `scavChunkData`，标记内存块的空闲情况，并可能更新 `searchAddrForce`，以便更快地回收刚释放的内存。

5. **推进 GC 代龄 (`nextGen`)**:
   -  `nextGen` 函数在每个 GC 周期结束时被调用，用于更新 `scavengeIndex` 的代龄计数器 `gen`，并根据本轮释放的内存情况更新 `searchAddrBg`。

6. **标记内存块为空 (`setEmpty`)**:
   -  `setEmpty` 函数用于标记一个内存块当前没有可回收的内存，避免回收器重复检查。

7. **PID 控制器 (`piController`)**:
   -  实现了一个标准的比例-积分（PI）控制器。
   -  这个控制器可能用于调节内存回收的速率，根据某些指标（例如内存使用量）来动态调整回收的力度。

**Go 代码示例 (推断 `findScavengeCandidate` 的使用场景):**

假设我们有一个 `pallocData` 类型的变量 `pd`，代表一块内存区域。我们想要找到一块至少包含 4 页，并且是 4 页对齐的空闲且未回收的内存块，并期望找到尽可能大的块。

```go
package main

import (
	"fmt"
	"runtime"
	_ "unsafe" // for go:linkname

	"internal/abi"
	"internal/goarch"
	"internal/goos"
	"internal/sys"
)

// 假设 pallocData 和相关结构体的定义在其他地方，这里只做类型声明
type pallocData struct {
	scavenged  []uint64
	pallocBits []uint64
}

const (
	pageSize            = 8192 // 假设页大小为 8KB
	pallocChunkPages    = 512  // 假设一个 chunk 包含 512 页
	maxPagesPerPhysPage = 256  // 假设最大物理页大小
)

//go:linkname alignUp runtime.alignUp
func alignUp(ptr uintptr, align uintptr) uintptr

func main() {
	// 模拟一个 pallocData 结构，实际场景中会由 runtime 管理
	pd := pallocData{
		scavenged:  make([]uint64, pallocChunkPages/64),
		pallocBits: make([]uint64, pallocChunkPages/64),
	}

	// 假设有一些内存被分配和回收，这里简单模拟一下，
	// 例如，将前 64 页标记为已回收
	for i := 0; i < 1; i++ {
		pd.scavenged[i] = ^uint64(0)
	}

	// 设置查找参数
	searchIdx := uint(pallocChunkPages) // 从末尾开始搜索
	minPages := uintptr(4)
	maxPages := uintptr(pallocChunkPages)

	// 调用 findScavengeCandidate 查找可回收的内存块
	startIdx, size := pd.findScavengeCandidate(searchIdx, minPages, maxPages)

	if size > 0 {
		fmt.Printf("找到可回收内存块：起始页索引 = %d, 大小 = %d 页\n", startIdx, size)
	} else {
		fmt.Println("未找到符合条件的可回收内存块")
	}
}

func (m *pallocData) findScavengeCandidate(searchIdx uint, minimum, max uintptr) (uint, uint) {
	if minimum&(minimum-1) != 0 || minimum == 0 {
		print("runtime: min = ", minimum, "\n")
		panic("min must be a non-zero power of 2")
	} else if minimum > maxPagesPerPhysPage {
		print("runtime: min = ", minimum, "\n")
		panic("min too large")
	}
	if max == 0 {
		max = minimum
	} else {
		max = alignUp(max, minimum)
	}

	i := int(searchIdx / 64)
	for ; i >= 0; i-- {
		x := fillAligned(m.scavenged[i]|m.pallocBits[i], uint(minimum))
		if x != ^uint64(0) {
			break
		}
	}
	if i < 0 {
		return 0, 0
	}
	x := fillAligned(m.scavenged[i]|m.pallocBits[i], uint(minimum))
	z1 := uint(sys.LeadingZeros64(^x))
	run, end := uint(0), uint(i)*64+(64-z1)
	if x<<z1 != 0 {
		run = uint(sys.LeadingZeros64(x << z1))
	} else {
		run = 64 - z1
		for j := i - 1; j >= 0; j-- {
			x := fillAligned(m.scavenged[j]|m.pallocBits[j], uint(minimum))
			run += uint(sys.LeadingZeros64(x))
			if x != 0 {
				break
			}
		}
	}

	size := min(run, uint(max))
	start := end - size

	return start, size
}

//go:linkname fillAligned runtime.fillAligned
func fillAligned(x uint64, m uint) uint64

func min(a, b uint) uint {
	if a < b {
		return a
	}
	return b
}
```

**假设的输入与输出：**

- **假设输入:**
    - `pd.scavenged` 的前 64 位都被设置为 1 (表示前 64 页已回收)。
    - `searchIdx` = `pallocChunkPages` (从末尾开始搜索)。
    - `minimum` = 4 (最小 4 页)。
    - `max` = `pallocChunkPages` (期望尽可能大)。
- **预期输出:**
    - `startIdx` 接近 0 (因为前 64 页已被回收)。
    - `size` 可能是一个较大的值，取决于后续未被分配的连续页数。例如，如果接下来的内存都是空闲的，`size` 可能会接近 `pallocChunkPages - 64`。

**命令行参数：**

这段代码本身不直接处理命令行参数。垃圾回收的参数通常通过环境变量（例如 `GOGC`）或 runtime 包的函数来配置。

**使用者易犯错的点：**

这段代码是 Go 运行时环境的一部分，普通 Go 开发者不会直接使用这些函数。但是，理解其背后的原理有助于理解 Go 的内存管理和性能特性。

**总结 (第 2 部分功能归纳):**

这段代码是 Go 运行时垃圾回收机制中**内存回收（Scavenging）**的关键组成部分。它负责：

- **高效地识别和定位连续的、空闲且未被回收的内存页块。**
- **维护和更新内存块的回收状态信息。**
- **管理可回收内存块的索引，以便快速找到潜在的回收目标。**
- **通过 PID 控制器等机制，可能实现对内存回收速率的动态调节。**

总而言之，这段代码的目标是**将不再使用的内存归还给系统或为未来的分配做准备，从而提高内存利用率和程序性能。** 它体现了 Go 运行时在内存管理方面的精细控制和优化。

Prompt: 
```
这是路径为go/src/runtime/mgcscavenge.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
y(x, 0x7fffffffffffffff)
	default:
		throw("bad m value")
	}
	// Now, the top bit of each m-aligned group in x is set
	// that group was all zero in the original x.

	// From each group of m bits subtract 1.
	// Because we know only the top bits of each
	// m-aligned group are set, we know this will
	// set each group to have all the bits set except
	// the top bit, so just OR with the original
	// result to set all the bits.
	return ^((x - (x >> (m - 1))) | x)
}

// findScavengeCandidate returns a start index and a size for this pallocData
// segment which represents a contiguous region of free and unscavenged memory.
//
// searchIdx indicates the page index within this chunk to start the search, but
// note that findScavengeCandidate searches backwards through the pallocData. As
// a result, it will return the highest scavenge candidate in address order.
//
// min indicates a hard minimum size and alignment for runs of pages. That is,
// findScavengeCandidate will not return a region smaller than min pages in size,
// or that is min pages or greater in size but not aligned to min. min must be
// a non-zero power of 2 <= maxPagesPerPhysPage.
//
// max is a hint for how big of a region is desired. If max >= pallocChunkPages, then
// findScavengeCandidate effectively returns entire free and unscavenged regions.
// If max < pallocChunkPages, it may truncate the returned region such that size is
// max. However, findScavengeCandidate may still return a larger region if, for
// example, it chooses to preserve huge pages, or if max is not aligned to min (it
// will round up). That is, even if max is small, the returned size is not guaranteed
// to be equal to max. max is allowed to be less than min, in which case it is as if
// max == min.
func (m *pallocData) findScavengeCandidate(searchIdx uint, minimum, max uintptr) (uint, uint) {
	if minimum&(minimum-1) != 0 || minimum == 0 {
		print("runtime: min = ", minimum, "\n")
		throw("min must be a non-zero power of 2")
	} else if minimum > maxPagesPerPhysPage {
		print("runtime: min = ", minimum, "\n")
		throw("min too large")
	}
	// max may not be min-aligned, so we might accidentally truncate to
	// a max value which causes us to return a non-min-aligned value.
	// To prevent this, align max up to a multiple of min (which is always
	// a power of 2). This also prevents max from ever being less than
	// min, unless it's zero, so handle that explicitly.
	if max == 0 {
		max = minimum
	} else {
		max = alignUp(max, minimum)
	}

	i := int(searchIdx / 64)
	// Start by quickly skipping over blocks of non-free or scavenged pages.
	for ; i >= 0; i-- {
		// 1s are scavenged OR non-free => 0s are unscavenged AND free
		x := fillAligned(m.scavenged[i]|m.pallocBits[i], uint(minimum))
		if x != ^uint64(0) {
			break
		}
	}
	if i < 0 {
		// Failed to find any free/unscavenged pages.
		return 0, 0
	}
	// We have something in the 64-bit chunk at i, but it could
	// extend further. Loop until we find the extent of it.

	// 1s are scavenged OR non-free => 0s are unscavenged AND free
	x := fillAligned(m.scavenged[i]|m.pallocBits[i], uint(minimum))
	z1 := uint(sys.LeadingZeros64(^x))
	run, end := uint(0), uint(i)*64+(64-z1)
	if x<<z1 != 0 {
		// After shifting out z1 bits, we still have 1s,
		// so the run ends inside this word.
		run = uint(sys.LeadingZeros64(x << z1))
	} else {
		// After shifting out z1 bits, we have no more 1s.
		// This means the run extends to the bottom of the
		// word so it may extend into further words.
		run = 64 - z1
		for j := i - 1; j >= 0; j-- {
			x := fillAligned(m.scavenged[j]|m.pallocBits[j], uint(minimum))
			run += uint(sys.LeadingZeros64(x))
			if x != 0 {
				// The run stopped in this word.
				break
			}
		}
	}

	// Split the run we found if it's larger than max but hold on to
	// our original length, since we may need it later.
	size := min(run, uint(max))
	start := end - size

	// Each huge page is guaranteed to fit in a single palloc chunk.
	//
	// TODO(mknyszek): Support larger huge page sizes.
	// TODO(mknyszek): Consider taking pages-per-huge-page as a parameter
	// so we can write tests for this.
	if physHugePageSize > pageSize && physHugePageSize > physPageSize {
		// We have huge pages, so let's ensure we don't break one by scavenging
		// over a huge page boundary. If the range [start, start+size) overlaps with
		// a free-and-unscavenged huge page, we want to grow the region we scavenge
		// to include that huge page.

		// Compute the huge page boundary above our candidate.
		pagesPerHugePage := physHugePageSize / pageSize
		hugePageAbove := uint(alignUp(uintptr(start), pagesPerHugePage))

		// If that boundary is within our current candidate, then we may be breaking
		// a huge page.
		if hugePageAbove <= end {
			// Compute the huge page boundary below our candidate.
			hugePageBelow := uint(alignDown(uintptr(start), pagesPerHugePage))

			if hugePageBelow >= end-run {
				// We're in danger of breaking apart a huge page since start+size crosses
				// a huge page boundary and rounding down start to the nearest huge
				// page boundary is included in the full run we found. Include the entire
				// huge page in the bound by rounding down to the huge page size.
				size = size + (start - hugePageBelow)
				start = hugePageBelow
			}
		}
	}
	return start, size
}

// scavengeIndex is a structure for efficiently managing which pageAlloc chunks have
// memory available to scavenge.
type scavengeIndex struct {
	// chunks is a scavChunkData-per-chunk structure that indicates the presence of pages
	// available for scavenging. Updates to the index are serialized by the pageAlloc lock.
	//
	// It tracks chunk occupancy and a generation counter per chunk. If a chunk's occupancy
	// never exceeds pallocChunkDensePages over the course of a single GC cycle, the chunk
	// becomes eligible for scavenging on the next cycle. If a chunk ever hits this density
	// threshold it immediately becomes unavailable for scavenging in the current cycle as
	// well as the next.
	//
	// [min, max) represents the range of chunks that is safe to access (i.e. will not cause
	// a fault). As an optimization minHeapIdx represents the true minimum chunk that has been
	// mapped, since min is likely rounded down to include the system page containing minHeapIdx.
	//
	// For a chunk size of 4 MiB this structure will only use 2 MiB for a 1 TiB contiguous heap.
	chunks     []atomicScavChunkData
	min, max   atomic.Uintptr
	minHeapIdx atomic.Uintptr

	// searchAddr* is the maximum address (in the offset address space, so we have a linear
	// view of the address space; see mranges.go:offAddr) containing memory available to
	// scavenge. It is a hint to the find operation to avoid O(n^2) behavior in repeated lookups.
	//
	// searchAddr* is always inclusive and should be the base address of the highest runtime
	// page available for scavenging.
	//
	// searchAddrForce is managed by find and free.
	// searchAddrBg is managed by find and nextGen.
	//
	// Normally, find monotonically decreases searchAddr* as it finds no more free pages to
	// scavenge. However, mark, when marking a new chunk at an index greater than the current
	// searchAddr, sets searchAddr to the *negative* index into chunks of that page. The trick here
	// is that concurrent calls to find will fail to monotonically decrease searchAddr*, and so they
	// won't barge over new memory becoming available to scavenge. Furthermore, this ensures
	// that some future caller of find *must* observe the new high index. That caller
	// (or any other racing with it), then makes searchAddr positive before continuing, bringing
	// us back to our monotonically decreasing steady-state.
	//
	// A pageAlloc lock serializes updates between min, max, and searchAddr, so abs(searchAddr)
	// is always guaranteed to be >= min and < max (converted to heap addresses).
	//
	// searchAddrBg is increased only on each new generation and is mainly used by the
	// background scavenger and heap-growth scavenging. searchAddrForce is increased continuously
	// as memory gets freed and is mainly used by eager memory reclaim such as debug.FreeOSMemory
	// and scavenging to maintain the memory limit.
	searchAddrBg    atomicOffAddr
	searchAddrForce atomicOffAddr

	// freeHWM is the highest address (in offset address space) that was freed
	// this generation.
	freeHWM offAddr

	// Generation counter. Updated by nextGen at the end of each mark phase.
	gen uint32

	// test indicates whether or not we're in a test.
	test bool
}

// init initializes the scavengeIndex.
//
// Returns the amount added to sysStat.
func (s *scavengeIndex) init(test bool, sysStat *sysMemStat) uintptr {
	s.searchAddrBg.Clear()
	s.searchAddrForce.Clear()
	s.freeHWM = minOffAddr
	s.test = test
	return s.sysInit(test, sysStat)
}

// sysGrow updates the index's backing store in response to a heap growth.
//
// Returns the amount of memory added to sysStat.
func (s *scavengeIndex) grow(base, limit uintptr, sysStat *sysMemStat) uintptr {
	// Update minHeapIdx. Note that even if there's no mapping work to do,
	// we may still have a new, lower minimum heap address.
	minHeapIdx := s.minHeapIdx.Load()
	if baseIdx := uintptr(chunkIndex(base)); minHeapIdx == 0 || baseIdx < minHeapIdx {
		s.minHeapIdx.Store(baseIdx)
	}
	return s.sysGrow(base, limit, sysStat)
}

// find returns the highest chunk index that may contain pages available to scavenge.
// It also returns an offset to start searching in the highest chunk.
func (s *scavengeIndex) find(force bool) (chunkIdx, uint) {
	cursor := &s.searchAddrBg
	if force {
		cursor = &s.searchAddrForce
	}
	searchAddr, marked := cursor.Load()
	if searchAddr == minOffAddr.addr() {
		// We got a cleared search addr.
		return 0, 0
	}

	// Starting from searchAddr's chunk, iterate until we find a chunk with pages to scavenge.
	gen := s.gen
	min := chunkIdx(s.minHeapIdx.Load())
	start := chunkIndex(searchAddr)
	// N.B. We'll never map the 0'th chunk, so minHeapIdx ensures this loop overflow.
	for i := start; i >= min; i-- {
		// Skip over chunks.
		if !s.chunks[i].load().shouldScavenge(gen, force) {
			continue
		}
		// We're still scavenging this chunk.
		if i == start {
			return i, chunkPageIndex(searchAddr)
		}
		// Try to reduce searchAddr to newSearchAddr.
		newSearchAddr := chunkBase(i) + pallocChunkBytes - pageSize
		if marked {
			// Attempt to be the first one to decrease the searchAddr
			// after an increase. If we fail, that means there was another
			// increase, or somebody else got to it before us. Either way,
			// it doesn't matter. We may lose some performance having an
			// incorrect search address, but it's far more important that
			// we don't miss updates.
			cursor.StoreUnmark(searchAddr, newSearchAddr)
		} else {
			// Decrease searchAddr.
			cursor.StoreMin(newSearchAddr)
		}
		return i, pallocChunkPages - 1
	}
	// Clear searchAddr, because we've exhausted the heap.
	cursor.Clear()
	return 0, 0
}

// alloc updates metadata for chunk at index ci with the fact that
// an allocation of npages occurred. It also eagerly attempts to collapse
// the chunk's memory into hugepage if the chunk has become sufficiently
// dense and we're not allocating the whole chunk at once (which suggests
// the allocation is part of a bigger one and it's probably not worth
// eagerly collapsing).
//
// alloc may only run concurrently with find.
func (s *scavengeIndex) alloc(ci chunkIdx, npages uint) {
	sc := s.chunks[ci].load()
	sc.alloc(npages, s.gen)
	// TODO(mknyszek): Consider eagerly backing memory with huge pages
	// here and track whether we believe this chunk is backed by huge pages.
	// In the past we've attempted to use sysHugePageCollapse (which uses
	// MADV_COLLAPSE on Linux, and is unsupported elswhere) for this purpose,
	// but that caused performance issues in production environments.
	s.chunks[ci].store(sc)
}

// free updates metadata for chunk at index ci with the fact that
// a free of npages occurred.
//
// free may only run concurrently with find.
func (s *scavengeIndex) free(ci chunkIdx, page, npages uint) {
	sc := s.chunks[ci].load()
	sc.free(npages, s.gen)
	s.chunks[ci].store(sc)

	// Update scavenge search addresses.
	addr := chunkBase(ci) + uintptr(page+npages-1)*pageSize
	if s.freeHWM.lessThan(offAddr{addr}) {
		s.freeHWM = offAddr{addr}
	}
	// N.B. Because free is serialized, it's not necessary to do a
	// full CAS here. free only ever increases searchAddr, while
	// find only ever decreases it. Since we only ever race with
	// decreases, even if the value we loaded is stale, the actual
	// value will never be larger.
	searchAddr, _ := s.searchAddrForce.Load()
	if (offAddr{searchAddr}).lessThan(offAddr{addr}) {
		s.searchAddrForce.StoreMarked(addr)
	}
}

// nextGen moves the scavenger forward one generation. Must be called
// once per GC cycle, but may be called more often to force more memory
// to be released.
//
// nextGen may only run concurrently with find.
func (s *scavengeIndex) nextGen() {
	s.gen++
	searchAddr, _ := s.searchAddrBg.Load()
	if (offAddr{searchAddr}).lessThan(s.freeHWM) {
		s.searchAddrBg.StoreMarked(s.freeHWM.addr())
	}
	s.freeHWM = minOffAddr
}

// setEmpty marks that the scavenger has finished looking at ci
// for now to prevent the scavenger from getting stuck looking
// at the same chunk.
//
// setEmpty may only run concurrently with find.
func (s *scavengeIndex) setEmpty(ci chunkIdx) {
	val := s.chunks[ci].load()
	val.setEmpty()
	s.chunks[ci].store(val)
}

// atomicScavChunkData is an atomic wrapper around a scavChunkData
// that stores it in its packed form.
type atomicScavChunkData struct {
	value atomic.Uint64
}

// load loads and unpacks a scavChunkData.
func (sc *atomicScavChunkData) load() scavChunkData {
	return unpackScavChunkData(sc.value.Load())
}

// store packs and writes a new scavChunkData. store must be serialized
// with other calls to store.
func (sc *atomicScavChunkData) store(ssc scavChunkData) {
	sc.value.Store(ssc.pack())
}

// scavChunkData tracks information about a palloc chunk for
// scavenging. It packs well into 64 bits.
//
// The zero value always represents a valid newly-grown chunk.
type scavChunkData struct {
	// inUse indicates how many pages in this chunk are currently
	// allocated.
	//
	// Only the first 10 bits are used.
	inUse uint16

	// lastInUse indicates how many pages in this chunk were allocated
	// when we transitioned from gen-1 to gen.
	//
	// Only the first 10 bits are used.
	lastInUse uint16

	// gen is the generation counter from a scavengeIndex from the
	// last time this scavChunkData was updated.
	gen uint32

	// scavChunkFlags represents additional flags
	//
	// Note: only 6 bits are available.
	scavChunkFlags
}

// unpackScavChunkData unpacks a scavChunkData from a uint64.
func unpackScavChunkData(sc uint64) scavChunkData {
	return scavChunkData{
		inUse:          uint16(sc),
		lastInUse:      uint16(sc>>16) & scavChunkInUseMask,
		gen:            uint32(sc >> 32),
		scavChunkFlags: scavChunkFlags(uint8(sc>>(16+logScavChunkInUseMax)) & scavChunkFlagsMask),
	}
}

// pack returns sc packed into a uint64.
func (sc scavChunkData) pack() uint64 {
	return uint64(sc.inUse) |
		(uint64(sc.lastInUse) << 16) |
		(uint64(sc.scavChunkFlags) << (16 + logScavChunkInUseMax)) |
		(uint64(sc.gen) << 32)
}

const (
	// scavChunkHasFree indicates whether the chunk has anything left to
	// scavenge. This is the opposite of "empty," used elsewhere in this
	// file. The reason we say "HasFree" here is so the zero value is
	// correct for a newly-grown chunk. (New memory is scavenged.)
	scavChunkHasFree scavChunkFlags = 1 << iota

	// scavChunkMaxFlags is the maximum number of flags we can have, given how
	// a scavChunkData is packed into 8 bytes.
	scavChunkMaxFlags  = 6
	scavChunkFlagsMask = (1 << scavChunkMaxFlags) - 1

	// logScavChunkInUseMax is the number of bits needed to represent the number
	// of pages allocated in a single chunk. This is 1 more than log2 of the
	// number of pages in the chunk because we need to represent a fully-allocated
	// chunk.
	logScavChunkInUseMax = logPallocChunkPages + 1
	scavChunkInUseMask   = (1 << logScavChunkInUseMax) - 1
)

// scavChunkFlags is a set of bit-flags for the scavenger for each palloc chunk.
type scavChunkFlags uint8

// isEmpty returns true if the hasFree flag is unset.
func (sc *scavChunkFlags) isEmpty() bool {
	return (*sc)&scavChunkHasFree == 0
}

// setEmpty clears the hasFree flag.
func (sc *scavChunkFlags) setEmpty() {
	*sc &^= scavChunkHasFree
}

// setNonEmpty sets the hasFree flag.
func (sc *scavChunkFlags) setNonEmpty() {
	*sc |= scavChunkHasFree
}

// shouldScavenge returns true if the corresponding chunk should be interrogated
// by the scavenger.
func (sc scavChunkData) shouldScavenge(currGen uint32, force bool) bool {
	if sc.isEmpty() {
		// Nothing to scavenge.
		return false
	}
	if force {
		// We're forcing the memory to be scavenged.
		return true
	}
	if sc.gen == currGen {
		// In the current generation, if either the current or last generation
		// is dense, then skip scavenging. Inverting that, we should scavenge
		// if both the current and last generation were not dense.
		return sc.inUse < scavChunkHiOccPages && sc.lastInUse < scavChunkHiOccPages
	}
	// If we're one or more generations ahead, we know inUse represents the current
	// state of the chunk, since otherwise it would've been updated already.
	return sc.inUse < scavChunkHiOccPages
}

// alloc updates sc given that npages were allocated in the corresponding chunk.
func (sc *scavChunkData) alloc(npages uint, newGen uint32) {
	if uint(sc.inUse)+npages > pallocChunkPages {
		print("runtime: inUse=", sc.inUse, " npages=", npages, "\n")
		throw("too many pages allocated in chunk?")
	}
	if sc.gen != newGen {
		sc.lastInUse = sc.inUse
		sc.gen = newGen
	}
	sc.inUse += uint16(npages)
	if sc.inUse == pallocChunkPages {
		// There's nothing for the scavenger to take from here.
		sc.setEmpty()
	}
}

// free updates sc given that npages was freed in the corresponding chunk.
func (sc *scavChunkData) free(npages uint, newGen uint32) {
	if uint(sc.inUse) < npages {
		print("runtime: inUse=", sc.inUse, " npages=", npages, "\n")
		throw("allocated pages below zero?")
	}
	if sc.gen != newGen {
		sc.lastInUse = sc.inUse
		sc.gen = newGen
	}
	sc.inUse -= uint16(npages)
	// The scavenger can no longer be done with this chunk now that
	// new memory has been freed into it.
	sc.setNonEmpty()
}

type piController struct {
	kp float64 // Proportional constant.
	ti float64 // Integral time constant.
	tt float64 // Reset time.

	min, max float64 // Output boundaries.

	// PI controller state.

	errIntegral float64 // Integral of the error from t=0 to now.

	// Error flags.
	errOverflow   bool // Set if errIntegral ever overflowed.
	inputOverflow bool // Set if an operation with the input overflowed.
}

// next provides a new sample to the controller.
//
// input is the sample, setpoint is the desired point, and period is how much
// time (in whatever unit makes the most sense) has passed since the last sample.
//
// Returns a new value for the variable it's controlling, and whether the operation
// completed successfully. One reason this might fail is if error has been growing
// in an unbounded manner, to the point of overflow.
//
// In the specific case of an error overflow occurs, the errOverflow field will be
// set and the rest of the controller's internal state will be fully reset.
func (c *piController) next(input, setpoint, period float64) (float64, bool) {
	// Compute the raw output value.
	prop := c.kp * (setpoint - input)
	rawOutput := prop + c.errIntegral

	// Clamp rawOutput into output.
	output := rawOutput
	if isInf(output) || isNaN(output) {
		// The input had a large enough magnitude that either it was already
		// overflowed, or some operation with it overflowed.
		// Set a flag and reset. That's the safest thing to do.
		c.reset()
		c.inputOverflow = true
		return c.min, false
	}
	if output < c.min {
		output = c.min
	} else if output > c.max {
		output = c.max
	}

	// Update the controller's state.
	if c.ti != 0 && c.tt != 0 {
		c.errIntegral += (c.kp*period/c.ti)*(setpoint-input) + (period/c.tt)*(output-rawOutput)
		if isInf(c.errIntegral) || isNaN(c.errIntegral) {
			// So much error has accumulated that we managed to overflow.
			// The assumptions around the controller have likely broken down.
			// Set a flag and reset. That's the safest thing to do.
			c.reset()
			c.errOverflow = true
			return c.min, false
		}
	}
	return output, true
}

// reset resets the controller state, except for controller error flags.
func (c *piController) reset() {
	c.errIntegral = 0
}

"""




```