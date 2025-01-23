Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The main goal is to analyze the provided Go code snippet (the beginning of `runtime/malloc.go`) and explain its function, illustrate its usage, identify potential pitfalls, and summarize its role. The request explicitly mentions it's the *first* part of a larger file, so the summary should focus on the functions and data structures defined in this segment.

2. **Initial Scan and Keyword Recognition:** I quickly scan the code for key terms and concepts related to memory management. "allocator," "heap," "size classes," "spans," "caches," "mheap," "mspan," "mcache," "arenas," and "virtual memory layout" immediately jump out. These words indicate the core functionality revolves around allocating and managing memory within the Go runtime.

3. **Break Down the Code into Logical Sections:**  I mentally divide the code into its main components:
    * **Copyright and Overview Comments:** These provide a high-level description of the file's purpose and its origins (tcmalloc).
    * **Data Structures (Implicit):** The comments mention key data structures (fixalloc, mheap, mspan, etc.). While not explicitly defined in this snippet, their purpose is described.
    * **Constants:** A large block of `const` definitions. These are crucial for understanding the sizing and organization of the memory allocator.
    * **Global Variables:** `physPageSize`, `physHugePageSize`, and `physHugePageShift`. These indicate interaction with the operating system.
    * **`mallocinit()` function:** This function clearly initializes the memory allocator.
    * **`sysAlloc()` function:** This function is responsible for allocating large chunks of memory from the operating system.
    * **`sysReserveAligned()` function:** This function is related to reserving memory.

4. **Analyze Each Section and Extract Information:**

    * **Comments:** I read the overview comments carefully. They outline the tiered allocation strategy (mcache -> mcentral -> mheap -> OS), the handling of small and large objects, and the sweeping process. The virtual memory layout section introduces the concept of arenas.

    * **Constants:** I examine the constants, paying attention to their names and values. I group them logically:
        * **Size-related:** `maxTinySize`, `tinySizeClass`, `maxSmallSize`, `pageSize`, `pageShift`.
        * **Architecture-related:** `_64bit`, `heapAddrBits`.
        * **Tiny allocator related:** `_TinySize`, `_TinySizeClass`.
        * **Stack cache related:** `_StackCacheSize`, `_NumStackOrders`.
        * **Arena related:** `heapArenaBytes`, `logHeapArenaBytes`, `pagesPerArena`, `arenaL1Bits`, `arenaL2Bits`, `arenaBaseOffset`.
        * **GC related:** `_MaxGcproc`.
        * **Pointer related:** `minLegalPointer`.
        * **Huge page related:** `minHeapForMetadataHugePages`.
        * I recognize that these constants define the fundamental parameters of the memory management system.

    * **Global Variables:** I note that `physPageSize` and `physHugePageSize` are obtained from the OS, indicating interaction with the underlying system.

    * **`mallocinit()`:** I understand this is the initialization function. Key actions include:
        * Basic sanity checks.
        * Heap initialization (`mheap_.init()`).
        * MCache allocation (`allocmcache()`).
        * Lock initialization.
        * Setting up initial arena growth hints, often starting in the middle of the address space on 64-bit systems to avoid conflicts.
        * Handling 32-bit initialization differently, reserving space for heap metadata.
        * Initializing the memory limit.

    * **`sysAlloc()`:** This is the core function for getting memory from the OS. I note its arguments (size, hints, registration), its responsibility for aligning memory, creating arena metadata, and updating hints. The handling of `raceenabled` is also important.

    * **`sysReserveAligned()`:**  I see it's similar to `sysAlloc` but focuses on reserving memory with a specific alignment.

5. **Infer Go Language Features and Provide Examples:** Based on the identified functionality, I connect it to core Go concepts:

    * **Memory Allocation:** This is the obvious one. I think about how `new()` and `make()` use the underlying allocator.
    * **Garbage Collection:**  The comments about sweeping and the `mstats` data structure hint at the GC's interaction with this code.
    * **Concurrency (implicitly):** The presence of `mcache` (per-P cache) and the discussion of locks suggest that the allocator is designed to be efficient in concurrent scenarios.
    * **Operating System Interaction:** `sysReserve`, `sysFreeOS`, `physPageSize`, `physHugePageSize` clearly show interaction with the OS for memory management.

    I then construct simple Go code examples to illustrate how `new` and `make` trigger the underlying allocation mechanisms described in the code.

6. **Identify Potential Pitfalls:** I consider common mistakes related to memory management in Go:

    * **Memory Leaks (though Go's GC mitigates this):**  While the GC helps, holding onto references unnecessarily can still lead to high memory usage.
    * **Incorrect Size Calculations:**  Misunderstanding the size requirements for data structures can lead to inefficient allocation.
    * **Ignoring Performance Implications:**  While the allocator is optimized, excessively large allocations or very frequent small allocations *can* impact performance.

7. **Address Command-Line Parameters and Assumptions:**  I recognize that this code snippet doesn't directly handle command-line parameters. However, I can mention that flags like `-gcflags` can influence the GC and potentially indirectly affect allocator behavior. I also highlight the assumptions about OS page size.

8. **Summarize the Functionality (Part 1):** I synthesize the information gathered into a concise summary, focusing on the components and functions present in *this specific snippet*. I emphasize the core concepts of tiered allocation, handling small and large objects, arena management, and the initialization process.

9. **Review and Refine:** I read through my answer to ensure clarity, accuracy, and completeness, addressing all parts of the original request. I double-check that the examples are correct and the explanations are easy to understand. I make sure the summary accurately reflects the content of the provided code.
这是一个 Go 语言运行时（runtime）包中 `malloc.go` 文件的一部分，主要负责**内存分配**的核心功能。

**功能归纳（针对提供的第 1 部分）：**

1. **定义了内存分配器的基本架构和数据结构:**  描述了 Go 语言内存分配器如何组织和管理内存，包括 `fixalloc`（固定大小分配器）、`mheap`（堆）、`mspan`（内存页的运行单元）、`mcentral`（特定大小类的 span 集合）、`mcache`（每个 P 的 span 缓存）和 `mstats`（分配统计信息）。
2. **阐述了小对象的分配流程:**  详细说明了分配小于等于 32KB 的小对象时，如何通过 `mcache` -> `mcentral` -> `mheap` -> 操作系统逐级查找和分配空闲内存的过程，以及使用 free bitmap 管理对象。
3. **描述了 mspan 的回收流程:**  解释了如何将 sweep 过的 mspan 返回到 `mcache` 或 `mcentral` 的空闲列表，或者将完全空闲的 mspan 释放回 `mheap`。
4. **指出了大对象的分配方式:** 说明了大于 32KB 的大对象会直接通过 `mheap` 进行分配，绕过 `mcache` 和 `mcentral`。
5. **介绍了延迟清零的机制:** 解释了 `mspan.needzero` 的作用，以及延迟清零的好处，例如避免不必要的清零，提高时间局部性等。
6. **定义了虚拟内存布局:** 详细描述了堆内存的组织方式，包括 `arena`（内存区域）、`heapArena`（arena 的元数据）、`arena map`（映射 arena 帧号到 `heapArena`）等概念，以及它们在 32 位和 64 位系统上的差异。
7. **声明了大量的常量:**  定义了与内存分配相关的各种常量，例如最大小对象大小、页大小、arena 大小、各种缓存大小、地址位数等等，这些常量决定了内存分配器的行为和限制。
8. **声明了与操作系统交互的全局变量:** 声明了 `physPageSize` 和 `physHugePageSize`，用于获取操作系统的物理页大小和巨页大小，表明了内存分配器需要与操作系统进行交互。
9. **实现了内存分配器的初始化函数 `mallocinit()`:** 负责初始化内存分配器的各种组件，包括检查配置、初始化 `mheap`、分配初始 `mcache`、初始化锁、创建初始 arena 增长提示等。
10. **实现了系统级别的内存分配函数 `sysAlloc()`:**  负责从操作系统层面分配大块内存（以 `heapArenaBytes` 对齐），并创建相应的 arena 元数据。
11. **实现了系统级别的对齐内存预留函数 `sysReserveAligned()`:** 类似于 `sysAlloc`，但可以保证分配的内存按照指定的字节数对齐。

**尝试推理 Go 语言功能并举例说明:**

这部分代码是 Go 语言**内存管理**功能的核心实现。它支撑着 Go 程序中所有动态内存的分配和回收。

**示例： 小对象的分配**

假设我们有以下 Go 代码：

```go
package main

func main() {
	// 分配一个小整数
	x := new(int)
	*x = 10

	// 分配一个小的切片
	s := make([]int, 5)
	s[0] = 1
}
```

**推理过程：**

1. 当执行 `new(int)` 时，Go 编译器会确定 `int` 的大小（通常是 4 或 8 字节）。
2. 这个大小会被向上取整到某个预定义的**大小类**（size class），例如可能是 8 字节。
3. Go 运行时会首先查看当前 Goroutine 关联的 **mcache** 中是否有对应大小类的 **mspan** 存在空闲的 slot。
4. 如果 **mcache** 中存在可用的 mspan 和 slot，则直接分配并返回内存地址，无需加锁。
5. 如果 **mcache** 中没有可用的 mspan，则会从 **mcentral** 获取一个新的包含空闲 slot 的 mspan。这个过程可能需要加锁。
6. 如果 **mcentral** 也没有可用的 mspan，则 **mheap** 会分配新的页，并将其划分成对应大小类的对象，创建一个新的 mspan。
7. 如果 **mheap** 没有足够的内存，则会向操作系统请求更大的内存块（通常是 1MB 或更大）。

**假设的输入与输出：**

* **假设输入:**  执行 `new(int)`，`int` 大小为 8 字节。假设当前 Goroutine 的 `mcache` 中没有 8 字节大小类的空闲 mspan。
* **假设输出:**  `new(int)` 返回一个指向新分配的 8 字节内存的指针。Go 运行时可能从 `mcentral` 获取了一个新的 mspan，该 mspan 由 `mheap` 分配的页分割而成。

**示例： 大对象的分配**

假设我们有以下 Go 代码：

```go
package main

func main() {
	// 分配一个较大的切片
	largeSlice := make([]byte, 100000) // 100KB
	largeSlice[0] = 'A'
}
```

**推理过程：**

1. 当执行 `make([]byte, 100000)` 时，Go 编译器会确定需要分配 100KB 的内存。
2. 由于 100KB 大于 32KB 的阈值，这是一个大对象分配。
3. Go 运行时会直接与 **mheap** 交互，请求分配至少包含 100KB 的连续内存页。
4. 如果 **mheap** 没有足够的连续内存页，则会向操作系统请求新的内存块。

**假设的输入与输出：**

* **假设输入:** 执行 `make([]byte, 100000)`。
* **假设输出:** `make` 返回一个指向新分配的 100KB 内存的切片。Go 运行时可能直接从 `mheap` 分配了多个连续的页来满足请求。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。与内存分配相关的命令行参数通常在 Go 运行时的其他部分进行处理，例如 `runtime` 包的 `proc.go` 或 `os_*.go` 文件中。 这些参数可能会影响例如：

* **`-gc`:**  启用或禁用垃圾回收。
* **`-G`:**  设置初始堆大小。
* **与内存限制相关的参数:**  例如 `GOMEMLIMIT` 环境变量。

这些参数会影响 `mallocinit()` 中 `mheap_` 的初始化，以及后续的内存分配和垃圾回收行为。

**使用者易犯错的点:**

虽然 Go 的内存管理是自动的，但开发者仍然可能犯一些与内存相关的错误，这些错误与这段代码的功能间接相关：

1. **持有不再需要的对象引用:** 即使 Go 有垃圾回收，如果程序中仍然存在对某个对象的引用，即使该对象不再被使用，垃圾回收器也无法回收它，导致内存占用过高。

   ```go
   package main

   import "time"

   func main() {
       var largeData []byte
       for i := 0; i < 1000000; i++ {
           // 每次循环都分配一个大的 byte slice
           largeData = make([]byte, 1024*1024)
           largeData[0] = 1
           // 错误：始终持有 largeData 的引用，导致之前的内存无法回收
       }
       time.Sleep(time.Hour) // 让程序运行一段时间以便观察内存
   }
   ```

2. **错误地估计数据结构的大小:**  在某些需要预分配内存的场景下，如果估计的大小不准确，可能会导致频繁的内存重新分配，影响性能。

   ```go
   package main

   func main() {
       // 错误：初始容量太小，导致频繁的扩容
       mySlice := make([]int, 0, 10)
       for i := 0; i < 100; i++ {
           mySlice = append(mySlice, i)
       }
   }
   ```

**总结（针对提供的第 1 部分）：**

提供的代码片段是 Go 语言运行时内存分配器的核心部分，它定义了内存分配的基本结构、小对象和大对象的分配流程、内存回收机制、虚拟内存布局以及相关的常量和初始化过程。它负责 Go 程序中动态内存的申请和管理，是 Go 语言高效内存管理的关键组成部分。

### 提示词
```
这是路径为go/src/runtime/malloc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Memory allocator.
//
// This was originally based on tcmalloc, but has diverged quite a bit.
// http://goog-perftools.sourceforge.net/doc/tcmalloc.html

// The main allocator works in runs of pages.
// Small allocation sizes (up to and including 32 kB) are
// rounded to one of about 70 size classes, each of which
// has its own free set of objects of exactly that size.
// Any free page of memory can be split into a set of objects
// of one size class, which are then managed using a free bitmap.
//
// The allocator's data structures are:
//
//	fixalloc: a free-list allocator for fixed-size off-heap objects,
//		used to manage storage used by the allocator.
//	mheap: the malloc heap, managed at page (8192-byte) granularity.
//	mspan: a run of in-use pages managed by the mheap.
//	mcentral: collects all spans of a given size class.
//	mcache: a per-P cache of mspans with free space.
//	mstats: allocation statistics.
//
// Allocating a small object proceeds up a hierarchy of caches:
//
//	1. Round the size up to one of the small size classes
//	   and look in the corresponding mspan in this P's mcache.
//	   Scan the mspan's free bitmap to find a free slot.
//	   If there is a free slot, allocate it.
//	   This can all be done without acquiring a lock.
//
//	2. If the mspan has no free slots, obtain a new mspan
//	   from the mcentral's list of mspans of the required size
//	   class that have free space.
//	   Obtaining a whole span amortizes the cost of locking
//	   the mcentral.
//
//	3. If the mcentral's mspan list is empty, obtain a run
//	   of pages from the mheap to use for the mspan.
//
//	4. If the mheap is empty or has no page runs large enough,
//	   allocate a new group of pages (at least 1MB) from the
//	   operating system. Allocating a large run of pages
//	   amortizes the cost of talking to the operating system.
//
// Sweeping an mspan and freeing objects on it proceeds up a similar
// hierarchy:
//
//	1. If the mspan is being swept in response to allocation, it
//	   is returned to the mcache to satisfy the allocation.
//
//	2. Otherwise, if the mspan still has allocated objects in it,
//	   it is placed on the mcentral free list for the mspan's size
//	   class.
//
//	3. Otherwise, if all objects in the mspan are free, the mspan's
//	   pages are returned to the mheap and the mspan is now dead.
//
// Allocating and freeing a large object uses the mheap
// directly, bypassing the mcache and mcentral.
//
// If mspan.needzero is false, then free object slots in the mspan are
// already zeroed. Otherwise if needzero is true, objects are zeroed as
// they are allocated. There are various benefits to delaying zeroing
// this way:
//
//	1. Stack frame allocation can avoid zeroing altogether.
//
//	2. It exhibits better temporal locality, since the program is
//	   probably about to write to the memory.
//
//	3. We don't zero pages that never get reused.

// Virtual memory layout
//
// The heap consists of a set of arenas, which are 64MB on 64-bit and
// 4MB on 32-bit (heapArenaBytes). Each arena's start address is also
// aligned to the arena size.
//
// Each arena has an associated heapArena object that stores the
// metadata for that arena: the heap bitmap for all words in the arena
// and the span map for all pages in the arena. heapArena objects are
// themselves allocated off-heap.
//
// Since arenas are aligned, the address space can be viewed as a
// series of arena frames. The arena map (mheap_.arenas) maps from
// arena frame number to *heapArena, or nil for parts of the address
// space not backed by the Go heap. The arena map is structured as a
// two-level array consisting of a "L1" arena map and many "L2" arena
// maps; however, since arenas are large, on many architectures, the
// arena map consists of a single, large L2 map.
//
// The arena map covers the entire possible address space, allowing
// the Go heap to use any part of the address space. The allocator
// attempts to keep arenas contiguous so that large spans (and hence
// large objects) can cross arenas.

package runtime

import (
	"internal/goarch"
	"internal/goos"
	"internal/runtime/atomic"
	"internal/runtime/math"
	"internal/runtime/sys"
	"unsafe"
)

const (
	maxTinySize   = _TinySize
	tinySizeClass = _TinySizeClass
	maxSmallSize  = _MaxSmallSize

	pageShift = _PageShift
	pageSize  = _PageSize

	_PageSize = 1 << _PageShift
	_PageMask = _PageSize - 1

	// _64bit = 1 on 64-bit systems, 0 on 32-bit systems
	_64bit = 1 << (^uintptr(0) >> 63) / 2

	// Tiny allocator parameters, see "Tiny allocator" comment in malloc.go.
	_TinySize      = 16
	_TinySizeClass = int8(2)

	_FixAllocChunk = 16 << 10 // Chunk size for FixAlloc

	// Per-P, per order stack segment cache size.
	_StackCacheSize = 32 * 1024

	// Number of orders that get caching. Order 0 is FixedStack
	// and each successive order is twice as large.
	// We want to cache 2KB, 4KB, 8KB, and 16KB stacks. Larger stacks
	// will be allocated directly.
	// Since FixedStack is different on different systems, we
	// must vary NumStackOrders to keep the same maximum cached size.
	//   OS               | FixedStack | NumStackOrders
	//   -----------------+------------+---------------
	//   linux/darwin/bsd | 2KB        | 4
	//   windows/32       | 4KB        | 3
	//   windows/64       | 8KB        | 2
	//   plan9            | 4KB        | 3
	_NumStackOrders = 4 - goarch.PtrSize/4*goos.IsWindows - 1*goos.IsPlan9

	// heapAddrBits is the number of bits in a heap address. On
	// amd64, addresses are sign-extended beyond heapAddrBits. On
	// other arches, they are zero-extended.
	//
	// On most 64-bit platforms, we limit this to 48 bits based on a
	// combination of hardware and OS limitations.
	//
	// amd64 hardware limits addresses to 48 bits, sign-extended
	// to 64 bits. Addresses where the top 16 bits are not either
	// all 0 or all 1 are "non-canonical" and invalid. Because of
	// these "negative" addresses, we offset addresses by 1<<47
	// (arenaBaseOffset) on amd64 before computing indexes into
	// the heap arenas index. In 2017, amd64 hardware added
	// support for 57 bit addresses; however, currently only Linux
	// supports this extension and the kernel will never choose an
	// address above 1<<47 unless mmap is called with a hint
	// address above 1<<47 (which we never do).
	//
	// arm64 hardware (as of ARMv8) limits user addresses to 48
	// bits, in the range [0, 1<<48).
	//
	// ppc64, mips64, and s390x support arbitrary 64 bit addresses
	// in hardware. On Linux, Go leans on stricter OS limits. Based
	// on Linux's processor.h, the user address space is limited as
	// follows on 64-bit architectures:
	//
	// Architecture  Name              Maximum Value (exclusive)
	// ---------------------------------------------------------------------
	// amd64         TASK_SIZE_MAX     0x007ffffffff000 (47 bit addresses)
	// arm64         TASK_SIZE_64      0x01000000000000 (48 bit addresses)
	// ppc64{,le}    TASK_SIZE_USER64  0x00400000000000 (46 bit addresses)
	// mips64{,le}   TASK_SIZE64       0x00010000000000 (40 bit addresses)
	// s390x         TASK_SIZE         1<<64 (64 bit addresses)
	//
	// These limits may increase over time, but are currently at
	// most 48 bits except on s390x. On all architectures, Linux
	// starts placing mmap'd regions at addresses that are
	// significantly below 48 bits, so even if it's possible to
	// exceed Go's 48 bit limit, it's extremely unlikely in
	// practice.
	//
	// On 32-bit platforms, we accept the full 32-bit address
	// space because doing so is cheap.
	// mips32 only has access to the low 2GB of virtual memory, so
	// we further limit it to 31 bits.
	//
	// On ios/arm64, although 64-bit pointers are presumably
	// available, pointers are truncated to 33 bits in iOS <14.
	// Furthermore, only the top 4 GiB of the address space are
	// actually available to the application. In iOS >=14, more
	// of the address space is available, and the OS can now
	// provide addresses outside of those 33 bits. Pick 40 bits
	// as a reasonable balance between address space usage by the
	// page allocator, and flexibility for what mmap'd regions
	// we'll accept for the heap. We can't just move to the full
	// 48 bits because this uses too much address space for older
	// iOS versions.
	// TODO(mknyszek): Once iOS <14 is deprecated, promote ios/arm64
	// to a 48-bit address space like every other arm64 platform.
	//
	// WebAssembly currently has a limit of 4GB linear memory.
	heapAddrBits = (_64bit*(1-goarch.IsWasm)*(1-goos.IsIos*goarch.IsArm64))*48 + (1-_64bit+goarch.IsWasm)*(32-(goarch.IsMips+goarch.IsMipsle)) + 40*goos.IsIos*goarch.IsArm64

	// maxAlloc is the maximum size of an allocation. On 64-bit,
	// it's theoretically possible to allocate 1<<heapAddrBits bytes. On
	// 32-bit, however, this is one less than 1<<32 because the
	// number of bytes in the address space doesn't actually fit
	// in a uintptr.
	maxAlloc = (1 << heapAddrBits) - (1-_64bit)*1

	// The number of bits in a heap address, the size of heap
	// arenas, and the L1 and L2 arena map sizes are related by
	//
	//   (1 << addr bits) = arena size * L1 entries * L2 entries
	//
	// Currently, we balance these as follows:
	//
	//       Platform  Addr bits  Arena size  L1 entries   L2 entries
	// --------------  ---------  ----------  ----------  -----------
	//       */64-bit         48        64MB           1    4M (32MB)
	// windows/64-bit         48         4MB          64    1M  (8MB)
	//      ios/arm64         40         4MB           1  256K  (2MB)
	//       */32-bit         32         4MB           1  1024  (4KB)
	//     */mips(le)         31         4MB           1   512  (2KB)

	// heapArenaBytes is the size of a heap arena. The heap
	// consists of mappings of size heapArenaBytes, aligned to
	// heapArenaBytes. The initial heap mapping is one arena.
	//
	// This is currently 64MB on 64-bit non-Windows and 4MB on
	// 32-bit and on Windows. We use smaller arenas on Windows
	// because all committed memory is charged to the process,
	// even if it's not touched. Hence, for processes with small
	// heaps, the mapped arena space needs to be commensurate.
	// This is particularly important with the race detector,
	// since it significantly amplifies the cost of committed
	// memory.
	heapArenaBytes = 1 << logHeapArenaBytes

	heapArenaWords = heapArenaBytes / goarch.PtrSize

	// logHeapArenaBytes is log_2 of heapArenaBytes. For clarity,
	// prefer using heapArenaBytes where possible (we need the
	// constant to compute some other constants).
	logHeapArenaBytes = (6+20)*(_64bit*(1-goos.IsWindows)*(1-goarch.IsWasm)*(1-goos.IsIos*goarch.IsArm64)) + (2+20)*(_64bit*goos.IsWindows) + (2+20)*(1-_64bit) + (2+20)*goarch.IsWasm + (2+20)*goos.IsIos*goarch.IsArm64

	// heapArenaBitmapWords is the size of each heap arena's bitmap in uintptrs.
	heapArenaBitmapWords = heapArenaWords / (8 * goarch.PtrSize)

	pagesPerArena = heapArenaBytes / pageSize

	// arenaL1Bits is the number of bits of the arena number
	// covered by the first level arena map.
	//
	// This number should be small, since the first level arena
	// map requires PtrSize*(1<<arenaL1Bits) of space in the
	// binary's BSS. It can be zero, in which case the first level
	// index is effectively unused. There is a performance benefit
	// to this, since the generated code can be more efficient,
	// but comes at the cost of having a large L2 mapping.
	//
	// We use the L1 map on 64-bit Windows because the arena size
	// is small, but the address space is still 48 bits, and
	// there's a high cost to having a large L2.
	arenaL1Bits = 6 * (_64bit * goos.IsWindows)

	// arenaL2Bits is the number of bits of the arena number
	// covered by the second level arena index.
	//
	// The size of each arena map allocation is proportional to
	// 1<<arenaL2Bits, so it's important that this not be too
	// large. 48 bits leads to 32MB arena index allocations, which
	// is about the practical threshold.
	arenaL2Bits = heapAddrBits - logHeapArenaBytes - arenaL1Bits

	// arenaL1Shift is the number of bits to shift an arena frame
	// number by to compute an index into the first level arena map.
	arenaL1Shift = arenaL2Bits

	// arenaBits is the total bits in a combined arena map index.
	// This is split between the index into the L1 arena map and
	// the L2 arena map.
	arenaBits = arenaL1Bits + arenaL2Bits

	// arenaBaseOffset is the pointer value that corresponds to
	// index 0 in the heap arena map.
	//
	// On amd64, the address space is 48 bits, sign extended to 64
	// bits. This offset lets us handle "negative" addresses (or
	// high addresses if viewed as unsigned).
	//
	// On aix/ppc64, this offset allows to keep the heapAddrBits to
	// 48. Otherwise, it would be 60 in order to handle mmap addresses
	// (in range 0x0a00000000000000 - 0x0afffffffffffff). But in this
	// case, the memory reserved in (s *pageAlloc).init for chunks
	// is causing important slowdowns.
	//
	// On other platforms, the user address space is contiguous
	// and starts at 0, so no offset is necessary.
	arenaBaseOffset = 0xffff800000000000*goarch.IsAmd64 + 0x0a00000000000000*goos.IsAix
	// A typed version of this constant that will make it into DWARF (for viewcore).
	arenaBaseOffsetUintptr = uintptr(arenaBaseOffset)

	// Max number of threads to run garbage collection.
	// 2, 3, and 4 are all plausible maximums depending
	// on the hardware details of the machine. The garbage
	// collector scales well to 32 cpus.
	_MaxGcproc = 32

	// minLegalPointer is the smallest possible legal pointer.
	// This is the smallest possible architectural page size,
	// since we assume that the first page is never mapped.
	//
	// This should agree with minZeroPage in the compiler.
	minLegalPointer uintptr = 4096

	// minHeapForMetadataHugePages sets a threshold on when certain kinds of
	// heap metadata, currently the arenas map L2 entries and page alloc bitmap
	// mappings, are allowed to be backed by huge pages. If the heap goal ever
	// exceeds this threshold, then huge pages are enabled.
	//
	// These numbers are chosen with the assumption that huge pages are on the
	// order of a few MiB in size.
	//
	// The kind of metadata this applies to has a very low overhead when compared
	// to address space used, but their constant overheads for small heaps would
	// be very high if they were to be backed by huge pages (e.g. a few MiB makes
	// a huge difference for an 8 MiB heap, but barely any difference for a 1 GiB
	// heap). The benefit of huge pages is also not worth it for small heaps,
	// because only a very, very small part of the metadata is used for small heaps.
	//
	// N.B. If the heap goal exceeds the threshold then shrinks to a very small size
	// again, then huge pages will still be enabled for this mapping. The reason is that
	// there's no point unless we're also returning the physical memory for these
	// metadata mappings back to the OS. That would be quite complex to do in general
	// as the heap is likely fragmented after a reduction in heap size.
	minHeapForMetadataHugePages = 1 << 30
)

// physPageSize is the size in bytes of the OS's physical pages.
// Mapping and unmapping operations must be done at multiples of
// physPageSize.
//
// This must be set by the OS init code (typically in osinit) before
// mallocinit.
var physPageSize uintptr

// physHugePageSize is the size in bytes of the OS's default physical huge
// page size whose allocation is opaque to the application. It is assumed
// and verified to be a power of two.
//
// If set, this must be set by the OS init code (typically in osinit) before
// mallocinit. However, setting it at all is optional, and leaving the default
// value is always safe (though potentially less efficient).
//
// Since physHugePageSize is always assumed to be a power of two,
// physHugePageShift is defined as physHugePageSize == 1 << physHugePageShift.
// The purpose of physHugePageShift is to avoid doing divisions in
// performance critical functions.
var (
	physHugePageSize  uintptr
	physHugePageShift uint
)

func mallocinit() {
	if class_to_size[_TinySizeClass] != _TinySize {
		throw("bad TinySizeClass")
	}

	if heapArenaBitmapWords&(heapArenaBitmapWords-1) != 0 {
		// heapBits expects modular arithmetic on bitmap
		// addresses to work.
		throw("heapArenaBitmapWords not a power of 2")
	}

	// Check physPageSize.
	if physPageSize == 0 {
		// The OS init code failed to fetch the physical page size.
		throw("failed to get system page size")
	}
	if physPageSize > maxPhysPageSize {
		print("system page size (", physPageSize, ") is larger than maximum page size (", maxPhysPageSize, ")\n")
		throw("bad system page size")
	}
	if physPageSize < minPhysPageSize {
		print("system page size (", physPageSize, ") is smaller than minimum page size (", minPhysPageSize, ")\n")
		throw("bad system page size")
	}
	if physPageSize&(physPageSize-1) != 0 {
		print("system page size (", physPageSize, ") must be a power of 2\n")
		throw("bad system page size")
	}
	if physHugePageSize&(physHugePageSize-1) != 0 {
		print("system huge page size (", physHugePageSize, ") must be a power of 2\n")
		throw("bad system huge page size")
	}
	if physHugePageSize > maxPhysHugePageSize {
		// physHugePageSize is greater than the maximum supported huge page size.
		// Don't throw here, like in the other cases, since a system configured
		// in this way isn't wrong, we just don't have the code to support them.
		// Instead, silently set the huge page size to zero.
		physHugePageSize = 0
	}
	if physHugePageSize != 0 {
		// Since physHugePageSize is a power of 2, it suffices to increase
		// physHugePageShift until 1<<physHugePageShift == physHugePageSize.
		for 1<<physHugePageShift != physHugePageSize {
			physHugePageShift++
		}
	}
	if pagesPerArena%pagesPerSpanRoot != 0 {
		print("pagesPerArena (", pagesPerArena, ") is not divisible by pagesPerSpanRoot (", pagesPerSpanRoot, ")\n")
		throw("bad pagesPerSpanRoot")
	}
	if pagesPerArena%pagesPerReclaimerChunk != 0 {
		print("pagesPerArena (", pagesPerArena, ") is not divisible by pagesPerReclaimerChunk (", pagesPerReclaimerChunk, ")\n")
		throw("bad pagesPerReclaimerChunk")
	}
	// Check that the minimum size (exclusive) for a malloc header is also
	// a size class boundary. This is important to making sure checks align
	// across different parts of the runtime.
	//
	// While we're here, also check to make sure all these size classes'
	// span sizes are one page. Some code relies on this.
	minSizeForMallocHeaderIsSizeClass := false
	sizeClassesUpToMinSizeForMallocHeaderAreOnePage := true
	for i := 0; i < len(class_to_size); i++ {
		if class_to_allocnpages[i] > 1 {
			sizeClassesUpToMinSizeForMallocHeaderAreOnePage = false
		}
		if minSizeForMallocHeader == uintptr(class_to_size[i]) {
			minSizeForMallocHeaderIsSizeClass = true
			break
		}
	}
	if !minSizeForMallocHeaderIsSizeClass {
		throw("min size of malloc header is not a size class boundary")
	}
	if !sizeClassesUpToMinSizeForMallocHeaderAreOnePage {
		throw("expected all size classes up to min size for malloc header to fit in one-page spans")
	}
	// Check that the pointer bitmap for all small sizes without a malloc header
	// fits in a word.
	if minSizeForMallocHeader/goarch.PtrSize > 8*goarch.PtrSize {
		throw("max pointer/scan bitmap size for headerless objects is too large")
	}

	if minTagBits > taggedPointerBits {
		throw("taggedPointerBits too small")
	}

	// Initialize the heap.
	mheap_.init()
	mcache0 = allocmcache()
	lockInit(&gcBitsArenas.lock, lockRankGcBitsArenas)
	lockInit(&profInsertLock, lockRankProfInsert)
	lockInit(&profBlockLock, lockRankProfBlock)
	lockInit(&profMemActiveLock, lockRankProfMemActive)
	for i := range profMemFutureLock {
		lockInit(&profMemFutureLock[i], lockRankProfMemFuture)
	}
	lockInit(&globalAlloc.mutex, lockRankGlobalAlloc)

	// Create initial arena growth hints.
	if isSbrkPlatform {
		// Don't generate hints on sbrk platforms. We can
		// only grow the break sequentially.
	} else if goarch.PtrSize == 8 {
		// On a 64-bit machine, we pick the following hints
		// because:
		//
		// 1. Starting from the middle of the address space
		// makes it easier to grow out a contiguous range
		// without running in to some other mapping.
		//
		// 2. This makes Go heap addresses more easily
		// recognizable when debugging.
		//
		// 3. Stack scanning in gccgo is still conservative,
		// so it's important that addresses be distinguishable
		// from other data.
		//
		// Starting at 0x00c0 means that the valid memory addresses
		// will begin 0x00c0, 0x00c1, ...
		// In little-endian, that's c0 00, c1 00, ... None of those are valid
		// UTF-8 sequences, and they are otherwise as far away from
		// ff (likely a common byte) as possible. If that fails, we try other 0xXXc0
		// addresses. An earlier attempt to use 0x11f8 caused out of memory errors
		// on OS X during thread allocations.  0x00c0 causes conflicts with
		// AddressSanitizer which reserves all memory up to 0x0100.
		// These choices reduce the odds of a conservative garbage collector
		// not collecting memory because some non-pointer block of memory
		// had a bit pattern that matched a memory address.
		//
		// However, on arm64, we ignore all this advice above and slam the
		// allocation at 0x40 << 32 because when using 4k pages with 3-level
		// translation buffers, the user address space is limited to 39 bits
		// On ios/arm64, the address space is even smaller.
		//
		// On AIX, mmaps starts at 0x0A00000000000000 for 64-bit.
		// processes.
		//
		// Space mapped for user arenas comes immediately after the range
		// originally reserved for the regular heap when race mode is not
		// enabled because user arena chunks can never be used for regular heap
		// allocations and we want to avoid fragmenting the address space.
		//
		// In race mode we have no choice but to just use the same hints because
		// the race detector requires that the heap be mapped contiguously.
		for i := 0x7f; i >= 0; i-- {
			var p uintptr
			switch {
			case raceenabled:
				// The TSAN runtime requires the heap
				// to be in the range [0x00c000000000,
				// 0x00e000000000).
				p = uintptr(i)<<32 | uintptrMask&(0x00c0<<32)
				if p >= uintptrMask&0x00e000000000 {
					continue
				}
			case GOARCH == "arm64" && GOOS == "ios":
				p = uintptr(i)<<40 | uintptrMask&(0x0013<<28)
			case GOARCH == "arm64":
				p = uintptr(i)<<40 | uintptrMask&(0x0040<<32)
			case GOOS == "aix":
				if i == 0 {
					// We don't use addresses directly after 0x0A00000000000000
					// to avoid collisions with others mmaps done by non-go programs.
					continue
				}
				p = uintptr(i)<<40 | uintptrMask&(0xa0<<52)
			default:
				p = uintptr(i)<<40 | uintptrMask&(0x00c0<<32)
			}
			// Switch to generating hints for user arenas if we've gone
			// through about half the hints. In race mode, take only about
			// a quarter; we don't have very much space to work with.
			hintList := &mheap_.arenaHints
			if (!raceenabled && i > 0x3f) || (raceenabled && i > 0x5f) {
				hintList = &mheap_.userArena.arenaHints
			}
			hint := (*arenaHint)(mheap_.arenaHintAlloc.alloc())
			hint.addr = p
			hint.next, *hintList = *hintList, hint
		}
	} else {
		// On a 32-bit machine, we're much more concerned
		// about keeping the usable heap contiguous.
		// Hence:
		//
		// 1. We reserve space for all heapArenas up front so
		// they don't get interleaved with the heap. They're
		// ~258MB, so this isn't too bad. (We could reserve a
		// smaller amount of space up front if this is a
		// problem.)
		//
		// 2. We hint the heap to start right above the end of
		// the binary so we have the best chance of keeping it
		// contiguous.
		//
		// 3. We try to stake out a reasonably large initial
		// heap reservation.

		const arenaMetaSize = (1 << arenaBits) * unsafe.Sizeof(heapArena{})
		meta := uintptr(sysReserve(nil, arenaMetaSize))
		if meta != 0 {
			mheap_.heapArenaAlloc.init(meta, arenaMetaSize, true)
		}

		// We want to start the arena low, but if we're linked
		// against C code, it's possible global constructors
		// have called malloc and adjusted the process' brk.
		// Query the brk so we can avoid trying to map the
		// region over it (which will cause the kernel to put
		// the region somewhere else, likely at a high
		// address).
		procBrk := sbrk0()

		// If we ask for the end of the data segment but the
		// operating system requires a little more space
		// before we can start allocating, it will give out a
		// slightly higher pointer. Except QEMU, which is
		// buggy, as usual: it won't adjust the pointer
		// upward. So adjust it upward a little bit ourselves:
		// 1/4 MB to get away from the running binary image.
		p := firstmoduledata.end
		if p < procBrk {
			p = procBrk
		}
		if mheap_.heapArenaAlloc.next <= p && p < mheap_.heapArenaAlloc.end {
			p = mheap_.heapArenaAlloc.end
		}
		p = alignUp(p+(256<<10), heapArenaBytes)
		// Because we're worried about fragmentation on
		// 32-bit, we try to make a large initial reservation.
		arenaSizes := []uintptr{
			512 << 20,
			256 << 20,
			128 << 20,
		}
		for _, arenaSize := range arenaSizes {
			a, size := sysReserveAligned(unsafe.Pointer(p), arenaSize, heapArenaBytes)
			if a != nil {
				mheap_.arena.init(uintptr(a), size, false)
				p = mheap_.arena.end // For hint below
				break
			}
		}
		hint := (*arenaHint)(mheap_.arenaHintAlloc.alloc())
		hint.addr = p
		hint.next, mheap_.arenaHints = mheap_.arenaHints, hint

		// Place the hint for user arenas just after the large reservation.
		//
		// While this potentially competes with the hint above, in practice we probably
		// aren't going to be getting this far anyway on 32-bit platforms.
		userArenaHint := (*arenaHint)(mheap_.arenaHintAlloc.alloc())
		userArenaHint.addr = p
		userArenaHint.next, mheap_.userArena.arenaHints = mheap_.userArena.arenaHints, userArenaHint
	}
	// Initialize the memory limit here because the allocator is going to look at it
	// but we haven't called gcinit yet and we're definitely going to allocate memory before then.
	gcController.memoryLimit.Store(maxInt64)
}

// sysAlloc allocates heap arena space for at least n bytes. The
// returned pointer is always heapArenaBytes-aligned and backed by
// h.arenas metadata. The returned size is always a multiple of
// heapArenaBytes. sysAlloc returns nil on failure.
// There is no corresponding free function.
//
// hintList is a list of hint addresses for where to allocate new
// heap arenas. It must be non-nil.
//
// register indicates whether the heap arena should be registered
// in allArenas.
//
// sysAlloc returns a memory region in the Reserved state. This region must
// be transitioned to Prepared and then Ready before use.
//
// h must be locked.
func (h *mheap) sysAlloc(n uintptr, hintList **arenaHint, register bool) (v unsafe.Pointer, size uintptr) {
	assertLockHeld(&h.lock)

	n = alignUp(n, heapArenaBytes)

	if hintList == &h.arenaHints {
		// First, try the arena pre-reservation.
		// Newly-used mappings are considered released.
		//
		// Only do this if we're using the regular heap arena hints.
		// This behavior is only for the heap.
		v = h.arena.alloc(n, heapArenaBytes, &gcController.heapReleased)
		if v != nil {
			size = n
			goto mapped
		}
	}

	// Try to grow the heap at a hint address.
	for *hintList != nil {
		hint := *hintList
		p := hint.addr
		if hint.down {
			p -= n
		}
		if p+n < p {
			// We can't use this, so don't ask.
			v = nil
		} else if arenaIndex(p+n-1) >= 1<<arenaBits {
			// Outside addressable heap. Can't use.
			v = nil
		} else {
			v = sysReserve(unsafe.Pointer(p), n)
		}
		if p == uintptr(v) {
			// Success. Update the hint.
			if !hint.down {
				p += n
			}
			hint.addr = p
			size = n
			break
		}
		// Failed. Discard this hint and try the next.
		//
		// TODO: This would be cleaner if sysReserve could be
		// told to only return the requested address. In
		// particular, this is already how Windows behaves, so
		// it would simplify things there.
		if v != nil {
			sysFreeOS(v, n)
		}
		*hintList = hint.next
		h.arenaHintAlloc.free(unsafe.Pointer(hint))
	}

	if size == 0 {
		if raceenabled {
			// The race detector assumes the heap lives in
			// [0x00c000000000, 0x00e000000000), but we
			// just ran out of hints in this region. Give
			// a nice failure.
			throw("too many address space collisions for -race mode")
		}

		// All of the hints failed, so we'll take any
		// (sufficiently aligned) address the kernel will give
		// us.
		v, size = sysReserveAligned(nil, n, heapArenaBytes)
		if v == nil {
			return nil, 0
		}

		// Create new hints for extending this region.
		hint := (*arenaHint)(h.arenaHintAlloc.alloc())
		hint.addr, hint.down = uintptr(v), true
		hint.next, mheap_.arenaHints = mheap_.arenaHints, hint
		hint = (*arenaHint)(h.arenaHintAlloc.alloc())
		hint.addr = uintptr(v) + size
		hint.next, mheap_.arenaHints = mheap_.arenaHints, hint
	}

	// Check for bad pointers or pointers we can't use.
	{
		var bad string
		p := uintptr(v)
		if p+size < p {
			bad = "region exceeds uintptr range"
		} else if arenaIndex(p) >= 1<<arenaBits {
			bad = "base outside usable address space"
		} else if arenaIndex(p+size-1) >= 1<<arenaBits {
			bad = "end outside usable address space"
		}
		if bad != "" {
			// This should be impossible on most architectures,
			// but it would be really confusing to debug.
			print("runtime: memory allocated by OS [", hex(p), ", ", hex(p+size), ") not in usable address space: ", bad, "\n")
			throw("memory reservation exceeds address space limit")
		}
	}

	if uintptr(v)&(heapArenaBytes-1) != 0 {
		throw("misrounded allocation in sysAlloc")
	}

mapped:
	// Create arena metadata.
	for ri := arenaIndex(uintptr(v)); ri <= arenaIndex(uintptr(v)+size-1); ri++ {
		l2 := h.arenas[ri.l1()]
		if l2 == nil {
			// Allocate an L2 arena map.
			//
			// Use sysAllocOS instead of sysAlloc or persistentalloc because there's no
			// statistic we can comfortably account for this space in. With this structure,
			// we rely on demand paging to avoid large overheads, but tracking which memory
			// is paged in is too expensive. Trying to account for the whole region means
			// that it will appear like an enormous memory overhead in statistics, even though
			// it is not.
			l2 = (*[1 << arenaL2Bits]*heapArena)(sysAllocOS(unsafe.Sizeof(*l2)))
			if l2 == nil {
				throw("out of memory allocating heap arena map")
			}
			if h.arenasHugePages {
				sysHugePage(unsafe.Pointer(l2), unsafe.Sizeof(*l2))
			} else {
				sysNoHugePage(unsafe.Pointer(l2), unsafe.Sizeof(*l2))
			}
			atomic.StorepNoWB(unsafe.Pointer(&h.arenas[ri.l1()]), unsafe.Pointer(l2))
		}

		if l2[ri.l2()] != nil {
			throw("arena already initialized")
		}
		var r *heapArena
		r = (*heapArena)(h.heapArenaAlloc.alloc(unsafe.Sizeof(*r), goarch.PtrSize, &memstats.gcMiscSys))
		if r == nil {
			r = (*heapArena)(persistentalloc(unsafe.Sizeof(*r), goarch.PtrSize, &memstats.gcMiscSys))
			if r == nil {
				throw("out of memory allocating heap arena metadata")
			}
		}

		// Register the arena in allArenas if requested.
		if register {
			if len(h.allArenas) == cap(h.allArenas) {
				size := 2 * uintptr(cap(h.allArenas)) * goarch.PtrSize
				if size == 0 {
					size = physPageSize
				}
				newArray := (*notInHeap)(persistentalloc(size, goarch.PtrSize, &memstats.gcMiscSys))
				if newArray == nil {
					throw("out of memory allocating allArenas")
				}
				oldSlice := h.allArenas
				*(*notInHeapSlice)(unsafe.Pointer(&h.allArenas)) = notInHeapSlice{newArray, len(h.allArenas), int(size / goarch.PtrSize)}
				copy(h.allArenas, oldSlice)
				// Do not free the old backing array because
				// there may be concurrent readers. Since we
				// double the array each time, this can lead
				// to at most 2x waste.
			}
			h.allArenas = h.allArenas[:len(h.allArenas)+1]
			h.allArenas[len(h.allArenas)-1] = ri
		}

		// Store atomically just in case an object from the
		// new heap arena becomes visible before the heap lock
		// is released (which shouldn't happen, but there's
		// little downside to this).
		atomic.StorepNoWB(unsafe.Pointer(&l2[ri.l2()]), unsafe.Pointer(r))
	}

	// Tell the race detector about the new heap memory.
	if raceenabled {
		racemapshadow(v, size)
	}

	return
}

// sysReserveAligned is like sysReserve, but the returned pointer is
// aligned to align bytes. It may reserve either n or n+align bytes,
// so it returns the size that was reserved.
func sysReserveAligned(v unsafe.Pointer, size, align uintptr) (unsa
```