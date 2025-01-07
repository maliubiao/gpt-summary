Response:
我的思考过程如下：

1. **理解目标：** 仔细阅读题目要求，明确需要提取 `mranges.go` 的功能，并尽可能推理其背后的 Go 语言特性。还需要提供代码示例、输入输出、命令行参数（如果适用）、以及易错点。

2. **代码概览与核心数据结构识别：**  快速浏览代码，注意到核心的数据结构是 `addrRange` 和 `addrRanges`。 `addrRange` 代表一个连续的地址范围，而 `addrRanges` 是一个存储多个 `addrRange` 的集合。

3. **`addrRange` 功能分析：**  逐个分析 `addrRange` 结构体和相关方法：
    * `addrRange` 结构体：包含 `base` 和 `limit`，定义了地址范围的起始和结束。注意 `offAddr` 类型的使用，暗示可能存在地址空间的偏移或分段。
    * `makeAddrRange`：创建 `addrRange`，并检查 `base` 和 `limit` 是否在同一内存段。
    * `size`：计算地址范围的大小。
    * `contains`：检查地址是否在范围内。
    * `subtract`：从一个范围中减去另一个范围的重叠部分。注意它对重叠情况的假设和 `throw` 的使用，说明了其特定的使用场景。
    * `takeFromFront` 和 `takeFromBack`：从范围的开头或结尾取出一部分，并进行对齐。这是内存分配中常见的操作。
    * `removeGreaterEqual`：移除大于等于给定地址的部分。

4. **`offAddr` 和 `atomicOffAddr` 分析：**
    * `offAddr`：表示偏移地址，其方法如 `add`、`sub`、`diff`、`lessThan` 等，都是基本的地址操作。`arenaBaseOffset` 的出现进一步印证了可能存在地址空间偏移。
    * `atomicOffAddr`：基于 `atomic.Int64` 的原子操作偏移地址，用于并发安全的场景。其方法 `Clear`、`StoreMin`、`StoreUnmark`、`StoreMarked`、`Load` 涉及到原子比较和交换，以及标记位的处理。

5. **`addrRanges` 功能分析：** 逐个分析 `addrRanges` 结构体和相关方法：
    * `addrRanges` 结构体：包含一个排序的 `addrRange` 切片 `ranges`，总字节数 `totalBytes`，以及用于统计的 `sysStat`。 说明了它用于管理和跟踪内存地址范围。
    * `init`：初始化 `addrRanges`，分配底层存储空间。使用了 `persistentalloc`，暗示这部分内存的特殊性（不参与 GC？）。
    * `findSucc`：查找给定地址的后继范围的索引，使用了优化的二分查找。
    * `findAddrGreaterEqual`：查找大于等于给定地址的最小地址。
    * `contains`：检查地址是否在任何一个范围中。
    * `add`：添加一个新的地址范围，并进行合并以减少碎片。 注意到扩容时的策略，以及对性能的考虑。
    * `removeLast`：移除并返回最后一个范围的一部分或全部。
    * `removeGreaterEqual`：移除大于等于给定地址的所有范围，并可能拆分包含该地址的范围。
    * `cloneInto`：深拷贝 `addrRanges`。

6. **推理 Go 语言功能：**  结合以上分析，可以推断出 `mranges.go` 主要用于 **管理堆内存的地址范围**。  具体来说：
    * **堆内存管理：**  `addrRange` 表示堆上的一个连续内存块，`addrRanges` 管理多个这样的块。
    * **内存分配：**  `takeFromFront` 和 `takeFromBack` 像是分配内存的操作。
    * **内存回收/释放：** `subtract` 和 `removeGreaterEqual` 可能是释放内存或整理内存空间的操作。
    * **并发安全：** `atomicOffAddr` 用于在并发环境下安全地操作地址信息。

7. **编写代码示例：**  根据推理出的功能，编写示例代码来演示 `addrRanges` 的创建、添加范围、检查包含、移除范围等操作。  选择具有代表性的操作进行演示。

8. **构造输入输出：**  为示例代码构造明确的输入和预期的输出，以便验证代码的功能。

9. **识别易错点：**  考虑使用 `addrRanges` 时可能出现的错误：
    * 添加重叠的范围。
    * 添加零大小的范围。

10. **组织答案：** 将以上分析组织成清晰的中文回答，包括功能列表、Go 语言功能推断、代码示例、输入输出、以及易错点。  确保逻辑清晰，表达准确。

11. **审阅和完善：**  重新阅读答案，检查是否有遗漏、错误或不清晰的地方，进行必要的修改和完善。 例如，一开始可能只关注了 `addrRange` 的基本功能，后来在分析 `addrRanges` 的 `add` 方法时，才更明确地意识到它与堆内存管理的关联。  同样，`atomicOffAddr` 的出现也提示了并发安全的重要性。

通过以上步骤，我逐步理解了 `mranges.go` 的功能，并最终形成了较为完善的答案。
`go/src/runtime/mranges.go` 文件实现了用于管理有序地址范围的数据结构。从代码的结构和方法来看，它主要用于 **管理堆内存的地址空间**，跟踪哪些地址范围是可用的或已被分配。

以下是它的主要功能：

**核心数据结构：**

* **`addrRange`**: 表示一个地址空间区域，包含起始地址 `base` 和结束地址 `limit`（不包含）。
    * 提供创建、计算大小、判断是否包含特定地址、裁剪（`subtract`）、从头尾获取指定大小的对齐地址范围（`takeFromFront`, `takeFromBack`）、移除大于等于特定地址的部分（`removeGreaterEqual`）等操作。
* **`offAddr`**:  表示地址空间中的偏移地址，用于处理可能存在的地址空间分段的情况。提供基本的加减、比较等操作。
* **`atomicOffAddr`**:  `offAddr` 的原子版本，用于并发安全的地址操作，支持标记地址以避免被覆盖。
* **`addrRanges`**:  一个包含多个 `addrRange` 的数据结构，用于管理一组不重叠的地址范围。
    * 提供初始化、查找（`findSucc`, `findAddrGreaterEqual`）、判断是否包含地址、添加新范围（自动合并相邻范围）、移除最后添加的范围（`removeLast`）、移除大于等于特定地址的所有范围、克隆等操作。

**推断的 Go 语言功能实现：堆内存管理**

从代码的功能和命名可以推断，`mranges.go` 是 Go 运行时系统中 **堆内存管理** 的一部分。它负责跟踪哪些地址范围是空闲的，哪些已经被分配，并且能够进行分配和释放操作。

**Go 代码示例：**

假设 `addrRanges` 用于管理堆内存，我们可以模拟以下场景：

```go
package main

import (
	"fmt"
	"unsafe"
	"internal/goarch"
	"internal/runtime/atomic"
)

// 模拟 runtime 包中的部分结构和函数
type offAddr struct {
	a uintptr
}

func (l offAddr) lessThan(l2 offAddr) bool {
	// 简化比较逻辑
	return l.a < l2.a
}

func (l offAddr) lessEqual(l2 offAddr) bool {
	return l.a <= l2.a
}

func (l offAddr) equal(l2 offAddr) bool {
	return l.a == l2.a
}

func (l offAddr) addr() uintptr {
	return l.a
}

func (l offAddr) diff(l2 offAddr) uintptr {
	return l.a - l2.a
}

type addrRange struct {
	base, limit offAddr
}

func makeAddrRange(base, limit uintptr) addrRange {
	return addrRange{offAddr{base}, offAddr{limit}}
}

func (a addrRange) size() uintptr {
	if !a.base.lessThan(a.limit) {
		return 0
	}
	return a.limit.diff(a.base)
}

func (a addrRange) contains(addr uintptr) bool {
	return a.base.lessEqual(offAddr{addr}) && (offAddr{addr}).lessThan(a.limit)
}

func alignUp(ptr, align uintptr) uintptr {
	return (ptr + align - 1) &^ (align - 1)
}

func alignDown(ptr, align uintptr) uintptr {
	return ptr &^ (align - 1)
}

func (a *addrRange) takeFromFront(len uintptr, align uint8) (uintptr, bool) {
	base := alignUp(a.base.addr(), uintptr(align)) + len
	if base > a.limit.addr() {
		return 0, false
	}
	a.base = offAddr{base}
	return base - len, true
}

// 模拟 persistentalloc
func persistentalloc(size, align uintptr, stat *sysMemStat) unsafe.Pointer {
	mem := make([]byte, size)
	return unsafe.Pointer(&mem[0])
}

type notInHeap struct {
	ptr unsafe.Pointer
}

type notInHeapSlice struct {
	array *notInHeap
	len   int
	cap   int
}

type sysMemStat struct{}

type addrRanges struct {
	ranges     []addrRange
	totalBytes uintptr
	sysStat    *sysMemStat
}

func (a *addrRanges) init(sysStat *sysMemStat) {
	ranges := (*notInHeapSlice)(unsafe.Pointer(&a.ranges))
	ranges.len = 0
	ranges.cap = 16
	ranges.array = (*notInHeap)(persistentalloc(unsafe.Sizeof(addrRange{})*uintptr(ranges.cap), goarch.PtrSize, sysStat))
	a.sysStat = sysStat
	a.totalBytes = 0
}

func (a *addrRanges) add(r addrRange) {
	a.ranges = append(a.ranges, r)
	a.totalBytes += r.size()
}

func main() {
	var ranges addrRanges
	var stat sysMemStat
	ranges.init(&stat)

	// 假设从操作系统获得一块内存区域 [0x1000, 0x5000)
	region1 := makeAddrRange(0x1000, 0x5000)
	ranges.add(region1)
	fmt.Printf("添加区域1，总大小: %d\n", ranges.totalBytes)

	// 从该区域分配 100 字节，按 8 字节对齐
	allocPtr, ok := (&ranges.ranges[0]).takeFromFront(100, 8)
	if ok {
		fmt.Printf("分配了 100 字节，起始地址: 0x%x\n", allocPtr)
		fmt.Printf("剩余区域大小: %d\n", ranges.ranges[0].size())
	}

	// 检查地址是否包含在管理范围内
	fmt.Printf("地址 0x1100 是否在管理范围内: %t\n", ranges.contains(0x1100))
	fmt.Printf("地址 0x6000 是否在管理范围内: %t\n", ranges.contains(0x6000))
}

func (a *addrRanges) contains(addr uintptr) bool {
	for _, r := range a.ranges {
		if r.contains(addr) {
			return true
		}
	}
	return false
}
```

**假设的输入与输出：**

由于示例代码中没有涉及外部输入，输出取决于代码逻辑。

```
添加区域1，总大小: 16384
分配了 100 字节，起始地址: 0x1000
剩余区域大小: 16284
地址 0x1100 是否在管理范围内: true
地址 0x6000 是否在管理范围内: false
```

**命令行参数：**

该代码片段本身不涉及命令行参数的处理。它是 Go 运行时系统内部的一部分，其行为通常由 Go 程序的内存分配请求驱动。

**使用者易犯错的点：**

假设开发者直接使用 `addrRanges` 来管理自己的内存，可能会犯以下错误：

1. **添加重叠的地址范围：**  `addrRanges` 的设计假设它管理的范围是不重叠的。如果添加重叠的范围，会导致状态混乱，例如重复分配同一块内存。虽然代码中 `add` 方法有合并相邻范围的逻辑，但并没有明确处理任意重叠的情况。

   ```go
   // 错误示例：添加重叠的地址范围
   region1 := makeAddrRange(0x1000, 0x5000)
   ranges.add(region1)
   region2 := makeAddrRange(0x3000, 0x7000) // 与 region1 重叠
   // 此时 ranges 的状态是不确定的，可能会导致错误
   // ranges.add(region2)
   ```

2. **对 `addrRange` 进行不正确的裁剪：** `subtract` 方法假设输入范围与被裁剪的范围只有单侧重叠或相等，如果出现内含的情况会 `throw`。不理解这个假设可能会导致程序 panic。

   ```go
   regionA := makeAddrRange(0x1000, 0x5000)
   regionB := makeAddrRange(0x2000, 0x3000) // regionB 完全包含在 regionA 中
   // 调用 subtract 会导致 panic
   // regionA.subtract(regionB)
   ```

总而言之，`go/src/runtime/mranges.go` 提供了一个用于管理有序地址范围的底层数据结构，它在 Go 运行时系统中扮演着关键的角色，尤其是在堆内存管理方面。开发者直接使用它的机会不多，但理解其原理有助于深入理解 Go 的内存管理机制。

Prompt: 
```
这是路径为go/src/runtime/mranges.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Address range data structure.
//
// This file contains an implementation of a data structure which
// manages ordered address ranges.

package runtime

import (
	"internal/goarch"
	"internal/runtime/atomic"
	"unsafe"
)

// addrRange represents a region of address space.
//
// An addrRange must never span a gap in the address space.
type addrRange struct {
	// base and limit together represent the region of address space
	// [base, limit). That is, base is inclusive, limit is exclusive.
	// These are address over an offset view of the address space on
	// platforms with a segmented address space, that is, on platforms
	// where arenaBaseOffset != 0.
	base, limit offAddr
}

// makeAddrRange creates a new address range from two virtual addresses.
//
// Throws if the base and limit are not in the same memory segment.
func makeAddrRange(base, limit uintptr) addrRange {
	r := addrRange{offAddr{base}, offAddr{limit}}
	if (base-arenaBaseOffset >= base) != (limit-arenaBaseOffset >= limit) {
		throw("addr range base and limit are not in the same memory segment")
	}
	return r
}

// size returns the size of the range represented in bytes.
func (a addrRange) size() uintptr {
	if !a.base.lessThan(a.limit) {
		return 0
	}
	// Subtraction is safe because limit and base must be in the same
	// segment of the address space.
	return a.limit.diff(a.base)
}

// contains returns whether or not the range contains a given address.
func (a addrRange) contains(addr uintptr) bool {
	return a.base.lessEqual(offAddr{addr}) && (offAddr{addr}).lessThan(a.limit)
}

// subtract takes the addrRange toPrune and cuts out any overlap with
// from, then returns the new range. subtract assumes that a and b
// either don't overlap at all, only overlap on one side, or are equal.
// If b is strictly contained in a, thus forcing a split, it will throw.
func (a addrRange) subtract(b addrRange) addrRange {
	if b.base.lessEqual(a.base) && a.limit.lessEqual(b.limit) {
		return addrRange{}
	} else if a.base.lessThan(b.base) && b.limit.lessThan(a.limit) {
		throw("bad prune")
	} else if b.limit.lessThan(a.limit) && a.base.lessThan(b.limit) {
		a.base = b.limit
	} else if a.base.lessThan(b.base) && b.base.lessThan(a.limit) {
		a.limit = b.base
	}
	return a
}

// takeFromFront takes len bytes from the front of the address range, aligning
// the base to align first. On success, returns the aligned start of the region
// taken and true.
func (a *addrRange) takeFromFront(len uintptr, align uint8) (uintptr, bool) {
	base := alignUp(a.base.addr(), uintptr(align)) + len
	if base > a.limit.addr() {
		return 0, false
	}
	a.base = offAddr{base}
	return base - len, true
}

// takeFromBack takes len bytes from the end of the address range, aligning
// the limit to align after subtracting len. On success, returns the aligned
// start of the region taken and true.
func (a *addrRange) takeFromBack(len uintptr, align uint8) (uintptr, bool) {
	limit := alignDown(a.limit.addr()-len, uintptr(align))
	if a.base.addr() > limit {
		return 0, false
	}
	a.limit = offAddr{limit}
	return limit, true
}

// removeGreaterEqual removes all addresses in a greater than or equal
// to addr and returns the new range.
func (a addrRange) removeGreaterEqual(addr uintptr) addrRange {
	if (offAddr{addr}).lessEqual(a.base) {
		return addrRange{}
	}
	if a.limit.lessEqual(offAddr{addr}) {
		return a
	}
	return makeAddrRange(a.base.addr(), addr)
}

var (
	// minOffAddr is the minimum address in the offset space, and
	// it corresponds to the virtual address arenaBaseOffset.
	minOffAddr = offAddr{arenaBaseOffset}

	// maxOffAddr is the maximum address in the offset address
	// space. It corresponds to the highest virtual address representable
	// by the page alloc chunk and heap arena maps.
	maxOffAddr = offAddr{(((1 << heapAddrBits) - 1) + arenaBaseOffset) & uintptrMask}
)

// offAddr represents an address in a contiguous view
// of the address space on systems where the address space is
// segmented. On other systems, it's just a normal address.
type offAddr struct {
	// a is just the virtual address, but should never be used
	// directly. Call addr() to get this value instead.
	a uintptr
}

// add adds a uintptr offset to the offAddr.
func (l offAddr) add(bytes uintptr) offAddr {
	return offAddr{a: l.a + bytes}
}

// sub subtracts a uintptr offset from the offAddr.
func (l offAddr) sub(bytes uintptr) offAddr {
	return offAddr{a: l.a - bytes}
}

// diff returns the amount of bytes in between the
// two offAddrs.
func (l1 offAddr) diff(l2 offAddr) uintptr {
	return l1.a - l2.a
}

// lessThan returns true if l1 is less than l2 in the offset
// address space.
func (l1 offAddr) lessThan(l2 offAddr) bool {
	return (l1.a - arenaBaseOffset) < (l2.a - arenaBaseOffset)
}

// lessEqual returns true if l1 is less than or equal to l2 in
// the offset address space.
func (l1 offAddr) lessEqual(l2 offAddr) bool {
	return (l1.a - arenaBaseOffset) <= (l2.a - arenaBaseOffset)
}

// equal returns true if the two offAddr values are equal.
func (l1 offAddr) equal(l2 offAddr) bool {
	// No need to compare in the offset space, it
	// means the same thing.
	return l1 == l2
}

// addr returns the virtual address for this offset address.
func (l offAddr) addr() uintptr {
	return l.a
}

// atomicOffAddr is like offAddr, but operations on it are atomic.
// It also contains operations to be able to store marked addresses
// to ensure that they're not overridden until they've been seen.
type atomicOffAddr struct {
	// a contains the offset address, unlike offAddr.
	a atomic.Int64
}

// Clear attempts to store minOffAddr in atomicOffAddr. It may fail
// if a marked value is placed in the box in the meanwhile.
func (b *atomicOffAddr) Clear() {
	for {
		old := b.a.Load()
		if old < 0 {
			return
		}
		if b.a.CompareAndSwap(old, int64(minOffAddr.addr()-arenaBaseOffset)) {
			return
		}
	}
}

// StoreMin stores addr if it's less than the current value in the
// offset address space if the current value is not marked.
func (b *atomicOffAddr) StoreMin(addr uintptr) {
	new := int64(addr - arenaBaseOffset)
	for {
		old := b.a.Load()
		if old < new {
			return
		}
		if b.a.CompareAndSwap(old, new) {
			return
		}
	}
}

// StoreUnmark attempts to unmark the value in atomicOffAddr and
// replace it with newAddr. markedAddr must be a marked address
// returned by Load. This function will not store newAddr if the
// box no longer contains markedAddr.
func (b *atomicOffAddr) StoreUnmark(markedAddr, newAddr uintptr) {
	b.a.CompareAndSwap(-int64(markedAddr-arenaBaseOffset), int64(newAddr-arenaBaseOffset))
}

// StoreMarked stores addr but first converted to the offset address
// space and then negated.
func (b *atomicOffAddr) StoreMarked(addr uintptr) {
	b.a.Store(-int64(addr - arenaBaseOffset))
}

// Load returns the address in the box as a virtual address. It also
// returns if the value was marked or not.
func (b *atomicOffAddr) Load() (uintptr, bool) {
	v := b.a.Load()
	wasMarked := false
	if v < 0 {
		wasMarked = true
		v = -v
	}
	return uintptr(v) + arenaBaseOffset, wasMarked
}

// addrRanges is a data structure holding a collection of ranges of
// address space.
//
// The ranges are coalesced eagerly to reduce the
// number ranges it holds.
//
// The slice backing store for this field is persistentalloc'd
// and thus there is no way to free it.
//
// addrRanges is not thread-safe.
type addrRanges struct {
	// ranges is a slice of ranges sorted by base.
	ranges []addrRange

	// totalBytes is the total amount of address space in bytes counted by
	// this addrRanges.
	totalBytes uintptr

	// sysStat is the stat to track allocations by this type
	sysStat *sysMemStat
}

func (a *addrRanges) init(sysStat *sysMemStat) {
	ranges := (*notInHeapSlice)(unsafe.Pointer(&a.ranges))
	ranges.len = 0
	ranges.cap = 16
	ranges.array = (*notInHeap)(persistentalloc(unsafe.Sizeof(addrRange{})*uintptr(ranges.cap), goarch.PtrSize, sysStat))
	a.sysStat = sysStat
	a.totalBytes = 0
}

// findSucc returns the first index in a such that addr is
// less than the base of the addrRange at that index.
func (a *addrRanges) findSucc(addr uintptr) int {
	base := offAddr{addr}

	// Narrow down the search space via a binary search
	// for large addrRanges until we have at most iterMax
	// candidates left.
	const iterMax = 8
	bot, top := 0, len(a.ranges)
	for top-bot > iterMax {
		i := int(uint(bot+top) >> 1)
		if a.ranges[i].contains(base.addr()) {
			// a.ranges[i] contains base, so
			// its successor is the next index.
			return i + 1
		}
		if base.lessThan(a.ranges[i].base) {
			// In this case i might actually be
			// the successor, but we can't be sure
			// until we check the ones before it.
			top = i
		} else {
			// In this case we know base is
			// greater than or equal to a.ranges[i].limit-1,
			// so i is definitely not the successor.
			// We already checked i, so pick the next
			// one.
			bot = i + 1
		}
	}
	// There are top-bot candidates left, so
	// iterate over them and find the first that
	// base is strictly less than.
	for i := bot; i < top; i++ {
		if base.lessThan(a.ranges[i].base) {
			return i
		}
	}
	return top
}

// findAddrGreaterEqual returns the smallest address represented by a
// that is >= addr. Thus, if the address is represented by a,
// then it returns addr. The second return value indicates whether
// such an address exists for addr in a. That is, if addr is larger than
// any address known to a, the second return value will be false.
func (a *addrRanges) findAddrGreaterEqual(addr uintptr) (uintptr, bool) {
	i := a.findSucc(addr)
	if i == 0 {
		return a.ranges[0].base.addr(), true
	}
	if a.ranges[i-1].contains(addr) {
		return addr, true
	}
	if i < len(a.ranges) {
		return a.ranges[i].base.addr(), true
	}
	return 0, false
}

// contains returns true if a covers the address addr.
func (a *addrRanges) contains(addr uintptr) bool {
	i := a.findSucc(addr)
	if i == 0 {
		return false
	}
	return a.ranges[i-1].contains(addr)
}

// add inserts a new address range to a.
//
// r must not overlap with any address range in a and r.size() must be > 0.
func (a *addrRanges) add(r addrRange) {
	// The copies in this function are potentially expensive, but this data
	// structure is meant to represent the Go heap. At worst, copying this
	// would take ~160µs assuming a conservative copying rate of 25 GiB/s (the
	// copy will almost never trigger a page fault) for a 1 TiB heap with 4 MiB
	// arenas which is completely discontiguous. ~160µs is still a lot, but in
	// practice most platforms have 64 MiB arenas (which cuts this by a factor
	// of 16) and Go heaps are usually mostly contiguous, so the chance that
	// an addrRanges even grows to that size is extremely low.

	// An empty range has no effect on the set of addresses represented
	// by a, but passing a zero-sized range is almost always a bug.
	if r.size() == 0 {
		print("runtime: range = {", hex(r.base.addr()), ", ", hex(r.limit.addr()), "}\n")
		throw("attempted to add zero-sized address range")
	}
	// Because we assume r is not currently represented in a,
	// findSucc gives us our insertion index.
	i := a.findSucc(r.base.addr())
	coalescesDown := i > 0 && a.ranges[i-1].limit.equal(r.base)
	coalescesUp := i < len(a.ranges) && r.limit.equal(a.ranges[i].base)
	if coalescesUp && coalescesDown {
		// We have neighbors and they both border us.
		// Merge a.ranges[i-1], r, and a.ranges[i] together into a.ranges[i-1].
		a.ranges[i-1].limit = a.ranges[i].limit

		// Delete a.ranges[i].
		copy(a.ranges[i:], a.ranges[i+1:])
		a.ranges = a.ranges[:len(a.ranges)-1]
	} else if coalescesDown {
		// We have a neighbor at a lower address only and it borders us.
		// Merge the new space into a.ranges[i-1].
		a.ranges[i-1].limit = r.limit
	} else if coalescesUp {
		// We have a neighbor at a higher address only and it borders us.
		// Merge the new space into a.ranges[i].
		a.ranges[i].base = r.base
	} else {
		// We may or may not have neighbors which don't border us.
		// Add the new range.
		if len(a.ranges)+1 > cap(a.ranges) {
			// Grow the array. Note that this leaks the old array, but since
			// we're doubling we have at most 2x waste. For a 1 TiB heap and
			// 4 MiB arenas which are all discontiguous (both very conservative
			// assumptions), this would waste at most 4 MiB of memory.
			oldRanges := a.ranges
			ranges := (*notInHeapSlice)(unsafe.Pointer(&a.ranges))
			ranges.len = len(oldRanges) + 1
			ranges.cap = cap(oldRanges) * 2
			ranges.array = (*notInHeap)(persistentalloc(unsafe.Sizeof(addrRange{})*uintptr(ranges.cap), goarch.PtrSize, a.sysStat))

			// Copy in the old array, but make space for the new range.
			copy(a.ranges[:i], oldRanges[:i])
			copy(a.ranges[i+1:], oldRanges[i:])
		} else {
			a.ranges = a.ranges[:len(a.ranges)+1]
			copy(a.ranges[i+1:], a.ranges[i:])
		}
		a.ranges[i] = r
	}
	a.totalBytes += r.size()
}

// removeLast removes and returns the highest-addressed contiguous range
// of a, or the last nBytes of that range, whichever is smaller. If a is
// empty, it returns an empty range.
func (a *addrRanges) removeLast(nBytes uintptr) addrRange {
	if len(a.ranges) == 0 {
		return addrRange{}
	}
	r := a.ranges[len(a.ranges)-1]
	size := r.size()
	if size > nBytes {
		newEnd := r.limit.sub(nBytes)
		a.ranges[len(a.ranges)-1].limit = newEnd
		a.totalBytes -= nBytes
		return addrRange{newEnd, r.limit}
	}
	a.ranges = a.ranges[:len(a.ranges)-1]
	a.totalBytes -= size
	return r
}

// removeGreaterEqual removes the ranges of a which are above addr, and additionally
// splits any range containing addr.
func (a *addrRanges) removeGreaterEqual(addr uintptr) {
	pivot := a.findSucc(addr)
	if pivot == 0 {
		// addr is before all ranges in a.
		a.totalBytes = 0
		a.ranges = a.ranges[:0]
		return
	}
	removed := uintptr(0)
	for _, r := range a.ranges[pivot:] {
		removed += r.size()
	}
	if r := a.ranges[pivot-1]; r.contains(addr) {
		removed += r.size()
		r = r.removeGreaterEqual(addr)
		if r.size() == 0 {
			pivot--
		} else {
			removed -= r.size()
			a.ranges[pivot-1] = r
		}
	}
	a.ranges = a.ranges[:pivot]
	a.totalBytes -= removed
}

// cloneInto makes a deep clone of a's state into b, re-using
// b's ranges if able.
func (a *addrRanges) cloneInto(b *addrRanges) {
	if len(a.ranges) > cap(b.ranges) {
		// Grow the array.
		ranges := (*notInHeapSlice)(unsafe.Pointer(&b.ranges))
		ranges.len = 0
		ranges.cap = cap(a.ranges)
		ranges.array = (*notInHeap)(persistentalloc(unsafe.Sizeof(addrRange{})*uintptr(ranges.cap), goarch.PtrSize, b.sysStat))
	}
	b.ranges = b.ranges[:len(a.ranges)]
	b.totalBytes = a.totalBytes
	copy(b.ranges, a.ranges)
}

"""



```