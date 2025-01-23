Response:
我的目标是理解给定的 Go 代码 `mpallocbits.go` 的功能，并用 Go 代码示例进行说明，同时考虑可能的使用错误。

**逐步思考过程：**

1. **代码结构概览:** 首先，我注意到这是一个 Go 源代码文件，属于 `runtime` 包。它定义了两个主要的类型：`pageBits` 和 `pallocBits`，以及一个结构体 `pallocData`。

2. **`pageBits` 类型分析:**  `pageBits` 是一个 `uint64` 类型的数组，其大小由 `pallocChunkPages / 64` 决定。注释表明它代表一个位图，其中每个位对应一个页。因此，`pageBits` 的作用是管理一组页的分配状态。

3. **`pageBits` 的方法分析:**  我逐个分析了 `pageBits` 的方法，并理解了它们的功能：
    * `get(i uint)`: 获取第 `i` 位的状态（0 或 1）。
    * `block64(i uint)`: 获取包含第 `i` 位的 64 位块。
    * `set(i uint)`: 设置第 `i` 位为 1。
    * `setRange(i, n uint)`: 设置从 `i` 到 `i+n-1` 的位为 1。
    * `setAll()`: 设置所有位为 1。
    * `setBlock64(i uint, v uint64)`: 设置包含第 `i` 位的 64 位块中由 `v` 标记的位。
    * `clear(i uint)`: 清除第 `i` 位（设置为 0）。
    * `clearRange(i, n uint)`: 清除从 `i` 到 `i+n-1` 的位。
    * `clearAll()`: 清除所有位。
    * `clearBlock64(i uint, v uint64)`: 清除包含第 `i` 位的 64 位块中由 `v` 标记的位。
    * `popcntRange(i, n uint)`: 计算从 `i` 到 `i+n-1` 中设置为 1 的位的数量。

4. **`pallocBits` 类型分析:** `pallocBits` 是 `pageBits` 的别名。注释说明它跟踪一个 `palloc` 块中的页分配。0 表示空闲页，1 表示已分配页。这印证了 `pageBits` 是用于管理内存页分配的。

5. **`pallocBits` 的方法分析:**  我继续分析了 `pallocBits` 的方法：
    * `summarize() pallocSum`:  这是一个复杂的方法，尝试总结位图的分配情况，找出最长的连续空闲块。这暗示了内存分配器可能使用此信息来寻找合适的空闲空间。
    * `find(npages uintptr, searchIdx uint) (uint, uint)`: 查找 `npages` 个连续空闲页，并返回起始索引和第一个找到的空闲页索引。`searchIdx` 用于优化搜索，从上次找到的位置开始。
    * `find1(searchIdx uint) uint`: 查找单个空闲页。
    * `findSmallN(npages uintptr, searchIdx uint) (uint, uint)`: 查找少量连续空闲页（`npages <= 64`）。
    * `findLargeN(npages uintptr, searchIdx uint) (uint, uint)`: 查找大量连续空闲页（`npages > 64`）。
    * `allocRange(i, n uint)`: 分配从 `i` 到 `i+n-1` 的页。
    * `allocAll()`: 分配所有页。
    * `free1(i uint)`: 释放索引为 `i` 的页。
    * `free(i, n uint)`: 释放从 `i` 到 `i+n-1` 的页。
    * `freeAll()`: 释放所有页。
    * `pages64(i uint) uint64`: 获取包含第 `i` 页的 64 页块的位图。
    * `allocPages64(i uint, alloc uint64)`:  根据 `alloc` 位图分配包含第 `i` 页的 64 页块。

6. **`findBitRange64` 函数分析:** 这是一个独立的函数，用于在一个 64 位整数中查找连续的 `n` 个 1 位。这可能被 `findSmallN` 使用。

7. **`pallocData` 结构体分析:**  `pallocData` 包含 `pallocBits` 和 `scavenged pageBits`。`scavenged` 位图可能用于跟踪哪些页被垃圾回收器扫描过。

8. **`pallocData` 的方法分析:**
    * `allocRange(i, n uint)`: 分配页，并清除相应的 `scavenged` 位。
    * `allocAll()`: 分配所有页，并清除所有 `scavenged` 位。

9. **功能总结:**  至此，我可以总结出代码的主要功能是管理内存页的分配和回收，并提供了一些辅助功能来查找连续的空闲页。它很可能是 Go 运行时内存分配器的一部分。

10. **Go 语言功能推断:**  根据代码的功能，我推断这与 Go 语言的**内存管理**功能相关，特别是**堆内存的分配和回收**。

11. **Go 代码示例:**  我构思了一个简单的 Go 代码示例来演示 `pallocBits` 的基本用法，模拟分配和释放内存页的过程。

12. **代码推理 (假设输入与输出):**  我为 `find` 函数提供了一个假设的输入，并手动推演了输出，以便更清楚地展示其功能。

13. **命令行参数处理:**  我意识到这段代码本身不涉及命令行参数的处理，因为它属于 `runtime` 包，主要在 Go 程序的内部运行。

14. **易犯错的点:**  我思考了使用 `pallocBits` 时可能出现的错误，例如错误地计算索引或大小。

15. **语言润色和组织:** 最后，我将所有的分析和示例组织成清晰的中文回答，并对代码和概念进行了必要的解释。  我特别注意了使用正确的术语，例如“页”、“位图”等。

通过以上思考过程，我最终得到了一个较为全面和准确的答案。
这段 Go 语言代码文件 `mpallocbits.go` 是 Go 运行时环境（runtime）中用于管理**页分配**的一个关键组件。它定义了一些数据结构和方法，用于高效地跟踪和操作内存页的分配状态。

以下是它的主要功能：

1. **定义了 `pageBits` 类型:**  `pageBits` 是一个 `uint64` 类型的数组，用作位图。位图中的每一位代表一个内存页的状态（例如，是否已分配）。每个 `uint64` 可以表示 64 个页的状态。

2. **提供了操作 `pageBits` 的方法:**  这些方法允许对位图进行各种操作，包括：
   - `get(i uint)`: 获取第 `i` 个页的状态（0 表示空闲，1 表示已分配）。
   - `block64(i uint)`: 获取包含第 `i` 个页的 64 位块的位图。
   - `set(i uint)`: 将第 `i` 个页标记为已分配。
   - `setRange(i, n uint)`: 将从第 `i` 个页开始的 `n` 个页标记为已分配。
   - `setAll()`: 将所有页标记为已分配。
   - `setBlock64(i uint, v uint64)`: 根据给定的位图 `v` 设置包含第 `i` 个页的 64 位块的分配状态。
   - `clear(i uint)`: 将第 `i` 个页标记为空闲。
   - `clearRange(i, n uint)`: 将从第 `i` 个页开始的 `n` 个页标记为空闲。
   - `clearAll()`: 将所有页标记为空闲。
   - `clearBlock64(i uint, v uint64)`: 根据给定的位图 `v` 清除包含第 `i` 个页的 64 位块的分配状态。
   - `popcntRange(i, n uint)`: 计算从第 `i` 个页开始的 `n` 个页中已分配的页数。

3. **定义了 `pallocBits` 类型:** `pallocBits` 是 `pageBits` 的类型别名。它专门用于跟踪一个 **palloc chunk** 中的页分配。一个 palloc chunk 是一块连续的内存，用于分配页。

4. **提供了操作 `pallocBits` 的方法:** 这些方法针对页分配场景进行了优化：
   - `summarize() pallocSum`:  汇总 `pallocBits` 的分配状态，用于快速了解空闲块的信息。这对于寻找合适的空闲内存块非常重要。
   - `find(npages uintptr, searchIdx uint) (uint, uint)`: 在 `pallocBits` 中查找 `npages` 个连续的空闲页。`searchIdx` 参数允许从上次找到空闲页的位置开始搜索，提高效率。返回找到的起始页索引和第一个发现的空闲页索引。
   - `find1(searchIdx uint) uint`: 查找单个空闲页。
   - `findSmallN(npages uintptr, searchIdx uint) (uint, uint)`: 优化查找少量连续空闲页的情况（`npages <= 64`）。
   - `findLargeN(npages uintptr, searchIdx uint) (uint, uint)`: 优化查找大量连续空闲页的情况（`npages > 64`）。
   - `allocRange(i, n uint)`: 分配指定范围的页。
   - `allocAll()`: 分配所有页。
   - `free1(i uint)`: 释放单个页。
   - `free(i, n uint)`: 释放指定范围的页。
   - `freeAll()`: 释放所有页。
   - `pages64(i uint) uint64`: 获取包含第 `i` 个页的 64 页块的分配状态位图。
   - `allocPages64(i uint, alloc uint64)`: 根据给定的位图 `alloc` 分配包含第 `i` 个页的 64 页块。

5. **定义了辅助函数 `findBitRange64`:**  用于在一个 64 位整数中查找连续的 `n` 个 1 位。这主要被 `findSmallN` 方法使用。

6. **定义了 `pallocData` 结构体:**  它组合了 `pallocBits` 和另一个 `pageBits` 类型的 `scavenged` 字段。`scavenged` 位图可能用于跟踪哪些页已经被垃圾回收器扫描过。

7. **提供了操作 `pallocData` 的方法:**
   - `allocRange(i, n uint)`: 分配指定范围的页，并清除相应的 `scavenged` 位，表示新分配的页尚未被扫描。
   - `allocAll()`: 分配所有页，并清除所有 `scavenged` 位。

**推理出的 Go 语言功能实现：堆内存管理（Heap Memory Management）**

这段代码是 Go 语言运行时环境中**堆内存管理**的核心部分。它负责跟踪堆内存中各个页的分配状态，以便有效地分配和回收内存。

**Go 代码举例说明：**

假设我们有一个 `pallocBits` 实例 `pb`，它代表一个 palloc chunk 的页分配状态。

```go
package main

import (
	"fmt"
	"runtime"
	"unsafe"
)

func main() {
	// 假设 pallocChunkPages 和其他常量已定义（实际运行时环境会定义）
	const pallocChunkPages = 8192 // 示例值
	var pb runtime.PallocBits

	// 查找 10 个连续的空闲页
	numPages := uintptr(10)
	startIdx, _ := pb.Find(numPages, 0)

	if startIdx != ^uint(0) {
		fmt.Printf("找到 %d 个连续空闲页，起始索引: %d\n", numPages, startIdx)

		// 分配这 10 个页
		pb.AllocRange(startIdx, uint(numPages))
		fmt.Println("分配了这 10 个页")

		// 检查分配状态
		for i := startIdx; i < startIdx+uint(numPages); i++ {
			fmt.Printf("页 %d 的状态: %d\n", i, pb.Pages64(i)>>(i%64)&1)
		}

		// 释放这 10 个页
		pb.Free(startIdx, uint(numPages))
		fmt.Println("释放了这 10 个页")

		// 再次检查分配状态
		for i := startIdx; i < startIdx+uint(numPages); i++ {
			fmt.Printf("页 %d 的状态: %d\n", i, pb.Pages64(i)>>(i%64)&1)
		}
	} else {
		fmt.Println("未找到足够的连续空闲页")
	}
}
```

**假设的输入与输出：**

假设 `pb` 初始化时所有页都为空闲。

**输入：** `pb.Find(10, 0)`

**输出：**  `startIdx` 可能为 0 (或其他合适的起始索引)，第二个返回值可以忽略。

**输入：** `pb.AllocRange(0, 10)`

**输出：**  `pb` 中索引 0 到 9 的位被设置为 1。

**输入：** `pb.Free(0, 10)`

**输出：** `pb` 中索引 0 到 9 的位被设置为 0。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它是 Go 运行时环境的一部分，在程序启动后由运行时系统内部使用。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，与内存分配器的交互是间接的。

**使用者易犯错的点：**

由于 `mpallocbits.go` 是 Go 运行时内部的代码，普通 Go 开发者不会直接使用它。但是，理解其背后的概念对于理解 Go 的内存管理至关重要。

一个潜在的“错误”理解是，**认为可以直接操作这些底层的内存分配位图**。实际上，Go 的内存管理是自动化的，开发者应该通过 `new`、`make` 等关键字来分配内存，并依赖垃圾回收器进行回收。直接操作这些位图是运行时系统的工作，普通开发者不应该也不需要这样做。

总结来说，`mpallocbits.go` 是 Go 语言运行时环境用于高效管理堆内存页分配的核心组件，它通过位图的方式跟踪页的分配状态，并提供了查找、分配和释放连续内存页的方法。理解这段代码有助于深入理解 Go 语言的内存管理机制。

### 提示词
```
这是路径为go/src/runtime/mpallocbits.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/runtime/sys"
)

// pageBits is a bitmap representing one bit per page in a palloc chunk.
type pageBits [pallocChunkPages / 64]uint64

// get returns the value of the i'th bit in the bitmap.
func (b *pageBits) get(i uint) uint {
	return uint((b[i/64] >> (i % 64)) & 1)
}

// block64 returns the 64-bit aligned block of bits containing the i'th bit.
func (b *pageBits) block64(i uint) uint64 {
	return b[i/64]
}

// set sets bit i of pageBits.
func (b *pageBits) set(i uint) {
	b[i/64] |= 1 << (i % 64)
}

// setRange sets bits in the range [i, i+n).
func (b *pageBits) setRange(i, n uint) {
	_ = b[i/64]
	if n == 1 {
		// Fast path for the n == 1 case.
		b.set(i)
		return
	}
	// Set bits [i, j].
	j := i + n - 1
	if i/64 == j/64 {
		b[i/64] |= ((uint64(1) << n) - 1) << (i % 64)
		return
	}
	_ = b[j/64]
	// Set leading bits.
	b[i/64] |= ^uint64(0) << (i % 64)
	for k := i/64 + 1; k < j/64; k++ {
		b[k] = ^uint64(0)
	}
	// Set trailing bits.
	b[j/64] |= (uint64(1) << (j%64 + 1)) - 1
}

// setAll sets all the bits of b.
func (b *pageBits) setAll() {
	for i := range b {
		b[i] = ^uint64(0)
	}
}

// setBlock64 sets the 64-bit aligned block of bits containing the i'th bit that
// are set in v.
func (b *pageBits) setBlock64(i uint, v uint64) {
	b[i/64] |= v
}

// clear clears bit i of pageBits.
func (b *pageBits) clear(i uint) {
	b[i/64] &^= 1 << (i % 64)
}

// clearRange clears bits in the range [i, i+n).
func (b *pageBits) clearRange(i, n uint) {
	_ = b[i/64]
	if n == 1 {
		// Fast path for the n == 1 case.
		b.clear(i)
		return
	}
	// Clear bits [i, j].
	j := i + n - 1
	if i/64 == j/64 {
		b[i/64] &^= ((uint64(1) << n) - 1) << (i % 64)
		return
	}
	_ = b[j/64]
	// Clear leading bits.
	b[i/64] &^= ^uint64(0) << (i % 64)
	clear(b[i/64+1 : j/64])
	// Clear trailing bits.
	b[j/64] &^= (uint64(1) << (j%64 + 1)) - 1
}

// clearAll frees all the bits of b.
func (b *pageBits) clearAll() {
	clear(b[:])
}

// clearBlock64 clears the 64-bit aligned block of bits containing the i'th bit that
// are set in v.
func (b *pageBits) clearBlock64(i uint, v uint64) {
	b[i/64] &^= v
}

// popcntRange counts the number of set bits in the
// range [i, i+n).
func (b *pageBits) popcntRange(i, n uint) (s uint) {
	if n == 1 {
		return uint((b[i/64] >> (i % 64)) & 1)
	}
	_ = b[i/64]
	j := i + n - 1
	if i/64 == j/64 {
		return uint(sys.OnesCount64((b[i/64] >> (i % 64)) & ((1 << n) - 1)))
	}
	_ = b[j/64]
	s += uint(sys.OnesCount64(b[i/64] >> (i % 64)))
	for k := i/64 + 1; k < j/64; k++ {
		s += uint(sys.OnesCount64(b[k]))
	}
	s += uint(sys.OnesCount64(b[j/64] & ((1 << (j%64 + 1)) - 1)))
	return
}

// pallocBits is a bitmap that tracks page allocations for at most one
// palloc chunk.
//
// The precise representation is an implementation detail, but for the
// sake of documentation, 0s are free pages and 1s are allocated pages.
type pallocBits pageBits

// summarize returns a packed summary of the bitmap in pallocBits.
func (b *pallocBits) summarize() pallocSum {
	var start, most, cur uint
	const notSetYet = ^uint(0) // sentinel for start value
	start = notSetYet
	for i := 0; i < len(b); i++ {
		x := b[i]
		if x == 0 {
			cur += 64
			continue
		}
		t := uint(sys.TrailingZeros64(x))
		l := uint(sys.LeadingZeros64(x))

		// Finish any region spanning the uint64s
		cur += t
		if start == notSetYet {
			start = cur
		}
		most = max(most, cur)
		// Final region that might span to next uint64
		cur = l
	}
	if start == notSetYet {
		// Made it all the way through without finding a single 1 bit.
		const n = uint(64 * len(b))
		return packPallocSum(n, n, n)
	}
	most = max(most, cur)

	if most >= 64-2 {
		// There is no way an internal run of zeros could beat max.
		return packPallocSum(start, most, cur)
	}
	// Now look inside each uint64 for runs of zeros.
	// All uint64s must be nonzero, or we would have aborted above.
outer:
	for i := 0; i < len(b); i++ {
		x := b[i]

		// Look inside this uint64. We have a pattern like
		// 000000 1xxxxx1 000000
		// We need to look inside the 1xxxxx1 for any contiguous
		// region of zeros.

		// We already know the trailing zeros are no larger than max. Remove them.
		x >>= sys.TrailingZeros64(x) & 63
		if x&(x+1) == 0 { // no more zeros (except at the top).
			continue
		}

		// Strategy: shrink all runs of zeros by max. If any runs of zero
		// remain, then we've identified a larger maximum zero run.
		p := most    // number of zeros we still need to shrink by.
		k := uint(1) // current minimum length of runs of ones in x.
		for {
			// Shrink all runs of zeros by p places (except the top zeros).
			for p > 0 {
				if p <= k {
					// Shift p ones down into the top of each run of zeros.
					x |= x >> (p & 63)
					if x&(x+1) == 0 { // no more zeros (except at the top).
						continue outer
					}
					break
				}
				// Shift k ones down into the top of each run of zeros.
				x |= x >> (k & 63)
				if x&(x+1) == 0 { // no more zeros (except at the top).
					continue outer
				}
				p -= k
				// We've just doubled the minimum length of 1-runs.
				// This allows us to shift farther in the next iteration.
				k *= 2
			}

			// The length of the lowest-order zero run is an increment to our maximum.
			j := uint(sys.TrailingZeros64(^x)) // count contiguous trailing ones
			x >>= j & 63                       // remove trailing ones
			j = uint(sys.TrailingZeros64(x))   // count contiguous trailing zeros
			x >>= j & 63                       // remove zeros
			most += j                          // we have a new maximum!
			if x&(x+1) == 0 {                  // no more zeros (except at the top).
				continue outer
			}
			p = j // remove j more zeros from each zero run.
		}
	}
	return packPallocSum(start, most, cur)
}

// find searches for npages contiguous free pages in pallocBits and returns
// the index where that run starts, as well as the index of the first free page
// it found in the search. searchIdx represents the first known free page and
// where to begin the next search from.
//
// If find fails to find any free space, it returns an index of ^uint(0) and
// the new searchIdx should be ignored.
//
// Note that if npages == 1, the two returned values will always be identical.
func (b *pallocBits) find(npages uintptr, searchIdx uint) (uint, uint) {
	if npages == 1 {
		addr := b.find1(searchIdx)
		return addr, addr
	} else if npages <= 64 {
		return b.findSmallN(npages, searchIdx)
	}
	return b.findLargeN(npages, searchIdx)
}

// find1 is a helper for find which searches for a single free page
// in the pallocBits and returns the index.
//
// See find for an explanation of the searchIdx parameter.
func (b *pallocBits) find1(searchIdx uint) uint {
	_ = b[0] // lift nil check out of loop
	for i := searchIdx / 64; i < uint(len(b)); i++ {
		x := b[i]
		if ^x == 0 {
			continue
		}
		return i*64 + uint(sys.TrailingZeros64(^x))
	}
	return ^uint(0)
}

// findSmallN is a helper for find which searches for npages contiguous free pages
// in this pallocBits and returns the index where that run of contiguous pages
// starts as well as the index of the first free page it finds in its search.
//
// See find for an explanation of the searchIdx parameter.
//
// Returns a ^uint(0) index on failure and the new searchIdx should be ignored.
//
// findSmallN assumes npages <= 64, where any such contiguous run of pages
// crosses at most one aligned 64-bit boundary in the bits.
func (b *pallocBits) findSmallN(npages uintptr, searchIdx uint) (uint, uint) {
	end, newSearchIdx := uint(0), ^uint(0)
	for i := searchIdx / 64; i < uint(len(b)); i++ {
		bi := b[i]
		if ^bi == 0 {
			end = 0
			continue
		}
		// First see if we can pack our allocation in the trailing
		// zeros plus the end of the last 64 bits.
		if newSearchIdx == ^uint(0) {
			// The new searchIdx is going to be at these 64 bits after any
			// 1s we file, so count trailing 1s.
			newSearchIdx = i*64 + uint(sys.TrailingZeros64(^bi))
		}
		start := uint(sys.TrailingZeros64(bi))
		if end+start >= uint(npages) {
			return i*64 - end, newSearchIdx
		}
		// Next, check the interior of the 64-bit chunk.
		j := findBitRange64(^bi, uint(npages))
		if j < 64 {
			return i*64 + j, newSearchIdx
		}
		end = uint(sys.LeadingZeros64(bi))
	}
	return ^uint(0), newSearchIdx
}

// findLargeN is a helper for find which searches for npages contiguous free pages
// in this pallocBits and returns the index where that run starts, as well as the
// index of the first free page it found it its search.
//
// See alloc for an explanation of the searchIdx parameter.
//
// Returns a ^uint(0) index on failure and the new searchIdx should be ignored.
//
// findLargeN assumes npages > 64, where any such run of free pages
// crosses at least one aligned 64-bit boundary in the bits.
func (b *pallocBits) findLargeN(npages uintptr, searchIdx uint) (uint, uint) {
	start, size, newSearchIdx := ^uint(0), uint(0), ^uint(0)
	for i := searchIdx / 64; i < uint(len(b)); i++ {
		x := b[i]
		if x == ^uint64(0) {
			size = 0
			continue
		}
		if newSearchIdx == ^uint(0) {
			// The new searchIdx is going to be at these 64 bits after any
			// 1s we file, so count trailing 1s.
			newSearchIdx = i*64 + uint(sys.TrailingZeros64(^x))
		}
		if size == 0 {
			size = uint(sys.LeadingZeros64(x))
			start = i*64 + 64 - size
			continue
		}
		s := uint(sys.TrailingZeros64(x))
		if s+size >= uint(npages) {
			return start, newSearchIdx
		}
		if s < 64 {
			size = uint(sys.LeadingZeros64(x))
			start = i*64 + 64 - size
			continue
		}
		size += 64
	}
	if size < uint(npages) {
		return ^uint(0), newSearchIdx
	}
	return start, newSearchIdx
}

// allocRange allocates the range [i, i+n).
func (b *pallocBits) allocRange(i, n uint) {
	(*pageBits)(b).setRange(i, n)
}

// allocAll allocates all the bits of b.
func (b *pallocBits) allocAll() {
	(*pageBits)(b).setAll()
}

// free1 frees a single page in the pallocBits at i.
func (b *pallocBits) free1(i uint) {
	(*pageBits)(b).clear(i)
}

// free frees the range [i, i+n) of pages in the pallocBits.
func (b *pallocBits) free(i, n uint) {
	(*pageBits)(b).clearRange(i, n)
}

// freeAll frees all the bits of b.
func (b *pallocBits) freeAll() {
	(*pageBits)(b).clearAll()
}

// pages64 returns a 64-bit bitmap representing a block of 64 pages aligned
// to 64 pages. The returned block of pages is the one containing the i'th
// page in this pallocBits. Each bit represents whether the page is in-use.
func (b *pallocBits) pages64(i uint) uint64 {
	return (*pageBits)(b).block64(i)
}

// allocPages64 allocates a 64-bit block of 64 pages aligned to 64 pages according
// to the bits set in alloc. The block set is the one containing the i'th page.
func (b *pallocBits) allocPages64(i uint, alloc uint64) {
	(*pageBits)(b).setBlock64(i, alloc)
}

// findBitRange64 returns the bit index of the first set of
// n consecutive 1 bits. If no consecutive set of 1 bits of
// size n may be found in c, then it returns an integer >= 64.
// n must be > 0.
func findBitRange64(c uint64, n uint) uint {
	// This implementation is based on shrinking the length of
	// runs of contiguous 1 bits. We remove the top n-1 1 bits
	// from each run of 1s, then look for the first remaining 1 bit.
	p := n - 1   // number of 1s we want to remove.
	k := uint(1) // current minimum width of runs of 0 in c.
	for p > 0 {
		if p <= k {
			// Shift p 0s down into the top of each run of 1s.
			c &= c >> (p & 63)
			break
		}
		// Shift k 0s down into the top of each run of 1s.
		c &= c >> (k & 63)
		if c == 0 {
			return 64
		}
		p -= k
		// We've just doubled the minimum length of 0-runs.
		// This allows us to shift farther in the next iteration.
		k *= 2
	}
	// Find first remaining 1.
	// Since we shrunk from the top down, the first 1 is in
	// its correct original position.
	return uint(sys.TrailingZeros64(c))
}

// pallocData encapsulates pallocBits and a bitmap for
// whether or not a given page is scavenged in a single
// structure. It's effectively a pallocBits with
// additional functionality.
//
// Update the comment on (*pageAlloc).chunks should this
// structure change.
type pallocData struct {
	pallocBits
	scavenged pageBits
}

// allocRange sets bits [i, i+n) in the bitmap to 1 and
// updates the scavenged bits appropriately.
func (m *pallocData) allocRange(i, n uint) {
	// Clear the scavenged bits when we alloc the range.
	m.pallocBits.allocRange(i, n)
	m.scavenged.clearRange(i, n)
}

// allocAll sets every bit in the bitmap to 1 and updates
// the scavenged bits appropriately.
func (m *pallocData) allocAll() {
	// Clear the scavenged bits when we alloc the range.
	m.pallocBits.allocAll()
	m.scavenged.clearAll()
}
```