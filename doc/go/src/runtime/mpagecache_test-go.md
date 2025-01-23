Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file name `mpagecache_test.go` and the package `runtime_test` strongly suggest this is a testing file for some runtime functionality. The presence of `PageCache` in function and test names hints that the core functionality being tested is related to a "page cache."

2. **Examine the Helper Functions:**  The first function, `checkPageCache`, is a test utility. It takes a `testing.T`, a `got` `PageCache`, and a `want` `PageCache`. It compares the `Base()`, `Cache()`, and `Scav()` methods of these `PageCache` instances and reports errors if they don't match. This tells us that a `PageCache` likely has these three properties.

3. **Analyze Individual Tests:**  Now, let's go through each test function.

    * **`TestPageCacheAlloc`:** The name suggests it tests the allocation functionality of the `PageCache`. It defines various test cases (named "Empty", "Lo1", "Hi1", etc.). Each test case has a `cache` (a `PageCache` instance created using `NewPageCache`) and a slice of `hits`. Each `hit` struct contains `npages`, `base`, and `scav`. The inner loop calls `c.Alloc(h.npages)` and compares the returned values with `h.base` and `h.scav`. This strongly suggests `PageCache` has an `Alloc` method that takes a number of pages and returns a base address and some other value (likely related to scavenging or metadata). The various test cases with different initial `cache` values and expected `hits` explore different allocation scenarios.

    * **`TestPageCacheFlush`:** This test focuses on a `Flush` method. It uses a helper function `bits64ToBitRanges` to convert a bitmask into ranges. The `runTest` function creates a `PageAlloc` (another data structure), initializes a `PageCache`, calls `c.Flush(b)`, and then checks if the `PageAlloc` has been updated as expected. The test runs with empty, full, and random cache/scav values. This indicates `Flush` likely takes a `PageAlloc` and updates its state based on the `PageCache`'s contents.

    * **`TestPageAllocAllocToCache`:** The name implies this test is about moving allocations *to* the cache. It defines test cases with `beforeAlloc`, `beforeScav`, `hits` (which are `PageCache` instances), and `afterAlloc`, `afterScav`. The test creates a `PageAlloc`, iterates through the `hits`, calling `b.AllocToCache()` and comparing the result with the expected `PageCache` in `hits`. Finally, it compares the state of the `PageAlloc` after the operations with the `afterAlloc` and `afterScav` expectations. This suggests `PageAlloc` has an `AllocToCache` method that returns a `PageCache`, potentially transferring ownership or information about allocated pages to the cache.

4. **Infer Functionality and Data Structures:** Based on the tests, we can infer the following:

    * **`PageCache`:** Represents a cache of memory pages. It has methods like `NewPageCache`, `Base()`, `Cache()`, `Scav()`, `Alloc()`, `Flush()`, and `Empty()`. It stores information about available or scavengeable pages within a chunk.
    * **`PageAlloc`:**  Likely represents the overall allocation state. It seems to track allocated and scavenged memory regions, possibly at a higher level than `PageCache`. It has methods like `NewPageAlloc`, `FreePageAlloc`, and `AllocToCache`.
    * **`BaseChunkIdx`:** A constant representing a base index for memory chunks.
    * **`PageBase`:** A function to calculate a page base address given a chunk index and an offset within the chunk.
    * **`PageSize`:** A constant representing the size of a memory page.
    * **`BitRange`:** A struct likely representing a contiguous range of bits/pages.
    * **`ChunkIdx`:** A type representing an index for memory chunks.
    * **The overall system seems to manage memory allocation at a page level, potentially optimizing for performance by using a cache.**  The `Scav` part likely relates to memory scavenging or reclamation.

5. **Construct Code Examples:** Based on the inferences, we can create example Go code demonstrating the likely usage:

   ```go
   package main

   import (
       "fmt"
       "runtime"
   )

   func main() {
       // Assuming these functions/types exist in the 'runtime' package
       base := runtime.PageBase(runtime.BaseChunkIdx, 0)
       cache := runtime.NewPageCache(base, 0, 0)

       // Allocate 5 pages
       allocatedBase, scavInfo := cache.Alloc(5)
       fmt.Printf("Allocated 5 pages at base: 0x%x, scav info: %d\n", allocatedBase, scavInfo)

       // ... potentially more allocations or other operations ...

       // Create a PageAlloc (assuming its structure and usage)
       // beforeAlloc := ...
       // beforeScav := ...
       // pageAlloc := runtime.NewPageAlloc(beforeAlloc, beforeScav)

       // Flush the cache to the PageAlloc
       // cache.Flush(pageAlloc)
   }
   ```

6. **Address Specific Questions:**  Now, we can answer the user's specific questions:

    * **Functionality:** List the inferred functionalities of the tested code.
    * **Go Language Feature:**  Infer that it's likely related to memory management within the Go runtime.
    * **Code Examples:** Provide the generated Go code example.
    * **Input/Output for Code Reasoning:**  Use the test cases in the code to provide examples of input and output for the `Alloc` method.
    * **Command-Line Arguments:** The provided code doesn't directly handle command-line arguments, so state that.
    * **Common Mistakes:**  Think about potential pitfalls, like incorrect assumptions about the state of the `PageAlloc` when flushing the cache.

7. **Review and Refine:**  Finally, review the analysis and the generated answers to ensure accuracy, clarity, and completeness. For example, ensure that the explanations are in Chinese as requested.
这段代码是Go语言运行时（runtime）包中 `mpagecache_test.go` 文件的一部分，它主要用于测试 **页缓存（Page Cache）** 的相关功能。页缓存是Go运行时内存管理中用于加速分配和回收大块内存页的一种机制。

以下是这段代码的具体功能分解：

**1. `checkPageCache(t *testing.T, got, want PageCache)`:**
   - 这是一个辅助测试函数，用于比较两个 `PageCache` 结构体实例 `got` (实际获取的) 和 `want` (期望的) 是否相等。
   - 它会逐个比较 `PageCache` 的 `Base()` (基地址), `Cache()` (缓存位图), 和 `Scav()` (回收位图) 这三个字段。
   - 如果有任何字段不匹配，它会使用 `t.Errorf` 报告错误信息。

**2. `TestPageCacheAlloc(t *testing.T)`:**
   - 这个测试函数专门测试 `PageCache` 的 **分配 (Allocation)** 功能，即 `Alloc` 方法。
   - 它定义了一系列的测试用例，每个用例包含一个初始的 `PageCache` 状态和一个 `hits` 切片。
   - `hits` 切片中的每个元素 `hit` 结构体定义了期望的分配结果，包括请求分配的页数 (`npages`)、预期的分配基地址 (`base`) 和预期的回收信息 (`scav`)。
   - 测试循环会遍历 `hits` 切片，对当前的 `PageCache` 调用 `Alloc(h.npages)` 方法，并将返回的实际基地址和回收信息与 `hit` 中期望的值进行比较。
   - 如果实际结果与期望不符，则使用 `t.Fatalf` 报告致命错误。
   - 测试用例覆盖了多种场景，包括：
     - 空的页缓存
     - 页缓存中某些位被标记为已使用或可回收
     - 分配不同数量的页
     - 分配可能跨越缓存位图边界的页

**3. `TestPageCacheFlush(t *testing.T)`:**
   - 这个测试函数测试 `PageCache` 的 **刷新 (Flush)** 功能，即 `Flush` 方法。
   - `Flush` 方法的作用是将页缓存中的信息同步回底层的页分配器 (Page Allocator)。
   - 它首先定义了一个辅助函数 `bits64ToBitRanges`，用于将 64 位的位图转换为 `BitRange` 切片，方便比较。
   - `runTest` 函数是实际的测试逻辑，它接收一个基地址 `base`，以及页缓存的 `cache` 和 `scav` 位图。
   - `runTest` 内部会：
     - 根据 `beforeAlloc` 和 `beforeScav` 初始化一个 `PageAlloc` 实例 `b`，模拟刷新前的分配状态。
     - 创建一个 `PageCache` 实例 `c`。
     - 调用 `c.Flush(b)` 将缓存信息刷新到 `PageAlloc` `b` 中。
     - 检查刷新后 `PageCache` 是否为空 (`c.Empty()`)。
     - 根据预期的 `afterAlloc` 和 `afterScav` 初始化另一个 `PageAlloc` 实例 `want`，表示刷新后的期望状态。
     - 使用 `checkPageAlloc` (代码中未提供，但应该是另一个测试辅助函数) 比较实际刷新后的 `PageAlloc` `b` 和期望的 `PageAlloc` `want` 是否一致。
   - `TestPageCacheFlush` 会执行多个 `runTest` 用例，包括空缓存、全满缓存和随机缓存状态。

**4. `TestPageAllocAllocToCache(t *testing.T)`:**
   - 这个测试函数测试 **将分配的页添加到页缓存 (Alloc To Cache)** 的功能，即 `PageAlloc` 的 `AllocToCache` 方法。
   - 它定义了一系列测试用例，每个用例包含：
     - `beforeAlloc`:  刷新前页分配器的分配状态。
     - `beforeScav`:  刷新前页分配器的回收状态。
     - `hits`: 一个 `PageCache` 切片，每个元素代表调用 `AllocToCache` 后期望返回的 `PageCache` 状态。
     - `afterAlloc`: 刷新后页分配器的期望分配状态。
     - `afterScav`: 刷新后页分配器的期望回收状态。
   - 测试循环会：
     - 根据 `beforeAlloc` 和 `beforeScav` 初始化一个 `PageAlloc` 实例 `b`。
     - 遍历 `hits` 切片，依次调用 `b.AllocToCache()`，并将返回的 `PageCache` 与 `hits` 中的期望值使用 `checkPageCache` 进行比较。
     - 最后，将刷新后的 `PageAlloc` `b` 与期望的 `afterAlloc` 和 `afterScav` 状态进行比较。
   - 测试用例覆盖了多种场景，包括：
     - 所有页都空闲
     - 跨越多个内存 arena 的分配
     - 非连续的内存区域
     - 第一次分配
     - 分配失败的情况
     - 保留回收位信息的情况

**推理 `PageCache` 和相关功能的实现:**

这段测试代码暗示了 `PageCache` 是 Go 运行时内存管理中用于优化大页分配和回收的关键组件。它可以被认为是位于底层的页分配器 (`PageAlloc`) 之上的一个缓存层。

**可能的实现逻辑：**

- **`PageCache` 结构体:** 很可能包含以下字段：
    - `base`:  缓存所覆盖的内存区域的起始基地址。
    - `cache`: 一个位图，用于标记哪些页是空闲可用的。每一位对应一个页，1 表示空闲，0 表示已分配。
    - `scav`: 一个位图，用于标记哪些页可以被回收（scavenged）。

- **`NewPageCache(base uintptr, cache uint64, scav uint64)`:**  构造函数，用于创建一个新的 `PageCache` 实例，指定其覆盖的基地址和初始的缓存/回收位图。

- **`Alloc(npages uintptr) (base uintptr, scav uintptr)`:**
    - 在 `cache` 位图中查找连续 `npages` 个为 1 的位。
    - 如果找到，将这些位设置为 0，并返回分配的起始基地址和相应的回收信息。
    - 如果找不到，可能返回 0 或表示分配失败的值。

- **`Flush(alloc *PageAlloc)`:**
    - 将 `PageCache` 中的 `cache` 和 `scav` 位图信息同步到 `PageAlloc` 中，更新底层的分配状态。
    - 具体实现可能涉及遍历 `cache` 和 `scav` 位图，并更新 `PageAlloc` 中对应的元数据结构。

- **`AllocToCache() PageCache` (作为 `PageAlloc` 的方法):**
    - `PageAlloc` 可能会管理更大的内存区域。当它分配了一块或多块连续的页时，它可以将这些新分配的页的信息（基地址、页数）写入到一个新的 `PageCache` 结构体中并返回。这样，后续的分配请求可以优先从这些缓存的页中获取，提高效率。

**Go 代码示例说明:**

假设 `PageCache` 的结构体定义如下（这只是一个推测的简化版本）：

```go
package runtime

type PageCache struct {
	base  uintptr
	cache uint64
	scav  uint64
}

const PageSize = 8192 // 假设页大小为 8KB

func NewPageCache(base uintptr, cache uint64, scav uint64) PageCache {
	return PageCache{base: base, cache: cache, scav: scav}
}

func (c PageCache) Base() uintptr {
	return c.base
}

func (c PageCache) Cache() uint64 {
	return c.cache
}

func (c PageCache) Scav() uint64 {
	return c.scav
}

func (c *PageCache) Alloc(npages uintptr) (uintptr, uintptr) {
	for i := 0; i <= 64-int(npages); i++ {
		mask := ^uint64(0) >> (64 - npages) << i
		if c.cache&mask == mask {
			c.cache &= ^mask // 标记为已使用
			return c.base + uintptr(i)*PageSize, c.scav & mask // 返回基地址和对应的回收信息
		}
	}
	return 0, 0 // 分配失败
}

func (c *PageCache) Empty() bool {
	return c.cache == 0
}

// Flush 方法的具体实现会比较复杂，涉及到与 PageAlloc 的交互
// 这里只是一个示意
func (c *PageCache) Flush(alloc *PageAlloc) {
	// ... 将 c.cache 和 c.scav 的信息同步到 alloc 中 ...
	println("Flushing PageCache")
}
```

**假设的输入与输出 (针对 `TestPageCacheAlloc` 中的一个用例 "Lo1")：**

- **输入:**
  - `cache`: `NewPageCache(base, 0x1, 0x1)`，其中 `base` 是一个预定义的基地址。这意味着页缓存中最低位对应的页是空闲的，并且可以被回收。
  - `hits`: `[]hit{{1, base, PageSize}, {1, 0, 0}, {10, 0, 0}}`

- **输出 (模拟 `Alloc` 方法的行为):**
  1. `c.Alloc(1)`: 应该返回 `(base, PageSize)`，因为最低位的页是空闲的，且标记为可回收。
  2. 此时 `cache` 会变成 `0x0`。
  3. `c.Alloc(1)`: 应该返回 `(0, 0)`，因为现在没有空闲页了。
  4. `c.Alloc(10)`: 应该返回 `(0, 0)`，因为没有连续 10 个空闲页。

**使用者易犯错的点 (假设使用者直接操作 `PageCache`，这在实际 Go 运行时中不太可能发生，因为它是内部实现):**

1. **错误地理解 `cache` 和 `scav` 位图的含义:**  例如，不清楚 1 和 0 分别代表什么状态。
2. **手动修改 `PageCache` 的状态后，没有正确地与底层的 `PageAlloc` 同步 (即没有调用 `Flush`)**: 这会导致内存管理状态不一致。
3. **假设 `Alloc` 方法总是能成功分配**: 需要检查 `Alloc` 的返回值，处理分配失败的情况。
4. **不了解页缓存的生命周期和适用场景**: 页缓存主要用于加速大块内存的分配，对于小对象的分配可能没有明显的优势。

**命令行参数的具体处理:**

这段代码是测试代码，本身不涉及命令行参数的处理。命令行参数的处理通常发生在 `main` 函数中，并通过 `flag` 包或者直接解析 `os.Args` 实现。

总而言之，这段代码是 Go 运行时系统中用于测试页缓存功能的关键部分，它验证了页缓存的分配、刷新以及与底层页分配器交互的正确性。理解这段代码有助于深入了解 Go 语言的内存管理机制。

### 提示词
```
这是路径为go/src/runtime/mpagecache_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package runtime_test

import (
	"internal/goos"
	"math/rand"
	. "runtime"
	"testing"
)

func checkPageCache(t *testing.T, got, want PageCache) {
	if got.Base() != want.Base() {
		t.Errorf("bad pageCache base: got 0x%x, want 0x%x", got.Base(), want.Base())
	}
	if got.Cache() != want.Cache() {
		t.Errorf("bad pageCache bits: got %016x, want %016x", got.Base(), want.Base())
	}
	if got.Scav() != want.Scav() {
		t.Errorf("bad pageCache scav: got %016x, want %016x", got.Scav(), want.Scav())
	}
}

func TestPageCacheAlloc(t *testing.T) {
	base := PageBase(BaseChunkIdx, 0)
	type hit struct {
		npages uintptr
		base   uintptr
		scav   uintptr
	}
	tests := map[string]struct {
		cache PageCache
		hits  []hit
	}{
		"Empty": {
			cache: NewPageCache(base, 0, 0),
			hits: []hit{
				{1, 0, 0},
				{2, 0, 0},
				{3, 0, 0},
				{4, 0, 0},
				{5, 0, 0},
				{11, 0, 0},
				{12, 0, 0},
				{16, 0, 0},
				{27, 0, 0},
				{32, 0, 0},
				{43, 0, 0},
				{57, 0, 0},
				{64, 0, 0},
				{121, 0, 0},
			},
		},
		"Lo1": {
			cache: NewPageCache(base, 0x1, 0x1),
			hits: []hit{
				{1, base, PageSize},
				{1, 0, 0},
				{10, 0, 0},
			},
		},
		"Hi1": {
			cache: NewPageCache(base, 0x1<<63, 0x1),
			hits: []hit{
				{1, base + 63*PageSize, 0},
				{1, 0, 0},
				{10, 0, 0},
			},
		},
		"Swiss1": {
			cache: NewPageCache(base, 0x20005555, 0x5505),
			hits: []hit{
				{2, 0, 0},
				{1, base, PageSize},
				{1, base + 2*PageSize, PageSize},
				{1, base + 4*PageSize, 0},
				{1, base + 6*PageSize, 0},
				{1, base + 8*PageSize, PageSize},
				{1, base + 10*PageSize, PageSize},
				{1, base + 12*PageSize, PageSize},
				{1, base + 14*PageSize, PageSize},
				{1, base + 29*PageSize, 0},
				{1, 0, 0},
				{10, 0, 0},
			},
		},
		"Lo2": {
			cache: NewPageCache(base, 0x3, 0x2<<62),
			hits: []hit{
				{2, base, 0},
				{2, 0, 0},
				{1, 0, 0},
			},
		},
		"Hi2": {
			cache: NewPageCache(base, 0x3<<62, 0x3<<62),
			hits: []hit{
				{2, base + 62*PageSize, 2 * PageSize},
				{2, 0, 0},
				{1, 0, 0},
			},
		},
		"Swiss2": {
			cache: NewPageCache(base, 0x3333<<31, 0x3030<<31),
			hits: []hit{
				{2, base + 31*PageSize, 0},
				{2, base + 35*PageSize, 2 * PageSize},
				{2, base + 39*PageSize, 0},
				{2, base + 43*PageSize, 2 * PageSize},
				{2, 0, 0},
			},
		},
		"Hi53": {
			cache: NewPageCache(base, ((uint64(1)<<53)-1)<<10, ((uint64(1)<<16)-1)<<10),
			hits: []hit{
				{53, base + 10*PageSize, 16 * PageSize},
				{53, 0, 0},
				{1, 0, 0},
			},
		},
		"Full53": {
			cache: NewPageCache(base, ^uint64(0), ((uint64(1)<<16)-1)<<10),
			hits: []hit{
				{53, base, 16 * PageSize},
				{53, 0, 0},
				{1, base + 53*PageSize, 0},
			},
		},
		"Full64": {
			cache: NewPageCache(base, ^uint64(0), ^uint64(0)),
			hits: []hit{
				{64, base, 64 * PageSize},
				{64, 0, 0},
				{1, 0, 0},
			},
		},
		"FullMixed": {
			cache: NewPageCache(base, ^uint64(0), ^uint64(0)),
			hits: []hit{
				{5, base, 5 * PageSize},
				{7, base + 5*PageSize, 7 * PageSize},
				{1, base + 12*PageSize, 1 * PageSize},
				{23, base + 13*PageSize, 23 * PageSize},
				{63, 0, 0},
				{3, base + 36*PageSize, 3 * PageSize},
				{3, base + 39*PageSize, 3 * PageSize},
				{3, base + 42*PageSize, 3 * PageSize},
				{12, base + 45*PageSize, 12 * PageSize},
				{11, 0, 0},
				{4, base + 57*PageSize, 4 * PageSize},
				{4, 0, 0},
				{6, 0, 0},
				{36, 0, 0},
				{2, base + 61*PageSize, 2 * PageSize},
				{3, 0, 0},
				{1, base + 63*PageSize, 1 * PageSize},
				{4, 0, 0},
				{2, 0, 0},
				{62, 0, 0},
				{1, 0, 0},
			},
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			c := test.cache
			for i, h := range test.hits {
				b, s := c.Alloc(h.npages)
				if b != h.base {
					t.Fatalf("bad alloc base #%d: got 0x%x, want 0x%x", i, b, h.base)
				}
				if s != h.scav {
					t.Fatalf("bad alloc scav #%d: got %d, want %d", i, s, h.scav)
				}
			}
		})
	}
}

func TestPageCacheFlush(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	bits64ToBitRanges := func(bits uint64, base uint) []BitRange {
		var ranges []BitRange
		start, size := uint(0), uint(0)
		for i := 0; i < 64; i++ {
			if bits&(1<<i) != 0 {
				if size == 0 {
					start = uint(i) + base
				}
				size++
			} else {
				if size != 0 {
					ranges = append(ranges, BitRange{start, size})
					size = 0
				}
			}
		}
		if size != 0 {
			ranges = append(ranges, BitRange{start, size})
		}
		return ranges
	}
	runTest := func(t *testing.T, base uint, cache, scav uint64) {
		// Set up the before state.
		beforeAlloc := map[ChunkIdx][]BitRange{
			BaseChunkIdx: {{base, 64}},
		}
		beforeScav := map[ChunkIdx][]BitRange{
			BaseChunkIdx: {},
		}
		b := NewPageAlloc(beforeAlloc, beforeScav)
		defer FreePageAlloc(b)

		// Create and flush the cache.
		c := NewPageCache(PageBase(BaseChunkIdx, base), cache, scav)
		c.Flush(b)
		if !c.Empty() {
			t.Errorf("pageCache flush did not clear cache")
		}

		// Set up the expected after state.
		afterAlloc := map[ChunkIdx][]BitRange{
			BaseChunkIdx: bits64ToBitRanges(^cache, base),
		}
		afterScav := map[ChunkIdx][]BitRange{
			BaseChunkIdx: bits64ToBitRanges(scav, base),
		}
		want := NewPageAlloc(afterAlloc, afterScav)
		defer FreePageAlloc(want)

		// Check to see if it worked.
		checkPageAlloc(t, want, b)
	}

	// Empty.
	runTest(t, 0, 0, 0)

	// Full.
	runTest(t, 0, ^uint64(0), ^uint64(0))

	// Random.
	for i := 0; i < 100; i++ {
		// Generate random valid base within a chunk.
		base := uint(rand.Intn(PallocChunkPages/64)) * 64

		// Generate random cache.
		cache := rand.Uint64()
		scav := rand.Uint64() & cache

		// Run the test.
		runTest(t, base, cache, scav)
	}
}

func TestPageAllocAllocToCache(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	type test struct {
		beforeAlloc map[ChunkIdx][]BitRange
		beforeScav  map[ChunkIdx][]BitRange
		hits        []PageCache // expected base addresses and patterns
		afterAlloc  map[ChunkIdx][]BitRange
		afterScav   map[ChunkIdx][]BitRange
	}
	tests := map[string]test{
		"AllFree": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{1, 1}, {64, 64}},
			},
			hits: []PageCache{
				NewPageCache(PageBase(BaseChunkIdx, 0), ^uint64(0), 0x2),
				NewPageCache(PageBase(BaseChunkIdx, 64), ^uint64(0), ^uint64(0)),
				NewPageCache(PageBase(BaseChunkIdx, 128), ^uint64(0), 0),
				NewPageCache(PageBase(BaseChunkIdx, 192), ^uint64(0), 0),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 256}},
			},
		},
		"ManyArena": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages - 64}},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {},
			},
			hits: []PageCache{
				NewPageCache(PageBase(BaseChunkIdx+2, PallocChunkPages-64), ^uint64(0), 0),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
		},
		"NotContiguous": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{0, 0}},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{31, 67}},
			},
			hits: []PageCache{
				NewPageCache(PageBase(BaseChunkIdx+0xff, 0), ^uint64(0), ((uint64(1)<<33)-1)<<31),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{0, 64}},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{64, 34}},
			},
		},
		"First": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 32}, {33, 31}, {96, 32}},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{1, 4}, {31, 5}, {66, 2}},
			},
			hits: []PageCache{
				NewPageCache(PageBase(BaseChunkIdx, 0), 1<<32, 1<<32),
				NewPageCache(PageBase(BaseChunkIdx, 64), (uint64(1)<<32)-1, 0x3<<2),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 128}},
			},
		},
		"Fail": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			hits: []PageCache{
				NewPageCache(0, 0, 0),
				NewPageCache(0, 0, 0),
				NewPageCache(0, 0, 0),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
		},
		"RetainScavBits": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 1}, {10, 2}},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 4}, {11, 1}},
			},
			hits: []PageCache{
				NewPageCache(PageBase(BaseChunkIdx, 0), ^uint64(0x1|(0x3<<10)), 0x7<<1),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 64}},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 1}, {11, 1}},
			},
		},
	}
	// Disable these tests on iOS since we have a small address space.
	// See #46860.
	if PageAlloc64Bit != 0 && goos.IsIos == 0 {
		const chunkIdxBigJump = 0x100000 // chunk index offset which translates to O(TiB)

		// This test is similar to the one with the same name for
		// pageAlloc.alloc and serves the same purpose.
		// See mpagealloc_test.go for details.
		sumsPerPhysPage := ChunkIdx(PhysPageSize / PallocSumBytes)
		baseChunkIdx := BaseChunkIdx &^ (sumsPerPhysPage - 1)
		tests["DiscontiguousMappedSumBoundary"] = test{
			beforeAlloc: map[ChunkIdx][]BitRange{
				baseChunkIdx + sumsPerPhysPage - 1: {{0, PallocChunkPages - 1}},
				baseChunkIdx + chunkIdxBigJump:     {{1, PallocChunkPages - 1}},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				baseChunkIdx + sumsPerPhysPage - 1: {},
				baseChunkIdx + chunkIdxBigJump:     {},
			},
			hits: []PageCache{
				NewPageCache(PageBase(baseChunkIdx+sumsPerPhysPage-1, PallocChunkPages-64), 1<<63, 0),
				NewPageCache(PageBase(baseChunkIdx+chunkIdxBigJump, 0), 1, 0),
				NewPageCache(0, 0, 0),
			},
			afterAlloc: map[ChunkIdx][]BitRange{
				baseChunkIdx + sumsPerPhysPage - 1: {{0, PallocChunkPages}},
				baseChunkIdx + chunkIdxBigJump:     {{0, PallocChunkPages}},
			},
		}
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := NewPageAlloc(v.beforeAlloc, v.beforeScav)
			defer FreePageAlloc(b)

			for _, expect := range v.hits {
				checkPageCache(t, b.AllocToCache(), expect)
				if t.Failed() {
					return
				}
			}
			want := NewPageAlloc(v.afterAlloc, v.afterScav)
			defer FreePageAlloc(want)

			checkPageAlloc(t, want, b)
		})
	}
}
```