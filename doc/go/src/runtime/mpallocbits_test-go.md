Response:
Let's break down the thought process to arrive at the comprehensive answer about `mpallocbits_test.go`.

1. **Understanding the Context:** The filename `mpallocbits_test.go` immediately suggests this is a testing file for a component related to memory page allocation (`mpallocbits`). The `runtime` package import confirms this is part of the Go runtime's memory management system.

2. **Initial Scan for Core Functionality:** I'll read through the code, focusing on the declared functions and their names. Key functions that stand out are:
    * `checkPallocBits`:  Likely a helper for comparing `PallocBits` structures.
    * `makePallocBits`:  Seems to create and initialize `PallocBits`.
    * `TestPallocBitsAllocRange`: Tests the `AllocRange` method of `PallocBits`. This is a crucial method for setting bits.
    * `invertPallocBits`:  Inverts the bits of a `PallocBits`.
    * `checkPallocSum`:  Compares `PallocSum` structures.
    * `TestMallocBitsPopcntRange`: Tests counting set bits within a range.
    * `TestPallocBitsSummarizeRandom` and `TestPallocBitsSummarize`: Test the summarization functionality of `PallocBits`.
    * `BenchmarkPallocBitsSummarize`: Measures the performance of summarization.
    * `TestPallocBitsAlloc`: Tests the allocation of pages.
    * `TestPallocBitsFree`: Tests the freeing of pages.
    * `TestFindBitRange64`: Tests a utility function for finding contiguous bits within a 64-bit word.
    * `BenchmarkFindBitRange64`: Measures the performance of `FindBitRange64`.

3. **Identifying Key Data Structures:** The names `PallocBits` and `PallocSum` appear frequently. This suggests they are central data structures for managing page allocation information. `BitRange` is also important for defining ranges of bits.

4. **Deduction of `PallocBits` Functionality:** Based on the tests, I can infer the core purpose of `PallocBits`:
    * **Bit-level Tracking:** It uses a bit array (likely a slice of `uint64`) to represent the allocation status of memory pages.
    * **Allocation (`AllocRange`, `TestPallocBitsAlloc`):** It allows marking ranges of pages as allocated (setting bits to 1 or 0 depending on the convention). The tests demonstrate setting single bits, ranges within a word, and ranges spanning multiple words.
    * **Freeing (`TestPallocBitsFree`):** It enables marking allocated pages as free.
    * **Counting Allocated Pages (`TestMallocBitsPopcntRange`):** It can efficiently count the number of allocated pages within a given range.
    * **Summarization (`TestPallocBitsSummarize`, `TestPallocBitsSummarizeRandom`):**  It can generate a summary (`PallocSum`) likely containing information like the start and end of allocated/free blocks. The benchmark suggests performance is important.
    * **Finding Free Ranges (`TestPallocBitsAlloc`, `FindBitRange64`):** It provides mechanisms to search for contiguous free blocks of a specified size. `FindBitRange64` seems to be a low-level helper for this.

5. **Inferring the Higher-Level Go Feature:**  The names "palloc" and the context within the `runtime` package strongly indicate this is related to the **page allocator** within Go's memory management. Go's memory is divided into pages, and the runtime needs a way to track which pages are in use. `PallocBits` is likely the data structure used for this tracking within a specific memory region or arena.

6. **Constructing the Go Code Example:** To illustrate the use of `PallocBits`, I need to show its core operations. This involves:
    * Creating a `PallocBits` instance.
    * Allocating a range using `AllocRange`.
    * Freeing a range using `Free`.
    * Counting allocated pages using `PopcntRange`.
    * Summarizing the allocation status using `Summarize`.

7. **Reasoning about Input and Output (for Code Reasoning):** When explaining `AllocRange`, I'll use concrete examples:
    * Input: Starting bit index and number of bits to allocate.
    * Output: The `PallocBits` array with the corresponding bits set. I'll need to show how the bit manipulation works at the `uint64` level.

8. **Considering Command-Line Arguments:** I'll carefully review the code for any interaction with command-line flags or environment variables. In this specific code, there are no direct command-line argument processing. The tests are driven by the `testing` package.

9. **Identifying Potential User Mistakes:** I will think about common errors when working with bit manipulation and memory management:
    * **Off-by-one errors:** Incorrectly calculating start and end indices.
    * **Incorrect size:** Requesting an allocation size that exceeds the available space.
    * **Double freeing:** Trying to free the same memory twice.
    * **Forgetting the underlying data structure:** Not realizing `PallocBits` is just a bit array.

10. **Structuring the Answer:**  I'll organize the answer logically:
    * Start with a concise summary of the file's purpose.
    * Explain the inferred Go feature.
    * Provide a Go code example demonstrating usage.
    * Detail the functionality of key functions.
    * Include reasoned input and output examples.
    * Address command-line arguments (even if none are present).
    * Discuss common mistakes.

11. **Refining the Language:**  I'll use clear and precise Chinese terminology, ensuring the explanation is easy to understand. For instance, using "位图" for "bit array" and clearly explaining the bitwise operations.

By following this structured approach, I can comprehensively analyze the given Go code snippet and provide an accurate and helpful explanation. The iterative process of scanning, deducing, and constructing examples allows me to build a complete picture of the code's purpose and functionality.
这段代码是 Go 语言运行时（`runtime` 包）中 `mpallocbits_test.go` 文件的一部分，主要用于测试与内存页分配相关的位图操作功能。具体来说，它测试了 `PallocBits` 结构体及其相关方法的正确性。

以下是代码中主要功能点的列举：

1. **`checkPallocBits(t *testing.T, got, want *PallocBits) bool`:**
   - **功能:**  比较两个 `PallocBits` 结构体 `got` 和 `want` 是否相同。如果不同，则会打印出详细的差异信息，包括不同位所在的索引以及实际值和期望值。
   - **用途:**  作为测试辅助函数，用于验证 `PallocBits` 操作的结果是否符合预期。

2. **`makePallocBits(s []BitRange) *PallocBits`:**
   - **功能:**  创建一个新的 `PallocBits` 结构体，并根据传入的 `BitRange` 切片 `s` 初始化位图。`BitRange` 结构体定义了需要设置为 1 的比特位的起始索引和数量。
   - **用途:**  方便地创建具有特定位模式的 `PallocBits` 实例，用于测试。

3. **`TestPallocBitsAllocRange(t *testing.T)`:**
   - **功能:**  测试 `PallocBits` 的 `AllocRange(i, n uint)` 方法。该方法用于将位图中从索引 `i` 开始的 `n` 个比特位设置为 1。
   - **测试用例:**  包含了多种情况，例如设置单个比特位、设置位于高位的比特位、设置连续的多个比特位、设置跨越多个 64 位字的比特位等。
   - **推理的 Go 语言功能:**  这个测试直接针对的是 `PallocBits` 结构体的 `AllocRange` 方法，该方法是管理内存页分配的核心操作之一，用于标记哪些页被分配了。

   ```go
   package main

   import (
       "fmt"
       . "runtime" // 假设 PallocBits 在 runtime 包中
   )

   func main() {
       pb := new(PallocBits)

       // 假设 PallocChunkPages 是 PallocBits 的总比特数
       fmt.Println("初始状态:", StringifyPallocBits(pb, BitRange{I: 0, N: PallocChunkPages}))

       // 分配从索引 10 开始的 5 个页
       pb.AllocRange(10, 5)
       fmt.Println("分配后状态 (10, 5):", StringifyPallocBits(pb, BitRange{I: 0, N: PallocChunkPages}))

       // 再次分配从索引 20 开始的 3 个页
       pb.AllocRange(20, 3)
       fmt.Println("分配后状态 (20, 3):", StringifyPallocBits(pb, BitRange{I: 0, N: PallocChunkPages}))
   }

   // 假设的 StringifyPallocBits 函数，用于将 PallocBits 转换为字符串表示
   func StringifyPallocBits(pb *PallocBits, r BitRange) string {
       // ... 实现细节 ...
       return "..." // 这里只是占位符
   }
   ```
   **假设的输入与输出:**  假设 `PallocChunkPages` 为 256。
   - **初始状态:**  所有比特位都为 0。
   - **分配后状态 (10, 5):**  从索引 10 到 14 的比特位被设置为 1。
   - **分配后状态 (20, 3):**  从索引 10 到 14 以及索引 20 到 22 的比特位被设置为 1。

4. **`invertPallocBits(b *PallocBits)`:**
   - **功能:**  反转 `PallocBits` 结构体 `b` 中的所有比特位，将 0 变为 1，将 1 变为 0。

5. **`checkPallocSum(t testing.TB, got, want PallocSum)`:**
   - **功能:**  比较两个 `PallocSum` 结构体 `got` 和 `want` 是否相同，用于测试位图的汇总信息是否正确。
   - **用途:**  验证 `PallocBits` 的汇总功能。

6. **`TestMallocBitsPopcntRange(t *testing.T)`:**
   - **功能:**  测试 `PallocBits` 的 `PopcntRange(i, n uint)` 方法。该方法用于计算位图中从索引 `i` 开始的 `n` 个比特位中，值为 1 的比特位的数量。
   - **测试用例:**  包含了多种初始化位图模式和不同的计算范围，验证了在不同情况下计数功能的正确性。

7. **`TestPallocBitsSummarizeRandom(t *testing.T)` 和 `TestPallocBitsSummarize(t *testing.T)`:**
   - **功能:**  测试 `PallocBits` 的 `Summarize()` 方法。该方法用于生成 `PallocSum` 结构体，其中包含了位图的汇总信息，例如第一个被分配的页、最后一个被分配的页等等。
   - **推理的 Go 语言功能:**  `Summarize` 方法用于快速获取 `PallocBits` 中已分配内存块的起始和结束位置，这对于内存管理的决策非常重要。

8. **`BenchmarkPallocBitsSummarize(b *testing.B)`:**
   - **功能:**  对 `PallocBits` 的 `Summarize()` 方法进行性能基准测试，衡量其执行速度。

9. **`TestPallocBitsAlloc(t *testing.T)`:**
   - **功能:**  测试 `PallocBits` 的 `Find(npages uintptr, align uintptr)` 方法。该方法用于在位图中查找连续的 `npages` 个空闲页（比特位为 0）。
   - **测试用例:**  涵盖了在完全空闲、部分空闲和完全占用的位图中查找空闲页的情况。
   - **推理的 Go 语言功能:**  `Find` 方法是内存分配的核心，用于找到可以分配给定数量页面的连续空闲内存块。

   ```go
   package main

   import (
       "fmt"
       . "runtime" // 假设 PallocBits 在 runtime 包中
   )

   func main() {
       pb := new(PallocBits)
       // 假设所有页都空闲

       // 尝试分配 3 个页
       index, _ := pb.Find(3, 0)
       if index != ^uint(0) {
           fmt.Printf("找到空闲起始索引: %d\n", index)
           pb.AllocRange(index, 3) // 标记为已分配
           fmt.Println("分配后状态:", StringifyPallocBits(pb, BitRange{I: 0, N: PallocChunkPages}))
       } else {
           fmt.Println("未找到足够的连续空闲页")
       }
   }
   ```
   **假设的输入与输出:** 假设 `PallocChunkPages` 为 256，初始所有页空闲。
   - **输出:**  `找到空闲起始索引: 0` (或任何第一个找到的连续 3 个空闲页的起始索引)，并且相应的比特位被设置为 1。

10. **`TestPallocBitsFree(t *testing.T)`:**
    - **功能:** 测试 `PallocBits` 的 `Free(i uint, n uintptr)` 方法。该方法用于将位图中从索引 `i` 开始的 `n` 个比特位设置为 0，表示这些页被释放。
    - **推理的 Go 语言功能:** `Free` 方法用于标记已分配的内存页为空闲，是内存回收的关键操作。

    ```go
    package main

    import (
        "fmt"
        . "runtime" // 假设 PallocBits 在 runtime 包中
    )

    func main() {
        pb := new(PallocBits)
        pb.AllocRange(10, 5) // 先分配一些页
        fmt.Println("分配后状态:", StringifyPallocBits(pb, BitRange{I: 0, N: PallocChunkPages}))

        // 释放从索引 10 开始的 3 个页
        pb.Free(10, 3)
        fmt.Println("释放后状态:", StringifyPallocBits(pb, BitRange{I: 0, N: PallocChunkPages}))
    }
    ```
    **假设的输入与输出:** 假设 `PallocChunkPages` 为 256。
    - **分配后状态:** 从索引 10 到 14 的比特位为 1。
    - **释放后状态:** 从索引 10 到 12 的比特位为 0，索引 13 和 14 的比特位仍然为 1。

11. **`TestFindBitRange64(t *testing.T)` 和 `BenchmarkFindBitRange64(b *testing.B)`:**
    - **功能:** 测试和基准测试 `FindBitRange64(x uint64, n uint)` 函数。该函数在一个 64 位的无符号整数 `x` 中查找连续的 `n` 个值为 0 的比特位，并返回起始索引。
    - **推理的 Go 语言功能:** 这是一个底层的位操作辅助函数，用于在 64 位字级别快速查找空闲位，是 `PallocBits` 中 `Find` 方法的基础。

**总而言之，这段代码测试了 Go 语言运行时中用于管理内存页分配状态的位图 (`PallocBits`) 的各种操作，包括分配、释放、计数和汇总等。它是 Go 语言内存管理机制的重要组成部分。**

**命令行参数的具体处理:**

这段代码本身是一个测试文件，不涉及处理命令行参数。它是由 `go test` 命令执行的。`go test` 命令有一些标准参数，例如 `-v` (显示详细输出)、`-run` (指定要运行的测试用例) 等，但这些是 `go test` 命令本身的参数，而不是这段代码处理的。

**使用者易犯错的点:**

由于这段代码是 Go 运行时的一部分，普通 Go 开发者不会直接使用 `PallocBits` 结构体及其方法。这些是运行时内部使用的机制。因此，不存在普通使用者易犯错的点。

但是，如果你是 Go 运行时或相关底层库的开发者，在使用或修改这些代码时，可能会犯以下错误：

1. **位运算错误:** 在操作位图时，容易出现位移、按位与、按位或等运算的错误，导致分配或释放的范围不正确。
2. **索引越界:**  在访问或修改位图中的比特位时，可能会出现索引越界的情况。
3. **并发安全问题:** 如果多个 goroutine 同时操作同一个 `PallocBits` 实例，可能会出现数据竞争，需要使用适当的同步机制。
4. **对齐错误:** 在内存分配中，对齐是非常重要的。如果 `Find` 方法的对齐参数处理不当，可能会导致分配的内存块不满足对齐要求。
5. **资源泄漏:** 如果分配了内存页但在不再使用时没有正确释放，会导致内存泄漏。

这段测试代码的目的是为了尽早发现这些潜在的错误，确保内存管理机制的稳定性和正确性。

### 提示词
```
这是路径为go/src/runtime/mpallocbits_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"math/rand"
	. "runtime"
	"testing"
)

// Ensures that got and want are the same, and if not, reports
// detailed diff information.
func checkPallocBits(t *testing.T, got, want *PallocBits) bool {
	d := DiffPallocBits(got, want)
	if len(d) != 0 {
		t.Errorf("%d range(s) different", len(d))
		for _, bits := range d {
			t.Logf("\t@ bit index %d", bits.I)
			t.Logf("\t|  got: %s", StringifyPallocBits(got, bits))
			t.Logf("\t| want: %s", StringifyPallocBits(want, bits))
		}
		return false
	}
	return true
}

// makePallocBits produces an initialized PallocBits by setting
// the ranges in s to 1 and the rest to zero.
func makePallocBits(s []BitRange) *PallocBits {
	b := new(PallocBits)
	for _, v := range s {
		b.AllocRange(v.I, v.N)
	}
	return b
}

// Ensures that PallocBits.AllocRange works, which is a fundamental
// method used for testing and initialization since it's used by
// makePallocBits.
func TestPallocBitsAllocRange(t *testing.T) {
	test := func(t *testing.T, i, n uint, want *PallocBits) {
		checkPallocBits(t, makePallocBits([]BitRange{{i, n}}), want)
	}
	t.Run("OneLow", func(t *testing.T) {
		want := new(PallocBits)
		want[0] = 0x1
		test(t, 0, 1, want)
	})
	t.Run("OneHigh", func(t *testing.T) {
		want := new(PallocBits)
		want[PallocChunkPages/64-1] = 1 << 63
		test(t, PallocChunkPages-1, 1, want)
	})
	t.Run("Inner", func(t *testing.T) {
		want := new(PallocBits)
		want[2] = 0x3e
		test(t, 129, 5, want)
	})
	t.Run("Aligned", func(t *testing.T) {
		want := new(PallocBits)
		want[2] = ^uint64(0)
		want[3] = ^uint64(0)
		test(t, 128, 128, want)
	})
	t.Run("Begin", func(t *testing.T) {
		want := new(PallocBits)
		want[0] = ^uint64(0)
		want[1] = ^uint64(0)
		want[2] = ^uint64(0)
		want[3] = ^uint64(0)
		want[4] = ^uint64(0)
		want[5] = 0x1
		test(t, 0, 321, want)
	})
	t.Run("End", func(t *testing.T) {
		want := new(PallocBits)
		want[PallocChunkPages/64-1] = ^uint64(0)
		want[PallocChunkPages/64-2] = ^uint64(0)
		want[PallocChunkPages/64-3] = ^uint64(0)
		want[PallocChunkPages/64-4] = 1 << 63
		test(t, PallocChunkPages-(64*3+1), 64*3+1, want)
	})
	t.Run("All", func(t *testing.T) {
		want := new(PallocBits)
		for i := range want {
			want[i] = ^uint64(0)
		}
		test(t, 0, PallocChunkPages, want)
	})
}

// Inverts every bit in the PallocBits.
func invertPallocBits(b *PallocBits) {
	for i := range b {
		b[i] = ^b[i]
	}
}

// Ensures two packed summaries are identical, and reports a detailed description
// of the difference if they're not.
func checkPallocSum(t testing.TB, got, want PallocSum) {
	if got.Start() != want.Start() {
		t.Errorf("inconsistent start: got %d, want %d", got.Start(), want.Start())
	}
	if got.Max() != want.Max() {
		t.Errorf("inconsistent max: got %d, want %d", got.Max(), want.Max())
	}
	if got.End() != want.End() {
		t.Errorf("inconsistent end: got %d, want %d", got.End(), want.End())
	}
}

func TestMallocBitsPopcntRange(t *testing.T) {
	type test struct {
		i, n uint // bit range to popcnt over.
		want uint // expected popcnt result on that range.
	}
	tests := map[string]struct {
		init  []BitRange // bit ranges to set to 1 in the bitmap.
		tests []test     // a set of popcnt tests to run over the bitmap.
	}{
		"None": {
			tests: []test{
				{0, 1, 0},
				{5, 3, 0},
				{2, 11, 0},
				{PallocChunkPages/4 + 1, PallocChunkPages / 2, 0},
				{0, PallocChunkPages, 0},
			},
		},
		"All": {
			init: []BitRange{{0, PallocChunkPages}},
			tests: []test{
				{0, 1, 1},
				{5, 3, 3},
				{2, 11, 11},
				{PallocChunkPages/4 + 1, PallocChunkPages / 2, PallocChunkPages / 2},
				{0, PallocChunkPages, PallocChunkPages},
			},
		},
		"Half": {
			init: []BitRange{{PallocChunkPages / 2, PallocChunkPages / 2}},
			tests: []test{
				{0, 1, 0},
				{5, 3, 0},
				{2, 11, 0},
				{PallocChunkPages/2 - 1, 1, 0},
				{PallocChunkPages / 2, 1, 1},
				{PallocChunkPages/2 + 10, 1, 1},
				{PallocChunkPages/2 - 1, 2, 1},
				{PallocChunkPages / 4, PallocChunkPages / 4, 0},
				{PallocChunkPages / 4, PallocChunkPages/4 + 1, 1},
				{PallocChunkPages/4 + 1, PallocChunkPages / 2, PallocChunkPages/4 + 1},
				{0, PallocChunkPages, PallocChunkPages / 2},
			},
		},
		"OddBound": {
			init: []BitRange{{0, 111}},
			tests: []test{
				{0, 1, 1},
				{5, 3, 3},
				{2, 11, 11},
				{110, 2, 1},
				{99, 50, 12},
				{110, 1, 1},
				{111, 1, 0},
				{99, 1, 1},
				{120, 1, 0},
				{PallocChunkPages / 2, PallocChunkPages / 2, 0},
				{0, PallocChunkPages, 111},
			},
		},
		"Scattered": {
			init: []BitRange{
				{1, 3}, {5, 1}, {7, 1}, {10, 2}, {13, 1}, {15, 4},
				{21, 1}, {23, 1}, {26, 2}, {30, 5}, {36, 2}, {40, 3},
				{44, 6}, {51, 1}, {53, 2}, {58, 3}, {63, 1}, {67, 2},
				{71, 10}, {84, 1}, {89, 7}, {99, 2}, {103, 1}, {107, 2},
				{111, 1}, {113, 1}, {115, 1}, {118, 1}, {120, 2}, {125, 5},
			},
			tests: []test{
				{0, 11, 6},
				{0, 64, 39},
				{13, 64, 40},
				{64, 64, 34},
				{0, 128, 73},
				{1, 128, 74},
				{0, PallocChunkPages, 75},
			},
		},
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := makePallocBits(v.init)
			for _, h := range v.tests {
				if got := b.PopcntRange(h.i, h.n); got != h.want {
					t.Errorf("bad popcnt (i=%d, n=%d): got %d, want %d", h.i, h.n, got, h.want)
				}
			}
		})
	}
}

// Ensures computing bit summaries works as expected by generating random
// bitmaps and checking against a reference implementation.
func TestPallocBitsSummarizeRandom(t *testing.T) {
	b := new(PallocBits)
	for i := 0; i < 1000; i++ {
		// Randomize bitmap.
		for i := range b {
			b[i] = rand.Uint64()
		}
		// Check summary against reference implementation.
		checkPallocSum(t, b.Summarize(), SummarizeSlow(b))
	}
}

// Ensures computing bit summaries works as expected.
func TestPallocBitsSummarize(t *testing.T) {
	var emptySum = PackPallocSum(PallocChunkPages, PallocChunkPages, PallocChunkPages)
	type test struct {
		free []BitRange // Ranges of free (zero) bits.
		hits []PallocSum
	}
	tests := make(map[string]test)
	tests["NoneFree"] = test{
		free: []BitRange{},
		hits: []PallocSum{
			PackPallocSum(0, 0, 0),
		},
	}
	tests["OnlyStart"] = test{
		free: []BitRange{{0, 10}},
		hits: []PallocSum{
			PackPallocSum(10, 10, 0),
		},
	}
	tests["OnlyEnd"] = test{
		free: []BitRange{{PallocChunkPages - 40, 40}},
		hits: []PallocSum{
			PackPallocSum(0, 40, 40),
		},
	}
	tests["StartAndEnd"] = test{
		free: []BitRange{{0, 11}, {PallocChunkPages - 23, 23}},
		hits: []PallocSum{
			PackPallocSum(11, 23, 23),
		},
	}
	tests["StartMaxEnd"] = test{
		free: []BitRange{{0, 4}, {50, 100}, {PallocChunkPages - 4, 4}},
		hits: []PallocSum{
			PackPallocSum(4, 100, 4),
		},
	}
	tests["OnlyMax"] = test{
		free: []BitRange{{1, 20}, {35, 241}, {PallocChunkPages - 50, 30}},
		hits: []PallocSum{
			PackPallocSum(0, 241, 0),
		},
	}
	tests["MultiMax"] = test{
		free: []BitRange{{35, 2}, {40, 5}, {100, 5}},
		hits: []PallocSum{
			PackPallocSum(0, 5, 0),
		},
	}
	tests["One"] = test{
		free: []BitRange{{2, 1}},
		hits: []PallocSum{
			PackPallocSum(0, 1, 0),
		},
	}
	tests["AllFree"] = test{
		free: []BitRange{{0, PallocChunkPages}},
		hits: []PallocSum{
			emptySum,
		},
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := makePallocBits(v.free)
			// In the PallocBits we create 1's represent free spots, but in our actual
			// PallocBits 1 means not free, so invert.
			invertPallocBits(b)
			for _, h := range v.hits {
				checkPallocSum(t, b.Summarize(), h)
			}
		})
	}
}

// Benchmarks how quickly we can summarize a PallocBits.
func BenchmarkPallocBitsSummarize(b *testing.B) {
	patterns := []uint64{
		0,
		^uint64(0),
		0xaa,
		0xaaaaaaaaaaaaaaaa,
		0x80000000aaaaaaaa,
		0xaaaaaaaa00000001,
		0xbbbbbbbbbbbbbbbb,
		0x80000000bbbbbbbb,
		0xbbbbbbbb00000001,
		0xcccccccccccccccc,
		0x4444444444444444,
		0x4040404040404040,
		0x4000400040004000,
		0x1000404044ccaaff,
	}
	for _, p := range patterns {
		buf := new(PallocBits)
		for i := 0; i < len(buf); i++ {
			buf[i] = p
		}
		b.Run(fmt.Sprintf("Unpacked%02X", p), func(b *testing.B) {
			checkPallocSum(b, buf.Summarize(), SummarizeSlow(buf))
			for i := 0; i < b.N; i++ {
				buf.Summarize()
			}
		})
	}
}

// Ensures page allocation works.
func TestPallocBitsAlloc(t *testing.T) {
	tests := map[string]struct {
		before []BitRange
		after  []BitRange
		npages uintptr
		hits   []uint
	}{
		"AllFree1": {
			npages: 1,
			hits:   []uint{0, 1, 2, 3, 4, 5},
			after:  []BitRange{{0, 6}},
		},
		"AllFree2": {
			npages: 2,
			hits:   []uint{0, 2, 4, 6, 8, 10},
			after:  []BitRange{{0, 12}},
		},
		"AllFree5": {
			npages: 5,
			hits:   []uint{0, 5, 10, 15, 20},
			after:  []BitRange{{0, 25}},
		},
		"AllFree64": {
			npages: 64,
			hits:   []uint{0, 64, 128},
			after:  []BitRange{{0, 192}},
		},
		"AllFree65": {
			npages: 65,
			hits:   []uint{0, 65, 130},
			after:  []BitRange{{0, 195}},
		},
		"SomeFree64": {
			before: []BitRange{{0, 32}, {64, 32}, {100, PallocChunkPages - 100}},
			npages: 64,
			hits:   []uint{^uint(0)},
			after:  []BitRange{{0, 32}, {64, 32}, {100, PallocChunkPages - 100}},
		},
		"NoneFree1": {
			before: []BitRange{{0, PallocChunkPages}},
			npages: 1,
			hits:   []uint{^uint(0), ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"NoneFree2": {
			before: []BitRange{{0, PallocChunkPages}},
			npages: 2,
			hits:   []uint{^uint(0), ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"NoneFree5": {
			before: []BitRange{{0, PallocChunkPages}},
			npages: 5,
			hits:   []uint{^uint(0), ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"NoneFree65": {
			before: []BitRange{{0, PallocChunkPages}},
			npages: 65,
			hits:   []uint{^uint(0), ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"ExactFit1": {
			before: []BitRange{{0, PallocChunkPages/2 - 3}, {PallocChunkPages/2 - 2, PallocChunkPages/2 + 2}},
			npages: 1,
			hits:   []uint{PallocChunkPages/2 - 3, ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"ExactFit2": {
			before: []BitRange{{0, PallocChunkPages/2 - 3}, {PallocChunkPages/2 - 1, PallocChunkPages/2 + 1}},
			npages: 2,
			hits:   []uint{PallocChunkPages/2 - 3, ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"ExactFit5": {
			before: []BitRange{{0, PallocChunkPages/2 - 3}, {PallocChunkPages/2 + 2, PallocChunkPages/2 - 2}},
			npages: 5,
			hits:   []uint{PallocChunkPages/2 - 3, ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"ExactFit65": {
			before: []BitRange{{0, PallocChunkPages/2 - 31}, {PallocChunkPages/2 + 34, PallocChunkPages/2 - 34}},
			npages: 65,
			hits:   []uint{PallocChunkPages/2 - 31, ^uint(0)},
			after:  []BitRange{{0, PallocChunkPages}},
		},
		"SomeFree161": {
			before: []BitRange{{0, 185}, {331, 1}},
			npages: 161,
			hits:   []uint{332},
			after:  []BitRange{{0, 185}, {331, 162}},
		},
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := makePallocBits(v.before)
			for iter, i := range v.hits {
				a, _ := b.Find(v.npages, 0)
				if i != a {
					t.Fatalf("find #%d picked wrong index: want %d, got %d", iter+1, i, a)
				}
				if i != ^uint(0) {
					b.AllocRange(a, uint(v.npages))
				}
			}
			want := makePallocBits(v.after)
			checkPallocBits(t, b, want)
		})
	}
}

// Ensures page freeing works.
func TestPallocBitsFree(t *testing.T) {
	tests := map[string]struct {
		beforeInv []BitRange
		afterInv  []BitRange
		frees     []uint
		npages    uintptr
	}{
		"SomeFree": {
			npages:    1,
			beforeInv: []BitRange{{0, 32}, {64, 32}, {100, 1}},
			frees:     []uint{32},
			afterInv:  []BitRange{{0, 33}, {64, 32}, {100, 1}},
		},
		"NoneFree1": {
			npages:   1,
			frees:    []uint{0, 1, 2, 3, 4, 5},
			afterInv: []BitRange{{0, 6}},
		},
		"NoneFree2": {
			npages:   2,
			frees:    []uint{0, 2, 4, 6, 8, 10},
			afterInv: []BitRange{{0, 12}},
		},
		"NoneFree5": {
			npages:   5,
			frees:    []uint{0, 5, 10, 15, 20},
			afterInv: []BitRange{{0, 25}},
		},
		"NoneFree64": {
			npages:   64,
			frees:    []uint{0, 64, 128},
			afterInv: []BitRange{{0, 192}},
		},
		"NoneFree65": {
			npages:   65,
			frees:    []uint{0, 65, 130},
			afterInv: []BitRange{{0, 195}},
		},
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := makePallocBits(v.beforeInv)
			invertPallocBits(b)
			for _, i := range v.frees {
				b.Free(i, uint(v.npages))
			}
			want := makePallocBits(v.afterInv)
			invertPallocBits(want)
			checkPallocBits(t, b, want)
		})
	}
}

func TestFindBitRange64(t *testing.T) {
	check := func(x uint64, n uint, result uint) {
		i := FindBitRange64(x, n)
		if result == ^uint(0) && i < 64 {
			t.Errorf("case (%016x, %d): got %d, want failure", x, n, i)
		} else if result != ^uint(0) && i != result {
			t.Errorf("case (%016x, %d): got %d, want %d", x, n, i, result)
		}
	}
	for i := uint(1); i <= 64; i++ {
		check(^uint64(0), i, 0)
	}
	for i := uint(1); i <= 64; i++ {
		check(0, i, ^uint(0))
	}
	check(0x8000000000000000, 1, 63)
	check(0xc000010001010000, 2, 62)
	check(0xc000010001030000, 2, 16)
	check(0xe000030001030000, 3, 61)
	check(0xe000030001070000, 3, 16)
	check(0xffff03ff01070000, 16, 48)
	check(0xffff03ff0107ffff, 16, 0)
	check(0x0fff03ff01079fff, 16, ^uint(0))
}

func BenchmarkFindBitRange64(b *testing.B) {
	patterns := []uint64{
		0,
		^uint64(0),
		0xaa,
		0xaaaaaaaaaaaaaaaa,
		0x80000000aaaaaaaa,
		0xaaaaaaaa00000001,
		0xbbbbbbbbbbbbbbbb,
		0x80000000bbbbbbbb,
		0xbbbbbbbb00000001,
		0xcccccccccccccccc,
		0x4444444444444444,
		0x4040404040404040,
		0x4000400040004000,
	}
	sizes := []uint{
		2, 8, 32,
	}
	for _, pattern := range patterns {
		for _, size := range sizes {
			b.Run(fmt.Sprintf("Pattern%02XSize%d", pattern, size), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					FindBitRange64(pattern, size)
				}
			})
		}
	}
}
```