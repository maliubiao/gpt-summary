Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary goal is to understand the *functionality* of the provided Go code. This involves identifying what the code does, what Go feature it likely implements (even if it's internal), and any important details about its operation.

2. **Initial Scan for Clues:**  Quickly read through the code, looking for keywords and identifiers that suggest the code's purpose. Key observations:
    * The package is `runtime_test`, indicating this is a test file within the Go runtime.
    * There's a `PageAlloc` struct and related functions like `NewPageAlloc`, `FreePageAlloc`, `Alloc`, and `Free`. This strongly suggests memory management, specifically at the page level.
    * The presence of `ChunkIdx`, `AddrRange`, `BitRange`, and functions like `PageBase` further reinforce the idea of managing memory in chunks and pages.
    * The tests (`TestPageAllocGrow`, `TestPageAllocAlloc`, `TestPageAllocFree`, etc.) provide concrete examples of how the `PageAlloc` works.
    * The `checkPageAlloc` function suggests a way to verify the internal state of the `PageAlloc`.

3. **Focus on Key Data Structures:**  The `PageAlloc` struct is central. Although its internal definition isn't provided in this snippet, its methods give clues about its purpose. We can infer it likely stores information about allocated and free pages.

4. **Analyze Individual Test Functions:** This is crucial for understanding the behavior of `PageAlloc`.
    * **`TestPageAllocGrow`:** This test seems to focus on how the `PageAlloc` expands its managed memory as new chunks are added. The `chunks` and `inUse` fields in the test cases define the expected state after adding specific chunks. The `MakeAddrRange` function helps define the contiguous regions of allocated memory.
    * **`TestPageAllocAlloc`:** This test focuses on the allocation process. The `before`, `scav`, and `after` maps define the state of the memory before and after allocations. The `hits` slice defines sequences of allocation requests and their expected return values (base address and scavenged size). The `scav` map likely relates to garbage collection or memory scavenging.
    * **`TestPageAllocFree`:** This test is about freeing allocated memory. Similar to `TestPageAllocAlloc`, it uses `before` and `after` states and a `frees` slice indicating which addresses to free.
    * **`TestPageAllocExhaust`:** This test specifically checks the behavior when the `PageAlloc` runs out of memory.
    * **`TestPageAllocAllocAndFree`:**  This test likely combines allocation and freeing operations to check their interaction.

5. **Infer Functionality from Tests:** Based on the test names and their setups, we can infer the following about `PageAlloc`:
    * It manages memory in units of "pages".
    * It organizes pages into larger units called "chunks".
    * It can grow its managed memory by incorporating new chunks.
    * It can allocate blocks of contiguous pages.
    * It can free previously allocated blocks of pages.
    * It keeps track of which pages are allocated and which are free.
    * It seems to interact with a "scavenger," possibly for garbage collection purposes.

6. **Consider Edge Cases and Error Handling:** The tests include various scenarios, including:
    * Contiguous and discontiguous memory regions.
    * Allocations spanning chunk boundaries.
    * Exhausting available memory.
    * Scavenged memory.
    * Special handling for certain operating systems (like OpenBSD).

7. **Connect to Go Concepts:** Based on the inferred functionality, we can connect `PageAlloc` to Go's memory management. It's likely a low-level component used by the Go runtime to manage the heap, providing the foundation for allocating larger objects. The interaction with "scavenging" suggests its involvement in garbage collection.

8. **Address Specific Questions:**  Now, specifically address the user's questions:
    * **Functionality:** Summarize the inferred functionalities.
    * **Go Feature:**  Identify it as a low-level memory management component, likely part of the heap management within the Go runtime.
    * **Code Example:** Create a simplified Go example to illustrate the general concept of allocating and freeing memory, even if it doesn't directly use `PageAlloc`. Focus on demonstrating the idea of requesting memory and then releasing it.
    * **Assumptions, Inputs, Outputs (for code reasoning):** For the test functions, the `before` maps are the assumed input state, and the `after` maps are the expected output state. The `hits` and `frees` slices define the actions performed.
    * **Command-line arguments:** Scan the code for command-line flag usage. There isn't any in this snippet.
    * **Common mistakes:** Think about how a user interacting with a similar memory management system might make mistakes (e.g., double-freeing, not freeing memory, incorrect size calculations). Since this is internal Go code, direct user interaction is limited, but the tests reveal potential internal complexities.
    * **Summarize Functionality (Part 1):**  Condense the main functions of the code as requested.

9. **Refine and Organize:**  Review the analysis for clarity, accuracy, and completeness. Organize the information logically under the user's specific prompts. Use clear and concise language, avoiding overly technical jargon where possible.

By following these steps, we can systematically analyze the provided Go code snippet and arrive at a comprehensive understanding of its functionality and its place within the Go runtime.
这段Go语言代码是 `runtime` 包中关于 `PageAlloc` 的测试代码的一部分。`PageAlloc` 似乎是 Go 运行时系统中用于管理**页级别内存分配**的一个核心组件。

**功能归纳:**

这段代码主要包含了对 `PageAlloc` 结构体的各种操作进行单元测试的函数。具体来说，它测试了以下功能：

1. **`TestPageAllocGrow`**:  测试 `PageAlloc` 如何**扩展**其管理的内存区域。它模拟了向 `PageAlloc` 添加不同的内存块（chunks），并验证 `PageAlloc` 能否正确地跟踪和报告当前已使用的内存范围。
2. **`TestPageAllocAlloc`**: 测试 `PageAlloc` 的**分配**功能。它模拟了在不同的内存布局下请求分配指定数量的页，并验证 `PageAlloc` 是否返回了正确的起始地址和是否正确地更新了内部的分配状态（例如，哪些页被标记为已分配）。同时，它还考虑了与内存回收（scavenging）相关的状态。
3. **`TestPageAllocExhaust`**: 测试当 `PageAlloc` **耗尽**可用内存时的行为。它通过不断分配内存直到分配失败，来验证 `PageAlloc` 是否能正确地返回失败状态，并且其内部状态是否正确。
4. **`TestPageAllocFree`**: 测试 `PageAlloc` 的**释放**功能。它模拟了释放之前分配的内存，并验证 `PageAlloc` 是否正确地将释放的页标记为可用。
5. **`TestPageAllocAllocAndFree`**:  测试**分配和释放**操作的组合，以验证这两个操作在一起工作时的正确性。

**推断的 Go 语言功能实现: 页级别的内存分配**

基于测试代码的结构和涉及的操作（Grow, Alloc, Free），可以推断 `PageAlloc` 是 Go 运行时系统中负责管理**页级别**内存分配的关键数据结构。它可能被更高级的内存分配器（如 mcache, mcentral 等）所使用，作为其底层机制来分配和释放内存。

**Go 代码举例说明:**

虽然 `PageAlloc` 是 `runtime` 包的内部实现，我们无法直接在用户代码中创建和使用它。但是，我们可以用一个简化的例子来模拟其核心功能：分配和释放内存页。

```go
package main

import "fmt"

const PageSize = 4096 // 假设页大小为 4KB

// 模拟的 PageAlloc 结构体 (简化)
type MockPageAlloc struct {
	allocatedPages map[uintptr]bool
}

// 模拟的分配函数
func (m *MockPageAlloc) allocPages(numPages uintptr) []uintptr {
	allocated := make([]uintptr, numPages)
	for i := uintptr(0); i < numPages; i++ {
		// 实际实现会涉及更复杂的逻辑，例如查找空闲页
		addr := uintptr(len(m.allocatedPages)) * PageSize // 简单地用已分配页的数量 * 页大小作为起始地址
		allocated[i] = addr
		m.allocatedPages[addr] = true
	}
	return allocated
}

// 模拟的释放函数
func (m *MockPageAlloc) freePages(addrs []uintptr) {
	for _, addr := range addrs {
		delete(m.allocatedPages, addr)
	}
}

func main() {
	pageAlloc := MockPageAlloc{allocatedPages: make(map[uintptr]bool)}

	// 分配 3 个页
	allocated1 := pageAlloc.allocPages(3)
	fmt.Println("分配的页 1:", allocated1)

	// 分配 2 个页
	allocated2 := pageAlloc.allocPages(2)
	fmt.Println("分配的页 2:", allocated2)

	// 释放第一个分配的 2 个页
	pagesToFree := allocated1[:2]
	pageAlloc.freePages(pagesToFree)
	fmt.Println("释放页:", pagesToFree)

	// 再次分配 1 个页
	allocated3 := pageAlloc.allocPages(1)
	fmt.Println("再次分配的页:", allocated3)
}
```

**假设的输入与输出 (基于 `TestPageAllocAlloc`):**

假设 `TestPageAllocAlloc` 中的一个测试用例 "AllFree1"：

* **假设输入 (`before`):**  `PageAlloc` 管理着一个 chunk，这个 chunk 中没有任何页被标记为已分配。
* **假设输入 (`scav`):**  `PageAlloc` 知道在这个 chunk 中，第 0, 2 页是被回收的 (scavenged)。
* **操作 (`hits`):**
    1. 请求分配 1 个页。
    2. 请求分配 1 个页。
    3. 请求分配 1 个页。
    4. 请求分配 1 个页。
    5. 请求分配 1 个页。
* **预期输出 (`after`):** `PageAlloc` 的内部状态应该更新为这个 chunk 的前 5 个页都被标记为已分配。
* **预期输出 (`hits` 的返回值):**
    1. 分配成功，返回基地址 `PageBase(BaseChunkIdx, 0)`，回收大小为 `PageSize`（因为第 0 页被回收）。
    2. 分配成功，返回基地址 `PageBase(BaseChunkIdx, 1)`，回收大小为 0。
    3. 分配成功，返回基地址 `PageBase(BaseChunkIdx, 2)`，回收大小为 `PageSize`（因为第 2 页被回收）。
    4. 分配成功，返回基地址 `PageBase(BaseChunkIdx, 3)`，回收大小为 `PageSize`（假设后续的 scavenged 信息）。
    5. 分配成功，返回基地址 `PageBase(BaseChunkIdx, 4)`，回收大小为 0。

**命令行参数的具体处理:**

在这段代码中，没有直接涉及到命令行参数的处理。这是一个单元测试文件，通常由 `go test` 命令执行。`go test` 命令本身可以接受一些参数，例如指定要运行的测试文件或函数，设置超时时间等。

**使用者易犯错的点:**

由于 `PageAlloc` 是 Go 运行时内部的实现，普通 Go 开发者不会直接使用它。 然而，理解其背后的概念有助于理解 Go 内存管理的原理。

对于实现了类似页分配器的开发者来说，一些常见的错误可能包括：

* **内存泄漏:** 分配了内存页但没有正确释放。
* **野指针:** 释放了内存页后，仍然持有指向该内存页的指针并尝试访问。
* **重复释放:**  多次释放同一个内存页。
* **越界访问:**  在分配的内存页之外进行读写操作。
* **并发安全问题:** 在多线程环境下，如果没有正确的同步机制，多个线程可能同时操作同一个 `PageAlloc` 实例，导致数据竞争和状态错误。

**总结 (Part 1 的功能):**

这段 `go/src/runtime/mpagealloc_test.go` 的第一部分代码主要定义了多个单元测试函数，用于详细测试 `runtime.PageAlloc` 结构体的以下核心功能：

* **内存增长 (`Grow`)**: 验证 `PageAlloc` 如何管理和跟踪新加入的内存块。
* **内存分配 (`Alloc`)**: 验证 `PageAlloc` 在不同内存状态下分配指定大小内存页的能力，并检查其对回收内存的处理。
* **内存耗尽 (`Exhaust`)**: 验证当所有内存都被分配完时 `PageAlloc` 的行为。

这些测试用例通过预设的内存状态 (`before`) 和期望的内存状态 (`after`)，以及一系列的操作 (`hits`, `frees`)，来验证 `PageAlloc` 实现的正确性。这部分代码是 Go 运行时系统自测试的重要组成部分，确保了底层内存管理机制的稳定性和可靠性。

### 提示词
```
这是路径为go/src/runtime/mpagealloc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package runtime_test

import (
	"fmt"
	"internal/goos"
	. "runtime"
	"testing"
)

func checkPageAlloc(t *testing.T, want, got *PageAlloc) {
	// Ensure start and end are correct.
	wantStart, wantEnd := want.Bounds()
	gotStart, gotEnd := got.Bounds()
	if gotStart != wantStart {
		t.Fatalf("start values not equal: got %d, want %d", gotStart, wantStart)
	}
	if gotEnd != wantEnd {
		t.Fatalf("end values not equal: got %d, want %d", gotEnd, wantEnd)
	}

	for i := gotStart; i < gotEnd; i++ {
		// Check the bitmaps. Note that we may have nil data.
		gb, wb := got.PallocData(i), want.PallocData(i)
		if gb == nil && wb == nil {
			continue
		}
		if (gb == nil && wb != nil) || (gb != nil && wb == nil) {
			t.Errorf("chunk %d nilness mismatch", i)
		}
		if !checkPallocBits(t, gb.PallocBits(), wb.PallocBits()) {
			t.Logf("in chunk %d (mallocBits)", i)
		}
		if !checkPallocBits(t, gb.Scavenged(), wb.Scavenged()) {
			t.Logf("in chunk %d (scavenged)", i)
		}
	}
	// TODO(mknyszek): Verify summaries too?
}

func TestPageAllocGrow(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	type test struct {
		chunks []ChunkIdx
		inUse  []AddrRange
	}
	tests := map[string]test{
		"One": {
			chunks: []ChunkIdx{
				BaseChunkIdx,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0)),
			},
		},
		"Contiguous2": {
			chunks: []ChunkIdx{
				BaseChunkIdx,
				BaseChunkIdx + 1,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+2, 0)),
			},
		},
		"Contiguous5": {
			chunks: []ChunkIdx{
				BaseChunkIdx,
				BaseChunkIdx + 1,
				BaseChunkIdx + 2,
				BaseChunkIdx + 3,
				BaseChunkIdx + 4,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+5, 0)),
			},
		},
		"Discontiguous": {
			chunks: []ChunkIdx{
				BaseChunkIdx,
				BaseChunkIdx + 2,
				BaseChunkIdx + 4,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+2, 0), PageBase(BaseChunkIdx+3, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+4, 0), PageBase(BaseChunkIdx+5, 0)),
			},
		},
		"Mixed": {
			chunks: []ChunkIdx{
				BaseChunkIdx,
				BaseChunkIdx + 1,
				BaseChunkIdx + 2,
				BaseChunkIdx + 4,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+3, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+4, 0), PageBase(BaseChunkIdx+5, 0)),
			},
		},
		"WildlyDiscontiguous": {
			chunks: []ChunkIdx{
				BaseChunkIdx,
				BaseChunkIdx + 1,
				BaseChunkIdx + 0x10,
				BaseChunkIdx + 0x21,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+2, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+0x10, 0), PageBase(BaseChunkIdx+0x11, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+0x21, 0), PageBase(BaseChunkIdx+0x22, 0)),
			},
		},
		"ManyDiscontiguous": {
			// The initial cap is 16. Test 33 ranges, to exercise the growth path (twice).
			chunks: []ChunkIdx{
				BaseChunkIdx, BaseChunkIdx + 2, BaseChunkIdx + 4, BaseChunkIdx + 6,
				BaseChunkIdx + 8, BaseChunkIdx + 10, BaseChunkIdx + 12, BaseChunkIdx + 14,
				BaseChunkIdx + 16, BaseChunkIdx + 18, BaseChunkIdx + 20, BaseChunkIdx + 22,
				BaseChunkIdx + 24, BaseChunkIdx + 26, BaseChunkIdx + 28, BaseChunkIdx + 30,
				BaseChunkIdx + 32, BaseChunkIdx + 34, BaseChunkIdx + 36, BaseChunkIdx + 38,
				BaseChunkIdx + 40, BaseChunkIdx + 42, BaseChunkIdx + 44, BaseChunkIdx + 46,
				BaseChunkIdx + 48, BaseChunkIdx + 50, BaseChunkIdx + 52, BaseChunkIdx + 54,
				BaseChunkIdx + 56, BaseChunkIdx + 58, BaseChunkIdx + 60, BaseChunkIdx + 62,
				BaseChunkIdx + 64,
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+2, 0), PageBase(BaseChunkIdx+3, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+4, 0), PageBase(BaseChunkIdx+5, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+6, 0), PageBase(BaseChunkIdx+7, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+8, 0), PageBase(BaseChunkIdx+9, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+10, 0), PageBase(BaseChunkIdx+11, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+12, 0), PageBase(BaseChunkIdx+13, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+14, 0), PageBase(BaseChunkIdx+15, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+16, 0), PageBase(BaseChunkIdx+17, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+18, 0), PageBase(BaseChunkIdx+19, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+20, 0), PageBase(BaseChunkIdx+21, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+22, 0), PageBase(BaseChunkIdx+23, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+24, 0), PageBase(BaseChunkIdx+25, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+26, 0), PageBase(BaseChunkIdx+27, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+28, 0), PageBase(BaseChunkIdx+29, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+30, 0), PageBase(BaseChunkIdx+31, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+32, 0), PageBase(BaseChunkIdx+33, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+34, 0), PageBase(BaseChunkIdx+35, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+36, 0), PageBase(BaseChunkIdx+37, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+38, 0), PageBase(BaseChunkIdx+39, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+40, 0), PageBase(BaseChunkIdx+41, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+42, 0), PageBase(BaseChunkIdx+43, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+44, 0), PageBase(BaseChunkIdx+45, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+46, 0), PageBase(BaseChunkIdx+47, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+48, 0), PageBase(BaseChunkIdx+49, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+50, 0), PageBase(BaseChunkIdx+51, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+52, 0), PageBase(BaseChunkIdx+53, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+54, 0), PageBase(BaseChunkIdx+55, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+56, 0), PageBase(BaseChunkIdx+57, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+58, 0), PageBase(BaseChunkIdx+59, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+60, 0), PageBase(BaseChunkIdx+61, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+62, 0), PageBase(BaseChunkIdx+63, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+64, 0), PageBase(BaseChunkIdx+65, 0)),
			},
		},
	}
	// Disable these tests on iOS since we have a small address space.
	// See #46860.
	if PageAlloc64Bit != 0 && goos.IsIos == 0 {
		tests["ExtremelyDiscontiguous"] = test{
			chunks: []ChunkIdx{
				BaseChunkIdx,
				BaseChunkIdx + 0x100000, // constant translates to O(TiB)
			},
			inUse: []AddrRange{
				MakeAddrRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0)),
				MakeAddrRange(PageBase(BaseChunkIdx+0x100000, 0), PageBase(BaseChunkIdx+0x100001, 0)),
			},
		}
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			// By creating a new pageAlloc, we will
			// grow it for each chunk defined in x.
			x := make(map[ChunkIdx][]BitRange)
			for _, c := range v.chunks {
				x[c] = []BitRange{}
			}
			b := NewPageAlloc(x, nil)
			defer FreePageAlloc(b)

			got := b.InUse()
			want := v.inUse

			// Check for mismatches.
			if len(got) != len(want) {
				t.Fail()
			} else {
				for i := range want {
					if !want[i].Equals(got[i]) {
						t.Fail()
						break
					}
				}
			}
			if t.Failed() {
				t.Logf("found inUse mismatch")
				t.Logf("got:")
				for i, r := range got {
					t.Logf("\t#%d [0x%x, 0x%x)", i, r.Base(), r.Limit())
				}
				t.Logf("want:")
				for i, r := range want {
					t.Logf("\t#%d [0x%x, 0x%x)", i, r.Base(), r.Limit())
				}
			}
		})
	}
}

func TestPageAllocAlloc(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	type hit struct {
		npages, base, scav uintptr
	}
	type test struct {
		scav   map[ChunkIdx][]BitRange
		before map[ChunkIdx][]BitRange
		after  map[ChunkIdx][]BitRange
		hits   []hit
	}
	tests := map[string]test{
		"AllFree1": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 1}, {2, 2}},
			},
			hits: []hit{
				{1, PageBase(BaseChunkIdx, 0), PageSize},
				{1, PageBase(BaseChunkIdx, 1), 0},
				{1, PageBase(BaseChunkIdx, 2), PageSize},
				{1, PageBase(BaseChunkIdx, 3), PageSize},
				{1, PageBase(BaseChunkIdx, 4), 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 5}},
			},
		},
		"ManyArena1": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages - 1}},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
			hits: []hit{
				{1, PageBase(BaseChunkIdx+2, PallocChunkPages-1), PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
		},
		"NotContiguous1": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{0, 0}},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{0, PallocChunkPages}},
			},
			hits: []hit{
				{1, PageBase(BaseChunkIdx+0xff, 0), PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0xff: {{0, 1}},
			},
		},
		"AllFree2": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 3}, {7, 1}},
			},
			hits: []hit{
				{2, PageBase(BaseChunkIdx, 0), 2 * PageSize},
				{2, PageBase(BaseChunkIdx, 2), PageSize},
				{2, PageBase(BaseChunkIdx, 4), 0},
				{2, PageBase(BaseChunkIdx, 6), PageSize},
				{2, PageBase(BaseChunkIdx, 8), 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 10}},
			},
		},
		"Straddle2": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages - 1}},
				BaseChunkIdx + 1: {{1, PallocChunkPages - 1}},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{PallocChunkPages - 1, 1}},
				BaseChunkIdx + 1: {},
			},
			hits: []hit{
				{2, PageBase(BaseChunkIdx, PallocChunkPages-1), PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
		},
		"AllFree5": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 8}, {9, 1}, {17, 5}},
			},
			hits: []hit{
				{5, PageBase(BaseChunkIdx, 0), 5 * PageSize},
				{5, PageBase(BaseChunkIdx, 5), 4 * PageSize},
				{5, PageBase(BaseChunkIdx, 10), 0},
				{5, PageBase(BaseChunkIdx, 15), 3 * PageSize},
				{5, PageBase(BaseChunkIdx, 20), 2 * PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 25}},
			},
		},
		"AllFree64": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{21, 1}, {63, 65}},
			},
			hits: []hit{
				{64, PageBase(BaseChunkIdx, 0), 2 * PageSize},
				{64, PageBase(BaseChunkIdx, 64), 64 * PageSize},
				{64, PageBase(BaseChunkIdx, 128), 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 192}},
			},
		},
		"AllFree65": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{129, 1}},
			},
			hits: []hit{
				{65, PageBase(BaseChunkIdx, 0), 0},
				{65, PageBase(BaseChunkIdx, 65), PageSize},
				{65, PageBase(BaseChunkIdx, 130), 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 195}},
			},
		},
		"ExhaustPallocChunkPages-3": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{10, 1}},
			},
			hits: []hit{
				{PallocChunkPages - 3, PageBase(BaseChunkIdx, 0), PageSize},
				{PallocChunkPages - 3, 0, 0},
				{1, PageBase(BaseChunkIdx, PallocChunkPages-3), 0},
				{2, PageBase(BaseChunkIdx, PallocChunkPages-2), 0},
				{1, 0, 0},
				{PallocChunkPages - 3, 0, 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
		},
		"AllFreePallocChunkPages": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, 1}, {PallocChunkPages - 1, 1}},
			},
			hits: []hit{
				{PallocChunkPages, PageBase(BaseChunkIdx, 0), 2 * PageSize},
				{PallocChunkPages, 0, 0},
				{1, 0, 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
		},
		"StraddlePallocChunkPages": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages / 2}},
				BaseChunkIdx + 1: {{PallocChunkPages / 2, PallocChunkPages / 2}},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {{3, 100}},
			},
			hits: []hit{
				{PallocChunkPages, PageBase(BaseChunkIdx, PallocChunkPages/2), 100 * PageSize},
				{PallocChunkPages, 0, 0},
				{1, 0, 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
		},
		"StraddlePallocChunkPages+1": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages / 2}},
				BaseChunkIdx + 1: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
			hits: []hit{
				{PallocChunkPages + 1, PageBase(BaseChunkIdx, PallocChunkPages/2), (PallocChunkPages + 1) * PageSize},
				{PallocChunkPages, 0, 0},
				{1, PageBase(BaseChunkIdx+1, PallocChunkPages/2+1), PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages/2 + 2}},
			},
		},
		"AllFreePallocChunkPages*2": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
			},
			hits: []hit{
				{PallocChunkPages * 2, PageBase(BaseChunkIdx, 0), 0},
				{PallocChunkPages * 2, 0, 0},
				{1, 0, 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
		},
		"NotContiguousPallocChunkPages*2": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {},
				BaseChunkIdx + 0x40: {},
				BaseChunkIdx + 0x41: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, PallocChunkPages}},
				BaseChunkIdx + 0x40: {},
				BaseChunkIdx + 0x41: {},
			},
			hits: []hit{
				{PallocChunkPages * 2, PageBase(BaseChunkIdx+0x40, 0), 0},
				{21, PageBase(BaseChunkIdx, 0), 21 * PageSize},
				{1, PageBase(BaseChunkIdx, 21), PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:        {{0, 22}},
				BaseChunkIdx + 0x40: {{0, PallocChunkPages}},
				BaseChunkIdx + 0x41: {{0, PallocChunkPages}},
			},
		},
		"StraddlePallocChunkPages*2": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages / 2}},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {{PallocChunkPages / 2, PallocChunkPages / 2}},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, 7}},
				BaseChunkIdx + 1: {{3, 5}, {121, 10}},
				BaseChunkIdx + 2: {{PallocChunkPages/2 + 12, 2}},
			},
			hits: []hit{
				{PallocChunkPages * 2, PageBase(BaseChunkIdx, PallocChunkPages/2), 15 * PageSize},
				{PallocChunkPages * 2, 0, 0},
				{1, 0, 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
		},
		"StraddlePallocChunkPages*5/4": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages * 3 / 4}},
				BaseChunkIdx + 2: {{0, PallocChunkPages * 3 / 4}},
				BaseChunkIdx + 3: {{0, 0}},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{PallocChunkPages / 2, PallocChunkPages/4 + 1}},
				BaseChunkIdx + 2: {{PallocChunkPages / 3, 1}},
				BaseChunkIdx + 3: {{PallocChunkPages * 2 / 3, 1}},
			},
			hits: []hit{
				{PallocChunkPages * 5 / 4, PageBase(BaseChunkIdx+2, PallocChunkPages*3/4), PageSize},
				{PallocChunkPages * 5 / 4, 0, 0},
				{1, PageBase(BaseChunkIdx+1, PallocChunkPages*3/4), PageSize},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages*3/4 + 1}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
				BaseChunkIdx + 3: {{0, PallocChunkPages}},
			},
		},
		"AllFreePallocChunkPages*7+5": {
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {},
				BaseChunkIdx + 3: {},
				BaseChunkIdx + 4: {},
				BaseChunkIdx + 5: {},
				BaseChunkIdx + 6: {},
				BaseChunkIdx + 7: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{50, 1}},
				BaseChunkIdx + 1: {{31, 1}},
				BaseChunkIdx + 2: {{7, 1}},
				BaseChunkIdx + 3: {{200, 1}},
				BaseChunkIdx + 4: {{3, 1}},
				BaseChunkIdx + 5: {{51, 1}},
				BaseChunkIdx + 6: {{20, 1}},
				BaseChunkIdx + 7: {{1, 1}},
			},
			hits: []hit{
				{PallocChunkPages*7 + 5, PageBase(BaseChunkIdx, 0), 8 * PageSize},
				{PallocChunkPages*7 + 5, 0, 0},
				{1, PageBase(BaseChunkIdx+7, 5), 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
				BaseChunkIdx + 3: {{0, PallocChunkPages}},
				BaseChunkIdx + 4: {{0, PallocChunkPages}},
				BaseChunkIdx + 5: {{0, PallocChunkPages}},
				BaseChunkIdx + 6: {{0, PallocChunkPages}},
				BaseChunkIdx + 7: {{0, 6}},
			},
		},
	}
	// Disable these tests on iOS since we have a small address space.
	// See #46860.
	if PageAlloc64Bit != 0 && goos.IsIos == 0 {
		const chunkIdxBigJump = 0x100000 // chunk index offset which translates to O(TiB)

		// This test attempts to trigger a bug wherein we look at unmapped summary
		// memory that isn't just in the case where we exhaust the heap.
		//
		// It achieves this by placing a chunk such that its summary will be
		// at the very end of a physical page. It then also places another chunk
		// much further up in the address space, such that any allocations into the
		// first chunk do not exhaust the heap and the second chunk's summary is not in the
		// page immediately adjacent to the first chunk's summary's page.
		// Allocating into this first chunk to exhaustion and then into the second
		// chunk may then trigger a check in the allocator which erroneously looks at
		// unmapped summary memory and crashes.

		// Figure out how many chunks are in a physical page, then align BaseChunkIdx
		// to a physical page in the chunk summary array. Here we only assume that
		// each summary array is aligned to some physical page.
		sumsPerPhysPage := ChunkIdx(PhysPageSize / PallocSumBytes)
		baseChunkIdx := BaseChunkIdx &^ (sumsPerPhysPage - 1)
		tests["DiscontiguousMappedSumBoundary"] = test{
			before: map[ChunkIdx][]BitRange{
				baseChunkIdx + sumsPerPhysPage - 1: {},
				baseChunkIdx + chunkIdxBigJump:     {},
			},
			scav: map[ChunkIdx][]BitRange{
				baseChunkIdx + sumsPerPhysPage - 1: {},
				baseChunkIdx + chunkIdxBigJump:     {},
			},
			hits: []hit{
				{PallocChunkPages - 1, PageBase(baseChunkIdx+sumsPerPhysPage-1, 0), 0},
				{1, PageBase(baseChunkIdx+sumsPerPhysPage-1, PallocChunkPages-1), 0},
				{1, PageBase(baseChunkIdx+chunkIdxBigJump, 0), 0},
				{PallocChunkPages - 1, PageBase(baseChunkIdx+chunkIdxBigJump, 1), 0},
				{1, 0, 0},
			},
			after: map[ChunkIdx][]BitRange{
				baseChunkIdx + sumsPerPhysPage - 1: {{0, PallocChunkPages}},
				baseChunkIdx + chunkIdxBigJump:     {{0, PallocChunkPages}},
			},
		}

		// Test to check for issue #40191. Essentially, the candidate searchAddr
		// discovered by find may not point to mapped memory, so we need to handle
		// that explicitly.
		//
		// chunkIdxSmallOffset is an offset intended to be used within chunkIdxBigJump.
		// It is far enough within chunkIdxBigJump that the summaries at the beginning
		// of an address range the size of chunkIdxBigJump will not be mapped in.
		const chunkIdxSmallOffset = 0x503
		tests["DiscontiguousBadSearchAddr"] = test{
			before: map[ChunkIdx][]BitRange{
				// The mechanism for the bug involves three chunks, A, B, and C, which are
				// far apart in the address space. In particular, B is chunkIdxBigJump +
				// chunkIdxSmalloffset chunks away from B, and C is 2*chunkIdxBigJump chunks
				// away from A. A has 1 page free, B has several (NOT at the end of B), and
				// C is totally free.
				// Note that B's free memory must not be at the end of B because the fast
				// path in the page allocator will check if the searchAddr even gives us
				// enough space to place the allocation in a chunk before accessing the
				// summary.
				BaseChunkIdx + chunkIdxBigJump*0: {{0, PallocChunkPages - 1}},
				BaseChunkIdx + chunkIdxBigJump*1 + chunkIdxSmallOffset: {
					{0, PallocChunkPages - 10},
					{PallocChunkPages - 1, 1},
				},
				BaseChunkIdx + chunkIdxBigJump*2: {},
			},
			scav: map[ChunkIdx][]BitRange{
				BaseChunkIdx + chunkIdxBigJump*0:                       {},
				BaseChunkIdx + chunkIdxBigJump*1 + chunkIdxSmallOffset: {},
				BaseChunkIdx + chunkIdxBigJump*2:                       {},
			},
			hits: []hit{
				// We first allocate into A to set the page allocator's searchAddr to the
				// end of that chunk. That is the only purpose A serves.
				{1, PageBase(BaseChunkIdx, PallocChunkPages-1), 0},
				// Then, we make a big allocation that doesn't fit into B, and so must be
				// fulfilled by C.
				//
				// On the way to fulfilling the allocation into C, we estimate searchAddr
				// using the summary structure, but that will give us a searchAddr of
				// B's base address minus chunkIdxSmallOffset chunks. These chunks will
				// not be mapped.
				{100, PageBase(baseChunkIdx+chunkIdxBigJump*2, 0), 0},
				// Now we try to make a smaller allocation that can be fulfilled by B.
				// In an older implementation of the page allocator, this will segfault,
				// because this last allocation will first try to access the summary
				// for B's base address minus chunkIdxSmallOffset chunks in the fast path,
				// and this will not be mapped.
				{9, PageBase(baseChunkIdx+chunkIdxBigJump*1+chunkIdxSmallOffset, PallocChunkPages-10), 0},
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx + chunkIdxBigJump*0:                       {{0, PallocChunkPages}},
				BaseChunkIdx + chunkIdxBigJump*1 + chunkIdxSmallOffset: {{0, PallocChunkPages}},
				BaseChunkIdx + chunkIdxBigJump*2:                       {{0, 100}},
			},
		}
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := NewPageAlloc(v.before, v.scav)
			defer FreePageAlloc(b)

			for iter, i := range v.hits {
				a, s := b.Alloc(i.npages)
				if a != i.base {
					t.Fatalf("bad alloc #%d: want base 0x%x, got 0x%x", iter+1, i.base, a)
				}
				if s != i.scav {
					t.Fatalf("bad alloc #%d: want scav %d, got %d", iter+1, i.scav, s)
				}
			}
			want := NewPageAlloc(v.after, v.scav)
			defer FreePageAlloc(want)

			checkPageAlloc(t, want, b)
		})
	}
}

func TestPageAllocExhaust(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	for _, npages := range []uintptr{1, 2, 3, 4, 5, 8, 16, 64, 1024, 1025, 2048, 2049} {
		npages := npages
		t.Run(fmt.Sprintf("%d", npages), func(t *testing.T) {
			// Construct b.
			bDesc := make(map[ChunkIdx][]BitRange)
			for i := ChunkIdx(0); i < 4; i++ {
				bDesc[BaseChunkIdx+i] = []BitRange{}
			}
			b := NewPageAlloc(bDesc, nil)
			defer FreePageAlloc(b)

			// Allocate into b with npages until we've exhausted the heap.
			nAlloc := (PallocChunkPages * 4) / int(npages)
			for i := 0; i < nAlloc; i++ {
				addr := PageBase(BaseChunkIdx, uint(i)*uint(npages))
				if a, _ := b.Alloc(npages); a != addr {
					t.Fatalf("bad alloc #%d: want 0x%x, got 0x%x", i+1, addr, a)
				}
			}

			// Check to make sure the next allocation fails.
			if a, _ := b.Alloc(npages); a != 0 {
				t.Fatalf("bad alloc #%d: want 0, got 0x%x", nAlloc, a)
			}

			// Construct what we want the heap to look like now.
			allocPages := nAlloc * int(npages)
			wantDesc := make(map[ChunkIdx][]BitRange)
			for i := ChunkIdx(0); i < 4; i++ {
				if allocPages >= PallocChunkPages {
					wantDesc[BaseChunkIdx+i] = []BitRange{{0, PallocChunkPages}}
					allocPages -= PallocChunkPages
				} else if allocPages > 0 {
					wantDesc[BaseChunkIdx+i] = []BitRange{{0, uint(allocPages)}}
					allocPages = 0
				} else {
					wantDesc[BaseChunkIdx+i] = []BitRange{}
				}
			}
			want := NewPageAlloc(wantDesc, nil)
			defer FreePageAlloc(want)

			// Check to make sure the heap b matches what we want.
			checkPageAlloc(t, want, b)
		})
	}
}

func TestPageAllocFree(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	tests := map[string]struct {
		before map[ChunkIdx][]BitRange
		after  map[ChunkIdx][]BitRange
		npages uintptr
		frees  []uintptr
	}{
		"Free1": {
			npages: 1,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
				PageBase(BaseChunkIdx, 1),
				PageBase(BaseChunkIdx, 2),
				PageBase(BaseChunkIdx, 3),
				PageBase(BaseChunkIdx, 4),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{5, PallocChunkPages - 5}},
			},
		},
		"ManyArena1": {
			npages: 1,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, PallocChunkPages/2),
				PageBase(BaseChunkIdx+1, 0),
				PageBase(BaseChunkIdx+2, PallocChunkPages-1),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages / 2}, {PallocChunkPages/2 + 1, PallocChunkPages/2 - 1}},
				BaseChunkIdx + 1: {{1, PallocChunkPages - 1}},
				BaseChunkIdx + 2: {{0, PallocChunkPages - 1}},
			},
		},
		"Free2": {
			npages: 2,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
				PageBase(BaseChunkIdx, 2),
				PageBase(BaseChunkIdx, 4),
				PageBase(BaseChunkIdx, 6),
				PageBase(BaseChunkIdx, 8),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{10, PallocChunkPages - 10}},
			},
		},
		"Straddle2": {
			npages: 2,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{PallocChunkPages - 1, 1}},
				BaseChunkIdx + 1: {{0, 1}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, PallocChunkPages-1),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
			},
		},
		"Free5": {
			npages: 5,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
				PageBase(BaseChunkIdx, 5),
				PageBase(BaseChunkIdx, 10),
				PageBase(BaseChunkIdx, 15),
				PageBase(BaseChunkIdx, 20),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{25, PallocChunkPages - 25}},
			},
		},
		"Free64": {
			npages: 64,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
				PageBase(BaseChunkIdx, 64),
				PageBase(BaseChunkIdx, 128),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{192, PallocChunkPages - 192}},
			},
		},
		"Free65": {
			npages: 65,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
				PageBase(BaseChunkIdx, 65),
				PageBase(BaseChunkIdx, 130),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{195, PallocChunkPages - 195}},
			},
		},
		"FreePallocChunkPages": {
			npages: PallocChunkPages,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
		},
		"StraddlePallocChunkPages": {
			npages: PallocChunkPages,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{PallocChunkPages / 2, PallocChunkPages / 2}},
				BaseChunkIdx + 1: {{0, PallocChunkPages / 2}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, PallocChunkPages/2),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
			},
		},
		"StraddlePallocChunkPages+1": {
			npages: PallocChunkPages + 1,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, PallocChunkPages/2),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages / 2}},
				BaseChunkIdx + 1: {{PallocChunkPages/2 + 1, PallocChunkPages/2 - 1}},
			},
		},
		"FreePallocChunkPages*2": {
			npages: PallocChunkPages * 2,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
			},
		},
		"StraddlePallocChunkPages*2": {
			npages: PallocChunkPages * 2,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, PallocChunkPages/2),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages / 2}},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {{PallocChunkPages / 2, PallocChunkPages / 2}},
			},
		},
		"AllFreePallocChunkPages*7+5": {
			npages: PallocChunkPages*7 + 5,
			before: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
				BaseChunkIdx + 3: {{0, PallocChunkPages}},
				BaseChunkIdx + 4: {{0, PallocChunkPages}},
				BaseChunkIdx + 5: {{0, PallocChunkPages}},
				BaseChunkIdx + 6: {{0, PallocChunkPages}},
				BaseChunkIdx + 7: {{0, PallocChunkPages}},
			},
			frees: []uintptr{
				PageBase(BaseChunkIdx, 0),
			},
			after: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {},
				BaseChunkIdx + 3: {},
				BaseChunkIdx + 4: {},
				BaseChunkIdx + 5: {},
				BaseChunkIdx + 6: {},
				BaseChunkIdx + 7: {{5, PallocChunkPages - 5}},
			},
		},
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := NewPageAlloc(v.before, nil)
			defer FreePageAlloc(b)

			for _, addr := range v.frees {
				b.Free(addr, v.npages)
			}
			want := NewPageAlloc(v.after, nil)
			defer FreePageAlloc(want)

			checkPageAlloc(t, want, b)
		})
	}
}

func TestPageAllocAllocAndFree(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	type hit struct {
		alloc  bool
		npages uintptr
		base   uintptr
	}
	tests := map[string]struct {
		init map[ChunkIdx][]BitRange
		hits []hit
	}{
		// TODO(mknyszek): Write more tests here.
		"Chunks8": {
			init: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {},
				BaseChunkIdx + 3: {},
				BaseChunkIdx + 4: {},
				BaseChunkIdx + 5: {},
				BaseChunkIdx + 6: {},
				BaseChunkIdx + 7: {},
			},
			hits: []hit{
				{true, PallocChunkPages * 8, PageBase(BaseChunkIdx, 0)},
				{false, PallocChunkPages * 8, PageBase(BaseChunkIdx, 0)},
				{true, PallocChunkPages * 8, PageBase(BaseChunkIdx, 0)},
				{false, PallocChunkPages * 8, PageBase(BaseChunkIdx, 0)},
				{true, PallocChunkPages * 8, PageBase(BaseChunkId
```