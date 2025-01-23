Response:
My goal is to analyze the provided Go code snippet from `go/src/runtime/mgcscavenge_test.go` and explain its functionality in detail, including its role within the Go runtime. Here's my thought process:

1. **Understand the Context:** The file name `mgcscavenge_test.go` immediately suggests this code is for testing the memory garbage collector's scavenging functionality. The `package runtime_test` confirms this is an external test package for the `runtime` package.

2. **Identify Key Data Structures and Functions:** I'll scan the code for important types and functions.

    * `PallocData`: This struct and associated methods (`AllocRange`, `ScavengedSetRange`, `FindScavengeCandidate`) seem central to managing allocation and scavenging information within a chunk of memory. The `BitRange` struct likely represents a range of pages.

    * `FillAligned`: This function performs bit manipulation, aligning bits based on a given mask. It looks like a utility function.

    * `TestFillAligned`: This is a unit test for the `FillAligned` function.

    * `TestPallocDataFindScavengeCandidate`:  This test focuses on the `FindScavengeCandidate` method of `PallocData`. It sets up different scenarios of allocated and scavenged memory to verify the candidate selection logic.

    * `TestPageAllocScavenge`: This test seems to be testing the end-to-end scavenging process using a `PageAlloc` type (not directly defined in the snippet but implied).

    * `TestScavenger`: This test appears to simulate and verify the behavior of a central `Scavenger` component, likely responsible for coordinating the scavenging process.

    * `TestScavengeIndex`: This test targets a `ScavengeIndex` data structure, which is likely used to efficiently track and find pages eligible for scavenging.

    * `TestScavChunkDataPack`: This tests the packing and unpacking of `scavChunkData`, which probably stores metadata about scavenged chunks.

    * `FuzzPIController`: This is a fuzz test for a `PIController`, suggesting that the scavenging process or related logic involves some form of proportional-integral control.

3. **Deduce Functionality and Purpose:** Based on the identified components, I can start inferring the broader picture:

    * **Memory Management:** The code deals with managing memory at a page level. `PallocData` represents the allocation state within a "chunk" of pages.
    * **Scavenging:** The core focus is on the scavenging process, which aims to identify and potentially reuse memory that is no longer actively used but hasn't been formally freed. This is a crucial part of garbage collection.
    * **Scavenger Coordination:** The `Scavenger` likely acts as a controller, deciding when and how much memory to scavenge.
    * **Indexing:** `ScavengeIndex` appears to be an optimization for quickly finding scavengeable pages, likely by maintaining some kind of index or bitmap.
    * **Control Theory:** The `PIController` suggests that the scavenging process might be dynamically adjusted based on feedback, aiming for a target state.

4. **Explain Specific Functions and Tests:** Now I can elaborate on each function and test, explaining what they do and how they contribute to verifying the scavenging implementation.

    * `makePallocData`:  A helper to create `PallocData` instances with specific allocation and scavenging states for testing.
    * `FillAligned`:  A bit manipulation utility, potentially used for efficiently updating bitmaps related to allocation. The test exhaustively checks its behavior with various inputs and mask sizes.
    * `TestPallocDataFindScavengeCandidate`:  This is crucial for verifying that the logic for identifying candidate pages for scavenging works correctly under different allocation patterns, including handling edge cases and alignment constraints. The "min" and "max" parameters likely control the minimum and maximum size of the scavenge candidate. The tests cover various scenarios like all free, all scavenged, partially free, and scenarios involving huge pages.
    * `TestPageAllocScavenge`: This test simulates the actual scavenging process on a higher-level `PageAlloc` structure. It sets up different initial allocation and scavenging states and then checks if the `Scavenge` method correctly identifies and returns memory regions for scavenging.
    * `TestScavenger`: This test focuses on the central coordinating component. It simulates work being available and checks if the scavenger wakes up, performs the expected amount of work, and respects stopping conditions, while also trying to meet a target CPU utilization.
    * `TestScavengeIndex`: This test verifies the logic of the `ScavengeIndex`, ensuring it can correctly identify and locate scavengeable pages after they have been marked. The "force" parameter likely bypasses some internal state checks for immediate scavenging.
    * `TestScavChunkDataPack`: This is a simple test to ensure that the packing and unpacking of the `scavChunkData` struct work correctly, preventing data corruption.
    * `FuzzPIController`: This uses fuzzing to test the robustness of the `PIController` under a wide range of random inputs, ensuring it doesn't produce unexpected errors or invalid outputs.

5. **Address Specific Instructions:** Finally, I need to address the requirements of the prompt:

    * **Functionality Listing:**  Summarize the functions' purposes clearly.
    * **Go Feature Identification:**  Conclude that the code implements *memory scavenging* as part of the garbage collection process.
    * **Code Examples:** Provide illustrative examples using the tested functions, including hypothetical inputs and expected outputs where applicable (especially for `FillAligned` and `FindScavengeCandidate`).
    * **Code Reasoning:** Explain the logic of tests where reasoning is involved, such as the different scenarios in `TestPallocDataFindScavengeCandidate`.
    * **Command-Line Arguments:**  Since the code is primarily test code and doesn't directly handle command-line arguments, I'll state that it doesn't involve specific command-line processing.
    * **Common Mistakes:** Analyze the tests for potential pitfalls for users (developers working on the runtime). For example, misunderstanding alignment requirements or the interaction between allocation and scavenging states.
    * **Language:** Ensure the response is in Chinese.

By following these steps, I can generate a comprehensive and accurate explanation of the provided Go code snippet, fulfilling all the requirements of the prompt.
这段代码是 Go 语言运行时（runtime）中 `mgcscavenge_test.go` 文件的一部分，主要用于测试内存垃圾回收器（garbage collector, GC）的**内存回收（scavenging）**功能。

以下是它的一些主要功能：

1. **`makePallocData` 函数:**
   - 功能：创建一个初始化的 `PallocData` 结构体，用于模拟内存页的分配和回收状态。
   - 参数：
     - `alloc`: 一个 `BitRange` 切片，描述了哪些内存页被分配了。
     - `scavenged`: 一个 `BitRange` 切片，描述了哪些内存页被标记为已回收。
   - 返回值：一个指向 `PallocData` 结构体的指针。
   - 作用：方便在测试中创建具有特定分配和回收状态的 `PallocData` 实例。

2. **`TestFillAligned` 函数:**
   - 功能：测试 `FillAligned` 函数的正确性。
   - `FillAligned` 函数（虽然代码中没有直接定义，但被测试了）的功能是根据给定的掩码 `m`，将 `uint64` 类型的输入 `x` 中 set 的位向上对齐到 `m` 的倍数。例如，如果 `m` 是 4，并且 `x` 的某一位被 set，那么从该位开始的连续 4 位都会被 set。
   - 测试用例包括各种边界情况和随机生成的数字，以确保 `FillAligned` 函数在不同情况下都能正确工作。

   ```go
   // 假设 FillAligned 的实现如下
   func FillAligned(x uint64, m uint) uint64 {
       // ... 实现 ...
       return 0
   }

   // 测试用例：
   // 输入 x = 0b000000010010, m = 4
   // 预期输出：0b00000011110000

   // 假设的输入和输出：
   inputX := uint64(0b000000010010)
   inputM := uint(4)
   output := FillAligned(inputX, inputM)
   // 预期 output 的二进制表示为 0b00000011110000
   ```

3. **`TestPallocDataFindScavengeCandidate` 函数:**
   - 功能：测试 `PallocData` 结构体的 `FindScavengeCandidate` 方法。
   - `FindScavengeCandidate` 方法的目的是在 `PallocData` 中找到一个可以被回收的内存页范围。它会考虑已分配和已回收的内存页，以及最小和最大回收页数限制。
   - 测试用例定义了各种不同的分配和回收状态 (`alloc`, `scavenged`)，以及最小 (`min`) 和最大 (`max`) 回收页数，并断言 `FindScavengeCandidate` 返回的回收候选范围 (`want`) 是否符合预期。
   - 涉及到物理大页 (`PhysHugePageSize`) 的测试用例，是为了验证在存在大页的情况下，回收逻辑是否能正确处理，避免打断大页的完整性。

   ```go
   // 假设的 PallocData 和 FindScavengeCandidate 实现
   type PallocData struct {
       // ...
   }
   type BitRange struct {
       I, N uint
   }
   func (b *PallocData) FindScavengeCandidate(limit uintptr, min, max uintptr) (uintptr, uintptr) {
       // ... 实现 ...
       return 0, 0
   }

   // 测试用例 "MixedMin1" 的假设输入和输出：
   allocData := []BitRange{{0, 40}, {42, PallocChunkPages - 42}}
   scavengedData := []BitRange{{0, 41}, {42, PallocChunkPages - 42}}
   minPages := uintptr(1)
   maxPages := uintptr(PallocChunkPages)
   pd := makePallocData(allocData, scavengedData)
   start, size := pd.FindScavengeCandidate(PallocChunkPages-1, minPages, maxPages)
   // 预期 start 为 41，size 为 1，对应 want: BitRange{41, 1}
   ```

4. **`TestPageAllocScavenge` 函数:**
   - 功能：测试更高级别的 `PageAlloc` 结构体的 `Scavenge` 方法。
   - `PageAlloc` 负责管理多个 `PallocData` 实例，代表更大的内存区域。
   - `Scavenge` 方法尝试回收指定数量的内存。
   - 测试用例模拟了不同的初始分配和回收状态，以及不同的回收请求 (`request`)，并验证实际回收的内存量 (`expect`) 是否符合预期，以及回收后的内存状态 (`afterScav`) 是否正确。

5. **`TestScavenger` 函数:**
   - 功能：测试后台的内存回收器 (`Scavenger`) 的行为。
   - `Scavenger` 是一个 Goroutine，周期性地检查并执行内存回收操作。
   - 测试用例模拟了内存回收工作量的变化，并验证 `Scavenger` 能否按照预期的速率执行回收，并在没有工作时进入休眠状态。它还验证了 `Scavenger` 是否能达到预期的 CPU 使用率目标。

6. **`TestScavengeIndex` 函数:**
   - 功能：测试 `ScavengeIndex` 数据结构的正确性。
   - `ScavengeIndex` 用于高效地跟踪哪些内存页可以被回收。它使用位图或其他数据结构来记录内存页的状态。
   - 测试用例涵盖了标记（mark）内存页为可回收和查找（find）可回收内存页的不同场景，包括单页、多页、整个 chunk 以及跨 chunk 的情况。`force` 参数可能用于强制查找，忽略某些内部状态检查。

7. **`TestScavChunkDataPack` 函数:**
   - 功能：测试 `scavChunkData` 结构体的打包和解包操作。
   - `scavChunkData` 可能用于存储关于已回收内存块的元数据，需要进行打包以便存储和传输。

8. **`FuzzPIController` 函数:**
   - 功能：使用模糊测试（fuzzing）来测试 `PIController` 的稳定性。
   - `PIController` 可能是用于控制内存回收的速率或其他参数的比例-积分 (Proportional-Integral) 控制器。
   - 模糊测试通过生成大量的随机输入来查找可能导致崩溃或错误的行为。

**它是什么 Go 语言功能的实现？**

这段代码主要测试 Go 语言运行时中**内存垃圾回收器（GC）的内存回收（scavenging）**功能。 Scavenging 是一种 GC 技术，旨在识别和回收不再使用的内存页，即使这些页可能仍然被标记为已分配。这有助于更有效地利用内存，特别是对于长时间运行的程序。

**Go 代码举例说明:**

虽然这段代码本身是测试代码，但我们可以假设一些使用这些功能的场景。

```go
package main

import (
	"fmt"
	. "runtime"
	"unsafe"
)

func main() {
	// 假设我们有一个 PageAlloc 实例 (实际使用中由 runtime 管理)
	// 并且一些内存已经被分配和标记为可回收

	// 假设我们想手动触发一次回收操作（实际场景中通常由 runtime 自动触发）
	// 尝试回收 10 个页面的大小
	requestedBytes := uintptr(10 * PageSize)
	scavengedBytes := PageAllocScavenge(requestedBytes) // 假设存在这样的一个导出函数用于测试

	fmt.Printf("尝试回收 %d 字节，实际回收了 %d 字节\n", requestedBytes, scavengedBytes)

	// 低级别操作，在用户代码中不常见
	pd := &PallocData{} // 假设我们有一个 PallocData 实例
	pd.AllocRange(0, 5)  // 标记前 5 个页已分配
	pd.ScavengedSetRange(2, 2) // 标记第 3 和第 4 页为已回收

	minPages := uintptr(1)
	maxPages := uintptr(3)
	start, size := pd.FindScavengeCandidate(PallocChunkPages-1, minPages, maxPages)
	fmt.Printf("找到可回收候选：起始页 %d，大小 %d 页\n", start, size)

	// 使用 FillAligned 的示例 (虽然在 GC 内部使用，但可以演示其功能)
	input := uint64(0b000000010010)
	mask := uint(4)
	aligned := FillAligned(input, mask)
	fmt.Printf("填充对齐前：%b，填充对齐后：%b\n", input, aligned)
}

// 模拟 PageAllocScavenge 函数 (实际由 runtime 实现)
func PageAllocScavenge(n uintptr) uintptr {
	// ... 模拟回收逻辑 ...
	fmt.Printf("模拟 PageAlloc 回收 %d 字节\n", n)
	return n // 假设回收了请求的字节数
}

// 模拟 FillAligned 函数 (实际由 runtime 实现)
func FillAligned(x uint64, m uint) uint64 {
	if m == 1 {
		return x
	}
	out := uint64(0)
	for i := uint(0); i < 64; i += m {
		for j := uint(0); j < m; j++ {
			if x&(uint64(1)<<(i+j)) != 0 {
				out |= ((uint64(1) << m) - 1) << i
				break
			}
		}
	}
	return out
}

// 模拟 PallocChunkPages 和 PageSize 常量
const (
	PallocChunkPages = 256
	PageSize         = 8192
)
```

**代码推理 (带假设的输入与输出):**

在 `TestPallocDataFindScavengeCandidate` 中，例如 "MixedMin1" 测试用例：

- **假设输入:**
  - `alloc`: `[]BitRange{{0, 40}, {42, PallocChunkPages - 42}}`  (页 0-39 和 42 到结尾被分配)
  - `scavenged`: `[]BitRange{{0, 41}, {42, PallocChunkPages - 42}}` (页 0-40 和 42 到结尾被标记为已回收)
  - `min`: `1` (至少回收 1 页)
  - `max`: `PallocChunkPages` (最多回收整个 chunk)
- **推理:**  已分配但未被标记为已回收的页是第 40 页。而已标记为已回收但未分配的页是第 41 页。 `FindScavengeCandidate` 的目标是找到可以回收的页。在这个例子中，第 41 页是已回收但未分配的，可以被回收。
- **预期输出:** `BitRange{41, 1}` (起始页 41，回收 1 页)

**命令行参数的具体处理:**

这段代码是测试代码，通常不涉及直接处理命令行参数。Go 语言的测试框架 `testing` 使用 `go test` 命令来运行，可以通过一些标志（flags）来控制测试行为，例如 `-v` (显示详细输出), `-run` (运行特定的测试用例) 等。  这些标志由 `go test` 命令自身处理，而不是由测试代码显式解析。

**使用者易犯错的点:**

作为 Go 运行时的开发者，在使用或修改这些底层的内存管理代码时，容易犯以下错误：

1. **位运算错误:** 在 `FillAligned` 和 `PallocData` 等涉及位图操作的代码中，位运算的逻辑容易出错，导致内存状态跟踪不准确。
   ```go
   // 错误示例：位移方向错误
   x := uint64(1)
   y := x >> 2 // 应该使用 << 来设置位
   ```

2. **边界条件处理不当:** 在 `FindScavengeCandidate` 等函数中，处理内存块的起始和结束边界时容易出现 off-by-one 错误，导致回收范围不正确。
   ```go
   // 错误示例：循环边界错误
   for i := 0; i < length; i++ {
       // ... 可能访问超出数组边界的元素 ...
   }
   ```

3. **并发安全问题:** 内存管理涉及共享状态，在并发访问时需要特别注意同步，避免数据竞争。虽然这段测试代码本身是单线程的，但在实际的运行时环境中，并发问题是一个重要的考虑因素。

4. **对齐假设错误:** 在内存管理中，对齐是非常重要的。如果对齐假设不正确，可能会导致内存访问错误或性能下降。例如，`FillAligned` 函数的正确性依赖于对齐的理解。

5. **物理内存和虚拟内存的混淆:** 理解物理内存和虚拟内存的区别对于理解内存回收至关重要。错误的假设可能导致回收策略不当。

这段测试代码通过大量的单元测试和模糊测试，力求覆盖各种场景和边界情况，以确保 Go 语言运行时的内存回收功能能够稳定可靠地运行。

### 提示词
```
这是路径为go/src/runtime/mgcscavenge_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"internal/goos"
	"internal/runtime/atomic"
	"math"
	"math/rand"
	. "runtime"
	"testing"
	"time"
)

// makePallocData produces an initialized PallocData by setting
// the ranges of described in alloc and scavenge.
func makePallocData(alloc, scavenged []BitRange) *PallocData {
	b := new(PallocData)
	for _, v := range alloc {
		if v.N == 0 {
			// Skip N==0. It's harmless and allocRange doesn't
			// handle this case.
			continue
		}
		b.AllocRange(v.I, v.N)
	}
	for _, v := range scavenged {
		if v.N == 0 {
			// See the previous loop.
			continue
		}
		b.ScavengedSetRange(v.I, v.N)
	}
	return b
}

func TestFillAligned(t *testing.T) {
	fillAlignedSlow := func(x uint64, m uint) uint64 {
		if m == 1 {
			return x
		}
		out := uint64(0)
		for i := uint(0); i < 64; i += m {
			for j := uint(0); j < m; j++ {
				if x&(uint64(1)<<(i+j)) != 0 {
					out |= ((uint64(1) << m) - 1) << i
					break
				}
			}
		}
		return out
	}
	check := func(x uint64, m uint) {
		want := fillAlignedSlow(x, m)
		if got := FillAligned(x, m); got != want {
			t.Logf("got:  %064b", got)
			t.Logf("want: %064b", want)
			t.Errorf("bad fillAligned(%016x, %d)", x, m)
		}
	}
	for m := uint(1); m <= 64; m *= 2 {
		tests := []uint64{
			0x0000000000000000,
			0x00000000ffffffff,
			0xffffffff00000000,
			0x8000000000000001,
			0xf00000000000000f,
			0xf00000010050000f,
			0xffffffffffffffff,
			0x0000000000000001,
			0x0000000000000002,
			0x0000000000000008,
			uint64(1) << (m - 1),
			uint64(1) << m,
			// Try a few fixed arbitrary examples.
			0xb02b9effcf137016,
			0x3975a076a9fbff18,
			0x0f8c88ec3b81506e,
			0x60f14d80ef2fa0e6,
		}
		for _, test := range tests {
			check(test, m)
		}
		for i := 0; i < 1000; i++ {
			// Try a pseudo-random numbers.
			check(rand.Uint64(), m)

			if m > 1 {
				// For m != 1, let's construct a slightly more interesting
				// random test. Generate a bitmap which is either 0 or
				// randomly set bits for each m-aligned group of m bits.
				val := uint64(0)
				for n := uint(0); n < 64; n += m {
					// For each group of m bits, flip a coin:
					// * Leave them as zero.
					// * Set them randomly.
					if rand.Uint64()%2 == 0 {
						val |= (rand.Uint64() & ((1 << m) - 1)) << n
					}
				}
				check(val, m)
			}
		}
	}
}

func TestPallocDataFindScavengeCandidate(t *testing.T) {
	type test struct {
		alloc, scavenged []BitRange
		min, max         uintptr
		want             BitRange
	}
	tests := map[string]test{
		"MixedMin1": {
			alloc:     []BitRange{{0, 40}, {42, PallocChunkPages - 42}},
			scavenged: []BitRange{{0, 41}, {42, PallocChunkPages - 42}},
			min:       1,
			max:       PallocChunkPages,
			want:      BitRange{41, 1},
		},
		"MultiMin1": {
			alloc:     []BitRange{{0, 63}, {65, 20}, {87, PallocChunkPages - 87}},
			scavenged: []BitRange{{86, 1}},
			min:       1,
			max:       PallocChunkPages,
			want:      BitRange{85, 1},
		},
	}
	// Try out different page minimums.
	for m := uintptr(1); m <= 64; m *= 2 {
		suffix := fmt.Sprintf("Min%d", m)
		tests["AllFree"+suffix] = test{
			min:  m,
			max:  PallocChunkPages,
			want: BitRange{0, PallocChunkPages},
		}
		tests["AllScavenged"+suffix] = test{
			scavenged: []BitRange{{0, PallocChunkPages}},
			min:       m,
			max:       PallocChunkPages,
			want:      BitRange{0, 0},
		}
		tests["NoneFree"+suffix] = test{
			alloc:     []BitRange{{0, PallocChunkPages}},
			scavenged: []BitRange{{PallocChunkPages / 2, PallocChunkPages / 2}},
			min:       m,
			max:       PallocChunkPages,
			want:      BitRange{0, 0},
		}
		tests["StartFree"+suffix] = test{
			alloc: []BitRange{{uint(m), PallocChunkPages - uint(m)}},
			min:   m,
			max:   PallocChunkPages,
			want:  BitRange{0, uint(m)},
		}
		tests["EndFree"+suffix] = test{
			alloc: []BitRange{{0, PallocChunkPages - uint(m)}},
			min:   m,
			max:   PallocChunkPages,
			want:  BitRange{PallocChunkPages - uint(m), uint(m)},
		}
		tests["Straddle64"+suffix] = test{
			alloc: []BitRange{{0, 64 - uint(m)}, {64 + uint(m), PallocChunkPages - (64 + uint(m))}},
			min:   m,
			max:   2 * m,
			want:  BitRange{64 - uint(m), 2 * uint(m)},
		}
		tests["BottomEdge64WithFull"+suffix] = test{
			alloc:     []BitRange{{64, 64}, {128 + 3*uint(m), PallocChunkPages - (128 + 3*uint(m))}},
			scavenged: []BitRange{{1, 10}},
			min:       m,
			max:       3 * m,
			want:      BitRange{128, 3 * uint(m)},
		}
		tests["BottomEdge64WithPocket"+suffix] = test{
			alloc:     []BitRange{{64, 62}, {127, 1}, {128 + 3*uint(m), PallocChunkPages - (128 + 3*uint(m))}},
			scavenged: []BitRange{{1, 10}},
			min:       m,
			max:       3 * m,
			want:      BitRange{128, 3 * uint(m)},
		}
		tests["Max0"+suffix] = test{
			scavenged: []BitRange{{0, PallocChunkPages - uint(m)}},
			min:       m,
			max:       0,
			want:      BitRange{PallocChunkPages - uint(m), uint(m)},
		}
		if m <= 8 {
			tests["OneFree"] = test{
				alloc: []BitRange{{0, 40}, {40 + uint(m), PallocChunkPages - (40 + uint(m))}},
				min:   m,
				max:   PallocChunkPages,
				want:  BitRange{40, uint(m)},
			}
			tests["OneScavenged"] = test{
				alloc:     []BitRange{{0, 40}, {40 + uint(m), PallocChunkPages - (40 + uint(m))}},
				scavenged: []BitRange{{40, 1}},
				min:       m,
				max:       PallocChunkPages,
				want:      BitRange{0, 0},
			}
		}
		if m > 1 {
			tests["MaxUnaligned"+suffix] = test{
				scavenged: []BitRange{{0, PallocChunkPages - uint(m*2-1)}},
				min:       m,
				max:       m - 2,
				want:      BitRange{PallocChunkPages - uint(m), uint(m)},
			}
			tests["SkipSmall"+suffix] = test{
				alloc: []BitRange{{0, 64 - uint(m)}, {64, 5}, {70, 11}, {82, PallocChunkPages - 82}},
				min:   m,
				max:   m,
				want:  BitRange{64 - uint(m), uint(m)},
			}
			tests["SkipMisaligned"+suffix] = test{
				alloc: []BitRange{{0, 64 - uint(m)}, {64, 63}, {127 + uint(m), PallocChunkPages - (127 + uint(m))}},
				min:   m,
				max:   m,
				want:  BitRange{64 - uint(m), uint(m)},
			}
			tests["MaxLessThan"+suffix] = test{
				scavenged: []BitRange{{0, PallocChunkPages - uint(m)}},
				min:       m,
				max:       1,
				want:      BitRange{PallocChunkPages - uint(m), uint(m)},
			}
		}
	}
	if PhysHugePageSize > uintptr(PageSize) {
		// Check hugepage preserving behavior.
		bits := uint(PhysHugePageSize / uintptr(PageSize))
		if bits < PallocChunkPages {
			tests["PreserveHugePageBottom"] = test{
				alloc: []BitRange{{bits + 2, PallocChunkPages - (bits + 2)}},
				min:   1,
				max:   3, // Make it so that max would have us try to break the huge page.
				want:  BitRange{0, bits + 2},
			}
			if 3*bits < PallocChunkPages {
				// We need at least 3 huge pages in a chunk for this test to make sense.
				tests["PreserveHugePageMiddle"] = test{
					alloc: []BitRange{{0, bits - 10}, {2*bits + 10, PallocChunkPages - (2*bits + 10)}},
					min:   1,
					max:   12, // Make it so that max would have us try to break the huge page.
					want:  BitRange{bits, bits + 10},
				}
			}
			tests["PreserveHugePageTop"] = test{
				alloc: []BitRange{{0, PallocChunkPages - bits}},
				min:   1,
				max:   1, // Even one page would break a huge page in this case.
				want:  BitRange{PallocChunkPages - bits, bits},
			}
		} else if bits == PallocChunkPages {
			tests["PreserveHugePageAll"] = test{
				min:  1,
				max:  1, // Even one page would break a huge page in this case.
				want: BitRange{0, PallocChunkPages},
			}
		} else {
			// The huge page size is greater than pallocChunkPages, so it should
			// be effectively disabled. There's no way we can possible scavenge
			// a huge page out of this bitmap chunk.
			tests["PreserveHugePageNone"] = test{
				min:  1,
				max:  1,
				want: BitRange{PallocChunkPages - 1, 1},
			}
		}
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := makePallocData(v.alloc, v.scavenged)
			start, size := b.FindScavengeCandidate(PallocChunkPages-1, v.min, v.max)
			got := BitRange{start, size}
			if !(got.N == 0 && v.want.N == 0) && got != v.want {
				t.Fatalf("candidate mismatch: got %v, want %v", got, v.want)
			}
		})
	}
}

// Tests end-to-end scavenging on a pageAlloc.
func TestPageAllocScavenge(t *testing.T) {
	if GOOS == "openbsd" && testing.Short() {
		t.Skip("skipping because virtual memory is limited; see #36210")
	}
	type test struct {
		request, expect uintptr
	}
	minPages := PhysPageSize / PageSize
	if minPages < 1 {
		minPages = 1
	}
	type setup struct {
		beforeAlloc map[ChunkIdx][]BitRange
		beforeScav  map[ChunkIdx][]BitRange
		expect      []test
		afterScav   map[ChunkIdx][]BitRange
	}
	tests := map[string]setup{
		"AllFreeUnscavExhaust": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {},
			},
			expect: []test{
				{^uintptr(0), 3 * PallocChunkPages * PageSize},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
		},
		"NoneFreeUnscavExhaust": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {},
				BaseChunkIdx + 2: {{0, PallocChunkPages}},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {},
			},
			expect: []test{
				{^uintptr(0), 0},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
				BaseChunkIdx + 2: {},
			},
		},
		"ScavHighestPageFirst": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{uint(minPages), PallocChunkPages - uint(2*minPages)}},
			},
			expect: []test{
				{1, minPages * PageSize},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{uint(minPages), PallocChunkPages - uint(minPages)}},
			},
		},
		"ScavMultiple": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{uint(minPages), PallocChunkPages - uint(2*minPages)}},
			},
			expect: []test{
				{minPages * PageSize, minPages * PageSize},
				{minPages * PageSize, minPages * PageSize},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx: {{0, PallocChunkPages}},
			},
		},
		"ScavMultiple2": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {},
				BaseChunkIdx + 1: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{uint(minPages), PallocChunkPages - uint(2*minPages)}},
				BaseChunkIdx + 1: {{0, PallocChunkPages - uint(2*minPages)}},
			},
			expect: []test{
				{2 * minPages * PageSize, 2 * minPages * PageSize},
				{minPages * PageSize, minPages * PageSize},
				{minPages * PageSize, minPages * PageSize},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:     {{0, PallocChunkPages}},
				BaseChunkIdx + 1: {{0, PallocChunkPages}},
			},
		},
		"ScavDiscontiguous": {
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:       {},
				BaseChunkIdx + 0xe: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:       {{uint(minPages), PallocChunkPages - uint(2*minPages)}},
				BaseChunkIdx + 0xe: {{uint(2 * minPages), PallocChunkPages - uint(2*minPages)}},
			},
			expect: []test{
				{2 * minPages * PageSize, 2 * minPages * PageSize},
				{^uintptr(0), 2 * minPages * PageSize},
				{^uintptr(0), 0},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:       {{0, PallocChunkPages}},
				BaseChunkIdx + 0xe: {{0, PallocChunkPages}},
			},
		},
	}
	// Disable these tests on iOS since we have a small address space.
	// See #46860.
	if PageAlloc64Bit != 0 && goos.IsIos == 0 {
		tests["ScavAllVeryDiscontiguous"] = setup{
			beforeAlloc: map[ChunkIdx][]BitRange{
				BaseChunkIdx:          {},
				BaseChunkIdx + 0x1000: {},
			},
			beforeScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:          {},
				BaseChunkIdx + 0x1000: {},
			},
			expect: []test{
				{^uintptr(0), 2 * PallocChunkPages * PageSize},
				{^uintptr(0), 0},
			},
			afterScav: map[ChunkIdx][]BitRange{
				BaseChunkIdx:          {{0, PallocChunkPages}},
				BaseChunkIdx + 0x1000: {{0, PallocChunkPages}},
			},
		}
	}
	for name, v := range tests {
		v := v
		t.Run(name, func(t *testing.T) {
			b := NewPageAlloc(v.beforeAlloc, v.beforeScav)
			defer FreePageAlloc(b)

			for iter, h := range v.expect {
				if got := b.Scavenge(h.request); got != h.expect {
					t.Fatalf("bad scavenge #%d: want %d, got %d", iter+1, h.expect, got)
				}
			}
			want := NewPageAlloc(v.beforeAlloc, v.afterScav)
			defer FreePageAlloc(want)

			checkPageAlloc(t, want, b)
		})
	}
}

func TestScavenger(t *testing.T) {
	// workedTime is a standard conversion of bytes of scavenge
	// work to time elapsed.
	workedTime := func(bytes uintptr) int64 {
		return int64((bytes+4095)/4096) * int64(10*time.Microsecond)
	}

	// Set up a bunch of state that we're going to track and verify
	// throughout the test.
	totalWork := uint64(64<<20 - 3*PhysPageSize)
	var totalSlept, totalWorked atomic.Int64
	var availableWork atomic.Uint64
	var stopAt atomic.Uint64 // How much available work to stop at.

	// Set up the scavenger.
	var s Scavenger
	s.Sleep = func(ns int64) int64 {
		totalSlept.Add(ns)
		return ns
	}
	s.Scavenge = func(bytes uintptr) (uintptr, int64) {
		avail := availableWork.Load()
		if uint64(bytes) > avail {
			bytes = uintptr(avail)
		}
		t := workedTime(bytes)
		if bytes != 0 {
			availableWork.Add(-int64(bytes))
			totalWorked.Add(t)
		}
		return bytes, t
	}
	s.ShouldStop = func() bool {
		if availableWork.Load() <= stopAt.Load() {
			return true
		}
		return false
	}
	s.GoMaxProcs = func() int32 {
		return 1
	}

	// Define a helper for verifying that various properties hold.
	verifyScavengerState := func(t *testing.T, expWork uint64) {
		t.Helper()

		// Check to make sure it did the amount of work we expected.
		if workDone := uint64(s.Released()); workDone != expWork {
			t.Errorf("want %d bytes of work done, got %d", expWork, workDone)
		}
		// Check to make sure the scavenger is meeting its CPU target.
		idealFraction := float64(ScavengePercent) / 100.0
		cpuFraction := float64(totalWorked.Load()) / float64(totalWorked.Load()+totalSlept.Load())
		if cpuFraction < idealFraction-0.005 || cpuFraction > idealFraction+0.005 {
			t.Errorf("want %f CPU fraction, got %f", idealFraction, cpuFraction)
		}
	}

	// Start the scavenger.
	s.Start()

	// Set up some work and let the scavenger run to completion.
	availableWork.Store(totalWork)
	s.Wake()
	if !s.BlockUntilParked(2e9 /* 2 seconds */) {
		t.Fatal("timed out waiting for scavenger to run to completion")
	}
	// Run a check.
	verifyScavengerState(t, totalWork)

	// Now let's do it again and see what happens when we have no work to do.
	// It should've gone right back to sleep.
	s.Wake()
	if !s.BlockUntilParked(2e9 /* 2 seconds */) {
		t.Fatal("timed out waiting for scavenger to run to completion")
	}
	// Run another check.
	verifyScavengerState(t, totalWork)

	// One more time, this time doing the same amount of work as the first time.
	// Let's see if we can get the scavenger to continue.
	availableWork.Store(totalWork)
	s.Wake()
	if !s.BlockUntilParked(2e9 /* 2 seconds */) {
		t.Fatal("timed out waiting for scavenger to run to completion")
	}
	// Run another check.
	verifyScavengerState(t, 2*totalWork)

	// This time, let's stop after a certain amount of work.
	//
	// Pick a stopping point such that when subtracted from totalWork
	// we get a multiple of a relatively large power of 2. verifyScavengerState
	// always makes an exact check, but the scavenger might go a little over,
	// which is OK. If this breaks often or gets annoying to maintain, modify
	// verifyScavengerState.
	availableWork.Store(totalWork)
	stoppingPoint := uint64(1<<20 - 3*PhysPageSize)
	stopAt.Store(stoppingPoint)
	s.Wake()
	if !s.BlockUntilParked(2e9 /* 2 seconds */) {
		t.Fatal("timed out waiting for scavenger to run to completion")
	}
	// Run another check.
	verifyScavengerState(t, 2*totalWork+(totalWork-stoppingPoint))

	// Clean up.
	s.Stop()
}

func TestScavengeIndex(t *testing.T) {
	// This test suite tests the scavengeIndex data structure.

	// markFunc is a function that makes the address range [base, limit)
	// available for scavenging in a test index.
	type markFunc func(base, limit uintptr)

	// findFunc is a function that searches for the next available page
	// to scavenge in the index. It asserts that the page is found in
	// chunk "ci" at page "offset."
	type findFunc func(ci ChunkIdx, offset uint)

	// The structure of the tests below is as follows:
	//
	// setup creates a fake scavengeIndex that can be mutated and queried by
	// the functions it returns. Those functions capture the testing.T that
	// setup is called with, so they're bound to the subtest they're created in.
	//
	// Tests are then organized into test cases which mark some pages as
	// scavenge-able then try to find them. Tests expect that the initial
	// state of the scavengeIndex has all of the chunks as dense in the last
	// generation and empty to the scavenger.
	//
	// There are a few additional tests that interleave mark and find operations,
	// so they're defined separately, but use the same infrastructure.
	setup := func(t *testing.T, force bool) (mark markFunc, find findFunc, nextGen func()) {
		t.Helper()

		// Pick some reasonable bounds. We don't need a huge range just to test.
		si := NewScavengeIndex(BaseChunkIdx, BaseChunkIdx+64)

		// Initialize all the chunks as dense and empty.
		//
		// Also, reset search addresses so that we can get page offsets.
		si.AllocRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+64, 0))
		si.NextGen()
		si.FreeRange(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+64, 0))
		for ci := BaseChunkIdx; ci < BaseChunkIdx+64; ci++ {
			si.SetEmpty(ci)
		}
		si.ResetSearchAddrs()

		// Create and return test functions.
		mark = func(base, limit uintptr) {
			t.Helper()

			si.AllocRange(base, limit)
			si.FreeRange(base, limit)
		}
		find = func(want ChunkIdx, wantOffset uint) {
			t.Helper()

			got, gotOffset := si.Find(force)
			if want != got {
				t.Errorf("find: wanted chunk index %d, got %d", want, got)
			}
			if wantOffset != gotOffset {
				t.Errorf("find: wanted page offset %d, got %d", wantOffset, gotOffset)
			}
			if t.Failed() {
				t.FailNow()
			}
			si.SetEmpty(got)
		}
		nextGen = func() {
			t.Helper()

			si.NextGen()
		}
		return
	}

	// Each of these test cases calls mark and then find once.
	type testCase struct {
		name string
		mark func(markFunc)
		find func(findFunc)
	}
	for _, test := range []testCase{
		{
			name: "Uninitialized",
			mark: func(_ markFunc) {},
			find: func(_ findFunc) {},
		},
		{
			name: "OnePage",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 3), PageBase(BaseChunkIdx, 4))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx, 3)
			},
		},
		{
			name: "FirstPage",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx, 1))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx, 0)
			},
		},
		{
			name: "SeveralPages",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 9), PageBase(BaseChunkIdx, 14))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx, 13)
			},
		},
		{
			name: "WholeChunk",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx, PallocChunkPages-1)
			},
		},
		{
			name: "LastPage",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, PallocChunkPages-1), PageBase(BaseChunkIdx+1, 0))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx, PallocChunkPages-1)
			},
		},
		{
			name: "TwoChunks",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 128), PageBase(BaseChunkIdx+1, 128))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx+1, 127)
				find(BaseChunkIdx, PallocChunkPages-1)
			},
		},
		{
			name: "TwoChunksOffset",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx+7, 128), PageBase(BaseChunkIdx+8, 129))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx+8, 128)
				find(BaseChunkIdx+7, PallocChunkPages-1)
			},
		},
		{
			name: "SevenChunksOffset",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx+6, 11), PageBase(BaseChunkIdx+13, 15))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx+13, 14)
				for i := BaseChunkIdx + 12; i >= BaseChunkIdx+6; i-- {
					find(i, PallocChunkPages-1)
				}
			},
		},
		{
			name: "ThirtyTwoChunks",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+32, 0))
			},
			find: func(find findFunc) {
				for i := BaseChunkIdx + 31; i >= BaseChunkIdx; i-- {
					find(i, PallocChunkPages-1)
				}
			},
		},
		{
			name: "ThirtyTwoChunksOffset",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx+3, 0), PageBase(BaseChunkIdx+35, 0))
			},
			find: func(find findFunc) {
				for i := BaseChunkIdx + 34; i >= BaseChunkIdx+3; i-- {
					find(i, PallocChunkPages-1)
				}
			},
		},
		{
			name: "Mark",
			mark: func(mark markFunc) {
				for i := BaseChunkIdx; i < BaseChunkIdx+32; i++ {
					mark(PageBase(i, 0), PageBase(i+1, 0))
				}
			},
			find: func(find findFunc) {
				for i := BaseChunkIdx + 31; i >= BaseChunkIdx; i-- {
					find(i, PallocChunkPages-1)
				}
			},
		},
		{
			name: "MarkIdempotentOneChunk",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0))
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+1, 0))
			},
			find: func(find findFunc) {
				find(BaseChunkIdx, PallocChunkPages-1)
			},
		},
		{
			name: "MarkIdempotentThirtyTwoChunks",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+32, 0))
				mark(PageBase(BaseChunkIdx, 0), PageBase(BaseChunkIdx+32, 0))
			},
			find: func(find findFunc) {
				for i := BaseChunkIdx + 31; i >= BaseChunkIdx; i-- {
					find(i, PallocChunkPages-1)
				}
			},
		},
		{
			name: "MarkIdempotentThirtyTwoChunksOffset",
			mark: func(mark markFunc) {
				mark(PageBase(BaseChunkIdx+4, 0), PageBase(BaseChunkIdx+31, 0))
				mark(PageBase(BaseChunkIdx+5, 0), PageBase(BaseChunkIdx+36, 0))
			},
			find: func(find findFunc) {
				for i := BaseChunkIdx + 35; i >= BaseChunkIdx+4; i-- {
					find(i, PallocChunkPages-1)
				}
			},
		},
	} {
		test := test
		t.Run("Bg/"+test.name, func(t *testing.T) {
			mark, find, nextGen := setup(t, false)
			test.mark(mark)
			find(0, 0)      // Make sure we find nothing at this point.
			nextGen()       // Move to the next generation.
			test.find(find) // Now we should be able to find things.
			find(0, 0)      // The test should always fully exhaust the index.
		})
		t.Run("Force/"+test.name, func(t *testing.T) {
			mark, find, _ := setup(t, true)
			test.mark(mark)
			test.find(find) // Finding should always work when forced.
			find(0, 0)      // The test should always fully exhaust the index.
		})
	}
	t.Run("Bg/MarkInterleaved", func(t *testing.T) {
		mark, find, nextGen := setup(t, false)
		for i := BaseChunkIdx; i < BaseChunkIdx+32; i++ {
			mark(PageBase(i, 0), PageBase(i+1, 0))
			nextGen()
			find(i, PallocChunkPages-1)
		}
		find(0, 0)
	})
	t.Run("Force/MarkInterleaved", func(t *testing.T) {
		mark, find, _ := setup(t, true)
		for i := BaseChunkIdx; i < BaseChunkIdx+32; i++ {
			mark(PageBase(i, 0), PageBase(i+1, 0))
			find(i, PallocChunkPages-1)
		}
		find(0, 0)
	})
}

func TestScavChunkDataPack(t *testing.T) {
	if !CheckPackScavChunkData(1918237402, 512, 512, 0b11) {
		t.Error("failed pack/unpack check for scavChunkData 1")
	}
	if !CheckPackScavChunkData(^uint32(0), 12, 0, 0b00) {
		t.Error("failed pack/unpack check for scavChunkData 2")
	}
}

func FuzzPIController(f *testing.F) {
	isNormal := func(x float64) bool {
		return !math.IsInf(x, 0) && !math.IsNaN(x)
	}
	isPositive := func(x float64) bool {
		return isNormal(x) && x > 0
	}
	// Seed with constants from controllers in the runtime.
	// It's not critical that we keep these in sync, they're just
	// reasonable seed inputs.
	f.Add(0.3375, 3.2e6, 1e9, 0.001, 1000.0, 0.01)
	f.Add(0.9, 4.0, 1000.0, -1000.0, 1000.0, 0.84)
	f.Fuzz(func(t *testing.T, kp, ti, tt, min, max, setPoint float64) {
		// Ignore uninteresting invalid parameters. These parameters
		// are constant, so in practice surprising values will be documented
		// or will be other otherwise immediately visible.
		//
		// We just want to make sure that given a non-Inf, non-NaN input,
		// we always get a non-Inf, non-NaN output.
		if !isPositive(kp) || !isPositive(ti) || !isPositive(tt) {
			return
		}
		if !isNormal(min) || !isNormal(max) || min > max {
			return
		}
		// Use a random source, but make it deterministic.
		rs := rand.New(rand.NewSource(800))
		randFloat64 := func() float64 {
			return math.Float64frombits(rs.Uint64())
		}
		p := NewPIController(kp, ti, tt, min, max)
		state := float64(0)
		for i := 0; i < 100; i++ {
			input := randFloat64()
			// Ignore the "ok" parameter. We're just trying to break it.
			// state is intentionally completely uncorrelated with the input.
			var ok bool
			state, ok = p.Next(input, setPoint, 1.0)
			if !isNormal(state) {
				t.Fatalf("got NaN or Inf result from controller: %f %v", state, ok)
			}
		}
	})
}
```