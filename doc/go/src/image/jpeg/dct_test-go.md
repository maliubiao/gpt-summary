Response:
Let's break down the thought process for analyzing this Go test file.

1. **Identify the Core Purpose:** The file name `dct_test.go` immediately suggests it's testing something related to Discrete Cosine Transform (DCT). The package declaration `package jpeg` further clarifies that this is within the JPEG image processing library in Go's standard library.

2. **Scan for Key Functions:** Look for function definitions, especially those starting with `Test` and `Benchmark`. This provides immediate clues about the testing and performance aspects. We see `TestDCT`, `BenchmarkFDCT`, and `BenchmarkIDCT`. This confirms the focus on testing the DCT and its inverse (IDCT).

3. **Understand `TestDCT`:**
    * **Initialization:** The test initializes with `testBlocks` and then generates more random blocks. This suggests testing with both predefined and diverse input.
    * **Core Logic (Inverses):** The main loop performs FDCT and IDCT on the `got` block and compares it to the original `want`. Crucially, it includes scaling (`* 8`) and level shifting (`- 128`, `+ 128`) before and after the transforms. This hints at how the DCT is implemented for JPEG, where pixel values are often shifted to be centered around zero. The comparison uses a tolerance (`differ`) of 2, indicating that exact equality isn't expected due to floating-point rounding.
    * **Optimized vs. Slow:** The test then compares the optimized `fdct` and `idct` functions with their "slow" counterparts (`slowFDCT`, `slowIDCT`). This strongly implies there are two implementations, likely for performance reasons.

4. **Understand Benchmarks:** `BenchmarkFDCT` and `BenchmarkIDCT` are straightforward. They measure the execution time of the `fdct` and `idct` functions, respectively. The `benchmarkDCT` helper function likely handles common setup for these benchmarks.

5. **Analyze Helper Functions:**
    * **`differ`:**  This function clarifies the tolerance used in comparisons, explaining that minor differences are acceptable due to IDCT rounding errors. This is a crucial detail for understanding the nature of DCT and its implementations.
    * **`alpha`:** This function implements a scaling factor used in the DCT formula. The comment clearly states its purpose.
    * **`slowFDCT` and `slowIDCT`:** These functions contain the explicit mathematical formulas for the forward and inverse DCT. The comments directly transcribe the standard DCT equations. This reinforces the purpose of the test file.
    * **`String` on `block`:** This provides a way to print the contents of a `block` for debugging, as seen in the `t.Errorf` messages.

6. **Examine Data Structures:** The `block` type (though not explicitly defined in this snippet) is clearly an array or slice of some kind, likely representing an 8x8 block of pixel or coefficient data. The `testBlocks` variable provides concrete examples of pre-DCT blocks.

7. **Infer Go Features:**
    * **Testing:** The `testing` package is used extensively for unit tests and benchmarks.
    * **Slices and Arrays:** The `block` type and the way blocks are created and manipulated point to the use of slices and arrays.
    * **Functions as First-Class Citizens:** The `benchmarkDCT` function takes a function as an argument (`f func(*block)`).
    * **Floating-Point Math:** The use of `math.Sqrt2` and the `cosines` array indicates floating-point calculations.
    * **Formatted Output:** `fmt.Sprintf` is used for creating error messages.

8. **Code Example Construction:** Based on the analysis, we can construct a simple example demonstrating the FDCT and IDCT. We'd need to:
    * Define the `block` type (assuming `[64]int32`).
    * Include the `fdct` and `idct` functions (though the snippet doesn't provide their *optimized* implementations, we can infer their behavior from the tests and the `slow` versions).
    * Create a sample `block`, apply FDCT, then IDCT, and print the results.

9. **Command-Line Arguments (Not Applicable):**  This file is for testing, not a standalone executable, so command-line arguments aren't relevant.

10. **Common Mistakes:** The tolerance in `differ` suggests a potential pitfall: expecting exact equality when comparing DCT results. Also, the scaling and level shifting are important steps that might be missed if someone tries to implement DCT without understanding the specifics of this implementation.

11. **Structure the Answer:** Organize the findings into logical sections like "功能", "实现的Go语言功能", "代码举例", etc., as requested in the prompt. Provide clear explanations and code examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the file tests different DCT algorithms.
* **Correction:** The comparison with `slowFDCT` and `slowIDCT` suggests there's an optimized version being tested against a simpler, likely mathematically correct, but potentially slower version.
* **Initial thought:** The `block` type is just an array of integers.
* **Refinement:** The scaling and shifting suggest the integers likely represent pixel values *before* DCT, and the DCT transforms them into frequency domain coefficients, which can also be represented as integers after quantization. The values in `testBlocks` also support this.
* **Realization:** The `cosines` array pre-calculates cosine values to potentially improve performance.

By following this detailed analysis, we can comprehensively understand the purpose and functionality of the provided Go test file.
这个go语言源文件 `go/src/image/jpeg/dct_test.go` 的主要功能是**测试 JPEG 编解码过程中使用的离散余弦变换 (Discrete Cosine Transform, DCT) 及其逆变换 (Inverse Discrete Cosine Transform, IDCT)**。

具体来说，它包含了以下几个方面的功能：

1. **基准测试 (Benchmarks)：**
   - `BenchmarkFDCT(b *testing.B)`:  对前向离散余弦变换 (FDCT) 函数 `fdct` 进行性能基准测试。它可以测量在给定数量的迭代中，`fdct` 函数的平均执行时间。
   - `BenchmarkIDCT(b *testing.B)`: 对反向离散余弦变换 (IDCT) 函数 `idct` 进行性能基准测试。它可以测量在给定数量的迭代中，`idct` 函数的平均执行时间。
   - `benchmarkDCT(b *testing.B, f func(*block))`:  这是一个辅助函数，用于执行 DCT 相关的基准测试。它接收一个 `testing.B` 对象和一个执行 DCT 操作的函数 `f` 作为参数，并负责设置测试数据和计时。

2. **单元测试 (Unit Tests)：**
   - `TestDCT(t *testing.T)`: 这是主要的单元测试函数，用于验证 FDCT 和 IDCT 函数的正确性。它包含了多个测试用例：
     - **验证 FDCT 和 IDCT 互为逆运算：**  对于一组预定义的测试块 (`testBlocks`) 和随机生成的块，先对块进行预处理（减去 128 并乘以 8），然后应用 `slowFDCT` 和 `slowIDCT` 函数，最后再进行反向处理（除以 8 并加上 128）。它会比较经过变换和逆变换后的结果与原始块是否在容差范围内 (`differ` 函数)。
     - **验证优化后的 FDCT 实现与慢速实现的一致性：**  它比较 `fdct` 函数（可能是优化后的实现）和 `slowFDCT` 函数（一个更直接的、可能更慢的实现）在相同输入下的输出是否一致。同样，它也会进行必要的预处理。
     - **验证优化后的 IDCT 实现与慢速实现的一致性：** 它比较 `idct` 函数和 `slowIDCT` 函数在相同输入下的输出是否一致。

3. **辅助函数：**
   - `differ(b0, b1 *block) bool`:  用于比较两个 `block` 是否在容差范围内不同。由于 JPEG 解码存在一定的精度损失，因此不是要求完全相等，而是允许一定的误差 (差值小于 2)。
   - `alpha(i int) float64`:  这是一个计算 DCT 公式中缩放因子的辅助函数。
   - `slowFDCT(b *block)`:  一个“慢速”的 FDCT 实现，其代码直接对应了二维离散余弦变换的数学公式。这通常用于与优化后的 `fdct` 函数进行比较，以验证其正确性。
   - `slowIDCT(b *block)`: 一个“慢速”的 IDCT 实现，其代码直接对应了二维反向离散余弦变换的数学公式。
   - `(b *block) String() string`:  为 `block` 类型定义了一个 `String()` 方法，用于方便地格式化输出 `block` 的内容，主要用于调试信息。

4. **测试数据：**
   - `testBlocks [10]block`:  一个包含 10 个 `block` 类型的数组，用于作为测试 `DCT` 函数的输入数据。这些数据是从实际的 JPEG 文件中提取出来的。

**可以推理出它是什么go语言功能的实现：**

根据代码中的函数名和逻辑，可以推断出 `fdct` 和 `idct` 函数是实现了 JPEG 压缩标准中关键的离散余弦变换和反离散余弦变换。这两个变换是将图像数据从像素域转换到频率域，以及从频率域转换回像素域的核心步骤。

**用go代码举例说明：**

假设 `block` 类型是一个包含 64 个 `int32` 元素的数组，代表一个 8x8 的像素块。

```go
package main

import (
	"fmt"
	"image/jpeg" // 假设 fdct 和 idct 在 jpeg 包中
)

func main() {
	// 假设我们有一个 8x8 的像素块
	initialBlock := jpeg.Block{
		// ... 填充 64 个 int32 值 ...
		100, 110, 120, 130, 140, 150, 160, 170,
		105, 115, 125, 135, 145, 155, 165, 175,
		// ... 更多像素值 ...
	}

	fmt.Println("原始块:")
	fmt.Println(initialBlock.String())

	// 执行前向 DCT
	dctBlock := initialBlock
	jpeg.Fdct(&dctBlock) // 假设 Fdct 是优化后的 FDCT 函数

	fmt.Println("\nDCT 变换后的块:")
	fmt.Println(dctBlock.String())

	// 执行反向 DCT
	idctBlock := dctBlock
	jpeg.Idct(&idctBlock) // 假设 Idct 是优化后的 IDCT 函数

	fmt.Println("\nIDCT 变换后的块:")
	fmt.Println(idctBlock.String())

	// 注意：由于精度损失，idctBlock 可能与 initialBlock 不完全相同，
	// 但应该在可接受的误差范围内。
}
```

**假设的输入与输出：**

**输入 (initialBlock):** 一个 8x8 的 `jpeg.Block`，包含一些像素值。例如：

```
{
	0x0064, 0x006e, 0x0078, 0x0082, 0x008c, 0x0096, 0x00a0, 0x00aa,
	0x0069, 0x0073, 0x007d, 0x0087, 0x0091, 0x009b, 0x00a5, 0x00af,
	// ... 更多像素值 ...
}
```

**输出 (dctBlock):**  经过 FDCT 变换后的 `jpeg.Block`，包含频率域的系数。这些系数通常会有一些低频分量和一些高频分量。

```
{
	0x08c0, 0xfefb, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0xfffd, 0x0003, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	// ... 更多系数 ...
}
```

**输出 (idctBlock):** 经过 IDCT 变换后的 `jpeg.Block`，应该尽可能接近原始的 `initialBlock`。

```
{
	0x0064, 0x006e, 0x0078, 0x0082, 0x008c, 0x0096, 0x00a0, 0x00aa,
	0x0069, 0x0073, 0x007d, 0x0087, 0x0091, 0x009b, 0x00a5, 0x00af,
	// ... 更多接近原始的像素值 ...
}
```

**命令行参数的具体处理：**

这个文件是一个测试文件，通常不会直接作为可执行程序运行，因此不涉及命令行参数的处理。它是通过 `go test` 命令来运行的。

**使用者易犯错的点：**

对于使用 `image/jpeg` 包的开发者来说，关于 DCT 的直接操作并不常见，因为这些变换通常在编码和解码的内部流程中处理。但是，如果开发者试图手动实现或者理解 JPEG 算法，可能会遇到以下易犯错的点：

1. **精度问题：**  DCT 和 IDCT 涉及浮点数运算，直接进行整数比较可能会失败。需要理解并接受一定的精度误差，就像 `differ` 函数中做的那样。

   ```go
   // 错误的做法，直接比较浮点数
   // if transformedBlock == originalBlock { ... }

   // 正确的做法，允许一定的误差
   diff := calculateDifference(transformedBlock, originalBlock)
   if diff < tolerance { ... }
   ```

2. **缩放和偏移：**  在 JPEG 标准中，像素值通常会被偏移和缩放后再进行 DCT 变换（例如，从 0-255 偏移到 -128 到 127）。直接对原始像素值应用 DCT 可能得不到期望的结果。文件中的测试代码也体现了这一点，在 `TestDCT` 中对数据进行了 `(got[j] - 128) * 8` 的预处理。

3. **DCT 的公式和实现细节：**  DCT 的实现有多种形式（例如，整数 DCT），且公式中的系数和缩放因子需要仔细处理。直接照搬公式而不考虑具体实现可能导致错误。`slowFDCT` 和 `slowIDCT` 体现了基本的浮点数 DCT 公式，但实际的 `fdct` 和 `idct` 可能是更高效的整数实现。

4. **块的大小：**  JPEG 标准中，DCT 通常作用于 8x8 的像素块。如果处理的块大小不正确，变换结果将毫无意义。

总而言之，这个 `dct_test.go` 文件是 Go 语言 `image/jpeg` 包中用于测试 DCT 和 IDCT 功能的核心测试文件，它通过基准测试和单元测试来确保这些关键算法的性能和正确性。对于一般的 JPEG 包使用者来说，无需直接操作这些函数，但理解其背后的原理对于深入了解 JPEG 压缩至关重要。

Prompt: 
```
这是路径为go/src/image/jpeg/dct_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package jpeg

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

func benchmarkDCT(b *testing.B, f func(*block)) {
	b.StopTimer()
	blocks := make([]block, 0, b.N*len(testBlocks))
	for i := 0; i < b.N; i++ {
		blocks = append(blocks, testBlocks[:]...)
	}
	b.StartTimer()
	for i := range blocks {
		f(&blocks[i])
	}
}

func BenchmarkFDCT(b *testing.B) {
	benchmarkDCT(b, fdct)
}

func BenchmarkIDCT(b *testing.B) {
	benchmarkDCT(b, idct)
}

func TestDCT(t *testing.T) {
	blocks := make([]block, len(testBlocks))
	copy(blocks, testBlocks[:])

	// Append some randomly generated blocks of varying sparseness.
	r := rand.New(rand.NewSource(123))
	for i := 0; i < 100; i++ {
		b := block{}
		n := r.Int() % 64
		for j := 0; j < n; j++ {
			b[r.Int()%len(b)] = r.Int31() % 256
		}
		blocks = append(blocks, b)
	}

	// Check that the FDCT and IDCT functions are inverses, after a scale and
	// level shift. Scaling reduces the rounding errors in the conversion from
	// floats to ints.
	for i, b := range blocks {
		got, want := b, b
		for j := range got {
			got[j] = (got[j] - 128) * 8
		}
		slowFDCT(&got)
		slowIDCT(&got)
		for j := range got {
			got[j] = got[j]/8 + 128
		}
		if differ(&got, &want) {
			t.Errorf("i=%d: IDCT(FDCT)\nsrc\n%s\ngot\n%s\nwant\n%s\n", i, &b, &got, &want)
		}
	}

	// Check that the optimized and slow FDCT implementations agree.
	// The fdct function already does a scale and level shift.
	for i, b := range blocks {
		got, want := b, b
		fdct(&got)
		for j := range want {
			want[j] = (want[j] - 128) * 8
		}
		slowFDCT(&want)
		if differ(&got, &want) {
			t.Errorf("i=%d: FDCT\nsrc\n%s\ngot\n%s\nwant\n%s\n", i, &b, &got, &want)
		}
	}

	// Check that the optimized and slow IDCT implementations agree.
	for i, b := range blocks {
		got, want := b, b
		idct(&got)
		slowIDCT(&want)
		if differ(&got, &want) {
			t.Errorf("i=%d: IDCT\nsrc\n%s\ngot\n%s\nwant\n%s\n", i, &b, &got, &want)
		}
	}
}

// differ reports whether any pair-wise elements in b0 and b1 differ by 2 or
// more. That tolerance is because there isn't a single definitive decoding of
// a given JPEG image, even before the YCbCr to RGB conversion; implementations
// can have different IDCT rounding errors.
func differ(b0, b1 *block) bool {
	for i := range b0 {
		delta := b0[i] - b1[i]
		if delta < -2 || +2 < delta {
			return true
		}
	}
	return false
}

// alpha returns 1 if i is 0 and returns √2 otherwise.
func alpha(i int) float64 {
	if i == 0 {
		return 1
	}
	return math.Sqrt2
}

var cosines = [32]float64{
	+1.0000000000000000000000000000000000000000000000000000000000000000, // cos(π/16 *  0)
	+0.9807852804032304491261822361342390369739337308933360950029160885, // cos(π/16 *  1)
	+0.9238795325112867561281831893967882868224166258636424861150977312, // cos(π/16 *  2)
	+0.8314696123025452370787883776179057567385608119872499634461245902, // cos(π/16 *  3)
	+0.7071067811865475244008443621048490392848359376884740365883398689, // cos(π/16 *  4)
	+0.5555702330196022247428308139485328743749371907548040459241535282, // cos(π/16 *  5)
	+0.3826834323650897717284599840303988667613445624856270414338006356, // cos(π/16 *  6)
	+0.1950903220161282678482848684770222409276916177519548077545020894, // cos(π/16 *  7)

	-0.0000000000000000000000000000000000000000000000000000000000000000, // cos(π/16 *  8)
	-0.1950903220161282678482848684770222409276916177519548077545020894, // cos(π/16 *  9)
	-0.3826834323650897717284599840303988667613445624856270414338006356, // cos(π/16 * 10)
	-0.5555702330196022247428308139485328743749371907548040459241535282, // cos(π/16 * 11)
	-0.7071067811865475244008443621048490392848359376884740365883398689, // cos(π/16 * 12)
	-0.8314696123025452370787883776179057567385608119872499634461245902, // cos(π/16 * 13)
	-0.9238795325112867561281831893967882868224166258636424861150977312, // cos(π/16 * 14)
	-0.9807852804032304491261822361342390369739337308933360950029160885, // cos(π/16 * 15)

	-1.0000000000000000000000000000000000000000000000000000000000000000, // cos(π/16 * 16)
	-0.9807852804032304491261822361342390369739337308933360950029160885, // cos(π/16 * 17)
	-0.9238795325112867561281831893967882868224166258636424861150977312, // cos(π/16 * 18)
	-0.8314696123025452370787883776179057567385608119872499634461245902, // cos(π/16 * 19)
	-0.7071067811865475244008443621048490392848359376884740365883398689, // cos(π/16 * 20)
	-0.5555702330196022247428308139485328743749371907548040459241535282, // cos(π/16 * 21)
	-0.3826834323650897717284599840303988667613445624856270414338006356, // cos(π/16 * 22)
	-0.1950903220161282678482848684770222409276916177519548077545020894, // cos(π/16 * 23)

	+0.0000000000000000000000000000000000000000000000000000000000000000, // cos(π/16 * 24)
	+0.1950903220161282678482848684770222409276916177519548077545020894, // cos(π/16 * 25)
	+0.3826834323650897717284599840303988667613445624856270414338006356, // cos(π/16 * 26)
	+0.5555702330196022247428308139485328743749371907548040459241535282, // cos(π/16 * 27)
	+0.7071067811865475244008443621048490392848359376884740365883398689, // cos(π/16 * 28)
	+0.8314696123025452370787883776179057567385608119872499634461245902, // cos(π/16 * 29)
	+0.9238795325112867561281831893967882868224166258636424861150977312, // cos(π/16 * 30)
	+0.9807852804032304491261822361342390369739337308933360950029160885, // cos(π/16 * 31)
}

// slowFDCT performs the 8*8 2-dimensional forward discrete cosine transform:
//
//	dst[u,v] = (1/8) * Σ_x Σ_y alpha(u) * alpha(v) * src[x,y] *
//		cos((π/2) * (2*x + 1) * u / 8) *
//		cos((π/2) * (2*y + 1) * v / 8)
//
// x and y are in pixel space, and u and v are in transform space.
//
// b acts as both dst and src.
func slowFDCT(b *block) {
	var dst [blockSize]float64
	for v := 0; v < 8; v++ {
		for u := 0; u < 8; u++ {
			sum := 0.0
			for y := 0; y < 8; y++ {
				for x := 0; x < 8; x++ {
					sum += alpha(u) * alpha(v) * float64(b[8*y+x]) *
						cosines[((2*x+1)*u)%32] *
						cosines[((2*y+1)*v)%32]
				}
			}
			dst[8*v+u] = sum / 8
		}
	}
	// Convert from float64 to int32.
	for i := range dst {
		b[i] = int32(dst[i] + 0.5)
	}
}

// slowIDCT performs the 8*8 2-dimensional inverse discrete cosine transform:
//
//	dst[x,y] = (1/8) * Σ_u Σ_v alpha(u) * alpha(v) * src[u,v] *
//		cos((π/2) * (2*x + 1) * u / 8) *
//		cos((π/2) * (2*y + 1) * v / 8)
//
// x and y are in pixel space, and u and v are in transform space.
//
// b acts as both dst and src.
func slowIDCT(b *block) {
	var dst [blockSize]float64
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			sum := 0.0
			for v := 0; v < 8; v++ {
				for u := 0; u < 8; u++ {
					sum += alpha(u) * alpha(v) * float64(b[8*v+u]) *
						cosines[((2*x+1)*u)%32] *
						cosines[((2*y+1)*v)%32]
				}
			}
			dst[8*y+x] = sum / 8
		}
	}
	// Convert from float64 to int32.
	for i := range dst {
		b[i] = int32(dst[i] + 0.5)
	}
}

func (b *block) String() string {
	s := &strings.Builder{}
	fmt.Fprintf(s, "{\n")
	for y := 0; y < 8; y++ {
		fmt.Fprintf(s, "\t")
		for x := 0; x < 8; x++ {
			fmt.Fprintf(s, "0x%04x, ", uint16(b[8*y+x]))
		}
		fmt.Fprintln(s)
	}
	fmt.Fprintf(s, "}")
	return s.String()
}

// testBlocks are the first 10 pre-IDCT blocks from ../testdata/video-001.jpeg.
var testBlocks = [10]block{
	{
		0x7f, 0xf6, 0x01, 0x07, 0xff, 0x00, 0x00, 0x00,
		0xf5, 0x01, 0xfa, 0x01, 0xfe, 0x00, 0x01, 0x00,
		0x05, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xff, 0xf8, 0x00, 0x01, 0xff, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01, 0x00, 0xff, 0xff, 0x00,
		0xff, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x01, 0xff, 0x01, 0x00, 0xfe,
	},
	{
		0x29, 0x07, 0x00, 0xfc, 0x01, 0x01, 0x00, 0x00,
		0x07, 0x00, 0x03, 0x00, 0x01, 0x00, 0xff, 0xff,
		0xff, 0xfd, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x04, 0x00, 0xff, 0x01, 0x00, 0x00,
		0x01, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x01, 0xfa, 0x01, 0x00, 0x01, 0x00, 0x01, 0xff,
		0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0x00, 0xff, 0x00, 0x02,
	},
	{
		0xc5, 0xfa, 0x01, 0x00, 0x00, 0x01, 0x00, 0xff,
		0x02, 0xff, 0x01, 0x00, 0x01, 0x00, 0xff, 0x00,
		0xff, 0xff, 0x00, 0xff, 0x01, 0x00, 0x00, 0x00,
		0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	},
	{
		0x86, 0x05, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00,
		0xf2, 0x06, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
		0xf6, 0xfa, 0xf9, 0x00, 0xff, 0x01, 0x00, 0x00,
		0xf9, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
		0xff, 0x00, 0x00, 0x01, 0x00, 0xff, 0x01, 0x00,
		0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x01, 0xff, 0x01, 0x00, 0xff, 0x00, 0x00,
	},
	{
		0x24, 0xfe, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00,
		0x08, 0xfd, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00,
		0x06, 0x03, 0x03, 0xff, 0x00, 0x00, 0x00, 0x00,
		0x04, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
		0x01, 0x00, 0x01, 0xff, 0x00, 0x01, 0x00, 0x00,
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0x01,
	},
	{
		0xcd, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
		0x03, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xff,
	},
	{
		0x81, 0xfe, 0x05, 0xff, 0x01, 0xff, 0x01, 0x00,
		0xef, 0xf9, 0x00, 0xf9, 0x00, 0xff, 0x00, 0xff,
		0x05, 0xf9, 0x00, 0xf8, 0x01, 0xff, 0x01, 0xff,
		0x00, 0xff, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x01,
		0xff, 0x01, 0x01, 0x00, 0xff, 0x00, 0x00, 0x00,
		0x01, 0x01, 0x00, 0xff, 0x00, 0x00, 0x00, 0xff,
	},
	{
		0x28, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0b, 0x02, 0x01, 0x03, 0x00, 0xff, 0x00, 0x01,
		0xfe, 0x02, 0x01, 0x03, 0xff, 0x00, 0x00, 0x00,
		0x01, 0x00, 0xfd, 0x00, 0x01, 0x00, 0xff, 0x00,
		0x01, 0xff, 0x00, 0xff, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xff, 0x01, 0x01, 0x00, 0xff,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x01,
	},
	{
		0xdf, 0xf9, 0xfe, 0x00, 0x03, 0x01, 0xff, 0xff,
		0x04, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0xfe, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xff, 0x01, 0x00, 0x00, 0x00, 0x01,
		0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0xff, 0x00, 0xff, 0x01, 0x00, 0x00, 0x01,
		0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	},
	{
		0x88, 0xfd, 0x00, 0x00, 0xff, 0x00, 0x01, 0xff,
		0xe1, 0x06, 0x06, 0x01, 0xff, 0x00, 0x01, 0x00,
		0x08, 0x00, 0xfa, 0x00, 0xff, 0xff, 0xff, 0xff,
		0x08, 0x01, 0x00, 0xff, 0x01, 0xff, 0x00, 0x00,
		0xf5, 0xff, 0x00, 0x01, 0xff, 0x01, 0x01, 0x00,
		0xff, 0xff, 0x01, 0xff, 0x01, 0x00, 0x01, 0x00,
		0x00, 0x01, 0x01, 0xff, 0x00, 0xff, 0x00, 0x01,
		0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00,
	},
}

"""



```