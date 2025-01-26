Response:
Let's break down the thought process for analyzing this Go test file.

**1. Initial Scan and High-Level Understanding:**

* **File Name and Path:**  `go/src/math/bits/bits_test.go`. This immediately suggests it's a test file for the `math/bits` package. The `_test.go` suffix confirms this.
* **Package Declaration:** `package bits_test`. This is standard for Go test files; they are in a separate package from the code they're testing.
* **Imports:**  `"math/bits"`, `"runtime"`, `"testing"`, `"unsafe"`. These give clues about the functionality being tested. We'll be dealing with bit manipulation (`math/bits`), runtime information, standard testing, and potentially low-level memory operations (`unsafe`).
* **Comments:** The copyright notice and license are standard boilerplate.

**2. Identifying Key Functionalities by Test Function Names:**

The core of understanding a test file lies in examining the test function names. They usually follow the pattern `Test<FunctionName>` or `Benchmark<FunctionName>`.

* **`TestUintSize`:**  Likely testing the size of the `uint` type.
* **`TestLeadingZeros`, `BenchmarkLeadingZeros*`:**  Related to counting leading zero bits. The different suffixes (8, 16, 32, 64) suggest testing these functions for different integer sizes.
* **`TestTrailingZeros`, `BenchmarkTrailingZeros*`:**  Related to counting trailing zero bits, with similar size variations.
* **`TestOnesCount`, `BenchmarkOnesCount*`:**  Related to counting the number of set bits (ones).
* **`TestRotateLeft`, `BenchmarkRotateLeft*`:**  Related to bitwise left rotation.
* **`TestReverse`, `BenchmarkReverse*`:**  Related to reversing the order of bits.
* **`TestReverseBytes`, `BenchmarkReverseBytes*`:** Related to reversing the order of bytes within a multi-byte integer.
* **`TestLen`:** Likely testing the number of bits required to represent a number (excluding leading zeros).
* **`TestAddSubUint*`:** Testing addition and subtraction with carry/borrow.
* **`TestMulDiv*`:** Testing multiplication and division, likely returning both quotient and remainder (or high and low parts of the product).
* **`Test*PanicOverflow`, `Test*PanicZero`:** These test that the code panics correctly when division by zero or overflow occurs.
* **`TestRem*`:** Testing the remainder operation specifically, particularly in cases where a direct division might overflow.
* **`BenchmarkAdd*`, `BenchmarkSub*`, `BenchmarkMul*`, `BenchmarkDiv*`:** Performance benchmarks for the arithmetic operations.

**3. Analyzing Test Function Logic (Example: `TestLeadingZeros`):**

Let's take `TestLeadingZeros` as an example of the more complex tests:

* **Outer Loop (`i < 256`):** Iterates through all possible values of a `uint8`. This suggests it's testing the behavior for small numbers exhaustively.
* **`nlz := tab[i].nlz`:**  This implies there's a global variable `tab` (likely an array or slice) with precomputed leading zero counts. This is common in `math/bits` for performance reasons (often lookup tables are used).
* **Inner Loop (`k < 64-8`):**  Shifts the initial `uint8` value left by `k` bits. This effectively tests the `LeadingZeros` functions for various positions of the most significant bit.
* **`if x <= 1<<8-1 { ... }` blocks:**  These blocks check the `LeadingZeros8` function. The `want` calculation (`nlz - k + (8 - 8)`) is a bit tricky but essentially accounts for the initial leading zeros in `i`, the left shift `k`, and the size of the `uint8`. The special case for `x == 0` is important because leading zeros for zero are the size of the type.
* **Similar blocks for `LeadingZeros16`, `LeadingZeros32`, `LeadingZeros64`, and the generic `LeadingZeros`:** The structure is very similar, just adjusting the bit size and the `want` calculation accordingly.
* **`t.Fatalf(...)`:**  This is the standard Go testing function for reporting a fatal error if the `got` and `want` values don't match.

**4. Inferring Function Implementations (and using Go Playground):**

Based on the test names and logic, we can infer what the corresponding functions in `math/bits` likely do. For example, `LeadingZeros8(uint8(x))` likely returns the number of leading zero bits in the `uint8` `x`.

To confirm our assumptions or understand the nuances, we can use the Go Playground (play.golang.org). We can write small code snippets to test the behavior of the `math/bits` functions with various inputs. This helps solidify our understanding of what the test code is verifying.

**5. Identifying Benchmarks:**

The `Benchmark*` functions use the `testing.B` type and the `b.N` loop. These are designed to measure the performance of the corresponding functions. The global `Input` and `Output` variables are used to prevent the compiler from optimizing away the benchmarked code.

**6. Looking for Edge Cases and Error Handling:**

The `TestDivPanicOverflow` and `TestDivPanicZero` functions explicitly check for panics in division operations, demonstrating that the `math/bits` package handles these error conditions. The `TestRem*Overflow` functions explore remainder calculations in scenarios where direct division would overflow.

**7. Synthesizing the Summary:**

Finally, we combine our observations from the function names, test logic, and inferred functionality to create a concise summary of what the test file does. We focus on the main areas of functionality being tested: size of `uint`, counting leading/trailing zeros and set bits, bitwise rotation and reversal, byte reversal, length calculation, and basic arithmetic operations with overflow checks.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption about `tab`:**  Initially, I might not know what `tab` is. By looking at how it's used in the loops and the calculation of `want`, I can infer that it likely holds precomputed values related to bit counts for `uint8` values.
* **Understanding `want` Calculation:** The calculation of the `want` value in `TestLeadingZeros` might seem confusing at first. Breaking it down step-by-step and considering the effect of the left shift is crucial.
* **Connecting Benchmarks to Tests:**  Realizing that each `Benchmark*` function corresponds to a `Test*` function helps in understanding the overall structure and purpose of the file.
* **Recognizing the Purpose of Global Variables in Benchmarks:**  Understanding why `Input` and `Output` are used in the benchmarks is important for correctly interpreting their role.

By following these steps, we can systematically analyze the Go test file and extract its key functionalities, even without knowing the exact implementation details of the `math/bits` package.
这个go语言测试文件（`bits_test.go`）是用来测试 `math/bits` 包中提供的各种位操作相关功能的。它包含了多个测试函数和基准测试函数，用于验证这些位操作函数的正确性和性能。

**主要功能归纳：**

1. **测试 `uint` 类型的大小：** 验证 `bits.UintSize` 常量是否正确反映了当前平台上 `uint` 类型的大小（以位为单位）。

2. **测试计算前导零的函数：**
   - 测试 `LeadingZeros8`, `LeadingZeros16`, `LeadingZeros32`, `LeadingZeros64` 以及通用的 `LeadingZeros` 函数，用于计算不同大小的无符号整数类型中前导零的个数。

3. **测试计算尾部零的函数：**
   - 测试 `TrailingZeros8`, `TrailingZeros16`, `TrailingZeros32`, `TrailingZeros64` 以及通用的 `TrailingZeros` 函数，用于计算不同大小的无符号整数类型中尾部零的个数。

4. **测试计算置位比特（1）数量的函数：**
   - 测试 `OnesCount8`, `OnesCount16`, `OnesCount32`, `OnesCount64` 以及通用的 `OnesCount` 函数，用于计算不同大小的无符号整数类型中比特位为1的个数。

5. **测试循环左移函数：**
   - 测试 `RotateLeft8`, `RotateLeft16`, `RotateLeft32`, `RotateLeft64` 以及通用的 `RotateLeft` 函数，用于对不同大小的无符号整数类型进行循环左移操作。

6. **测试比特位反转函数：**
   - 测试 `Reverse8`, `Reverse16`, `Reverse32`, `Reverse64` 以及通用的 `Reverse` 函数，用于反转不同大小的无符号整数类型的比特位顺序。

7. **测试字节反转函数：**
   - 测试 `ReverseBytes16`, `ReverseBytes32`, `ReverseBytes64` 以及通用的 `ReverseBytes` 函数，用于反转不同大小的无符号整数类型的字节顺序。

8. **测试计算表示数字所需最少比特位数的函数：**
   - 测试 `Len8`, `Len16`, `Len32`, `Len64` 以及通用的 `Len` 函数，用于计算表示不同大小的无符号整数类型所需的最少比特位数（不包括前导零）。

9. **测试带进位/借位的加法和减法函数：**
   - 测试 `Add`, `Add32`, `Add64` 和 `Sub`, `Sub32`, `Sub64` 函数，用于执行带进位（加法）和借位（减法）的无符号整数运算。

10. **测试乘法和除法函数：**
    - 测试 `Mul`, `Mul32`, `Mul64` 函数，用于执行无符号整数乘法，并返回高位和低位结果。
    - 测试 `Div`, `Div32`, `Div64` 函数，用于执行无符号整数除法，并返回商和余数。

11. **测试除法运算的 panic 行为：**
    - 测试当除法运算发生溢出或除数为零时，`Div`, `Div32`, `Div64` 函数是否会正确地触发 panic。

12. **测试带高低位的取余运算函数：**
    - 测试 `Rem32` 和 `Rem64` 函数，用于计算带高低位的无符号整数除法运算的余数。

13. **基准测试：**
    - 包含了对上述各种位操作函数以及加减乘除函数的性能基准测试 (`Benchmark...`)，用于评估它们的执行效率。

**它是什么go语言功能的实现？**

这个测试文件主要测试的是 `math/bits` 包中提供的**位操作（Bit Manipulation）**功能的实现。`math/bits` 包提供了一系列函数，用于对无符号整数进行底层的位级操作，例如计算前导零、尾部零、比特位计数、循环移位、比特位反转、字节反转以及带进位的加减法和乘除法等。这些功能在很多底层编程、算法和数据结构实现中非常有用。

**go代码举例说明：**

以下举例说明如何使用 `math/bits` 包中的一些功能，以及对应的测试用例是如何验证的：

```go
package main

import (
	"fmt"
	"math/bits"
)

func main() {
	var x uint32 = 0b00001010000000000000000000000000 // 二进制表示

	// 计算前导零
	leadingZeros := bits.LeadingZeros32(x)
	fmt.Printf("Leading zeros of %#b: %d\n", x, leadingZeros) // Output: Leading zeros of 0b10100000000000000000000000000000: 27

	// 计算尾部零
	trailingZeros := bits.TrailingZeros32(x)
	fmt.Printf("Trailing zeros of %#b: %d\n", x, trailingZeros) // Output: Trailing zeros of 0b10100000000000000000000000000000: 20

	// 计算置位比特数
	onesCount := bits.OnesCount32(x)
	fmt.Printf("Number of ones in %#b: %d\n", x, onesCount) // Output: Number of ones in 0b10100000000000000000000000000000: 2

	// 循环左移
	rotatedLeft := bits.RotateLeft32(x, 3)
	fmt.Printf("%#b rotated left by 3: %#b\n", x, rotatedLeft) // Output: 0b10100000000000000000000000000000 rotated left by 3: 0b10100000000000000000000000000

	// 比特位反转
	reversed := bits.Reverse32(x)
	fmt.Printf("Reverse of %#b: %#b\n", x, reversed) // Output: Reverse of 0b10100000000000000000000000000000: 0b00000000000000000000000001010000

	// 计算表示数字所需的最少比特位数
	length := bits.Len32(x)
	fmt.Printf("Length of %#b: %d\n", x, length) // Output: Length of 0b10100000000000000000000000000000: 5

	// 带进位的加法
	var a uint32 = 10
	var b uint32 = 5
	sum, carry := bits.Add32(a, b, 0)
	fmt.Printf("%d + %d + carry(0) = %d, carry = %d\n", a, b, sum, carry) // Output: 10 + 5 + carry(0) = 15, carry = 0

	// 带借位的减法
	var c uint32 = 10
	var d uint32 = 5
	diff, borrow := bits.Sub32(c, d, 0)
	fmt.Printf("%d - %d - borrow(0) = %d, borrow = %d\n", c, d, diff, borrow) // Output: 10 - 5 - borrow(0) = 5, borrow = 0
}
```

在 `bits_test.go` 文件中，你会看到类似以下的测试用例来验证 `LeadingZeros32` 函数：

```go
func TestLeadingZeros(t *testing.T) {
	// ...
	for i := 0; i < 256; i++ {
		nlz := tab[i].nlz // 假设 tab 是一个预先计算好前导零的表格
		for k := 0; k < 64-8; k++ {
			x := uint64(i) << uint(k)
			if x <= 1<<32-1 {
				got := LeadingZeros32(uint32(x))
				want := nlz - k + (32 - 8)
				if x == 0 {
					want = 32
				}
				if got != want {
					t.Fatalf("LeadingZeros32(%#08x) == %d; want %d", x, got, want)
				}
				// ...
			}
			// ...
		}
	}
	// ...
}
```

**代码推理与假设的输入输出：**

在 `TestLeadingZeros` 函数中，外层循环遍历 `i` 从 0 到 255，内层循环通过左移 `k` 位来创建不同的测试输入。

**假设输入：** `x = 0b00000010` (十进制 2), `k = 3`
- `uint64(i)` 就是 `uint64(2)`
- `x := uint64(i) << uint(k)`  计算得到 `x = 2 << 3 = 16` (二进制 `0b00010000`)
- `LeadingZeros32(uint32(x))` 将计算 `LeadingZeros32(16)`
- **假设 `tab[2].nlz` 是 6 （因为 `0b00000010` 有 6 个前导零）**
- `want := nlz - k + (32 - 8)` 计算得到 `want = 6 - 3 + 24 = 27`
- `LeadingZeros32(16)` 的结果应该是 27，因为 `0b00000000000000000000000000010000` 有 27 个前导零。
- 如果 `got != want`，则测试失败。

**命令行参数的具体处理：**

这个测试文件本身不涉及命令行参数的处理。它是 Go 语言的测试文件，通过 `go test` 命令来运行。`go test` 命令本身有一些标准参数，例如指定要运行的测试函数、运行基准测试、显示详细输出等，但这些参数是 `go test` 命令提供的，而不是这个测试文件自身定义的。

**使用者易犯错的点：**

在使用 `math/bits` 包时，使用者容易犯错的点通常与对位运算的理解不足有关，例如：

1. **混淆有符号和无符号类型：** `math/bits` 包的函数主要针对无符号整数。对有符号整数使用可能会得到意想不到的结果。
2. **位移操作的溢出：**  确保位移量在有效范围内，避免超过整数类型的大小，否则行为是未定义的。
3. **对特定平台的字节序不敏感：** 在进行字节反转等操作时，需要了解目标平台的字节序（大端或小端）。
4. **错误理解前导零和尾部零的含义：**  例如，对于数字 0，所有的位都是零，前导零和尾部零的数量等于类型的大小。
5. **忽视进位和借位：** 在使用 `Add` 和 `Sub` 函数时，需要正确处理返回的进位和借位值，尤其是在实现多精度算术时。

**总结一下它的功能（对于第1部分）：**

这部分代码主要负责测试 `math/bits` 包中用于计算整数前导零、尾部零、置位比特数以及循环左移的功能的正确性。它通过大量的测试用例，覆盖了不同大小的无符号整数类型，并包含了性能基准测试来评估这些功能的效率。它验证了这些核心位操作函数在各种输入下的行为是否符合预期。

Prompt: 
```
这是路径为go/src/math/bits/bits_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bits_test

import (
	. "math/bits"
	"runtime"
	"testing"
	"unsafe"
)

func TestUintSize(t *testing.T) {
	var x uint
	if want := unsafe.Sizeof(x) * 8; UintSize != want {
		t.Fatalf("UintSize = %d; want %d", UintSize, want)
	}
}

func TestLeadingZeros(t *testing.T) {
	for i := 0; i < 256; i++ {
		nlz := tab[i].nlz
		for k := 0; k < 64-8; k++ {
			x := uint64(i) << uint(k)
			if x <= 1<<8-1 {
				got := LeadingZeros8(uint8(x))
				want := nlz - k + (8 - 8)
				if x == 0 {
					want = 8
				}
				if got != want {
					t.Fatalf("LeadingZeros8(%#02x) == %d; want %d", x, got, want)
				}
			}

			if x <= 1<<16-1 {
				got := LeadingZeros16(uint16(x))
				want := nlz - k + (16 - 8)
				if x == 0 {
					want = 16
				}
				if got != want {
					t.Fatalf("LeadingZeros16(%#04x) == %d; want %d", x, got, want)
				}
			}

			if x <= 1<<32-1 {
				got := LeadingZeros32(uint32(x))
				want := nlz - k + (32 - 8)
				if x == 0 {
					want = 32
				}
				if got != want {
					t.Fatalf("LeadingZeros32(%#08x) == %d; want %d", x, got, want)
				}
				if UintSize == 32 {
					got = LeadingZeros(uint(x))
					if got != want {
						t.Fatalf("LeadingZeros(%#08x) == %d; want %d", x, got, want)
					}
				}
			}

			if x <= 1<<64-1 {
				got := LeadingZeros64(uint64(x))
				want := nlz - k + (64 - 8)
				if x == 0 {
					want = 64
				}
				if got != want {
					t.Fatalf("LeadingZeros64(%#016x) == %d; want %d", x, got, want)
				}
				if UintSize == 64 {
					got = LeadingZeros(uint(x))
					if got != want {
						t.Fatalf("LeadingZeros(%#016x) == %d; want %d", x, got, want)
					}
				}
			}
		}
	}
}

// Exported (global) variable serving as input for some
// of the benchmarks to ensure side-effect free calls
// are not optimized away.
var Input uint64 = DeBruijn64

// Exported (global) variable to store function results
// during benchmarking to ensure side-effect free calls
// are not optimized away.
var Output int

func BenchmarkLeadingZeros(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += LeadingZeros(uint(Input) >> (uint(i) % UintSize))
	}
	Output = s
}

func BenchmarkLeadingZeros8(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += LeadingZeros8(uint8(Input) >> (uint(i) % 8))
	}
	Output = s
}

func BenchmarkLeadingZeros16(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += LeadingZeros16(uint16(Input) >> (uint(i) % 16))
	}
	Output = s
}

func BenchmarkLeadingZeros32(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += LeadingZeros32(uint32(Input) >> (uint(i) % 32))
	}
	Output = s
}

func BenchmarkLeadingZeros64(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += LeadingZeros64(uint64(Input) >> (uint(i) % 64))
	}
	Output = s
}

func TestTrailingZeros(t *testing.T) {
	for i := 0; i < 256; i++ {
		ntz := tab[i].ntz
		for k := 0; k < 64-8; k++ {
			x := uint64(i) << uint(k)
			want := ntz + k
			if x <= 1<<8-1 {
				got := TrailingZeros8(uint8(x))
				if x == 0 {
					want = 8
				}
				if got != want {
					t.Fatalf("TrailingZeros8(%#02x) == %d; want %d", x, got, want)
				}
			}

			if x <= 1<<16-1 {
				got := TrailingZeros16(uint16(x))
				if x == 0 {
					want = 16
				}
				if got != want {
					t.Fatalf("TrailingZeros16(%#04x) == %d; want %d", x, got, want)
				}
			}

			if x <= 1<<32-1 {
				got := TrailingZeros32(uint32(x))
				if x == 0 {
					want = 32
				}
				if got != want {
					t.Fatalf("TrailingZeros32(%#08x) == %d; want %d", x, got, want)
				}
				if UintSize == 32 {
					got = TrailingZeros(uint(x))
					if got != want {
						t.Fatalf("TrailingZeros(%#08x) == %d; want %d", x, got, want)
					}
				}
			}

			if x <= 1<<64-1 {
				got := TrailingZeros64(uint64(x))
				if x == 0 {
					want = 64
				}
				if got != want {
					t.Fatalf("TrailingZeros64(%#016x) == %d; want %d", x, got, want)
				}
				if UintSize == 64 {
					got = TrailingZeros(uint(x))
					if got != want {
						t.Fatalf("TrailingZeros(%#016x) == %d; want %d", x, got, want)
					}
				}
			}
		}
	}
}

func BenchmarkTrailingZeros(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += TrailingZeros(uint(Input) << (uint(i) % UintSize))
	}
	Output = s
}

func BenchmarkTrailingZeros8(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += TrailingZeros8(uint8(Input) << (uint(i) % 8))
	}
	Output = s
}

func BenchmarkTrailingZeros16(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += TrailingZeros16(uint16(Input) << (uint(i) % 16))
	}
	Output = s
}

func BenchmarkTrailingZeros32(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += TrailingZeros32(uint32(Input) << (uint(i) % 32))
	}
	Output = s
}

func BenchmarkTrailingZeros64(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += TrailingZeros64(uint64(Input) << (uint(i) % 64))
	}
	Output = s
}

func TestOnesCount(t *testing.T) {
	var x uint64
	for i := 0; i <= 64; i++ {
		testOnesCount(t, x, i)
		x = x<<1 | 1
	}

	for i := 64; i >= 0; i-- {
		testOnesCount(t, x, i)
		x = x << 1
	}

	for i := 0; i < 256; i++ {
		for k := 0; k < 64-8; k++ {
			testOnesCount(t, uint64(i)<<uint(k), tab[i].pop)
		}
	}
}

func testOnesCount(t *testing.T, x uint64, want int) {
	if x <= 1<<8-1 {
		got := OnesCount8(uint8(x))
		if got != want {
			t.Fatalf("OnesCount8(%#02x) == %d; want %d", uint8(x), got, want)
		}
	}

	if x <= 1<<16-1 {
		got := OnesCount16(uint16(x))
		if got != want {
			t.Fatalf("OnesCount16(%#04x) == %d; want %d", uint16(x), got, want)
		}
	}

	if x <= 1<<32-1 {
		got := OnesCount32(uint32(x))
		if got != want {
			t.Fatalf("OnesCount32(%#08x) == %d; want %d", uint32(x), got, want)
		}
		if UintSize == 32 {
			got = OnesCount(uint(x))
			if got != want {
				t.Fatalf("OnesCount(%#08x) == %d; want %d", uint32(x), got, want)
			}
		}
	}

	if x <= 1<<64-1 {
		got := OnesCount64(uint64(x))
		if got != want {
			t.Fatalf("OnesCount64(%#016x) == %d; want %d", x, got, want)
		}
		if UintSize == 64 {
			got = OnesCount(uint(x))
			if got != want {
				t.Fatalf("OnesCount(%#016x) == %d; want %d", x, got, want)
			}
		}
	}
}

func BenchmarkOnesCount(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += OnesCount(uint(Input))
	}
	Output = s
}

func BenchmarkOnesCount8(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += OnesCount8(uint8(Input))
	}
	Output = s
}

func BenchmarkOnesCount16(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += OnesCount16(uint16(Input))
	}
	Output = s
}

func BenchmarkOnesCount32(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += OnesCount32(uint32(Input))
	}
	Output = s
}

func BenchmarkOnesCount64(b *testing.B) {
	var s int
	for i := 0; i < b.N; i++ {
		s += OnesCount64(uint64(Input))
	}
	Output = s
}

func TestRotateLeft(t *testing.T) {
	var m uint64 = DeBruijn64

	for k := uint(0); k < 128; k++ {
		x8 := uint8(m)
		got8 := RotateLeft8(x8, int(k))
		want8 := x8<<(k&0x7) | x8>>(8-k&0x7)
		if got8 != want8 {
			t.Fatalf("RotateLeft8(%#02x, %d) == %#02x; want %#02x", x8, k, got8, want8)
		}
		got8 = RotateLeft8(want8, -int(k))
		if got8 != x8 {
			t.Fatalf("RotateLeft8(%#02x, -%d) == %#02x; want %#02x", want8, k, got8, x8)
		}

		x16 := uint16(m)
		got16 := RotateLeft16(x16, int(k))
		want16 := x16<<(k&0xf) | x16>>(16-k&0xf)
		if got16 != want16 {
			t.Fatalf("RotateLeft16(%#04x, %d) == %#04x; want %#04x", x16, k, got16, want16)
		}
		got16 = RotateLeft16(want16, -int(k))
		if got16 != x16 {
			t.Fatalf("RotateLeft16(%#04x, -%d) == %#04x; want %#04x", want16, k, got16, x16)
		}

		x32 := uint32(m)
		got32 := RotateLeft32(x32, int(k))
		want32 := x32<<(k&0x1f) | x32>>(32-k&0x1f)
		if got32 != want32 {
			t.Fatalf("RotateLeft32(%#08x, %d) == %#08x; want %#08x", x32, k, got32, want32)
		}
		got32 = RotateLeft32(want32, -int(k))
		if got32 != x32 {
			t.Fatalf("RotateLeft32(%#08x, -%d) == %#08x; want %#08x", want32, k, got32, x32)
		}
		if UintSize == 32 {
			x := uint(m)
			got := RotateLeft(x, int(k))
			want := x<<(k&0x1f) | x>>(32-k&0x1f)
			if got != want {
				t.Fatalf("RotateLeft(%#08x, %d) == %#08x; want %#08x", x, k, got, want)
			}
			got = RotateLeft(want, -int(k))
			if got != x {
				t.Fatalf("RotateLeft(%#08x, -%d) == %#08x; want %#08x", want, k, got, x)
			}
		}

		x64 := uint64(m)
		got64 := RotateLeft64(x64, int(k))
		want64 := x64<<(k&0x3f) | x64>>(64-k&0x3f)
		if got64 != want64 {
			t.Fatalf("RotateLeft64(%#016x, %d) == %#016x; want %#016x", x64, k, got64, want64)
		}
		got64 = RotateLeft64(want64, -int(k))
		if got64 != x64 {
			t.Fatalf("RotateLeft64(%#016x, -%d) == %#016x; want %#016x", want64, k, got64, x64)
		}
		if UintSize == 64 {
			x := uint(m)
			got := RotateLeft(x, int(k))
			want := x<<(k&0x3f) | x>>(64-k&0x3f)
			if got != want {
				t.Fatalf("RotateLeft(%#016x, %d) == %#016x; want %#016x", x, k, got, want)
			}
			got = RotateLeft(want, -int(k))
			if got != x {
				t.Fatalf("RotateLeft(%#08x, -%d) == %#08x; want %#08x", want, k, got, x)
			}
		}
	}
}

func BenchmarkRotateLeft(b *testing.B) {
	var s uint
	for i := 0; i < b.N; i++ {
		s += RotateLeft(uint(Input), i)
	}
	Output = int(s)
}

func BenchmarkRotateLeft8(b *testing.B) {
	var s uint8
	for i := 0; i < b.N; i++ {
		s += RotateLeft8(uint8(Input), i)
	}
	Output = int(s)
}

func BenchmarkRotateLeft16(b *testing.B) {
	var s uint16
	for i := 0; i < b.N; i++ {
		s += RotateLeft16(uint16(Input), i)
	}
	Output = int(s)
}

func BenchmarkRotateLeft32(b *testing.B) {
	var s uint32
	for i := 0; i < b.N; i++ {
		s += RotateLeft32(uint32(Input), i)
	}
	Output = int(s)
}

func BenchmarkRotateLeft64(b *testing.B) {
	var s uint64
	for i := 0; i < b.N; i++ {
		s += RotateLeft64(uint64(Input), i)
	}
	Output = int(s)
}

func TestReverse(t *testing.T) {
	// test each bit
	for i := uint(0); i < 64; i++ {
		testReverse(t, uint64(1)<<i, uint64(1)<<(63-i))
	}

	// test a few patterns
	for _, test := range []struct {
		x, r uint64
	}{
		{0, 0},
		{0x1, 0x8 << 60},
		{0x2, 0x4 << 60},
		{0x3, 0xc << 60},
		{0x4, 0x2 << 60},
		{0x5, 0xa << 60},
		{0x6, 0x6 << 60},
		{0x7, 0xe << 60},
		{0x8, 0x1 << 60},
		{0x9, 0x9 << 60},
		{0xa, 0x5 << 60},
		{0xb, 0xd << 60},
		{0xc, 0x3 << 60},
		{0xd, 0xb << 60},
		{0xe, 0x7 << 60},
		{0xf, 0xf << 60},
		{0x5686487, 0xe12616a000000000},
		{0x0123456789abcdef, 0xf7b3d591e6a2c480},
	} {
		testReverse(t, test.x, test.r)
		testReverse(t, test.r, test.x)
	}
}

func testReverse(t *testing.T, x64, want64 uint64) {
	x8 := uint8(x64)
	got8 := Reverse8(x8)
	want8 := uint8(want64 >> (64 - 8))
	if got8 != want8 {
		t.Fatalf("Reverse8(%#02x) == %#02x; want %#02x", x8, got8, want8)
	}

	x16 := uint16(x64)
	got16 := Reverse16(x16)
	want16 := uint16(want64 >> (64 - 16))
	if got16 != want16 {
		t.Fatalf("Reverse16(%#04x) == %#04x; want %#04x", x16, got16, want16)
	}

	x32 := uint32(x64)
	got32 := Reverse32(x32)
	want32 := uint32(want64 >> (64 - 32))
	if got32 != want32 {
		t.Fatalf("Reverse32(%#08x) == %#08x; want %#08x", x32, got32, want32)
	}
	if UintSize == 32 {
		x := uint(x32)
		got := Reverse(x)
		want := uint(want32)
		if got != want {
			t.Fatalf("Reverse(%#08x) == %#08x; want %#08x", x, got, want)
		}
	}

	got64 := Reverse64(x64)
	if got64 != want64 {
		t.Fatalf("Reverse64(%#016x) == %#016x; want %#016x", x64, got64, want64)
	}
	if UintSize == 64 {
		x := uint(x64)
		got := Reverse(x)
		want := uint(want64)
		if got != want {
			t.Fatalf("Reverse(%#08x) == %#016x; want %#016x", x, got, want)
		}
	}
}

func BenchmarkReverse(b *testing.B) {
	var s uint
	for i := 0; i < b.N; i++ {
		s += Reverse(uint(i))
	}
	Output = int(s)
}

func BenchmarkReverse8(b *testing.B) {
	var s uint8
	for i := 0; i < b.N; i++ {
		s += Reverse8(uint8(i))
	}
	Output = int(s)
}

func BenchmarkReverse16(b *testing.B) {
	var s uint16
	for i := 0; i < b.N; i++ {
		s += Reverse16(uint16(i))
	}
	Output = int(s)
}

func BenchmarkReverse32(b *testing.B) {
	var s uint32
	for i := 0; i < b.N; i++ {
		s += Reverse32(uint32(i))
	}
	Output = int(s)
}

func BenchmarkReverse64(b *testing.B) {
	var s uint64
	for i := 0; i < b.N; i++ {
		s += Reverse64(uint64(i))
	}
	Output = int(s)
}

func TestReverseBytes(t *testing.T) {
	for _, test := range []struct {
		x, r uint64
	}{
		{0, 0},
		{0x01, 0x01 << 56},
		{0x0123, 0x2301 << 48},
		{0x012345, 0x452301 << 40},
		{0x01234567, 0x67452301 << 32},
		{0x0123456789, 0x8967452301 << 24},
		{0x0123456789ab, 0xab8967452301 << 16},
		{0x0123456789abcd, 0xcdab8967452301 << 8},
		{0x0123456789abcdef, 0xefcdab8967452301 << 0},
	} {
		testReverseBytes(t, test.x, test.r)
		testReverseBytes(t, test.r, test.x)
	}
}

func testReverseBytes(t *testing.T, x64, want64 uint64) {
	x16 := uint16(x64)
	got16 := ReverseBytes16(x16)
	want16 := uint16(want64 >> (64 - 16))
	if got16 != want16 {
		t.Fatalf("ReverseBytes16(%#04x) == %#04x; want %#04x", x16, got16, want16)
	}

	x32 := uint32(x64)
	got32 := ReverseBytes32(x32)
	want32 := uint32(want64 >> (64 - 32))
	if got32 != want32 {
		t.Fatalf("ReverseBytes32(%#08x) == %#08x; want %#08x", x32, got32, want32)
	}
	if UintSize == 32 {
		x := uint(x32)
		got := ReverseBytes(x)
		want := uint(want32)
		if got != want {
			t.Fatalf("ReverseBytes(%#08x) == %#08x; want %#08x", x, got, want)
		}
	}

	got64 := ReverseBytes64(x64)
	if got64 != want64 {
		t.Fatalf("ReverseBytes64(%#016x) == %#016x; want %#016x", x64, got64, want64)
	}
	if UintSize == 64 {
		x := uint(x64)
		got := ReverseBytes(x)
		want := uint(want64)
		if got != want {
			t.Fatalf("ReverseBytes(%#016x) == %#016x; want %#016x", x, got, want)
		}
	}
}

func BenchmarkReverseBytes(b *testing.B) {
	var s uint
	for i := 0; i < b.N; i++ {
		s += ReverseBytes(uint(i))
	}
	Output = int(s)
}

func BenchmarkReverseBytes16(b *testing.B) {
	var s uint16
	for i := 0; i < b.N; i++ {
		s += ReverseBytes16(uint16(i))
	}
	Output = int(s)
}

func BenchmarkReverseBytes32(b *testing.B) {
	var s uint32
	for i := 0; i < b.N; i++ {
		s += ReverseBytes32(uint32(i))
	}
	Output = int(s)
}

func BenchmarkReverseBytes64(b *testing.B) {
	var s uint64
	for i := 0; i < b.N; i++ {
		s += ReverseBytes64(uint64(i))
	}
	Output = int(s)
}

func TestLen(t *testing.T) {
	for i := 0; i < 256; i++ {
		len := 8 - tab[i].nlz
		for k := 0; k < 64-8; k++ {
			x := uint64(i) << uint(k)
			want := 0
			if x != 0 {
				want = len + k
			}
			if x <= 1<<8-1 {
				got := Len8(uint8(x))
				if got != want {
					t.Fatalf("Len8(%#02x) == %d; want %d", x, got, want)
				}
			}

			if x <= 1<<16-1 {
				got := Len16(uint16(x))
				if got != want {
					t.Fatalf("Len16(%#04x) == %d; want %d", x, got, want)
				}
			}

			if x <= 1<<32-1 {
				got := Len32(uint32(x))
				if got != want {
					t.Fatalf("Len32(%#08x) == %d; want %d", x, got, want)
				}
				if UintSize == 32 {
					got := Len(uint(x))
					if got != want {
						t.Fatalf("Len(%#08x) == %d; want %d", x, got, want)
					}
				}
			}

			if x <= 1<<64-1 {
				got := Len64(uint64(x))
				if got != want {
					t.Fatalf("Len64(%#016x) == %d; want %d", x, got, want)
				}
				if UintSize == 64 {
					got := Len(uint(x))
					if got != want {
						t.Fatalf("Len(%#016x) == %d; want %d", x, got, want)
					}
				}
			}
		}
	}
}

const (
	_M   = 1<<UintSize - 1
	_M32 = 1<<32 - 1
	_M64 = 1<<64 - 1
)

func TestAddSubUint(t *testing.T) {
	test := func(msg string, f func(x, y, c uint) (z, cout uint), x, y, c, z, cout uint) {
		z1, cout1 := f(x, y, c)
		if z1 != z || cout1 != cout {
			t.Errorf("%s: got z:cout = %#x:%#x; want %#x:%#x", msg, z1, cout1, z, cout)
		}
	}
	for _, a := range []struct{ x, y, c, z, cout uint }{
		{0, 0, 0, 0, 0},
		{0, 1, 0, 1, 0},
		{0, 0, 1, 1, 0},
		{0, 1, 1, 2, 0},
		{12345, 67890, 0, 80235, 0},
		{12345, 67890, 1, 80236, 0},
		{_M, 1, 0, 0, 1},
		{_M, 0, 1, 0, 1},
		{_M, 1, 1, 1, 1},
		{_M, _M, 0, _M - 1, 1},
		{_M, _M, 1, _M, 1},
	} {
		test("Add", Add, a.x, a.y, a.c, a.z, a.cout)
		test("Add symmetric", Add, a.y, a.x, a.c, a.z, a.cout)
		test("Sub", Sub, a.z, a.x, a.c, a.y, a.cout)
		test("Sub symmetric", Sub, a.z, a.y, a.c, a.x, a.cout)
		// The above code can't test intrinsic implementation, because the passed function is not called directly.
		// The following code uses a closure to test the intrinsic version in case the function is intrinsified.
		test("Add intrinsic", func(x, y, c uint) (uint, uint) { return Add(x, y, c) }, a.x, a.y, a.c, a.z, a.cout)
		test("Add intrinsic symmetric", func(x, y, c uint) (uint, uint) { return Add(x, y, c) }, a.y, a.x, a.c, a.z, a.cout)
		test("Sub intrinsic", func(x, y, c uint) (uint, uint) { return Sub(x, y, c) }, a.z, a.x, a.c, a.y, a.cout)
		test("Sub intrinsic symmetric", func(x, y, c uint) (uint, uint) { return Sub(x, y, c) }, a.z, a.y, a.c, a.x, a.cout)

	}
}

func TestAddSubUint32(t *testing.T) {
	test := func(msg string, f func(x, y, c uint32) (z, cout uint32), x, y, c, z, cout uint32) {
		z1, cout1 := f(x, y, c)
		if z1 != z || cout1 != cout {
			t.Errorf("%s: got z:cout = %#x:%#x; want %#x:%#x", msg, z1, cout1, z, cout)
		}
	}
	for _, a := range []struct{ x, y, c, z, cout uint32 }{
		{0, 0, 0, 0, 0},
		{0, 1, 0, 1, 0},
		{0, 0, 1, 1, 0},
		{0, 1, 1, 2, 0},
		{12345, 67890, 0, 80235, 0},
		{12345, 67890, 1, 80236, 0},
		{_M32, 1, 0, 0, 1},
		{_M32, 0, 1, 0, 1},
		{_M32, 1, 1, 1, 1},
		{_M32, _M32, 0, _M32 - 1, 1},
		{_M32, _M32, 1, _M32, 1},
	} {
		test("Add32", Add32, a.x, a.y, a.c, a.z, a.cout)
		test("Add32 symmetric", Add32, a.y, a.x, a.c, a.z, a.cout)
		test("Sub32", Sub32, a.z, a.x, a.c, a.y, a.cout)
		test("Sub32 symmetric", Sub32, a.z, a.y, a.c, a.x, a.cout)
	}
}

func TestAddSubUint64(t *testing.T) {
	test := func(msg string, f func(x, y, c uint64) (z, cout uint64), x, y, c, z, cout uint64) {
		z1, cout1 := f(x, y, c)
		if z1 != z || cout1 != cout {
			t.Errorf("%s: got z:cout = %#x:%#x; want %#x:%#x", msg, z1, cout1, z, cout)
		}
	}
	for _, a := range []struct{ x, y, c, z, cout uint64 }{
		{0, 0, 0, 0, 0},
		{0, 1, 0, 1, 0},
		{0, 0, 1, 1, 0},
		{0, 1, 1, 2, 0},
		{12345, 67890, 0, 80235, 0},
		{12345, 67890, 1, 80236, 0},
		{_M64, 1, 0, 0, 1},
		{_M64, 0, 1, 0, 1},
		{_M64, 1, 1, 1, 1},
		{_M64, _M64, 0, _M64 - 1, 1},
		{_M64, _M64, 1, _M64, 1},
	} {
		test("Add64", Add64, a.x, a.y, a.c, a.z, a.cout)
		test("Add64 symmetric", Add64, a.y, a.x, a.c, a.z, a.cout)
		test("Sub64", Sub64, a.z, a.x, a.c, a.y, a.cout)
		test("Sub64 symmetric", Sub64, a.z, a.y, a.c, a.x, a.cout)
		// The above code can't test intrinsic implementation, because the passed function is not called directly.
		// The following code uses a closure to test the intrinsic version in case the function is intrinsified.
		test("Add64 intrinsic", func(x, y, c uint64) (uint64, uint64) { return Add64(x, y, c) }, a.x, a.y, a.c, a.z, a.cout)
		test("Add64 intrinsic symmetric", func(x, y, c uint64) (uint64, uint64) { return Add64(x, y, c) }, a.y, a.x, a.c, a.z, a.cout)
		test("Sub64 intrinsic", func(x, y, c uint64) (uint64, uint64) { return Sub64(x, y, c) }, a.z, a.x, a.c, a.y, a.cout)
		test("Sub64 intrinsic symmetric", func(x, y, c uint64) (uint64, uint64) { return Sub64(x, y, c) }, a.z, a.y, a.c, a.x, a.cout)
	}
}

func TestAdd64OverflowPanic(t *testing.T) {
	// Test that 64-bit overflow panics fire correctly.
	// These are designed to improve coverage of compiler intrinsics.
	tests := []func(uint64, uint64) uint64{
		func(a, b uint64) uint64 {
			x, c := Add64(a, b, 0)
			if c > 0 {
				panic("overflow")
			}
			return x
		},
		func(a, b uint64) uint64 {
			x, c := Add64(a, b, 0)
			if c != 0 {
				panic("overflow")
			}
			return x
		},
		func(a, b uint64) uint64 {
			x, c := Add64(a, b, 0)
			if c == 1 {
				panic("overflow")
			}
			return x
		},
		func(a, b uint64) uint64 {
			x, c := Add64(a, b, 0)
			if c != 1 {
				return x
			}
			panic("overflow")
		},
		func(a, b uint64) uint64 {
			x, c := Add64(a, b, 0)
			if c == 0 {
				return x
			}
			panic("overflow")
		},
	}
	for _, test := range tests {
		shouldPanic := func(f func()) {
			defer func() {
				if err := recover(); err == nil {
					t.Fatalf("expected panic")
				}
			}()
			f()
		}

		// overflow
		shouldPanic(func() { test(_M64, 1) })
		shouldPanic(func() { test(1, _M64) })
		shouldPanic(func() { test(_M64, _M64) })

		// no overflow
		test(_M64, 0)
		test(0, 0)
		test(1, 1)
	}
}

func TestSub64OverflowPanic(t *testing.T) {
	// Test that 64-bit overflow panics fire correctly.
	// These are designed to improve coverage of compiler intrinsics.
	tests := []func(uint64, uint64) uint64{
		func(a, b uint64) uint64 {
			x, c := Sub64(a, b, 0)
			if c > 0 {
				panic("overflow")
			}
			return x
		},
		func(a, b uint64) uint64 {
			x, c := Sub64(a, b, 0)
			if c != 0 {
				panic("overflow")
			}
			return x
		},
		func(a, b uint64) uint64 {
			x, c := Sub64(a, b, 0)
			if c == 1 {
				panic("overflow")
			}
			return x
		},
		func(a, b uint64) uint64 {
			x, c := Sub64(a, b, 0)
			if c != 1 {
				return x
			}
			panic("overflow")
		},
		func(a, b uint64) uint64 {
			x, c := Sub64(a, b, 0)
			if c == 0 {
				return x
			}
			panic("overflow")
		},
	}
	for _, test := range tests {
		shouldPanic := func(f func()) {
			defer func() {
				if err := recover(); err == nil {
					t.Fatalf("expected panic")
				}
			}()
			f()
		}

		// overflow
		shouldPanic(func() { test(0, 1) })
		shouldPanic(func() { test(1, _M64) })
		shouldPanic(func() { test(_M64-1, _M64) })

		// no overflow
		test(_M64, 0)
		test(0, 0)
		test(1, 1)
	}
}

func TestMulDiv(t *testing.T) {
	testMul := func(msg string, f func(x, y uint) (hi, lo uint), x, y, hi, lo uint) {
		hi1, lo1 := f(x, y)
		if hi1 != hi || lo1 != lo {
			t.Errorf("%s: got hi:lo = %#x:%#x; want %#x:%#x", msg, hi1, lo1, hi, lo)
		}
	}
	testDiv := func(msg string, f func(hi, lo, y uint) (q, r uint), hi, lo, y, q, r uint) {
		q1, r1 := f(hi, lo, y)
		if q1 != q || r1 != r {
			t.Errorf("%s: got q:r = %#x:%#x; want %#x:%#x", msg, q1, r1, q, r)
		}
	}
	for _, a := range []struct {
		x, y      uint
		hi, lo, r uint
	}{
		{1 << (UintSize - 1), 2, 1, 0, 1},
		{_M, _M, _M - 1, 1, 42},
	} {
		testMul("Mul", Mul, a.x, a.y, a.hi, a.lo)
		testMul("Mul symmetric", Mul, a.y, a.x, a.hi, a.lo)
		testDiv("Div", Div, a.hi, a.lo+a.r, a.y, a.x, a.r)
		testDiv("Div symmetric", Div, a.hi, a.lo+a.r, a.x, a.y, a.r)
		// The above code can't test intrinsic implementation, because the passed function is not called directly.
		// The following code uses a closure to test the intrinsic version in case the function is intrinsified.
		testMul("Mul intrinsic", func(x, y uint) (uint, uint) { return Mul(x, y) }, a.x, a.y, a.hi, a.lo)
		testMul("Mul intrinsic symmetric", func(x, y uint) (uint, uint) { return Mul(x, y) }, a.y, a.x, a.hi, a.lo)
		testDiv("Div intrinsic", func(hi, lo, y uint) (uint, uint) { return Div(hi, lo, y) }, a.hi, a.lo+a.r, a.y, a.x, a.r)
		testDiv("Div intrinsic symmetric", func(hi, lo, y uint) (uint, uint) { return Div(hi, lo, y) }, a.hi, a.lo+a.r, a.x, a.y, a.r)
	}
}

func TestMulDiv32(t *testing.T) {
	testMul := func(msg string, f func(x, y uint32) (hi, lo uint32), x, y, hi, lo uint32) {
		hi1, lo1 := f(x, y)
		if hi1 != hi || lo1 != lo {
			t.Errorf("%s: got hi:lo = %#x:%#x; want %#x:%#x", msg, hi1, lo1, hi, lo)
		}
	}
	testDiv := func(msg string, f func(hi, lo, y uint32) (q, r uint32), hi, lo, y, q, r uint32) {
		q1, r1 := f(hi, lo, y)
		if q1 != q || r1 != r {
			t.Errorf("%s: got q:r = %#x:%#x; want %#x:%#x", msg, q1, r1, q, r)
		}
	}
	for _, a := range []struct {
		x, y      uint32
		hi, lo, r uint32
	}{
		{1 << 31, 2, 1, 0, 1},
		{0xc47dfa8c, 50911, 0x98a4, 0x998587f4, 13},
		{_M32, _M32, _M32 - 1, 1, 42},
	} {
		testMul("Mul32", Mul32, a.x, a.y, a.hi, a.lo)
		testMul("Mul32 symmetric", Mul32, a.y, a.x, a.hi, a.lo)
		testDiv("Div32", Div32, a.hi, a.lo+a.r, a.y, a.x, a.r)
		testDiv("Div32 symmetric", Div32, a.hi, a.lo+a.r, a.x, a.y, a.r)
	}
}

func TestMulDiv64(t *testing.T) {
	testMul := func(msg string, f func(x, y uint64) (hi, lo uint64), x, y, hi, lo uint64) {
		hi1, lo1 := f(x, y)
		if hi1 != hi || lo1 != lo {
			t.Errorf("%s: got hi:lo = %#x:%#x; want %#x:%#x", msg, hi1, lo1, hi, lo)
		}
	}
	testDiv := func(msg string, f func(hi, lo, y uint64) (q, r uint64), hi, lo, y, q, r uint64) {
		q1, r1 := f(hi, lo, y)
		if q1 != q || r1 != r {
			t.Errorf("%s: got q:r = %#x:%#x; want %#x:%#x", msg, q1, r1, q, r)
		}
	}
	for _, a := range []struct {
		x, y      uint64
		hi, lo, r uint64
	}{
		{1 << 63, 2, 1, 0, 1},
		{0x3626229738a3b9, 0xd8988a9f1cc4a61, 0x2dd0712657fe8, 0x9dd6a3364c358319, 13},
		{_M64, _M64, _M64 - 1, 1, 42},
	} {
		testMul("Mul64", Mul64, a.x, a.y, a.hi, a.lo)
		testMul("Mul64 symmetric", Mul64, a.y, a.x, a.hi, a.lo)
		testDiv("Div64", Div64, a.hi, a.lo+a.r, a.y, a.x, a.r)
		testDiv("Div64 symmetric", Div64, a.hi, a.lo+a.r, a.x, a.y, a.r)
		// The above code can't test intrinsic implementation, because the passed function is not called directly.
		// The following code uses a closure to test the intrinsic version in case the function is intrinsified.
		testMul("Mul64 intrinsic", func(x, y uint64) (uint64, uint64) { return Mul64(x, y) }, a.x, a.y, a.hi, a.lo)
		testMul("Mul64 intrinsic symmetric", func(x, y uint64) (uint64, uint64) { return Mul64(x, y) }, a.y, a.x, a.hi, a.lo)
		testDiv("Div64 intrinsic", func(hi, lo, y uint64) (uint64, uint64) { return Div64(hi, lo, y) }, a.hi, a.lo+a.r, a.y, a.x, a.r)
		testDiv("Div64 intrinsic symmetric", func(hi, lo, y uint64) (uint64, uint64) { return Div64(hi, lo, y) }, a.hi, a.lo+a.r, a.x, a.y, a.r)
	}
}

const (
	divZeroError  = "runtime error: integer divide by zero"
	overflowError = "runtime error: integer overflow"
)

func TestDivPanicOverflow(t *testing.T) {
	// Expect a panic
	defer func() {
		if err := recover(); err == nil {
			t.Error("Div should have panicked when y<=hi")
		} else if e, ok := err.(runtime.Error); !ok || e.Error() != overflowError {
			t.Errorf("Div expected panic: %q, got: %q ", overflowError, e.Error())
		}
	}()
	q, r := Div(1, 0, 1)
	t.Errorf("undefined q, r = %v, %v calculated when Div should have panicked", q, r)
}

func TestDiv32PanicOverflow(t *testing.T) {
	// Expect a panic
	defer func() {
		if err := recover(); err == nil {
			t.Error("Div32 should have panicked when y<=hi")
		} else if e, ok := err.(runtime.Error); !ok || e.Error() != overflowError {
			t.Errorf("Div32 expected panic: %q, got: %q ", overflowError, e.Error())
		}
	}()
	q, r := Div32(1, 0, 1)
	t.Errorf("undefined q, r = %v, %v calculated when Div32 should have panicked", q, r)
}

func TestDiv64PanicOverflow(t *testing.T) {
	// Expect a panic
	defer func() {
		if err := recover(); err == nil {
			t.Error("Div64 should have panicked when y<=hi")
		} else if e, ok := err.(runtime.Error); !ok || e.Error() != overflowError {
			t.Errorf("Div64 expected panic: %q, got: %q ", overflowError, e.Error())
		}
	}()
	q, r := Div64(1, 0, 1)
	t.Errorf("undefined q, r = %v, %v calculated when Div64 should have panicked", q, r)
}

func TestDivPanicZero(t *testing.T) {
	// Expect a panic
	defer func() {
		if err := recover(); err == nil {
			t.Error("Div should have panicked when y==0")
		} else if e, ok := err.(runtime.Error); !ok || e.Error() != divZeroError {
			t.Errorf("Div expected panic: %q, got: %q ", divZeroError, e.Error())
		}
	}()
	q, r := Div(1, 1, 0)
	t.Errorf("undefined q, r = %v, %v calculated when Div should have panicked", q, r)
}

func TestDiv32PanicZero(t *testing.T) {
	// Expect a panic
	defer func() {
		if err := recover(); err == nil {
			t.Error("Div32 should have panicked when y==0")
		} else if e, ok := err.(runtime.Error); !ok || e.Error() != divZeroError {
			t.Errorf("Div32 expected panic: %q, got: %q ", divZeroError, e.Error())
		}
	}()
	q, r := Div32(1, 1, 0)
	t.Errorf("undefined q, r = %v, %v calculated when Div32 should have panicked", q, r)
}

func TestDiv64PanicZero(t *testing.T) {
	// Expect a panic
	defer func() {
		if err := recover(); err == nil {
			t.Error("Div64 should have panicked when y==0")
		} else if e, ok := err.(runtime.Error); !ok || e.Error() != divZeroError {
			t.Errorf("Div64 expected panic: %q, got: %q ", divZeroError, e.Error())
		}
	}()
	q, r := Div64(1, 1, 0)
	t.Errorf("undefined q, r = %v, %v calculated when Div64 should have panicked", q, r)
}

func TestRem32(t *testing.T) {
	// Sanity check: for non-overflowing dividends, the result is the
	// same as the rem returned by Div32
	hi, lo, y := uint32(510510), uint32(9699690), uint32(510510+1) // ensure hi < y
	for i := 0; i < 1000; i++ {
		r := Rem32(hi, lo, y)
		_, r2 := Div32(hi, lo, y)
		if r != r2 {
			t.Errorf("Rem32(%v, %v, %v) returned %v, but Div32 returned rem %v", hi, lo, y, r, r2)
		}
		y += 13
	}
}

func TestRem32Overflow(t *testing.T) {
	// To trigger a quotient overflow, we need y <= hi
	hi, lo, y := uint32(510510), uint32(9699690), uint32(7)
	for i := 0; i < 1000; i++ {
		r := Rem32(hi, lo, y)
		_, r2 := Div64(0, uint64(hi)<<32|uint64(lo), uint64(y))
		if r != uint32(r2) {
			t.Errorf("Rem32(%v, %v, %v) returned %v, but Div64 returned rem %v", hi, lo, y, r, r2)
		}
		y += 13
	}
}

func TestRem64(t *testing.T) {
	// Sanity check: for non-overflowing dividends, the result is the
	// same as the rem returned by Div64
	hi, lo, y := uint64(510510), uint64(9699690), uint64(510510+1) // ensure hi < y
	for i := 0; i < 1000; i++ {
		r := Rem64(hi, lo, y)
		_, r2 := Div64(hi, lo, y)
		if r != r2 {
			t.Errorf("Rem64(%v, %v, %v) returned %v, but Div64 returned rem %v", hi, lo, y, r, r2)
		}
		y += 13
	}
}

func TestRem64Overflow(t *testing.T) {
	Rem64Tests := []struct {
		hi, lo, y uint64
		rem       uint64
	}{
		// Testcases computed using Python 3, as:
		//   >>> hi = 42; lo = 1119; y = 42
		//   >>> ((hi<<64)+lo) % y
		{42, 1119, 42, 27},
		{42, 1119, 38, 9},
		{42, 1119, 26, 23},
		{469, 0, 467, 271},
		{469, 0, 113, 58},
		{111111, 111111, 1171, 803},
		{3968194946088682615, 3192705705065114702, 1000037, 56067},
	}

	for _, rt := range Rem64Tests {
		if rt.hi < rt.y {
			t.Fatalf("Rem64(%v, %v, %v) is not a test with quo overflow", rt.hi, rt.lo, rt.y)
		}
		rem := Rem64(rt.hi, rt.lo, rt.y)
		if rem != rt.rem {
			t.Errorf("Rem64(%v, %v, %v) returned %v, wanted %v",
				rt.hi, rt.lo, rt.y, rem, rt.rem)
		}
	}
}

func BenchmarkAdd(b *testing.B) {
	var z, c uint
	for i := 0; i < b.N; i++ {
		z, c = Add(uint(Input), uint(i), c)
	}
	Output = int(z + c)
}

func BenchmarkAdd32(b *testing.B) {
	var z, c uint32
	for i := 0; i < b.N; i++ {
		z, c = Add32(uint32(Input), uint32(i), c)
	}
	Output = int(z + c)
}

func BenchmarkAdd64(b *testing.B) {
	var z, c uint64
	for i := 0; i < b.N; i++ {
		z, c = Add64(uint64(Input), uint64(i), c)
	}
	Output = int(z + c)
}

func BenchmarkAdd64multiple(b *testing.B) {
	var z0 = uint64(Input)
	var z1 = uint64(Input)
	var z2 = uint64(Input)
	var z3 = uint64(Input)
	for i := 0; i < b.N; i++ {
		var c uint64
		z0, c = Add64(z0, uint64(i), c)
		z1, c = Add64(z1, uint64(i), c)
		z2, c = Add64(z2, uint64(i), c)
		z3, _ = Add64(z3, uint64(i), c)
	}
	Output = int(z0 + z1 + z2 + z3)
}

func BenchmarkSub(b *testing.B) {
	var z, c uint
	for i := 0; i < b.N; i++ {
		z, c = Sub(uint(Input), uint(i), c)
	}
	Output = int(z + c)
}

func BenchmarkSub32(b *testing.B) {
	var z, c uint32
	for i := 0; i < b.N; i++ {
		z, c = Sub32(uint32(Input), uint32(i), c)
	}
	Output = int(z + c)
}

func BenchmarkSub64(b *testing.B) {
	var z, c uint64
	for i := 0; i < b.N; i++ {
		z, c = Sub64(uint64(Input), uint64(i), c)
	}
	Output = int(z + c)
}

func BenchmarkSub64multiple(b *testing.B) {
	var z0 = uint64(Input)
	var z1 = uint64(Input)
	var z2 = uint64(Input)
	var z3 = uint64(Input)
	for i := 0; i < b.N; i++ {
		var c uint64
		z0, c = Sub64(z0, uint64(i), c)
		z1, c = Sub64(z1, uint64(i), c)
		z2, c = Sub64(z2, uint64(i), c)
		z3, _ = Sub64(z3, uint64(i), c)
	}
	Output = int(z0 + z1 + z2 + z3)
}

func BenchmarkMul(b *testing.B) {
	var hi, lo uint
	for i := 0; i < b.N; i++ {
		hi, lo = Mul(uint(Input), uint(i))
	}
	Output = int(hi + lo)
}

func BenchmarkMul32(b *testing.B) {
	var hi, lo uint32
	for i := 0; i < b.N; i++ {
		hi, lo = Mul32(uint32(Input), uint32(i))
	}
	Output = int(hi + lo)
}

func BenchmarkMul64(b *testing.B) {
	var hi, lo uint64
	for i := 0; i < b.N; i++ {
		hi, lo = Mul64(uint64(Input), uint64(i))
	}
	Output = int(hi + lo)
}

func BenchmarkDiv(b *testing.B) {
	var q, r uint
	for i := 0; i < b.N; i++ {
		q, r = Div(1, uint(i), uint(Input))
	}
	Output = int(q + r)
}

func BenchmarkDiv32(b *testing.B) {
	var q, r uint32
	for i := 0; i < b.N; i++ {
		q, r = Div32(1, uint32(i), uint32(Input))
	}
	Output = int(q + r)
}

func BenchmarkDiv64(b *testing.B) {
	var q, r uint64
	for i := 0; i < b.N; i++ {
		q, r = Div64(1, uint64(i), uint64(Input))
	}
	Output = int(q + r)
}

// ----------------------------------------------------------------------------
// Tes
"""




```