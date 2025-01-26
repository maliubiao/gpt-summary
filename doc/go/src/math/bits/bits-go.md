Response:
The user wants to understand the functionality of the `go/src/math/bits/bits.go` file. I need to:
1. **List the functions and their purposes.**  The comments in the code provide a good starting point. I should group them logically (e.g., leading zeros, trailing zeros, etc.).
2. **Infer the overall purpose of the package.** Based on the function names and descriptions, it's clear this package provides bit manipulation utilities.
3. **Provide Go code examples.** For some core functionalities, I should demonstrate how to use the functions with example inputs and outputs.
4. **Address code reasoning (if applicable).** The provided code includes some interesting algorithms (like De Bruijn sequences for trailing zeros). I'll need to explain the logic, potentially with simplified examples.
5. **Discuss command-line arguments (if applicable).**  This file uses `//go:generate`. I need to explain what this means and how the `make_tables.go` script likely works.
6. **Point out common mistakes.** Based on the function descriptions and typical bit manipulation pitfalls, I can suggest potential errors.

**Plan:**

1. **Categorize Functions:** Group functions by their primary function (LeadingZeros, TrailingZeros, OnesCount, RotateLeft, Reverse, ReverseBytes, Len, Add, Sub, Mul, Div, Rem).
2. **Describe Each Category:** Briefly explain the purpose of each category and the specific functions within it.
3. **Provide Core Examples:** Focus on demonstrating `LeadingZeros`, `TrailingZeros`, `OnesCount`, and `RotateLeft` with simple `uint` examples.
4. **Explain Trailing Zero Logic:**  Detail how the De Bruijn sequence works in `TrailingZeros`.
5. **Address `go:generate`:** Explain its role and the likely purpose of `make_tables.go`.
6. **Identify Potential Mistakes:** Think about common errors when working with bit manipulation (e.g., misunderstanding the behavior with zero inputs, incorrect rotation amounts).
这个 `go/src/math/bits/bits.go` 文件是 Go 语言标准库中 `math/bits` 包的一部分，它提供了一系列用于对无符号整数类型进行位计数和操作的函数。

**以下是它提供的功能列表：**

1. **前导零计数 (Leading Zeros):**
    *   `LeadingZeros(x uint) int`: 返回 `uint` 类型 `x` 中前导零比特的数量。如果 `x` 为 0，则返回 `UintSize` (32 或 64，取决于系统架构)。
    *   `LeadingZeros8(x uint8) int`: 返回 `uint8` 类型 `x` 中前导零比特的数量。如果 `x` 为 0，则返回 8。
    *   `LeadingZeros16(x uint16) int`: 返回 `uint16` 类型 `x` 中前导零比特的数量。如果 `x` 为 0，则返回 16。
    *   `LeadingZeros32(x uint32) int`: 返回 `uint32` 类型 `x` 中前导零比特的数量。如果 `x` 为 0，则返回 32。
    *   `LeadingZeros64(x uint64) int`: 返回 `uint64` 类型 `x` 中前导零比特的数量。如果 `x` 为 0，则返回 64。

2. **尾部零计数 (Trailing Zeros):**
    *   `TrailingZeros(x uint) int`: 返回 `uint` 类型 `x` 中尾部零比特的数量。如果 `x` 为 0，则返回 `UintSize`。
    *   `TrailingZeros8(x uint8) int`: 返回 `uint8` 类型 `x` 中尾部零比特的数量。如果 `x` 为 0，则返回 8。
    *   `TrailingZeros16(x uint16) int`: 返回 `uint16` 类型 `x` 中尾部零比特的数量。如果 `x` 为 0，则返回 16。
    *   `TrailingZeros32(x uint32) int`: 返回 `uint32` 类型 `x` 中尾部零比特的数量。如果 `x` 为 0，则返回 32。
    *   `TrailingZeros64(x uint64) int`: 返回 `uint64` 类型 `x` 中尾部零比特的数量。如果 `x` 为 0，则返回 64。

3. **置位比特计数 (Ones Count):**
    *   `OnesCount(x uint) int`: 返回 `uint` 类型 `x` 中置位比特 (值为 1 的比特) 的数量，也称为“人口计数”。
    *   `OnesCount8(x uint8) int`: 返回 `uint8` 类型 `x` 中置位比特的数量。
    *   `OnesCount16(x uint16) int`: 返回 `uint16` 类型 `x` 中置位比特的数量。
    *   `OnesCount32(x uint32) int`: 返回 `uint32` 类型 `x` 中置位比特的数量。
    *   `OnesCount64(x uint64) int`: 返回 `uint64` 类型 `x` 中置位比特的数量。

4. **循环左移 (Rotate Left):**
    *   `RotateLeft(x uint, k int) uint`: 返回将 `uint` 类型的 `x` 循环左移 `k` 位后的值。要循环右移 `k` 位，可以调用 `RotateLeft(x, -k)`。
    *   `RotateLeft8(x uint8, k int) uint8`: 返回将 `uint8` 类型的 `x` 循环左移 `k` 位后的值。
    *   `RotateLeft16(x uint16, k int) uint16`: 返回将 `uint16` 类型的 `x` 循环左移 `k` 位后的值。
    *   `RotateLeft32(x uint32, k int) uint32`: 返回将 `uint32` 类型的 `x` 循环左移 `k` 位后的值。
    *   `RotateLeft64(x uint64, k int) uint64`: 返回将 `uint64` 类型的 `x` 循环左移 `k` 位后的值。

5. **比特反转 (Reverse):**
    *   `Reverse(x uint) uint`: 返回 `uint` 类型的 `x`，其所有比特的顺序都被反转。
    *   `Reverse8(x uint8) uint8`: 返回 `uint8` 类型的 `x`，其所有比特的顺序都被反转。
    *   `Reverse16(x uint16) uint16`: 返回 `uint16` 类型的 `x`，其所有比特的顺序都被反转。
    *   `Reverse32(x uint32) uint32`: 返回 `uint32` 类型的 `x`，其所有比特的顺序都被反转。
    *   `Reverse64(x uint64) uint64`: 返回 `uint64` 类型的 `x`，其所有比特的顺序都被反转。

6. **字节反转 (Reverse Bytes):**
    *   `ReverseBytes(x uint) uint`: 返回 `uint` 类型的 `x`，其所有字节的顺序都被反转。
    *   `ReverseBytes16(x uint16) uint16`: 返回 `uint16` 类型的 `x`，其所有字节的顺序都被反转。
    *   `ReverseBytes32(x uint32) uint32`: 返回 `uint32` 类型的 `x`，其所有字节的顺序都被反转。
    *   `ReverseBytes64(x uint64) uint64`: 返回 `uint64` 类型的 `x`，其所有字节的顺序都被反转。

7. **长度 (Length):**
    *   `Len(x uint) int`: 返回表示 `uint` 类型的 `x` 所需的最小比特数。如果 `x` 为 0，则结果为 0。
    *   `Len8(x uint8) int`: 返回表示 `uint8` 类型的 `x` 所需的最小比特数。如果 `x` 为 0，则结果为 0。
    *   `Len16(x uint16) int`: 返回表示 `uint16` 类型的 `x` 所需的最小比特数。如果 `x` 为 0，则结果为 0。
    *   `Len32(x uint32) int`: 返回表示 `uint32` 类型的 `x` 所需的最小比特数。如果 `x` 为 0，则结果为 0。
    *   `Len64(x uint64) int`: 返回表示 `uint64` 类型的 `x` 所需的最小比特数。如果 `x` 为 0，则结果为 0。

8. **带进位的加法 (Add with Carry):**
    *   `Add(x, y, carry uint) (sum, carryOut uint)`: 返回 `x`、`y` 和 `carry` 的和，其中 `carry` 必须是 0 或 1。返回结果的和 `sum` 和进位 `carryOut` (0 或 1)。
    *   `Add32(x, y, carry uint32) (sum, carryOut uint32)`: 返回 `uint32` 类型的 `x`、`y` 和 `carry` 的和。
    *   `Add64(x, y, carry uint64) (sum, carryOut uint64)`: 返回 `uint64` 类型的 `x`、`y` 和 `carry` 的和。

9. **带借位的减法 (Subtract with Borrow):**
    *   `Sub(x, y, borrow uint) (diff, borrowOut uint)`: 返回 `x`、`y` 和 `borrow` 的差，其中 `borrow` 必须是 0 或 1。返回结果的差 `diff` 和借位 `borrowOut` (0 或 1)。
    *   `Sub32(x, y, borrow uint32) (diff, borrowOut uint32)`: 返回 `uint32` 类型的 `x`、`y` 和 `borrow` 的差。
    *   `Sub64(x, y, borrow uint64) (diff, borrowOut uint64)`: 返回 `uint64` 类型的 `x`、`y` 和 `borrow` 的差。

10. **全宽乘法 (Full-width Multiply):**
    *   `Mul(x, y uint) (hi, lo uint)`: 返回 `uint` 类型的 `x` 和 `y` 的全宽乘积。高位部分返回在 `hi` 中，低位部分返回在 `lo` 中。
    *   `Mul32(x, y uint32) (hi, lo uint32)`: 返回 `uint32` 类型的 `x` 和 `y` 的 64 位乘积。
    *   `Mul64(x, y uint64) (hi, lo uint64)`: 返回 `uint64` 类型的 `x` 和 `y` 的 128 位乘积。

11. **全宽除法 (Full-width Divide):**
    *   `Div(hi, lo, y uint) (quo, rem uint)`: 返回由高位 `hi` 和低位 `lo` 组成的被除数除以 `y` 的商 `quo` 和余数 `rem`。如果 `y` 为 0 或 `y <= hi` (导致商溢出) 时会 panic。
    *   `Div32(hi, lo, y uint32) (quo, rem uint32)`: 返回 `uint32` 类型的全宽除法结果。
    *   `Div64(hi, lo, y uint64) (quo, rem uint64)`: 返回 `uint64` 类型的全宽除法结果。

12. **全宽求余 (Full-width Remainder):**
    *   `Rem(hi, lo, y uint) uint`: 返回由高位 `hi` 和低位 `lo` 组成的被除数除以 `y` 的余数。如果 `y` 为 0 会 panic，但不会像 `Div` 那样在商溢出时 panic。
    *   `Rem32(hi, lo, y uint32) uint32`: 返回 `uint32` 类型的全宽求余结果。
    *   `Rem64(hi, lo, y uint64) uint64`: 返回 `uint64` 类型的全宽求余结果。

**这个包是 Go 语言进行底层位操作的基础工具集。**  它可以用于实现各种算法，例如哈希函数、数据压缩、加密算法等。

**以下是用 Go 代码举例说明其中一些功能的实现：**

```go
package main

import (
	"fmt"
	"math/bits"
)

func main() {
	var x uint = 12 // 二进制: 1100
	var y uint32 = 7 // 二进制: 0111

	// 前导零计数
	leadingZeros := bits.LeadingZeros(x)
	leadingZeros32 := bits.LeadingZeros32(y)
	fmt.Printf("Leading zeros of %b (uint): %d\n", x, leadingZeros) // 假设 UintSize 为 64，输出: Leading zeros of 1100 (uint): 60
	fmt.Printf("Leading zeros of %b (uint32): %d\n", y, leadingZeros32) // 输出: Leading zeros of 111 (uint32): 29

	// 尾部零计数
	trailingZeros := bits.TrailingZeros(x)
	trailingZeros32 := bits.TrailingZeros32(y)
	fmt.Printf("Trailing zeros of %b (uint): %d\n", x, trailingZeros) // 输出: Trailing zeros of 1100 (uint): 2
	fmt.Printf("Trailing zeros of %b (uint32): %d\n", y, trailingZeros32) // 输出: Trailing zeros of 111 (uint32): 0

	// 置位比特计数
	onesCount := bits.OnesCount(x)
	onesCount32 := bits.OnesCount32(y)
	fmt.Printf("Ones count of %b (uint): %d\n", x, onesCount) // 输出: Ones count of 1100 (uint): 2
	fmt.Printf("Ones count of %b (uint32): %d\n", y, onesCount32) // 输出: Ones count of 111 (uint32): 3

	// 循环左移
	rotatedLeft := bits.RotateLeft(x, 1)
	rotatedLeft32 := bits.RotateLeft32(y, 2)
	fmt.Printf("Rotate left of %b (uint) by 1: %b\n", x, rotatedLeft) // 输出: Rotate left of 1100 (uint) by 1: 11000
	fmt.Printf("Rotate left of %b (uint32) by 2: %b\n", y, rotatedLeft32) // 输出: Rotate left of 111 (uint32) by 2: 11100

	// 比特反转
	reversed := bits.Reverse(x)
	reversed32 := bits.Reverse32(y)
	fmt.Printf("Reverse bits of %b (uint): %b\n", x, reversed) // 输出取决于 UintSize，例如 64 位系统: Reverse bits of 1100 (uint): 0011000000000000000000000000000000000000000000000000000000000011
	fmt.Printf("Reverse bits of %b (uint32): %b\n", y, reversed32) // 输出: Reverse bits of 111 (uint32): 11100000000000000000000000000000

	// 长度
	length := bits.Len(x)
	length32 := bits.Len32(y)
	fmt.Printf("Length of %b (uint): %d\n", x, length) // 输出: Length of 1100 (uint): 4
	fmt.Printf("Length of %b (uint32): %d\n", y, length32) // 输出: Length of 111 (uint32): 3
}
```

**代码推理 - 尾部零计数 (Trailing Zeros):**

`TrailingZeros` 函数使用了 **De Bruijn 序列** 的技巧来高效地计算尾部零的个数。

**假设输入:** `x = 8` (二进制 `1000`)

1. **`x & -x`:**  这个操作会提取出最右边的置位比特。对于 `x = 8`，`-x` 的二进制补码是 `...11111000` (假设无限位)，`x & -x` 结果是 `1000`。
2. **乘法:** 将结果乘以一个特定的 De Bruijn 常数 (`deBruijn32` 或 `deBruijn64`)。例如，对于 `TrailingZeros32`，乘以 `0x077CB531`。
    `1000` (8) * `0x077CB531` = `0x3B95A98` (二进制表示会比较长)。
3. **右移:** 将乘积向右移动 `32-5` (或 `64-6`) 位。对于 32 位，右移 `27` 位。
    假设乘积的二进制表示是 `...0000001110111001011010011000`，右移 27 位后，会保留右边 5 位的子串，这个子串的模式会唯一对应于尾部零的个数。
4. **查表:** 将右移后的结果作为索引，在预先计算好的 `deBruijn32tab` 或 `deBruijn64tab` 表中查找对应的值。这个表中存储了尾部零的个数。对于 `x = 8`，最终索引会指向值为 `3` 的元素，因为 `8` 有 3 个尾部零。

**假设输入:** `x = 12` (二进制 `1100`)

1. **`x & -x`:** `1100 & ...11110100` = `0100` (4)
2. **乘法:** `4` * `0x077CB531` = `0x1ED2E544`
3. **右移:** `0x1ED2E544` 右移 27 位，结果取决于具体的二进制表示，但最终会指向 `deBruijn32tab` 中索引为 `2` 的位置，因为 `12` 有 2 个尾部零。

**命令行参数处理：**

这个文件中包含 `//go:generate go run make_tables.go` 注释。 这被称为 **`go generate` 指令**。

*   `go generate` 是 Go 语言提供的一个工具，用于在构建程序之前生成代码。
*   `//go:generate` 注释告诉 `go generate` 工具需要执行的命令。
*   在这个例子中，它指示 `go generate` 运行当前目录下的 `make_tables.go` 程序。

**`make_tables.go` 的作用很可能是生成查找表 (`deBruijn32tab`, `deBruijn64tab`, `pop8tab`, `rev8tab`, `len8tab`) 的 Go 代码。** 这些查找表用于提高某些位操作函数的性能。 `make_tables.go` 可能会使用循环或者数学公式预先计算好这些表格的值，然后将其输出为 Go 源代码，最终会被编译到 `bits.go` 包中。

**使用者易犯错的点：**

1. **对零值的处理：** 许多函数（如 `LeadingZeros`，`TrailingZeros`，`Len`）对于输入为零的情况有特殊的返回值（例如，`LeadingZeros(0)` 返回 `UintSize`）。使用者可能会忘记处理这种情况，导致逻辑错误。

    ```go
    package main

    import (
    	"fmt"
    	"math/bits"
    )

    func main() {
    	var zero uint = 0
    	lz := bits.LeadingZeros(zero)
    	fmt.Println(lz) // 输出可能是 64 或 32，取决于系统架构，而不是 0
    }
    ```

2. **循环移位的方向：** `RotateLeft` 函数的第二个参数 `k` 为正数时表示左移，负数表示右移。使用者可能会混淆。

    ```go
    package main

    import (
    	"fmt"
    	"math/bits"
    )

    func main() {
    	var x uint8 = 1 // 00000001
    	rotated := bits.RotateLeft8(x, 1)
    	fmt.Printf("%08b\n", rotated) // 输出: 00000010 (左移)

    	rotatedRight := bits.RotateLeft8(x, -1)
    	fmt.Printf("%08b\n", rotatedRight) // 输出: 10000000 (右移)
    }
    ```

3. **全宽除法的溢出 panic：**  `Div` 函数在除数为零或者结果会溢出时会 panic。使用者在调用 `Div` 时需要确保除数不为零，并且被除数的高位小于除数，否则程序会崩溃。而 `Rem` 函数则不会在溢出时 panic。

    ```go
    package main

    import (
    	"fmt"
    	"math/bits"
    )

    func main() {
    	hi := uint(1)
    	lo := uint(0)
    	divisor := uint(1)

    	// 这会 panic，因为 hi (1) >= divisor (1)
    	// quo, rem := bits.Div(hi, lo, divisor)
    	// fmt.Println(quo, rem)

    	rem := bits.Rem(hi, lo, divisor)
    	fmt.Println(rem) // 输出: 0，Rem 不会 panic
    }
    ```

理解这些细节可以帮助你更有效地使用 `math/bits` 包，并避免常见的错误。

Prompt: 
```
这是路径为go/src/math/bits/bits.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run make_tables.go

// Package bits implements bit counting and manipulation
// functions for the predeclared unsigned integer types.
//
// Functions in this package may be implemented directly by
// the compiler, for better performance. For those functions
// the code in this package will not be used. Which
// functions are implemented by the compiler depends on the
// architecture and the Go release.
package bits

const uintSize = 32 << (^uint(0) >> 63) // 32 or 64

// UintSize is the size of a uint in bits.
const UintSize = uintSize

// --- LeadingZeros ---

// LeadingZeros returns the number of leading zero bits in x; the result is [UintSize] for x == 0.
func LeadingZeros(x uint) int { return UintSize - Len(x) }

// LeadingZeros8 returns the number of leading zero bits in x; the result is 8 for x == 0.
func LeadingZeros8(x uint8) int { return 8 - Len8(x) }

// LeadingZeros16 returns the number of leading zero bits in x; the result is 16 for x == 0.
func LeadingZeros16(x uint16) int { return 16 - Len16(x) }

// LeadingZeros32 returns the number of leading zero bits in x; the result is 32 for x == 0.
func LeadingZeros32(x uint32) int { return 32 - Len32(x) }

// LeadingZeros64 returns the number of leading zero bits in x; the result is 64 for x == 0.
func LeadingZeros64(x uint64) int { return 64 - Len64(x) }

// --- TrailingZeros ---

// See http://keithandkatie.com/keith/papers/debruijn.html
const deBruijn32 = 0x077CB531

var deBruijn32tab = [32]byte{
	0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
	31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9,
}

const deBruijn64 = 0x03f79d71b4ca8b09

var deBruijn64tab = [64]byte{
	0, 1, 56, 2, 57, 49, 28, 3, 61, 58, 42, 50, 38, 29, 17, 4,
	62, 47, 59, 36, 45, 43, 51, 22, 53, 39, 33, 30, 24, 18, 12, 5,
	63, 55, 48, 27, 60, 41, 37, 16, 46, 35, 44, 21, 52, 32, 23, 11,
	54, 26, 40, 15, 34, 20, 31, 10, 25, 14, 19, 9, 13, 8, 7, 6,
}

// TrailingZeros returns the number of trailing zero bits in x; the result is [UintSize] for x == 0.
func TrailingZeros(x uint) int {
	if UintSize == 32 {
		return TrailingZeros32(uint32(x))
	}
	return TrailingZeros64(uint64(x))
}

// TrailingZeros8 returns the number of trailing zero bits in x; the result is 8 for x == 0.
func TrailingZeros8(x uint8) int {
	return int(ntz8tab[x])
}

// TrailingZeros16 returns the number of trailing zero bits in x; the result is 16 for x == 0.
func TrailingZeros16(x uint16) int {
	if x == 0 {
		return 16
	}
	// see comment in TrailingZeros64
	return int(deBruijn32tab[uint32(x&-x)*deBruijn32>>(32-5)])
}

// TrailingZeros32 returns the number of trailing zero bits in x; the result is 32 for x == 0.
func TrailingZeros32(x uint32) int {
	if x == 0 {
		return 32
	}
	// see comment in TrailingZeros64
	return int(deBruijn32tab[(x&-x)*deBruijn32>>(32-5)])
}

// TrailingZeros64 returns the number of trailing zero bits in x; the result is 64 for x == 0.
func TrailingZeros64(x uint64) int {
	if x == 0 {
		return 64
	}
	// If popcount is fast, replace code below with return popcount(^x & (x - 1)).
	//
	// x & -x leaves only the right-most bit set in the word. Let k be the
	// index of that bit. Since only a single bit is set, the value is two
	// to the power of k. Multiplying by a power of two is equivalent to
	// left shifting, in this case by k bits. The de Bruijn (64 bit) constant
	// is such that all six bit, consecutive substrings are distinct.
	// Therefore, if we have a left shifted version of this constant we can
	// find by how many bits it was shifted by looking at which six bit
	// substring ended up at the top of the word.
	// (Knuth, volume 4, section 7.3.1)
	return int(deBruijn64tab[(x&-x)*deBruijn64>>(64-6)])
}

// --- OnesCount ---

const m0 = 0x5555555555555555 // 01010101 ...
const m1 = 0x3333333333333333 // 00110011 ...
const m2 = 0x0f0f0f0f0f0f0f0f // 00001111 ...
const m3 = 0x00ff00ff00ff00ff // etc.
const m4 = 0x0000ffff0000ffff

// OnesCount returns the number of one bits ("population count") in x.
func OnesCount(x uint) int {
	if UintSize == 32 {
		return OnesCount32(uint32(x))
	}
	return OnesCount64(uint64(x))
}

// OnesCount8 returns the number of one bits ("population count") in x.
func OnesCount8(x uint8) int {
	return int(pop8tab[x])
}

// OnesCount16 returns the number of one bits ("population count") in x.
func OnesCount16(x uint16) int {
	return int(pop8tab[x>>8] + pop8tab[x&0xff])
}

// OnesCount32 returns the number of one bits ("population count") in x.
func OnesCount32(x uint32) int {
	return int(pop8tab[x>>24] + pop8tab[x>>16&0xff] + pop8tab[x>>8&0xff] + pop8tab[x&0xff])
}

// OnesCount64 returns the number of one bits ("population count") in x.
func OnesCount64(x uint64) int {
	// Implementation: Parallel summing of adjacent bits.
	// See "Hacker's Delight", Chap. 5: Counting Bits.
	// The following pattern shows the general approach:
	//
	//   x = x>>1&(m0&m) + x&(m0&m)
	//   x = x>>2&(m1&m) + x&(m1&m)
	//   x = x>>4&(m2&m) + x&(m2&m)
	//   x = x>>8&(m3&m) + x&(m3&m)
	//   x = x>>16&(m4&m) + x&(m4&m)
	//   x = x>>32&(m5&m) + x&(m5&m)
	//   return int(x)
	//
	// Masking (& operations) can be left away when there's no
	// danger that a field's sum will carry over into the next
	// field: Since the result cannot be > 64, 8 bits is enough
	// and we can ignore the masks for the shifts by 8 and up.
	// Per "Hacker's Delight", the first line can be simplified
	// more, but it saves at best one instruction, so we leave
	// it alone for clarity.
	const m = 1<<64 - 1
	x = x>>1&(m0&m) + x&(m0&m)
	x = x>>2&(m1&m) + x&(m1&m)
	x = (x>>4 + x) & (m2 & m)
	x += x >> 8
	x += x >> 16
	x += x >> 32
	return int(x) & (1<<7 - 1)
}

// --- RotateLeft ---

// RotateLeft returns the value of x rotated left by (k mod [UintSize]) bits.
// To rotate x right by k bits, call RotateLeft(x, -k).
//
// This function's execution time does not depend on the inputs.
func RotateLeft(x uint, k int) uint {
	if UintSize == 32 {
		return uint(RotateLeft32(uint32(x), k))
	}
	return uint(RotateLeft64(uint64(x), k))
}

// RotateLeft8 returns the value of x rotated left by (k mod 8) bits.
// To rotate x right by k bits, call RotateLeft8(x, -k).
//
// This function's execution time does not depend on the inputs.
func RotateLeft8(x uint8, k int) uint8 {
	const n = 8
	s := uint(k) & (n - 1)
	return x<<s | x>>(n-s)
}

// RotateLeft16 returns the value of x rotated left by (k mod 16) bits.
// To rotate x right by k bits, call RotateLeft16(x, -k).
//
// This function's execution time does not depend on the inputs.
func RotateLeft16(x uint16, k int) uint16 {
	const n = 16
	s := uint(k) & (n - 1)
	return x<<s | x>>(n-s)
}

// RotateLeft32 returns the value of x rotated left by (k mod 32) bits.
// To rotate x right by k bits, call RotateLeft32(x, -k).
//
// This function's execution time does not depend on the inputs.
func RotateLeft32(x uint32, k int) uint32 {
	const n = 32
	s := uint(k) & (n - 1)
	return x<<s | x>>(n-s)
}

// RotateLeft64 returns the value of x rotated left by (k mod 64) bits.
// To rotate x right by k bits, call RotateLeft64(x, -k).
//
// This function's execution time does not depend on the inputs.
func RotateLeft64(x uint64, k int) uint64 {
	const n = 64
	s := uint(k) & (n - 1)
	return x<<s | x>>(n-s)
}

// --- Reverse ---

// Reverse returns the value of x with its bits in reversed order.
func Reverse(x uint) uint {
	if UintSize == 32 {
		return uint(Reverse32(uint32(x)))
	}
	return uint(Reverse64(uint64(x)))
}

// Reverse8 returns the value of x with its bits in reversed order.
func Reverse8(x uint8) uint8 {
	return rev8tab[x]
}

// Reverse16 returns the value of x with its bits in reversed order.
func Reverse16(x uint16) uint16 {
	return uint16(rev8tab[x>>8]) | uint16(rev8tab[x&0xff])<<8
}

// Reverse32 returns the value of x with its bits in reversed order.
func Reverse32(x uint32) uint32 {
	const m = 1<<32 - 1
	x = x>>1&(m0&m) | x&(m0&m)<<1
	x = x>>2&(m1&m) | x&(m1&m)<<2
	x = x>>4&(m2&m) | x&(m2&m)<<4
	return ReverseBytes32(x)
}

// Reverse64 returns the value of x with its bits in reversed order.
func Reverse64(x uint64) uint64 {
	const m = 1<<64 - 1
	x = x>>1&(m0&m) | x&(m0&m)<<1
	x = x>>2&(m1&m) | x&(m1&m)<<2
	x = x>>4&(m2&m) | x&(m2&m)<<4
	return ReverseBytes64(x)
}

// --- ReverseBytes ---

// ReverseBytes returns the value of x with its bytes in reversed order.
//
// This function's execution time does not depend on the inputs.
func ReverseBytes(x uint) uint {
	if UintSize == 32 {
		return uint(ReverseBytes32(uint32(x)))
	}
	return uint(ReverseBytes64(uint64(x)))
}

// ReverseBytes16 returns the value of x with its bytes in reversed order.
//
// This function's execution time does not depend on the inputs.
func ReverseBytes16(x uint16) uint16 {
	return x>>8 | x<<8
}

// ReverseBytes32 returns the value of x with its bytes in reversed order.
//
// This function's execution time does not depend on the inputs.
func ReverseBytes32(x uint32) uint32 {
	const m = 1<<32 - 1
	x = x>>8&(m3&m) | x&(m3&m)<<8
	return x>>16 | x<<16
}

// ReverseBytes64 returns the value of x with its bytes in reversed order.
//
// This function's execution time does not depend on the inputs.
func ReverseBytes64(x uint64) uint64 {
	const m = 1<<64 - 1
	x = x>>8&(m3&m) | x&(m3&m)<<8
	x = x>>16&(m4&m) | x&(m4&m)<<16
	return x>>32 | x<<32
}

// --- Len ---

// Len returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len(x uint) int {
	if UintSize == 32 {
		return Len32(uint32(x))
	}
	return Len64(uint64(x))
}

// Len8 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len8(x uint8) int {
	return int(len8tab[x])
}

// Len16 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len16(x uint16) (n int) {
	if x >= 1<<8 {
		x >>= 8
		n = 8
	}
	return n + int(len8tab[x])
}

// Len32 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len32(x uint32) (n int) {
	if x >= 1<<16 {
		x >>= 16
		n = 16
	}
	if x >= 1<<8 {
		x >>= 8
		n += 8
	}
	return n + int(len8tab[x])
}

// Len64 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
func Len64(x uint64) (n int) {
	if x >= 1<<32 {
		x >>= 32
		n = 32
	}
	if x >= 1<<16 {
		x >>= 16
		n += 16
	}
	if x >= 1<<8 {
		x >>= 8
		n += 8
	}
	return n + int(len8tab[x])
}

// --- Add with carry ---

// Add returns the sum with carry of x, y and carry: sum = x + y + carry.
// The carry input must be 0 or 1; otherwise the behavior is undefined.
// The carryOut output is guaranteed to be 0 or 1.
//
// This function's execution time does not depend on the inputs.
func Add(x, y, carry uint) (sum, carryOut uint) {
	if UintSize == 32 {
		s32, c32 := Add32(uint32(x), uint32(y), uint32(carry))
		return uint(s32), uint(c32)
	}
	s64, c64 := Add64(uint64(x), uint64(y), uint64(carry))
	return uint(s64), uint(c64)
}

// Add32 returns the sum with carry of x, y and carry: sum = x + y + carry.
// The carry input must be 0 or 1; otherwise the behavior is undefined.
// The carryOut output is guaranteed to be 0 or 1.
//
// This function's execution time does not depend on the inputs.
func Add32(x, y, carry uint32) (sum, carryOut uint32) {
	sum64 := uint64(x) + uint64(y) + uint64(carry)
	sum = uint32(sum64)
	carryOut = uint32(sum64 >> 32)
	return
}

// Add64 returns the sum with carry of x, y and carry: sum = x + y + carry.
// The carry input must be 0 or 1; otherwise the behavior is undefined.
// The carryOut output is guaranteed to be 0 or 1.
//
// This function's execution time does not depend on the inputs.
func Add64(x, y, carry uint64) (sum, carryOut uint64) {
	sum = x + y + carry
	// The sum will overflow if both top bits are set (x & y) or if one of them
	// is (x | y), and a carry from the lower place happened. If such a carry
	// happens, the top bit will be 1 + 0 + 1 = 0 (&^ sum).
	carryOut = ((x & y) | ((x | y) &^ sum)) >> 63
	return
}

// --- Subtract with borrow ---

// Sub returns the difference of x, y and borrow: diff = x - y - borrow.
// The borrow input must be 0 or 1; otherwise the behavior is undefined.
// The borrowOut output is guaranteed to be 0 or 1.
//
// This function's execution time does not depend on the inputs.
func Sub(x, y, borrow uint) (diff, borrowOut uint) {
	if UintSize == 32 {
		d32, b32 := Sub32(uint32(x), uint32(y), uint32(borrow))
		return uint(d32), uint(b32)
	}
	d64, b64 := Sub64(uint64(x), uint64(y), uint64(borrow))
	return uint(d64), uint(b64)
}

// Sub32 returns the difference of x, y and borrow, diff = x - y - borrow.
// The borrow input must be 0 or 1; otherwise the behavior is undefined.
// The borrowOut output is guaranteed to be 0 or 1.
//
// This function's execution time does not depend on the inputs.
func Sub32(x, y, borrow uint32) (diff, borrowOut uint32) {
	diff = x - y - borrow
	// The difference will underflow if the top bit of x is not set and the top
	// bit of y is set (^x & y) or if they are the same (^(x ^ y)) and a borrow
	// from the lower place happens. If that borrow happens, the result will be
	// 1 - 1 - 1 = 0 - 0 - 1 = 1 (& diff).
	borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 31
	return
}

// Sub64 returns the difference of x, y and borrow: diff = x - y - borrow.
// The borrow input must be 0 or 1; otherwise the behavior is undefined.
// The borrowOut output is guaranteed to be 0 or 1.
//
// This function's execution time does not depend on the inputs.
func Sub64(x, y, borrow uint64) (diff, borrowOut uint64) {
	diff = x - y - borrow
	// See Sub32 for the bit logic.
	borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 63
	return
}

// --- Full-width multiply ---

// Mul returns the full-width product of x and y: (hi, lo) = x * y
// with the product bits' upper half returned in hi and the lower
// half returned in lo.
//
// This function's execution time does not depend on the inputs.
func Mul(x, y uint) (hi, lo uint) {
	if UintSize == 32 {
		h, l := Mul32(uint32(x), uint32(y))
		return uint(h), uint(l)
	}
	h, l := Mul64(uint64(x), uint64(y))
	return uint(h), uint(l)
}

// Mul32 returns the 64-bit product of x and y: (hi, lo) = x * y
// with the product bits' upper half returned in hi and the lower
// half returned in lo.
//
// This function's execution time does not depend on the inputs.
func Mul32(x, y uint32) (hi, lo uint32) {
	tmp := uint64(x) * uint64(y)
	hi, lo = uint32(tmp>>32), uint32(tmp)
	return
}

// Mul64 returns the 128-bit product of x and y: (hi, lo) = x * y
// with the product bits' upper half returned in hi and the lower
// half returned in lo.
//
// This function's execution time does not depend on the inputs.
func Mul64(x, y uint64) (hi, lo uint64) {
	const mask32 = 1<<32 - 1
	x0 := x & mask32
	x1 := x >> 32
	y0 := y & mask32
	y1 := y >> 32
	w0 := x0 * y0
	t := x1*y0 + w0>>32
	w1 := t & mask32
	w2 := t >> 32
	w1 += x0 * y1
	hi = x1*y1 + w2 + w1>>32
	lo = x * y
	return
}

// --- Full-width divide ---

// Div returns the quotient and remainder of (hi, lo) divided by y:
// quo = (hi, lo)/y, rem = (hi, lo)%y with the dividend bits' upper
// half in parameter hi and the lower half in parameter lo.
// Div panics for y == 0 (division by zero) or y <= hi (quotient overflow).
func Div(hi, lo, y uint) (quo, rem uint) {
	if UintSize == 32 {
		q, r := Div32(uint32(hi), uint32(lo), uint32(y))
		return uint(q), uint(r)
	}
	q, r := Div64(uint64(hi), uint64(lo), uint64(y))
	return uint(q), uint(r)
}

// Div32 returns the quotient and remainder of (hi, lo) divided by y:
// quo = (hi, lo)/y, rem = (hi, lo)%y with the dividend bits' upper
// half in parameter hi and the lower half in parameter lo.
// Div32 panics for y == 0 (division by zero) or y <= hi (quotient overflow).
func Div32(hi, lo, y uint32) (quo, rem uint32) {
	if y != 0 && y <= hi {
		panic(overflowError)
	}
	z := uint64(hi)<<32 | uint64(lo)
	quo, rem = uint32(z/uint64(y)), uint32(z%uint64(y))
	return
}

// Div64 returns the quotient and remainder of (hi, lo) divided by y:
// quo = (hi, lo)/y, rem = (hi, lo)%y with the dividend bits' upper
// half in parameter hi and the lower half in parameter lo.
// Div64 panics for y == 0 (division by zero) or y <= hi (quotient overflow).
func Div64(hi, lo, y uint64) (quo, rem uint64) {
	if y == 0 {
		panic(divideError)
	}
	if y <= hi {
		panic(overflowError)
	}

	// If high part is zero, we can directly return the results.
	if hi == 0 {
		return lo / y, lo % y
	}

	s := uint(LeadingZeros64(y))
	y <<= s

	const (
		two32  = 1 << 32
		mask32 = two32 - 1
	)
	yn1 := y >> 32
	yn0 := y & mask32
	un32 := hi<<s | lo>>(64-s)
	un10 := lo << s
	un1 := un10 >> 32
	un0 := un10 & mask32
	q1 := un32 / yn1
	rhat := un32 - q1*yn1

	for q1 >= two32 || q1*yn0 > two32*rhat+un1 {
		q1--
		rhat += yn1
		if rhat >= two32 {
			break
		}
	}

	un21 := un32*two32 + un1 - q1*y
	q0 := un21 / yn1
	rhat = un21 - q0*yn1

	for q0 >= two32 || q0*yn0 > two32*rhat+un0 {
		q0--
		rhat += yn1
		if rhat >= two32 {
			break
		}
	}

	return q1*two32 + q0, (un21*two32 + un0 - q0*y) >> s
}

// Rem returns the remainder of (hi, lo) divided by y. Rem panics for
// y == 0 (division by zero) but, unlike Div, it doesn't panic on a
// quotient overflow.
func Rem(hi, lo, y uint) uint {
	if UintSize == 32 {
		return uint(Rem32(uint32(hi), uint32(lo), uint32(y)))
	}
	return uint(Rem64(uint64(hi), uint64(lo), uint64(y)))
}

// Rem32 returns the remainder of (hi, lo) divided by y. Rem32 panics
// for y == 0 (division by zero) but, unlike [Div32], it doesn't panic
// on a quotient overflow.
func Rem32(hi, lo, y uint32) uint32 {
	return uint32((uint64(hi)<<32 | uint64(lo)) % uint64(y))
}

// Rem64 returns the remainder of (hi, lo) divided by y. Rem64 panics
// for y == 0 (division by zero) but, unlike [Div64], it doesn't panic
// on a quotient overflow.
func Rem64(hi, lo, y uint64) uint64 {
	// We scale down hi so that hi < y, then use Div64 to compute the
	// rem with the guarantee that it won't panic on quotient overflow.
	// Given that
	//   hi ≡ hi%y    (mod y)
	// we have
	//   hi<<64 + lo ≡ (hi%y)<<64 + lo    (mod y)
	_, rem := Div64(hi%y, lo, y)
	return rem
}

"""



```