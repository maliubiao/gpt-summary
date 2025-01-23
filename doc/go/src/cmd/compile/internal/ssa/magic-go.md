Response: My thinking process to answer the request about `go/src/cmd/compile/internal/ssa/magic.go` would go like this:

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet and explain its functionality, particularly focusing on the "magic" it performs, provide examples, and identify potential pitfalls.

2. **Initial Scan and Keyword Recognition:** I'd quickly scan the code for keywords and recognizable patterns. I see comments mentioning division, multiplication, shifts, "strength reduction," "magic," and references to papers like the GMP library's division by constant technique and "Hacker's Delight."  This immediately tells me the code is about optimizing division and divisibility checks involving constants.

3. **Break Down by Functionality (Major Sections):** The code is naturally divided into sections based on the type of operation and data (unsigned vs. signed):
    * **Unsigned Division (`umagic`)**:  This section deals with optimizing `x / c` where `x` and `c` are unsigned.
    * **Signed Division (`smagic`)**:  This section focuses on optimizing `x / c` where `x` is signed and `c` is positive.
    * **Unsigned Divisibility (`udivisible`)**: This section tackles optimizing checks for `x % c == 0` for unsigned `x` and `c`.
    * **Signed Divisibility (`sdivisible`)**:  This handles the optimization of `x % c == 0` for signed `x` and positive `c`.

4. **Analyze Each Section Deeply:**  I'd go through each of these sections, paying close attention to the comments and formulas. The comments explain the mathematical reasoning behind the optimization techniques.

    * **Unsigned Division (`umagic`):** The core idea is to replace division by a constant with multiplication and shifts. I'd trace the mathematical derivation to understand how the magic constants `m` and `s` are calculated. The cases (m even, c even, and neither) are important implementation details.

    * **Signed Division (`smagic`):** Similar to unsigned division, but with adjustments for signed numbers and the need to handle negative inputs. I'd focus on the correction factor added when `x` is negative.

    * **Unsigned Divisibility (`udivisible`):** This section uses modular inverses and bit rotations. The key insight is transforming the divisibility check into a multiplication and comparison. The reference to "Hacker's Delight" is a strong clue about the techniques used.

    * **Signed Divisibility (`sdivisible`):** Builds on the unsigned divisibility by incorporating the handling of signed numbers, again using "Hacker's Delight" theorems (ZRU/ZRS) involving bit rotations and adjustments.

5. **Identify Key Functions and Data Structures:**  I'd note the important functions:
    * `umagicOK/smagicOK/udivisibleOK/sdivisibleOK`: These determine *whether* the optimization should be applied. They check for trivial cases (division by 0, powers of 2).
    * `umagic/smagic/udivisible/sdivisible`: These functions calculate the "magic" constants needed for the optimized operations.
    * The `umagicData`/`smagicData`/`udivisibleData`/`sdivisibleData` structs hold these precomputed constants.

6. **Infer Go Language Feature Implementation:** Based on the context (the `cmd/compile` package, specifically `internal/ssa`), I'd infer that this code is part of the Go compiler's optimization pipeline. It's used during the static single assignment (SSA) phase to replace expensive division and modulo operations with cheaper sequences of multiplications, shifts, and additions when the divisor is a constant.

7. **Construct Go Code Examples:**  To illustrate the functionality, I'd create simple Go examples that demonstrate the original division/modulo operations and how the compiler (using these "magic" techniques) would transform them. This involves showing the original Go code and then the equivalent sequence of operations using the calculated magic constants. I'd make sure to include examples for both unsigned and signed cases.

8. **Address Command-Line Parameters:** Since this code is part of the compiler's internal workings, it's unlikely to be directly influenced by command-line flags in a typical compilation. However, I would mention compiler optimization flags (like `-gcflags`) that might indirectly influence whether these optimizations are applied.

9. **Identify Potential Pitfalls:** The most common mistake would be trying to apply these transformations manually without understanding the underlying mathematics and the specific conditions under which they are valid. Incorrectly calculating or applying the magic constants would lead to wrong results. I'd emphasize that this is a compiler optimization and not something typical Go programmers should implement themselves.

10. **Structure the Answer:** Finally, I'd organize the information clearly:
    * Start with a high-level summary of the file's purpose.
    * Explain the functionality, breaking it down by unsigned/signed division/divisibility.
    * Provide concrete Go code examples to illustrate the transformations.
    * Discuss the role of command-line parameters (or the lack thereof).
    * Highlight potential pitfalls and common mistakes.

Throughout this process, I'd constantly refer back to the code and comments to ensure accuracy and completeness. The mathematical formulas and explanations in the comments are crucial for understanding the "magic" being performed.
`go/src/cmd/compile/internal/ssa/magic.go` 的 Go 语言实现部分，主要功能是**在编译期间对整数的除法和取模运算进行优化，特别是当除数是常量时**。  这种优化被称为**强度削减 (strength reduction)**，即将耗时的操作（如除法）替换为更廉价的操作序列（如乘法、移位和加法）。

以下是该文件的具体功能分解：

**1. 无符号整数除法优化 (`umagic`)**

* **功能:** 当除数 `c` 是常量时，将无符号整数除法 `x / c` 替换为等价的乘法和移位操作。这避免了使用机器的除法指令，因为除法指令通常比较慢。
* **实现原理:**  该部分代码基于 GMP 库中的优化技术，预先计算一个魔术数字 `m` 和一个移位量 `s`。对于无符号除法，它利用了以下公式：
    ```
    floor(x / c) = floor(x * m / 2^(n+s))
    ```
    其中 `n` 是操作数的位宽。
* **具体步骤:**
    * `umagicOK(n, c)`:  判断是否应该对一个 `n` 位的无符号除法除以常量 `c` 进行强度削减。 只有当 `c` 不是 0 或 2 的幂时才进行优化。
    * `umagic(n, c)`: 计算进行优化的魔术常量 `m` 和移位量 `s`。
    * 针对不同位宽 (`uint8`, `uint16`, `uint32`, `uint64`) 提供了辅助函数 `umagic8`, `umagic16`, `umagic32`, `umagic64`。
* **代码推理与示例:**
    * **假设输入:**  `n = 32`, `c = 7`
    * **计算过程 (简化):**
        * `s = ceil(log2(7)) = 3`
        * `m = ceil(2^(32+3) / 7) - 2^32`  (实际计算使用 `big.Int` 进行高精度运算)
    * **输出:** `umagicData{s: 3, m: 计算出的m值}`
    * **Go 代码示例:**  假设 `umagic(32, 7)` 返回 `data`。  那么，在编译期间，表达式 `uint32(x) / 7` 可能会被转化为类似以下的操作（具体指令会根据架构有所不同）：
        ```go
        // 原始代码
        quotient := uint32(x) / 7

        // 优化后的代码 (大致)
        tmp := uint64(x) * (data.m + (1 << 32)) // 乘以 m + 2^n
        quotient = uint32(tmp >> (32 + data.s))    // 右移 n + s 位
        ```
* **使用者易犯错的点:**  普通 Go 程序员不会直接调用这些函数，这是编译器内部的优化。  如果尝试手动实现类似的优化，可能会因为精度问题或对不同情况的处理不当而引入错误。

**2. 有符号整数除法优化 (`smagic`)**

* **功能:** 当除数 `c` 是正的常量时，将有符号整数除法 `x / c` 替换为等价的乘法和移位操作。
* **实现原理:** 类似于无符号除法，但需要处理符号。对于负除数，可以先转化为正除数的情况处理。 公式略有不同，并需要考虑对负数结果的调整。
* **具体步骤:**
    * `smagicOK(n, c)`: 判断是否应该对一个 `n` 位的有符号除法除以常量 `c` 进行强度削减。 只有当 `c` 是正数且不是 0 或 2 的幂时才进行优化。
    * `smagic(n, c)`: 计算进行优化的魔术常量 `m` 和移位量 `s`。
    * 针对不同位宽 (`int8`, `int16`, `int32`, `int64`) 提供了辅助函数 `smagic8`, `smagic16`, `smagic32`, `smagic64`。
* **代码推理与示例:**
    * **假设输入:** `n = 32`, `c = 5`
    * **计算过程 (简化):**
        * `s = ceil(log2(5)) - 1 = 2 - 1 = 1`
        * `m = ceil(2^(32+1) / 5)`
    * **输出:** `smagicData{s: 1, m: 计算出的m值}`
    * **Go 代码示例:** 假设 `smagic(32, 5)` 返回 `data`。 那么，在编译期间，表达式 `int32(x) / 5` 可能会被转化为类似以下的操作：
        ```go
        // 原始代码
        quotient := int32(x) / 5

        // 优化后的代码 (大致)
        tmp := int64(x) * int64(data.m)
        quotient = int32(tmp >> (32 + data.s))
        if x < 0 {
            quotient++
        }
        ```
* **使用者易犯错的点:**  同无符号除法，这是编译器优化。 手动实现时需要仔细处理符号和边界情况。

**3. 无符号整数的整除性检查优化 (`udivisible`)**

* **功能:** 当除数 `c` 是常量时，将无符号整数的整除性检查 `x % c == 0` 替换为更高效的操作。
* **实现原理:** 该部分基于 Granlund 和 Montgomery 的论文以及 "Hacker's Delight" 中的方法，利用模逆元和位旋转。
* **具体步骤:**
    * `udivisibleOK(n, c)`: 判断是否应该对一个 `n` 位的无符号整除性检查除以常量 `c` 进行强度削减。
    * `udivisible(n, c)`: 计算进行优化的常量 `k`, `m`, 和 `max`。
    * 针对不同位宽提供了辅助函数 `udivisible8`, `udivisible16`, `udivisible32`, `udivisible64`。
* **代码推理与示例:**
    * **假设输入:** `n = 32`, `c = 6`
    * **计算过程 (简化):**
        * `k = trailingZeros(6) = 1`
        * `d0 = 6 >> 1 = 3` (奇数部分)
        * 计算 `m` 使得 `m * 3 mod 2^32 == 1` (模逆元)
        * `max = (2^32 - 1) / 6`
    * **输出:** `udivisibleData{k: 1, m: 计算出的m值, max: 计算出的max值}`
    * **Go 代码示例:** 假设 `udivisible(32, 6)` 返回 `data`。 那么，在编译期间，表达式 `uint32(x) % 6 == 0` 可能会被转化为类似以下的操作：
        ```go
        // 原始代码
        isDivisible := uint32(x) % 6 == 0

        // 优化后的代码 (大致)
        tmp := uint32(x) * data.m
        rotated := bits.RotateRight32(tmp, int(data.k))
        isDivisible = rotated <= data.max
        ```
* **使用者易犯错的点:**  同样是编译器优化，手动实现需要对数论和位运算有深入理解。

**4. 有符号整数的整除性检查优化 (`sdivisible`)**

* **功能:** 当除数 `c` 是正的常量时，将有符号整数的整除性检查 `x % c == 0` 替换为更高效的操作。
* **实现原理:**  类似于无符号整除性检查，但需要处理符号，也使用了 "Hacker's Delight" 中的定理。
* **具体步骤:**
    * `sdivisibleOK(n, c)`: 判断是否应该对一个 `n` 位的有符号整除性检查除以常量 `c` 进行强度削减。
    * `sdivisible(n, c)`: 计算进行优化的常量 `k`, `m`, `a`, 和 `max`。
    * 针对不同位宽提供了辅助函数 `sdivisible8`, `sdivisible16`, `sdivisible32`, `sdivisible64`。
* **代码推理与示例:**
    * **假设输入:** `n = 32`, `c = 10`
    * **计算过程 (简化):**
        * `k = trailingZeros(10) = 1`
        * `d0 = 10 >> 1 = 5`
        * 计算 `m` 使得 `m * 5 mod 2^32 == 1`
        * 计算 `a` 和 `max`
    * **输出:** `sdivisibleData{k: 1, m: 计算出的m值, a: 计算出的a值, max: 计算出的max值}`
    * **Go 代码示例:** 假设 `sdivisible(32, 10)` 返回 `data`。 那么，在编译期间，表达式 `int32(x) % 10 == 0` 可能会被转化为类似以下的操作：
        ```go
        // 原始代码
        isDivisible := int32(x) % 10 == 0

        // 优化后的代码 (大致)
        tmp := uint32(int32(x)) * data.m // 注意类型转换
        rotated := bits.RotateRight32(tmp + uint32(data.a), int(data.k))
        isDivisible = rotated <= data.max
        ```
* **使用者易犯错的点:**  与前面的优化类似，属于编译器内部实现，手动实现容易出错。

**命令行参数处理:**

该文件本身不直接处理命令行参数。 然而，Go 编译器的优化级别可以通过 `go build` 或 `go run` 命令的 `-gcflags` 参数进行调整。  例如：

```bash
go build -gcflags="-N -l" your_program.go  // 禁用优化和内联
go build your_program.go                 // 默认启用优化
```

* `-N`: 禁用所有优化。
* `-l`: 禁用内联。

如果禁用了优化，那么 `magic.go` 中的这些强度削减技术就不会被应用。

**总结:**

`magic.go` 文件是 Go 编译器中一个关键的优化组件，它通过预先计算魔术数字，将常量除法和取模运算转化为更快的乘法、移位和加法操作，从而提高程序的执行效率。 这项工作是在编译期间完成的，对最终生成的可执行文件产生了影响。普通 Go 程序员无需直接使用或修改这个文件，但了解其功能可以帮助理解编译器优化的原理。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/magic.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"math/big"
	"math/bits"
)

// So you want to compute x / c for some constant c?
// Machine division instructions are slow, so we try to
// compute this division with a multiplication + a few
// other cheap instructions instead.
// (We assume here that c != 0, +/- 1, or +/- 2^i.  Those
// cases are easy to handle in different ways).

// Technique from https://gmplib.org/~tege/divcnst-pldi94.pdf

// First consider unsigned division.
// Our strategy is to precompute 1/c then do
//   ⎣x / c⎦ = ⎣x * (1/c)⎦.
// 1/c is less than 1, so we can't compute it directly in
// integer arithmetic.  Let's instead compute 2^e/c
// for a value of e TBD (^ = exponentiation).  Then
//   ⎣x / c⎦ = ⎣x * (2^e/c) / 2^e⎦.
// Dividing by 2^e is easy.  2^e/c isn't an integer, unfortunately.
// So we must approximate it.  Let's call its approximation m.
// We'll then compute
//   ⎣x * m / 2^e⎦
// Which we want to be equal to ⎣x / c⎦ for 0 <= x < 2^n-1
// where n is the word size.
// Setting x = c gives us c * m >= 2^e.
// We'll chose m = ⎡2^e/c⎤ to satisfy that equation.
// What remains is to choose e.
// Let m = 2^e/c + delta, 0 <= delta < 1
//   ⎣x * (2^e/c + delta) / 2^e⎦
//   ⎣x / c + x * delta / 2^e⎦
// We must have x * delta / 2^e < 1/c so that this
// additional term never rounds differently than ⎣x / c⎦ does.
// Rearranging,
//   2^e > x * delta * c
// x can be at most 2^n-1 and delta can be at most 1.
// So it is sufficient to have 2^e >= 2^n*c.
// So we'll choose e = n + s, with s = ⎡log2(c)⎤.
//
// An additional complication arises because m has n+1 bits in it.
// Hardware restricts us to n bit by n bit multiplies.
// We divide into 3 cases:
//
// Case 1: m is even.
//   ⎣x / c⎦ = ⎣x * m / 2^(n+s)⎦
//   ⎣x / c⎦ = ⎣x * (m/2) / 2^(n+s-1)⎦
//   ⎣x / c⎦ = ⎣x * (m/2) / 2^n / 2^(s-1)⎦
//   ⎣x / c⎦ = ⎣⎣x * (m/2) / 2^n⎦ / 2^(s-1)⎦
//   multiply + shift
//
// Case 2: c is even.
//   ⎣x / c⎦ = ⎣(x/2) / (c/2)⎦
//   ⎣x / c⎦ = ⎣⎣x/2⎦ / (c/2)⎦
//     This is just the original problem, with x' = ⎣x/2⎦, c' = c/2, n' = n-1.
//       s' = s-1
//       m' = ⎡2^(n'+s')/c'⎤
//          = ⎡2^(n+s-1)/c⎤
//          = ⎡m/2⎤
//   ⎣x / c⎦ = ⎣x' * m' / 2^(n'+s')⎦
//   ⎣x / c⎦ = ⎣⎣x/2⎦ * ⎡m/2⎤ / 2^(n+s-2)⎦
//   ⎣x / c⎦ = ⎣⎣⎣x/2⎦ * ⎡m/2⎤ / 2^n⎦ / 2^(s-2)⎦
//   shift + multiply + shift
//
// Case 3: everything else
//   let k = m - 2^n. k fits in n bits.
//   ⎣x / c⎦ = ⎣x * m / 2^(n+s)⎦
//   ⎣x / c⎦ = ⎣x * (2^n + k) / 2^(n+s)⎦
//   ⎣x / c⎦ = ⎣(x + x * k / 2^n) / 2^s⎦
//   ⎣x / c⎦ = ⎣(x + ⎣x * k / 2^n⎦) / 2^s⎦
//   ⎣x / c⎦ = ⎣(x + ⎣x * k / 2^n⎦) / 2^s⎦
//   ⎣x / c⎦ = ⎣⎣(x + ⎣x * k / 2^n⎦) / 2⎦ / 2^(s-1)⎦
//   multiply + avg + shift
//
// These can be implemented in hardware using:
//  ⎣a * b / 2^n⎦ - aka high n bits of an n-bit by n-bit multiply.
//  ⎣(a+b) / 2⎦   - aka "average" of two n-bit numbers.
//                  (Not just a regular add & shift because the intermediate result
//                   a+b has n+1 bits in it.  Nevertheless, can be done
//                   in 2 instructions on x86.)

// umagicOK reports whether we should strength reduce a n-bit divide by c.
func umagicOK(n uint, c int64) bool {
	// Convert from ConstX auxint values to the real uint64 constant they represent.
	d := uint64(c) << (64 - n) >> (64 - n)

	// Doesn't work for 0.
	// Don't use for powers of 2.
	return d&(d-1) != 0
}

// umagicOKn reports whether we should strength reduce an unsigned n-bit divide by c.
// We can strength reduce when c != 0 and c is not a power of two.
func umagicOK8(c int8) bool   { return c&(c-1) != 0 }
func umagicOK16(c int16) bool { return c&(c-1) != 0 }
func umagicOK32(c int32) bool { return c&(c-1) != 0 }
func umagicOK64(c int64) bool { return c&(c-1) != 0 }

type umagicData struct {
	s int64  // ⎡log2(c)⎤
	m uint64 // ⎡2^(n+s)/c⎤ - 2^n
}

// umagic computes the constants needed to strength reduce unsigned n-bit divides by the constant uint64(c).
// The return values satisfy for all 0 <= x < 2^n
//
//	floor(x / uint64(c)) = x * (m + 2^n) >> (n+s)
func umagic(n uint, c int64) umagicData {
	// Convert from ConstX auxint values to the real uint64 constant they represent.
	d := uint64(c) << (64 - n) >> (64 - n)

	C := new(big.Int).SetUint64(d)
	s := C.BitLen()
	M := big.NewInt(1)
	M.Lsh(M, n+uint(s))     // 2^(n+s)
	M.Add(M, C)             // 2^(n+s)+c
	M.Sub(M, big.NewInt(1)) // 2^(n+s)+c-1
	M.Div(M, C)             // ⎡2^(n+s)/c⎤
	if M.Bit(int(n)) != 1 {
		panic("n+1st bit isn't set")
	}
	M.SetBit(M, int(n), 0)
	m := M.Uint64()
	return umagicData{s: int64(s), m: m}
}

func umagic8(c int8) umagicData   { return umagic(8, int64(c)) }
func umagic16(c int16) umagicData { return umagic(16, int64(c)) }
func umagic32(c int32) umagicData { return umagic(32, int64(c)) }
func umagic64(c int64) umagicData { return umagic(64, c) }

// For signed division, we use a similar strategy.
// First, we enforce a positive c.
//   x / c = -(x / (-c))
// This will require an additional Neg op for c<0.
//
// If x is positive we're in a very similar state
// to the unsigned case above.  We define:
//   s = ⎡log2(c)⎤-1
//   m = ⎡2^(n+s)/c⎤
// Then
//   ⎣x / c⎦ = ⎣x * m / 2^(n+s)⎦
// If x is negative we have
//   ⎡x / c⎤ = ⎣x * m / 2^(n+s)⎦ + 1
// (TODO: derivation?)
//
// The multiply is a bit odd, as it is a signed n-bit value
// times an unsigned n-bit value.  For n smaller than the
// word size, we can extend x and m appropriately and use the
// signed multiply instruction.  For n == word size,
// we must use the signed multiply high and correct
// the result by adding x*2^n.
//
// Adding 1 if x<0 is done by subtracting x>>(n-1).

func smagicOK(n uint, c int64) bool {
	if c < 0 {
		// Doesn't work for negative c.
		return false
	}
	// Doesn't work for 0.
	// Don't use it for powers of 2.
	return c&(c-1) != 0
}

// smagicOKn reports whether we should strength reduce a signed n-bit divide by c.
func smagicOK8(c int8) bool   { return smagicOK(8, int64(c)) }
func smagicOK16(c int16) bool { return smagicOK(16, int64(c)) }
func smagicOK32(c int32) bool { return smagicOK(32, int64(c)) }
func smagicOK64(c int64) bool { return smagicOK(64, c) }

type smagicData struct {
	s int64  // ⎡log2(c)⎤-1
	m uint64 // ⎡2^(n+s)/c⎤
}

// smagic computes the constants needed to strength reduce signed n-bit divides by the constant c.
// Must have c>0.
// The return values satisfy for all -2^(n-1) <= x < 2^(n-1)
//
//	trunc(x / c) = x * m >> (n+s) + (x < 0 ? 1 : 0)
func smagic(n uint, c int64) smagicData {
	C := new(big.Int).SetInt64(c)
	s := C.BitLen() - 1
	M := big.NewInt(1)
	M.Lsh(M, n+uint(s))     // 2^(n+s)
	M.Add(M, C)             // 2^(n+s)+c
	M.Sub(M, big.NewInt(1)) // 2^(n+s)+c-1
	M.Div(M, C)             // ⎡2^(n+s)/c⎤
	if M.Bit(int(n)) != 0 {
		panic("n+1st bit is set")
	}
	if M.Bit(int(n-1)) == 0 {
		panic("nth bit is not set")
	}
	m := M.Uint64()
	return smagicData{s: int64(s), m: m}
}

func smagic8(c int8) smagicData   { return smagic(8, int64(c)) }
func smagic16(c int16) smagicData { return smagic(16, int64(c)) }
func smagic32(c int32) smagicData { return smagic(32, int64(c)) }
func smagic64(c int64) smagicData { return smagic(64, c) }

// Divisibility x%c == 0 can be checked more efficiently than directly computing
// the modulus x%c and comparing against 0.
//
// The same "Division by invariant integers using multiplication" paper
// by Granlund and Montgomery referenced above briefly mentions this method
// and it is further elaborated in "Hacker's Delight" by Warren Section 10-17
//
// The first thing to note is that for odd integers, exact division can be computed
// by using the modular inverse with respect to the word size 2^n.
//
// Given c, compute m such that (c * m) mod 2^n == 1
// Then if c divides x (x%c ==0), the quotient is given by q = x/c == x*m mod 2^n
//
// x can range from 0, c, 2c, 3c, ... ⎣(2^n - 1)/c⎦ * c the maximum multiple
// Thus, x*m mod 2^n is 0, 1, 2, 3, ... ⎣(2^n - 1)/c⎦
// i.e. the quotient takes all values from zero up to max = ⎣(2^n - 1)/c⎦
//
// If x is not divisible by c, then x*m mod 2^n must take some larger value than max.
//
// This gives x*m mod 2^n <= ⎣(2^n - 1)/c⎦ as a test for divisibility
// involving one multiplication and compare.
//
// To extend this to even integers, consider c = d0 * 2^k where d0 is odd.
// We can test whether x is divisible by both d0 and 2^k.
// For d0, the test is the same as above.  Let m be such that m*d0 mod 2^n == 1
// Then x*m mod 2^n <= ⎣(2^n - 1)/d0⎦ is the first test.
// The test for divisibility by 2^k is a check for k trailing zeroes.
// Note that since d0 is odd, m is odd and thus x*m will have the same number of
// trailing zeroes as x.  So the two tests are,
//
// x*m mod 2^n <= ⎣(2^n - 1)/d0⎦
// and x*m ends in k zero bits
//
// These can be combined into a single comparison by the following
// (theorem ZRU in Hacker's Delight) for unsigned integers.
//
// x <= a and x ends in k zero bits if and only if RotRight(x ,k) <= ⎣a/(2^k)⎦
// Where RotRight(x ,k) is right rotation of x by k bits.
//
// To prove the first direction, x <= a -> ⎣x/(2^k)⎦ <= ⎣a/(2^k)⎦
// But since x ends in k zeroes all the rotated bits would be zero too.
// So RotRight(x, k) == ⎣x/(2^k)⎦ <= ⎣a/(2^k)⎦
//
// If x does not end in k zero bits, then RotRight(x, k)
// has some non-zero bits in the k highest bits.
// ⎣x/(2^k)⎦ has all zeroes in the k highest bits,
// so RotRight(x, k) > ⎣x/(2^k)⎦
//
// Finally, if x > a and has k trailing zero bits, then RotRight(x, k) == ⎣x/(2^k)⎦
// and ⎣x/(2^k)⎦ must be greater than ⎣a/(2^k)⎦, that is the top n-k bits of x must
// be greater than the top n-k bits of a because the rest of x bits are zero.
//
// So the two conditions about can be replaced with the single test
//
// RotRight(x*m mod 2^n, k) <= ⎣(2^n - 1)/c⎦
//
// Where d0*2^k was replaced by c on the right hand side.

// udivisibleOK reports whether we should strength reduce an unsigned n-bit divisibility check by c.
func udivisibleOK(n uint, c int64) bool {
	// Convert from ConstX auxint values to the real uint64 constant they represent.
	d := uint64(c) << (64 - n) >> (64 - n)

	// Doesn't work for 0.
	// Don't use for powers of 2.
	return d&(d-1) != 0
}

func udivisibleOK8(c int8) bool   { return udivisibleOK(8, int64(c)) }
func udivisibleOK16(c int16) bool { return udivisibleOK(16, int64(c)) }
func udivisibleOK32(c int32) bool { return udivisibleOK(32, int64(c)) }
func udivisibleOK64(c int64) bool { return udivisibleOK(64, c) }

type udivisibleData struct {
	k   int64  // trailingZeros(c)
	m   uint64 // m * (c>>k) mod 2^n == 1 multiplicative inverse of odd portion modulo 2^n
	max uint64 // ⎣(2^n - 1)/ c⎦ max value to for divisibility
}

func udivisible(n uint, c int64) udivisibleData {
	// Convert from ConstX auxint values to the real uint64 constant they represent.
	d := uint64(c) << (64 - n) >> (64 - n)

	k := bits.TrailingZeros64(d)
	d0 := d >> uint(k) // the odd portion of the divisor

	mask := ^uint64(0) >> (64 - n)

	// Calculate the multiplicative inverse via Newton's method.
	// Quadratic convergence doubles the number of correct bits per iteration.
	m := d0            // initial guess correct to 3-bits d0*d0 mod 8 == 1
	m = m * (2 - m*d0) // 6-bits
	m = m * (2 - m*d0) // 12-bits
	m = m * (2 - m*d0) // 24-bits
	m = m * (2 - m*d0) // 48-bits
	m = m * (2 - m*d0) // 96-bits >= 64-bits
	m = m & mask

	max := mask / d

	return udivisibleData{
		k:   int64(k),
		m:   m,
		max: max,
	}
}

func udivisible8(c int8) udivisibleData   { return udivisible(8, int64(c)) }
func udivisible16(c int16) udivisibleData { return udivisible(16, int64(c)) }
func udivisible32(c int32) udivisibleData { return udivisible(32, int64(c)) }
func udivisible64(c int64) udivisibleData { return udivisible(64, c) }

// For signed integers, a similar method follows.
//
// Given c > 1 and odd, compute m such that (c * m) mod 2^n == 1
// Then if c divides x (x%c ==0), the quotient is given by q = x/c == x*m mod 2^n
//
// x can range from ⎡-2^(n-1)/c⎤ * c, ... -c, 0, c, ...  ⎣(2^(n-1) - 1)/c⎦ * c
// Thus, x*m mod 2^n is ⎡-2^(n-1)/c⎤, ... -2, -1, 0, 1, 2, ... ⎣(2^(n-1) - 1)/c⎦
//
// So, x is a multiple of c if and only if:
// ⎡-2^(n-1)/c⎤ <= x*m mod 2^n <= ⎣(2^(n-1) - 1)/c⎦
//
// Since c > 1 and odd, this can be simplified by
// ⎡-2^(n-1)/c⎤ == ⎡(-2^(n-1) + 1)/c⎤ == -⎣(2^(n-1) - 1)/c⎦
//
// -⎣(2^(n-1) - 1)/c⎦ <= x*m mod 2^n <= ⎣(2^(n-1) - 1)/c⎦
//
// To extend this to even integers, consider c = d0 * 2^k where d0 is odd.
// We can test whether x is divisible by both d0 and 2^k.
//
// Let m be such that (d0 * m) mod 2^n == 1.
// Let q = x*m mod 2^n. Then c divides x if:
//
// -⎣(2^(n-1) - 1)/d0⎦ <= q <= ⎣(2^(n-1) - 1)/d0⎦ and q ends in at least k 0-bits
//
// To transform this to a single comparison, we use the following theorem (ZRS in Hacker's Delight).
//
// For a >= 0 the following conditions are equivalent:
// 1) -a <= x <= a and x ends in at least k 0-bits
// 2) RotRight(x+a', k) <= ⎣2a'/2^k⎦
//
// Where a' = a & -2^k (a with its right k bits set to zero)
//
// To see that 1 & 2 are equivalent, note that -a <= x <= a is equivalent to
// -a' <= x <= a' if and only if x ends in at least k 0-bits.  Adding -a' to each side gives,
// 0 <= x + a' <= 2a' and x + a' ends in at least k 0-bits if and only if x does since a' has
// k 0-bits by definition.  We can use theorem ZRU above with x -> x + a' and a -> 2a' giving 1) == 2).
//
// Let m be such that (d0 * m) mod 2^n == 1.
// Let q = x*m mod 2^n.
// Let a' = ⎣(2^(n-1) - 1)/d0⎦ & -2^k
//
// Then the divisibility test is:
//
// RotRight(q+a', k) <= ⎣2a'/2^k⎦
//
// Note that the calculation is performed using unsigned integers.
// Since a' can have n-1 bits, 2a' may have n bits and there is no risk of overflow.

// sdivisibleOK reports whether we should strength reduce a signed n-bit divisibility check by c.
func sdivisibleOK(n uint, c int64) bool {
	if c < 0 {
		// Doesn't work for negative c.
		return false
	}
	// Doesn't work for 0.
	// Don't use it for powers of 2.
	return c&(c-1) != 0
}

func sdivisibleOK8(c int8) bool   { return sdivisibleOK(8, int64(c)) }
func sdivisibleOK16(c int16) bool { return sdivisibleOK(16, int64(c)) }
func sdivisibleOK32(c int32) bool { return sdivisibleOK(32, int64(c)) }
func sdivisibleOK64(c int64) bool { return sdivisibleOK(64, c) }

type sdivisibleData struct {
	k   int64  // trailingZeros(c)
	m   uint64 // m * (c>>k) mod 2^n == 1 multiplicative inverse of odd portion modulo 2^n
	a   uint64 // ⎣(2^(n-1) - 1)/ (c>>k)⎦ & -(1<<k) additive constant
	max uint64 // ⎣(2 a) / (1<<k)⎦ max value to for divisibility
}

func sdivisible(n uint, c int64) sdivisibleData {
	d := uint64(c)
	k := bits.TrailingZeros64(d)
	d0 := d >> uint(k) // the odd portion of the divisor

	mask := ^uint64(0) >> (64 - n)

	// Calculate the multiplicative inverse via Newton's method.
	// Quadratic convergence doubles the number of correct bits per iteration.
	m := d0            // initial guess correct to 3-bits d0*d0 mod 8 == 1
	m = m * (2 - m*d0) // 6-bits
	m = m * (2 - m*d0) // 12-bits
	m = m * (2 - m*d0) // 24-bits
	m = m * (2 - m*d0) // 48-bits
	m = m * (2 - m*d0) // 96-bits >= 64-bits
	m = m & mask

	a := ((mask >> 1) / d0) & -(1 << uint(k))
	max := (2 * a) >> uint(k)

	return sdivisibleData{
		k:   int64(k),
		m:   m,
		a:   a,
		max: max,
	}
}

func sdivisible8(c int8) sdivisibleData   { return sdivisible(8, int64(c)) }
func sdivisible16(c int16) sdivisibleData { return sdivisible(16, int64(c)) }
func sdivisible32(c int32) sdivisibleData { return sdivisible(32, int64(c)) }
func sdivisible64(c int64) sdivisibleData { return sdivisible(64, c) }
```