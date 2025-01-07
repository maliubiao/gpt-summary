Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding and Context:**

* The prompt states this is part of `go/src/crypto/internal/fips140/nistec/fiat/p384_fiat64.go`. This immediately tells us it's related to cryptography, specifically the P384 elliptic curve, and likely involves low-level, performance-sensitive operations. The "fiat64" suggests it's using 64-bit integers for efficiency.
* The prompt explicitly asks to summarize the functionality and, if possible, infer the Go language feature being implemented.

**2. Scanning the Code - Identifying Patterns:**

* **Repetitive Structures:** The code is dominated by sequences of variable declarations and assignments using `bits.Mul64` and `bits.Add64`. This strong pattern suggests it's performing some form of large integer arithmetic.
* **`p384Uint1`:**  The function `p384Uint1` is used extensively within the `bits.Add64` calls. This function likely extracts a single bit (or a small integer value) from a `uint64`. The context of addition suggests it's handling carry bits in multi-word arithmetic.
* **Large Number of Variables:**  The sheer volume of `x` variables (`x1` to `x410` in the first function) reinforces the idea of multi-word arithmetic where each `uint64` represents a "limb" of a larger number.
* **Multiplication by Constants:**  `bits.Mul64` is used with specific hexadecimal constants like `0x200000000`, `0xfffffffe00000001`, `0x100000001`, and various values composed of `0xffffffff`. These constants are likely related to the modulus of the finite field over which the elliptic curve is defined or to pre-computation steps.
* **`p384CmovznzU64` and `p384Selectznz`:** These functions clearly implement conditional moves/selections based on a `p384Uint1` condition. This is a common technique in cryptographic implementations to avoid branching for security reasons (to prevent timing attacks).
* **`p384ToBytes` and `p384FromBytes`:** The names are self-explanatory. These functions handle the serialization and deserialization of the large integer representation to and from byte arrays. The little-endian order is also mentioned.

**3. Inferring Functionality (Building Hypotheses):**

Based on the patterns, several hypotheses emerge:

* **Core Arithmetic:** The primary function is performing arithmetic operations on large integers, likely representing elements of a finite field used in elliptic curve cryptography.
* **Multiplication:** The frequent use of `bits.Mul64` points to multiplication as a fundamental operation.
* **Modular Reduction:** The constants used in multiplication, particularly those involving `0xffffffff` and the patterns of additions and carry handling, strongly suggest modular reduction is being performed. The specific constants likely relate to the P384 modulus.
* **Conditional Operations:** `p384CmovznzU64` and `p384Selectznz` are implementing conditional logic without branching, crucial for security.
* **Serialization/Deserialization:** `p384ToBytes` and `p384FromBytes` handle the conversion between the internal multi-word representation and byte arrays.

**4. Focusing on the First Function (Code Deduction):**

The first large block of code is the most complex. The structure of multiplications and additions strongly resembles a multiplication algorithm, likely a schoolbook multiplication or a slightly optimized variant. The carry propagation is evident in the `p384Uint1` calls within the additions. The multiplications by specific constants seem to be performing parts of a modular reduction following the multiplication.

**5. Go Feature Identification:**

* **Low-level Optimization:** The code directly manipulates `uint64` and uses functions like `bits.Mul64` and `bits.Add64`. This points to a focus on performance and low-level control, which is characteristic of the `crypto/internal` package.
* **Potential for Assembly:** While the provided code is Go, the extreme low-level nature suggests that assembly language might be used for further optimization in the actual implementation. The fiat-crypto project often involves generated assembly.

**6. Code Example (Illustrative, Not Exact):**

Given the inference of large integer multiplication and modular reduction, a simplified Go example can be constructed to demonstrate the concept, even if it doesn't perfectly replicate the given code's complexity:

```go
package main

import "fmt"
import "math/bits"

// Simplified representation of a large integer
type LargeInt [6]uint64

// Simplified add with carry (illustrative)
func addCarry(a, b, carry uint64) (sum, newCarry uint64) {
	sum64, carryBit := bits.Add64(a, b, carry)
	return sum64, carryBit
}

// Simplified multiply (illustrative)
func multiply(x LargeInt, y uint64) LargeInt {
	var result LargeInt
	var carry uint64
	for i := 0; i < 6; i++ {
		hi, lo := bits.Mul64(x[i], y)
		sum, newCarry := addCarry(result[i], lo, carry)
		result[i] = sum
		carry, _ = bits.Add64(hi, 0, newCarry) // Simplified carry handling
	}
	// ... more complex modular reduction would go here ...
	return result
}

func main() {
	a := LargeInt{1, 0, 0, 0, 0, 0} // Example input
	b := uint64(10)                 // Example multiplier
	result := multiply(a, b)
	fmt.Println(result)
}
```

**7. Identifying Potential Mistakes:**

* **Incorrect Carry Handling:**  Manually managing carry bits in multi-word arithmetic is error-prone. A small mistake can lead to incorrect results.
* **Off-by-One Errors:**  Loop bounds and array indices are critical and easy to get wrong.
* **Endianness Issues:**  When converting between byte arrays and multi-word integers, incorrect handling of endianness will lead to wrong values.

**8. Finalizing the Summary (Part 2):**

The concluding summary focuses on the overarching purpose of the code within the context of cryptographic operations on the P384 curve. It emphasizes the core functionalities identified earlier, such as large integer arithmetic, modular reduction, and secure conditional operations.
这是第2部分，对提供的Go语言代码片段进行功能归纳：

**功能归纳:**

总而言之，这段代码是 `go/src/crypto/internal/fips140/nistec/fiat/p384_fiat64.go` 文件的一部分，它实现了 **P-384 椭圆曲线的底层算术运算**。  更具体地说，它提供了以下关键功能：

1. **大整数（多精度整数）的加法和乘法:**  代码中大量使用了 `bits.Mul64` 和 `bits.Add64`，这表明它正在执行 64 位整数的乘法和带进位的加法。结合大量的临时变量，可以推断这是在模拟大于 64 位的整数的运算，即多精度算术。这对于椭圆曲线密码学中处理大素数域的元素是至关重要的。

2. **模约简 (Modular Reduction):**  虽然没有显式的模运算符号，但代码中 `bits.Mul64` 的第二个参数出现了很多特定的十六进制常数，例如 `0x200000000`, `0xfffffffe00000001`, `0x100000001` 以及一系列 `0xffffffffffffffff` 和 `0xffffffff00000000` 的组合。这些常数很可能与 P-384 曲线所使用的素数模数有关。 通过与这些常数进行乘法和后续的加法/减法操作，可以推断代码在执行模约简，即将运算结果限制在模数范围内的操作。

3. **条件赋值 (Conditional Move):**  `p384CmovznzU64` 函数实现了基于一个 `p384Uint1` 类型的条件进行 64 位整数的赋值。这是一种条件移动操作，常用于密码学实现中以避免分支，从而防止旁路攻击（例如，定时攻击）。

4. **条件选择 (Conditional Select):** `p384Selectznz` 函数实现了基于一个 `p384Uint1` 类型的条件，从两个 `[6]uint64` 数组中选择一个作为输出。 同样，这也是一种避免分支的条件操作。

5. **字节序列化和反序列化:** `p384ToBytes` 函数将一个由 6 个 `uint64` 组成的数组（代表一个大整数）转换为 48 字节的字节数组，采用小端字节序。`p384FromBytes` 函数则执行相反的操作，将 48 字节的字节数组反序列化为 6 个 `uint64`。 这两个函数用于在内部表示和外部字节表示之间转换大整数。

**总结:**

这段代码的核心目标是提供高效且安全的 P-384 曲线上的有限域算术运算，包括大整数的加法、乘法和模约简。  `p384CmovznzU64` 和 `p384Selectznz` 函数的出现强调了安全性和防止旁路攻击的重要性。  `p384ToBytes` 和 `p384FromBytes` 负责数据的序列化和反序列化，以便与其他系统或存储进行交互。

总的来说，这是构成 P-384 椭圆曲线密码学实现的关键底层组件，专注于性能和安全性。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/nistec/fiat/p384_fiat64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
00)
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x6, 0x200000000)
	var x13 uint64
	var x14 uint64
	x14, x13 = bits.Mul64(x6, 0xfffffffe00000001)
	var x15 uint64
	var x16 uint64
	x15, x16 = bits.Add64(x14, x11, uint64(0x0))
	var x17 uint64
	var x18 uint64
	x17, x18 = bits.Add64(x12, x9, uint64(p384Uint1(x16)))
	var x19 uint64
	var x20 uint64
	x19, x20 = bits.Add64(x10, x7, uint64(p384Uint1(x18)))
	var x21 uint64
	var x22 uint64
	x21, x22 = bits.Add64(x8, x6, uint64(p384Uint1(x20)))
	var x23 uint64
	_, x23 = bits.Mul64(x13, 0x100000001)
	var x25 uint64
	var x26 uint64
	x26, x25 = bits.Mul64(x23, 0xffffffffffffffff)
	var x27 uint64
	var x28 uint64
	x28, x27 = bits.Mul64(x23, 0xffffffffffffffff)
	var x29 uint64
	var x30 uint64
	x30, x29 = bits.Mul64(x23, 0xffffffffffffffff)
	var x31 uint64
	var x32 uint64
	x32, x31 = bits.Mul64(x23, 0xfffffffffffffffe)
	var x33 uint64
	var x34 uint64
	x34, x33 = bits.Mul64(x23, 0xffffffff00000000)
	var x35 uint64
	var x36 uint64
	x36, x35 = bits.Mul64(x23, 0xffffffff)
	var x37 uint64
	var x38 uint64
	x37, x38 = bits.Add64(x36, x33, uint64(0x0))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x34, x31, uint64(p384Uint1(x38)))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x32, x29, uint64(p384Uint1(x40)))
	var x43 uint64
	var x44 uint64
	x43, x44 = bits.Add64(x30, x27, uint64(p384Uint1(x42)))
	var x45 uint64
	var x46 uint64
	x45, x46 = bits.Add64(x28, x25, uint64(p384Uint1(x44)))
	var x48 uint64
	_, x48 = bits.Add64(x13, x35, uint64(0x0))
	var x49 uint64
	var x50 uint64
	x49, x50 = bits.Add64(x15, x37, uint64(p384Uint1(x48)))
	var x51 uint64
	var x52 uint64
	x51, x52 = bits.Add64(x17, x39, uint64(p384Uint1(x50)))
	var x53 uint64
	var x54 uint64
	x53, x54 = bits.Add64(x19, x41, uint64(p384Uint1(x52)))
	var x55 uint64
	var x56 uint64
	x55, x56 = bits.Add64(x21, x43, uint64(p384Uint1(x54)))
	var x57 uint64
	var x58 uint64
	x57, x58 = bits.Add64(uint64(p384Uint1(x22)), x45, uint64(p384Uint1(x56)))
	var x59 uint64
	var x60 uint64
	x59, x60 = bits.Add64(uint64(0x0), (uint64(p384Uint1(x46)) + x26), uint64(p384Uint1(x58)))
	var x61 uint64
	var x62 uint64
	x62, x61 = bits.Mul64(x1, 0x200000000)
	var x63 uint64
	var x64 uint64
	x64, x63 = bits.Mul64(x1, 0xfffffffe00000000)
	var x65 uint64
	var x66 uint64
	x66, x65 = bits.Mul64(x1, 0x200000000)
	var x67 uint64
	var x68 uint64
	x68, x67 = bits.Mul64(x1, 0xfffffffe00000001)
	var x69 uint64
	var x70 uint64
	x69, x70 = bits.Add64(x68, x65, uint64(0x0))
	var x71 uint64
	var x72 uint64
	x71, x72 = bits.Add64(x66, x63, uint64(p384Uint1(x70)))
	var x73 uint64
	var x74 uint64
	x73, x74 = bits.Add64(x64, x61, uint64(p384Uint1(x72)))
	var x75 uint64
	var x76 uint64
	x75, x76 = bits.Add64(x62, x1, uint64(p384Uint1(x74)))
	var x77 uint64
	var x78 uint64
	x77, x78 = bits.Add64(x49, x67, uint64(0x0))
	var x79 uint64
	var x80 uint64
	x79, x80 = bits.Add64(x51, x69, uint64(p384Uint1(x78)))
	var x81 uint64
	var x82 uint64
	x81, x82 = bits.Add64(x53, x71, uint64(p384Uint1(x80)))
	var x83 uint64
	var x84 uint64
	x83, x84 = bits.Add64(x55, x73, uint64(p384Uint1(x82)))
	var x85 uint64
	var x86 uint64
	x85, x86 = bits.Add64(x57, x75, uint64(p384Uint1(x84)))
	var x87 uint64
	var x88 uint64
	x87, x88 = bits.Add64(x59, uint64(p384Uint1(x76)), uint64(p384Uint1(x86)))
	var x89 uint64
	_, x89 = bits.Mul64(x77, 0x100000001)
	var x91 uint64
	var x92 uint64
	x92, x91 = bits.Mul64(x89, 0xffffffffffffffff)
	var x93 uint64
	var x94 uint64
	x94, x93 = bits.Mul64(x89, 0xffffffffffffffff)
	var x95 uint64
	var x96 uint64
	x96, x95 = bits.Mul64(x89, 0xffffffffffffffff)
	var x97 uint64
	var x98 uint64
	x98, x97 = bits.Mul64(x89, 0xfffffffffffffffe)
	var x99 uint64
	var x100 uint64
	x100, x99 = bits.Mul64(x89, 0xffffffff00000000)
	var x101 uint64
	var x102 uint64
	x102, x101 = bits.Mul64(x89, 0xffffffff)
	var x103 uint64
	var x104 uint64
	x103, x104 = bits.Add64(x102, x99, uint64(0x0))
	var x105 uint64
	var x106 uint64
	x105, x106 = bits.Add64(x100, x97, uint64(p384Uint1(x104)))
	var x107 uint64
	var x108 uint64
	x107, x108 = bits.Add64(x98, x95, uint64(p384Uint1(x106)))
	var x109 uint64
	var x110 uint64
	x109, x110 = bits.Add64(x96, x93, uint64(p384Uint1(x108)))
	var x111 uint64
	var x112 uint64
	x111, x112 = bits.Add64(x94, x91, uint64(p384Uint1(x110)))
	var x114 uint64
	_, x114 = bits.Add64(x77, x101, uint64(0x0))
	var x115 uint64
	var x116 uint64
	x115, x116 = bits.Add64(x79, x103, uint64(p384Uint1(x114)))
	var x117 uint64
	var x118 uint64
	x117, x118 = bits.Add64(x81, x105, uint64(p384Uint1(x116)))
	var x119 uint64
	var x120 uint64
	x119, x120 = bits.Add64(x83, x107, uint64(p384Uint1(x118)))
	var x121 uint64
	var x122 uint64
	x121, x122 = bits.Add64(x85, x109, uint64(p384Uint1(x120)))
	var x123 uint64
	var x124 uint64
	x123, x124 = bits.Add64(x87, x111, uint64(p384Uint1(x122)))
	var x125 uint64
	var x126 uint64
	x125, x126 = bits.Add64((uint64(p384Uint1(x88)) + uint64(p384Uint1(x60))), (uint64(p384Uint1(x112)) + x92), uint64(p384Uint1(x124)))
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(x2, 0x200000000)
	var x129 uint64
	var x130 uint64
	x130, x129 = bits.Mul64(x2, 0xfffffffe00000000)
	var x131 uint64
	var x132 uint64
	x132, x131 = bits.Mul64(x2, 0x200000000)
	var x133 uint64
	var x134 uint64
	x134, x133 = bits.Mul64(x2, 0xfffffffe00000001)
	var x135 uint64
	var x136 uint64
	x135, x136 = bits.Add64(x134, x131, uint64(0x0))
	var x137 uint64
	var x138 uint64
	x137, x138 = bits.Add64(x132, x129, uint64(p384Uint1(x136)))
	var x139 uint64
	var x140 uint64
	x139, x140 = bits.Add64(x130, x127, uint64(p384Uint1(x138)))
	var x141 uint64
	var x142 uint64
	x141, x142 = bits.Add64(x128, x2, uint64(p384Uint1(x140)))
	var x143 uint64
	var x144 uint64
	x143, x144 = bits.Add64(x115, x133, uint64(0x0))
	var x145 uint64
	var x146 uint64
	x145, x146 = bits.Add64(x117, x135, uint64(p384Uint1(x144)))
	var x147 uint64
	var x148 uint64
	x147, x148 = bits.Add64(x119, x137, uint64(p384Uint1(x146)))
	var x149 uint64
	var x150 uint64
	x149, x150 = bits.Add64(x121, x139, uint64(p384Uint1(x148)))
	var x151 uint64
	var x152 uint64
	x151, x152 = bits.Add64(x123, x141, uint64(p384Uint1(x150)))
	var x153 uint64
	var x154 uint64
	x153, x154 = bits.Add64(x125, uint64(p384Uint1(x142)), uint64(p384Uint1(x152)))
	var x155 uint64
	_, x155 = bits.Mul64(x143, 0x100000001)
	var x157 uint64
	var x158 uint64
	x158, x157 = bits.Mul64(x155, 0xffffffffffffffff)
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(x155, 0xffffffffffffffff)
	var x161 uint64
	var x162 uint64
	x162, x161 = bits.Mul64(x155, 0xffffffffffffffff)
	var x163 uint64
	var x164 uint64
	x164, x163 = bits.Mul64(x155, 0xfffffffffffffffe)
	var x165 uint64
	var x166 uint64
	x166, x165 = bits.Mul64(x155, 0xffffffff00000000)
	var x167 uint64
	var x168 uint64
	x168, x167 = bits.Mul64(x155, 0xffffffff)
	var x169 uint64
	var x170 uint64
	x169, x170 = bits.Add64(x168, x165, uint64(0x0))
	var x171 uint64
	var x172 uint64
	x171, x172 = bits.Add64(x166, x163, uint64(p384Uint1(x170)))
	var x173 uint64
	var x174 uint64
	x173, x174 = bits.Add64(x164, x161, uint64(p384Uint1(x172)))
	var x175 uint64
	var x176 uint64
	x175, x176 = bits.Add64(x162, x159, uint64(p384Uint1(x174)))
	var x177 uint64
	var x178 uint64
	x177, x178 = bits.Add64(x160, x157, uint64(p384Uint1(x176)))
	var x180 uint64
	_, x180 = bits.Add64(x143, x167, uint64(0x0))
	var x181 uint64
	var x182 uint64
	x181, x182 = bits.Add64(x145, x169, uint64(p384Uint1(x180)))
	var x183 uint64
	var x184 uint64
	x183, x184 = bits.Add64(x147, x171, uint64(p384Uint1(x182)))
	var x185 uint64
	var x186 uint64
	x185, x186 = bits.Add64(x149, x173, uint64(p384Uint1(x184)))
	var x187 uint64
	var x188 uint64
	x187, x188 = bits.Add64(x151, x175, uint64(p384Uint1(x186)))
	var x189 uint64
	var x190 uint64
	x189, x190 = bits.Add64(x153, x177, uint64(p384Uint1(x188)))
	var x191 uint64
	var x192 uint64
	x191, x192 = bits.Add64((uint64(p384Uint1(x154)) + uint64(p384Uint1(x126))), (uint64(p384Uint1(x178)) + x158), uint64(p384Uint1(x190)))
	var x193 uint64
	var x194 uint64
	x194, x193 = bits.Mul64(x3, 0x200000000)
	var x195 uint64
	var x196 uint64
	x196, x195 = bits.Mul64(x3, 0xfffffffe00000000)
	var x197 uint64
	var x198 uint64
	x198, x197 = bits.Mul64(x3, 0x200000000)
	var x199 uint64
	var x200 uint64
	x200, x199 = bits.Mul64(x3, 0xfffffffe00000001)
	var x201 uint64
	var x202 uint64
	x201, x202 = bits.Add64(x200, x197, uint64(0x0))
	var x203 uint64
	var x204 uint64
	x203, x204 = bits.Add64(x198, x195, uint64(p384Uint1(x202)))
	var x205 uint64
	var x206 uint64
	x205, x206 = bits.Add64(x196, x193, uint64(p384Uint1(x204)))
	var x207 uint64
	var x208 uint64
	x207, x208 = bits.Add64(x194, x3, uint64(p384Uint1(x206)))
	var x209 uint64
	var x210 uint64
	x209, x210 = bits.Add64(x181, x199, uint64(0x0))
	var x211 uint64
	var x212 uint64
	x211, x212 = bits.Add64(x183, x201, uint64(p384Uint1(x210)))
	var x213 uint64
	var x214 uint64
	x213, x214 = bits.Add64(x185, x203, uint64(p384Uint1(x212)))
	var x215 uint64
	var x216 uint64
	x215, x216 = bits.Add64(x187, x205, uint64(p384Uint1(x214)))
	var x217 uint64
	var x218 uint64
	x217, x218 = bits.Add64(x189, x207, uint64(p384Uint1(x216)))
	var x219 uint64
	var x220 uint64
	x219, x220 = bits.Add64(x191, uint64(p384Uint1(x208)), uint64(p384Uint1(x218)))
	var x221 uint64
	_, x221 = bits.Mul64(x209, 0x100000001)
	var x223 uint64
	var x224 uint64
	x224, x223 = bits.Mul64(x221, 0xffffffffffffffff)
	var x225 uint64
	var x226 uint64
	x226, x225 = bits.Mul64(x221, 0xffffffffffffffff)
	var x227 uint64
	var x228 uint64
	x228, x227 = bits.Mul64(x221, 0xffffffffffffffff)
	var x229 uint64
	var x230 uint64
	x230, x229 = bits.Mul64(x221, 0xfffffffffffffffe)
	var x231 uint64
	var x232 uint64
	x232, x231 = bits.Mul64(x221, 0xffffffff00000000)
	var x233 uint64
	var x234 uint64
	x234, x233 = bits.Mul64(x221, 0xffffffff)
	var x235 uint64
	var x236 uint64
	x235, x236 = bits.Add64(x234, x231, uint64(0x0))
	var x237 uint64
	var x238 uint64
	x237, x238 = bits.Add64(x232, x229, uint64(p384Uint1(x236)))
	var x239 uint64
	var x240 uint64
	x239, x240 = bits.Add64(x230, x227, uint64(p384Uint1(x238)))
	var x241 uint64
	var x242 uint64
	x241, x242 = bits.Add64(x228, x225, uint64(p384Uint1(x240)))
	var x243 uint64
	var x244 uint64
	x243, x244 = bits.Add64(x226, x223, uint64(p384Uint1(x242)))
	var x246 uint64
	_, x246 = bits.Add64(x209, x233, uint64(0x0))
	var x247 uint64
	var x248 uint64
	x247, x248 = bits.Add64(x211, x235, uint64(p384Uint1(x246)))
	var x249 uint64
	var x250 uint64
	x249, x250 = bits.Add64(x213, x237, uint64(p384Uint1(x248)))
	var x251 uint64
	var x252 uint64
	x251, x252 = bits.Add64(x215, x239, uint64(p384Uint1(x250)))
	var x253 uint64
	var x254 uint64
	x253, x254 = bits.Add64(x217, x241, uint64(p384Uint1(x252)))
	var x255 uint64
	var x256 uint64
	x255, x256 = bits.Add64(x219, x243, uint64(p384Uint1(x254)))
	var x257 uint64
	var x258 uint64
	x257, x258 = bits.Add64((uint64(p384Uint1(x220)) + uint64(p384Uint1(x192))), (uint64(p384Uint1(x244)) + x224), uint64(p384Uint1(x256)))
	var x259 uint64
	var x260 uint64
	x260, x259 = bits.Mul64(x4, 0x200000000)
	var x261 uint64
	var x262 uint64
	x262, x261 = bits.Mul64(x4, 0xfffffffe00000000)
	var x263 uint64
	var x264 uint64
	x264, x263 = bits.Mul64(x4, 0x200000000)
	var x265 uint64
	var x266 uint64
	x266, x265 = bits.Mul64(x4, 0xfffffffe00000001)
	var x267 uint64
	var x268 uint64
	x267, x268 = bits.Add64(x266, x263, uint64(0x0))
	var x269 uint64
	var x270 uint64
	x269, x270 = bits.Add64(x264, x261, uint64(p384Uint1(x268)))
	var x271 uint64
	var x272 uint64
	x271, x272 = bits.Add64(x262, x259, uint64(p384Uint1(x270)))
	var x273 uint64
	var x274 uint64
	x273, x274 = bits.Add64(x260, x4, uint64(p384Uint1(x272)))
	var x275 uint64
	var x276 uint64
	x275, x276 = bits.Add64(x247, x265, uint64(0x0))
	var x277 uint64
	var x278 uint64
	x277, x278 = bits.Add64(x249, x267, uint64(p384Uint1(x276)))
	var x279 uint64
	var x280 uint64
	x279, x280 = bits.Add64(x251, x269, uint64(p384Uint1(x278)))
	var x281 uint64
	var x282 uint64
	x281, x282 = bits.Add64(x253, x271, uint64(p384Uint1(x280)))
	var x283 uint64
	var x284 uint64
	x283, x284 = bits.Add64(x255, x273, uint64(p384Uint1(x282)))
	var x285 uint64
	var x286 uint64
	x285, x286 = bits.Add64(x257, uint64(p384Uint1(x274)), uint64(p384Uint1(x284)))
	var x287 uint64
	_, x287 = bits.Mul64(x275, 0x100000001)
	var x289 uint64
	var x290 uint64
	x290, x289 = bits.Mul64(x287, 0xffffffffffffffff)
	var x291 uint64
	var x292 uint64
	x292, x291 = bits.Mul64(x287, 0xffffffffffffffff)
	var x293 uint64
	var x294 uint64
	x294, x293 = bits.Mul64(x287, 0xffffffffffffffff)
	var x295 uint64
	var x296 uint64
	x296, x295 = bits.Mul64(x287, 0xfffffffffffffffe)
	var x297 uint64
	var x298 uint64
	x298, x297 = bits.Mul64(x287, 0xffffffff00000000)
	var x299 uint64
	var x300 uint64
	x300, x299 = bits.Mul64(x287, 0xffffffff)
	var x301 uint64
	var x302 uint64
	x301, x302 = bits.Add64(x300, x297, uint64(0x0))
	var x303 uint64
	var x304 uint64
	x303, x304 = bits.Add64(x298, x295, uint64(p384Uint1(x302)))
	var x305 uint64
	var x306 uint64
	x305, x306 = bits.Add64(x296, x293, uint64(p384Uint1(x304)))
	var x307 uint64
	var x308 uint64
	x307, x308 = bits.Add64(x294, x291, uint64(p384Uint1(x306)))
	var x309 uint64
	var x310 uint64
	x309, x310 = bits.Add64(x292, x289, uint64(p384Uint1(x308)))
	var x312 uint64
	_, x312 = bits.Add64(x275, x299, uint64(0x0))
	var x313 uint64
	var x314 uint64
	x313, x314 = bits.Add64(x277, x301, uint64(p384Uint1(x312)))
	var x315 uint64
	var x316 uint64
	x315, x316 = bits.Add64(x279, x303, uint64(p384Uint1(x314)))
	var x317 uint64
	var x318 uint64
	x317, x318 = bits.Add64(x281, x305, uint64(p384Uint1(x316)))
	var x319 uint64
	var x320 uint64
	x319, x320 = bits.Add64(x283, x307, uint64(p384Uint1(x318)))
	var x321 uint64
	var x322 uint64
	x321, x322 = bits.Add64(x285, x309, uint64(p384Uint1(x320)))
	var x323 uint64
	var x324 uint64
	x323, x324 = bits.Add64((uint64(p384Uint1(x286)) + uint64(p384Uint1(x258))), (uint64(p384Uint1(x310)) + x290), uint64(p384Uint1(x322)))
	var x325 uint64
	var x326 uint64
	x326, x325 = bits.Mul64(x5, 0x200000000)
	var x327 uint64
	var x328 uint64
	x328, x327 = bits.Mul64(x5, 0xfffffffe00000000)
	var x329 uint64
	var x330 uint64
	x330, x329 = bits.Mul64(x5, 0x200000000)
	var x331 uint64
	var x332 uint64
	x332, x331 = bits.Mul64(x5, 0xfffffffe00000001)
	var x333 uint64
	var x334 uint64
	x333, x334 = bits.Add64(x332, x329, uint64(0x0))
	var x335 uint64
	var x336 uint64
	x335, x336 = bits.Add64(x330, x327, uint64(p384Uint1(x334)))
	var x337 uint64
	var x338 uint64
	x337, x338 = bits.Add64(x328, x325, uint64(p384Uint1(x336)))
	var x339 uint64
	var x340 uint64
	x339, x340 = bits.Add64(x326, x5, uint64(p384Uint1(x338)))
	var x341 uint64
	var x342 uint64
	x341, x342 = bits.Add64(x313, x331, uint64(0x0))
	var x343 uint64
	var x344 uint64
	x343, x344 = bits.Add64(x315, x333, uint64(p384Uint1(x342)))
	var x345 uint64
	var x346 uint64
	x345, x346 = bits.Add64(x317, x335, uint64(p384Uint1(x344)))
	var x347 uint64
	var x348 uint64
	x347, x348 = bits.Add64(x319, x337, uint64(p384Uint1(x346)))
	var x349 uint64
	var x350 uint64
	x349, x350 = bits.Add64(x321, x339, uint64(p384Uint1(x348)))
	var x351 uint64
	var x352 uint64
	x351, x352 = bits.Add64(x323, uint64(p384Uint1(x340)), uint64(p384Uint1(x350)))
	var x353 uint64
	_, x353 = bits.Mul64(x341, 0x100000001)
	var x355 uint64
	var x356 uint64
	x356, x355 = bits.Mul64(x353, 0xffffffffffffffff)
	var x357 uint64
	var x358 uint64
	x358, x357 = bits.Mul64(x353, 0xffffffffffffffff)
	var x359 uint64
	var x360 uint64
	x360, x359 = bits.Mul64(x353, 0xffffffffffffffff)
	var x361 uint64
	var x362 uint64
	x362, x361 = bits.Mul64(x353, 0xfffffffffffffffe)
	var x363 uint64
	var x364 uint64
	x364, x363 = bits.Mul64(x353, 0xffffffff00000000)
	var x365 uint64
	var x366 uint64
	x366, x365 = bits.Mul64(x353, 0xffffffff)
	var x367 uint64
	var x368 uint64
	x367, x368 = bits.Add64(x366, x363, uint64(0x0))
	var x369 uint64
	var x370 uint64
	x369, x370 = bits.Add64(x364, x361, uint64(p384Uint1(x368)))
	var x371 uint64
	var x372 uint64
	x371, x372 = bits.Add64(x362, x359, uint64(p384Uint1(x370)))
	var x373 uint64
	var x374 uint64
	x373, x374 = bits.Add64(x360, x357, uint64(p384Uint1(x372)))
	var x375 uint64
	var x376 uint64
	x375, x376 = bits.Add64(x358, x355, uint64(p384Uint1(x374)))
	var x378 uint64
	_, x378 = bits.Add64(x341, x365, uint64(0x0))
	var x379 uint64
	var x380 uint64
	x379, x380 = bits.Add64(x343, x367, uint64(p384Uint1(x378)))
	var x381 uint64
	var x382 uint64
	x381, x382 = bits.Add64(x345, x369, uint64(p384Uint1(x380)))
	var x383 uint64
	var x384 uint64
	x383, x384 = bits.Add64(x347, x371, uint64(p384Uint1(x382)))
	var x385 uint64
	var x386 uint64
	x385, x386 = bits.Add64(x349, x373, uint64(p384Uint1(x384)))
	var x387 uint64
	var x388 uint64
	x387, x388 = bits.Add64(x351, x375, uint64(p384Uint1(x386)))
	var x389 uint64
	var x390 uint64
	x389, x390 = bits.Add64((uint64(p384Uint1(x352)) + uint64(p384Uint1(x324))), (uint64(p384Uint1(x376)) + x356), uint64(p384Uint1(x388)))
	var x391 uint64
	var x392 uint64
	x391, x392 = bits.Sub64(x379, 0xffffffff, uint64(0x0))
	var x393 uint64
	var x394 uint64
	x393, x394 = bits.Sub64(x381, 0xffffffff00000000, uint64(p384Uint1(x392)))
	var x395 uint64
	var x396 uint64
	x395, x396 = bits.Sub64(x383, 0xfffffffffffffffe, uint64(p384Uint1(x394)))
	var x397 uint64
	var x398 uint64
	x397, x398 = bits.Sub64(x385, 0xffffffffffffffff, uint64(p384Uint1(x396)))
	var x399 uint64
	var x400 uint64
	x399, x400 = bits.Sub64(x387, 0xffffffffffffffff, uint64(p384Uint1(x398)))
	var x401 uint64
	var x402 uint64
	x401, x402 = bits.Sub64(x389, 0xffffffffffffffff, uint64(p384Uint1(x400)))
	var x404 uint64
	_, x404 = bits.Sub64(uint64(p384Uint1(x390)), uint64(0x0), uint64(p384Uint1(x402)))
	var x405 uint64
	p384CmovznzU64(&x405, p384Uint1(x404), x391, x379)
	var x406 uint64
	p384CmovznzU64(&x406, p384Uint1(x404), x393, x381)
	var x407 uint64
	p384CmovznzU64(&x407, p384Uint1(x404), x395, x383)
	var x408 uint64
	p384CmovznzU64(&x408, p384Uint1(x404), x397, x385)
	var x409 uint64
	p384CmovznzU64(&x409, p384Uint1(x404), x399, x387)
	var x410 uint64
	p384CmovznzU64(&x410, p384Uint1(x404), x401, x389)
	out1[0] = x405
	out1[1] = x406
	out1[2] = x407
	out1[3] = x408
	out1[4] = x409
	out1[5] = x410
}

// p384Selectznz is a multi-limb conditional select.
//
// Postconditions:
//
//	eval out1 = (if arg1 = 0 then eval arg2 else eval arg3)
//
// Input Bounds:
//
//	arg1: [0x0 ~> 0x1]
//	arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//	arg3: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func p384Selectznz(out1 *[6]uint64, arg1 p384Uint1, arg2 *[6]uint64, arg3 *[6]uint64) {
	var x1 uint64
	p384CmovznzU64(&x1, arg1, arg2[0], arg3[0])
	var x2 uint64
	p384CmovznzU64(&x2, arg1, arg2[1], arg3[1])
	var x3 uint64
	p384CmovznzU64(&x3, arg1, arg2[2], arg3[2])
	var x4 uint64
	p384CmovznzU64(&x4, arg1, arg2[3], arg3[3])
	var x5 uint64
	p384CmovznzU64(&x5, arg1, arg2[4], arg3[4])
	var x6 uint64
	p384CmovznzU64(&x6, arg1, arg2[5], arg3[5])
	out1[0] = x1
	out1[1] = x2
	out1[2] = x3
	out1[3] = x4
	out1[4] = x5
	out1[5] = x6
}

// p384ToBytes serializes a field element NOT in the Montgomery domain to bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ eval arg1 < m
//
// Postconditions:
//
//	out1 = map (λ x, ⌊((eval arg1 mod m) mod 2^(8 * (x + 1))) / 2^(8 * x)⌋) [0..47]
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
func p384ToBytes(out1 *[48]uint8, arg1 *[6]uint64) {
	x1 := arg1[5]
	x2 := arg1[4]
	x3 := arg1[3]
	x4 := arg1[2]
	x5 := arg1[1]
	x6 := arg1[0]
	x7 := (uint8(x6) & 0xff)
	x8 := (x6 >> 8)
	x9 := (uint8(x8) & 0xff)
	x10 := (x8 >> 8)
	x11 := (uint8(x10) & 0xff)
	x12 := (x10 >> 8)
	x13 := (uint8(x12) & 0xff)
	x14 := (x12 >> 8)
	x15 := (uint8(x14) & 0xff)
	x16 := (x14 >> 8)
	x17 := (uint8(x16) & 0xff)
	x18 := (x16 >> 8)
	x19 := (uint8(x18) & 0xff)
	x20 := uint8((x18 >> 8))
	x21 := (uint8(x5) & 0xff)
	x22 := (x5 >> 8)
	x23 := (uint8(x22) & 0xff)
	x24 := (x22 >> 8)
	x25 := (uint8(x24) & 0xff)
	x26 := (x24 >> 8)
	x27 := (uint8(x26) & 0xff)
	x28 := (x26 >> 8)
	x29 := (uint8(x28) & 0xff)
	x30 := (x28 >> 8)
	x31 := (uint8(x30) & 0xff)
	x32 := (x30 >> 8)
	x33 := (uint8(x32) & 0xff)
	x34 := uint8((x32 >> 8))
	x35 := (uint8(x4) & 0xff)
	x36 := (x4 >> 8)
	x37 := (uint8(x36) & 0xff)
	x38 := (x36 >> 8)
	x39 := (uint8(x38) & 0xff)
	x40 := (x38 >> 8)
	x41 := (uint8(x40) & 0xff)
	x42 := (x40 >> 8)
	x43 := (uint8(x42) & 0xff)
	x44 := (x42 >> 8)
	x45 := (uint8(x44) & 0xff)
	x46 := (x44 >> 8)
	x47 := (uint8(x46) & 0xff)
	x48 := uint8((x46 >> 8))
	x49 := (uint8(x3) & 0xff)
	x50 := (x3 >> 8)
	x51 := (uint8(x50) & 0xff)
	x52 := (x50 >> 8)
	x53 := (uint8(x52) & 0xff)
	x54 := (x52 >> 8)
	x55 := (uint8(x54) & 0xff)
	x56 := (x54 >> 8)
	x57 := (uint8(x56) & 0xff)
	x58 := (x56 >> 8)
	x59 := (uint8(x58) & 0xff)
	x60 := (x58 >> 8)
	x61 := (uint8(x60) & 0xff)
	x62 := uint8((x60 >> 8))
	x63 := (uint8(x2) & 0xff)
	x64 := (x2 >> 8)
	x65 := (uint8(x64) & 0xff)
	x66 := (x64 >> 8)
	x67 := (uint8(x66) & 0xff)
	x68 := (x66 >> 8)
	x69 := (uint8(x68) & 0xff)
	x70 := (x68 >> 8)
	x71 := (uint8(x70) & 0xff)
	x72 := (x70 >> 8)
	x73 := (uint8(x72) & 0xff)
	x74 := (x72 >> 8)
	x75 := (uint8(x74) & 0xff)
	x76 := uint8((x74 >> 8))
	x77 := (uint8(x1) & 0xff)
	x78 := (x1 >> 8)
	x79 := (uint8(x78) & 0xff)
	x80 := (x78 >> 8)
	x81 := (uint8(x80) & 0xff)
	x82 := (x80 >> 8)
	x83 := (uint8(x82) & 0xff)
	x84 := (x82 >> 8)
	x85 := (uint8(x84) & 0xff)
	x86 := (x84 >> 8)
	x87 := (uint8(x86) & 0xff)
	x88 := (x86 >> 8)
	x89 := (uint8(x88) & 0xff)
	x90 := uint8((x88 >> 8))
	out1[0] = x7
	out1[1] = x9
	out1[2] = x11
	out1[3] = x13
	out1[4] = x15
	out1[5] = x17
	out1[6] = x19
	out1[7] = x20
	out1[8] = x21
	out1[9] = x23
	out1[10] = x25
	out1[11] = x27
	out1[12] = x29
	out1[13] = x31
	out1[14] = x33
	out1[15] = x34
	out1[16] = x35
	out1[17] = x37
	out1[18] = x39
	out1[19] = x41
	out1[20] = x43
	out1[21] = x45
	out1[22] = x47
	out1[23] = x48
	out1[24] = x49
	out1[25] = x51
	out1[26] = x53
	out1[27] = x55
	out1[28] = x57
	out1[29] = x59
	out1[30] = x61
	out1[31] = x62
	out1[32] = x63
	out1[33] = x65
	out1[34] = x67
	out1[35] = x69
	out1[36] = x71
	out1[37] = x73
	out1[38] = x75
	out1[39] = x76
	out1[40] = x77
	out1[41] = x79
	out1[42] = x81
	out1[43] = x83
	out1[44] = x85
	out1[45] = x87
	out1[46] = x89
	out1[47] = x90
}

// p384FromBytes deserializes a field element NOT in the Montgomery domain from bytes in little-endian order.
//
// Preconditions:
//
//	0 ≤ bytes_eval arg1 < m
//
// Postconditions:
//
//	eval out1 mod m = bytes_eval arg1 mod m
//	0 ≤ eval out1 < m
//
// Input Bounds:
//
//	arg1: [[0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff], [0x0 ~> 0xff]]
//
// Output Bounds:
//
//	out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func p384FromBytes(out1 *[6]uint64, arg1 *[48]uint8) {
	x1 := (uint64(arg1[47]) << 56)
	x2 := (uint64(arg1[46]) << 48)
	x3 := (uint64(arg1[45]) << 40)
	x4 := (uint64(arg1[44]) << 32)
	x5 := (uint64(arg1[43]) << 24)
	x6 := (uint64(arg1[42]) << 16)
	x7 := (uint64(arg1[41]) << 8)
	x8 := arg1[40]
	x9 := (uint64(arg1[39]) << 56)
	x10 := (uint64(arg1[38]) << 48)
	x11 := (uint64(arg1[37]) << 40)
	x12 := (uint64(arg1[36]) << 32)
	x13 := (uint64(arg1[35]) << 24)
	x14 := (uint64(arg1[34]) << 16)
	x15 := (uint64(arg1[33]) << 8)
	x16 := arg1[32]
	x17 := (uint64(arg1[31]) << 56)
	x18 := (uint64(arg1[30]) << 48)
	x19 := (uint64(arg1[29]) << 40)
	x20 := (uint64(arg1[28]) << 32)
	x21 := (uint64(arg1[27]) << 24)
	x22 := (uint64(arg1[26]) << 16)
	x23 := (uint64(arg1[25]) << 8)
	x24 := arg1[24]
	x25 := (uint64(arg1[23]) << 56)
	x26 := (uint64(arg1[22]) << 48)
	x27 := (uint64(arg1[21]) << 40)
	x28 := (uint64(arg1[20]) << 32)
	x29 := (uint64(arg1[19]) << 24)
	x30 := (uint64(arg1[18]) << 16)
	x31 := (uint64(arg1[17]) << 8)
	x32 := arg1[16]
	x33 := (uint64(arg1[15]) << 56)
	x34 := (uint64(arg1[14]) << 48)
	x35 := (uint64(arg1[13]) << 40)
	x36 := (uint64(arg1[12]) << 32)
	x37 := (uint64(arg1[11]) << 24)
	x38 := (uint64(arg1[10]) << 16)
	x39 := (uint64(arg1[9]) << 8)
	x40 := arg1[8]
	x41 := (uint64(arg1[7]) << 56)
	x42 := (uint64(arg1[6]) << 48)
	x43 := (uint64(arg1[5]) << 40)
	x44 := (uint64(arg1[4]) << 32)
	x45 := (uint64(arg1[3]) << 24)
	x46 := (uint64(arg1[2]) << 16)
	x47 := (uint64(arg1[1]) << 8)
	x48 := arg1[0]
	x49 := (x47 + uint64(x48))
	x50 := (x46 + x49)
	x51 := (x45 + x50)
	x52 := (x44 + x51)
	x53 := (x43 + x52)
	x54 := (x42 + x53)
	x55 := (x41 + x54)
	x56 := (x39 + uint64(x40))
	x57 := (x38 + x56)
	x58 := (x37 + x57)
	x59 := (x36 + x58)
	x60 := (x35 + x59)
	x61 := (x34 + x60)
	x62 := (x33 + x61)
	x63 := (x31 + uint64(x32))
	x64 := (x30 + x63)
	x65 := (x29 + x64)
	x66 := (x28 + x65)
	x67 := (x27 + x66)
	x68 := (x26 + x67)
	x69 := (x25 + x68)
	x70 := (x23 + uint64(x24))
	x71 := (x22 + x70)
	x72 := (x21 + x71)
	x73 := (x20 + x72)
	x74 := (x19 + x73)
	x75 := (x18 + x74)
	x76 := (x17 + x75)
	x77 := (x15 + uint64(x16))
	x78 := (x14 + x77)
	x79 := (x13 + x78)
	x80 := (x12 + x79)
	x81 := (x11 + x80)
	x82 := (x10 + x81)
	x83 := (x9 + x82)
	x84 := (x7 + uint64(x8))
	x85 := (x6 + x84)
	x86 := (x5 + x85)
	x87 := (x4 + x86)
	x88 := (x3 + x87)
	x89 := (x2 + x88)
	x90 := (x1 + x89)
	out1[0] = x55
	out1[1] = x62
	out1[2] = x69
	out1[3] = x76
	out1[4] = x83
	out1[5] = x90
}

"""




```