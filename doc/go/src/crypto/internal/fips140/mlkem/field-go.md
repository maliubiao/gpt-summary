Response:
The user wants to understand the functionality of the provided Go code snippet. This code implements field arithmetic and polynomial operations over a finite field, likely used in a cryptographic context, specifically ML-KEM.

Here's a breakdown of the thought process:

1. **Identify the Core Data Structures:** The code defines `fieldElement` (uint16 representing elements in ℤ_q) and `ringElement` (array of `fieldElement` representing polynomials). Also, `nttElement` is introduced, which looks like another representation of a polynomial, possibly in the Number Theoretic Transform domain.

2. **Analyze Individual Functions:** Go through each function and determine its purpose:
    * `fieldCheckReduced`: Checks if a `uint16` is less than `q`.
    * `fieldReduceOnce`: Reduces a `uint16` modulo `q` (assuming it's less than `2q`).
    * `fieldAdd`, `fieldSub`, `fieldMul`: Standard field arithmetic operations.
    * `fieldReduce`: Reduces a `uint32` modulo `q` using Barrett reduction.
    * `fieldMulSub`, `fieldAddMul`: Fused field operations for efficiency.
    * `compress`, `decompress`: Functions for mapping field elements to and from a smaller bit representation.
    * `polyAdd`, `polySub`: Polynomial addition and subtraction.
    * `polyByteEncode`, `polyByteDecode`: Functions for encoding and decoding polynomial coefficients to/from byte arrays.
    * `sliceForAppend`: A utility function for efficient byte slice appending.
    * `ringCompressAndEncodeX`, `ringDecodeAndDecompressX`:  Functions for compressing and encoding/decoding ring elements with different compression ratios. These likely correspond to different levels of precision or bandwidth requirements.
    * `samplePolyCBD`: Samples a polynomial from a specific distribution using a pseudo-random function.
    * `ntt`, `inverseNTT`: Implement the Number Theoretic Transform and its inverse. This is a fast way to perform polynomial multiplication in specific algebraic structures.
    * `nttMul`: Multiplies two polynomials in the NTT domain.
    * `sampleNTT`: Samples a polynomial directly in the NTT domain.

3. **Infer Overall Purpose:** Based on the function names and the use of terms like "compress," "decompress," "NTT," and the FIPS copyright notice, the code likely implements core mathematical operations for a lattice-based cryptographic scheme, probably ML-KEM (based on the package name). The compression/decompression functions suggest this is about efficiently representing and transmitting these elements. The NTT functions indicate polynomial multiplication is a key operation.

4. **Provide Code Examples:**  Illustrate the usage of key functions with simple examples. Focus on demonstrating the basic operations like addition, subtraction, multiplication, and compression/decompression. Include expected inputs and outputs to make the examples clear.

5. **Consider Command-Line Arguments:** Since the code is a library, it doesn't directly handle command-line arguments. Mention that its usage is within a larger application.

6. **Identify Potential Pitfalls:** Think about common mistakes when using this type of code:
    * **Incorrectly assuming inputs are reduced:**  Highlight the importance of ensuring inputs to functions like `fieldAdd` are already reduced modulo `q`. The `fieldCheckReduced` function is a hint towards this.
    * **Mismatched compression/decompression parameters:** Emphasize the need to use the same `d` value for compression and decompression.

7. **Structure the Answer:** Organize the information logically with clear headings for functionality, code examples, command-line arguments, and potential pitfalls. Use Chinese as requested.

8. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the code examples are correct and easy to understand.
这段代码是 Go 语言中用于实现 ML-KEM（Module-Lattice-based Key Encapsulation Mechanism）算法中有限域运算的一部分。更具体地说，它定义了在模 `q` 的整数环上的元素及其运算，以及在该环上的多项式（环元素）的表示和操作。

以下是其主要功能：

1. **定义有限域元素:**
   - 定义了 `fieldElement` 类型，它是一个 `uint16` 类型的别名，用于表示模 `q` 的整数。
   - 提供 `fieldCheckReduced` 函数来检查一个 `uint16` 值是否小于 `q`，即是否已约减。
   - 提供 `fieldReduceOnce` 函数用于将一个小于 `2q` 的 `uint16` 值约减到模 `q` 的范围内。

2. **实现有限域算术运算:**
   - 提供了 `fieldAdd`、`fieldSub` 和 `fieldMul` 函数，分别用于执行有限域元素的加法、减法和乘法运算，结果始终保持约减状态。
   - 提供了使用 Barrett 约减算法的 `fieldReduce` 函数，用于高效地将一个小于 `2q²` 的 `uint32` 值约减到模 `q` 的范围内。这通常用于乘法运算后的结果约减。
   - 提供了优化的复合运算 `fieldMulSub` (计算 `a * (b - c)`) 和 `fieldAddMul` (计算 `a * b + c * d`)，以减少约减操作的次数，提高效率。

3. **实现有限域元素的压缩和解压缩:**
   - 提供了 `compress` 函数，将一个有限域元素均匀地映射到 `0` 到 `2ᵈ-1` 的范围内，用于减小数据表示的大小。这个过程遵循 FIPS 203 的定义。
   - 提供了 `decompress` 函数，将一个 `0` 到 `2ᵈ-1` 范围内的数均匀地映射回完整的有限域元素范围。这个过程也遵循 FIPS 203 的定义。

4. **定义环元素（多项式）及其运算:**
   - 定义了 `ringElement` 类型，它是一个包含 `n` 个 `fieldElement` 的数组，表示模 `xⁿ + 1` 的多项式。
   - 提供了 `polyAdd` 和 `polySub` 函数，用于执行环元素的加法和减法运算。

5. **实现环元素的字节编码和解码:**
   - 提供了 `polyByteEncode` 函数，将一个环元素编码为 384 字节的表示。
   - 提供了 `polyByteDecode` 函数，从 384 字节的编码解码出一个环元素，并检查所有系数是否已正确约减。

6. **提供辅助函数:**
   - 提供了 `sliceForAppend` 函数，用于高效地扩展字节切片。

7. **实现环元素的压缩和编码/解码的不同方案:**
   - 提供了多种 `ringCompressAndEncodeX` 和 `ringDecodeAndDecompressX` 函数，其中 `X` 表示压缩的比特数 (1, 4, 10, 5, 11)。这些函数用于将环元素压缩到不同的比特长度，并在字节数组之间进行编码和解码。

8. **实现基于中心二项分布 (CBD) 的多项式采样:**
   - 提供了 `samplePolyCBD` 函数，根据 FIPS 203 的算法，使用伪随机函数 (PRF) 生成的随机字节流，采样出一个服从特定分布的环元素。

9. **定义 NTT 元素及其运算:**
   - 定义了 `nttElement` 类型，它是一个包含 `n` 个 `fieldElement` 的数组，表示经过数论变换 (NTT) 后的多项式。
   - 提供了 `nttMul` 函数，用于执行两个 NTT 元素的乘法运算。

10. **实现数论变换 (NTT) 及其逆变换:**
    - 提供了 `ntt` 函数，将一个环元素转换为其 NTT 表示。
    - 提供了 `inverseNTT` 函数，将一个 NTT 元素转换回其环元素表示。

11. **实现 NTT 元素的采样:**
    - 提供了 `sampleNTT` 函数，使用可扩展输出函数 (XOF) 生成的随机字节流，采样出一个均匀随机的 NTT 元素。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了**模运算**和**多项式运算**，这是许多密码学算法的基础。具体来说，它针对 ML-KEM 算法的需求，实现了在特定有限域上的高效算术运算，以及多项式的表示、编码、解码和采样。  NTT 的实现是为了加速多项式乘法，这在 ML-KEM 的密钥生成、加密和解密过程中是核心操作。

**Go 代码举例说明:**

假设我们要对两个有限域元素进行加法和乘法运算：

```go
package main

import (
	"fmt"
	"go/src/crypto/internal/fips140/mlkem" // 假设你的代码在这个路径
)

func main() {
	// 假设 q 的值在 mlkem 包的其他地方定义
	const q = 3329 // 示例值

	// 创建两个有限域元素
	a, err := mlkem.FieldCheckReduced(100)
	if err != nil {
		panic(err)
	}
	b, err := mlkem.FieldCheckReduced(200)
	if err != nil {
		panic(err)
	}

	// 执行加法
	sum := mlkem.FieldAdd(a, b)
	fmt.Printf("a + b = %d\n", sum) // 输出: a + b = 300

	// 执行乘法
	product := mlkem.FieldMul(a, b)
	fmt.Printf("a * b = %d\n", product) // 输出: a * b = 2000

	// 创建一个未约减的元素并进行约减
	unreduced := uint16(q + 100)
	reduced := mlkem.FieldReduceOnce(unreduced)
	fmt.Printf("Reduced %d to %d\n", unreduced, reduced) // 输出: Reduced 3429 to 100
}
```

**假设的输入与输出:**

在上面的例子中：

- **输入:** `a = 100`, `b = 200`
- **输出:** `sum = 300`, `product = 2000`

- **输入:** `unreduced = 3429` (假设 `q = 3329`)
- **输出:** `reduced = 100`

**命令行参数的具体处理:**

这段代码本身是一个库，并不直接处理命令行参数。它提供的功能会被其他的程序或库调用。如果一个使用这个库的程序需要处理命令行参数，那将是在该程序中实现的，而不是在这段代码中。

**使用者易犯错的点:**

1. **没有检查输入是否已约减:**  使用者可能会直接使用大于或等于 `q` 的值进行运算，导致结果不正确。例如：

   ```go
   package main

   import (
   	"fmt"
   	"go/src/crypto/internal/fips140/mlkem" // 假设你的代码在这个路径
   )

   func main() {
   	const q = 3329 // 示例值

   	// 错误地使用未约减的值
   	a := mlkem.FieldElement(q + 100)
   	b := mlkem.FieldElement(200)

   	// 加法结果可能不符合预期，因为 a 不是一个有效的约减后的 fieldElement
   	sum := mlkem.FieldAdd(a, b)
   	fmt.Printf("错误的 a + b = %d\n", sum) // 输出: 错误的 a + b = 499
   }
   ```

   在这个例子中，`a` 的值是 `3429`，虽然它可以被转换为 `fieldElement` 类型，但它并不是一个已经约减的值。如果直接使用它进行运算，结果可能不是预期的模 `q` 的结果。正确的做法是先使用 `fieldCheckReduced` 检查或使用 `fieldReduceOnce` 进行约减。

2. **压缩和解压缩时使用错误的 `d` 值:** `compress` 和 `decompress` 函数依赖于相同的 `d` 值。如果压缩时使用了某个 `d` 值，解压缩时使用了不同的 `d` 值，将会得到错误的结果。

   ```go
   package main

   import (
   	"fmt"
   	"go/src/crypto/internal/fips140/mlkem" // 假设你的代码在这个路径
   )

   func main() {
   	const q = 3329 // 示例值

   	val, _ := mlkem.FieldCheckReduced(1234)

   	// 使用 d=4 进行压缩
   	compressed := mlkem.Compress(val, 4)
   	fmt.Printf("Compressed value: %d\n", compressed)

   	// 错误地使用 d=5 进行解压缩
   	decompressed := mlkem.Decompress(compressed, 5)
   	fmt.Printf("Incorrectly decompressed value: %d\n", decompressed)

   	// 正确地使用 d=4 进行解压缩
   	correctlyDecompressed := mlkem.Decompress(compressed, 4)
   	fmt.Printf("Correctly decompressed value: %d\n", correctlyDecompressed)
   }
   ```

   在这个例子中，使用 `d=4` 压缩后，如果使用 `d=5` 解压缩，得到的值将与原始值不同。必须使用相同的 `d` 值才能正确恢复原始的有限域元素。

Prompt: 
```
这是路径为go/src/crypto/internal/fips140/mlkem/field.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mlkem

import (
	"crypto/internal/fips140/sha3"
	"crypto/internal/fips140deps/byteorder"
	"errors"
)

// fieldElement is an integer modulo q, an element of ℤ_q. It is always reduced.
type fieldElement uint16

// fieldCheckReduced checks that a value a is < q.
func fieldCheckReduced(a uint16) (fieldElement, error) {
	if a >= q {
		return 0, errors.New("unreduced field element")
	}
	return fieldElement(a), nil
}

// fieldReduceOnce reduces a value a < 2q.
func fieldReduceOnce(a uint16) fieldElement {
	x := a - q
	// If x underflowed, then x >= 2¹⁶ - q > 2¹⁵, so the top bit is set.
	x += (x >> 15) * q
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint16(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint16(a - b + q)
	return fieldReduceOnce(x)
}

const (
	barrettMultiplier = 5039 // 2¹² * 2¹² / q
	barrettShift      = 24   // log₂(2¹² * 2¹²)
)

// fieldReduce reduces a value a < 2q² using Barrett reduction, to avoid
// potentially variable-time division.
func fieldReduce(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

func fieldMul(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldReduce(x)
}

// fieldMulSub returns a * (b - c). This operation is fused to save a
// fieldReduceOnce after the subtraction.
func fieldMulSub(a, b, c fieldElement) fieldElement {
	x := uint32(a) * uint32(b-c+q)
	return fieldReduce(x)
}

// fieldAddMul returns a * b + c * d. This operation is fused to save a
// fieldReduceOnce and a fieldReduce.
func fieldAddMul(a, b, c, d fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	x += uint32(c) * uint32(d)
	return fieldReduce(x)
}

// compress maps a field element uniformly to the range 0 to 2ᵈ-1, according to
// FIPS 203, Definition 4.7.
func compress(x fieldElement, d uint8) uint16 {
	// We want to compute (x * 2ᵈ) / q, rounded to nearest integer, with 1/2
	// rounding up (see FIPS 203, Section 2.3).

	// Barrett reduction produces a quotient and a remainder in the range [0, 2q),
	// such that dividend = quotient * q + remainder.
	dividend := uint32(x) << d // x * 2ᵈ
	quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
	remainder := dividend - quotient*q

	// Since the remainder is in the range [0, 2q), not [0, q), we need to
	// portion it into three spans for rounding.
	//
	//     [ 0,       q/2     ) -> round to 0
	//     [ q/2,     q + q/2 ) -> round to 1
	//     [ q + q/2, 2q      ) -> round to 2
	//
	// We can convert that to the following logic: add 1 if remainder > q/2,
	// then add 1 again if remainder > q + q/2.
	//
	// Note that if remainder > x, then ⌊x⌋ - remainder underflows, and the top
	// bit of the difference will be set.
	quotient += (q/2 - remainder) >> 31 & 1
	quotient += (q + q/2 - remainder) >> 31 & 1

	// quotient might have overflowed at this point, so reduce it by masking.
	var mask uint32 = (1 << d) - 1
	return uint16(quotient & mask)
}

// decompress maps a number x between 0 and 2ᵈ-1 uniformly to the full range of
// field elements, according to FIPS 203, Definition 4.8.
func decompress(y uint16, d uint8) fieldElement {
	// We want to compute (y * q) / 2ᵈ, rounded to nearest integer, with 1/2
	// rounding up (see FIPS 203, Section 2.3).

	dividend := uint32(y) * q
	quotient := dividend >> d // (y * q) / 2ᵈ

	// The d'th least-significant bit of the dividend (the most significant bit
	// of the remainder) is 1 for the top half of the values that divide to the
	// same quotient, which are the ones that round up.
	quotient += dividend >> (d - 1) & 1

	// quotient is at most (2¹¹-1) * q / 2¹¹ + 1 = 3328, so it didn't overflow.
	return fieldElement(quotient)
}

// ringElement is a polynomial, an element of R_q, represented as an array
// according to FIPS 203, Section 2.4.4.
type ringElement [n]fieldElement

// polyAdd adds two ringElements or nttElements.
func polyAdd[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldAdd(a[i], b[i])
	}
	return s
}

// polySub subtracts two ringElements or nttElements.
func polySub[T ~[n]fieldElement](a, b T) (s T) {
	for i := range s {
		s[i] = fieldSub(a[i], b[i])
	}
	return s
}

// polyByteEncode appends the 384-byte encoding of f to b.
//
// It implements ByteEncode₁₂, according to FIPS 203, Algorithm 5.
func polyByteEncode[T ~[n]fieldElement](b []byte, f T) []byte {
	out, B := sliceForAppend(b, encodingSize12)
	for i := 0; i < n; i += 2 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		B[0] = uint8(x)
		B[1] = uint8(x >> 8)
		B[2] = uint8(x >> 16)
		B = B[3:]
	}
	return out
}

// polyByteDecode decodes the 384-byte encoding of a polynomial, checking that
// all the coefficients are properly reduced. This fulfills the "Modulus check"
// step of ML-KEM Encapsulation.
//
// It implements ByteDecode₁₂, according to FIPS 203, Algorithm 6.
func polyByteDecode[T ~[n]fieldElement](b []byte) (T, error) {
	if len(b) != encodingSize12 {
		return T{}, errors.New("mlkem: invalid encoding length")
	}
	var f T
	for i := 0; i < n; i += 2 {
		d := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		const mask12 = 0b1111_1111_1111
		var err error
		if f[i], err = fieldCheckReduced(uint16(d & mask12)); err != nil {
			return T{}, errors.New("mlkem: invalid polynomial encoding")
		}
		if f[i+1], err = fieldCheckReduced(uint16(d >> 12)); err != nil {
			return T{}, errors.New("mlkem: invalid polynomial encoding")
		}
		b = b[3:]
	}
	return f, nil
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// ringCompressAndEncode1 appends a 32-byte encoding of a ring element to s,
// compressing one coefficients per bit.
//
// It implements Compress₁, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode1(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	for i := range b {
		b[i] = 0
	}
	for i := range f {
		b[i/8] |= uint8(compress(f[i], 1) << (i % 8))
	}
	return s
}

// ringDecodeAndDecompress1 decodes a 32-byte slice to a ring element where each
// bit is mapped to 0 or ⌈q/2⌋.
//
// It implements ByteDecode₁, according to FIPS 203, Algorithm 6,
// followed by Decompress₁, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress1(b *[encodingSize1]byte) ringElement {
	var f ringElement
	for i := range f {
		b_i := b[i/8] >> (i % 8) & 1
		const halfQ = (q + 1) / 2        // ⌈q/2⌋, rounded up per FIPS 203, Section 2.3
		f[i] = fieldElement(b_i) * halfQ // 0 decompresses to 0, and 1 to ⌈q/2⌋
	}
	return f
}

// ringCompressAndEncode4 appends a 128-byte encoding of a ring element to s,
// compressing two coefficients per byte.
//
// It implements Compress₄, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₄, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode4(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[i/2] = uint8(compress(f[i], 4) | compress(f[i+1], 4)<<4)
	}
	return s
}

// ringDecodeAndDecompress4 decodes a 128-byte encoding of a ring element where
// each four bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₄, according to FIPS 203, Algorithm 6,
// followed by Decompress₄, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress4(b *[encodingSize4]byte) ringElement {
	var f ringElement
	for i := 0; i < n; i += 2 {
		f[i] = fieldElement(decompress(uint16(b[i/2]&0b1111), 4))
		f[i+1] = fieldElement(decompress(uint16(b[i/2]>>4), 4))
	}
	return f
}

// ringCompressAndEncode10 appends a 320-byte encoding of a ring element to s,
// compressing four coefficients per five bytes.
//
// It implements Compress₁₀, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁₀, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode10(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	for i := 0; i < n; i += 4 {
		var x uint64
		x |= uint64(compress(f[i], 10))
		x |= uint64(compress(f[i+1], 10)) << 10
		x |= uint64(compress(f[i+2], 10)) << 20
		x |= uint64(compress(f[i+3], 10)) << 30
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b[3] = uint8(x >> 24)
		b[4] = uint8(x >> 32)
		b = b[5:]
	}
	return s
}

// ringDecodeAndDecompress10 decodes a 320-byte encoding of a ring element where
// each ten bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₁₀, according to FIPS 203, Algorithm 6,
// followed by Decompress₁₀, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress10(bb *[encodingSize10]byte) ringElement {
	b := bb[:]
	var f ringElement
	for i := 0; i < n; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
		b = b[5:]
		f[i] = fieldElement(decompress(uint16(x>>0&0b11_1111_1111), 10))
		f[i+1] = fieldElement(decompress(uint16(x>>10&0b11_1111_1111), 10))
		f[i+2] = fieldElement(decompress(uint16(x>>20&0b11_1111_1111), 10))
		f[i+3] = fieldElement(decompress(uint16(x>>30&0b11_1111_1111), 10))
	}
	return f
}

// ringCompressAndEncode appends an encoding of a ring element to s,
// compressing each coefficient to d bits.
//
// It implements Compress, according to FIPS 203, Definition 4.7,
// followed by ByteEncode, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode(s []byte, f ringElement, d uint8) []byte {
	var b byte
	var bIdx uint8
	for i := 0; i < n; i++ {
		c := compress(f[i], d)
		var cIdx uint8
		for cIdx < d {
			b |= byte(c>>cIdx) << bIdx
			bits := min(8-bIdx, d-cIdx)
			bIdx += bits
			cIdx += bits
			if bIdx == 8 {
				s = append(s, b)
				b = 0
				bIdx = 0
			}
		}
	}
	if bIdx != 0 {
		panic("mlkem: internal error: bitsFilled != 0")
	}
	return s
}

// ringDecodeAndDecompress decodes an encoding of a ring element where
// each d bits are mapped to an equidistant distribution.
//
// It implements ByteDecode, according to FIPS 203, Algorithm 6,
// followed by Decompress, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress(b []byte, d uint8) ringElement {
	var f ringElement
	var bIdx uint8
	for i := 0; i < n; i++ {
		var c uint16
		var cIdx uint8
		for cIdx < d {
			c |= uint16(b[0]>>bIdx) << cIdx
			c &= (1 << d) - 1
			bits := min(8-bIdx, d-cIdx)
			bIdx += bits
			cIdx += bits
			if bIdx == 8 {
				b = b[1:]
				bIdx = 0
			}
		}
		f[i] = fieldElement(decompress(c, d))
	}
	if len(b) != 0 {
		panic("mlkem: internal error: leftover bytes")
	}
	return f
}

// ringCompressAndEncode5 appends a 160-byte encoding of a ring element to s,
// compressing eight coefficients per five bytes.
//
// It implements Compress₅, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₅, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode5(s []byte, f ringElement) []byte {
	return ringCompressAndEncode(s, f, 5)
}

// ringDecodeAndDecompress5 decodes a 160-byte encoding of a ring element where
// each five bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₅, according to FIPS 203, Algorithm 6,
// followed by Decompress₅, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress5(bb *[encodingSize5]byte) ringElement {
	return ringDecodeAndDecompress(bb[:], 5)
}

// ringCompressAndEncode11 appends a 352-byte encoding of a ring element to s,
// compressing eight coefficients per eleven bytes.
//
// It implements Compress₁₁, according to FIPS 203, Definition 4.7,
// followed by ByteEncode₁₁, according to FIPS 203, Algorithm 5.
func ringCompressAndEncode11(s []byte, f ringElement) []byte {
	return ringCompressAndEncode(s, f, 11)
}

// ringDecodeAndDecompress11 decodes a 352-byte encoding of a ring element where
// each eleven bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₁₁, according to FIPS 203, Algorithm 6,
// followed by Decompress₁₁, according to FIPS 203, Definition 4.8.
func ringDecodeAndDecompress11(bb *[encodingSize11]byte) ringElement {
	return ringDecodeAndDecompress(bb[:], 11)
}

// samplePolyCBD draws a ringElement from the special Dη distribution given a
// stream of random bytes generated by the PRF function, according to FIPS 203,
// Algorithm 8 and Definition 4.3.
func samplePolyCBD(s []byte, b byte) ringElement {
	prf := sha3.NewShake256()
	prf.Write(s)
	prf.Write([]byte{b})
	B := make([]byte, 64*2) // η = 2
	prf.Read(B)

	// SamplePolyCBD simply draws four (2η) bits for each coefficient, and adds
	// the first two and subtracts the last two.

	var f ringElement
	for i := 0; i < n; i += 2 {
		b := B[i/2]
		b_7, b_6, b_5, b_4 := b>>7, b>>6&1, b>>5&1, b>>4&1
		b_3, b_2, b_1, b_0 := b>>3&1, b>>2&1, b>>1&1, b&1
		f[i] = fieldSub(fieldElement(b_0+b_1), fieldElement(b_2+b_3))
		f[i+1] = fieldSub(fieldElement(b_4+b_5), fieldElement(b_6+b_7))
	}
	return f
}

// nttElement is an NTT representation, an element of T_q, represented as an
// array according to FIPS 203, Section 2.4.4.
type nttElement [n]fieldElement

// gammas are the values ζ^2BitRev7(i)+1 mod q for each index i, according to
// FIPS 203, Appendix A (with negative values reduced to positive).
var gammas = [128]fieldElement{17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175}

// nttMul multiplies two nttElements.
//
// It implements MultiplyNTTs, according to FIPS 203, Algorithm 11.
func nttMul(f, g nttElement) nttElement {
	var h nttElement
	// We use i += 2 for bounds check elimination. See https://go.dev/issue/66826.
	for i := 0; i < 256; i += 2 {
		a0, a1 := f[i], f[i+1]
		b0, b1 := g[i], g[i+1]
		h[i] = fieldAddMul(a0, b0, fieldMul(a1, b1), gammas[i/2])
		h[i+1] = fieldAddMul(a0, b1, a1, b0)
	}
	return h
}

// zetas are the values ζ^BitRev7(k) mod q for each index k, according to FIPS
// 203, Appendix A.
var zetas = [128]fieldElement{1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154}

// ntt maps a ringElement to its nttElement representation.
//
// It implements NTT, according to FIPS 203, Algorithm 9.
func ntt(f ringElement) nttElement {
	k := 1
	for len := 128; len >= 2; len /= 2 {
		for start := 0; start < 256; start += 2 * len {
			zeta := zetas[k]
			k++
			// Bounds check elimination hint.
			f, flen := f[start:start+len], f[start+len:start+len+len]
			for j := 0; j < len; j++ {
				t := fieldMul(zeta, flen[j])
				flen[j] = fieldSub(f[j], t)
				f[j] = fieldAdd(f[j], t)
			}
		}
	}
	return nttElement(f)
}

// inverseNTT maps a nttElement back to the ringElement it represents.
//
// It implements NTT⁻¹, according to FIPS 203, Algorithm 10.
func inverseNTT(f nttElement) ringElement {
	k := 127
	for len := 2; len <= 128; len *= 2 {
		for start := 0; start < 256; start += 2 * len {
			zeta := zetas[k]
			k--
			// Bounds check elimination hint.
			f, flen := f[start:start+len], f[start+len:start+len+len]
			for j := 0; j < len; j++ {
				t := f[j]
				f[j] = fieldAdd(t, flen[j])
				flen[j] = fieldMulSub(zeta, flen[j], t)
			}
		}
	}
	for i := range f {
		f[i] = fieldMul(f[i], 3303) // 3303 = 128⁻¹ mod q
	}
	return ringElement(f)
}

// sampleNTT draws a uniformly random nttElement from a stream of uniformly
// random bytes generated by the XOF function, according to FIPS 203,
// Algorithm 7.
func sampleNTT(rho []byte, ii, jj byte) nttElement {
	B := sha3.NewShake128()
	B.Write(rho)
	B.Write([]byte{ii, jj})

	// SampleNTT essentially draws 12 bits at a time from r, interprets them in
	// little-endian, and rejects values higher than q, until it drew 256
	// values. (The rejection rate is approximately 19%.)
	//
	// To do this from a bytes stream, it draws three bytes at a time, and
	// splits them into two uint16 appropriately masked.
	//
	//               r₀              r₁              r₂
	//       |- - - - - - - -|- - - - - - - -|- - - - - - - -|
	//
	//               Uint16(r₀ || r₁)
	//       |- - - - - - - - - - - - - - - -|
	//       |- - - - - - - - - - - -|
	//                   d₁
	//
	//                                Uint16(r₁ || r₂)
	//                       |- - - - - - - - - - - - - - - -|
	//                               |- - - - - - - - - - - -|
	//                                           d₂
	//
	// Note that in little-endian, the rightmost bits are the most significant
	// bits (dropped with a mask) and the leftmost bits are the least
	// significant bits (dropped with a right shift).

	var a nttElement
	var j int        // index into a
	var buf [24]byte // buffered reads from B
	off := len(buf)  // index into buf, starts in a "buffer fully consumed" state
	for {
		if off >= len(buf) {
			B.Read(buf[:])
			off = 0
		}
		d1 := byteorder.LEUint16(buf[off:]) & 0b1111_1111_1111
		d2 := byteorder.LEUint16(buf[off+1:]) >> 4
		off += 3
		if d1 < q {
			a[j] = fieldElement(d1)
			j++
		}
		if j >= len(a) {
			break
		}
		if d2 < q {
			a[j] = fieldElement(d2)
			j++
		}
		if j >= len(a) {
			break
		}
	}
	return a
}

"""



```