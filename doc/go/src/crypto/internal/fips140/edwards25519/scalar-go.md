Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the given Go code, its purpose, examples, potential pitfalls, and to be in Chinese.

2. **Initial Scan and Key Observations:**  The first thing that jumps out is the package name: `go/src/crypto/internal/fips140/edwards25519/scalar.go`. This immediately suggests cryptographic operations related to the Edwards25519 curve, and the "fips140" part hints at a focus on compliance and potentially restricted functionality. The filename `scalar.go` strongly implies this code deals with scalar values used in the elliptic curve cryptography context.

3. **Decomposition by Type and Functions:**  Next, systematically analyze the defined types and functions:

    * **`Scalar` struct:**  The comment clearly defines it as an integer modulo `l`, the order of the Edwards25519 group. It also mentions it works similarly to `math/big.Int`. The presence of `fiatScalarMontgomeryDomainFieldElement` as its underlying representation is a crucial detail, indicating a specific mathematical domain used for efficient computation. The comments about `fiat-crypto` and its license are also important context.

    * **`NewScalar()`:**  This is a straightforward constructor returning a zero-initialized `Scalar`.

    * **Arithmetic Operations (`MultiplyAdd`, `Add`, `Subtract`, `Negate`, `Multiply`):**  These functions implement standard modular arithmetic operations for scalars. The comments like `// s = 1 * x + y mod l` are helpful in understanding the underlying mathematical operations. Notice they all call `fiatScalar...` functions, further reinforcing the use of the `fiat-crypto` library.

    * **`Set()`:**  A simple setter to copy the value of another `Scalar`.

    * **`SetUniformBytes()`:** This function takes a 64-byte slice and sets the `Scalar` to its value modulo `l`. The code's explanation of how it handles the 512-bit input using precomputed powers of 2 is a key detail.

    * **`scalarTwo168` and `scalarTwo336`:** These are constants used within `SetUniformBytes` for the modular reduction.

    * **`setShortBytes()`:** A helper function to set a `Scalar` from a shorter byte slice (less than 32 bytes). The conversion to Montgomery domain is noted.

    * **`SetCanonicalBytes()`:**  This function sets a `Scalar` from a 32-byte little-endian representation *only if* it's a canonical encoding (less than `l`). The `isReduced()` function is clearly related.

    * **`scalarMinusOneBytes`:**  The value of `l - 1` in little-endian, used by `isReduced()`.

    * **`isReduced()`:** Checks if a byte slice represents a scalar less than `l`.

    * **`SetBytesWithClamping()`:** This function implements the clamping operation specified in RFC 8032. The comment explains the historical reasons and the fact that the cofactor clearing aspect isn't relevant here since we are always working modulo `l`. The use of `SetUniformBytes` internally is a key observation.

    * **`Bytes()` and `bytes()`:**  Functions to get the canonical 32-byte little-endian representation of the `Scalar`. The conversion from Montgomery domain back to the standard representation is important.

    * **`Equal()`:** Compares two `Scalar`s for equality. The bitwise operations to check if `diff` is zero are a bitmask trick.

    * **`nonAdjacentForm()`:** Computes the Non-Adjacent Form (NAF) of the scalar, which is used in efficient scalar multiplication algorithms. The reference to `curve25519-dalek` is a good pointer for more information.

    * **`signedRadix16()`:**  Computes the signed radix-16 representation of the scalar, another technique used for efficient scalar multiplication.

4. **Identify the Core Functionality:** Based on the individual function analysis, the core functionality revolves around:

    * **Representing scalars modulo the order of the Edwards25519 group.**
    * **Performing modular arithmetic operations on these scalars.**
    * **Converting between byte representations and `Scalar` objects.**
    * **Implementing optimizations for scalar multiplication (NAF and signed radix-16).**

5. **Infer the Go Language Feature:**  The code implements a custom data type (`Scalar`) with methods that overload operators conceptually (add, subtract, multiply). This is a fundamental aspect of Go's type system and method implementation.

6. **Construct Examples:**  Create illustrative Go code snippets for the key functionalities. Choose simple examples to clearly demonstrate the behavior. Include input and expected output for better understanding.

7. **Identify Potential Pitfalls:** Think about common mistakes users might make:

    * **Incorrect input lengths for `SetUniformBytes` and `SetCanonicalBytes`.**
    * **Providing non-canonical byte representations to `SetCanonicalBytes`.**

8. **Address Missing Aspects (Command-line Arguments):** The code snippet doesn't involve command-line argument processing, so explicitly state this.

9. **Structure the Answer in Chinese:** Translate the findings into clear and concise Chinese, following the structure requested in the prompt. Use appropriate technical terms.

10. **Review and Refine:**  Read through the entire answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have just said "implements scalar arithmetic". But refining it to "represents scalars modulo the order of the Edwards25519 group and performs modular arithmetic" is more precise. Similarly, explicitly mentioning the `fiat-crypto` library and the Montgomery domain adds valuable detail.
这段 Go 语言代码是 `crypto/internal/fips140/edwards25519` 包中 `scalar.go` 文件的一部分，它定义了用于表示 Edwards25519 曲线标量（Scalar）的 `Scalar` 类型，并实现了与标量相关的各种操作。由于路径中包含 `fips140`，可以推断这是为了满足 FIPS 140 标准而实现的版本。

**功能列表:**

1. **表示 Edwards25519 标量:** `Scalar` 结构体用于表示一个整数，该整数模数为 `l = 2^252 + 27742317777372353535851937790883648493`，这是 Edwards25519 群的素阶。
2. **标量运算:** 提供了标量的基本算术运算，包括：
    * `MultiplyAdd(x, y, z *Scalar) *Scalar`: 计算 `s = x * y + z mod l`。
    * `Add(x, y *Scalar) *Scalar`: 计算 `s = x + y mod l`。
    * `Subtract(x, y *Scalar) *Scalar`: 计算 `s = x - y mod l`。
    * `Negate(x *Scalar) *Scalar`: 计算 `s = -x mod l`。
    * `Multiply(x, y *Scalar) *Scalar`: 计算 `s = x * y mod l`。
3. **标量赋值:**
    * `Set(x *Scalar) *Scalar`: 将 `s` 的值设置为 `x`。
    * `NewScalar() *Scalar`: 返回一个新的零值 `Scalar`。
4. **从字节数组设置标量:**
    * `SetUniformBytes(x []byte) (*Scalar, error)`: 将 `s` 设置为 64 字节小端整数 `x` 模 `l` 的结果。通常用于从随机字节生成均匀分布的标量。
    * `SetCanonicalBytes(x []byte) (*Scalar, error)`: 将 `s` 设置为 32 字节小端编码的标量 `x`。如果 `x` 不是规范编码（小于 `l`），则返回错误。
    * `SetBytesWithClamping(x []byte) (*Scalar, error)`: 应用 RFC 8032 第 5.1.5 节中描述的缓冲修剪（clamping）并将结果设置为 `s`。输入必须是 32 字节。
    * `setShortBytes(x []byte) *Scalar`: （内部函数）将 `s` 设置为小于 32 字节的小端整数 `x` 模 `l` 的结果。
5. **将标量转换为字节数组:**
    * `Bytes() []byte`: 返回 `s` 的 32 字节小端规范编码。
    * `bytes(out *[32]byte) []byte`: （内部函数）将 `s` 的规范编码写入提供的字节数组。
6. **标量比较:**
    * `Equal(t *Scalar) int`: 比较 `s` 和 `t` 是否相等，相等返回 1，否则返回 0。
7. **标量的高级表示:**
    * `nonAdjacentForm(w uint) [256]int8`: 计算标量的宽度为 `w` 的非邻接形式 (NAF)。NAF 常用于优化标量乘法。
    * `signedRadix16() [64]int8`: 计算标量的带符号基 16 表示，也用于优化标量乘法。
8. **辅助函数:**
    * `isReduced(s []byte) bool`: （内部函数）检查给定的 32 字节小端编码是否是模 `l` 的简化形式。

**Go 语言功能实现推断 (自定义数据类型和方法):**

这段代码主要实现了自定义数据类型 `Scalar`，并为其定义了一系列方法。这体现了 Go 语言面向对象编程中的结构体和方法的概念。`Scalar` 结构体封装了标量的内部表示 (`fiatScalarMontgomeryDomainFieldElement`)，而各种方法则提供了对 `Scalar` 结构体的操作。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"go/src/crypto/internal/fips140/edwards25519"
)

func main() {
	// 创建两个标量
	scalar1 := edwards25519.NewScalar()
	scalar2 := edwards25519.NewScalar()

	// 从字节数组设置标量
	bytes1 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	scalar1.SetCanonicalBytes(bytes1)
	fmt.Printf("Scalar 1 from bytes: %x\n", scalar1.Bytes())

	bytes2 := []byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	scalar2.SetCanonicalBytes(bytes2)
	fmt.Printf("Scalar 2 from bytes: %x\n", scalar2.Bytes())

	// 执行加法
	sum := edwards25519.NewScalar()
	sum.Add(scalar1, scalar2)
	fmt.Printf("Sum: %x\n", sum.Bytes())

	// 执行乘法
	product := edwards25519.NewScalar()
	product.Multiply(scalar1, scalar2)
	fmt.Printf("Product: %x\n", product.Bytes())

	// 执行乘加运算
	scalar3 := edwards25519.NewScalar()
	scalar3Bytes := []byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 10, 20, 30, 40, 50, 60, 70}
	scalar3.SetCanonicalBytes(scalar3Bytes)
	multiplyAddResult := edwards25519.NewScalar()
	multiplyAddResult.MultiplyAdd(scalar1, scalar2, scalar3)
	fmt.Printf("MultiplyAdd result: %x\n", multiplyAddResult.Bytes())

	// 比较标量
	if scalar1.Equal(scalar2) == 1 {
		fmt.Println("Scalar 1 and Scalar 2 are equal")
	} else {
		fmt.Println("Scalar 1 and Scalar 2 are not equal")
	}
}
```

**假设的输入与输出:**

假设 `bytes1` 和 `bytes2` 的值如代码中所示，那么输出可能如下（实际输出会根据具体的模运算结果）：

```
Scalar 1 from bytes: 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
Scalar 2 from bytes: 201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201
Sum: <具体的 32 字节十六进制表示>
Product: <具体的 32 字节十六进制表示>
MultiplyAdd result: <具体的 32 字节十六进制表示>
Scalar 1 and Scalar 2 are not equal
```

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数的功能。它主要定义了标量的表示和操作。如果要在命令行中使用这些功能，需要在更上层的代码中调用这些函数，并解析命令行参数来生成或操作标量。例如，可以使用 `flag` 包来处理命令行参数，然后调用 `SetCanonicalBytes` 或 `SetUniformBytes` 来根据参数设置标量的值。

**使用者易犯错的点:**

1. **`SetCanonicalBytes` 的输入不是规范编码:**  使用者可能会提供一个 32 字节的数组，但其表示的值大于或等于模数 `l`，这将导致 `SetCanonicalBytes` 返回错误。

   ```go
   package main

   import (
       "fmt"
       "go/src/crypto/internal/fips140/edwards25519"
   )

   func main() {
       // 构造一个大于等于模 l 的字节数组 (简化例子，实际构造需要知道 l 的值)
       nonCanonicalBytes := []byte{
           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, // 这是一个接近但不小于 l 的值
       }

       scalar := edwards25519.NewScalar()
       _, err := scalar.SetCanonicalBytes(nonCanonicalBytes)
       if err != nil {
           fmt.Println("Error setting canonical bytes:", err) // 输出错误信息
       } else {
           fmt.Println("Scalar set successfully:", scalar.Bytes())
       }
   }
   ```

2. **`SetUniformBytes` 的输入长度错误:** `SetUniformBytes` 要求输入必须是 64 字节，如果传入其他长度的字节数组会返回错误。

   ```go
   package main

   import (
       "fmt"
       "go/src/crypto/internal/fips140/edwards25519"
   )

   func main() {
       invalidBytes := []byte{1, 2, 3, 4} // 长度不足 64 字节
       scalar := edwards25519.NewScalar()
       _, err := scalar.SetUniformBytes(invalidBytes)
       if err != nil {
           fmt.Println("Error setting uniform bytes:", err) // 输出错误信息
       } else {
           fmt.Println("Scalar set successfully:", scalar.Bytes())
       }
   }
   ```

总而言之，这段 `scalar.go` 代码是 Edwards25519 椭圆曲线密码学中处理标量的核心组件，提供了创建、操作和转换标量的功能，并且由于包含在 `fips140` 目录中，可以推断其实现遵循了 FIPS 140 标准的要求。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/edwards25519/scalar.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright (c) 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	"crypto/internal/fips140deps/byteorder"
	"errors"
)

// A Scalar is an integer modulo
//
//	l = 2^252 + 27742317777372353535851937790883648493
//
// which is the prime order of the edwards25519 group.
//
// This type works similarly to math/big.Int, and all arguments and
// receivers are allowed to alias.
//
// The zero value is a valid zero element.
type Scalar struct {
	// s is the scalar in the Montgomery domain, in the format of the
	// fiat-crypto implementation.
	s fiatScalarMontgomeryDomainFieldElement
}

// The field implementation in scalar_fiat.go is generated by the fiat-crypto
// project (https://github.com/mit-plv/fiat-crypto) at version v0.0.9 (23d2dbc)
// from a formally verified model.
//
// fiat-crypto code comes under the following license.
//
//     Copyright (c) 2015-2020 The fiat-crypto Authors. All rights reserved.
//
//     Redistribution and use in source and binary forms, with or without
//     modification, are permitted provided that the following conditions are
//     met:
//
//         1. Redistributions of source code must retain the above copyright
//         notice, this list of conditions and the following disclaimer.
//
//     THIS SOFTWARE IS PROVIDED BY the fiat-crypto authors "AS IS"
//     AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
//     THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
//     PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Berkeley Software Design,
//     Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
//     EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//     PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//     PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//     LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//     NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//     SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// NewScalar returns a new zero Scalar.
func NewScalar() *Scalar {
	return &Scalar{}
}

// MultiplyAdd sets s = x * y + z mod l, and returns s. It is equivalent to
// using Multiply and then Add.
func (s *Scalar) MultiplyAdd(x, y, z *Scalar) *Scalar {
	// Make a copy of z in case it aliases s.
	zCopy := new(Scalar).Set(z)
	return s.Multiply(x, y).Add(s, zCopy)
}

// Add sets s = x + y mod l, and returns s.
func (s *Scalar) Add(x, y *Scalar) *Scalar {
	// s = 1 * x + y mod l
	fiatScalarAdd(&s.s, &x.s, &y.s)
	return s
}

// Subtract sets s = x - y mod l, and returns s.
func (s *Scalar) Subtract(x, y *Scalar) *Scalar {
	// s = -1 * y + x mod l
	fiatScalarSub(&s.s, &x.s, &y.s)
	return s
}

// Negate sets s = -x mod l, and returns s.
func (s *Scalar) Negate(x *Scalar) *Scalar {
	// s = -1 * x + 0 mod l
	fiatScalarOpp(&s.s, &x.s)
	return s
}

// Multiply sets s = x * y mod l, and returns s.
func (s *Scalar) Multiply(x, y *Scalar) *Scalar {
	// s = x * y + 0 mod l
	fiatScalarMul(&s.s, &x.s, &y.s)
	return s
}

// Set sets s = x, and returns s.
func (s *Scalar) Set(x *Scalar) *Scalar {
	*s = *x
	return s
}

// SetUniformBytes sets s = x mod l, where x is a 64-byte little-endian integer.
// If x is not of the right length, SetUniformBytes returns nil and an error,
// and the receiver is unchanged.
//
// SetUniformBytes can be used to set s to a uniformly distributed value given
// 64 uniformly distributed random bytes.
func (s *Scalar) SetUniformBytes(x []byte) (*Scalar, error) {
	if len(x) != 64 {
		return nil, errors.New("edwards25519: invalid SetUniformBytes input length")
	}

	// We have a value x of 512 bits, but our fiatScalarFromBytes function
	// expects an input lower than l, which is a little over 252 bits.
	//
	// Instead of writing a reduction function that operates on wider inputs, we
	// can interpret x as the sum of three shorter values a, b, and c.
	//
	//    x = a + b * 2^168 + c * 2^336  mod l
	//
	// We then precompute 2^168 and 2^336 modulo l, and perform the reduction
	// with two multiplications and two additions.

	s.setShortBytes(x[:21])
	t := new(Scalar).setShortBytes(x[21:42])
	s.Add(s, t.Multiply(t, scalarTwo168))
	t.setShortBytes(x[42:])
	s.Add(s, t.Multiply(t, scalarTwo336))

	return s, nil
}

// scalarTwo168 and scalarTwo336 are 2^168 and 2^336 modulo l, encoded as a
// fiatScalarMontgomeryDomainFieldElement, which is a little-endian 4-limb value
// in the 2^256 Montgomery domain.
var scalarTwo168 = &Scalar{s: [4]uint64{0x5b8ab432eac74798, 0x38afddd6de59d5d7,
	0xa2c131b399411b7c, 0x6329a7ed9ce5a30}}
var scalarTwo336 = &Scalar{s: [4]uint64{0xbd3d108e2b35ecc5, 0x5c3a3718bdf9c90b,
	0x63aa97a331b4f2ee, 0x3d217f5be65cb5c}}

// setShortBytes sets s = x mod l, where x is a little-endian integer shorter
// than 32 bytes.
func (s *Scalar) setShortBytes(x []byte) *Scalar {
	if len(x) >= 32 {
		panic("edwards25519: internal error: setShortBytes called with a long string")
	}
	var buf [32]byte
	copy(buf[:], x)
	fiatScalarFromBytes((*[4]uint64)(&s.s), &buf)
	fiatScalarToMontgomery(&s.s, (*fiatScalarNonMontgomeryDomainFieldElement)(&s.s))
	return s
}

// SetCanonicalBytes sets s = x, where x is a 32-byte little-endian encoding of
// s, and returns s. If x is not a canonical encoding of s, SetCanonicalBytes
// returns nil and an error, and the receiver is unchanged.
func (s *Scalar) SetCanonicalBytes(x []byte) (*Scalar, error) {
	if len(x) != 32 {
		return nil, errors.New("invalid scalar length")
	}
	if !isReduced(x) {
		return nil, errors.New("invalid scalar encoding")
	}

	fiatScalarFromBytes((*[4]uint64)(&s.s), (*[32]byte)(x))
	fiatScalarToMontgomery(&s.s, (*fiatScalarNonMontgomeryDomainFieldElement)(&s.s))

	return s, nil
}

// scalarMinusOneBytes is l - 1 in little endian.
var scalarMinusOneBytes = [32]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}

// isReduced returns whether the given scalar in 32-byte little endian encoded
// form is reduced modulo l.
func isReduced(s []byte) bool {
	if len(s) != 32 {
		return false
	}

	for i := len(s) - 1; i >= 0; i-- {
		switch {
		case s[i] > scalarMinusOneBytes[i]:
			return false
		case s[i] < scalarMinusOneBytes[i]:
			return true
		}
	}
	return true
}

// SetBytesWithClamping applies the buffer pruning described in RFC 8032,
// Section 5.1.5 (also known as clamping) and sets s to the result. The input
// must be 32 bytes, and it is not modified. If x is not of the right length,
// SetBytesWithClamping returns nil and an error, and the receiver is unchanged.
//
// Note that since Scalar values are always reduced modulo the prime order of
// the curve, the resulting value will not preserve any of the cofactor-clearing
// properties that clamping is meant to provide. It will however work as
// expected as long as it is applied to points on the prime order subgroup, like
// in Ed25519. In fact, it is lost to history why RFC 8032 adopted the
// irrelevant RFC 7748 clamping, but it is now required for compatibility.
func (s *Scalar) SetBytesWithClamping(x []byte) (*Scalar, error) {
	// The description above omits the purpose of the high bits of the clamping
	// for brevity, but those are also lost to reductions, and are also
	// irrelevant to edwards25519 as they protect against a specific
	// implementation bug that was once observed in a generic Montgomery ladder.
	if len(x) != 32 {
		return nil, errors.New("edwards25519: invalid SetBytesWithClamping input length")
	}

	// We need to use the wide reduction from SetUniformBytes, since clamping
	// sets the 2^254 bit, making the value higher than the order.
	var wideBytes [64]byte
	copy(wideBytes[:], x[:])
	wideBytes[0] &= 248
	wideBytes[31] &= 63
	wideBytes[31] |= 64
	return s.SetUniformBytes(wideBytes[:])
}

// Bytes returns the canonical 32-byte little-endian encoding of s.
func (s *Scalar) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var encoded [32]byte
	return s.bytes(&encoded)
}

func (s *Scalar) bytes(out *[32]byte) []byte {
	var ss fiatScalarNonMontgomeryDomainFieldElement
	fiatScalarFromMontgomery(&ss, &s.s)
	fiatScalarToBytes(out, (*[4]uint64)(&ss))
	return out[:]
}

// Equal returns 1 if s and t are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	var diff fiatScalarMontgomeryDomainFieldElement
	fiatScalarSub(&diff, &s.s, &t.s)
	var nonzero uint64
	fiatScalarNonzero(&nonzero, (*[4]uint64)(&diff))
	nonzero |= nonzero >> 32
	nonzero |= nonzero >> 16
	nonzero |= nonzero >> 8
	nonzero |= nonzero >> 4
	nonzero |= nonzero >> 2
	nonzero |= nonzero >> 1
	return int(^nonzero) & 1
}

// nonAdjacentForm computes a width-w non-adjacent form for this scalar.
//
// w must be between 2 and 8, or nonAdjacentForm will panic.
func (s *Scalar) nonAdjacentForm(w uint) [256]int8 {
	// This implementation is adapted from the one
	// in curve25519-dalek and is documented there:
	// https://github.com/dalek-cryptography/curve25519-dalek/blob/f630041af28e9a405255f98a8a93adca18e4315b/src/scalar.rs#L800-L871
	b := s.Bytes()
	if b[31] > 127 {
		panic("scalar has high bit set illegally")
	}
	if w < 2 {
		panic("w must be at least 2 by the definition of NAF")
	} else if w > 8 {
		panic("NAF digits must fit in int8")
	}

	var naf [256]int8
	var digits [5]uint64

	for i := 0; i < 4; i++ {
		digits[i] = byteorder.LEUint64(b[i*8:])
	}

	width := uint64(1 << w)
	windowMask := uint64(width - 1)

	pos := uint(0)
	carry := uint64(0)
	for pos < 256 {
		indexU64 := pos / 64
		indexBit := pos % 64
		var bitBuf uint64
		if indexBit < 64-w {
			// This window's bits are contained in a single u64
			bitBuf = digits[indexU64] >> indexBit
		} else {
			// Combine the current 64 bits with bits from the next 64
			bitBuf = (digits[indexU64] >> indexBit) | (digits[1+indexU64] << (64 - indexBit))
		}

		// Add carry into the current window
		window := carry + (bitBuf & windowMask)

		if window&1 == 0 {
			// If the window value is even, preserve the carry and continue.
			// Why is the carry preserved?
			// If carry == 0 and window & 1 == 0,
			//    then the next carry should be 0
			// If carry == 1 and window & 1 == 0,
			//    then bit_buf & 1 == 1 so the next carry should be 1
			pos += 1
			continue
		}

		if window < width/2 {
			carry = 0
			naf[pos] = int8(window)
		} else {
			carry = 1
			naf[pos] = int8(window) - int8(width)
		}

		pos += w
	}
	return naf
}

func (s *Scalar) signedRadix16() [64]int8 {
	b := s.Bytes()
	if b[31] > 127 {
		panic("scalar has high bit set illegally")
	}

	var digits [64]int8

	// Compute unsigned radix-16 digits:
	for i := 0; i < 32; i++ {
		digits[2*i] = int8(b[i] & 15)
		digits[2*i+1] = int8((b[i] >> 4) & 15)
	}

	// Recenter coefficients:
	for i := 0; i < 63; i++ {
		carry := (digits[i] + 8) >> 4
		digits[i] -= carry << 4
		digits[i+1] += carry
	}

	return digits
}
```