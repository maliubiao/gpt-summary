Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Reading and High-Level Understanding:**

The first step is a quick scan to understand the overall purpose. Keywords like "edwards25519", "Point", "field.Element", "crypto", and "fips140" immediately suggest this code is part of a cryptographic library implementing the Edwards25519 elliptic curve, specifically within a FIPS 140 compliant context. The import of `crypto/internal/fips140/check` further reinforces this.

**2. Identifying Core Data Structures:**

Next, focus on the `type` definitions. These are the building blocks of the implementation:

* `projP1xP1`, `projP2`: These likely represent points in different projective coordinate systems used for efficient calculations. The names are suggestive of the underlying mathematical representations (e.g., "P1xP1" might indicate a specific form of projective coordinates).
* `Point`: This is clearly the main representation of a point on the Edwards25519 curve. The comment about it being "similar to math/big.Int" hints at how it's intended to be used (as a value type where operations modify the receiver). The `incomparable` field is a Go idiom to prevent direct comparison, which is often necessary for cryptographic objects.
* `projCached`, `affineCached`: The "Cached" suffix suggests these are optimized representations of points for specific operations, likely precomputing some values to speed up point addition or scalar multiplication. "Affine" refers to a coordinate system where Z=1.

**3. Analyzing Key Functions and Their Functionality:**

Now, go through the functions and methods, grouping them by their apparent purpose:

* **Constructors:**  Functions like `Zero`, `NewIdentityPoint`, `NewGeneratorPoint`. These are clearly for creating and initializing `Point` objects in specific states (zero point, identity point, generator point). The hardcoded byte arrays in `identity` and `generator` are the standard encodings for these points.
* **Encoding/Decoding:** `Bytes()` and `SetBytes()`. These handle the conversion between the internal `Point` representation and its byte-level encoding, crucial for serialization and interoperability. The detailed comments in `SetBytes` about non-canonical encodings are important to note.
* **Conversions:** Functions like `FromP1xP1`, `FromP3`, `fromP1xP1`, `fromP2`, `FromP3` (for both cached types). These are about converting between the different internal point representations. This is a common optimization technique in elliptic curve cryptography.
* **Point Arithmetic:** `Add`, `Subtract`, `Double`, `Negate`. These implement the core group operations on the Edwards25519 curve. The existence of `AddAffine` and `SubAffine` suggests optimizations when one of the points is in affine coordinates. The `projP1xP1` versions of `Add` and `Sub` are likely internal helper functions.
* **Comparison:** `Equal`. This checks if two `Point` objects represent the same point on the curve.
* **Constant-Time Operations:** `Select`, `CondNeg`. These are crucial for security in cryptographic implementations to prevent timing attacks.

**4. Identifying the Go Language Features Used:**

As you examine the code, note the use of:

* **Structs:**  For defining the point types.
* **Methods:**  Functions associated with the `Point` and other types (e.g., `v.Set(u)`).
* **Pointers:** Heavily used for modifying `Point` objects in place and for efficiency.
* **Slices (`[]byte`):** For representing byte arrays in `Bytes` and `SetBytes`.
* **Error Handling:** Returning `error` from `SetBytes`.
* **Panic:** Used in `checkInitialized` for a critical error.
* **Constants:**  `identity`, `generator`, `d`, `d2`.
* **Blank Identifier (`_`):** Used to ignore the error return from `SetBytes` in the initialization of `identity` and `generator`, which is acceptable because those byte arrays are assumed to be valid.

**5. Inferring the Overall Functionality:**

Based on the structures and functions, it's clear this code provides the fundamental building blocks for Edwards25519 point arithmetic. It allows users to:

* Create and initialize Edwards25519 points.
* Encode and decode points to and from byte arrays.
* Perform point addition, subtraction, doubling, and negation.
* Compare points for equality.

**6. Constructing Examples and Identifying Potential Pitfalls:**

Now, think about how a user would interact with this code and where they might make mistakes:

* **Uninitialized Points:** The `checkInitialized` function and the comment on the zero value of `Point` immediately highlight this as a potential issue. Demonstrate this with an example.
* **Ignoring Errors from `SetBytes`:**  Since `SetBytes` can return an error, users must handle it. Show an example of what happens when invalid input is provided.
* **Mutability:**  Emphasize that `Point` operations modify the receiver.

**7. Considering Command-Line Arguments (If Applicable):**

In *this specific snippet*, there are no direct command-line argument handling. However, if the code were part of a larger program that *did* take command-line arguments (e.g., for key generation or signing), you'd analyze how those arguments are parsed and used. Since this snippet is low-level, this part isn't relevant here.

**8. Structuring the Answer:**

Finally, organize the information in a clear and logical way, using the headings requested in the prompt. Provide code examples to illustrate the functionality and potential pitfalls. Use clear, concise language.

By following these steps, you can systematically analyze Go code snippets and provide a comprehensive explanation of their functionality, potential uses, and common pitfalls.
这段Go语言代码是 `crypto/internal/fips140/edwards25519` 包的核心部分，专注于实现 **Edwards25519 椭圆曲线上的点运算**。由于路径中包含 `fips140`，可以推断这是一个为了满足 FIPS 140 标准而特殊构建的 Edwards25519 实现。

以下是它的主要功能：

1. **定义了 Edwards25519 曲线上的点的多种内部表示形式:**
   - `projP1xP1`: 一种用于中间计算的投影坐标系。
   - `projP2`: 另一种投影坐标系。
   - `Point`:  代表 Edwards25519 曲线上的点的最终用户可见的结构体。它使用扩展坐标 (X, Y, Z, T) 表示点，其中 x = X/Z, y = Y/Z, xy = T/Z。
   - `projCached`, `affineCached`:  分别用于存储投影和仿射坐标系下的预计算值，以优化点运算。

2. **提供了创建和初始化 `Point` 对象的方法:**
   - `NewIdentityPoint()`: 返回表示曲线上的零点的 `Point` 对象（也称为无穷远点或单位元）。
   - `NewGeneratorPoint()`: 返回表示 Edwards25519 曲线标准基点的 `Point` 对象。
   - `SetBytes([]byte)`:  从 32 字节的编码中设置 `Point` 对象的值。

3. **实现了 `Point` 对象的编码和解码:**
   - `Bytes()`: 将 `Point` 对象编码为 32 字节的表示，遵循 RFC 8032 规范。
   - `SetBytes([]byte)`: 从 32 字节的编码中恢复 `Point` 对象。这个实现比 RFC 8032 更宽松，接受一些非规范的编码。

4. **实现了点之间的基本运算:**
   - `Add(p, q *Point)`:  计算两个点 `p` 和 `q` 的和，并将结果存储在接收者 `v` 中。
   - `Subtract(p, q *Point)`: 计算点 `p` 和 `q` 的差，并将结果存储在接收者 `v` 中。
   - `Negate(p *Point)`: 计算点 `p` 的负元，并将结果存储在接收者 `v` 中。
   - `Double(p *projP2)`: 计算点 `p` 的两倍，用于高效的标量乘法。

5. **实现了不同坐标系之间的转换:**
   - `FromP1xP1`, `FromP3`, `fromP1xP1`, `fromP2`:  用于在不同的点表示形式之间进行转换，以优化不同的运算。

6. **提供了点相等性比较的方法:**
   - `Equal(u *Point)`: 判断两个点 `v` 和 `u` 是否相等。

7. **实现了常数时间操作:**
   - `Select(a, b *projCached, cond int)` 和 `Select(a, b *affineCached, cond int)`:  根据条件 `cond` 选择 `a` 或 `b`，以避免时序攻击。
   - `CondNeg(cond int)` 和 `CondNeg(cond int)`:  根据条件 `cond` 对点取反，也用于防止时序攻击。

**推理它是什么go语言功能的实现:**

从其功能来看，这段代码是 Go 语言标准库 `crypto/edwards25519` 的一个内部实现，特别针对需要满足 FIPS 140 标准的场景。FIPS 140 是一套关于密码模块安全性的美国政府标准。`crypto/internal/fips140` 路径表明这个实现是 `crypto` 包的内部细节，用于在特定 FIPS 模式下提供 Edwards25519 功能。

**Go 代码示例:**

假设我们想使用这段代码创建一个新的基点，并将其编码为字节：

```go
package main

import (
	"fmt"
	"go/src/crypto/internal/fips140/edwards25519" // 假设你将代码放在了这个路径
)

func main() {
	// 创建一个新的基点
	generator := edwards25519.NewGeneratorPoint()

	// 将基点编码为字节
	encodedGenerator := generator.Bytes()

	fmt.Printf("Encoded Generator: %x\n", encodedGenerator)

	// 从字节解码回基点
	decodedGenerator := new(edwards25519.Point)
	_, err := decodedGenerator.SetBytes(encodedGenerator)
	if err != nil {
		fmt.Println("Error decoding:", err)
		return
	}

	// 比较原始基点和解码后的基点
	if generator.Equal(decodedGenerator) == 1 {
		fmt.Println("Encoding and decoding successful!")
	} else {
		fmt.Println("Encoding and decoding failed!")
	}
}
```

**假设的输入与输出：**

在这个例子中，`NewGeneratorPoint()` 没有显式的输入。输出是 `generator` 变量，它是一个 `*edwards25519.Point` 类型，代表 Edwards25519 曲线的基点。

`generator.Bytes()` 的输出是一个 32 字节的 `[]byte`，代表基点的编码。根据代码中的定义，其值应为：

```
5866666666666666666666666666666666666666666666666666666666666666
```

`decodedGenerator.SetBytes(encodedGenerator)` 的输入是 `encodedGenerator` 这个字节切片。如果解码成功，`decodedGenerator` 将会和 `generator` 表示同一个点。如果解码失败，`err` 将不会为 `nil`。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。它是一个底层的密码学原语实现。如果需要处理命令行参数，通常会在调用这个库的上层代码中进行，例如一个使用 Edwards25519 进行签名或密钥交换的工具。

**使用者易犯错的点:**

1. **使用未初始化的 `Point` 对象:** 代码中 `checkInitialized` 函数会检测并 panic 如果使用了零值的 `Point` 对象。使用者容易忘记调用 `NewIdentityPoint()` 或 `NewGeneratorPoint()` 或者 `SetBytes()` 来初始化 `Point`。

   ```go
   package main

   import "go/src/crypto/internal/fips140/edwards25519"

   func main() {
       var p edwards25519.Point // 未初始化
       p.Bytes() // 这将会导致 panic
   }
   ```

2. **忽略 `SetBytes` 的错误返回值:**  `SetBytes` 方法在解码无效字节时会返回错误。使用者必须检查这个错误，否则可能会使用一个无效的 `Point` 对象。

   ```go
   package main

   import (
       "fmt"
       "go/src/crypto/internal/fips140/edwards25519"
   )

   func main() {
       invalidBytes := []byte("this is not a valid 32-byte encoding") // 长度错误
       point := new(edwards25519.Point)
       _, err := point.SetBytes(invalidBytes)
       if err != nil {
           fmt.Println("Error setting bytes:", err)
       } else {
           fmt.Println("Point set successfully (this should not happen)")
       }
   }
   ```

3. **混淆不同的点表示形式:** 代码中定义了多种内部的点表示形式（`projP1xP1`, `projP2`, `projCached`, `affineCached`）。使用者通常只需要使用 `Point` 类型，但如果深入到内部实现，可能会因为对不同表示形式的用途和转换不熟悉而犯错。

这段代码是实现 Edwards25519 密码学功能的基础，它提供了在椭圆曲线上进行点运算的关键组件。上层应用会基于这些基础功能构建更高级的密码学协议，例如签名、密钥交换等。

### 提示词
```
这是路径为go/src/crypto/internal/fips140/edwards25519/edwards25519.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright (c) 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package edwards25519

import (
	_ "crypto/internal/fips140/check"
	"crypto/internal/fips140/edwards25519/field"
	"errors"
)

// Point types.

type projP1xP1 struct {
	X, Y, Z, T field.Element
}

type projP2 struct {
	X, Y, Z field.Element
}

// Point represents a point on the edwards25519 curve.
//
// This type works similarly to math/big.Int, and all arguments and receivers
// are allowed to alias.
//
// The zero value is NOT valid, and it may be used only as a receiver.
type Point struct {
	// Make the type not comparable (i.e. used with == or as a map key), as
	// equivalent points can be represented by different Go values.
	_ incomparable

	// The point is internally represented in extended coordinates (X, Y, Z, T)
	// where x = X/Z, y = Y/Z, and xy = T/Z per https://eprint.iacr.org/2008/522.
	x, y, z, t field.Element
}

type incomparable [0]func()

func checkInitialized(points ...*Point) {
	for _, p := range points {
		if p.x == (field.Element{}) && p.y == (field.Element{}) {
			panic("edwards25519: use of uninitialized Point")
		}
	}
}

type projCached struct {
	YplusX, YminusX, Z, T2d field.Element
}

type affineCached struct {
	YplusX, YminusX, T2d field.Element
}

// Constructors.

func (v *projP2) Zero() *projP2 {
	v.X.Zero()
	v.Y.One()
	v.Z.One()
	return v
}

// identity is the point at infinity.
var identity, _ = new(Point).SetBytes([]byte{
	1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})

// NewIdentityPoint returns a new Point set to the identity.
func NewIdentityPoint() *Point {
	return new(Point).Set(identity)
}

// generator is the canonical curve basepoint. See TestGenerator for the
// correspondence of this encoding with the values in RFC 8032.
var generator, _ = new(Point).SetBytes([]byte{
	0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66})

// NewGeneratorPoint returns a new Point set to the canonical generator.
func NewGeneratorPoint() *Point {
	return new(Point).Set(generator)
}

func (v *projCached) Zero() *projCached {
	v.YplusX.One()
	v.YminusX.One()
	v.Z.One()
	v.T2d.Zero()
	return v
}

func (v *affineCached) Zero() *affineCached {
	v.YplusX.One()
	v.YminusX.One()
	v.T2d.Zero()
	return v
}

// Assignments.

// Set sets v = u, and returns v.
func (v *Point) Set(u *Point) *Point {
	*v = *u
	return v
}

// Encoding.

// Bytes returns the canonical 32-byte encoding of v, according to RFC 8032,
// Section 5.1.2.
func (v *Point) Bytes() []byte {
	// This function is outlined to make the allocations inline in the caller
	// rather than happen on the heap.
	var buf [32]byte
	return v.bytes(&buf)
}

func (v *Point) bytes(buf *[32]byte) []byte {
	checkInitialized(v)

	var zInv, x, y field.Element
	zInv.Invert(&v.z)       // zInv = 1 / Z
	x.Multiply(&v.x, &zInv) // x = X / Z
	y.Multiply(&v.y, &zInv) // y = Y / Z

	out := copyFieldElement(buf, &y)
	out[31] |= byte(x.IsNegative() << 7)
	return out
}

var feOne = new(field.Element).One()

// SetBytes sets v = x, where x is a 32-byte encoding of v. If x does not
// represent a valid point on the curve, SetBytes returns nil and an error and
// the receiver is unchanged. Otherwise, SetBytes returns v.
//
// Note that SetBytes accepts all non-canonical encodings of valid points.
// That is, it follows decoding rules that match most implementations in
// the ecosystem rather than RFC 8032.
func (v *Point) SetBytes(x []byte) (*Point, error) {
	// Specifically, the non-canonical encodings that are accepted are
	//   1) the ones where the field element is not reduced (see the
	//      (*field.Element).SetBytes docs) and
	//   2) the ones where the x-coordinate is zero and the sign bit is set.
	//
	// Read more at https://hdevalence.ca/blog/2020-10-04-its-25519am,
	// specifically the "Canonical A, R" section.

	y, err := new(field.Element).SetBytes(x)
	if err != nil {
		return nil, errors.New("edwards25519: invalid point encoding length")
	}

	// -x² + y² = 1 + dx²y²
	// x² + dx²y² = x²(dy² + 1) = y² - 1
	// x² = (y² - 1) / (dy² + 1)

	// u = y² - 1
	y2 := new(field.Element).Square(y)
	u := new(field.Element).Subtract(y2, feOne)

	// v = dy² + 1
	vv := new(field.Element).Multiply(y2, d)
	vv = vv.Add(vv, feOne)

	// x = +√(u/v)
	xx, wasSquare := new(field.Element).SqrtRatio(u, vv)
	if wasSquare == 0 {
		return nil, errors.New("edwards25519: invalid point encoding")
	}

	// Select the negative square root if the sign bit is set.
	xxNeg := new(field.Element).Negate(xx)
	xx = xx.Select(xxNeg, xx, int(x[31]>>7))

	v.x.Set(xx)
	v.y.Set(y)
	v.z.One()
	v.t.Multiply(xx, y) // xy = T / Z

	return v, nil
}

func copyFieldElement(buf *[32]byte, v *field.Element) []byte {
	copy(buf[:], v.Bytes())
	return buf[:]
}

// Conversions.

func (v *projP2) FromP1xP1(p *projP1xP1) *projP2 {
	v.X.Multiply(&p.X, &p.T)
	v.Y.Multiply(&p.Y, &p.Z)
	v.Z.Multiply(&p.Z, &p.T)
	return v
}

func (v *projP2) FromP3(p *Point) *projP2 {
	v.X.Set(&p.x)
	v.Y.Set(&p.y)
	v.Z.Set(&p.z)
	return v
}

func (v *Point) fromP1xP1(p *projP1xP1) *Point {
	v.x.Multiply(&p.X, &p.T)
	v.y.Multiply(&p.Y, &p.Z)
	v.z.Multiply(&p.Z, &p.T)
	v.t.Multiply(&p.X, &p.Y)
	return v
}

func (v *Point) fromP2(p *projP2) *Point {
	v.x.Multiply(&p.X, &p.Z)
	v.y.Multiply(&p.Y, &p.Z)
	v.z.Square(&p.Z)
	v.t.Multiply(&p.X, &p.Y)
	return v
}

// d is a constant in the curve equation.
var d, _ = new(field.Element).SetBytes([]byte{
	0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
	0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
	0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
	0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52})
var d2 = new(field.Element).Add(d, d)

func (v *projCached) FromP3(p *Point) *projCached {
	v.YplusX.Add(&p.y, &p.x)
	v.YminusX.Subtract(&p.y, &p.x)
	v.Z.Set(&p.z)
	v.T2d.Multiply(&p.t, d2)
	return v
}

func (v *affineCached) FromP3(p *Point) *affineCached {
	v.YplusX.Add(&p.y, &p.x)
	v.YminusX.Subtract(&p.y, &p.x)
	v.T2d.Multiply(&p.t, d2)

	var invZ field.Element
	invZ.Invert(&p.z)
	v.YplusX.Multiply(&v.YplusX, &invZ)
	v.YminusX.Multiply(&v.YminusX, &invZ)
	v.T2d.Multiply(&v.T2d, &invZ)
	return v
}

// (Re)addition and subtraction.

// Add sets v = p + q, and returns v.
func (v *Point) Add(p, q *Point) *Point {
	checkInitialized(p, q)
	qCached := new(projCached).FromP3(q)
	result := new(projP1xP1).Add(p, qCached)
	return v.fromP1xP1(result)
}

// Subtract sets v = p - q, and returns v.
func (v *Point) Subtract(p, q *Point) *Point {
	checkInitialized(p, q)
	qCached := new(projCached).FromP3(q)
	result := new(projP1xP1).Sub(p, qCached)
	return v.fromP1xP1(result)
}

func (v *projP1xP1) Add(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 field.Element

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YplusX)
	MM.Multiply(&YminusX, &q.YminusX)
	TT2d.Multiply(&p.t, &q.T2d)
	ZZ2.Multiply(&p.z, &q.Z)

	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&ZZ2, &TT2d)
	v.T.Subtract(&ZZ2, &TT2d)
	return v
}

func (v *projP1xP1) Sub(p *Point, q *projCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, ZZ2 field.Element

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YminusX) // flipped sign
	MM.Multiply(&YminusX, &q.YplusX) // flipped sign
	TT2d.Multiply(&p.t, &q.T2d)
	ZZ2.Multiply(&p.z, &q.Z)

	ZZ2.Add(&ZZ2, &ZZ2)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Subtract(&ZZ2, &TT2d) // flipped sign
	v.T.Add(&ZZ2, &TT2d)      // flipped sign
	return v
}

func (v *projP1xP1) AddAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 field.Element

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YplusX)
	MM.Multiply(&YminusX, &q.YminusX)
	TT2d.Multiply(&p.t, &q.T2d)

	Z2.Add(&p.z, &p.z)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Add(&Z2, &TT2d)
	v.T.Subtract(&Z2, &TT2d)
	return v
}

func (v *projP1xP1) SubAffine(p *Point, q *affineCached) *projP1xP1 {
	var YplusX, YminusX, PP, MM, TT2d, Z2 field.Element

	YplusX.Add(&p.y, &p.x)
	YminusX.Subtract(&p.y, &p.x)

	PP.Multiply(&YplusX, &q.YminusX) // flipped sign
	MM.Multiply(&YminusX, &q.YplusX) // flipped sign
	TT2d.Multiply(&p.t, &q.T2d)

	Z2.Add(&p.z, &p.z)

	v.X.Subtract(&PP, &MM)
	v.Y.Add(&PP, &MM)
	v.Z.Subtract(&Z2, &TT2d) // flipped sign
	v.T.Add(&Z2, &TT2d)      // flipped sign
	return v
}

// Doubling.

func (v *projP1xP1) Double(p *projP2) *projP1xP1 {
	var XX, YY, ZZ2, XplusYsq field.Element

	XX.Square(&p.X)
	YY.Square(&p.Y)
	ZZ2.Square(&p.Z)
	ZZ2.Add(&ZZ2, &ZZ2)
	XplusYsq.Add(&p.X, &p.Y)
	XplusYsq.Square(&XplusYsq)

	v.Y.Add(&YY, &XX)
	v.Z.Subtract(&YY, &XX)

	v.X.Subtract(&XplusYsq, &v.Y)
	v.T.Subtract(&ZZ2, &v.Z)
	return v
}

// Negation.

// Negate sets v = -p, and returns v.
func (v *Point) Negate(p *Point) *Point {
	checkInitialized(p)
	v.x.Negate(&p.x)
	v.y.Set(&p.y)
	v.z.Set(&p.z)
	v.t.Negate(&p.t)
	return v
}

// Equal returns 1 if v is equivalent to u, and 0 otherwise.
func (v *Point) Equal(u *Point) int {
	checkInitialized(v, u)

	var t1, t2, t3, t4 field.Element
	t1.Multiply(&v.x, &u.z)
	t2.Multiply(&u.x, &v.z)
	t3.Multiply(&v.y, &u.z)
	t4.Multiply(&u.y, &v.z)

	return t1.Equal(&t2) & t3.Equal(&t4)
}

// Constant-time operations

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *projCached) Select(a, b *projCached, cond int) *projCached {
	v.YplusX.Select(&a.YplusX, &b.YplusX, cond)
	v.YminusX.Select(&a.YminusX, &b.YminusX, cond)
	v.Z.Select(&a.Z, &b.Z, cond)
	v.T2d.Select(&a.T2d, &b.T2d, cond)
	return v
}

// Select sets v to a if cond == 1 and to b if cond == 0.
func (v *affineCached) Select(a, b *affineCached, cond int) *affineCached {
	v.YplusX.Select(&a.YplusX, &b.YplusX, cond)
	v.YminusX.Select(&a.YminusX, &b.YminusX, cond)
	v.T2d.Select(&a.T2d, &b.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1 and leaves it unchanged if cond == 0.
func (v *projCached) CondNeg(cond int) *projCached {
	v.YplusX.Swap(&v.YminusX, cond)
	v.T2d.Select(new(field.Element).Negate(&v.T2d), &v.T2d, cond)
	return v
}

// CondNeg negates v if cond == 1 and leaves it unchanged if cond == 0.
func (v *affineCached) CondNeg(cond int) *affineCached {
	v.YplusX.Swap(&v.YminusX, cond)
	v.T2d.Select(new(field.Element).Negate(&v.T2d), &v.T2d, cond)
	return v
}
```