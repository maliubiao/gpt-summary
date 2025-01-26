Response:
Let's break down the thought process to analyze the given Go code snippet for `math/big/rat.go`.

**1. Understanding the Core Goal:**

The first line `// This file implements multi-precision rational numbers.` immediately tells us the primary purpose. The code is about representing and manipulating rational numbers with arbitrary precision. This is a key differentiator from standard `float32` or `float64` which have fixed precision.

**2. Identifying the Main Data Structure:**

The `Rat` struct is the central data structure. It's crucial to understand its components:

```go
type Rat struct {
	a, b Int
}
```

This shows a rational number is represented by a numerator (`a`) and a denominator (`b`), both of type `Int`. The comment about `b` being treated as 1 if its length is 0 is a critical detail for understanding the zero value of `Rat`. The comment about `a.neg` determining the sign is also important.

**3. Analyzing Key Functions and Methods:**

I'll go through the provided methods, grouping them by functionality and noting their purpose:

* **Creation/Initialization:**
    * `NewRat(a, b int64) *Rat`: Creates a `Rat` from two `int64`.
    * `SetFloat64(f float64) *Rat`: Creates a `Rat` from a `float64`. This involves a non-trivial conversion, which is interesting. I'd note this for potential code reasoning examples.

* **Setting Values:**
    * `SetFrac(a, b *Int) *Rat`: Sets the numerator and denominator from `Int` pointers.
    * `SetFrac64(a, b int64) *Rat`: Sets the numerator and denominator from `int64`.
    * `SetInt(x *Int) *Rat`: Sets the `Rat` to an integer.
    * `SetInt64(x int64) *Rat`: Sets the `Rat` to an integer.
    * `SetUint64(x uint64) *Rat`: Sets the `Rat` to an integer.
    * `Set(x *Rat) *Rat`: Copies the value from another `Rat`.

* **Conversion to Float:**
    * `quotToFloat32(a, b nat) (f float32, exact bool)`:  Internal function to convert a quotient of `nat` types to `float32`. The `exact` return value is important.
    * `quotToFloat64(a, b nat) (f float64, exact bool)`: Internal function to convert a quotient of `nat` types to `float64`.
    * `Float32() (f float32, exact bool)`: Converts the `Rat` to `float32`.
    * `Float64() (f float64, exact bool)`: Converts the `Rat` to `float64`. The existence of both 32 and 64-bit float conversions suggests dealing with potential precision loss.

* **Basic Arithmetic Operations:**
    * `Abs(x *Rat) *Rat`: Absolute value.
    * `Neg(x *Rat) *Rat`: Negation.
    * `Inv(x *Rat) *Rat`: Inverse (reciprocal).
    * `Add(x, y *Rat) *Rat`: Addition.
    * `Sub(x, y *Rat) *Rat`: Subtraction.
    * `Mul(x, y *Rat) *Rat`: Multiplication.
    * `Quo(x, y *Rat) *Rat`: Division.

* **Comparison and Information:**
    * `Sign() int`: Returns the sign.
    * `IsInt() bool`: Checks if it's an integer.
    * `Num() *Int`: Returns the numerator.
    * `Denom() *Int`: Returns the denominator.
    * `Cmp(y *Rat) int`: Compares two `Rat` numbers.

* **Internal Utility:**
    * `norm() *Rat`: Normalizes the `Rat` (simplifies the fraction).
    * `mulDenom(z, x, y nat) nat`: Helper for denominator multiplication.
    * `scaleDenom(z *Int, x *Int, f nat)`: Helper for scaling the numerator.

**4. Identifying Core Functionality:**

Based on the methods, the core functionalities are:

* **Representation of Arbitrary Precision Rationals:** The `Rat` struct and the use of `Int` for numerator and denominator are key here.
* **Basic Arithmetic Operations:**  Add, Subtract, Multiply, Divide.
* **Conversions:** Converting to and from `float64` and representing integers as rationals.
* **Comparison:**  Being able to compare rational numbers.
* **Normalization:** Simplifying fractions to their lowest terms.

**5. Considering Potential Issues and Error Points:**

The comments in the code itself offer clues:

* **Zero Denominator:**  Several methods explicitly mention panicking on division by zero (`SetFrac`, `SetFrac64`, `Inv`, `Quo`). This is a common error.
* **Shallow Copies:** The comment at the beginning of the `Rat` struct definition warns against shallow copies. This is crucial for understanding how to work with `Rat` values correctly.
* **Uninitialized `Rat`:** The `Denom()` method has special handling for uninitialized `Rat` values. This is another point to highlight.

**6. Planning Examples and Code Reasoning:**

For code examples, I'd focus on:

* **Basic arithmetic:**  Showing addition, subtraction, multiplication, and division.
* **Conversions:**  Demonstrating conversion from `float64` and back. Highlighting potential loss of precision.
* **Normalization:** Showing how the `norm()` method simplifies fractions.
* **The "shallow copy" issue:** Demonstrating the correct way to copy `Rat` values using `Set()`.
* **Division by Zero:** Showing the panic.

For code reasoning, the `SetFloat64` function is interesting due to its bit manipulation. I'd consider breaking down a simple case to show how it works.

**7. Structuring the Answer:**

Finally, I'd organize the answer into the requested sections:

* **Functionality Listing:** A straightforward list of what the code does.
* **Go Language Feature:** Identifying it as arbitrary-precision rational number implementation and providing relevant code examples.
* **Code Reasoning:**  Selecting a complex function like `SetFloat64` and explaining its logic with an example.
* **Command-line Arguments:**  This section will likely be empty since the provided code doesn't handle command-line arguments directly.
* **Common Mistakes:**  Focusing on division by zero and the shallow copy issue.

By following this structured thought process, I can systematically analyze the code and generate a comprehensive and accurate answer.
这段代码是 Go 语言 `math/big` 包中关于**多精度有理数 (Rational Numbers)** 的实现。它定义了一个名为 `Rat` 的结构体，用于表示任意精度的有理数。

**主要功能列举:**

1. **表示有理数:**  `Rat` 结构体可以精确地表示任意精度的有理数，避免了浮点数运算中可能出现的精度损失。它通过存储分子 (`a`) 和分母 (`b`) 的 `Int` 类型（也是 `math/big` 包中的多精度整数类型）来实现这一点。

2. **创建有理数:**
    *   `NewRat(a, b int64) *Rat`:  使用 `int64` 类型的分子和分母创建一个新的 `Rat` 对象。
    *   `SetFloat64(f float64) *Rat`:  将一个 `float64` 类型的值精确地转换为 `Rat` 对象。如果 `float64` 不是有限数（例如 `NaN` 或无穷大），则返回 `nil`。

3. **设置有理数的值:**
    *   `SetFrac(a, b *Int) *Rat`:  将 `Rat` 对象设置为给定的分子 `a` 和分母 `b` 的值。
    *   `SetFrac64(a, b int64) *Rat`:  将 `Rat` 对象设置为给定的 `int64` 类型的分子和分母的值。
    *   `SetInt(x *Int) *Rat`:  将 `Rat` 对象设置为给定的整数 `x` 的值（相当于分母为 1）。
    *   `SetInt64(x int64) *Rat`:  将 `Rat` 对象设置为给定的 `int64` 类型整数的值。
    *   `SetUint64(x uint64) *Rat`:  将 `Rat` 对象设置为给定的 `uint64` 类型整数的值。
    *   `Set(x *Rat) *Rat`:  将 `Rat` 对象设置为另一个 `Rat` 对象 `x` 的值（进行深拷贝）。

4. **转换为浮点数:**
    *   `Float32() (f float32, exact bool)`:  返回最接近 `Rat` 值的 `float32` 值，并返回一个布尔值指示该 `float32` 值是否精确地表示了该有理数。
    *   `Float64() (f float64, exact bool)`:  返回最接近 `Rat` 值的 `float64` 值，并返回一个布尔值指示该 `float64` 值是否精确地表示了该有理数。内部使用了 `quotToFloat32` 和 `quotToFloat64` 这两个函数来执行转换。

5. **基本算术运算:**
    *   `Abs(x *Rat) *Rat`:  计算 `Rat` 对象的绝对值。
    *   `Neg(x *Rat) *Rat`:  计算 `Rat` 对象的相反数。
    *   `Inv(x *Rat) *Rat`:  计算 `Rat` 对象的倒数。
    *   `Add(x, y *Rat) *Rat`:  计算两个 `Rat` 对象的和。
    *   `Sub(x, y *Rat) *Rat`:  计算两个 `Rat` 对象的差。
    *   `Mul(x, y *Rat) *Rat`:  计算两个 `Rat` 对象的积。
    *   `Quo(x, y *Rat) *Rat`:  计算两个 `Rat` 对象的商。

6. **比较运算:**
    *   `Cmp(y *Rat) int`:  比较两个 `Rat` 对象的大小，返回 -1（小于）、0（等于）或 1（大于）。
    *   `Sign() int`:  返回 `Rat` 对象的符号，返回 -1（负数）、0（零）或 1（正数）。

7. **查询信息:**
    *   `IsInt() bool`:  判断 `Rat` 对象是否表示一个整数（分母为 1）。
    *   `Num() *Int`:  返回 `Rat` 对象的分子。注意返回的是指向内部数据的指针，修改它可能会影响 `Rat` 对象本身。
    *   `Denom() *Int`: 返回 `Rat` 对象的分母。同样返回的是指针。

8. **内部规范化:**
    *   `norm() *Rat`:  将 `Rat` 对象规范化，即约分到最简形式，并处理符号。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言中的**高精度有理数运算**功能。Go 语言内置的 `float32` 和 `float64` 类型在进行某些计算时可能会损失精度。`math/big` 包提供的 `Rat` 类型则可以精确地表示和计算有理数，适用于对精度要求极高的场景。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	// 创建 Rat 对象
	r1 := big.NewRat(1, 3)  // 1/3
	r2 := big.NewRat(2, 5)  // 2/5

	fmt.Println("r1:", r1.String()) // 输出: r1: 1/3
	fmt.Println("r2:", r2.String()) // 输出: r2: 2/5

	// 加法
	sum := new(big.Rat).Add(r1, r2)
	fmt.Println("r1 + r2:", sum.String()) // 输出: r1 + r2: 11/15

	// 乘法
	product := new(big.Rat).Mul(r1, r2)
	fmt.Println("r1 * r2:", product.String()) // 输出: r1 * r2: 2/15

	// 比较
	if r1.Cmp(r2) < 0 {
		fmt.Println("r1 < r2") // 输出: r1 < r2
	}

	// 转换为 float64
	f64, exact := r1.Float64()
	fmt.Printf("r1 as float64: %f, exact: %t\n", f64, exact) // 输出: r1 as float64: 0.333333, exact: false

	// 从 float64 创建 Rat
	f := 0.75
	r3 := new(big.Rat).SetFloat64(f)
	fmt.Println("0.75 as Rat:", r3.String()) // 输出: 0.75 as Rat: 3/4

	// 从整数创建 Rat
	i := big.NewInt(10)
	r4 := new(big.Rat).SetInt(i)
	fmt.Println("10 as Rat:", r4.String()) // 输出: 10 as Rat: 10/1
}
```

**假设的输入与输出（代码推理）:**

以 `SetFloat64` 函数为例，假设输入以下 `float64` 值：

*   **输入:** `f = 0.5`
    *   **推理:**  `0.5` 可以精确地表示为 1/2。函数会将浮点数的尾数和指数提取出来，然后构造分子和分母。
    *   **输出:**  `Rat` 对象，其分子为 1，分母为 2。`exact` 返回 `true`。

*   **输入:** `f = 0.333`
    *   **推理:** `0.333` 是 `1/3` 的一个近似值，无法精确表示。函数会尝试找到最接近的精确有理数表示。
    *   **输出:** `Rat` 对象，其值可能是一个非常接近 `333/1000` 的有理数，但由于 `float64` 的精度限制，不会是精确的 `1/3`。 `exact` 返回 `false`。

*   **输入:** `f = math.NaN()`
    *   **推理:**  `NaN` 不是一个有限数。
    *   **输出:** `nil`。

**命令行参数的具体处理:**

这段代码本身并不涉及命令行参数的处理。`math/big` 包主要提供数学运算的功能，与命令行参数的解析和处理无关。命令行参数的处理通常由 `os` 包和 `flag` 包等来完成。

**使用者易犯错的点:**

1. **浅拷贝问题:**  `Rat` 类型的值应该通过指针操作 (`*Rat`)。直接赋值会进行浅拷贝，导致多个变量指向同一个内部数据，修改一个变量可能会影响其他变量。
    ```go
    r1 := big.NewRat(1, 2)
    r2 := r1 // 错误：浅拷贝
    r2.Mul(r2, big.NewRat(2, 1))
    fmt.Println(r1.String()) // 输出: 1/1， r1 也被修改了

    r3 := big.NewRat(1, 2)
    r4 := new(big.Rat).Set(r3) // 正确：使用 Set 进行深拷贝
    r4.Mul(r4, big.NewRat(2, 1))
    fmt.Println(r3.String()) // 输出: 1/2， r3 没有被修改
    ```

2. **除零错误:**  在创建或进行除法运算时，如果分母为零，会引发 panic。
    ```go
    // 运行时会 panic: division by zero
    // r := big.NewRat(1, 0)

    r1 := big.NewRat(1, 2)
    r2 := big.NewRat(0, 1)
    // 运行时会 panic: division by zero
    // result := new(big.Rat).Quo(r1, r2)
    ```

3. **误解 `Num()` 和 `Denom()` 的返回值:**  这两个方法返回的是指向内部 `Int` 对象的指针。直接修改这些指针指向的 `Int` 对象会直接修改 `Rat` 对象的状态。如果不需要修改，应该创建副本。
    ```go
    r := big.NewRat(3, 4)
    numerator := r.Num()
    numerator.SetInt64(5) // 直接修改了 r 的分子
    fmt.Println(r.String()) // 输出: 5/4
    ```

总而言之，`go/src/math/big/rat.go` 这部分代码实现了 Go 语言中用于进行高精度有理数运算的核心功能，为需要精确计算的场景提供了重要的支持。

Prompt: 
```
这是路径为go/src/math/big/rat.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements multi-precision rational numbers.

package big

import (
	"fmt"
	"math"
)

// A Rat represents a quotient a/b of arbitrary precision.
// The zero value for a Rat represents the value 0.
//
// Operations always take pointer arguments (*Rat) rather
// than Rat values, and each unique Rat value requires
// its own unique *Rat pointer. To "copy" a Rat value,
// an existing (or newly allocated) Rat must be set to
// a new value using the [Rat.Set] method; shallow copies
// of Rats are not supported and may lead to errors.
type Rat struct {
	// To make zero values for Rat work w/o initialization,
	// a zero value of b (len(b) == 0) acts like b == 1. At
	// the earliest opportunity (when an assignment to the Rat
	// is made), such uninitialized denominators are set to 1.
	// a.neg determines the sign of the Rat, b.neg is ignored.
	a, b Int
}

// NewRat creates a new [Rat] with numerator a and denominator b.
func NewRat(a, b int64) *Rat {
	return new(Rat).SetFrac64(a, b)
}

// SetFloat64 sets z to exactly f and returns z.
// If f is not finite, SetFloat returns nil.
func (z *Rat) SetFloat64(f float64) *Rat {
	const expMask = 1<<11 - 1
	bits := math.Float64bits(f)
	mantissa := bits & (1<<52 - 1)
	exp := int((bits >> 52) & expMask)
	switch exp {
	case expMask: // non-finite
		return nil
	case 0: // denormal
		exp -= 1022
	default: // normal
		mantissa |= 1 << 52
		exp -= 1023
	}

	shift := 52 - exp

	// Optimization (?): partially pre-normalise.
	for mantissa&1 == 0 && shift > 0 {
		mantissa >>= 1
		shift--
	}

	z.a.SetUint64(mantissa)
	z.a.neg = f < 0
	z.b.Set(intOne)
	if shift > 0 {
		z.b.Lsh(&z.b, uint(shift))
	} else {
		z.a.Lsh(&z.a, uint(-shift))
	}
	return z.norm()
}

// quotToFloat32 returns the non-negative float32 value
// nearest to the quotient a/b, using round-to-even in
// halfway cases. It does not mutate its arguments.
// Preconditions: b is non-zero; a and b have no common factors.
func quotToFloat32(a, b nat) (f float32, exact bool) {
	const (
		// float size in bits
		Fsize = 32

		// mantissa
		Msize  = 23
		Msize1 = Msize + 1 // incl. implicit 1
		Msize2 = Msize1 + 1

		// exponent
		Esize = Fsize - Msize1
		Ebias = 1<<(Esize-1) - 1
		Emin  = 1 - Ebias
		Emax  = Ebias
	)

	// TODO(adonovan): specialize common degenerate cases: 1.0, integers.
	alen := a.bitLen()
	if alen == 0 {
		return 0, true
	}
	blen := b.bitLen()
	if blen == 0 {
		panic("division by zero")
	}

	// 1. Left-shift A or B such that quotient A/B is in [1<<Msize1, 1<<(Msize2+1)
	// (Msize2 bits if A < B when they are left-aligned, Msize2+1 bits if A >= B).
	// This is 2 or 3 more than the float32 mantissa field width of Msize:
	// - the optional extra bit is shifted away in step 3 below.
	// - the high-order 1 is omitted in "normal" representation;
	// - the low-order 1 will be used during rounding then discarded.
	exp := alen - blen
	var a2, b2 nat
	a2 = a2.set(a)
	b2 = b2.set(b)
	if shift := Msize2 - exp; shift > 0 {
		a2 = a2.shl(a2, uint(shift))
	} else if shift < 0 {
		b2 = b2.shl(b2, uint(-shift))
	}

	// 2. Compute quotient and remainder (q, r).  NB: due to the
	// extra shift, the low-order bit of q is logically the
	// high-order bit of r.
	var q nat
	q, r := q.div(a2, a2, b2) // (recycle a2)
	mantissa := low32(q)
	haveRem := len(r) > 0 // mantissa&1 && !haveRem => remainder is exactly half

	// 3. If quotient didn't fit in Msize2 bits, redo division by b2<<1
	// (in effect---we accomplish this incrementally).
	if mantissa>>Msize2 == 1 {
		if mantissa&1 == 1 {
			haveRem = true
		}
		mantissa >>= 1
		exp++
	}
	if mantissa>>Msize1 != 1 {
		panic(fmt.Sprintf("expected exactly %d bits of result", Msize2))
	}

	// 4. Rounding.
	if Emin-Msize <= exp && exp <= Emin {
		// Denormal case; lose 'shift' bits of precision.
		shift := uint(Emin - (exp - 1)) // [1..Esize1)
		lostbits := mantissa & (1<<shift - 1)
		haveRem = haveRem || lostbits != 0
		mantissa >>= shift
		exp = 2 - Ebias // == exp + shift
	}
	// Round q using round-half-to-even.
	exact = !haveRem
	if mantissa&1 != 0 {
		exact = false
		if haveRem || mantissa&2 != 0 {
			if mantissa++; mantissa >= 1<<Msize2 {
				// Complete rollover 11...1 => 100...0, so shift is safe
				mantissa >>= 1
				exp++
			}
		}
	}
	mantissa >>= 1 // discard rounding bit.  Mantissa now scaled by 1<<Msize1.

	f = float32(math.Ldexp(float64(mantissa), exp-Msize1))
	if math.IsInf(float64(f), 0) {
		exact = false
	}
	return
}

// quotToFloat64 returns the non-negative float64 value
// nearest to the quotient a/b, using round-to-even in
// halfway cases. It does not mutate its arguments.
// Preconditions: b is non-zero; a and b have no common factors.
func quotToFloat64(a, b nat) (f float64, exact bool) {
	const (
		// float size in bits
		Fsize = 64

		// mantissa
		Msize  = 52
		Msize1 = Msize + 1 // incl. implicit 1
		Msize2 = Msize1 + 1

		// exponent
		Esize = Fsize - Msize1
		Ebias = 1<<(Esize-1) - 1
		Emin  = 1 - Ebias
		Emax  = Ebias
	)

	// TODO(adonovan): specialize common degenerate cases: 1.0, integers.
	alen := a.bitLen()
	if alen == 0 {
		return 0, true
	}
	blen := b.bitLen()
	if blen == 0 {
		panic("division by zero")
	}

	// 1. Left-shift A or B such that quotient A/B is in [1<<Msize1, 1<<(Msize2+1)
	// (Msize2 bits if A < B when they are left-aligned, Msize2+1 bits if A >= B).
	// This is 2 or 3 more than the float64 mantissa field width of Msize:
	// - the optional extra bit is shifted away in step 3 below.
	// - the high-order 1 is omitted in "normal" representation;
	// - the low-order 1 will be used during rounding then discarded.
	exp := alen - blen
	var a2, b2 nat
	a2 = a2.set(a)
	b2 = b2.set(b)
	if shift := Msize2 - exp; shift > 0 {
		a2 = a2.shl(a2, uint(shift))
	} else if shift < 0 {
		b2 = b2.shl(b2, uint(-shift))
	}

	// 2. Compute quotient and remainder (q, r).  NB: due to the
	// extra shift, the low-order bit of q is logically the
	// high-order bit of r.
	var q nat
	q, r := q.div(a2, a2, b2) // (recycle a2)
	mantissa := low64(q)
	haveRem := len(r) > 0 // mantissa&1 && !haveRem => remainder is exactly half

	// 3. If quotient didn't fit in Msize2 bits, redo division by b2<<1
	// (in effect---we accomplish this incrementally).
	if mantissa>>Msize2 == 1 {
		if mantissa&1 == 1 {
			haveRem = true
		}
		mantissa >>= 1
		exp++
	}
	if mantissa>>Msize1 != 1 {
		panic(fmt.Sprintf("expected exactly %d bits of result", Msize2))
	}

	// 4. Rounding.
	if Emin-Msize <= exp && exp <= Emin {
		// Denormal case; lose 'shift' bits of precision.
		shift := uint(Emin - (exp - 1)) // [1..Esize1)
		lostbits := mantissa & (1<<shift - 1)
		haveRem = haveRem || lostbits != 0
		mantissa >>= shift
		exp = 2 - Ebias // == exp + shift
	}
	// Round q using round-half-to-even.
	exact = !haveRem
	if mantissa&1 != 0 {
		exact = false
		if haveRem || mantissa&2 != 0 {
			if mantissa++; mantissa >= 1<<Msize2 {
				// Complete rollover 11...1 => 100...0, so shift is safe
				mantissa >>= 1
				exp++
			}
		}
	}
	mantissa >>= 1 // discard rounding bit.  Mantissa now scaled by 1<<Msize1.

	f = math.Ldexp(float64(mantissa), exp-Msize1)
	if math.IsInf(f, 0) {
		exact = false
	}
	return
}

// Float32 returns the nearest float32 value for x and a bool indicating
// whether f represents x exactly. If the magnitude of x is too large to
// be represented by a float32, f is an infinity and exact is false.
// The sign of f always matches the sign of x, even if f == 0.
func (x *Rat) Float32() (f float32, exact bool) {
	b := x.b.abs
	if len(b) == 0 {
		b = natOne
	}
	f, exact = quotToFloat32(x.a.abs, b)
	if x.a.neg {
		f = -f
	}
	return
}

// Float64 returns the nearest float64 value for x and a bool indicating
// whether f represents x exactly. If the magnitude of x is too large to
// be represented by a float64, f is an infinity and exact is false.
// The sign of f always matches the sign of x, even if f == 0.
func (x *Rat) Float64() (f float64, exact bool) {
	b := x.b.abs
	if len(b) == 0 {
		b = natOne
	}
	f, exact = quotToFloat64(x.a.abs, b)
	if x.a.neg {
		f = -f
	}
	return
}

// SetFrac sets z to a/b and returns z.
// If b == 0, SetFrac panics.
func (z *Rat) SetFrac(a, b *Int) *Rat {
	z.a.neg = a.neg != b.neg
	babs := b.abs
	if len(babs) == 0 {
		panic("division by zero")
	}
	if &z.a == b || alias(z.a.abs, babs) {
		babs = nat(nil).set(babs) // make a copy
	}
	z.a.abs = z.a.abs.set(a.abs)
	z.b.abs = z.b.abs.set(babs)
	return z.norm()
}

// SetFrac64 sets z to a/b and returns z.
// If b == 0, SetFrac64 panics.
func (z *Rat) SetFrac64(a, b int64) *Rat {
	if b == 0 {
		panic("division by zero")
	}
	z.a.SetInt64(a)
	if b < 0 {
		b = -b
		z.a.neg = !z.a.neg
	}
	z.b.abs = z.b.abs.setUint64(uint64(b))
	return z.norm()
}

// SetInt sets z to x (by making a copy of x) and returns z.
func (z *Rat) SetInt(x *Int) *Rat {
	z.a.Set(x)
	z.b.abs = z.b.abs.setWord(1)
	return z
}

// SetInt64 sets z to x and returns z.
func (z *Rat) SetInt64(x int64) *Rat {
	z.a.SetInt64(x)
	z.b.abs = z.b.abs.setWord(1)
	return z
}

// SetUint64 sets z to x and returns z.
func (z *Rat) SetUint64(x uint64) *Rat {
	z.a.SetUint64(x)
	z.b.abs = z.b.abs.setWord(1)
	return z
}

// Set sets z to x (by making a copy of x) and returns z.
func (z *Rat) Set(x *Rat) *Rat {
	if z != x {
		z.a.Set(&x.a)
		z.b.Set(&x.b)
	}
	if len(z.b.abs) == 0 {
		z.b.abs = z.b.abs.setWord(1)
	}
	return z
}

// Abs sets z to |x| (the absolute value of x) and returns z.
func (z *Rat) Abs(x *Rat) *Rat {
	z.Set(x)
	z.a.neg = false
	return z
}

// Neg sets z to -x and returns z.
func (z *Rat) Neg(x *Rat) *Rat {
	z.Set(x)
	z.a.neg = len(z.a.abs) > 0 && !z.a.neg // 0 has no sign
	return z
}

// Inv sets z to 1/x and returns z.
// If x == 0, Inv panics.
func (z *Rat) Inv(x *Rat) *Rat {
	if len(x.a.abs) == 0 {
		panic("division by zero")
	}
	z.Set(x)
	z.a.abs, z.b.abs = z.b.abs, z.a.abs
	return z
}

// Sign returns:
//   - -1 if x < 0;
//   - 0 if x == 0;
//   - +1 if x > 0.
func (x *Rat) Sign() int {
	return x.a.Sign()
}

// IsInt reports whether the denominator of x is 1.
func (x *Rat) IsInt() bool {
	return len(x.b.abs) == 0 || x.b.abs.cmp(natOne) == 0
}

// Num returns the numerator of x; it may be <= 0.
// The result is a reference to x's numerator; it
// may change if a new value is assigned to x, and vice versa.
// The sign of the numerator corresponds to the sign of x.
func (x *Rat) Num() *Int {
	return &x.a
}

// Denom returns the denominator of x; it is always > 0.
// The result is a reference to x's denominator, unless
// x is an uninitialized (zero value) [Rat], in which case
// the result is a new [Int] of value 1. (To initialize x,
// any operation that sets x will do, including x.Set(x).)
// If the result is a reference to x's denominator it
// may change if a new value is assigned to x, and vice versa.
func (x *Rat) Denom() *Int {
	// Note that x.b.neg is guaranteed false.
	if len(x.b.abs) == 0 {
		// Note: If this proves problematic, we could
		//       panic instead and require the Rat to
		//       be explicitly initialized.
		return &Int{abs: nat{1}}
	}
	return &x.b
}

func (z *Rat) norm() *Rat {
	switch {
	case len(z.a.abs) == 0:
		// z == 0; normalize sign and denominator
		z.a.neg = false
		fallthrough
	case len(z.b.abs) == 0:
		// z is integer; normalize denominator
		z.b.abs = z.b.abs.setWord(1)
	default:
		// z is fraction; normalize numerator and denominator
		neg := z.a.neg
		z.a.neg = false
		z.b.neg = false
		if f := NewInt(0).lehmerGCD(nil, nil, &z.a, &z.b); f.Cmp(intOne) != 0 {
			z.a.abs, _ = z.a.abs.div(nil, z.a.abs, f.abs)
			z.b.abs, _ = z.b.abs.div(nil, z.b.abs, f.abs)
		}
		z.a.neg = neg
	}
	return z
}

// mulDenom sets z to the denominator product x*y (by taking into
// account that 0 values for x or y must be interpreted as 1) and
// returns z.
func mulDenom(z, x, y nat) nat {
	switch {
	case len(x) == 0 && len(y) == 0:
		return z.setWord(1)
	case len(x) == 0:
		return z.set(y)
	case len(y) == 0:
		return z.set(x)
	}
	return z.mul(x, y)
}

// scaleDenom sets z to the product x*f.
// If f == 0 (zero value of denominator), z is set to (a copy of) x.
func (z *Int) scaleDenom(x *Int, f nat) {
	if len(f) == 0 {
		z.Set(x)
		return
	}
	z.abs = z.abs.mul(x.abs, f)
	z.neg = x.neg
}

// Cmp compares x and y and returns:
//   - -1 if x < y;
//   - 0 if x == y;
//   - +1 if x > y.
func (x *Rat) Cmp(y *Rat) int {
	var a, b Int
	a.scaleDenom(&x.a, y.b.abs)
	b.scaleDenom(&y.a, x.b.abs)
	return a.Cmp(&b)
}

// Add sets z to the sum x+y and returns z.
func (z *Rat) Add(x, y *Rat) *Rat {
	var a1, a2 Int
	a1.scaleDenom(&x.a, y.b.abs)
	a2.scaleDenom(&y.a, x.b.abs)
	z.a.Add(&a1, &a2)
	z.b.abs = mulDenom(z.b.abs, x.b.abs, y.b.abs)
	return z.norm()
}

// Sub sets z to the difference x-y and returns z.
func (z *Rat) Sub(x, y *Rat) *Rat {
	var a1, a2 Int
	a1.scaleDenom(&x.a, y.b.abs)
	a2.scaleDenom(&y.a, x.b.abs)
	z.a.Sub(&a1, &a2)
	z.b.abs = mulDenom(z.b.abs, x.b.abs, y.b.abs)
	return z.norm()
}

// Mul sets z to the product x*y and returns z.
func (z *Rat) Mul(x, y *Rat) *Rat {
	if x == y {
		// a squared Rat is positive and can't be reduced (no need to call norm())
		z.a.neg = false
		z.a.abs = z.a.abs.sqr(x.a.abs)
		if len(x.b.abs) == 0 {
			z.b.abs = z.b.abs.setWord(1)
		} else {
			z.b.abs = z.b.abs.sqr(x.b.abs)
		}
		return z
	}
	z.a.Mul(&x.a, &y.a)
	z.b.abs = mulDenom(z.b.abs, x.b.abs, y.b.abs)
	return z.norm()
}

// Quo sets z to the quotient x/y and returns z.
// If y == 0, Quo panics.
func (z *Rat) Quo(x, y *Rat) *Rat {
	if len(y.a.abs) == 0 {
		panic("division by zero")
	}
	var a, b Int
	a.scaleDenom(&x.a, y.b.abs)
	b.scaleDenom(&y.a, x.b.abs)
	z.a.abs = a.abs
	z.b.abs = b.abs
	z.a.neg = a.neg != b.neg
	return z.norm()
}

"""



```