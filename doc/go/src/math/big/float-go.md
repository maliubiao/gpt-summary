Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `float.go` file in the `math/big` package.

Here's a breakdown of the thought process to address the request:

1. **Identify the Core Purpose:** The initial comments clearly state that this file implements multi-precision floating-point numbers, similar to the GNU MPFR library. This is the central theme.

2. **Analyze the `Float` Type:**  The `Float` struct is the heart of the implementation. Deconstruct its fields:
    * `prec`: Precision (number of mantissa bits).
    * `mode`: Rounding mode.
    * `acc`: Accuracy of the value.
    * `form`:  Indicates whether the float is zero, finite, or infinite.
    * `neg`: Sign.
    * `mant`: Mantissa (represented as a `nat` - likely a slice of `uint` or `uintptr`).
    * `exp`: Exponent.

3. **Examine Key Methods:**  Go through the provided methods and group them by functionality:
    * **Creation/Initialization:** `NewFloat`, `SetFloat64`, `SetUint64`, `SetInt64`, `SetInt`, `SetRat`, `SetMantExp`, `SetInf`, `Set`.
    * **Accessors:** `Prec`, `MinPrec`, `Mode`, `Acc`, `Sign`, `Signbit`, `IsInf`, `IsInt`, `MantExp`.
    * **Mutators (setting properties):** `SetPrec`, `SetMode`.
    * **Conversion to other types:** `Uint64`, `Int64`, `Float32`, `Float64`, `Int`, `Rat`.
    * **Other operations:** `Copy`, `Abs`, `Neg`.
    * **Internal/Helper:** `round`, `setBits64`, `fnorm`, `setExpAndRound`, `validate`, `validate0`.

4. **Infer Functionality from Method Names and Comments:** The names of the methods are generally descriptive. The comments provide valuable context. For example, `SetPrec` clearly sets the precision and handles rounding. `MantExp` extracts the mantissa and exponent.

5. **Identify Core Concepts:** Extract the key concepts related to multi-precision floats:
    * Precision.
    * Rounding modes.
    * Accuracy.
    * Special values (zero, infinity, NaN).
    * Internal representation (sign, mantissa, exponent).

6. **Address Specific Questions:** Go through the user's requests point-by-point:
    * **List the functionalities:** Summarize the categories identified in step 3.
    * **Infer Go language feature:**  The `math/big` package demonstrates the ability to implement custom number types beyond the built-in `float32` and `float64`. It uses structs and methods to achieve this. The `nat` type suggests using arbitrary-precision integers as the underlying representation for the mantissa.
    * **Code examples:** Provide examples for key functionalities like creating a `Float`, setting its value, performing operations, and converting to other types. Include expected inputs and outputs.
    * **Command-line arguments:**  The provided code snippet doesn't involve command-line arguments. State this explicitly.
    * **Common mistakes:** Focus on the pointer-based nature of `Float` and the importance of using `Set` or `Copy` instead of direct assignment to avoid unintended side effects.
    * **Summarize the functionality:**  Provide a concise overview of what the code does.

7. **Structure the Answer:** Organize the information logically using headings and bullet points for clarity. Use code blocks for examples.

8. **Refine and Review:** Read through the answer to ensure accuracy, completeness, and clarity. Double-check the code examples. Ensure the language is accessible and avoids jargon where possible. Make sure the summary directly answers the final request in Part 1.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus solely on the individual methods.
* **Correction:** Group methods by functionality for a higher-level understanding.
* **Initial thought:** Assume the user is familiar with floating-point concepts.
* **Correction:** Briefly explain the core concepts like precision and rounding modes.
* **Initial thought:** Provide very simple code examples.
* **Correction:** Make the examples more illustrative, showing different ways to create and manipulate `Float` values.
* **Initial thought:**  Only list the methods.
* **Correction:**  Explain *what* each method does and *why* it's important in the context of multi-precision arithmetic.

By following these steps, the resulting answer accurately reflects the functionality of the provided Go code and addresses all aspects of the user's request.
这是一个Go语言实现的用于表示**任意精度浮点数**的代码片段，它提供了比Go语言内置的`float32`和`float64`更高的精度。 这个代码是 `math/big` 包中 `Float` 类型的定义和部分实现。

**主要功能归纳：**

1. **表示任意精度的浮点数:** `Float` 结构体能够存储和操作具有任意指定精度的浮点数。这超越了标准 IEEE 754 浮点类型的精度限制。
2. **支持不同的舍入模式:**  `RoundingMode` 类型定义了多种舍入模式，允许用户控制在精度受限时如何对结果进行舍入。
3. **跟踪计算的精度:** `Accuracy` 类型用于记录最近一次操作产生的舍入误差。
4. **支持特殊值:** 可以表示正负零 (+0, -0) 和正负无穷 (+Inf, -Inf)。
5. **提供基本的浮点数操作:** 实现了诸如设置精度、设置舍入模式、获取符号、获取尾数和指数、设置尾数和指数、转换为其他类型（如 `uint64`, `int64`, `float32`, `float64`, `Int`, `Rat`）、取绝对值和取反等操作。

**它可以被推理为 Go 语言中实现任意精度浮点数的功能。**

**Go 代码举例说明:**

假设我们想要计算一个高精度的 π 值，并将其转换为 `float64`。

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	// 创建一个新的 Float，并设置其精度为 100 bits
	pi := new(big.Float).SetPrec(100)

	// 这里假设有一个计算高精度 π 的函数 (实际中需要自己实现或使用库)
	// 假设 calculateHighPrecisionPi(prec uint) 返回一个 *big.Float
	// pi = calculateHighPrecisionPi(100)

	// 为了演示，我们这里简单设置一个接近 π 的值
	pi.SetString("3.14159265358979323846264338327950288419716939937510582097494459")

	fmt.Println("高精度 π:", pi.String())

	// 将高精度 π 转换为 float64
	piFloat64, accuracy := pi.Float64()
	fmt.Println("转换为 float64:", piFloat64)
	fmt.Println("转换精度:", accuracy)

	// 创建另一个 Float 并从 float64 设置值
	f := new(big.Float).SetFloat64(3.14)
	fmt.Println("从 float64 创建的 Float:", f.String())

	// 获取 f 的尾数和指数
	mant := new(big.Float)
	exp := f.MantExp(mant)
	fmt.Printf("尾数: %s, 指数: %d\n", mant.String(), exp)

	// 创建一个精度为 80 的 Float，并从上面的尾数和指数设置值
	g := new(big.Float).SetPrec(80).SetMantExp(mant, exp)
	fmt.Println("从尾数和指数创建的 Float:", g.String())

	// 获取 g 的精度
	fmt.Println("g 的精度:", g.Prec())
}
```

**假设的输入与输出:**

由于代码中 `calculateHighPrecisionPi` 是一个假设的函数，我们使用 `SetString` 来设置 `pi` 的值。

**假设 `pi.SetString("3.14159265358979323846264338327950288419716939937510582097494459")`**

**输出:**

```
高精度 π: 3.14159265358979323846264338327950288419716939937510582097494459
转换为 float64: 3.141592653589793
转换精度: Below
从 float64 创建的 Float: 3.14
尾数: 0.785, 指数: 2
从尾数和指数创建的 Float: 3.14
g 的精度: 80
```

**代码推理:**

* `new(big.Float).SetPrec(100)`: 创建一个新的 `Float` 变量 `pi`，并将其精度设置为 100 位。这意味着 `pi` 可以存储大约 30 位十进制有效数字。
* `pi.SetString(...)`: 将一个字符串表示的高精度 π 值赋给 `pi`。
* `pi.Float64()`: 将 `pi` 转换为 Go 语言的内置 `float64` 类型。由于 `float64` 的精度有限（大约 15-17 位十进制有效数字），转换可能会导致精度损失，因此转换精度为 `Below`，表示结果是向下舍入的。
* `new(big.Float).SetFloat64(3.14)`: 创建一个新的 `Float` 变量 `f`，并将其值设置为 `float64` 类型的 `3.14`。
* `f.MantExp(mant)`: 将 `f` 分解为尾数 `mant` 和指数，满足 `f == mant * 2**exp`，其中 `0.5 <= |mant| < 1.0`。对于 `3.14`，其二进制表示为 `1.10011001100110011001101... * 2^1`，归一化后尾数为 `0.110011001100110011001101...` (二进制)，对应十进制大约 `0.785`，指数为 `2`。
* `new(big.Float).SetPrec(80).SetMantExp(mant, exp)`: 创建一个新的 `Float` 变量 `g`，设置其精度为 80 位，并使用之前获取的 `mant` 和 `exp` 设置 `g` 的值。

**使用者易犯错的点:**

一个常见的错误是**直接赋值 `Float` 类型的值**，而不是使用指针和 `Set` 或 `Copy` 方法。由于 `Float` 类型内部包含 `nat` 类型的切片（用于存储尾数），直接赋值会导致多个 `Float` 变量共享同一个底层的尾数数据，从而在一个变量上的修改会影响到其他变量。

**错误示例:**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	a := new(big.Float).SetFloat64(1.0)
	b := a // 错误：直接赋值

	b.SetFloat64(2.0)

	fmt.Println("a:", a.String()) // 期望输出: 1，实际输出: 2
	fmt.Println("b:", b.String())
}
```

**正确的做法是使用 `Set` 方法进行复制:**

```go
package main

import (
	"fmt"
	"math/big"
)

func main() {
	a := new(big.Float).SetFloat64(1.0)
	b := new(big.Float).Set(a) // 正确：使用 Set 方法复制

	b.SetFloat64(2.0)

	fmt.Println("a:", a.String()) // 输出: 1
	fmt.Println("b:", b.String()) // 输出: 2
}
```

**总结一下它的功能:**

这段 Go 代码是 `math/big` 包中 `Float` 类型的核心实现，它提供了**任意精度浮点数**的支持，允许用户进行高精度的浮点数运算。它包括了 `Float` 类型的定义，以及用于创建、访问、修改和转换 `Float` 值的基本方法。 核心功能包括：**表示高精度浮点数，支持多种舍入模式，跟踪精度，支持特殊值，以及提供基本的算术操作的基础**。

Prompt: 
```
这是路径为go/src/math/big/float.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements multi-precision floating-point numbers.
// Like in the GNU MPFR library (https://www.mpfr.org/), operands
// can be of mixed precision. Unlike MPFR, the rounding mode is
// not specified with each operation, but with each operand. The
// rounding mode of the result operand determines the rounding
// mode of an operation. This is a from-scratch implementation.

package big

import (
	"fmt"
	"math"
	"math/bits"
)

const debugFloat = false // enable for debugging

// A nonzero finite Float represents a multi-precision floating point number
//
//	sign × mantissa × 2**exponent
//
// with 0.5 <= mantissa < 1.0, and MinExp <= exponent <= MaxExp.
// A Float may also be zero (+0, -0) or infinite (+Inf, -Inf).
// All Floats are ordered, and the ordering of two Floats x and y
// is defined by x.Cmp(y).
//
// Each Float value also has a precision, rounding mode, and accuracy.
// The precision is the maximum number of mantissa bits available to
// represent the value. The rounding mode specifies how a result should
// be rounded to fit into the mantissa bits, and accuracy describes the
// rounding error with respect to the exact result.
//
// Unless specified otherwise, all operations (including setters) that
// specify a *Float variable for the result (usually via the receiver
// with the exception of [Float.MantExp]), round the numeric result according
// to the precision and rounding mode of the result variable.
//
// If the provided result precision is 0 (see below), it is set to the
// precision of the argument with the largest precision value before any
// rounding takes place, and the rounding mode remains unchanged. Thus,
// uninitialized Floats provided as result arguments will have their
// precision set to a reasonable value determined by the operands, and
// their mode is the zero value for RoundingMode (ToNearestEven).
//
// By setting the desired precision to 24 or 53 and using matching rounding
// mode (typically [ToNearestEven]), Float operations produce the same results
// as the corresponding float32 or float64 IEEE 754 arithmetic for operands
// that correspond to normal (i.e., not denormal) float32 or float64 numbers.
// Exponent underflow and overflow lead to a 0 or an Infinity for different
// values than IEEE 754 because Float exponents have a much larger range.
//
// The zero (uninitialized) value for a Float is ready to use and represents
// the number +0.0 exactly, with precision 0 and rounding mode [ToNearestEven].
//
// Operations always take pointer arguments (*Float) rather
// than Float values, and each unique Float value requires
// its own unique *Float pointer. To "copy" a Float value,
// an existing (or newly allocated) Float must be set to
// a new value using the [Float.Set] method; shallow copies
// of Floats are not supported and may lead to errors.
type Float struct {
	prec uint32
	mode RoundingMode
	acc  Accuracy
	form form
	neg  bool
	mant nat
	exp  int32
}

// An ErrNaN panic is raised by a [Float] operation that would lead to
// a NaN under IEEE 754 rules. An ErrNaN implements the error interface.
type ErrNaN struct {
	msg string
}

func (err ErrNaN) Error() string {
	return err.msg
}

// NewFloat allocates and returns a new [Float] set to x,
// with precision 53 and rounding mode [ToNearestEven].
// NewFloat panics with [ErrNaN] if x is a NaN.
func NewFloat(x float64) *Float {
	if math.IsNaN(x) {
		panic(ErrNaN{"NewFloat(NaN)"})
	}
	return new(Float).SetFloat64(x)
}

// Exponent and precision limits.
const (
	MaxExp  = math.MaxInt32  // largest supported exponent
	MinExp  = math.MinInt32  // smallest supported exponent
	MaxPrec = math.MaxUint32 // largest (theoretically) supported precision; likely memory-limited
)

// Internal representation: The mantissa bits x.mant of a nonzero finite
// Float x are stored in a nat slice long enough to hold up to x.prec bits;
// the slice may (but doesn't have to) be shorter if the mantissa contains
// trailing 0 bits. x.mant is normalized if the msb of x.mant == 1 (i.e.,
// the msb is shifted all the way "to the left"). Thus, if the mantissa has
// trailing 0 bits or x.prec is not a multiple of the Word size _W,
// x.mant[0] has trailing zero bits. The msb of the mantissa corresponds
// to the value 0.5; the exponent x.exp shifts the binary point as needed.
//
// A zero or non-finite Float x ignores x.mant and x.exp.
//
// x                 form      neg      mant         exp
// ----------------------------------------------------------
// ±0                zero      sign     -            -
// 0 < |x| < +Inf    finite    sign     mantissa     exponent
// ±Inf              inf       sign     -            -

// A form value describes the internal representation.
type form byte

// The form value order is relevant - do not change!
const (
	zero form = iota
	finite
	inf
)

// RoundingMode determines how a [Float] value is rounded to the
// desired precision. Rounding may change the [Float] value; the
// rounding error is described by the [Float]'s [Accuracy].
type RoundingMode byte

// These constants define supported rounding modes.
const (
	ToNearestEven RoundingMode = iota // == IEEE 754-2008 roundTiesToEven
	ToNearestAway                     // == IEEE 754-2008 roundTiesToAway
	ToZero                            // == IEEE 754-2008 roundTowardZero
	AwayFromZero                      // no IEEE 754-2008 equivalent
	ToNegativeInf                     // == IEEE 754-2008 roundTowardNegative
	ToPositiveInf                     // == IEEE 754-2008 roundTowardPositive
)

//go:generate stringer -type=RoundingMode

// Accuracy describes the rounding error produced by the most recent
// operation that generated a [Float] value, relative to the exact value.
type Accuracy int8

// Constants describing the [Accuracy] of a [Float].
const (
	Below Accuracy = -1
	Exact Accuracy = 0
	Above Accuracy = +1
)

//go:generate stringer -type=Accuracy

// SetPrec sets z's precision to prec and returns the (possibly) rounded
// value of z. Rounding occurs according to z's rounding mode if the mantissa
// cannot be represented in prec bits without loss of precision.
// SetPrec(0) maps all finite values to ±0; infinite values remain unchanged.
// If prec > [MaxPrec], it is set to [MaxPrec].
func (z *Float) SetPrec(prec uint) *Float {
	z.acc = Exact // optimistically assume no rounding is needed

	// special case
	if prec == 0 {
		z.prec = 0
		if z.form == finite {
			// truncate z to 0
			z.acc = makeAcc(z.neg)
			z.form = zero
		}
		return z
	}

	// general case
	if prec > MaxPrec {
		prec = MaxPrec
	}
	old := z.prec
	z.prec = uint32(prec)
	if z.prec < old {
		z.round(0)
	}
	return z
}

func makeAcc(above bool) Accuracy {
	if above {
		return Above
	}
	return Below
}

// SetMode sets z's rounding mode to mode and returns an exact z.
// z remains unchanged otherwise.
// z.SetMode(z.Mode()) is a cheap way to set z's accuracy to [Exact].
func (z *Float) SetMode(mode RoundingMode) *Float {
	z.mode = mode
	z.acc = Exact
	return z
}

// Prec returns the mantissa precision of x in bits.
// The result may be 0 for |x| == 0 and |x| == Inf.
func (x *Float) Prec() uint {
	return uint(x.prec)
}

// MinPrec returns the minimum precision required to represent x exactly
// (i.e., the smallest prec before x.SetPrec(prec) would start rounding x).
// The result is 0 for |x| == 0 and |x| == Inf.
func (x *Float) MinPrec() uint {
	if x.form != finite {
		return 0
	}
	return uint(len(x.mant))*_W - x.mant.trailingZeroBits()
}

// Mode returns the rounding mode of x.
func (x *Float) Mode() RoundingMode {
	return x.mode
}

// Acc returns the accuracy of x produced by the most recent
// operation, unless explicitly documented otherwise by that
// operation.
func (x *Float) Acc() Accuracy {
	return x.acc
}

// Sign returns:
//   - -1 if x < 0;
//   - 0 if x is ±0;
//   - +1 if x > 0.
func (x *Float) Sign() int {
	if debugFloat {
		x.validate()
	}
	if x.form == zero {
		return 0
	}
	if x.neg {
		return -1
	}
	return 1
}

// MantExp breaks x into its mantissa and exponent components
// and returns the exponent. If a non-nil mant argument is
// provided its value is set to the mantissa of x, with the
// same precision and rounding mode as x. The components
// satisfy x == mant × 2**exp, with 0.5 <= |mant| < 1.0.
// Calling MantExp with a nil argument is an efficient way to
// get the exponent of the receiver.
//
// Special cases are:
//
//	(  ±0).MantExp(mant) = 0, with mant set to   ±0
//	(±Inf).MantExp(mant) = 0, with mant set to ±Inf
//
// x and mant may be the same in which case x is set to its
// mantissa value.
func (x *Float) MantExp(mant *Float) (exp int) {
	if debugFloat {
		x.validate()
	}
	if x.form == finite {
		exp = int(x.exp)
	}
	if mant != nil {
		mant.Copy(x)
		if mant.form == finite {
			mant.exp = 0
		}
	}
	return
}

func (z *Float) setExpAndRound(exp int64, sbit uint) {
	if exp < MinExp {
		// underflow
		z.acc = makeAcc(z.neg)
		z.form = zero
		return
	}

	if exp > MaxExp {
		// overflow
		z.acc = makeAcc(!z.neg)
		z.form = inf
		return
	}

	z.form = finite
	z.exp = int32(exp)
	z.round(sbit)
}

// SetMantExp sets z to mant × 2**exp and returns z.
// The result z has the same precision and rounding mode
// as mant. SetMantExp is an inverse of [Float.MantExp] but does
// not require 0.5 <= |mant| < 1.0. Specifically, for a
// given x of type *[Float], SetMantExp relates to [Float.MantExp]
// as follows:
//
//	mant := new(Float)
//	new(Float).SetMantExp(mant, x.MantExp(mant)).Cmp(x) == 0
//
// Special cases are:
//
//	z.SetMantExp(  ±0, exp) =   ±0
//	z.SetMantExp(±Inf, exp) = ±Inf
//
// z and mant may be the same in which case z's exponent
// is set to exp.
func (z *Float) SetMantExp(mant *Float, exp int) *Float {
	if debugFloat {
		z.validate()
		mant.validate()
	}
	z.Copy(mant)

	if z.form == finite {
		// 0 < |mant| < +Inf
		z.setExpAndRound(int64(z.exp)+int64(exp), 0)
	}
	return z
}

// Signbit reports whether x is negative or negative zero.
func (x *Float) Signbit() bool {
	return x.neg
}

// IsInf reports whether x is +Inf or -Inf.
func (x *Float) IsInf() bool {
	return x.form == inf
}

// IsInt reports whether x is an integer.
// ±Inf values are not integers.
func (x *Float) IsInt() bool {
	if debugFloat {
		x.validate()
	}
	// special cases
	if x.form != finite {
		return x.form == zero
	}
	// x.form == finite
	if x.exp <= 0 {
		return false
	}
	// x.exp > 0
	return x.prec <= uint32(x.exp) || x.MinPrec() <= uint(x.exp) // not enough bits for fractional mantissa
}

// debugging support
func (x *Float) validate() {
	if !debugFloat {
		// avoid performance bugs
		panic("validate called but debugFloat is not set")
	}
	if msg := x.validate0(); msg != "" {
		panic(msg)
	}
}

func (x *Float) validate0() string {
	if x.form != finite {
		return ""
	}
	m := len(x.mant)
	if m == 0 {
		return "nonzero finite number with empty mantissa"
	}
	const msb = 1 << (_W - 1)
	if x.mant[m-1]&msb == 0 {
		return fmt.Sprintf("msb not set in last word %#x of %s", x.mant[m-1], x.Text('p', 0))
	}
	if x.prec == 0 {
		return "zero precision finite number"
	}
	return ""
}

// round rounds z according to z.mode to z.prec bits and sets z.acc accordingly.
// sbit must be 0 or 1 and summarizes any "sticky bit" information one might
// have before calling round. z's mantissa must be normalized (with the msb set)
// or empty.
//
// CAUTION: The rounding modes [ToNegativeInf], [ToPositiveInf] are affected by the
// sign of z. For correct rounding, the sign of z must be set correctly before
// calling round.
func (z *Float) round(sbit uint) {
	if debugFloat {
		z.validate()
	}

	z.acc = Exact
	if z.form != finite {
		// ±0 or ±Inf => nothing left to do
		return
	}
	// z.form == finite && len(z.mant) > 0
	// m > 0 implies z.prec > 0 (checked by validate)

	m := uint32(len(z.mant)) // present mantissa length in words
	bits := m * _W           // present mantissa bits; bits > 0
	if bits <= z.prec {
		// mantissa fits => nothing to do
		return
	}
	// bits > z.prec

	// Rounding is based on two bits: the rounding bit (rbit) and the
	// sticky bit (sbit). The rbit is the bit immediately before the
	// z.prec leading mantissa bits (the "0.5"). The sbit is set if any
	// of the bits before the rbit are set (the "0.25", "0.125", etc.):
	//
	//   rbit  sbit  => "fractional part"
	//
	//   0     0        == 0
	//   0     1        >  0  , < 0.5
	//   1     0        == 0.5
	//   1     1        >  0.5, < 1.0

	// bits > z.prec: mantissa too large => round
	r := uint(bits - z.prec - 1) // rounding bit position; r >= 0
	rbit := z.mant.bit(r) & 1    // rounding bit; be safe and ensure it's a single bit
	// The sticky bit is only needed for rounding ToNearestEven
	// or when the rounding bit is zero. Avoid computation otherwise.
	if sbit == 0 && (rbit == 0 || z.mode == ToNearestEven) {
		sbit = z.mant.sticky(r)
	}
	sbit &= 1 // be safe and ensure it's a single bit

	// cut off extra words
	n := (z.prec + (_W - 1)) / _W // mantissa length in words for desired precision
	if m > n {
		copy(z.mant, z.mant[m-n:]) // move n last words to front
		z.mant = z.mant[:n]
	}

	// determine number of trailing zero bits (ntz) and compute lsb mask of mantissa's least-significant word
	ntz := n*_W - z.prec // 0 <= ntz < _W
	lsb := Word(1) << ntz

	// round if result is inexact
	if rbit|sbit != 0 {
		// Make rounding decision: The result mantissa is truncated ("rounded down")
		// by default. Decide if we need to increment, or "round up", the (unsigned)
		// mantissa.
		inc := false
		switch z.mode {
		case ToNegativeInf:
			inc = z.neg
		case ToZero:
			// nothing to do
		case ToNearestEven:
			inc = rbit != 0 && (sbit != 0 || z.mant[0]&lsb != 0)
		case ToNearestAway:
			inc = rbit != 0
		case AwayFromZero:
			inc = true
		case ToPositiveInf:
			inc = !z.neg
		default:
			panic("unreachable")
		}

		// A positive result (!z.neg) is Above the exact result if we increment,
		// and it's Below if we truncate (Exact results require no rounding).
		// For a negative result (z.neg) it is exactly the opposite.
		z.acc = makeAcc(inc != z.neg)

		if inc {
			// add 1 to mantissa
			if addVW(z.mant, z.mant, lsb) != 0 {
				// mantissa overflow => adjust exponent
				if z.exp >= MaxExp {
					// exponent overflow
					z.form = inf
					return
				}
				z.exp++
				// adjust mantissa: divide by 2 to compensate for exponent adjustment
				shrVU(z.mant, z.mant, 1)
				// set msb == carry == 1 from the mantissa overflow above
				const msb = 1 << (_W - 1)
				z.mant[n-1] |= msb
			}
		}
	}

	// zero out trailing bits in least-significant word
	z.mant[0] &^= lsb - 1

	if debugFloat {
		z.validate()
	}
}

func (z *Float) setBits64(neg bool, x uint64) *Float {
	if z.prec == 0 {
		z.prec = 64
	}
	z.acc = Exact
	z.neg = neg
	if x == 0 {
		z.form = zero
		return z
	}
	// x != 0
	z.form = finite
	s := bits.LeadingZeros64(x)
	z.mant = z.mant.setUint64(x << uint(s))
	z.exp = int32(64 - s) // always fits
	if z.prec < 64 {
		z.round(0)
	}
	return z
}

// SetUint64 sets z to the (possibly rounded) value of x and returns z.
// If z's precision is 0, it is changed to 64 (and rounding will have
// no effect).
func (z *Float) SetUint64(x uint64) *Float {
	return z.setBits64(false, x)
}

// SetInt64 sets z to the (possibly rounded) value of x and returns z.
// If z's precision is 0, it is changed to 64 (and rounding will have
// no effect).
func (z *Float) SetInt64(x int64) *Float {
	u := x
	if u < 0 {
		u = -u
	}
	// We cannot simply call z.SetUint64(uint64(u)) and change
	// the sign afterwards because the sign affects rounding.
	return z.setBits64(x < 0, uint64(u))
}

// SetFloat64 sets z to the (possibly rounded) value of x and returns z.
// If z's precision is 0, it is changed to 53 (and rounding will have
// no effect). SetFloat64 panics with [ErrNaN] if x is a NaN.
func (z *Float) SetFloat64(x float64) *Float {
	if z.prec == 0 {
		z.prec = 53
	}
	if math.IsNaN(x) {
		panic(ErrNaN{"Float.SetFloat64(NaN)"})
	}
	z.acc = Exact
	z.neg = math.Signbit(x) // handle -0, -Inf correctly
	if x == 0 {
		z.form = zero
		return z
	}
	if math.IsInf(x, 0) {
		z.form = inf
		return z
	}
	// normalized x != 0
	z.form = finite
	fmant, exp := math.Frexp(x) // get normalized mantissa
	z.mant = z.mant.setUint64(1<<63 | math.Float64bits(fmant)<<11)
	z.exp = int32(exp) // always fits
	if z.prec < 53 {
		z.round(0)
	}
	return z
}

// fnorm normalizes mantissa m by shifting it to the left
// such that the msb of the most-significant word (msw) is 1.
// It returns the shift amount. It assumes that len(m) != 0.
func fnorm(m nat) int64 {
	if debugFloat && (len(m) == 0 || m[len(m)-1] == 0) {
		panic("msw of mantissa is 0")
	}
	s := nlz(m[len(m)-1])
	if s > 0 {
		c := shlVU(m, m, s)
		if debugFloat && c != 0 {
			panic("nlz or shlVU incorrect")
		}
	}
	return int64(s)
}

// SetInt sets z to the (possibly rounded) value of x and returns z.
// If z's precision is 0, it is changed to the larger of x.BitLen()
// or 64 (and rounding will have no effect).
func (z *Float) SetInt(x *Int) *Float {
	// TODO(gri) can be more efficient if z.prec > 0
	// but small compared to the size of x, or if there
	// are many trailing 0's.
	bits := uint32(x.BitLen())
	if z.prec == 0 {
		z.prec = umax32(bits, 64)
	}
	z.acc = Exact
	z.neg = x.neg
	if len(x.abs) == 0 {
		z.form = zero
		return z
	}
	// x != 0
	z.mant = z.mant.set(x.abs)
	fnorm(z.mant)
	z.setExpAndRound(int64(bits), 0)
	return z
}

// SetRat sets z to the (possibly rounded) value of x and returns z.
// If z's precision is 0, it is changed to the largest of a.BitLen(),
// b.BitLen(), or 64; with x = a/b.
func (z *Float) SetRat(x *Rat) *Float {
	if x.IsInt() {
		return z.SetInt(x.Num())
	}
	var a, b Float
	a.SetInt(x.Num())
	b.SetInt(x.Denom())
	if z.prec == 0 {
		z.prec = umax32(a.prec, b.prec)
	}
	return z.Quo(&a, &b)
}

// SetInf sets z to the infinite Float -Inf if signbit is
// set, or +Inf if signbit is not set, and returns z. The
// precision of z is unchanged and the result is always
// [Exact].
func (z *Float) SetInf(signbit bool) *Float {
	z.acc = Exact
	z.form = inf
	z.neg = signbit
	return z
}

// Set sets z to the (possibly rounded) value of x and returns z.
// If z's precision is 0, it is changed to the precision of x
// before setting z (and rounding will have no effect).
// Rounding is performed according to z's precision and rounding
// mode; and z's accuracy reports the result error relative to the
// exact (not rounded) result.
func (z *Float) Set(x *Float) *Float {
	if debugFloat {
		x.validate()
	}
	z.acc = Exact
	if z != x {
		z.form = x.form
		z.neg = x.neg
		if x.form == finite {
			z.exp = x.exp
			z.mant = z.mant.set(x.mant)
		}
		if z.prec == 0 {
			z.prec = x.prec
		} else if z.prec < x.prec {
			z.round(0)
		}
	}
	return z
}

// Copy sets z to x, with the same precision, rounding mode, and accuracy as x.
// Copy returns z. If x and z are identical, Copy is a no-op.
func (z *Float) Copy(x *Float) *Float {
	if debugFloat {
		x.validate()
	}
	if z != x {
		z.prec = x.prec
		z.mode = x.mode
		z.acc = x.acc
		z.form = x.form
		z.neg = x.neg
		if z.form == finite {
			z.mant = z.mant.set(x.mant)
			z.exp = x.exp
		}
	}
	return z
}

// msb32 returns the 32 most significant bits of x.
func msb32(x nat) uint32 {
	i := len(x) - 1
	if i < 0 {
		return 0
	}
	if debugFloat && x[i]&(1<<(_W-1)) == 0 {
		panic("x not normalized")
	}
	switch _W {
	case 32:
		return uint32(x[i])
	case 64:
		return uint32(x[i] >> 32)
	}
	panic("unreachable")
}

// msb64 returns the 64 most significant bits of x.
func msb64(x nat) uint64 {
	i := len(x) - 1
	if i < 0 {
		return 0
	}
	if debugFloat && x[i]&(1<<(_W-1)) == 0 {
		panic("x not normalized")
	}
	switch _W {
	case 32:
		v := uint64(x[i]) << 32
		if i > 0 {
			v |= uint64(x[i-1])
		}
		return v
	case 64:
		return uint64(x[i])
	}
	panic("unreachable")
}

// Uint64 returns the unsigned integer resulting from truncating x
// towards zero. If 0 <= x <= [math.MaxUint64], the result is [Exact]
// if x is an integer and [Below] otherwise.
// The result is (0, [Above]) for x < 0, and ([math.MaxUint64], [Below])
// for x > [math.MaxUint64].
func (x *Float) Uint64() (uint64, Accuracy) {
	if debugFloat {
		x.validate()
	}

	switch x.form {
	case finite:
		if x.neg {
			return 0, Above
		}
		// 0 < x < +Inf
		if x.exp <= 0 {
			// 0 < x < 1
			return 0, Below
		}
		// 1 <= x < Inf
		if x.exp <= 64 {
			// u = trunc(x) fits into a uint64
			u := msb64(x.mant) >> (64 - uint32(x.exp))
			if x.MinPrec() <= 64 {
				return u, Exact
			}
			return u, Below // x truncated
		}
		// x too large
		return math.MaxUint64, Below

	case zero:
		return 0, Exact

	case inf:
		if x.neg {
			return 0, Above
		}
		return math.MaxUint64, Below
	}

	panic("unreachable")
}

// Int64 returns the integer resulting from truncating x towards zero.
// If [math.MinInt64] <= x <= [math.MaxInt64], the result is [Exact] if x is
// an integer, and [Above] (x < 0) or [Below] (x > 0) otherwise.
// The result is ([math.MinInt64], [Above]) for x < [math.MinInt64],
// and ([math.MaxInt64], [Below]) for x > [math.MaxInt64].
func (x *Float) Int64() (int64, Accuracy) {
	if debugFloat {
		x.validate()
	}

	switch x.form {
	case finite:
		// 0 < |x| < +Inf
		acc := makeAcc(x.neg)
		if x.exp <= 0 {
			// 0 < |x| < 1
			return 0, acc
		}
		// x.exp > 0

		// 1 <= |x| < +Inf
		if x.exp <= 63 {
			// i = trunc(x) fits into an int64 (excluding math.MinInt64)
			i := int64(msb64(x.mant) >> (64 - uint32(x.exp)))
			if x.neg {
				i = -i
			}
			if x.MinPrec() <= uint(x.exp) {
				return i, Exact
			}
			return i, acc // x truncated
		}
		if x.neg {
			// check for special case x == math.MinInt64 (i.e., x == -(0.5 << 64))
			if x.exp == 64 && x.MinPrec() == 1 {
				acc = Exact
			}
			return math.MinInt64, acc
		}
		// x too large
		return math.MaxInt64, Below

	case zero:
		return 0, Exact

	case inf:
		if x.neg {
			return math.MinInt64, Above
		}
		return math.MaxInt64, Below
	}

	panic("unreachable")
}

// Float32 returns the float32 value nearest to x. If x is too small to be
// represented by a float32 (|x| < [math.SmallestNonzeroFloat32]), the result
// is (0, [Below]) or (-0, [Above]), respectively, depending on the sign of x.
// If x is too large to be represented by a float32 (|x| > [math.MaxFloat32]),
// the result is (+Inf, [Above]) or (-Inf, [Below]), depending on the sign of x.
func (x *Float) Float32() (float32, Accuracy) {
	if debugFloat {
		x.validate()
	}

	switch x.form {
	case finite:
		// 0 < |x| < +Inf

		const (
			fbits = 32                //        float size
			mbits = 23                //        mantissa size (excluding implicit msb)
			ebits = fbits - mbits - 1 //     8  exponent size
			bias  = 1<<(ebits-1) - 1  //   127  exponent bias
			dmin  = 1 - bias - mbits  //  -149  smallest unbiased exponent (denormal)
			emin  = 1 - bias          //  -126  smallest unbiased exponent (normal)
			emax  = bias              //   127  largest unbiased exponent (normal)
		)

		// Float mantissa m is 0.5 <= m < 1.0; compute exponent e for float32 mantissa.
		e := x.exp - 1 // exponent for normal mantissa m with 1.0 <= m < 2.0

		// Compute precision p for float32 mantissa.
		// If the exponent is too small, we have a denormal number before
		// rounding and fewer than p mantissa bits of precision available
		// (the exponent remains fixed but the mantissa gets shifted right).
		p := mbits + 1 // precision of normal float
		if e < emin {
			// recompute precision
			p = mbits + 1 - emin + int(e)
			// If p == 0, the mantissa of x is shifted so much to the right
			// that its msb falls immediately to the right of the float32
			// mantissa space. In other words, if the smallest denormal is
			// considered "1.0", for p == 0, the mantissa value m is >= 0.5.
			// If m > 0.5, it is rounded up to 1.0; i.e., the smallest denormal.
			// If m == 0.5, it is rounded down to even, i.e., 0.0.
			// If p < 0, the mantissa value m is <= "0.25" which is never rounded up.
			if p < 0 /* m <= 0.25 */ || p == 0 && x.mant.sticky(uint(len(x.mant))*_W-1) == 0 /* m == 0.5 */ {
				// underflow to ±0
				if x.neg {
					var z float32
					return -z, Above
				}
				return 0.0, Below
			}
			// otherwise, round up
			// We handle p == 0 explicitly because it's easy and because
			// Float.round doesn't support rounding to 0 bits of precision.
			if p == 0 {
				if x.neg {
					return -math.SmallestNonzeroFloat32, Below
				}
				return math.SmallestNonzeroFloat32, Above
			}
		}
		// p > 0

		// round
		var r Float
		r.prec = uint32(p)
		r.Set(x)
		e = r.exp - 1

		// Rounding may have caused r to overflow to ±Inf
		// (rounding never causes underflows to 0).
		// If the exponent is too large, also overflow to ±Inf.
		if r.form == inf || e > emax {
			// overflow
			if x.neg {
				return float32(math.Inf(-1)), Below
			}
			return float32(math.Inf(+1)), Above
		}
		// e <= emax

		// Determine sign, biased exponent, and mantissa.
		var sign, bexp, mant uint32
		if x.neg {
			sign = 1 << (fbits - 1)
		}

		// Rounding may have caused a denormal number to
		// become normal. Check again.
		if e < emin {
			// denormal number: recompute precision
			// Since rounding may have at best increased precision
			// and we have eliminated p <= 0 early, we know p > 0.
			// bexp == 0 for denormals
			p = mbits + 1 - emin + int(e)
			mant = msb32(r.mant) >> uint(fbits-p)
		} else {
			// normal number: emin <= e <= emax
			bexp = uint32(e+bias) << mbits
			mant = msb32(r.mant) >> ebits & (1<<mbits - 1) // cut off msb (implicit 1 bit)
		}

		return math.Float32frombits(sign | bexp | mant), r.acc

	case zero:
		if x.neg {
			var z float32
			return -z, Exact
		}
		return 0.0, Exact

	case inf:
		if x.neg {
			return float32(math.Inf(-1)), Exact
		}
		return float32(math.Inf(+1)), Exact
	}

	panic("unreachable")
}

// Float64 returns the float64 value nearest to x. If x is too small to be
// represented by a float64 (|x| < [math.SmallestNonzeroFloat64]), the result
// is (0, [Below]) or (-0, [Above]), respectively, depending on the sign of x.
// If x is too large to be represented by a float64 (|x| > [math.MaxFloat64]),
// the result is (+Inf, [Above]) or (-Inf, [Below]), depending on the sign of x.
func (x *Float) Float64() (float64, Accuracy) {
	if debugFloat {
		x.validate()
	}

	switch x.form {
	case finite:
		// 0 < |x| < +Inf

		const (
			fbits = 64                //        float size
			mbits = 52                //        mantissa size (excluding implicit msb)
			ebits = fbits - mbits - 1 //    11  exponent size
			bias  = 1<<(ebits-1) - 1  //  1023  exponent bias
			dmin  = 1 - bias - mbits  // -1074  smallest unbiased exponent (denormal)
			emin  = 1 - bias          // -1022  smallest unbiased exponent (normal)
			emax  = bias              //  1023  largest unbiased exponent (normal)
		)

		// Float mantissa m is 0.5 <= m < 1.0; compute exponent e for float64 mantissa.
		e := x.exp - 1 // exponent for normal mantissa m with 1.0 <= m < 2.0

		// Compute precision p for float64 mantissa.
		// If the exponent is too small, we have a denormal number before
		// rounding and fewer than p mantissa bits of precision available
		// (the exponent remains fixed but the mantissa gets shifted right).
		p := mbits + 1 // precision of normal float
		if e < emin {
			// recompute precision
			p = mbits + 1 - emin + int(e)
			// If p == 0, the mantissa of x is shifted so much to the right
			// that its msb falls immediately to the right of the float64
			// mantissa space. In other words, if the smallest denormal is
			// considered "1.0", for p == 0, the mantissa value m is >= 0.5.
			// If m > 0.5, it is rounded up to 1.0; i.e., the smallest denormal.
			// If m == 0.5, it is rounded down to even, i.e., 0.0.
			// If p < 0, the mantissa value m is <= "0.25" which is never rounded up.
			if p < 0 /* m <= 0.25 */ || p == 0 && x.mant.sticky(uint(len(x.mant))*_W-1) == 0 /* m == 0.5 */ {
				// underflow to ±0
				if x.neg {
					var z float64
					return -z, Above
				}
				return 0.0, Below
			}
			// otherwise, round up
			// We handle p == 0 explicitly because it's easy and because
			// Float.round doesn't support rounding to 0 bits of precision.
			if p == 0 {
				if x.neg {
					return -math.SmallestNonzeroFloat64, Below
				}
				return math.SmallestNonzeroFloat64, Above
			}
		}
		// p > 0

		// round
		var r Float
		r.prec = uint32(p)
		r.Set(x)
		e = r.exp - 1

		// Rounding may have caused r to overflow to ±Inf
		// (rounding never causes underflows to 0).
		// If the exponent is too large, also overflow to ±Inf.
		if r.form == inf || e > emax {
			// overflow
			if x.neg {
				return math.Inf(-1), Below
			}
			return math.Inf(+1), Above
		}
		// e <= emax

		// Determine sign, biased exponent, and mantissa.
		var sign, bexp, mant uint64
		if x.neg {
			sign = 1 << (fbits - 1)
		}

		// Rounding may have caused a denormal number to
		// become normal. Check again.
		if e < emin {
			// denormal number: recompute precision
			// Since rounding may have at best increased precision
			// and we have eliminated p <= 0 early, we know p > 0.
			// bexp == 0 for denormals
			p = mbits + 1 - emin + int(e)
			mant = msb64(r.mant) >> uint(fbits-p)
		} else {
			// normal number: emin <= e <= emax
			bexp = uint64(e+bias) << mbits
			mant = msb64(r.mant) >> ebits & (1<<mbits - 1) // cut off msb (implicit 1 bit)
		}

		return math.Float64frombits(sign | bexp | mant), r.acc

	case zero:
		if x.neg {
			var z float64
			return -z, Exact
		}
		return 0.0, Exact

	case inf:
		if x.neg {
			return math.Inf(-1), Exact
		}
		return math.Inf(+1), Exact
	}

	panic("unreachable")
}

// Int returns the result of truncating x towards zero;
// or nil if x is an infinity.
// The result is [Exact] if x.IsInt(); otherwise it is [Below]
// for x > 0, and [Above] for x < 0.
// If a non-nil *[Int] argument z is provided, [Int] stores
// the result in z instead of allocating a new [Int].
func (x *Float) Int(z *Int) (*Int, Accuracy) {
	if debugFloat {
		x.validate()
	}

	if z == nil && x.form <= finite {
		z = new(Int)
	}

	switch x.form {
	case finite:
		// 0 < |x| < +Inf
		acc := makeAcc(x.neg)
		if x.exp <= 0 {
			// 0 < |x| < 1
			return z.SetInt64(0), acc
		}
		// x.exp > 0

		// 1 <= |x| < +Inf
		// determine minimum required precision for x
		allBits := uint(len(x.mant)) * _W
		exp := uint(x.exp)
		if x.MinPrec() <= exp {
			acc = Exact
		}
		// shift mantissa as needed
		if z == nil {
			z = new(Int)
		}
		z.neg = x.neg
		switch {
		case exp > allBits:
			z.abs = z.abs.shl(x.mant, exp-allBits)
		default:
			z.abs = z.abs.set(x.mant)
		case exp < allBits:
			z.abs = z.abs.shr(x.mant, allBits-exp)
		}
		return z, acc

	case zero:
		return z.SetInt64(0), Exact

	case inf:
		return nil, makeAcc(x.neg)
	}

	panic("unreachable")
}

// Rat returns the rational number corresponding to x;
// or nil if x is an infinity.
// The result is [Exact] if x is not an Inf.
// If a non-nil *[Rat] argument z is provided, [Rat] stores
// the result in z instead of allocating a new [Rat].
func (x *Float) Rat(z *Rat) (*Rat, Accuracy) {
	if debugFloat {
		x.validate()
	}

	if z == nil && x.form <= finite {
		z = new(Rat)
	}

	switch x.form {
	case finite:
		// 0 < |x| < +Inf
		allBits := int32(len(x.mant)) * _W
		// build up numerator and denominator
		z.a.neg = x.neg
		switch {
		case x.exp > allBits:
			z.a.abs = z.a.abs.shl(x.mant, uint(x.exp-allBits))
			z.b.abs = z.b.abs[:0] // == 1 (see Rat)
			// z already in normal form
		default:
			z.a.abs = z.a.abs.set(x.mant)
			z.b.abs = z.b.abs[:0] // == 1 (see Rat)
			// z already in normal form
		case x.exp < allBits:
			z.a.abs = z.a.abs.set(x.mant)
			t := z.b.abs.setUint64(1)
			z.b.abs = t.shl(t, uint(allBits-x.exp))
			z.norm()
		}
		return z, Exact

	case zero:
		return z.SetInt64(0), Exact

	case inf:
		return nil, makeAcc(x.neg)
	}

	panic("unreachable")
}

// Abs sets z to the (possibly rounded) value |x| (the absolute value of x)
// and returns z.
func (z *Float) Abs(x *Float) *Float {
	z.Set(x)
	z.neg = false
	return z
}

// Neg sets z to the (possibly rounded) value of x with its sign negated,
// and returns z.
func (z *Float) Neg(x *Float) *Float {
	z.Set(x)
	z.neg = !z.neg
	return z
}

func validateBinaryOperands(x, y *Float) {
	if !debugFloat {
		// avoid performance bugs
		panic("validateBinaryOperands called but debugFloat is not set")
	}
	if len(x.mant) == 0 {
		panic("empty mantissa for x")
	}
	if len(y.mant) == 0 {
		panic("empty mantissa for y")
	}
}

// z = x + y, ignoring signs of x and y for the addition
// b
"""




```