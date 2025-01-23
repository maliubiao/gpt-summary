Response:
我的思考过程如下：

1. **理解目标：** 目标是分析给定的 Go 语言 `value.go` 文件的部分代码，并总结其功能，最好能推断其实现的 Go 语言特性，并提供代码示例、参数处理、常见错误等。 这是第一部分，需要进行功能归纳。

2. **代码结构概览：**  快速浏览代码，关注 `package constant` 声明，以及导入的包。 核心部分是 `Kind` 类型定义和 `Value` 接口。 往下是各种类型的实现，如 `unknownVal`, `boolVal`, `stringVal`, `int64Val`, `intVal`, `ratVal`, `floatVal`, `complexVal`。  以及与这些类型相关的各种方法。

3. **核心概念识别：**
    * **常量表示：** 显然，这个包的核心目的是表示 Go 语言中的常量。
    * **不同的常量类型：**  `Kind` 枚举定义了常量可以有的类型：`Unknown`, `Bool`, `String`, `Int`, `Float`, `Complex`。
    * **`Value` 接口：**  这是一个关键接口，所有具体的常量类型都实现了它。 它定义了获取类型、字符串表示（短的和精确的）的方法。
    * **内部表示优化：**  对于 `Int` 和 `Float`，存在多种内部表示（例如 `int64Val` 和 `intVal`，`ratVal` 和 `floatVal`），这暗示了对性能和精度的一种权衡。 小的值或能精确表示的值使用更紧凑或精确的表示。
    * **`stringVal` 的特殊处理：** `stringVal` 使用了延迟求值和互斥锁来优化字符串连接操作，这是一个值得注意的点。
    * **工厂函数：**  存在 `Make...`  系列的函数（如 `MakeInt64`, `MakeString` 等），用于创建特定类型的 `Value`。
    * **访问器函数：**  存在 `...Val` 系列的函数（如 `BoolVal`, `StringVal`），用于获取 `Value` 的 Go 语言原生类型值。
    * **类型转换函数：**  `ToInt`, `ToFloat`, `ToComplex` 用于常量之间的类型转换。
    * **运算符函数：** `UnaryOp`, `BinaryOp`, `Shift` 用于执行常量的运算。

4. **功能归纳（第一部分）：**  基于以上分析，可以总结出以下功能：
    * **定义了表示 Go 语言常量的 `Value` 接口和 `Kind` 类型。**
    * **提供了表示不同类型常量的具体实现：未知、布尔、字符串、整数、浮点数和复数。**
    * **针对整数和浮点数，使用了多种内部表示以优化存储和精度。**
    * **实现了获取常量类型、短字符串表示和精确字符串表示的方法。**
    * **提供了用于创建不同类型常量的工厂函数。**
    * **提供了用于从 `Value` 获取 Go 原生类型值的访问器函数。**

5. **推断 Go 语言特性（初步思考）：**  基于代码，可以推断这个包是用于支持 Go 语言中常量相关的操作，例如：
    * **常量声明和初始化：** 编译器或解释器可以使用这个包来表示和处理代码中声明的常量。
    * **常量表达式求值：** 在编译时或解释执行时，可能需要对常量表达式进行求值，这个包提供了相关的运算功能。
    * **类型推断：** 常量的值和类型可能需要参与类型推断过程。

6. **代码示例（初步想法）：**  思考如何用代码演示这个包的用法。  可以创建不同类型的常量，并进行一些基本操作。

7. **易错点（初步考虑）：**  访问器函数 `...Val` 在参数类型不匹配时会 `panic`，这是一个潜在的易错点。

8. **命令行参数（排除）：**  代码中没有看到与命令行参数处理相关的逻辑。

9. **整理和润色：**  将以上分析和想法组织成清晰的中文描述。  强调第一部分的要求是功能归纳。

在实际操作中，我可能会多次审视代码，尤其是一些细节，比如 `stringVal` 的实现方式，以及 `match` 函数的作用，来更深入地理解其设计意图。  我也会思考 `prec` 常量的意义，以及 TODO 注释暗示的未来改进方向。  这个过程是迭代的，从宏观到微观，再回到宏观，不断完善理解。
这个Go语言源文件 `go/src/go/constant/value.go` 的一部分主要功能是：

**定义和实现了表示 Go 语言常量的 `Value` 接口及其各种具体类型。**

具体来说，它做了以下几件事情：

1. **定义了常量的种类 (`Kind`)：**  通过枚举 `Kind` 定义了 Go 语言常量可以拥有的类型，包括 `Unknown` (未知), `Bool` (布尔值), `String` (字符串), `Int` (整数), `Float` (浮点数), 和 `Complex` (复数)。

2. **定义了 `Value` 接口：**  `Value` 接口是所有常量类型的抽象，它定义了获取常量类型 (`Kind()`)、获取常量字符串表示 (`String()` 和 `ExactString()`) 的方法。 `String()` 返回一个简短的带引号的表示，而 `ExactString()` 返回精确的带引号的表示。

3. **实现了不同类型的常量：**  为每种 `Kind` 都提供了具体的结构体实现：
    * `unknownVal`: 表示未知常量。
    * `boolVal`: 表示布尔常量。
    * `stringVal`: 表示字符串常量，特别地，它使用了一种延迟求值的方式来处理字符串连接，避免在大型连接中构建中间字符串。
    * `int64Val`:  表示可以用 `int64` 类型表示的整数常量，这是一种优化。
    * `intVal`: 表示不能用 `int64` 表示的任意大小的整数常量，使用 `big.Int`。
    * `ratVal`: 表示可以用分数精确表示的浮点数常量，使用 `big.Rat`。
    * `floatVal`: 表示不能用分数精确表示的浮点数常量，使用 `big.Float`。
    * `complexVal`: 表示复数常量，由实部和虚部两个 `Value` 组成。

4. **提供了创建常量值的工厂函数：**  例如 `MakeUnknown()`, `MakeBool()`, `MakeString()`, `MakeInt64()`, `MakeUint64()`, `MakeFloat64()`, `MakeFromLiteral()` 等函数，用于创建不同类型的 `Value` 实例。 `MakeFromLiteral()` 允许从字符串字面量创建常量。

5. **提供了访问常量值的方法：**  例如 `BoolVal()`, `StringVal()`, `Int64Val()`, `Uint64Val()`, `Float64Val()`, `Val()` 等函数，用于获取 `Value` 对象所代表的 Go 语言原生类型的值。

6. **实现了常量的字符串表示：**  每个具体的常量类型都实现了 `String()` 和 `ExactString()` 方法，用于生成常量的字符串表示。  `stringVal` 的 `String()` 方法还考虑了截断过长的字符串。

7. **实现了数值常量的基本属性获取：** 提供了 `BitLen()` 获取整数的位长， `Sign()` 获取数值的符号。

8. **提供了数值常量的底层字节表示和重建：** `Bytes()` 用于获取整数的字节表示， `MakeFromBytes()` 用于从字节表示重建整数。

9. **提供了获取浮点数的分子和分母的方法：** `Num()` 和 `Denom()` 用于获取浮点数（如果可以表示为分数）的分子和分母。

10. **提供了创建纯虚数的方法：** `MakeImag()` 用于创建一个虚部为给定值，实部为 0 的复数。

11. **提供了获取复数的实部和虚部的方法：** `Real()` 和 `Imag()` 用于获取复数的实部和虚部。

12. **提供了常量类型转换的方法：** `ToInt()`, `ToFloat()`, `ToComplex()` 用于尝试将一个 `Value` 转换为另一种类型的 `Value`。

13. **实现了常量的基本运算：**  `UnaryOp()` 用于执行一元运算， `BinaryOp()` 用于执行二元运算， `Shift()` 用于执行位移运算。 `match()` 函数用于在执行二元运算前，将两个不同类型的数值常量转换为兼容的类型。

**总而言之，这段代码是 `go/constant` 包的核心，负责定义和实现 Go 语言中各种常量值的内部表示和基本操作。 它是 Go 语言编译器或其他需要处理 Go 常量的工具的基础。**

由于这是第一部分，我们主要关注了 `value.go` 中常量值的定义和基本操作。  后面的部分很可能涉及更复杂的常量运算和比较等功能。

### 提示词
```
这是路径为go/src/go/constant/value.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package constant implements Values representing untyped
// Go constants and their corresponding operations.
//
// A special Unknown value may be used when a value
// is unknown due to an error. Operations on unknown
// values produce unknown values unless specified
// otherwise.
package constant

import (
	"fmt"
	"go/token"
	"math"
	"math/big"
	"math/bits"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

//go:generate stringer -type Kind

// Kind specifies the kind of value represented by a [Value].
type Kind int

const (
	// unknown values
	Unknown Kind = iota

	// non-numeric values
	Bool
	String

	// numeric values
	Int
	Float
	Complex
)

// A Value represents the value of a Go constant.
type Value interface {
	// Kind returns the value kind.
	Kind() Kind

	// String returns a short, quoted (human-readable) form of the value.
	// For numeric values, the result may be an approximation;
	// for String values the result may be a shortened string.
	// Use ExactString for a string representing a value exactly.
	String() string

	// ExactString returns an exact, quoted (human-readable) form of the value.
	// If the Value is of Kind String, use StringVal to obtain the unquoted string.
	ExactString() string

	// Prevent external implementations.
	implementsValue()
}

// ----------------------------------------------------------------------------
// Implementations

// Maximum supported mantissa precision.
// The spec requires at least 256 bits; typical implementations use 512 bits.
const prec = 512

// TODO(gri) Consider storing "error" information in an unknownVal so clients
// can provide better error messages. For instance, if a number is
// too large (incl. infinity), that could be recorded in unknownVal.
// See also #20583 and #42695 for use cases.

// Representation of values:
//
// Values of Int and Float Kind have two different representations each: int64Val
// and intVal, and ratVal and floatVal. When possible, the "smaller", respectively
// more precise (for Floats) representation is chosen. However, once a Float value
// is represented as a floatVal, any subsequent results remain floatVals (unless
// explicitly converted); i.e., no attempt is made to convert a floatVal back into
// a ratVal. The reasoning is that all representations but floatVal are mathematically
// exact, but once that precision is lost (by moving to floatVal), moving back to
// a different representation implies a precision that's not actually there.

type (
	unknownVal struct{}
	boolVal    bool
	stringVal  struct {
		// Lazy value: either a string (l,r==nil) or an addition (l,r!=nil).
		mu   sync.Mutex
		s    string
		l, r *stringVal
	}
	int64Val   int64                    // Int values representable as an int64
	intVal     struct{ val *big.Int }   // Int values not representable as an int64
	ratVal     struct{ val *big.Rat }   // Float values representable as a fraction
	floatVal   struct{ val *big.Float } // Float values not representable as a fraction
	complexVal struct{ re, im Value }
)

func (unknownVal) Kind() Kind { return Unknown }
func (boolVal) Kind() Kind    { return Bool }
func (*stringVal) Kind() Kind { return String }
func (int64Val) Kind() Kind   { return Int }
func (intVal) Kind() Kind     { return Int }
func (ratVal) Kind() Kind     { return Float }
func (floatVal) Kind() Kind   { return Float }
func (complexVal) Kind() Kind { return Complex }

func (unknownVal) String() string { return "unknown" }
func (x boolVal) String() string  { return strconv.FormatBool(bool(x)) }

// String returns a possibly shortened quoted form of the String value.
func (x *stringVal) String() string {
	const maxLen = 72 // a reasonable length
	s := strconv.Quote(x.string())
	if utf8.RuneCountInString(s) > maxLen {
		// The string without the enclosing quotes is greater than maxLen-2 runes
		// long. Remove the last 3 runes (including the closing '"') by keeping
		// only the first maxLen-3 runes; then add "...".
		i := 0
		for n := 0; n < maxLen-3; n++ {
			_, size := utf8.DecodeRuneInString(s[i:])
			i += size
		}
		s = s[:i] + "..."
	}
	return s
}

// string constructs and returns the actual string literal value.
// If x represents an addition, then it rewrites x to be a single
// string, to speed future calls. This lazy construction avoids
// building different string values for all subpieces of a large
// concatenation. See golang.org/issue/23348.
func (x *stringVal) string() string {
	x.mu.Lock()
	if x.l != nil {
		x.s = strings.Join(reverse(x.appendReverse(nil)), "")
		x.l = nil
		x.r = nil
	}
	s := x.s
	x.mu.Unlock()

	return s
}

// reverse reverses x in place and returns it.
func reverse(x []string) []string {
	n := len(x)
	for i := 0; i+i < n; i++ {
		x[i], x[n-1-i] = x[n-1-i], x[i]
	}
	return x
}

// appendReverse appends to list all of x's subpieces, but in reverse,
// and returns the result. Appending the reversal allows processing
// the right side in a recursive call and the left side in a loop.
// Because a chain like a + b + c + d + e is actually represented
// as ((((a + b) + c) + d) + e), the left-side loop avoids deep recursion.
// x must be locked.
func (x *stringVal) appendReverse(list []string) []string {
	y := x
	for y.r != nil {
		y.r.mu.Lock()
		list = y.r.appendReverse(list)
		y.r.mu.Unlock()

		l := y.l
		if y != x {
			y.mu.Unlock()
		}
		l.mu.Lock()
		y = l
	}
	s := y.s
	if y != x {
		y.mu.Unlock()
	}
	return append(list, s)
}

func (x int64Val) String() string { return strconv.FormatInt(int64(x), 10) }
func (x intVal) String() string   { return x.val.String() }
func (x ratVal) String() string   { return rtof(x).String() }

// String returns a decimal approximation of the Float value.
func (x floatVal) String() string {
	f := x.val

	// Don't try to convert infinities (will not terminate).
	if f.IsInf() {
		return f.String()
	}

	// Use exact fmt formatting if in float64 range (common case):
	// proceed if f doesn't underflow to 0 or overflow to inf.
	if x, _ := f.Float64(); f.Sign() == 0 == (x == 0) && !math.IsInf(x, 0) {
		s := fmt.Sprintf("%.6g", x)
		if !f.IsInt() && strings.IndexByte(s, '.') < 0 {
			// f is not an integer, but its string representation
			// doesn't reflect that. Use more digits. See issue 56220.
			s = fmt.Sprintf("%g", x)
		}
		return s
	}

	// Out of float64 range. Do approximate manual to decimal
	// conversion to avoid precise but possibly slow Float
	// formatting.
	// f = mant * 2**exp
	var mant big.Float
	exp := f.MantExp(&mant) // 0.5 <= |mant| < 1.0

	// approximate float64 mantissa m and decimal exponent d
	// f ~ m * 10**d
	m, _ := mant.Float64()                     // 0.5 <= |m| < 1.0
	d := float64(exp) * (math.Ln2 / math.Ln10) // log_10(2)

	// adjust m for truncated (integer) decimal exponent e
	e := int64(d)
	m *= math.Pow(10, d-float64(e))

	// ensure 1 <= |m| < 10
	switch am := math.Abs(m); {
	case am < 1-0.5e-6:
		// The %.6g format below rounds m to 5 digits after the
		// decimal point. Make sure that m*10 < 10 even after
		// rounding up: m*10 + 0.5e-5 < 10 => m < 1 - 0.5e6.
		m *= 10
		e--
	case am >= 10:
		m /= 10
		e++
	}

	return fmt.Sprintf("%.6ge%+d", m, e)
}

func (x complexVal) String() string { return fmt.Sprintf("(%s + %si)", x.re, x.im) }

func (x unknownVal) ExactString() string { return x.String() }
func (x boolVal) ExactString() string    { return x.String() }
func (x *stringVal) ExactString() string { return strconv.Quote(x.string()) }
func (x int64Val) ExactString() string   { return x.String() }
func (x intVal) ExactString() string     { return x.String() }

func (x ratVal) ExactString() string {
	r := x.val
	if r.IsInt() {
		return r.Num().String()
	}
	return r.String()
}

func (x floatVal) ExactString() string { return x.val.Text('p', 0) }

func (x complexVal) ExactString() string {
	return fmt.Sprintf("(%s + %si)", x.re.ExactString(), x.im.ExactString())
}

func (unknownVal) implementsValue() {}
func (boolVal) implementsValue()    {}
func (*stringVal) implementsValue() {}
func (int64Val) implementsValue()   {}
func (ratVal) implementsValue()     {}
func (intVal) implementsValue()     {}
func (floatVal) implementsValue()   {}
func (complexVal) implementsValue() {}

func newInt() *big.Int     { return new(big.Int) }
func newRat() *big.Rat     { return new(big.Rat) }
func newFloat() *big.Float { return new(big.Float).SetPrec(prec) }

func i64toi(x int64Val) intVal   { return intVal{newInt().SetInt64(int64(x))} }
func i64tor(x int64Val) ratVal   { return ratVal{newRat().SetInt64(int64(x))} }
func i64tof(x int64Val) floatVal { return floatVal{newFloat().SetInt64(int64(x))} }
func itor(x intVal) ratVal       { return ratVal{newRat().SetInt(x.val)} }
func itof(x intVal) floatVal     { return floatVal{newFloat().SetInt(x.val)} }
func rtof(x ratVal) floatVal     { return floatVal{newFloat().SetRat(x.val)} }
func vtoc(x Value) complexVal    { return complexVal{x, int64Val(0)} }

func makeInt(x *big.Int) Value {
	if x.IsInt64() {
		return int64Val(x.Int64())
	}
	return intVal{x}
}

func makeRat(x *big.Rat) Value {
	a := x.Num()
	b := x.Denom()
	if smallInt(a) && smallInt(b) {
		// ok to remain fraction
		return ratVal{x}
	}
	// components too large => switch to float
	return floatVal{newFloat().SetRat(x)}
}

var floatVal0 = floatVal{newFloat()}

func makeFloat(x *big.Float) Value {
	// convert -0
	if x.Sign() == 0 {
		return floatVal0
	}
	if x.IsInf() {
		return unknownVal{}
	}
	// No attempt is made to "go back" to ratVal, even if possible,
	// to avoid providing the illusion of a mathematically exact
	// representation.
	return floatVal{x}
}

func makeComplex(re, im Value) Value {
	if re.Kind() == Unknown || im.Kind() == Unknown {
		return unknownVal{}
	}
	return complexVal{re, im}
}

func makeFloatFromLiteral(lit string) Value {
	if f, ok := newFloat().SetString(lit); ok {
		if smallFloat(f) {
			// ok to use rationals
			if f.Sign() == 0 {
				// Issue 20228: If the float underflowed to zero, parse just "0".
				// Otherwise, lit might contain a value with a large negative exponent,
				// such as -6e-1886451601. As a float, that will underflow to 0,
				// but it'll take forever to parse as a Rat.
				lit = "0"
			}
			if r, ok := newRat().SetString(lit); ok {
				return ratVal{r}
			}
		}
		// otherwise use floats
		return makeFloat(f)
	}
	return nil
}

// Permit fractions with component sizes up to maxExp
// before switching to using floating-point numbers.
const maxExp = 4 << 10

// smallInt reports whether x would lead to "reasonably"-sized fraction
// if converted to a *big.Rat.
func smallInt(x *big.Int) bool {
	return x.BitLen() < maxExp
}

// smallFloat64 reports whether x would lead to "reasonably"-sized fraction
// if converted to a *big.Rat.
func smallFloat64(x float64) bool {
	if math.IsInf(x, 0) {
		return false
	}
	_, e := math.Frexp(x)
	return -maxExp < e && e < maxExp
}

// smallFloat reports whether x would lead to "reasonably"-sized fraction
// if converted to a *big.Rat.
func smallFloat(x *big.Float) bool {
	if x.IsInf() {
		return false
	}
	e := x.MantExp(nil)
	return -maxExp < e && e < maxExp
}

// ----------------------------------------------------------------------------
// Factories

// MakeUnknown returns the [Unknown] value.
func MakeUnknown() Value { return unknownVal{} }

// MakeBool returns the [Bool] value for b.
func MakeBool(b bool) Value { return boolVal(b) }

// MakeString returns the [String] value for s.
func MakeString(s string) Value {
	if s == "" {
		return &emptyString // common case
	}
	return &stringVal{s: s}
}

var emptyString stringVal

// MakeInt64 returns the [Int] value for x.
func MakeInt64(x int64) Value { return int64Val(x) }

// MakeUint64 returns the [Int] value for x.
func MakeUint64(x uint64) Value {
	if x < 1<<63 {
		return int64Val(int64(x))
	}
	return intVal{newInt().SetUint64(x)}
}

// MakeFloat64 returns the [Float] value for x.
// If x is -0.0, the result is 0.0.
// If x is not finite, the result is an [Unknown].
func MakeFloat64(x float64) Value {
	if math.IsInf(x, 0) || math.IsNaN(x) {
		return unknownVal{}
	}
	if smallFloat64(x) {
		return ratVal{newRat().SetFloat64(x + 0)} // convert -0 to 0
	}
	return floatVal{newFloat().SetFloat64(x + 0)}
}

// MakeFromLiteral returns the corresponding integer, floating-point,
// imaginary, character, or string value for a Go literal string. The
// tok value must be one of [token.INT], [token.FLOAT], [token.IMAG],
// [token.CHAR], or [token.STRING]. The final argument must be zero.
// If the literal string syntax is invalid, the result is an [Unknown].
func MakeFromLiteral(lit string, tok token.Token, zero uint) Value {
	if zero != 0 {
		panic("MakeFromLiteral called with non-zero last argument")
	}

	switch tok {
	case token.INT:
		if x, err := strconv.ParseInt(lit, 0, 64); err == nil {
			return int64Val(x)
		}
		if x, ok := newInt().SetString(lit, 0); ok {
			return intVal{x}
		}

	case token.FLOAT:
		if x := makeFloatFromLiteral(lit); x != nil {
			return x
		}

	case token.IMAG:
		if n := len(lit); n > 0 && lit[n-1] == 'i' {
			if im := makeFloatFromLiteral(lit[:n-1]); im != nil {
				return makeComplex(int64Val(0), im)
			}
		}

	case token.CHAR:
		if n := len(lit); n >= 2 {
			if code, _, _, err := strconv.UnquoteChar(lit[1:n-1], '\''); err == nil {
				return MakeInt64(int64(code))
			}
		}

	case token.STRING:
		if s, err := strconv.Unquote(lit); err == nil {
			return MakeString(s)
		}

	default:
		panic(fmt.Sprintf("%v is not a valid token", tok))
	}

	return unknownVal{}
}

// ----------------------------------------------------------------------------
// Accessors
//
// For unknown arguments the result is the zero value for the respective
// accessor type, except for Sign, where the result is 1.

// BoolVal returns the Go boolean value of x, which must be a [Bool] or an [Unknown].
// If x is [Unknown], the result is false.
func BoolVal(x Value) bool {
	switch x := x.(type) {
	case boolVal:
		return bool(x)
	case unknownVal:
		return false
	default:
		panic(fmt.Sprintf("%v not a Bool", x))
	}
}

// StringVal returns the Go string value of x, which must be a [String] or an [Unknown].
// If x is [Unknown], the result is "".
func StringVal(x Value) string {
	switch x := x.(type) {
	case *stringVal:
		return x.string()
	case unknownVal:
		return ""
	default:
		panic(fmt.Sprintf("%v not a String", x))
	}
}

// Int64Val returns the Go int64 value of x and whether the result is exact;
// x must be an [Int] or an [Unknown]. If the result is not exact, its value is undefined.
// If x is [Unknown], the result is (0, false).
func Int64Val(x Value) (int64, bool) {
	switch x := x.(type) {
	case int64Val:
		return int64(x), true
	case intVal:
		return x.val.Int64(), false // not an int64Val and thus not exact
	case unknownVal:
		return 0, false
	default:
		panic(fmt.Sprintf("%v not an Int", x))
	}
}

// Uint64Val returns the Go uint64 value of x and whether the result is exact;
// x must be an [Int] or an [Unknown]. If the result is not exact, its value is undefined.
// If x is [Unknown], the result is (0, false).
func Uint64Val(x Value) (uint64, bool) {
	switch x := x.(type) {
	case int64Val:
		return uint64(x), x >= 0
	case intVal:
		return x.val.Uint64(), x.val.IsUint64()
	case unknownVal:
		return 0, false
	default:
		panic(fmt.Sprintf("%v not an Int", x))
	}
}

// Float32Val is like [Float64Val] but for float32 instead of float64.
func Float32Val(x Value) (float32, bool) {
	switch x := x.(type) {
	case int64Val:
		f := float32(x)
		return f, int64Val(f) == x
	case intVal:
		f, acc := newFloat().SetInt(x.val).Float32()
		return f, acc == big.Exact
	case ratVal:
		return x.val.Float32()
	case floatVal:
		f, acc := x.val.Float32()
		return f, acc == big.Exact
	case unknownVal:
		return 0, false
	default:
		panic(fmt.Sprintf("%v not a Float", x))
	}
}

// Float64Val returns the nearest Go float64 value of x and whether the result is exact;
// x must be numeric or an [Unknown], but not [Complex]. For values too small (too close to 0)
// to represent as float64, [Float64Val] silently underflows to 0. The result sign always
// matches the sign of x, even for 0.
// If x is [Unknown], the result is (0, false).
func Float64Val(x Value) (float64, bool) {
	switch x := x.(type) {
	case int64Val:
		f := float64(int64(x))
		return f, int64Val(f) == x
	case intVal:
		f, acc := newFloat().SetInt(x.val).Float64()
		return f, acc == big.Exact
	case ratVal:
		return x.val.Float64()
	case floatVal:
		f, acc := x.val.Float64()
		return f, acc == big.Exact
	case unknownVal:
		return 0, false
	default:
		panic(fmt.Sprintf("%v not a Float", x))
	}
}

// Val returns the underlying value for a given constant. Since it returns an
// interface, it is up to the caller to type assert the result to the expected
// type. The possible dynamic return types are:
//
//	x Kind             type of result
//	-----------------------------------------
//	Bool               bool
//	String             string
//	Int                int64 or *big.Int
//	Float              *big.Float or *big.Rat
//	everything else    nil
func Val(x Value) any {
	switch x := x.(type) {
	case boolVal:
		return bool(x)
	case *stringVal:
		return x.string()
	case int64Val:
		return int64(x)
	case intVal:
		return x.val
	case ratVal:
		return x.val
	case floatVal:
		return x.val
	default:
		return nil
	}
}

// Make returns the [Value] for x.
//
//	type of x        result Kind
//	----------------------------
//	bool             Bool
//	string           String
//	int64            Int
//	*big.Int         Int
//	*big.Float       Float
//	*big.Rat         Float
//	anything else    Unknown
func Make(x any) Value {
	switch x := x.(type) {
	case bool:
		return boolVal(x)
	case string:
		return &stringVal{s: x}
	case int64:
		return int64Val(x)
	case *big.Int:
		return makeInt(x)
	case *big.Rat:
		return makeRat(x)
	case *big.Float:
		return makeFloat(x)
	default:
		return unknownVal{}
	}
}

// BitLen returns the number of bits required to represent
// the absolute value x in binary representation; x must be an [Int] or an [Unknown].
// If x is [Unknown], the result is 0.
func BitLen(x Value) int {
	switch x := x.(type) {
	case int64Val:
		u := uint64(x)
		if x < 0 {
			u = uint64(-x)
		}
		return 64 - bits.LeadingZeros64(u)
	case intVal:
		return x.val.BitLen()
	case unknownVal:
		return 0
	default:
		panic(fmt.Sprintf("%v not an Int", x))
	}
}

// Sign returns -1, 0, or 1 depending on whether x < 0, x == 0, or x > 0;
// x must be numeric or [Unknown]. For complex values x, the sign is 0 if x == 0,
// otherwise it is != 0. If x is [Unknown], the result is 1.
func Sign(x Value) int {
	switch x := x.(type) {
	case int64Val:
		switch {
		case x < 0:
			return -1
		case x > 0:
			return 1
		}
		return 0
	case intVal:
		return x.val.Sign()
	case ratVal:
		return x.val.Sign()
	case floatVal:
		return x.val.Sign()
	case complexVal:
		return Sign(x.re) | Sign(x.im)
	case unknownVal:
		return 1 // avoid spurious division by zero errors
	default:
		panic(fmt.Sprintf("%v not numeric", x))
	}
}

// ----------------------------------------------------------------------------
// Support for assembling/disassembling numeric values

const (
	// Compute the size of a Word in bytes.
	_m       = ^big.Word(0)
	_log     = _m>>8&1 + _m>>16&1 + _m>>32&1
	wordSize = 1 << _log
)

// Bytes returns the bytes for the absolute value of x in little-
// endian binary representation; x must be an [Int].
func Bytes(x Value) []byte {
	var t intVal
	switch x := x.(type) {
	case int64Val:
		t = i64toi(x)
	case intVal:
		t = x
	default:
		panic(fmt.Sprintf("%v not an Int", x))
	}

	words := t.val.Bits()
	bytes := make([]byte, len(words)*wordSize)

	i := 0
	for _, w := range words {
		for j := 0; j < wordSize; j++ {
			bytes[i] = byte(w)
			w >>= 8
			i++
		}
	}
	// remove leading 0's
	for i > 0 && bytes[i-1] == 0 {
		i--
	}

	return bytes[:i]
}

// MakeFromBytes returns the [Int] value given the bytes of its little-endian
// binary representation. An empty byte slice argument represents 0.
func MakeFromBytes(bytes []byte) Value {
	words := make([]big.Word, (len(bytes)+(wordSize-1))/wordSize)

	i := 0
	var w big.Word
	var s uint
	for _, b := range bytes {
		w |= big.Word(b) << s
		if s += 8; s == wordSize*8 {
			words[i] = w
			i++
			w = 0
			s = 0
		}
	}
	// store last word
	if i < len(words) {
		words[i] = w
		i++
	}
	// remove leading 0's
	for i > 0 && words[i-1] == 0 {
		i--
	}

	return makeInt(newInt().SetBits(words[:i]))
}

// Num returns the numerator of x; x must be [Int], [Float], or [Unknown].
// If x is [Unknown], or if it is too large or small to represent as a
// fraction, the result is [Unknown]. Otherwise the result is an [Int]
// with the same sign as x.
func Num(x Value) Value {
	switch x := x.(type) {
	case int64Val, intVal:
		return x
	case ratVal:
		return makeInt(x.val.Num())
	case floatVal:
		if smallFloat(x.val) {
			r, _ := x.val.Rat(nil)
			return makeInt(r.Num())
		}
	case unknownVal:
		break
	default:
		panic(fmt.Sprintf("%v not Int or Float", x))
	}
	return unknownVal{}
}

// Denom returns the denominator of x; x must be [Int], [Float], or [Unknown].
// If x is [Unknown], or if it is too large or small to represent as a
// fraction, the result is [Unknown]. Otherwise the result is an [Int] >= 1.
func Denom(x Value) Value {
	switch x := x.(type) {
	case int64Val, intVal:
		return int64Val(1)
	case ratVal:
		return makeInt(x.val.Denom())
	case floatVal:
		if smallFloat(x.val) {
			r, _ := x.val.Rat(nil)
			return makeInt(r.Denom())
		}
	case unknownVal:
		break
	default:
		panic(fmt.Sprintf("%v not Int or Float", x))
	}
	return unknownVal{}
}

// MakeImag returns the [Complex] value x*i;
// x must be [Int], [Float], or [Unknown].
// If x is [Unknown], the result is [Unknown].
func MakeImag(x Value) Value {
	switch x.(type) {
	case unknownVal:
		return x
	case int64Val, intVal, ratVal, floatVal:
		return makeComplex(int64Val(0), x)
	default:
		panic(fmt.Sprintf("%v not Int or Float", x))
	}
}

// Real returns the real part of x, which must be a numeric or unknown value.
// If x is [Unknown], the result is [Unknown].
func Real(x Value) Value {
	switch x := x.(type) {
	case unknownVal, int64Val, intVal, ratVal, floatVal:
		return x
	case complexVal:
		return x.re
	default:
		panic(fmt.Sprintf("%v not numeric", x))
	}
}

// Imag returns the imaginary part of x, which must be a numeric or unknown value.
// If x is [Unknown], the result is [Unknown].
func Imag(x Value) Value {
	switch x := x.(type) {
	case unknownVal:
		return x
	case int64Val, intVal, ratVal, floatVal:
		return int64Val(0)
	case complexVal:
		return x.im
	default:
		panic(fmt.Sprintf("%v not numeric", x))
	}
}

// ----------------------------------------------------------------------------
// Numeric conversions

// ToInt converts x to an [Int] value if x is representable as an [Int].
// Otherwise it returns an [Unknown].
func ToInt(x Value) Value {
	switch x := x.(type) {
	case int64Val, intVal:
		return x

	case ratVal:
		if x.val.IsInt() {
			return makeInt(x.val.Num())
		}

	case floatVal:
		// avoid creation of huge integers
		// (Existing tests require permitting exponents of at least 1024;
		// allow any value that would also be permissible as a fraction.)
		if smallFloat(x.val) {
			i := newInt()
			if _, acc := x.val.Int(i); acc == big.Exact {
				return makeInt(i)
			}

			// If we can get an integer by rounding up or down,
			// assume x is not an integer because of rounding
			// errors in prior computations.

			const delta = 4 // a small number of bits > 0
			var t big.Float
			t.SetPrec(prec - delta)

			// try rounding down a little
			t.SetMode(big.ToZero)
			t.Set(x.val)
			if _, acc := t.Int(i); acc == big.Exact {
				return makeInt(i)
			}

			// try rounding up a little
			t.SetMode(big.AwayFromZero)
			t.Set(x.val)
			if _, acc := t.Int(i); acc == big.Exact {
				return makeInt(i)
			}
		}

	case complexVal:
		if re := ToFloat(x); re.Kind() == Float {
			return ToInt(re)
		}
	}

	return unknownVal{}
}

// ToFloat converts x to a [Float] value if x is representable as a [Float].
// Otherwise it returns an [Unknown].
func ToFloat(x Value) Value {
	switch x := x.(type) {
	case int64Val:
		return i64tor(x) // x is always a small int
	case intVal:
		if smallInt(x.val) {
			return itor(x)
		}
		return itof(x)
	case ratVal, floatVal:
		return x
	case complexVal:
		if Sign(x.im) == 0 {
			return ToFloat(x.re)
		}
	}
	return unknownVal{}
}

// ToComplex converts x to a [Complex] value if x is representable as a [Complex].
// Otherwise it returns an [Unknown].
func ToComplex(x Value) Value {
	switch x := x.(type) {
	case int64Val, intVal, ratVal, floatVal:
		return vtoc(x)
	case complexVal:
		return x
	}
	return unknownVal{}
}

// ----------------------------------------------------------------------------
// Operations

// is32bit reports whether x can be represented using 32 bits.
func is32bit(x int64) bool {
	const s = 32
	return -1<<(s-1) <= x && x <= 1<<(s-1)-1
}

// is63bit reports whether x can be represented using 63 bits.
func is63bit(x int64) bool {
	const s = 63
	return -1<<(s-1) <= x && x <= 1<<(s-1)-1
}

// UnaryOp returns the result of the unary expression op y.
// The operation must be defined for the operand.
// If prec > 0 it specifies the ^ (xor) result size in bits.
// If y is [Unknown], the result is [Unknown].
func UnaryOp(op token.Token, y Value, prec uint) Value {
	switch op {
	case token.ADD:
		switch y.(type) {
		case unknownVal, int64Val, intVal, ratVal, floatVal, complexVal:
			return y
		}

	case token.SUB:
		switch y := y.(type) {
		case unknownVal:
			return y
		case int64Val:
			if z := -y; z != y {
				return z // no overflow
			}
			return makeInt(newInt().Neg(big.NewInt(int64(y))))
		case intVal:
			return makeInt(newInt().Neg(y.val))
		case ratVal:
			return makeRat(newRat().Neg(y.val))
		case floatVal:
			return makeFloat(newFloat().Neg(y.val))
		case complexVal:
			re := UnaryOp(token.SUB, y.re, 0)
			im := UnaryOp(token.SUB, y.im, 0)
			return makeComplex(re, im)
		}

	case token.XOR:
		z := newInt()
		switch y := y.(type) {
		case unknownVal:
			return y
		case int64Val:
			z.Not(big.NewInt(int64(y)))
		case intVal:
			z.Not(y.val)
		default:
			goto Error
		}
		// For unsigned types, the result will be negative and
		// thus "too large": We must limit the result precision
		// to the type's precision.
		if prec > 0 {
			z.AndNot(z, newInt().Lsh(big.NewInt(-1), prec)) // z &^= (-1)<<prec
		}
		return makeInt(z)

	case token.NOT:
		switch y := y.(type) {
		case unknownVal:
			return y
		case boolVal:
			return !y
		}
	}

Error:
	panic(fmt.Sprintf("invalid unary operation %s%v", op, y))
}

func ord(x Value) int {
	switch x.(type) {
	default:
		// force invalid value into "x position" in match
		// (don't panic here so that callers can provide a better error message)
		return -1
	case unknownVal:
		return 0
	case boolVal, *stringVal:
		return 1
	case int64Val:
		return 2
	case intVal:
		return 3
	case ratVal:
		return 4
	case floatVal:
		return 5
	case complexVal:
		return 6
	}
}

// match returns the matching representation (same type) with the
// smallest complexity for two values x and y. If one of them is
// numeric, both of them must be numeric. If one of them is Unknown
// or invalid (say, nil) both results are that value.
func match(x, y Value) (_, _ Value) {
	switch ox, oy := ord(x), ord(y); {
	case ox < oy:
		x, y = match0(x, y)
	case ox > oy:
		y, x = match0(y, x)
	}
	return x, y
}

// match0 must only be called by match.
// Invariant: ord(x) < ord(y)
func match0(x, y Value) (_, _ Value) {
	// Prefer to return the original x and y arguments when possible,
	// to avoid unnecessary heap allocations.

	switch y.(type) {
	case intVal:
		switch x1 := x.(type) {
		case int64Val:
			return i64toi(x1), y
		}
	case ratVal:
		switch x1 := x.(type) {
		case int64Val:
			return i64tor(x1), y
		case intVal:
			return itor(x1), y
		}
	case floatVal:
		switch x1 := x.(type) {
		case int64Val:
			return i64tof(x1), y
		case intVal:
			return itof(x1), y
		case ratVal:
			return rtof(x1), y
		}
	case complexVal:
		return vtoc(x), y
	}

	// force unknown and invalid values into "x position" in callers of match
	// (don't panic here so that callers can provide a better error message)
	return x, x
}

// BinaryOp returns the result of the binary expression x op y.
// The operation must be defined for the operands. If one of the
// operands is [Unknown], the result is [Unknown].
// BinaryOp doesn't handle comparisons or shifts; use [Compare]
// or [Shift] instead.
//
// To force integer division of [Int] operands, use op == [token.QUO_ASSIGN]
// instead of [token.QUO]; the result is guaranteed to be [Int] in this case.
// Division by zero leads to a run-time panic.
func BinaryOp(x_ Value, op token.Token, y_ Value) Value {
	x, y := match(x_, y_)

	switch x := x.(type) {
	case unknownVal:
		return x

	case boolVal:
		y := y.(boolVal)
		switch op {
		case token.LAND:
			return x && y
		case token.LOR:
			return x || y
		}

	case int64Val:
		a := int64(x)
		b := int64(y.(int64Val))
		var c int64
		switch op {
		case token.ADD:
			if !is63bit(a) || !is63bit(b) {
				return makeInt(newInt().Add(big.NewInt(a), big.NewInt(b)))
			}
			c = a + b
		case token.SUB:
			if !is63bit(a) || !is63bit(b) {
				return makeInt(newInt().Sub(big.NewInt(a), big.NewInt(b)))
			}
			c = a - b
		case token.MUL:
			if !is32bit(a) || !is32bit(b) {
				return makeInt(newInt().Mul(big.NewInt(a), big.NewInt(b)))
			}
			c = a * b
		case token.QUO:
			return makeRat(big.NewRat(a, b))
		case token.QUO_ASSIGN: // force integer division
			c = a / b
		case token.REM:
			c = a % b
		case token.AND:
			c = a & b
		case token.OR:
			c = a | b
		case token.XOR:
			c = a ^ b
		case token.AND_NOT:
			c = a &^ b
		default:
			goto Error
		}
		return int64Val(c)

	case intVal:
		a := x.val
		b := y.(intVal).val
		c := newInt()
		switch op {
		case token.ADD:
			c.Add(a, b)
		case token.SUB:
			c.Sub(a, b)
		case token.MUL:
			c.Mul(a, b)
		case token.QUO:
			return makeRat(newRat().SetFrac(a, b))
		case token.QUO_ASSIGN: // force integer division
			c.Quo(a, b)
		case token.REM:
			c.Rem(a, b)
		case token.AND:
			c.And(a, b)
		case token.OR:
			c.Or(a, b)
		case token.XOR:
			c.Xor(a, b)
		case token.AND_NOT:
			c.AndNot(a, b)
		default:
			goto Error
		}
		return makeInt(c)

	case ratVal:
		a := x.val
		b := y.(ratVal).val
		c := newRat()
		switch op {
		case token.ADD:
			c.Add(a, b)
		case token.SUB:
			c.Sub(a, b)
		case token.MUL:
			c.Mul(a, b)
		case token.QUO:
			c.Quo(a, b)
		default:
			goto Error
		}
		return makeRat(c)

	case floatVal:
		a := x.val
		b := y.(floatVal).val
		c := newFloat()
		switch op {
		case token.ADD:
			c.Add(a, b)
		case token.SUB:
			c.Sub(a, b)
		case token.MUL:
			c.Mul(a, b)
		case token.QUO:
			c.Quo(a, b)
		default:
			goto Error
		}
		return makeFloat(c)

	case complexVal:
		y := y.(complexVal)
		a, b := x.re, x.im
		c, d := y.re, y.im
		var re, im Value
		switch op {
		case token.ADD:
			// (a+c) + i(b+d)
			re = add(a, c)
			im = add(b, d)
		case token.SUB:
			// (a-c) + i(b-d)
			re = sub(a, c)
			im = sub(b, d)
		case token.MUL:
			// (ac-bd) + i(bc+ad)
			ac := mul(a, c)
			bd := mul(b, d)
			bc := mul(b, c)
			ad := mul(a, d)
			re = sub(ac, bd)
			im = add(bc, ad)
		case token.QUO:
			// (ac+bd)/s + i(bc-ad)/s, with s = cc + dd
			ac := mul(a, c)
			bd := mul(b, d)
			bc := mul(b, c)
			ad := mul(a, d)
			cc := mul(c, c)
			dd := mul(d, d)
			s := add(cc, dd)
			re = add(ac, bd)
			re = quo(re, s)
			im = sub(bc, ad)
			im = quo(im, s)
		default:
			goto Error
		}
		return makeComplex(re, im)

	case *stringVal:
		if op == token.ADD {
			return &stringVal{l: x, r: y.(*stringVal)}
		}
	}

Error:
	panic(fmt.Sprintf("invalid binary operation %v %s %v", x_, op, y_))
}

func add(x, y Value) Value { return BinaryOp(x, token.ADD, y) }
func sub(x, y Value) Value { return BinaryOp(x, token.SUB, y) }
func mul(x, y Value) Value { return BinaryOp(x, token.MUL, y) }
func quo(x, y Value) Value { return BinaryOp(x, token.QUO, y) }

// Shift returns the result of the shift expression x op s
// with op == [token.SHL] or [token.SHR] (<< or >>). x must be
// an [Int] or an [Unknown]. If x is [Unknown], the result is x.
func Shift(x Value, op token.Token, s uint) Value {
	switch x := x.(type) {
	case unknownVal:
		return x

	case int64Val:
		if s == 0 {
			return x
		}
		switch op {
		case token.SHL:
			z := i64toi(x).val
			return makeInt(z.Lsh(z, s))
		case token.SHR:
			return x >> s
		}

	case intVal:
		if s == 0
```