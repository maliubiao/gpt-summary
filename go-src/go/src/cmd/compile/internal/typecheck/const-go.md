Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: Purpose and Context**

The first step is to understand the overall goal of the code. The file path `go/src/cmd/compile/internal/typecheck/const.go` immediately suggests this code is part of the Go compiler, specifically within the type checking phase, and deals with constants. The package declaration `package typecheck` confirms this. The copyright notice reinforces that this is official Go source code.

**2. Decomposing Function by Function**

The next step is to examine each function individually to grasp its specific responsibility. I'd go through the code sequentially:

* **`roundFloat(v constant.Value, sz int64) constant.Value`:** The name and parameters strongly suggest it's about rounding floating-point constant values based on size (likely 32-bit or 64-bit). The `switch sz` confirms this.

* **`truncfltlit(v constant.Value, t *types.Type) constant.Value`:**  The name "truncfltlit" hints at truncating floating-point literals. It checks if the type is untyped, and if not, calls `roundFloat` with the type's size. This suggests it handles implicit and explicit type conversions for float literals.

* **`trunccmplxlit(v constant.Value, t *types.Type) constant.Value`:**  Similar to `truncfltlit`, but for complex literals. It extracts the real and imaginary parts and calls `roundFloat` for each.

* **`convlit(n ir.Node, t *types.Type) ir.Node` and `DefaultLit(n ir.Node, t *types.Type) ir.Node`:** These are simple wrappers around `convlit1`. This suggests `convlit1` is the core function for converting literals.

* **`convlit1(n ir.Node, t *types.Type, explicit bool, context func() string) ir.Node`:**  This is the most complex function so far. The comments are very helpful: "converts an untyped expression n to type t." The `explicit` flag suggests handling both explicit type conversions (like `int(x)`) and implicit ones (like assignment). The logic branches based on the `Op()` of the input node `n`, indicating it handles different kinds of constant expressions (literals, unary operations, binary operations, comparisons, shifts). The handling of `ir.OLITERAL` by calling `ConvertVal` is a key observation.

* **`operandType(op ir.Op, t *types.Type) *types.Type`:** This function seems to determine the operand type required for a given operation (`op`) and target type (`t`). The `switch op` suggests different rules for different operators.

* **`ConvertVal(v constant.Value, t *types.Type, explicit bool) constant.Value`:** This function performs the actual conversion of constant values. The `switch ct := v.Kind()` handles different constant types (bool, string, int, float, complex). The `explicit` flag is used to allow string conversions from integers. Calls to `toint`, `toflt`, `tocplx`, and `tostr` suggest further specialized conversion functions.

* **`tocplx`, `toflt`, `toint`, `tostr`:** These are helper functions that perform the core type conversions. `toint`'s error handling for truncated floats is interesting.

* **`makeFloat64(f float64) constant.Value` and `makeComplex(real, imag constant.Value) constant.Value`:**  These construct `constant.Value` instances for floats and complex numbers, with a check for infinity.

* **`defaultlit2(l ir.Node, r ir.Node, force bool) (ir.Node, ir.Node)`:**  This function seems to handle the case where you have two untyped literals and need to give them a consistent type. The `force` flag implies there are situations where a concrete type *must* be assigned.

* **`mixUntyped(t1, t2 *types.Type) *types.Type`:**  This helps `defaultlit2` by determining the "more general" type between two untyped types. The ranking order (Int < Rune < Float < Complex) is important.

* **`defaultType(t *types.Type) *types.Type`:** This function provides the default Go type for untyped constants (e.g., `UntypedInt` becomes `int`).

* **`IndexConst(n ir.Node) int64`:** This extracts the integer value from a constant node, used for array indexing, etc.

* **`callOrChan(n ir.Node) bool`:**  This function simply checks if a given node represents a function call or a channel operation.

**3. Identifying Core Functionality and Relationships**

After examining individual functions, I started connecting the dots:

* **`convlit1` is the central conversion function.** It orchestrates the process.
* **`ConvertVal` does the low-level value conversion.**
* The `truncfltlit` and `trunccmplxlit` functions handle precision for float and complex literals.
* `defaultlit2`, `mixUntyped`, and `defaultType` work together to resolve the types of untyped expressions.

**4. Inferring Go Language Features**

Based on the identified functionality, I started relating it to Go language features:

* **Constant declarations:** The code clearly handles how Go deals with constants, their types, and conversions.
* **Literal values:** The functions processing `ir.OLITERAL` show how Go represents and converts literal values (integers, floats, strings, booleans, complex numbers).
* **Type inference:** The `convlit1` function and the `defaultlit2`/`mixUntyped`/`defaultType` group are directly related to Go's type inference rules for untyped constants.
* **Implicit and explicit type conversions:**  The `explicit` flag in `convlit1` highlights the difference between these.
* **Arithmetic and logical operations on constants:** The handling of `ir.OADD`, `ir.OSUB`, `ir.OEQ`, etc., shows how the compiler type-checks and potentially converts operands in constant expressions.
* **Shift operations:** The specific handling of `ir.OLSH` and `ir.ORSH` demonstrates the type constraints for shift operations.
* **Default types for untyped constants:** The `defaultType` function directly implements this Go feature.

**5. Code Examples and Assumptions**

To illustrate the functionality, I created Go code examples. For each example, I made assumptions about the input and then reasoned about the output based on my understanding of the code. For example, for `convlit1`, I considered both implicit and explicit conversions with different types.

**6. Command-line Arguments (Not Applicable)**

I noticed that the provided code doesn't directly handle command-line arguments. This is expected, as this specific file is focused on type checking of constant expressions, which is a phase after parsing the command-line arguments.

**7. Common Mistakes**

Thinking about how developers use Go and the potential pitfalls related to constants led to the "Common Mistakes" section. The key error is misunderstanding how default types are assigned to untyped constants, especially in mixed-type scenarios.

**Self-Correction/Refinement During the Process:**

* **Initial Focus on Syntax:**  At first glance, I might have been tempted to focus heavily on the `ir.Node` and `types.Type` structures. However, I quickly realized that understanding the *purpose* of the functions was more important than the low-level details of these structures.
* **Understanding `constant.Value`:**  Recognizing the role of `go/constant.Value` was crucial for understanding how constant values are represented and manipulated within the compiler.
* **Connecting to Go Language Specs:**  Constantly asking myself "How does this relate to the actual Go language?" helped me move beyond just understanding the code to understanding its significance.

By following these steps, I could systematically analyze the code, infer its purpose, connect it to Go language features, provide illustrative examples, and identify potential areas of confusion for developers.
这段代码是 Go 编译器 `cmd/compile/internal/typecheck` 包中处理常量表达式的一部分，主要负责**对常量进行类型检查和转换**。

下面列举其主要功能：

1. **常量值精度调整 (Truncation):**
   - `roundFloat`:  根据目标类型的大小（32位或64位）对浮点数常量值进行四舍五入。
   - `truncfltlit`:  将浮点字面量的值截断为目标类型的精度（float32 或 float64）。
   - `trunccmplxlit`: 将复数字面量的实部和虚部分别截断为目标类型的精度（complex64 或 complex128）。

2. **常量类型转换:**
   - `convlit1`:  这是核心的常量类型转换函数。它可以将一个无类型（untyped）的表达式 `n` 转换为目标类型 `t`。它可以处理显式类型转换和隐式类型转换。
     - 对于字面量 (OLITERAL)，它会调用 `ConvertVal` 进行实际的值转换。
     - 对于一元运算（如 `+`, `-`, `!`），它会递归地转换操作数。
     - 对于二元运算（如 `+`, `-`, `*`, `/`），它会转换两个操作数，并确保它们的类型一致。
     - 对于比较运算（如 `==`, `!=`, `<`），它会设置结果类型为 `bool`。
     - 对于位移运算（如 `<<`, `>>`），它会转换左操作数的类型。
   - `convlit` 和 `DefaultLit` 只是 `convlit1` 的简化版本。

3. **底层常量值转换:**
   - `ConvertVal`:  根据目标类型 `t` 将常量值 `v` 转换为合适的表示。它处理 `bool`, `string`, `int`, `float`, `complex` 等不同类型的常量。
   - `tocplx`, `toflt`, `toint`, `tostr`:  这些是辅助函数，用于将常量值转换为复数、浮点数、整数和字符串。`toint` 中包含了对大整数和截断错误的特殊处理。

4. **创建特定类型的常量值:**
   - `makeFloat64`:  创建一个 `constant.Value` 类型的浮点数。
   - `makeComplex`: 创建一个 `constant.Value` 类型的复数。

5. **处理无类型常量的默认类型:**
   - `defaultlit2`:  当有两个无类型常量进行运算时，确定它们的默认类型。
   - `mixUntyped`:  在两个无类型常量中选择“更宽”的类型作为它们的共同类型。
   - `defaultType`:  为无类型常量指定默认的具体类型（例如，`UntypedInt` 变为 `int`）。

6. **获取常量索引值:**
   - `IndexConst`:  从常量节点 `n` 中提取整数索引值。

7. **判断节点是否为函数调用或通道操作:**
   - `callOrChan`: 判断给定的节点 `n` 是否表示函数调用或通道操作。这个函数似乎与常量处理关联不大，可能用于区分常量表达式和其他类型的表达式。

**推理 Go 语言功能的实现:**

这段代码是 Go 语言中**常量表达式求值和类型推断**的关键部分。Go 语言允许在编译时进行常量计算，并且对于未明确指定类型的常量（称为无类型常量），Go 会根据上下文推断其类型。

**Go 代码示例:**

```go
package main

import "fmt"

const (
	a = 10        // untyped int
	b = 3.14      // untyped float
	c = 'A'       // untyped rune
	d = "hello"   // untyped string
	e = 2 + 3i    // untyped complex
	f float32 = 1.23 // typed float32
)

func main() {
	fmt.Printf("Type of a: %T, Value: %v\n", a, a)
	fmt.Printf("Type of b: %T, Value: %v\n", b, b)
	fmt.Printf("Type of c: %T, Value: %v\n", c, c)
	fmt.Printf("Type of d: %T, Value: %v\n", d, d)
	fmt.Printf("Type of e: %T, Value: %v\n", e, e)
	fmt.Printf("Type of f: %T, Value: %v\n", f, f)

	// 常量间的运算
	const sum = a + b // b 会被隐式转换为 float64
	fmt.Printf("Type of sum: %T, Value: %v\n", sum, sum)

	// 显式类型转换
	const intB = int(b)
	fmt.Printf("Type of intB: %T, Value: %v\n", intB, intB)

	// 将整数常量转换为字符串 (在 ConvertVal 中处理)
	const charCode = 65
	const charString = string(charCode)
	fmt.Printf("Type of charString: %T, Value: %v\n", charString, charString)
}
```

**假设的输入与输出 (基于 `convlit1` 函数):**

**假设输入 1 (隐式类型转换):**

- `n`: 一个表示无类型整数常量 `10` 的 `ir.Node` (其类型为 `types.UntypedInt`)。
- `t`:  `nil` (表示隐式转换)。

**输出 1:**

- 一个表示类型为 `int`，值为 `10` 的 `ir.Node`。`convlit1` 会调用 `defaultType` 将 `types.UntypedInt` 转换为 `types.TINT`。

**假设输入 2 (显式类型转换):**

- `n`: 一个表示无类型浮点数常量 `3.14` 的 `ir.Node` (其类型为 `types.UntypedFloat`)。
- `t`:  指向 `float32` 类型的 `types.Type` 指针。
- `explicit`: `true`。

**输出 2:**

- 一个表示类型为 `float32`，值为 `3.14` (可能被截断为 float32 的精度) 的 `ir.Node`。`convlit1` 会调用 `ConvertVal`，然后 `truncfltlit` 会进行精度调整。

**假设输入 3 (常量间的加法运算):**

- `n`: 一个表示表达式 `a + b` 的 `ir.Node` (假设 `a` 是无类型整数常量，`b` 是无类型浮点数常量)。
- `t`: `nil` (隐式转换)。

**输出 3:**

- 一个表示类型为 `float64` 的 `ir.Node`。`convlit1` 会先递归调用自身处理 `a` 和 `b`，然后 `defaultlit2` 和 `mixUntyped` 会将它们的共同类型确定为 `float64`。

**涉及命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在编译器的前端部分，例如在词法分析、语法分析阶段。这段代码属于类型检查阶段，它接收的是已经解析过的抽象语法树 (AST) 节点。

**使用者易犯错的点:**

1. **混淆无类型常量和有类型常量:**  Go 的无类型常量具有更大的灵活性，可以参与更多类型的运算，因为它们的类型会根据上下文推断。但如果直接将无类型常量赋值给需要特定类型的变量，可能会因为默认类型不匹配而导致错误。

   ```go
   const x = 10 // untyped int
   var y int8 = x // 错误: cannot use x (untyped int constant) as int8 value in variable declaration (overflows)

   const z int8 = 10 // typed int8
   var w int8 = z // 正确
   ```

2. **浮点数常量的精度丢失:** 当将无类型浮点数常量赋值给 `float32` 类型的变量时，可能会发生精度丢失。

   ```go
   const pi = 3.1415926535 // untyped float
   var pi32 float32 = pi
   fmt.Println(pi32) // 输出可能不是完整的 pi 值
   ```

3. **整数常量溢出:** 当将无类型整数常量赋值给一个范围较小的整数类型时，可能会发生溢出。

   ```go
   const bigNumber = 1 << 63 // untyped int
   var smallInt int8 = bigNumber // 错误: constant 9223372036854775808 overflows int8
   ```

4. **字符串类型转换的限制:**  虽然可以将整数常量显式转换为字符串（得到对应的 Unicode 字符），但不能将其他类型的常量直接转换为字符串常量。

   ```go
   const floatVal = 3.14
   // const strVal = string(floatVal) // 错误: cannot convert floatVal (untyped float constant) to string
   ```

总而言之，这段代码是 Go 编译器中负责确保常量在编译时具有正确类型和值的关键部分，它实现了 Go 语言常量类型推断和转换的核心逻辑。理解这段代码有助于深入理解 Go 语言的编译过程和常量的工作原理。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/typecheck/const.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package typecheck

import (
	"fmt"
	"go/constant"
	"go/token"
	"math"
	"math/big"
	"unicode"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
)

func roundFloat(v constant.Value, sz int64) constant.Value {
	switch sz {
	case 4:
		f, _ := constant.Float32Val(v)
		return makeFloat64(float64(f))
	case 8:
		f, _ := constant.Float64Val(v)
		return makeFloat64(f)
	}
	base.Fatalf("unexpected size: %v", sz)
	panic("unreachable")
}

// truncate float literal fv to 32-bit or 64-bit precision
// according to type; return truncated value.
func truncfltlit(v constant.Value, t *types.Type) constant.Value {
	if t.IsUntyped() {
		return v
	}

	return roundFloat(v, t.Size())
}

// truncate Real and Imag parts of Mpcplx to 32-bit or 64-bit
// precision, according to type; return truncated value. In case of
// overflow, calls Errorf but does not truncate the input value.
func trunccmplxlit(v constant.Value, t *types.Type) constant.Value {
	if t.IsUntyped() {
		return v
	}

	fsz := t.Size() / 2
	return makeComplex(roundFloat(constant.Real(v), fsz), roundFloat(constant.Imag(v), fsz))
}

// TODO(mdempsky): Replace these with better APIs.
func convlit(n ir.Node, t *types.Type) ir.Node    { return convlit1(n, t, false, nil) }
func DefaultLit(n ir.Node, t *types.Type) ir.Node { return convlit1(n, t, false, nil) }

// convlit1 converts an untyped expression n to type t. If n already
// has a type, convlit1 has no effect.
//
// For explicit conversions, t must be non-nil, and integer-to-string
// conversions are allowed.
//
// For implicit conversions (e.g., assignments), t may be nil; if so,
// n is converted to its default type.
//
// If there's an error converting n to t, context is used in the error
// message.
func convlit1(n ir.Node, t *types.Type, explicit bool, context func() string) ir.Node {
	if explicit && t == nil {
		base.Fatalf("explicit conversion missing type")
	}
	if t != nil && t.IsUntyped() {
		base.Fatalf("bad conversion to untyped: %v", t)
	}

	if n == nil || n.Type() == nil {
		// Allow sloppy callers.
		return n
	}
	if !n.Type().IsUntyped() {
		// Already typed; nothing to do.
		return n
	}

	// Nil is technically not a constant, so handle it specially.
	if n.Type().Kind() == types.TNIL {
		if n.Op() != ir.ONIL {
			base.Fatalf("unexpected op: %v (%v)", n, n.Op())
		}
		n = ir.Copy(n)
		if t == nil {
			base.Fatalf("use of untyped nil")
		}

		if !t.HasNil() {
			// Leave for caller to handle.
			return n
		}

		n.SetType(t)
		return n
	}

	if t == nil || !ir.OKForConst[t.Kind()] {
		t = defaultType(n.Type())
	}

	switch n.Op() {
	default:
		base.Fatalf("unexpected untyped expression: %v", n)

	case ir.OLITERAL:
		v := ConvertVal(n.Val(), t, explicit)
		if v.Kind() == constant.Unknown {
			n = ir.NewConstExpr(n.Val(), n)
			break
		}
		n = ir.NewConstExpr(v, n)
		n.SetType(t)
		return n

	case ir.OPLUS, ir.ONEG, ir.OBITNOT, ir.ONOT, ir.OREAL, ir.OIMAG:
		ot := operandType(n.Op(), t)
		if ot == nil {
			n = DefaultLit(n, nil)
			break
		}

		n := n.(*ir.UnaryExpr)
		n.X = convlit(n.X, ot)
		if n.X.Type() == nil {
			n.SetType(nil)
			return n
		}
		n.SetType(t)
		return n

	case ir.OADD, ir.OSUB, ir.OMUL, ir.ODIV, ir.OMOD, ir.OOR, ir.OXOR, ir.OAND, ir.OANDNOT, ir.OOROR, ir.OANDAND, ir.OCOMPLEX:
		ot := operandType(n.Op(), t)
		if ot == nil {
			n = DefaultLit(n, nil)
			break
		}

		var l, r ir.Node
		switch n := n.(type) {
		case *ir.BinaryExpr:
			n.X = convlit(n.X, ot)
			n.Y = convlit(n.Y, ot)
			l, r = n.X, n.Y
		case *ir.LogicalExpr:
			n.X = convlit(n.X, ot)
			n.Y = convlit(n.Y, ot)
			l, r = n.X, n.Y
		}

		if l.Type() == nil || r.Type() == nil {
			n.SetType(nil)
			return n
		}
		if !types.Identical(l.Type(), r.Type()) {
			base.Errorf("invalid operation: %v (mismatched types %v and %v)", n, l.Type(), r.Type())
			n.SetType(nil)
			return n
		}

		n.SetType(t)
		return n

	case ir.OEQ, ir.ONE, ir.OLT, ir.OLE, ir.OGT, ir.OGE:
		n := n.(*ir.BinaryExpr)
		if !t.IsBoolean() {
			break
		}
		n.SetType(t)
		return n

	case ir.OLSH, ir.ORSH:
		n := n.(*ir.BinaryExpr)
		n.X = convlit1(n.X, t, explicit, nil)
		n.SetType(n.X.Type())
		if n.Type() != nil && !n.Type().IsInteger() {
			base.Errorf("invalid operation: %v (shift of type %v)", n, n.Type())
			n.SetType(nil)
		}
		return n
	}

	if explicit {
		base.Fatalf("cannot convert %L to type %v", n, t)
	} else if context != nil {
		base.Fatalf("cannot use %L as type %v in %s", n, t, context())
	} else {
		base.Fatalf("cannot use %L as type %v", n, t)
	}

	n.SetType(nil)
	return n
}

func operandType(op ir.Op, t *types.Type) *types.Type {
	switch op {
	case ir.OCOMPLEX:
		if t.IsComplex() {
			return types.FloatForComplex(t)
		}
	case ir.OREAL, ir.OIMAG:
		if t.IsFloat() {
			return types.ComplexForFloat(t)
		}
	default:
		if okfor[op][t.Kind()] {
			return t
		}
	}
	return nil
}

// ConvertVal converts v into a representation appropriate for t. If
// no such representation exists, it returns constant.MakeUnknown()
// instead.
//
// If explicit is true, then conversions from integer to string are
// also allowed.
func ConvertVal(v constant.Value, t *types.Type, explicit bool) constant.Value {
	switch ct := v.Kind(); ct {
	case constant.Bool:
		if t.IsBoolean() {
			return v
		}

	case constant.String:
		if t.IsString() {
			return v
		}

	case constant.Int:
		if explicit && t.IsString() {
			return tostr(v)
		}
		fallthrough
	case constant.Float, constant.Complex:
		switch {
		case t.IsInteger():
			v = toint(v)
			return v
		case t.IsFloat():
			v = toflt(v)
			v = truncfltlit(v, t)
			return v
		case t.IsComplex():
			v = tocplx(v)
			v = trunccmplxlit(v, t)
			return v
		}
	}

	return constant.MakeUnknown()
}

func tocplx(v constant.Value) constant.Value {
	return constant.ToComplex(v)
}

func toflt(v constant.Value) constant.Value {
	if v.Kind() == constant.Complex {
		v = constant.Real(v)
	}

	return constant.ToFloat(v)
}

func toint(v constant.Value) constant.Value {
	if v.Kind() == constant.Complex {
		v = constant.Real(v)
	}

	if v := constant.ToInt(v); v.Kind() == constant.Int {
		return v
	}

	// The value of v cannot be represented as an integer;
	// so we need to print an error message.
	// Unfortunately some float values cannot be
	// reasonably formatted for inclusion in an error
	// message (example: 1 + 1e-100), so first we try to
	// format the float; if the truncation resulted in
	// something that looks like an integer we omit the
	// value from the error message.
	// (See issue #11371).
	f := ir.BigFloat(v)
	if f.MantExp(nil) > 2*ir.ConstPrec {
		base.Errorf("integer too large")
	} else {
		var t big.Float
		t.Parse(fmt.Sprint(v), 0)
		if t.IsInt() {
			base.Errorf("constant truncated to integer")
		} else {
			base.Errorf("constant %v truncated to integer", v)
		}
	}

	// Prevent follow-on errors.
	return constant.MakeUnknown()
}

func tostr(v constant.Value) constant.Value {
	if v.Kind() == constant.Int {
		r := unicode.ReplacementChar
		if x, ok := constant.Uint64Val(v); ok && x <= unicode.MaxRune {
			r = rune(x)
		}
		v = constant.MakeString(string(r))
	}
	return v
}

func makeFloat64(f float64) constant.Value {
	if math.IsInf(f, 0) {
		base.Fatalf("infinity is not a valid constant")
	}
	return constant.MakeFloat64(f)
}

func makeComplex(real, imag constant.Value) constant.Value {
	return constant.BinaryOp(constant.ToFloat(real), token.ADD, constant.MakeImag(constant.ToFloat(imag)))
}

// DefaultLit on both nodes simultaneously;
// if they're both ideal going in they better
// get the same type going out.
// force means must assign concrete (non-ideal) type.
// The results of defaultlit2 MUST be assigned back to l and r, e.g.
//
//	n.Left, n.Right = defaultlit2(n.Left, n.Right, force)
func defaultlit2(l ir.Node, r ir.Node, force bool) (ir.Node, ir.Node) {
	if l.Type() == nil || r.Type() == nil {
		return l, r
	}

	if !l.Type().IsInterface() && !r.Type().IsInterface() {
		// Can't mix bool with non-bool, string with non-string.
		if l.Type().IsBoolean() != r.Type().IsBoolean() {
			return l, r
		}
		if l.Type().IsString() != r.Type().IsString() {
			return l, r
		}
	}

	if !l.Type().IsUntyped() {
		r = convlit(r, l.Type())
		return l, r
	}

	if !r.Type().IsUntyped() {
		l = convlit(l, r.Type())
		return l, r
	}

	if !force {
		return l, r
	}

	// Can't mix nil with anything untyped.
	if ir.IsNil(l) || ir.IsNil(r) {
		return l, r
	}
	t := defaultType(mixUntyped(l.Type(), r.Type()))
	l = convlit(l, t)
	r = convlit(r, t)
	return l, r
}

func mixUntyped(t1, t2 *types.Type) *types.Type {
	if t1 == t2 {
		return t1
	}

	rank := func(t *types.Type) int {
		switch t {
		case types.UntypedInt:
			return 0
		case types.UntypedRune:
			return 1
		case types.UntypedFloat:
			return 2
		case types.UntypedComplex:
			return 3
		}
		base.Fatalf("bad type %v", t)
		panic("unreachable")
	}

	if rank(t2) > rank(t1) {
		return t2
	}
	return t1
}

func defaultType(t *types.Type) *types.Type {
	if !t.IsUntyped() || t.Kind() == types.TNIL {
		return t
	}

	switch t {
	case types.UntypedBool:
		return types.Types[types.TBOOL]
	case types.UntypedString:
		return types.Types[types.TSTRING]
	case types.UntypedInt:
		return types.Types[types.TINT]
	case types.UntypedRune:
		return types.RuneType
	case types.UntypedFloat:
		return types.Types[types.TFLOAT64]
	case types.UntypedComplex:
		return types.Types[types.TCOMPLEX128]
	}

	base.Fatalf("bad type %v", t)
	return nil
}

// IndexConst returns the index value of constant Node n.
func IndexConst(n ir.Node) int64 {
	return ir.IntVal(types.Types[types.TINT], toint(n.Val()))
}

// callOrChan reports whether n is a call or channel operation.
func callOrChan(n ir.Node) bool {
	switch n.Op() {
	case ir.OAPPEND,
		ir.OCALL,
		ir.OCALLFUNC,
		ir.OCALLINTER,
		ir.OCALLMETH,
		ir.OCAP,
		ir.OCLEAR,
		ir.OCLOSE,
		ir.OCOMPLEX,
		ir.OCOPY,
		ir.ODELETE,
		ir.OIMAG,
		ir.OLEN,
		ir.OMAKE,
		ir.OMAX,
		ir.OMIN,
		ir.ONEW,
		ir.OPANIC,
		ir.OPRINT,
		ir.OPRINTLN,
		ir.OREAL,
		ir.ORECOVER,
		ir.ORECOVERFP,
		ir.ORECV,
		ir.OUNSAFEADD,
		ir.OUNSAFESLICE,
		ir.OUNSAFESLICEDATA,
		ir.OUNSAFESTRING,
		ir.OUNSAFESTRINGDATA:
		return true
	}
	return false
}

"""



```