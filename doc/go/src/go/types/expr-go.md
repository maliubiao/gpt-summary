Response:
My goal is to analyze the provided Go code snippet and answer the user's request comprehensively. Here's a breakdown of the thought process:

1. **Understanding the Core Request:** The user wants to know the functionality of the `go/src/go/types/expr.go` file, specifically the part provided. They also want examples and explanations of potential errors. The request is explicitly marked as the first part of a two-part query.

2. **Initial Code Scan and Keyword Recognition:**  I'll quickly scan the code for prominent keywords and structures. This includes:
    * `package types`:  Confirms this code is part of the `go/types` package, responsible for type checking.
    * Function signatures like `func (check *Checker) ...`:  Indicates methods belonging to a `Checker` type, which is the central type-checking engine.
    * Comments explaining the type-checking algorithm: "Expressions are checked recursively, top down."
    * Handling of different `ast.Expr` types (e.g., `*ast.BinaryExpr`, `*ast.UnaryExpr`, `*ast.CallExpr`): This suggests the code is handling various expression kinds in Go.
    * Concepts like "untyped expressions," "constant values," "type inference," "implicit conversion," "comparisons," and "shifts": These are key areas of type checking.
    * Error handling using `check.errorf`.
    * The `operand` struct: Likely holds information about an expression's value, type, and mode (e.g., constant, variable).

3. **Dissecting Key Functions and Concepts:**

    * **`rawExpr` and `exprInternal`:** These seem to be the main entry points for type-checking expressions. The comments in `rawExpr` explicitly describe the purpose.
    * **`updateExprType`:** This function handles the process of assigning a concrete type to an initially "untyped" expression. The comments here are very informative.
    * **`unary` and `binary`:** These functions deal with type-checking unary and binary operators, respectively. They check for valid operands and perform constant folding.
    * **`comparison`:** Specifically handles comparison operators, considering comparability of types and special cases like comparison with `nil`.
    * **`shift`:**  Focuses on the type rules for shift operations, including constraints on the operands.
    * **`implicitTypeAndValue`:**  Handles implicit type conversions in certain contexts.
    * **The `operand` struct and its `mode`:**  This is central to tracking the state of an expression during type checking. The different modes (e.g., `invalid`, `value`, `constant_`) are important.
    * **Untyped Constants:** The code explicitly mentions "untyped expressions" and how they are handled. This is a crucial part of Go's type system.

4. **Inferring Go Feature Implementations:** Based on the functions and concepts, I can deduce the Go language features being implemented:
    * **Expression Type Checking:**  The core purpose of the file.
    * **Unary and Binary Operators:**  `unary` and `binary` clearly handle these.
    * **Arithmetic, Bitwise, and Logical Operations:**  The operators handled in `unary` and `binary` directly correspond to these.
    * **Comparisons:** The `comparison` function deals with `==`, `!=`, `<`, `<=`, `>`, `>=`.
    * **Shift Operations:** The `shift` function handles `<<` and `>>`.
    * **Address-of Operator (`&`):** Handled in the `unary` function.
    * **Receive Operator (`<-`):** Also handled in `unary`.
    * **Type Assertions:** The `TypeAssertExpr` case in `exprInternal`.
    * **Constant Folding:** The code performs constant evaluation at compile time.
    * **Implicit Type Conversions:**  `implicitTypeAndValue` handles this.
    * **Handling of Untyped Constants:** A significant part of the code is dedicated to this.

5. **Generating Go Code Examples:** For each inferred feature, I need to create concise Go code examples demonstrating the functionality. This involves thinking about valid and potentially invalid scenarios. I will include the assumed input (the Go code) and the expected output (the type information or an error message).

6. **Considering Command-Line Arguments:**  This part of the request seems less relevant to the provided code snippet itself. The `go/types` package is primarily used programmatically. Command-line arguments would be more applicable to the `go` compiler itself or tools that use `go/types`. I will note this.

7. **Identifying Common Mistakes:**  Based on the type-checking rules enforced in the code, I can identify common errors:
    * Applying operators to incompatible types.
    * Non-addressable operands for the address-of operator (excluding composite literals).
    * Receiving from non-channel types or send-only channels.
    * Invalid shift counts (negative or non-integer).
    * Comparing incomparable types (slices, maps, functions, but comparison with `nil` is allowed).
    * Division by zero.
    * Using generic types or functions without instantiation.
    * Invalid type assertions.

8. **Structuring the Answer:** I will structure the answer logically, following the user's request:
    * **Summary of Functionality:** A high-level overview.
    * **Explanation of Go Features with Examples:** For each feature, provide a code example, assumed input, and output.
    * **Code Reasoning:** Explain *how* the code snippet implements these features. Reference specific functions and logic.
    * **Command-Line Arguments:** Address this by explaining its limited relevance to the snippet.
    * **Common Mistakes:** Provide clear examples of errors.
    * **Conclusion/Summary of Functionality (Part 1):** As requested by the user.

9. **Refinement and Language:** I will ensure the language is clear, concise, and uses correct terminology. I'll avoid overly technical jargon where possible and explain concepts simply. Since the request is in Chinese, the final response needs to be in Chinese.

By following these steps, I can generate a comprehensive and accurate answer to the user's request, covering all the specified aspects. The process involves understanding the code, relating it to Go language features, providing concrete examples, and addressing potential errors.
## go/src/go/types/expr.go (第1部分) 功能归纳

这是 Go 语言 `types` 包中负责 **表达式类型检查** 的一部分代码。其核心功能是遍历抽象语法树 (AST) 中的表达式节点，并根据 Go 语言的类型规则，推断和验证表达式的类型、值（如果是常量）以及是否合法。

**具体功能点包括：**

1. **表达式类型推断：**  代码的核心目标是确定每个表达式的类型。这包括基本类型（如 `int`, `string`, `bool`），复合类型（如 `struct`, `slice`, `map`），以及自定义类型。对于未明确指定类型的表达式（例如常量），会尝试推断其类型。

2. **常量表达式求值：** 如果表达式是常量表达式（其值在编译时可以确定），代码会计算其值，并将其记录下来。这包括对常量进行算术、逻辑和位运算。

3. **运算符类型检查：** 验证运算符的操作数是否具有兼容的类型。例如，加法运算符要求操作数是数字或字符串类型。对于不兼容的类型，会产生编译错误。

4. **类型转换处理：**  处理隐式和显式类型转换。对于某些情况，Go 允许隐式类型转换（例如，将 untyped 的常量赋值给特定类型的变量）。代码会检查这些转换是否合法。

5. **特殊表达式处理：**  针对各种类型的表达式（如一元表达式、二元表达式、调用表达式、索引表达式、切片表达式、类型断言等）进行特定的类型检查和处理。

6. **处理 "untyped" 类型：**  Go 语言中有 "untyped" 的常量和表达式。这段代码会追踪这些 untyped 表达式，并在它们最终被赋值或使用时，确定它们的具体类型。

7. **错误报告：**  如果表达式不符合 Go 语言的类型规则，代码会生成相应的编译错误信息，指出错误的位置和原因。

8. **记录类型和值信息：**  将推断出的类型和常量值信息记录在 `Info.Types` 中，供后续的编译阶段使用。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言 **类型系统** 的核心实现之一，特别是负责 **表达式的静态类型检查**。静态类型检查是编译型语言的关键特性，它能在编译时发现类型错误，提高代码的可靠性和安全性。

**Go 代码举例说明：**

```go
package main

func main() {
	var a int = 10
	var b float64 = 3.14
	var c string = "hello"
	var d bool = true

	_ = a + 5      // 类型推断：int + int = int
	_ = b * 2.0    // 类型推断：float64 * float64 = float64
	_ = c + " world" // 类型推断：string + string = string
	_ = !d         // 类型推断：!bool = bool

	// 假设输入 AST 节点表示表达式 "a + 5"
	// 输入:  e = &ast.BinaryExpr{X: ast.Ident{Name: "a"}, Op: token.ADD, Y: ast.BasicLit{Value: "5", Kind: token.INT}}
	// 假设 check.expr 处理完 "a" 后，x.mode = value, x.typ = int
	// 假设 check.expr 处理完 "5" 后，y.mode = constant_, y.typ = UntypedInt, y.val = 5
	// 输出 (在 check.binary 函数中): x.mode = value, x.typ = int (类型不变)

	// 假设输入 AST 节点表示表达式 "a + b"
	// 输入: e = &ast.BinaryExpr{X: ast.Ident{Name: "a"}, Op: token.ADD, Y: ast.Ident{Name: "b"}}
	// 假设 check.expr 处理完 "a" 后，x.mode = value, x.typ = int
	// 假设 check.expr 处理完 "b" 后，y.mode = value, y.typ = float64
	// 输出 (在 check.binary 函数中): 编译错误，提示 "mismatched types int and float64"

	// 假设输入 AST 节点表示表达式 "10 * 2"
	// 输入: e = &ast.BinaryExpr{X: ast.BasicLit{Value: "10", Kind: token.INT}, Op: token.MUL, Y: ast.BasicLit{Value: "2", Kind: token.INT}}
	// 假设 check.expr 处理完 "10" 后，x.mode = constant_, x.typ = UntypedInt, x.val = 10
	// 假设 check.expr 处理完 "2" 后，y.mode = constant_, y.typ = UntypedInt, y.val = 2
	// 输出 (在 check.binary 函数中): x.mode = constant_, x.typ = UntypedInt, x.val = 20
}
```

**代码推理 (带假设的输入与输出):**

上面的代码示例中，我加入了针对 `check.binary` 函数的推理示例。`check.binary` 函数负责处理二元运算符。

* **假设输入 "a + 5"：** 代码会先分别处理 `a` 和 `5`。`a` 是一个 `int` 类型的变量，`5` 是一个 untyped 的整数常量。在 `check.binary` 中，会进行类型匹配，由于常量可以隐式转换为 `int`，最终表达式的类型会被确定为 `int`。
* **假设输入 "a + b"：** `a` 是 `int`，`b` 是 `float64`。在 `check.binary` 中，类型不匹配，会产生编译错误。
* **假设输入 "10 * 2"：** 两个操作数都是 untyped 的整数常量。`check.binary` 会进行常量计算，得到结果 `20`，类型仍然是 untyped 的整数。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`go/types` 包通常被 `go` 编译器或其他静态分析工具使用。这些工具可能会有自己的命令行参数，用于控制类型检查的行为，例如：

* **`-e`:** 允许编译时报错，即使代码包含错误。
* **`-l`:**  限制并行编译的核心数。
* **与构建标签相关的参数:**  影响哪些代码会被编译和类型检查。

然而，这些参数是由调用 `go/types` 包的工具处理的，而不是直接由 `expr.go` 中的代码处理。

**使用者易犯错的点：**

1. **运算符应用于不兼容的类型：** 这是最常见的错误。例如，尝试将字符串和数字相加，或者对布尔值进行算术运算。

   ```go
   var a int = 10
   var b string = "hello"
   // _ = a + b // 编译错误：invalid operation: a + b (mismatched types int and string)
   ```

2. **不理解 untyped 常量的行为：**  Untyped 常量的类型会根据上下文进行推断。如果上下文不明确，可能会导致意外的类型。

   ```go
   const x = 10 // untyped integer
   var f float32 = x // x 可以隐式转换为 float32
   // var s string = x // 编译错误：cannot convert x (untyped int constant) to string
   ```

3. **位运算应用于非整数类型：** 位运算符（如 `&`, `|`, `^`）只能应用于整数类型。

   ```go
   var b bool = true
   // _ = b & true // 编译错误：invalid operation: b & true (operator & not defined on bool)
   ```

4. **比较不可比较的类型：** 某些类型（如 `slice`, `map`, `func`）只能与 `nil` 进行比较。直接比较两个 slice 或 map 会导致编译错误。

   ```go
   var s1 []int
   var s2 []int
   // _ = s1 == s2 // 编译错误：invalid operation: s1 == s2 (slice can only be compared to nil)
   ```

**总结 (功能归纳 for 第 1 部分):**

`go/src/go/types/expr.go` 的第 1 部分主要负责 Go 语言表达式的 **类型推断、常量求值和运算符类型检查**。它遍历 AST 中的表达式节点，根据 Go 的类型规则，确定表达式的类型、值，并验证其操作的合法性。这是 Go 语言静态类型检查的核心组成部分，旨在在编译时发现类型错误，提高代码质量。它还处理了 untyped 常量的特殊情况，并为后续的编译阶段记录类型信息。

### 提示词
```
这是路径为go/src/go/types/expr.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements typechecking of expressions.

package types

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	. "internal/types/errors"
)

/*
Basic algorithm:

Expressions are checked recursively, top down. Expression checker functions
are generally of the form:

  func f(x *operand, e *ast.Expr, ...)

where e is the expression to be checked, and x is the result of the check.
The check performed by f may fail in which case x.mode == invalid, and
related error messages will have been issued by f.

If a hint argument is present, it is the composite literal element type
of an outer composite literal; it is used to type-check composite literal
elements that have no explicit type specification in the source
(e.g.: []T{{...}, {...}}, the hint is the type T in this case).

All expressions are checked via rawExpr, which dispatches according
to expression kind. Upon returning, rawExpr is recording the types and
constant values for all expressions that have an untyped type (those types
may change on the way up in the expression tree). Usually these are constants,
but the results of comparisons or non-constant shifts of untyped constants
may also be untyped, but not constant.

Untyped expressions may eventually become fully typed (i.e., not untyped),
typically when the value is assigned to a variable, or is used otherwise.
The updateExprType method is used to record this final type and update
the recorded types: the type-checked expression tree is again traversed down,
and the new type is propagated as needed. Untyped constant expression values
that become fully typed must now be representable by the full type (constant
sub-expression trees are left alone except for their roots). This mechanism
ensures that a client sees the actual (run-time) type an untyped value would
have. It also permits type-checking of lhs shift operands "as if the shift
were not present": when updateExprType visits an untyped lhs shift operand
and assigns it its final type, that type must be an integer type, and a
constant lhs must be representable as an integer.

When an expression gets its final type, either on the way out from rawExpr,
on the way down in updateExprType, or at the end of the type checker run,
the type (and constant value, if any) is recorded via Info.Types, if present.
*/

type opPredicates map[token.Token]func(Type) bool

var unaryOpPredicates opPredicates

func init() {
	// Setting unaryOpPredicates in init avoids declaration cycles.
	unaryOpPredicates = opPredicates{
		token.ADD: allNumeric,
		token.SUB: allNumeric,
		token.XOR: allInteger,
		token.NOT: allBoolean,
	}
}

func (check *Checker) op(m opPredicates, x *operand, op token.Token) bool {
	if pred := m[op]; pred != nil {
		if !pred(x.typ) {
			check.errorf(x, UndefinedOp, invalidOp+"operator %s not defined on %s", op, x)
			return false
		}
	} else {
		check.errorf(x, InvalidSyntaxTree, "unknown operator %s", op)
		return false
	}
	return true
}

// opPos returns the position of the operator if x is an operation;
// otherwise it returns the start position of x.
func opPos(x ast.Expr) token.Pos {
	switch op := x.(type) {
	case nil:
		return nopos // don't crash
	case *ast.BinaryExpr:
		return op.OpPos
	default:
		return x.Pos()
	}
}

// opName returns the name of the operation if x is an operation
// that might overflow; otherwise it returns the empty string.
func opName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.BinaryExpr:
		if int(e.Op) < len(op2str2) {
			return op2str2[e.Op]
		}
	case *ast.UnaryExpr:
		if int(e.Op) < len(op2str1) {
			return op2str1[e.Op]
		}
	}
	return ""
}

var op2str1 = [...]string{
	token.XOR: "bitwise complement",
}

// This is only used for operations that may cause overflow.
var op2str2 = [...]string{
	token.ADD: "addition",
	token.SUB: "subtraction",
	token.XOR: "bitwise XOR",
	token.MUL: "multiplication",
	token.SHL: "shift",
}

// The unary expression e may be nil. It's passed in for better error messages only.
func (check *Checker) unary(x *operand, e *ast.UnaryExpr) {
	check.expr(nil, x, e.X)
	if x.mode == invalid {
		return
	}

	op := e.Op
	switch op {
	case token.AND:
		// spec: "As an exception to the addressability
		// requirement x may also be a composite literal."
		if _, ok := ast.Unparen(e.X).(*ast.CompositeLit); !ok && x.mode != variable {
			check.errorf(x, UnaddressableOperand, invalidOp+"cannot take address of %s", x)
			x.mode = invalid
			return
		}
		x.mode = value
		x.typ = &Pointer{base: x.typ}
		return

	case token.ARROW:
		u := coreType(x.typ)
		if u == nil {
			check.errorf(x, InvalidReceive, invalidOp+"cannot receive from %s (no core type)", x)
			x.mode = invalid
			return
		}
		ch, _ := u.(*Chan)
		if ch == nil {
			check.errorf(x, InvalidReceive, invalidOp+"cannot receive from non-channel %s", x)
			x.mode = invalid
			return
		}
		if ch.dir == SendOnly {
			check.errorf(x, InvalidReceive, invalidOp+"cannot receive from send-only channel %s", x)
			x.mode = invalid
			return
		}

		x.mode = commaok
		x.typ = ch.elem
		check.hasCallOrRecv = true
		return

	case token.TILDE:
		// Provide a better error position and message than what check.op below would do.
		if !allInteger(x.typ) {
			check.error(e, UndefinedOp, "cannot use ~ outside of interface or type constraint")
			x.mode = invalid
			return
		}
		check.error(e, UndefinedOp, "cannot use ~ outside of interface or type constraint (use ^ for bitwise complement)")
		op = token.XOR
	}

	if !check.op(unaryOpPredicates, x, op) {
		x.mode = invalid
		return
	}

	if x.mode == constant_ {
		if x.val.Kind() == constant.Unknown {
			// nothing to do (and don't cause an error below in the overflow check)
			return
		}
		var prec uint
		if isUnsigned(x.typ) {
			prec = uint(check.conf.sizeof(x.typ) * 8)
		}
		x.val = constant.UnaryOp(op, x.val, prec)
		x.expr = e
		check.overflow(x, opPos(x.expr))
		return
	}

	x.mode = value
	// x.typ remains unchanged
}

func isShift(op token.Token) bool {
	return op == token.SHL || op == token.SHR
}

func isComparison(op token.Token) bool {
	// Note: tokens are not ordered well to make this much easier
	switch op {
	case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	}
	return false
}

// updateExprType updates the type of x to typ and invokes itself
// recursively for the operands of x, depending on expression kind.
// If typ is still an untyped and not the final type, updateExprType
// only updates the recorded untyped type for x and possibly its
// operands. Otherwise (i.e., typ is not an untyped type anymore,
// or it is the final type for x), the type and value are recorded.
// Also, if x is a constant, it must be representable as a value of typ,
// and if x is the (formerly untyped) lhs operand of a non-constant
// shift, it must be an integer value.
func (check *Checker) updateExprType(x ast.Expr, typ Type, final bool) {
	old, found := check.untyped[x]
	if !found {
		return // nothing to do
	}

	// update operands of x if necessary
	switch x := x.(type) {
	case *ast.BadExpr,
		*ast.FuncLit,
		*ast.CompositeLit,
		*ast.IndexExpr,
		*ast.SliceExpr,
		*ast.TypeAssertExpr,
		*ast.StarExpr,
		*ast.KeyValueExpr,
		*ast.ArrayType,
		*ast.StructType,
		*ast.FuncType,
		*ast.InterfaceType,
		*ast.MapType,
		*ast.ChanType:
		// These expression are never untyped - nothing to do.
		// The respective sub-expressions got their final types
		// upon assignment or use.
		if debug {
			check.dump("%v: found old type(%s): %s (new: %s)", x.Pos(), x, old.typ, typ)
			panic("unreachable")
		}
		return

	case *ast.CallExpr:
		// Resulting in an untyped constant (e.g., built-in complex).
		// The respective calls take care of calling updateExprType
		// for the arguments if necessary.

	case *ast.Ident, *ast.BasicLit, *ast.SelectorExpr:
		// An identifier denoting a constant, a constant literal,
		// or a qualified identifier (imported untyped constant).
		// No operands to take care of.

	case *ast.ParenExpr:
		check.updateExprType(x.X, typ, final)

	case *ast.UnaryExpr:
		// If x is a constant, the operands were constants.
		// The operands don't need to be updated since they
		// never get "materialized" into a typed value. If
		// left in the untyped map, they will be processed
		// at the end of the type check.
		if old.val != nil {
			break
		}
		check.updateExprType(x.X, typ, final)

	case *ast.BinaryExpr:
		if old.val != nil {
			break // see comment for unary expressions
		}
		if isComparison(x.Op) {
			// The result type is independent of operand types
			// and the operand types must have final types.
		} else if isShift(x.Op) {
			// The result type depends only on lhs operand.
			// The rhs type was updated when checking the shift.
			check.updateExprType(x.X, typ, final)
		} else {
			// The operand types match the result type.
			check.updateExprType(x.X, typ, final)
			check.updateExprType(x.Y, typ, final)
		}

	default:
		panic("unreachable")
	}

	// If the new type is not final and still untyped, just
	// update the recorded type.
	if !final && isUntyped(typ) {
		old.typ = under(typ).(*Basic)
		check.untyped[x] = old
		return
	}

	// Otherwise we have the final (typed or untyped type).
	// Remove it from the map of yet untyped expressions.
	delete(check.untyped, x)

	if old.isLhs {
		// If x is the lhs of a shift, its final type must be integer.
		// We already know from the shift check that it is representable
		// as an integer if it is a constant.
		if !allInteger(typ) {
			check.errorf(x, InvalidShiftOperand, invalidOp+"shifted operand %s (type %s) must be integer", x, typ)
			return
		}
		// Even if we have an integer, if the value is a constant we
		// still must check that it is representable as the specific
		// int type requested (was go.dev/issue/22969). Fall through here.
	}
	if old.val != nil {
		// If x is a constant, it must be representable as a value of typ.
		c := operand{old.mode, x, old.typ, old.val, 0}
		check.convertUntyped(&c, typ)
		if c.mode == invalid {
			return
		}
	}

	// Everything's fine, record final type and value for x.
	check.recordTypeAndValue(x, old.mode, typ, old.val)
}

// updateExprVal updates the value of x to val.
func (check *Checker) updateExprVal(x ast.Expr, val constant.Value) {
	if info, ok := check.untyped[x]; ok {
		info.val = val
		check.untyped[x] = info
	}
}

// implicitTypeAndValue returns the implicit type of x when used in a context
// where the target type is expected. If no such implicit conversion is
// possible, it returns a nil Type and non-zero error code.
//
// If x is a constant operand, the returned constant.Value will be the
// representation of x in this context.
func (check *Checker) implicitTypeAndValue(x *operand, target Type) (Type, constant.Value, Code) {
	if x.mode == invalid || isTyped(x.typ) || !isValid(target) {
		return x.typ, nil, 0
	}
	// x is untyped

	if isUntyped(target) {
		// both x and target are untyped
		if m := maxType(x.typ, target); m != nil {
			return m, nil, 0
		}
		return nil, nil, InvalidUntypedConversion
	}

	switch u := under(target).(type) {
	case *Basic:
		if x.mode == constant_ {
			v, code := check.representation(x, u)
			if code != 0 {
				return nil, nil, code
			}
			return target, v, code
		}
		// Non-constant untyped values may appear as the
		// result of comparisons (untyped bool), intermediate
		// (delayed-checked) rhs operands of shifts, and as
		// the value nil.
		switch x.typ.(*Basic).kind {
		case UntypedBool:
			if !isBoolean(target) {
				return nil, nil, InvalidUntypedConversion
			}
		case UntypedInt, UntypedRune, UntypedFloat, UntypedComplex:
			if !isNumeric(target) {
				return nil, nil, InvalidUntypedConversion
			}
		case UntypedString:
			// Non-constant untyped string values are not permitted by the spec and
			// should not occur during normal typechecking passes, but this path is
			// reachable via the AssignableTo API.
			if !isString(target) {
				return nil, nil, InvalidUntypedConversion
			}
		case UntypedNil:
			// Unsafe.Pointer is a basic type that includes nil.
			if !hasNil(target) {
				return nil, nil, InvalidUntypedConversion
			}
			// Preserve the type of nil as UntypedNil: see go.dev/issue/13061.
			return Typ[UntypedNil], nil, 0
		default:
			return nil, nil, InvalidUntypedConversion
		}
	case *Interface:
		if isTypeParam(target) {
			if !underIs(target, func(u Type) bool {
				if u == nil {
					return false
				}
				t, _, _ := check.implicitTypeAndValue(x, u)
				return t != nil
			}) {
				return nil, nil, InvalidUntypedConversion
			}
			// keep nil untyped (was bug go.dev/issue/39755)
			if x.isNil() {
				return Typ[UntypedNil], nil, 0
			}
			break
		}
		// Values must have concrete dynamic types. If the value is nil,
		// keep it untyped (this is important for tools such as go vet which
		// need the dynamic type for argument checking of say, print
		// functions)
		if x.isNil() {
			return Typ[UntypedNil], nil, 0
		}
		// cannot assign untyped values to non-empty interfaces
		if !u.Empty() {
			return nil, nil, InvalidUntypedConversion
		}
		return Default(x.typ), nil, 0
	case *Pointer, *Signature, *Slice, *Map, *Chan:
		if !x.isNil() {
			return nil, nil, InvalidUntypedConversion
		}
		// Keep nil untyped - see comment for interfaces, above.
		return Typ[UntypedNil], nil, 0
	default:
		return nil, nil, InvalidUntypedConversion
	}
	return target, nil, 0
}

// If switchCase is true, the operator op is ignored.
func (check *Checker) comparison(x, y *operand, op token.Token, switchCase bool) {
	// Avoid spurious errors if any of the operands has an invalid type (go.dev/issue/54405).
	if !isValid(x.typ) || !isValid(y.typ) {
		x.mode = invalid
		return
	}

	if switchCase {
		op = token.EQL
	}

	errOp := x  // operand for which error is reported, if any
	cause := "" // specific error cause, if any

	// spec: "In any comparison, the first operand must be assignable
	// to the type of the second operand, or vice versa."
	code := MismatchedTypes
	ok, _ := x.assignableTo(check, y.typ, nil)
	if !ok {
		ok, _ = y.assignableTo(check, x.typ, nil)
	}
	if !ok {
		// Report the error on the 2nd operand since we only
		// know after seeing the 2nd operand whether we have
		// a type mismatch.
		errOp = y
		cause = check.sprintf("mismatched types %s and %s", x.typ, y.typ)
		goto Error
	}

	// check if comparison is defined for operands
	code = UndefinedOp
	switch op {
	case token.EQL, token.NEQ:
		// spec: "The equality operators == and != apply to operands that are comparable."
		switch {
		case x.isNil() || y.isNil():
			// Comparison against nil requires that the other operand type has nil.
			typ := x.typ
			if x.isNil() {
				typ = y.typ
			}
			if !hasNil(typ) {
				// This case should only be possible for "nil == nil".
				// Report the error on the 2nd operand since we only
				// know after seeing the 2nd operand whether we have
				// an invalid comparison.
				errOp = y
				goto Error
			}

		case !Comparable(x.typ):
			errOp = x
			cause = check.incomparableCause(x.typ)
			goto Error

		case !Comparable(y.typ):
			errOp = y
			cause = check.incomparableCause(y.typ)
			goto Error
		}

	case token.LSS, token.LEQ, token.GTR, token.GEQ:
		// spec: The ordering operators <, <=, >, and >= apply to operands that are ordered."
		switch {
		case !allOrdered(x.typ):
			errOp = x
			goto Error
		case !allOrdered(y.typ):
			errOp = y
			goto Error
		}

	default:
		panic("unreachable")
	}

	// comparison is ok
	if x.mode == constant_ && y.mode == constant_ {
		x.val = constant.MakeBool(constant.Compare(x.val, op, y.val))
		// The operands are never materialized; no need to update
		// their types.
	} else {
		x.mode = value
		// The operands have now their final types, which at run-
		// time will be materialized. Update the expression trees.
		// If the current types are untyped, the materialized type
		// is the respective default type.
		check.updateExprType(x.expr, Default(x.typ), true)
		check.updateExprType(y.expr, Default(y.typ), true)
	}

	// spec: "Comparison operators compare two operands and yield
	//        an untyped boolean value."
	x.typ = Typ[UntypedBool]
	return

Error:
	// We have an offending operand errOp and possibly an error cause.
	if cause == "" {
		if isTypeParam(x.typ) || isTypeParam(y.typ) {
			// TODO(gri) should report the specific type causing the problem, if any
			if !isTypeParam(x.typ) {
				errOp = y
			}
			cause = check.sprintf("type parameter %s cannot use operator %s", errOp.typ, op)
		} else {
			// catch-all neither x nor y is a type parameter
			what := compositeKind(errOp.typ)
			if what == "" {
				what = check.sprintf("%s", errOp.typ)
			}
			cause = check.sprintf("operator %s not defined on %s", op, what)
		}
	}
	if switchCase {
		check.errorf(x, code, "invalid case %s in switch on %s (%s)", x.expr, y.expr, cause) // error position always at 1st operand
	} else {
		check.errorf(errOp, code, invalidOp+"%s %s %s (%s)", x.expr, op, y.expr, cause)
	}
	x.mode = invalid
}

// incomparableCause returns a more specific cause why typ is not comparable.
// If there is no more specific cause, the result is "".
func (check *Checker) incomparableCause(typ Type) string {
	switch under(typ).(type) {
	case *Slice, *Signature, *Map:
		return compositeKind(typ) + " can only be compared to nil"
	}
	// see if we can extract a more specific error
	var cause string
	comparableType(typ, true, nil, func(format string, args ...interface{}) {
		cause = check.sprintf(format, args...)
	})
	return cause
}

// If e != nil, it must be the shift expression; it may be nil for non-constant shifts.
func (check *Checker) shift(x, y *operand, e ast.Expr, op token.Token) {
	// TODO(gri) This function seems overly complex. Revisit.

	var xval constant.Value
	if x.mode == constant_ {
		xval = constant.ToInt(x.val)
	}

	if allInteger(x.typ) || isUntyped(x.typ) && xval != nil && xval.Kind() == constant.Int {
		// The lhs is of integer type or an untyped constant representable
		// as an integer. Nothing to do.
	} else {
		// shift has no chance
		check.errorf(x, InvalidShiftOperand, invalidOp+"shifted operand %s must be integer", x)
		x.mode = invalid
		return
	}

	// spec: "The right operand in a shift expression must have integer type
	// or be an untyped constant representable by a value of type uint."

	// Check that constants are representable by uint, but do not convert them
	// (see also go.dev/issue/47243).
	var yval constant.Value
	if y.mode == constant_ {
		// Provide a good error message for negative shift counts.
		yval = constant.ToInt(y.val) // consider -1, 1.0, but not -1.1
		if yval.Kind() == constant.Int && constant.Sign(yval) < 0 {
			check.errorf(y, InvalidShiftCount, invalidOp+"negative shift count %s", y)
			x.mode = invalid
			return
		}

		if isUntyped(y.typ) {
			// Caution: Check for representability here, rather than in the switch
			// below, because isInteger includes untyped integers (was bug go.dev/issue/43697).
			check.representable(y, Typ[Uint])
			if y.mode == invalid {
				x.mode = invalid
				return
			}
		}
	} else {
		// Check that RHS is otherwise at least of integer type.
		switch {
		case allInteger(y.typ):
			if !allUnsigned(y.typ) && !check.verifyVersionf(y, go1_13, invalidOp+"signed shift count %s", y) {
				x.mode = invalid
				return
			}
		case isUntyped(y.typ):
			// This is incorrect, but preserves pre-existing behavior.
			// See also go.dev/issue/47410.
			check.convertUntyped(y, Typ[Uint])
			if y.mode == invalid {
				x.mode = invalid
				return
			}
		default:
			check.errorf(y, InvalidShiftCount, invalidOp+"shift count %s must be integer", y)
			x.mode = invalid
			return
		}
	}

	if x.mode == constant_ {
		if y.mode == constant_ {
			// if either x or y has an unknown value, the result is unknown
			if x.val.Kind() == constant.Unknown || y.val.Kind() == constant.Unknown {
				x.val = constant.MakeUnknown()
				// ensure the correct type - see comment below
				if !isInteger(x.typ) {
					x.typ = Typ[UntypedInt]
				}
				return
			}
			// rhs must be within reasonable bounds in constant shifts
			const shiftBound = 1023 - 1 + 52 // so we can express smallestFloat64 (see go.dev/issue/44057)
			s, ok := constant.Uint64Val(yval)
			if !ok || s > shiftBound {
				check.errorf(y, InvalidShiftCount, invalidOp+"invalid shift count %s", y)
				x.mode = invalid
				return
			}
			// The lhs is representable as an integer but may not be an integer
			// (e.g., 2.0, an untyped float) - this can only happen for untyped
			// non-integer numeric constants. Correct the type so that the shift
			// result is of integer type.
			if !isInteger(x.typ) {
				x.typ = Typ[UntypedInt]
			}
			// x is a constant so xval != nil and it must be of Int kind.
			x.val = constant.Shift(xval, op, uint(s))
			x.expr = e
			check.overflow(x, opPos(x.expr))
			return
		}

		// non-constant shift with constant lhs
		if isUntyped(x.typ) {
			// spec: "If the left operand of a non-constant shift
			// expression is an untyped constant, the type of the
			// constant is what it would be if the shift expression
			// were replaced by its left operand alone.".
			//
			// Delay operand checking until we know the final type
			// by marking the lhs expression as lhs shift operand.
			//
			// Usually (in correct programs), the lhs expression
			// is in the untyped map. However, it is possible to
			// create incorrect programs where the same expression
			// is evaluated twice (via a declaration cycle) such
			// that the lhs expression type is determined in the
			// first round and thus deleted from the map, and then
			// not found in the second round (double insertion of
			// the same expr node still just leads to one entry for
			// that node, and it can only be deleted once).
			// Be cautious and check for presence of entry.
			// Example: var e, f = int(1<<""[f]) // go.dev/issue/11347
			if info, found := check.untyped[x.expr]; found {
				info.isLhs = true
				check.untyped[x.expr] = info
			}
			// keep x's type
			x.mode = value
			return
		}
	}

	// non-constant shift - lhs must be an integer
	if !allInteger(x.typ) {
		check.errorf(x, InvalidShiftOperand, invalidOp+"shifted operand %s must be integer", x)
		x.mode = invalid
		return
	}

	x.mode = value
}

var binaryOpPredicates opPredicates

func init() {
	// Setting binaryOpPredicates in init avoids declaration cycles.
	binaryOpPredicates = opPredicates{
		token.ADD: allNumericOrString,
		token.SUB: allNumeric,
		token.MUL: allNumeric,
		token.QUO: allNumeric,
		token.REM: allInteger,

		token.AND:     allInteger,
		token.OR:      allInteger,
		token.XOR:     allInteger,
		token.AND_NOT: allInteger,

		token.LAND: allBoolean,
		token.LOR:  allBoolean,
	}
}

// If e != nil, it must be the binary expression; it may be nil for non-constant expressions
// (when invoked for an assignment operation where the binary expression is implicit).
func (check *Checker) binary(x *operand, e ast.Expr, lhs, rhs ast.Expr, op token.Token, opPos token.Pos) {
	var y operand

	check.expr(nil, x, lhs)
	check.expr(nil, &y, rhs)

	if x.mode == invalid {
		return
	}
	if y.mode == invalid {
		x.mode = invalid
		x.expr = y.expr
		return
	}

	if isShift(op) {
		check.shift(x, &y, e, op)
		return
	}

	check.matchTypes(x, &y)
	if x.mode == invalid {
		return
	}

	if isComparison(op) {
		check.comparison(x, &y, op, false)
		return
	}

	if !Identical(x.typ, y.typ) {
		// only report an error if we have valid types
		// (otherwise we had an error reported elsewhere already)
		if isValid(x.typ) && isValid(y.typ) {
			var posn positioner = x
			if e != nil {
				posn = e
			}
			if e != nil {
				check.errorf(posn, MismatchedTypes, invalidOp+"%s (mismatched types %s and %s)", e, x.typ, y.typ)
			} else {
				check.errorf(posn, MismatchedTypes, invalidOp+"%s %s= %s (mismatched types %s and %s)", lhs, op, rhs, x.typ, y.typ)
			}
		}
		x.mode = invalid
		return
	}

	if !check.op(binaryOpPredicates, x, op) {
		x.mode = invalid
		return
	}

	if op == token.QUO || op == token.REM {
		// check for zero divisor
		if (x.mode == constant_ || allInteger(x.typ)) && y.mode == constant_ && constant.Sign(y.val) == 0 {
			check.error(&y, DivByZero, invalidOp+"division by zero")
			x.mode = invalid
			return
		}

		// check for divisor underflow in complex division (see go.dev/issue/20227)
		if x.mode == constant_ && y.mode == constant_ && isComplex(x.typ) {
			re, im := constant.Real(y.val), constant.Imag(y.val)
			re2, im2 := constant.BinaryOp(re, token.MUL, re), constant.BinaryOp(im, token.MUL, im)
			if constant.Sign(re2) == 0 && constant.Sign(im2) == 0 {
				check.error(&y, DivByZero, invalidOp+"division by zero")
				x.mode = invalid
				return
			}
		}
	}

	if x.mode == constant_ && y.mode == constant_ {
		// if either x or y has an unknown value, the result is unknown
		if x.val.Kind() == constant.Unknown || y.val.Kind() == constant.Unknown {
			x.val = constant.MakeUnknown()
			// x.typ is unchanged
			return
		}
		// force integer division of integer operands
		if op == token.QUO && isInteger(x.typ) {
			op = token.QUO_ASSIGN
		}
		x.val = constant.BinaryOp(x.val, op, y.val)
		x.expr = e
		check.overflow(x, opPos)
		return
	}

	x.mode = value
	// x.typ is unchanged
}

// matchTypes attempts to convert any untyped types x and y such that they match.
// If an error occurs, x.mode is set to invalid.
func (check *Checker) matchTypes(x, y *operand) {
	// mayConvert reports whether the operands x and y may
	// possibly have matching types after converting one
	// untyped operand to the type of the other.
	// If mayConvert returns true, we try to convert the
	// operands to each other's types, and if that fails
	// we report a conversion failure.
	// If mayConvert returns false, we continue without an
	// attempt at conversion, and if the operand types are
	// not compatible, we report a type mismatch error.
	mayConvert := func(x, y *operand) bool {
		// If both operands are typed, there's no need for an implicit conversion.
		if isTyped(x.typ) && isTyped(y.typ) {
			return false
		}
		// An untyped operand may convert to its default type when paired with an empty interface
		// TODO(gri) This should only matter for comparisons (the only binary operation that is
		//           valid with interfaces), but in that case the assignability check should take
		//           care of the conversion. Verify and possibly eliminate this extra test.
		if isNonTypeParamInterface(x.typ) || isNonTypeParamInterface(y.typ) {
			return true
		}
		// A boolean type can only convert to another boolean type.
		if allBoolean(x.typ) != allBoolean(y.typ) {
			return false
		}
		// A string type can only convert to another string type.
		if allString(x.typ) != allString(y.typ) {
			return false
		}
		// Untyped nil can only convert to a type that has a nil.
		if x.isNil() {
			return hasNil(y.typ)
		}
		if y.isNil() {
			return hasNil(x.typ)
		}
		// An untyped operand cannot convert to a pointer.
		// TODO(gri) generalize to type parameters
		if isPointer(x.typ) || isPointer(y.typ) {
			return false
		}
		return true
	}

	if mayConvert(x, y) {
		check.convertUntyped(x, y.typ)
		if x.mode == invalid {
			return
		}
		check.convertUntyped(y, x.typ)
		if y.mode == invalid {
			x.mode = invalid
			return
		}
	}
}

// exprKind describes the kind of an expression; the kind
// determines if an expression is valid in 'statement context'.
type exprKind int

const (
	conversion exprKind = iota
	expression
	statement
)

// target represent the (signature) type and description of the LHS
// variable of an assignment, or of a function result variable.
type target struct {
	sig  *Signature
	desc string
}

// newTarget creates a new target for the given type and description.
// The result is nil if typ is not a signature.
func newTarget(typ Type, desc string) *target {
	if typ != nil {
		if sig, _ := under(typ).(*Signature); sig != nil {
			return &target{sig, desc}
		}
	}
	return nil
}

// rawExpr typechecks expression e and initializes x with the expression
// value or type. If an error occurred, x.mode is set to invalid.
// If a non-nil target T is given and e is a generic function,
// T is used to infer the type arguments for e.
// If hint != nil, it is the type of a composite literal element.
// If allowGeneric is set, the operand type may be an uninstantiated
// parameterized type or function value.
func (check *Checker) rawExpr(T *target, x *operand, e ast.Expr, hint Type, allowGeneric bool) exprKind {
	if check.conf._Trace {
		check.trace(e.Pos(), "-- expr %s", e)
		check.indent++
		defer func() {
			check.indent--
			check.trace(e.Pos(), "=> %s", x)
		}()
	}

	kind := check.exprInternal(T, x, e, hint)

	if !allowGeneric {
		check.nonGeneric(T, x)
	}

	check.record(x)

	return kind
}

// If x is a generic type, or a generic function whose type arguments cannot be inferred
// from a non-nil target T, nonGeneric reports an error and invalidates x.mode and x.typ.
// Otherwise it leaves x alone.
func (check *Checker) nonGeneric(T *target, x *operand) {
	if x.mode == invalid || x.mode == novalue {
		return
	}
	var what string
	switch t := x.typ.(type) {
	case *Alias, *Named:
		if isGeneric(t) {
			what = "type"
		}
	case *Signature:
		if t.tparams != nil {
			if enableReverseTypeInference && T != nil {
				check.funcInst(T, x.Pos(), x, nil, true)
				return
			}
			what = "function"
		}
	}
	if what != "" {
		check.errorf(x.expr, WrongTypeArgCount, "cannot use generic %s %s without instantiation", what, x.expr)
		x.mode = invalid
		x.typ = Typ[Invalid]
	}
}

// exprInternal contains the core of type checking of expressions.
// Must only be called by rawExpr.
// (See rawExpr for an explanation of the parameters.)
func (check *Checker) exprInternal(T *target, x *operand, e ast.Expr, hint Type) exprKind {
	// make sure x has a valid state in case of bailout
	// (was go.dev/issue/5770)
	x.mode = invalid
	x.typ = Typ[Invalid]

	switch e := e.(type) {
	case *ast.BadExpr:
		goto Error // error was reported before

	case *ast.Ident:
		check.ident(x, e, nil, false)

	case *ast.Ellipsis:
		// ellipses are handled explicitly where they are legal
		// (array composite literals and parameter lists)
		check.error(e, BadDotDotDotSyntax, "invalid use of '...'")
		goto Error

	case *ast.BasicLit:
		check.basicLit(x, e)
		if x.mode == invalid {
			goto Error
		}

	case *ast.FuncLit:
		check.funcLit(x, e)
		if x.mode == invalid {
			goto Error
		}

	case *ast.CompositeLit:
		check.compositeLit(x, e, hint)
		if x.mode == invalid {
			goto Error
		}

	case *ast.ParenExpr:
		// type inference doesn't go past parentheses (target type T = nil)
		kind := check.rawExpr(nil, x, e.X, nil, false)
		x.expr = e
		return kind

	case *ast.SelectorExpr:
		check.selector(x, e, nil, false)

	case *ast.IndexExpr, *ast.IndexListExpr:
		ix := unpackIndexedExpr(e)
		if check.indexExpr(x, ix) {
			if !enableReverseTypeInference {
				T = nil
			}
			check.funcInst(T, e.Pos(), x, ix, true)
		}
		if x.mode == invalid {
			goto Error
		}

	case *ast.SliceExpr:
		check.sliceExpr(x, e)
		if x.mode == invalid {
			goto Error
		}

	case *ast.TypeAssertExpr:
		check.expr(nil, x, e.X)
		if x.mode == invalid {
			goto Error
		}
		// x.(type) expressions are handled explicitly in type switches
		if e.Type == nil {
			// Don't use InvalidSyntaxTree because this can occur in the AST produced by
			// go/parser.
			check.error(e, BadTypeKeyword, "use of .(type) outside type switch")
			goto Error
		}
		if isTypeParam(x.typ) {
			check.errorf(x, InvalidAssert, invalidOp+"cannot use type assertion on type parameter value %s", x)
			goto Error
		}
		if _, ok := under(x.typ).(*Interface); !ok {
			check.errorf(x, InvalidAssert, invalidOp+"%s is not an interface", x)
			goto Error
		}
		T := check.varType(e.Type)
		if !isValid(T) {
			goto Error
		}
		check.typeAssertion(e, x, T, false)
		x.mode = commaok
		x.typ = T

	case *ast.CallExpr:
		return check.callExpr(x, e)

	case *ast.StarExpr:
		check.exprOrType(x, e.X, false)
		switch x.mode {
		case invalid:
			goto Error
		case typexpr:
			check.validVarType(e.X, x.typ)
			x.typ = &Pointer{base: x.typ}
		default:
			var base Type
			if !underIs(x.typ, func(u Type) bool {
				p, _ := u.(*Pointer)
				if p == nil {
					check.errorf(x, InvalidIndirection, invalidOp+"cannot indirect %s", x)
					return false
				}
				if base != nil && !Identical(p.base, base) {
					check.errorf(x, InvalidIndirection, invalidOp+"pointers of %s must have identical base types", x)
					return false
				}
				base = p.base
				return true
```