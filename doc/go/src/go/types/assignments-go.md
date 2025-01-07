Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a functional description, potential Go feature implementation, code examples, handling of command-line arguments (if any), and common pitfalls related to the provided `assignments.go` code.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the code, looking for prominent keywords and structural elements:
    * Package declaration (`package types`) - Indicates the code belongs to the `types` package.
    * Import statements - Show dependencies like `fmt`, `go/ast`, `internal/types/errors`, and `strings`.
    * Function definitions -  `assignment`, `initConst`, `initVar`, `lhsVar`, `assignVar`, `operandTypes`, `varTypes`, `typesSummary`, `measure`, `assignError`, `returnError`, `initVars`, `assignVars`, `shortVarDecl`.
    * Comments - Provide hints about the purpose of the code, especially the initial comments about initialization and assignment checks.

3. **Focus on Key Functions:**  The function names are quite descriptive. Prioritize understanding the core functions:
    * `assignment`: This seems to be the central function for checking if a value (`x`) can be assigned to a type (`T`). The `context` string provides information about where the assignment occurs.
    * `initConst`, `initVar`: These likely handle initialization scenarios for constants and variables, respectively.
    * `lhsVar`: This probably deals with analyzing the left-hand side of an assignment. The comment about not counting an identifier as a "use" is important.
    * `assignVar`: This function checks the validity of an assignment.
    * `initVars`, `assignVars`: These functions seem to handle assignments involving multiple variables and expressions.
    * `shortVarDecl`: This clearly relates to short variable declarations (`:=`).

4. **Analyze Individual Function Logic (Iterative Process):** Go through each important function, focusing on the logic and what it does:
    * **`assignment`:**
        * Handles different modes of the assigned value (`x.mode`).
        * Deals with untyped constants and their default types.
        * Checks for assignability using `x.assignableTo`.
        * Handles the blank identifier (`_`).
    * **`initConst`:** Ensures the right-hand side is a constant and calls `assignment`.
    * **`initVar`:** Handles variable initialization, including inferring the type if not explicitly provided.
    * **`lhsVar`:**  Specifically handles the blank identifier and avoids counting a variable on the LHS as a regular use. It checks if the LHS is addressable or a map index.
    * **`assignVar`:**  Calls `lhsVar` to get the LHS type and then uses `assignment`.
    * **`initVars`, `assignVars`:** Handles the logic for multiple assignments, including checking for assignment mismatches and handling function calls returning multiple values. The distinction between `initVars` and `assignVars` seems to be initialization vs. later assignment.
    * **`shortVarDecl`:** Handles the specifics of `:=` declarations, including checking for redeclarations and declaring new variables in the correct scope.

5. **Infer Go Feature Implementation:** Based on the function names and logic, connect the code to specific Go language features:
    * **Type Checking:** The core purpose is clearly type checking during assignments and initializations.
    * **Constant and Variable Declarations:**  `initConst`, `initVar`, and `shortVarDecl` directly relate to these.
    * **Assignment Statements:** `assignVar` and `assignVars` are about general assignment.
    * **Short Variable Declarations (`:=`):**  `shortVarDecl` is specifically for this.
    * **Multiple Return Values:** The logic in `initVars` and `assignVars` dealing with function calls and multiple expressions suggests handling functions that return multiple values.
    * **Blank Identifier:**  The special handling of `_` in `lhsVar` and `assignment` is relevant.
    * **Untyped Constants:** The logic in `assignment` about default types directly relates to how Go handles untyped constants.

6. **Construct Go Code Examples:**  Create simple, illustrative examples for the inferred features:
    * **Basic Assignment:** Show valid and invalid assignments.
    * **Short Variable Declaration:**  Demonstrate its usage and type inference.
    * **Multiple Return Values:** Example of a function returning multiple values and how they are assigned.
    * **Blank Identifier:**  Show its usage on the LHS.
    * **Untyped Constants:** Illustrate how untyped constants are assigned to different types.

7. **Address Command-Line Arguments:**  Carefully review the code and comments for any indication of command-line argument processing. The initial comments mention `"go test -run=Generate -write=all"`, but this is related to *generating* this code, not the runtime behavior of the `types` package itself. Therefore, conclude that this specific code snippet doesn't directly handle command-line arguments in its normal operation.

8. **Identify Common Pitfalls:**  Think about common errors developers make when dealing with assignments and declarations in Go:
    * **Assignment Mismatches:** Incorrect number of values on the left and right sides.
    * **Type Mismatches:** Assigning values of incompatible types.
    * **Using `nil` Incorrectly:**  Especially with untyped `nil`.
    * **Redeclaring Variables with `:=`:**  Understanding the scope and when `:=` creates a new variable vs. assigns to an existing one.
    * **Assigning to Unaddressable Values:**  Understanding what can be on the LHS of an assignment.

9. **Structure the Answer:** Organize the findings into the requested sections: functions, feature implementation, code examples, command-line arguments, and common mistakes. Use clear and concise language, providing explanations for the code examples.

10. **Review and Refine:**  Read through the answer, ensuring accuracy, clarity, and completeness. Check that the code examples are correct and illustrate the intended points. Ensure that the explanation of the Go features aligns with the code's logic.

This systematic approach, starting with a broad overview and then diving into specific details, helps in effectively understanding and explaining complex code snippets like the one provided. The iterative process of analyzing functions and then connecting them to higher-level Go features is key.
这段代码是 Go 语言 `go/types` 包中 `assignments.go` 文件的一部分，主要负责实现 Go 语言中**赋值操作**和**初始化操作**的类型检查。

**核心功能概览:**

* **`assignment(x *operand, T Type, context string)`:**  这是核心函数，用于检查一个操作数 `x` 是否可以赋值给类型 `T` 的变量。它会处理隐式类型转换（特别是针对 untyped 常量），并根据不同的场景（`context`）给出详细的错误信息。
* **`initConst(lhs *Const, x *operand)`:**  检查常量声明的初始化，确保右侧 `x` 是一个常量，并进行类型赋值检查。
* **`initVar(lhs *Var, x *operand, context string)`:** 检查变量声明的初始化，如果左侧变量 `lhs` 没有类型，则会尝试推断类型。
* **`lhsVar(lhs ast.Expr) Type`:**  检查赋值语句左侧的表达式 `lhs` 是否有效，并返回其类型。它会特殊处理空白标识符 `_`。
* **`assignVar(lhs, rhs ast.Expr, x *operand, context string)`:** 检查赋值语句 `lhs = rhs` 的类型是否匹配。
* **`initVars(lhs []*Var, orig_rhs []ast.Expr, returnStmt ast.Stmt)`:** 检查多个变量的初始化，通常用于函数返回值的赋值。
* **`assignVars(lhs, orig_rhs []ast.Expr)`:** 检查多个变量的赋值操作。
* **`shortVarDecl(pos positioner, lhs, rhs []ast.Expr)`:** 处理短变量声明 `:=`，包括类型推断和作用域管理。
* **辅助函数:**  还包含一些辅助函数，如 `operandTypes`, `varTypes`, `typesSummary`, `assignError`, `returnError` 等，用于组织和格式化类型信息，以及生成更友好的错误消息。

**推断的 Go 语言功能实现：类型检查和赋值**

这段代码是 Go 语言类型系统中至关重要的一部分，它确保了程序在编译时能够检测到类型不匹配的赋值错误，保证了程序的类型安全。 它实现了以下 Go 语言核心功能：

1. **基本赋值语句的类型检查:** 检查能否将一个表达式的值赋给一个指定类型的变量。
2. **常量和变量的初始化:**  检查声明时提供的初始值是否与声明的类型兼容。
3. **短变量声明 (`:=`) 的类型推断和检查:**  允许根据右侧表达式的类型自动推断左侧变量的类型，并进行类型检查。
4. **多重赋值:**  支持将一个返回多个值的函数调用结果赋值给多个变量。
5. **空白标识符 (`_`) 的特殊处理:**  允许将任何值赋给空白标识符，但不做任何实际存储。
6. **Untyped 常量的处理:**  当将 untyped 常量赋值给特定类型的变量时，会尝试进行隐式类型转换。
7. **函数返回值的赋值:**  检查函数返回值的数量和类型是否与接收返回值的变量匹配。

**Go 代码举例说明:**

```go
package main

func main() {
	var i int = 10        // initVar 的典型场景
	j := 20              // shortVarDecl 的典型场景
	var k float64 = 3.14  // initVar 的典型场景

	i = j                 // assignVar 的典型场景，int 可以赋值 int
	// i = k              // 编译错误：assignVar 检测到类型不匹配

	_, err := someFunction() // lhsVar 特殊处理空白标识符，initVars 的场景
	if err != nil {
		println("Error occurred")
	}

	const pi = 3.14159      // initConst 的典型场景
	// const str string = 123 // 编译错误：initConst 检测到类型不匹配

	var a interface{} = 10 // assignment 处理接口类型的赋值

	// 多重赋值
	x, y := multiReturn()  // initVars 或 assignVars 的场景

	println(i, j, k, pi, a, x, y)
}

func someFunction() (int, error) {
	return 1, nil
}

func multiReturn() (int, string) {
	return 100, "hello"
}
```

**假设输入与输出（`assignment` 函数为例）:**

假设我们正在检查 `i = j` 这个赋值语句，其中 `i` 是 `int` 类型，`j` 是 `int` 类型的操作数。

**输入:**

* `x`: 一个表示 `j` 的 `operand` 结构体，其类型为 `int`。
* `T`: 表示 `i` 的 `Type`，即 `int` 类型。
* `context`: 字符串 "assignment"。

**预期输出:**

`assignment` 函数会检查 `x.typ` (int) 是否可以赋值给 `T` (int)。由于类型匹配，函数会正常返回，不会修改 `x.mode`。

**假设输入与输出（`assignment` 函数，类型不匹配为例）:**

假设我们正在检查 `i = k` 这个赋值语句，其中 `i` 是 `int` 类型，`k` 是 `float64` 类型的操作数。

**输入:**

* `x`: 一个表示 `k` 的 `operand` 结构体，其类型为 `float64`。
* `T`: 表示 `i` 的 `Type`，即 `int` 类型。
* `context`: 字符串 "assignment"。

**预期输出:**

`assignment` 函数会检查 `x.typ` (float64) 是否可以赋值给 `T` (int)。由于类型不匹配，函数会调用 `check.errorf` 报告错误，并将 `x.mode` 设置为 `invalid`。  编译器会输出类似 "cannot use k (variable of type float64) as int value in assignment" 的错误信息。

**命令行参数处理:**

这段代码本身并不直接处理命令行参数。它是 `go/types` 包的一部分，用于 Go 语言的编译过程。命令行参数的处理通常发生在 `go` 命令本身以及相关的构建工具中。

**使用者易犯错的点:**

1. **赋值类型不匹配:**  这是最常见的错误。尝试将一种类型的值赋给不兼容的类型的变量，例如将 `string` 赋值给 `int` 变量。

   ```go
   var count int
   name := "Alice"
   // count = name // 编译错误：cannot use name (variable of type string) as int value in assignment
   ```

2. **短变量声明的重复定义:** 在同一个作用域内，使用 `:=` 声明一个已经存在的变量，除非是多重赋值的一部分，并且至少有一个新的变量被声明。

   ```go
   count := 10
   // count := 20 // 编译错误：no new variables on left side of :=
   count, err := someFunction() // 合法，因为 err 是新变量
   ```

3. **未初始化变量的使用:** 虽然 Go 语言有默认的零值，但在某些情况下，依赖未显式初始化的变量可能会导致逻辑错误。 类型检查器本身不会直接报错，但良好的编程实践是始终初始化变量。

4. **对只接收通道进行赋值:**  尝试将值发送到只接收 (receive-only) 的通道。

   ```go
   ch := make(<-chan int)
   // ch <- 10 // 编译错误：Invalid send to receive-only channel
   ```

5. **对 `nil` 切片或 `nil` map 进行赋值操作:**  虽然可以声明 `nil` 切片和 `nil` map，但在未进行 `make` 初始化的情况下直接赋值会导致运行时 panic。类型检查器会检查赋值的类型，但不会在编译时捕捉到这种潜在的运行时错误。

   ```go
   var s []int
   // s[0] = 1 // 运行时 panic: index out of range [0] with length 0

   var m map[string]int
   // m["key"] = 10 // 运行时 panic: assignment to entry in nil map
   ```

总而言之，`go/src/go/types/assignments.go` 这部分代码是 Go 语言类型检查的核心组件，它通过静态分析来保证赋值操作的类型安全，帮助开发者在编译阶段发现潜在的类型错误，从而提高代码的可靠性。

Prompt: 
```
这是路径为go/src/go/types/assignments.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Code generated by "go test -run=Generate -write=all"; DO NOT EDIT.
// Source: ../../cmd/compile/internal/types2/assignments.go

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements initialization and assignment checks.

package types

import (
	"fmt"
	"go/ast"
	. "internal/types/errors"
	"strings"
)

// assignment reports whether x can be assigned to a variable of type T,
// if necessary by attempting to convert untyped values to the appropriate
// type. context describes the context in which the assignment takes place.
// Use T == nil to indicate assignment to an untyped blank identifier.
// If the assignment check fails, x.mode is set to invalid.
func (check *Checker) assignment(x *operand, T Type, context string) {
	check.singleValue(x)

	switch x.mode {
	case invalid:
		return // error reported before
	case nilvalue:
		assert(isTypes2)
		// ok
	case constant_, variable, mapindex, value, commaok, commaerr:
		// ok
	default:
		// we may get here because of other problems (go.dev/issue/39634, crash 12)
		// TODO(gri) do we need a new "generic" error code here?
		check.errorf(x, IncompatibleAssign, "cannot assign %s to %s in %s", x, T, context)
		x.mode = invalid
		return
	}

	if isUntyped(x.typ) {
		target := T
		// spec: "If an untyped constant is assigned to a variable of interface
		// type or the blank identifier, the constant is first converted to type
		// bool, rune, int, float64, complex128 or string respectively, depending
		// on whether the value is a boolean, rune, integer, floating-point,
		// complex, or string constant."
		if isTypes2 {
			if x.isNil() {
				if T == nil {
					check.errorf(x, UntypedNilUse, "use of untyped nil in %s", context)
					x.mode = invalid
					return
				}
			} else if T == nil || isNonTypeParamInterface(T) {
				target = Default(x.typ)
			}
		} else { // go/types
			if T == nil || isNonTypeParamInterface(T) {
				if T == nil && x.typ == Typ[UntypedNil] {
					check.errorf(x, UntypedNilUse, "use of untyped nil in %s", context)
					x.mode = invalid
					return
				}
				target = Default(x.typ)
			}
		}
		newType, val, code := check.implicitTypeAndValue(x, target)
		if code != 0 {
			msg := check.sprintf("cannot use %s as %s value in %s", x, target, context)
			switch code {
			case TruncatedFloat:
				msg += " (truncated)"
			case NumericOverflow:
				msg += " (overflows)"
			default:
				code = IncompatibleAssign
			}
			check.error(x, code, msg)
			x.mode = invalid
			return
		}
		if val != nil {
			x.val = val
			check.updateExprVal(x.expr, val)
		}
		if newType != x.typ {
			x.typ = newType
			check.updateExprType(x.expr, newType, false)
		}
	}
	// x.typ is typed

	// A generic (non-instantiated) function value cannot be assigned to a variable.
	if sig, _ := under(x.typ).(*Signature); sig != nil && sig.TypeParams().Len() > 0 {
		check.errorf(x, WrongTypeArgCount, "cannot use generic function %s without instantiation in %s", x, context)
		x.mode = invalid
		return
	}

	// spec: "If a left-hand side is the blank identifier, any typed or
	// non-constant value except for the predeclared identifier nil may
	// be assigned to it."
	if T == nil {
		return
	}

	cause := ""
	if ok, code := x.assignableTo(check, T, &cause); !ok {
		if cause != "" {
			check.errorf(x, code, "cannot use %s as %s value in %s: %s", x, T, context, cause)
		} else {
			check.errorf(x, code, "cannot use %s as %s value in %s", x, T, context)
		}
		x.mode = invalid
	}
}

func (check *Checker) initConst(lhs *Const, x *operand) {
	if x.mode == invalid || !isValid(x.typ) || !isValid(lhs.typ) {
		if lhs.typ == nil {
			lhs.typ = Typ[Invalid]
		}
		return
	}

	// rhs must be a constant
	if x.mode != constant_ {
		check.errorf(x, InvalidConstInit, "%s is not constant", x)
		if lhs.typ == nil {
			lhs.typ = Typ[Invalid]
		}
		return
	}
	assert(isConstType(x.typ))

	// If the lhs doesn't have a type yet, use the type of x.
	if lhs.typ == nil {
		lhs.typ = x.typ
	}

	check.assignment(x, lhs.typ, "constant declaration")
	if x.mode == invalid {
		return
	}

	lhs.val = x.val
}

// initVar checks the initialization lhs = x in a variable declaration.
// If lhs doesn't have a type yet, it is given the type of x,
// or Typ[Invalid] in case of an error.
// If the initialization check fails, x.mode is set to invalid.
func (check *Checker) initVar(lhs *Var, x *operand, context string) {
	if x.mode == invalid || !isValid(x.typ) || !isValid(lhs.typ) {
		if lhs.typ == nil {
			lhs.typ = Typ[Invalid]
		}
		x.mode = invalid
		return
	}

	// If lhs doesn't have a type yet, use the type of x.
	if lhs.typ == nil {
		typ := x.typ
		if isUntyped(typ) {
			// convert untyped types to default types
			if typ == Typ[UntypedNil] {
				check.errorf(x, UntypedNilUse, "use of untyped nil in %s", context)
				lhs.typ = Typ[Invalid]
				x.mode = invalid
				return
			}
			typ = Default(typ)
		}
		lhs.typ = typ
	}

	check.assignment(x, lhs.typ, context)
}

// lhsVar checks a lhs variable in an assignment and returns its type.
// lhsVar takes care of not counting a lhs identifier as a "use" of
// that identifier. The result is nil if it is the blank identifier,
// and Typ[Invalid] if it is an invalid lhs expression.
func (check *Checker) lhsVar(lhs ast.Expr) Type {
	// Determine if the lhs is a (possibly parenthesized) identifier.
	ident, _ := ast.Unparen(lhs).(*ast.Ident)

	// Don't evaluate lhs if it is the blank identifier.
	if ident != nil && ident.Name == "_" {
		check.recordDef(ident, nil)
		return nil
	}

	// If the lhs is an identifier denoting a variable v, this reference
	// is not a 'use' of v. Remember current value of v.used and restore
	// after evaluating the lhs via check.expr.
	var v *Var
	var v_used bool
	if ident != nil {
		if obj := check.lookup(ident.Name); obj != nil {
			// It's ok to mark non-local variables, but ignore variables
			// from other packages to avoid potential race conditions with
			// dot-imported variables.
			if w, _ := obj.(*Var); w != nil && w.pkg == check.pkg {
				v = w
				v_used = v.used
			}
		}
	}

	var x operand
	check.expr(nil, &x, lhs)

	if v != nil {
		v.used = v_used // restore v.used
	}

	if x.mode == invalid || !isValid(x.typ) {
		return Typ[Invalid]
	}

	// spec: "Each left-hand side operand must be addressable, a map index
	// expression, or the blank identifier. Operands may be parenthesized."
	switch x.mode {
	case invalid:
		return Typ[Invalid]
	case variable, mapindex:
		// ok
	default:
		if sel, ok := x.expr.(*ast.SelectorExpr); ok {
			var op operand
			check.expr(nil, &op, sel.X)
			if op.mode == mapindex {
				check.errorf(&x, UnaddressableFieldAssign, "cannot assign to struct field %s in map", ExprString(x.expr))
				return Typ[Invalid]
			}
		}
		check.errorf(&x, UnassignableOperand, "cannot assign to %s (neither addressable nor a map index expression)", x.expr)
		return Typ[Invalid]
	}

	return x.typ
}

// assignVar checks the assignment lhs = rhs (if x == nil), or lhs = x (if x != nil).
// If x != nil, it must be the evaluation of rhs (and rhs will be ignored).
// If the assignment check fails and x != nil, x.mode is set to invalid.
func (check *Checker) assignVar(lhs, rhs ast.Expr, x *operand, context string) {
	T := check.lhsVar(lhs) // nil if lhs is _
	if !isValid(T) {
		if x != nil {
			x.mode = invalid
		} else {
			check.use(rhs)
		}
		return
	}

	if x == nil {
		var target *target
		// avoid calling ExprString if not needed
		if T != nil {
			if _, ok := under(T).(*Signature); ok {
				target = newTarget(T, ExprString(lhs))
			}
		}
		x = new(operand)
		check.expr(target, x, rhs)
	}

	if T == nil && context == "assignment" {
		context = "assignment to _ identifier"
	}
	check.assignment(x, T, context)
}

// operandTypes returns the list of types for the given operands.
func operandTypes(list []*operand) (res []Type) {
	for _, x := range list {
		res = append(res, x.typ)
	}
	return res
}

// varTypes returns the list of types for the given variables.
func varTypes(list []*Var) (res []Type) {
	for _, x := range list {
		res = append(res, x.typ)
	}
	return res
}

// typesSummary returns a string of the form "(t1, t2, ...)" where the
// ti's are user-friendly string representations for the given types.
// If variadic is set and the last type is a slice, its string is of
// the form "...E" where E is the slice's element type.
// If hasDots is set, the last argument string is of the form "T..."
// where T is the last type.
// Only one of variadic and hasDots may be set.
func (check *Checker) typesSummary(list []Type, variadic, hasDots bool) string {
	assert(!(variadic && hasDots))
	var res []string
	for i, t := range list {
		var s string
		switch {
		case t == nil:
			fallthrough // should not happen but be cautious
		case !isValid(t):
			s = "unknown type"
		case isUntyped(t): // => *Basic
			if isNumeric(t) {
				// Do not imply a specific type requirement:
				// "have number, want float64" is better than
				// "have untyped int, want float64" or
				// "have int, want float64".
				s = "number"
			} else {
				// If we don't have a number, omit the "untyped" qualifier
				// for compactness.
				s = strings.Replace(t.(*Basic).name, "untyped ", "", -1)
			}
		default:
			s = check.sprintf("%s", t)
		}
		// handle ... parameters/arguments
		if i == len(list)-1 {
			switch {
			case variadic:
				// In correct code, the parameter type is a slice, but be careful.
				if t, _ := t.(*Slice); t != nil {
					s = check.sprintf("%s", t.elem)
				}
				s = "..." + s
			case hasDots:
				s += "..."
			}
		}
		res = append(res, s)
	}
	return "(" + strings.Join(res, ", ") + ")"
}

func measure(x int, unit string) string {
	if x != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", x, unit)
}

func (check *Checker) assignError(rhs []ast.Expr, l, r int) {
	vars := measure(l, "variable")
	vals := measure(r, "value")
	rhs0 := rhs[0]

	if len(rhs) == 1 {
		if call, _ := ast.Unparen(rhs0).(*ast.CallExpr); call != nil {
			check.errorf(rhs0, WrongAssignCount, "assignment mismatch: %s but %s returns %s", vars, call.Fun, vals)
			return
		}
	}
	check.errorf(rhs0, WrongAssignCount, "assignment mismatch: %s but %s", vars, vals)
}

func (check *Checker) returnError(at positioner, lhs []*Var, rhs []*operand) {
	l, r := len(lhs), len(rhs)
	qualifier := "not enough"
	if r > l {
		at = rhs[l] // report at first extra value
		qualifier = "too many"
	} else if r > 0 {
		at = rhs[r-1] // report at last value
	}
	err := check.newError(WrongResultCount)
	err.addf(at, "%s return values", qualifier)
	err.addf(noposn, "have %s", check.typesSummary(operandTypes(rhs), false, false))
	err.addf(noposn, "want %s", check.typesSummary(varTypes(lhs), false, false))
	err.report()
}

// initVars type-checks assignments of initialization expressions orig_rhs
// to variables lhs.
// If returnStmt is non-nil, initVars type-checks the implicit assignment
// of result expressions orig_rhs to function result parameters lhs.
func (check *Checker) initVars(lhs []*Var, orig_rhs []ast.Expr, returnStmt ast.Stmt) {
	context := "assignment"
	if returnStmt != nil {
		context = "return statement"
	}

	l, r := len(lhs), len(orig_rhs)

	// If l == 1 and the rhs is a single call, for a better
	// error message don't handle it as n:n mapping below.
	isCall := false
	if r == 1 {
		_, isCall = ast.Unparen(orig_rhs[0]).(*ast.CallExpr)
	}

	// If we have a n:n mapping from lhs variable to rhs expression,
	// each value can be assigned to its corresponding variable.
	if l == r && !isCall {
		var x operand
		for i, lhs := range lhs {
			desc := lhs.name
			if returnStmt != nil && desc == "" {
				desc = "result variable"
			}
			check.expr(newTarget(lhs.typ, desc), &x, orig_rhs[i])
			check.initVar(lhs, &x, context)
		}
		return
	}

	// If we don't have an n:n mapping, the rhs must be a single expression
	// resulting in 2 or more values; otherwise we have an assignment mismatch.
	if r != 1 {
		// Only report a mismatch error if there are no other errors on the rhs.
		if check.use(orig_rhs...) {
			if returnStmt != nil {
				rhs := check.exprList(orig_rhs)
				check.returnError(returnStmt, lhs, rhs)
			} else {
				check.assignError(orig_rhs, l, r)
			}
		}
		// ensure that LHS variables have a type
		for _, v := range lhs {
			if v.typ == nil {
				v.typ = Typ[Invalid]
			}
		}
		return
	}

	rhs, commaOk := check.multiExpr(orig_rhs[0], l == 2 && returnStmt == nil)
	r = len(rhs)
	if l == r {
		for i, lhs := range lhs {
			check.initVar(lhs, rhs[i], context)
		}
		// Only record comma-ok expression if both initializations succeeded
		// (go.dev/issue/59371).
		if commaOk && rhs[0].mode != invalid && rhs[1].mode != invalid {
			check.recordCommaOkTypes(orig_rhs[0], rhs)
		}
		return
	}

	// In all other cases we have an assignment mismatch.
	// Only report a mismatch error if there are no other errors on the rhs.
	if rhs[0].mode != invalid {
		if returnStmt != nil {
			check.returnError(returnStmt, lhs, rhs)
		} else {
			check.assignError(orig_rhs, l, r)
		}
	}
	// ensure that LHS variables have a type
	for _, v := range lhs {
		if v.typ == nil {
			v.typ = Typ[Invalid]
		}
	}
	// orig_rhs[0] was already evaluated
}

// assignVars type-checks assignments of expressions orig_rhs to variables lhs.
func (check *Checker) assignVars(lhs, orig_rhs []ast.Expr) {
	l, r := len(lhs), len(orig_rhs)

	// If l == 1 and the rhs is a single call, for a better
	// error message don't handle it as n:n mapping below.
	isCall := false
	if r == 1 {
		_, isCall = ast.Unparen(orig_rhs[0]).(*ast.CallExpr)
	}

	// If we have a n:n mapping from lhs variable to rhs expression,
	// each value can be assigned to its corresponding variable.
	if l == r && !isCall {
		for i, lhs := range lhs {
			check.assignVar(lhs, orig_rhs[i], nil, "assignment")
		}
		return
	}

	// If we don't have an n:n mapping, the rhs must be a single expression
	// resulting in 2 or more values; otherwise we have an assignment mismatch.
	if r != 1 {
		// Only report a mismatch error if there are no other errors on the lhs or rhs.
		okLHS := check.useLHS(lhs...)
		okRHS := check.use(orig_rhs...)
		if okLHS && okRHS {
			check.assignError(orig_rhs, l, r)
		}
		return
	}

	rhs, commaOk := check.multiExpr(orig_rhs[0], l == 2)
	r = len(rhs)
	if l == r {
		for i, lhs := range lhs {
			check.assignVar(lhs, nil, rhs[i], "assignment")
		}
		// Only record comma-ok expression if both assignments succeeded
		// (go.dev/issue/59371).
		if commaOk && rhs[0].mode != invalid && rhs[1].mode != invalid {
			check.recordCommaOkTypes(orig_rhs[0], rhs)
		}
		return
	}

	// In all other cases we have an assignment mismatch.
	// Only report a mismatch error if there are no other errors on the rhs.
	if rhs[0].mode != invalid {
		check.assignError(orig_rhs, l, r)
	}
	check.useLHS(lhs...)
	// orig_rhs[0] was already evaluated
}

func (check *Checker) shortVarDecl(pos positioner, lhs, rhs []ast.Expr) {
	top := len(check.delayed)
	scope := check.scope

	// collect lhs variables
	seen := make(map[string]bool, len(lhs))
	lhsVars := make([]*Var, len(lhs))
	newVars := make([]*Var, 0, len(lhs))
	hasErr := false
	for i, lhs := range lhs {
		ident, _ := lhs.(*ast.Ident)
		if ident == nil {
			check.useLHS(lhs)
			// TODO(gri) This is redundant with a go/parser error. Consider omitting in go/types?
			check.errorf(lhs, BadDecl, "non-name %s on left side of :=", lhs)
			hasErr = true
			continue
		}

		name := ident.Name
		if name != "_" {
			if seen[name] {
				check.errorf(lhs, RepeatedDecl, "%s repeated on left side of :=", lhs)
				hasErr = true
				continue
			}
			seen[name] = true
		}

		// Use the correct obj if the ident is redeclared. The
		// variable's scope starts after the declaration; so we
		// must use Scope.Lookup here and call Scope.Insert
		// (via check.declare) later.
		if alt := scope.Lookup(name); alt != nil {
			check.recordUse(ident, alt)
			// redeclared object must be a variable
			if obj, _ := alt.(*Var); obj != nil {
				lhsVars[i] = obj
			} else {
				check.errorf(lhs, UnassignableOperand, "cannot assign to %s", lhs)
				hasErr = true
			}
			continue
		}

		// declare new variable
		obj := NewVar(ident.Pos(), check.pkg, name, nil)
		lhsVars[i] = obj
		if name != "_" {
			newVars = append(newVars, obj)
		}
		check.recordDef(ident, obj)
	}

	// create dummy variables where the lhs is invalid
	for i, obj := range lhsVars {
		if obj == nil {
			lhsVars[i] = NewVar(lhs[i].Pos(), check.pkg, "_", nil)
		}
	}

	check.initVars(lhsVars, rhs, nil)

	// process function literals in rhs expressions before scope changes
	check.processDelayed(top)

	if len(newVars) == 0 && !hasErr {
		check.softErrorf(pos, NoNewVar, "no new variables on left side of :=")
		return
	}

	// declare new variables
	// spec: "The scope of a constant or variable identifier declared inside
	// a function begins at the end of the ConstSpec or VarSpec (ShortVarDecl
	// for short variable declarations) and ends at the end of the innermost
	// containing block."
	scopePos := endPos(rhs[len(rhs)-1])
	for _, obj := range newVars {
		check.declare(scope, nil, obj, scopePos) // id = nil: recordDef already called
	}
}

"""



```