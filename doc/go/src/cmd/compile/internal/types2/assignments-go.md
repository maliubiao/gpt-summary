Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Initial Reading and Goal Identification:**  The first step is to read through the code to get a general sense of its purpose. The comments at the beginning immediately signal that this file (`assignments.go`) is related to "initialization and assignment checks" within the `types2` package of the Go compiler. This sets the high-level context.

2. **Function-by-Function Analysis:**  The most effective way to understand the code is to examine each function individually.

   * **`assignment(x *operand, T Type, context string)`:**  The name itself is highly suggestive. It seems to check if an `operand` `x` can be assigned to a `Type` `T`. The `context` string provides more information about where this assignment is happening. Key details emerge upon closer inspection:
      * It handles untyped constants and their default types.
      * It checks for assignability using `x.assignableTo(check, T, &cause)`.
      * It has specific logic for the blank identifier (`T == nil`).
      * It deals with generic functions.

   * **`initConst(lhs *Const, x *operand)`:** This function focuses on initializing constants. It verifies that the right-hand side (`x`) is indeed a constant and assigns its value and type to the left-hand side constant (`lhs`).

   * **`initVar(lhs *Var, x *operand, context string)`:**  Similar to `initConst`, but for variables. It handles the case where the variable's type is not yet known, inferring it from the initialization expression. It also handles untyped `nil`.

   * **`lhsVar(lhs syntax.Expr) Type`:**  This function appears to be responsible for analyzing the left-hand side of an assignment. It needs to determine the type of the variable being assigned to. Key observations:
      * It specifically handles the blank identifier (`_`).
      * It checks if the left-hand side is addressable or a map index expression.
      * It manages the `used` status of variables to avoid counting assignments as regular uses.

   * **`assignVar(lhs, rhs syntax.Expr, x *operand, context string)`:**  This function handles the core assignment operation. It calls `lhsVar` to get the type of the left-hand side and then calls `assignment` to check the compatibility.

   * **Helper Functions (`operandTypes`, `varTypes`, `typesSummary`, `measure`, `assignError`, `returnError`):**  These functions provide utility for formatting error messages and working with lists of operands and types. `typesSummary` is particularly useful for creating human-readable type lists.

   * **`initVars(lhs []*Var, orig_rhs []syntax.Expr, returnStmt syntax.Stmt)`:** This handles the initialization of multiple variables, potentially with multiple return values from a function call. It distinguishes between regular assignments and return statements.

   * **`assignVars(lhs, orig_rhs []syntax.Expr)`:** Similar to `initVars`, but for general assignments (not initializations).

   * **`shortVarDecl(pos poser, lhs, rhs []syntax.Expr)`:**  This is specifically for short variable declarations (`:=`). It involves declaring new variables and handling redeclarations.

3. **Identifying Go Language Features:**  As each function is analyzed, connections to specific Go features become apparent:

   * **Assignments and Initialization:** The entire file is about this fundamental Go concept.
   * **Type Checking:**  The core functionality revolves around ensuring type compatibility.
   * **Constants and Variables:**  Separate functions handle initialization for each.
   * **Blank Identifier:** `lhsVar` has explicit handling for `_`.
   * **Multiple Return Values:** `initVars` and `assignVars` handle functions returning multiple values.
   * **Short Variable Declarations:** `shortVarDecl` is dedicated to this syntax.
   * **Untyped Constants:** The `assignment` function specifically addresses how untyped constants are handled in assignments.
   * **Interfaces:** The code mentions "interface type" and `isNonTypeParamInterface`.
   * **Generic Functions:** The `assignment` function has checks for generic functions without instantiation.

4. **Generating Examples:** Once the features are identified, concrete Go code examples can be created to illustrate the functionality. The key is to choose examples that highlight the specific checks being performed by each function.

5. **Code Inference and Assumptions:** For code inference, the most important function is `assignment`. By looking at the conditions and error messages, one can infer how Go handles different assignment scenarios. Assumptions need to be made about the `operand` type and the `Checker` struct, based on the context of type checking.

6. **Command-Line Arguments:**  The code itself doesn't seem to directly process command-line arguments. This is important to note. The `cmd/compile` part of the path suggests it's part of the compiler, but the *specific* argument handling would likely be in a different part of the compiler's source.

7. **Common Mistakes:**  Thinking about common Go programming errors related to assignment helps identify potential pitfalls that this code aims to prevent:

   * Type mismatches.
   * Incorrect number of return values.
   * Attempting to assign to non-addressable values.
   * Redeclaring variables in short variable declarations.
   * Misunderstanding how untyped constants are assigned.

8. **Structuring the Output:** Finally, the information needs to be organized logically, addressing each part of the prompt: function descriptions, feature identification, code examples, inferences, command-line arguments, and common mistakes. Using clear headings and code formatting improves readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `operand` is just a simple value. **Correction:**  Looking closer, it has a `mode` and `typ`, suggesting it's more complex and represents an expression's evaluation state during type checking.
* **Initial thought:** The code directly handles command-line arguments. **Correction:** The path suggests it's *part* of the compiler, but the specific argument parsing is likely elsewhere. The code focuses on the *logic* of assignment checking, not the CLI interface.
* **Focus shift:** Initially, I might have just described what each line of code does. **Refinement:**  The prompt asks for *functionality* and connecting it to Go *features*. This requires a higher level of analysis.

By following these steps, iteratively analyzing the code, and connecting it to Go's language features, one can effectively understand and explain the purpose of the provided code snippet.
这段代码是 Go 语言编译器 `cmd/compile/internal/types2` 包中 `assignments.go` 文件的一部分，它主要负责**实现 Go 语言中的赋值操作的类型检查和初始化检查**。

更具体地说，它包含了以下几个方面的功能：

**1. 检查赋值的有效性 (`assignment` 函数):**

* **功能:** 判断一个表达式 (`x`) 的值是否可以赋值给一个指定类型 (`T`) 的变量。
* **类型转换:**  如果需要，它会尝试将无类型的值转换为合适的类型。例如，将无类型的整数常量赋值给 `int` 类型的变量。
* **上下文信息:**  `context` 参数用于提供赋值发生的上下文信息，例如 "assignment"、"constant declaration" 等，以便在报错时提供更清晰的错误信息。
* **特殊情况处理:**
    * **空标识符 (`_`)**: 允许将任何类型的值赋值给空标识符（但 `nil` 常量除外）。
    * **接口类型:**  对于赋值给接口类型的情况，会处理无类型常量的默认类型转换。
    * **泛型函数:**  检查是否尝试将未实例化的泛型函数赋值给变量。
* **错误处理:** 如果赋值检查失败，会将 `x` 的 `mode` 设置为 `invalid`，并报告相应的错误。

**2. 初始化常量 (`initConst` 函数):**

* **功能:** 检查常量声明中的初始化表达式。
* **常量性检查:**  确保初始化表达式的值是一个常量。
* **类型推断:** 如果常量没有显式声明类型，则使用初始化表达式的类型。
* **赋值检查:**  调用 `assignment` 函数来检查初始化值的类型是否与常量类型兼容。

**3. 初始化变量 (`initVar` 函数):**

* **功能:** 检查变量声明中的初始化表达式。
* **类型推断:** 如果变量没有显式声明类型，则使用初始化表达式的类型 (如果是无类型常量，则使用其默认类型)。
* **`nil` 的处理:**  如果初始化表达式是无类型的 `nil`，则会报错。
* **赋值检查:**  调用 `assignment` 函数来检查初始化值的类型是否与变量类型兼容。

**4. 处理赋值左侧的变量 (`lhsVar` 函数):**

* **功能:** 检查赋值语句左侧的表达式，并返回其类型。
* **空标识符处理:** 如果左侧是空标识符 `_`，则返回 `nil`。
* **可赋值性检查:**  确保左侧的表达式是可赋值的（例如，变量、可寻址的表达式、map 索引表达式）。
* **副作用控制:**  对于直接赋值给变量的情况，会暂时取消将该变量标记为 "已使用"，以避免在赋值语句中将其计算为 "使用"。

**5. 赋值变量 (`assignVar` 函数):**

* **功能:** 检查赋值语句 `lhs = rhs` 或 `lhs = x` (当 `x` 已经求值) 的类型兼容性。
* **获取左侧类型:**  调用 `lhsVar` 函数获取左侧表达式的类型。
* **求值右侧表达式:** 如果 `x` 为 `nil`，则会求值右侧表达式 `rhs`。
* **赋值检查:** 调用 `assignment` 函数来检查右侧值的类型是否可以赋值给左侧变量的类型。

**6. 处理多个变量的初始化 (`initVars` 函数):**

* **功能:**  处理多个变量同时初始化的情况，例如 `a, b := 1, 2` 或 `a, b := f()`。
* **逐个检查:** 如果左右两侧表达式数量相同，则逐个检查赋值的兼容性。
* **多返回值处理:**  如果右侧是一个返回多个值的函数调用，则检查返回值数量和类型是否与左侧变量匹配。
* **错误报告:**  如果赋值数量不匹配或类型不兼容，会报告相应的错误。

**7. 处理多个变量的赋值 (`assignVars` 函数):**

* **功能:**  处理多个变量同时赋值的情况，例如 `a, b = 1, 2` 或 `a, b = f()`。
* **逻辑与 `initVars` 类似，但用于已声明的变量赋值。**

**8. 处理短变量声明 (`shortVarDecl` 函数):**

* **功能:**  处理短变量声明语句 `a := 1` 或 `a, b := f()`。
* **检查左侧标识符:** 确保左侧是有效的标识符，并且没有重复声明。
* **处理新变量和已存在变量:**  区分声明新变量和重新赋值给已存在的变量。
* **调用 `initVars` 进行初始化检查。**
* **作用域管理:**  在当前作用域中声明新变量。

**9. 辅助函数:**

* `operandTypes`, `varTypes`:  获取操作数或变量的类型列表。
* `typesSummary`:  生成类型列表的字符串表示形式，用于错误消息。
* `measure`:  根据数量生成单复数形式的字符串，用于错误消息。
* `assignError`, `returnError`:  生成赋值或返回语句的类型不匹配错误信息。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码的核心是实现了 **Go 语言的赋值语句和变量声明时的类型检查规则**。 它确保了在赋值操作中，右侧表达式的值的类型与左侧变量的类型是兼容的，从而保证了 Go 语言的类型安全。

**Go 代码举例说明:**

```go
package main

func main() {
	var a int = 10      // initVar 检查这里
	b := "hello"         // shortVarDecl 和 initVars 检查这里
	c, d := 1.23, true  // shortVarDecl 和 initVars 检查这里

	a = 20             // assignVar 检查这里
	b = "world"

	var e float64
	e = 5             // assignment 检查 int 可以赋值给 float64

	_, f := getValues() // assignVars 检查这里，忽略第一个返回值

	// 错误示例：
	// a = "abc"  // 编译时会报错，assignment 函数会检测到类型不匹配

	println(a, b, c, d, e, f)
}

func getValues() (int, string) {
	return 100, "test"
}
```

**假设的输入与输出 (以 `assignment` 函数为例):**

**假设输入:**

* `x`: 一个 `operand`，其类型是 `types2.Typ[types2.UntypedInt]`，值是常量 `5`。
* `T`: `types2.Typ[types2.Int]` (Go 语言的 `int` 类型)。
* `context`: `"assignment"`。

**推理过程:**

1. `assignment` 函数首先检查 `x` 的 `mode`，这里是 `constant_`，属于允许赋值的情况。
2. `isUntyped(x.typ)` 返回 `true`。
3. 由于 `T` 不是 `nil` 并且不是非类型参数的接口，`target` 仍然是 `types2.Typ[types2.Int]`。
4. `check.implicitTypeAndValue(x, target)` 会尝试将无类型的整数常量 `5` 转换为 `int` 类型。这个转换是合法的。
5. `x.assignableTo(check, T, &cause)` 会检查 `int` 类型是否可以赋值给 `int` 类型，结果为 `true`。

**假设输出 (没有错误):**

* 函数执行成功，没有错误报告。
* `x` 的 `typ` 可能会被更新为 `types2.Typ[types2.Int]` (如果之前的类型只是无类型的)。

**假设输入 (有错误):**

* `x`: 一个 `operand`，其类型是 `types2.Typ[types2.UntypedString]`，值是常量 `"hello"`。
* `T`: `types2.Typ[types2.Int]`。
* `context`: `"assignment"`。

**推理过程:**

1. `assignment` 函数前几步类似。
2. `check.implicitTypeAndValue(x, target)` 会尝试将无类型的字符串常量转换为 `int` 类型，这个转换会失败。
3. `x.assignableTo(check, T, &cause)` 会检查 `string` 类型是否可以赋值给 `int` 类型，结果为 `false`。

**假设输出 (有错误):**

* `check.errorf` 会被调用，报告类似 "cannot use string constant "hello" as int value in assignment"。
* `x.mode` 会被设置为 `invalid`。

**命令行参数的具体处理:**

这段代码本身**不直接处理命令行参数**。它是 Go 语言编译器内部类型检查逻辑的一部分。 命令行参数的处理通常发生在编译器的前端和主控流程中，用于指定编译选项、输入文件等。

**使用者易犯错的点 (对应这段代码负责的检查):**

1. **类型不匹配的赋值:**
   ```go
   var i int
   var s string = "hello"
   i = s // 编译错误：cannot use s (variable of type string) as int value in assignment
   ```
   `assignment` 函数会检测到 `string` 类型的值不能直接赋值给 `int` 类型的变量。

2. **尝试将 `nil` 赋值给未指定类型的变量:**
   ```go
   var x interface{} = nil
   y := nil // 编译错误：use of untyped nil in short variable declaration
   ```
   `initVar` 或 `shortVarDecl` 结合 `assignment` 会检测到无类型的 `nil` 不能用于初始化没有明确类型的变量。

3. **函数返回值的数量与接收变量的数量不匹配:**
   ```go
   func foo() (int, string) {
       return 1, "hello"
   }

   var a int
   a = foo() // 编译错误：assignment mismatch: 1 variable but foo returns 2 values

   var b int, c int
   b, c = foo() // 编译错误：assignment mismatch: 2 variables but foo returns 2 values
   ```
   `initVars` 或 `assignVars` 会检测到返回值数量与接收变量数量不一致。

4. **尝试赋值给不可赋值的表达式:**
   ```go
   func getPtr() *int {
       var i int = 5
       return &i
   }

   getPtr() = 10 // 编译错误：cannot assign to result of getPtr()
   ```
   `lhsVar` 会检测到赋值操作的左侧不是一个可赋值的表达式。

5. **短变量声明中的重复声明 (在同一作用域内):**
   ```go
   a := 10
   a, b := 20, "world" // 编译错误：no new variables on left side of :="
   ```
   `shortVarDecl` 会检测到左侧没有新的变量被声明。

理解这段代码对于理解 Go 语言的类型系统和编译原理至关重要。 它展示了编译器如何在编译时进行静态类型检查，以避免运行时出现类型相关的错误，从而提高了 Go 程序的稳定性和可靠性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/assignments.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements initialization and assignment checks.

package types2

import (
	"cmd/compile/internal/syntax"
	"fmt"
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
func (check *Checker) lhsVar(lhs syntax.Expr) Type {
	// Determine if the lhs is a (possibly parenthesized) identifier.
	ident, _ := syntax.Unparen(lhs).(*syntax.Name)

	// Don't evaluate lhs if it is the blank identifier.
	if ident != nil && ident.Value == "_" {
		check.recordDef(ident, nil)
		return nil
	}

	// If the lhs is an identifier denoting a variable v, this reference
	// is not a 'use' of v. Remember current value of v.used and restore
	// after evaluating the lhs via check.expr.
	var v *Var
	var v_used bool
	if ident != nil {
		if obj := check.lookup(ident.Value); obj != nil {
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
		if sel, ok := x.expr.(*syntax.SelectorExpr); ok {
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
func (check *Checker) assignVar(lhs, rhs syntax.Expr, x *operand, context string) {
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

func (check *Checker) assignError(rhs []syntax.Expr, l, r int) {
	vars := measure(l, "variable")
	vals := measure(r, "value")
	rhs0 := rhs[0]

	if len(rhs) == 1 {
		if call, _ := syntax.Unparen(rhs0).(*syntax.CallExpr); call != nil {
			check.errorf(rhs0, WrongAssignCount, "assignment mismatch: %s but %s returns %s", vars, call.Fun, vals)
			return
		}
	}
	check.errorf(rhs0, WrongAssignCount, "assignment mismatch: %s but %s", vars, vals)
}

func (check *Checker) returnError(at poser, lhs []*Var, rhs []*operand) {
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
	err.addf(nopos, "have %s", check.typesSummary(operandTypes(rhs), false, false))
	err.addf(nopos, "want %s", check.typesSummary(varTypes(lhs), false, false))
	err.report()
}

// initVars type-checks assignments of initialization expressions orig_rhs
// to variables lhs.
// If returnStmt is non-nil, initVars type-checks the implicit assignment
// of result expressions orig_rhs to function result parameters lhs.
func (check *Checker) initVars(lhs []*Var, orig_rhs []syntax.Expr, returnStmt syntax.Stmt) {
	context := "assignment"
	if returnStmt != nil {
		context = "return statement"
	}

	l, r := len(lhs), len(orig_rhs)

	// If l == 1 and the rhs is a single call, for a better
	// error message don't handle it as n:n mapping below.
	isCall := false
	if r == 1 {
		_, isCall = syntax.Unparen(orig_rhs[0]).(*syntax.CallExpr)
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
func (check *Checker) assignVars(lhs, orig_rhs []syntax.Expr) {
	l, r := len(lhs), len(orig_rhs)

	// If l == 1 and the rhs is a single call, for a better
	// error message don't handle it as n:n mapping below.
	isCall := false
	if r == 1 {
		_, isCall = syntax.Unparen(orig_rhs[0]).(*syntax.CallExpr)
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

func (check *Checker) shortVarDecl(pos poser, lhs, rhs []syntax.Expr) {
	top := len(check.delayed)
	scope := check.scope

	// collect lhs variables
	seen := make(map[string]bool, len(lhs))
	lhsVars := make([]*Var, len(lhs))
	newVars := make([]*Var, 0, len(lhs))
	hasErr := false
	for i, lhs := range lhs {
		ident, _ := lhs.(*syntax.Name)
		if ident == nil {
			check.useLHS(lhs)
			// TODO(gri) This is redundant with a go/parser error. Consider omitting in go/types?
			check.errorf(lhs, BadDecl, "non-name %s on left side of :=", lhs)
			hasErr = true
			continue
		}

		name := ident.Value
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
```