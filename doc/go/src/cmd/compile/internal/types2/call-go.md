Response: My thinking process to analyze the Go code and answer the request goes like this:

1. **Understand the Goal:** The core request is to understand the functionality of the provided `call.go` code snippet within the `types2` package of the Go compiler. Specifically, it asks for the file's functions, their purpose, how they relate to Go language features, illustrative Go code examples, handling of command-line arguments (if any), and common mistakes users might make.

2. **High-Level Overview:** I first scan the entire code to get a sense of the major components. I notice the package declaration (`package types2`), several imports related to compiler internals (`cmd/compile/internal/syntax`, `internal/types/errors`), and core Go types (`strings`). The comment at the beginning of the file clearly states its purpose: "typechecking of call and selector expressions." This is a crucial piece of information.

3. **Identify Key Functions:** I then go through each function definition and its associated comments. The key functions I identify are:

    * `funcInst`:  The comment explicitly describes it as handling "function instantiation" for generic functions. This immediately connects it to Go's generics feature introduced in Go 1.18.
    * `instantiateSignature`:  This function likely handles the process of creating a concrete signature from a generic one by substituting type parameters with actual types.
    * `callExpr`: This appears to be the central function for handling function and method calls. It deals with different call scenarios, including conversions, built-in functions, and regular function/method calls. The handling of generic functions and their instantiation within this function is noteworthy.
    * `exprList` and `genericExprList`: These seem to be responsible for evaluating lists of expressions, with `genericExprList` specifically handling potentially generic function expressions.
    * `arguments`: This function is clearly dedicated to type-checking the arguments passed to a function call, including handling variadic functions and type inference for generic functions.
    * `selector`: This function deals with the type-checking of selector expressions (e.g., `x.y`). It handles package-qualified identifiers and field/method lookups.
    * `use`, `useLHS`, `useN`, `use1`: These utility functions likely ensure that expressions are evaluated and variables are marked as "used" during type checking.

4. **Connect Functions to Go Features:**  Based on the function names and comments, I can connect them to specific Go language features:

    * **Generics:** `funcInst` and the handling of type parameters within `callExpr` and `arguments` directly relate to Go's generics feature.
    * **Function and Method Calls:** `callExpr` and `arguments` are the core of this.
    * **Selectors:** The `selector` function directly handles the `.` operator for accessing fields, methods, and package members.
    * **Built-in Functions:** The `callExpr` function has a specific case for handling built-in functions.
    * **Conversions:** `callExpr` also deals with type conversions.
    * **Variadic Functions:** The `arguments` function explicitly handles the `...` syntax for variadic functions.

5. **Develop Go Code Examples:** For the more prominent features like generics, function calls, and selectors, I construct simple Go code examples to illustrate how the code in `call.go` would be involved in type-checking them. I focus on scenarios that highlight the specific functionality of the mentioned functions (e.g., instantiating a generic function, calling a method on a struct).

6. **Infer Input/Output for Code Reasoning:**  For the `funcInst` function, which explicitly mentions input and output parameters, I make assumptions about a possible input (a generic function and type arguments) and the expected output (the instantiated function type). This demonstrates how the `funcInst` function transforms a generic function into a concrete one.

7. **Address Command-Line Arguments:**  I carefully review the code and the imports. I don't see any direct handling of command-line arguments within this specific snippet. Therefore, I conclude that it primarily operates within the compiler's type-checking phase and isn't directly influenced by command-line flags.

8. **Identify Potential User Mistakes:** This requires thinking about common errors developers encounter when working with the features handled by the code.

    * **Incorrect number of type arguments:**  This is a common mistake when using generics, and the `funcInst` function explicitly checks for this.
    * **Calling non-function types:** The `callExpr` function handles this scenario.
    * **Using unexported names:** The `selector` function checks for the visibility of imported names.
    * **Incorrect number of arguments in function calls:** The `arguments` function handles this.
    * **Using `...` incorrectly:** The `arguments` function checks the usage of the ellipsis operator.

9. **Structure the Answer:** Finally, I organize the information logically, addressing each part of the request: functionalities, Go feature implementation, code examples with assumptions, command-line arguments, and common mistakes. I use clear headings and code formatting to improve readability.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the low-level details of the code. I realized I needed to step back and understand the high-level purpose of each function and how it contributes to type-checking.
*  I paid closer attention to the comments in the code, as they provide valuable insights into the intended functionality and edge cases.
* I specifically looked for keywords like "generic," "instantiation," "selector," and "call" to guide my understanding.
* I made sure my Go code examples were concise and directly relevant to the functions being discussed.
* I double-checked that my assumptions about input/output for code reasoning were reasonable and aligned with the code's logic.
这是 `go/src/cmd/compile/internal/types2/call.go` 文件的一部分，它主要负责 Go 语言中**函数调用**和**选择器表达式（selector expressions）**的类型检查。

以下是它包含的功能的详细列表：

**核心功能:**

1. **函数实例化 (`funcInst`)**:
   -  处理泛型函数的实例化。
   -  可以显式提供类型参数，也可以尝试推断缺失的类型参数。
   -  检查提供的类型参数的数量是否正确。
   -  在需要时进行类型参数的推断。
   -  在成功实例化后，更新函数操作数 (`operand`) 的类型。

2. **实例化签名 (`instantiateSignature`)**:
   -  根据提供的类型参数实例化函数签名（`Signature`）。
   -  创建一个非泛型的具体签名。
   -  记录实例化信息，以便后续使用。
   -  延迟执行实例化验证，例如检查类型约束是否满足。

3. **调用表达式 (`callExpr`)**:
   -  处理各种形式的函数调用，包括普通函数调用、方法调用、类型转换和内置函数调用。
   -  处理泛型函数的调用，包括显式提供类型参数的情况。
   -  检查函数调用的参数数量和类型是否正确。
   -  处理 `...` 语法（用于传递可变参数）。
   -  确定函数调用的结果类型和模式（例如，返回值、多返回值）。
   -  处理内置函数的特殊逻辑。
   -  区分类型转换和函数调用。

4. **表达式列表 (`exprList`, `genericExprList`)**:
   -  `exprList`: 评估一个表达式列表，并返回相应的操作数 (`operand`) 列表。
   -  `genericExprList`: 类似于 `exprList`，但能处理返回未实例化或部分实例化泛型函数的表达式。这在 Go 1.21 及更高版本中允许作为参数传递。

5. **参数类型检查 (`arguments`)**:
   -  核心的参数类型检查逻辑。
   -  比较函数调用提供的参数和函数签名的参数。
   -  处理可变参数函数的特殊情况。
   -  结合函数自身的类型参数和参数中的泛型函数，进行类型推断。
   -  在推断出类型参数后，实例化函数签名和参数中的泛型函数。

6. **选择器表达式 (`selector`)**:
   -  处理形如 `x.y` 的选择器表达式。
   -  如果 `x` 是包名，则查找包中的导出成员。
   -  如果 `x` 是类型，则查找类型的方法（方法表达式）。
   -  如果 `x` 是变量，则查找结构体字段或方法。
   -  处理 CGO 相关的特殊前缀。
   -  检查选择器的可访问性（是否导出）。
   -  处理方法表达式的类型构造。

7. **使用表达式 (`use`, `useLHS`, `useN`, `use1`)**:
   -  用于确保表达式被评估。
   -  `useLHS` 用于赋值语句的左侧，避免将左侧的变量标记为 "used"。

**推断的 Go 语言功能实现:**

这个文件是 Go 语言中实现以下功能的核心部分：

* **函数调用：**  无论是普通函数、方法还是泛型函数，这个文件都负责确保调用方式符合类型系统的规则。
* **方法调用：**  `selector` 和 `callExpr` 协同工作，处理方法调用，包括值接收者和指针接收者的情况。
* **泛型：** `funcInst`, `instantiateSignature`, `callExpr`, 和 `arguments` 紧密合作，实现了 Go 1.18 引入的泛型功能，包括类型参数的传递、推断和实例化。
* **类型转换：** `callExpr` 中的 `typexpr` 分支负责处理类型转换的语法和类型检查。
* **内置函数：** `callExpr` 中的 `builtin` 分支处理 Go 语言的内置函数，例如 `len`, `cap`, `make` 等。
* **包的导入和使用：** `selector` 负责处理通过包名访问成员的情况，并检查导出的规则。
* **选择器表达式：**  用于访问结构体字段、方法和包成员。
* **可变参数函数：** `arguments` 函数负责处理 `...` 语法。

**Go 代码举例说明:**

```go
package main

import "fmt"

// 泛型函数
func Max[T interface{ Less(T) bool }](a, b T) T {
	if a.Less(b) {
		return b
	}
	return a
}

type Integer int

func (i Integer) Less(other Integer) bool {
	return i < other
}

type MyStruct struct {
	Value int
}

func (ms MyStruct) Print() {
	fmt.Println("MyStruct value:", ms.Value)
}

func add(a int, args ...int) int {
	sum := a
	for _, arg := range args {
		sum += arg
	}
	return sum
}

func main() {
	// 泛型函数调用 (显式类型参数)
	fmt.Println(Max[Integer](10, 5))

	// 泛型函数调用 (类型推断)
	fmt.Println(Max(Integer(20), Integer(15)))

	// 方法调用
	ms := MyStruct{Value: 42}
	ms.Print()

	// 函数调用
	fmt.Println(add(1))
	fmt.Println(add(1, 2, 3, 4))

	// 类型转换
	var i int = 10
	var f float64 = float64(i)
	fmt.Println(f)
}
```

**假设的输入与输出 (针对 `funcInst`):**

**假设输入:**

* `x`: 一个 `*operand`，代表一个泛型函数 `Max`。其类型是 `func[T interface{ Less(T) bool }](T, T) T`。
* `inst`: 一个 `*syntax.IndexExpr`，代表 `Max[Integer]` 这样的语法结构。
* `infer`: `false` (假设不进行类型推断，类型参数已显式提供)。

**预期输出:**

* `targs`: `[]Type{Integer}` (类型参数 `Integer`)
* `xlist`: `[]syntax.Expr{syntax.Name{Value: "Integer"}}` (类型参数表达式)
* 函数 `funcInst` 会更新 `x.typ` 为实例化后的签名 `func(Integer, Integer) Integer`。

**假设输入 (针对 `funcInst`，进行类型推断):**

* `x`: 一个 `*operand`，代表一个泛型函数 `Max`。其类型是 `func[T interface{ Less(T) bool }](T, T) T`。
* `inst`: `nil` (没有显式提供类型参数)。
* `T`: 一个 `*target`，表示期望的目标类型，例如在赋值语句 `var result Integer = Max(a, b)` 中，`T` 可能代表 `Integer` 类型。
* `infer`: `true` (进行类型推断)。
* 假设调用 `Max(Integer(1), Integer(2))`，在类型检查参数时会提供足够的信息进行推断。

**预期输出:**

* `targs`: `[]Type{Integer}` (推断出的类型参数 `Integer`)
* `xlist`: `nil` (因为没有显式的类型参数表达式)
* 函数 `funcInst` 会更新 `x.typ` 为实例化后的签名 `func(Integer, Integer) Integer`。

**命令行参数的具体处理:**

在这个代码片段中，没有直接处理命令行参数的逻辑。这个文件是 Go 编译器内部类型检查器的一部分，它的执行是由编译器驱动的，而不是通过命令行参数直接控制。Go 编译器的命令行参数（如 `-gcflags`, `-ldflags` 等）会影响编译过程的各个阶段，但 `types2` 包主要关注类型系统的静态分析。

**使用者易犯错的点 (与这些功能相关):**

1. **泛型函数类型参数错误：**
   ```go
   // 错误示例：尝试用不满足约束的类型实例化泛型函数
   // 假设有另一个类型 NotComparable {}
   // fmt.Println(Max[NotComparable](NotComparable{}, NotComparable{})) // 编译错误
   ```
   编译器会报错，因为 `NotComparable` 没有 `Less` 方法，不满足 `Max` 函数的类型约束。

2. **泛型函数类型参数数量错误：**
   ```go
   // 错误示例：提供错误数量的类型参数
   // fmt.Println(Max[int, string](1, "hello")) // 编译错误
   ```
   `Max` 函数只接受一个类型参数，提供两个会报错。

3. **调用非函数类型：**
   ```go
   var x int = 10
   // x() // 编译错误：cannot call non-function x
   ```

4. **方法调用接收者类型不匹配：**
   ```go
   type MyInt int
   func (m MyInt) Double() MyInt { return m * 2 }

   var i int = 5
   // i.Double() // 编译错误：i.Double undefined (type int has no method Double)

   var mi MyInt = 5
   mi.Double() // 正确
   ```

5. **访问未导出的包成员：**
   如果尝试访问另一个包中未导出的标识符，编译器会报错。

6. **可变参数函数调用错误：**
   ```go
   // 假设有函数 func foo(a int, b ...int)
   // foo() // 编译错误：not enough arguments in call to foo
   // foo(1, "hello") // 编译错误：cannot use "hello" (untyped string constant) as int value in argument to foo
   ```
   可变参数函数至少需要提供非可变参数，且可变参数的类型必须匹配。

7. **类型转换错误：**
   ```go
   var s string = "hello"
   // var i int = int(s) // 编译错误：cannot convert s (variable of type string) to type int
   ```
   不能进行不兼容类型之间的转换。

这个文件是 Go 编译器类型检查的关键部分，确保代码在编译时符合 Go 语言的类型规则，从而提高代码的可靠性和安全性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/call.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This file implements typechecking of call and selector expressions.

package types2

import (
	"cmd/compile/internal/syntax"
	. "internal/types/errors"
	"strings"
)

// funcInst type-checks a function instantiation.
// The incoming x must be a generic function.
// If inst != nil, it provides some or all of the type arguments (inst.Index).
// If target != nil, it may be used to infer missing type arguments of x, if any.
// At least one of T or inst must be provided.
//
// There are two modes of operation:
//
//  1. If infer == true, funcInst infers missing type arguments as needed and
//     instantiates the function x. The returned results are nil.
//
//  2. If infer == false and inst provides all type arguments, funcInst
//     instantiates the function x. The returned results are nil.
//     If inst doesn't provide enough type arguments, funcInst returns the
//     available arguments and the corresponding expression list; x remains
//     unchanged.
//
// If an error (other than a version error) occurs in any case, it is reported
// and x.mode is set to invalid.
func (check *Checker) funcInst(T *target, pos syntax.Pos, x *operand, inst *syntax.IndexExpr, infer bool) ([]Type, []syntax.Expr) {
	assert(T != nil || inst != nil)

	var instErrPos poser
	if inst != nil {
		instErrPos = inst.Pos()
		x.expr = inst // if we don't have an index expression, keep the existing expression of x
	} else {
		instErrPos = pos
	}
	versionErr := !check.verifyVersionf(instErrPos, go1_18, "function instantiation")

	// targs and xlist are the type arguments and corresponding type expressions, or nil.
	var targs []Type
	var xlist []syntax.Expr
	if inst != nil {
		xlist = syntax.UnpackListExpr(inst.Index)
		targs = check.typeList(xlist)
		if targs == nil {
			x.mode = invalid
			return nil, nil
		}
		assert(len(targs) == len(xlist))
	}

	// Check the number of type arguments (got) vs number of type parameters (want).
	// Note that x is a function value, not a type expression, so we don't need to
	// call under below.
	sig := x.typ.(*Signature)
	got, want := len(targs), sig.TypeParams().Len()
	if got > want {
		// Providing too many type arguments is always an error.
		check.errorf(xlist[got-1], WrongTypeArgCount, "got %d type arguments but want %d", got, want)
		x.mode = invalid
		return nil, nil
	}

	if got < want {
		if !infer {
			return targs, xlist
		}

		// If the uninstantiated or partially instantiated function x is used in
		// an assignment (tsig != nil), infer missing type arguments by treating
		// the assignment
		//
		//    var tvar tsig = x
		//
		// like a call g(tvar) of the synthetic generic function g
		//
		//    func g[type_parameters_of_x](func_type_of_x)
		//
		var args []*operand
		var params []*Var
		var reverse bool
		if T != nil && sig.tparams != nil {
			if !versionErr && !check.allowVersion(go1_21) {
				if inst != nil {
					check.versionErrorf(instErrPos, go1_21, "partially instantiated function in assignment")
				} else {
					check.versionErrorf(instErrPos, go1_21, "implicitly instantiated function in assignment")
				}
			}
			gsig := NewSignatureType(nil, nil, nil, sig.params, sig.results, sig.variadic)
			params = []*Var{NewVar(x.Pos(), check.pkg, "", gsig)}
			// The type of the argument operand is tsig, which is the type of the LHS in an assignment
			// or the result type in a return statement. Create a pseudo-expression for that operand
			// that makes sense when reported in error messages from infer, below.
			expr := syntax.NewName(x.Pos(), T.desc)
			args = []*operand{{mode: value, expr: expr, typ: T.sig}}
			reverse = true
		}

		// Rename type parameters to avoid problems with recursive instantiations.
		// Note that NewTuple(params...) below is (*Tuple)(nil) if len(params) == 0, as desired.
		tparams, params2 := check.renameTParams(pos, sig.TypeParams().list(), NewTuple(params...))

		err := check.newError(CannotInferTypeArgs)
		targs = check.infer(pos, tparams, targs, params2.(*Tuple), args, reverse, err)
		if targs == nil {
			if !err.empty() {
				err.report()
			}
			x.mode = invalid
			return nil, nil
		}
		got = len(targs)
	}
	assert(got == want)

	// instantiate function signature
	sig = check.instantiateSignature(x.Pos(), x.expr, sig, targs, xlist)

	x.typ = sig
	x.mode = value
	return nil, nil
}

func (check *Checker) instantiateSignature(pos syntax.Pos, expr syntax.Expr, typ *Signature, targs []Type, xlist []syntax.Expr) (res *Signature) {
	assert(check != nil)
	assert(len(targs) == typ.TypeParams().Len())

	if check.conf.Trace {
		check.trace(pos, "-- instantiating signature %s with %s", typ, targs)
		check.indent++
		defer func() {
			check.indent--
			check.trace(pos, "=> %s (under = %s)", res, res.Underlying())
		}()
	}

	inst := check.instance(pos, typ, targs, nil, check.context()).(*Signature)
	assert(inst.TypeParams().Len() == 0) // signature is not generic anymore
	check.recordInstance(expr, targs, inst)
	assert(len(xlist) <= len(targs))

	// verify instantiation lazily (was go.dev/issue/50450)
	check.later(func() {
		tparams := typ.TypeParams().list()
		// check type constraints
		if i, err := check.verify(pos, tparams, targs, check.context()); err != nil {
			// best position for error reporting
			pos := pos
			if i < len(xlist) {
				pos = syntax.StartPos(xlist[i])
			}
			check.softErrorf(pos, InvalidTypeArg, "%s", err)
		} else {
			check.mono.recordInstance(check.pkg, pos, tparams, targs, xlist)
		}
	}).describef(pos, "verify instantiation")

	return inst
}

func (check *Checker) callExpr(x *operand, call *syntax.CallExpr) exprKind {
	var inst *syntax.IndexExpr // function instantiation, if any
	if iexpr, _ := call.Fun.(*syntax.IndexExpr); iexpr != nil {
		if check.indexExpr(x, iexpr) {
			// Delay function instantiation to argument checking,
			// where we combine type and value arguments for type
			// inference.
			assert(x.mode == value)
			inst = iexpr
		}
		x.expr = iexpr
		check.record(x)
	} else {
		check.exprOrType(x, call.Fun, true)
	}
	// x.typ may be generic

	switch x.mode {
	case invalid:
		check.use(call.ArgList...)
		x.expr = call
		return statement

	case typexpr:
		// conversion
		check.nonGeneric(nil, x)
		if x.mode == invalid {
			return conversion
		}
		T := x.typ
		x.mode = invalid
		switch n := len(call.ArgList); n {
		case 0:
			check.errorf(call, WrongArgCount, "missing argument in conversion to %s", T)
		case 1:
			check.expr(nil, x, call.ArgList[0])
			if x.mode != invalid {
				if t, _ := under(T).(*Interface); t != nil && !isTypeParam(T) {
					if !t.IsMethodSet() {
						check.errorf(call, MisplacedConstraintIface, "cannot use interface %s in conversion (contains specific type constraints or is comparable)", T)
						break
					}
				}
				if hasDots(call) {
					check.errorf(call.ArgList[0], BadDotDotDotSyntax, "invalid use of ... in conversion to %s", T)
					break
				}
				check.conversion(x, T)
			}
		default:
			check.use(call.ArgList...)
			check.errorf(call.ArgList[n-1], WrongArgCount, "too many arguments in conversion to %s", T)
		}
		x.expr = call
		return conversion

	case builtin:
		// no need to check for non-genericity here
		id := x.id
		if !check.builtin(x, call, id) {
			x.mode = invalid
		}
		x.expr = call
		// a non-constant result implies a function call
		if x.mode != invalid && x.mode != constant_ {
			check.hasCallOrRecv = true
		}
		return predeclaredFuncs[id].kind
	}

	// ordinary function/method call
	// signature may be generic
	cgocall := x.mode == cgofunc

	// a type parameter may be "called" if all types have the same signature
	sig, _ := coreType(x.typ).(*Signature)
	if sig == nil {
		check.errorf(x, InvalidCall, invalidOp+"cannot call non-function %s", x)
		x.mode = invalid
		x.expr = call
		return statement
	}

	// Capture wasGeneric before sig is potentially instantiated below.
	wasGeneric := sig.TypeParams().Len() > 0

	// evaluate type arguments, if any
	var xlist []syntax.Expr
	var targs []Type
	if inst != nil {
		xlist = syntax.UnpackListExpr(inst.Index)
		targs = check.typeList(xlist)
		if targs == nil {
			check.use(call.ArgList...)
			x.mode = invalid
			x.expr = call
			return statement
		}
		assert(len(targs) == len(xlist))

		// check number of type arguments (got) vs number of type parameters (want)
		got, want := len(targs), sig.TypeParams().Len()
		if got > want {
			check.errorf(xlist[want], WrongTypeArgCount, "got %d type arguments but want %d", got, want)
			check.use(call.ArgList...)
			x.mode = invalid
			x.expr = call
			return statement
		}

		// If sig is generic and all type arguments are provided, preempt function
		// argument type inference by explicitly instantiating the signature. This
		// ensures that we record accurate type information for sig, even if there
		// is an error checking its arguments (for example, if an incorrect number
		// of arguments is supplied).
		if got == want && want > 0 {
			check.verifyVersionf(inst, go1_18, "function instantiation")
			sig = check.instantiateSignature(inst.Pos(), inst, sig, targs, xlist)
			// targs have been consumed; proceed with checking arguments of the
			// non-generic signature.
			targs = nil
			xlist = nil
		}
	}

	// evaluate arguments
	args, atargs, atxlist := check.genericExprList(call.ArgList)
	sig = check.arguments(call, sig, targs, xlist, args, atargs, atxlist)

	if wasGeneric && sig.TypeParams().Len() == 0 {
		// update the recorded type of call.Fun to its instantiated type
		check.recordTypeAndValue(call.Fun, value, sig, nil)
	}

	// determine result
	switch sig.results.Len() {
	case 0:
		x.mode = novalue
	case 1:
		if cgocall {
			x.mode = commaerr
		} else {
			x.mode = value
		}
		x.typ = sig.results.vars[0].typ // unpack tuple
	default:
		x.mode = value
		x.typ = sig.results
	}
	x.expr = call
	check.hasCallOrRecv = true

	// if type inference failed, a parameterized result must be invalidated
	// (operands cannot have a parameterized type)
	if x.mode == value && sig.TypeParams().Len() > 0 && isParameterized(sig.TypeParams().list(), x.typ) {
		x.mode = invalid
	}

	return statement
}

// exprList evaluates a list of expressions and returns the corresponding operands.
// A single-element expression list may evaluate to multiple operands.
func (check *Checker) exprList(elist []syntax.Expr) (xlist []*operand) {
	if n := len(elist); n == 1 {
		xlist, _ = check.multiExpr(elist[0], false)
	} else if n > 1 {
		// multiple (possibly invalid) values
		xlist = make([]*operand, n)
		for i, e := range elist {
			var x operand
			check.expr(nil, &x, e)
			xlist[i] = &x
		}
	}
	return
}

// genericExprList is like exprList but result operands may be uninstantiated or partially
// instantiated generic functions (where constraint information is insufficient to infer
// the missing type arguments) for Go 1.21 and later.
// For each non-generic or uninstantiated generic operand, the corresponding targsList and
// xlistList elements do not exist (targsList and xlistList are nil) or the elements are nil.
// For each partially instantiated generic function operand, the corresponding targsList and
// xlistList elements are the operand's partial type arguments and type expression lists.
func (check *Checker) genericExprList(elist []syntax.Expr) (resList []*operand, targsList [][]Type, xlistList [][]syntax.Expr) {
	if debug {
		defer func() {
			// targsList and xlistList must have matching lengths
			assert(len(targsList) == len(xlistList))
			// type arguments must only exist for partially instantiated functions
			for i, x := range resList {
				if i < len(targsList) {
					if n := len(targsList[i]); n > 0 {
						// x must be a partially instantiated function
						assert(n < x.typ.(*Signature).TypeParams().Len())
					}
				}
			}
		}()
	}

	// Before Go 1.21, uninstantiated or partially instantiated argument functions are
	// nor permitted. Checker.funcInst must infer missing type arguments in that case.
	infer := true // for -lang < go1.21
	n := len(elist)
	if n > 0 && check.allowVersion(go1_21) {
		infer = false
	}

	if n == 1 {
		// single value (possibly a partially instantiated function), or a multi-valued expression
		e := elist[0]
		var x operand
		if inst, _ := e.(*syntax.IndexExpr); inst != nil && check.indexExpr(&x, inst) {
			// x is a generic function.
			targs, xlist := check.funcInst(nil, x.Pos(), &x, inst, infer)
			if targs != nil {
				// x was not instantiated: collect the (partial) type arguments.
				targsList = [][]Type{targs}
				xlistList = [][]syntax.Expr{xlist}
				// Update x.expr so that we can record the partially instantiated function.
				x.expr = inst
			} else {
				// x was instantiated: we must record it here because we didn't
				// use the usual expression evaluators.
				check.record(&x)
			}
			resList = []*operand{&x}
		} else {
			// x is not a function instantiation (it may still be a generic function).
			check.rawExpr(nil, &x, e, nil, true)
			check.exclude(&x, 1<<novalue|1<<builtin|1<<typexpr)
			if t, ok := x.typ.(*Tuple); ok && x.mode != invalid {
				// x is a function call returning multiple values; it cannot be generic.
				resList = make([]*operand, t.Len())
				for i, v := range t.vars {
					resList[i] = &operand{mode: value, expr: e, typ: v.typ}
				}
			} else {
				// x is exactly one value (possibly invalid or uninstantiated generic function).
				resList = []*operand{&x}
			}
		}
	} else if n > 1 {
		// multiple values
		resList = make([]*operand, n)
		targsList = make([][]Type, n)
		xlistList = make([][]syntax.Expr, n)
		for i, e := range elist {
			var x operand
			if inst, _ := e.(*syntax.IndexExpr); inst != nil && check.indexExpr(&x, inst) {
				// x is a generic function.
				targs, xlist := check.funcInst(nil, x.Pos(), &x, inst, infer)
				if targs != nil {
					// x was not instantiated: collect the (partial) type arguments.
					targsList[i] = targs
					xlistList[i] = xlist
					// Update x.expr so that we can record the partially instantiated function.
					x.expr = inst
				} else {
					// x was instantiated: we must record it here because we didn't
					// use the usual expression evaluators.
					check.record(&x)
				}
			} else {
				// x is exactly one value (possibly invalid or uninstantiated generic function).
				check.genericExpr(&x, e)
			}
			resList[i] = &x
		}
	}

	return
}

// arguments type-checks arguments passed to a function call with the given signature.
// The function and its arguments may be generic, and possibly partially instantiated.
// targs and xlist are the function's type arguments (and corresponding expressions).
// args are the function arguments. If an argument args[i] is a partially instantiated
// generic function, atargs[i] and atxlist[i] are the corresponding type arguments
// (and corresponding expressions).
// If the callee is variadic, arguments adjusts its signature to match the provided
// arguments. The type parameters and arguments of the callee and all its arguments
// are used together to infer any missing type arguments, and the callee and argument
// functions are instantiated as necessary.
// The result signature is the (possibly adjusted and instantiated) function signature.
// If an error occurred, the result signature is the incoming sig.
func (check *Checker) arguments(call *syntax.CallExpr, sig *Signature, targs []Type, xlist []syntax.Expr, args []*operand, atargs [][]Type, atxlist [][]syntax.Expr) (rsig *Signature) {
	rsig = sig

	// Function call argument/parameter count requirements
	//
	//               | standard call    | dotdotdot call |
	// --------------+------------------+----------------+
	// standard func | nargs == npars   | invalid        |
	// --------------+------------------+----------------+
	// variadic func | nargs >= npars-1 | nargs == npars |
	// --------------+------------------+----------------+

	nargs := len(args)
	npars := sig.params.Len()
	ddd := hasDots(call)

	// set up parameters
	sigParams := sig.params // adjusted for variadic functions (may be nil for empty parameter lists!)
	adjusted := false       // indicates if sigParams is different from sig.params
	if sig.variadic {
		if ddd {
			// variadic_func(a, b, c...)
			if len(call.ArgList) == 1 && nargs > 1 {
				// f()... is not permitted if f() is multi-valued
				//check.errorf(call.Ellipsis, "cannot use ... with %d-valued %s", nargs, call.ArgList[0])
				check.errorf(call, InvalidDotDotDot, "cannot use ... with %d-valued %s", nargs, call.ArgList[0])
				return
			}
		} else {
			// variadic_func(a, b, c)
			if nargs >= npars-1 {
				// Create custom parameters for arguments: keep
				// the first npars-1 parameters and add one for
				// each argument mapping to the ... parameter.
				vars := make([]*Var, npars-1) // npars > 0 for variadic functions
				copy(vars, sig.params.vars)
				last := sig.params.vars[npars-1]
				typ := last.typ.(*Slice).elem
				for len(vars) < nargs {
					vars = append(vars, NewParam(last.pos, last.pkg, last.name, typ))
				}
				sigParams = NewTuple(vars...) // possibly nil!
				adjusted = true
				npars = nargs
			} else {
				// nargs < npars-1
				npars-- // for correct error message below
			}
		}
	} else {
		if ddd {
			// standard_func(a, b, c...)
			//check.errorf(call.Ellipsis, "cannot use ... in call to non-variadic %s", call.Fun)
			check.errorf(call, NonVariadicDotDotDot, "cannot use ... in call to non-variadic %s", call.Fun)
			return
		}
		// standard_func(a, b, c)
	}

	// check argument count
	if nargs != npars {
		var at poser = call
		qualifier := "not enough"
		if nargs > npars {
			at = args[npars].expr // report at first extra argument
			qualifier = "too many"
		} else if nargs > 0 {
			at = args[nargs-1].expr // report at last argument
		}
		// take care of empty parameter lists represented by nil tuples
		var params []*Var
		if sig.params != nil {
			params = sig.params.vars
		}
		err := check.newError(WrongArgCount)
		err.addf(at, "%s arguments in call to %s", qualifier, call.Fun)
		err.addf(nopos, "have %s", check.typesSummary(operandTypes(args), false, ddd))
		err.addf(nopos, "want %s", check.typesSummary(varTypes(params), sig.variadic, false))
		err.report()
		return
	}

	// collect type parameters of callee and generic function arguments
	var tparams []*TypeParam

	// collect type parameters of callee
	n := sig.TypeParams().Len()
	if n > 0 {
		if !check.allowVersion(go1_18) {
			if iexpr, _ := call.Fun.(*syntax.IndexExpr); iexpr != nil {
				check.versionErrorf(iexpr, go1_18, "function instantiation")
			} else {
				check.versionErrorf(call, go1_18, "implicit function instantiation")
			}
		}
		// rename type parameters to avoid problems with recursive calls
		var tmp Type
		tparams, tmp = check.renameTParams(call.Pos(), sig.TypeParams().list(), sigParams)
		sigParams = tmp.(*Tuple)
		// make sure targs and tparams have the same length
		for len(targs) < len(tparams) {
			targs = append(targs, nil)
		}
	}
	assert(len(tparams) == len(targs))

	// collect type parameters from generic function arguments
	var genericArgs []int // indices of generic function arguments
	if enableReverseTypeInference {
		for i, arg := range args {
			// generic arguments cannot have a defined (*Named) type - no need for underlying type below
			if asig, _ := arg.typ.(*Signature); asig != nil && asig.TypeParams().Len() > 0 {
				// The argument type is a generic function signature. This type is
				// pointer-identical with (it's copied from) the type of the generic
				// function argument and thus the function object.
				// Before we change the type (type parameter renaming, below), make
				// a clone of it as otherwise we implicitly modify the object's type
				// (go.dev/issues/63260).
				asig = clone(asig)
				// Rename type parameters for cases like f(g, g); this gives each
				// generic function argument a unique type identity (go.dev/issues/59956).
				// TODO(gri) Consider only doing this if a function argument appears
				//           multiple times, which is rare (possible optimization).
				atparams, tmp := check.renameTParams(call.Pos(), asig.TypeParams().list(), asig)
				asig = tmp.(*Signature)
				asig.tparams = &TypeParamList{atparams} // renameTParams doesn't touch associated type parameters
				arg.typ = asig                          // new type identity for the function argument
				tparams = append(tparams, atparams...)
				// add partial list of type arguments, if any
				if i < len(atargs) {
					targs = append(targs, atargs[i]...)
				}
				// make sure targs and tparams have the same length
				for len(targs) < len(tparams) {
					targs = append(targs, nil)
				}
				genericArgs = append(genericArgs, i)
			}
		}
	}
	assert(len(tparams) == len(targs))

	// at the moment we only support implicit instantiations of argument functions
	_ = len(genericArgs) > 0 && check.verifyVersionf(args[genericArgs[0]], go1_21, "implicitly instantiated function as argument")

	// tparams holds the type parameters of the callee and generic function arguments, if any:
	// the first n type parameters belong to the callee, followed by mi type parameters for each
	// of the generic function arguments, where mi = args[i].typ.(*Signature).TypeParams().Len().

	// infer missing type arguments of callee and function arguments
	if len(tparams) > 0 {
		err := check.newError(CannotInferTypeArgs)
		targs = check.infer(call.Pos(), tparams, targs, sigParams, args, false, err)
		if targs == nil {
			// TODO(gri) If infer inferred the first targs[:n], consider instantiating
			//           the call signature for better error messages/gopls behavior.
			//           Perhaps instantiate as much as we can, also for arguments.
			//           This will require changes to how infer returns its results.
			if !err.empty() {
				check.errorf(err.pos(), CannotInferTypeArgs, "in call to %s, %s", call.Fun, err.msg())
			}
			return
		}

		// update result signature: instantiate if needed
		if n > 0 {
			rsig = check.instantiateSignature(call.Pos(), call.Fun, sig, targs[:n], xlist)
			// If the callee's parameter list was adjusted we need to update (instantiate)
			// it separately. Otherwise we can simply use the result signature's parameter
			// list.
			if adjusted {
				sigParams = check.subst(call.Pos(), sigParams, makeSubstMap(tparams[:n], targs[:n]), nil, check.context()).(*Tuple)
			} else {
				sigParams = rsig.params
			}
		}

		// compute argument signatures: instantiate if needed
		j := n
		for _, i := range genericArgs {
			arg := args[i]
			asig := arg.typ.(*Signature)
			k := j + asig.TypeParams().Len()
			// targs[j:k] are the inferred type arguments for asig
			arg.typ = check.instantiateSignature(call.Pos(), arg.expr, asig, targs[j:k], nil) // TODO(gri) provide xlist if possible (partial instantiations)
			check.record(arg)                                                                 // record here because we didn't use the usual expr evaluators
			j = k
		}
	}

	// check arguments
	if len(args) > 0 {
		context := check.sprintf("argument to %s", call.Fun)
		for i, a := range args {
			check.assignment(a, sigParams.vars[i].typ, context)
		}
	}

	return
}

var cgoPrefixes = [...]string{
	"_Ciconst_",
	"_Cfconst_",
	"_Csconst_",
	"_Ctype_",
	"_Cvar_", // actually a pointer to the var
	"_Cfpvar_fp_",
	"_Cfunc_",
	"_Cmacro_", // function to evaluate the expanded expression
}

func (check *Checker) selector(x *operand, e *syntax.SelectorExpr, def *TypeName, wantType bool) {
	// these must be declared before the "goto Error" statements
	var (
		obj      Object
		index    []int
		indirect bool
	)

	sel := e.Sel.Value
	// If the identifier refers to a package, handle everything here
	// so we don't need a "package" mode for operands: package names
	// can only appear in qualified identifiers which are mapped to
	// selector expressions.
	if ident, ok := e.X.(*syntax.Name); ok {
		obj := check.lookup(ident.Value)
		if pname, _ := obj.(*PkgName); pname != nil {
			assert(pname.pkg == check.pkg)
			check.recordUse(ident, pname)
			pname.used = true
			pkg := pname.imported

			var exp Object
			funcMode := value
			if pkg.cgo {
				// cgo special cases C.malloc: it's
				// rewritten to _CMalloc and does not
				// support two-result calls.
				if sel == "malloc" {
					sel = "_CMalloc"
				} else {
					funcMode = cgofunc
				}
				for _, prefix := range cgoPrefixes {
					// cgo objects are part of the current package (in file
					// _cgo_gotypes.go). Use regular lookup.
					exp = check.lookup(prefix + sel)
					if exp != nil {
						break
					}
				}
				if exp == nil {
					if isValidName(sel) {
						check.errorf(e.Sel, UndeclaredImportedName, "undefined: %s", syntax.Expr(e)) // cast to syntax.Expr to silence vet
					}
					goto Error
				}
				check.objDecl(exp, nil)
			} else {
				exp = pkg.scope.Lookup(sel)
				if exp == nil {
					if !pkg.fake && isValidName(sel) {
						check.errorf(e.Sel, UndeclaredImportedName, "undefined: %s", syntax.Expr(e))
					}
					goto Error
				}
				if !exp.Exported() {
					check.errorf(e.Sel, UnexportedName, "name %s not exported by package %s", sel, pkg.name)
					// ok to continue
				}
			}
			check.recordUse(e.Sel, exp)

			// Simplified version of the code for *syntax.Names:
			// - imported objects are always fully initialized
			switch exp := exp.(type) {
			case *Const:
				assert(exp.Val() != nil)
				x.mode = constant_
				x.typ = exp.typ
				x.val = exp.val
			case *TypeName:
				x.mode = typexpr
				x.typ = exp.typ
			case *Var:
				x.mode = variable
				x.typ = exp.typ
				if pkg.cgo && strings.HasPrefix(exp.name, "_Cvar_") {
					x.typ = x.typ.(*Pointer).base
				}
			case *Func:
				x.mode = funcMode
				x.typ = exp.typ
				if pkg.cgo && strings.HasPrefix(exp.name, "_Cmacro_") {
					x.mode = value
					x.typ = x.typ.(*Signature).results.vars[0].typ
				}
			case *Builtin:
				x.mode = builtin
				x.typ = exp.typ
				x.id = exp.id
			default:
				check.dump("%v: unexpected object %v", atPos(e.Sel), exp)
				panic("unreachable")
			}
			x.expr = e
			return
		}
	}

	check.exprOrType(x, e.X, false)
	switch x.mode {
	case typexpr:
		// don't crash for "type T T.x" (was go.dev/issue/51509)
		if def != nil && def.typ == x.typ {
			check.cycleError([]Object{def}, 0)
			goto Error
		}
	case builtin:
		check.errorf(e.Pos(), UncalledBuiltin, "invalid use of %s in selector expression", x)
		goto Error
	case invalid:
		goto Error
	}

	// Avoid crashing when checking an invalid selector in a method declaration
	// (i.e., where def is not set):
	//
	//   type S[T any] struct{}
	//   type V = S[any]
	//   func (fs *S[T]) M(x V.M) {}
	//
	// All codepaths below return a non-type expression. If we get here while
	// expecting a type expression, it is an error.
	//
	// See go.dev/issue/57522 for more details.
	//
	// TODO(rfindley): We should do better by refusing to check selectors in all cases where
	// x.typ is incomplete.
	if wantType {
		check.errorf(e.Sel, NotAType, "%s is not a type", syntax.Expr(e))
		goto Error
	}

	obj, index, indirect = lookupFieldOrMethod(x.typ, x.mode == variable, check.pkg, sel, false)
	if obj == nil {
		// Don't report another error if the underlying type was invalid (go.dev/issue/49541).
		if !isValid(under(x.typ)) {
			goto Error
		}

		if index != nil {
			// TODO(gri) should provide actual type where the conflict happens
			check.errorf(e.Sel, AmbiguousSelector, "ambiguous selector %s.%s", x.expr, sel)
			goto Error
		}

		if indirect {
			if x.mode == typexpr {
				check.errorf(e.Sel, InvalidMethodExpr, "invalid method expression %s.%s (needs pointer receiver (*%s).%s)", x.typ, sel, x.typ, sel)
			} else {
				check.errorf(e.Sel, InvalidMethodExpr, "cannot call pointer method %s on %s", sel, x.typ)
			}
			goto Error
		}

		var why string
		if isInterfacePtr(x.typ) {
			why = check.interfacePtrError(x.typ)
		} else {
			alt, _, _ := lookupFieldOrMethod(x.typ, x.mode == variable, check.pkg, sel, true)
			why = check.lookupError(x.typ, sel, alt, false)
		}
		check.errorf(e.Sel, MissingFieldOrMethod, "%s.%s undefined (%s)", x.expr, sel, why)
		goto Error
	}

	// methods may not have a fully set up signature yet
	if m, _ := obj.(*Func); m != nil {
		check.objDecl(m, nil)
	}

	if x.mode == typexpr {
		// method expression
		m, _ := obj.(*Func)
		if m == nil {
			check.errorf(e.Sel, MissingFieldOrMethod, "%s.%s undefined (type %s has no method %s)", x.expr, sel, x.typ, sel)
			goto Error
		}

		check.recordSelection(e, MethodExpr, x.typ, m, index, indirect)

		sig := m.typ.(*Signature)
		if sig.recv == nil {
			check.error(e, InvalidDeclCycle, "illegal cycle in method declaration")
			goto Error
		}

		// The receiver type becomes the type of the first function
		// argument of the method expression's function type.
		var params []*Var
		if sig.params != nil {
			params = sig.params.vars
		}
		// Be consistent about named/unnamed parameters. This is not needed
		// for type-checking, but the newly constructed signature may appear
		// in an error message and then have mixed named/unnamed parameters.
		// (An alternative would be to not print parameter names in errors,
		// but it's useful to see them; this is cheap and method expressions
		// are rare.)
		name := ""
		if len(params) > 0 && params[0].name != "" {
			// name needed
			name = sig.recv.name
			if name == "" {
				name = "_"
			}
		}
		params = append([]*Var{NewVar(sig.recv.pos, sig.recv.pkg, name, x.typ)}, params...)
		x.mode = value
		x.typ = &Signature{
			tparams:  sig.tparams,
			params:   NewTuple(params...),
			results:  sig.results,
			variadic: sig.variadic,
		}

		check.addDeclDep(m)

	} else {
		// regular selector
		switch obj := obj.(type) {
		case *Var:
			check.recordSelection(e, FieldVal, x.typ, obj, index, indirect)
			if x.mode == variable || indirect {
				x.mode = variable
			} else {
				x.mode = value
			}
			x.typ = obj.typ

		case *Func:
			// TODO(gri) If we needed to take into account the receiver's
			// addressability, should we report the type &(x.typ) instead?
			check.recordSelection(e, MethodVal, x.typ, obj, index, indirect)

			x.mode = value

			// remove receiver
			sig := *obj.typ.(*Signature)
			sig.recv = nil
			x.typ = &sig

			check.addDeclDep(obj)

		default:
			panic("unreachable")
		}
	}

	// everything went well
	x.expr = e
	return

Error:
	x.mode = invalid
	x.expr = e
}

// use type-checks each argument.
// Useful to make sure expressions are evaluated
// (and variables are "used") in the presence of
// other errors. Arguments may be nil.
// Reports if all arguments evaluated without error.
func (check *Checker) use(args ...syntax.Expr) bool { return check.useN(args, false) }

// useLHS is like use, but doesn't "use" top-level identifiers.
// It should be called instead of use if the arguments are
// expressions on the lhs of an assignment.
func (check *Checker) useLHS(args ...syntax.Expr) bool { return check.useN(args, true) }

func (check *Checker) useN(args []syntax.Expr, lhs bool) bool {
	ok := true
	for _, e := range args {
		if !check.use1(e, lhs) {
			ok = false
		}
	}
	return ok
}

func (check *Checker) use1(e syntax.Expr, lhs bool) bool {
	var x operand
	x.mode = value // anything but invalid
	switch n := syntax.Unparen(e).(type) {
	case nil:
		// nothing to do
	case *syntax.Name:
		// don't report an error evaluating blank
		if n.Value == "_" {
			break
		}
		// If the lhs is an identifier denoting a variable v, this assignment
		// is not a 'use' of v. Remember current value of v.used and restore
		// after evaluating the lhs via check.rawExpr.
		var v *Var
		var v_used bool
		if lhs {
			if obj := check.lookup(n.Value); obj != nil {
				// It's ok to mark non-local variables, but ignore variables
				// from other packages to avoid potential race conditions with
				// dot-imported variables.
				if w, _ := obj.(*Var); w != nil && w.pkg == check.pkg {
					v = w
					v_used = v.used
				}
			}
		}
		check.exprOrType(&x, n, true)
		if v != nil {
			v.used = v_used // restore v.used
		}
	case *syntax.ListExpr:
		return check.useN(n.ElemList, lhs)
	default:
		check.rawExpr(nil, &x, e, nil, true)
	}
	return x.mode != invalid
}
```