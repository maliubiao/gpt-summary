Response:
Let's break down the thought process to analyze the provided Go code snippet.

1. **Identify the Core Functionality:** The file path `go/src/go/types/call.go` and the initial comment `// This file implements typechecking of call and selector expressions.` immediately tell us the central theme:  handling function calls and member access (selectors) during Go type checking.

2. **Scan for Key Functions/Methods:** Quickly read through the code, looking for function definitions. The prominent ones are:
    * `funcInst`:  Something about function instantiation, likely related to generics.
    * `instantiateSignature`:  Specifically about creating concrete signatures from generic ones.
    * `callExpr`:  The core logic for processing function call expressions.
    * `exprList`, `genericExprList`:  Handling lists of expressions, with `genericExprList` hinting at special handling for generics.
    * `arguments`:  Type checking the arguments passed to a function.
    * `selector`:  Processing selector expressions (e.g., `x.field`, `pkg.Func`).

3. **Analyze `funcInst`:**
    * **Keywords:** "generic function," "type arguments," "infer."  This confirms its role in handling generic function instantiation.
    * **Two Modes:** The comment explicitly describes two modes: inferring type arguments and instantiating with provided arguments.
    * **Error Handling:** Mentions reporting errors and setting `x.mode` to `invalid`.
    * **Return Values:**  Returns type arguments and expressions in certain scenarios.

4. **Analyze `instantiateSignature`:**
    * **Keywords:** "instantiating signature," "generic," "type arguments."  Clearly responsible for creating a concrete function signature by substituting type parameters with concrete types.
    * **`check.instance`:**  This suggests a mechanism for creating instances of types (likely including signatures).
    * **`check.recordInstance`:**  Indicates that the instantiated signature is stored or associated with the expression.
    * **`check.later`:**  This hints at a deferred verification step, possibly for constraint checking.

5. **Analyze `callExpr`:**
    * **Central Role:**  This seems to be the main entry point for handling function calls.
    * **`unpackIndexedExpr`:** Suggests special handling for calls involving index expressions (likely for specifying type arguments in generic function calls).
    * **Switch on `x.mode`:** Different handling for `invalid`, `typexpr` (conversions), `builtin`, and regular function calls.
    * **Generics Handling:**  The code within the regular function call case explicitly deals with type arguments (`targs`, `xlist`) and calls `check.instantiateSignature`.
    * **Argument Evaluation:** Calls `check.genericExprList` and `check.arguments`.
    * **Result Determination:** Sets `x.mode` and `x.typ` based on the function's return values.

6. **Analyze `exprList` and `genericExprList`:**
    * **Basic Expression Lists:** `exprList` seems to handle simple lists.
    * **Generics in Argument Lists:** `genericExprList` is designed to handle lists where some elements might be partially instantiated generic functions. It distinguishes between instantiated and uninstantiated/partially instantiated cases.

7. **Analyze `arguments`:**
    * **Purpose:** Type checking function arguments.
    * **Variadic Handling:**  Logic to adjust the signature for variadic functions.
    * **Type Parameter Collection and Inference:**  Collects type parameters from the callee and arguments and attempts to infer missing ones.
    * **Instantiation:** Calls `check.instantiateSignature` for both the callee and argument functions.
    * **Assignment Check:**  Uses `check.assignment` to ensure argument types are compatible with parameter types.

8. **Analyze `selector`:**
    * **Member Access:** Handles accessing fields or methods of structs, interfaces, and packages.
    * **Package Handling:**  Special logic for resolving names within imported packages.
    * **Method Expressions:**  Handles creating function values from methods.
    * **Field and Method Resolution:** Uses `lookupFieldOrMethod`.

9. **Synthesize the Overall Functionality:**  Based on the individual function analyses, the overall purpose of `call.go` is to perform type checking related to function calls and selector expressions in Go, with a significant focus on handling generics (type parameters, type arguments, and instantiation).

10. **Infer Go Language Features:**  The presence of `funcInst`, `instantiateSignature`, and handling of type parameters and arguments strongly indicates the implementation of **Go Generics**. The `selector` function also relates to basic Go concepts of structs, interfaces, and packages.

11. **Construct Go Code Examples:**  Create examples that showcase the identified features, focusing on generic function calls and method calls.

12. **Infer Assumptions and Potential Issues:** Consider scenarios where type inference might fail or where the order of operations matters. The comments in the code itself provide hints (e.g., deferred verification, handling of partially instantiated functions). Think about common mistakes users might make with generics (incorrect number of type arguments, type constraint violations).

13. **Refine and Organize:** Structure the answer logically, starting with a high-level summary and then diving into specifics. Use clear headings and code formatting. Ensure the examples are relevant and easy to understand. Present the information about potential pitfalls concisely.

This step-by-step process, moving from identifying core functionality to detailed analysis and then synthesis, allows for a comprehensive understanding of the provided code snippet and its role in the Go type-checking process. The focus on keywords, function signatures, and code comments is crucial for efficiently grasping the essence of the code.
## go/src/go/types/call.go 代码功能归纳 (第1部分)

这段 Go 语言代码是 `go/types` 包中 `call.go` 文件的一部分，主要负责**对函数调用和选择器表达式进行类型检查**。  更具体地说，它实现了以下功能：

**1. 泛型函数实例化 (`funcInst`)：**

* **功能:**  处理泛型函数的实例化过程。当遇到一个泛型函数被调用或赋值时，此函数负责根据提供的类型实参或者通过类型推断，生成一个具体的、非泛型的函数类型。
* **两种操作模式:**
    * **推断模式 (infer = true):**  如果类型实参不完整，尝试根据上下文推断缺失的类型实参，并实例化函数。
    * **直接实例化模式 (infer = false):**  如果提供了所有类型实参，则直接实例化函数。如果提供的类型实参不足，则返回已有的类型实参和对应的表达式。
* **错误处理:**  如果实例化过程中发生错误（非版本错误），会报告错误并将函数的模式设置为 `invalid`。

**2. 实例化签名 (`instantiateSignature`)：**

* **功能:**  基于给定的泛型函数签名和类型实参，创建一个具体的、非泛型的函数签名。
* **延迟验证:**  它使用 `check.later` 延迟执行类型约束的验证，以确保所有必要的类型信息都已就绪。
* **记录实例:**  它会记录泛型函数和其对应的类型实参的实例化结果。

**3. 调用表达式处理 (`callExpr`)：**

* **功能:**  负责处理各种函数调用表达式，包括普通函数调用、方法调用、内置函数调用以及类型转换。
* **处理类型实参:**  如果调用表达式中包含类型实参（通过 `unpackIndexedExpr` 判断），则会提取并检查类型实参的数量。
* **泛型函数调用处理:**  对于泛型函数调用，它会根据是否提供了所有类型实参来决定是立即实例化还是延迟到参数检查阶段。
* **参数类型检查:**  调用 `check.genericExprList` 和 `check.arguments` 来处理函数调用的参数。
* **确定返回值类型:**  根据函数签名的返回值信息，设置调用表达式的模式 (`x.mode`) 和类型 (`x.typ`)。

**4. 表达式列表处理 (`exprList`, `genericExprList`)：**

* **`exprList` 功能:**  评估一个表达式列表，并返回对应的操作数（`operand`）。对于只有一个元素的列表，可能会返回多个操作数（例如，函数返回多个值）。
* **`genericExprList` 功能:**  类似于 `exprList`，但专门用于处理可能包含未实例化或部分实例化的泛型函数的参数列表。它可以区分完全实例化的参数和需要进一步推断类型实参的泛型函数参数，并返回相应的类型实参和表达式列表。

**5. 参数类型检查 (`arguments`)：**

* **功能:**  检查函数调用时提供的参数是否与函数签名匹配。
* **处理变参函数:**  能够处理变参函数，并根据提供的参数调整函数签名。
* **类型推断:**  如果函数或其参数是泛型的，并且缺少类型实参，则尝试进行类型推断。
* **参数赋值检查:**  使用 `check.assignment` 检查实际参数是否可以赋值给形参。

**6. 选择器表达式处理 (`selector`)：**

* **功能:**  处理选择器表达式（例如 `x.y`），用于访问结构体字段、方法或者包中的导出成员。
* **包成员查找:**  如果选择器表达式的左侧是包名，则会在对应的包中查找成员。
* **方法表达式处理:**  能够处理方法表达式（例如 `T.M`）。
* **字段和方法查找:**  使用 `lookupFieldOrMethod` 函数查找字段或方法。
* **类型推断和实例化:**  可能涉及到泛型类型的方法查找和实例化。

**总而言之，这段代码的核心功能是为 Go 语言的函数调用和成员访问提供强大的类型检查机制，尤其关注对泛型特性的支持，包括泛型函数的实例化、类型推断以及参数类型的匹配。**

由于这是第一部分，我们无法涵盖所有功能，但可以确定的是，这段代码集中在处理函数和成员访问相关的类型检查逻辑上。

在第二部分中，可能会涉及更具体的错误报告、类型转换、内置函数处理等方面的实现细节。

### 提示词
```
这是路径为go/src/go/types/call.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This file implements typechecking of call and selector expressions.

package types

import (
	"go/ast"
	"go/token"
	. "internal/types/errors"
	"strings"
)

// funcInst type-checks a function instantiation.
// The incoming x must be a generic function.
// If ix != nil, it provides some or all of the type arguments (ix.Indices).
// If target != nil, it may be used to infer missing type arguments of x, if any.
// At least one of T or ix must be provided.
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
func (check *Checker) funcInst(T *target, pos token.Pos, x *operand, ix *indexedExpr, infer bool) ([]Type, []ast.Expr) {
	assert(T != nil || ix != nil)

	var instErrPos positioner
	if ix != nil {
		instErrPos = inNode(ix.orig, ix.lbrack)
		x.expr = ix.orig // if we don't have an index expression, keep the existing expression of x
	} else {
		instErrPos = atPos(pos)
	}
	versionErr := !check.verifyVersionf(instErrPos, go1_18, "function instantiation")

	// targs and xlist are the type arguments and corresponding type expressions, or nil.
	var targs []Type
	var xlist []ast.Expr
	if ix != nil {
		xlist = ix.indices
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
		check.errorf(ix.indices[got-1], WrongTypeArgCount, "got %d type arguments but want %d", got, want)
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
				if ix != nil {
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
			expr := ast.NewIdent(T.desc)
			expr.NamePos = x.Pos() // correct position
			args = []*operand{{mode: value, expr: expr, typ: T.sig}}
			reverse = true
		}

		// Rename type parameters to avoid problems with recursive instantiations.
		// Note that NewTuple(params...) below is (*Tuple)(nil) if len(params) == 0, as desired.
		tparams, params2 := check.renameTParams(pos, sig.TypeParams().list(), NewTuple(params...))

		err := check.newError(CannotInferTypeArgs)
		targs = check.infer(atPos(pos), tparams, targs, params2.(*Tuple), args, reverse, err)
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

func (check *Checker) instantiateSignature(pos token.Pos, expr ast.Expr, typ *Signature, targs []Type, xlist []ast.Expr) (res *Signature) {
	assert(check != nil)
	assert(len(targs) == typ.TypeParams().Len())

	if check.conf._Trace {
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
				pos = xlist[i].Pos()
			}
			check.softErrorf(atPos(pos), InvalidTypeArg, "%s", err)
		} else {
			check.mono.recordInstance(check.pkg, pos, tparams, targs, xlist)
		}
	}).describef(atPos(pos), "verify instantiation")

	return inst
}

func (check *Checker) callExpr(x *operand, call *ast.CallExpr) exprKind {
	ix := unpackIndexedExpr(call.Fun)
	if ix != nil {
		if check.indexExpr(x, ix) {
			// Delay function instantiation to argument checking,
			// where we combine type and value arguments for type
			// inference.
			assert(x.mode == value)
		} else {
			ix = nil
		}
		x.expr = call.Fun
		check.record(x)
	} else {
		check.exprOrType(x, call.Fun, true)
	}
	// x.typ may be generic

	switch x.mode {
	case invalid:
		check.use(call.Args...)
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
		switch n := len(call.Args); n {
		case 0:
			check.errorf(inNode(call, call.Rparen), WrongArgCount, "missing argument in conversion to %s", T)
		case 1:
			check.expr(nil, x, call.Args[0])
			if x.mode != invalid {
				if hasDots(call) {
					check.errorf(call.Args[0], BadDotDotDotSyntax, "invalid use of ... in conversion to %s", T)
					break
				}
				if t, _ := under(T).(*Interface); t != nil && !isTypeParam(T) {
					if !t.IsMethodSet() {
						check.errorf(call, MisplacedConstraintIface, "cannot use interface %s in conversion (contains specific type constraints or is comparable)", T)
						break
					}
				}
				check.conversion(x, T)
			}
		default:
			check.use(call.Args...)
			check.errorf(call.Args[n-1], WrongArgCount, "too many arguments in conversion to %s", T)
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
	var xlist []ast.Expr
	var targs []Type
	if ix != nil {
		xlist = ix.indices
		targs = check.typeList(xlist)
		if targs == nil {
			check.use(call.Args...)
			x.mode = invalid
			x.expr = call
			return statement
		}
		assert(len(targs) == len(xlist))

		// check number of type arguments (got) vs number of type parameters (want)
		got, want := len(targs), sig.TypeParams().Len()
		if got > want {
			check.errorf(xlist[want], WrongTypeArgCount, "got %d type arguments but want %d", got, want)
			check.use(call.Args...)
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
			check.verifyVersionf(atPos(ix.lbrack), go1_18, "function instantiation")
			sig = check.instantiateSignature(ix.Pos(), ix.orig, sig, targs, xlist)
			// targs have been consumed; proceed with checking arguments of the
			// non-generic signature.
			targs = nil
			xlist = nil
		}
	}

	// evaluate arguments
	args, atargs, atxlist := check.genericExprList(call.Args)
	sig = check.arguments(call, sig, targs, xlist, args, atargs, atxlist)

	if wasGeneric && sig.TypeParams().Len() == 0 {
		// Update the recorded type of call.Fun to its instantiated type.
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
func (check *Checker) exprList(elist []ast.Expr) (xlist []*operand) {
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
func (check *Checker) genericExprList(elist []ast.Expr) (resList []*operand, targsList [][]Type, xlistList [][]ast.Expr) {
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
		if ix := unpackIndexedExpr(e); ix != nil && check.indexExpr(&x, ix) {
			// x is a generic function.
			targs, xlist := check.funcInst(nil, x.Pos(), &x, ix, infer)
			if targs != nil {
				// x was not instantiated: collect the (partial) type arguments.
				targsList = [][]Type{targs}
				xlistList = [][]ast.Expr{xlist}
				// Update x.expr so that we can record the partially instantiated function.
				x.expr = ix.orig
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
		xlistList = make([][]ast.Expr, n)
		for i, e := range elist {
			var x operand
			if ix := unpackIndexedExpr(e); ix != nil && check.indexExpr(&x, ix) {
				// x is a generic function.
				targs, xlist := check.funcInst(nil, x.Pos(), &x, ix, infer)
				if targs != nil {
					// x was not instantiated: collect the (partial) type arguments.
					targsList[i] = targs
					xlistList[i] = xlist
					// Update x.expr so that we can record the partially instantiated function.
					x.expr = ix.orig
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
func (check *Checker) arguments(call *ast.CallExpr, sig *Signature, targs []Type, xlist []ast.Expr, args []*operand, atargs [][]Type, atxlist [][]ast.Expr) (rsig *Signature) {
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
			if len(call.Args) == 1 && nargs > 1 {
				// f()... is not permitted if f() is multi-valued
				check.errorf(inNode(call, call.Ellipsis), InvalidDotDotDot, "cannot use ... with %d-valued %s", nargs, call.Args[0])
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
			check.errorf(inNode(call, call.Ellipsis), NonVariadicDotDotDot, "cannot use ... in call to non-variadic %s", call.Fun)
			return
		}
		// standard_func(a, b, c)
	}

	// check argument count
	if nargs != npars {
		var at positioner = call
		qualifier := "not enough"
		if nargs > npars {
			at = args[npars].expr // report at first extra argument
			qualifier = "too many"
		} else {
			at = atPos(call.Rparen) // report at closing )
		}
		// take care of empty parameter lists represented by nil tuples
		var params []*Var
		if sig.params != nil {
			params = sig.params.vars
		}
		err := check.newError(WrongArgCount)
		err.addf(at, "%s arguments in call to %s", qualifier, call.Fun)
		err.addf(noposn, "have %s", check.typesSummary(operandTypes(args), false, ddd))
		err.addf(noposn, "want %s", check.typesSummary(varTypes(params), sig.variadic, false))
		err.report()
		return
	}

	// collect type parameters of callee and generic function arguments
	var tparams []*TypeParam

	// collect type parameters of callee
	n := sig.TypeParams().Len()
	if n > 0 {
		if !check.allowVersion(go1_18) {
			switch call.Fun.(type) {
			case *ast.IndexExpr, *ast.IndexListExpr:
				ix := unpackIndexedExpr(call.Fun)
				check.versionErrorf(inNode(call.Fun, ix.lbrack), go1_18, "function instantiation")
			default:
				check.versionErrorf(inNode(call, call.Lparen), go1_18, "implicit function instantiation")
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
		targs = check.infer(call, tparams, targs, sigParams, args, false, err)
		if targs == nil {
			// TODO(gri) If infer inferred the first targs[:n], consider instantiating
			//           the call signature for better error messages/gopls behavior.
			//           Perhaps instantiate as much as we can, also for arguments.
			//           This will require changes to how infer returns its results.
			if !err.empty() {
				check.errorf(err.posn(), CannotInferTypeArgs, "in call to %s, %s", call.Fun, err.msg())
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

func (check *Checker) selector(x *operand, e *ast.SelectorExpr, def *TypeName, wantType bool) {
	// these must be declared before the "goto Error" statements
	var (
		obj      Object
		index    []int
		indirect bool
	)

	sel := e.Sel.Name
	// If the identifier refers to a package, handle everything here
	// so we don't need a "package" mode for operands: package names
	// can only appear in qualified identifiers which are mapped to
	// selector expressions.
	if ident, ok := e.X.(*ast.Ident); ok {
		obj := check.lookup(ident.Name)
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
						check.errorf(e.Sel, UndeclaredImportedName, "undefined: %s", ast.Expr(e)) // cast to ast.Expr to silence vet
					}
					goto Error
				}
				check.objDecl(exp, nil)
			} else {
				exp = pkg.scope.Lookup(sel)
				if exp == nil {
					if !pkg.fake && isValidName(sel) {
						check.errorf(e.Sel, UndeclaredImportedName, "undefined: %s", ast.Expr(e))
					}
					goto Error
				}
				if !exp.Exported() {
					check.errorf(e.Sel, UnexportedName, "name %s not exported by package %s", sel, pkg.name)
					// ok to continue
				}
			}
			check.recordUse(e.Sel, exp)

			// Simplified version of the code for *ast.Idents:
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
				check.dump("%v: unexpected object %v", e.Sel.Pos(), exp)
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
		// types2 uses the position of '.' for the error
		check.errorf(e.Sel, UncalledBuiltin, "invalid use of %s in selector expression", x)
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
		check.errorf(e.Sel, NotAType, "%s is not a type", ast.Expr(e))
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

		// the receiver type becomes the type of the first function
		// argument of the method expression's function type
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

			// TODO(gri) The verification pass below is disabled for now because
			//           method sets don't match method lookup in some cases.
			//           For instance, if we made a copy above when creating a
			//           custom method for a parameterized received type, the
			//           method set method doesn't match (no copy there). There
			///          may be other situations.
			disabled := true
			if !disabled && debug {
				// Verify that LookupFieldOrMethod and MethodSet.Lookup agree.
				// TODO(gri) This only works because we call LookupFieldOrMethod
				// _before_ calling NewMethodSet: LookupFieldOrMethod completes
				// any incomplete interfaces so they are available to NewMethodSet
				// (which assumes that interfaces have been completed already).
				typ := x.typ
				if x.mode == variable {
					// If typ is not an (unnamed) pointer or an interface,
					// use *typ instead, because the method set of *typ
					// includes the methods of typ.
					// Variables are addressable, so we can always take their
					// address.
					if _, ok := typ.(*Pointer); !ok && !IsInterface(typ) {
						typ = &Pointer{base: typ}
					}
				}
				// If we created a synthetic pointer type above, we will throw
				// away the method set computed here after use.
				// TODO(gri) Method set computation should probably always compute
				// both, the value and the pointer receiver method set and represent
				// them in a single structure.
				// TODO(gri) Consider also using a method set cache for the lifetime
				// of checker once we rely on MethodSet lookup instead of individual
				// lookup.
				mset := NewMethodSet(typ)
				if m := mset.Lookup(check.pkg, sel); m == nil || m.obj != obj {
					check.dump("%v: (%s).%v -> %s", e.Pos(), typ, obj.name, m)
					check.dump("%s\n", mset)
					// Caution: MethodSets are supposed to be used externally
					// only (after all interface types were completed). It's
					// now possible that we get here incorrectly. Not urgent
					// to fix since we only run this code in debug mode.
					// TODO(gri) fix this eventually.
					panic("method sets and lookup don't agree")
				}
			}

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
func (check *Checker)
```