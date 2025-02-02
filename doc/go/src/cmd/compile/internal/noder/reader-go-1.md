Response: Let's break down the thought process for summarizing the provided Go code snippet.

1. **Initial Scan and Keyword Recognition:**  The first step is to quickly scan the code, looking for recurring patterns, function names, and comments. Keywords like `reader`, `expr`, `type`, `funcInst`, `methodExpr`, `inline`, and comments mentioning "dictionary" and "shape types" immediately stand out. The file path `go/src/cmd/compile/internal/noder/reader.go` also tells us this code is part of the Go compiler's intermediate representation (IR) building process.

2. **Function Grouping and Purpose Identification:**  Next, I mentally group related functions and try to understand their overall purpose.

    * **`expr()` family:** Functions like `expr()`, `optExpr()`, `multiExpr()`, `exprList()`, `exprs()`, `compLit()`, `funcLit()` clearly deal with reading and constructing Go expressions. The different variations suggest handling single expressions, optional expressions, multiple expressions, composite literals, and function literals.

    * **`funcInst()` and `methodExpr()`:** These appear to handle the instantiation of functions and methods, particularly in the context of generics (type parameters) as evidenced by the "dictionary" concepts.

    * **`syntheticClosure()`, `curry()`, `methodExprWrap()`:** These functions are involved in creating synthetic function literals, likely for implementing features like currying and adapting method signatures.

    * **`inline` related functions:**  `unifiedHaveInlineBody()`, `unifiedInlineCall()`, `expandInline()`, `inlReturn()` clearly handle the inlining of function calls.

    * **`wrapper` related functions:** Functions like `needWrapper()`, `MakeWrappers()`, `wrapType()`, `methodWrapper()`, `wrapMethodValue()` are dedicated to generating "wrapper" functions for adapting method calls in various scenarios (pointer receivers, promoted methods, method values).

    * **`rtype()` and `convRTTI()`:** These deal with reading and handling runtime type information (RTTI), crucial for type conversions and interface implementations.

    * **`pkgInit()` family:** `pkgInit()`, `pkgInitOrder()`, `pkgDecls()`, `pkgObjs()` are responsible for reading and processing package-level declarations and initialization.

3. **Identifying Core Concepts and Relationships:**  Based on the function groupings, I identify the core concepts and how they relate:

    * **Reading and Building IR:** The `reader` struct is central to reading information from the compiled package data and constructing the Go compiler's IR.

    * **Generics/Type Parameters:**  The frequent mentions of "dictionary," `funcInst()`, and `methodExpr()` with dictionary parameters indicate a significant focus on handling generics.

    * **Inlining:** The `inline` functions demonstrate the compiler's inlining capabilities.

    * **Method Wrappers:** The `wrapper` functions reveal how the compiler adapts methods for different calling conventions.

    * **Runtime Type Information (RTTI):**  The `rtype` and `convRTTI` functions highlight the importance of RTTI for type safety and dynamic dispatch.

4. **Inferring Go Feature Implementations (with Caveats):** This is where the "reasoning" comes in. I connect the code patterns to specific Go language features.

    * **Generics:**  The "dictionary" concept strongly suggests the implementation of Go generics. The dictionary holds runtime type information needed when working with type parameters. `funcInst()` and `methodExpr()` handle calling generic functions and methods.

    * **Inlining:**  The `unifiedInlineCall()` function directly implements function inlining.

    * **Method Sets and Interface Satisfaction:** The `wrapper` functions are crucial for implementing Go's method sets, including how value receiver methods are accessible through pointer receivers, and how embedding works. They are also used for method values, which are closely related to interface satisfaction.

    * **Type Conversions and Interfaces:**  The `convRTTI()` function is directly related to how type conversions, especially involving interfaces, are implemented at runtime.

5. **Structuring the Summary:** I organize the identified functions and concepts into logical categories for clarity. I start with the main purpose and then delve into specific features. I explicitly mention the "part 2" aspect of the request and summarize the overall function.

6. **Refining and Adding Detail:** I review the initial summary and add more specific details about the purpose of individual functions or groups of functions. For instance, I specify that `funcInst()` handles instantiated function references and `methodExpr()` handles method expressions. I also mention the nuances of the dictionary parameter.

7. **Considering Potential Mistakes (Self-Correction):** I briefly consider common errors a user might make when dealing with these concepts, although the prompt asked to skip this if there weren't any obvious ones directly within this *code* (as opposed to using the *feature*). In this case, it's less about user errors with the *code* and more about understanding how the compiler *implements* these features.

8. **Review and Finalization:**  I read through the entire summary to ensure accuracy, clarity, and completeness based on the provided code snippet. I make sure the overall summary at the end captures the essence of the code.
这是对Go语言编译器中 `go/src/cmd/compile/internal/noder/reader.go` 文件一部分代码的功能归纳。

**功能归纳:**

这部分代码主要负责从编译后的包数据中读取信息，并构建Go语言程序的抽象语法树 (AST) 中的表达式节点 (`ir.Node`)。它处理各种Go语言表达式的读取和重建，特别是与以下功能密切相关：

* **读取和重建各种Go语言表达式:** 包括基础的字面量、标识符、运算符、函数调用、方法调用、类型转换、复合字面量、函数字面量等。
* **处理泛型 (Type Parameters):** 代码中大量涉及 "dictionary" (字典) 的概念，这指的是在编译时为泛型函数和类型生成的字典数据，用于在运行时提供类型信息。`funcInst` 和 `methodExpr` 函数负责读取和处理泛型函数和方法的实例化。
* **处理方法表达式和方法值:** 代码能够读取和重建方法表达式 (`x.M`) 和方法值 (`t.M`)。
* **处理内联 (Inlining):** 代码包含 `unifiedInlineCall` 等函数，负责在读取编译后的数据时处理函数内联。
* **处理类型转换:** `exprConvert` 分支以及 `convRTTI` 函数负责读取和处理各种类型转换，包括接口类型转换，并处理运行时类型信息 (RTTI)。
* **处理复合字面量:** `compLit` 函数负责读取和构建结构体、数组、切片和映射的复合字面量。
* **处理闭包 (Closures):** `funcLit` 和 `syntheticClosure` 函数负责读取和构建函数字面量（闭包）。
* **处理方法包装器 (Method Wrappers):**  代码生成用于适应不同调用约定的方法包装器，例如处理值接收者方法在指针接收者上的调用。
* **处理包级别的初始化:** `pkgInit` 及其相关函数负责读取和处理包级别的变量初始化和 `init` 函数。

**可以推理出的Go语言功能的实现:**

这部分代码的核心目标是实现 Go 语言的**泛型 (Generics)** 和相关的语言特性，例如**方法表达式**、**方法值**、**类型转换**以及**函数内联**。

**Go代码举例说明 (泛型):**

假设有如下的 Go 语言代码：

```go
package main

import "fmt"

func Print[T any](s []T) {
	for _, v := range s {
		fmt.Println(v)
	}
}

func main() {
	ints := []int{1, 2, 3}
	strings := []string{"hello", "world"}
	Print(ints)
	Print(strings)
}
```

**假设的输入与输出 (泛型):**

当编译器处理 `Print(ints)` 和 `Print(strings)` 这两个调用时，`reader.go` 的这部分代码会从编译后的包数据中读取关于 `Print` 函数的信息，包括其泛型类型参数。

* **假设输入 (对于 `Print(ints)`):** 编译后的数据会包含 `Print` 函数的符号信息，以及用于实例化 `Print[int]` 的类型信息 (关于 `int`)。 还会包含指示这是一个泛型函数实例化的信息。
* **假设输出 (对于 `Print(ints)`):**  `funcInst` 函数（或者相关的处理逻辑）会构建一个表示 `Print[int]` 的 `ir.Name` 节点，可能还会包含一个指向用于 `int` 类型的字典数据的引用 (`dictPtr`)。

* **假设输入 (对于 `Print(strings)`):**  编译后的数据会包含 `Print` 函数的符号信息，以及用于实例化 `Print[string]` 的类型信息 (关于 `string`)。
* **假设输出 (对于 `Print(strings)`):**  `funcInst` 函数会构建一个表示 `Print[string]` 的 `ir.Name` 节点，可能也会包含一个指向用于 `string` 类型的字典数据的引用。

**Go代码举例说明 (类型转换):**

```go
package main

import "fmt"

type MyInt int

func main() {
	var i int = 10
	var mi MyInt = MyInt(i)
	var iface interface{} = mi
	_, ok := iface.(MyInt)
	fmt.Println(ok)
}
```

**假设的输入与输出 (类型转换):**

* **假设输入 (对于 `MyInt(i)`):** 编译后的数据会包含类型转换操作的信息，源类型 `int` 和目标类型 `MyInt`。
* **假设输出 (对于 `MyInt(i)`):** `exprConvert` 函数会构建一个 `ir.ConvExpr` 节点，表示类型转换操作。

* **假设输入 (对于 `iface.(MyInt)`):** 编译后的数据会包含类型断言操作的信息，接口类型 `interface{}` 和要断言的类型 `MyInt`。
* **假设输出 (对于 `iface.(MyInt)`):**  `expr` 函数会根据操作码构建相应的类型断言节点。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的解析和处理通常发生在编译器的其他阶段，例如 `go/src/cmd/compile/main.go` 中。 这部分代码读取的是已经过命令行参数影响后生成的编译结果数据。

**使用者易犯错的点:**

虽然这段代码是编译器内部实现，普通 Go 开发者不会直接使用，但理解其功能有助于理解一些 Go 语言特性背后的机制，例如：

* **泛型的开销:** 字典传递等机制在运行时会有一定的性能开销。
* **类型转换的限制:** 理解类型转换的底层机制可以帮助开发者避免一些不合法的类型转换。
* **内联的条件:**  了解编译器如何进行内联决策，可以帮助开发者编写更易于优化的代码。

**归纳一下它的功能:**

作为 `go/src/cmd/compile/internal/noder/reader.go` 的一部分，这段代码的核心功能是**从编译后的包数据中读取信息，并负责重建 Go 语言程序的表达式节点，特别是处理与泛型、方法、类型转换和内联相关的表达式**。 它在 Go 语言编译器的前端扮演着关键的角色，将编译后的中间表示转换成编译器可以进一步处理的抽象语法树。

### 提示词
```
这是路径为go/src/cmd/compile/internal/noder/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
eld(r.Len())
			offset += field.Offset
			typ = field.Type
		}

		return ir.NewUintptr(pos, offset)

	case exprReshape:
		typ := r.typ()
		x := r.expr()

		if types.IdenticalStrict(x.Type(), typ) {
			return x
		}

		// Comparison expressions are constructed as "untyped bool" still.
		//
		// TODO(mdempsky): It should be safe to reshape them here too, but
		// maybe it's better to construct them with the proper type
		// instead.
		if x.Type() == types.UntypedBool && typ.IsBoolean() {
			return x
		}

		base.AssertfAt(x.Type().HasShape() || typ.HasShape(), x.Pos(), "%L and %v are not shape types", x, typ)
		base.AssertfAt(types.Identical(x.Type(), typ), x.Pos(), "%L is not shape-identical to %v", x, typ)

		// We use ir.HasUniquePos here as a check that x only appears once
		// in the AST, so it's okay for us to call SetType without
		// breaking any other uses of it.
		//
		// Notably, any ONAMEs should already have the exactly right shape
		// type and been caught by types.IdenticalStrict above.
		base.AssertfAt(ir.HasUniquePos(x), x.Pos(), "cannot call SetType(%v) on %L", typ, x)

		if base.Debug.Reshape != 0 {
			base.WarnfAt(x.Pos(), "reshaping %L to %v", x, typ)
		}

		x.SetType(typ)
		return x

	case exprConvert:
		implicit := r.Bool()
		typ := r.typ()
		pos := r.pos()
		typeWord, srcRType := r.convRTTI(pos)
		dstTypeParam := r.Bool()
		identical := r.Bool()
		x := r.expr()

		// TODO(mdempsky): Stop constructing expressions of untyped type.
		x = typecheck.DefaultLit(x, typ)

		ce := ir.NewConvExpr(pos, ir.OCONV, typ, x)
		ce.TypeWord, ce.SrcRType = typeWord, srcRType
		if implicit {
			ce.SetImplicit(true)
		}
		n := typecheck.Expr(ce)

		// Conversions between non-identical, non-empty interfaces always
		// requires a runtime call, even if they have identical underlying
		// interfaces. This is because we create separate itab instances
		// for each unique interface type, not merely each unique
		// interface shape.
		//
		// However, due to shape types, typecheck.Expr might mistakenly
		// think a conversion between two non-empty interfaces are
		// identical and set ir.OCONVNOP, instead of ir.OCONVIFACE. To
		// ensure we update the itab field appropriately, we force it to
		// ir.OCONVIFACE instead when shape types are involved.
		//
		// TODO(mdempsky): Are there other places we might get this wrong?
		// Should this be moved down into typecheck.{Assign,Convert}op?
		// This would be a non-issue if itabs were unique for each
		// *underlying* interface type instead.
		if !identical {
			if n, ok := n.(*ir.ConvExpr); ok && n.Op() == ir.OCONVNOP && n.Type().IsInterface() && !n.Type().IsEmptyInterface() && (n.Type().HasShape() || n.X.Type().HasShape()) {
				n.SetOp(ir.OCONVIFACE)
			}
		}

		// spec: "If the type is a type parameter, the constant is converted
		// into a non-constant value of the type parameter."
		if dstTypeParam && ir.IsConstNode(n) {
			// Wrap in an OCONVNOP node to ensure result is non-constant.
			n = Implicit(ir.NewConvExpr(pos, ir.OCONVNOP, n.Type(), n))
			n.SetTypecheck(1)
		}
		return n

	case exprRuntimeBuiltin:
		builtin := typecheck.LookupRuntime(r.String())
		return builtin
	}
}

// funcInst reads an instantiated function reference, and returns
// three (possibly nil) expressions related to it:
//
// baseFn is always non-nil: it's either a function of the appropriate
// type already, or it has an extra dictionary parameter as the first
// parameter.
//
// If dictPtr is non-nil, then it's a dictionary argument that must be
// passed as the first argument to baseFn.
//
// If wrapperFn is non-nil, then it's either the same as baseFn (if
// dictPtr is nil), or it's semantically equivalent to currying baseFn
// to pass dictPtr. (wrapperFn is nil when dictPtr is an expression
// that needs to be computed dynamically.)
//
// For callers that are creating a call to the returned function, it's
// best to emit a call to baseFn, and include dictPtr in the arguments
// list as appropriate.
//
// For callers that want to return the function without invoking it,
// they may return wrapperFn if it's non-nil; but otherwise, they need
// to create their own wrapper.
func (r *reader) funcInst(pos src.XPos) (wrapperFn, baseFn, dictPtr ir.Node) {
	// Like in methodExpr, I'm pretty sure this isn't needed.
	var implicits []*types.Type
	if r.dict != nil {
		implicits = r.dict.targs
	}

	if r.Bool() { // dynamic subdictionary
		idx := r.Len()
		info := r.dict.subdicts[idx]
		explicits := r.p.typListIdx(info.explicits, r.dict)

		baseFn = r.p.objIdx(info.idx, implicits, explicits, true).(*ir.Name)

		// TODO(mdempsky): Is there a more robust way to get the
		// dictionary pointer type here?
		dictPtrType := baseFn.Type().Param(0).Type
		dictPtr = typecheck.Expr(ir.NewConvExpr(pos, ir.OCONVNOP, dictPtrType, r.dictWord(pos, r.dict.subdictsOffset()+idx)))

		return
	}

	info := r.objInfo()
	explicits := r.p.typListIdx(info.explicits, r.dict)

	wrapperFn = r.p.objIdx(info.idx, implicits, explicits, false).(*ir.Name)
	baseFn = r.p.objIdx(info.idx, implicits, explicits, true).(*ir.Name)

	dictName := r.p.objDictName(info.idx, implicits, explicits)
	dictPtr = typecheck.Expr(ir.NewAddrExpr(pos, dictName))

	return
}

func (pr *pkgReader) objDictName(idx index, implicits, explicits []*types.Type) *ir.Name {
	rname := pr.newReader(pkgbits.RelocName, idx, pkgbits.SyncObject1)
	_, sym := rname.qualifiedIdent()
	tag := pkgbits.CodeObj(rname.Code(pkgbits.SyncCodeObj))

	if tag == pkgbits.ObjStub {
		assert(!sym.IsBlank())
		if pri, ok := objReader[sym]; ok {
			return pri.pr.objDictName(pri.idx, nil, explicits)
		}
		base.Fatalf("unresolved stub: %v", sym)
	}

	dict, err := pr.objDictIdx(sym, idx, implicits, explicits, false)
	if err != nil {
		base.Fatalf("%v", err)
	}

	return pr.dictNameOf(dict)
}

// curry returns a function literal that calls fun with arg0 and
// (optionally) arg1, accepting additional arguments to the function
// literal as necessary to satisfy fun's signature.
//
// If nilCheck is true and arg0 is an interface value, then it's
// checked to be non-nil as an initial step at the point of evaluating
// the function literal itself.
func (r *reader) curry(origPos src.XPos, ifaceHack bool, fun ir.Node, arg0, arg1 ir.Node) ir.Node {
	var captured ir.Nodes
	captured.Append(fun, arg0)
	if arg1 != nil {
		captured.Append(arg1)
	}

	params, results := syntheticSig(fun.Type())
	params = params[len(captured)-1:] // skip curried parameters
	typ := types.NewSignature(nil, params, results)

	addBody := func(pos src.XPos, r *reader, captured []ir.Node) {
		fun := captured[0]

		var args ir.Nodes
		args.Append(captured[1:]...)
		args.Append(r.syntheticArgs()...)

		r.syntheticTailCall(pos, fun, args)
	}

	return r.syntheticClosure(origPos, typ, ifaceHack, captured, addBody)
}

// methodExprWrap returns a function literal that changes method's
// first parameter's type to recv, and uses implicits/deref/addr to
// select the appropriate receiver parameter to pass to method.
func (r *reader) methodExprWrap(origPos src.XPos, recv *types.Type, implicits []int, deref, addr bool, method, dictPtr ir.Node) ir.Node {
	var captured ir.Nodes
	captured.Append(method)

	params, results := syntheticSig(method.Type())

	// Change first parameter to recv.
	params[0].Type = recv

	// If we have a dictionary pointer argument to pass, then omit the
	// underlying method expression's dictionary parameter from the
	// returned signature too.
	if dictPtr != nil {
		captured.Append(dictPtr)
		params = append(params[:1], params[2:]...)
	}

	typ := types.NewSignature(nil, params, results)

	addBody := func(pos src.XPos, r *reader, captured []ir.Node) {
		fn := captured[0]
		args := r.syntheticArgs()

		// Rewrite first argument based on implicits/deref/addr.
		{
			arg := args[0]
			for _, ix := range implicits {
				arg = Implicit(typecheck.DotField(pos, arg, ix))
			}
			if deref {
				arg = Implicit(Deref(pos, arg.Type().Elem(), arg))
			} else if addr {
				arg = Implicit(Addr(pos, arg))
			}
			args[0] = arg
		}

		// Insert dictionary argument, if provided.
		if dictPtr != nil {
			newArgs := make([]ir.Node, len(args)+1)
			newArgs[0] = args[0]
			newArgs[1] = captured[1]
			copy(newArgs[2:], args[1:])
			args = newArgs
		}

		r.syntheticTailCall(pos, fn, args)
	}

	return r.syntheticClosure(origPos, typ, false, captured, addBody)
}

// syntheticClosure constructs a synthetic function literal for
// currying dictionary arguments. origPos is the position used for the
// closure, which must be a non-inlined position. typ is the function
// literal's signature type.
//
// captures is a list of expressions that need to be evaluated at the
// point of function literal evaluation and captured by the function
// literal. If ifaceHack is true and captures[1] is an interface type,
// it's checked to be non-nil after evaluation.
//
// addBody is a callback function to populate the function body. The
// list of captured values passed back has the captured variables for
// use within the function literal, corresponding to the expressions
// in captures.
func (r *reader) syntheticClosure(origPos src.XPos, typ *types.Type, ifaceHack bool, captures ir.Nodes, addBody func(pos src.XPos, r *reader, captured []ir.Node)) ir.Node {
	// isSafe reports whether n is an expression that we can safely
	// defer to evaluating inside the closure instead, to avoid storing
	// them into the closure.
	//
	// In practice this is always (and only) the wrappee function.
	isSafe := func(n ir.Node) bool {
		if n.Op() == ir.ONAME && n.(*ir.Name).Class == ir.PFUNC {
			return true
		}
		if n.Op() == ir.OMETHEXPR {
			return true
		}

		return false
	}

	fn := r.inlClosureFunc(origPos, typ, ir.OCLOSURE)
	fn.SetWrapper(true)

	clo := fn.OClosure
	inlPos := clo.Pos()

	var init ir.Nodes
	for i, n := range captures {
		if isSafe(n) {
			continue // skip capture; can reference directly
		}

		tmp := r.tempCopy(inlPos, n, &init)
		ir.NewClosureVar(origPos, fn, tmp)

		// We need to nil check interface receivers at the point of method
		// value evaluation, ugh.
		if ifaceHack && i == 1 && n.Type().IsInterface() {
			check := ir.NewUnaryExpr(inlPos, ir.OCHECKNIL, ir.NewUnaryExpr(inlPos, ir.OITAB, tmp))
			init.Append(typecheck.Stmt(check))
		}
	}

	pri := pkgReaderIndex{synthetic: func(pos src.XPos, r *reader) {
		captured := make([]ir.Node, len(captures))
		next := 0
		for i, n := range captures {
			if isSafe(n) {
				captured[i] = n
			} else {
				captured[i] = r.closureVars[next]
				next++
			}
		}
		assert(next == len(r.closureVars))

		addBody(origPos, r, captured)
	}}
	bodyReader[fn] = pri
	pri.funcBody(fn)

	return ir.InitExpr(init, clo)
}

// syntheticSig duplicates and returns the params and results lists
// for sig, but renaming anonymous parameters so they can be assigned
// ir.Names.
func syntheticSig(sig *types.Type) (params, results []*types.Field) {
	clone := func(params []*types.Field) []*types.Field {
		res := make([]*types.Field, len(params))
		for i, param := range params {
			// TODO(mdempsky): It would be nice to preserve the original
			// parameter positions here instead, but at least
			// typecheck.NewMethodType replaces them with base.Pos, making
			// them useless. Worse, the positions copied from base.Pos may
			// have inlining contexts, which we definitely don't want here
			// (e.g., #54625).
			res[i] = types.NewField(base.AutogeneratedPos, param.Sym, param.Type)
			res[i].SetIsDDD(param.IsDDD())
		}
		return res
	}

	return clone(sig.Params()), clone(sig.Results())
}

func (r *reader) optExpr() ir.Node {
	if r.Bool() {
		return r.expr()
	}
	return nil
}

// methodExpr reads a method expression reference, and returns three
// (possibly nil) expressions related to it:
//
// baseFn is always non-nil: it's either a function of the appropriate
// type already, or it has an extra dictionary parameter as the second
// parameter (i.e., immediately after the promoted receiver
// parameter).
//
// If dictPtr is non-nil, then it's a dictionary argument that must be
// passed as the second argument to baseFn.
//
// If wrapperFn is non-nil, then it's either the same as baseFn (if
// dictPtr is nil), or it's semantically equivalent to currying baseFn
// to pass dictPtr. (wrapperFn is nil when dictPtr is an expression
// that needs to be computed dynamically.)
//
// For callers that are creating a call to the returned method, it's
// best to emit a call to baseFn, and include dictPtr in the arguments
// list as appropriate.
//
// For callers that want to return a method expression without
// invoking it, they may return wrapperFn if it's non-nil; but
// otherwise, they need to create their own wrapper.
func (r *reader) methodExpr() (wrapperFn, baseFn, dictPtr ir.Node) {
	recv := r.typ()
	sig0 := r.typ()
	pos := r.pos()
	sym := r.selector()

	// Signature type to return (i.e., recv prepended to the method's
	// normal parameters list).
	sig := typecheck.NewMethodType(sig0, recv)

	if r.Bool() { // type parameter method expression
		idx := r.Len()
		word := r.dictWord(pos, r.dict.typeParamMethodExprsOffset()+idx)

		// TODO(mdempsky): If the type parameter was instantiated with an
		// interface type (i.e., embed.IsInterface()), then we could
		// return the OMETHEXPR instead and save an indirection.

		// We wrote the method expression's entry point PC into the
		// dictionary, but for Go `func` values we need to return a
		// closure (i.e., pointer to a structure with the PC as the first
		// field). Because method expressions don't have any closure
		// variables, we pun the dictionary entry as the closure struct.
		fn := typecheck.Expr(ir.NewConvExpr(pos, ir.OCONVNOP, sig, ir.NewAddrExpr(pos, word)))
		return fn, fn, nil
	}

	// TODO(mdempsky): I'm pretty sure this isn't needed: implicits is
	// only relevant to locally defined types, but they can't have
	// (non-promoted) methods.
	var implicits []*types.Type
	if r.dict != nil {
		implicits = r.dict.targs
	}

	if r.Bool() { // dynamic subdictionary
		idx := r.Len()
		info := r.dict.subdicts[idx]
		explicits := r.p.typListIdx(info.explicits, r.dict)

		shapedObj := r.p.objIdx(info.idx, implicits, explicits, true).(*ir.Name)
		shapedFn := shapedMethodExpr(pos, shapedObj, sym)

		// TODO(mdempsky): Is there a more robust way to get the
		// dictionary pointer type here?
		dictPtrType := shapedFn.Type().Param(1).Type
		dictPtr := typecheck.Expr(ir.NewConvExpr(pos, ir.OCONVNOP, dictPtrType, r.dictWord(pos, r.dict.subdictsOffset()+idx)))

		return nil, shapedFn, dictPtr
	}

	if r.Bool() { // static dictionary
		info := r.objInfo()
		explicits := r.p.typListIdx(info.explicits, r.dict)

		shapedObj := r.p.objIdx(info.idx, implicits, explicits, true).(*ir.Name)
		shapedFn := shapedMethodExpr(pos, shapedObj, sym)

		dict := r.p.objDictName(info.idx, implicits, explicits)
		dictPtr := typecheck.Expr(ir.NewAddrExpr(pos, dict))

		// Check that dictPtr matches shapedFn's dictionary parameter.
		if !types.Identical(dictPtr.Type(), shapedFn.Type().Param(1).Type) {
			base.FatalfAt(pos, "dict %L, but shaped method %L", dict, shapedFn)
		}

		// For statically known instantiations, we can take advantage of
		// the stenciled wrapper.
		base.AssertfAt(!recv.HasShape(), pos, "shaped receiver %v", recv)
		wrapperFn := typecheck.NewMethodExpr(pos, recv, sym)
		base.AssertfAt(types.Identical(sig, wrapperFn.Type()), pos, "wrapper %L does not have type %v", wrapperFn, sig)

		return wrapperFn, shapedFn, dictPtr
	}

	// Simple method expression; no dictionary needed.
	base.AssertfAt(!recv.HasShape() || recv.IsInterface(), pos, "shaped receiver %v", recv)
	fn := typecheck.NewMethodExpr(pos, recv, sym)
	return fn, fn, nil
}

// shapedMethodExpr returns the specified method on the given shaped
// type.
func shapedMethodExpr(pos src.XPos, obj *ir.Name, sym *types.Sym) *ir.SelectorExpr {
	assert(obj.Op() == ir.OTYPE)

	typ := obj.Type()
	assert(typ.HasShape())

	method := func() *types.Field {
		for _, method := range typ.Methods() {
			if method.Sym == sym {
				return method
			}
		}

		base.FatalfAt(pos, "failed to find method %v in shaped type %v", sym, typ)
		panic("unreachable")
	}()

	// Construct an OMETHEXPR node.
	recv := method.Type.Recv().Type
	return typecheck.NewMethodExpr(pos, recv, sym)
}

func (r *reader) multiExpr() []ir.Node {
	r.Sync(pkgbits.SyncMultiExpr)

	if r.Bool() { // N:1
		pos := r.pos()
		expr := r.expr()

		results := make([]ir.Node, r.Len())
		as := ir.NewAssignListStmt(pos, ir.OAS2, nil, []ir.Node{expr})
		as.Def = true
		for i := range results {
			tmp := r.temp(pos, r.typ())
			as.PtrInit().Append(ir.NewDecl(pos, ir.ODCL, tmp))
			as.Lhs.Append(tmp)

			res := ir.Node(tmp)
			if r.Bool() {
				n := ir.NewConvExpr(pos, ir.OCONV, r.typ(), res)
				n.TypeWord, n.SrcRType = r.convRTTI(pos)
				n.SetImplicit(true)
				res = typecheck.Expr(n)
			}
			results[i] = res
		}

		// TODO(mdempsky): Could use ir.InlinedCallExpr instead?
		results[0] = ir.InitExpr([]ir.Node{typecheck.Stmt(as)}, results[0])
		return results
	}

	// N:N
	exprs := make([]ir.Node, r.Len())
	if len(exprs) == 0 {
		return nil
	}
	for i := range exprs {
		exprs[i] = r.expr()
	}
	return exprs
}

// temp returns a new autotemp of the specified type.
func (r *reader) temp(pos src.XPos, typ *types.Type) *ir.Name {
	return typecheck.TempAt(pos, r.curfn, typ)
}

// tempCopy declares and returns a new autotemp initialized to the
// value of expr.
func (r *reader) tempCopy(pos src.XPos, expr ir.Node, init *ir.Nodes) *ir.Name {
	tmp := r.temp(pos, expr.Type())

	init.Append(typecheck.Stmt(ir.NewDecl(pos, ir.ODCL, tmp)))

	assign := ir.NewAssignStmt(pos, tmp, expr)
	assign.Def = true
	init.Append(typecheck.Stmt(ir.NewAssignStmt(pos, tmp, expr)))

	tmp.Defn = assign

	return tmp
}

func (r *reader) compLit() ir.Node {
	r.Sync(pkgbits.SyncCompLit)
	pos := r.pos()
	typ0 := r.typ()

	typ := typ0
	if typ.IsPtr() {
		typ = typ.Elem()
	}
	if typ.Kind() == types.TFORW {
		base.FatalfAt(pos, "unresolved composite literal type: %v", typ)
	}
	var rtype ir.Node
	if typ.IsMap() {
		rtype = r.rtype(pos)
	}
	isStruct := typ.Kind() == types.TSTRUCT

	elems := make([]ir.Node, r.Len())
	for i := range elems {
		elemp := &elems[i]

		if isStruct {
			sk := ir.NewStructKeyExpr(r.pos(), typ.Field(r.Len()), nil)
			*elemp, elemp = sk, &sk.Value
		} else if r.Bool() {
			kv := ir.NewKeyExpr(r.pos(), r.expr(), nil)
			*elemp, elemp = kv, &kv.Value
		}

		*elemp = r.expr()
	}

	lit := typecheck.Expr(ir.NewCompLitExpr(pos, ir.OCOMPLIT, typ, elems))
	if rtype != nil {
		lit := lit.(*ir.CompLitExpr)
		lit.RType = rtype
	}
	if typ0.IsPtr() {
		lit = typecheck.Expr(typecheck.NodAddrAt(pos, lit))
		lit.SetType(typ0)
	}
	return lit
}

func (r *reader) funcLit() ir.Node {
	r.Sync(pkgbits.SyncFuncLit)

	// The underlying function declaration (including its parameters'
	// positions, if any) need to remain the original, uninlined
	// positions. This is because we track inlining-context on nodes so
	// we can synthesize the extra implied stack frames dynamically when
	// generating tracebacks, whereas those stack frames don't make
	// sense *within* the function literal. (Any necessary inlining
	// adjustments will have been applied to the call expression
	// instead.)
	//
	// This is subtle, and getting it wrong leads to cycles in the
	// inlining tree, which lead to infinite loops during stack
	// unwinding (#46234, #54625).
	//
	// Note that we *do* want the inline-adjusted position for the
	// OCLOSURE node, because that position represents where any heap
	// allocation of the closure is credited (#49171).
	r.suppressInlPos++
	origPos := r.pos()
	sig := r.signature(nil)
	r.suppressInlPos--
	why := ir.OCLOSURE
	if r.Bool() {
		why = ir.ORANGE
	}

	fn := r.inlClosureFunc(origPos, sig, why)

	fn.ClosureVars = make([]*ir.Name, 0, r.Len())
	for len(fn.ClosureVars) < cap(fn.ClosureVars) {
		// TODO(mdempsky): I think these should be original positions too
		// (i.e., not inline-adjusted).
		ir.NewClosureVar(r.pos(), fn, r.useLocal())
	}
	if param := r.dictParam; param != nil {
		// If we have a dictionary parameter, capture it too. For
		// simplicity, we capture it last and unconditionally.
		ir.NewClosureVar(param.Pos(), fn, param)
	}

	r.addBody(fn, nil)

	return fn.OClosure
}

// inlClosureFunc constructs a new closure function, but correctly
// handles inlining.
func (r *reader) inlClosureFunc(origPos src.XPos, sig *types.Type, why ir.Op) *ir.Func {
	curfn := r.inlCaller
	if curfn == nil {
		curfn = r.curfn
	}

	// TODO(mdempsky): Remove hard-coding of typecheck.Target.
	return ir.NewClosureFunc(origPos, r.inlPos(origPos), why, sig, curfn, typecheck.Target)
}

func (r *reader) exprList() []ir.Node {
	r.Sync(pkgbits.SyncExprList)
	return r.exprs()
}

func (r *reader) exprs() []ir.Node {
	r.Sync(pkgbits.SyncExprs)
	nodes := make([]ir.Node, r.Len())
	if len(nodes) == 0 {
		return nil // TODO(mdempsky): Unclear if this matters.
	}
	for i := range nodes {
		nodes[i] = r.expr()
	}
	return nodes
}

// dictWord returns an expression to return the specified
// uintptr-typed word from the dictionary parameter.
func (r *reader) dictWord(pos src.XPos, idx int) ir.Node {
	base.AssertfAt(r.dictParam != nil, pos, "expected dictParam in %v", r.curfn)
	return typecheck.Expr(ir.NewIndexExpr(pos, r.dictParam, ir.NewInt(pos, int64(idx))))
}

// rttiWord is like dictWord, but converts it to *byte (the type used
// internally to represent *runtime._type and *runtime.itab).
func (r *reader) rttiWord(pos src.XPos, idx int) ir.Node {
	return typecheck.Expr(ir.NewConvExpr(pos, ir.OCONVNOP, types.NewPtr(types.Types[types.TUINT8]), r.dictWord(pos, idx)))
}

// rtype reads a type reference from the element bitstream, and
// returns an expression of type *runtime._type representing that
// type.
func (r *reader) rtype(pos src.XPos) ir.Node {
	_, rtype := r.rtype0(pos)
	return rtype
}

func (r *reader) rtype0(pos src.XPos) (typ *types.Type, rtype ir.Node) {
	r.Sync(pkgbits.SyncRType)
	if r.Bool() { // derived type
		idx := r.Len()
		info := r.dict.rtypes[idx]
		typ = r.p.typIdx(info, r.dict, true)
		rtype = r.rttiWord(pos, r.dict.rtypesOffset()+idx)
		return
	}

	typ = r.typ()
	rtype = reflectdata.TypePtrAt(pos, typ)
	return
}

// varDictIndex populates name.DictIndex if name is a derived type.
func (r *reader) varDictIndex(name *ir.Name) {
	if r.Bool() {
		idx := 1 + r.dict.rtypesOffset() + r.Len()
		if int(uint16(idx)) != idx {
			base.FatalfAt(name.Pos(), "DictIndex overflow for %v: %v", name, idx)
		}
		name.DictIndex = uint16(idx)
	}
}

// itab returns a (typ, iface) pair of types.
//
// typRType and ifaceRType are expressions that evaluate to the
// *runtime._type for typ and iface, respectively.
//
// If typ is a concrete type and iface is a non-empty interface type,
// then itab is an expression that evaluates to the *runtime.itab for
// the pair. Otherwise, itab is nil.
func (r *reader) itab(pos src.XPos) (typ *types.Type, typRType ir.Node, iface *types.Type, ifaceRType ir.Node, itab ir.Node) {
	typ, typRType = r.rtype0(pos)
	iface, ifaceRType = r.rtype0(pos)

	idx := -1
	if r.Bool() {
		idx = r.Len()
	}

	if !typ.IsInterface() && iface.IsInterface() && !iface.IsEmptyInterface() {
		if idx >= 0 {
			itab = r.rttiWord(pos, r.dict.itabsOffset()+idx)
		} else {
			base.AssertfAt(!typ.HasShape(), pos, "%v is a shape type", typ)
			base.AssertfAt(!iface.HasShape(), pos, "%v is a shape type", iface)

			lsym := reflectdata.ITabLsym(typ, iface)
			itab = typecheck.LinksymAddr(pos, lsym, types.Types[types.TUINT8])
		}
	}

	return
}

// convRTTI returns expressions appropriate for populating an
// ir.ConvExpr's TypeWord and SrcRType fields, respectively.
func (r *reader) convRTTI(pos src.XPos) (typeWord, srcRType ir.Node) {
	r.Sync(pkgbits.SyncConvRTTI)
	src, srcRType0, dst, dstRType, itab := r.itab(pos)
	if !dst.IsInterface() {
		return
	}

	// See reflectdata.ConvIfaceTypeWord.
	switch {
	case dst.IsEmptyInterface():
		if !src.IsInterface() {
			typeWord = srcRType0 // direct eface construction
		}
	case !src.IsInterface():
		typeWord = itab // direct iface construction
	default:
		typeWord = dstRType // convI2I
	}

	// See reflectdata.ConvIfaceSrcRType.
	if !src.IsInterface() {
		srcRType = srcRType0
	}

	return
}

func (r *reader) exprType() ir.Node {
	r.Sync(pkgbits.SyncExprType)
	pos := r.pos()

	var typ *types.Type
	var rtype, itab ir.Node

	if r.Bool() {
		typ, rtype, _, _, itab = r.itab(pos)
		if !typ.IsInterface() {
			rtype = nil // TODO(mdempsky): Leave set?
		}
	} else {
		typ, rtype = r.rtype0(pos)

		if !r.Bool() { // not derived
			return ir.TypeNode(typ)
		}
	}

	dt := ir.NewDynamicType(pos, rtype)
	dt.ITab = itab
	dt = typed(typ, dt).(*ir.DynamicType)
	if st := dt.ToStatic(); st != nil {
		return st
	}
	return dt
}

func (r *reader) op() ir.Op {
	r.Sync(pkgbits.SyncOp)
	return ir.Op(r.Len())
}

// @@@ Package initialization

func (r *reader) pkgInit(self *types.Pkg, target *ir.Package) {
	cgoPragmas := make([][]string, r.Len())
	for i := range cgoPragmas {
		cgoPragmas[i] = r.Strings()
	}
	target.CgoPragmas = cgoPragmas

	r.pkgInitOrder(target)

	r.pkgDecls(target)

	r.Sync(pkgbits.SyncEOF)
}

// pkgInitOrder creates a synthetic init function to handle any
// package-scope initialization statements.
func (r *reader) pkgInitOrder(target *ir.Package) {
	initOrder := make([]ir.Node, r.Len())
	if len(initOrder) == 0 {
		return
	}

	// Make a function that contains all the initialization statements.
	pos := base.AutogeneratedPos
	base.Pos = pos

	fn := ir.NewFunc(pos, pos, typecheck.Lookup("init"), types.NewSignature(nil, nil, nil))
	fn.SetIsPackageInit(true)
	fn.SetInlinabilityChecked(true) // suppress useless "can inline" diagnostics

	typecheck.DeclFunc(fn)
	r.curfn = fn

	for i := range initOrder {
		lhs := make([]ir.Node, r.Len())
		for j := range lhs {
			lhs[j] = r.obj()
		}
		rhs := r.expr()
		pos := lhs[0].Pos()

		var as ir.Node
		if len(lhs) == 1 {
			as = typecheck.Stmt(ir.NewAssignStmt(pos, lhs[0], rhs))
		} else {
			as = typecheck.Stmt(ir.NewAssignListStmt(pos, ir.OAS2, lhs, []ir.Node{rhs}))
		}

		for _, v := range lhs {
			v.(*ir.Name).Defn = as
		}

		initOrder[i] = as
	}

	fn.Body = initOrder

	typecheck.FinishFuncBody()
	r.curfn = nil
	r.locals = nil

	// Outline (if legal/profitable) global map inits.
	staticinit.OutlineMapInits(fn)

	target.Inits = append(target.Inits, fn)
}

func (r *reader) pkgDecls(target *ir.Package) {
	r.Sync(pkgbits.SyncDecls)
	for {
		switch code := codeDecl(r.Code(pkgbits.SyncDecl)); code {
		default:
			panic(fmt.Sprintf("unhandled decl: %v", code))

		case declEnd:
			return

		case declFunc:
			names := r.pkgObjs(target)
			assert(len(names) == 1)
			target.Funcs = append(target.Funcs, names[0].Func)

		case declMethod:
			typ := r.typ()
			sym := r.selector()

			method := typecheck.Lookdot1(nil, sym, typ, typ.Methods(), 0)
			target.Funcs = append(target.Funcs, method.Nname.(*ir.Name).Func)

		case declVar:
			names := r.pkgObjs(target)

			if n := r.Len(); n > 0 {
				assert(len(names) == 1)
				embeds := make([]ir.Embed, n)
				for i := range embeds {
					embeds[i] = ir.Embed{Pos: r.pos(), Patterns: r.Strings()}
				}
				names[0].Embed = &embeds
				target.Embeds = append(target.Embeds, names[0])
			}

		case declOther:
			r.pkgObjs(target)
		}
	}
}

func (r *reader) pkgObjs(target *ir.Package) []*ir.Name {
	r.Sync(pkgbits.SyncDeclNames)
	nodes := make([]*ir.Name, r.Len())
	for i := range nodes {
		r.Sync(pkgbits.SyncDeclName)

		name := r.obj().(*ir.Name)
		nodes[i] = name

		sym := name.Sym()
		if sym.IsBlank() {
			continue
		}

		switch name.Class {
		default:
			base.FatalfAt(name.Pos(), "unexpected class: %v", name.Class)

		case ir.PEXTERN:
			target.Externs = append(target.Externs, name)

		case ir.PFUNC:
			assert(name.Type().Recv() == nil)

			// TODO(mdempsky): Cleaner way to recognize init?
			if strings.HasPrefix(sym.Name, "init.") {
				target.Inits = append(target.Inits, name.Func)
			}
		}

		if base.Ctxt.Flag_dynlink && types.LocalPkg.Name == "main" && types.IsExported(sym.Name) && name.Op() == ir.ONAME {
			assert(!sym.OnExportList())
			target.PluginExports = append(target.PluginExports, name)
			sym.SetOnExportList(true)
		}

		if base.Flag.AsmHdr != "" && (name.Op() == ir.OLITERAL || name.Op() == ir.OTYPE) {
			assert(!sym.Asm())
			target.AsmHdrDecls = append(target.AsmHdrDecls, name)
			sym.SetAsm(true)
		}
	}

	return nodes
}

// @@@ Inlining

// unifiedHaveInlineBody reports whether we have the function body for
// fn, so we can inline it.
func unifiedHaveInlineBody(fn *ir.Func) bool {
	if fn.Inl == nil {
		return false
	}

	_, ok := bodyReaderFor(fn)
	return ok
}

var inlgen = 0

// unifiedInlineCall implements inline.NewInline by re-reading the function
// body from its Unified IR export data.
func unifiedInlineCall(callerfn *ir.Func, call *ir.CallExpr, fn *ir.Func, inlIndex int) *ir.InlinedCallExpr {
	pri, ok := bodyReaderFor(fn)
	if !ok {
		base.FatalfAt(call.Pos(), "cannot inline call to %v: missing inline body", fn)
	}

	if !fn.Inl.HaveDcl {
		expandInline(fn, pri)
	}

	r := pri.asReader(pkgbits.RelocBody, pkgbits.SyncFuncBody)

	tmpfn := ir.NewFunc(fn.Pos(), fn.Nname.Pos(), callerfn.Sym(), fn.Type())

	r.curfn = tmpfn

	r.inlCaller = callerfn
	r.inlCall = call
	r.inlFunc = fn
	r.inlTreeIndex = inlIndex
	r.inlPosBases = make(map[*src.PosBase]*src.PosBase)
	r.funarghack = true

	r.closureVars = make([]*ir.Name, len(r.inlFunc.ClosureVars))
	for i, cv := range r.inlFunc.ClosureVars {
		// TODO(mdempsky): It should be possible to support this case, but
		// for now we rely on the inliner avoiding it.
		if cv.Outer.Curfn != callerfn {
			base.FatalfAt(call.Pos(), "inlining closure call across frames")
		}
		r.closureVars[i] = cv.Outer
	}
	if len(r.closureVars) != 0 && r.hasTypeParams() {
		r.dictParam = r.closureVars[len(r.closureVars)-1] // dictParam is last; see reader.funcLit
	}

	r.declareParams()

	var inlvars, retvars []*ir.Name
	{
		sig := r.curfn.Type()
		endParams := sig.NumRecvs() + sig.NumParams()
		endResults := endParams + sig.NumResults()

		inlvars = r.curfn.Dcl[:endParams]
		retvars = r.curfn.Dcl[endParams:endResults]
	}

	r.delayResults = fn.Inl.CanDelayResults

	r.retlabel = typecheck.AutoLabel(".i")
	inlgen++

	init := ir.TakeInit(call)

	// For normal function calls, the function callee expression
	// may contain side effects. Make sure to preserve these,
	// if necessary (#42703).
	if call.Op() == ir.OCALLFUNC {
		inline.CalleeEffects(&init, call.Fun)
	}

	var args ir.Nodes
	if call.Op() == ir.OCALLMETH {
		base.FatalfAt(call.Pos(), "OCALLMETH missed by typecheck")
	}
	args.Append(call.Args...)

	// Create assignment to declare and initialize inlvars.
	as2 := ir.NewAssignListStmt(call.Pos(), ir.OAS2, ir.ToNodes(inlvars), args)
	as2.Def = true
	var as2init ir.Nodes
	for _, name := range inlvars {
		if ir.IsBlank(name) {
			continue
		}
		// TODO(mdempsky): Use inlined position of name.Pos() instead?
		as2init.Append(ir.NewDecl(call.Pos(), ir.ODCL, name))
		name.Defn = as2
	}
	as2.SetInit(as2init)
	init.Append(typecheck.Stmt(as2))

	if !r.delayResults {
		// If not delaying retvars, declare and zero initialize the
		// result variables now.
		for _, name := range retvars {
			// TODO(mdempsky): Use inlined position of name.Pos() instead?
			init.Append(ir.NewDecl(call.Pos(), ir.ODCL, name))
			ras := ir.NewAssignStmt(call.Pos(), name, nil)
			init.Append(typecheck.Stmt(ras))
		}
	}

	// Add an inline mark just before the inlined body.
	// This mark is inline in the code so that it's a reasonable spot
	// to put a breakpoint. Not sure if that's really necessary or not
	// (in which case it could go at the end of the function instead).
	// Note issue 28603.
	init.Append(ir.NewInlineMarkStmt(call.Pos().WithIsStmt(), int64(r.inlTreeIndex)))

	ir.WithFunc(r.curfn, func() {
		if !r.syntheticBody(call.Pos()) {
			assert(r.Bool()) // have body

			r.curfn.Body = r.stmts()
			r.curfn.Endlineno = r.pos()
		}

		// TODO(mdempsky): This shouldn't be necessary. Inlining might
		// read in new function/method declarations, which could
		// potentially be recursively inlined themselves; but we shouldn't
		// need to read in the non-inlined bodies for the declarations
		// themselves. But currently it's an easy fix to #50552.
		readBodies(typecheck.Target, true)

		// Replace any "return" statements within the function body.
		var edit func(ir.Node) ir.Node
		edit = func(n ir.Node) ir.Node {
			if ret, ok := n.(*ir.ReturnStmt); ok {
				n = typecheck.Stmt(r.inlReturn(ret, retvars))
			}
			ir.EditChildren(n, edit)
			return n
		}
		edit(r.curfn)
	})

	body := ir.Nodes(r.curfn.Body)

	// Reparent any declarations into the caller function.
	for _, name := range r.curfn.Dcl {
		name.Curfn = callerfn

		if name.Class != ir.PAUTO {
			name.SetPos(r.inlPos(name.Pos()))
			name.SetInlFormal(true)
			name.Class = ir.PAUTO
		} else {
			name.SetInlLocal(true)
		}
	}
	callerfn.Dcl = append(callerfn.Dcl, r.curfn.Dcl...)

	body.Append(ir.NewLabelStmt(call.Pos(), r.retlabel))

	res := ir.NewInlinedCallExpr(call.Pos(), body, ir.ToNodes(retvars))
	res.SetInit(init)
	res.SetType(call.Type())
	res.SetTypecheck(1)

	// Inlining shouldn't add any functions to todoBodies.
	assert(len(todoBodies) == 0)

	return res
}

// inlReturn returns a statement that can substitute for the given
// return statement when inlining.
func (r *reader) inlReturn(ret *ir.ReturnStmt, retvars []*ir.Name) *ir.BlockStmt {
	pos := r.inlCall.Pos()

	block := ir.TakeInit(ret)

	if results := ret.Results; len(results) != 0 {
		assert(len(retvars) == len(results))

		as2 := ir.NewAssignListStmt(pos, ir.OAS2, ir.ToNodes(retvars), ret.Results)

		if r.delayResults {
			for _, name := range retvars {
				// TODO(mdempsky): Use inlined position of name.Pos() instead?
				block.Append(ir.NewDecl(pos, ir.ODCL, name))
				name.Defn = as2
			}
		}

		block.Append(as2)
	}

	block.Append(ir.NewBranchStmt(pos, ir.OGOTO, r.retlabel))
	return ir.NewBlockStmt(pos, block)
}

// expandInline reads in an extra copy of IR to populate
// fn.Inl.Dcl.
func expandInline(fn *ir.Func, pri pkgReaderIndex) {
	// TODO(mdempsky): Remove this function. It's currently needed by
	// dwarfgen/dwarf.go:preInliningDcls, which requires fn.Inl.Dcl to
	// create abstract function DIEs. But we should be able to provide it
	// with the same information some other way.

	fndcls := len(fn.Dcl)
	topdcls := len(typecheck.Target.Funcs)

	tmpfn := ir.NewFunc(fn.Pos(), fn.Nname.Pos(), fn.Sym(), fn.Type())
	tmpfn.ClosureVars = fn.ClosureVars

	{
		r := pri.asReader(pkgbits.RelocBody, pkgbits.SyncFuncBody)

		// Don't change parameter's Sym/Nname fields.
		r.funarghack = true

		r.funcBody(tmpfn)
	}

	// Move tmpfn's params to fn.Inl.Dcl, and reparent under fn.
	for _, name := range tmpfn.Dcl {
		name.Curfn = fn
	}
	fn.Inl.Dcl = tmpfn.Dcl
	fn.Inl.HaveDcl = true

	// Double check that we didn't change fn.Dcl by accident.
	assert(fndcls == len(fn.Dcl))

	// typecheck.Stmts may have added function literals to
	// typecheck.Target.Decls. Remove them again so we don't risk trying
	// to compile them multiple times.
	typecheck.Target.Funcs = typecheck.Target.Funcs[:topdcls]
}

// usedLocals returns a set of local variables that are used within body.
func usedLocals(body []ir.Node) ir.NameSet {
	var used ir.NameSet
	ir.VisitList(body, func(n ir.Node) {
		if n, ok := n.(*ir.Name); ok && n.Op() == ir.ONAME && n.Class == ir.PAUTO {
			used.Add(n)
		}
	})
	return used
}

// @@@ Method wrappers
//
// Here we handle constructing "method wrappers," alternative entry
// points that adapt methods to different calling conventions. Given a
// user-declared method "func (T) M(i int) bool { ... }", there are a
// few wrappers we may need to construct:
//
//	- Implicit dereferencing. Methods declared with a value receiver T
//	  are also included in the method set of the pointer type *T, so
//	  we need to construct a wrapper like "func (recv *T) M(i int)
//	  bool { return (*recv).M(i) }".
//
//	- Promoted methods. If struct type U contains an embedded field of
//	  type T or *T, we need to construct a wrapper like "func (recv U)
//	  M(i int) bool { return recv.T.M(i) }".
//
//	- Method values. If x is an expression of type T, then "x.M" is
//	  roughly "tmp := x; func(i int) bool { return tmp.M(i) }".
//
// At call sites, we always prefer to call the user-declared method
// directly, if known, so wrappers are only needed for indirect calls
// (for example, interface method calls that can't be devirtualized).
// Consequently, we can save some compile time by skipping
// construction of wrappers that are never needed.
//
// Alternatively, because the linker doesn't care which compilation
// unit constructed a particular wrapper, we can instead construct
// them as needed. However, if a wrapper is needed in multiple
// downstream packages, we may end up needing to compile it multiple
// times, costing us more compile time and object file size. (We mark
// the wrappers as DUPOK, so the linker doesn't complain about the
// duplicate symbols.)
//
// The current heuristics we use to balance these trade offs are:
//
//	- For a (non-parameterized) defined type T, we construct wrappers
//	  for *T and any promoted methods on T (and *T) in the same
//	  compilation unit as the type declaration.
//
//	- For a parameterized defined type, we construct wrappers in the
//	  compilation units in which the type is instantiated. We
//	  similarly handle wrappers for anonymous types with methods and
//	  compilation units where their type literals appear in source.
//
//	- Method value expressions are relatively uncommon, so we
//	  construct their wrappers in the compilation units that they
//	  appear in.
//
// Finally, as an opportunistic compile-time optimization, if we know
// a wrapper was constructed in any imported package's compilation
// unit, then we skip constructing a duplicate one. However, currently
// this is only done on a best-effort basis.

// needWrapperTypes lists types for which we may need to generate
// method wrappers.
var needWrapperTypes []*types.Type

// haveWrapperTypes lists types for which we know we already have
// method wrappers, because we found the type in an imported package.
var haveWrapperTypes []*types.Type

// needMethodValueWrappers lists methods for which we may need to
// generate method value wrappers.
var needMethodValueWrappers []methodValueWrapper

// haveMethodValueWrappers lists methods for which we know we already
// have method value wrappers, because we found it in an imported
// package.
var haveMethodValueWrappers []methodValueWrapper

type methodValueWrapper struct {
	rcvr   *types.Type
	method *types.Field
}

// needWrapper records that wrapper methods may be needed at link
// time.
func (r *reader) needWrapper(typ *types.Type) {
	if typ.IsPtr() {
		return
	}

	// Special case: runtime must define error even if imported packages mention it (#29304).
	forceNeed := typ == types.ErrorType && base.Ctxt.Pkgpath == "runtime"

	// If a type was found in an imported package, then we can assume
	// that package (or one of its transitive dependencies) already
	// generated method wrappers for it.
	if r.importedDef() && !forceNeed {
		haveWrapperTypes = append(haveWrapperTypes, typ)
	} else {
		needWrapperTypes = append(needWrapperTypes, typ)
	}
}

// importedDef reports whether r is reading from an imported and
// non-generic element.
//
// If a type was found in an imported package, then we can assume that
// package (or one of its transitive dependencies) already generated
// method wrappers for it.
//
// Exception: If we're instantiating an imported generic type or
// function, we might be instantiating it with type arguments not
// previously seen before.
//
// TODO(mdempsky): Distinguish when a generic function or type was
// instantiated in an imported package so that we can add types to
// haveWrapperTypes instead.
func (r *reader) importedDef() bool {
	return r.p != localPkgReader && !r.hasTypeParams()
}

// MakeWrappers constructs all wrapper methods needed for the target
// compilation unit.
func MakeWrappers(target *ir.Package) {
	// always generate a wrapper for error.Error (#29304)
	needWrapperTypes = append(needWrapperTypes, types.ErrorType)

	seen := make(map[string]*types.Type)

	for _, typ := range haveWrapperTypes {
		wrapType(typ, target, seen, false)
	}
	haveWrapperTypes = nil

	for _, typ := range needWrapperTypes {
		wrapType(typ, target, seen, true)
	}
	needWrapperTypes = nil

	for _, wrapper := range haveMethodValueWrappers {
		wrapMethodValue(wrapper.rcvr, wrapper.method, target, false)
	}
	haveMethodValueWrappers = nil

	for _, wrapper := range needMethodValueWrappers {
		wrapMethodValue(wrapper.rcvr, wrapper.method, target, true)
	}
	needMethodValueWrappers = nil
}

func wrapType(typ *types.Type, target *ir.Package, seen map[string]*types.Type, needed bool) {
	key := typ.LinkString()
	if prev := seen[key]; prev != nil {
		if !types.Identical(typ, prev) {
			base.Fatalf("collision: types %v and %v have link string %q", typ, prev, key)
		}
		return
	}
	seen[key] = typ

	if !needed {
		// Only called to add to 'seen'.
		return
	}

	if !typ.IsInterface() {
		typecheck.CalcMethods(typ)
	}
	for _, meth := range typ.AllMethods() {
		if meth.Sym.IsBlank() || !meth.IsMethod() {
			base.FatalfAt(meth.Pos, "invalid method: %v", meth)
		}

		methodWrapper(0, typ, meth, target)

		// For non-interface types, we also want *T wrappers.
		if !typ.IsInterface() {
			methodWrapper(1, typ, meth, target)

			// For not-in-heap types, *T is a scalar, not pointer shaped,
			// so the interface wrappers use **T.
			if typ.NotInHeap() {
				methodWrapper(2, typ, meth, target)
			}
		}
	}
}

func methodWrapper(derefs int, tbase *types.Type, method *types.Field, target *ir.Package) {
	wrapper := tbase
	for i := 0; i < derefs; i++ {
		wrapper = types.NewPtr(wrapper)
	}

	sym := ir.MethodSym(wrapper, method.Sym)
	base.Assertf(!sym.Siggen(), "already generated wrapper %v", sym)
	sym.SetSiggen(true)

	wrappee := method.Type.Recv().Type
	if types.Identical(wrapper, wrappee) ||
		!types.IsMethodApplicable(wrapper, method) ||
		!reflectdata.NeedEmit(tbase) {
		return
	}

	// TODO(mdempsky): Use method.Pos instead?
	pos := base.AutogeneratedPos

	fn := newWrapperFunc(pos, sym, wrapper, method)

	var recv ir.Node = fn.Nname.Type().Recv().Nname.(*ir.Name)

	// For simple *T wrappers around T methods, panicwrap produces a
	// nicer panic message.
	if wrapper.IsPtr() && types.Identical(wrapper.Elem(), wrappee) {
		cond := ir.NewBinaryExpr(pos, ir.OEQ, recv, types.BuiltinPkg.Lookup("nil").Def.(ir.Node))
		then := []ir.Node{ir.NewCallExpr(pos, ir.OCALL, typecheck.LookupRuntime("panicwrap"), nil)}
		fn.Body.Append(ir.NewIfStmt(pos, cond, then, nil))
	}

	// typecheck will add one implicit deref, if necessary,
	// but not-in-heap types require more for their **T wrappers.
	for i := 1; i < derefs; i++ {
		recv = Implicit(ir.NewStarExpr(pos, recv))
	}

	addTailCall(pos, fn, recv, method)

	finishWrapperFunc(fn, target)
}

func wrapMethodValue(recvType *types.Type, method *types.Field, target *ir.Package, needed bool) {
	sym := ir.MethodSymSuffix(recvType, method.Sym, "-fm")
	if sym.Uniq() {
		return
	}
	sym.SetUniq(true)

	// TODO(mdempsky): Use method.Pos instead?
	pos := base.AutogeneratedPos

	fn := newWrapperFunc(pos, sym, nil, method)
	sym.Def = fn.Nname

	// Declare and initialize variable holding receiver.
	recv := ir.NewHiddenParam(pos, fn, typecheck.Lookup(".this"), recvType)

	if !needed {
		return
	}

	addTailCall(pos, fn, recv, method)

	finishWrapperFunc(fn, target)
}

func newWrapperFunc(pos src.XPos, sym *types.Sym, wrapper *types.Type, method *types.Field) *ir.Func {
	sig := newWrapperType(wrapper, method)
	fn := ir.NewFunc(pos, pos, sym, sig)
	fn.DeclareParams(true)
	fn.SetDupok(true) // TODO(mdempsky): Leave unset for local, non-generic wrappers?

	return fn
}

func finishWrapperFunc(fn *ir.Func, target *ir.Package) {
	ir.WithFunc(fn, func() {
		typecheck.Stmts(fn.Body)
	})

	// We generate wrappers after the global inlining pass,
	// so we're responsible for applying inlining ourselves here.
	// TODO(prattmic): plumb PGO.
	interleaved.DevirtualizeAndInlineFunc(fn, nil)

	// The body of wrapper function after inlining may reveal new ir.OMETHVALUE node,
	// we don't know whether wrapper function has been generated for it or not, so
	// generate one immediately here.
	//
	// Further, after CL 492017, function that construct closures is allowed to be inlined,
	// even though the closure itself can't be inline. So we also need to visit body of any
	// closure that we see when visiting body of the wrapper function.
	ir.VisitFuncAndClosures(fn, func(n ir.Node) {
		if n, ok := n.(*ir.SelectorExpr); ok && n.Op() == ir.OMETHVALUE {
			wrapMethodValue(n.X.Type(), n.Selection, target, true)
		}
	})

	fn.Nname.Defn = fn
	target.Funcs = append(target.Funcs, fn)
}

// newWrapperType returns a copy of the given signature type, but with
// the receiver parameter type substituted with recvType.
// If recvType is nil, newWrapperType returns a signature
// without a receiver parameter.
func newWrapperType(recvType *types.Type, method *types.Field) *types.Type {
	clone := func(params []*types.Field) []*types.Field {
		res := make([]*types.Field, len(params))
		for i, param := range params {
			res[i] = types.NewField(param.Pos, param.Sym, param.Type)
			res[i].SetIsDDD(param.IsDDD())
		}
		return res
	}

	sig := method.Type

	var recv *types.Field
	if recvType != nil {
		recv = types.NewField(sig.Recv().Pos, sig.Recv().Sym, recvType)
	}
	params := clone(sig.Params())
	results := clone(sig.Results())

	return types.NewSignature(recv, params, results)
}

func addTailCall(pos src.XPos, fn *ir.Func, recv ir.Node, method *types.Field) {
	sig := fn.Nname.Type()
	args := make([]ir.Node, sig.NumParams())
	for i, param := range sig.Params() {
		args[i] = param.Nname.(*ir.Name)
	}

	dot := typecheck.XDotMethod(pos, recv, method.Sym, true)
	call := typecheck.Call(pos, dot, args, method.Type.IsVariadic()).(*ir.CallExpr)

	if recv.Type() != nil && recv.Type().IsPtr() && method.Type.Recv().Type.IsPtr() &&
		method.Embedded != 0 && !types.IsInterfaceMethod(method.Type) &&
		!unifiedHaveInlineBody(ir.MethodExprName(dot).Func) &&
		!(base.Ctxt.Arch.Name == "ppc64le" && base.Ctxt.Flag_dynlink) {
		if base.Debug.TailCall != 0 {
			base.WarnfAt(fn.Nname.Type().Recv().Type.Elem().Pos(), "tail call emitted for the method %v wrapper", method.Nname)
		}
		// Prefer OTAILCALL to reduce code size (except the case when the called method can be inlined).
		fn.Body.Append(ir.NewTailCallStmt(pos, call))
		return
	}

	fn.SetWrapper(true)

	if method.Type.NumResults() == 0 {
		fn.Body.Append(call)
		return
	}

	ret := ir.NewReturnStmt(pos, nil)
	ret.Results = []ir.Node{call}
	fn.Body.Append(ret)
}

func setBasePos(pos src.XPos) {
	// Set the position for any error messages we might print (e.g. too large types).
	base.Pos = pos
}

// dictParamName is the name of the synthetic dictionary parameter
// added to shaped functions.
//
// N.B., this variable name is known to Delve:
// https://github.com/go-delve/delve/blob/cb91509630529e6055be845688fd21eb89ae8714/pkg/proc/eval.go#L28
const dictParamName = typecheck.LocalDictName

// shapeSig returns a copy of fn's signature, except adding a
// dictionary parameter and promoting the receiver parameter (if any)
// to a normal parameter.
//
// The parameter types.Fields are all copied too, so their Nname
// fields can be initialized for use by the shape function.
func shapeSig(fn *ir.Func, dict *readerDict) *types.Type {
	sig := fn.Nname.Type()
	oldRecv := sig.Recv()

	var recv *types.Field
	if oldRecv != nil {
		recv = types.NewField(oldRecv.Pos, oldRecv.Sym, oldRecv.Type)
	}

	params := make([]*types.Field, 1+sig.NumParams())
	params[0] = types.NewField(fn.Pos(), fn.Sym().Pkg.Lookup(dictParamName), types.NewPtr(dict.varType()))
	for i, param := range sig.Params() {
		d := types.NewField(param.Pos, param.Sym, param.Type)
		d.SetIsDDD(param.IsDDD())
		params[1+i] = d
	}

	results := make([]*types.Field, sig.NumResults())
	for i, result := range sig.Results() {
		results[i] = types.NewField(result.Pos, result.Sym, result.Type)
	}

	return types.NewSignature(recv, params, results)
}
```