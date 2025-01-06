Response:
The user wants a summary of the functionality of the Go code snippet provided, which is a part of the `reader.go` file in the `cmd/compile/internal/noder` package. This file is responsible for reading and interpreting the serialized representation of the Go program's intermediate representation (IR).

The snippet seems to focus on reading and reconstructing various expressions and function-related constructs.

**High-level plan:**

1. Identify the main categories of functionality within the snippet.
2. Summarize the purpose of each category.
3. Connect these functionalities to the overall goal of the `reader.go` file.
这段代码是 `go/src/cmd/compile/internal/noder/reader.go` 文件的第三部分，主要负责从序列化的数据中读取和重建 Go 语言的各种表达式和函数相关的结构。

**主要功能归纳：**

1. **表达式的读取和重建：**
    *   `expr()` 函数作为入口，根据不同的 `exprCode` 读取和创建各种类型的表达式节点（`ir.Node`）。
    *   支持读取和重建的表达式类型包括：字面量（`exprConst`）、标识符（`exprLocal`、`exprGoLocal`、`expr গো`）、点操作（`exprDotField`、`exprDotMethod`）、索引操作（`exprIndex`）、切片操作（`exprSlice`）、调用（`exprCall`）、类型断言（`exprAssert`）、类型转换（`exprConvert`）、内置函数调用（`exprRuntimeBuiltin`）、函数实例化（`funcInst`）、方法表达式（`methodExpr`）。
    *   对于需要类型信息的表达式，会调用 `r.typ()` 来读取类型信息。
    *   对于涉及泛型的表达式，会处理字典（dictionaries）相关的逻辑，例如读取子字典（`dynamic subdictionary`）和静态字典。

2. **函数相关的读取和重建：**
    *   `funcInst()` 读取函数实例化信息，用于处理泛型函数的调用。它会返回基础函数 (`baseFn`)、字典指针 (`dictPtr`) 和包装函数 (`wrapperFn`)，用于正确地调用泛型函数。
    *   `methodExpr()` 读取方法表达式信息，用于处理将方法作为一等公民值的情况。它也返回基础函数、字典指针和包装函数。
    *   `curry()` 创建一个闭包，用于柯里化函数参数，通常用于处理泛型方法表达式。
    *   `methodExprWrap()` 创建一个闭包，用于调整方法表达式接收者的类型。
    *   `syntheticClosure()` 构建一个合成的函数字面量，用于处理例如柯里化字典参数的情况。
    *   `funcLit()` 读取函数字面量（匿名函数）的信息并重建。

3. **复合字面量的读取和重建：**
    *   `compLit()` 读取并重建结构体、数组、切片和映射的复合字面量。

4. **多返回值表达式的处理：**
    *   `multiExpr()` 读取并处理返回多个值的表达式。

5. **临时变量的创建：**
    *   `temp()` 和 `tempCopy()` 用于创建临时变量，通常用于中间计算结果的存储。

6. **类型信息的读取：**
    *   `rtype()` 和 `rtype0()` 读取并获取 `*runtime._type` 的表达式，用于表示类型信息，尤其在处理反射和泛型时。
    *   `itab()` 读取接口类型和具体类型的信息，以及可能存在的 `*runtime.itab` 的表达式，用于接口类型的动态分发。
    *   `convRTTI()` 返回用于填充 `ir.ConvExpr` 中 `TypeWord` 和 `SrcRType` 字段的表达式，用于类型转换。
    *   `exprType()` 读取并重建表示类型信息的表达式，包括静态类型和动态类型。

7. **操作符的读取：**
    *   `op()` 读取操作符 (`ir.Op`)。

**与 Go 语言功能的关联：**

这段代码主要服务于 Go 语言的编译过程，特别是类型检查和中间代码生成阶段。它负责将编译器前端（例如词法分析、语法分析）生成的抽象语法树转换成更底层的静态单赋值形式的中间表示（SSA IR）。

**Go 代码示例 (类型转换 `exprConvert`)：**

假设输入的序列化数据表示一个将 `int` 类型的变量 `x` 转换为 `interface{}` 类型的操作。

**假设输入：**

```
exprCode: exprConvert
implicit: true // 隐式转换
typ: interface{}
pos: ...
typeWord, srcRType: ... // *runtime._type 的信息
dstTypeParam: false
identical: false
x: (表示 int 变量 x 的表达式)
```

**输出（近似 Go 代码）：**

```go
var x int = ... // 假设 x 已经被声明和赋值
var iface interface{}
iface = x // 隐式转换
```

这段代码会创建一个 `ir.ConvExpr` 节点，表示这个类型转换操作。

**命令行参数处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在编译器的其他阶段，例如 `go/src/cmd/compile/main.go` 或 `go/src/cmd/compile/internal/gc/main.go`。

**使用者易犯错的点：**

这段代码是编译器内部实现的一部分，普通 Go 语言开发者不会直接接触。因此，不存在使用者易犯错的点。

**总结这段代码的功能：**

这段 `reader.go` 的代码片段是 Go 编译器中将序列化的中间表示数据转换回内存中 `ir.Node` 结构的关键部分。它涵盖了表达式、函数、复合字面量和类型信息的读取和重建，是连接编译器前端和后端的重要桥梁，为后续的类型检查、优化和代码生成提供基础。它精细地处理了各种 Go 语言特性，包括泛型、接口和类型转换等。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/noder/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
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

	// Reparent any declarations into the
"""




```