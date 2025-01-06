Response:
The user wants a summary of the Go code provided, specifically focusing on its functionalities within the `go/src/cmd/compile/internal/noder/reader.go` file. This is part 4 of a series, so I should provide a cumulative summary. The key functionalities seem to revolve around inlining function calls and generating wrapper functions for methods.

Here's a breakdown of the code's main tasks:

1. **Inlining:**  The code handles the process of substituting a function call with the actual body of the function. This involves:
    - Managing local variable declarations within the inlined function.
    - Handling return statements within the inlined function.
    - Constructing an `ir.InlinedCallExpr` to represent the inlined call.
2. **Method Wrappers:** The code generates adapter functions (wrappers) for methods to handle different calling conventions, such as:
    - Implicit dereferencing for value receivers.
    - Promoted methods in embedded structs.
    - Method values (e.g., `x.M`).
3. **Helper Functions:** There are utility functions for:
    - Expanding inline information for a function.
    - Identifying used local variables within a code block.
    - Managing lists of types and methods that need wrappers.
4. **Shaping Functions:** The code introduces the concept of "shaped functions," likely for generics. It modifies function signatures to include a dictionary parameter.
这是 `go/src/cmd/compile/internal/noder/reader.go` 文件的一部分，主要负责在编译过程中处理函数调用的内联（inlining）和方法包装器（method wrappers）的生成。结合之前的部分，我们可以归纳一下 `reader.go` 的总体功能：

**`reader.go` 的总体功能归纳:**

`reader.go` 负责从编译中间表示（likely package bits）中读取信息，并将这些信息转换为编译器内部的抽象语法树（AST）表示，也就是 `ir.Node`。 它在编译流程中扮演着至关重要的角色，特别是在处理函数和方法相关的操作时。

具体来说，`reader.go` 实现了以下核心功能：

1. **读取和解析包信息:** 它负责读取编译过程中产生的中间文件，这些文件包含了类型信息、函数定义、声明等。
2. **构建 IR 节点:**  根据读取到的信息，它创建相应的 `ir.Node`，例如 `ir.Func` (函数), `ir.Name` (变量), `ir.Type` (类型) 等，构建出程序结构的内部表示。
3. **处理函数和方法:**  它能够读取和重建函数和方法的定义，包括参数、返回值、函数体等。
4. **处理内联:**  它实现了函数内联的逻辑。当编译器决定将某个函数调用内联时，`reader.go` 中的代码会负责读取被内联函数的函数体，并将其插入到调用者的函数体中。这部分代码（本部分）主要处理内联的具体步骤，包括：
    - **管理内联函数的局部变量:** 为内联函数的局部变量设置正确的属性，例如将其 `Curfn` 指针指向调用者函数。
    - **处理内联函数的返回语句:** 将内联函数的 `return` 语句转换为在调用者函数中跳转到正确位置的 `goto` 语句。
    - **构建 `ir.InlinedCallExpr`:** 创建表示内联调用的节点。
5. **生成方法包装器:** 为了支持不同的方法调用方式（例如，值接收者和指针接收者之间的调用，以及嵌入字段的方法提升），`reader.go` 负责生成必要的“包装器”函数。这部分代码（本部分）实现了生成这些包装器的逻辑，包括：
    - **创建包装器函数:**  为需要包装的方法生成新的函数定义。
    - **调整参数和调用:**  在包装器函数中，调整接收者参数，并调用原始方法。
    - **处理方法值:**  生成用于表示方法值的包装器。
6. **支持泛型（可能）:** 代码中出现了 `shapeSig` 函数，它为函数签名添加了一个“字典”参数，这暗示了 `reader.go` 也参与了泛型的实现，可能是在实例化泛型函数时生成特定的函数变体。

**本部分代码的功能归纳:**

本部分主要集中在函数内联的具体实现细节以及方法包装器的生成。

* **函数内联 (`inlCall`):**
    -  将内联函数的声明添加到调用者函数的声明列表中。
    -  将内联函数的返回语句替换为跳转到调用者函数中返回标签的 `goto` 语句。
    -  创建一个 `ir.InlinedCallExpr` 节点来表示内联的函数调用。
* **处理内联函数的返回 (`inlReturn`):**
    -  将内联函数的返回值赋值给调用者函数中用于接收返回值的变量。
    -  生成一个 `goto` 语句，跳转到调用者函数中内联调用之后的标签。
* **扩展内联信息 (`expandInline`):**
    -  读取内联函数的声明信息并存储在 `fn.Inl.Dcl` 中。这主要是为了支持一些需要完整声明信息的工具，例如 `dwarfgen`。
* **查找使用的局部变量 (`usedLocals`):**
    -  遍历代码块，找出其中使用的局部变量。
* **方法包装器生成 (`needWrapper`, `MakeWrappers`, `wrapType`, `methodWrapper`, `wrapMethodValue`, `newWrapperFunc`, `finishWrapperFunc`, `newWrapperType`, `addTailCall`):**
    -  维护需要生成和已经生成包装器的类型和方法列表。
    -  为值接收者生成指针接收者的包装器，以及处理嵌入字段的方法提升。
    -  为方法值生成包装器函数。
    -  创建包装器函数，设置其参数和返回值类型。
    -  在包装器函数中调用原始方法。
    -  处理尾调用优化。
* **设置基本位置 (`setBasePos`):**
    -  设置错误消息输出的位置信息。
* **处理泛型（`shapeSig`）:**
    -  修改函数签名，添加一个用于传递类型信息的“字典”参数。这很可能是为了支持泛型函数的实例化。

**Go 代码示例 (内联):**

假设我们有以下 Go 代码：

```go
package main

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(1, 2)
	println(result)
}
```

当编译器决定内联 `add` 函数时，`inlCall` 和 `inlReturn` 函数会参与转换。

**假设的输入 (简化):**

* `call`:  表示 `add(1, 2)` 调用的 `ir.CallExpr` 节点。
* `r.curfn`:  表示 `add` 函数的 `ir.Func` 节点。
* `callerfn`: 表示 `main` 函数的 `ir.Func` 节点。
* `retvars`:  用于接收 `add` 函数返回值的 `ir.Name` 节点 (例如 `result`)。

**假设的输出 (简化):**

`inlCall` 函数会生成类似以下的 IR 节点结构（伪代码）：

```
// 在 main 函数的函数体中
// ... 之前的代码 ...

// 内联 add 函数的 body
temp_0 := 1 // 假设常量 1 被赋值给一个临时变量
temp_1 := 2 // 假设常量 2 被赋值给一个临时变量
result := temp_0 + temp_1 // add 函数的返回值被赋值给 result

// ... 后续的代码 ...
```

`inlReturn` 函数会将 `add` 函数的 `return a + b` 转换为将 `a + b` 的结果赋值给 `result`。

**Go 代码示例 (方法包装器):**

```go
package main

type MyInt int

func (m MyInt) Double() int {
	return int(m * 2)
}

func main() {
	var i MyInt = 5
	_ = i.Double // 这里可能会触发方法值包装器的生成
}
```

对于 `MyInt` 类型的 `Double` 方法，`methodWrapper` 可能会生成一个类似于以下的包装器函数（伪代码）：

```go
func MyInt_Double_wrapper(recv MyInt) int {
	return recv.Double()
}
```

对于方法值 `i.Double`，`wrapMethodValue` 可能会生成一个类似于以下的包装器函数：

```go
func MyInt_Double_fm(this MyInt) int {
	return this.Double()
}
```

**命令行参数处理:**

这部分代码主要关注内部的 IR 构建和转换，不太直接涉及命令行参数的处理。 命令行参数的处理通常发生在编译器的前端和主流程中，例如控制是否进行内联优化。

**使用者易犯错的点:**

作为编译器内部实现的一部分，普通 Go 开发者通常不会直接与这部分代码交互。 易犯错的点更多是编译器开发者需要注意的，例如：

* **内联的副作用:**  错误的内联处理可能导致程序的行为发生改变，特别是当内联函数有副作用时。
* **包装器函数的正确性:**  生成的包装器函数必须正确地适配不同的调用约定，否则可能导致程序崩溃或产生错误结果。

总而言之，`go/src/cmd/compile/internal/noder/reader.go` 的这部分代码是 Go 编译器进行函数内联优化和方法调用处理的关键组成部分，它负责将编译中间表示转换为可操作的 IR 节点，并生成必要的辅助函数来支持不同的语言特性。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/noder/reader.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共4部分，请归纳一下它的功能

"""
 caller function.
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

"""




```