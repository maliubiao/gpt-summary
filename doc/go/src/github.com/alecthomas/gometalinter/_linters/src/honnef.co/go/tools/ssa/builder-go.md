Response:
The user provided a snippet of Go code from `go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/builder.go` and asked for its functionality. The request specifically asked to summarize the functionality in this first part of the code.

**Plan:**

1. **Identify the primary goal of this code segment:**  Based on the package name (`ssa`) and comments like "BUILD phase of SSA construction", the core function is to convert Go AST (Abstract Syntax Tree) into SSA (Static Single Assignment) form.
2. **Analyze key types and functions:** Look for structs, methods, and important variables to understand the main building blocks and operations. Pay attention to types like `builder`, `Function`, `BasicBlock`, `Value`, and operations like `cond`, `expr`, `assign`, `compLit`.
3. **Trace the code flow:**  Understand how the code processes different Go language constructs (expressions, statements, literals, etc.) and converts them into SSA instructions.
4. **Summarize the core functionalities:** Condense the findings into a concise description of what the code does.
这段代码是 Go 语言 SSA（Static Single Assignment）构建过程中的 **BUILD 阶段** 的一部分， 它的主要功能是将 Go 语言的抽象语法树（AST）转换成静态单赋值（SSA）形式的中间表示。

具体来说，这段代码实现了以下功能：

1. **初始化构建器状态:**  定义了 `builder` 结构体，它维护了当前正在构建的包的状态。同时定义了一些常量，例如布尔类型 `tBool`，整型 `tInt`，以及一些预定义的 SSA 值，如 `vZero` 和 `vTrue`。

2. **条件语句处理 (`cond` 方法):**  将 Go 语言的条件表达式（例如 `if` 语句的条件）转换成控制流图中的跳转指令。它会处理括号表达式、逻辑运算符 (`&&`, `||`) 和取反运算符 (`!`)，并根据条件表达式的值跳转到不同的基本块 (`BasicBlock`)。

3. **逻辑二元运算符处理 (`logicalBinop` 方法):**  专门处理逻辑与 (`&&`) 和逻辑或 (`||`) 运算符。它实现了短路求值，即如果左操作数已经能确定整个表达式的值，则右操作数不会被执行。

4. **多返回值表达式处理 (`exprN` 方法):**  处理返回多个值的表达式，例如函数调用返回多个值，类型断言的 "value, ok" 形式，以及从 map 中取值时的 "value, ok" 形式。它将这些多返回值表达式转换为一个 `types.Tuple` 类型的 SSA `Value`，后续可以通过 `Extract` 指令来访问各个返回值。

5. **内置函数处理 (`builtin` 方法):**  处理 Go 语言的内置函数，例如 `make`, `new`, `len`, `cap`, `panic` 等。它会根据不同的内置函数生成相应的 SSA 指令。

6. **地址获取 (`addr` 方法):**  获取可寻址表达式的地址，并返回一个表示左值 (`lvalue`) 的对象。这个方法会处理标识符、复合字面量、选择器表达式（例如 `a.b`）、索引表达式（例如 `a[i]`）和解引用表达式（例如 `*p`）。它还会处理逃逸分析，标记某些变量为可能逃逸的指针值。

7. **赋值语句处理 (`assign` 方法):**  将表达式的值赋给一个左值。它会尝试进行原地初始化，特别是对于复合字面量。如果无法原地初始化，则会生成存储指令。

8. **单返回值表达式处理 (`expr` 和 `expr0` 方法):**  将 Go 语言的各种表达式转换成 SSA `Value`。它会处理常量、函数字面量、类型断言、函数调用、一元运算符、二元运算符、切片表达式、标识符和选择器表达式。

9. **语句列表处理 (`stmtList` 方法):**  遍历并处理语句列表中的所有语句。

10. **接收者处理 (`receiver` 方法):**  处理方法调用中的接收者。

11. **函数调用参数设置 (`setCallFunc` 和 `emitCallArgs` 方法):**  设置函数调用的参数，包括处理方法调用、可变参数等情况。

12. **赋值运算符处理 (`assignOp` 方法):**  处理赋值运算符，例如 `+=` 和 `-=`。

13. **局部变量声明处理 (`localValueSpec` 方法):**  处理函数内部的变量声明。

14. **赋值语句处理 (`assignStmt` 方法):**  处理赋值语句，包括并行赋值和短变量声明。

15. **数组长度计算 (`arrayLen` 方法):**  计算复合字面量表示的数组的长度。

16. **复合字面量处理 (`compLit` 方法):**  处理复合字面量（例如结构体、数组、切片的初始化），将其初始化到指定的内存地址。它会递归处理嵌套的复合字面量，并使用 `storebuf` 来暂存存储操作，以确保在 RHS 引用 LHS 的情况下，读取发生在写入之前。

总而言之，这段代码是 Go 语言 SSA 构建器的核心部分，负责将 Go 语言的各种语法结构转换为更底层的 SSA 中间表示，为后续的静态分析和优化奠定基础。它处理了表达式、语句、内置函数和各种类型，并考虑了逃逸分析等问题。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/builder.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

// This file implements the BUILD phase of SSA construction.
//
// SSA construction has two phases, CREATE and BUILD.  In the CREATE phase
// (create.go), all packages are constructed and type-checked and
// definitions of all package members are created, method-sets are
// computed, and wrapper methods are synthesized.
// ssa.Packages are created in arbitrary order.
//
// In the BUILD phase (builder.go), the builder traverses the AST of
// each Go source function and generates SSA instructions for the
// function body.  Initializer expressions for package-level variables
// are emitted to the package's init() function in the order specified
// by go/types.Info.InitOrder, then code for each function in the
// package is generated in lexical order.
// The BUILD phases for distinct packages are independent and are
// executed in parallel.
//
// TODO(adonovan): indeed, building functions is now embarrassingly parallel.
// Audit for concurrency then benchmark using more goroutines.
//
// The builder's and Program's indices (maps) are populated and
// mutated during the CREATE phase, but during the BUILD phase they
// remain constant.  The sole exception is Prog.methodSets and its
// related maps, which are protected by a dedicated mutex.

import (
	"fmt"
	"go/ast"
	exact "go/constant"
	"go/token"
	"go/types"
	"os"
	"sync"
)

type opaqueType struct {
	types.Type
	name string
}

func (t *opaqueType) String() string { return t.name }

var (
	varOk    = newVar("ok", tBool)
	varIndex = newVar("index", tInt)

	// Type constants.
	tBool       = types.Typ[types.Bool]
	tByte       = types.Typ[types.Byte]
	tInt        = types.Typ[types.Int]
	tInvalid    = types.Typ[types.Invalid]
	tString     = types.Typ[types.String]
	tUntypedNil = types.Typ[types.UntypedNil]
	tRangeIter  = &opaqueType{nil, "iter"} // the type of all "range" iterators
	tEface      = types.NewInterface(nil, nil).Complete()

	// SSA Value constants.
	vZero = intConst(0)
	vOne  = intConst(1)
	vTrue = NewConst(exact.MakeBool(true), tBool)
)

// builder holds state associated with the package currently being built.
// Its methods contain all the logic for AST-to-SSA conversion.
type builder struct{}

// cond emits to fn code to evaluate boolean condition e and jump
// to t or f depending on its value, performing various simplifications.
//
// Postcondition: fn.currentBlock is nil.
//
func (b *builder) cond(fn *Function, e ast.Expr, t, f *BasicBlock) {
	switch e := e.(type) {
	case *ast.ParenExpr:
		b.cond(fn, e.X, t, f)
		return

	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			ltrue := fn.newBasicBlock("cond.true")
			b.cond(fn, e.X, ltrue, f)
			fn.currentBlock = ltrue
			b.cond(fn, e.Y, t, f)
			return

		case token.LOR:
			lfalse := fn.newBasicBlock("cond.false")
			b.cond(fn, e.X, t, lfalse)
			fn.currentBlock = lfalse
			b.cond(fn, e.Y, t, f)
			return
		}

	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			b.cond(fn, e.X, f, t)
			return
		}
	}

	// A traditional compiler would simplify "if false" (etc) here
	// but we do not, for better fidelity to the source code.
	//
	// The value of a constant condition may be platform-specific,
	// and may cause blocks that are reachable in some configuration
	// to be hidden from subsequent analyses such as bug-finding tools.
	emitIf(fn, b.expr(fn, e), t, f)
}

// logicalBinop emits code to fn to evaluate e, a &&- or
// ||-expression whose reified boolean value is wanted.
// The value is returned.
//
func (b *builder) logicalBinop(fn *Function, e *ast.BinaryExpr) Value {
	rhs := fn.newBasicBlock("binop.rhs")
	done := fn.newBasicBlock("binop.done")

	// T(e) = T(e.X) = T(e.Y) after untyped constants have been
	// eliminated.
	// TODO(adonovan): not true; MyBool==MyBool yields UntypedBool.
	t := fn.Pkg.typeOf(e)

	var short Value // value of the short-circuit path
	switch e.Op {
	case token.LAND:
		b.cond(fn, e.X, rhs, done)
		short = NewConst(exact.MakeBool(false), t)

	case token.LOR:
		b.cond(fn, e.X, done, rhs)
		short = NewConst(exact.MakeBool(true), t)
	}

	// Is rhs unreachable?
	if rhs.Preds == nil {
		// Simplify false&&y to false, true||y to true.
		fn.currentBlock = done
		return short
	}

	// Is done unreachable?
	if done.Preds == nil {
		// Simplify true&&y (or false||y) to y.
		fn.currentBlock = rhs
		return b.expr(fn, e.Y)
	}

	// All edges from e.X to done carry the short-circuit value.
	var edges []Value
	for range done.Preds {
		edges = append(edges, short)
	}

	// The edge from e.Y to done carries the value of e.Y.
	fn.currentBlock = rhs
	edges = append(edges, b.expr(fn, e.Y))
	emitJump(fn, done)
	fn.currentBlock = done

	phi := &Phi{Edges: edges, Comment: e.Op.String()}
	phi.pos = e.OpPos
	phi.typ = t
	return done.emit(phi)
}

// exprN lowers a multi-result expression e to SSA form, emitting code
// to fn and returning a single Value whose type is a *types.Tuple.
// The caller must access the components via Extract.
//
// Multi-result expressions include CallExprs in a multi-value
// assignment or return statement, and "value,ok" uses of
// TypeAssertExpr, IndexExpr (when X is a map), and UnaryExpr (when Op
// is token.ARROW).
//
func (b *builder) exprN(fn *Function, e ast.Expr) Value {
	typ := fn.Pkg.typeOf(e).(*types.Tuple)
	switch e := e.(type) {
	case *ast.ParenExpr:
		return b.exprN(fn, e.X)

	case *ast.CallExpr:
		// Currently, no built-in function nor type conversion
		// has multiple results, so we can avoid some of the
		// cases for single-valued CallExpr.
		var c Call
		b.setCall(fn, e, &c.Call)
		c.typ = typ
		return fn.emit(&c)

	case *ast.IndexExpr:
		mapt := fn.Pkg.typeOf(e.X).Underlying().(*types.Map)
		lookup := &Lookup{
			X:       b.expr(fn, e.X),
			Index:   emitConv(fn, b.expr(fn, e.Index), mapt.Key()),
			CommaOk: true,
		}
		lookup.setType(typ)
		lookup.setPos(e.Lbrack)
		return fn.emit(lookup)

	case *ast.TypeAssertExpr:
		return emitTypeTest(fn, b.expr(fn, e.X), typ.At(0).Type(), e.Lparen)

	case *ast.UnaryExpr: // must be receive <-
		unop := &UnOp{
			Op:      token.ARROW,
			X:       b.expr(fn, e.X),
			CommaOk: true,
		}
		unop.setType(typ)
		unop.setPos(e.OpPos)
		return fn.emit(unop)
	}
	panic(fmt.Sprintf("exprN(%T) in %s", e, fn))
}

// builtin emits to fn SSA instructions to implement a call to the
// built-in function obj with the specified arguments
// and return type.  It returns the value defined by the result.
//
// The result is nil if no special handling was required; in this case
// the caller should treat this like an ordinary library function
// call.
//
func (b *builder) builtin(fn *Function, obj *types.Builtin, args []ast.Expr, typ types.Type, pos token.Pos) Value {
	switch obj.Name() {
	case "make":
		switch typ.Underlying().(type) {
		case *types.Slice:
			n := b.expr(fn, args[1])
			m := n
			if len(args) == 3 {
				m = b.expr(fn, args[2])
			}
			if m, ok := m.(*Const); ok {
				// treat make([]T, n, m) as new([m]T)[:n]
				cap := m.Int64()
				at := types.NewArray(typ.Underlying().(*types.Slice).Elem(), cap)
				alloc := emitNew(fn, at, pos)
				alloc.Comment = "makeslice"
				v := &Slice{
					X:    alloc,
					High: n,
				}
				v.setPos(pos)
				v.setType(typ)
				return fn.emit(v)
			}
			v := &MakeSlice{
				Len: n,
				Cap: m,
			}
			v.setPos(pos)
			v.setType(typ)
			return fn.emit(v)

		case *types.Map:
			var res Value
			if len(args) == 2 {
				res = b.expr(fn, args[1])
			}
			v := &MakeMap{Reserve: res}
			v.setPos(pos)
			v.setType(typ)
			return fn.emit(v)

		case *types.Chan:
			var sz Value = vZero
			if len(args) == 2 {
				sz = b.expr(fn, args[1])
			}
			v := &MakeChan{Size: sz}
			v.setPos(pos)
			v.setType(typ)
			return fn.emit(v)
		}

	case "new":
		alloc := emitNew(fn, deref(typ), pos)
		alloc.Comment = "new"
		return alloc

	case "len", "cap":
		// Special case: len or cap of an array or *array is
		// based on the type, not the value which may be nil.
		// We must still evaluate the value, though.  (If it
		// was side-effect free, the whole call would have
		// been constant-folded.)
		t := deref(fn.Pkg.typeOf(args[0])).Underlying()
		if at, ok := t.(*types.Array); ok {
			b.expr(fn, args[0]) // for effects only
			return intConst(at.Len())
		}
		// Otherwise treat as normal.

	case "panic":
		fn.emit(&Panic{
			X:   emitConv(fn, b.expr(fn, args[0]), tEface),
			pos: pos,
		})
		fn.currentBlock = fn.newBasicBlock("unreachable")
		return vTrue // any non-nil Value will do
	}
	return nil // treat all others as a regular function call
}

// addr lowers a single-result addressable expression e to SSA form,
// emitting code to fn and returning the location (an lvalue) defined
// by the expression.
//
// If escaping is true, addr marks the base variable of the
// addressable expression e as being a potentially escaping pointer
// value.  For example, in this code:
//
//   a := A{
//     b: [1]B{B{c: 1}}
//   }
//   return &a.b[0].c
//
// the application of & causes a.b[0].c to have its address taken,
// which means that ultimately the local variable a must be
// heap-allocated.  This is a simple but very conservative escape
// analysis.
//
// Operations forming potentially escaping pointers include:
// - &x, including when implicit in method call or composite literals.
// - a[:] iff a is an array (not *array)
// - references to variables in lexically enclosing functions.
//
func (b *builder) addr(fn *Function, e ast.Expr, escaping bool) lvalue {
	switch e := e.(type) {
	case *ast.Ident:
		if isBlankIdent(e) {
			return blank{}
		}
		obj := fn.Pkg.objectOf(e)
		v := fn.Prog.packageLevelValue(obj) // var (address)
		if v == nil {
			v = fn.lookup(obj, escaping)
		}
		return &address{addr: v, pos: e.Pos(), expr: e}

	case *ast.CompositeLit:
		t := deref(fn.Pkg.typeOf(e))
		var v *Alloc
		if escaping {
			v = emitNew(fn, t, e.Lbrace)
		} else {
			v = fn.addLocal(t, e.Lbrace)
		}
		v.Comment = "complit"
		var sb storebuf
		b.compLit(fn, v, e, true, &sb)
		sb.emit(fn)
		return &address{addr: v, pos: e.Lbrace, expr: e}

	case *ast.ParenExpr:
		return b.addr(fn, e.X, escaping)

	case *ast.SelectorExpr:
		sel, ok := fn.Pkg.info.Selections[e]
		if !ok {
			// qualified identifier
			return b.addr(fn, e.Sel, escaping)
		}
		if sel.Kind() != types.FieldVal {
			panic(sel)
		}
		wantAddr := true
		v := b.receiver(fn, e.X, wantAddr, escaping, sel)
		last := len(sel.Index()) - 1
		return &address{
			addr: emitFieldSelection(fn, v, sel.Index()[last], true, e.Sel),
			pos:  e.Sel.Pos(),
			expr: e.Sel,
		}

	case *ast.IndexExpr:
		var x Value
		var et types.Type
		switch t := fn.Pkg.typeOf(e.X).Underlying().(type) {
		case *types.Array:
			x = b.addr(fn, e.X, escaping).address(fn)
			et = types.NewPointer(t.Elem())
		case *types.Pointer: // *array
			x = b.expr(fn, e.X)
			et = types.NewPointer(t.Elem().Underlying().(*types.Array).Elem())
		case *types.Slice:
			x = b.expr(fn, e.X)
			et = types.NewPointer(t.Elem())
		case *types.Map:
			return &element{
				m:   b.expr(fn, e.X),
				k:   emitConv(fn, b.expr(fn, e.Index), t.Key()),
				t:   t.Elem(),
				pos: e.Lbrack,
			}
		default:
			panic("unexpected container type in IndexExpr: " + t.String())
		}
		v := &IndexAddr{
			X:     x,
			Index: emitConv(fn, b.expr(fn, e.Index), tInt),
		}
		v.setPos(e.Lbrack)
		v.setType(et)
		return &address{addr: fn.emit(v), pos: e.Lbrack, expr: e}

	case *ast.StarExpr:
		return &address{addr: b.expr(fn, e.X), pos: e.Star, expr: e}
	}

	panic(fmt.Sprintf("unexpected address expression: %T", e))
}

type store struct {
	lhs lvalue
	rhs Value
}

type storebuf struct{ stores []store }

func (sb *storebuf) store(lhs lvalue, rhs Value) {
	sb.stores = append(sb.stores, store{lhs, rhs})
}

func (sb *storebuf) emit(fn *Function) {
	for _, s := range sb.stores {
		s.lhs.store(fn, s.rhs)
	}
}

// assign emits to fn code to initialize the lvalue loc with the value
// of expression e.  If isZero is true, assign assumes that loc holds
// the zero value for its type.
//
// This is equivalent to loc.store(fn, b.expr(fn, e)), but may generate
// better code in some cases, e.g., for composite literals in an
// addressable location.
//
// If sb is not nil, assign generates code to evaluate expression e, but
// not to update loc.  Instead, the necessary stores are appended to the
// storebuf sb so that they can be executed later.  This allows correct
// in-place update of existing variables when the RHS is a composite
// literal that may reference parts of the LHS.
//
func (b *builder) assign(fn *Function, loc lvalue, e ast.Expr, isZero bool, sb *storebuf) {
	// Can we initialize it in place?
	if e, ok := unparen(e).(*ast.CompositeLit); ok {
		// A CompositeLit never evaluates to a pointer,
		// so if the type of the location is a pointer,
		// an &-operation is implied.
		if _, ok := loc.(blank); !ok { // avoid calling blank.typ()
			if isPointer(loc.typ()) {
				ptr := b.addr(fn, e, true).address(fn)
				// copy address
				if sb != nil {
					sb.store(loc, ptr)
				} else {
					loc.store(fn, ptr)
				}
				return
			}
		}

		if _, ok := loc.(*address); ok {
			if isInterface(loc.typ()) {
				// e.g. var x interface{} = T{...}
				// Can't in-place initialize an interface value.
				// Fall back to copying.
			} else {
				// x = T{...} or x := T{...}
				addr := loc.address(fn)
				if sb != nil {
					b.compLit(fn, addr, e, isZero, sb)
				} else {
					var sb storebuf
					b.compLit(fn, addr, e, isZero, &sb)
					sb.emit(fn)
				}

				// Subtle: emit debug ref for aggregate types only;
				// slice and map are handled by store ops in compLit.
				switch loc.typ().Underlying().(type) {
				case *types.Struct, *types.Array:
					emitDebugRef(fn, e, addr, true)
				}

				return
			}
		}
	}

	// simple case: just copy
	rhs := b.expr(fn, e)
	if sb != nil {
		sb.store(loc, rhs)
	} else {
		loc.store(fn, rhs)
	}
}

// expr lowers a single-result expression e to SSA form, emitting code
// to fn and returning the Value defined by the expression.
//
func (b *builder) expr(fn *Function, e ast.Expr) Value {
	e = unparen(e)

	tv := fn.Pkg.info.Types[e]

	// Is expression a constant?
	if tv.Value != nil {
		return NewConst(tv.Value, tv.Type)
	}

	var v Value
	if tv.Addressable() {
		// Prefer pointer arithmetic ({Index,Field}Addr) followed
		// by Load over subelement extraction (e.g. Index, Field),
		// to avoid large copies.
		v = b.addr(fn, e, false).load(fn)
	} else {
		v = b.expr0(fn, e, tv)
	}
	if fn.debugInfo() {
		emitDebugRef(fn, e, v, false)
	}
	return v
}

func (b *builder) expr0(fn *Function, e ast.Expr, tv types.TypeAndValue) Value {
	switch e := e.(type) {
	case *ast.BasicLit:
		panic("non-constant BasicLit") // unreachable

	case *ast.FuncLit:
		fn2 := &Function{
			name:      fmt.Sprintf("%s$%d", fn.Name(), 1+len(fn.AnonFuncs)),
			Signature: fn.Pkg.typeOf(e.Type).Underlying().(*types.Signature),
			pos:       e.Type.Func,
			parent:    fn,
			Pkg:       fn.Pkg,
			Prog:      fn.Prog,
			syntax:    e,
		}
		fn.AnonFuncs = append(fn.AnonFuncs, fn2)
		b.buildFunction(fn2)
		if fn2.FreeVars == nil {
			return fn2
		}
		v := &MakeClosure{Fn: fn2}
		v.setType(tv.Type)
		for _, fv := range fn2.FreeVars {
			v.Bindings = append(v.Bindings, fv.outer)
			fv.outer = nil
		}
		return fn.emit(v)

	case *ast.TypeAssertExpr: // single-result form only
		return emitTypeAssert(fn, b.expr(fn, e.X), tv.Type, e.Lparen)

	case *ast.CallExpr:
		if fn.Pkg.info.Types[e.Fun].IsType() {
			// Explicit type conversion, e.g. string(x) or big.Int(x)
			x := b.expr(fn, e.Args[0])
			y := emitConv(fn, x, tv.Type)
			if y != x {
				switch y := y.(type) {
				case *Convert:
					y.pos = e.Lparen
				case *ChangeType:
					y.pos = e.Lparen
				case *MakeInterface:
					y.pos = e.Lparen
				}
			}
			return y
		}
		// Call to "intrinsic" built-ins, e.g. new, make, panic.
		if id, ok := unparen(e.Fun).(*ast.Ident); ok {
			if obj, ok := fn.Pkg.info.Uses[id].(*types.Builtin); ok {
				if v := b.builtin(fn, obj, e.Args, tv.Type, e.Lparen); v != nil {
					return v
				}
			}
		}
		// Regular function call.
		var v Call
		b.setCall(fn, e, &v.Call)
		v.setType(tv.Type)
		return fn.emit(&v)

	case *ast.UnaryExpr:
		switch e.Op {
		case token.AND: // &X --- potentially escaping.
			addr := b.addr(fn, e.X, true)
			if _, ok := unparen(e.X).(*ast.StarExpr); ok {
				// &*p must panic if p is nil (http://golang.org/s/go12nil).
				// For simplicity, we'll just (suboptimally) rely
				// on the side effects of a load.
				// TODO(adonovan): emit dedicated nilcheck.
				addr.load(fn)
			}
			return addr.address(fn)
		case token.ADD:
			return b.expr(fn, e.X)
		case token.NOT, token.ARROW, token.SUB, token.XOR: // ! <- - ^
			v := &UnOp{
				Op: e.Op,
				X:  b.expr(fn, e.X),
			}
			v.setPos(e.OpPos)
			v.setType(tv.Type)
			return fn.emit(v)
		default:
			panic(e.Op)
		}

	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND, token.LOR:
			return b.logicalBinop(fn, e)
		case token.SHL, token.SHR:
			fallthrough
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM, token.AND, token.OR, token.XOR, token.AND_NOT:
			return emitArith(fn, e.Op, b.expr(fn, e.X), b.expr(fn, e.Y), tv.Type, e.OpPos)

		case token.EQL, token.NEQ, token.GTR, token.LSS, token.LEQ, token.GEQ:
			cmp := emitCompare(fn, e.Op, b.expr(fn, e.X), b.expr(fn, e.Y), e.OpPos)
			// The type of x==y may be UntypedBool.
			return emitConv(fn, cmp, DefaultType(tv.Type))
		default:
			panic("illegal op in BinaryExpr: " + e.Op.String())
		}

	case *ast.SliceExpr:
		var low, high, max Value
		var x Value
		switch fn.Pkg.typeOf(e.X).Underlying().(type) {
		case *types.Array:
			// Potentially escaping.
			x = b.addr(fn, e.X, true).address(fn)
		case *types.Basic, *types.Slice, *types.Pointer: // *array
			x = b.expr(fn, e.X)
		default:
			panic("unreachable")
		}
		if e.High != nil {
			high = b.expr(fn, e.High)
		}
		if e.Low != nil {
			low = b.expr(fn, e.Low)
		}
		if e.Slice3 {
			max = b.expr(fn, e.Max)
		}
		v := &Slice{
			X:    x,
			Low:  low,
			High: high,
			Max:  max,
		}
		v.setPos(e.Lbrack)
		v.setType(tv.Type)
		return fn.emit(v)

	case *ast.Ident:
		obj := fn.Pkg.info.Uses[e]
		// Universal built-in or nil?
		switch obj := obj.(type) {
		case *types.Builtin:
			return &Builtin{name: obj.Name(), sig: tv.Type.(*types.Signature)}
		case *types.Nil:
			return nilConst(tv.Type)
		}
		// Package-level func or var?
		if v := fn.Prog.packageLevelValue(obj); v != nil {
			if _, ok := obj.(*types.Var); ok {
				return emitLoad(fn, v) // var (address)
			}
			return v // (func)
		}
		// Local var.
		return emitLoad(fn, fn.lookup(obj, false)) // var (address)

	case *ast.SelectorExpr:
		sel, ok := fn.Pkg.info.Selections[e]
		if !ok {
			// qualified identifier
			return b.expr(fn, e.Sel)
		}
		switch sel.Kind() {
		case types.MethodExpr:
			// (*T).f or T.f, the method f from the method-set of type T.
			// The result is a "thunk".
			return emitConv(fn, makeThunk(fn.Prog, sel), tv.Type)

		case types.MethodVal:
			// e.f where e is an expression and f is a method.
			// The result is a "bound".
			obj := sel.Obj().(*types.Func)
			rt := recvType(obj)
			wantAddr := isPointer(rt)
			escaping := true
			v := b.receiver(fn, e.X, wantAddr, escaping, sel)
			if isInterface(rt) {
				// If v has interface type I,
				// we must emit a check that v is non-nil.
				// We use: typeassert v.(I).
				emitTypeAssert(fn, v, rt, token.NoPos)
			}
			c := &MakeClosure{
				Fn:       makeBound(fn.Prog, obj),
				Bindings: []Value{v},
			}
			c.setPos(e.Sel.Pos())
			c.setType(tv.Type)
			return fn.emit(c)

		case types.FieldVal:
			indices := sel.Index()
			last := len(indices) - 1
			v := b.expr(fn, e.X)
			v = emitImplicitSelections(fn, v, indices[:last])
			v = emitFieldSelection(fn, v, indices[last], false, e.Sel)
			return v
		}

		panic("unexpected expression-relative selector")

	case *ast.IndexExpr:
		switch t := fn.Pkg.typeOf(e.X).Underlying().(type) {
		case *types.Array:
			// Non-addressable array (in a register).
			v := &Index{
				X:     b.expr(fn, e.X),
				Index: emitConv(fn, b.expr(fn, e.Index), tInt),
			}
			v.setPos(e.Lbrack)
			v.setType(t.Elem())
			return fn.emit(v)

		case *types.Map:
			// Maps are not addressable.
			mapt := fn.Pkg.typeOf(e.X).Underlying().(*types.Map)
			v := &Lookup{
				X:     b.expr(fn, e.X),
				Index: emitConv(fn, b.expr(fn, e.Index), mapt.Key()),
			}
			v.setPos(e.Lbrack)
			v.setType(mapt.Elem())
			return fn.emit(v)

		case *types.Basic: // => string
			// Strings are not addressable.
			v := &Lookup{
				X:     b.expr(fn, e.X),
				Index: b.expr(fn, e.Index),
			}
			v.setPos(e.Lbrack)
			v.setType(tByte)
			return fn.emit(v)

		case *types.Slice, *types.Pointer: // *array
			// Addressable slice/array; use IndexAddr and Load.
			return b.addr(fn, e, false).load(fn)

		default:
			panic("unexpected container type in IndexExpr: " + t.String())
		}

	case *ast.CompositeLit, *ast.StarExpr:
		// Addressable types (lvalues)
		return b.addr(fn, e, false).load(fn)
	}

	panic(fmt.Sprintf("unexpected expr: %T", e))
}

// stmtList emits to fn code for all statements in list.
func (b *builder) stmtList(fn *Function, list []ast.Stmt) {
	for _, s := range list {
		b.stmt(fn, s)
	}
}

// receiver emits to fn code for expression e in the "receiver"
// position of selection e.f (where f may be a field or a method) and
// returns the effective receiver after applying the implicit field
// selections of sel.
//
// wantAddr requests that the result is an an address.  If
// !sel.Indirect(), this may require that e be built in addr() mode; it
// must thus be addressable.
//
// escaping is defined as per builder.addr().
//
func (b *builder) receiver(fn *Function, e ast.Expr, wantAddr, escaping bool, sel *types.Selection) Value {
	var v Value
	if wantAddr && !sel.Indirect() && !isPointer(fn.Pkg.typeOf(e)) {
		v = b.addr(fn, e, escaping).address(fn)
	} else {
		v = b.expr(fn, e)
	}

	last := len(sel.Index()) - 1
	v = emitImplicitSelections(fn, v, sel.Index()[:last])
	if !wantAddr && isPointer(v.Type()) {
		v = emitLoad(fn, v)
	}
	return v
}

// setCallFunc populates the function parts of a CallCommon structure
// (Func, Method, Recv, Args[0]) based on the kind of invocation
// occurring in e.
//
func (b *builder) setCallFunc(fn *Function, e *ast.CallExpr, c *CallCommon) {
	c.pos = e.Lparen

	// Is this a method call?
	if selector, ok := unparen(e.Fun).(*ast.SelectorExpr); ok {
		sel, ok := fn.Pkg.info.Selections[selector]
		if ok && sel.Kind() == types.MethodVal {
			obj := sel.Obj().(*types.Func)
			recv := recvType(obj)
			wantAddr := isPointer(recv)
			escaping := true
			v := b.receiver(fn, selector.X, wantAddr, escaping, sel)
			if isInterface(recv) {
				// Invoke-mode call.
				c.Value = v
				c.Method = obj
			} else {
				// "Call"-mode call.
				c.Value = fn.Prog.declaredFunc(obj)
				c.Args = append(c.Args, v)
			}
			return
		}

		// sel.Kind()==MethodExpr indicates T.f() or (*T).f():
		// a statically dispatched call to the method f in the
		// method-set of T or *T.  T may be an interface.
		//
		// e.Fun would evaluate to a concrete method, interface
		// wrapper function, or promotion wrapper.
		//
		// For now, we evaluate it in the usual way.
		//
		// TODO(adonovan): opt: inline expr() here, to make the
		// call static and to avoid generation of wrappers.
		// It's somewhat tricky as it may consume the first
		// actual parameter if the call is "invoke" mode.
		//
		// Examples:
		//  type T struct{}; func (T) f() {}   // "call" mode
		//  type T interface { f() }           // "invoke" mode
		//
		//  type S struct{ T }
		//
		//  var s S
		//  S.f(s)
		//  (*S).f(&s)
		//
		// Suggested approach:
		// - consume the first actual parameter expression
		//   and build it with b.expr().
		// - apply implicit field selections.
		// - use MethodVal logic to populate fields of c.
	}

	// Evaluate the function operand in the usual way.
	c.Value = b.expr(fn, e.Fun)
}

// emitCallArgs emits to f code for the actual parameters of call e to
// a (possibly built-in) function of effective type sig.
// The argument values are appended to args, which is then returned.
//
func (b *builder) emitCallArgs(fn *Function, sig *types.Signature, e *ast.CallExpr, args []Value) []Value {
	// f(x, y, z...): pass slice z straight through.
	if e.Ellipsis != 0 {
		for i, arg := range e.Args {
			v := emitConv(fn, b.expr(fn, arg), sig.Params().At(i).Type())
			args = append(args, v)
		}
		return args
	}

	offset := len(args) // 1 if call has receiver, 0 otherwise

	// Evaluate actual parameter expressions.
	//
	// If this is a chained call of the form f(g()) where g has
	// multiple return values (MRV), they are flattened out into
	// args; a suffix of them may end up in a varargs slice.
	for _, arg := range e.Args {
		v := b.expr(fn, arg)
		if ttuple, ok := v.Type().(*types.Tuple); ok { // MRV chain
			for i, n := 0, ttuple.Len(); i < n; i++ {
				args = append(args, emitExtract(fn, v, i))
			}
		} else {
			args = append(args, v)
		}
	}

	// Actual->formal assignability conversions for normal parameters.
	np := sig.Params().Len() // number of normal parameters
	if sig.Variadic() {
		np--
	}
	for i := 0; i < np; i++ {
		args[offset+i] = emitConv(fn, args[offset+i], sig.Params().At(i).Type())
	}

	// Actual->formal assignability conversions for variadic parameter,
	// and construction of slice.
	if sig.Variadic() {
		varargs := args[offset+np:]
		st := sig.Params().At(np).Type().(*types.Slice)
		vt := st.Elem()
		if len(varargs) == 0 {
			args = append(args, nilConst(st))
		} else {
			// Replace a suffix of args with a slice containing it.
			at := types.NewArray(vt, int64(len(varargs)))
			a := emitNew(fn, at, token.NoPos)
			a.setPos(e.Rparen)
			a.Comment = "varargs"
			for i, arg := range varargs {
				iaddr := &IndexAddr{
					X:     a,
					Index: intConst(int64(i)),
				}
				iaddr.setType(types.NewPointer(vt))
				fn.emit(iaddr)
				emitStore(fn, iaddr, arg, arg.Pos())
			}
			s := &Slice{X: a}
			s.setType(st)
			args[offset+np] = fn.emit(s)
			args = args[:offset+np+1]
		}
	}
	return args
}

// setCall emits to fn code to evaluate all the parameters of a function
// call e, and populates *c with those values.
//
func (b *builder) setCall(fn *Function, e *ast.CallExpr, c *CallCommon) {
	// First deal with the f(...) part and optional receiver.
	b.setCallFunc(fn, e, c)

	// Then append the other actual parameters.
	sig, _ := fn.Pkg.typeOf(e.Fun).Underlying().(*types.Signature)
	if sig == nil {
		panic(fmt.Sprintf("no signature for call of %s", e.Fun))
	}
	c.Args = b.emitCallArgs(fn, sig, e, c.Args)
}

// assignOp emits to fn code to perform loc += incr or loc -= incr.
func (b *builder) assignOp(fn *Function, loc lvalue, incr Value, op token.Token, pos token.Pos) {
	oldv := loc.load(fn)
	loc.store(fn, emitArith(fn, op, oldv, emitConv(fn, incr, oldv.Type()), loc.typ(), pos))
}

// localValueSpec emits to fn code to define all of the vars in the
// function-local ValueSpec, spec.
//
func (b *builder) localValueSpec(fn *Function, spec *ast.ValueSpec) {
	switch {
	case len(spec.Values) == len(spec.Names):
		// e.g. var x, y = 0, 1
		// 1:1 assignment
		for i, id := range spec.Names {
			if !isBlankIdent(id) {
				fn.addLocalForIdent(id)
			}
			lval := b.addr(fn, id, false) // non-escaping
			b.assign(fn, lval, spec.Values[i], true, nil)
		}

	case len(spec.Values) == 0:
		// e.g. var x, y int
		// Locals are implicitly zero-initialized.
		for _, id := range spec.Names {
			if !isBlankIdent(id) {
				lhs := fn.addLocalForIdent(id)
				if fn.debugInfo() {
					emitDebugRef(fn, id, lhs, true)
				}
			}
		}

	default:
		// e.g. var x, y = pos()
		tuple := b.exprN(fn, spec.Values[0])
		for i, id := range spec.Names {
			if !isBlankIdent(id) {
				fn.addLocalForIdent(id)
				lhs := b.addr(fn, id, false) // non-escaping
				lhs.store(fn, emitExtract(fn, tuple, i))
			}
		}
	}
}

// assignStmt emits code to fn for a parallel assignment of rhss to lhss.
// isDef is true if this is a short variable declaration (:=).
//
// Note the similarity with localValueSpec.
//
func (b *builder) assignStmt(fn *Function, lhss, rhss []ast.Expr, isDef bool) {
	// Side effects of all LHSs and RHSs must occur in left-to-right order.
	lvals := make([]lvalue, len(lhss))
	isZero := make([]bool, len(lhss))
	for i, lhs := range lhss {
		var lval lvalue = blank{}
		if !isBlankIdent(lhs) {
			if isDef {
				if obj := fn.Pkg.info.Defs[lhs.(*ast.Ident)]; obj != nil {
					fn.addNamedLocal(obj)
					isZero[i] = true
				}
			}
			lval = b.addr(fn, lhs, false) // non-escaping
		}
		lvals[i] = lval
	}
	if len(lhss) == len(rhss) {
		// Simple assignment:   x     = f()        (!isDef)
		// Parallel assignment: x, y  = f(), g()   (!isDef)
		// or short var decl:   x, y := f(), g()   (isDef)
		//
		// In all cases, the RHSs may refer to the LHSs,
		// so we need a storebuf.
		var sb storebuf
		for i := range rhss {
			b.assign(fn, lvals[i], rhss[i], isZero[i], &sb)
		}
		sb.emit(fn)
	} else {
		// e.g. x, y = pos()
		tuple := b.exprN(fn, rhss[0])
		emitDebugRef(fn, rhss[0], tuple, false)
		for i, lval := range lvals {
			lval.store(fn, emitExtract(fn, tuple, i))
		}
	}
}

// arrayLen returns the length of the array whose composite literal elements are elts.
func (b *builder) arrayLen(fn *Function, elts []ast.Expr) int64 {
	var max int64 = -1
	var i int64 = -1
	for _, e := range elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			i = b.expr(fn, kv.Key).(*Const).Int64()
		} else {
			i++
		}
		if i > max {
			max = i
		}
	}
	return max + 1
}

// compLit emits to fn code to initialize a composite literal e at
// address addr with type typ.
//
// Nested composite literals are recursively initialized in place
// where possible. If isZero is true, compLit assumes that addr
// holds the zero value for typ.
//
// Because the elements of a composite literal may refer to the
// variables being updated, as in the second line below,
//	x := T{a: 1}
//	x = T{a: x.a}
// all the reads must occur before all the writes.  Thus all stores to
// loc are emitted to the storebuf sb for later execution.
//
// A CompositeLit may have pointer type only in the recursive (nested)
// case when the type name is implicit.  e.g. in []*T{{}}, the inner
// literal has type *T behaves like &T{}.
// In that case, addr must hold a T, not a *T.
//
func (b *builder) compLit(fn *Function, addr Value, e *ast.CompositeLit, isZero bool, sb *storebuf) {
	typ := deref(fn.Pkg.typeOf(e))
	switch t := typ.Underlying().(type) {
	case *types.Struct:
		if !isZero && len(e.Elts) != t.NumFields() {
			// memclear
			sb.store(&address{addr, e.Lbrace, nil},
				zeroValue(fn, deref(addr.Type())))
			isZero = true
		}
		for i, e := range e.Elts {
			fieldIndex := i
			pos := e.Pos()
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				fname := kv.Key.(*ast.Ident).Name
				for i, n := 0, t.NumFields(); i < n; i++ {
					sf := t.Field(i)
					if sf.Name() == fname {
						fieldIndex = i
						pos = kv.Colon
						e = kv.Value
						break
					}
				}
			}
			sf := t.Field(fieldIndex)
			faddr := &FieldAddr{
				X:     addr,
				Field: fieldIndex,
			}
			faddr.setType(types.NewPointer(sf.Type()))
			fn.emit(faddr)
			b.assign(fn, &address{addr: faddr, pos: pos, expr: e}, e, isZero, sb)
		}

	case *types.Array, *types.Slice:
		var at *types.Array
		var array Value
		switch t := t.(type) {
		case *types.Slice:
			at = types.NewArray(t.Elem(), b.arrayLen(fn, e.Elts))
			alloc := emitNew(fn, at, e.Lbrace)
			alloc.Comment = "slicelit"
			array = alloc
		case *types.Array:
			at = t
			array = addr

			if !isZero && int64(len(e.Elts)) != at.Len() {
				// memclear
				sb.store(&address{array, e.Lbrace, nil},
					zeroValue(fn, deref(array.Type())))
			}
		}

		var idx *Const
		for _, e := range e.Elts {
			pos := e.Pos()
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				idx = b.expr(fn, kv.Key).(*Const)
				pos = kv.Colon
				e = kv.Value
			} else {
				var idxval int64
				if idx != nil {
					idxval = idx.Int64() + 1
				}
				idx = intConst(idxval)
			}
			iaddr := &IndexAddr{
				X:     array,
				Index: idx,
			}
			iaddr.setType(types.NewPointer(at.Elem()))
			fn.emit(iaddr)
			if t != at { // slice
				// backing array is unaliased => storebuf not needed.
				b.assign(fn, &address{addr: iaddr, pos: pos, expr: e}, e, true, nil)
			} else {
				b.assign(fn, &address{addr: iaddr, pos: pos, expr: e}, e, true, sb)
			}
		}

		if t != at { // slice
			s := &Slice{X: array}
			s.setPos(e.Lbrace)
			s.setType(typ)
			sb.store(&address{addr: addr, pos: e.Lbrace, expr: e}, fn.emit(s
"""




```