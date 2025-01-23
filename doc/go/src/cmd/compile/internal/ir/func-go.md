Response: The user wants to understand the functionality of the provided Go code snippet, which is a part of the Go compiler's intermediate representation (IR) for functions. I need to break down the code and identify its key features, relate it to Go language concepts, provide code examples, and point out potential pitfalls.

Here's a plan:

1. **Identify the core data structure:** The `Func` struct is central. I'll describe its purpose and the meaning of its fields.
2. **Relate `Func` to Go language features:** Explain how `Func` represents functions, methods, and closures in Go.
3. **Provide code examples:**  Illustrate how different Go code constructs would be represented by `Func` instances.
4. **Explain specific methods and functions:** Describe the purpose of key functions like `NewFunc`, `FuncName`, `NewClosureFunc`, etc.
5. **Address command-line parameters:**  Check if the provided code directly interacts with command-line parameters.
6. **Identify potential errors:** Look for common mistakes users might make when interacting with or understanding this part of the compiler.
这段代码是Go编译器中表示函数（`Func`）的数据结构定义及其相关辅助函数的实现。它的主要功能是：

1. **表示 Go 语言中的函数:**  `Func` 结构体包含了描述一个 Go 函数的所有必要信息，例如函数名、类型、参数、局部变量、函数体、以及与内联、闭包等特性相关的元数据。

2. **区分不同类型的函数表示:**  代码中注释解释了 `Func` 结构体在 IR 中的不同角色：
    *   **ONAME 节点 (Func.Nname):** 用于普通引用函数，例如在函数调用时。
    *   **ODCLFUNC 节点 (Func 本身):** 用于表示函数的声明代码。
    *   **OCLOSURE 节点 (Func.OClosure):** 用于表示函数字面量（闭包）。

3. **处理导入的函数:** 导入的函数在 IR 中会有一个 `ONAME` 节点指向一个 `Func` 实例，但其函数体 `Body` 为空。

4. **处理声明的函数和方法:** 声明的函数和方法既有 `ODCLFUNC` 节点（即 `Func` 自身），也有一个关联的 `ONAME` 节点。对于方法，`f.Sym` 会是带有接收者类型的限定方法名 (例如 "T.m")。

5. **处理函数字面量 (闭包):**  函数字面量由 `OCLOSURE` 节点直接表示，但编译器也会为其生成一个底层的 `ODCLFUNC` 和 `ONAME` 来表示闭包的编译形式。这个编译后的形式会访问捕获的变量。

6. **处理方法表达式和方法值:**
    *   **方法表达式 (T.M):**  表示为 `OMETHEXPR` 节点，其 `n.Left` 和 `n.Right` 分别指向类型和方法。
    *   **方法值 (t.M):**  在直接调用时表示为 `ODOTMETH`/`ODOTINTER`，否则表示为 `OMETHVALUE`。`OMETHVALUE` 最终会被实现为一个新的函数，类似于闭包，拥有自己的 `ODCLFUNC`。

7. **存储函数的元数据:** `Func` 结构体包含了大量的字段来存储函数的各种属性，例如：
    *   `Body`: 函数体的 IR 节点列表。
    *   `Dcl`: 函数的参数和局部变量的 `ONAME` 节点列表。
    *   `ClosureVars`: 闭包捕获的外部变量列表。
    *   `Closures`: 当前函数内包含的闭包函数列表。
    *   `Pragma`:  `go:xxx` 形式的函数注解。
    *   `ABI`: 函数的 ABI (应用程序二进制接口)。
    *   `Inl`:  用于内联优化的信息。

8. **生成唯一的闭包名称:**  `closureName` 函数用于为函数字面量生成唯一的名称。

9. **创建新的 `Func` 实例:** `NewFunc` 和 `NewClosureFunc` 函数用于创建不同类型的 `Func` 实例。

10. **判断和设置函数的属性标志:** 提供了一系列以 `Dupok`, `Wrapper`, `HasDefer` 等开头的函数，用于访问和设置 `Func` 结构体中的标志位，表示函数的特定属性。

11. **获取函数名称:** 提供了 `FuncName`, `PkgFuncName`, `LinkFuncName` 等函数来获取不同形式的函数名称。

12. **处理 `defer` 语句:**  `NumDefers` 字段记录了函数中的 `defer` 调用数量。

13. **处理内联:** `Inline` 结构体存储了与函数内联相关的信息。

14. **处理 WebAssembly 导入和导出:** `WasmImport` 和 `WasmExport` 结构体用于存储 `//go:wasmimport` 和 `//go:wasmexport` 指令的相关信息。

**它可以推理出这是 Go 语言中函数、方法和闭包的 IR 表示的实现。**

**Go 代码示例：**

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

type MyInt int

func (m MyInt) Double() MyInt {
	return m * 2
}

func main() {
	sum := add(3, 5)
	fmt.Println(sum)

	var num MyInt = 10
	doubled := num.Double()
	fmt.Println(doubled)

	multiplier := 5
	multiply := func(x int) int { // 闭包
		return x * multiplier
	}
	result := multiply(7)
	fmt.Println(result)
}
```

**假设的输入与输出（代码推理）：**

当 Go 编译器处理上述代码时，`go/src/cmd/compile/internal/ir/func.go` 中定义的结构体和函数会被用来创建和操作表示 `add`, `MyInt.Double`, 以及匿名函数 `func(x int) int` 的 `Func` 实例。

*   **`add` 函数:**
    *   会创建一个 `Func` 实例，其 `Nname.Sym().Name` 为 "add"。
    *   `Body` 包含表示 `return a + b` 的 IR 节点。
    *   `Dcl` 包含表示参数 `a` 和 `b` 以及返回值（如果显式声明）的 `Name` 节点。

*   **`MyInt.Double` 方法:**
    *   会创建一个 `Func` 实例，其 `Nname.Sym().Name` 为 "MyInt.Double"。
    *   `Body` 包含表示 `return m * 2` 的 IR 节点。
    *   `Dcl` 包含表示接收者 `m` 和返回值的 `Name` 节点。

*   **闭包 `func(x int) int`:**
    *   会创建一个 `Func` 实例，其 `OClosure` 字段会指向一个 `ClosureExpr` 节点。
    *   `Nname.Sym().Name` 会是一个编译器生成的唯一名称，例如 `main.main.func1`。
    *   `ClosureVars` 会包含表示捕获的变量 `multiplier` 的 `Name` 节点。
    *   `Body` 包含表示 `return x * multiplier` 的 IR 节点。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在编译器的其他部分，例如 `cmd/compile/internal/gc/main.go` 或相关的标志位解析逻辑中。这些参数可能会影响到 `Func` 结构体中某些标志位的设置，例如是否禁用 nil 检查 (`funcNilCheckDisabled`) 或是否进行内联 (`Inline` 结构体的使用)。

**使用者易犯错的点：**

虽然普通 Go 开发者不会直接操作这些编译器内部的数据结构，但理解其背后的概念有助于理解 Go 语言的一些特性和限制。一个可能的误解是关于闭包的实现方式。

**示例：**

```go
package main

import "fmt"

func makeAdder(x int) func(int) int {
	return func(y int) int {
		return x + y
	}
}

func main() {
	add5 := makeAdder(5)
	add10 := makeAdder(10)
	fmt.Println(add5(3))  // 输出 8
	fmt.Println(add10(3)) // 输出 13
}
```

在这个例子中，`makeAdder` 函数返回一个闭包。对于每个 `makeAdder` 的调用，编译器都会创建一个新的 `Func` 实例来表示这个闭包。新手可能会误以为所有由 `makeAdder` 返回的闭包都共享相同的底层函数结构，但实际上它们是不同的函数实例，各自捕获了不同的 `x` 的值。`Func` 结构体中的 `ClosureVars` 字段就体现了这种捕获行为。

总结来说，`go/src/cmd/compile/internal/ir/func.go` 定义了 Go 编译器内部表示函数的核心数据结构，它是理解 Go 语言编译过程和一些高级特性的基础。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ir/func.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ir

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"fmt"
	"strings"
	"unicode/utf8"
)

// A Func corresponds to a single function in a Go program
// (and vice versa: each function is denoted by exactly one *Func).
//
// There are multiple nodes that represent a Func in the IR.
//
// The ONAME node (Func.Nname) is used for plain references to it.
// The ODCLFUNC node (the Func itself) is used for its declaration code.
// The OCLOSURE node (Func.OClosure) is used for a reference to a
// function literal.
//
// An imported function will have an ONAME node which points to a Func
// with an empty body.
// A declared function or method has an ODCLFUNC (the Func itself) and an ONAME.
// A function literal is represented directly by an OCLOSURE, but it also
// has an ODCLFUNC (and a matching ONAME) representing the compiled
// underlying form of the closure, which accesses the captured variables
// using a special data structure passed in a register.
//
// A method declaration is represented like functions, except f.Sym
// will be the qualified method name (e.g., "T.m").
//
// A method expression (T.M) is represented as an OMETHEXPR node,
// in which n.Left and n.Right point to the type and method, respectively.
// Each distinct mention of a method expression in the source code
// constructs a fresh node.
//
// A method value (t.M) is represented by ODOTMETH/ODOTINTER
// when it is called directly and by OMETHVALUE otherwise.
// These are like method expressions, except that for ODOTMETH/ODOTINTER,
// the method name is stored in Sym instead of Right.
// Each OMETHVALUE ends up being implemented as a new
// function, a bit like a closure, with its own ODCLFUNC.
// The OMETHVALUE uses n.Func to record the linkage to
// the generated ODCLFUNC, but there is no
// pointer from the Func back to the OMETHVALUE.
type Func struct {
	// if you add or remove a field, don't forget to update sizeof_test.go

	miniNode
	Body Nodes

	Nname    *Name        // ONAME node
	OClosure *ClosureExpr // OCLOSURE node

	// ONAME nodes for all params/locals for this func/closure, does NOT
	// include closurevars until transforming closures during walk.
	// Names must be listed PPARAMs, PPARAMOUTs, then PAUTOs,
	// with PPARAMs and PPARAMOUTs in order corresponding to the function signature.
	// Anonymous and blank params are declared as ~pNN (for PPARAMs) and ~rNN (for PPARAMOUTs).
	Dcl []*Name

	// ClosureVars lists the free variables that are used within a
	// function literal, but formally declared in an enclosing
	// function. The variables in this slice are the closure function's
	// own copy of the variables, which are used within its function
	// body. They will also each have IsClosureVar set, and will have
	// Byval set if they're captured by value.
	ClosureVars []*Name

	// Enclosed functions that need to be compiled.
	// Populated during walk.
	Closures []*Func

	// Parent of a closure
	ClosureParent *Func

	// Parents records the parent scope of each scope within a
	// function. The root scope (0) has no parent, so the i'th
	// scope's parent is stored at Parents[i-1].
	Parents []ScopeID

	// Marks records scope boundary changes.
	Marks []Mark

	FieldTrack map[*obj.LSym]struct{}
	DebugInfo  interface{}
	LSym       *obj.LSym // Linker object in this function's native ABI (Func.ABI)

	Inl *Inline

	// RangeParent, if non-nil, is the first non-range body function containing
	// the closure for the body of a range function.
	RangeParent *Func

	// funcLitGen, rangeLitGen and goDeferGen track how many closures have been
	// created in this function for function literals, range-over-func loops,
	// and go/defer wrappers, respectively. Used by closureName for creating
	// unique function names.
	// Tracking goDeferGen separately avoids wrappers throwing off
	// function literal numbering (e.g., runtime/trace_test.TestTraceSymbolize.func11).
	funcLitGen  int32
	rangeLitGen int32
	goDeferGen  int32

	Label int32 // largest auto-generated label in this function

	Endlineno src.XPos
	WBPos     src.XPos // position of first write barrier; see SetWBPos

	Pragma PragmaFlag // go:xxx function annotations

	flags bitset16

	// ABI is a function's "definition" ABI. This is the ABI that
	// this function's generated code is expecting to be called by.
	//
	// For most functions, this will be obj.ABIInternal. It may be
	// a different ABI for functions defined in assembly or ABI wrappers.
	//
	// This is included in the export data and tracked across packages.
	ABI obj.ABI
	// ABIRefs is the set of ABIs by which this function is referenced.
	// For ABIs other than this function's definition ABI, the
	// compiler generates ABI wrapper functions. This is only tracked
	// within a package.
	ABIRefs obj.ABISet

	NumDefers  int32 // number of defer calls in the function
	NumReturns int32 // number of explicit returns in the function

	// NWBRCalls records the LSyms of functions called by this
	// function for go:nowritebarrierrec analysis. Only filled in
	// if nowritebarrierrecCheck != nil.
	NWBRCalls *[]SymAndPos

	// For wrapper functions, WrappedFunc point to the original Func.
	// Currently only used for go/defer wrappers.
	WrappedFunc *Func

	// WasmImport is used by the //go:wasmimport directive to store info about
	// a WebAssembly function import.
	WasmImport *WasmImport
	// WasmExport is used by the //go:wasmexport directive to store info about
	// a WebAssembly function import.
	WasmExport *WasmExport
}

// WasmImport stores metadata associated with the //go:wasmimport pragma.
type WasmImport struct {
	Module string
	Name   string
}

// WasmExport stores metadata associated with the //go:wasmexport pragma.
type WasmExport struct {
	Name string
}

// NewFunc returns a new Func with the given name and type.
//
// fpos is the position of the "func" token, and npos is the position
// of the name identifier.
//
// TODO(mdempsky): I suspect there's no need for separate fpos and
// npos.
func NewFunc(fpos, npos src.XPos, sym *types.Sym, typ *types.Type) *Func {
	name := NewNameAt(npos, sym, typ)
	name.Class = PFUNC
	sym.SetFunc(true)

	fn := &Func{Nname: name}
	fn.pos = fpos
	fn.op = ODCLFUNC
	// Most functions are ABIInternal. The importer or symabis
	// pass may override this.
	fn.ABI = obj.ABIInternal
	fn.SetTypecheck(1)

	name.Func = fn

	return fn
}

func (f *Func) isStmt() {}

func (n *Func) copy() Node                                   { panic(n.no("copy")) }
func (n *Func) doChildren(do func(Node) bool) bool           { return doNodes(n.Body, do) }
func (n *Func) doChildrenWithHidden(do func(Node) bool) bool { return doNodes(n.Body, do) }
func (n *Func) editChildren(edit func(Node) Node)            { editNodes(n.Body, edit) }
func (n *Func) editChildrenWithHidden(edit func(Node) Node)  { editNodes(n.Body, edit) }

func (f *Func) Type() *types.Type                { return f.Nname.Type() }
func (f *Func) Sym() *types.Sym                  { return f.Nname.Sym() }
func (f *Func) Linksym() *obj.LSym               { return f.Nname.Linksym() }
func (f *Func) LinksymABI(abi obj.ABI) *obj.LSym { return f.Nname.LinksymABI(abi) }

// An Inline holds fields used for function bodies that can be inlined.
type Inline struct {
	Cost int32 // heuristic cost of inlining this function

	// Copy of Func.Dcl for use during inlining. This copy is needed
	// because the function's Dcl may change from later compiler
	// transformations. This field is also populated when a function
	// from another package is imported and inlined.
	Dcl     []*Name
	HaveDcl bool // whether we've loaded Dcl

	// Function properties, encoded as a string (these are used for
	// making inlining decisions). See cmd/compile/internal/inline/inlheur.
	Properties string

	// CanDelayResults reports whether it's safe for the inliner to delay
	// initializing the result parameters until immediately before the
	// "return" statement.
	CanDelayResults bool
}

// A Mark represents a scope boundary.
type Mark struct {
	// Pos is the position of the token that marks the scope
	// change.
	Pos src.XPos

	// Scope identifies the innermost scope to the right of Pos.
	Scope ScopeID
}

// A ScopeID represents a lexical scope within a function.
type ScopeID int32

const (
	funcDupok                    = 1 << iota // duplicate definitions ok
	funcWrapper                              // hide frame from users (elide in tracebacks, don't count as a frame for recover())
	funcABIWrapper                           // is an ABI wrapper (also set flagWrapper)
	funcNeedctxt                             // function uses context register (has closure variables)
	funcHasDefer                             // contains a defer statement
	funcNilCheckDisabled                     // disable nil checks when compiling this function
	funcInlinabilityChecked                  // inliner has already determined whether the function is inlinable
	funcNeverReturns                         // function never returns (in most cases calls panic(), os.Exit(), or equivalent)
	funcOpenCodedDeferDisallowed             // can't do open-coded defers
	funcClosureResultsLost                   // closure is called indirectly and we lost track of its results; used by escape analysis
	funcPackageInit                          // compiler emitted .init func for package
)

type SymAndPos struct {
	Sym *obj.LSym // LSym of callee
	Pos src.XPos  // line of call
}

func (f *Func) Dupok() bool                    { return f.flags&funcDupok != 0 }
func (f *Func) Wrapper() bool                  { return f.flags&funcWrapper != 0 }
func (f *Func) ABIWrapper() bool               { return f.flags&funcABIWrapper != 0 }
func (f *Func) Needctxt() bool                 { return f.flags&funcNeedctxt != 0 }
func (f *Func) HasDefer() bool                 { return f.flags&funcHasDefer != 0 }
func (f *Func) NilCheckDisabled() bool         { return f.flags&funcNilCheckDisabled != 0 }
func (f *Func) InlinabilityChecked() bool      { return f.flags&funcInlinabilityChecked != 0 }
func (f *Func) NeverReturns() bool             { return f.flags&funcNeverReturns != 0 }
func (f *Func) OpenCodedDeferDisallowed() bool { return f.flags&funcOpenCodedDeferDisallowed != 0 }
func (f *Func) ClosureResultsLost() bool       { return f.flags&funcClosureResultsLost != 0 }
func (f *Func) IsPackageInit() bool            { return f.flags&funcPackageInit != 0 }

func (f *Func) SetDupok(b bool)                    { f.flags.set(funcDupok, b) }
func (f *Func) SetWrapper(b bool)                  { f.flags.set(funcWrapper, b) }
func (f *Func) SetABIWrapper(b bool)               { f.flags.set(funcABIWrapper, b) }
func (f *Func) SetNeedctxt(b bool)                 { f.flags.set(funcNeedctxt, b) }
func (f *Func) SetHasDefer(b bool)                 { f.flags.set(funcHasDefer, b) }
func (f *Func) SetNilCheckDisabled(b bool)         { f.flags.set(funcNilCheckDisabled, b) }
func (f *Func) SetInlinabilityChecked(b bool)      { f.flags.set(funcInlinabilityChecked, b) }
func (f *Func) SetNeverReturns(b bool)             { f.flags.set(funcNeverReturns, b) }
func (f *Func) SetOpenCodedDeferDisallowed(b bool) { f.flags.set(funcOpenCodedDeferDisallowed, b) }
func (f *Func) SetClosureResultsLost(b bool)       { f.flags.set(funcClosureResultsLost, b) }
func (f *Func) SetIsPackageInit(b bool)            { f.flags.set(funcPackageInit, b) }

func (f *Func) SetWBPos(pos src.XPos) {
	if base.Debug.WB != 0 {
		base.WarnfAt(pos, "write barrier")
	}
	if !f.WBPos.IsKnown() {
		f.WBPos = pos
	}
}

// IsClosure reports whether f is a function literal that captures at least one value.
func (f *Func) IsClosure() bool {
	if f.OClosure == nil {
		return false
	}
	return len(f.ClosureVars) > 0
}

// FuncName returns the name (without the package) of the function f.
func FuncName(f *Func) string {
	if f == nil || f.Nname == nil {
		return "<nil>"
	}
	return f.Sym().Name
}

// PkgFuncName returns the name of the function referenced by f, with package
// prepended.
//
// This differs from the compiler's internal convention where local functions
// lack a package. This is primarily useful when the ultimate consumer of this
// is a human looking at message.
func PkgFuncName(f *Func) string {
	if f == nil || f.Nname == nil {
		return "<nil>"
	}
	s := f.Sym()
	pkg := s.Pkg

	return pkg.Path + "." + s.Name
}

// LinkFuncName returns the name of the function f, as it will appear in the
// symbol table of the final linked binary.
func LinkFuncName(f *Func) string {
	if f == nil || f.Nname == nil {
		return "<nil>"
	}
	s := f.Sym()
	pkg := s.Pkg

	return objabi.PathToPrefix(pkg.Path) + "." + s.Name
}

// ParseLinkFuncName parsers a symbol name (as returned from LinkFuncName) back
// to the package path and local symbol name.
func ParseLinkFuncName(name string) (pkg, sym string, err error) {
	pkg, sym = splitPkg(name)
	if pkg == "" {
		return "", "", fmt.Errorf("no package path in name")
	}

	pkg, err = objabi.PrefixToPath(pkg) // unescape
	if err != nil {
		return "", "", fmt.Errorf("malformed package path: %v", err)
	}

	return pkg, sym, nil
}

// Borrowed from x/mod.
func modPathOK(r rune) bool {
	if r < utf8.RuneSelf {
		return r == '-' || r == '.' || r == '_' || r == '~' ||
			'0' <= r && r <= '9' ||
			'A' <= r && r <= 'Z' ||
			'a' <= r && r <= 'z'
	}
	return false
}

func escapedImportPathOK(r rune) bool {
	return modPathOK(r) || r == '+' || r == '/' || r == '%'
}

// splitPkg splits the full linker symbol name into package and local symbol
// name.
func splitPkg(name string) (pkgpath, sym string) {
	// package-sym split is at first dot after last the / that comes before
	// any characters illegal in a package path.

	lastSlashIdx := 0
	for i, r := range name {
		// Catches cases like:
		// * example.foo[sync/atomic.Uint64].
		// * example%2ecom.foo[sync/atomic.Uint64].
		//
		// Note that name is still escaped; unescape occurs after splitPkg.
		if !escapedImportPathOK(r) {
			break
		}
		if r == '/' {
			lastSlashIdx = i
		}
	}
	for i := lastSlashIdx; i < len(name); i++ {
		r := name[i]
		if r == '.' {
			return name[:i], name[i+1:]
		}
	}

	return "", name
}

var CurFunc *Func

// WithFunc invokes do with CurFunc and base.Pos set to curfn and
// curfn.Pos(), respectively, and then restores their previous values
// before returning.
func WithFunc(curfn *Func, do func()) {
	oldfn, oldpos := CurFunc, base.Pos
	defer func() { CurFunc, base.Pos = oldfn, oldpos }()

	CurFunc, base.Pos = curfn, curfn.Pos()
	do()
}

func FuncSymName(s *types.Sym) string {
	return s.Name + "·f"
}

// ClosureDebugRuntimeCheck applies boilerplate checks for debug flags
// and compiling runtime.
func ClosureDebugRuntimeCheck(clo *ClosureExpr) {
	if base.Debug.Closure > 0 {
		if clo.Esc() == EscHeap {
			base.WarnfAt(clo.Pos(), "heap closure, captured vars = %v", clo.Func.ClosureVars)
		} else {
			base.WarnfAt(clo.Pos(), "stack closure, captured vars = %v", clo.Func.ClosureVars)
		}
	}
	if base.Flag.CompilingRuntime && clo.Esc() == EscHeap && !clo.IsGoWrap {
		base.ErrorfAt(clo.Pos(), 0, "heap-allocated closure %s, not allowed in runtime", FuncName(clo.Func))
	}
}

// globClosgen is like Func.Closgen, but for the global scope.
var globClosgen int32

// closureName generates a new unique name for a closure within outerfn at pos.
func closureName(outerfn *Func, pos src.XPos, why Op) *types.Sym {
	if outerfn.OClosure != nil && outerfn.OClosure.Func.RangeParent != nil {
		outerfn = outerfn.OClosure.Func.RangeParent
	}
	pkg := types.LocalPkg
	outer := "glob."
	var suffix string = "."
	switch why {
	default:
		base.FatalfAt(pos, "closureName: bad Op: %v", why)
	case OCLOSURE:
		if outerfn.OClosure == nil {
			suffix = ".func"
		}
	case ORANGE:
		suffix = "-range"
	case OGO:
		suffix = ".gowrap"
	case ODEFER:
		suffix = ".deferwrap"
	}
	gen := &globClosgen

	// There may be multiple functions named "_". In those
	// cases, we can't use their individual Closgens as it
	// would lead to name clashes.
	if !IsBlank(outerfn.Nname) {
		pkg = outerfn.Sym().Pkg
		outer = FuncName(outerfn)

		switch why {
		case OCLOSURE:
			gen = &outerfn.funcLitGen
		case ORANGE:
			gen = &outerfn.rangeLitGen
		default:
			gen = &outerfn.goDeferGen
		}
	}

	// If this closure was created due to inlining, then incorporate any
	// inlined functions' names into the closure's linker symbol name
	// too (#60324).
	if inlIndex := base.Ctxt.InnermostPos(pos).Base().InliningIndex(); inlIndex >= 0 {
		names := []string{outer}
		base.Ctxt.InlTree.AllParents(inlIndex, func(call obj.InlinedCall) {
			names = append(names, call.Name)
		})
		outer = strings.Join(names, ".")
	}

	*gen++
	return pkg.Lookup(fmt.Sprintf("%s%s%d", outer, suffix, *gen))
}

// NewClosureFunc creates a new Func to represent a function literal
// with the given type.
//
// fpos the position used for the underlying ODCLFUNC and ONAME,
// whereas cpos is the position used for the OCLOSURE. They're
// separate because in the presence of inlining, the OCLOSURE node
// should have an inline-adjusted position, whereas the ODCLFUNC and
// ONAME must not.
//
// outerfn is the enclosing function. The returned function is
// appending to pkg.Funcs.
//
// why is the reason we're generating this Func. It can be OCLOSURE
// (for a normal function literal) or OGO or ODEFER (for wrapping a
// call expression that has parameters or results).
func NewClosureFunc(fpos, cpos src.XPos, why Op, typ *types.Type, outerfn *Func, pkg *Package) *Func {
	if outerfn == nil {
		base.FatalfAt(fpos, "outerfn is nil")
	}

	fn := NewFunc(fpos, fpos, closureName(outerfn, cpos, why), typ)
	fn.SetDupok(outerfn.Dupok()) // if the outer function is dupok, so is the closure

	clo := &ClosureExpr{Func: fn}
	clo.op = OCLOSURE
	clo.pos = cpos
	clo.SetType(typ)
	clo.SetTypecheck(1)
	if why == ORANGE {
		clo.Func.RangeParent = outerfn
		if outerfn.OClosure != nil && outerfn.OClosure.Func.RangeParent != nil {
			clo.Func.RangeParent = outerfn.OClosure.Func.RangeParent
		}
	}
	fn.OClosure = clo

	fn.Nname.Defn = fn
	pkg.Funcs = append(pkg.Funcs, fn)
	fn.ClosureParent = outerfn

	return fn
}

// IsFuncPCIntrinsic returns whether n is a direct call of internal/abi.FuncPCABIxxx functions.
func IsFuncPCIntrinsic(n *CallExpr) bool {
	if n.Op() != OCALLFUNC || n.Fun.Op() != ONAME {
		return false
	}
	fn := n.Fun.(*Name).Sym()
	return (fn.Name == "FuncPCABI0" || fn.Name == "FuncPCABIInternal") &&
		fn.Pkg.Path == "internal/abi"
}

// IsIfaceOfFunc inspects whether n is an interface conversion from a direct
// reference of a func. If so, it returns referenced Func; otherwise nil.
//
// This is only usable before walk.walkConvertInterface, which converts to an
// OMAKEFACE.
func IsIfaceOfFunc(n Node) *Func {
	if n, ok := n.(*ConvExpr); ok && n.Op() == OCONVIFACE {
		if name, ok := n.X.(*Name); ok && name.Op() == ONAME && name.Class == PFUNC {
			return name.Func
		}
	}
	return nil
}

// FuncPC returns a uintptr-typed expression that evaluates to the PC of a
// function as uintptr, as returned by internal/abi.FuncPC{ABI0,ABIInternal}.
//
// n should be a Node of an interface type, as is passed to
// internal/abi.FuncPC{ABI0,ABIInternal}.
//
// TODO(prattmic): Since n is simply an interface{} there is no assertion that
// it is actually a function at all. Perhaps we should emit a runtime type
// assertion?
func FuncPC(pos src.XPos, n Node, wantABI obj.ABI) Node {
	if !n.Type().IsInterface() {
		base.ErrorfAt(pos, 0, "internal/abi.FuncPC%s expects an interface value, got %v", wantABI, n.Type())
	}

	if fn := IsIfaceOfFunc(n); fn != nil {
		name := fn.Nname
		abi := fn.ABI
		if abi != wantABI {
			base.ErrorfAt(pos, 0, "internal/abi.FuncPC%s expects an %v function, %s is defined as %v", wantABI, wantABI, name.Sym().Name, abi)
		}
		var e Node = NewLinksymExpr(pos, name.LinksymABI(abi), types.Types[types.TUINTPTR])
		e = NewAddrExpr(pos, e)
		e.SetType(types.Types[types.TUINTPTR].PtrTo())
		e = NewConvExpr(pos, OCONVNOP, types.Types[types.TUINTPTR], e)
		e.SetTypecheck(1)
		return e
	}
	// fn is not a defined function. It must be ABIInternal.
	// Read the address from func value, i.e. *(*uintptr)(idata(fn)).
	if wantABI != obj.ABIInternal {
		base.ErrorfAt(pos, 0, "internal/abi.FuncPC%s does not accept func expression, which is ABIInternal", wantABI)
	}
	var e Node = NewUnaryExpr(pos, OIDATA, n)
	e.SetType(types.Types[types.TUINTPTR].PtrTo())
	e.SetTypecheck(1)
	e = NewStarExpr(pos, e)
	e.SetType(types.Types[types.TUINTPTR])
	e.SetTypecheck(1)
	return e
}

// DeclareParams creates Names for all of the parameters in fn's
// signature and adds them to fn.Dcl.
//
// If setNname is true, then it also sets types.Field.Nname for each
// parameter.
func (fn *Func) DeclareParams(setNname bool) {
	if fn.Dcl != nil {
		base.FatalfAt(fn.Pos(), "%v already has Dcl", fn)
	}

	declareParams := func(params []*types.Field, ctxt Class, prefix string, offset int) {
		for i, param := range params {
			sym := param.Sym
			if sym == nil || sym.IsBlank() {
				sym = fn.Sym().Pkg.LookupNum(prefix, i)
			}

			name := NewNameAt(param.Pos, sym, param.Type)
			name.Class = ctxt
			name.Curfn = fn
			fn.Dcl[offset+i] = name

			if setNname {
				param.Nname = name
			}
		}
	}

	sig := fn.Type()
	params := sig.RecvParams()
	results := sig.Results()

	fn.Dcl = make([]*Name, len(params)+len(results))
	declareParams(params, PPARAM, "~p", 0)
	declareParams(results, PPARAMOUT, "~r", len(params))
}
```