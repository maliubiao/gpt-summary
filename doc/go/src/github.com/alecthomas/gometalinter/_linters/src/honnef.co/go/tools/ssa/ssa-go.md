Response:
My thinking process to arrive at the summary of `ssa.go`'s functionality involved these steps:

1. **Identify the core purpose:** The initial comments of the file and the `package ssa` declaration immediately tell us this code defines a Static Single Assignment (SSA) intermediate representation for Go programs. This is the fundamental concept around which everything else revolves.

2. **Analyze the key data structures:** I scanned the code for type definitions. The prominent structures are `Program`, `Package`, `Member`, `Value`, `Instruction`, `Function`, and `BasicBlock`. I focused on understanding the relationships between these types and their primary roles.

3. **Deconstruct the `Program` structure:**
    * `Fset`:  Position information. Essential for debugging and error reporting.
    * `imported`, `packages`: Management of dependencies and loaded packages.
    * `mode`: Configuration options during SSA construction.
    * `MethodSets`:  Caching of method sets, important for interface resolution.
    * The `sync.Mutex` and related maps (`methodSets`, `runtimeTypes`, `canon`, `bounds`, `thunks`) point to optimizations and management of method-related information, particularly for generics and method calls.

4. **Deconstruct the `Package` structure:**
    * `Prog`: Back-reference to the owning program.
    * `Pkg`: Link to the `go/types` package representation.
    * `Members`:  The central container for all named entities within a package.
    * `values`: Mapping of `types.Object` to `Value`, hinting at how type information is connected to the SSA representation.
    * `init`:  Representation of the package's initialization logic.
    * The `sync.Once` and transient fields (`ninit`, `info`, `files`) relate to the build process of the SSA form.

5. **Examine `Member` and its subtypes:**  Understanding that `Member` is an interface implemented by `NamedConst`, `Global`, `Function`, and `Type` clarifies how different kinds of package-level declarations are represented.

6. **Dive into `Value` and `Instruction`:**  These are the building blocks of the SSA representation.
    * `Value` represents a computed result. I noted the `Name()`, `String()`, `Type()`, `Parent()`, and `Referrers()` methods and their significance. The description emphasized that names aren't semantically important, highlighting the SSA nature.
    * `Instruction` represents an operation. I paid attention to the distinction between instructions that produce a `Value` and those that have side effects. The `Operands()` method is crucial for graph analysis.

7. **Understand `Function` and `BasicBlock`:**
    * `Function` encapsulates the code and metadata of a function. The `Blocks` field is the core of the control flow graph. I noted the handling of external functions and free variables for closures.
    * `BasicBlock` represents a sequence of instructions with a single entry and exit point. The `Preds` and `Succs` fields define the control flow.

8. **Recognize the "Pure Values":**  Structures like `FreeVar`, `Parameter`, `Const`, `Global`, and `Builtin` represent constant or directly accessible values.

9. **Categorize the "Value-defining instructions":**  This section is extensive and represents the core operations in the SSA form. I mentally grouped them into categories like:
    * Memory allocation (`Alloc`)
    * Data manipulation (`Phi`, `Sigma`, `BinOp`, `UnOp`, `Convert`, `ChangeType`, `ChangeInterface`, `MakeInterface`)
    * Function calls (`Call`, `MakeClosure`)
    * Data structure operations (`MakeMap`, `MakeChan`, `MakeSlice`, `Slice`, `FieldAddr`, `Field`, `IndexAddr`, `Index`, `Lookup`)
    * Control flow (`Select`, `Range`, `Next` - although `Next` wasn't included in this snippet)

10. **Synthesize the summary:** Based on the above analysis, I formulated the key functionalities:
    * **Core Function:** Defining an SSA IR for Go.
    * **Key Structures:**  Listing the main types and their purposes.
    * **Program-level:**  Managing packages, imports, and compilation settings.
    * **Package-level:** Representing package members (functions, variables, constants, types).
    * **Function-level:**  Representing function code as a CFG of basic blocks and SSA instructions.
    * **Value and Instruction:**  The fundamental units of computation.
    * **Operations:**  Listing the types of operations supported by the SSA representation.

11. **Review and refine:** I reread the generated summary to ensure it was accurate, concise, and covered the most important aspects of the code snippet. I made sure to use clear and understandable language.
这段代码是Go语言SSA（Static Single Assignment，静态单赋值）中间表示的一部分实现，主要定义了构建和表示Go程序SSA形式所需的各种数据结构。以下是它的功能归纳：

**核心功能：定义Go语言程序的静态单赋值（SSA）中间表示**

更具体来说，它定义了以下关键的数据结构，用于在编译过程中将Go源代码转换为一种更易于分析和优化的形式：

* **`Program`**:  代表一个完整的或部分的Go程序，包含了程序的文件信息、导入的包、已加载的包以及构建SSA的模式设置。它还维护了方法集缓存和类型规范化相关的映射。
* **`Package`**: 代表一个被分析的Go包，包含了这个包中所有包级别的函数、变量、常量和类型的成员信息。还包含了包的初始化函数等。
* **`Member`**:  一个接口，表示包的成员，由 `NamedConst`（命名常量）、`Global`（全局变量）、`Function`（函数）和 `Type`（类型）实现。
* **`Type`**: 代表包级别的命名类型。
* **`NamedConst`**: 代表包级别的命名常量，包含了常量的值和定义位置信息。
* **`Value`**:  一个接口，代表SSA中的一个值，可以被指令引用。它定义了获取值的名称、字符串表示、类型、所属函数、引用它的指令以及定义位置的方法。
* **`Instruction`**: 一个接口，代表SSA中的一条指令，用于计算新的值或产生某种效果。定义了获取指令的字符串表示、所属函数、所属基本块、操作数和定义位置的方法。
* **`Node`**: 一个接口，包含了 `Value` 和 `Instruction` 共有的方法，以及通用的获取操作数和引用者的方法，用于简化SSA图算法。
* **`Function`**: 代表函数或方法的参数、返回值和代码。如果 `Blocks` 为 `nil`，则表示这是一个外部函数。包含了函数的参数、自由变量、局部变量、基本块、异常恢复入口等信息。
* **`BasicBlock`**: 代表SSA的基本块，是顺序执行的指令序列，以控制流转移指令结尾。包含了块内的指令、前驱和后继基本块、以及支配树信息。
* **`FreeVar`**: 代表函数中引用的外部（自由）变量。
* **`Parameter`**: 代表函数的输入参数。
* **`Const`**: 代表常量表达式的值。
* **`Global`**: 代表包级别变量的地址。
* **`Builtin`**: 代表内置函数的特定用法。
* **各种具体的指令类型**:  例如 `Alloc`（内存分配）、`Phi`（φ节点，合并来自不同控制流路径的值）、`Call`（函数调用）、`BinOp`（二元运算）、`UnOp`（一元运算）、`Convert`（类型转换）、`MakeInterface`（创建接口值）、`MakeClosure`（创建闭包）、`MakeMap`（创建map）、`MakeChan`（创建channel）、`MakeSlice`（创建slice）、`Slice`（切片操作）、`FieldAddr`（获取结构体字段地址）、`Field`（获取结构体字段）、`IndexAddr`（获取数组或切片元素地址）、`Index`（获取数组元素）、`Lookup`（map或字符串查找）、`Select`（select语句）、`Range`（range循环）等。

**总结:**

这段代码的核心是定义了一套数据结构，用于将Go语言程序表示成静态单赋值（SSA）形式。SSA是一种重要的中间表示，它具有每个变量只被赋值一次的特性，这使得编译器能够更容易地进行各种静态分析和优化，例如死代码消除、常量折叠、寄存器分配等。这些数据结构涵盖了程序、包、成员（变量、常量、函数、类型）、值、指令、基本块等各个方面，为后续的SSA构建和使用奠定了基础。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This package defines a high-level intermediate representation for
// Go programs using static single-assignment (SSA) form.

import (
	"fmt"
	"go/ast"
	exact "go/constant"
	"go/token"
	"go/types"
	"sync"

	"golang.org/x/tools/go/types/typeutil"
)

// A Program is a partial or complete Go program converted to SSA form.
type Program struct {
	Fset       *token.FileSet              // position information for the files of this Program
	imported   map[string]*Package         // all importable Packages, keyed by import path
	packages   map[*types.Package]*Package // all loaded Packages, keyed by object
	mode       BuilderMode                 // set of mode bits for SSA construction
	MethodSets typeutil.MethodSetCache     // cache of type-checker's method-sets

	methodsMu    sync.Mutex                 // guards the following maps:
	methodSets   typeutil.Map               // maps type to its concrete methodSet
	runtimeTypes typeutil.Map               // types for which rtypes are needed
	canon        typeutil.Map               // type canonicalization map
	bounds       map[*types.Func]*Function  // bounds for curried x.Method closures
	thunks       map[selectionKey]*Function // thunks for T.Method expressions
}

// A Package is a single analyzed Go package containing Members for
// all package-level functions, variables, constants and types it
// declares.  These may be accessed directly via Members, or via the
// type-specific accessor methods Func, Type, Var and Const.
//
// Members also contains entries for "init" (the synthetic package
// initializer) and "init#%d", the nth declared init function,
// and unspecified other things too.
//
type Package struct {
	Prog    *Program               // the owning program
	Pkg     *types.Package         // the corresponding go/types.Package
	Members map[string]Member      // all package members keyed by name (incl. init and init#%d)
	values  map[types.Object]Value // package members (incl. types and methods), keyed by object
	init    *Function              // Func("init"); the package's init function
	debug   bool                   // include full debug info in this package

	// The following fields are set transiently, then cleared
	// after building.
	buildOnce sync.Once   // ensures package building occurs once
	ninit     int32       // number of init functions
	info      *types.Info // package type information
	files     []*ast.File // package ASTs
}

// A Member is a member of a Go package, implemented by *NamedConst,
// *Global, *Function, or *Type; they are created by package-level
// const, var, func and type declarations respectively.
//
type Member interface {
	Name() string                    // declared name of the package member
	String() string                  // package-qualified name of the package member
	RelString(*types.Package) string // like String, but relative refs are unqualified
	Object() types.Object            // typechecker's object for this member, if any
	Pos() token.Pos                  // position of member's declaration, if known
	Type() types.Type                // type of the package member
	Token() token.Token              // token.{VAR,FUNC,CONST,TYPE}
	Package() *Package               // the containing package
}

// A Type is a Member of a Package representing a package-level named type.
type Type struct {
	object *types.TypeName
	pkg    *Package
}

// A NamedConst is a Member of a Package representing a package-level
// named constant.
//
// Pos() returns the position of the declaring ast.ValueSpec.Names[*]
// identifier.
//
// NB: a NamedConst is not a Value; it contains a constant Value, which
// it augments with the name and position of its 'const' declaration.
//
type NamedConst struct {
	object *types.Const
	Value  *Const
	pkg    *Package
}

// A Value is an SSA value that can be referenced by an instruction.
type Value interface {
	// Name returns the name of this value, and determines how
	// this Value appears when used as an operand of an
	// Instruction.
	//
	// This is the same as the source name for Parameters,
	// Builtins, Functions, FreeVars, Globals.
	// For constants, it is a representation of the constant's value
	// and type.  For all other Values this is the name of the
	// virtual register defined by the instruction.
	//
	// The name of an SSA Value is not semantically significant,
	// and may not even be unique within a function.
	Name() string

	// If this value is an Instruction, String returns its
	// disassembled form; otherwise it returns unspecified
	// human-readable information about the Value, such as its
	// kind, name and type.
	String() string

	// Type returns the type of this value.  Many instructions
	// (e.g. IndexAddr) change their behaviour depending on the
	// types of their operands.
	Type() types.Type

	// Parent returns the function to which this Value belongs.
	// It returns nil for named Functions, Builtin, Const and Global.
	Parent() *Function

	// Referrers returns the list of instructions that have this
	// value as one of their operands; it may contain duplicates
	// if an instruction has a repeated operand.
	//
	// Referrers actually returns a pointer through which the
	// caller may perform mutations to the object's state.
	//
	// Referrers is currently only defined if Parent()!=nil,
	// i.e. for the function-local values FreeVar, Parameter,
	// Functions (iff anonymous) and all value-defining instructions.
	// It returns nil for named Functions, Builtin, Const and Global.
	//
	// Instruction.Operands contains the inverse of this relation.
	Referrers() *[]Instruction

	// Pos returns the location of the AST token most closely
	// associated with the operation that gave rise to this value,
	// or token.NoPos if it was not explicit in the source.
	//
	// For each ast.Node type, a particular token is designated as
	// the closest location for the expression, e.g. the Lparen
	// for an *ast.CallExpr.  This permits a compact but
	// approximate mapping from Values to source positions for use
	// in diagnostic messages, for example.
	//
	// (Do not use this position to determine which Value
	// corresponds to an ast.Expr; use Function.ValueForExpr
	// instead.  NB: it requires that the function was built with
	// debug information.)
	Pos() token.Pos
}

// An Instruction is an SSA instruction that computes a new Value or
// has some effect.
//
// An Instruction that defines a value (e.g. BinOp) also implements
// the Value interface; an Instruction that only has an effect (e.g. Store)
// does not.
//
type Instruction interface {
	// String returns the disassembled form of this value.
	//
	// Examples of Instructions that are Values:
	//       "x + y"     (BinOp)
	//       "len([])"   (Call)
	// Note that the name of the Value is not printed.
	//
	// Examples of Instructions that are not Values:
	//       "return x"  (Return)
	//       "*y = x"    (Store)
	//
	// (The separation Value.Name() from Value.String() is useful
	// for some analyses which distinguish the operation from the
	// value it defines, e.g., 'y = local int' is both an allocation
	// of memory 'local int' and a definition of a pointer y.)
	String() string

	// Parent returns the function to which this instruction
	// belongs.
	Parent() *Function

	// Block returns the basic block to which this instruction
	// belongs.
	Block() *BasicBlock

	// setBlock sets the basic block to which this instruction belongs.
	setBlock(*BasicBlock)

	// Operands returns the operands of this instruction: the
	// set of Values it references.
	//
	// Specifically, it appends their addresses to rands, a
	// user-provided slice, and returns the resulting slice,
	// permitting avoidance of memory allocation.
	//
	// The operands are appended in undefined order, but the order
	// is consistent for a given Instruction; the addresses are
	// always non-nil but may point to a nil Value.  Clients may
	// store through the pointers, e.g. to effect a value
	// renaming.
	//
	// Value.Referrers is a subset of the inverse of this
	// relation.  (Referrers are not tracked for all types of
	// Values.)
	Operands(rands []*Value) []*Value

	// Pos returns the location of the AST token most closely
	// associated with the operation that gave rise to this
	// instruction, or token.NoPos if it was not explicit in the
	// source.
	//
	// For each ast.Node type, a particular token is designated as
	// the closest location for the expression, e.g. the Go token
	// for an *ast.GoStmt.  This permits a compact but approximate
	// mapping from Instructions to source positions for use in
	// diagnostic messages, for example.
	//
	// (Do not use this position to determine which Instruction
	// corresponds to an ast.Expr; see the notes for Value.Pos.
	// This position may be used to determine which non-Value
	// Instruction corresponds to some ast.Stmts, but not all: If
	// and Jump instructions have no Pos(), for example.)
	Pos() token.Pos
}

// A Node is a node in the SSA value graph.  Every concrete type that
// implements Node is also either a Value, an Instruction, or both.
//
// Node contains the methods common to Value and Instruction, plus the
// Operands and Referrers methods generalized to return nil for
// non-Instructions and non-Values, respectively.
//
// Node is provided to simplify SSA graph algorithms.  Clients should
// use the more specific and informative Value or Instruction
// interfaces where appropriate.
//
type Node interface {
	// Common methods:
	String() string
	Pos() token.Pos
	Parent() *Function

	// Partial methods:
	Operands(rands []*Value) []*Value // nil for non-Instructions
	Referrers() *[]Instruction        // nil for non-Values
}

// Function represents the parameters, results, and code of a function
// or method.
//
// If Blocks is nil, this indicates an external function for which no
// Go source code is available.  In this case, FreeVars and Locals
// are nil too.  Clients performing whole-program analysis must
// handle external functions specially.
//
// Blocks contains the function's control-flow graph (CFG).
// Blocks[0] is the function entry point; block order is not otherwise
// semantically significant, though it may affect the readability of
// the disassembly.
// To iterate over the blocks in dominance order, use DomPreorder().
//
// Recover is an optional second entry point to which control resumes
// after a recovered panic.  The Recover block may contain only a return
// statement, preceded by a load of the function's named return
// parameters, if any.
//
// A nested function (Parent()!=nil) that refers to one or more
// lexically enclosing local variables ("free variables") has FreeVars.
// Such functions cannot be called directly but require a
// value created by MakeClosure which, via its Bindings, supplies
// values for these parameters.
//
// If the function is a method (Signature.Recv() != nil) then the first
// element of Params is the receiver parameter.
//
// A Go package may declare many functions called "init".
// For each one, Object().Name() returns "init" but Name() returns
// "init#1", etc, in declaration order.
//
// Pos() returns the declaring ast.FuncLit.Type.Func or the position
// of the ast.FuncDecl.Name, if the function was explicit in the
// source.  Synthetic wrappers, for which Synthetic != "", may share
// the same position as the function they wrap.
// Syntax.Pos() always returns the position of the declaring "func" token.
//
// Type() returns the function's Signature.
//
type Function struct {
	name      string
	object    types.Object     // a declared *types.Func or one of its wrappers
	method    *types.Selection // info about provenance of synthetic methods
	Signature *types.Signature
	pos       token.Pos

	Synthetic string        // provenance of synthetic function; "" for true source functions
	syntax    ast.Node      // *ast.Func{Decl,Lit}; replaced with simple ast.Node after build, unless debug mode
	parent    *Function     // enclosing function if anon; nil if global
	Pkg       *Package      // enclosing package; nil for shared funcs (wrappers and error.Error)
	Prog      *Program      // enclosing program
	Params    []*Parameter  // function parameters; for methods, includes receiver
	FreeVars  []*FreeVar    // free variables whose values must be supplied by closure
	Locals    []*Alloc      // local variables of this function
	Blocks    []*BasicBlock // basic blocks of the function; nil => external
	Recover   *BasicBlock   // optional; control transfers here after recovered panic
	AnonFuncs []*Function   // anonymous functions directly beneath this one
	referrers []Instruction // referring instructions (iff Parent() != nil)

	// The following fields are set transiently during building,
	// then cleared.
	currentBlock *BasicBlock             // where to emit code
	objects      map[types.Object]Value  // addresses of local variables
	namedResults []*Alloc                // tuple of named results
	targets      *targets                // linked stack of branch targets
	lblocks      map[*ast.Object]*lblock // labelled blocks
}

// BasicBlock represents an SSA basic block.
//
// The final element of Instrs is always an explicit transfer of
// control (If, Jump, Return, or Panic).
//
// A block may contain no Instructions only if it is unreachable,
// i.e., Preds is nil.  Empty blocks are typically pruned.
//
// BasicBlocks and their Preds/Succs relation form a (possibly cyclic)
// graph independent of the SSA Value graph: the control-flow graph or
// CFG.  It is illegal for multiple edges to exist between the same
// pair of blocks.
//
// Each BasicBlock is also a node in the dominator tree of the CFG.
// The tree may be navigated using Idom()/Dominees() and queried using
// Dominates().
//
// The order of Preds and Succs is significant (to Phi and If
// instructions, respectively).
//
type BasicBlock struct {
	Index        int            // index of this block within Parent().Blocks
	Comment      string         // optional label; no semantic significance
	parent       *Function      // parent function
	Instrs       []Instruction  // instructions in order
	Preds, Succs []*BasicBlock  // predecessors and successors
	succs2       [2]*BasicBlock // initial space for Succs
	dom          domInfo        // dominator tree info
	gaps         int            // number of nil Instrs (transient)
	rundefers    int            // number of rundefers (transient)
}

// Pure values ----------------------------------------

// A FreeVar represents a free variable of the function to which it
// belongs.
//
// FreeVars are used to implement anonymous functions, whose free
// variables are lexically captured in a closure formed by
// MakeClosure.  The value of such a free var is an Alloc or another
// FreeVar and is considered a potentially escaping heap address, with
// pointer type.
//
// FreeVars are also used to implement bound method closures.  Such a
// free var represents the receiver value and may be of any type that
// has concrete methods.
//
// Pos() returns the position of the value that was captured, which
// belongs to an enclosing function.
//
type FreeVar struct {
	name      string
	typ       types.Type
	pos       token.Pos
	parent    *Function
	referrers []Instruction

	// Transiently needed during building.
	outer Value // the Value captured from the enclosing context.
}

// A Parameter represents an input parameter of a function.
//
type Parameter struct {
	name      string
	object    types.Object // a *types.Var; nil for non-source locals
	typ       types.Type
	pos       token.Pos
	parent    *Function
	referrers []Instruction
}

// A Const represents the value of a constant expression.
//
// The underlying type of a constant may be any boolean, numeric, or
// string type.  In addition, a Const may represent the nil value of
// any reference type---interface, map, channel, pointer, slice, or
// function---but not "untyped nil".
//
// All source-level constant expressions are represented by a Const
// of the same type and value.
//
// Value holds the exact value of the constant, independent of its
// Type(), using the same representation as package go/exact uses for
// constants, or nil for a typed nil value.
//
// Pos() returns token.NoPos.
//
// Example printed form:
// 	42:int
//	"hello":untyped string
//	3+4i:MyComplex
//
type Const struct {
	typ   types.Type
	Value exact.Value
}

// A Global is a named Value holding the address of a package-level
// variable.
//
// Pos() returns the position of the ast.ValueSpec.Names[*]
// identifier.
//
type Global struct {
	name   string
	object types.Object // a *types.Var; may be nil for synthetics e.g. init$guard
	typ    types.Type
	pos    token.Pos

	Pkg *Package
}

// A Builtin represents a specific use of a built-in function, e.g. len.
//
// Builtins are immutable values.  Builtins do not have addresses.
// Builtins can only appear in CallCommon.Func.
//
// Name() indicates the function: one of the built-in functions from the
// Go spec (excluding "make" and "new") or one of these ssa-defined
// intrinsics:
//
//   // wrapnilchk returns ptr if non-nil, panics otherwise.
//   // (For use in indirection wrappers.)
//   func ssa:wrapnilchk(ptr *T, recvType, methodName string) *T
//
// Object() returns a *types.Builtin for built-ins defined by the spec,
// nil for others.
//
// Type() returns a *types.Signature representing the effective
// signature of the built-in for this call.
//
type Builtin struct {
	name string
	sig  *types.Signature
}

// Value-defining instructions  ----------------------------------------

// The Alloc instruction reserves space for a variable of the given type,
// zero-initializes it, and yields its address.
//
// Alloc values are always addresses, and have pointer types, so the
// type of the allocated variable is actually
// Type().Underlying().(*types.Pointer).Elem().
//
// If Heap is false, Alloc allocates space in the function's
// activation record (frame); we refer to an Alloc(Heap=false) as a
// "local" alloc.  Each local Alloc returns the same address each time
// it is executed within the same activation; the space is
// re-initialized to zero.
//
// If Heap is true, Alloc allocates space in the heap; we
// refer to an Alloc(Heap=true) as a "new" alloc.  Each new Alloc
// returns a different address each time it is executed.
//
// When Alloc is applied to a channel, map or slice type, it returns
// the address of an uninitialized (nil) reference of that kind; store
// the result of MakeSlice, MakeMap or MakeChan in that location to
// instantiate these types.
//
// Pos() returns the ast.CompositeLit.Lbrace for a composite literal,
// or the ast.CallExpr.Rparen for a call to new() or for a call that
// allocates a varargs slice.
//
// Example printed form:
// 	t0 = local int
// 	t1 = new int
//
type Alloc struct {
	register
	Comment string
	Heap    bool
	index   int // dense numbering; for lifting
}

var _ Instruction = (*Sigma)(nil)
var _ Value = (*Sigma)(nil)

type Sigma struct {
	register
	X      Value
	Branch bool
}

func (p *Sigma) Value() Value {
	v := p.X
	for {
		sigma, ok := v.(*Sigma)
		if !ok {
			break
		}
		v = sigma
	}
	return v
}

func (p *Sigma) String() string {
	return fmt.Sprintf("σ [%s.%t]", relName(p.X, p), p.Branch)
}

// The Phi instruction represents an SSA φ-node, which combines values
// that differ across incoming control-flow edges and yields a new
// value.  Within a block, all φ-nodes must appear before all non-φ
// nodes.
//
// Pos() returns the position of the && or || for short-circuit
// control-flow joins, or that of the *Alloc for φ-nodes inserted
// during SSA renaming.
//
// Example printed form:
// 	t2 = phi [0: t0, 1: t1]
//
type Phi struct {
	register
	Comment string  // a hint as to its purpose
	Edges   []Value // Edges[i] is value for Block().Preds[i]
}

// The Call instruction represents a function or method call.
//
// The Call instruction yields the function result if there is exactly
// one.  Otherwise it returns a tuple, the components of which are
// accessed via Extract.
//
// See CallCommon for generic function call documentation.
//
// Pos() returns the ast.CallExpr.Lparen, if explicit in the source.
//
// Example printed form:
// 	t2 = println(t0, t1)
// 	t4 = t3()
// 	t7 = invoke t5.Println(...t6)
//
type Call struct {
	register
	Call CallCommon
}

// The BinOp instruction yields the result of binary operation X Op Y.
//
// Pos() returns the ast.BinaryExpr.OpPos, if explicit in the source.
//
// Example printed form:
// 	t1 = t0 + 1:int
//
type BinOp struct {
	register
	// One of:
	// ADD SUB MUL QUO REM          + - * / %
	// AND OR XOR SHL SHR AND_NOT   & | ^ << >> &~
	// EQL LSS GTR NEQ LEQ GEQ      == != < <= < >=
	Op   token.Token
	X, Y Value
}

// The UnOp instruction yields the result of Op X.
// ARROW is channel receive.
// MUL is pointer indirection (load).
// XOR is bitwise complement.
// SUB is negation.
// NOT is logical negation.
//
// If CommaOk and Op=ARROW, the result is a 2-tuple of the value above
// and a boolean indicating the success of the receive.  The
// components of the tuple are accessed using Extract.
//
// Pos() returns the ast.UnaryExpr.OpPos, if explicit in the source.
// For receive operations (ARROW) implicit in ranging over a channel,
// Pos() returns the ast.RangeStmt.For.
// For implicit memory loads (STAR), Pos() returns the position of the
// most closely associated source-level construct; the details are not
// specified.
//
// Example printed form:
// 	t0 = *x
// 	t2 = <-t1,ok
//
type UnOp struct {
	register
	Op      token.Token // One of: NOT SUB ARROW MUL XOR ! - <- * ^
	X       Value
	CommaOk bool
}

// The ChangeType instruction applies to X a value-preserving type
// change to Type().
//
// Type changes are permitted:
//    - between a named type and its underlying type.
//    - between two named types of the same underlying type.
//    - between (possibly named) pointers to identical base types.
//    - from a bidirectional channel to a read- or write-channel,
//      optionally adding/removing a name.
//
// This operation cannot fail dynamically.
//
// Pos() returns the ast.CallExpr.Lparen, if the instruction arose
// from an explicit conversion in the source.
//
// Example printed form:
// 	t1 = changetype *int <- IntPtr (t0)
//
type ChangeType struct {
	register
	X Value
}

// The Convert instruction yields the conversion of value X to type
// Type().  One or both of those types is basic (but possibly named).
//
// A conversion may change the value and representation of its operand.
// Conversions are permitted:
//    - between real numeric types.
//    - between complex numeric types.
//    - between string and []byte or []rune.
//    - between pointers and unsafe.Pointer.
//    - between unsafe.Pointer and uintptr.
//    - from (Unicode) integer to (UTF-8) string.
// A conversion may imply a type name change also.
//
// This operation cannot fail dynamically.
//
// Conversions of untyped string/number/bool constants to a specific
// representation are eliminated during SSA construction.
//
// Pos() returns the ast.CallExpr.Lparen, if the instruction arose
// from an explicit conversion in the source.
//
// Example printed form:
// 	t1 = convert []byte <- string (t0)
//
type Convert struct {
	register
	X Value
}

// ChangeInterface constructs a value of one interface type from a
// value of another interface type known to be assignable to it.
// This operation cannot fail.
//
// Pos() returns the ast.CallExpr.Lparen if the instruction arose from
// an explicit T(e) conversion; the ast.TypeAssertExpr.Lparen if the
// instruction arose from an explicit e.(T) operation; or token.NoPos
// otherwise.
//
// Example printed form:
// 	t1 = change interface interface{} <- I (t0)
//
type ChangeInterface struct {
	register
	X Value
}

// MakeInterface constructs an instance of an interface type from a
// value of a concrete type.
//
// Use Program.MethodSets.MethodSet(X.Type()) to find the method-set
// of X, and Program.Method(m) to find the implementation of a method.
//
// To construct the zero value of an interface type T, use:
// 	NewConst(exact.MakeNil(), T, pos)
//
// Pos() returns the ast.CallExpr.Lparen, if the instruction arose
// from an explicit conversion in the source.
//
// Example printed form:
// 	t1 = make interface{} <- int (42:int)
// 	t2 = make Stringer <- t0
//
type MakeInterface struct {
	register
	X Value
}

// The MakeClosure instruction yields a closure value whose code is
// Fn and whose free variables' values are supplied by Bindings.
//
// Type() returns a (possibly named) *types.Signature.
//
// Pos() returns the ast.FuncLit.Type.Func for a function literal
// closure or the ast.SelectorExpr.Sel for a bound method closure.
//
// Example printed form:
// 	t0 = make closure anon@1.2 [x y z]
// 	t1 = make closure bound$(main.I).add [i]
//
type MakeClosure struct {
	register
	Fn       Value   // always a *Function
	Bindings []Value // values for each free variable in Fn.FreeVars
}

// The MakeMap instruction creates a new hash-table-based map object
// and yields a value of kind map.
//
// Type() returns a (possibly named) *types.Map.
//
// Pos() returns the ast.CallExpr.Lparen, if created by make(map), or
// the ast.CompositeLit.Lbrack if created by a literal.
//
// Example printed form:
// 	t1 = make map[string]int t0
// 	t1 = make StringIntMap t0
//
type MakeMap struct {
	register
	Reserve Value // initial space reservation; nil => default
}

// The MakeChan instruction creates a new channel object and yields a
// value of kind chan.
//
// Type() returns a (possibly named) *types.Chan.
//
// Pos() returns the ast.CallExpr.Lparen for the make(chan) that
// created it.
//
// Example printed form:
// 	t0 = make chan int 0
// 	t0 = make IntChan 0
//
type MakeChan struct {
	register
	Size Value // int; size of buffer; zero => synchronous.
}

// The MakeSlice instruction yields a slice of length Len backed by a
// newly allocated array of length Cap.
//
// Both Len and Cap must be non-nil Values of integer type.
//
// (Alloc(types.Array) followed by Slice will not suffice because
// Alloc can only create arrays of constant length.)
//
// Type() returns a (possibly named) *types.Slice.
//
// Pos() returns the ast.CallExpr.Lparen for the make([]T) that
// created it.
//
// Example printed form:
// 	t1 = make []string 1:int t0
// 	t1 = make StringSlice 1:int t0
//
type MakeSlice struct {
	register
	Len Value
	Cap Value
}

// The Slice instruction yields a slice of an existing string, slice
// or *array X between optional integer bounds Low and High.
//
// Dynamically, this instruction panics if X evaluates to a nil *array
// pointer.
//
// Type() returns string if the type of X was string, otherwise a
// *types.Slice with the same element type as X.
//
// Pos() returns the ast.SliceExpr.Lbrack if created by a x[:] slice
// operation, the ast.CompositeLit.Lbrace if created by a literal, or
// NoPos if not explicit in the source (e.g. a variadic argument slice).
//
// Example printed form:
// 	t1 = slice t0[1:]
//
type Slice struct {
	register
	X              Value // slice, string, or *array
	Low, High, Max Value // each may be nil
}

// The FieldAddr instruction yields the address of Field of *struct X.
//
// The field is identified by its index within the field list of the
// struct type of X.
//
// Dynamically, this instruction panics if X evaluates to a nil
// pointer.
//
// Type() returns a (possibly named) *types.Pointer.
//
// Pos() returns the position of the ast.SelectorExpr.Sel for the
// field, if explicit in the source.
//
// Example printed form:
// 	t1 = &t0.name [#1]
//
type FieldAddr struct {
	register
	X     Value // *struct
	Field int   // index into X.Type().Deref().(*types.Struct).Fields
}

// The Field instruction yields the Field of struct X.
//
// The field is identified by its index within the field list of the
// struct type of X; by using numeric indices we avoid ambiguity of
// package-local identifiers and permit compact representations.
//
// Pos() returns the position of the ast.SelectorExpr.Sel for the
// field, if explicit in the source.
//
// Example printed form:
// 	t1 = t0.name [#1]
//
type Field struct {
	register
	X     Value // struct
	Field int   // index into X.Type().(*types.Struct).Fields
}

// The IndexAddr instruction yields the address of the element at
// index Index of collection X.  Index is an integer expression.
//
// The elements of maps and strings are not addressable; use Lookup or
// MapUpdate instead.
//
// Dynamically, this instruction panics if X evaluates to a nil *array
// pointer.
//
// Type() returns a (possibly named) *types.Pointer.
//
// Pos() returns the ast.IndexExpr.Lbrack for the index operation, if
// explicit in the source.
//
// Example printed form:
// 	t2 = &t0[t1]
//
type IndexAddr struct {
	register
	X     Value // slice or *array,
	Index Value // numeric index
}

// The Index instruction yields element Index of array X.
//
// Pos() returns the ast.IndexExpr.Lbrack for the index operation, if
// explicit in the source.
//
// Example printed form:
// 	t2 = t0[t1]
//
type Index struct {
	register
	X     Value // array
	Index Value // integer index
}

// The Lookup instruction yields element Index of collection X, a map
// or string.  Index is an integer expression if X is a string or the
// appropriate key type if X is a map.
//
// If CommaOk, the result is a 2-tuple of the value above and a
// boolean indicating the result of a map membership test for the key.
// The components of the tuple are accessed using Extract.
//
// Pos() returns the ast.IndexExpr.Lbrack, if explicit in the source.
//
// Example printed form:
// 	t2 = t0[t1]
// 	t5 = t3[t4],ok
//
type Lookup struct {
	register
	X       Value // string or map
	Index   Value // numeric or key-typed index
	CommaOk bool  // return a value,ok pair
}

// SelectState is a helper for Select.
// It represents one goal state and its corresponding communication.
//
type SelectState struct {
	Dir       types.ChanDir // direction of case (SendOnly or RecvOnly)
	Chan      Value         // channel to use (for send or receive)
	Send      Value         // value to send (for send)
	Pos       token.Pos     // position of token.ARROW
	DebugNode ast.Node      // ast.SendStmt or ast.UnaryExpr(<-) [debug mode]
}

// The Select instruction tests whether (or blocks until) one
// of the specified sent or received states is entered.
//
// Let n be the number of States for which Dir==RECV and T_i (0<=i<n)
// be the element type of each such state's Chan.
// Select returns an n+2-tuple
//    (index int, recvOk bool, r_0 T_0, ... r_n-1 T_n-1)
// The tuple's components, described below, must be accessed via the
// Extract instruction.
//
// If Blocking, select waits until exactly one state holds, i.e. a
// channel becomes ready for the designated operation of sending or
// receiving; select chooses one among the ready states
// pseudorandomly, performs the send or receive operation, and sets
// 'index' to the index of the chosen channel.
//
// If !Blocking, select doesn't block if no states hold; instead it
// returns immediately with index equal to -1.
//
// If the chosen channel was used for a receive, the r_i component is
// set to the received value, where i is the index of that state among
// all n receive states; otherwise r_i has the zero value of type T_i.
// Note that the receive index i is not the same as the state
// index index.
//
// The second component of the triple, recvOk, is a boolean whose value
// is true iff the selected operation was a receive and the receive
// successfully yielded a value.
//
// Pos() returns the ast.SelectStmt.Select.
//
// Example printed form:
// 	t3 = select nonblocking [<-t0, t1<-t2]
// 	t4 = select blocking []
//
type Select struct {
	register
	States   []*SelectState
	Blocking bool
}

// The Range instruction yields an iterator over the domain and range
// of X, which must be a string or map.
//
// Elements are accessed via Next.
//
// Type() returns an opaque and degenerate "rangeIter" type.
//
// Pos() returns the ast.RangeStmt.For.
//
// Example printed form:
// 	t0 = range "hello":string
//
type Range struct {
	register
	X Value // string or map
}

// The Next instruction reads and advances the (map or string)
// iterator Iter and returns a 3-tuple value (ok, k, v).  If the
// iterator is not exhausted, ok is true and k and v are the next
// elements of the domain and range, respectively.  Otherwise ok i
"""




```