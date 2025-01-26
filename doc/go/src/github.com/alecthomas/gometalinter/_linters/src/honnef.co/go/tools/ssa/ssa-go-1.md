Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `ssa` package in `honnef.co/go/tools`. This package likely deals with Static Single Assignment (SSA) form for Go programs.

The request asks for:
1. **Functionality listing:** Describe what each struct and its methods do.
2. **Go feature implementation inference:** Deduce which Go language features these SSA constructs represent.
3. **Go code examples:** Illustrate the inferred Go features with example code.
4. **Input/output for code examples:** Provide hypothetical inputs and outputs for the code examples.
5. **Command-line argument handling:** Explain how command-line arguments are processed (if applicable).
6. **Common user errors:** Point out potential mistakes users might make (if any).
7. **Overall function summarization:**  Provide a concise summary of the code's purpose.

Since this is the second part of the request, I need to focus on summarizing the functionality of the structs and methods defined in this specific code block. The first part likely covered the definitions of `Value`, `Instruction`, `BasicBlock`, and other foundational elements of the SSA representation.

Let's analyze the structs and their methods:

- **`Next`:** Represents the operation of getting the next element from an iterator (likely from a `range` loop over a map or string).
- **`TypeAssert`:**  Corresponds to type assertions in Go (`x.(T)`).
- **`Extract`:** Used to extract individual values from a tuple (multiple return values).
- **Instructions executed for effect (no return value):**
    - **`Jump`:** Unconditional control flow transfer.
    - **`If`:** Conditional control flow transfer.
    - **`Return`:** Returning from a function.
    - **`RunDefers`:** Executing deferred function calls.
    - **`Panic`:** Initiating a panic.
    - **`Go`:** Starting a new goroutine.
    - **`Defer`:** Scheduling a function call to be executed later.
    - **`Send`:** Sending a value on a channel.
    - **`Store`:** Assigning a value to a memory location.
    - **`BlankStore`:** Assignment to the blank identifier (`_`).
    - **`MapUpdate`:** Updating a value in a map.
    - **`DebugRef`:**  Debugging information linking SSA values to source code expressions.
- **Mix-ins and Helpers:**
    - **`register`:** Base struct for SSA values that are also instructions (virtual registers).
    - **`anInstruction`:** Base struct for all instructions, managing the associated basic block.
    - **`CallCommon`:** Holds common information for function calls (`Go`, `Defer`, `Call`).
- **Interfaces:**
    - **`CallInstruction`:** Interface for instructions that represent function calls.
- **Methods on non-instruction types:** Provide access to type information, names, and relationships within the SSA representation.

The primary function of this code snippet is to define the **instruction set** of the SSA representation. Each struct represents a specific operation that can occur in a Go program, translated into the SSA form. The mix-ins and helpers provide common functionality and structure to these instructions.
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/ssa.go的go语言实现的一部分，主要定义了SSA（Static Single Assignment）形式的各种指令 (Instruction) 和相关的辅助结构。

**归纳一下它的功能:**

这部分代码主要定义了 SSA 中用于表示程序行为的各种指令。这些指令可以分为以下几类：

1. **值指令 (Value Instructions):** 这些指令会产生一个值，并将其存储在一个虚拟寄存器中。包括：
    *   **`Next`:** 用于从迭代器中获取下一个键值对。
    *   **`TypeAssert`:** 用于类型断言。
    *   **`Extract`:** 用于提取元组中的某个元素。

2. **效果指令 (Effect Instructions):** 这些指令主要用于控制程序的执行流程或产生副作用，但不产生需要存储的值。包括：
    *   **`Jump`:** 无条件跳转。
    *   **`If`:** 条件跳转。
    *   **`Return`:** 从函数返回。
    *   **`RunDefers`:** 执行所有延迟调用的函数。
    *   **`Panic`:** 触发 panic。
    *   **`Go`:** 启动一个新的 goroutine。
    *   **`Defer`:** 延迟函数调用。
    *   **`Send`:** 向 channel 发送数据。
    *   **`Store`:** 将值存储到内存地址。
    *   **`BlankStore`:**  对空标识符的赋值操作（实际上不执行任何操作）。
    *   **`MapUpdate`:** 更新 map 中的键值对。
    *   **`DebugRef`:**  用于调试，将源代码表达式与 SSA 值关联起来。

3. **辅助结构和 Mix-ins:**
    *   **`register`:**  作为所有值指令的基类，代表一个虚拟寄存器。
    *   **`anInstruction`:** 作为所有指令的基类，包含指令所属的 `BasicBlock` 信息。
    *   **`CallCommon`:**  用于存储函数调用（`Call`、`Go`、`Defer`）的通用信息。

4. **接口:**
    *   **`CallInstruction`:**  定义了 `Go`, `Defer`, `Call` 指令的通用接口。

总而言之，这部分代码定义了 SSA 中表示程序控制流和数据操作的核心构建块。这些指令构成了程序在 SSA 形式下的中间表示，方便进行各种静态分析和优化。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/ssa.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
s
// false and k and v are undefined.
//
// Components of the tuple are accessed using Extract.
//
// The IsString field distinguishes iterators over strings from those
// over maps, as the Type() alone is insufficient: consider
// map[int]rune.
//
// Type() returns a *types.Tuple for the triple (ok, k, v).
// The types of k and/or v may be types.Invalid.
//
// Example printed form:
// 	t1 = next t0
//
type Next struct {
	register
	Iter     Value
	IsString bool // true => string iterator; false => map iterator.
}

// The TypeAssert instruction tests whether interface value X has type
// AssertedType.
//
// If !CommaOk, on success it returns v, the result of the conversion
// (defined below); on failure it panics.
//
// If CommaOk: on success it returns a pair (v, true) where v is the
// result of the conversion; on failure it returns (z, false) where z
// is AssertedType's zero value.  The components of the pair must be
// accessed using the Extract instruction.
//
// If AssertedType is a concrete type, TypeAssert checks whether the
// dynamic type in interface X is equal to it, and if so, the result
// of the conversion is a copy of the value in the interface.
//
// If AssertedType is an interface, TypeAssert checks whether the
// dynamic type of the interface is assignable to it, and if so, the
// result of the conversion is a copy of the interface value X.
// If AssertedType is a superinterface of X.Type(), the operation will
// fail iff the operand is nil.  (Contrast with ChangeInterface, which
// performs no nil-check.)
//
// Type() reflects the actual type of the result, possibly a
// 2-types.Tuple; AssertedType is the asserted type.
//
// Pos() returns the ast.CallExpr.Lparen if the instruction arose from
// an explicit T(e) conversion; the ast.TypeAssertExpr.Lparen if the
// instruction arose from an explicit e.(T) operation; or the
// ast.CaseClause.Case if the instruction arose from a case of a
// type-switch statement.
//
// Example printed form:
// 	t1 = typeassert t0.(int)
// 	t3 = typeassert,ok t2.(T)
//
type TypeAssert struct {
	register
	X            Value
	AssertedType types.Type
	CommaOk      bool
}

// The Extract instruction yields component Index of Tuple.
//
// This is used to access the results of instructions with multiple
// return values, such as Call, TypeAssert, Next, UnOp(ARROW) and
// IndexExpr(Map).
//
// Example printed form:
// 	t1 = extract t0 #1
//
type Extract struct {
	register
	Tuple Value
	Index int
}

// Instructions executed for effect.  They do not yield a value. --------------------

// The Jump instruction transfers control to the sole successor of its
// owning block.
//
// A Jump must be the last instruction of its containing BasicBlock.
//
// Pos() returns NoPos.
//
// Example printed form:
// 	jump done
//
type Jump struct {
	anInstruction
}

// The If instruction transfers control to one of the two successors
// of its owning block, depending on the boolean Cond: the first if
// true, the second if false.
//
// An If instruction must be the last instruction of its containing
// BasicBlock.
//
// Pos() returns NoPos.
//
// Example printed form:
// 	if t0 goto done else body
//
type If struct {
	anInstruction
	Cond Value
}

// The Return instruction returns values and control back to the calling
// function.
//
// len(Results) is always equal to the number of results in the
// function's signature.
//
// If len(Results) > 1, Return returns a tuple value with the specified
// components which the caller must access using Extract instructions.
//
// There is no instruction to return a ready-made tuple like those
// returned by a "value,ok"-mode TypeAssert, Lookup or UnOp(ARROW) or
// a tail-call to a function with multiple result parameters.
//
// Return must be the last instruction of its containing BasicBlock.
// Such a block has no successors.
//
// Pos() returns the ast.ReturnStmt.Return, if explicit in the source.
//
// Example printed form:
// 	return
// 	return nil:I, 2:int
//
type Return struct {
	anInstruction
	Results []Value
	pos     token.Pos
}

// The RunDefers instruction pops and invokes the entire stack of
// procedure calls pushed by Defer instructions in this function.
//
// It is legal to encounter multiple 'rundefers' instructions in a
// single control-flow path through a function; this is useful in
// the combined init() function, for example.
//
// Pos() returns NoPos.
//
// Example printed form:
//	rundefers
//
type RunDefers struct {
	anInstruction
}

// The Panic instruction initiates a panic with value X.
//
// A Panic instruction must be the last instruction of its containing
// BasicBlock, which must have no successors.
//
// NB: 'go panic(x)' and 'defer panic(x)' do not use this instruction;
// they are treated as calls to a built-in function.
//
// Pos() returns the ast.CallExpr.Lparen if this panic was explicit
// in the source.
//
// Example printed form:
// 	panic t0
//
type Panic struct {
	anInstruction
	X   Value // an interface{}
	pos token.Pos
}

// The Go instruction creates a new goroutine and calls the specified
// function within it.
//
// See CallCommon for generic function call documentation.
//
// Pos() returns the ast.GoStmt.Go.
//
// Example printed form:
// 	go println(t0, t1)
// 	go t3()
// 	go invoke t5.Println(...t6)
//
type Go struct {
	anInstruction
	Call CallCommon
	pos  token.Pos
}

// The Defer instruction pushes the specified call onto a stack of
// functions to be called by a RunDefers instruction or by a panic.
//
// See CallCommon for generic function call documentation.
//
// Pos() returns the ast.DeferStmt.Defer.
//
// Example printed form:
// 	defer println(t0, t1)
// 	defer t3()
// 	defer invoke t5.Println(...t6)
//
type Defer struct {
	anInstruction
	Call CallCommon
	pos  token.Pos
}

// The Send instruction sends X on channel Chan.
//
// Pos() returns the ast.SendStmt.Arrow, if explicit in the source.
//
// Example printed form:
// 	send t0 <- t1
//
type Send struct {
	anInstruction
	Chan, X Value
	pos     token.Pos
}

// The Store instruction stores Val at address Addr.
// Stores can be of arbitrary types.
//
// Pos() returns the position of the source-level construct most closely
// associated with the memory store operation.
// Since implicit memory stores are numerous and varied and depend upon
// implementation choices, the details are not specified.
//
// Example printed form:
// 	*x = y
//
type Store struct {
	anInstruction
	Addr Value
	Val  Value
	pos  token.Pos
}

// The BlankStore instruction is emitted for assignments to the blank
// identifier.
//
// BlankStore is a pseudo-instruction: it has no dynamic effect.
//
// Pos() returns NoPos.
//
// Example printed form:
//	_ = t0
//
type BlankStore struct {
	anInstruction
	Val Value
}

// The MapUpdate instruction updates the association of Map[Key] to
// Value.
//
// Pos() returns the ast.KeyValueExpr.Colon or ast.IndexExpr.Lbrack,
// if explicit in the source.
//
// Example printed form:
//	t0[t1] = t2
//
type MapUpdate struct {
	anInstruction
	Map   Value
	Key   Value
	Value Value
	pos   token.Pos
}

// A DebugRef instruction maps a source-level expression Expr to the
// SSA value X that represents the value (!IsAddr) or address (IsAddr)
// of that expression.
//
// DebugRef is a pseudo-instruction: it has no dynamic effect.
//
// Pos() returns Expr.Pos(), the start position of the source-level
// expression.  This is not the same as the "designated" token as
// documented at Value.Pos(). e.g. CallExpr.Pos() does not return the
// position of the ("designated") Lparen token.
//
// If Expr is an *ast.Ident denoting a var or func, Object() returns
// the object; though this information can be obtained from the type
// checker, including it here greatly facilitates debugging.
// For non-Ident expressions, Object() returns nil.
//
// DebugRefs are generated only for functions built with debugging
// enabled; see Package.SetDebugMode() and the GlobalDebug builder
// mode flag.
//
// DebugRefs are not emitted for ast.Idents referring to constants or
// predeclared identifiers, since they are trivial and numerous.
// Nor are they emitted for ast.ParenExprs.
//
// (By representing these as instructions, rather than out-of-band,
// consistency is maintained during transformation passes by the
// ordinary SSA renaming machinery.)
//
// Example printed form:
//      ; *ast.CallExpr @ 102:9 is t5
//      ; var x float64 @ 109:72 is x
//      ; address of *ast.CompositeLit @ 216:10 is t0
//
type DebugRef struct {
	anInstruction
	Expr   ast.Expr     // the referring expression (never *ast.ParenExpr)
	object types.Object // the identity of the source var/func
	IsAddr bool         // Expr is addressable and X is the address it denotes
	X      Value        // the value or address of Expr
}

// Embeddable mix-ins and helpers for common parts of other structs. -----------

// register is a mix-in embedded by all SSA values that are also
// instructions, i.e. virtual registers, and provides a uniform
// implementation of most of the Value interface: Value.Name() is a
// numbered register (e.g. "t0"); the other methods are field accessors.
//
// Temporary names are automatically assigned to each register on
// completion of building a function in SSA form.
//
// Clients must not assume that the 'id' value (and the Name() derived
// from it) is unique within a function.  As always in this API,
// semantics are determined only by identity; names exist only to
// facilitate debugging.
//
type register struct {
	anInstruction
	num       int        // "name" of virtual register, e.g. "t0".  Not guaranteed unique.
	typ       types.Type // type of virtual register
	pos       token.Pos  // position of source expression, or NoPos
	referrers []Instruction
}

// anInstruction is a mix-in embedded by all Instructions.
// It provides the implementations of the Block and setBlock methods.
type anInstruction struct {
	block *BasicBlock // the basic block of this instruction
}

// CallCommon is contained by Go, Defer and Call to hold the
// common parts of a function or method call.
//
// Each CallCommon exists in one of two modes, function call and
// interface method invocation, or "call" and "invoke" for short.
//
// 1. "call" mode: when Method is nil (!IsInvoke), a CallCommon
// represents an ordinary function call of the value in Value,
// which may be a *Builtin, a *Function or any other value of kind
// 'func'.
//
// Value may be one of:
//    (a) a *Function, indicating a statically dispatched call
//        to a package-level function, an anonymous function, or
//        a method of a named type.
//    (b) a *MakeClosure, indicating an immediately applied
//        function literal with free variables.
//    (c) a *Builtin, indicating a statically dispatched call
//        to a built-in function.
//    (d) any other value, indicating a dynamically dispatched
//        function call.
// StaticCallee returns the identity of the callee in cases
// (a) and (b), nil otherwise.
//
// Args contains the arguments to the call.  If Value is a method,
// Args[0] contains the receiver parameter.
//
// Example printed form:
// 	t2 = println(t0, t1)
// 	go t3()
//	defer t5(...t6)
//
// 2. "invoke" mode: when Method is non-nil (IsInvoke), a CallCommon
// represents a dynamically dispatched call to an interface method.
// In this mode, Value is the interface value and Method is the
// interface's abstract method.  Note: an abstract method may be
// shared by multiple interfaces due to embedding; Value.Type()
// provides the specific interface used for this call.
//
// Value is implicitly supplied to the concrete method implementation
// as the receiver parameter; in other words, Args[0] holds not the
// receiver but the first true argument.
//
// Example printed form:
// 	t1 = invoke t0.String()
// 	go invoke t3.Run(t2)
// 	defer invoke t4.Handle(...t5)
//
// For all calls to variadic functions (Signature().Variadic()),
// the last element of Args is a slice.
//
type CallCommon struct {
	Value  Value       // receiver (invoke mode) or func value (call mode)
	Method *types.Func // abstract method (invoke mode)
	Args   []Value     // actual parameters (in static method call, includes receiver)
	pos    token.Pos   // position of CallExpr.Lparen, iff explicit in source
}

// IsInvoke returns true if this call has "invoke" (not "call") mode.
func (c *CallCommon) IsInvoke() bool {
	return c.Method != nil
}

func (c *CallCommon) Pos() token.Pos { return c.pos }

// Signature returns the signature of the called function.
//
// For an "invoke"-mode call, the signature of the interface method is
// returned.
//
// In either "call" or "invoke" mode, if the callee is a method, its
// receiver is represented by sig.Recv, not sig.Params().At(0).
//
func (c *CallCommon) Signature() *types.Signature {
	if c.Method != nil {
		return c.Method.Type().(*types.Signature)
	}
	return c.Value.Type().Underlying().(*types.Signature)
}

// StaticCallee returns the callee if this is a trivially static
// "call"-mode call to a function.
func (c *CallCommon) StaticCallee() *Function {
	switch fn := c.Value.(type) {
	case *Function:
		return fn
	case *MakeClosure:
		return fn.Fn.(*Function)
	}
	return nil
}

// Description returns a description of the mode of this call suitable
// for a user interface, e.g., "static method call".
func (c *CallCommon) Description() string {
	switch fn := c.Value.(type) {
	case *Builtin:
		return "built-in function call"
	case *MakeClosure:
		return "static function closure call"
	case *Function:
		if fn.Signature.Recv() != nil {
			return "static method call"
		}
		return "static function call"
	}
	if c.IsInvoke() {
		return "dynamic method call" // ("invoke" mode)
	}
	return "dynamic function call"
}

// The CallInstruction interface, implemented by *Go, *Defer and *Call,
// exposes the common parts of function-calling instructions,
// yet provides a way back to the Value defined by *Call alone.
//
type CallInstruction interface {
	Instruction
	Common() *CallCommon // returns the common parts of the call
	Value() *Call        // returns the result value of the call (*Call) or nil (*Go, *Defer)
}

func (s *Call) Common() *CallCommon  { return &s.Call }
func (s *Defer) Common() *CallCommon { return &s.Call }
func (s *Go) Common() *CallCommon    { return &s.Call }

func (s *Call) Value() *Call  { return s }
func (s *Defer) Value() *Call { return nil }
func (s *Go) Value() *Call    { return nil }

func (v *Builtin) Type() types.Type        { return v.sig }
func (v *Builtin) Name() string            { return v.name }
func (*Builtin) Referrers() *[]Instruction { return nil }
func (v *Builtin) Pos() token.Pos          { return token.NoPos }
func (v *Builtin) Object() types.Object    { return types.Universe.Lookup(v.name) }
func (v *Builtin) Parent() *Function       { return nil }

func (v *FreeVar) Type() types.Type          { return v.typ }
func (v *FreeVar) Name() string              { return v.name }
func (v *FreeVar) Referrers() *[]Instruction { return &v.referrers }
func (v *FreeVar) Pos() token.Pos            { return v.pos }
func (v *FreeVar) Parent() *Function         { return v.parent }

func (v *Global) Type() types.Type                     { return v.typ }
func (v *Global) Name() string                         { return v.name }
func (v *Global) Parent() *Function                    { return nil }
func (v *Global) Pos() token.Pos                       { return v.pos }
func (v *Global) Referrers() *[]Instruction            { return nil }
func (v *Global) Token() token.Token                   { return token.VAR }
func (v *Global) Object() types.Object                 { return v.object }
func (v *Global) String() string                       { return v.RelString(nil) }
func (v *Global) Package() *Package                    { return v.Pkg }
func (v *Global) RelString(from *types.Package) string { return relString(v, from) }

func (v *Function) Name() string         { return v.name }
func (v *Function) Type() types.Type     { return v.Signature }
func (v *Function) Pos() token.Pos       { return v.pos }
func (v *Function) Token() token.Token   { return token.FUNC }
func (v *Function) Object() types.Object { return v.object }
func (v *Function) String() string       { return v.RelString(nil) }
func (v *Function) Package() *Package    { return v.Pkg }
func (v *Function) Parent() *Function    { return v.parent }
func (v *Function) Referrers() *[]Instruction {
	if v.parent != nil {
		return &v.referrers
	}
	return nil
}

func (v *Parameter) Type() types.Type          { return v.typ }
func (v *Parameter) Name() string              { return v.name }
func (v *Parameter) Object() types.Object      { return v.object }
func (v *Parameter) Referrers() *[]Instruction { return &v.referrers }
func (v *Parameter) Pos() token.Pos            { return v.pos }
func (v *Parameter) Parent() *Function         { return v.parent }

func (v *Alloc) Type() types.Type          { return v.typ }
func (v *Alloc) Referrers() *[]Instruction { return &v.referrers }
func (v *Alloc) Pos() token.Pos            { return v.pos }

func (v *register) Type() types.Type          { return v.typ }
func (v *register) setType(typ types.Type)    { v.typ = typ }
func (v *register) Name() string              { return fmt.Sprintf("t%d", v.num) }
func (v *register) setNum(num int)            { v.num = num }
func (v *register) Referrers() *[]Instruction { return &v.referrers }
func (v *register) Pos() token.Pos            { return v.pos }
func (v *register) setPos(pos token.Pos)      { v.pos = pos }

func (v *anInstruction) Parent() *Function          { return v.block.parent }
func (v *anInstruction) Block() *BasicBlock         { return v.block }
func (v *anInstruction) setBlock(block *BasicBlock) { v.block = block }
func (v *anInstruction) Referrers() *[]Instruction  { return nil }

func (t *Type) Name() string                         { return t.object.Name() }
func (t *Type) Pos() token.Pos                       { return t.object.Pos() }
func (t *Type) Type() types.Type                     { return t.object.Type() }
func (t *Type) Token() token.Token                   { return token.TYPE }
func (t *Type) Object() types.Object                 { return t.object }
func (t *Type) String() string                       { return t.RelString(nil) }
func (t *Type) Package() *Package                    { return t.pkg }
func (t *Type) RelString(from *types.Package) string { return relString(t, from) }

func (c *NamedConst) Name() string                         { return c.object.Name() }
func (c *NamedConst) Pos() token.Pos                       { return c.object.Pos() }
func (c *NamedConst) String() string                       { return c.RelString(nil) }
func (c *NamedConst) Type() types.Type                     { return c.object.Type() }
func (c *NamedConst) Token() token.Token                   { return token.CONST }
func (c *NamedConst) Object() types.Object                 { return c.object }
func (c *NamedConst) Package() *Package                    { return c.pkg }
func (c *NamedConst) RelString(from *types.Package) string { return relString(c, from) }

// Func returns the package-level function of the specified name,
// or nil if not found.
//
func (p *Package) Func(name string) (f *Function) {
	f, _ = p.Members[name].(*Function)
	return
}

// Var returns the package-level variable of the specified name,
// or nil if not found.
//
func (p *Package) Var(name string) (g *Global) {
	g, _ = p.Members[name].(*Global)
	return
}

// Const returns the package-level constant of the specified name,
// or nil if not found.
//
func (p *Package) Const(name string) (c *NamedConst) {
	c, _ = p.Members[name].(*NamedConst)
	return
}

// Type returns the package-level type of the specified name,
// or nil if not found.
//
func (p *Package) Type(name string) (t *Type) {
	t, _ = p.Members[name].(*Type)
	return
}

func (v *Call) Pos() token.Pos       { return v.Call.pos }
func (s *Defer) Pos() token.Pos      { return s.pos }
func (s *Go) Pos() token.Pos         { return s.pos }
func (s *MapUpdate) Pos() token.Pos  { return s.pos }
func (s *Panic) Pos() token.Pos      { return s.pos }
func (s *Return) Pos() token.Pos     { return s.pos }
func (s *Send) Pos() token.Pos       { return s.pos }
func (s *Store) Pos() token.Pos      { return s.pos }
func (s *BlankStore) Pos() token.Pos { return token.NoPos }
func (s *If) Pos() token.Pos         { return token.NoPos }
func (s *Jump) Pos() token.Pos       { return token.NoPos }
func (s *RunDefers) Pos() token.Pos  { return token.NoPos }
func (s *DebugRef) Pos() token.Pos   { return s.Expr.Pos() }

// Operands.

func (v *Alloc) Operands(rands []*Value) []*Value {
	return rands
}

func (v *BinOp) Operands(rands []*Value) []*Value {
	return append(rands, &v.X, &v.Y)
}

func (c *CallCommon) Operands(rands []*Value) []*Value {
	rands = append(rands, &c.Value)
	for i := range c.Args {
		rands = append(rands, &c.Args[i])
	}
	return rands
}

func (s *Go) Operands(rands []*Value) []*Value {
	return s.Call.Operands(rands)
}

func (s *Call) Operands(rands []*Value) []*Value {
	return s.Call.Operands(rands)
}

func (s *Defer) Operands(rands []*Value) []*Value {
	return s.Call.Operands(rands)
}

func (v *ChangeInterface) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (v *ChangeType) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (v *Convert) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (s *DebugRef) Operands(rands []*Value) []*Value {
	return append(rands, &s.X)
}

func (v *Extract) Operands(rands []*Value) []*Value {
	return append(rands, &v.Tuple)
}

func (v *Field) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (v *FieldAddr) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (s *If) Operands(rands []*Value) []*Value {
	return append(rands, &s.Cond)
}

func (v *Index) Operands(rands []*Value) []*Value {
	return append(rands, &v.X, &v.Index)
}

func (v *IndexAddr) Operands(rands []*Value) []*Value {
	return append(rands, &v.X, &v.Index)
}

func (*Jump) Operands(rands []*Value) []*Value {
	return rands
}

func (v *Lookup) Operands(rands []*Value) []*Value {
	return append(rands, &v.X, &v.Index)
}

func (v *MakeChan) Operands(rands []*Value) []*Value {
	return append(rands, &v.Size)
}

func (v *MakeClosure) Operands(rands []*Value) []*Value {
	rands = append(rands, &v.Fn)
	for i := range v.Bindings {
		rands = append(rands, &v.Bindings[i])
	}
	return rands
}

func (v *MakeInterface) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (v *MakeMap) Operands(rands []*Value) []*Value {
	return append(rands, &v.Reserve)
}

func (v *MakeSlice) Operands(rands []*Value) []*Value {
	return append(rands, &v.Len, &v.Cap)
}

func (v *MapUpdate) Operands(rands []*Value) []*Value {
	return append(rands, &v.Map, &v.Key, &v.Value)
}

func (v *Next) Operands(rands []*Value) []*Value {
	return append(rands, &v.Iter)
}

func (s *Panic) Operands(rands []*Value) []*Value {
	return append(rands, &s.X)
}

func (v *Sigma) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (v *Phi) Operands(rands []*Value) []*Value {
	for i := range v.Edges {
		rands = append(rands, &v.Edges[i])
	}
	return rands
}

func (v *Range) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (s *Return) Operands(rands []*Value) []*Value {
	for i := range s.Results {
		rands = append(rands, &s.Results[i])
	}
	return rands
}

func (*RunDefers) Operands(rands []*Value) []*Value {
	return rands
}

func (v *Select) Operands(rands []*Value) []*Value {
	for i := range v.States {
		rands = append(rands, &v.States[i].Chan, &v.States[i].Send)
	}
	return rands
}

func (s *Send) Operands(rands []*Value) []*Value {
	return append(rands, &s.Chan, &s.X)
}

func (v *Slice) Operands(rands []*Value) []*Value {
	return append(rands, &v.X, &v.Low, &v.High, &v.Max)
}

func (s *Store) Operands(rands []*Value) []*Value {
	return append(rands, &s.Addr, &s.Val)
}

func (s *BlankStore) Operands(rands []*Value) []*Value {
	return append(rands, &s.Val)
}

func (v *TypeAssert) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

func (v *UnOp) Operands(rands []*Value) []*Value {
	return append(rands, &v.X)
}

// Non-Instruction Values:
func (v *Builtin) Operands(rands []*Value) []*Value   { return rands }
func (v *FreeVar) Operands(rands []*Value) []*Value   { return rands }
func (v *Const) Operands(rands []*Value) []*Value     { return rands }
func (v *Function) Operands(rands []*Value) []*Value  { return rands }
func (v *Global) Operands(rands []*Value) []*Value    { return rands }
func (v *Parameter) Operands(rands []*Value) []*Value { return rands }

"""




```