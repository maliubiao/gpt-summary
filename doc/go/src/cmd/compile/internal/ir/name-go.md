Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Type:** The first thing that jumps out is the `Name` struct. This is clearly a central data structure in this file. The comments also confirm this, stating "Name holds Node fields used only by named nodes". This immediately tells us the file is about how the compiler represents named entities.

2. **Examine the `Name` Struct Fields:**  Go through each field of the `Name` struct. For each field:
    * **Understand its type:**  Knowing the type (e.g., `Op`, `Class`, `*types.Sym`, `*Func`, `constant.Value`, `Node`) gives a strong hint about its purpose.
    * **Read the comment:**  The comments are crucial. They often directly explain the field's role. For example, the comment for `Defn` is very descriptive.
    * **Consider its name:**  The field name itself often provides clues (e.g., `BuiltinOp`, `Offset_`, `Heapaddr`).
    * **Look for related methods:**  Are there methods that get or set this field?  This confirms its usage.

3. **Identify Key Concepts and Relationships:**  As you examine the fields, start noticing relationships and key concepts:
    * **Symbols (`*types.Sym`):**  Appear in both `Ident` and `Name`. This suggests a fundamental link between identifiers and their underlying symbol information.
    * **Types (`*types.Type`):**  Methods like `NewNameAt` show the association of types with names.
    * **Operations (`Op`):**  The `BuiltinOp` field and the various `New...` functions (like `NewBuiltin`, `NewLocal`, `NewConstAt`) point to different kinds of named entities.
    * **Scope/Context (`*Func`, `Curfn`, `Outer`):**  These fields are clearly related to function scope and closures.
    * **Memory Management/Escape Analysis (`Opt`, `Heapaddr`):** These hint at the compiler's work in managing memory.
    * **Flags (`flags`):** The `bitset16` field and associated methods (`Readonly`, `SetUsed`, etc.) indicate boolean properties of the named entity.

4. **Analyze the Functions:** Now look at the functions defined in the file:
    * **Constructors (`NewIdent`, `NewNameAt`, `NewBuiltin`, `NewLocal`, `NewDeclNameAt`, `NewConstAt`, `NewClosureVar`, `NewHiddenParam`):**  These functions create instances of `Ident` and `Name`. Pay attention to the parameters they take, as this indicates the information needed to create these objects. The `Op` parameter in many `New...` functions is particularly important.
    * **Getters and Setters:** Methods like `Sym()`, `SetSym()`, `FrameOffset()`, `SetVal()`, `Pragma()`, `SetAlias()`, etc., provide access and modification to the `Name` struct's fields.
    * **Behavioral Methods:** Functions like `Canonical()`, `OnStack()`, `MarkReadonly()`, `Uses()`, `DeclaredBy()` reveal the intended usage and properties of `Name` objects.

5. **Infer Functionality and Go Feature:** Based on the identified concepts and relationships, start to infer the overall functionality. The strong presence of `Name`, the association with symbols and types, and the various constructors for different kinds of names strongly suggest this code is responsible for representing named entities (variables, constants, functions, types) within the Go compiler's internal representation (IR). The closure-related fields directly point to the implementation of closures.

6. **Construct Examples:**  Now, try to create Go code examples that would lead to the creation and manipulation of these `Ident` and `Name` objects. Think about:
    * **Variable declarations:** This should involve `NewLocal` or `NewNameAt` with `ONAME`.
    * **Constants:** This should involve `NewConstAt` with `OLITERAL`.
    * **Function declarations:**  The `Func` field within `Name` hints at this.
    * **Closures:**  The `NewClosureVar` function makes this a clear target.
    * **Built-in functions:** `NewBuiltin` is the obvious function to use.
    * **Type declarations:** `NewNameAt` with `OTYPE` is the likely candidate.

7. **Consider Edge Cases and Potential Errors:** Think about what could go wrong or be confusing when using this code:
    * **Incorrect `Op` values:** Passing the wrong `Op` to constructors could lead to errors.
    * **Not setting `Curfn`:**  The comments mention the caller's responsibility.
    * **Misunderstanding closure variable access:** The distinction between the original variable and the closure variable could be a source of confusion.
    * **Forcing methods on incorrect node types:** The panics in some methods (like `SetVal` on non-`OLITERAL`) highlight potential errors.

8. **Command-Line Arguments (If Applicable):**  In this specific snippet, there's no direct handling of command-line arguments. However, remember that this code is *part* of the `cmd/compile` package. The compiler as a whole *does* take command-line arguments. So, the connection is that this code helps *implement* the compilation process initiated by command-line arguments.

9. **Refine and Organize:** Finally, organize your findings into a clear and structured answer, like the example provided earlier. Use headings, bullet points, and code examples to make the information easy to understand. Ensure you address all parts of the prompt.

This iterative process of examining the code, understanding its components, inferring its purpose, creating examples, and considering potential issues leads to a comprehensive understanding of the code's functionality.
这段代码是 Go 编译器 `cmd/compile/internal/ir` 包中 `name.go` 文件的一部分。它定义了 Go 语言中**标识符 (Identifier)** 和 **命名实体 (Named Entity)** 的内部表示结构体和相关操作。

**功能概览:**

1. **`Ident` 结构体:** 代表一个标识符，可能带有包限定符。它主要用于语法解析阶段，表示源代码中的名字。

2. **`Name` 结构体:** 代表一个被命名的实体，例如变量、常量、类型、函数等。它是编译器进行类型检查、SSA 生成等后续编译阶段的核心数据结构。

3. **创建 `Ident` 和 `Name` 实例的工厂函数:**  提供了 `NewIdent` 和一系列 `New...At` 函数（例如 `NewNameAt`, `NewBuiltin`, `NewLocal`, `NewConstAt`, `NewClosureVar`, `NewHiddenParam`）用于创建不同类型的标识符和命名实体。这些函数在编译器的不同阶段被调用。

4. **访问和修改 `Ident` 和 `Name` 结构体字段的方法:**  提供了诸如 `Sym()`, `SetSym()`, `FrameOffset()`, `SetVal()`, `Pragma()`, `SetAlias()` 等方法，用于访问和修改标识符和命名实体的属性。

5. **命名实体的分类 (Class):** 使用 `Class` 枚举类型来区分命名实体的存储类别 (例如 `PEXTERN` 表示全局变量, `PAUTO` 表示局部变量, `PPARAM` 表示函数参数等)。

6. **命名实体的属性标记 (Flags):** 使用 `bitset16` 来存储命名实体的各种布尔属性，例如是否只读 (`nameReadonly`)，是否需要零初始化 (`nameNeedzero`)，是否是闭包变量 (`nameIsClosureVar`) 等。

7. **闭包变量的支持:** 提供了 `NewClosureVar` 和 `NewHiddenParam` 函数来支持闭包的实现。`Outer` 字段用于指向外层函数的闭包变量。

8. **常量值的存储:** `val` 字段用于存储常量的值。

9. **与符号表 (`types.Sym`) 的关联:** `sym` 字段存储了与该标识符或命名实体关联的符号表条目。符号表存储了关于程序中所有标识符的元信息，如类型、作用域等。

**它是什么 Go 语言功能的实现 (推断):**

基于代码结构和命名，可以推断出 `name.go` 文件是 Go 编译器中**标识符和命名实体表示**的核心组成部分。 它直接参与了以下 Go 语言功能的实现：

* **变量声明和使用:** `Name` 结构体用于表示声明的变量，`NewLocal` 用于创建局部变量，`Uses` 函数用于检查表达式是否使用了某个变量。
* **常量声明和使用:** `Name` 结构体用于表示常量，`NewConstAt` 用于创建常量。
* **函数声明和调用:** `Name` 结构体可以表示函数名，`Func` 字段指向对应的 `Func` 节点。
* **类型声明和使用:** `Name` 结构体用于表示类型名，`NewNameAt` 可以创建 `OTYPE` 类型的 `Name` 节点，`Alias` 和 `SetAlias` 用于处理类型别名。
* **闭包:** `NewClosureVar` 和 `NewHiddenParam` 以及 `Outer` 字段是实现闭包的关键。
* **内置函数:** `NewBuiltin` 用于表示内置函数。
* **方法:** 虽然代码中没有直接提及方法调用的实现细节，但 `Func` 字段的注释 `// TODO(austin): nil for I.M` 暗示了方法也与 `Func` 节点关联。
* **类型参数 (泛型):** `PTYPEPARAM` 常量表明它也参与了泛型的实现。

**Go 代码示例:**

以下示例展示了 `name.go` 中可能被使用的一些场景：

```go
package main

func main() {
	x := 10 // 变量声明
	println(x)

	const pi = 3.14 // 常量声明
	println(pi)

	func localFunc() { // 局部函数
		println("inside localFunc")
	}
	localFunc()

	type MyInt int // 类型声明

	add := func(a, b int) int { // 闭包
		return a + b
	}
	println(add(1, 2))
}
```

**代码推理 (假设的输入与输出):**

假设编译器正在处理以下代码片段：

```go
func foo(a int) int {
	b := a * 2
	return b
}
```

在处理这个函数时，`name.go` 中的相关函数会被调用，可能会创建以下 `Name` 节点：

* **输入:**  符号表中的 `foo`, `a`, `b` 的 `*types.Sym`，以及它们对应的类型信息。
* **输出:**
    * 对于 `foo`: 一个 `Name` 节点，`Op` 为 `ONAME` (或者与函数相关的其他 Op)，`Class` 为 `PFUNC`，`Func` 指向表示 `foo` 函数体的 `Func` 节点。
    * 对于参数 `a`: 一个 `Name` 节点，`Op` 为 `ONAME`，`Class` 为 `PPARAM`。
    * 对于局部变量 `b`: 一个 `Name` 节点，`Op` 为 `ONAME`，`Class` 为 `PAUTO`。
    * 每个 `Name` 节点的 `sym` 字段会指向对应的符号表条目。
    * `b` 的 `Defn` 字段可能会指向赋值语句 `b := a * 2` 对应的节点。
    * `a` 和 `b` 的 `Curfn` 字段会指向表示 `foo` 函数的 `Func` 节点。

**命令行参数的具体处理:**

`name.go` 文件本身不直接处理命令行参数。命令行参数的处理主要发生在 `cmd/compile/internal/gc` 包 (或者更上层的 `cmd/compile`) 中。  当编译器接收到命令行参数（例如要编译的源文件），它会解析这些参数，然后调用词法分析器、语法分析器等组件来处理源代码。 在语法分析阶段，会创建 `Ident` 节点，然后在类型检查阶段，会将 `Ident` 节点转换为 `Name` 节点，并填充相应的属性。

**使用者易犯错的点:**

由于 `name.go` 是 Go 编译器的内部实现，一般的 Go 开发者不会直接使用或操作这些结构体。 然而，对于编译器开发者来说，理解这些结构体的含义和使用方式至关重要。

一些潜在的易错点包括：

1. **混淆 `Ident` 和 `Name` 的用途:** `Ident` 主要用于语法解析，而 `Name` 用于后续的语义分析和代码生成。在错误的阶段使用错误的结构体可能会导致错误。

2. **不正确地设置 `Name` 节点的属性:** 例如，没有正确设置 `Class` 或 `Type`，可能导致类型检查错误或代码生成错误。

3. **在应该使用 `Canonical()` 的时候直接操作闭包变量:**  对于闭包变量，`Canonical()` 方法返回原始的 (外层) 变量 `Name` 节点。直接操作闭包变量自身的 `Name` 节点可能会导致逻辑错误。

4. **误解 `Defn` 字段的含义:** `Defn` 字段根据 `Name` 节点的不同类型有不同的含义，例如对于局部变量是初始化赋值语句，对于闭包变量是原始变量。误解其含义可能导致错误的分析。

总之，`name.go` 定义了 Go 编译器内部表示命名实体的核心数据结构和相关操作，是理解 Go 编译过程的关键组成部分。理解其功能有助于深入理解 Go 语言的实现细节。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ir/name.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
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

	"go/constant"
)

// An Ident is an identifier, possibly qualified.
type Ident struct {
	miniExpr
	sym *types.Sym
}

func NewIdent(pos src.XPos, sym *types.Sym) *Ident {
	n := new(Ident)
	n.op = ONONAME
	n.pos = pos
	n.sym = sym
	return n
}

func (n *Ident) Sym() *types.Sym { return n.sym }

// Name holds Node fields used only by named nodes (ONAME, OTYPE, some OLITERAL).
type Name struct {
	miniExpr
	BuiltinOp Op         // uint8
	Class     Class      // uint8
	pragma    PragmaFlag // int16
	flags     bitset16
	DictIndex uint16 // index of the dictionary entry describing the type of this variable declaration plus 1
	sym       *types.Sym
	Func      *Func // TODO(austin): nil for I.M
	Offset_   int64
	val       constant.Value
	Opt       interface{} // for use by escape analysis
	Embed     *[]Embed    // list of embedded files, for ONAME var

	// For a local variable (not param) or extern, the initializing assignment (OAS or OAS2).
	// For a closure var, the ONAME node of the original (outermost) captured variable.
	// For the case-local variables of a type switch, the type switch guard (OTYPESW).
	// For a range variable, the range statement (ORANGE)
	// For a recv variable in a case of a select statement, the receive assignment (OSELRECV2)
	// For the name of a function, points to corresponding Func node.
	Defn Node

	// The function, method, or closure in which local variable or param is declared.
	Curfn *Func

	Heapaddr *Name // temp holding heap address of param

	// Outer points to the immediately enclosing function's copy of this
	// closure variable. If not a closure variable, then Outer is nil.
	Outer *Name
}

func (n *Name) isExpr() {}

func (n *Name) copy() Node                                   { panic(n.no("copy")) }
func (n *Name) doChildren(do func(Node) bool) bool           { return false }
func (n *Name) doChildrenWithHidden(do func(Node) bool) bool { return false }
func (n *Name) editChildren(edit func(Node) Node)            {}
func (n *Name) editChildrenWithHidden(edit func(Node) Node)  {}

// RecordFrameOffset records the frame offset for the name.
// It is used by package types when laying out function arguments.
func (n *Name) RecordFrameOffset(offset int64) {
	n.SetFrameOffset(offset)
}

// NewNameAt returns a new ONAME Node associated with symbol s at position pos.
// The caller is responsible for setting Curfn.
func NewNameAt(pos src.XPos, sym *types.Sym, typ *types.Type) *Name {
	if sym == nil {
		base.Fatalf("NewNameAt nil")
	}
	n := newNameAt(pos, ONAME, sym)
	if typ != nil {
		n.SetType(typ)
		n.SetTypecheck(1)
	}
	return n
}

// NewBuiltin returns a new Name representing a builtin function,
// either predeclared or from package unsafe.
func NewBuiltin(sym *types.Sym, op Op) *Name {
	n := newNameAt(src.NoXPos, ONAME, sym)
	n.BuiltinOp = op
	n.SetTypecheck(1)
	sym.Def = n
	return n
}

// NewLocal returns a new function-local variable with the given name and type.
func (fn *Func) NewLocal(pos src.XPos, sym *types.Sym, typ *types.Type) *Name {
	if fn.Dcl == nil {
		base.FatalfAt(pos, "must call DeclParams on %v first", fn)
	}

	n := NewNameAt(pos, sym, typ)
	n.Class = PAUTO
	n.Curfn = fn
	fn.Dcl = append(fn.Dcl, n)
	return n
}

// NewDeclNameAt returns a new Name associated with symbol s at position pos.
// The caller is responsible for setting Curfn.
func NewDeclNameAt(pos src.XPos, op Op, sym *types.Sym) *Name {
	if sym == nil {
		base.Fatalf("NewDeclNameAt nil")
	}
	switch op {
	case ONAME, OTYPE, OLITERAL:
		// ok
	default:
		base.Fatalf("NewDeclNameAt op %v", op)
	}
	return newNameAt(pos, op, sym)
}

// NewConstAt returns a new OLITERAL Node associated with symbol s at position pos.
func NewConstAt(pos src.XPos, sym *types.Sym, typ *types.Type, val constant.Value) *Name {
	if sym == nil {
		base.Fatalf("NewConstAt nil")
	}
	n := newNameAt(pos, OLITERAL, sym)
	n.SetType(typ)
	n.SetTypecheck(1)
	n.SetVal(val)
	return n
}

// newNameAt is like NewNameAt but allows sym == nil.
func newNameAt(pos src.XPos, op Op, sym *types.Sym) *Name {
	n := new(Name)
	n.op = op
	n.pos = pos
	n.sym = sym
	return n
}

func (n *Name) Name() *Name            { return n }
func (n *Name) Sym() *types.Sym        { return n.sym }
func (n *Name) SetSym(x *types.Sym)    { n.sym = x }
func (n *Name) SubOp() Op              { return n.BuiltinOp }
func (n *Name) SetSubOp(x Op)          { n.BuiltinOp = x }
func (n *Name) SetFunc(x *Func)        { n.Func = x }
func (n *Name) FrameOffset() int64     { return n.Offset_ }
func (n *Name) SetFrameOffset(x int64) { n.Offset_ = x }

func (n *Name) Linksym() *obj.LSym               { return n.sym.Linksym() }
func (n *Name) LinksymABI(abi obj.ABI) *obj.LSym { return n.sym.LinksymABI(abi) }

func (*Name) CanBeNtype()    {}
func (*Name) CanBeAnSSASym() {}
func (*Name) CanBeAnSSAAux() {}

// Pragma returns the PragmaFlag for p, which must be for an OTYPE.
func (n *Name) Pragma() PragmaFlag { return n.pragma }

// SetPragma sets the PragmaFlag for p, which must be for an OTYPE.
func (n *Name) SetPragma(flag PragmaFlag) { n.pragma = flag }

// Alias reports whether p, which must be for an OTYPE, is a type alias.
func (n *Name) Alias() bool { return n.flags&nameAlias != 0 }

// SetAlias sets whether p, which must be for an OTYPE, is a type alias.
func (n *Name) SetAlias(alias bool) { n.flags.set(nameAlias, alias) }

const (
	nameReadonly                 = 1 << iota
	nameByval                    // is the variable captured by value or by reference
	nameNeedzero                 // if it contains pointers, needs to be zeroed on function entry
	nameAutoTemp                 // is the variable a temporary (implies no dwarf info. reset if escapes to heap)
	nameUsed                     // for variable declared and not used error
	nameIsClosureVar             // PAUTOHEAP closure pseudo-variable; original (if any) at n.Defn
	nameIsOutputParamHeapAddr    // pointer to a result parameter's heap copy
	nameIsOutputParamInRegisters // output parameter in registers spills as an auto
	nameAddrtaken                // address taken, even if not moved to heap
	nameInlFormal                // PAUTO created by inliner, derived from callee formal
	nameInlLocal                 // PAUTO created by inliner, derived from callee local
	nameOpenDeferSlot            // if temporary var storing info for open-coded defers
	nameLibfuzzer8BitCounter     // if PEXTERN should be assigned to __sancov_cntrs section
	nameCoverageAuxVar           // instrumentation counter var or pkg ID for cmd/cover
	nameAlias                    // is type name an alias
	nameNonMergeable             // not a candidate for stack slot merging
)

func (n *Name) Readonly() bool                 { return n.flags&nameReadonly != 0 }
func (n *Name) Needzero() bool                 { return n.flags&nameNeedzero != 0 }
func (n *Name) AutoTemp() bool                 { return n.flags&nameAutoTemp != 0 }
func (n *Name) Used() bool                     { return n.flags&nameUsed != 0 }
func (n *Name) IsClosureVar() bool             { return n.flags&nameIsClosureVar != 0 }
func (n *Name) IsOutputParamHeapAddr() bool    { return n.flags&nameIsOutputParamHeapAddr != 0 }
func (n *Name) IsOutputParamInRegisters() bool { return n.flags&nameIsOutputParamInRegisters != 0 }
func (n *Name) Addrtaken() bool                { return n.flags&nameAddrtaken != 0 }
func (n *Name) InlFormal() bool                { return n.flags&nameInlFormal != 0 }
func (n *Name) InlLocal() bool                 { return n.flags&nameInlLocal != 0 }
func (n *Name) OpenDeferSlot() bool            { return n.flags&nameOpenDeferSlot != 0 }
func (n *Name) Libfuzzer8BitCounter() bool     { return n.flags&nameLibfuzzer8BitCounter != 0 }
func (n *Name) CoverageAuxVar() bool           { return n.flags&nameCoverageAuxVar != 0 }
func (n *Name) NonMergeable() bool             { return n.flags&nameNonMergeable != 0 }

func (n *Name) setReadonly(b bool)                 { n.flags.set(nameReadonly, b) }
func (n *Name) SetNeedzero(b bool)                 { n.flags.set(nameNeedzero, b) }
func (n *Name) SetAutoTemp(b bool)                 { n.flags.set(nameAutoTemp, b) }
func (n *Name) SetUsed(b bool)                     { n.flags.set(nameUsed, b) }
func (n *Name) SetIsClosureVar(b bool)             { n.flags.set(nameIsClosureVar, b) }
func (n *Name) SetIsOutputParamHeapAddr(b bool)    { n.flags.set(nameIsOutputParamHeapAddr, b) }
func (n *Name) SetIsOutputParamInRegisters(b bool) { n.flags.set(nameIsOutputParamInRegisters, b) }
func (n *Name) SetAddrtaken(b bool)                { n.flags.set(nameAddrtaken, b) }
func (n *Name) SetInlFormal(b bool)                { n.flags.set(nameInlFormal, b) }
func (n *Name) SetInlLocal(b bool)                 { n.flags.set(nameInlLocal, b) }
func (n *Name) SetOpenDeferSlot(b bool)            { n.flags.set(nameOpenDeferSlot, b) }
func (n *Name) SetLibfuzzer8BitCounter(b bool)     { n.flags.set(nameLibfuzzer8BitCounter, b) }
func (n *Name) SetCoverageAuxVar(b bool)           { n.flags.set(nameCoverageAuxVar, b) }
func (n *Name) SetNonMergeable(b bool)             { n.flags.set(nameNonMergeable, b) }

// OnStack reports whether variable n may reside on the stack.
func (n *Name) OnStack() bool {
	if n.Op() == ONAME {
		switch n.Class {
		case PPARAM, PPARAMOUT, PAUTO:
			return n.Esc() != EscHeap
		case PEXTERN, PAUTOHEAP:
			return false
		}
	}
	// Note: fmt.go:dumpNodeHeader calls all "func() bool"-typed
	// methods, but it can only recover from panics, not Fatalf.
	panic(fmt.Sprintf("%v: not a variable: %v", base.FmtPos(n.Pos()), n))
}

// MarkReadonly indicates that n is an ONAME with readonly contents.
func (n *Name) MarkReadonly() {
	if n.Op() != ONAME {
		base.Fatalf("Node.MarkReadonly %v", n.Op())
	}
	n.setReadonly(true)
	// Mark the linksym as readonly immediately
	// so that the SSA backend can use this information.
	// It will be overridden later during dumpglobls.
	n.Linksym().Type = objabi.SRODATA
}

// Val returns the constant.Value for the node.
func (n *Name) Val() constant.Value {
	if n.val == nil {
		return constant.MakeUnknown()
	}
	return n.val
}

// SetVal sets the constant.Value for the node.
func (n *Name) SetVal(v constant.Value) {
	if n.op != OLITERAL {
		panic(n.no("SetVal"))
	}
	AssertValidTypeForConst(n.Type(), v)
	n.val = v
}

// Canonical returns the logical declaration that n represents. If n
// is a closure variable, then Canonical returns the original Name as
// it appears in the function that immediately contains the
// declaration. Otherwise, Canonical simply returns n itself.
func (n *Name) Canonical() *Name {
	if n.IsClosureVar() && n.Defn != nil {
		n = n.Defn.(*Name)
	}
	return n
}

func (n *Name) SetByval(b bool) {
	if n.Canonical() != n {
		base.Fatalf("SetByval called on non-canonical variable: %v", n)
	}
	n.flags.set(nameByval, b)
}

func (n *Name) Byval() bool {
	// We require byval to be set on the canonical variable, but we
	// allow it to be accessed from any instance.
	return n.Canonical().flags&nameByval != 0
}

// NewClosureVar returns a new closure variable for fn to refer to
// outer variable n.
func NewClosureVar(pos src.XPos, fn *Func, n *Name) *Name {
	switch n.Class {
	case PAUTO, PPARAM, PPARAMOUT, PAUTOHEAP:
		// ok
	default:
		// Prevent mistaken capture of global variables.
		base.Fatalf("NewClosureVar: %+v", n)
	}

	c := NewNameAt(pos, n.Sym(), n.Type())
	c.Curfn = fn
	c.Class = PAUTOHEAP
	c.SetIsClosureVar(true)
	c.Defn = n.Canonical()
	c.Outer = n

	fn.ClosureVars = append(fn.ClosureVars, c)

	return c
}

// NewHiddenParam returns a new hidden parameter for fn with the given
// name and type.
func NewHiddenParam(pos src.XPos, fn *Func, sym *types.Sym, typ *types.Type) *Name {
	if fn.OClosure != nil {
		base.FatalfAt(fn.Pos(), "cannot add hidden parameters to closures")
	}

	fn.SetNeedctxt(true)

	// Create a fake parameter, disassociated from any real function, to
	// pretend to capture.
	fake := NewNameAt(pos, sym, typ)
	fake.Class = PPARAM
	fake.SetByval(true)

	return NewClosureVar(pos, fn, fake)
}

// SameSource reports whether two nodes refer to the same source
// element.
//
// It exists to help incrementally migrate the compiler towards
// allowing the introduction of IdentExpr (#42990). Once we have
// IdentExpr, it will no longer be safe to directly compare Node
// values to tell if they refer to the same Name. Instead, code will
// need to explicitly get references to the underlying Name object(s),
// and compare those instead.
//
// It will still be safe to compare Nodes directly for checking if two
// nodes are syntactically the same. The SameSource function exists to
// indicate code that intentionally compares Nodes for syntactic
// equality as opposed to code that has yet to be updated in
// preparation for IdentExpr.
func SameSource(n1, n2 Node) bool {
	return n1 == n2
}

// Uses reports whether expression x is a (direct) use of the given
// variable.
func Uses(x Node, v *Name) bool {
	if v == nil || v.Op() != ONAME {
		base.Fatalf("RefersTo bad Name: %v", v)
	}
	return x.Op() == ONAME && x.Name() == v
}

// DeclaredBy reports whether expression x refers (directly) to a
// variable that was declared by the given statement.
func DeclaredBy(x, stmt Node) bool {
	if stmt == nil {
		base.Fatalf("DeclaredBy nil")
	}
	return x.Op() == ONAME && SameSource(x.Name().Defn, stmt)
}

// The Class of a variable/function describes the "storage class"
// of a variable or function. During parsing, storage classes are
// called declaration contexts.
type Class uint8

//go:generate stringer -type=Class name.go
const (
	Pxxx       Class = iota // no class; used during ssa conversion to indicate pseudo-variables
	PEXTERN                 // global variables
	PAUTO                   // local variables
	PAUTOHEAP               // local variables or parameters moved to heap
	PPARAM                  // input arguments
	PPARAMOUT               // output results
	PTYPEPARAM              // type params
	PFUNC                   // global functions

	// Careful: Class is stored in three bits in Node.flags.
	_ = uint((1 << 3) - iota) // static assert for iota <= (1 << 3)
)

type Embed struct {
	Pos      src.XPos
	Patterns []string
}

"""



```