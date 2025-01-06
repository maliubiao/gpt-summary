Response: The user wants to understand the functionality of the Go code snippet provided, which is the `node.go` file from the `cmd/compile/internal/ir` package. This file defines the core data structures for the compiler's intermediate representation (IR).

Here's a plan to address the user's request:

1. **Identify the main purpose of `node.go`:** This file defines the `Node` interface and various concrete types that represent nodes in the abstract syntax tree (AST) or the compiler's internal representation.

2. **List the core functionalities:**
    - Defining the `Node` interface with common methods for all IR nodes.
    - Defining concrete node types (structs) that implement the `Node` interface. While the code doesn't show the *struct definitions*, it lists the `Op` (operation) constants, which gives a strong indication of the types of nodes that exist.
    - Providing helper functions to work with `Node` instances (e.g., `Line`, `IsSynthetic`, `MayBeShared`, `InitExpr`, `OuterValue`).
    - Defining supporting data structures like `Nodes`, `NameQueue`, and `NameSet`.
    - Defining constants related to node properties (e.g., `Op`, `PragmaFlag`, `Esc`).

3. **Infer Go language features based on the code:** The `Op` constants provide clues about the Go language features being represented in the IR. Examples include:
    - Basic arithmetic and logical operations (`OADD`, `OSUB`, `OAND`, `OOR`).
    - Control flow statements (`OIF`, `OFOR`, `OSWITCH`).
    - Function calls and method calls (`OCALLFUNC`, `OCALLMETH`, `OCALLINTER`).
    - Data structures (`OCOMPLIT`, `OMAPLIT`, `OSLICELIT`).
    - Type conversions (`OCONV`, `OCONVIFACE`).
    - Goroutines and channels (`OGO`, `OSEND`, `ORECV`).
    - Built-in functions (`OLEN`, `OCAP`, `OAPPEND`, `OMAKE`, `ODELETE`, `OPANIC`, `ORECOVER`).
    - Unsafe operations (`OUNSAFEADD`, `OUNSAFESLICE`).
    - Generics (`ODYNAMICDOTTYPE`, `ODYNAMICTYPE`).

4. **Provide Go code examples for some of these features:** Illustrate how these Go features might be represented using the concepts defined in `node.go`. Focus on demonstrating how different `Op` values correspond to Go syntax.

5. **Address code reasoning with assumptions:** For features like `InitExpr` or `OuterValue`,  provide a simple scenario, hypothetical input `Node` structures, and explain the expected output.

6. **Explain command-line parameter handling (if applicable):**  While this specific file doesn't handle command-line arguments directly, it's part of the compiler. Briefly explain that the broader `cmd/compile` package handles command-line flags that influence the compilation process, which might affect how these IR nodes are generated or processed. Give a few examples of relevant flags.

7. **Identify potential pitfalls for users (if any):**  Since this is internal compiler code, direct end-users generally don't interact with it. However, for compiler developers, misunderstandings about when to copy nodes (`MayBeShared`) or how `InitExpr` works could be pitfalls.

**(Self-correction during thought process):** Initially, I might have focused too much on the individual methods of the `Node` interface. However, the core value of this file is defining the *types* of operations and data the compiler manipulates. Therefore, emphasizing the `Op` constants and relating them to Go language features is more important. Also, directly citing the struct definitions would be more helpful, but since they aren't provided in the snippet, inferring from `Op` is the next best approach. I need to be careful to state assumptions clearly when providing code examples based on the provided `Op` values without the full struct definitions.
`go/src/cmd/compile/internal/ir/node.go` 文件是 Go 编译器中表示抽象语法树（AST）节点的核心定义文件。它定义了 `Node` 接口以及各种具体的节点类型，用于在编译的不同阶段表示 Go 程序的结构。

以下是它的主要功能：

1. **定义 `Node` 接口:**  这是所有 AST 节点的抽象接口，强制所有节点类型实现一组通用方法。这些方法提供了访问和操作节点的基本功能，例如：
    - `Format`: 用于格式化输出节点信息，通常用于调试或打印 AST。
    - `Pos` 和 `SetPos`:  获取和设置节点在源代码中的位置，对于错误报告和调试至关重要。
    - `copy`: 用于创建节点的副本，这在编译器的一些优化和转换过程中是必需的。
    - `doChildren` 和 `editChildren`:  用于遍历和修改节点的子节点，是进行 AST 分析和转换的基础。
    - `Op`: 返回节点的具体操作类型 (例如，加法、函数调用、赋值等)。
    - `Init`: 返回与该节点关联的初始化语句列表。
    - `Type` 和 `SetType`: 获取和设置节点表示的表达式或变量的类型。
    - `Name`: 如果节点表示一个命名实体（变量、函数等），则返回其名称信息。
    - `Sym`: 返回与命名实体关联的符号信息。
    - `Val` 和 `SetVal`: 对于常量节点，获取和设置其值。
    - `Esc` 和 `SetEsc`: 用于存储逃逸分析的结果。
    - `Typecheck` 和 `SetTypecheck`: 跟踪节点的类型检查状态。
    - `NonNil` 和 `MarkNonNil`: 用于标记节点的值已知非 nil。

2. **定义 `Op` 类型:**  这是一个枚举类型，定义了所有可能的节点操作类型。每个 `Op` 常量代表一种不同的 Go 语言构造，例如：
    - 算术运算 (`OADD`, `OSUB`, `OMUL`, `ODIV`)
    - 逻辑运算 (`OANDAND`, `OOROR`)
    - 赋值 (`OAS`, `OAS2`)
    - 函数调用 (`OCALL`, `OCALLFUNC`, `OCALLMETH`)
    - 字面量 (`OLITERAL`, `OCOMPLIT`)
    - 控制流 (`OIF`, `OFOR`, `OSWITCH`)
    - 类型转换 (`OCONV`)
    - 内存操作 (`OADDR`, `ODEREF`)
    - Goroutine 和 channel 操作 (`OGO`, `OSEND`, `ORECV`)
    - 内置函数 (`OLEN`, `OCAP`, `OAPPEND`)
    - 以及更多其他操作。

3. **定义辅助函数:**  文件中还包含一些辅助函数，用于操作和检查 `Node` 实例：
    - `Line`: 返回节点所在源代码行的字符串表示。
    - `IsSynthetic`: 判断节点是否是编译器自动生成的。
    - `IsAutoTmp`: 判断节点是否是编译器创建的临时变量。
    - `MayBeShared`: 判断节点是否可能在 AST 中多处引用，需要谨慎修改。
    - `TakeInit`: 获取并清空节点的初始化语句列表。
    - `ToNodes`: 将其他类型的节点切片转换为 `Nodes` 类型。
    - `Append` 和 `Prepend`: 向 `Nodes` 切片添加节点。
    - `Copy`: 创建 `Nodes` 切片的副本。
    - `InitExpr`: 将初始化语句列表添加到给定的表达式节点。
    - `OuterValue`:  查找表达式影响的最外层值（例如，结构体或数组）。
    - `IsConst`, `IsNil`, `IsBlank`, `IsMethod`, `HasUniquePos`, `SetPos`.

4. **定义其他数据结构:**  例如 `Nodes` (节点切片), `NameQueue` (命名实体队列), `NameSet` (命名实体集合) 等，用于在编译过程中组织和管理节点信息。

5. **定义 Pragma 标志:** `PragmaFlag` 定义了可以应用于函数声明的编译指示标志，例如 `//go:noinline`。

**它是什么 Go 语言功能的实现？**

`node.go` 实际上是 Go 编译器内部表示所有 Go 语言特性的基础。每当你写一段 Go 代码，编译器在解析和类型检查后，都会将其转换为由 `ir.Node` 接口及其具体实现类型组成的 AST。

**Go 代码举例说明:**

假设有以下简单的 Go 代码片段：

```go
package main

func add(a int, b int) int {
	sum := a + b
	return sum
}

func main() {
	result := add(10, 20)
	println(result)
}
```

在编译器的内部表示中，这段代码会被分解成各种 `ir.Node` 节点。以下是一些可能的节点及其对应的 `Op` 值（这只是一个简化的概念性示例，实际的 AST 会更复杂）：

- **函数声明 `add`:**  可能对应一个 `ODCLFUNC` 节点，其子节点包含参数列表 (`ONAME` 节点) 和函数体 (`OBLOCK` 节点)。
- **变量声明 `sum := a + b`:**  可能对应一个 `OAS` 节点（赋值），其左侧是一个 `ONAME` 节点 (表示 `sum`)，右侧是一个 `OADD` 节点 (表示 `a + b`)，而 `a` 和 `b` 也是 `ONAME` 节点。
- **`return sum`:** 对应一个 `ORETURN` 节点，其子节点是表示 `sum` 的 `ONAME` 节点。
- **函数调用 `add(10, 20)`:** 对应一个 `OCALLFUNC` 节点，其子节点包含被调用的函数 (`ONAME` 节点表示 `add`) 和参数列表 (`OLITERAL` 节点表示 `10` 和 `20`)。
- **变量声明 `result := add(10, 20)`:**  类似于 `sum` 的声明，是一个 `OAS` 节点，左侧是 `result` 的 `ONAME` 节点，右侧是 `add(10, 20)` 的 `OCALLFUNC` 节点。
- **函数调用 `println(result)`:**  对应一个 `OCALLFUNC` 节点，调用的是内置函数 `println`。

**代码推理（带假设的输入与输出）：**

考虑 `InitExpr` 函数。

**假设输入:**
- `init`: 一个包含一个 `ir.ODCL` 节点的 `Nodes` 切片，表示变量声明 `var temp int = 5`。
- `expr`: 一个 `ir.OADD` 节点，表示表达式 `x + 10`，其中 `x` 是一个 `ir.ONAME` 节点。

**处理过程:** `InitExpr` 会将 `init` 中的声明语句添加到 `expr` 节点的前面。由于 `OADD` 节点（假设其对应的结构体没有 `Init` 字段或者 `MayBeShared` 返回 `true`），`InitExpr` 会创建一个 `OCONVNOP` 节点来包装 `expr`，并将 `init` 添加到 `OCONVNOP` 节点的初始化列表中。

**预期输出:** 一个 `ir.OCONVNOP` 节点，其 `Init` 字段包含输入的 `ir.ODCL` 节点，其 `X` 字段是输入的 `ir.OADD` 节点。  最终的结构逻辑上相当于：

```go
{
    var temp int = 5
    _ = x + 10 // OCONVNOP 包裹了 OADD
}
```

**命令行参数的具体处理:**

`go/src/cmd/compile/internal/ir/node.go` 本身不直接处理命令行参数。命令行参数的处理发生在 `cmd/compile/internal/gc` 包（或其他上层包）中。这些参数会影响编译器的行为，进而影响到生成的 AST 结构和节点的属性。

例如：

- **`-N` (禁用优化):**  可能会导致编译器生成更直接的 AST，避免某些优化相关的节点转换。
- **`-l` (禁用内联):**  会阻止函数内联优化，使得 `OINLCALL` 节点不会被生成。
- **`-race` (启用竞态检测):**  可能会在 AST 中插入额外的节点或修改现有节点的属性，以便在运行时进行竞态检测。
- **`-buildvcs` (在构建信息中嵌入版本控制信息):**  可能影响到与包信息相关的节点的生成。

编译器会解析这些参数，并在构建 AST 和后续的编译阶段使用这些信息来指导节点的创建和操作。

**使用者易犯错的点：**

由于 `go/src/cmd/compile/internal/ir` 是 Go 编译器的内部实现，直接的使用者是 Go 编译器的开发者。对于他们来说，一些容易犯错的点可能包括：

- **直接修改可能被共享的节点 (`MayBeShared` 返回 `true`)：**  如果不小心修改了被多处引用的节点，可能会导致意想不到的编译错误或运行时行为。必须先进行深拷贝。
    ```go
    // 假设 n 是一个 MayBeShared 的节点
    copyN := n.copy()
    // 修改 copyN 而不是 n
    ```

- **不正确地处理节点的 `Init` 列表：**  某些节点可能包含初始化语句，这些语句需要在代码生成阶段正确处理。忽略或错误地处理 `Init` 列表可能导致编译错误或不正确的代码执行。例如，在使用 `InitExpr` 添加初始化语句后，必须确保后续处理阶段会考虑到这些初始化语句。

- **误解不同 `Op` 值的含义和用法：**  每种 `Op` 值都有特定的语义和预期用途。错误地创建或操作具有特定 `Op` 值的节点可能导致编译错误或逻辑错误。例如，不应该手动创建一个 `OTYPESW` 节点，它的创建通常是由类型开关语句的解析过程驱动的。

- **在不应该修改 AST 的阶段修改它：**  编译过程的不同阶段有不同的职责。在某些阶段修改 AST 可能破坏后续阶段的假设，导致崩溃或错误的结果。例如，在某些优化 pass 之后，再进行某些类型的 AST 修改可能是不安全的。

总而言之，`go/src/cmd/compile/internal/ir/node.go` 是 Go 编译器内部表示 Go 代码结构的关键部分，定义了编译器进行分析、优化和代码生成的基石。理解这个文件对于深入了解 Go 编译器的内部工作原理至关重要。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ir/node.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// “Abstract” syntax representation.

package ir

import (
	"fmt"
	"go/constant"

	"cmd/compile/internal/base"
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// A Node is the abstract interface to an IR node.
type Node interface {
	// Formatting
	Format(s fmt.State, verb rune)

	// Source position.
	Pos() src.XPos
	SetPos(x src.XPos)

	// For making copies. For Copy and SepCopy.
	copy() Node

	doChildren(func(Node) bool) bool
	doChildrenWithHidden(func(Node) bool) bool
	editChildren(func(Node) Node)
	editChildrenWithHidden(func(Node) Node)

	// Abstract graph structure, for generic traversals.
	Op() Op
	Init() Nodes

	// Fields specific to certain Ops only.
	Type() *types.Type
	SetType(t *types.Type)
	Name() *Name
	Sym() *types.Sym
	Val() constant.Value
	SetVal(v constant.Value)

	// Storage for analysis passes.
	Esc() uint16
	SetEsc(x uint16)

	// Typecheck values:
	//  0 means the node is not typechecked
	//  1 means the node is completely typechecked
	//  2 means typechecking of the node is in progress
	Typecheck() uint8
	SetTypecheck(x uint8)
	NonNil() bool
	MarkNonNil()
}

// Line returns n's position as a string. If n has been inlined,
// it uses the outermost position where n has been inlined.
func Line(n Node) string {
	return base.FmtPos(n.Pos())
}

func IsSynthetic(n Node) bool {
	name := n.Sym().Name
	return name[0] == '.' || name[0] == '~'
}

// IsAutoTmp indicates if n was created by the compiler as a temporary,
// based on the setting of the .AutoTemp flag in n's Name.
func IsAutoTmp(n Node) bool {
	if n == nil || n.Op() != ONAME {
		return false
	}
	return n.Name().AutoTemp()
}

// MayBeShared reports whether n may occur in multiple places in the AST.
// Extra care must be taken when mutating such a node.
func MayBeShared(n Node) bool {
	switch n.Op() {
	case ONAME, OLITERAL, ONIL, OTYPE:
		return true
	}
	return false
}

type InitNode interface {
	Node
	PtrInit() *Nodes
	SetInit(x Nodes)
}

func TakeInit(n Node) Nodes {
	init := n.Init()
	if len(init) != 0 {
		n.(InitNode).SetInit(nil)
	}
	return init
}

//go:generate stringer -type=Op -trimprefix=O node.go

type Op uint8

// Node ops.
const (
	OXXX Op = iota

	// names
	ONAME // var or func name
	// Unnamed arg or return value: f(int, string) (int, error) { etc }
	// Also used for a qualified package identifier that hasn't been resolved yet.
	ONONAME
	OTYPE    // type name
	OLITERAL // literal
	ONIL     // nil

	// expressions
	OADD          // X + Y
	OSUB          // X - Y
	OOR           // X | Y
	OXOR          // X ^ Y
	OADDSTR       // +{List} (string addition, list elements are strings)
	OADDR         // &X
	OANDAND       // X && Y
	OAPPEND       // append(Args); after walk, X may contain elem type descriptor
	OBYTES2STR    // Type(X) (Type is string, X is a []byte)
	OBYTES2STRTMP // Type(X) (Type is string, X is a []byte, ephemeral)
	ORUNES2STR    // Type(X) (Type is string, X is a []rune)
	OSTR2BYTES    // Type(X) (Type is []byte, X is a string)
	OSTR2BYTESTMP // Type(X) (Type is []byte, X is a string, ephemeral)
	OSTR2RUNES    // Type(X) (Type is []rune, X is a string)
	OSLICE2ARR    // Type(X) (Type is [N]T, X is a []T)
	OSLICE2ARRPTR // Type(X) (Type is *[N]T, X is a []T)
	// X = Y or (if Def=true) X := Y
	// If Def, then Init includes a DCL node for X.
	OAS
	// Lhs = Rhs (x, y, z = a, b, c) or (if Def=true) Lhs := Rhs
	// If Def, then Init includes DCL nodes for Lhs
	OAS2
	OAS2DOTTYPE // Lhs = Rhs (x, ok = I.(int))
	OAS2FUNC    // Lhs = Rhs (x, y = f())
	OAS2MAPR    // Lhs = Rhs (x, ok = m["foo"])
	OAS2RECV    // Lhs = Rhs (x, ok = <-c)
	OASOP       // X AsOp= Y (x += y)
	OCALL       // X(Args) (function call, method call or type conversion)

	// OCALLFUNC, OCALLMETH, and OCALLINTER have the same structure.
	// Prior to walk, they are: X(Args), where Args is all regular arguments.
	// After walk, if any argument whose evaluation might requires temporary variable,
	// that temporary variable will be pushed to Init, Args will contain an updated
	// set of arguments.
	OCALLFUNC  // X(Args) (function call f(args))
	OCALLMETH  // X(Args) (direct method call x.Method(args))
	OCALLINTER // X(Args) (interface method call x.Method(args))
	OCAP       // cap(X)
	OCLEAR     // clear(X)
	OCLOSE     // close(X)
	OCLOSURE   // func Type { Func.Closure.Body } (func literal)
	OCOMPLIT   // Type{List} (composite literal, not yet lowered to specific form)
	OMAPLIT    // Type{List} (composite literal, Type is map)
	OSTRUCTLIT // Type{List} (composite literal, Type is struct)
	OARRAYLIT  // Type{List} (composite literal, Type is array)
	OSLICELIT  // Type{List} (composite literal, Type is slice), Len is slice length.
	OPTRLIT    // &X (X is composite literal)
	OCONV      // Type(X) (type conversion)
	OCONVIFACE // Type(X) (type conversion, to interface)
	OCONVNOP   // Type(X) (type conversion, no effect)
	OCOPY      // copy(X, Y)
	ODCL       // var X (declares X of type X.Type)

	// Used during parsing but don't last.
	ODCLFUNC // func f() or func (r) f()

	ODELETE        // delete(Args)
	ODOT           // X.Sel (X is of struct type)
	ODOTPTR        // X.Sel (X is of pointer to struct type)
	ODOTMETH       // X.Sel (X is non-interface, Sel is method name)
	ODOTINTER      // X.Sel (X is interface, Sel is method name)
	OXDOT          // X.Sel (before rewrite to one of the preceding)
	ODOTTYPE       // X.Ntype or X.Type (.Ntype during parsing, .Type once resolved); after walk, Itab contains address of interface type descriptor and Itab.X contains address of concrete type descriptor
	ODOTTYPE2      // X.Ntype or X.Type (.Ntype during parsing, .Type once resolved; on rhs of OAS2DOTTYPE); after walk, Itab contains address of interface type descriptor
	OEQ            // X == Y
	ONE            // X != Y
	OLT            // X < Y
	OLE            // X <= Y
	OGE            // X >= Y
	OGT            // X > Y
	ODEREF         // *X
	OINDEX         // X[Index] (index of array or slice)
	OINDEXMAP      // X[Index] (index of map)
	OKEY           // Key:Value (key:value in struct/array/map literal)
	OSTRUCTKEY     // Field:Value (key:value in struct literal, after type checking)
	OLEN           // len(X)
	OMAKE          // make(Args) (before type checking converts to one of the following)
	OMAKECHAN      // make(Type[, Len]) (type is chan)
	OMAKEMAP       // make(Type[, Len]) (type is map)
	OMAKESLICE     // make(Type[, Len[, Cap]]) (type is slice)
	OMAKESLICECOPY // makeslicecopy(Type, Len, Cap) (type is slice; Len is length and Cap is the copied from slice)
	// OMAKESLICECOPY is created by the order pass and corresponds to:
	//  s = make(Type, Len); copy(s, Cap)
	//
	// Bounded can be set on the node when Len == len(Cap) is known at compile time.
	//
	// This node is created so the walk pass can optimize this pattern which would
	// otherwise be hard to detect after the order pass.
	OMUL              // X * Y
	ODIV              // X / Y
	OMOD              // X % Y
	OLSH              // X << Y
	ORSH              // X >> Y
	OAND              // X & Y
	OANDNOT           // X &^ Y
	ONEW              // new(X); corresponds to calls to new in source code
	ONOT              // !X
	OBITNOT           // ^X
	OPLUS             // +X
	ONEG              // -X
	OOROR             // X || Y
	OPANIC            // panic(X)
	OPRINT            // print(List)
	OPRINTLN          // println(List)
	OPAREN            // (X)
	OSEND             // Chan <- Value
	OSLICE            // X[Low : High] (X is untypechecked or slice)
	OSLICEARR         // X[Low : High] (X is pointer to array)
	OSLICESTR         // X[Low : High] (X is string)
	OSLICE3           // X[Low : High : Max] (X is untypedchecked or slice)
	OSLICE3ARR        // X[Low : High : Max] (X is pointer to array)
	OSLICEHEADER      // sliceheader{Ptr, Len, Cap} (Ptr is unsafe.Pointer, Len is length, Cap is capacity)
	OSTRINGHEADER     // stringheader{Ptr, Len} (Ptr is unsafe.Pointer, Len is length)
	ORECOVER          // recover()
	ORECOVERFP        // recover(Args) w/ explicit FP argument
	ORECV             // <-X
	ORUNESTR          // Type(X) (Type is string, X is rune)
	OSELRECV2         // like OAS2: Lhs = Rhs where len(Lhs)=2, len(Rhs)=1, Rhs[0].Op = ORECV (appears as .Var of OCASE)
	OMIN              // min(List)
	OMAX              // max(List)
	OREAL             // real(X)
	OIMAG             // imag(X)
	OCOMPLEX          // complex(X, Y)
	OUNSAFEADD        // unsafe.Add(X, Y)
	OUNSAFESLICE      // unsafe.Slice(X, Y)
	OUNSAFESLICEDATA  // unsafe.SliceData(X)
	OUNSAFESTRING     // unsafe.String(X, Y)
	OUNSAFESTRINGDATA // unsafe.StringData(X)
	OMETHEXPR         // X(Args) (method expression T.Method(args), first argument is the method receiver)
	OMETHVALUE        // X.Sel   (method expression t.Method, not called)

	// statements
	OBLOCK // { List } (block of code)
	OBREAK // break [Label]
	// OCASE:  case List: Body (List==nil means default)
	//   For OTYPESW, List is a OTYPE node for the specified type (or OLITERAL
	//   for nil) or an ODYNAMICTYPE indicating a runtime type for generics.
	//   If a type-switch variable is specified, Var is an
	//   ONAME for the version of the type-switch variable with the specified
	//   type.
	OCASE
	OCONTINUE // continue [Label]
	ODEFER    // defer Call
	OFALL     // fallthrough
	OFOR      // for Init; Cond; Post { Body }
	OGOTO     // goto Label
	OIF       // if Init; Cond { Then } else { Else }
	OLABEL    // Label:
	OGO       // go Call
	ORANGE    // for Key, Value = range X { Body }
	ORETURN   // return Results
	OSELECT   // select { Cases }
	OSWITCH   // switch Init; Expr { Cases }
	// OTYPESW:  X := Y.(type) (appears as .Tag of OSWITCH)
	//   X is nil if there is no type-switch variable
	OTYPESW

	// misc
	// intermediate representation of an inlined call.  Uses Init (assignments
	// for the captured variables, parameters, retvars, & INLMARK op),
	// Body (body of the inlined function), and ReturnVars (list of
	// return values)
	OINLCALL         // intermediary representation of an inlined call.
	OMAKEFACE        // construct an interface value from rtype/itab and data pointers
	OITAB            // rtype/itab pointer of an interface value
	OIDATA           // data pointer of an interface value
	OSPTR            // base pointer of a slice or string. Bounded==1 means known non-nil.
	OCFUNC           // reference to c function pointer (not go func value)
	OCHECKNIL        // emit code to ensure pointer/interface not nil
	ORESULT          // result of a function call; Xoffset is stack offset
	OINLMARK         // start of an inlined body, with file/line of caller. Xoffset is an index into the inline tree.
	OLINKSYMOFFSET   // offset within a name
	OJUMPTABLE       // A jump table structure for implementing dense expression switches
	OINTERFACESWITCH // A type switch with interface cases

	// opcodes for generics
	ODYNAMICDOTTYPE  // x = i.(T) where T is a type parameter (or derived from a type parameter)
	ODYNAMICDOTTYPE2 // x, ok = i.(T) where T is a type parameter (or derived from a type parameter)
	ODYNAMICTYPE     // a type node for type switches (represents a dynamic target type for a type switch)

	// arch-specific opcodes
	OTAILCALL    // tail call to another function
	OGETG        // runtime.getg() (read g pointer)
	OGETCALLERSP // internal/runtime/sys.GetCallerSP() (stack pointer in caller frame)

	OEND
)

// IsCmp reports whether op is a comparison operation (==, !=, <, <=,
// >, or >=).
func (op Op) IsCmp() bool {
	switch op {
	case OEQ, ONE, OLT, OLE, OGT, OGE:
		return true
	}
	return false
}

// Nodes is a slice of Node.
type Nodes []Node

// ToNodes returns s as a slice of Nodes.
func ToNodes[T Node](s []T) Nodes {
	res := make(Nodes, len(s))
	for i, n := range s {
		res[i] = n
	}
	return res
}

// Append appends entries to Nodes.
func (n *Nodes) Append(a ...Node) {
	if len(a) == 0 {
		return
	}
	*n = append(*n, a...)
}

// Prepend prepends entries to Nodes.
// If a slice is passed in, this will take ownership of it.
func (n *Nodes) Prepend(a ...Node) {
	if len(a) == 0 {
		return
	}
	*n = append(a, *n...)
}

// Take clears n, returning its former contents.
func (n *Nodes) Take() []Node {
	ret := *n
	*n = nil
	return ret
}

// Copy returns a copy of the content of the slice.
func (n Nodes) Copy() Nodes {
	if n == nil {
		return nil
	}
	c := make(Nodes, len(n))
	copy(c, n)
	return c
}

// NameQueue is a FIFO queue of *Name. The zero value of NameQueue is
// a ready-to-use empty queue.
type NameQueue struct {
	ring       []*Name
	head, tail int
}

// Empty reports whether q contains no Names.
func (q *NameQueue) Empty() bool {
	return q.head == q.tail
}

// PushRight appends n to the right of the queue.
func (q *NameQueue) PushRight(n *Name) {
	if len(q.ring) == 0 {
		q.ring = make([]*Name, 16)
	} else if q.head+len(q.ring) == q.tail {
		// Grow the ring.
		nring := make([]*Name, len(q.ring)*2)
		// Copy the old elements.
		part := q.ring[q.head%len(q.ring):]
		if q.tail-q.head <= len(part) {
			part = part[:q.tail-q.head]
			copy(nring, part)
		} else {
			pos := copy(nring, part)
			copy(nring[pos:], q.ring[:q.tail%len(q.ring)])
		}
		q.ring, q.head, q.tail = nring, 0, q.tail-q.head
	}

	q.ring[q.tail%len(q.ring)] = n
	q.tail++
}

// PopLeft pops a Name from the left of the queue. It panics if q is
// empty.
func (q *NameQueue) PopLeft() *Name {
	if q.Empty() {
		panic("dequeue empty")
	}
	n := q.ring[q.head%len(q.ring)]
	q.head++
	return n
}

// NameSet is a set of Names.
type NameSet map[*Name]struct{}

// Has reports whether s contains n.
func (s NameSet) Has(n *Name) bool {
	_, isPresent := s[n]
	return isPresent
}

// Add adds n to s.
func (s *NameSet) Add(n *Name) {
	if *s == nil {
		*s = make(map[*Name]struct{})
	}
	(*s)[n] = struct{}{}
}

type PragmaFlag uint16

const (
	// Func pragmas.
	Nointerface      PragmaFlag = 1 << iota
	Noescape                    // func parameters don't escape
	Norace                      // func must not have race detector annotations
	Nosplit                     // func should not execute on separate stack
	Noinline                    // func should not be inlined
	NoCheckPtr                  // func should not be instrumented by checkptr
	CgoUnsafeArgs               // treat a pointer to one arg as a pointer to them all
	UintptrKeepAlive            // pointers converted to uintptr must be kept alive
	UintptrEscapes              // pointers converted to uintptr escape

	// Runtime-only func pragmas.
	// See ../../../../runtime/HACKING.md for detailed descriptions.
	Systemstack        // func must run on system stack
	Nowritebarrier     // emit compiler error instead of write barrier
	Nowritebarrierrec  // error on write barrier in this or recursive callees
	Yeswritebarrierrec // cancels Nowritebarrierrec in this function and callees

	// Go command pragmas
	GoBuildPragma

	RegisterParams // TODO(register args) remove after register abi is working

)

var BlankNode *Name

func IsConst(n Node, ct constant.Kind) bool {
	return ConstType(n) == ct
}

// IsNil reports whether n represents the universal untyped zero value "nil".
func IsNil(n Node) bool {
	return n != nil && n.Op() == ONIL
}

func IsBlank(n Node) bool {
	if n == nil {
		return false
	}
	return n.Sym().IsBlank()
}

// IsMethod reports whether n is a method.
// n must be a function or a method.
func IsMethod(n Node) bool {
	return n.Type().Recv() != nil
}

// HasUniquePos reports whether n has a unique position that can be
// used for reporting error messages.
//
// It's primarily used to distinguish references to named objects,
// whose Pos will point back to their declaration position rather than
// their usage position.
func HasUniquePos(n Node) bool {
	switch n.Op() {
	case ONAME:
		return false
	case OLITERAL, ONIL, OTYPE:
		if n.Sym() != nil {
			return false
		}
	}

	if !n.Pos().IsKnown() {
		if base.Flag.K != 0 {
			base.Warn("setlineno: unknown position (line 0)")
		}
		return false
	}

	return true
}

func SetPos(n Node) src.XPos {
	lno := base.Pos
	if n != nil && HasUniquePos(n) {
		base.Pos = n.Pos()
	}
	return lno
}

// The result of InitExpr MUST be assigned back to n, e.g.
//
//	n.X = InitExpr(init, n.X)
func InitExpr(init []Node, expr Node) Node {
	if len(init) == 0 {
		return expr
	}

	n, ok := expr.(InitNode)
	if !ok || MayBeShared(n) {
		// Introduce OCONVNOP to hold init list.
		n = NewConvExpr(base.Pos, OCONVNOP, nil, expr)
		n.SetType(expr.Type())
		n.SetTypecheck(1)
	}

	n.PtrInit().Prepend(init...)
	return n
}

// what's the outer value that a write to n affects?
// outer value means containing struct or array.
func OuterValue(n Node) Node {
	for {
		switch nn := n; nn.Op() {
		case OXDOT:
			base.FatalfAt(n.Pos(), "OXDOT in OuterValue: %v", n)
		case ODOT:
			nn := nn.(*SelectorExpr)
			n = nn.X
			continue
		case OPAREN:
			nn := nn.(*ParenExpr)
			n = nn.X
			continue
		case OCONVNOP:
			nn := nn.(*ConvExpr)
			n = nn.X
			continue
		case OINDEX:
			nn := nn.(*IndexExpr)
			if nn.X.Type() == nil {
				base.Fatalf("OuterValue needs type for %v", nn.X)
			}
			if nn.X.Type().IsArray() {
				n = nn.X
				continue
			}
		}

		return n
	}
}

const (
	EscUnknown = iota
	EscNone    // Does not escape to heap, result, or parameters.
	EscHeap    // Reachable from the heap
	EscNever   // By construction will not escape.
)

"""



```