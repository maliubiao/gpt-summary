Response: Let's break down the thought process for analyzing the `stmt.go` file.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code snippet, to infer what Go language features it implements, provide Go code examples, explain code reasoning with assumptions, detail command-line argument handling (if any), and identify common mistakes.

2. **Initial Scan and Keywords:** I quickly scanned the code for keywords and structure. I noticed:
    * `package ir`: This indicates it's part of the Go compiler's internal representation (IR).
    * Struct definitions like `Decl`, `AssignStmt`, `ForStmt`, `IfStmt`, etc. These clearly represent different types of statements in Go.
    * Methods like `NewDecl`, `NewAssignStmt`, `SetOp`, `Init`, `SetInit`, etc. These are constructors and setters for the struct fields.
    * Interfaces like `Stmt`. This suggests a common behavior shared by different statement types.
    * Comments explaining the purpose of each struct and field. This is a huge help.
    * Use of types from other internal packages like `cmd/compile/internal/base`, `cmd/compile/internal/types`, `cmd/internal/obj`, `cmd/internal/src`, and `go/constant`. This reinforces the compiler IR context.
    * Opcodes (e.g., `ODCL`, `OAS`, `OFOR`). These are likely internal representations of statement types.
    * Panic statements with messages like "invalid Decl op". This indicates error handling and constraints on how these structures are used.

3. **Categorize the Structs:** I started grouping the structs based on their names and comments:
    * **Declarations:** `Decl` (for `const`, `type`, `var`).
    * **Assignments:** `AssignStmt`, `AssignListStmt`, `AssignOpStmt`.
    * **Control Flow:** `BlockStmt`, `BranchStmt`, `CaseClause`, `CommClause`, `ForStmt`, `GoDeferStmt`, `IfStmt`, `JumpTableStmt`, `InterfaceSwitchStmt`, `ReturnStmt`, `SelectStmt`, `SwitchStmt`.
    * **Looping:** `ForStmt`, `RangeStmt`.
    * **Communication:** `SendStmt`.
    * **Other:** `InlineMarkStmt`, `LabelStmt`, `TailCallStmt`, `TypeSwitchGuard`.

4. **Infer Functionality based on Struct Names and Fields:** For each struct, I analyzed its fields to understand what information it holds and thus what aspect of a Go statement it represents. For example:
    * `AssignStmt` has `X`, `Y`, and `Def`. This strongly suggests a simple assignment (`x = y` or `x := y`).
    * `ForStmt` has `Init`, `Cond`, `Post`, and `Body`. This maps directly to the components of a `for` loop.
    * `IfStmt` has `Cond`, `Body`, and `Else`. This clearly represents an `if-else` statement.

5. **Connect Structs to Go Language Features:**  This is the core of the inference process. I linked the identified struct categories to corresponding Go syntax:
    * `Decl` -> Variable, constant, and type declarations.
    * `AssignStmt`, `AssignListStmt`, `AssignOpStmt` -> Different forms of assignment.
    * `BlockStmt` -> Code blocks enclosed in `{}`.
    * `BranchStmt` -> `break`, `continue`, `goto`, `fallthrough`.
    * `CaseClause`, `CommClause` -> `case` statements in `switch` and `select`.
    * `ForStmt` -> Standard `for` loops.
    * `RangeStmt` -> `for...range` loops.
    * `GoDeferStmt` -> `go` and `defer` statements.
    * `IfStmt` -> `if` and `if-else` statements.
    * `ReturnStmt` -> `return` statements.
    * `SelectStmt` -> `select` statements for channel operations.
    * `SwitchStmt` -> `switch` statements.
    * `SendStmt` -> Sending values on channels (`<-`).

6. **Construct Go Code Examples:** For the key statement types, I created simple, illustrative Go code examples. The goal here was clarity, not complexity. I tried to match the structure of the example to the fields of the corresponding struct.

7. **Reason about Code and Provide Assumptions:** For the more complex structs (like `JumpTableStmt` and `InterfaceSwitchStmt`), I had to rely more on the comments and inferred behavior. I stated clear assumptions about how these structures might be used during compilation.

8. **Address Command-Line Arguments:** I realized that this code snippet focuses on the *internal representation* of statements. It doesn't directly handle command-line arguments. Therefore, I stated that explicitly.

9. **Identify Common Mistakes:**  This requires understanding how developers use these language features. I focused on common errors related to the semantics of the identified statements:
    * `Decl`: Shadowing variables.
    * `AssignStmt`: Incorrect type assignments.
    * `ForStmt`: Infinite loops.
    * `RangeStmt`: Modifying the collection being iterated over.
    * `IfStmt`: Incorrect conditional logic.
    * `SwitchStmt`: Missing `break` (though Go doesn't require it like C/Java, sometimes it's intended).
    * `GoDeferStmt`: Misunderstanding `defer`'s execution order.
    * `SelectStmt`: Forgetting a `default` case.

10. **Review and Refine:** I reread my analysis and examples to ensure they were accurate, clear, and addressed all parts of the request. I double-checked the connection between the structs and the Go language features.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Are these structs directly representing the AST?"  Correction: While related to the AST, these are part of the *Intermediate Representation* used during compilation, which is a step further in the process.
* **Struggling with `JumpTableStmt` and `InterfaceSwitchStmt`:** Realized the comments provided crucial hints about their purpose in implementing `switch` statements efficiently. Focused on explaining their likely function in code generation.
* **Considering command-line arguments:**  Initially thought about compiler flags, but then realized this code is *part of* the compiler, not directly handling flags. Clarified the distinction.
* **Choosing examples:**  Prioritized simple, direct examples over complex ones to clearly illustrate the functionality.

By following this structured approach, combining code analysis, comment understanding, and knowledge of Go language semantics, I could effectively address the request and provide a comprehensive explanation of the `stmt.go` code.
The provided Go code snippet from `go/src/cmd/compile/internal/ir/stmt.go` defines the internal representation (IR) of various Go statements within the Go compiler. It's a crucial part of how the compiler understands and manipulates Go code during the compilation process.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Defining Statement Types:** The code defines Go structs that represent different kinds of statements in the Go language. Each struct encapsulates the essential information needed to represent that specific statement. Examples include:
    * `Decl`: Represents a declaration (e.g., `var x int`, `const c = 10`).
    * `AssignStmt`: Represents a simple assignment (e.g., `x = 5`).
    * `AssignListStmt`: Represents multi-value assignments (e.g., `x, y = 1, 2`).
    * `ForStmt`: Represents a `for` loop.
    * `IfStmt`: Represents an `if` statement.
    * `ReturnStmt`: Represents a `return` statement.
    * `GoDeferStmt`: Represents `go` and `defer` statements.
    * `SwitchStmt`: Represents a `switch` statement.
    * `SelectStmt`: Represents a `select` statement.
    * `RangeStmt`: Represents a `for...range` loop.
    * `BranchStmt`: Represents `break`, `continue`, `goto`, and `fallthrough`.

2. **Providing Constructors:**  For each statement type, the code offers `New...Stmt` functions. These functions act as constructors, creating new instances of the statement structs and initializing their basic properties (like position in the source code and the operation code).

3. **Defining a `Stmt` Interface:** The `Stmt` interface acts as a common type for all statement nodes. This allows the compiler to treat different statement types uniformly when iterating through and processing the code.

4. **Embedding `miniStmt` and `miniNode`:** The structs often embed `miniStmt` (which itself embeds `miniNode`). This is a form of code reuse, providing common fields like the source code position (`pos`) and the operation code (`op`) to all statement types. The `Init()` and `SetInit()` methods on `miniStmt` are for handling initialization statements that might precede the main statement (e.g., in `if init; condition {}`).

5. **Methods for Setting Properties:** Some structs have methods like `SetOp` to explicitly set or change the operation code, although often the operation code is set in the constructor.

**Inferred Go Language Features and Examples:**

Based on the defined structs, we can infer that this code is responsible for representing the following core Go language features:

* **Variable and Constant Declarations:** The `Decl` struct represents declarations.

   ```go
   // Assuming 's' is a *types.Sym representing the variable name "x"
   // and 't' is a *types.Type representing the type 'int'
   name := NewName(src.NoXPos, s)
   name.SetType(t)
   decl := NewDecl(src.NoXPos, ODCL, name)
   // This 'decl' would represent something like "var x int" or "const x = 10"
   ```

* **Assignments:** `AssignStmt`, `AssignListStmt`, and `AssignOpStmt` handle different assignment scenarios.

   ```go
   // Simple assignment: x = y
   // Assuming 'xNode' and 'yNode' are IR nodes representing the variables x and y
   assignStmt := NewAssignStmt(src.NoXPos, xNode, yNode)

   // Multi-value assignment: a, b := f()
   // Assuming 'aNode', 'bNode' are IR nodes for a and b, and 'fCall' is the IR node for the function call f()
   assignListStmt := NewAssignListStmt(src.NoXPos, OAS2FUNC, []Node{aNode, bNode}, []Node{fCall})

   // Assignment with operation: i += 1
   // Assuming 'iNode' and 'oneNode' are IR nodes for i and the constant 1
   assignOpStmt := NewAssignOpStmt(src.NoXPos, OADD, iNode, oneNode)
   ```
   **Assumption:** `xNode`, `yNode`, `aNode`, `bNode`, `fCall`, `iNode`, `oneNode` are already constructed `ir.Node` objects representing the respective expressions.

* **Control Flow Statements:** `BlockStmt`, `IfStmt`, `ForStmt`, `SwitchStmt`, `SelectStmt`, `ReturnStmt`, `BranchStmt` are all about controlling the execution flow.

   ```go
   // If statement: if x > 0 { println("positive") }
   // Assuming 'condNode' is the IR for 'x > 0', and 'bodyNodes' is a slice of IR nodes for the block
   ifStmt := NewIfStmt(src.NoXPos, condNode, bodyNodes, nil) // 'nil' for no else block

   // For loop: for i := 0; i < 10; i++ { println(i) }
   // Assuming 'initStmt' is the IR for 'i := 0', 'condNode' for 'i < 10', 'postStmt' for 'i++', and 'loopBody' for the loop's body
   forStmt := NewForStmt(src.NoXPos, initStmt, condNode, postStmt, loopBody, false)

   // Return statement: return result
   // Assuming 'resultNode' is the IR node representing the value to return
   returnStmt := NewReturnStmt(src.NoXPos, []Node{resultNode})

   // Break statement inside a loop
   breakStmt := NewBranchStmt(src.NoXPos, OBREAK, nil) // 'nil' if no label
   ```
   **Assumption:**  `condNode`, `bodyNodes`, `initStmt`, `postStmt`, `loopBody`, `resultNode` are pre-existing `ir.Node` objects.

* **`go` and `defer` Statements:** The `GoDeferStmt` handles these.

   ```go
   // Go statement: go func() { println("hello") }()
   // Assuming 'callNode' is the IR for the function call
   goStmt := NewGoDeferStmt(src.NoXPos, OGO, callNode)

   // Defer statement: defer file.Close()
   // Assuming 'callNode' is the IR for the method call
   deferStmt := NewGoDeferStmt(src.NoXPos, ODEFER, callNode)
   ```
   **Assumption:** `callNode` is an existing `ir.Node` representing the function or method call.

* **`for...range` Loops:**  The `RangeStmt` is for iterating over collections.

   ```go
   // Range loop: for i, v := range slice { println(i, v) }
   // Assuming 'keyNode' is the IR for 'i', 'valueNode' for 'v', 'sliceNode' for the slice, and 'rangeBody' for the loop's body
   rangeStmt := NewRangeStmt(src.NoXPos, keyNode, valueNode, sliceNode, rangeBody, false)
   ```
   **Assumption:** `keyNode`, `valueNode`, `sliceNode`, `rangeBody` are existing `ir.Node` objects.

* **`switch` and `select` Statements:** `SwitchStmt` and `SelectStmt` represent conditional branching based on values or communication.

   ```go
   // Switch statement: switch x { case 1: println("one") }
   // Assuming 'tagNode' is the IR for 'x', and 'caseClauses' is a slice of *CaseClause
   switchStmt := NewSwitchStmt(src.NoXPos, tagNode, caseClauses)

   // Select statement: select { case <-ch: println("received") }
   // Assuming 'commClauses' is a slice of *CommClause
   selectStmt := NewSelectStmt(src.NoXPos, commClauses)
   ```
   **Assumption:** `tagNode`, `caseClauses`, `commClauses` are appropriately constructed IR objects for the switch/select structure.

**Code Reasoning with Assumptions:**

The code works by defining a set of data structures that mirror the syntax and semantics of Go statements. The `New...Stmt` functions act as factories, creating these structures. The compiler, during its parsing and semantic analysis phases, will generate these IR nodes to represent the Go code it's processing.

**Example: Analyzing `AssignStmt`**

```go
// An AssignStmt is a simple assignment statement: X = Y.
// If Def is true, the assignment is a :=.
type AssignStmt struct {
	miniStmt
	X   Node
	Def bool
	Y   Node
}

func NewAssignStmt(pos src.XPos, x, y Node) *AssignStmt {
	n := &AssignStmt{X: x, Y: y}
	n.pos = pos
	n.op = OAS
	return n
}
```

**Assumption:** When the Go compiler encounters an assignment like `a = b` or `c := d`, it will:

1. Identify the left-hand side expression (`a` or `c`) and create an `ir.Node` representing it.
2. Identify the right-hand side expression (`b` or `d`) and create an `ir.Node` representing it.
3. Determine if it's a defining assignment (`:=`).
4. Call `NewAssignStmt` with the position information, the IR nodes for the left and right sides, and potentially set the `Def` field.

**Hypothetical Input:**  Go source code: `package main; func main() { x := 10 }`

**Hypothetical Output (for the assignment part):** The compiler would create an `AssignStmt` where:

* `pos` would point to the location of `x := 10` in the source.
* `X` would be an `ir.Name` node representing the variable `x`.
* `Def` would be `true`.
* `Y` would be an `ir.ConstExpr` node representing the constant `10`.
* `op` would be `OAS`.

**Command-Line Argument Handling:**

This specific code snippet (`stmt.go`) does **not** directly handle command-line arguments. It's part of the internal representation of the Go code. Command-line arguments for the Go compiler (like `-o`, `-gcflags`, etc.) are handled in other parts of the `cmd/compile` package, likely during the initial parsing and setup phases.

**Common Mistakes Users Might Make (Relating to the Represented Features):**

While this code is internal to the compiler, understanding how it represents statements can shed light on common user errors:

* **Incorrectly assuming the order of evaluation:**  For example, in `AssignListStmt`, the compiler needs to evaluate all right-hand side expressions before assigning to the left-hand side variables. Users might sometimes misunderstand this.

* **Shadowing variables:** When dealing with `Decl` and assignments, users might accidentally shadow variables in nested scopes, leading to unexpected behavior.

* **Infinite loops in `ForStmt`:**  Users might create `for` loops where the condition never becomes false.

* **Incorrect `break` or `continue` usage in loops:**  Misplacing `break` or `continue` can lead to unexpected control flow.

* **Forgetting `break` in `switch` statements (in languages where it's necessary):**  While Go doesn't require `break` by default, users coming from other languages might make this mistake or misunderstand the fallthrough behavior.

* **Misunderstanding `defer` execution order:**  Users might not fully grasp that `defer`red function calls execute in LIFO order when the surrounding function returns.

**In Summary:**

`go/src/cmd/compile/internal/ir/stmt.go` is a fundamental piece of the Go compiler. It defines the data structures used to represent Go statements in the compiler's internal representation. This representation is crucial for the subsequent phases of compilation, such as type checking, optimization, and code generation. Understanding this code provides insight into how the Go compiler understands and processes the structure of Go programs.

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ir/stmt.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmd/internal/src"
	"go/constant"
)

// A Decl is a declaration of a const, type, or var. (A declared func is a Func.)
type Decl struct {
	miniNode
	X *Name // the thing being declared
}

func NewDecl(pos src.XPos, op Op, x *Name) *Decl {
	n := &Decl{X: x}
	n.pos = pos
	switch op {
	default:
		panic("invalid Decl op " + op.String())
	case ODCL:
		n.op = op
	}
	return n
}

func (*Decl) isStmt() {}

// A Stmt is a Node that can appear as a statement.
// This includes statement-like expressions such as f().
//
// (It's possible it should include <-c, but that would require
// splitting ORECV out of UnaryExpr, which hasn't yet been
// necessary. Maybe instead we will introduce ExprStmt at
// some point.)
type Stmt interface {
	Node
	isStmt()
}

// A miniStmt is a miniNode with extra fields common to statements.
type miniStmt struct {
	miniNode
	init Nodes
}

func (*miniStmt) isStmt() {}

func (n *miniStmt) Init() Nodes     { return n.init }
func (n *miniStmt) SetInit(x Nodes) { n.init = x }
func (n *miniStmt) PtrInit() *Nodes { return &n.init }

// An AssignListStmt is an assignment statement with
// more than one item on at least one side: Lhs = Rhs.
// If Def is true, the assignment is a :=.
type AssignListStmt struct {
	miniStmt
	Lhs Nodes
	Def bool
	Rhs Nodes
}

func NewAssignListStmt(pos src.XPos, op Op, lhs, rhs []Node) *AssignListStmt {
	n := &AssignListStmt{}
	n.pos = pos
	n.SetOp(op)
	n.Lhs = lhs
	n.Rhs = rhs
	return n
}

func (n *AssignListStmt) SetOp(op Op) {
	switch op {
	default:
		panic(n.no("SetOp " + op.String()))
	case OAS2, OAS2DOTTYPE, OAS2FUNC, OAS2MAPR, OAS2RECV, OSELRECV2:
		n.op = op
	}
}

// An AssignStmt is a simple assignment statement: X = Y.
// If Def is true, the assignment is a :=.
type AssignStmt struct {
	miniStmt
	X   Node
	Def bool
	Y   Node
}

func NewAssignStmt(pos src.XPos, x, y Node) *AssignStmt {
	n := &AssignStmt{X: x, Y: y}
	n.pos = pos
	n.op = OAS
	return n
}

func (n *AssignStmt) SetOp(op Op) {
	switch op {
	default:
		panic(n.no("SetOp " + op.String()))
	case OAS:
		n.op = op
	}
}

// An AssignOpStmt is an AsOp= assignment statement: X AsOp= Y.
type AssignOpStmt struct {
	miniStmt
	X      Node
	AsOp   Op // OADD etc
	Y      Node
	IncDec bool // actually ++ or --
}

func NewAssignOpStmt(pos src.XPos, asOp Op, x, y Node) *AssignOpStmt {
	n := &AssignOpStmt{AsOp: asOp, X: x, Y: y}
	n.pos = pos
	n.op = OASOP
	return n
}

// A BlockStmt is a block: { List }.
type BlockStmt struct {
	miniStmt
	List Nodes
}

func NewBlockStmt(pos src.XPos, list []Node) *BlockStmt {
	n := &BlockStmt{}
	n.pos = pos
	if !pos.IsKnown() {
		n.pos = base.Pos
		if len(list) > 0 {
			n.pos = list[0].Pos()
		}
	}
	n.op = OBLOCK
	n.List = list
	return n
}

// A BranchStmt is a break, continue, fallthrough, or goto statement.
type BranchStmt struct {
	miniStmt
	Label *types.Sym // label if present
}

func NewBranchStmt(pos src.XPos, op Op, label *types.Sym) *BranchStmt {
	switch op {
	case OBREAK, OCONTINUE, OFALL, OGOTO:
		// ok
	default:
		panic("NewBranch " + op.String())
	}
	n := &BranchStmt{Label: label}
	n.pos = pos
	n.op = op
	return n
}

func (n *BranchStmt) SetOp(op Op) {
	switch op {
	default:
		panic(n.no("SetOp " + op.String()))
	case OBREAK, OCONTINUE, OFALL, OGOTO:
		n.op = op
	}
}

func (n *BranchStmt) Sym() *types.Sym { return n.Label }

// A CaseClause is a case statement in a switch or select: case List: Body.
type CaseClause struct {
	miniStmt
	Var  *Name // declared variable for this case in type switch
	List Nodes // list of expressions for switch, early select

	// RTypes is a list of RType expressions, which are copied to the
	// corresponding OEQ nodes that are emitted when switch statements
	// are desugared. RTypes[i] must be non-nil if the emitted
	// comparison for List[i] will be a mixed interface/concrete
	// comparison; see reflectdata.CompareRType for details.
	//
	// Because mixed interface/concrete switch cases are rare, we allow
	// len(RTypes) < len(List). Missing entries are implicitly nil.
	RTypes Nodes

	Body Nodes
}

func NewCaseStmt(pos src.XPos, list, body []Node) *CaseClause {
	n := &CaseClause{List: list, Body: body}
	n.pos = pos
	n.op = OCASE
	return n
}

type CommClause struct {
	miniStmt
	Comm Node // communication case
	Body Nodes
}

func NewCommStmt(pos src.XPos, comm Node, body []Node) *CommClause {
	n := &CommClause{Comm: comm, Body: body}
	n.pos = pos
	n.op = OCASE
	return n
}

// A ForStmt is a non-range for loop: for Init; Cond; Post { Body }
type ForStmt struct {
	miniStmt
	Label        *types.Sym
	Cond         Node
	Post         Node
	Body         Nodes
	DistinctVars bool
}

func NewForStmt(pos src.XPos, init Node, cond, post Node, body []Node, distinctVars bool) *ForStmt {
	n := &ForStmt{Cond: cond, Post: post}
	n.pos = pos
	n.op = OFOR
	if init != nil {
		n.init = []Node{init}
	}
	n.Body = body
	n.DistinctVars = distinctVars
	return n
}

// A GoDeferStmt is a go or defer statement: go Call / defer Call.
//
// The two opcodes use a single syntax because the implementations
// are very similar: both are concerned with saving Call and running it
// in a different context (a separate goroutine or a later time).
type GoDeferStmt struct {
	miniStmt
	Call    Node
	DeferAt Expr
}

func NewGoDeferStmt(pos src.XPos, op Op, call Node) *GoDeferStmt {
	n := &GoDeferStmt{Call: call}
	n.pos = pos
	switch op {
	case ODEFER, OGO:
		n.op = op
	default:
		panic("NewGoDeferStmt " + op.String())
	}
	return n
}

// An IfStmt is a return statement: if Init; Cond { Body } else { Else }.
type IfStmt struct {
	miniStmt
	Cond   Node
	Body   Nodes
	Else   Nodes
	Likely bool // code layout hint
}

func NewIfStmt(pos src.XPos, cond Node, body, els []Node) *IfStmt {
	n := &IfStmt{Cond: cond}
	n.pos = pos
	n.op = OIF
	n.Body = body
	n.Else = els
	return n
}

// A JumpTableStmt is used to implement switches. Its semantics are:
//
//	tmp := jt.Idx
//	if tmp == Cases[0] goto Targets[0]
//	if tmp == Cases[1] goto Targets[1]
//	...
//	if tmp == Cases[n] goto Targets[n]
//
// Note that a JumpTableStmt is more like a multiway-goto than
// a multiway-if. In particular, the case bodies are just
// labels to jump to, not full Nodes lists.
type JumpTableStmt struct {
	miniStmt

	// Value used to index the jump table.
	// We support only integer types that
	// are at most the size of a uintptr.
	Idx Node

	// If Idx is equal to Cases[i], jump to Targets[i].
	// Cases entries must be distinct and in increasing order.
	// The length of Cases and Targets must be equal.
	Cases   []constant.Value
	Targets []*types.Sym
}

func NewJumpTableStmt(pos src.XPos, idx Node) *JumpTableStmt {
	n := &JumpTableStmt{Idx: idx}
	n.pos = pos
	n.op = OJUMPTABLE
	return n
}

// An InterfaceSwitchStmt is used to implement type switches.
// Its semantics are:
//
//	if RuntimeType implements Descriptor.Cases[0] {
//	    Case, Itab = 0, itab<RuntimeType, Descriptor.Cases[0]>
//	} else if RuntimeType implements Descriptor.Cases[1] {
//	    Case, Itab = 1, itab<RuntimeType, Descriptor.Cases[1]>
//	...
//	} else if RuntimeType implements Descriptor.Cases[N-1] {
//	    Case, Itab = N-1, itab<RuntimeType, Descriptor.Cases[N-1]>
//	} else {
//	    Case, Itab = len(cases), nil
//	}
//
// RuntimeType must be a non-nil *runtime._type.
// Hash must be the hash field of RuntimeType (or its copy loaded from an itab).
// Descriptor must represent an abi.InterfaceSwitch global variable.
type InterfaceSwitchStmt struct {
	miniStmt

	Case        Node
	Itab        Node
	RuntimeType Node
	Hash        Node
	Descriptor  *obj.LSym
}

func NewInterfaceSwitchStmt(pos src.XPos, case_, itab, runtimeType, hash Node, descriptor *obj.LSym) *InterfaceSwitchStmt {
	n := &InterfaceSwitchStmt{
		Case:        case_,
		Itab:        itab,
		RuntimeType: runtimeType,
		Hash:        hash,
		Descriptor:  descriptor,
	}
	n.pos = pos
	n.op = OINTERFACESWITCH
	return n
}

// An InlineMarkStmt is a marker placed just before an inlined body.
type InlineMarkStmt struct {
	miniStmt
	Index int64
}

func NewInlineMarkStmt(pos src.XPos, index int64) *InlineMarkStmt {
	n := &InlineMarkStmt{Index: index}
	n.pos = pos
	n.op = OINLMARK
	return n
}

func (n *InlineMarkStmt) Offset() int64     { return n.Index }
func (n *InlineMarkStmt) SetOffset(x int64) { n.Index = x }

// A LabelStmt is a label statement (just the label, not including the statement it labels).
type LabelStmt struct {
	miniStmt
	Label *types.Sym // "Label:"
}

func NewLabelStmt(pos src.XPos, label *types.Sym) *LabelStmt {
	n := &LabelStmt{Label: label}
	n.pos = pos
	n.op = OLABEL
	return n
}

func (n *LabelStmt) Sym() *types.Sym { return n.Label }

// A RangeStmt is a range loop: for Key, Value = range X { Body }
type RangeStmt struct {
	miniStmt
	Label        *types.Sym
	Def          bool
	X            Node
	RType        Node `mknode:"-"` // see reflectdata/helpers.go
	Key          Node
	Value        Node
	Body         Nodes
	DistinctVars bool
	Prealloc     *Name

	// When desugaring the RangeStmt during walk, the assignments to Key
	// and Value may require OCONVIFACE operations. If so, these fields
	// will be copied to their respective ConvExpr fields.
	KeyTypeWord   Node `mknode:"-"`
	KeySrcRType   Node `mknode:"-"`
	ValueTypeWord Node `mknode:"-"`
	ValueSrcRType Node `mknode:"-"`
}

func NewRangeStmt(pos src.XPos, key, value, x Node, body []Node, distinctVars bool) *RangeStmt {
	n := &RangeStmt{X: x, Key: key, Value: value}
	n.pos = pos
	n.op = ORANGE
	n.Body = body
	n.DistinctVars = distinctVars
	return n
}

// A ReturnStmt is a return statement.
type ReturnStmt struct {
	miniStmt
	Results Nodes // return list
}

func NewReturnStmt(pos src.XPos, results []Node) *ReturnStmt {
	n := &ReturnStmt{}
	n.pos = pos
	n.op = ORETURN
	n.Results = results
	return n
}

// A SelectStmt is a block: { Cases }.
type SelectStmt struct {
	miniStmt
	Label *types.Sym
	Cases []*CommClause

	// TODO(rsc): Instead of recording here, replace with a block?
	Compiled Nodes // compiled form, after walkSelect
}

func NewSelectStmt(pos src.XPos, cases []*CommClause) *SelectStmt {
	n := &SelectStmt{Cases: cases}
	n.pos = pos
	n.op = OSELECT
	return n
}

// A SendStmt is a send statement: X <- Y.
type SendStmt struct {
	miniStmt
	Chan  Node
	Value Node
}

func NewSendStmt(pos src.XPos, ch, value Node) *SendStmt {
	n := &SendStmt{Chan: ch, Value: value}
	n.pos = pos
	n.op = OSEND
	return n
}

// A SwitchStmt is a switch statement: switch Init; Tag { Cases }.
type SwitchStmt struct {
	miniStmt
	Tag   Node
	Cases []*CaseClause
	Label *types.Sym

	// TODO(rsc): Instead of recording here, replace with a block?
	Compiled Nodes // compiled form, after walkSwitch
}

func NewSwitchStmt(pos src.XPos, tag Node, cases []*CaseClause) *SwitchStmt {
	n := &SwitchStmt{Tag: tag, Cases: cases}
	n.pos = pos
	n.op = OSWITCH
	return n
}

// A TailCallStmt is a tail call statement, which is used for back-end
// code generation to jump directly to another function entirely.
type TailCallStmt struct {
	miniStmt
	Call *CallExpr // the underlying call
}

func NewTailCallStmt(pos src.XPos, call *CallExpr) *TailCallStmt {
	n := &TailCallStmt{Call: call}
	n.pos = pos
	n.op = OTAILCALL
	return n
}

// A TypeSwitchGuard is the [Name :=] X.(type) in a type switch.
type TypeSwitchGuard struct {
	miniNode
	Tag  *Ident
	X    Node
	Used bool
}

func NewTypeSwitchGuard(pos src.XPos, tag *Ident, x Node) *TypeSwitchGuard {
	n := &TypeSwitchGuard{Tag: tag, X: x}
	n.pos = pos
	n.op = OTYPESW
	return n
}

"""



```