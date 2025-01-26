Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for a description of the code's functionality, identification of the Go feature it implements, an illustrative example, information on command-line arguments (if applicable), and common pitfalls.

2. **Initial Scan and Identification of Key Areas:**  A quick skim reveals keywords like `package parse`, `type Node interface`, `type NodeType int`, and various structs like `ListNode`, `TextNode`, `IfNode`, etc. This immediately suggests the code is involved in *parsing* something and representing it as a tree structure. The `template` package name in the path further hints that it's related to Go templates.

3. **Focus on the `Node` Interface:** The `Node` interface is central. It defines the basic building blocks of the parse tree. Understanding its methods (`Type`, `String`, `Copy`, `Position`, `tree`, `writeTo`) is crucial. The unexported `tree()` method is a key detail, ensuring that only types within this package can implement the `Node` interface.

4. **Examine `NodeType` and the Constants:** The `NodeType` enum and its associated constants (`NodeText`, `NodeAction`, `NodeIf`, etc.) provide the taxonomy of the parse tree elements. This is where the different kinds of template constructs are categorized.

5. **Analyze Concrete Node Types (Structs):**  Go through the structs like `ListNode`, `TextNode`, `ActionNode`, `IfNode`, etc. For each struct:
    * **Identify its purpose:** What kind of template element does it represent?  The struct name often gives this away (e.g., `TextNode` for plain text, `IfNode` for `if` blocks).
    * **Examine its fields:** What data does it hold?  This helps understand the information captured during parsing (e.g., `TextNode` has `Text`, `IfNode` has `Pipe`, `List`, `ElseList`).
    * **Look at the methods:**  Pay attention to `String()` and `writeTo()`. These are responsible for converting the node back into a string representation, which is important for debugging or output. The `Copy()` method indicates the ability to create independent copies of the nodes.

6. **Identify Core Functionality:** Based on the node types, it becomes clear that this code is responsible for representing the structure of Go templates. It can handle:
    * Plain text (`TextNode`)
    * Actions/expressions within `{{ ... }}` (`ActionNode`, `PipeNode`, `CommandNode`)
    * Control structures (`IfNode`, `RangeNode`, `WithNode`)
    * Template invocations (`TemplateNode`)
    * Variables, identifiers, constants (`VariableNode`, `IdentifierNode`, `BoolNode`, `NumberNode`, `StringNode`)
    * Comments (`CommentNode`)
    * Break and Continue statements within loops (`BreakNode`, `ContinueNode`)

7. **Infer the Go Feature:**  Given the context of templates and the parsing of constructs like `{{ if ... }}`, `{{ range ... }}`, and `{{ template ... }}`, the core Go feature being implemented is **text/template parsing**.

8. **Construct an Illustrative Example:**  Create a simple template string that utilizes some of the identified node types (e.g., text, an `if` condition, a variable). Then, write Go code that uses the `text/template/parse` package (even though we don't have the *parser* code here, we can illustrate how the *nodes* would be used after parsing). Crucially, *assume* a parsing function exists that would return the root `ListNode`.

9. **Address Command-Line Arguments:**  Scan the code for any explicit handling of command-line arguments. In this snippet, there's none. Therefore, the answer is that this specific code doesn't handle command-line arguments. The broader `text/template` package *might*, but this specific file doesn't.

10. **Identify Potential Pitfalls:** Think about how a user might interact with the *results* of this parsing. Common mistakes might involve:
    * Incorrectly assuming the `Node` interface can be implemented outside the `parse` package due to the unexported `tree()` method.
    * Forgetting to handle different `NodeType` values when traversing the parse tree.
    * Issues related to the `Pos` information (byte positions) if manually manipulating the parsed structure.

11. **Structure the Answer:** Organize the findings into clear sections as requested: functionality, Go feature, example, command-line arguments, and common mistakes. Use clear and concise language. Use code blocks for the Go example.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is about general parsing.
* **Correction:** The `template` in the path is a strong indicator. The specific node types solidify this.
* **Initial thought:** Focus heavily on the *how* of parsing.
* **Correction:** The provided code is about the *representation* of the parsed template (the nodes). The parsing logic itself isn't in this snippet. Adjust the focus accordingly.
* **Initial thought:**  Are there complex interactions between nodes?
* **Refinement:** The code provides the basic building blocks. The relationships are implicit in the tree structure built by the parser (which isn't shown). Focus on the individual node roles.

By following these steps, including the self-correction, you can systematically analyze the code snippet and arrive at a comprehensive and accurate answer.
这段代码是 Go 语言标准库 `text/template/parse` 包中的 `node.go` 文件的一部分。它定义了用于表示模板解析树的各种**节点类型 (Node Types)** 和 **节点结构体 (Node Structures)**。

**功能概览:**

1. **定义了 `Node` 接口:**  这是一个核心接口，所有表示模板语法元素的类型都必须实现这个接口。它定义了获取节点类型、字符串表示、深拷贝、位置信息、所属的语法树以及将自身写入字符串构建器的方法。
2. **定义了 `NodeType` 类型:**  这是一个枚举类型，用于标识不同类型语法树节点，例如文本、动作、控制语句（if、range、with）、变量、常量等。
3. **定义了各种具体的节点结构体:**  每种 `NodeType` 都有对应的结构体来存储节点的具体信息，例如：
    * `TextNode`:  存储纯文本内容。
    * `ActionNode`:  存储用 `{{` 和 `}}` 包围的动作（例如变量求值）。
    * `IfNode`:  存储 `{{if}}` 语句的信息，包括条件、执行体和可选的 `{{else}}` 执行体。
    * `RangeNode`:  存储 `{{range}}` 循环语句的信息。
    * `WithNode`:  存储 `{{with}}` 语句的信息。
    * `VariableNode`: 存储变量名。
    * `IdentifierNode`: 存储标识符（通常是函数名）。
    * `StringNode`: 存储字符串常量。
    * `NumberNode`: 存储数字常量。
    * ...以及其他表示不同模板语法元素的节点。
4. **提供了创建新节点的方法:**  每个节点结构体通常都有一个关联的 `newXxx` 函数（例如 `t.newText`，`t.newIf`），用于创建该类型的节点实例。这些方法通常与 `Tree` 结构体关联（虽然这段代码中没有完整展示 `Tree` 的定义）。
5. **实现了 `Node` 接口的方法:**  每个节点结构体都实现了 `Node` 接口中定义的方法，例如 `Type()`, `String()`, `Copy()`, `Position()`, `tree()`, `writeTo()`。
6. **支持节点的深拷贝:**  `Copy()` 方法允许创建节点的完整副本，这在修改或分析语法树时非常重要，可以避免修改原始树。

**推理 Go 语言功能实现：**

这段代码是 `text/template` 包中**模板解析器**的核心组成部分。它定义了抽象语法树 (Abstract Syntax Tree, AST) 的结构。当 `text/template` 包解析一个模板字符串时，它会将模板的语法结构转换成由这些节点组成的树形结构。这个 AST 随后会被用于执行模板，根据提供的数据动态生成输出。

**Go 代码举例说明:**

假设我们有一个简单的模板字符串 `{{if .Condition}}Hello, {{.Name}}!{{end}}`。解析器会将其转换为以下节点结构（简化表示）：

```go
// 假设已经存在一个解析器和 Tree 结构体
package main

import (
	"fmt"
	"strings"
	"text/template/parse"
)

func main() {
	// 模拟解析过程，实际解析由 text/template/parse 包完成
	// 这里我们手动构建一个简化的 AST

	text1 := &parse.TextNode{Text: []byte("Hello, ")}
	field := &parse.FieldNode{Ident: []string{"Name"}}
	action := &parse.ActionNode{Pipe: &parse.PipeNode{Cmds: []*parse.CommandNode{{Args: []parse.Node{field}}}}}
	text2 := &parse.TextNode{Text: []byte("!")}

	ifNode := &parse.IfNode{
		BranchNode: parse.BranchNode{
			Pipe: &parse.PipeNode{
				Cmds: []*parse.CommandNode{{
					Args: []parse.Node{&parse.FieldNode{Ident: []string{"Condition"}}},
				}}},
			List: &parse.ListNode{Nodes: []parse.Node{text1, action, text2}},
		},
	}

	root := &parse.ListNode{Nodes: []parse.Node{ifNode}}

	// 遍历并打印 AST (简化)
	var sb strings.Builder
	printNode(root, &sb)
	fmt.Println(sb.String())
}

func printNode(node parse.Node, sb *strings.Builder) {
	switch n := node.(type) {
	case *parse.ListNode:
		sb.WriteString("ListNode{\n")
		for _, child := range n.Nodes {
			printNode(child, sb)
		}
		sb.WriteString("}\n")
	case *parse.IfNode:
		sb.WriteString("IfNode{\n")
		sb.WriteString("  Pipe: ")
		printNode(n.Pipe, sb)
		sb.WriteString("  List: ")
		printNode(n.List, sb)
		if n.ElseList != nil {
			sb.WriteString("  ElseList: ")
			printNode(n.ElseList, sb)
		}
		sb.WriteString("}\n")
	case *parse.PipeNode:
		sb.WriteString("PipeNode{\n")
		for _, cmd := range n.Cmds {
			printNode(cmd, sb)
		}
		sb.WriteString("}\n")
	case *parse.CommandNode:
		sb.WriteString("CommandNode{\n  Args: ")
		for _, arg := range n.Args {
			printNode(arg, sb)
		}
		sb.WriteString("}\n")
	case *parse.TextNode:
		sb.WriteString(fmt.Sprintf("TextNode{Text: %q}\n", n.Text))
	case *parse.FieldNode:
		sb.WriteString(fmt.Sprintf("FieldNode{Ident: %v}\n", n.Ident))
	case *parse.ActionNode:
		sb.WriteString("ActionNode{\n  Pipe: ")
		printNode(n.Pipe, sb)
		sb.WriteString("}\n")
	default:
		sb.WriteString(fmt.Sprintf("UnknownNode{%T}\n", n))
	}
}
```

**假设的输入与输出:**

**输入 (模板字符串):** `{{if .Condition}}Hello, {{.Name}}!{{end}}`

**输出 (简化的 AST 结构打印):**

```
ListNode{
IfNode{
  Pipe: PipeNode{
CommandNode{
  Args: FieldNode{Ident: [Condition]}
}}
  List: ListNode{
TextNode{Text: "Hello, "}
ActionNode{
  Pipe: PipeNode{
CommandNode{
  Args: FieldNode{Ident: [Name]}
}}
}
TextNode{Text: "!"}
}
}
}
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。`text/template` 包的使用者通常会在自己的程序中解析模板并提供数据。例如：

```go
package main

import (
	"os"
	"text/template"
)

type Data struct {
	Condition bool
	Name      string
}

func main() {
	tmplStr := `{{if .Condition}}Hello, {{.Name}}!{{end}}`
	tmpl, err := template.New("greeting").Parse(tmplStr)
	if err != nil {
		panic(err)
	}

	data := Data{Condition: true, Name: "World"}
	err = tmpl.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
```

在这个例子中，没有直接的命令行参数被 `node.go` 处理。命令行参数可能会影响模板的内容或用于指定模板文件的路径，但这需要在调用 `text/template` 包的程序中进行处理。

**使用者易犯错的点:**

1. **尝试在 `parse` 包外部创建 `Node` 接口的实现:**  `Node` 接口包含一个未导出的方法 `tree() *Tree`。这意味着只有 `parse` 包内部的类型才能真正实现这个接口。如果尝试在外部创建 `Node` 的实现，Go 编译器会报错。

   ```go
   // 在 parse 包外部尝试实现 Node 接口 (错误示例)
   package mypackage

   import "text/template/parse"

   type MyNode struct {
       parse.NodeType
       // ... 其他字段
   }

   func (m *MyNode) Type() parse.NodeType { return m.NodeType }
   func (m *MyNode) String() string         { return "my node" }
   func (m *MyNode) Copy() parse.Node       { return &MyNode{} }
   func (m *MyNode) Position() parse.Pos   { return 0 }
   func (m *MyNode) tree() *parse.Tree     { return nil } // 无法访问 parse.Tree
   func (m *MyNode) writeTo(*strings.Builder) {}

   func main() {
       var n parse.Node = &MyNode{} // 编译错误
       println(n.String())
   }
   ```

   **错误信息:**  `cannot use &MyNode{} (value of type *MyNode) as parse.Node value in variable declaration: *MyNode does not implement parse.Node (missing method tree)`

   这个错误提示说明 `MyNode` 没有实现 `parse.Node` 接口，因为它无法访问并实现未导出的 `tree()` 方法。

总而言之，`go/src/text/template/parse/node.go` 定义了模板解析树的结构，是 `text/template` 包实现模板解析和执行的基础。使用者通常不会直接与这些节点类型交互，而是使用 `text/template` 包提供的更高级的 API 来解析和执行模板。

Prompt: 
```
这是路径为go/src/text/template/parse/node.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Parse nodes.

package parse

import (
	"fmt"
	"strconv"
	"strings"
)

var textFormat = "%s" // Changed to "%q" in tests for better error messages.

// A Node is an element in the parse tree. The interface is trivial.
// The interface contains an unexported method so that only
// types local to this package can satisfy it.
type Node interface {
	Type() NodeType
	String() string
	// Copy does a deep copy of the Node and all its components.
	// To avoid type assertions, some XxxNodes also have specialized
	// CopyXxx methods that return *XxxNode.
	Copy() Node
	Position() Pos // byte position of start of node in full original input string
	// tree returns the containing *Tree.
	// It is unexported so all implementations of Node are in this package.
	tree() *Tree
	// writeTo writes the String output to the builder.
	writeTo(*strings.Builder)
}

// NodeType identifies the type of a parse tree node.
type NodeType int

// Pos represents a byte position in the original input text from which
// this template was parsed.
type Pos int

func (p Pos) Position() Pos {
	return p
}

// Type returns itself and provides an easy default implementation
// for embedding in a Node. Embedded in all non-trivial Nodes.
func (t NodeType) Type() NodeType {
	return t
}

const (
	NodeText       NodeType = iota // Plain text.
	NodeAction                     // A non-control action such as a field evaluation.
	NodeBool                       // A boolean constant.
	NodeChain                      // A sequence of field accesses.
	NodeCommand                    // An element of a pipeline.
	NodeDot                        // The cursor, dot.
	nodeElse                       // An else action. Not added to tree.
	nodeEnd                        // An end action. Not added to tree.
	NodeField                      // A field or method name.
	NodeIdentifier                 // An identifier; always a function name.
	NodeIf                         // An if action.
	NodeList                       // A list of Nodes.
	NodeNil                        // An untyped nil constant.
	NodeNumber                     // A numerical constant.
	NodePipe                       // A pipeline of commands.
	NodeRange                      // A range action.
	NodeString                     // A string constant.
	NodeTemplate                   // A template invocation action.
	NodeVariable                   // A $ variable.
	NodeWith                       // A with action.
	NodeComment                    // A comment.
	NodeBreak                      // A break action.
	NodeContinue                   // A continue action.
)

// Nodes.

// ListNode holds a sequence of nodes.
type ListNode struct {
	NodeType
	Pos
	tr    *Tree
	Nodes []Node // The element nodes in lexical order.
}

func (t *Tree) newList(pos Pos) *ListNode {
	return &ListNode{tr: t, NodeType: NodeList, Pos: pos}
}

func (l *ListNode) append(n Node) {
	l.Nodes = append(l.Nodes, n)
}

func (l *ListNode) tree() *Tree {
	return l.tr
}

func (l *ListNode) String() string {
	var sb strings.Builder
	l.writeTo(&sb)
	return sb.String()
}

func (l *ListNode) writeTo(sb *strings.Builder) {
	for _, n := range l.Nodes {
		n.writeTo(sb)
	}
}

func (l *ListNode) CopyList() *ListNode {
	if l == nil {
		return l
	}
	n := l.tr.newList(l.Pos)
	for _, elem := range l.Nodes {
		n.append(elem.Copy())
	}
	return n
}

func (l *ListNode) Copy() Node {
	return l.CopyList()
}

// TextNode holds plain text.
type TextNode struct {
	NodeType
	Pos
	tr   *Tree
	Text []byte // The text; may span newlines.
}

func (t *Tree) newText(pos Pos, text string) *TextNode {
	return &TextNode{tr: t, NodeType: NodeText, Pos: pos, Text: []byte(text)}
}

func (t *TextNode) String() string {
	return fmt.Sprintf(textFormat, t.Text)
}

func (t *TextNode) writeTo(sb *strings.Builder) {
	sb.WriteString(t.String())
}

func (t *TextNode) tree() *Tree {
	return t.tr
}

func (t *TextNode) Copy() Node {
	return &TextNode{tr: t.tr, NodeType: NodeText, Pos: t.Pos, Text: append([]byte{}, t.Text...)}
}

// CommentNode holds a comment.
type CommentNode struct {
	NodeType
	Pos
	tr   *Tree
	Text string // Comment text.
}

func (t *Tree) newComment(pos Pos, text string) *CommentNode {
	return &CommentNode{tr: t, NodeType: NodeComment, Pos: pos, Text: text}
}

func (c *CommentNode) String() string {
	var sb strings.Builder
	c.writeTo(&sb)
	return sb.String()
}

func (c *CommentNode) writeTo(sb *strings.Builder) {
	sb.WriteString("{{")
	sb.WriteString(c.Text)
	sb.WriteString("}}")
}

func (c *CommentNode) tree() *Tree {
	return c.tr
}

func (c *CommentNode) Copy() Node {
	return &CommentNode{tr: c.tr, NodeType: NodeComment, Pos: c.Pos, Text: c.Text}
}

// PipeNode holds a pipeline with optional declaration
type PipeNode struct {
	NodeType
	Pos
	tr       *Tree
	Line     int             // The line number in the input. Deprecated: Kept for compatibility.
	IsAssign bool            // The variables are being assigned, not declared.
	Decl     []*VariableNode // Variables in lexical order.
	Cmds     []*CommandNode  // The commands in lexical order.
}

func (t *Tree) newPipeline(pos Pos, line int, vars []*VariableNode) *PipeNode {
	return &PipeNode{tr: t, NodeType: NodePipe, Pos: pos, Line: line, Decl: vars}
}

func (p *PipeNode) append(command *CommandNode) {
	p.Cmds = append(p.Cmds, command)
}

func (p *PipeNode) String() string {
	var sb strings.Builder
	p.writeTo(&sb)
	return sb.String()
}

func (p *PipeNode) writeTo(sb *strings.Builder) {
	if len(p.Decl) > 0 {
		for i, v := range p.Decl {
			if i > 0 {
				sb.WriteString(", ")
			}
			v.writeTo(sb)
		}
		if p.IsAssign {
			sb.WriteString(" = ")
		} else {
			sb.WriteString(" := ")
		}
	}
	for i, c := range p.Cmds {
		if i > 0 {
			sb.WriteString(" | ")
		}
		c.writeTo(sb)
	}
}

func (p *PipeNode) tree() *Tree {
	return p.tr
}

func (p *PipeNode) CopyPipe() *PipeNode {
	if p == nil {
		return p
	}
	vars := make([]*VariableNode, len(p.Decl))
	for i, d := range p.Decl {
		vars[i] = d.Copy().(*VariableNode)
	}
	n := p.tr.newPipeline(p.Pos, p.Line, vars)
	n.IsAssign = p.IsAssign
	for _, c := range p.Cmds {
		n.append(c.Copy().(*CommandNode))
	}
	return n
}

func (p *PipeNode) Copy() Node {
	return p.CopyPipe()
}

// ActionNode holds an action (something bounded by delimiters).
// Control actions have their own nodes; ActionNode represents simple
// ones such as field evaluations and parenthesized pipelines.
type ActionNode struct {
	NodeType
	Pos
	tr   *Tree
	Line int       // The line number in the input. Deprecated: Kept for compatibility.
	Pipe *PipeNode // The pipeline in the action.
}

func (t *Tree) newAction(pos Pos, line int, pipe *PipeNode) *ActionNode {
	return &ActionNode{tr: t, NodeType: NodeAction, Pos: pos, Line: line, Pipe: pipe}
}

func (a *ActionNode) String() string {
	var sb strings.Builder
	a.writeTo(&sb)
	return sb.String()
}

func (a *ActionNode) writeTo(sb *strings.Builder) {
	sb.WriteString("{{")
	a.Pipe.writeTo(sb)
	sb.WriteString("}}")
}

func (a *ActionNode) tree() *Tree {
	return a.tr
}

func (a *ActionNode) Copy() Node {
	return a.tr.newAction(a.Pos, a.Line, a.Pipe.CopyPipe())
}

// CommandNode holds a command (a pipeline inside an evaluating action).
type CommandNode struct {
	NodeType
	Pos
	tr   *Tree
	Args []Node // Arguments in lexical order: Identifier, field, or constant.
}

func (t *Tree) newCommand(pos Pos) *CommandNode {
	return &CommandNode{tr: t, NodeType: NodeCommand, Pos: pos}
}

func (c *CommandNode) append(arg Node) {
	c.Args = append(c.Args, arg)
}

func (c *CommandNode) String() string {
	var sb strings.Builder
	c.writeTo(&sb)
	return sb.String()
}

func (c *CommandNode) writeTo(sb *strings.Builder) {
	for i, arg := range c.Args {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if arg, ok := arg.(*PipeNode); ok {
			sb.WriteByte('(')
			arg.writeTo(sb)
			sb.WriteByte(')')
			continue
		}
		arg.writeTo(sb)
	}
}

func (c *CommandNode) tree() *Tree {
	return c.tr
}

func (c *CommandNode) Copy() Node {
	if c == nil {
		return c
	}
	n := c.tr.newCommand(c.Pos)
	for _, c := range c.Args {
		n.append(c.Copy())
	}
	return n
}

// IdentifierNode holds an identifier.
type IdentifierNode struct {
	NodeType
	Pos
	tr    *Tree
	Ident string // The identifier's name.
}

// NewIdentifier returns a new [IdentifierNode] with the given identifier name.
func NewIdentifier(ident string) *IdentifierNode {
	return &IdentifierNode{NodeType: NodeIdentifier, Ident: ident}
}

// SetPos sets the position. [NewIdentifier] is a public method so we can't modify its signature.
// Chained for convenience.
// TODO: fix one day?
func (i *IdentifierNode) SetPos(pos Pos) *IdentifierNode {
	i.Pos = pos
	return i
}

// SetTree sets the parent tree for the node. [NewIdentifier] is a public method so we can't modify its signature.
// Chained for convenience.
// TODO: fix one day?
func (i *IdentifierNode) SetTree(t *Tree) *IdentifierNode {
	i.tr = t
	return i
}

func (i *IdentifierNode) String() string {
	return i.Ident
}

func (i *IdentifierNode) writeTo(sb *strings.Builder) {
	sb.WriteString(i.String())
}

func (i *IdentifierNode) tree() *Tree {
	return i.tr
}

func (i *IdentifierNode) Copy() Node {
	return NewIdentifier(i.Ident).SetTree(i.tr).SetPos(i.Pos)
}

// VariableNode holds a list of variable names, possibly with chained field
// accesses. The dollar sign is part of the (first) name.
type VariableNode struct {
	NodeType
	Pos
	tr    *Tree
	Ident []string // Variable name and fields in lexical order.
}

func (t *Tree) newVariable(pos Pos, ident string) *VariableNode {
	return &VariableNode{tr: t, NodeType: NodeVariable, Pos: pos, Ident: strings.Split(ident, ".")}
}

func (v *VariableNode) String() string {
	var sb strings.Builder
	v.writeTo(&sb)
	return sb.String()
}

func (v *VariableNode) writeTo(sb *strings.Builder) {
	for i, id := range v.Ident {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(id)
	}
}

func (v *VariableNode) tree() *Tree {
	return v.tr
}

func (v *VariableNode) Copy() Node {
	return &VariableNode{tr: v.tr, NodeType: NodeVariable, Pos: v.Pos, Ident: append([]string{}, v.Ident...)}
}

// DotNode holds the special identifier '.'.
type DotNode struct {
	NodeType
	Pos
	tr *Tree
}

func (t *Tree) newDot(pos Pos) *DotNode {
	return &DotNode{tr: t, NodeType: NodeDot, Pos: pos}
}

func (d *DotNode) Type() NodeType {
	// Override method on embedded NodeType for API compatibility.
	// TODO: Not really a problem; could change API without effect but
	// api tool complains.
	return NodeDot
}

func (d *DotNode) String() string {
	return "."
}

func (d *DotNode) writeTo(sb *strings.Builder) {
	sb.WriteString(d.String())
}

func (d *DotNode) tree() *Tree {
	return d.tr
}

func (d *DotNode) Copy() Node {
	return d.tr.newDot(d.Pos)
}

// NilNode holds the special identifier 'nil' representing an untyped nil constant.
type NilNode struct {
	NodeType
	Pos
	tr *Tree
}

func (t *Tree) newNil(pos Pos) *NilNode {
	return &NilNode{tr: t, NodeType: NodeNil, Pos: pos}
}

func (n *NilNode) Type() NodeType {
	// Override method on embedded NodeType for API compatibility.
	// TODO: Not really a problem; could change API without effect but
	// api tool complains.
	return NodeNil
}

func (n *NilNode) String() string {
	return "nil"
}

func (n *NilNode) writeTo(sb *strings.Builder) {
	sb.WriteString(n.String())
}

func (n *NilNode) tree() *Tree {
	return n.tr
}

func (n *NilNode) Copy() Node {
	return n.tr.newNil(n.Pos)
}

// FieldNode holds a field (identifier starting with '.').
// The names may be chained ('.x.y').
// The period is dropped from each ident.
type FieldNode struct {
	NodeType
	Pos
	tr    *Tree
	Ident []string // The identifiers in lexical order.
}

func (t *Tree) newField(pos Pos, ident string) *FieldNode {
	return &FieldNode{tr: t, NodeType: NodeField, Pos: pos, Ident: strings.Split(ident[1:], ".")} // [1:] to drop leading period
}

func (f *FieldNode) String() string {
	var sb strings.Builder
	f.writeTo(&sb)
	return sb.String()
}

func (f *FieldNode) writeTo(sb *strings.Builder) {
	for _, id := range f.Ident {
		sb.WriteByte('.')
		sb.WriteString(id)
	}
}

func (f *FieldNode) tree() *Tree {
	return f.tr
}

func (f *FieldNode) Copy() Node {
	return &FieldNode{tr: f.tr, NodeType: NodeField, Pos: f.Pos, Ident: append([]string{}, f.Ident...)}
}

// ChainNode holds a term followed by a chain of field accesses (identifier starting with '.').
// The names may be chained ('.x.y').
// The periods are dropped from each ident.
type ChainNode struct {
	NodeType
	Pos
	tr    *Tree
	Node  Node
	Field []string // The identifiers in lexical order.
}

func (t *Tree) newChain(pos Pos, node Node) *ChainNode {
	return &ChainNode{tr: t, NodeType: NodeChain, Pos: pos, Node: node}
}

// Add adds the named field (which should start with a period) to the end of the chain.
func (c *ChainNode) Add(field string) {
	if len(field) == 0 || field[0] != '.' {
		panic("no dot in field")
	}
	field = field[1:] // Remove leading dot.
	if field == "" {
		panic("empty field")
	}
	c.Field = append(c.Field, field)
}

func (c *ChainNode) String() string {
	var sb strings.Builder
	c.writeTo(&sb)
	return sb.String()
}

func (c *ChainNode) writeTo(sb *strings.Builder) {
	if _, ok := c.Node.(*PipeNode); ok {
		sb.WriteByte('(')
		c.Node.writeTo(sb)
		sb.WriteByte(')')
	} else {
		c.Node.writeTo(sb)
	}
	for _, field := range c.Field {
		sb.WriteByte('.')
		sb.WriteString(field)
	}
}

func (c *ChainNode) tree() *Tree {
	return c.tr
}

func (c *ChainNode) Copy() Node {
	return &ChainNode{tr: c.tr, NodeType: NodeChain, Pos: c.Pos, Node: c.Node, Field: append([]string{}, c.Field...)}
}

// BoolNode holds a boolean constant.
type BoolNode struct {
	NodeType
	Pos
	tr   *Tree
	True bool // The value of the boolean constant.
}

func (t *Tree) newBool(pos Pos, true bool) *BoolNode {
	return &BoolNode{tr: t, NodeType: NodeBool, Pos: pos, True: true}
}

func (b *BoolNode) String() string {
	if b.True {
		return "true"
	}
	return "false"
}

func (b *BoolNode) writeTo(sb *strings.Builder) {
	sb.WriteString(b.String())
}

func (b *BoolNode) tree() *Tree {
	return b.tr
}

func (b *BoolNode) Copy() Node {
	return b.tr.newBool(b.Pos, b.True)
}

// NumberNode holds a number: signed or unsigned integer, float, or complex.
// The value is parsed and stored under all the types that can represent the value.
// This simulates in a small amount of code the behavior of Go's ideal constants.
type NumberNode struct {
	NodeType
	Pos
	tr         *Tree
	IsInt      bool       // Number has an integral value.
	IsUint     bool       // Number has an unsigned integral value.
	IsFloat    bool       // Number has a floating-point value.
	IsComplex  bool       // Number is complex.
	Int64      int64      // The signed integer value.
	Uint64     uint64     // The unsigned integer value.
	Float64    float64    // The floating-point value.
	Complex128 complex128 // The complex value.
	Text       string     // The original textual representation from the input.
}

func (t *Tree) newNumber(pos Pos, text string, typ itemType) (*NumberNode, error) {
	n := &NumberNode{tr: t, NodeType: NodeNumber, Pos: pos, Text: text}
	switch typ {
	case itemCharConstant:
		rune, _, tail, err := strconv.UnquoteChar(text[1:], text[0])
		if err != nil {
			return nil, err
		}
		if tail != "'" {
			return nil, fmt.Errorf("malformed character constant: %s", text)
		}
		n.Int64 = int64(rune)
		n.IsInt = true
		n.Uint64 = uint64(rune)
		n.IsUint = true
		n.Float64 = float64(rune) // odd but those are the rules.
		n.IsFloat = true
		return n, nil
	case itemComplex:
		// fmt.Sscan can parse the pair, so let it do the work.
		if _, err := fmt.Sscan(text, &n.Complex128); err != nil {
			return nil, err
		}
		n.IsComplex = true
		n.simplifyComplex()
		return n, nil
	}
	// Imaginary constants can only be complex unless they are zero.
	if len(text) > 0 && text[len(text)-1] == 'i' {
		f, err := strconv.ParseFloat(text[:len(text)-1], 64)
		if err == nil {
			n.IsComplex = true
			n.Complex128 = complex(0, f)
			n.simplifyComplex()
			return n, nil
		}
	}
	// Do integer test first so we get 0x123 etc.
	u, err := strconv.ParseUint(text, 0, 64) // will fail for -0; fixed below.
	if err == nil {
		n.IsUint = true
		n.Uint64 = u
	}
	i, err := strconv.ParseInt(text, 0, 64)
	if err == nil {
		n.IsInt = true
		n.Int64 = i
		if i == 0 {
			n.IsUint = true // in case of -0.
			n.Uint64 = u
		}
	}
	// If an integer extraction succeeded, promote the float.
	if n.IsInt {
		n.IsFloat = true
		n.Float64 = float64(n.Int64)
	} else if n.IsUint {
		n.IsFloat = true
		n.Float64 = float64(n.Uint64)
	} else {
		f, err := strconv.ParseFloat(text, 64)
		if err == nil {
			// If we parsed it as a float but it looks like an integer,
			// it's a huge number too large to fit in an int. Reject it.
			if !strings.ContainsAny(text, ".eEpP") {
				return nil, fmt.Errorf("integer overflow: %q", text)
			}
			n.IsFloat = true
			n.Float64 = f
			// If a floating-point extraction succeeded, extract the int if needed.
			if !n.IsInt && float64(int64(f)) == f {
				n.IsInt = true
				n.Int64 = int64(f)
			}
			if !n.IsUint && float64(uint64(f)) == f {
				n.IsUint = true
				n.Uint64 = uint64(f)
			}
		}
	}
	if !n.IsInt && !n.IsUint && !n.IsFloat {
		return nil, fmt.Errorf("illegal number syntax: %q", text)
	}
	return n, nil
}

// simplifyComplex pulls out any other types that are represented by the complex number.
// These all require that the imaginary part be zero.
func (n *NumberNode) simplifyComplex() {
	n.IsFloat = imag(n.Complex128) == 0
	if n.IsFloat {
		n.Float64 = real(n.Complex128)
		n.IsInt = float64(int64(n.Float64)) == n.Float64
		if n.IsInt {
			n.Int64 = int64(n.Float64)
		}
		n.IsUint = float64(uint64(n.Float64)) == n.Float64
		if n.IsUint {
			n.Uint64 = uint64(n.Float64)
		}
	}
}

func (n *NumberNode) String() string {
	return n.Text
}

func (n *NumberNode) writeTo(sb *strings.Builder) {
	sb.WriteString(n.String())
}

func (n *NumberNode) tree() *Tree {
	return n.tr
}

func (n *NumberNode) Copy() Node {
	nn := new(NumberNode)
	*nn = *n // Easy, fast, correct.
	return nn
}

// StringNode holds a string constant. The value has been "unquoted".
type StringNode struct {
	NodeType
	Pos
	tr     *Tree
	Quoted string // The original text of the string, with quotes.
	Text   string // The string, after quote processing.
}

func (t *Tree) newString(pos Pos, orig, text string) *StringNode {
	return &StringNode{tr: t, NodeType: NodeString, Pos: pos, Quoted: orig, Text: text}
}

func (s *StringNode) String() string {
	return s.Quoted
}

func (s *StringNode) writeTo(sb *strings.Builder) {
	sb.WriteString(s.String())
}

func (s *StringNode) tree() *Tree {
	return s.tr
}

func (s *StringNode) Copy() Node {
	return s.tr.newString(s.Pos, s.Quoted, s.Text)
}

// endNode represents an {{end}} action.
// It does not appear in the final parse tree.
type endNode struct {
	NodeType
	Pos
	tr *Tree
}

func (t *Tree) newEnd(pos Pos) *endNode {
	return &endNode{tr: t, NodeType: nodeEnd, Pos: pos}
}

func (e *endNode) String() string {
	return "{{end}}"
}

func (e *endNode) writeTo(sb *strings.Builder) {
	sb.WriteString(e.String())
}

func (e *endNode) tree() *Tree {
	return e.tr
}

func (e *endNode) Copy() Node {
	return e.tr.newEnd(e.Pos)
}

// elseNode represents an {{else}} action. Does not appear in the final tree.
type elseNode struct {
	NodeType
	Pos
	tr   *Tree
	Line int // The line number in the input. Deprecated: Kept for compatibility.
}

func (t *Tree) newElse(pos Pos, line int) *elseNode {
	return &elseNode{tr: t, NodeType: nodeElse, Pos: pos, Line: line}
}

func (e *elseNode) Type() NodeType {
	return nodeElse
}

func (e *elseNode) String() string {
	return "{{else}}"
}

func (e *elseNode) writeTo(sb *strings.Builder) {
	sb.WriteString(e.String())
}

func (e *elseNode) tree() *Tree {
	return e.tr
}

func (e *elseNode) Copy() Node {
	return e.tr.newElse(e.Pos, e.Line)
}

// BranchNode is the common representation of if, range, and with.
type BranchNode struct {
	NodeType
	Pos
	tr       *Tree
	Line     int       // The line number in the input. Deprecated: Kept for compatibility.
	Pipe     *PipeNode // The pipeline to be evaluated.
	List     *ListNode // What to execute if the value is non-empty.
	ElseList *ListNode // What to execute if the value is empty (nil if absent).
}

func (b *BranchNode) String() string {
	var sb strings.Builder
	b.writeTo(&sb)
	return sb.String()
}

func (b *BranchNode) writeTo(sb *strings.Builder) {
	name := ""
	switch b.NodeType {
	case NodeIf:
		name = "if"
	case NodeRange:
		name = "range"
	case NodeWith:
		name = "with"
	default:
		panic("unknown branch type")
	}
	sb.WriteString("{{")
	sb.WriteString(name)
	sb.WriteByte(' ')
	b.Pipe.writeTo(sb)
	sb.WriteString("}}")
	b.List.writeTo(sb)
	if b.ElseList != nil {
		sb.WriteString("{{else}}")
		b.ElseList.writeTo(sb)
	}
	sb.WriteString("{{end}}")
}

func (b *BranchNode) tree() *Tree {
	return b.tr
}

func (b *BranchNode) Copy() Node {
	switch b.NodeType {
	case NodeIf:
		return b.tr.newIf(b.Pos, b.Line, b.Pipe, b.List, b.ElseList)
	case NodeRange:
		return b.tr.newRange(b.Pos, b.Line, b.Pipe, b.List, b.ElseList)
	case NodeWith:
		return b.tr.newWith(b.Pos, b.Line, b.Pipe, b.List, b.ElseList)
	default:
		panic("unknown branch type")
	}
}

// IfNode represents an {{if}} action and its commands.
type IfNode struct {
	BranchNode
}

func (t *Tree) newIf(pos Pos, line int, pipe *PipeNode, list, elseList *ListNode) *IfNode {
	return &IfNode{BranchNode{tr: t, NodeType: NodeIf, Pos: pos, Line: line, Pipe: pipe, List: list, ElseList: elseList}}
}

func (i *IfNode) Copy() Node {
	return i.tr.newIf(i.Pos, i.Line, i.Pipe.CopyPipe(), i.List.CopyList(), i.ElseList.CopyList())
}

// BreakNode represents a {{break}} action.
type BreakNode struct {
	tr *Tree
	NodeType
	Pos
	Line int
}

func (t *Tree) newBreak(pos Pos, line int) *BreakNode {
	return &BreakNode{tr: t, NodeType: NodeBreak, Pos: pos, Line: line}
}

func (b *BreakNode) Copy() Node                  { return b.tr.newBreak(b.Pos, b.Line) }
func (b *BreakNode) String() string              { return "{{break}}" }
func (b *BreakNode) tree() *Tree                 { return b.tr }
func (b *BreakNode) writeTo(sb *strings.Builder) { sb.WriteString("{{break}}") }

// ContinueNode represents a {{continue}} action.
type ContinueNode struct {
	tr *Tree
	NodeType
	Pos
	Line int
}

func (t *Tree) newContinue(pos Pos, line int) *ContinueNode {
	return &ContinueNode{tr: t, NodeType: NodeContinue, Pos: pos, Line: line}
}

func (c *ContinueNode) Copy() Node                  { return c.tr.newContinue(c.Pos, c.Line) }
func (c *ContinueNode) String() string              { return "{{continue}}" }
func (c *ContinueNode) tree() *Tree                 { return c.tr }
func (c *ContinueNode) writeTo(sb *strings.Builder) { sb.WriteString("{{continue}}") }

// RangeNode represents a {{range}} action and its commands.
type RangeNode struct {
	BranchNode
}

func (t *Tree) newRange(pos Pos, line int, pipe *PipeNode, list, elseList *ListNode) *RangeNode {
	return &RangeNode{BranchNode{tr: t, NodeType: NodeRange, Pos: pos, Line: line, Pipe: pipe, List: list, ElseList: elseList}}
}

func (r *RangeNode) Copy() Node {
	return r.tr.newRange(r.Pos, r.Line, r.Pipe.CopyPipe(), r.List.CopyList(), r.ElseList.CopyList())
}

// WithNode represents a {{with}} action and its commands.
type WithNode struct {
	BranchNode
}

func (t *Tree) newWith(pos Pos, line int, pipe *PipeNode, list, elseList *ListNode) *WithNode {
	return &WithNode{BranchNode{tr: t, NodeType: NodeWith, Pos: pos, Line: line, Pipe: pipe, List: list, ElseList: elseList}}
}

func (w *WithNode) Copy() Node {
	return w.tr.newWith(w.Pos, w.Line, w.Pipe.CopyPipe(), w.List.CopyList(), w.ElseList.CopyList())
}

// TemplateNode represents a {{template}} action.
type TemplateNode struct {
	NodeType
	Pos
	tr   *Tree
	Line int       // The line number in the input. Deprecated: Kept for compatibility.
	Name string    // The name of the template (unquoted).
	Pipe *PipeNode // The command to evaluate as dot for the template.
}

func (t *Tree) newTemplate(pos Pos, line int, name string, pipe *PipeNode) *TemplateNode {
	return &TemplateNode{tr: t, NodeType: NodeTemplate, Pos: pos, Line: line, Name: name, Pipe: pipe}
}

func (t *TemplateNode) String() string {
	var sb strings.Builder
	t.writeTo(&sb)
	return sb.String()
}

func (t *TemplateNode) writeTo(sb *strings.Builder) {
	sb.WriteString("{{template ")
	sb.WriteString(strconv.Quote(t.Name))
	if t.Pipe != nil {
		sb.WriteByte(' ')
		t.Pipe.writeTo(sb)
	}
	sb.WriteString("}}")
}

func (t *TemplateNode) tree() *Tree {
	return t.tr
}

func (t *TemplateNode) Copy() Node {
	return t.tr.newTemplate(t.Pos, t.Line, t.Name, t.Pipe.CopyPipe())
}

"""



```