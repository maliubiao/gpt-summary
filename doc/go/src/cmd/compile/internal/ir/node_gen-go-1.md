Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Context:**

The first and most crucial step is recognizing the file path: `go/src/cmd/compile/internal/ir/node_gen.go`. This immediately tells us we're dealing with the Go compiler's internal representation (IR) of Go code. Specifically, `node_gen.go` strongly suggests this file is auto-generated or at least handles the boilerplate for various IR node types.

**2. Identifying the Core Functionality:**

Scanning the code, a pattern emerges quickly:  Each block of code corresponds to a specific Go language construct (e.g., `RangeStmt`, `ReturnStmt`, `SelectStmt`, etc.). Within each block, there are common methods:

* `Format`:  Likely for debugging or printing the IR.
* `copy`:  Creating a deep copy of the node.
* `doChildren`:  Traversing the node's children (sub-nodes).
* `doChildrenWithHidden`:  Similar to `doChildren`, but includes "hidden" or less commonly accessed children.
* `editChildren`:  Modifying the node's children.
* `editChildrenWithHidden`:  Similar to `editChildren`, including "hidden" children.

This repetitive structure strongly indicates a generated code pattern for handling common operations on different IR node types.

**3. Inferring the Purpose of Each Method:**

* **`Format`:**  The name and the `fmtNode` call strongly suggest this method formats the node for output, probably during debugging or when inspecting the compiler's intermediate stages.

* **`copy`:** The code within this method uses the spread operator (`...`) for slices and assigns fields individually, which is the standard way to perform a deep copy in Go. The purpose is to create an independent copy of the IR node.

* **`doChildren` and `doChildrenWithHidden`:** These methods iterate through the potential child nodes of a given IR node. The `do` function argument is a callback, allowing users of these methods to perform some action on each child (e.g., inspecting its type, counting nodes, etc.). The "hidden" variant likely exposes less frequently used or internally managed child nodes.

* **`editChildren` and `editChildrenWithHidden`:**  Similar to `doChildren`, but instead of just traversing, these methods allow modification of the child nodes through the `edit` callback function. The type assertion `.(Node)` is important here, ensuring the edited result is still a valid `Node`.

**4. Relating to Go Language Features:**

Now, connect the IR node types with their corresponding Go language features:

* `RangeStmt`:  The `for...range` loop.
* `ReturnStmt`:  The `return` statement.
* `SelectStmt`:  The `select` statement for concurrency.
* `SelectorExpr`:  Accessing fields of a struct or methods of an object (e.g., `obj.field` or `obj.Method()`).
* `SendStmt`:  Sending a value on a channel (`ch <- value`).
* `SliceExpr`:  Slicing arrays or slices (`arr[low:high]`).
* `SliceHeaderExpr`: The underlying representation of a slice (pointer, length, capacity). This is less directly used in user code but is crucial for the compiler.
* `StarExpr`:  Pointer dereference (`*ptr`).
* `StringHeaderExpr`: The underlying representation of a string (pointer to bytes, length). Similar to `SliceHeaderExpr`.
* `StructKeyExpr`:  Initializing struct fields in a composite literal (e.g., `MyStruct{Field: value}`).
* `SwitchStmt`:  The `switch` statement.
* `TailCallStmt`:  A function call that occurs as the last operation of a function (important for optimization).
* `TypeAssertExpr`:  Type assertions (`x.(T)`).
* `TypeSwitchGuard`:  The variable declaration within a type switch (`switch v := x.(type)`).
* `UnaryExpr`:  Unary operators like negation (`-x`), address-of (`&x`), etc.
* `typeNode`: Represents a type itself.

**5. Constructing Example Code:**

Based on the identified Go features, create simple examples to illustrate them. The examples should focus on the core functionality represented by the IR nodes. For instance, for `RangeStmt`, a basic `for...range` loop is sufficient. For `SelectStmt`, a simple `select` with a `case` is enough.

**6. Inferring Command-Line Arguments (If Applicable):**

Since this code is part of the compiler's internal workings, it's unlikely to directly interact with command-line arguments in the same way a user application would. However, one can infer that compiler flags or options *indirectly* influence the creation and manipulation of these IR nodes. For example, optimization flags might cause the compiler to generate slightly different IR for the same source code.

**7. Identifying Potential User Errors (If Applicable):**

Given the nature of this code (internal compiler representation), direct user errors related to *using* these structures are unlikely. However, a user could write Go code that the *compiler* struggles to optimize or represent efficiently in its IR. For instance, excessive use of reflection might lead to more complex IR.

**8. Synthesizing the Summary:**

Finally, combine all the observations into a concise summary. Emphasize the core function of the code: providing the structural foundation and common operations for representing Go code within the compiler. Highlight the use of the visitor pattern-like methods (`doChildren`, `editChildren`).

This detailed thought process, focusing on pattern recognition, contextual understanding, and linking the code to familiar Go concepts, allows for a comprehensive analysis of the given Go compiler code snippet.
## 对 go/src/cmd/compile/internal/ir/node_gen.go 的功能归纳 (第2部分)

这是 `go/src/cmd/compile/internal/ir/node_gen.go` 文件的一部分，它主要负责为 Go 语言的抽象语法树 (AST) 中的各种节点类型生成通用的操作方法。 这些方法使得编译器能够方便地遍历、复制和修改 AST。

**归纳一下它的功能：**

这部分代码的核心功能是为各种代表 Go 语言语法结构的节点类型 (例如：`RangeStmt`、`ReturnStmt`、`SelectStmt` 等)  **自动生成或实现以下通用操作：**

1. **`Format(s fmt.State, verb rune)`:**  实现 `fmt.Formatter` 接口，用于格式化输出节点信息，方便调试和查看 AST 结构。 这部分代码简单地调用了 `fmtNode` 函数，假设该函数在其他地方定义，负责实际的格式化逻辑。

2. **`copy() Node`:**  创建一个当前节点的深拷贝。 这对于编译器的某些阶段非常重要，例如进行优化时，需要在不修改原始 AST 的情况下进行转换。  拷贝操作会递归地复制节点包含的其他子节点。

3. **`doChildren(do func(Node) bool) bool` 和 `doChildrenWithHidden(do func(Node) bool) bool`:**  实现对节点子节点的遍历。  这两个方法都接受一个函数 `do` 作为参数，该函数会对每个子节点执行。如果 `do` 函数返回 `true`，则遍历提前结束。 `doChildrenWithHidden` 版本通常会遍历更多的“隐藏”或内部使用的子节点。

4. **`editChildren(edit func(Node) Node)` 和 `editChildrenWithHidden(edit func(Node) Node)`:**  实现对节点子节点的编辑或修改。 这两个方法都接受一个函数 `edit` 作为参数，该函数会对每个子节点进行处理并返回一个新的节点（或相同的节点）。返回值会替换原来的子节点。 同样， `editChildrenWithHidden` 版本会处理更多的“隐藏”子节点。

5. **辅助的 `copyXXX`、`doXXX`、`editXXX` 函数:**  例如 `copyCaseClauses`、`doCommClauses` 等，这些函数用于处理节点中包含的特定类型的子节点列表（例如 `CaseClause` 列表、`CommClause` 列表等）。 它们提供了对这些列表进行复制、遍历和编辑的通用逻辑。

**可以推理出它是什么 go 语言功能的实现：**

这部分代码涵盖了 Go 语言中多种语句和表达式的 IR 节点表示，包括：

* **控制流语句:** `RangeStmt` (for...range 循环), `ReturnStmt` (return 语句), `SelectStmt` (select 语句), `SwitchStmt` (switch 语句)
* **表达式:** `SelectorExpr` (选择器表达式，如 `a.b`), `SendStmt` (发送语句，如 `ch <- v`), `SliceExpr` (切片表达式，如 `a[1:3]`), `SliceHeaderExpr` (切片头信息), `StarExpr` (解引用表达式，如 `*p`), `StringHeaderExpr` (字符串头信息), `StructKeyExpr` (结构体键值对), `TailCallStmt` (尾调用), `TypeAssertExpr` (类型断言), `UnaryExpr` (一元表达式，如 `-x`, `!b`)
* **类型相关:** `TypeSwitchGuard` (类型 switch 的 guard 变量), `typeNode` (类型节点)

**Go 代码举例说明：**

以下是一些与代码中提到的节点类型对应的 Go 代码示例：

```go
package main

func main() {
	// RangeStmt
	numbers := []int{1, 2, 3}
	for i, num := range numbers {
		println(i, num)
	}

	// ReturnStmt
	println(add(5, 3))
}

func add(a, b int) int {
	return a + b
}

func process(ch chan int) {
	// SelectStmt
	select {
	case val := <-ch:
		println("received:", val)
	default:
		println("no value received")
	}
}

type MyStruct struct {
	Field1 int
	Field2 string
}

func examples() {
	s := MyStruct{Field1: 10, Field2: "hello"} // StructKeyExpr, SelectorExpr
	println(s.Field1)                          // SelectorExpr

	ch := make(chan int)
	ch <- 42 // SendStmt

	arr := [5]int{1, 2, 3, 4, 5}
	slice := arr[1:3] // SliceExpr
	println(slice[0])

	ptr := &arr[0]
	println(*ptr) // StarExpr

	var i interface{} = 10
	if v, ok := i.(int); ok { // TypeAssertExpr
		println("is int:", v)
	}

	switch val := i.(type) { // TypeSwitchGuard
	case int:
		println("type is int")
	case string:
		println("type is string")
	default:
		println("unknown type")
	}

	x := 5
	y := -x // UnaryExpr
	println(y)
}
```

**假设的输入与输出（代码推理）：**

这些方法主要在编译器的内部流程中使用，并没有直接的“输入输出”的概念。 它们的输入是 AST 节点本身，输出是修改后的节点或布尔值 (用于 `doChildren` 系列方法)。

例如，对于 `RangeStmt` 的 `copy()` 方法：

**假设输入:** 一个 `RangeStmt` 类型的节点，表示 `for i, v := range slice { ... }` 这样的循环，包含了 `init` 语句（例如可能的变量声明），要遍历的表达式 `X` (例如 `slice`)，键值变量 `Key` 和 `Value`，以及循环体 `Body`。

**输出:**  一个新的 `RangeStmt` 类型的节点，它与输入的节点拥有相同的数据，但是是完全独立的对象。 对输出节点的修改不会影响到原始的输入节点。  `Body` 中的语句也会被深拷贝。

**命令行参数的具体处理：**

这个代码片段本身并不直接处理命令行参数。 然而，Go 编译器的命令行参数（例如 `-gcflags`，`-l` 等）会影响编译过程，进而影响到 AST 的构建和优化。 这些方法是对 AST 节点进行操作的基础，因此，命令行参数会间接地影响到这些方法所处理的 AST 结构。

**使用者易犯错的点：**

作为编译器内部代码，普通 Go 开发者不会直接使用这些类型和方法。  易犯错的点主要集中在 **编译器开发的层面：**

* **在 `copy()` 方法中没有正确地深拷贝子节点:** 这会导致修改拷贝后的节点时意外地影响到原始节点，产生难以调试的错误。
* **在 `doChildren` 和 `editChildren` 方法中遗漏了某些子节点的处理:**  这会导致某些子树没有被正确地遍历或修改，可能会导致编译错误或生成错误的代码。
* **`doChildrenWithHidden` 和 `editChildrenWithHidden` 的使用场景理解不足:** 错误地使用 "hidden" 版本可能会导致处理了不应该被直接操作的内部节点，造成不可预测的后果。

总而言之，这段代码是 Go 编译器内部表示和操作 Go 语言代码的关键组成部分，它通过提供通用的方法，简化了编译器各个阶段对 AST 的处理。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ir/node_gen.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
)
	c.Body = copyNodes(c.Body)
	return &c
}
func (n *RangeStmt) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.Key != nil && do(n.Key) {
		return true
	}
	if n.Value != nil && do(n.Value) {
		return true
	}
	if doNodes(n.Body, do) {
		return true
	}
	if n.Prealloc != nil && do(n.Prealloc) {
		return true
	}
	return false
}
func (n *RangeStmt) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.RType != nil && do(n.RType) {
		return true
	}
	if n.Key != nil && do(n.Key) {
		return true
	}
	if n.Value != nil && do(n.Value) {
		return true
	}
	if doNodes(n.Body, do) {
		return true
	}
	if n.Prealloc != nil && do(n.Prealloc) {
		return true
	}
	if n.KeyTypeWord != nil && do(n.KeyTypeWord) {
		return true
	}
	if n.KeySrcRType != nil && do(n.KeySrcRType) {
		return true
	}
	if n.ValueTypeWord != nil && do(n.ValueTypeWord) {
		return true
	}
	if n.ValueSrcRType != nil && do(n.ValueSrcRType) {
		return true
	}
	return false
}
func (n *RangeStmt) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.Key != nil {
		n.Key = edit(n.Key).(Node)
	}
	if n.Value != nil {
		n.Value = edit(n.Value).(Node)
	}
	editNodes(n.Body, edit)
	if n.Prealloc != nil {
		n.Prealloc = edit(n.Prealloc).(*Name)
	}
}
func (n *RangeStmt) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.RType != nil {
		n.RType = edit(n.RType).(Node)
	}
	if n.Key != nil {
		n.Key = edit(n.Key).(Node)
	}
	if n.Value != nil {
		n.Value = edit(n.Value).(Node)
	}
	editNodes(n.Body, edit)
	if n.Prealloc != nil {
		n.Prealloc = edit(n.Prealloc).(*Name)
	}
	if n.KeyTypeWord != nil {
		n.KeyTypeWord = edit(n.KeyTypeWord).(Node)
	}
	if n.KeySrcRType != nil {
		n.KeySrcRType = edit(n.KeySrcRType).(Node)
	}
	if n.ValueTypeWord != nil {
		n.ValueTypeWord = edit(n.ValueTypeWord).(Node)
	}
	if n.ValueSrcRType != nil {
		n.ValueSrcRType = edit(n.ValueSrcRType).(Node)
	}
}

func (n *ResultExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *ResultExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *ResultExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	return false
}
func (n *ResultExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	return false
}
func (n *ResultExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
}
func (n *ResultExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
}

func (n *ReturnStmt) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *ReturnStmt) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	c.Results = copyNodes(c.Results)
	return &c
}
func (n *ReturnStmt) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if doNodes(n.Results, do) {
		return true
	}
	return false
}
func (n *ReturnStmt) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if doNodes(n.Results, do) {
		return true
	}
	return false
}
func (n *ReturnStmt) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	editNodes(n.Results, edit)
}
func (n *ReturnStmt) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	editNodes(n.Results, edit)
}

func (n *SelectStmt) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *SelectStmt) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	c.Cases = copyCommClauses(c.Cases)
	c.Compiled = copyNodes(c.Compiled)
	return &c
}
func (n *SelectStmt) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if doCommClauses(n.Cases, do) {
		return true
	}
	if doNodes(n.Compiled, do) {
		return true
	}
	return false
}
func (n *SelectStmt) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if doCommClauses(n.Cases, do) {
		return true
	}
	if doNodes(n.Compiled, do) {
		return true
	}
	return false
}
func (n *SelectStmt) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	editCommClauses(n.Cases, edit)
	editNodes(n.Compiled, edit)
}
func (n *SelectStmt) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	editCommClauses(n.Cases, edit)
	editNodes(n.Compiled, edit)
}

func (n *SelectorExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *SelectorExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *SelectorExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.Prealloc != nil && do(n.Prealloc) {
		return true
	}
	return false
}
func (n *SelectorExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.Prealloc != nil && do(n.Prealloc) {
		return true
	}
	return false
}
func (n *SelectorExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.Prealloc != nil {
		n.Prealloc = edit(n.Prealloc).(*Name)
	}
}
func (n *SelectorExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.Prealloc != nil {
		n.Prealloc = edit(n.Prealloc).(*Name)
	}
}

func (n *SendStmt) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *SendStmt) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *SendStmt) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Chan != nil && do(n.Chan) {
		return true
	}
	if n.Value != nil && do(n.Value) {
		return true
	}
	return false
}
func (n *SendStmt) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Chan != nil && do(n.Chan) {
		return true
	}
	if n.Value != nil && do(n.Value) {
		return true
	}
	return false
}
func (n *SendStmt) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Chan != nil {
		n.Chan = edit(n.Chan).(Node)
	}
	if n.Value != nil {
		n.Value = edit(n.Value).(Node)
	}
}
func (n *SendStmt) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Chan != nil {
		n.Chan = edit(n.Chan).(Node)
	}
	if n.Value != nil {
		n.Value = edit(n.Value).(Node)
	}
}

func (n *SliceExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *SliceExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *SliceExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.Low != nil && do(n.Low) {
		return true
	}
	if n.High != nil && do(n.High) {
		return true
	}
	if n.Max != nil && do(n.Max) {
		return true
	}
	return false
}
func (n *SliceExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.Low != nil && do(n.Low) {
		return true
	}
	if n.High != nil && do(n.High) {
		return true
	}
	if n.Max != nil && do(n.Max) {
		return true
	}
	return false
}
func (n *SliceExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.Low != nil {
		n.Low = edit(n.Low).(Node)
	}
	if n.High != nil {
		n.High = edit(n.High).(Node)
	}
	if n.Max != nil {
		n.Max = edit(n.Max).(Node)
	}
}
func (n *SliceExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.Low != nil {
		n.Low = edit(n.Low).(Node)
	}
	if n.High != nil {
		n.High = edit(n.High).(Node)
	}
	if n.Max != nil {
		n.Max = edit(n.Max).(Node)
	}
}

func (n *SliceHeaderExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *SliceHeaderExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *SliceHeaderExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Ptr != nil && do(n.Ptr) {
		return true
	}
	if n.Len != nil && do(n.Len) {
		return true
	}
	if n.Cap != nil && do(n.Cap) {
		return true
	}
	return false
}
func (n *SliceHeaderExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Ptr != nil && do(n.Ptr) {
		return true
	}
	if n.Len != nil && do(n.Len) {
		return true
	}
	if n.Cap != nil && do(n.Cap) {
		return true
	}
	return false
}
func (n *SliceHeaderExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Ptr != nil {
		n.Ptr = edit(n.Ptr).(Node)
	}
	if n.Len != nil {
		n.Len = edit(n.Len).(Node)
	}
	if n.Cap != nil {
		n.Cap = edit(n.Cap).(Node)
	}
}
func (n *SliceHeaderExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Ptr != nil {
		n.Ptr = edit(n.Ptr).(Node)
	}
	if n.Len != nil {
		n.Len = edit(n.Len).(Node)
	}
	if n.Cap != nil {
		n.Cap = edit(n.Cap).(Node)
	}
}

func (n *StarExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *StarExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *StarExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *StarExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *StarExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}
func (n *StarExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}

func (n *StringHeaderExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *StringHeaderExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *StringHeaderExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Ptr != nil && do(n.Ptr) {
		return true
	}
	if n.Len != nil && do(n.Len) {
		return true
	}
	return false
}
func (n *StringHeaderExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Ptr != nil && do(n.Ptr) {
		return true
	}
	if n.Len != nil && do(n.Len) {
		return true
	}
	return false
}
func (n *StringHeaderExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Ptr != nil {
		n.Ptr = edit(n.Ptr).(Node)
	}
	if n.Len != nil {
		n.Len = edit(n.Len).(Node)
	}
}
func (n *StringHeaderExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Ptr != nil {
		n.Ptr = edit(n.Ptr).(Node)
	}
	if n.Len != nil {
		n.Len = edit(n.Len).(Node)
	}
}

func (n *StructKeyExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *StructKeyExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *StructKeyExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Value != nil && do(n.Value) {
		return true
	}
	return false
}
func (n *StructKeyExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Value != nil && do(n.Value) {
		return true
	}
	return false
}
func (n *StructKeyExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Value != nil {
		n.Value = edit(n.Value).(Node)
	}
}
func (n *StructKeyExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Value != nil {
		n.Value = edit(n.Value).(Node)
	}
}

func (n *SwitchStmt) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *SwitchStmt) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	c.Cases = copyCaseClauses(c.Cases)
	c.Compiled = copyNodes(c.Compiled)
	return &c
}
func (n *SwitchStmt) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Tag != nil && do(n.Tag) {
		return true
	}
	if doCaseClauses(n.Cases, do) {
		return true
	}
	if doNodes(n.Compiled, do) {
		return true
	}
	return false
}
func (n *SwitchStmt) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Tag != nil && do(n.Tag) {
		return true
	}
	if doCaseClauses(n.Cases, do) {
		return true
	}
	if doNodes(n.Compiled, do) {
		return true
	}
	return false
}
func (n *SwitchStmt) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Tag != nil {
		n.Tag = edit(n.Tag).(Node)
	}
	editCaseClauses(n.Cases, edit)
	editNodes(n.Compiled, edit)
}
func (n *SwitchStmt) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Tag != nil {
		n.Tag = edit(n.Tag).(Node)
	}
	editCaseClauses(n.Cases, edit)
	editNodes(n.Compiled, edit)
}

func (n *TailCallStmt) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *TailCallStmt) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *TailCallStmt) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Call != nil && do(n.Call) {
		return true
	}
	return false
}
func (n *TailCallStmt) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.Call != nil && do(n.Call) {
		return true
	}
	return false
}
func (n *TailCallStmt) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Call != nil {
		n.Call = edit(n.Call).(*CallExpr)
	}
}
func (n *TailCallStmt) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.Call != nil {
		n.Call = edit(n.Call).(*CallExpr)
	}
}

func (n *TypeAssertExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *TypeAssertExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *TypeAssertExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *TypeAssertExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	if n.ITab != nil && do(n.ITab) {
		return true
	}
	return false
}
func (n *TypeAssertExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}
func (n *TypeAssertExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
	if n.ITab != nil {
		n.ITab = edit(n.ITab).(Node)
	}
}

func (n *TypeSwitchGuard) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *TypeSwitchGuard) copy() Node {
	c := *n
	return &c
}
func (n *TypeSwitchGuard) doChildren(do func(Node) bool) bool {
	if n.Tag != nil && do(n.Tag) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *TypeSwitchGuard) doChildrenWithHidden(do func(Node) bool) bool {
	if n.Tag != nil && do(n.Tag) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *TypeSwitchGuard) editChildren(edit func(Node) Node) {
	if n.Tag != nil {
		n.Tag = edit(n.Tag).(*Ident)
	}
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}
func (n *TypeSwitchGuard) editChildrenWithHidden(edit func(Node) Node) {
	if n.Tag != nil {
		n.Tag = edit(n.Tag).(*Ident)
	}
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}

func (n *UnaryExpr) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *UnaryExpr) copy() Node {
	c := *n
	c.init = copyNodes(c.init)
	return &c
}
func (n *UnaryExpr) doChildren(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *UnaryExpr) doChildrenWithHidden(do func(Node) bool) bool {
	if doNodes(n.init, do) {
		return true
	}
	if n.X != nil && do(n.X) {
		return true
	}
	return false
}
func (n *UnaryExpr) editChildren(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}
func (n *UnaryExpr) editChildrenWithHidden(edit func(Node) Node) {
	editNodes(n.init, edit)
	if n.X != nil {
		n.X = edit(n.X).(Node)
	}
}

func (n *typeNode) Format(s fmt.State, verb rune) { fmtNode(n, s, verb) }
func (n *typeNode) copy() Node {
	c := *n
	return &c
}
func (n *typeNode) doChildren(do func(Node) bool) bool {
	return false
}
func (n *typeNode) doChildrenWithHidden(do func(Node) bool) bool {
	return false
}
func (n *typeNode) editChildren(edit func(Node) Node) {
}
func (n *typeNode) editChildrenWithHidden(edit func(Node) Node) {
}

func copyCaseClauses(list []*CaseClause) []*CaseClause {
	if list == nil {
		return nil
	}
	c := make([]*CaseClause, len(list))
	copy(c, list)
	return c
}
func doCaseClauses(list []*CaseClause, do func(Node) bool) bool {
	for _, x := range list {
		if x != nil && do(x) {
			return true
		}
	}
	return false
}
func editCaseClauses(list []*CaseClause, edit func(Node) Node) {
	for i, x := range list {
		if x != nil {
			list[i] = edit(x).(*CaseClause)
		}
	}
}

func copyCommClauses(list []*CommClause) []*CommClause {
	if list == nil {
		return nil
	}
	c := make([]*CommClause, len(list))
	copy(c, list)
	return c
}
func doCommClauses(list []*CommClause, do func(Node) bool) bool {
	for _, x := range list {
		if x != nil && do(x) {
			return true
		}
	}
	return false
}
func editCommClauses(list []*CommClause, edit func(Node) Node) {
	for i, x := range list {
		if x != nil {
			list[i] = edit(x).(*CommClause)
		}
	}
}

func copyNames(list []*Name) []*Name {
	if list == nil {
		return nil
	}
	c := make([]*Name, len(list))
	copy(c, list)
	return c
}
func doNames(list []*Name, do func(Node) bool) bool {
	for _, x := range list {
		if x != nil && do(x) {
			return true
		}
	}
	return false
}
func editNames(list []*Name, edit func(Node) Node) {
	for i, x := range list {
		if x != nil {
			list[i] = edit(x).(*Name)
		}
	}
}

func copyNodes(list []Node) []Node {
	if list == nil {
		return nil
	}
	c := make([]Node, len(list))
	copy(c, list)
	return c
}
func doNodes(list []Node, do func(Node) bool) bool {
	for _, x := range list {
		if x != nil && do(x) {
			return true
		}
	}
	return false
}
func editNodes(list []Node, edit func(Node) Node) {
	for i, x := range list {
		if x != nil {
			list[i] = edit(x).(Node)
		}
	}
}
```