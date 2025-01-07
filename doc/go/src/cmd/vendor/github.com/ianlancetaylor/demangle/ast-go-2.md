Response:
The user wants me to summarize the functionality of the provided Go code snippet. This code snippet is part of the `ast.go` file within the `demangle` package, which suggests it deals with abstract syntax trees for demangling C++ symbols.

The code defines several Go structs that represent different kinds of expressions and operations in C++, such as binary operations, ternary operations, function calls, literals, and more. Each struct has methods for:

1. **`print(ps *printState)`:** This method is likely responsible for converting the AST node back into a human-readable string representation of the C++ expression. It seems to handle different printing styles (`llvmStyle`).
2. **`Traverse(fn func(AST) bool)`:** This method implements a tree traversal, allowing a function to be applied to each node in the subtree.
3. **`Copy(fn func(AST) AST, skip func(AST) bool)`:** This method creates a copy of the AST node, potentially modifying parts of the copy based on the provided functions.
4. **`GoString() string` and `goString(indent int, field string) string`:** These methods are for generating a Go-specific string representation of the struct, useful for debugging.
5. **`prec() precedence` (for some structs):** This method likely returns the operator precedence of the expression, influencing how parentheses are added during printing.

Based on the names of the structs and their fields, I can infer the C++ language features they represent.

**Plan:**

1. Identify the main purpose of the code based on the provided structs and methods.
2. List the specific C++ language features each struct seems to represent.
3. Summarize the common functionalities (print, traverse, copy, GoString).这段代码是 `go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go` 文件的一部分，主要定义了用于表示 C++ 表达式的抽象语法树（AST）节点类型，并提供了将这些 AST 节点转换为字符串形式的功能。

**功能归纳:**

这段代码主要定义了以下几种用于表示 C++ 表达式的 AST 节点类型：

*   **`Binary`**: 表示二元运算表达式，例如 `a + b`。它包含运算符 (`Op`)、左操作数 (`Left`) 和右操作数 (`Right`)。
*   **`Trinary`**: 表示三元条件运算符表达式，例如 `a ? b : c`。它包含条件 (`Op`)、第一个结果 (`First`)、第二个结果 (`Second`) 和第三个结果 (`Third`)。
*   **`Fold`**: 表示 C++17 的折叠表达式，用于模板编程。它可以是单元折叠或二元折叠。
*   **`Subobject`**: 表示对表达式中某个子对象的引用，用于 C++20 中非类型模板参数的处理。
*   **`PtrMemCast`**: 表示将表达式转换为指向成员的指针类型，也用于 C++20 中非类型模板参数的处理。
*   **`New`**: 表示 `new` 运算符的使用，包含运算符 (`Op`)、放置 (`Place`)、类型 (`Type`) 和初始化器 (`Init`)。
*   **`Literal`**: 表示字面量，例如数字、布尔值等。包含类型 (`Type`)、值 (`Val`) 和是否为负数 (`Neg`)。
*   **`StringLiteral`**: 表示字符串字面量，包含类型 (`Type`)。
*   **`LambdaExpr`**: 表示 lambda 表达式，包含类型 (`Type`)，类型通常是 `Closure`。
*   **`ExprList`**: 表示表达式列表，通常用于函数调用的参数。
*   **`InitializerList`**: 表示初始化列表，包含可选的类型 (`Type`) 和表达式列表 (`Exprs`)。
*   **`DefaultArg`**: 表示局部名称的默认参数。
*   **`Closure`**: 表示闭包或 lambda 表达式，包含模板参数、类型、编号和调用约束。
*   **`StructuredBindings`**: 表示结构化绑定声明。
*   **`UnnamedType`**: 表示未命名的类型，只有一个索引。
*   **`Clone`**: 表示函数的克隆版本，带有后缀。
*   **`Special`**: 表示特殊的符号，带有前缀和值。
*   **`Special2`**: 类似于 `Special`，但使用两个值和一个中间字符串。
*   **`EnableIf`**: 表示 clang 的 `enable_if` 属性。
*   **`ModuleName`**: 表示 C++20 的模块。
*   **`ModuleEntity`**: 表示模块内部的名称。

对于每个 AST 节点类型，代码都提供了以下核心功能：

*   **`print(ps *printState)`**:  将 AST 节点以字符串形式打印出来。`printState` 结构体维护了打印状态，例如是否使用 LLVM 风格的输出。这个方法会根据不同的 AST 节点类型和打印风格，生成相应的字符串表示。
*   **`Traverse(fn func(AST) bool)`**:  对 AST 节点进行遍历，允许用户自定义函数 `fn` 对节点及其子节点进行操作。如果 `fn` 返回 `false`，则停止对当前节点的子节点进行遍历。
*   **`Copy(fn func(AST) AST, skip func(AST) bool)`**:  复制 AST 节点。`fn` 函数允许用户在复制过程中修改节点，`skip` 函数允许跳过某些节点的复制。
*   **`GoString() string` 和 `goString(indent int, field string) string`**:  生成 AST 节点的 Go 语言风格的字符串表示，主要用于调试。
*   部分节点类型还实现了 `prec() precedence` 方法，用于返回运算符的优先级，这在 `print` 方法中用于决定是否需要添加括号以保证表达式的正确性。

**代码推理与示例:**

这段代码是 C++ 符号反解器的一部分。反解器将编译器生成的符号名称（通常是经过 mangling 的）转换回人类可读的形式。这段代码处理的是表达式部分的反解，例如将 mangled 的函数调用、运算符表达式等转换成类似 C++ 代码的字符串。

**假设输入与输出 (以 `Binary` 节点为例):**

**假设输入 (Go 代码构建的 `Binary` 节点):**

```go
package main

import (
	"fmt"
	"strings"

	"github.com/ianlancetaylor/demangle/ast"
)

func main() {
	ps := &ast.PrintState{
		Buf: &strings.Builder{},
	}
	plusOp := &ast.Operator{Name: "+", Precedence: ast.PrecAdd}
	left := &ast.Name{Name: "a"}
	right := &ast.Name{Name: "b"}
	binaryExpr := &ast.Binary{Op: plusOp, Left: left, Right: right}

	binaryExpr.Print(ps)
	fmt.Println(ps.Buf.String())
}
```

**预期输出:**

```
a+b
```

**假设输入 (包含优先级的 `Binary` 节点):**

```go
package main

import (
	"fmt"
	"strings"

	"github.com/ianlancetaylor/demangle/ast"
)

func main() {
	ps := &ast.PrintState{
		Buf: &strings.Builder{},
	}
	mulOp := &ast.Operator{Name: "*", Precedence: ast.PrecMul}
	plusOp := &ast.Operator{Name: "+", Precedence: ast.PrecAdd}
	left := &ast.Binary{Op: plusOp, Left: &ast.Name{Name: "a"}, Right: &ast.Name{Name: "b"}}
	right := &ast.Name{Name: "c"}
	binaryExpr := &ast.Binary{Op: mulOp, Left: left, Right: right}

	binaryExpr.Print(ps)
	fmt.Println(ps.Buf.String())
}
```

**预期输出:**

```
(a+b)*c
```

**易犯错的点（这段代码片段中未体现明显的易错点）:**

这段代码主要关注 AST 节点的结构和打印逻辑，使用者通常是通过构建和操作这些 AST 节点来进行符号反解，易犯错的点可能在于如何正确构建复杂的 AST 结构来表示各种 C++ 符号。

**总结:**

这段代码是 Go 语言实现的 C++ 符号反解器中，用于表示和操作表达式抽象语法树的核心部分。它定义了多种 AST 节点类型来对应不同的 C++ 表达式结构，并提供了将这些 AST 节点转换回人类可读 C++ 代码的功能。这部分代码不涉及命令行参数的处理，主要关注内部的数据结构和算法。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共4部分，请归纳一下它的功能

"""
s.print(b.Left)
		if op.Name == "]=" {
			ps.writeByte(']')
		}
		if isDesignatedInitializer(b.Right) {
			// Don't add anything between designated
			// initializer chains.
			ps.print(b.Right)
		} else {
			if ps.llvmStyle {
				ps.writeString(" = ")
				ps.print(b.Right)
			} else {
				ps.writeByte('=')
				parenthesize(ps, b.Right)
			}
		}
		return
	}

	// Use an extra set of parentheses around an expression that
	// uses the greater-than operator, so that it does not get
	// confused with the '>' that ends template parameters.
	needsOuterParen := op != nil && (op.Name == ">" || op.Name == ">>")
	if ps.llvmStyle && ps.scopes > 0 {
		needsOuterParen = false
	}
	if needsOuterParen {
		ps.startScope('(')
	}

	left := b.Left

	skipParens := false
	addSpaces := ps.llvmStyle
	if ps.llvmStyle && op != nil {
		switch op.Name {
		case ".", "->", "->*":
			addSpaces = false
		}
	}

	// For a function call in an expression, don't print the types
	// of the arguments unless there is a return type.
	if op != nil && op.Name == "()" {
		if ty, ok := b.Left.(*Typed); ok {
			if ft, ok := ty.Type.(*FunctionType); ok {
				if ft.Return == nil {
					left = ty.Name
				} else {
					skipParens = true
				}
			} else {
				left = ty.Name
			}
		}
		if ps.llvmStyle {
			skipParens = true
		}
	}

	if skipParens {
		ps.print(left)
	} else if ps.llvmStyle {
		prec := precPrimary
		if p, ok := left.(hasPrec); ok {
			prec = p.prec()
		}
		needsParen := false
		if prec > b.prec() {
			needsParen = true
		}
		if needsParen {
			ps.startScope('(')
		}

		ps.print(left)

		if needsParen {
			ps.endScope(')')
		}
	} else {
		parenthesize(ps, left)
	}

	if op != nil && op.Name == "[]" {
		ps.writeByte('[')
		ps.print(b.Right)
		ps.writeByte(']')
		return
	}

	if op != nil {
		if op.Name != "()" {
			if addSpaces && op.Name != "," {
				ps.writeByte(' ')
			}
			ps.writeString(op.Name)
			if addSpaces {
				ps.writeByte(' ')
			}
		}
	} else {
		ps.print(b.Op)
	}

	if ps.llvmStyle {
		prec := precPrimary
		if p, ok := b.Right.(hasPrec); ok {
			prec = p.prec()
		}
		needsParen := false
		if prec >= b.prec() {
			needsParen = true
		}
		if needsParen {
			ps.startScope('(')
		}

		ps.print(b.Right)

		if needsParen {
			ps.endScope(')')
		}
	} else {
		parenthesize(ps, b.Right)
	}

	if needsOuterParen {
		ps.endScope(')')
	}
}

func (b *Binary) Traverse(fn func(AST) bool) {
	if fn(b) {
		b.Op.Traverse(fn)
		b.Left.Traverse(fn)
		b.Right.Traverse(fn)
	}
}

func (b *Binary) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(b) {
		return nil
	}
	op := b.Op.Copy(fn, skip)
	left := b.Left.Copy(fn, skip)
	right := b.Right.Copy(fn, skip)
	if op == nil && left == nil && right == nil {
		return fn(b)
	}
	if op == nil {
		op = b.Op
	}
	if left == nil {
		left = b.Left
	}
	if right == nil {
		right = b.Right
	}
	b = &Binary{Op: op, Left: left, Right: right}
	if r := fn(b); r != nil {
		return r
	}
	return b
}

func (b *Binary) GoString() string {
	return b.goString(0, "")
}

func (b *Binary) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sBinary:\n%s\n%s\n%s", indent, "", field,
		b.Op.goString(indent+2, "Op: "),
		b.Left.goString(indent+2, "Left: "),
		b.Right.goString(indent+2, "Right: "))
}

func (b *Binary) prec() precedence {
	if p, ok := b.Op.(hasPrec); ok {
		return p.prec()
	}
	return precDefault
}

// Trinary is the ?: trinary operation in an expression.
type Trinary struct {
	Op     AST
	First  AST
	Second AST
	Third  AST
}

func (t *Trinary) print(ps *printState) {
	if isDesignatedInitializer(t) {
		ps.writeByte('[')
		ps.print(t.First)
		ps.writeString(" ... ")
		ps.print(t.Second)
		ps.writeByte(']')
		if isDesignatedInitializer(t.Third) {
			// Don't add anything between designated
			// initializer chains.
			ps.print(t.Third)
		} else {
			if ps.llvmStyle {
				ps.writeString(" = ")
				ps.print(t.Third)
			} else {
				ps.writeByte('=')
				parenthesize(ps, t.Third)
			}
		}
		return
	}

	if ps.llvmStyle {
		wantParens := true
		opPrec := precPrimary
		if op, ok := t.Op.(*Operator); ok {
			opPrec = op.precedence
		}
		if p, ok := t.First.(hasPrec); ok {
			if p.prec() < opPrec {
				wantParens = false
			}
		}
		if wantParens {
			ps.startScope('(')
		}
		ps.print(t.First)
		if wantParens {
			ps.endScope(')')
		}
	} else {
		parenthesize(ps, t.First)
	}

	if ps.llvmStyle {
		ps.writeString(" ? ")
	} else {
		ps.writeByte('?')
	}

	if ps.llvmStyle {
		wantParens := true
		if p, ok := t.Second.(hasPrec); ok {
			if p.prec() < precDefault {
				wantParens = false
			}
		}
		if wantParens {
			ps.startScope('(')
		}
		ps.print(t.Second)
		if wantParens {
			ps.endScope(')')
		}
	} else {
		parenthesize(ps, t.Second)
	}

	ps.writeString(" : ")

	if ps.llvmStyle {
		wantParens := true
		if p, ok := t.Third.(hasPrec); ok {
			if p.prec() < precAssign {
				wantParens = false
			}
		}
		if wantParens {
			ps.startScope('(')
		}
		ps.print(t.Third)
		if wantParens {
			ps.endScope(')')
		}
	} else {
		parenthesize(ps, t.Third)
	}
}

func (t *Trinary) Traverse(fn func(AST) bool) {
	if fn(t) {
		t.Op.Traverse(fn)
		t.First.Traverse(fn)
		t.Second.Traverse(fn)
		t.Third.Traverse(fn)
	}
}

func (t *Trinary) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(t) {
		return nil
	}
	op := t.Op.Copy(fn, skip)
	first := t.First.Copy(fn, skip)
	second := t.Second.Copy(fn, skip)
	third := t.Third.Copy(fn, skip)
	if op == nil && first == nil && second == nil && third == nil {
		return fn(t)
	}
	if op == nil {
		op = t.Op
	}
	if first == nil {
		first = t.First
	}
	if second == nil {
		second = t.Second
	}
	if third == nil {
		third = t.Third
	}
	t = &Trinary{Op: op, First: first, Second: second, Third: third}
	if r := fn(t); r != nil {
		return r
	}
	return t
}

func (t *Trinary) GoString() string {
	return t.goString(0, "")
}

func (t *Trinary) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTrinary:\n%s\n%s\n%s\n%s", indent, "", field,
		t.Op.goString(indent+2, "Op: "),
		t.First.goString(indent+2, "First: "),
		t.Second.goString(indent+2, "Second: "),
		t.Third.goString(indent+2, "Third: "))
}

// Fold is a C++17 fold-expression.  Arg2 is nil for a unary operator.
type Fold struct {
	Left bool
	Op   AST
	Arg1 AST
	Arg2 AST
}

func (f *Fold) print(ps *printState) {
	op, _ := f.Op.(*Operator)
	printOp := func() {
		if op != nil {
			if ps.llvmStyle {
				ps.writeByte(' ')
			}
			ps.writeString(op.Name)
			if ps.llvmStyle {
				ps.writeByte(' ')
			}
		} else {
			ps.print(f.Op)
		}
	}
	foldParenthesize := func(a AST) {
		if ps.llvmStyle {
			prec := precDefault
			if p, ok := a.(hasPrec); ok {
				prec = p.prec()
			}
			needsParen := false
			if prec > precCast {
				needsParen = true
			}
			if needsParen {
				ps.startScope('(')
			}
			ps.print(a)
			if needsParen {
				ps.endScope(')')
			}
		} else {
			parenthesize(ps, a)
		}
	}

	if f.Arg2 == nil {
		if f.Left {
			ps.startScope('(')
			ps.writeString("...")
			printOp()
			foldParenthesize(f.Arg1)
			ps.endScope(')')
		} else {
			ps.startScope('(')
			foldParenthesize(f.Arg1)
			printOp()
			ps.writeString("...")
			ps.endScope(')')
		}
	} else {
		ps.startScope('(')
		foldParenthesize(f.Arg1)
		printOp()
		ps.writeString("...")
		printOp()
		foldParenthesize(f.Arg2)
		ps.endScope(')')
	}
}

func (f *Fold) Traverse(fn func(AST) bool) {
	if fn(f) {
		f.Op.Traverse(fn)
		f.Arg1.Traverse(fn)
		if f.Arg2 != nil {
			f.Arg2.Traverse(fn)
		}
	}
}

func (f *Fold) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(f) {
		return nil
	}
	op := f.Op.Copy(fn, skip)
	arg1 := f.Arg1.Copy(fn, skip)
	var arg2 AST
	if f.Arg2 != nil {
		arg2 = f.Arg2.Copy(fn, skip)
	}
	if op == nil && arg1 == nil && arg2 == nil {
		return fn(f)
	}
	if op == nil {
		op = f.Op
	}
	if arg1 == nil {
		arg1 = f.Arg1
	}
	if arg2 == nil {
		arg2 = f.Arg2
	}
	f = &Fold{Left: f.Left, Op: op, Arg1: arg1, Arg2: arg2}
	if r := fn(f); r != nil {
		return r
	}
	return f
}

func (f *Fold) GoString() string {
	return f.goString(0, "")
}

func (f *Fold) goString(indent int, field string) string {
	if f.Arg2 == nil {
		return fmt.Sprintf("%*s%sFold: Left: %t\n%s\n%s", indent, "", field,
			f.Left, f.Op.goString(indent+2, "Op: "),
			f.Arg1.goString(indent+2, "Arg1: "))
	} else {
		return fmt.Sprintf("%*s%sFold: Left: %t\n%s\n%s\n%s", indent, "", field,
			f.Left, f.Op.goString(indent+2, "Op: "),
			f.Arg1.goString(indent+2, "Arg1: "),
			f.Arg2.goString(indent+2, "Arg2: "))
	}
}

// Subobject is a a reference to an offset in an expression.  This is
// used for C++20 manglings of class types used as the type of
// non-type template arguments.
//
// See https://github.com/itanium-cxx-abi/cxx-abi/issues/47.
type Subobject struct {
	Type      AST
	SubExpr   AST
	Offset    int
	Selectors []int
	PastEnd   bool
}

func (so *Subobject) print(ps *printState) {
	ps.print(so.SubExpr)
	ps.writeString(".<")
	ps.print(so.Type)
	ps.writeString(fmt.Sprintf(" at offset %d>", so.Offset))
}

func (so *Subobject) Traverse(fn func(AST) bool) {
	if fn(so) {
		so.Type.Traverse(fn)
		so.SubExpr.Traverse(fn)
	}
}

func (so *Subobject) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(so) {
		return nil
	}
	typ := so.Type.Copy(fn, skip)
	subExpr := so.SubExpr.Copy(fn, skip)
	if typ == nil && subExpr == nil {
		return nil
	}
	if typ == nil {
		typ = so.Type
	}
	if subExpr == nil {
		subExpr = so.SubExpr
	}
	so = &Subobject{
		Type:      typ,
		SubExpr:   subExpr,
		Offset:    so.Offset,
		Selectors: so.Selectors,
		PastEnd:   so.PastEnd,
	}
	if r := fn(so); r != nil {
		return r
	}
	return so
}

func (so *Subobject) GoString() string {
	return so.goString(0, "")
}

func (so *Subobject) goString(indent int, field string) string {
	var selectors string
	for _, s := range so.Selectors {
		selectors += fmt.Sprintf(" %d", s)
	}
	return fmt.Sprintf("%*s%sSubobject:\n%s\n%s\n%*sOffset: %d\n%*sSelectors:%s\n%*sPastEnd: %t",
		indent, "", field,
		so.Type.goString(indent+2, "Type: "),
		so.SubExpr.goString(indent+2, "SubExpr: "),
		indent+2, "", so.Offset,
		indent+2, "", selectors,
		indent+2, "", so.PastEnd)
}

// PtrMemCast is a conversion of an expression to a pointer-to-member
// type.  This is used for C++20 manglings of class types used as the
// type of non-type template arguments.
//
// See https://github.com/itanium-cxx-abi/cxx-abi/issues/47.
type PtrMemCast struct {
	Type   AST
	Expr   AST
	Offset int
}

func (pmc *PtrMemCast) print(ps *printState) {
	ps.startScope('(')
	ps.print(pmc.Type)
	ps.writeString(")(")
	ps.print(pmc.Expr)
	ps.endScope(')')
}

func (pmc *PtrMemCast) Traverse(fn func(AST) bool) {
	if fn(pmc) {
		pmc.Type.Traverse(fn)
		pmc.Expr.Traverse(fn)
	}
}

func (pmc *PtrMemCast) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(pmc) {
		return nil
	}
	typ := pmc.Type.Copy(fn, skip)
	expr := pmc.Expr.Copy(fn, skip)
	if typ == nil && expr == nil {
		return nil
	}
	if typ == nil {
		typ = pmc.Type
	}
	if expr == nil {
		expr = pmc.Expr
	}
	pmc = &PtrMemCast{
		Type:   typ,
		Expr:   expr,
		Offset: pmc.Offset,
	}
	if r := fn(pmc); r != nil {
		return r
	}
	return pmc
}

func (pmc *PtrMemCast) GoString() string {
	return pmc.goString(0, "")
}

func (pmc *PtrMemCast) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sPtrMemCast:\n%s\n%s\n%*sOffset: %d",
		indent, "", field,
		pmc.Type.goString(indent+2, "Type: "),
		pmc.Expr.goString(indent+2, "Expr: "),
		indent+2, "", pmc.Offset)
}

// New is a use of operator new in an expression.
type New struct {
	Op    AST
	Place AST
	Type  AST
	Init  AST
}

func (n *New) print(ps *printState) {
	if !ps.llvmStyle {
		// Op doesn't really matter for printing--we always print "new".
		ps.writeString("new ")
	} else {
		op, _ := n.Op.(*Operator)
		if op != nil {
			ps.writeString(op.Name)
			if n.Place == nil {
				ps.writeByte(' ')
			}
		} else {
			ps.print(n.Op)
		}
	}
	if n.Place != nil {
		parenthesize(ps, n.Place)
		ps.writeByte(' ')
	}
	ps.print(n.Type)
	if n.Init != nil {
		parenthesize(ps, n.Init)
	}
}

func (n *New) Traverse(fn func(AST) bool) {
	if fn(n) {
		n.Op.Traverse(fn)
		if n.Place != nil {
			n.Place.Traverse(fn)
		}
		n.Type.Traverse(fn)
		if n.Init != nil {
			n.Init.Traverse(fn)
		}
	}
}

func (n *New) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(n) {
		return nil
	}
	op := n.Op.Copy(fn, skip)
	var place AST
	if n.Place != nil {
		place = n.Place.Copy(fn, skip)
	}
	typ := n.Type.Copy(fn, skip)
	var ini AST
	if n.Init != nil {
		ini = n.Init.Copy(fn, skip)
	}
	if op == nil && place == nil && typ == nil && ini == nil {
		return fn(n)
	}
	if op == nil {
		op = n.Op
	}
	if place == nil {
		place = n.Place
	}
	if typ == nil {
		typ = n.Type
	}
	if ini == nil {
		ini = n.Init
	}
	n = &New{Op: op, Place: place, Type: typ, Init: ini}
	if r := fn(n); r != nil {
		return r
	}
	return n
}

func (n *New) GoString() string {
	return n.goString(0, "")
}

func (n *New) goString(indent int, field string) string {
	var place string
	if n.Place == nil {
		place = fmt.Sprintf("%*sPlace: nil", indent, "")
	} else {
		place = n.Place.goString(indent+2, "Place: ")
	}
	var ini string
	if n.Init == nil {
		ini = fmt.Sprintf("%*sInit: nil", indent, "")
	} else {
		ini = n.Init.goString(indent+2, "Init: ")
	}
	return fmt.Sprintf("%*s%sNew:\n%s\n%s\n%s\n%s", indent, "", field,
		n.Op.goString(indent+2, "Op: "), place,
		n.Type.goString(indent+2, "Type: "), ini)
}

// Literal is a literal in an expression.
type Literal struct {
	Type AST
	Val  string
	Neg  bool
}

// Suffixes to use for constants of the given integer type.
var builtinTypeSuffix = map[string]string{
	"int":                "",
	"unsigned int":       "u",
	"long":               "l",
	"unsigned long":      "ul",
	"long long":          "ll",
	"unsigned long long": "ull",
}

// Builtin float types.
var builtinTypeFloat = map[string]bool{
	"double":      true,
	"long double": true,
	"float":       true,
	"__float128":  true,
	"half":        true,
}

func (l *Literal) print(ps *printState) {
	isFloat := false
	if b, ok := l.Type.(*BuiltinType); ok {
		if suffix, ok := builtinTypeSuffix[b.Name]; ok {
			if l.Neg {
				ps.writeByte('-')
			}
			ps.writeString(l.Val)
			ps.writeString(suffix)
			return
		} else if b.Name == "bool" && !l.Neg {
			switch l.Val {
			case "0":
				ps.writeString("false")
				return
			case "1":
				ps.writeString("true")
				return
			}
		} else if b.Name == "decltype(nullptr)" && (l.Val == "" || l.Val == "0") {
			if ps.llvmStyle {
				ps.writeString("nullptr")
			} else {
				ps.print(l.Type)
			}
			return
		} else {
			isFloat = builtinTypeFloat[b.Name]
		}
	}

	ps.startScope('(')
	ps.print(l.Type)
	ps.endScope(')')

	if isFloat {
		ps.writeByte('[')
	}
	if l.Neg {
		ps.writeByte('-')
	}
	ps.writeString(l.Val)
	if isFloat {
		ps.writeByte(']')
	}
}

func (l *Literal) Traverse(fn func(AST) bool) {
	if fn(l) {
		l.Type.Traverse(fn)
	}
}

func (l *Literal) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(l) {
		return nil
	}
	typ := l.Type.Copy(fn, skip)
	if typ == nil {
		return fn(l)
	}
	l = &Literal{Type: typ, Val: l.Val, Neg: l.Neg}
	if r := fn(l); r != nil {
		return r
	}
	return l
}

func (l *Literal) GoString() string {
	return l.goString(0, "")
}

func (l *Literal) goString(indent int, field string) string {
	var neg string
	if l.Neg {
		neg = " Neg: true"
	}
	return fmt.Sprintf("%*s%sLiteral:%s\n%s\n%*sVal: %s", indent, "", field,
		neg, l.Type.goString(indent+2, "Type: "),
		indent+2, "", l.Val)
}

func (l *Literal) prec() precedence {
	return precPrimary
}

// StringLiteral is a string literal.
type StringLiteral struct {
	Type AST
}

func (sl *StringLiteral) print(ps *printState) {
	ps.writeString(`"<`)
	sl.Type.print(ps)
	ps.writeString(`>"`)
}

func (sl *StringLiteral) Traverse(fn func(AST) bool) {
	if fn(sl) {
		sl.Type.Traverse(fn)
	}
}

func (sl *StringLiteral) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(sl) {
		return nil
	}
	typ := sl.Type.Copy(fn, skip)
	if typ == nil {
		return fn(sl)
	}
	sl = &StringLiteral{Type: typ}
	if r := fn(sl); r != nil {
		return r
	}
	return sl
}

func (sl *StringLiteral) GoString() string {
	return sl.goString(0, "")
}

func (sl *StringLiteral) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sStringLiteral:\n%s", indent, "", field,
		sl.Type.goString(indent+2, ""))
}

// LambdaExpr is a literal that is a lambda expression.
type LambdaExpr struct {
	Type AST
}

func (le *LambdaExpr) print(ps *printState) {
	ps.writeString("[]")
	if cl, ok := le.Type.(*Closure); ok {
		cl.printTypes(ps)
	}
	ps.writeString("{...}")
}

func (le *LambdaExpr) Traverse(fn func(AST) bool) {
	if fn(le) {
		le.Type.Traverse(fn)
	}
}

func (le *LambdaExpr) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(le) {
		return nil
	}
	typ := le.Type.Copy(fn, skip)
	if typ == nil {
		return fn(le)
	}
	le = &LambdaExpr{Type: typ}
	if r := fn(le); r != nil {
		return r
	}
	return le
}

func (le *LambdaExpr) GoString() string {
	return le.goString(0, "")
}

func (le *LambdaExpr) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sLambdaExpr:\n%s", indent, "", field,
		le.Type.goString(indent+2, ""))
}

// ExprList is a list of expressions, typically arguments to a
// function call in an expression.
type ExprList struct {
	Exprs []AST
}

func (el *ExprList) print(ps *printState) {
	ps.printList(el.Exprs, nil)
}

func (el *ExprList) Traverse(fn func(AST) bool) {
	if fn(el) {
		for _, e := range el.Exprs {
			e.Traverse(fn)
		}
	}
}

func (el *ExprList) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(el) {
		return nil
	}
	exprs := make([]AST, len(el.Exprs))
	changed := false
	for i, e := range el.Exprs {
		ec := e.Copy(fn, skip)
		if ec == nil {
			exprs[i] = e
		} else {
			exprs[i] = ec
			changed = true
		}
	}
	if !changed {
		return fn(el)
	}
	el = &ExprList{Exprs: exprs}
	if r := fn(el); r != nil {
		return r
	}
	return el
}

func (el *ExprList) GoString() string {
	return el.goString(0, "")
}

func (el *ExprList) goString(indent int, field string) string {
	if len(el.Exprs) == 0 {
		return fmt.Sprintf("%*s%sExprList: nil", indent, "", field)
	}
	s := fmt.Sprintf("%*s%sExprList:", indent, "", field)
	for i, e := range el.Exprs {
		s += "\n"
		s += e.goString(indent+2, fmt.Sprintf("%d: ", i))
	}
	return s
}

func (el *ExprList) prec() precedence {
	return precComma
}

// InitializerList is an initializer list: an optional type with a
// list of expressions.
type InitializerList struct {
	Type  AST
	Exprs AST
}

func (il *InitializerList) print(ps *printState) {
	if il.Type != nil {
		ps.print(il.Type)
	}
	ps.writeByte('{')
	ps.print(il.Exprs)
	ps.writeByte('}')
}

func (il *InitializerList) Traverse(fn func(AST) bool) {
	if fn(il) {
		if il.Type != nil {
			il.Type.Traverse(fn)
		}
		il.Exprs.Traverse(fn)
	}
}

func (il *InitializerList) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(il) {
		return nil
	}
	var typ AST
	if il.Type != nil {
		typ = il.Type.Copy(fn, skip)
	}
	exprs := il.Exprs.Copy(fn, skip)
	if typ == nil && exprs == nil {
		return fn(il)
	}
	if typ == nil {
		typ = il.Type
	}
	if exprs == nil {
		exprs = il.Exprs
	}
	il = &InitializerList{Type: typ, Exprs: exprs}
	if r := fn(il); r != nil {
		return r
	}
	return il
}

func (il *InitializerList) GoString() string {
	return il.goString(0, "")
}

func (il *InitializerList) goString(indent int, field string) string {
	var t string
	if il.Type == nil {
		t = fmt.Sprintf("%*sType: nil", indent+2, "")
	} else {
		t = il.Type.goString(indent+2, "Type: ")
	}
	return fmt.Sprintf("%*s%sInitializerList:\n%s\n%s", indent, "", field,
		t, il.Exprs.goString(indent+2, "Exprs: "))
}

// DefaultArg holds a default argument for a local name.
type DefaultArg struct {
	Num int
	Arg AST
}

func (da *DefaultArg) print(ps *printState) {
	if !ps.llvmStyle {
		fmt.Fprintf(&ps.buf, "{default arg#%d}::", da.Num+1)
	}
	ps.print(da.Arg)
}

func (da *DefaultArg) Traverse(fn func(AST) bool) {
	if fn(da) {
		da.Arg.Traverse(fn)
	}
}

func (da *DefaultArg) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(da) {
		return nil
	}
	arg := da.Arg.Copy(fn, skip)
	if arg == nil {
		return fn(da)
	}
	da = &DefaultArg{Num: da.Num, Arg: arg}
	if r := fn(da); r != nil {
		return r
	}
	return da
}

func (da *DefaultArg) GoString() string {
	return da.goString(0, "")
}

func (da *DefaultArg) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sDefaultArg: Num: %d\n%s", indent, "", field, da.Num,
		da.Arg.goString(indent+2, "Arg: "))
}

// Closure is a closure, or lambda expression.
type Closure struct {
	TemplateArgs           []AST
	TemplateArgsConstraint AST
	Types                  []AST
	Num                    int
	CallConstraint         AST
}

func (cl *Closure) print(ps *printState) {
	if ps.llvmStyle {
		if cl.Num == 0 {
			ps.writeString("'lambda'")
		} else {
			ps.writeString(fmt.Sprintf("'lambda%d'", cl.Num-1))
		}
	} else {
		ps.writeString("{lambda")
	}
	cl.printTypes(ps)
	if !ps.llvmStyle {
		ps.writeString(fmt.Sprintf("#%d}", cl.Num+1))
	}
}

func (cl *Closure) printTypes(ps *printState) {
	if len(cl.TemplateArgs) > 0 {
		scopes := ps.scopes
		ps.scopes = 0

		ps.writeString("<")
		ps.printList(cl.TemplateArgs, nil)
		ps.writeString(">")

		ps.scopes = scopes
	}

	if cl.TemplateArgsConstraint != nil {
		ps.writeString(" requires ")
		ps.print(cl.TemplateArgsConstraint)
		ps.writeByte(' ')
	}

	ps.startScope('(')
	ps.printList(cl.Types, nil)
	ps.endScope(')')

	if cl.CallConstraint != nil {
		ps.writeString(" requires ")
		ps.print(cl.CallConstraint)
	}
}

func (cl *Closure) Traverse(fn func(AST) bool) {
	if fn(cl) {
		for _, a := range cl.TemplateArgs {
			a.Traverse(fn)
		}
		if cl.TemplateArgsConstraint != nil {
			cl.TemplateArgsConstraint.Traverse(fn)
		}
		for _, t := range cl.Types {
			t.Traverse(fn)
		}
		if cl.CallConstraint != nil {
			cl.CallConstraint.Traverse(fn)
		}
	}
}

func (cl *Closure) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(cl) {
		return nil
	}
	changed := false

	args := make([]AST, len(cl.TemplateArgs))
	for i, a := range cl.TemplateArgs {
		ac := a.Copy(fn, skip)
		if ac == nil {
			args[i] = a
		} else {
			args[i] = ac
			changed = true
		}
	}

	var templateArgsConstraint AST
	if cl.TemplateArgsConstraint != nil {
		templateArgsConstraint = cl.TemplateArgsConstraint.Copy(fn, skip)
		if templateArgsConstraint == nil {
			templateArgsConstraint = cl.TemplateArgsConstraint
		} else {
			changed = true
		}
	}

	types := make([]AST, len(cl.Types))
	for i, t := range cl.Types {
		tc := t.Copy(fn, skip)
		if tc == nil {
			types[i] = t
		} else {
			types[i] = tc
			changed = true
		}
	}

	var callConstraint AST
	if cl.CallConstraint != nil {
		callConstraint = cl.CallConstraint.Copy(fn, skip)
		if callConstraint == nil {
			callConstraint = cl.CallConstraint
		} else {
			changed = true
		}
	}

	if !changed {
		return fn(cl)
	}
	cl = &Closure{
		TemplateArgs:           args,
		TemplateArgsConstraint: templateArgsConstraint,
		Types:                  types,
		Num:                    cl.Num,
		CallConstraint:         callConstraint,
	}
	if r := fn(cl); r != nil {
		return r
	}
	return cl
}

func (cl *Closure) GoString() string {
	return cl.goString(0, "")
}

func (cl *Closure) goString(indent int, field string) string {
	var args strings.Builder
	if len(cl.TemplateArgs) == 0 {
		fmt.Fprintf(&args, "%*sTemplateArgs: nil", indent+2, "")
	} else {
		fmt.Fprintf(&args, "%*sTemplateArgs:", indent+2, "")
		for i, a := range cl.TemplateArgs {
			args.WriteByte('\n')
			args.WriteString(a.goString(indent+4, fmt.Sprintf("%d: ", i)))
		}
	}

	var templateArgsConstraint string
	if cl.TemplateArgsConstraint != nil {
		templateArgsConstraint = "\n" + cl.TemplateArgsConstraint.goString(indent+2, "TemplateArgsConstraint: ")
	}

	var types strings.Builder
	if len(cl.Types) == 0 {
		fmt.Fprintf(&types, "%*sTypes: nil", indent+2, "")
	} else {
		fmt.Fprintf(&types, "%*sTypes:", indent+2, "")
		for i, t := range cl.Types {
			types.WriteByte('\n')
			types.WriteString(t.goString(indent+4, fmt.Sprintf("%d: ", i)))
		}
	}

	var callConstraint string
	if cl.CallConstraint != nil {
		callConstraint = "\n" + cl.CallConstraint.goString(indent+2, "CallConstraint: ")
	}

	return fmt.Sprintf("%*s%sClosure: Num: %d\n%s\n%s%s%s", indent, "", field,
		cl.Num, args.String(), templateArgsConstraint, types.String(),
		callConstraint)
}

// StructuredBindings is a structured binding declaration.
type StructuredBindings struct {
	Bindings []AST
}

func (sb *StructuredBindings) print(ps *printState) {
	ps.writeString("[")
	ps.printList(sb.Bindings, nil)
	ps.writeString("]")
}

func (sb *StructuredBindings) Traverse(fn func(AST) bool) {
	if fn(sb) {
		for _, b := range sb.Bindings {
			b.Traverse(fn)
		}
	}
}

func (sb *StructuredBindings) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(sb) {
		return nil
	}
	changed := false
	bindings := make([]AST, len(sb.Bindings))
	for i, b := range sb.Bindings {
		bc := b.Copy(fn, skip)
		if bc == nil {
			bindings[i] = b
		} else {
			bindings[i] = bc
			changed = true
		}
	}
	if !changed {
		return fn(sb)
	}
	sb = &StructuredBindings{Bindings: bindings}
	if r := fn(sb); r != nil {
		return r
	}
	return sb
}

func (sb *StructuredBindings) GoString() string {
	return sb.goString(0, "")
}

func (sb *StructuredBindings) goString(indent int, field string) string {
	var strb strings.Builder
	fmt.Fprintf(&strb, "%*s%sStructuredBinding:", indent, "", field)
	for _, b := range sb.Bindings {
		strb.WriteByte('\n')
		strb.WriteString(b.goString(indent+2, ""))
	}
	return strb.String()
}

// UnnamedType is an unnamed type, that just has an index.
type UnnamedType struct {
	Num int
}

func (ut *UnnamedType) print(ps *printState) {
	if ps.llvmStyle {
		if ut.Num == 0 {
			ps.writeString("'unnamed'")
		} else {
			ps.writeString(fmt.Sprintf("'unnamed%d'", ut.Num-1))
		}
	} else {
		ps.writeString(fmt.Sprintf("{unnamed type#%d}", ut.Num+1))
	}
}

func (ut *UnnamedType) Traverse(fn func(AST) bool) {
	fn(ut)
}

func (ut *UnnamedType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ut) {
		return nil
	}
	return fn(ut)
}

func (ut *UnnamedType) GoString() string {
	return ut.goString(0, "")
}

func (ut *UnnamedType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sUnnamedType: Num: %d", indent, "", field, ut.Num)
}

// Clone is a clone of a function, with a distinguishing suffix.
type Clone struct {
	Base   AST
	Suffix string
}

func (c *Clone) print(ps *printState) {
	ps.print(c.Base)
	if ps.llvmStyle {
		ps.writeByte(' ')
		ps.startScope('(')
		ps.writeString(c.Suffix)
		ps.endScope(')')
	} else {
		ps.writeString(fmt.Sprintf(" [clone %s]", c.Suffix))
	}
}

func (c *Clone) Traverse(fn func(AST) bool) {
	if fn(c) {
		c.Base.Traverse(fn)
	}
}

func (c *Clone) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(c) {
		return nil
	}
	base := c.Base.Copy(fn, skip)
	if base == nil {
		return fn(c)
	}
	c = &Clone{Base: base, Suffix: c.Suffix}
	if r := fn(c); r != nil {
		return r
	}
	return c
}

func (c *Clone) GoString() string {
	return c.goString(0, "")
}

func (c *Clone) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sClone: Suffix: %s\n%s", indent, "", field,
		c.Suffix, c.Base.goString(indent+2, "Base: "))
}

// Special is a special symbol, printed as a prefix plus another
// value.
type Special struct {
	Prefix string
	Val    AST
}

func (s *Special) print(ps *printState) {
	prefix := s.Prefix
	if ps.llvmStyle {
		switch prefix {
		case "TLS wrapper function for ":
			prefix = "thread-local wrapper routine for "
		case "TLS init function for ":
			prefix = "thread-local initialization routine for "
		}
	}
	ps.writeString(prefix)
	ps.print(s.Val)
}

func (s *Special) Traverse(fn func(AST) bool) {
	if fn(s) {
		s.Val.Traverse(fn)
	}
}

func (s *Special) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(s) {
		return nil
	}
	val := s.Val.Copy(fn, skip)
	if val == nil {
		return fn(s)
	}
	s = &Special{Prefix: s.Prefix, Val: val}
	if r := fn(s); r != nil {
		return r
	}
	return s
}

func (s *Special) GoString() string {
	return s.goString(0, "")
}

func (s *Special) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sSpecial: Prefix: %s\n%s", indent, "", field,
		s.Prefix, s.Val.goString(indent+2, "Val: "))
}

// Special2 is like special, but uses two values.
type Special2 struct {
	Prefix string
	Val1   AST
	Middle string
	Val2   AST
}

func (s *Special2) print(ps *printState) {
	ps.writeString(s.Prefix)
	ps.print(s.Val1)
	ps.writeString(s.Middle)
	ps.print(s.Val2)
}

func (s *Special2) Traverse(fn func(AST) bool) {
	if fn(s) {
		s.Val1.Traverse(fn)
		s.Val2.Traverse(fn)
	}
}

func (s *Special2) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(s) {
		return nil
	}
	val1 := s.Val1.Copy(fn, skip)
	val2 := s.Val2.Copy(fn, skip)
	if val1 == nil && val2 == nil {
		return fn(s)
	}
	if val1 == nil {
		val1 = s.Val1
	}
	if val2 == nil {
		val2 = s.Val2
	}
	s = &Special2{Prefix: s.Prefix, Val1: val1, Middle: s.Middle, Val2: val2}
	if r := fn(s); r != nil {
		return r
	}
	return s
}

func (s *Special2) GoString() string {
	return s.goString(0, "")
}

func (s *Special2) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sSpecial2: Prefix: %s\n%s\n%*sMiddle: %s\n%s", indent, "", field,
		s.Prefix, s.Val1.goString(indent+2, "Val1: "),
		indent+2, "", s.Middle, s.Val2.goString(indent+2, "Val2: "))
}

// EnableIf is used by clang for an enable_if attribute.
type EnableIf struct {
	Type AST
	Args []AST
}

func (ei *EnableIf) print(ps *printState) {
	ps.print(ei.Type)
	ps.writeString(" [enable_if:")
	ps.printList(ei.Args, nil)
	ps.writeString("]")
}

func (ei *EnableIf) Traverse(fn func(AST) bool) {
	if fn(ei) {
		ei.Type.Traverse(fn)
		for _, a := range ei.Args {
			a.Traverse(fn)
		}
	}
}

func (ei *EnableIf) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ei) {
		return nil
	}
	typ := ei.Type.Copy(fn, skip)
	argsChanged := false
	args := make([]AST, len(ei.Args))
	for i, a := range ei.Args {
		ac := a.Copy(fn, skip)
		if ac == nil {
			args[i] = a
		} else {
			args[i] = ac
			argsChanged = true
		}
	}
	if typ == nil && !argsChanged {
		return fn(ei)
	}
	if typ == nil {
		typ = ei.Type
	}
	ei = &EnableIf{Type: typ, Args: args}
	if r := fn(ei); r != nil {
		return r
	}
	return ei
}

func (ei *EnableIf) GoString() string {
	return ei.goString(0, "")
}

func (ei *EnableIf) goString(indent int, field string) string {
	var args string
	if len(ei.Args) == 0 {
		args = fmt.Sprintf("%*sArgs: nil", indent+2, "")
	} else {
		args = fmt.Sprintf("%*sArgs:", indent+2, "")
		for i, a := range ei.Args {
			args += "\n"
			args += a.goString(indent+4, fmt.Sprintf("%d: ", i))
		}
	}
	return fmt.Sprintf("%*s%sEnableIf:\n%s\n%s", indent, "", field,
		ei.Type.goString(indent+2, "Type: "), args)
}

// ModuleName is a C++20 module.
type ModuleName struct {
	Parent      AST
	Name        AST
	IsPartition bool
}

func (mn *ModuleName) print(ps *printState) {
	if mn.Parent != nil {
		ps.print(mn.Parent)
	}
	if mn.IsPartition {
		ps.writeByte(':')
	} else if mn.Parent != nil {
		ps.writeByte('.')
	}
	ps.print(mn.Name)
}

func (mn *ModuleName) Traverse(fn func(AST) bool) {
	if fn(mn) {
		mn.Parent.Traverse(fn)
		mn.Name.Traverse(fn)
	}
}

func (mn *ModuleName) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(mn) {
		return nil
	}
	var parent AST
	if mn.Parent != nil {
		parent = mn.Parent.Copy(fn, skip)
	}
	name := mn.Name.Copy(fn, skip)
	if parent == nil && name == nil {
		return fn(mn)
	}
	if parent == nil {
		parent = mn.Parent
	}
	if name == nil {
		name = mn.Name
	}
	mn = &ModuleName{Parent: parent, Name: name, IsPartition: mn.IsPartition}
	if r := fn(mn); r != nil {
		return r
	}
	return mn
}

func (mn *ModuleName) GoString() string {
	return mn.goString(0, "")
}

func (mn *ModuleName) goString(indent int, field string) string {
	var parent string
	if mn.Parent == nil {
		parent = fmt.Sprintf("%*sParent: nil", indent+2, "")
	} else {
		parent = mn.Parent.goString(indent+2, "Parent: ")
	}
	return fmt.Sprintf("%*s%sModuleName: IsPartition: %t\n%s\n%s", indent, "", field,
		mn.IsPartition, parent,
		mn.Name.goString(indent+2, "Name: "))
}

// ModuleEntity is a name inside a module.
type ModuleEntity struct {
	Module AST
	Name   AST
}

func (me *ModuleEntity) print(ps *printState) {
	ps.print(me.Name)
	ps.writeByte('@')
	ps.print(me.Module)
}

func (me *ModuleEntity) Traverse(fn func(AST) bool) {
	if fn(me) {
		me.Module.Traverse(fn)
		me.Name.Traverse(fn)
	}
}

func (me *ModuleEntity) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(me) {
		re
"""




```