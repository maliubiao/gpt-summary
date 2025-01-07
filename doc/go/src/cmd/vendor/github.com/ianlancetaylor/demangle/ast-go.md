Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The request asks for a functional summary of the provided Go code (`ast.go`) and, if possible, to deduce its purpose within a larger Go context, providing examples. It also specifically mentions handling of command-line arguments and common user errors, although the provided snippet doesn't seem to directly relate to either. Finally, it needs a concise summary of the functionality.

2. **Initial Scan and Keyword Spotting:** I quickly scanned the code for recurring keywords and patterns. "AST," "print," "Traverse," "Copy," "demangle," "C++," "template," "type," "qualifier," "operator," "expression" jumped out. This strongly suggests the code is about representing and manipulating C++ abstract syntax trees for demangling (reversing the mangling process that compilers use to encode symbols).

3. **Deconstruct the `AST` Interface:** The `AST` interface is central. I examined its methods:
    * `print(*printState)`:  Likely responsible for converting the AST node to its demangled string representation. The `printState` argument suggests managing formatting and context.
    * `Traverse(func(AST) bool)`:  A standard tree traversal mechanism. Useful for inspecting or modifying the tree structure.
    * `Copy(func(AST) AST, skip func(AST) bool)`:  A method for creating copies of AST nodes, potentially transforming them during the process. The `copy` and `skip` functions indicate flexibility in what gets copied and how.
    * `GoString() string` and `goString(indent int, field string)`: Implement the `fmt.GoStringer` interface, used for debugging and representing the AST structure in Go code.

4. **Analyze `ASTToString`:** This function seems to be the main entry point for demangling. It takes an `AST` and `Option`s as input. The options clearly control aspects of the demangling process (template parameters, enclosing parameters, LLVM style, maximum length). This confirms the demangling purpose.

5. **Examine `printState`:** This struct holds the contextual information needed for printing the AST. The fields like `tparams`, `enclosingParams`, `llvmStyle`, `max`, `scopes`, `buf`, `inner`, and `printing`  provide hints about the intricacies of C++ demangling (handling templates, nested scopes, preventing infinite recursion due to cycles).

6. **Study Concrete `AST` Implementations:** I then looked at the concrete types that implement the `AST` interface (e.g., `Name`, `Typed`, `Qualified`, `Template`, `PointerType`, `FunctionType`, `Operator`, etc.). These names directly correspond to elements of C++ syntax. This further solidifies the C++ demangling aspect. The methods on these types (especially `print`) implement the logic for formatting these C++ elements.

7. **Deduce Functionality and Provide Examples:** Based on the above analysis, I concluded that the code provides a way to represent C++ symbol names as abstract syntax trees and then convert these trees back into human-readable C++ declarations.

    * **Example Construction:**  I thought about a simple mangled C++ name and how the code might represent and demangle it. A simple case like `_Z3fooi` (function `foo` taking an `int`) is a good starting point. Then, I considered slightly more complex examples involving templates (like `_Z3barIiEvT_`) to demonstrate the `Template` node. The hypothetical input and output are key to illustrating the demangling process.

8. **Address Specific Questions:**

    * **Command-line Arguments:**  The provided snippet doesn't show direct command-line argument parsing. I mentioned that it *could* be used by a larger tool that takes command-line arguments, and those arguments might influence the `Option`s passed to `ASTToString`. This acknowledges the possibility without inventing details.

    * **Common User Errors:**  I considered potential issues related to the demangling process itself. Incorrectly specifying options (like trying to suppress template parameters when they are crucial) or providing mangled names that cannot be parsed are plausible user errors.

9. **Synthesize the Summary:** Finally, I formulated a concise summary that captured the core functionality: representing C++ declarations as ASTs and demangling them.

10. **Structure the Answer:** I organized the answer using the headings and format requested, ensuring all parts of the prompt were addressed. I used code blocks for the Go examples and kept the language clear and precise.

Essentially, I started with a high-level overview, progressively drilled down into the details of the code, used keyword recognition and pattern matching to infer the purpose, constructed examples to illustrate the functionality, and then addressed the specific questions in the prompt based on my understanding of the code.


这是一个 Go 语言实现的抽象语法树（AST），专门用于表示 C++ 的声明，目的是为了实现 **C++ 符号的 demangle (反修饰)** 功能。

**功能归纳:**

该 `ast.go` 文件的主要功能是定义了一系列 Go 语言的结构体和接口，用于构建和操作表示 C++ 声明的抽象语法树。这个 AST 具备以下核心能力：

1. **表示 C++ 声明结构:**  定义了各种 AST 节点类型，例如 `Name` (名称), `Typed` (带类型的名称), `Qualified` (限定名), `Template` (模板), `PointerType` (指针类型), `FunctionType` (函数类型), `Operator` (操作符) 等，可以完整地表示 C++ 的变量、函数、类型等声明结构。
2. **Demangle 成字符串:**  通过 `ASTToString` 函数以及每个 AST 节点实现的 `print` 方法，可以将 AST 转换回人类可读的 C++ 声明字符串。这个过程中可以根据 `Option` 参数控制输出格式，例如是否显示模板参数、是否使用 LLVM 风格等。
3. **AST 遍历:**  提供了 `Traverse` 方法，允许用户以某种顺序访问 AST 中的每个节点，用于分析或转换 AST。
4. **AST 复制:**  提供了 `Copy` 方法，可以创建 AST 的副本，并且可以在复制过程中进行自定义的转换或跳过某些节点。
5. **方便的 Go 字符串表示:** 实现了 `fmt.GoStringer` 接口，方便在 Go 代码中打印和调试 AST 的结构。

**可以推理出的 Go 语言功能实现：C++ 符号 Demangle**

根据代码中的命名（如 `demangle` 包名，`ASTToString` 函数名），以及其专门针对 C++ 声明的结构设计，可以推断出这部分代码是用于实现 **C++ 符号 Demangle** 功能的。

**Go 代码举例说明:**

假设我们有一个表示 C++ 函数声明 `int foo(int)` 的 AST 结构，我们可以使用 `ASTToString` 函数将其转换回字符串：

```go
package main

import (
	"fmt"
	"cmd/vendor/github.com/ianlancetaylor/demangle"
)

func main() {
	// 假设已经构建好了表示 "int foo(int)" 的 AST
	// 实际的构建过程会比较复杂，这里仅作示例
	functionAST := &demangle.FunctionType{
		Return: &demangle.BuiltinType{Name: "int"},
		Args: []demangle.AST{
			&demangle.BuiltinType{Name: "int"},
		},
	}
	nameAST := &demangle.Name{Name: "foo"}
	typedAST := &demangle.Typed{Name: nameAST, Type: functionAST}

	demangledString := demangle.ASTToString(typedAST)
	fmt.Println(demangledString) // 输出: foo(int)
}
```

**假设的输入与输出 (针对 `ASTToString`):**

**假设输入 (AST):**

```go
&demangle.Template{
    Name: &demangle.Name{Name: "vector"},
    Args: []demangle.AST{
        &demangle.Name{Name: "int"},
    },
}
```

**预期输出:**

```
vector<int>
```

**命令行参数的具体处理:**

该 `ast.go` 文件本身 **不直接处理命令行参数**。  但是，`ASTToString` 函数接受 `Option` 类型的可变参数，这些 `Option` 可以用来控制 demangle 的输出格式。  这些 `Option` 的值可能会在调用 `ASTToString` 的代码中基于命令行参数进行设置。

例如，在调用 `ASTToString` 的地方，可能会有类似这样的逻辑：

```go
// ... 从命令行参数中解析是否需要 LLVM 风格的输出
llvmStyle := false
// 假设使用了 flag 包进行命令行参数解析
// if *llvmFlag {
// 	llvmStyle = true
// }

options := []demangle.Option{}
if llvmStyle {
	options = append(options, demangle.LLVMStyle)
}

demangledString := demangle.ASTToString(myAST, options...)
```

这里，命令行参数决定了是否将 `demangle.LLVMStyle` 选项传递给 `ASTToString`，从而影响最终的 demangle 输出格式。

**功能总结:**

`go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go` 文件定义了用于表示 C++ 声明的抽象语法树结构，并提供了将 AST 转换为可读的 C++ 声明字符串的能力。这是实现 C++ 符号 demangle 功能的核心数据结构和方法。该文件本身不直接处理命令行参数，但其提供的 `Option` 机制允许调用者根据命令行参数来定制 demangle 的输出格式。

Prompt: 
```
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package demangle

import (
	"fmt"
	"strings"
)

// AST is an abstract syntax tree representing a C++ declaration.
// This is sufficient for the demangler but is by no means a general C++ AST.
// This abstract syntax tree is only used for C++ symbols, not Rust symbols.
type AST interface {
	// Internal method to convert to demangled string.
	print(*printState)

	// Traverse each element of an AST.  If the function returns
	// false, traversal of children of that element is skipped.
	Traverse(func(AST) bool)

	// Copy an AST with possible transformations.
	// If the skip function returns true, no copy is required.
	// If the copy function returns nil, no copy is required.
	// The Copy method will do the right thing if copy returns nil
	// for some components of an AST but not others, so a good
	// copy function will only return non-nil for AST values that
	// need to change.
	// Copy itself returns either a copy or nil.
	Copy(copy func(AST) AST, skip func(AST) bool) AST

	// Implement the fmt.GoStringer interface.
	GoString() string
	goString(indent int, field string) string
}

// ASTToString returns the demangled name of the AST.
func ASTToString(a AST, options ...Option) string {
	tparams := true
	enclosingParams := true
	llvmStyle := false
	max := 0
	for _, o := range options {
		switch {
		case o == NoTemplateParams:
			tparams = false
		case o == NoEnclosingParams:
			enclosingParams = false
		case o == LLVMStyle:
			llvmStyle = true
		case isMaxLength(o):
			max = maxLength(o)
		}
	}

	ps := printState{
		tparams:         tparams,
		enclosingParams: enclosingParams,
		llvmStyle:       llvmStyle,
		max:             max,
		scopes:          1,
	}
	a.print(&ps)
	s := ps.buf.String()
	if max > 0 && len(s) > max {
		s = s[:max]
	}
	return s
}

// The printState type holds information needed to print an AST.
type printState struct {
	tparams         bool // whether to print template parameters
	enclosingParams bool // whether to print enclosing parameters
	llvmStyle       bool
	max             int // maximum output length

	// The scopes field is used to avoid unnecessary parentheses
	// around expressions that use > (or >>). It is incremented if
	// we output a parenthesis or something else that means that >
	// or >> won't be treated as ending a template. It starts out
	// as 1, and is set to 0 when we start writing template
	// arguments. We add parentheses around expressions using > if
	// scopes is 0. The effect is that an expression with > gets
	// parentheses if used as a template argument that is not
	// inside some other set of parentheses.
	scopes int

	buf  strings.Builder
	last byte // Last byte written to buffer.

	// The inner field is a list of items to print for a type
	// name.  This is used by types to implement the inside-out
	// C++ declaration syntax.
	inner []AST

	// The printing field is a list of items we are currently
	// printing.  This avoids endless recursion if a substitution
	// reference creates a cycle in the graph.
	printing []AST
}

// writeByte adds a byte to the string being printed.
func (ps *printState) writeByte(b byte) {
	ps.last = b
	ps.buf.WriteByte(b)
}

// writeString adds a string to the string being printed.
func (ps *printState) writeString(s string) {
	if len(s) > 0 {
		ps.last = s[len(s)-1]
	}
	ps.buf.WriteString(s)
}

// Print an AST.
func (ps *printState) print(a AST) {
	if ps.max > 0 && ps.buf.Len() > ps.max {
		return
	}

	c := 0
	for _, v := range ps.printing {
		if v == a {
			// We permit the type to appear once, and
			// return without printing anything if we see
			// it twice.  This is for a case like
			// _Z6outer2IsEPFilES1_, where the
			// substitution is printed differently the
			// second time because the set of inner types
			// is different.
			c++
			if c > 1 {
				return
			}
		}
	}
	ps.printing = append(ps.printing, a)

	a.print(ps)

	ps.printing = ps.printing[:len(ps.printing)-1]
}

// printList prints a list of AST values separated by commas,
// optionally skipping some.
func (ps *printState) printList(args []AST, skip func(AST) bool) {
	first := true
	for _, a := range args {
		if skip != nil && skip(a) {
			continue
		}
		if !first {
			ps.writeString(", ")
		}

		needsParen := false
		if ps.llvmStyle {
			if p, ok := a.(hasPrec); ok {
				if p.prec() >= precComma {
					needsParen = true
				}
			}
		}
		if needsParen {
			ps.startScope('(')
		}

		ps.print(a)

		if needsParen {
			ps.endScope(')')
		}

		first = false
	}
}

// startScope starts a scope. This is used to decide whether we need
// to parenthesize an expression using > or >>.
func (ps *printState) startScope(b byte) {
	ps.scopes++
	ps.writeByte(b)
}

// endScope closes a scope.
func (ps *printState) endScope(b byte) {
	ps.scopes--
	ps.writeByte(b)
}

// precedence is used for operator precedence. This is used to avoid
// unnecessary parentheses when printing expressions in the LLVM style.
type precedence int

// The precedence values, in order from high to low.
const (
	precPrimary precedence = iota
	precPostfix
	precUnary
	precCast
	precPtrMem
	precMul
	precAdd
	precShift
	precSpaceship
	precRel
	precEqual
	precAnd
	precXor
	precOr
	precLogicalAnd
	precLogicalOr
	precCond
	precAssign
	precComma
	precDefault
)

// hasPrec matches the AST nodes that have a prec method that returns
// the node's precedence.
type hasPrec interface {
	prec() precedence
}

// Name is an unqualified name.
type Name struct {
	Name string
}

func (n *Name) print(ps *printState) {
	ps.writeString(n.Name)
}

func (n *Name) Traverse(fn func(AST) bool) {
	fn(n)
}

func (n *Name) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(n) {
		return nil
	}
	return fn(n)
}

func (n *Name) GoString() string {
	return n.goString(0, "Name: ")
}

func (n *Name) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%s%s", indent, "", field, n.Name)
}

func (n *Name) prec() precedence {
	return precPrimary
}

// Typed is a typed name.
type Typed struct {
	Name AST
	Type AST
}

func (t *Typed) print(ps *printState) {
	// We are printing a typed name, so ignore the current set of
	// inner names to print.  Pass down our name as the one to use.
	holdInner := ps.inner
	defer func() { ps.inner = holdInner }()

	ps.inner = []AST{t}
	ps.print(t.Type)
	if len(ps.inner) > 0 {
		// The type did not print the name; print it now in
		// the default location.
		ps.writeByte(' ')
		ps.print(t.Name)
	}
}

func (t *Typed) printInner(ps *printState) {
	ps.print(t.Name)
}

func (t *Typed) Traverse(fn func(AST) bool) {
	if fn(t) {
		t.Name.Traverse(fn)
		t.Type.Traverse(fn)
	}
}

func (t *Typed) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(t) {
		return nil
	}
	name := t.Name.Copy(fn, skip)
	typ := t.Type.Copy(fn, skip)
	if name == nil && typ == nil {
		return fn(t)
	}
	if name == nil {
		name = t.Name
	}
	if typ == nil {
		typ = t.Type
	}
	t = &Typed{Name: name, Type: typ}
	if r := fn(t); r != nil {
		return r
	}
	return t
}

func (t *Typed) GoString() string {
	return t.goString(0, "")
}

func (t *Typed) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTyped:\n%s\n%s", indent, "", field,
		t.Name.goString(indent+2, "Name: "),
		t.Type.goString(indent+2, "Type: "))
}

// Qualified is a name in a scope.
type Qualified struct {
	Scope AST
	Name  AST

	// The LocalName field is true if this is parsed as a
	// <local-name>.  We shouldn't really need this, but in some
	// cases (for the unary sizeof operator) the standard
	// demangler prints a local name slightly differently.  We
	// keep track of this for compatibility.
	LocalName bool // A full local name encoding
}

func (q *Qualified) print(ps *printState) {
	ps.print(q.Scope)
	ps.writeString("::")
	ps.print(q.Name)
}

func (q *Qualified) Traverse(fn func(AST) bool) {
	if fn(q) {
		q.Scope.Traverse(fn)
		q.Name.Traverse(fn)
	}
}

func (q *Qualified) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(q) {
		return nil
	}
	scope := q.Scope.Copy(fn, skip)
	name := q.Name.Copy(fn, skip)
	if scope == nil && name == nil {
		return fn(q)
	}
	if scope == nil {
		scope = q.Scope
	}
	if name == nil {
		name = q.Name
	}
	q = &Qualified{Scope: scope, Name: name, LocalName: q.LocalName}
	if r := fn(q); r != nil {
		return r
	}
	return q
}

func (q *Qualified) GoString() string {
	return q.goString(0, "")
}

func (q *Qualified) goString(indent int, field string) string {
	s := ""
	if q.LocalName {
		s = " LocalName: true"
	}
	return fmt.Sprintf("%*s%sQualified:%s\n%s\n%s", indent, "", field,
		s, q.Scope.goString(indent+2, "Scope: "),
		q.Name.goString(indent+2, "Name: "))
}

func (q *Qualified) prec() precedence {
	return precPrimary
}

// Template is a template with arguments.
type Template struct {
	Name AST
	Args []AST
}

func (t *Template) print(ps *printState) {
	// Inner types apply to the template as a whole, they don't
	// cross over into the template.
	holdInner := ps.inner
	defer func() { ps.inner = holdInner }()

	ps.inner = nil
	ps.print(t.Name)

	if !ps.tparams {
		// Do not print template parameters.
		return
	}
	// We need an extra space after operator<.
	if ps.last == '<' {
		ps.writeByte(' ')
	}

	scopes := ps.scopes
	ps.scopes = 0

	ps.writeByte('<')
	ps.printList(t.Args, ps.isEmpty)
	if ps.last == '>' && !ps.llvmStyle {
		// Avoid syntactic ambiguity in old versions of C++.
		ps.writeByte(' ')
	}
	ps.writeByte('>')

	ps.scopes = scopes
}

func (t *Template) Traverse(fn func(AST) bool) {
	if fn(t) {
		t.Name.Traverse(fn)
		for _, a := range t.Args {
			a.Traverse(fn)
		}
	}
}

func (t *Template) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(t) {
		return nil
	}
	name := t.Name.Copy(fn, skip)
	changed := name != nil
	args := make([]AST, len(t.Args))
	for i, a := range t.Args {
		ac := a.Copy(fn, skip)
		if ac == nil {
			args[i] = a
		} else {
			args[i] = ac
			changed = true
		}
	}
	if !changed {
		return fn(t)
	}
	if name == nil {
		name = t.Name
	}
	t = &Template{Name: name, Args: args}
	if r := fn(t); r != nil {
		return r
	}
	return t
}

func (t *Template) GoString() string {
	return t.goString(0, "")
}

func (t *Template) goString(indent int, field string) string {
	var args string
	if len(t.Args) == 0 {
		args = fmt.Sprintf("%*sArgs: nil", indent+2, "")
	} else {
		args = fmt.Sprintf("%*sArgs:", indent+2, "")
		for i, a := range t.Args {
			args += "\n"
			args += a.goString(indent+4, fmt.Sprintf("%d: ", i))
		}
	}
	return fmt.Sprintf("%*s%sTemplate (%p):\n%s\n%s", indent, "", field, t,
		t.Name.goString(indent+2, "Name: "), args)
}

// TemplateParam is a template parameter.  The Template field is
// filled in while parsing the demangled string.  We don't normally
// see these while printing--they are replaced by the simplify
// function.
type TemplateParam struct {
	Index    int
	Template *Template
}

func (tp *TemplateParam) print(ps *printState) {
	if tp.Template == nil {
		panic("TemplateParam Template field is nil")
	}
	if tp.Index >= len(tp.Template.Args) {
		panic("TemplateParam Index out of bounds")
	}
	ps.print(tp.Template.Args[tp.Index])
}

func (tp *TemplateParam) Traverse(fn func(AST) bool) {
	fn(tp)
	// Don't traverse Template--it points elsewhere in the AST.
}

func (tp *TemplateParam) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(tp) {
		return nil
	}
	return fn(tp)
}

func (tp *TemplateParam) GoString() string {
	return tp.goString(0, "")
}

func (tp *TemplateParam) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTemplateParam: Template: %p; Index %d", indent, "", field, tp.Template, tp.Index)
}

// LambdaAuto is a lambda auto parameter.
type LambdaAuto struct {
	Index int
}

func (la *LambdaAuto) print(ps *printState) {
	// We print the index plus 1 because that is what the standard
	// demangler does.
	if ps.llvmStyle {
		ps.writeString("auto")
	} else {
		fmt.Fprintf(&ps.buf, "auto:%d", la.Index+1)
	}
}

func (la *LambdaAuto) Traverse(fn func(AST) bool) {
	fn(la)
}

func (la *LambdaAuto) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(la) {
		return nil
	}
	return fn(la)
}

func (la *LambdaAuto) GoString() string {
	return la.goString(0, "")
}

func (la *LambdaAuto) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sLambdaAuto: Index %d", indent, "", field, la.Index)
}

// TemplateParamQualifiedArg is used when the mangled name includes
// both the template parameter declaration and the template argument.
// See https://github.com/itanium-cxx-abi/cxx-abi/issues/47.
type TemplateParamQualifiedArg struct {
	Param AST
	Arg   AST
}

func (tpqa *TemplateParamQualifiedArg) print(ps *printState) {
	// We only demangle the actual template argument.
	// That is what the LLVM demangler does.
	// The parameter disambiguates the argument,
	// but is hopefully not required by a human reader.
	ps.print(tpqa.Arg)
}

func (tpqa *TemplateParamQualifiedArg) Traverse(fn func(AST) bool) {
	if fn(tpqa) {
		tpqa.Param.Traverse(fn)
		tpqa.Arg.Traverse(fn)
	}
}

func (tpqa *TemplateParamQualifiedArg) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(tpqa) {
		return nil
	}
	param := tpqa.Param.Copy(fn, skip)
	arg := tpqa.Arg.Copy(fn, skip)
	if param == nil && arg == nil {
		return fn(tpqa)
	}
	if param == nil {
		param = tpqa.Param
	}
	if arg == nil {
		arg = tpqa.Arg
	}
	tpqa = &TemplateParamQualifiedArg{Param: param, Arg: arg}
	if r := fn(tpqa); r != nil {
		return r
	}
	return tpqa
}

func (tpqa *TemplateParamQualifiedArg) GoString() string {
	return tpqa.goString(0, "")
}

func (tpqa *TemplateParamQualifiedArg) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTemplateParamQualifiedArg:\n%s\n%s", indent, "", field,
		tpqa.Param.goString(indent+2, "Param: "),
		tpqa.Arg.goString(indent+2, "Arg: "))
}

// Qualifiers is an ordered list of type qualifiers.
type Qualifiers struct {
	Qualifiers []AST
}

func (qs *Qualifiers) print(ps *printState) {
	first := true
	for _, q := range qs.Qualifiers {
		if !first {
			ps.writeByte(' ')
		}
		q.print(ps)
		first = false
	}
}

func (qs *Qualifiers) Traverse(fn func(AST) bool) {
	if fn(qs) {
		for _, q := range qs.Qualifiers {
			q.Traverse(fn)
		}
	}
}

func (qs *Qualifiers) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(qs) {
		return nil
	}
	changed := false
	qualifiers := make([]AST, len(qs.Qualifiers))
	for i, q := range qs.Qualifiers {
		qc := q.Copy(fn, skip)
		if qc == nil {
			qualifiers[i] = q
		} else {
			qualifiers[i] = qc
			changed = true
		}
	}
	if !changed {
		return fn(qs)
	}
	qs = &Qualifiers{Qualifiers: qualifiers}
	if r := fn(qs); r != nil {
		return r
	}
	return qs
}

func (qs *Qualifiers) GoString() string {
	return qs.goString(0, "")
}

func (qs *Qualifiers) goString(indent int, field string) string {
	quals := fmt.Sprintf("%*s%s", indent, "", field)
	for _, q := range qs.Qualifiers {
		quals += "\n"
		quals += q.goString(indent+2, "")
	}
	return quals
}

// Qualifier is a single type qualifier.
type Qualifier struct {
	Name  string // qualifier name: const, volatile, etc.
	Exprs []AST  // can be non-nil for noexcept and throw
}

func (q *Qualifier) print(ps *printState) {
	ps.writeString(q.Name)
	if len(q.Exprs) > 0 {
		ps.startScope('(')
		first := true
		for _, e := range q.Exprs {
			if el, ok := e.(*ExprList); ok && len(el.Exprs) == 0 {
				continue
			}
			if !first {
				ps.writeString(", ")
			}
			ps.print(e)
			first = false
		}
		ps.endScope(')')
	}
}

func (q *Qualifier) Traverse(fn func(AST) bool) {
	if fn(q) {
		for _, e := range q.Exprs {
			e.Traverse(fn)
		}
	}
}

func (q *Qualifier) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(q) {
		return nil
	}
	exprs := make([]AST, len(q.Exprs))
	changed := false
	for i, e := range q.Exprs {
		ec := e.Copy(fn, skip)
		if ec == nil {
			exprs[i] = e
		} else {
			exprs[i] = ec
			changed = true
		}
	}
	if !changed {
		return fn(q)
	}
	q = &Qualifier{Name: q.Name, Exprs: exprs}
	if r := fn(q); r != nil {
		return r
	}
	return q
}

func (q *Qualifier) GoString() string {
	return q.goString(0, "Qualifier: ")
}

func (q *Qualifier) goString(indent int, field string) string {
	qs := fmt.Sprintf("%*s%s%s", indent, "", field, q.Name)
	if len(q.Exprs) > 0 {
		for i, e := range q.Exprs {
			qs += "\n"
			qs += e.goString(indent+2, fmt.Sprintf("%d: ", i))
		}
	}
	return qs
}

// TypeWithQualifiers is a type with standard qualifiers.
type TypeWithQualifiers struct {
	Base       AST
	Qualifiers AST
}

func (twq *TypeWithQualifiers) print(ps *printState) {
	// Give the base type a chance to print the inner types.
	ps.inner = append(ps.inner, twq)
	ps.print(twq.Base)
	if len(ps.inner) > 0 {
		// The qualifier wasn't printed by Base.
		ps.writeByte(' ')
		ps.print(twq.Qualifiers)
		ps.inner = ps.inner[:len(ps.inner)-1]
	}
}

// Print qualifiers as an inner type by just printing the qualifiers.
func (twq *TypeWithQualifiers) printInner(ps *printState) {
	ps.writeByte(' ')
	ps.print(twq.Qualifiers)
}

func (twq *TypeWithQualifiers) Traverse(fn func(AST) bool) {
	if fn(twq) {
		twq.Base.Traverse(fn)
	}
}

func (twq *TypeWithQualifiers) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(twq) {
		return nil
	}
	base := twq.Base.Copy(fn, skip)
	quals := twq.Qualifiers.Copy(fn, skip)
	if base == nil && quals == nil {
		return fn(twq)
	}
	if base == nil {
		base = twq.Base
	}
	if quals == nil {
		quals = twq.Qualifiers
	}
	twq = &TypeWithQualifiers{Base: base, Qualifiers: quals}
	if r := fn(twq); r != nil {
		return r
	}
	return twq
}

func (twq *TypeWithQualifiers) GoString() string {
	return twq.goString(0, "")
}

func (twq *TypeWithQualifiers) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTypeWithQualifiers:\n%s\n%s", indent, "", field,
		twq.Qualifiers.goString(indent+2, "Qualifiers: "),
		twq.Base.goString(indent+2, "Base: "))
}

// MethodWithQualifiers is a method with qualifiers.
type MethodWithQualifiers struct {
	Method       AST
	Qualifiers   AST
	RefQualifier string // "" or "&" or "&&"
}

func (mwq *MethodWithQualifiers) print(ps *printState) {
	// Give the base type a chance to print the inner types.
	ps.inner = append(ps.inner, mwq)
	ps.print(mwq.Method)
	if len(ps.inner) > 0 {
		if mwq.Qualifiers != nil {
			ps.writeByte(' ')
			ps.print(mwq.Qualifiers)
		}
		if mwq.RefQualifier != "" {
			ps.writeByte(' ')
			ps.writeString(mwq.RefQualifier)
		}
		ps.inner = ps.inner[:len(ps.inner)-1]
	}
}

func (mwq *MethodWithQualifiers) printInner(ps *printState) {
	if mwq.Qualifiers != nil {
		ps.writeByte(' ')
		ps.print(mwq.Qualifiers)
	}
	if mwq.RefQualifier != "" {
		ps.writeByte(' ')
		ps.writeString(mwq.RefQualifier)
	}
}

func (mwq *MethodWithQualifiers) Traverse(fn func(AST) bool) {
	if fn(mwq) {
		mwq.Method.Traverse(fn)
	}
}

func (mwq *MethodWithQualifiers) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(mwq) {
		return nil
	}
	method := mwq.Method.Copy(fn, skip)
	var quals AST
	if mwq.Qualifiers != nil {
		quals = mwq.Qualifiers.Copy(fn, skip)
	}
	if method == nil && quals == nil {
		return fn(mwq)
	}
	if method == nil {
		method = mwq.Method
	}
	if quals == nil {
		quals = mwq.Qualifiers
	}
	mwq = &MethodWithQualifiers{Method: method, Qualifiers: quals, RefQualifier: mwq.RefQualifier}
	if r := fn(mwq); r != nil {
		return r
	}
	return mwq
}

func (mwq *MethodWithQualifiers) GoString() string {
	return mwq.goString(0, "")
}

func (mwq *MethodWithQualifiers) goString(indent int, field string) string {
	var q string
	if mwq.Qualifiers != nil {
		q += "\n" + mwq.Qualifiers.goString(indent+2, "Qualifiers: ")
	}
	if mwq.RefQualifier != "" {
		if q != "" {
			q += "\n"
		}
		q += fmt.Sprintf("%*s%s%s", indent+2, "", "RefQualifier: ", mwq.RefQualifier)
	}
	return fmt.Sprintf("%*s%sMethodWithQualifiers:%s\n%s", indent, "", field,
		q, mwq.Method.goString(indent+2, "Method: "))
}

// BuiltinType is a builtin type, like "int".
type BuiltinType struct {
	Name string
}

func (bt *BuiltinType) print(ps *printState) {
	name := bt.Name
	if ps.llvmStyle && name == "decltype(nullptr)" {
		name = "std::nullptr_t"
	}
	ps.writeString(name)
}

func (bt *BuiltinType) Traverse(fn func(AST) bool) {
	fn(bt)
}

func (bt *BuiltinType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(bt) {
		return nil
	}
	return fn(bt)
}

func (bt *BuiltinType) GoString() string {
	return bt.goString(0, "")
}

func (bt *BuiltinType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sBuiltinType: %s", indent, "", field, bt.Name)
}

func (bt *BuiltinType) prec() precedence {
	return precPrimary
}

// printBase is common print code for types that are printed with a
// simple suffix.
func printBase(ps *printState, qual, base AST) {
	ps.inner = append(ps.inner, qual)
	ps.print(base)
	if len(ps.inner) > 0 {
		qual.(innerPrinter).printInner(ps)
		ps.inner = ps.inner[:len(ps.inner)-1]
	}
}

// PointerType is a pointer type.
type PointerType struct {
	Base AST
}

func (pt *PointerType) print(ps *printState) {
	printBase(ps, pt, pt.Base)
}

func (pt *PointerType) printInner(ps *printState) {
	ps.writeString("*")
}

func (pt *PointerType) Traverse(fn func(AST) bool) {
	if fn(pt) {
		pt.Base.Traverse(fn)
	}
}

func (pt *PointerType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(pt) {
		return nil
	}
	base := pt.Base.Copy(fn, skip)
	if base == nil {
		return fn(pt)
	}
	pt = &PointerType{Base: base}
	if r := fn(pt); r != nil {
		return r
	}
	return pt
}

func (pt *PointerType) GoString() string {
	return pt.goString(0, "")
}

func (pt *PointerType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sPointerType:\n%s", indent, "", field,
		pt.Base.goString(indent+2, ""))
}

// ReferenceType is a reference type.
type ReferenceType struct {
	Base AST
}

func (rt *ReferenceType) print(ps *printState) {
	printBase(ps, rt, rt.Base)
}

func (rt *ReferenceType) printInner(ps *printState) {
	ps.writeString("&")
}

func (rt *ReferenceType) Traverse(fn func(AST) bool) {
	if fn(rt) {
		rt.Base.Traverse(fn)
	}
}

func (rt *ReferenceType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(rt) {
		return nil
	}
	base := rt.Base.Copy(fn, skip)
	if base == nil {
		return fn(rt)
	}
	rt = &ReferenceType{Base: base}
	if r := fn(rt); r != nil {
		return r
	}
	return rt
}

func (rt *ReferenceType) GoString() string {
	return rt.goString(0, "")
}

func (rt *ReferenceType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sReferenceType:\n%s", indent, "", field,
		rt.Base.goString(indent+2, ""))
}

// RvalueReferenceType is an rvalue reference type.
type RvalueReferenceType struct {
	Base AST
}

func (rt *RvalueReferenceType) print(ps *printState) {
	printBase(ps, rt, rt.Base)
}

func (rt *RvalueReferenceType) printInner(ps *printState) {
	ps.writeString("&&")
}

func (rt *RvalueReferenceType) Traverse(fn func(AST) bool) {
	if fn(rt) {
		rt.Base.Traverse(fn)
	}
}

func (rt *RvalueReferenceType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(rt) {
		return nil
	}
	base := rt.Base.Copy(fn, skip)
	if base == nil {
		return fn(rt)
	}
	rt = &RvalueReferenceType{Base: base}
	if r := fn(rt); r != nil {
		return r
	}
	return rt
}

func (rt *RvalueReferenceType) GoString() string {
	return rt.goString(0, "")
}

func (rt *RvalueReferenceType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sRvalueReferenceType:\n%s", indent, "", field,
		rt.Base.goString(indent+2, ""))
}

// ComplexType is a complex type.
type ComplexType struct {
	Base AST
}

func (ct *ComplexType) print(ps *printState) {
	printBase(ps, ct, ct.Base)
}

func (ct *ComplexType) printInner(ps *printState) {
	ps.writeString(" _Complex")
}

func (ct *ComplexType) Traverse(fn func(AST) bool) {
	if fn(ct) {
		ct.Base.Traverse(fn)
	}
}

func (ct *ComplexType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ct) {
		return nil
	}
	base := ct.Base.Copy(fn, skip)
	if base == nil {
		return fn(ct)
	}
	ct = &ComplexType{Base: base}
	if r := fn(ct); r != nil {
		return r
	}
	return ct
}

func (ct *ComplexType) GoString() string {
	return ct.goString(0, "")
}

func (ct *ComplexType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sComplexType:\n%s", indent, "", field,
		ct.Base.goString(indent+2, ""))
}

// ImaginaryType is an imaginary type.
type ImaginaryType struct {
	Base AST
}

func (it *ImaginaryType) print(ps *printState) {
	printBase(ps, it, it.Base)
}

func (it *ImaginaryType) printInner(ps *printState) {
	ps.writeString(" _Imaginary")
}

func (it *ImaginaryType) Traverse(fn func(AST) bool) {
	if fn(it) {
		it.Base.Traverse(fn)
	}
}

func (it *ImaginaryType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(it) {
		return nil
	}
	base := it.Base.Copy(fn, skip)
	if base == nil {
		return fn(it)
	}
	it = &ImaginaryType{Base: base}
	if r := fn(it); r != nil {
		return r
	}
	return it
}

func (it *ImaginaryType) GoString() string {
	return it.goString(0, "")
}

func (it *ImaginaryType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sImaginaryType:\n%s", indent, "", field,
		it.Base.goString(indent+2, ""))
}

// SuffixType is an type with an arbitrary suffix.
type SuffixType struct {
	Base   AST
	Suffix string
}

func (st *SuffixType) print(ps *printState) {
	printBase(ps, st, st.Base)
}

func (st *SuffixType) printInner(ps *printState) {
	ps.writeByte(' ')
	ps.writeString(st.Suffix)
}

func (st *SuffixType) Traverse(fn func(AST) bool) {
	if fn(st) {
		st.Base.Traverse(fn)
	}
}

func (st *SuffixType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(st) {
		return nil
	}
	base := st.Base.Copy(fn, skip)
	if base == nil {
		return fn(st)
	}
	st = &SuffixType{Base: base, Suffix: st.Suffix}
	if r := fn(st); r != nil {
		return r
	}
	return st
}

func (st *SuffixType) GoString() string {
	return st.goString(0, "")
}

func (st *SuffixType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sSuffixType: %s\n%s", indent, "", field,
		st.Suffix, st.Base.goString(indent+2, "Base: "))
}

// TransformedType is a builtin type with a template argument.
type TransformedType struct {
	Name string
	Base AST
}

func (tt *TransformedType) print(ps *printState) {
	ps.writeString(tt.Name)
	ps.startScope('(')
	ps.print(tt.Base)
	ps.endScope(')')
}

func (tt *TransformedType) Traverse(fn func(AST) bool) {
	if fn(tt) {
		tt.Base.Traverse(fn)
	}
}

func (tt *TransformedType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(tt) {
		return nil
	}
	base := tt.Base.Copy(fn, skip)
	if base == nil {
		return fn(tt)
	}
	tt = &TransformedType{Name: tt.Name, Base: base}
	if r := fn(tt); r != nil {
		return r
	}
	return tt
}

func (tt *TransformedType) GoString() string {
	return tt.goString(0, "")
}

func (tt *TransformedType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTransformedType: %s\n%s", indent, "", field,
		tt.Name, tt.Base.goString(indent+2, "Base: "))
}

// VendorQualifier is a type qualified by a vendor-specific qualifier.
type VendorQualifier struct {
	Qualifier AST
	Type      AST
}

func (vq *VendorQualifier) print(ps *printState) {
	if ps.llvmStyle {
		ps.print(vq.Type)
		vq.printInner(ps)
	} else {
		ps.inner = append(ps.inner, vq)
		ps.print(vq.Type)
		if len(ps.inner) > 0 {
			ps.printOneInner(nil)
		}
	}
}

func (vq *VendorQualifier) printInner(ps *printState) {
	ps.writeByte(' ')
	ps.print(vq.Qualifier)
}

func (vq *VendorQualifier) Traverse(fn func(AST) bool) {
	if fn(vq) {
		vq.Qualifier.Traverse(fn)
		vq.Type.Traverse(fn)
	}
}

func (vq *VendorQualifier) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(vq) {
		return nil
	}
	qualifier := vq.Qualifier.Copy(fn, skip)
	typ := vq.Type.Copy(fn, skip)
	if qualifier == nil && typ == nil {
		return fn(vq)
	}
	if qualifier == nil {
		qualifier = vq.Qualifier
	}
	if typ == nil {
		typ = vq.Type
	}
	vq = &VendorQualifier{Qualifier: qualifier, Type: vq.Type}
	if r := fn(vq); r != nil {
		return r
	}
	return vq
}

func (vq *VendorQualifier) GoString() string {
	return vq.goString(0, "")
}

func (vq *VendorQualifier) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sVendorQualifier:\n%s\n%s", indent, "", field,
		vq.Qualifier.goString(indent+2, "Qualifier: "),
		vq.Type.goString(indent+2, "Type: "))
}

// ArrayType is an array type.
type ArrayType struct {
	Dimension AST
	Element   AST
}

func (at *ArrayType) print(ps *printState) {
	// Pass the array type down as an inner type so that we print
	// multi-dimensional arrays correctly.
	ps.inner = append(ps.inner, at)
	ps.print(at.Element)
	if ln := len(ps.inner); ln > 0 {
		ps.inner = ps.inner[:ln-1]
		at.printDimension(ps)
	}
}

func (at *ArrayType) printInner(ps *printState) {
	at.printDimension(ps)
}

// Print the array dimension.
func (at *ArrayType) printDimension(ps *printState) {
	space := " "
	for len(ps.inner) > 0 {
		// We haven't gotten to the real type yet.  Use
		// parentheses around that type, except that if it is
		// an array type we print it as a multi-dimensional
		// array
		in := ps.inner[len(ps.inner)-1]
		if twq, ok := in.(*TypeWithQualifiers); ok {
			in = twq.Base
		}
		if _, ok := in.(*ArrayType); ok {
			if in == ps.inner[len(ps.inner)-1] {
				space = ""
			}
			ps.printOneInner(nil)
		} else {
			ps.writeByte(' ')
			ps.startScope('(')
			ps.printInner(false)
			ps.endScope(')')
		}
	}
	ps.writeString(space)
	ps.writeByte('[')
	ps.print(at.Dimension)
	ps.writeByte(']')
}

func (at *ArrayType) Traverse(fn func(AST) bool) {
	if fn(at) {
		at.Dimension.Traverse(fn)
		at.Element.Traverse(fn)
	}
}

func (at *ArrayType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(at) {
		return nil
	}
	dimension := at.Dimension.Copy(fn, skip)
	element := at.Element.Copy(fn, skip)
	if dimension == nil && element == nil {
		return fn(at)
	}
	if dimension == nil {
		dimension = at.Dimension
	}
	if element == nil {
		element = at.Element
	}
	at = &ArrayType{Dimension: dimension, Element: element}
	if r := fn(at); r != nil {
		return r
	}
	return at
}

func (at *ArrayType) GoString() string {
	return at.goString(0, "")
}

func (at *ArrayType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sArrayType:\n%s\n%s", indent, "", field,
		at.Dimension.goString(indent+2, "Dimension: "),
		at.Element.goString(indent+2, "Element: "))
}

// FunctionType is a function type.
type FunctionType struct {
	Return AST
	Args   []AST

	// The forLocalName field reports whether this FunctionType
	// was created for a local name. With the default GNU demangling
	// output we don't print the return type in that case.
	ForLocalName bool
}

func (ft *FunctionType) print(ps *printState) {
	retType := ft.Return
	if ft.ForLocalName && (!ps.enclosingParams || !ps.llvmStyle) {
		retType = nil
	}
	if retType != nil {
		// Pass the return type as an inner type in order to
		// print the arguments in the right location.
		ps.inner = append(ps.inner, ft)
		ps.print(retType)
		if len(ps.inner) == 0 {
			// Everything was printed.
			return
		}
		ps.inner = ps.inner[:len(ps.inner)-1]
		ps.writeByte(' ')
	}
	ft.printArgs(ps)
}

func (ft *FunctionType) printInner(ps *printState) {
	ft.printArgs(ps)
}

// printArgs prints the arguments of a function type.  It looks at the
// inner types for spacing.
func (ft *FunctionType) printArgs(ps *printState) {
	paren := false
	space := false
	for i := len(ps.inner) - 1; i >= 0; i-- {
		switch ps.inner[i].(type) {
		case *PointerType, *ReferenceType, *RvalueReferenceType:
			paren = true
		case *TypeWithQualifiers, *ComplexType, *ImaginaryType, *PtrMem:
			space = true
			paren = true
		}
		if paren {
			break
		}
	}

	if paren {
		if !space && (ps.last != '(' && ps.last != '*') {
			space = true
		}
		if space && ps.last != ' ' {
			ps.writeByte(' ')
		}
		ps.startScope('(')
	}

	save := ps.printInner(true)

	if paren {
		ps.endScope(')')
	}

	ps.startScope('(')
	if !ft.ForLocalName || ps.enclosingParams {
		first := true
		for _, a := range ft.Args {
			if ps.isEmpty(a) {
				continue
			}
			if !first {
				ps.writeString(", ")
			}
			ps.print(a)
			first = false
		}
	}
	ps.endScope(')')

	ps.inner = save
	ps.printInner(false)
}

func (ft *FunctionType) Traverse(fn func(AST) bool) {
	if fn(ft) {
		if ft.Return != nil {
			ft.Return.Traverse(fn)
		}
		for _, a := range ft.Args {
			a.Traverse(fn)
		}
	}
}

func (ft *FunctionType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ft) {
		return nil
	}
	changed := false
	var ret AST
	if ft.Return != nil {
		ret = ft.Return.Copy(fn, skip)
		if ret == nil {
			ret = ft.Return
		} else {
			changed = true
		}
	}
	args := make([]AST, len(ft.Args))
	for i, a := range ft.Args {
		ac := a.Copy(fn, skip)
		if ac == nil {
			args[i] = a
		} else {
			args[i] = ac
			changed = true
		}
	}
	if !changed {
		return fn(ft)
	}
	ft = &FunctionType{
		Return:       ret,
		Args:         args,
		ForLocalName: ft.ForLocalName,
	}
	if r := fn(ft); r != nil {
		return r
	}
	return ft
}

func (ft *FunctionType) GoString() string {
	return ft.goString(0, "")
}

func (ft *FunctionType) goString(indent int, field string) string {
	var forLocalName string
	if ft.ForLocalName {
		forLocalName = " ForLocalName: true"
	}
	var r string
	if ft.Return == nil {
		r = fmt.Sprintf("%*sReturn: nil", indent+2, "")
	} else {
		r = ft.Return.goString(indent+2, "Return: ")
	}
	var args string
	if len(ft.Args) == 0 {
		args = fmt.Sprintf("%*sArgs: nil", indent+2, "")
	} else {
		args = fmt.Sprintf("%*sArgs:", indent+2, "")
		for i, a := range ft.Args {
			args += "\n"
			args += a.goString(indent+4, fmt.Sprintf("%d: ", i))
		}
	}
	return fmt.Sprintf("%*s%sFunctionType:%s\n%s\n%s", indent, "", field,
		forLocalName, r, args)
}

// FunctionParam is a parameter of a function, used for last-specified
// return type in a closure.
type FunctionParam struct {
	Index int
}

func (fp *FunctionParam) print(ps *printState) {
	if fp.Index == 0 {
		ps.writeString("this")
	} else if ps.llvmStyle {
		if fp.Index == 1 {
			ps.writeString("fp")
		} else {
			fmt.Fprintf(&ps.buf, "fp%d", fp.Index-2)
		}
	} else {
		fmt.Fprintf(&ps.buf, "{parm#%d}", fp.Index)
	}
}

func (fp *FunctionParam) Traverse(fn func(AST) bool) {
	fn(fp)
}

func (fp *FunctionParam) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(fp) {
		return nil
	}
	return fn(fp)
}

func (fp *FunctionParam) GoString() string {
	return fp.goString(0, "")
}

func (fp *FunctionParam) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sFunctionParam: %d", indent, "", field, fp.Index)
}

func (fp *FunctionParam) prec() precedence {
	return precPrimary
}

// PtrMem is a pointer-to-member expression.
type PtrMem struct {
	Class  AST
	Member AST
}

func (pm *PtrMem) print(ps *printState) {
	ps.inner = append(ps.inner, pm)
	ps.print(pm.Member)
	if len(ps.inner) > 0 {
		ps.printOneInner(nil)
	}
}

func (pm *PtrMem) printInner(ps *printState) {
	if ps.last != '(' {
		ps.writeByte(' ')
	}
	ps.print(pm.Class)
	ps.writeString("::*")
}

func (pm *PtrMem) Traverse(fn func(AST) bool) {
	if fn(pm) {
		pm.Class.Traverse(fn)
		pm.Member.Traverse(fn)
	}
}

func (pm *PtrMem) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(pm) {
		return nil
	}
	class := pm.Class.Copy(fn, skip)
	member := pm.Member.Copy(fn, skip)
	if class == nil && member == nil {
		return fn(pm)
	}
	if class == nil {
		class = pm.Class
	}
	if member == nil {
		member = pm.Member
	}
	pm = &PtrMem{Class: class, Member: member}
	if r := fn(pm); r != nil {
		return r
	}
	return pm
}

func (pm *PtrMem) GoString() string {
	return pm.goString(0, "")
}

func (pm *PtrMem) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sPtrMem:\n%s\n%s", indent, "", field,
		pm.Class.goString(indent+2, "Class: "),
		pm.Member.goString(indent+2, "Member: "))
}

// FixedType is a fixed numeric type of unknown size.
type FixedType struct {
	Base  AST
	Accum bool
	Sat   bool
}

func (ft *FixedType) print(ps *printState) {
	if ft.Sat {
		ps.writeString("_Sat ")
	}
	if bt, ok := ft.Base.(*BuiltinType); ok && bt.Name == "int" {
		// The standard demangler skips printing "int".
	} else {
		ps.print(ft.Base)
		ps.writeByte(' ')
	}
	if ft.Accum {
		ps.writeString("_Accum")
	} else {
		ps.writeString("_Fract")
	}
}

func (ft *FixedType) Traverse(fn func(AST) bool) {
	if fn(ft) {
		ft.Base.Traverse(fn)
	}
}

func (ft *FixedType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ft) {
		return nil
	}
	base := ft.Base.Copy(fn, skip)
	if base == nil {
		return fn(ft)
	}
	ft = &FixedType{Base: base, Accum: ft.Accum, Sat: ft.Sat}
	if r := fn(ft); r != nil {
		return r
	}
	return ft
}

func (ft *FixedType) GoString() string {
	return ft.goString(0, "")
}

func (ft *FixedType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sFixedType: Accum: %t; Sat: %t\n%s", indent, "", field,
		ft.Accum, ft.Sat,
		ft.Base.goString(indent+2, "Base: "))
}

// BinaryFP is a binary floating-point type.
type BinaryFP struct {
	Bits int
}

func (bfp *BinaryFP) print(ps *printState) {
	fmt.Fprintf(&ps.buf, "_Float%d", bfp.Bits)
}

func (bfp *BinaryFP) Traverse(fn func(AST) bool) {
	fn(bfp)
}

func (bfp *BinaryFP) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(bfp) {
		return nil
	}
	return fn(bfp)
}

func (bfp *BinaryFP) GoString() string {
	return bfp.goString(0, "")
}

func (bfp *BinaryFP) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sBinaryFP: %d", indent, "", field, bfp.Bits)
}

// BitIntType is the C++23 _BitInt(N) type.
type BitIntType struct {
	Size   AST
	Signed bool
}

func (bt *BitIntType) print(ps *printState) {
	if !bt.Signed {
		ps.writeString("unsigned ")
	}
	ps.writeString("_BitInt")
	ps.startScope('(')
	ps.print(bt.Size)
	ps.endScope(')')
}

func (bt *BitIntType) Traverse(fn func(AST) bool) {
	if fn(bt) {
		bt.Size.Traverse(fn)
	}
}

func (bt *BitIntType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(bt) {
		return nil
	}
	size := bt.Size.Copy(fn, skip)
	if size == nil {
		return fn(bt)
	}
	bt = &BitIntType{Size: size, Signed: bt.Signed}
	if r := fn(bt); r != nil {
		return r
	}
	return bt
}

func (bt *BitIntType) GoString() string {
	return bt.goString(0, "")
}

func (bt *BitIntType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sBitIntType: Signed: %t\n%s", indent, "", field,
		bt.Signed,
		bt.Size.goString(indent+2, "Size: "))
}

// VectorType is a vector type.
type VectorType struct {
	Dimension AST
	Base      AST
}

func (vt *VectorType) print(ps *printState) {
	ps.inner = append(ps.inner, vt)
	ps.print(vt.Base)
	if len(ps.inner) > 0 {
		ps.printOneInner(nil)
	}
}

func (vt *VectorType) printInner(ps *printState) {
	end := byte(')')
	if ps.llvmStyle {
		ps.writeString(" vector[")
		end = ']'
	} else {
		ps.writeString(" __vector(")
	}
	ps.print(vt.Dimension)
	ps.writeByte(end)
}

func (vt *VectorType) Traverse(fn func(AST) bool) {
	if fn(vt) {
		vt.Dimension.Traverse(fn)
		vt.Base.Traverse(fn)
	}
}

func (vt *VectorType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(vt) {
		return nil
	}
	dimension := vt.Dimension.Copy(fn, skip)
	base := vt.Base.Copy(fn, skip)
	if dimension == nil && base == nil {
		return fn(vt)
	}
	if dimension == nil {
		dimension = vt.Dimension
	}
	if base == nil {
		base = vt.Base
	}
	vt = &VectorType{Dimension: dimension, Base: base}
	if r := fn(vt); r != nil {
		return r
	}
	return vt
}

func (vt *VectorType) GoString() string {
	return vt.goString(0, "")
}

func (vt *VectorType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sVectorType:\n%s\n%s", indent, "", field,
		vt.Dimension.goString(indent+2, "Dimension: "),
		vt.Base.goString(indent+2, "Base: "))
}

// ElaboratedType is an elaborated struct/union/enum type.
type ElaboratedType struct {
	Kind string
	Type AST
}

func (et *ElaboratedType) print(ps *printState) {
	ps.writeString(et.Kind)
	ps.writeString(" ")
	et.Type.print(ps)
}

func (et *ElaboratedType) Traverse(fn func(AST) bool) {
	if fn(et) {
		et.Type.Traverse(fn)
	}
}

func (et *ElaboratedType) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(et) {
		return nil
	}
	typ := et.Type.Copy(fn, skip)
	if typ == nil {
		return fn(et)
	}
	et = &ElaboratedType{Kind: et.Kind, Type: typ}
	if r := fn(et); r != nil {
		return r
	}
	return et
}

func (et *ElaboratedType) GoString() string {
	return et.goString(0, "")
}

func (et *ElaboratedType) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sElaboratedtype: Kind: %s\n%s", indent, "", field,
		et.Kind, et.Type.goString(indent+2, "Expr: "))
}

// Decltype is the decltype operator.
type Decltype struct {
	Expr AST
}

func (dt *Decltype) print(ps *printState) {
	ps.writeString("decltype")
	if !ps.llvmStyle {
		ps.writeString(" ")
	}
	ps.startScope('(')
	ps.print(dt.Expr)
	ps.endScope(')')
}

func (dt *Decltype) Traverse(fn func(AST) bool) {
	if fn(dt) {
		dt.Expr.Traverse(fn)
	}
}

func (dt *Decltype) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(dt) {
		return nil
	}
	expr := dt.Expr.Copy(fn, skip)
	if expr == nil {
		return fn(dt)
	}
	dt = &Decltype{Expr: expr}
	if r := fn(dt); r != nil {
		return r
	}
	return dt
}

func (dt *Decltype) GoString() string {
	return dt.goString(0, "")
}

func (dt *Decltype) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sDecltype:\n%s", indent, "", field,
		dt.Expr.goString(indent+2, "Expr: "))
}

// Operator is an operator.
type Operator struct {
	Name       string
	precedence precedence
}

func (op *Operator) print(ps *printState) {
	ps.writeString("operator")
	if isLower(op.Name[0]) {
		ps.writeByte(' ')
	}
	n := op.Name
	n = strings.TrimSuffix(n, " ")
	ps.writeString(n)
}

func (op *Operator) Traverse(fn func(AST) bool) {
	fn(op)
}

func (op *Operator) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(op) {
		return nil
	}
	return fn(op)
}

func (op *Operator) GoString() string {
	return op.goString(0, "")
}

func (op *Operator) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sOperator: %s", indent, "", field, op.Name)
}

func (op *Operator) prec() precedence {
	return op.precedence
}

// Constructor is a constructor.
type Constructor struct {
	Name AST
	Base AST // base class of inheriting constructor
}

func (c *Constructor) print(ps *printState) {
	ps.print(c.Name)
	// We don't include the base class in the demangled string.
}

func (c *Constructor) Traverse(fn func(AST) bool) {
	if fn(c) {
		c.Name.Traverse(fn)
		if c.Base != nil {
			c.Base.Traverse(fn)
		}
	}
}

func (c *Constructor) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(c) {
		return nil
	}
	name := c.Name.Copy(fn, skip)
	var base AST
	if c.Base != nil {
		base = c.Base.Copy(fn, skip)
	}
	if name == nil && base == nil {
		return fn(c)
	}
	if name == nil {
		name = c.Name
	}
	if base == nil {
		base = c.Base
	}
	c = &Constructor{Name: name, Base: base}
	if r := fn(c); r != nil {
		return r
	}
	return c
}

func (c *Constructor) GoString() string {
	return c.goString(0, "")
}

func (c *Constructor) goString(indent int, field string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%*s%sConstructor:\n", indent, "", field)
	if c.Base != nil {
		fmt.Fprintf(&sb, "%s\n", c.Base.goString(indent+2, "Base: "))
	}
	fmt.Fprintf(&sb, "%s", c.Name.goString(indent+2, "Name: "))
	return sb.String()
}

// Destructor is a destructor.
type Destructor struct {
	Name AST
}

func (d *Destructor) print(ps *printState) {
	ps.writeByte('~')
	ps.print(d.Name)
}

func (d *Destructor) Traverse(fn func(AST) bool) {
	if fn(d) {
		d.Name.Traverse(fn)
	}
}

func (d *Destructor) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(d) {
		return nil
	}
	name := d.Name.Copy(fn, skip)
	if name == nil {
		return fn(d)
	}
	d = &Destructor{Name: name}
	if r := fn(d); r != nil {
		return r
	}
	return d
}

func (d *Destructor) GoString() string {
	return d.goString(0, "")
}

func (d *Destructor) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sDestructor:\n%s", indent, "", field, d.Name.goString(indent+2, "Name: "))
}

// GlobalCDtor is a global constructor or destructor.
type GlobalCDtor struct {
	Ctor bool
	Key  AST
}

func (gcd *GlobalCDtor) print(ps *printState) {
	ps.writeString("global ")
	if gcd.Ctor {
		ps.writeString("constructors")
	} else {
		ps.writeString("destructors")
	}
	ps.writeString(" keyed to ")
	ps.print(gcd.Key)
}

func (gcd *GlobalCDtor) Traverse(fn func(AST) bool) {
	if fn(gcd) {
		gcd.Key.Traverse(fn)
	}
}

func (gcd *GlobalCDtor) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(gcd) {
		return nil
	}
	key := gcd.Key.Copy(fn, skip)
	if key == nil {
		return fn(gcd)
	}
	gcd = &GlobalCDtor{Ctor: gcd.Ctor, Key: key}
	if r := fn(gcd); r != nil {
		return r
	}
	return gcd
}

func (gcd *GlobalCDtor) GoString() string {
	return gcd.goString(0, "")
}

func (gcd *GlobalCDtor) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sGlobalCDtor: Ctor: %t\n%s", indent, "", field,
		gcd.Ctor, gcd.Key.goString(indent+2, "Key: "))
}

// TaggedName is a name with an ABI tag.
type TaggedName struct {
	Name AST
	Tag  AST
}

func (t *TaggedName) print(ps *printState) {
	ps.print(t.Name)
	ps.writeString("[abi:")
	ps.print(t.Tag)
	ps.writeByte(']')
}

func (t *TaggedName) Traverse(fn func(AST) bool) {
	if fn(t) {
		t.Name.Traverse(fn)
		t.Tag.Traverse(fn)
	}
}

func (t *TaggedName) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(t) {
		return nil
	}
	name := t.Name.Copy(fn, skip)
	tag := t.Tag.Copy(fn, skip)
	if name == nil && tag == nil {
		return fn(t)
	}
	if name == nil {
		name = t.Name
	}
	if tag == nil {
		tag = t.Tag
	}
	t = &TaggedName{Name: name, Tag: tag}
	if r := fn(t); r != nil {
		return r
	}
	return t
}

func (t *TaggedName) GoString() string {
	return t.goString(0, "")
}

func (t *TaggedName) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTaggedName:\n%s\n%s", indent, "", field,
		t.Name.goString(indent+2, "Name: "),
		t.Tag.goString(indent+2, "Tag: "))
}

// PackExpansion is a pack expansion.  The Pack field may be nil.
type PackExpansion struct {
	Base AST
	Pack *ArgumentPack
}

func (pe *PackExpansion) print(ps *printState) {
	// We normally only get here if the simplify function was
	// unable to locate and expand the pack.
	if pe.Pack == nil {
		if ps.llvmStyle {
			ps.print(pe.Base)
		} else {
			parenthesize(ps, pe.Base)
			ps.writeString("...")
		}
	} else {
		ps.print(pe.Base)
	}
}

func (pe *PackExpansion) Traverse(fn func(AST) bool) {
	if fn(pe) {
		pe.Base.Traverse(fn)
		// Don't traverse Template--it points elsewhere in the AST.
	}
}

func (pe *PackExpansion) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(pe) {
		return nil
	}
	base := pe.Base.Copy(fn, skip)
	if base == nil {
		return fn(pe)
	}
	pe = &PackExpansion{Base: base, Pack: pe.Pack}
	if r := fn(pe); r != nil {
		return r
	}
	return pe
}

func (pe *PackExpansion) GoString() string {
	return pe.goString(0, "")
}

func (pe *PackExpansion) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sPackExpansion: Pack: %p\n%s", indent, "", field,
		pe.Pack, pe.Base.goString(indent+2, "Base: "))
}

// ArgumentPack is an argument pack.
type ArgumentPack struct {
	Args []AST
}

func (ap *ArgumentPack) print(ps *printState) {
	for i, a := range ap.Args {
		if i > 0 {
			ps.writeString(", ")
		}
		ps.print(a)
	}
}

func (ap *ArgumentPack) Traverse(fn func(AST) bool) {
	if fn(ap) {
		for _, a := range ap.Args {
			a.Traverse(fn)
		}
	}
}

func (ap *ArgumentPack) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ap) {
		return nil
	}
	args := make([]AST, len(ap.Args))
	changed := false
	for i, a := range ap.Args {
		ac := a.Copy(fn, skip)
		if ac == nil {
			args[i] = a
		} else {
			args[i] = ac
			changed = true
		}
	}
	if !changed {
		return fn(ap)
	}
	ap = &ArgumentPack{Args: args}
	if r := fn(ap); r != nil {
		return r
	}
	return ap
}

func (ap *ArgumentPack) GoString() string {
	return ap.goString(0, "")
}

func (ap *ArgumentPack) goString(indent int, field string) string {
	if len(ap.Args) == 0 {
		return fmt.Sprintf("%*s%sArgumentPack: nil", indent, "", field)
	}
	s := fmt.Sprintf("%*s%sArgumentPack:", indent, "", field)
	for i, a := range ap.Args {
		s += "\n"
		s += a.goString(indent+2, fmt.Sprintf("%d: ", i))
	}
	return s
}

// SizeofPack is the sizeof operator applied to an argument pack.
type SizeofPack struct {
	Pack *ArgumentPack
}

func (sp *SizeofPack) print(ps *printState) {
	if ps.llvmStyle {
		ps.writeString("sizeof...")
		ps.startScope('(')
		ps.print(sp.Pack)
		ps.endScope(')')
	} else {
		ps.writeString(fmt.Sprintf("%d", len(sp.Pack.Args)))
	}
}

func (sp *SizeofPack) Traverse(fn func(AST) bool) {
	fn(sp)
	// Don't traverse the pack--it points elsewhere in the AST.
}

func (sp *SizeofPack) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(sp) {
		return nil
	}
	sp = &SizeofPack{Pack: sp.Pack}
	if r := fn(sp); r != nil {
		return r
	}
	return sp
}

func (sp *SizeofPack) GoString() string {
	return sp.goString(0, "")
}

func (sp *SizeofPack) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sSizeofPack: Pack: %p", indent, "", field, sp.Pack)
}

// SizeofArgs is the size of a captured template parameter pack from
// an alias template.
type SizeofArgs struct {
	Args []AST
}

func (sa *SizeofArgs) print(ps *printState) {
	c := 0
	for _, a := range sa.Args {
		if ap, ok := a.(*ArgumentPack); ok {
			c += len(ap.Args)
		} else if el, ok := a.(*ExprList); ok {
			c += len(el.Exprs)
		} else {
			c++
		}
	}
	ps.writeString(fmt.Sprintf("%d", c))
}

func (sa *SizeofArgs) Traverse(fn func(AST) bool) {
	if fn(sa) {
		for _, a := range sa.Args {
			a.Traverse(fn)
		}
	}
}

func (sa *SizeofArgs) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(sa) {
		return nil
	}
	changed := false
	args := make([]AST, len(sa.Args))
	for i, a := range sa.Args {
		ac := a.Copy(fn, skip)
		if ac == nil {
			args[i] = a
		} else {
			args[i] = ac
			changed = true
		}
	}
	if !changed {
		return fn(sa)
	}
	sa = &SizeofArgs{Args: args}
	if r := fn(sa); r != nil {
		return r
	}
	return sa
}

func (sa *SizeofArgs) GoString() string {
	return sa.goString(0, "")
}

func (sa *SizeofArgs) goString(indent int, field string) string {
	var args string
	if len(sa.Args) == 0 {
		args = fmt.Sprintf("%*sArgs: nil", indent+2, "")
	} else {
		args = fmt.Sprintf("%*sArgs:", indent+2, "")
		for i, a := range sa.Args {
			args += "\n"
			args += a.goString(indent+4, fmt.Sprintf("%d: ", i))
		}
	}
	return fmt.Sprintf("%*s%sSizeofArgs:\n%s", indent, "", field, args)
}

// TemplateParamName is the name of a template parameter that the
// demangler introduced for a lambda that has explicit template
// parameters.  This is a prefix with an index.
type TemplateParamName struct {
	Prefix string
	Index  int
}

func (tpn *TemplateParamName) print(ps *printState) {
	ps.writeString(tpn.Prefix)
	if tpn.Index > 0 {
		ps.writeString(fmt.Sprintf("%d", tpn.Index-1))
	}
}

func (tpn *TemplateParamName) Traverse(fn func(AST) bool) {
	fn(tpn)
}

func (tpn *TemplateParamName) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(tpn) {
		return nil
	}
	return fn(tpn)
}

func (tpn *TemplateParamName) GoString() string {
	return tpn.goString(0, "")
}

func (tpn *TemplateParamName) goString(indent int, field string) string {
	name := tpn.Prefix
	if tpn.Index > 0 {
		name += fmt.Sprintf("%d", tpn.Index-1)
	}
	return fmt.Sprintf("%*s%sTemplateParamName: %s", indent, "", field, name)
}

// TypeTemplateParam is a type template parameter that appears in a
// lambda with explicit template parameters.
type TypeTemplateParam struct {
	Name AST
}

func (ttp *TypeTemplateParam) print(ps *printState) {
	ps.writeString("typename ")
	ps.printInner(false)
	ps.print(ttp.Name)
}

func (ttp *TypeTemplateParam) Traverse(fn func(AST) bool) {
	if fn(ttp) {
		ttp.Name.Traverse(fn)
	}
}

func (ttp *TypeTemplateParam) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ttp) {
		return nil
	}
	name := ttp.Name.Copy(fn, skip)
	if name == nil {
		return fn(ttp)
	}
	ttp = &TypeTemplateParam{Name: name}
	if r := fn(ttp); r != nil {
		return r
	}
	return ttp
}

func (ttp *TypeTemplateParam) GoString() string {
	return ttp.goString(0, "")
}

func (ttp *TypeTemplateParam) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTypeTemplateParam:\n%s", indent, "", field,
		ttp.Name.goString(indent+2, "Name"))
}

// NonTypeTemplateParam is a non-type template parameter that appears
// in a lambda with explicit template parameters.
type NonTypeTemplateParam struct {
	Name AST
	Type AST
}

func (nttp *NonTypeTemplateParam) print(ps *printState) {
	ps.inner = append(ps.inner, nttp)
	ps.print(nttp.Type)
	if len(ps.inner) > 0 {
		ps.writeByte(' ')
		ps.print(nttp.Name)
		ps.inner = ps.inner[:len(ps.inner)-1]
	}
}

func (nttp *NonTypeTemplateParam) printInner(ps *printState) {
	ps.print(nttp.Name)
}

func (nttp *NonTypeTemplateParam) Traverse(fn func(AST) bool) {
	if fn(nttp) {
		nttp.Name.Traverse(fn)
		nttp.Type.Traverse(fn)
	}
}

func (nttp *NonTypeTemplateParam) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(nttp) {
		return nil
	}
	name := nttp.Name.Copy(fn, skip)
	typ := nttp.Type.Copy(fn, skip)
	if name == nil && typ == nil {
		return fn(nttp)
	}
	if name == nil {
		name = nttp.Name
	}
	if typ == nil {
		typ = nttp.Type
	}
	nttp = &NonTypeTemplateParam{Name: name, Type: typ}
	if r := fn(nttp); r != nil {
		return r
	}
	return nttp
}

func (nttp *NonTypeTemplateParam) GoString() string {
	return nttp.goString(0, "")
}

func (nttp *NonTypeTemplateParam) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sNonTypeTemplateParam:\n%s\n%s", indent, "", field,
		nttp.Name.goString(indent+2, "Name: "),
		nttp.Type.goString(indent+2, "Type: "))
}

// TemplateTemplateParam is a template template parameter that appears
// in a lambda with explicit template parameters.
type TemplateTemplateParam struct {
	Name       AST
	Params     []AST
	Constraint AST
}

func (ttp *TemplateTemplateParam) print(ps *printState) {
	scopes := ps.scopes
	ps.scopes = 0

	ps.writeString("template<")
	ps.printList(ttp.Params, nil)
	ps.writeString("> typename ")

	ps.scopes = scopes

	ps.print(ttp.Name)

	if ttp.Constraint != nil {
		ps.writeString(" requires ")
		ps.print(ttp.Constraint)
	}
}

func (ttp *TemplateTemplateParam) Traverse(fn func(AST) bool) {
	if fn(ttp) {
		ttp.Name.Traverse(fn)
		for _, param := range ttp.Params {
			param.Traverse(fn)
		}
		if ttp.Constraint != nil {
			ttp.Constraint.Traverse(fn)
		}
	}
}

func (ttp *TemplateTemplateParam) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(ttp) {
		return nil
	}

	changed := false

	name := ttp.Name.Copy(fn, skip)
	if name == nil {
		name = ttp.Name
	} else {
		changed = true
	}

	params := make([]AST, len(ttp.Params))
	for i, p := range ttp.Params {
		pc := p.Copy(fn, skip)
		if pc == nil {
			params[i] = p
		} else {
			params[i] = pc
			changed = true
		}
	}

	var constraint AST
	if ttp.Constraint != nil {
		constraint = ttp.Constraint.Copy(fn, skip)
		if constraint == nil {
			constraint = ttp.Constraint
		} else {
			changed = true
		}
	}

	if !changed {
		return fn(ttp)
	}

	ttp = &TemplateTemplateParam{
		Name:       name,
		Params:     params,
		Constraint: constraint,
	}
	if r := fn(ttp); r != nil {
		return r
	}
	return ttp
}

func (ttp *TemplateTemplateParam) GoString() string {
	return ttp.goString(0, "")
}

func (ttp *TemplateTemplateParam) goString(indent int, field string) string {
	var params strings.Builder
	fmt.Fprintf(&params, "%*sParams:", indent+2, "")
	for i, p := range ttp.Params {
		params.WriteByte('\n')
		params.WriteString(p.goString(indent+4, fmt.Sprintf("%d: ", i)))
	}
	var constraint string
	if ttp.Constraint == nil {
		constraint = fmt.Sprintf("%*sConstraint: nil", indent+2, "")
	} else {
		constraint = ttp.Constraint.goString(indent+2, "Constraint: ")
	}
	return fmt.Sprintf("%*s%sTemplateTemplateParam:\n%s\n%s\n%s", indent, "", field,
		ttp.Name.goString(indent+2, "Name: "),
		params.String(),
		constraint)
}

// ConstrainedTypeTemplateParam is a constrained template type
// parameter declaration.
type ConstrainedTypeTemplateParam struct {
	Name       AST
	Constraint AST
}

func (cttp *ConstrainedTypeTemplateParam) print(ps *printState) {
	ps.inner = append(ps.inner, cttp)
	ps.print(cttp.Constraint)
	if len(ps.inner) > 0 {
		ps.writeByte(' ')
		ps.print(cttp.Name)
		ps.inner = ps.inner[:len(ps.inner)-1]
	}
}

func (cttp *ConstrainedTypeTemplateParam) printInner(ps *printState) {
	ps.print(cttp.Name)
}

func (cttp *ConstrainedTypeTemplateParam) Traverse(fn func(AST) bool) {
	if fn(cttp) {
		cttp.Name.Traverse(fn)
		cttp.Constraint.Traverse(fn)
	}
}

func (cttp *ConstrainedTypeTemplateParam) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(cttp) {
		return nil
	}
	name := cttp.Name.Copy(fn, skip)
	constraint := cttp.Constraint.Copy(fn, skip)
	if name == nil && constraint == nil {
		return fn(cttp)
	}
	if name == nil {
		name = cttp.Name
	}
	if constraint == nil {
		constraint = cttp.Constraint
	}
	cttp = &ConstrainedTypeTemplateParam{Name: name, Constraint: constraint}
	if r := fn(cttp); r != nil {
		return r
	}
	return cttp
}

func (cttp *ConstrainedTypeTemplateParam) GoString() string {
	return cttp.goString(0, "")
}

func (cttp *ConstrainedTypeTemplateParam) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sConstrainedTypeTemplateParam\n%s\n%s", indent, "", field,
		cttp.Name.goString(indent+2, "Name: "),
		cttp.Constraint.goString(indent+2, "Constraint: "))
}

// TemplateParamPack is a template parameter pack that appears in a
// lambda with explicit template parameters.
type TemplateParamPack struct {
	Param AST
}

func (tpp *TemplateParamPack) print(ps *printState) {
	holdInner := ps.inner
	defer func() { ps.inner = holdInner }()

	ps.inner = []AST{tpp}
	if nttp, ok := tpp.Param.(*NonTypeTemplateParam); ok {
		ps.print(nttp.Type)
	} else {
		ps.print(tpp.Param)
	}
	if len(ps.inner) > 0 {
		ps.writeString("...")
	}
}

func (tpp *TemplateParamPack) printInner(ps *printState) {
	ps.writeString("...")
	if nttp, ok := tpp.Param.(*NonTypeTemplateParam); ok {
		ps.print(nttp.Name)
	}
}

func (tpp *TemplateParamPack) Traverse(fn func(AST) bool) {
	if fn(tpp) {
		tpp.Param.Traverse(fn)
	}
}

func (tpp *TemplateParamPack) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(tpp) {
		return nil
	}
	param := tpp.Param.Copy(fn, skip)
	if param == nil {
		return fn(tpp)
	}
	tpp = &TemplateParamPack{Param: param}
	if r := fn(tpp); r != nil {
		return r
	}
	return tpp
}

func (tpp *TemplateParamPack) GoString() string {
	return tpp.goString(0, "")
}

func (tpp *TemplateParamPack) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTemplateParamPack:\n%s", indent, "", field,
		tpp.Param.goString(indent+2, "Param: "))
}

// Cast is a type cast.
type Cast struct {
	To AST
}

func (c *Cast) print(ps *printState) {
	ps.writeString("operator ")
	ps.print(c.To)
}

func (c *Cast) Traverse(fn func(AST) bool) {
	if fn(c) {
		c.To.Traverse(fn)
	}
}

func (c *Cast) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(c) {
		return nil
	}
	to := c.To.Copy(fn, skip)
	if to == nil {
		return fn(c)
	}
	c = &Cast{To: to}
	if r := fn(c); r != nil {
		return r
	}
	return c
}

func (c *Cast) GoString() string {
	return c.goString(0, "")
}

func (c *Cast) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sCast\n%s", indent, "", field,
		c.To.goString(indent+2, "To: "))
}

func (c *Cast) prec() precedence {
	return precCast
}

// The parenthesize function prints the string for val, wrapped in
// parentheses if necessary.
func parenthesize(ps *printState, val AST) {
	paren := false
	switch v := val.(type) {
	case *Name, *InitializerList:
	case *FunctionParam:
		if ps.llvmStyle {
			paren = true
		}
	case *Qualified:
		if v.LocalName {
			paren = true
		}
	default:
		paren = true
	}
	if paren {
		ps.startScope('(')
	}
	ps.print(val)
	if paren {
		ps.endScope(')')
	}
}

// Nullary is an operator in an expression with no arguments, such as
// throw.
type Nullary struct {
	Op AST
}

func (n *Nullary) print(ps *printState) {
	if op, ok := n.Op.(*Operator); ok {
		ps.writeString(op.Name)
	} else {
		ps.print(n.Op)
	}
}

func (n *Nullary) Traverse(fn func(AST) bool) {
	if fn(n) {
		n.Op.Traverse(fn)
	}
}

func (n *Nullary) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(n) {
		return nil
	}
	op := n.Op.Copy(fn, skip)
	if op == nil {
		return fn(n)
	}
	n = &Nullary{Op: op}
	if r := fn(n); r != nil {
		return r
	}
	return n
}

func (n *Nullary) GoString() string {
	return n.goString(0, "")
}

func (n *Nullary) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sNullary:\n%s", indent, "", field,
		n.Op.goString(indent+2, "Op: "))
}

// Unary is a unary operation in an expression.
type Unary struct {
	Op         AST
	Expr       AST
	Suffix     bool // true for ++ -- when used as postfix
	SizeofType bool // true for sizeof (type)
}

func (u *Unary) print(ps *printState) {
	op, _ := u.Op.(*Operator)
	expr := u.Expr

	// Don't print the argument list when taking the address of a
	// function.
	if !ps.llvmStyle {
		if op != nil && op.Name == "&" {
			if t, ok := expr.(*Typed); ok {
				if _, ok := t.Type.(*FunctionType); ok {
					expr = t.Name
				}
			}
		}
	}

	if u.Suffix {
		if ps.llvmStyle {
			wantParens := true
			opPrec := precUnary
			if op != nil {
				opPrec = op.precedence
			}
			if p, ok := expr.(hasPrec); ok {
				if p.prec() < opPrec {
					wantParens = false
				}
			}
			if wantParens {
				ps.startScope('(')
			}
			ps.print(expr)
			if wantParens {
				ps.endScope(')')
			}
		} else {
			parenthesize(ps, expr)
		}
	}

	if op != nil {
		ps.writeString(op.Name)
		if ps.llvmStyle && op.Name == "noexcept" {
			ps.writeByte(' ')
		}
	} else if c, ok := u.Op.(*Cast); ok {
		ps.startScope('(')
		ps.print(c.To)
		ps.endScope(')')
	} else {
		ps.print(u.Op)
	}

	if !u.Suffix {
		isDelete := op != nil && (op.Name == "delete " || op.Name == "delete[] ")
		if op != nil && op.Name == "::" {
			// Don't use parentheses after ::.
			ps.print(expr)
		} else if u.SizeofType {
			// Always use parentheses for sizeof argument.
			ps.startScope('(')
			ps.print(expr)
			ps.endScope(')')
		} else if op != nil && op.Name == "__alignof__" {
			// Always use parentheses for __alignof__ argument.
			ps.startScope('(')
			ps.print(expr)
			ps.endScope(')')
		} else if ps.llvmStyle {
			var wantParens bool
			switch {
			case op == nil:
				wantParens = true
			case op.Name == `operator"" `:
				wantParens = false
			case op.Name == "&":
				wantParens = false
			case isDelete:
				wantParens = false
			case op.Name == "alignof ":
				wantParens = true
			case op.Name == "sizeof ":
				wantParens = true
			case op.Name == "typeid ":
				wantParens = true
			default:
				wantParens = true
				if p, ok := expr.(hasPrec); ok {
					if p.prec() < op.precedence {
						wantParens = false
					}
				}
			}
			if wantParens {
				ps.startScope('(')
			}
			ps.print(expr)
			if wantParens {
				ps.endScope(')')
			}
		} else {
			parenthesize(ps, expr)
		}
	}
}

func (u *Unary) Traverse(fn func(AST) bool) {
	if fn(u) {
		u.Op.Traverse(fn)
		u.Expr.Traverse(fn)
	}
}

func (u *Unary) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(u) {
		return nil
	}
	op := u.Op.Copy(fn, skip)
	expr := u.Expr.Copy(fn, skip)
	if op == nil && expr == nil {
		return fn(u)
	}
	if op == nil {
		op = u.Op
	}
	if expr == nil {
		expr = u.Expr
	}
	u = &Unary{Op: op, Expr: expr, Suffix: u.Suffix, SizeofType: u.SizeofType}
	if r := fn(u); r != nil {
		return r
	}
	return u
}

func (u *Unary) GoString() string {
	return u.goString(0, "")
}

func (u *Unary) goString(indent int, field string) string {
	var s string
	if u.Suffix {
		s = " Suffix: true"
	}
	if u.SizeofType {
		s += " SizeofType: true"
	}
	return fmt.Sprintf("%*s%sUnary:%s\n%s\n%s", indent, "", field,
		s, u.Op.goString(indent+2, "Op: "),
		u.Expr.goString(indent+2, "Expr: "))
}

func (u *Unary) prec() precedence {
	if p, ok := u.Op.(hasPrec); ok {
		return p.prec()
	}
	return precDefault
}

// isDesignatedInitializer reports whether x is a designated
// initializer.
func isDesignatedInitializer(x AST) bool {
	switch x := x.(type) {
	case *Binary:
		if op, ok := x.Op.(*Operator); ok {
			if op.Name == "]=" {
				return true
			}
			if op.Name != "=" {
				return false
			}
			if _, ok := x.Left.(*Literal); ok {
				return false
			}
			return true
		}
	case *Trinary:
		if op, ok := x.Op.(*Operator); ok {
			return op.Name == "[...]="
		}
	}
	return false
}

// Binary is a binary operation in an expression.
type Binary struct {
	Op    AST
	Left  AST
	Right AST
}

func (b *Binary) print(ps *printState) {
	op, _ := b.Op.(*Operator)

	if op != nil && strings.Contains(op.Name, "cast") {
		ps.writeString(op.Name)

		scopes := ps.scopes
		ps.scopes = 0

		ps.writeByte('<')
		ps.print(b.Left)
		ps.writeString(">")

		ps.scopes = scopes

		ps.startScope('(')
		ps.print(b.Right)
		ps.endScope(')')
		return
	}

	if isDesignatedInitializer(b) {
		if op.Name == "=" {
			ps.writeByte('.')
		} else {
			ps.writeByte('[')
		}
		p
"""




```