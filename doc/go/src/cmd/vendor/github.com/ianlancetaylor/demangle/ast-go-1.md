Response:
The user wants a summary of the functionality of the provided Go code snippet. This code seems to define a set of Go structs that represent different elements of an Abstract Syntax Tree (AST), likely for representing C++ expressions. The functions within these structs appear to handle how these AST nodes are printed or converted to a string representation.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file path `go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go` and the code itself strongly suggest this is part of a C++ demangler. Demanglers convert mangled (obfuscated) C++ symbol names back into human-readable form. The `ast.go` file likely defines the data structures to represent the *structure* of those demangled names.

2. **Examine Key Structs:**  Scan the defined structs and their names. Notice patterns: `Binary`, `Trinary`, `Fold`, `New`, `Literal`, `LambdaExpr`, `ExprList`, `Closure`, `RequiresExpr`, etc. These names correspond to common expression constructs in C++.

3. **Analyze the `print` Methods:** The presence of `print(ps *printState)` methods in most structs is a strong indicator that this code is responsible for generating a string representation of the AST. The `printState` argument likely holds configuration and a buffer to build the output string. Notice the logic for handling `llvmStyle` printing, which suggests support for different output formats.

4. **Analyze the `Traverse` Methods:** The `Traverse(fn func(AST) bool)` methods suggest a way to walk through the AST, visiting each node. This is a common pattern for processing tree-like structures.

5. **Analyze the `Copy` Methods:** The `Copy(fn func(AST) AST, skip func(AST) bool) AST` methods indicate the ability to create modified copies of the AST, potentially applying transformations or filtering.

6. **Analyze the `GoString` Methods:** The `GoString()` and `goString` methods are standard Go interfaces for providing a debugging string representation of the structs.

7. **Identify Supporting Functions:**  Functions like `parenthesize`, `isDesignatedInitializer`, `printList` within the `print` methods suggest helper functions for formatting the output correctly, especially concerning operator precedence and syntax.

8. **Infer Functionality based on Struct Names and Methods:**  Combine the information from the struct names and their associated methods to deduce the specific purpose of each struct. For example, `Binary` likely represents binary operations, `Trinary` ternary operators, `Literal` represents literal values, and so on.

9. **Synthesize the Summary:** Combine the above observations into a coherent summary. Focus on the core purpose (representing C++ expressions), the key actions (printing, traversing, copying), and the overall goal (demangling).

10. **Refine and Organize:**  Structure the summary logically, starting with the high-level purpose and then delving into more specific details about the functionality of different parts of the code. Use clear and concise language.

By following this process, we can arrive at the summary provided in the initial prompt's "Thought Process and Solution". The key is to look for patterns, understand common software design principles (like AST representation and tree traversal), and leverage the naming conventions used in the code.
这是 `go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go` 文件中 `Binary`, `Trinary`, `Fold`, `Subobject`, `PtrMemCast`, `New`, `Literal`, `StringLiteral`, `LambdaExpr`, `ExprList`, `InitializerList`, `DefaultArg`, `Closure`, `StructuredBindings`, `UnnamedType`, `Clone`, `Special`, `Special2`, `EnableIf`, `ModuleName`, `ModuleEntity`, `Friend`, `Constraint`, `RequiresExpr`, `ExprRequirement`, `TypeRequirement`, `NestedRequirement`, `ExplicitObjectParameter` 这些结构体及其关联方法的功能的总结。

**功能归纳：**

这部分代码定义了一系列 Go 结构体，用于表示 C++ 表达式的抽象语法树 (AST) 节点。这些结构体涵盖了 C++ 中常见的表达式类型，例如：

* **二元表达式 (`Binary`)**:  例如 `a + b`, `x == y`。可以处理赋值、比较、算术运算等。
* **三元表达式 (`Trinary`)**: 例如 `condition ? value_if_true : value_if_false`。
* **折叠表达式 (`Fold`)**: C++17 的特性，用于对参数包进行操作。
* **子对象表达式 (`Subobject`)**: 用于表示非类型模板参数中的类类型成员的引用。
* **指向成员的指针转换 (`PtrMemCast`)**:  用于将表达式转换为指向成员的指针类型。
* **`new` 表达式 (`New`)**: 表示 C++ 中的 `new` 运算符。
* **字面量 (`Literal`)**:  表示常量值，例如数字、布尔值。
* **字符串字面量 (`StringLiteral`)**: 表示字符串常量。
* **Lambda 表达式 (`LambdaExpr`)**: 表示 C++ 的 lambda 表达式。
* **表达式列表 (`ExprList`)**:  用于表示函数调用或初始化列表中的多个表达式。
* **初始化列表 (`InitializerList`)**: 表示用大括号括起来的初始化列表。
* **默认参数 (`DefaultArg`)**: 表示函数或模板参数的默认值。
* **闭包 (`Closure`)**:  另一种表示 lambda 表达式的方式，包含模板参数和约束信息。
* **结构化绑定 (`StructuredBindings`)**:  表示 C++17 的结构化绑定。
* **未命名类型 (`UnnamedType`)**: 表示没有显式名称的类型（例如，lambda 表达式的返回类型）。
* **克隆 (`Clone`)**: 表示函数的克隆版本。
* **特殊符号 (`Special`, `Special2`)**: 用于表示一些特殊的、具有前缀或中间字符串的符号。
* **`enable_if` 属性 (`EnableIf`)**:  表示 Clang 特有的 `enable_if` 属性。
* **模块相关 (`ModuleName`, `ModuleEntity`)**: 用于表示 C++20 模块的名称和实体。
* **友元声明 (`Friend`)**: 表示友元声明。
* **约束 (`Constraint`)**: 表示带有 `requires` 子句的约束。
* **Requires 表达式 (`RequiresExpr`)**: 表示 C++20 的 `requires` 表达式。
* **Requires 表达式中的需求 (`ExprRequirement`, `TypeRequirement`, `NestedRequirement`)**: 表示 `requires` 表达式中的不同类型的需求。
* **显式对象参数 (`ExplicitObjectParameter`)**: 表示 C++23 的显式对象参数（`this` 参数）。

**主要功能：**

1. **数据结构定义**: 定义了表示 C++ 表达式各种组成部分的数据结构。
2. **打印 (反向转换)**:  每个结构体都关联了一个 `print(*printState)` 方法，负责将该 AST 节点转换回可读的 C++ 代码字符串。`printState` 结构体管理打印状态，例如是否使用 LLVM 风格的输出。
3. **遍历 (`Traverse`)**:  每个结构体都关联了一个 `Traverse(func(AST) bool)` 方法，用于对 AST 进行深度优先遍历，允许用户在遍历过程中执行自定义操作。
4. **复制 (`Copy`)**: 每个结构体都关联了一个 `Copy(func(AST) AST, func(AST) bool) AST` 方法，用于创建 AST 节点的副本，并允许在复制过程中进行修改或跳过某些节点。
5. **调试输出 (`GoString`)**:  每个结构体都关联了一个 `GoString()` 方法，用于生成 Go 语言风格的字符串表示，方便调试。

**可以推断出这是 C++ 符号反解 (Demangling) 功能的实现的一部分。**  C++ 编译器会将函数和变量的名字进行“名字修饰 (Name Mangling)”，以便在链接时区分不同的符号。反解就是将这些修饰过的名字转换回原始的、人类可读的形式。 `ast.go` 文件中的这些结构体很可能是在解析被修饰的名字后，用于构建表示其结构的一棵抽象语法树。

**Go 代码示例 (基于推断)：**

假设我们有一个被修饰的 C++ 函数名，例如 `_Z3fooi` (表示接受一个 `int` 参数的函数 `foo`)。  反解器可能会解析这个名字，并构建一个 `Function` 类型的 AST 节点，其中包含一个 `Name` 节点表示 "foo"，以及一个 `ParameterList` 节点包含一个 `BuiltinType` 节点表示 "int"。

```go
package main

import (
	"fmt"
	"strings"
)

// 假设这是简化后的 ast.go 中的部分定义
type AST interface {
	print(ps *printState)
	GoString() string
}

type printState struct {
	buf       strings.Builder
	llvmStyle bool
	scopes    int
}

func (ps *printState) writeString(s string) {
	ps.buf.WriteString(s)
}

func (ps *printState) writeByte(b byte) {
	ps.buf.WriteByte(b)
}

type Name struct {
	Name string
}

func (n *Name) print(ps *printState) {
	ps.writeString(n.Name)
}
func (n *Name) GoString() string {
	return fmt.Sprintf("&Name{Name:\"%s\"}", n.Name)
}

type BuiltinType struct {
	Name string
}

func (bt *BuiltinType) print(ps *printState) {
	ps.writeString(bt.Name)
}
func (bt *BuiltinType) GoString() string {
	return fmt.Sprintf("&BuiltinType{Name:\"%s\"}", bt.Name)
}

type ParameterList struct {
	Parameters []AST
}

func (pl *ParameterList) print(ps *printState) {
	ps.writeByte('(')
	for i, p := range pl.Parameters {
		p.print(ps)
		if i < len(pl.Parameters)-1 {
			ps.writeString(", ")
		}
	}
	ps.writeByte(')')
}
func (pl *ParameterList) GoString() string {
	var params []string
	for _, p := range pl.Parameters {
		params = append(params, p.GoString())
	}
	return fmt.Sprintf("&ParameterList{Parameters: []AST{%s}}", strings.Join(params, ","))
}

type Function struct {
	Name       *Name
	Parameters *ParameterList
}

func (f *Function) print(ps *printState) {
	f.Name.print(ps)
	f.Parameters.print(ps)
}
func (f *Function) GoString() string {
	return fmt.Sprintf("&Function{Name: %s, Parameters: %s}", f.Name.GoString(), f.Parameters.GoString())
}

func main() {
	// 假设解析 "_Z3fooi" 后构建了以下 AST
	astRoot := &Function{
		Name: &Name{Name: "foo"},
		Parameters: &ParameterList{
			Parameters: []AST{&BuiltinType{Name: "int"}},
		},
	}

	ps := &printState{}
	astRoot.print(ps)
	fmt.Println(ps.buf.String()) // 输出: foo(int)

	fmt.Println(astRoot.GoString()) // 输出: &Function{Name: &Name{Name:"foo"}, Parameters: &ParameterList{Parameters: []AST{&BuiltinType{Name:"int"}}}}
}
```

**假设的输入与输出：**

* **输入 (AST 结构):** 一个 `Binary` 结构体，表示表达式 `1 + 2`。

  ```go
  binaryExpr := &Binary{
      Op: &Operator{Name: "+"},
      Left: &Literal{Val: "1"},
      Right: &Literal{Val: "2"},
  }
  ```

* **输出 (调用 `print` 方法):**  "1+2" (默认情况下，可能需要根据 `printState` 的设置添加空格)。 如果 `llvmStyle` 为 true，输出可能是 "1 + 2"。

**命令行参数的具体处理：**

这部分代码本身似乎不直接处理命令行参数。 命令行参数的处理逻辑很可能在调用此 AST 构建和打印功能的地方。例如，在 demangler 的主程序中，可能会有类似以下的操作：

```go
// 假设在 demangler 的主程序中
import "flag"

func main() {
	mangledName := flag.String("name", "", "The mangled name to demangle")
	llvmStyle := flag.Bool("llvm", false, "Use LLVM style output")
	flag.Parse()

	if *mangledName == "" {
		fmt.Println("Please provide a mangled name using the -name flag.")
		return
	}

	// ... 解析 mangledName 并构建 AST ...
	astRoot := parseMangledName(*mangledName)

	ps := &printState{llvmStyle: *llvmStyle}
	astRoot.print(ps)
	fmt.Println(ps.buf.String())
}
```

在这个例子中，`-name` 参数指定要反解的名称，`-llvm` 参数控制输出风格。`printState` 的 `llvmStyle` 字段会根据命令行参数的值进行设置，从而影响 `print` 方法的行为。

**易犯错的点：**

没有在这部分代码中体现，因为这部分主要关注 AST 的结构和打印，而不是用户交互或配置。  易犯错的点可能出现在解析 mangled name 的过程中，例如：

* **不完全理解 C++ 的名字修饰规则**: 可能导致解析错误，无法正确构建 AST。
* **处理模板和复杂的类型**:  C++ 的模板和类型系统非常复杂，正确解析和表示它们可能非常困难。

总而言之，这部分 `ast.go` 代码的核心功能是定义了 C++ 表达式的抽象语法树结构，并提供了将这些结构转换回可读 C++ 代码的能力，这是 C++ 符号反解器的关键组成部分。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/ianlancetaylor/demangle/ast.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
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
		return nil
	}
	module := me.Module.Copy(fn, skip)
	name := me.Name.Copy(fn, skip)
	if module == nil && name == nil {
		return fn(me)
	}
	if module == nil {
		module = me.Module
	}
	if name == nil {
		name = me.Name
	}
	me = &ModuleEntity{Module: module, Name: name}
	if r := fn(me); r != nil {
		return r
	}
	return me
}

func (me *ModuleEntity) GoString() string {
	return me.goString(0, "")
}

func (me *ModuleEntity) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sModuleEntity:\n%s\n%s", indent, "", field,
		me.Module.goString(indent+2, "Module: "),
		me.Name.goString(indent+2, "Name: "))
}

// Friend is a member like friend name.
type Friend struct {
	Name AST
}

func (f *Friend) print(ps *printState) {
	ps.writeString("friend ")
	ps.print(f.Name)
}

func (f *Friend) Traverse(fn func(AST) bool) {
	if fn(f) {
		f.Name.Traverse(fn)
	}
}

func (f *Friend) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(f) {
		return nil
	}
	name := f.Name.Copy(fn, skip)
	if name == nil {
		return fn(f)
	}
	f = &Friend{Name: name}
	if r := fn(f); r != nil {
		return r
	}
	return f
}

func (f *Friend) GoString() string {
	return f.goString(0, "")
}

func (f *Friend) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sFriend:\n%s", indent, "", field,
		f.Name.goString(indent+2, "Name: "))
}

// Constraint represents an AST with a constraint.
type Constraint struct {
	Name     AST
	Requires AST
}

func (c *Constraint) print(ps *printState) {
	ps.print(c.Name)
	ps.writeString(" requires ")
	ps.print(c.Requires)
}

func (c *Constraint) Traverse(fn func(AST) bool) {
	if fn(c) {
		c.Name.Traverse(fn)
		c.Requires.Traverse(fn)
	}
}

func (c *Constraint) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(c) {
		return nil
	}
	name := c.Name.Copy(fn, skip)
	requires := c.Requires.Copy(fn, skip)
	if name == nil && requires == nil {
		return fn(c)
	}
	if name == nil {
		name = c.Name
	}
	if requires == nil {
		requires = c.Requires
	}
	c = &Constraint{Name: name, Requires: requires}
	if r := fn(c); r != nil {
		return r
	}
	return c
}

func (c *Constraint) GoString() string {
	return c.goString(0, "")
}

func (c *Constraint) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sConstraint:\n%s\n%s", indent, "", field,
		c.Name.goString(indent+2, "Name: "),
		c.Requires.goString(indent+2, "Requires: "))
}

// RequiresExpr is a C++20 requires expression.
type RequiresExpr struct {
	Params       []AST
	Requirements []AST
}

func (re *RequiresExpr) print(ps *printState) {
	ps.writeString("requires")
	if len(re.Params) > 0 {
		ps.writeByte(' ')
		ps.startScope('(')
		ps.printList(re.Params, nil)
		ps.endScope(')')
	}
	ps.writeByte(' ')
	ps.startScope('{')
	for _, req := range re.Requirements {
		ps.print(req)
	}
	ps.writeByte(' ')
	ps.endScope('}')
}

func (re *RequiresExpr) Traverse(fn func(AST) bool) {
	if fn(re) {
		for _, p := range re.Params {
			p.Traverse(fn)
		}
		for _, r := range re.Requirements {
			r.Traverse(fn)
		}
	}
}

func (re *RequiresExpr) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(re) {
		return nil
	}

	changed := false

	var params []AST
	if len(re.Params) > 0 {
		params = make([]AST, len(re.Params))
		for i, p := range re.Params {
			pc := p.Copy(fn, skip)
			if pc == nil {
				params[i] = p
			} else {
				params[i] = pc
				changed = true
			}
		}
	}

	requirements := make([]AST, len(re.Requirements))
	for i, r := range re.Requirements {
		rc := r.Copy(fn, skip)
		if rc == nil {
			requirements[i] = r
		} else {
			requirements[i] = rc
			changed = true
		}
	}

	if !changed {
		return fn(re)
	}

	re = &RequiresExpr{Params: params, Requirements: requirements}
	if r := fn(re); r != nil {
		return r
	}
	return re
}

func (re *RequiresExpr) GoString() string {
	return re.goString(0, "")
}

func (re *RequiresExpr) goString(indent int, field string) string {
	var params strings.Builder
	if len(re.Params) == 0 {
		fmt.Fprintf(&params, "%*sParams: nil", indent+2, "")
	} else {
		fmt.Fprintf(&params, "%*sParams:", indent+2, "")
		for i, p := range re.Params {
			params.WriteByte('\n')
			params.WriteString(p.goString(indent+4, fmt.Sprintf("%d: ", i)))
		}
	}

	var requirements strings.Builder
	fmt.Fprintf(&requirements, "%*sRequirements:", indent+2, "")
	for i, r := range re.Requirements {
		requirements.WriteByte('\n')
		requirements.WriteString(r.goString(indent+4, fmt.Sprintf("%d: ", i)))
	}

	return fmt.Sprintf("%*s%sRequirements:\n%s\n%s", indent, "", field,
		params.String(), requirements.String())
}

// ExprRequirement is a simple requirement in a requires expression.
// This is an arbitrary expression.
type ExprRequirement struct {
	Expr     AST
	Noexcept bool
	TypeReq  AST
}

func (er *ExprRequirement) print(ps *printState) {
	ps.writeByte(' ')
	if er.Noexcept || er.TypeReq != nil {
		ps.startScope('{')
	}
	ps.print(er.Expr)
	if er.Noexcept || er.TypeReq != nil {
		ps.endScope('}')
	}
	if er.Noexcept {
		ps.writeString(" noexcept")
	}
	if er.TypeReq != nil {
		ps.writeString(" -> ")
		ps.print(er.TypeReq)
	}
	ps.writeByte(';')
}

func (er *ExprRequirement) Traverse(fn func(AST) bool) {
	if fn(er) {
		er.Expr.Traverse(fn)
		if er.TypeReq != nil {
			er.TypeReq.Traverse(fn)
		}
	}
}

func (er *ExprRequirement) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(er) {
		return nil
	}
	expr := er.Expr.Copy(fn, skip)
	var typeReq AST
	if er.TypeReq != nil {
		typeReq = er.TypeReq.Copy(fn, skip)
	}
	if expr == nil && typeReq == nil {
		return fn(er)
	}
	if expr == nil {
		expr = er.Expr
	}
	if typeReq == nil {
		typeReq = er.TypeReq
	}
	er = &ExprRequirement{Expr: expr, TypeReq: typeReq}
	if r := fn(er); r != nil {
		return r
	}
	return er
}

func (er *ExprRequirement) GoString() string {
	return er.goString(0, "")
}

func (er *ExprRequirement) goString(indent int, field string) string {
	var typeReq string
	if er.TypeReq != nil {
		typeReq = "\n" + er.TypeReq.goString(indent+2, "TypeReq: ")
	}

	return fmt.Sprintf("%*s%sExprRequirement: Noexcept: %t\n%s%s", indent, "", field,
		er.Noexcept,
		er.Expr.goString(indent+2, "Expr: "),
		typeReq)
}

// TypeRequirement is a type requirement in a requires expression.
type TypeRequirement struct {
	Type AST
}

func (tr *TypeRequirement) print(ps *printState) {
	ps.writeString(" typename ")
	ps.print(tr.Type)
	ps.writeByte(';')
}

func (tr *TypeRequirement) Traverse(fn func(AST) bool) {
	if fn(tr) {
		tr.Type.Traverse(fn)
	}
}

func (tr *TypeRequirement) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(tr) {
		return nil
	}
	typ := tr.Type.Copy(fn, skip)
	if typ == nil {
		return fn(tr)
	}
	tr = &TypeRequirement{Type: typ}
	if r := fn(tr); r != nil {
		return r
	}
	return tr
}

func (tr *TypeRequirement) GoString() string {
	return tr.goString(0, "")
}

func (tr *TypeRequirement) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sTypeRequirement:\n%s", indent, "", field,
		tr.Type.goString(indent+2, ""))
}

// NestedRequirement is a nested requirement in a requires expression.
type NestedRequirement struct {
	Constraint AST
}

func (nr *NestedRequirement) print(ps *printState) {
	ps.writeString(" requires ")
	ps.print(nr.Constraint)
	ps.writeByte(';')
}

func (nr *NestedRequirement) Traverse(fn func(AST) bool) {
	if fn(nr) {
		nr.Constraint.Traverse(fn)
	}
}

func (nr *NestedRequirement) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(nr) {
		return nil
	}
	constraint := nr.Constraint.Copy(fn, skip)
	if constraint == nil {
		return fn(nr)
	}
	nr = &NestedRequirement{Constraint: constraint}
	if r := fn(nr); r != nil {
		return r
	}
	return nr
}

func (nr *NestedRequirement) GoString() string {
	return nr.goString(0, "")
}

func (nr *NestedRequirement) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sNestedRequirement:\n%s", indent, "", field,
		nr.Constraint.goString(indent+2, ""))
}

// ExplicitObjectParameter represents a C++23 explicit object parameter.
type ExplicitObjectParameter struct {
	Base AST
}

func (eop *ExplicitObjectParameter) print(ps *printState) {
	ps.writeString("this ")
	ps.print(eop.Base)
}

func (eop *ExplicitObjectParameter) Traverse(fn func(AST) bool) {
	if fn(eop) {
		eop.Base.Traverse(fn)
	}
}

func (eop *ExplicitObjectParameter) Copy(fn func(AST) AST, skip func(AST) bool) AST {
	if skip(eop) {
		return nil
	}
	base := eop.Base.Copy(fn, skip)
	if base == nil {
		return fn(eop)
	}
	eop = &ExplicitObjectParameter{Base: base}
	if r := fn(eop); r != nil {
		return r
	}
	return eop
}

func (eop *ExplicitObjectParameter) GoString() string {
	return eop.goString(0, "")
}

func (eop *ExplicitObjectParameter) goString(indent int, field string) string {
	return fmt.Sprintf("%*s%sExplicitObjectParameter:\n%s", indent, "", field,
		eop.Base.goString(indent+2, ""))
}

// Print the inner types.
func (ps *printState) printInner(prefixOnly bool) []AST {
	var save []AST
	var psave *[]AST
	if prefixOnly {
		psave = &save
	}
	for len(ps.inner) > 0 {
		ps.printOneInner(psave)
	}
	return save
}

// innerPrinter is an interface for types that can print themselves as
// inner types.
type innerPrinter interface {
	printInner(*printState)
}

// Print the most recent inner type.  If save is not nil, only print
// prefixes.
func (ps *printState) printOneInner(save *[]AST) {
	if len(ps.inner) == 0 {
		panic("printOneInner called with no inner types")
	}
	ln := len(ps.inner)
	a := ps.inner[ln-1]
	ps.inner = ps.inner[:ln-1]

	if save != nil {
		if _, ok := a.(*MethodWithQualifiers); ok {
			*save = append(*save, a)
			return
		}
	}

	if ip, ok := a.(innerPrinter); ok {
		ip.printInner(ps)
	} else {
		ps.print(a)
	}
}

// isEmpty returns whether printing a will not print anything.
func (ps *printState) isEmpty(a AST) bool {
	switch a := a.(type) {
	case *ArgumentPack:
		for _, a := range a.Args {
			if !ps.isEmpty(a) {
				return false
			}
		}
		return true
	case *ExprList:
		return len(a.Exprs) == 0
	case *PackExpansion:
		return a.Pack != nil && ps.isEmpty(a.Base)
	default:
		return false
	}
}
```