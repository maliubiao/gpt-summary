Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Request:**

The request asks for several things regarding the provided Go code:

* **Functionality:** What does this code do?
* **Go Feature:** What specific Go language feature is being implemented?
* **Code Example:** Demonstrate its usage with Go code, including input and output.
* **Command-Line Args:** Any command-line parameters handled?
* **Common Mistakes:**  Potential pitfalls for users.

**2. Initial Code Scan and Keyword Spotting:**

I first quickly scanned the code looking for key terms and structures:

* **`package astcontext`:**  Indicates this code is related to the Go Abstract Syntax Tree (AST) and provides some context around it.
* **`import`:**  Confirms reliance on standard Go packages like `bytes`, `errors`, `fmt`, `go/ast`, and `go/types`. This reinforces the AST focus.
* **`type FuncSignature struct`:** Defines a structure to represent function signatures. The fields suggest breakdown of receiver, name, parameters, and return types.
* **`type Func struct`:** Represents a function, holding its signature, positions of key elements (`func`, `{`, `}`), and the underlying AST node (`*ast.FuncDecl` or `*ast.FuncLit`).
* **`type Funcs []*Func`:**  A slice to hold multiple `Func` objects. This suggests processing lists of functions.
* **Methods on `Func` and `Funcs`:**  Methods like `IsDeclaration`, `IsLiteral`, `String`, `EnclosingFunc`, `NextFunc`, `PrevFunc`, `Len`, `Swap`, `Less`, `Reserve`, `Declarations` hint at operations on individual functions and collections of functions.
* **`NewFuncSignature`:** A function to create `FuncSignature` objects from AST nodes.
* **`type Parser struct` (implied):** The `Funcs()` method on `*Parser` suggests the existence of a `Parser` type, which is likely responsible for parsing Go code and building the AST. The code doesn't define `Parser` but uses its methods.

**3. Inferring Core Functionality:**

Based on the types and methods, I inferred the primary goal:

* **Extract function information from Go code's AST.**  The code aims to represent and manipulate functions found within Go source code.

**4. Identifying the Go Feature:**

The use of `go/ast` and `go/types` directly points to the **Abstract Syntax Tree (AST)** feature of Go. The code is manipulating the AST to extract information about functions.

**5. Developing a Code Example:**

To illustrate the functionality, I needed to:

* **Parse Go code:** Use `parser.ParseFile` to create an AST.
* **Use the `astcontext` package:** Create an instance of (the implied) `Parser` from the parsed file.
* **Call the relevant methods:**  `Funcs()` to get a list of functions and then iterate over them to access the `Signature`.
* **Consider both function declarations and literals:** Include examples of both to showcase the code's ability to handle both.
* **Construct a meaningful output:** Show the `Full` signature of the extracted functions.

This led to the example provided in the prompt's answer.

**6. Addressing Command-Line Arguments:**

The code itself doesn't directly process command-line arguments. It relies on the `Parser` (which is external to this snippet) to handle file input. Therefore, the explanation focused on how the `Parser` would likely be used (taking a file path).

**7. Identifying Potential Mistakes:**

I thought about common scenarios where a user might misuse this code:

* **Incorrectly assuming `EnclosingFunc` finds any code block:** It's specific to functions.
* **Misunderstanding `NextFunc`/`PrevFunc` with respect to comments:** The code handles this explicitly, so it's a potential point of confusion.
* **Not realizing the dependency on a `Parser`:** Users need to understand that this code snippet is part of a larger system.

This led to the "易犯错的点" section in the prompt's answer.

**8. Structuring the Answer:**

Finally, I organized the information according to the request's structure, using clear headings and bullet points for readability. I made sure to use Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps this code directly parsed files. However, the `Funcs()` method on `*Parser` clarified that parsing is likely handled elsewhere.
* **Focusing on the core purpose:** I prioritized explaining the function extraction and representation aspects over getting bogged down in the details of position tracking.
* **Making the code example concise:** I kept the example focused on the basic function extraction to avoid unnecessary complexity.

By following this systematic process, combining code analysis with reasoning about its purpose and usage, I arrived at the comprehensive answer.
这段Go语言代码实现了对Go语言源代码中函数信息的提取和操作功能。它属于一个名为 `astcontext` 的包，该包旨在为编辑器提供上下文感知的实用工具。

以下是该代码的主要功能点：

**1. 定义了表示函数签名和函数本身的结构体：**

* **`FuncSignature`:** 用于存储函数的签名信息，包括完整的签名字符串 (`Full`)，接收者 (`Recv`)，函数名 (`Name`)，输入参数 (`In`) 和输出参数 (`Out`)。
* **`Func`:** 用于存储函数的详细信息，包括 `FuncSignature`，`func` 关键字的位置 (`FuncPos`)，花括号的位置 (`Lbrace`, `Rbrace`)，以及文档注释的位置 (`Doc`)。它还包含一个 `ast.Node` 类型的 `node` 字段，指向实际的 `*ast.FuncDecl` (函数声明) 或 `*ast.FuncLit` (函数字面量) AST 节点。
* **`Funcs`:**  `Func` 结构体的切片，用于表示一组函数。

**2. 提供了判断函数类型的方法：**

* **`IsDeclaration()` (在 `Func` 类型上):** 判断一个 `Func` 是否表示一个函数声明 (`*ast.FuncDecl`)。
* **`IsLiteral()` (在 `Func` 类型上):** 判断一个 `Func` 是否表示一个函数字面量 (`*ast.FuncLit`)。

**3. 实现了从 AST 节点创建 `FuncSignature` 的功能：**

* **`NewFuncSignature(node ast.Node)`:**  这个函数接收一个 `ast.Node` 类型的参数，该参数应该是一个 `*ast.FuncDecl` 或 `*ast.FuncLit` 节点。它会解析该节点的结构，提取出函数的签名信息，并返回一个 `FuncSignature` 结构体。

**4. 提供了 `Func` 结构体的字符串表示方法：**

* **`String()` (在 `Func` 类型上):**  返回一个符合 GNU 错误消息格式的字符串，用于标识函数的位置和名称（或 "(literal)" 对于函数字面量）。

**5. 实现了从解析后的源代码中提取函数列表的功能：**

* **`Funcs()` (在 `*Parser` 类型上):**  这是一个 `Parser` 类型的方法（虽然代码中没有给出 `Parser` 类型的完整定义，但可以推断出它的存在）。它遍历解析后的 Go 源代码的 AST，找到所有的函数声明和函数字面量，并将它们封装成 `Func` 结构体存储在 `Funcs` 切片中并返回。返回的 `Funcs` 切片中的函数是按照它们在源代码中出现的顺序排列的。

**6. 提供了在函数列表中查找特定函数的功能：**

* **`EnclosingFunc(offset int)` (在 `Funcs` 类型上):**  给定一个偏移量 `offset`，该方法返回包含该偏移量的最内层函数。
* **`NextFunc(offset int)` / `NextFuncShift(offset int, shift int)` (在 `Funcs` 类型上):** 给定一个偏移量 `offset`，返回在该偏移量之后最近的下一个函数。`NextFuncShift` 允许指定一个偏移量 `shift`，用于获取更后面的函数。
* **`PrevFunc(offset int)` / `PrevFuncShift(offset int, shift int)` (在 `Funcs` 类型上):** 给定一个偏移量 `offset`，返回在该偏移量之前最近的上一个函数。`PrevFuncShift` 允许指定一个偏移量 `shift`，用于获取更前面的函数。

**7. 提供了对 `Funcs` 切片进行操作的方法：**

* **`Len()`, `Swap(i, j int)`, `Less(i, j int)` (在 `Funcs` 类型上):**  实现了 `sort.Interface` 接口，允许对 `Funcs` 切片进行排序。
* **`Reserve()` (在 `Funcs` 类型上):**  反转 `Funcs` 切片中的元素顺序。
* **`Declarations()` (在 `Funcs` 类型上):**  返回一个新的 `Funcs` 切片，其中只包含函数声明。

**可以推理出它是什么go语言功能的实现：**

这段代码主要实现了对 **Go 语言源代码的抽象语法树 (AST) 的分析和操作**。它利用 `go/ast` 和 `go/types` 标准库来解析 Go 代码并提取出函数的相关信息。

**用 go 代码举例说明：**

假设我们有以下 Go 源代码文件 `example.go`:

```go
package main

import "fmt"

// add 函数用于计算两个整数的和
func add(a int, b int) int {
	return a + b
}

func main() {
	result := add(1, 2)
	fmt.Println(result)

	subtract := func(x, y int) int {
		return x - y
	}
	fmt.Println(subtract(5, 3))
}
```

我们可以使用 `astcontext` 包中的 `Funcs()` 方法来提取该文件中的函数信息。假设我们已经有了一个 `Parser` 实例 `p` 并且已经解析了 `example.go` 文件：

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"

	"github.com/fatih/motion/astcontext" // 假设 astcontext 包在你的 GOPATH 中
)

func main() {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "example.go", nil, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	p := &astcontext.Parser{ // 假设 Parser 结构体包含 fset 和 file 字段
		fset: fset,
		file: file,
	}

	funcs := p.Funcs()
	for _, fn := range funcs {
		fmt.Printf("Function: %s, Declaration: %t, Literal: %t\n", fn.Signature.Full, fn.IsDeclaration(), fn.IsLiteral())
	}

	// 查找 "main" 函数的包围函数 (实际上就是 main 函数自身)
	mainFunc := funcs[1] // 假设 main 函数是列表中的第二个
	enclosing, err := funcs.EnclosingFunc(mainFunc.FuncPos.Offset)
	if err == nil {
		fmt.Printf("Enclosing function for main: %s\n", enclosing.Signature.Full)
	}

	// 查找 "add" 函数之后的下一个函数
	addFunc := funcs[0]
	nextFunc, err := funcs.NextFunc(addFunc.Rbrace.Offset)
	if err == nil {
		fmt.Printf("Next function after add: %s\n", nextFunc.Signature.Full)
	}
}
```

**假设的输出：**

```
Function: func add(a int, b int) int, Declaration: true, Literal: false
Function: func main(), Declaration: true, Literal: false
Function: func(x int, y int) int, Declaration: false, Literal: true
Enclosing function for main: func main()
Next function after add: func main()
```

**代码推理的输入与输出：**

以上面的 `example.go` 文件和代码为例：

* **输入 (对于 `NewFuncSignature`):**  `*ast.FuncDecl` 类型的 "add" 函数的 AST 节点。
* **输出 (对于 `NewFuncSignature`):** `FuncSignature` 结构体，其 `Full` 字段为 `"func add(a int, b int) int"`。

* **输入 (对于 `EnclosingFunc`):** `Funcs` 类型的函数列表，以及 `main` 函数中 `fmt.Println(result)` 语句的某个偏移量（例如，`fmt` 的 'f' 的位置）。
* **输出 (对于 `EnclosingFunc`):** 指向 `main` 函数的 `Func` 结构体的指针。

* **输入 (对于 `NextFunc`):** `Funcs` 类型的函数列表，以及 `add` 函数右花括号 `}` 的偏移量。
* **输出 (对于 `NextFunc`):** 指向 `main` 函数的 `Func` 结构体的指针。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它主要关注对已解析的 Go 代码进行分析。但是，可以推断出使用这个包的工具（例如，一个代码编辑器插件）可能会通过命令行参数接收要分析的 Go 代码文件的路径。

例如，一个使用 `astcontext` 的工具可能会像这样调用：

```bash
mygotool analyze example.go
```

在这个例子中，`example.go` 就是一个命令行参数，工具内部会使用 `go/parser` 解析该文件，然后利用 `astcontext` 包中的功能提取函数信息。

**使用者易犯错的点：**

1. **传递错误的 AST 节点给 `NewFuncSignature`:**  `NewFuncSignature` 期望接收 `*ast.FuncDecl` 或 `*ast.FuncLit` 类型的节点。如果传递了其他类型的节点，将会返回一个 `Full` 字段为 "UNKNOWN" 的 `FuncSignature`。

   ```go
   // 错误示例：传递一个 *ast.GenDecl 节点
   genDecl := &ast.GenDecl{/* ... */}
   sig := astcontext.NewFuncSignature(genDecl)
   fmt.Println(sig.Full) // 输出: UNKNOWN
   ```

2. **在 `EnclosingFunc`, `NextFunc`, `PrevFunc` 中使用错误的偏移量:**  偏移量必须是源代码中的有效字节偏移量。如果传递的偏移量不在任何函数的范围内，`EnclosingFunc` 将返回错误。`NextFunc` 和 `PrevFunc` 如果找不到符合条件的函数也会返回错误。

   ```go
   // 假设文件中只有 add 和 main 两个函数
   funcs := p.Funcs()

   // 错误的偏移量，在任何函数之外
   enclosing, err := funcs.EnclosingFunc(0)
   fmt.Println(err) // 输出: no enclosing functions found

   // 错误的偏移量，在最后一个函数之后
   next, err := funcs.NextFunc(10000) // 假设文件长度小于 10000
   fmt.Println(err) // 输出: no functions found
   ```

3. **没有正确初始化 `Parser` 结构体:**  虽然这段代码没有给出 `Parser` 结构体的完整定义，但可以推断它至少需要 `go/token.FileSet` 和 `go/ast.File` 实例。如果 `Parser` 没有被正确初始化，`Funcs()` 方法可能无法正常工作。

这些是一些使用这段代码时可能遇到的常见错误。理解 AST 的结构和偏移量的概念对于正确使用这些功能至关重要。

Prompt: 
```
这是路径为go/src/github.com/fatih/motion/astcontext/funcs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Package astcontext provides context aware utilities to be used within
// editors.
package astcontext

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/types"
	"sort"
)

// FuncSignature defines the function signature
type FuncSignature struct {
	// Full signature representation
	Full string `json:"full" vim:"full"`

	// Receiver representation. Empty for non methods.
	Recv string `json:"recv" vim:"recv"`

	// Name of the function. Empty for function literals.
	Name string `json:"name" vim:"name"`

	// Input arguments of the function, if present
	In string `json:"in" vim:"in"`

	// Output argument of the function, if present
	Out string `json:"out" vim:"out"`
}

func (s *FuncSignature) String() string { return s.Full }

// Func represents a declared (*ast.FuncDecl) or an anonymous (*ast.FuncLit) Go
// function
type Func struct {
	// Signature of the function
	Signature *FuncSignature `json:"sig" vim:"sig"`

	// position of the "func" keyword
	FuncPos *Position `json:"func" vim:"func"`
	Lbrace  *Position `json:"lbrace" vim:"lbrace"` // position of "{"
	Rbrace  *Position `json:"rbrace" vim:"rbrace"` // position of "}"

	// position of the doc comment, only for *ast.FuncDecl
	Doc *Position `json:"doc,omitempty" vim:"doc,omitempty"`

	node ast.Node // either *ast.FuncDecl or *ast.FuncLit
}

// Funcs represents a list of functions
type Funcs []*Func

// IsDeclaration returns true if the given function is a function declaration
// (*ast.FuncDecl)
func (f *Func) IsDeclaration() bool {
	_, ok := f.node.(*ast.FuncDecl)
	return ok
}

// IsLiteral returns true if the given function is a function literal
// (*ast.FuncLit)
func (f *Func) IsLiteral() bool {
	_, ok := f.node.(*ast.FuncLit)
	return ok
}

// NewFuncSignature returns a function signature from the given node. Node should
// be of type *ast.FuncDecl or *ast.FuncLit
func NewFuncSignature(node ast.Node) *FuncSignature {
	getParams := func(list []*ast.Field) string {
		buf := new(bytes.Buffer)
		for i, p := range list {
			for j, n := range p.Names {
				buf.WriteString(n.Name)
				if len(p.Names) != j+1 {
					buf.WriteString(", ")
				}
			}

			if len(p.Names) != 0 {
				buf.WriteString(" ")
			}

			types.WriteExpr(buf, p.Type)

			if len(list) != i+1 {
				buf.WriteString(", ")
			}
		}
		return buf.String()
	}
	isResultsNeedParens := func(list []*ast.Field) bool {
		if len(list) > 1 {
			return true
		}
		return len(list) != 0 && len(list[0].Names) != 0
	}

	switch x := node.(type) {
	case *ast.FuncDecl:
		sig := &FuncSignature{
			Name: x.Name.Name,
		}

		buf := bytes.NewBufferString("func ")

		if x.Recv != nil {
			sig.Recv = getParams(x.Recv.List)
			fmt.Fprintf(buf, "(%s) ", sig.Recv)
		}

		fmt.Fprintf(buf, "%s", sig.Name)

		if x.Type.Params != nil {
			sig.In = getParams(x.Type.Params.List)
			fmt.Fprintf(buf, "(%s)", sig.In)
		}

		if x.Type.Results != nil {
			sig.Out = getParams(x.Type.Results.List)
			if isResultsNeedParens(x.Type.Results.List) {
				fmt.Fprintf(buf, " (%s)", sig.Out)
			} else {
				fmt.Fprintf(buf, " %s", sig.Out)
			}
		}

		sig.Full = buf.String()
		return sig
	case *ast.FuncLit:
		sig := &FuncSignature{}

		buf := bytes.NewBufferString("func")

		if x.Type.Params != nil {
			sig.In = getParams(x.Type.Params.List)
			fmt.Fprintf(buf, "(%s)", sig.In)
		}
		if x.Type.Results != nil {
			sig.Out = getParams(x.Type.Results.List)
			if isResultsNeedParens(x.Type.Results.List) {
				fmt.Fprintf(buf, " (%s)", sig.Out)
			} else {
				fmt.Fprintf(buf, " %s", sig.Out)
			}
		}

		sig.Full = buf.String()
		return sig
	default:
		return &FuncSignature{Full: "UNKNOWN"}
	}
}

func (f *Func) String() string {
	// Print according to GNU error messaging format
	// https://www.gnu.org/prep/standards/html_node/Errors.html
	switch x := f.node.(type) {
	case *ast.FuncDecl:
		return fmt.Sprintf("%s:%d:%d %s",
			f.FuncPos.Filename, f.FuncPos.Line, f.FuncPos.Column, x.Name.Name)
	default:
		return fmt.Sprintf("%s:%d:%d %s",
			f.FuncPos.Filename, f.FuncPos.Line, f.FuncPos.Column, "(literal)")
	}
}

// Funcs returns a list of Func's from the parsed source. Func's are sorted
// according to the order of Go functions in the given source.
func (p *Parser) Funcs() Funcs {
	var files []*ast.File
	if p.file != nil {
		files = append(files, p.file)
	}

	if p.pkgs != nil {
		for _, pkg := range p.pkgs {
			for _, f := range pkg.Files {
				files = append(files, f)
			}
		}
	}

	var funcs []*Func
	inspect := func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			fn := &Func{
				FuncPos: ToPosition(p.fset.Position(x.Type.Func)),
				node:    x,
			}

			// can be nil for forward declarations
			if x.Body != nil {
				fn.Lbrace = ToPosition(p.fset.Position(x.Body.Lbrace))
				fn.Rbrace = ToPosition(p.fset.Position(x.Body.Rbrace))
			}

			if x.Doc != nil {
				fn.Doc = ToPosition(p.fset.Position(x.Doc.Pos()))
			}

			fn.Signature = NewFuncSignature(x)
			funcs = append(funcs, fn)
		case *ast.FuncLit:
			fn := &Func{
				Lbrace:  ToPosition(p.fset.Position(x.Body.Lbrace)),
				Rbrace:  ToPosition(p.fset.Position(x.Body.Rbrace)),
				FuncPos: ToPosition(p.fset.Position(x.Type.Func)),
				node:    x,
			}

			fn.Signature = NewFuncSignature(x)
			funcs = append(funcs, fn)
		}
		return true
	}

	for _, file := range files {
		// Inspect the AST and find all function declarements and literals
		ast.Inspect(file, inspect)
	}

	return funcs
}

// EnclosingFunc returns the enclosing *Func for the given offset
func (f Funcs) EnclosingFunc(offset int) (*Func, error) {
	var encFunc *Func

	// TODO(arslan) this is iterating over all functions. Benchmark it and see
	// if it's worth it to change it with a more effiecent search function. For
	// now this is enough for us.
	for _, fn := range f {
		// standard function declaration without any docs. Start from the func
		// keyword
		start := fn.FuncPos.Offset

		// has a doc, also include it
		if fn.Doc != nil && fn.Doc.IsValid() {
			start = fn.Doc.Offset
		}

		// one liner, start from the beginning to make it easier
		if fn.FuncPos.Line == fn.Rbrace.Line {
			start = fn.FuncPos.Offset - fn.FuncPos.Column
		}

		end := fn.Rbrace.Offset

		if start <= offset && offset <= end {
			encFunc = fn
		}
	}

	if encFunc == nil {
		return nil, errors.New("no enclosing functions found")
	}

	return encFunc, nil
}

// NextFunc returns the nearest next Func for the given offset.
func (f Funcs) NextFunc(offset int) (*Func, error) {
	return f.nextFuncShift(offset, 0)
}

// NextFuncShift returns the nearest next Func for the given offset. Shift
// shifts the index before returning. This is useful to get the second nearest
// next function (shift being 1), third nearest next function (shift being 2),
// etc...
func (f Funcs) NextFuncShift(offset, shift int) (*Func, error) {
	return f.nextFuncShift(offset, shift)
}

// PrevFunc returns the nearest previous *Func for the given offset.
func (f Funcs) PrevFunc(offset int) (*Func, error) {
	return f.prevFuncShift(offset, 0)
}

// PrevFuncShift returns the nearest previous Func for the given offset. Shift
// shifts the index before returning. This is useful to get the second nearest
// previous function (shift being 1), third nearest previous function (shift
// being 2), etc...
func (f Funcs) PrevFuncShift(offset, shift int) (*Func, error) {
	return f.prevFuncShift(offset, shift)
}

// nextFuncShift returns the nearest next function for the given offset and
// shift index. If index is zero it returns the nearest next function. If shift
// is non zero positive number it returns the function shifted by the given
// number. i.e: [a, b, c, d] if the nearest func is b (shift 0), shift with
// value 1 returns c, 2 returns d and anything larger returns an error.
func (f Funcs) nextFuncShift(offset, shift int) (*Func, error) {
	if shift < 0 {
		return nil, errors.New("shift can't be negative")
	}

	// find nearest next function
	nextIndex := sort.Search(len(f), func(i int) bool {
		return f[i].FuncPos.Offset > offset
	})

	if nextIndex >= len(f) {
		return nil, errors.New("no functions found")
	}

	fn := f[nextIndex]

	// if our position is inside the doc, increase the shift by one to pick up
	// the next function. This assumes that people editing a doc of a func want
	// to pick up the next function instead of the current function.
	if fn.Doc != nil && fn.Doc.IsValid() {
		if fn.Doc.Offset <= offset && offset < fn.FuncPos.Offset {
			shift++
		}
	}

	if nextIndex+shift >= len(f) {
		return nil, errors.New("no functions found")
	}

	return f[nextIndex+shift], nil
}

// prevFuncShift returns the nearest previous *Func for the given offset and
// shift index. If index is zero it returns the nearest previous function. If
// shift is non zero positive number it returns the function shifted by the
// given number. i.e: [a, b, c, d] if the nearest previous func is c (shift 0),
// shift with value 1 returns b, 2 returns a and anything larger returns an
// error.
func (f Funcs) prevFuncShift(offset, shift int) (*Func, error) {
	if shift < 0 {
		return nil, errors.New("shift can't be negative")
	}

	// start from the reverse to get the prev function
	f.Reserve()

	prevIndex := sort.Search(len(f), func(i int) bool {
		return f[i].FuncPos.Offset < offset
	})

	if prevIndex+shift >= len(f) {
		return nil, errors.New("no functions found")
	}

	return f[prevIndex+shift], nil
}

func (f Funcs) Len() int      { return len(f) }
func (f Funcs) Swap(i, j int) { f[i], f[j] = f[j], f[i] }
func (f Funcs) Less(i, j int) bool {
	return f[i].FuncPos.Offset < f[j].FuncPos.Offset
}

// Reserve reserves the Function data
func (f Funcs) Reserve() {
	for start, end := 0, f.Len()-1; start < end; {
		f.Swap(start, end)
		start++
		end--
	}
}

// Declarations returns a copy of funcs with only Function declarations
func (f Funcs) Declarations() Funcs {
	// NOTE(arslan): we can prepopulate these in the future, but again we need
	// to benchmark first
	var decls []*Func
	for _, fn := range f {
		if fn.IsDeclaration() {
			decls = append(decls, fn)
		}
	}
	return decls
}

"""



```