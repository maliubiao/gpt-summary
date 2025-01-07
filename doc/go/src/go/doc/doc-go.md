Response:
Let's break down the thought process for analyzing the `doc.go` file and generating the detailed explanation.

1. **Understand the Goal:** The core request is to explain the functionality of the Go code snippet, identify its purpose within the Go ecosystem, provide usage examples, discuss command-line arguments (if applicable), and highlight potential pitfalls.

2. **Initial Skim and High-Level Understanding:**  The first step is to quickly read through the code to get a general idea of what it's doing. Keywords like "package doc", "documentation", "AST", "New", "NewFromFiles", "Example", "Note", and the various struct types (Package, Value, Type, Func) immediately suggest that this code is about extracting and representing documentation from Go source code.

3. **Identify Key Data Structures:**  Pay close attention to the `struct` definitions. These represent the core data model for the documentation:
    * `Package`: Represents the documentation for an entire package. Note the fields like `Doc`, `Name`, `Imports`, `Consts`, `Types`, `Funcs`, `Examples`, and `Notes`. This structure holds the primary output of the documentation extraction process.
    * `Value`: Represents documentation for constants or variables.
    * `Type`: Represents documentation for a type declaration, including associated constants, variables, functions, and methods.
    * `Func`: Represents documentation for a function or method.
    * `Note`: Represents specially marked comments.
    * `Example`:  While the struct definition isn't shown here, the comments and the presence of `Examples` fields in other structs indicate its role in showcasing usage.

4. **Analyze Key Functions:** Focus on the functions that appear to be the main entry points and processing logic:
    * `New(pkg *ast.Package, importPath string, mode Mode) *Package`: This function takes an `ast.Package` and extracts documentation. The `mode` parameter hints at different levels of extraction.
    * `NewFromFiles(fset *token.FileSet, files []*ast.File, importPath string, opts ...any) (*Package, error)`: This function seems to be the more common entry point, taking a list of files and a file set. The `opts` parameter suggests configuration options.
    * Helper functions like `simpleImporter`, and the methods on the `Package` struct (e.g., `lookupSym`, `lookupPackage`, `Parser`, `Printer`, `HTML`, `Markdown`, `Text`) provide supporting functionalities.

5. **Infer the Overall Purpose:** Based on the data structures and key functions, it's clear that this code is responsible for parsing Go source code (represented by the AST) and extracting documentation comments, examples, and other relevant information to create a structured representation of the package's API. This representation is likely used by tools like `godoc` to generate documentation in various formats.

6. **Connect to Broader Go Concepts:** Recognize the use of `go/ast` (Abstract Syntax Tree) and `go/token` (token representation). This immediately places the code within the context of Go's compiler and tooling ecosystem. The mention of `_test.go` files connects to Go's testing conventions and how examples are incorporated.

7. **Construct Examples (Mental or Actual):**  Think about how someone would use this code. The `NewFromFiles` function is the most obvious starting point. Imagine a simple Go package with comments, constants, variables, types, functions, and example code in a `_test.go` file. This helps visualize the input and the expected output (a `Package` struct containing the extracted information).

8. **Address Specific Requirements:**  Go back to the original prompt and ensure all points are addressed:
    * **Functionality Listing:**  Summarize the identified functionalities clearly.
    * **Go Language Feature Implementation:**  Confirm it's about documentation extraction and relate it to `godoc`.
    * **Code Examples:**  Create concrete Go code examples showing how to use `NewFromFiles`. Crucially, include the setup with `token.FileSet` and parsing the files using `parser.ParseFile`. Include both success and potential error scenarios.
    * **Command-Line Arguments:** Realize that this *specific* code doesn't directly handle command-line arguments. The *users* of this library (like `godoc`) will handle those. Explain this distinction.
    * **Input/Output for Code Reasoning:**  Demonstrate the input (Go source code) and the kind of output (parts of the `Package` struct).
    * **User Errors:** Think about common mistakes users might make, such as forgetting to parse the files, providing an incorrect file set, or misunderstanding the `Mode` options.
    * **Language:** Ensure the explanation is in Chinese as requested.

9. **Refine and Structure:** Organize the information logically. Start with a high-level overview, then delve into specifics. Use clear headings and bullet points to improve readability. Ensure the code examples are complete and runnable. Double-check for accuracy and clarity. For instance, clarify the role of `simpleImporter` as a placeholder.

10. **Self-Correction/Review:**  Read through the explanation as if you were someone unfamiliar with the code. Are there any ambiguities? Is anything unclear?  For example, initially, I might have overlooked the significance of the `Mode` parameter, so I'd go back and explain its purpose. Similarly, clarifying that this code *is used by* tools like `godoc` is important.

By following this systematic approach, combining code analysis with an understanding of the broader Go ecosystem, and focusing on the specific requirements of the prompt, it's possible to generate a comprehensive and accurate explanation of the `doc.go` code.
这段代码是 Go 语言标准库 `go/doc` 包的一部分，主要负责从 Go 源代码的抽象语法树 (AST) 中提取文档信息。它的核心功能是解析 Go 代码中的注释，并将这些注释与相应的代码元素（如包、常量、变量、类型、函数和方法）关联起来，从而生成结构化的文档数据。

以下是其主要功能的详细列表：

**1. 解析 Go 代码并提取文档注释：**

*   **识别文档注释:**  它能够识别 Go 语言中的文档注释，即以 `//` 或 `/* ... */` 开头的注释，并将其与后续的声明关联起来。
*   **处理包文档:**  提取位于包声明前的包级别文档注释。
*   **处理常量、变量、类型和函数/方法文档:**  提取各个声明前的文档注释。
*   **处理示例代码:**  识别并提取 `_test.go` 文件中的示例函数，并将它们与相应的包、类型或函数/方法关联起来。示例函数的命名约定是 `Example` 开头，后面可以跟上类型或函数/方法名，以及可选的后缀。

**2. 构建文档的结构化表示：**

*   **`Package` 结构体:**  表示整个包的文档信息，包括包的文档字符串 (`Doc`)、名称 (`Name`)、导入路径 (`ImportPath`)、导入的包 (`Imports`)、包含的文件名 (`Filenames`)、注意事项 (`Notes`)、错误报告 (`Bugs`)、常量 (`Consts`)、类型 (`Types`)、变量 (`Vars`)、函数 (`Funcs`) 和示例 (`Examples`)。
*   **`Value` 结构体:**  表示常量或变量声明的文档，包括文档字符串 (`Doc`)、名称列表 (`Names`) 和对应的 AST 声明 (`Decl`)。
*   **`Type` 结构体:**  表示类型声明的文档，包括文档字符串 (`Doc`)、类型名称 (`Name`)、对应的 AST 声明 (`Decl`)，以及与该类型关联的常量、变量、函数和方法。
*   **`Func` 结构体:**  表示函数或方法声明的文档，包括文档字符串 (`Doc`)、名称 (`Name`)、对应的 AST 声明 (`Decl`)、接收者信息 (`Recv`, `Orig`, `Level`) 和示例。
*   **`Note` 结构体:**  表示带有特定标记的注释，用于提取如 `BUG` 等信息。

**3. 处理导入关系：**

*   记录包的导入路径 (`Imports`)。
*   提供 `lookupPackage` 方法，用于在当前包中查找给定名称对应的导入路径。这在解析文档注释中的链接时很有用。

**4. 提供灵活的文档提取模式：**

*   通过 `Mode` 类型定义了不同的提取模式，例如 `AllDecls` 可以提取所有包级别的声明，包括未导出的声明；`AllMethods` 可以显示所有嵌入的方法。

**5. 支持自定义的文档注释解析和打印：**

*   提供 `Parser()` 方法返回一个可以自定义的 `comment.Parser`，用于解析文档注释。
*   提供 `Printer()` 方法返回一个可以自定义的 `comment.Printer`，用于格式化文档注释为 HTML、Markdown 或纯文本。

**它是什么 Go 语言功能的实现？**

`go/doc` 包是 Go 语言中用于 **静态分析和提取源代码文档** 的核心组件。它是 `go doc` 命令行工具和在线文档 (pkg.go.dev) 的基础。通过解析源代码，它可以生成各种格式的 API 文档，帮助开发者理解和使用 Go 语言编写的库和应用程序。

**Go 代码举例说明：**

假设我们有以下 Go 源代码文件 `example.go`:

```go
package example

// Package example provides a simple example package.
// It demonstrates how to document Go code.
package example

// ConstantValue is a sample constant.
const ConstantValue = 10

// VariableValue is a sample variable.
var VariableValue int = 20

// MyType is a custom type.
// It represents a simple data structure.
type MyType struct {
    // FieldA is the first field.
    FieldA string
    // FieldB is the second field.
    FieldB int
}

// NewMyType creates a new MyType.
func NewMyType(a string, b int) *MyType {
    return &MyType{a, b}
}

// MethodA is a method of MyType.
func (m *MyType) MethodA() string {
    return m.FieldA
}
```

以及对应的测试文件 `example_test.go`:

```go
package example_test

import (
	"fmt"
	"example"
)

// ExampleConstantValue demonstrates the usage of ConstantValue.
func ExampleConstantValue() {
	fmt.Println(example.ConstantValue)
	// Output: 10
}

// ExampleNewMyType demonstrates how to create a MyType.
func ExampleNewMyType() {
	mt := example.NewMyType("hello", 123)
	fmt.Println(mt.FieldA, mt.FieldB)
	// Output: hello 123
}

// ExampleMyType_MethodA demonstrates the usage of MethodA.
func ExampleMyType_MethodA() {
	mt := example.NewMyType("world", 456)
	fmt.Println(mt.MethodA())
	// Output: world
}
```

我们可以使用 `go/doc` 包来提取这些代码的文档信息：

```go
package main

import (
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"log"
)

func main() {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "example.go", nil, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	files := []*ast.File{file}

	pkgInfo, err := doc.NewFromFiles(fset, files, "example")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Package Doc:", pkgInfo.Doc)
	fmt.Println("Constants:")
	for _, c := range pkgInfo.Consts {
		fmt.Printf("  %s: %s\n", strings.Join(c.Names, ", "), c.Doc)
	}
	fmt.Println("Variables:")
	for _, v := range pkgInfo.Vars {
		fmt.Printf("  %s: %s\n", strings.Join(v.Names, ", "), v.Doc)
	}
	fmt.Println("Types:")
	for _, t := range pkgInfo.Types {
		fmt.Printf("  %s: %s\n", t.Name, t.Doc)
		fmt.Println("  Fields:")
		if structType, ok := t.Decl.Specs[0].(*ast.TypeSpec).Type.(*ast.StructType); ok {
			for _, field := range structType.Fields.List {
				fmt.Printf("    %s: %s\n", strings.Join(field.Names, ", "), field.Doc.Text())
			}
		}
		fmt.Println("  Methods:")
		for _, m := range t.Methods {
			fmt.Printf("    %s: %s\n", m.Name, m.Doc)
		}
	}
	fmt.Println("Functions:")
	for _, f := range pkgInfo.Funcs {
		fmt.Printf("  %s: %s\n", f.Name, f.Doc)
	}
	fmt.Println("Examples:")
	for _, e := range pkgInfo.Examples {
		fmt.Printf("  %s:\n%s\n", e.Name, e.Doc)
	}
}
```

**假设的输入与输出：**

**输入:** `example.go` 和 `example_test.go` 的源代码。

**输出:**  (简化后的输出，实际输出会包含更多信息)

```
Package Doc: Package example provides a simple example package.
It demonstrates how to document Go code.
Constants:
  ConstantValue: ConstantValue is a sample constant.
Variables:
  VariableValue: VariableValue is a sample variable.
Types:
  MyType: MyType is a custom type.
It represents a simple data structure.
  Fields:
    FieldA: FieldA is the first field.
    FieldB: FieldB is the second field.
  Methods:
    MethodA: MethodA is a method of MyType.
Functions:
  NewMyType: NewMyType creates a new MyType.
Examples:
  ExampleConstantValue:
Output:
10

  ExampleNewMyType:
Output:
hello 123

  ExampleMyType_MethodA:
Output:
world
```

**命令行参数的具体处理：**

`go/doc` 包本身 **不直接处理命令行参数**。它的主要作用是提供 API 来提取文档信息。  像 `go doc` 这样的工具会使用 `go/doc` 包，并处理其自身的命令行参数来指定要查看文档的包、符号等。

例如，`go doc fmt` 命令会使用 `go/doc` 包来读取 `fmt` 包的源代码，提取文档信息，并将其格式化后输出到终端。

**使用者易犯错的点：**

1. **忘记解析文件:**  在使用 `NewFromFiles` 之前，需要使用 `go/parser` 包将 Go 源代码文件解析成 `*ast.File` 类型的抽象语法树。新手容易忘记这一步，直接将文件名传递给 `NewFromFiles`，导致程序出错。

    ```go
    // 错误示例
    // doc.NewFromFiles(nil, []string{"myfile.go"}, "mypkg") // 错误，files 需要是 []*ast.File

    // 正确示例
    fset := token.NewFileSet()
    file, err := parser.ParseFile(fset, "myfile.go", nil, parser.ParseComments)
    if err != nil {
        log.Fatal(err)
    }
    files := []*ast.File{file}
    pkgInfo, err := doc.NewFromFiles(fset, files, "mypkg")
    // ...
    ```

2. **`token.FileSet` 的使用:** `NewFromFiles` 需要一个 `token.FileSet` 参数，它用于维护文件和位置信息。 必须创建一个 `token.NewFileSet()` 实例并将其传递给 `parser.ParseFile` 和 `doc.NewFromFiles`。  如果传递 `nil` 会导致 panic。

    ```go
    // 错误示例
    // pkgInfo, err := doc.NewFromFiles(nil, files, "mypkg") // 错误，fset 不能为 nil

    // 正确示例
    fset := token.NewFileSet()
    // ... (解析文件)
    pkgInfo, err := doc.NewFromFiles(fset, files, "mypkg")
    ```

3. **不包含测试文件导致示例丢失:**  如果希望提取示例代码，必须将包含示例函数的 `_test.go` 文件也传递给 `NewFromFiles`。 否则，`Examples` 字段将为空。

    ```go
    // 只解析了 .go 文件，示例不会被提取
    fset := token.NewFileSet()
    file, _ := parser.ParseFile(fset, "myfile.go", nil, parser.ParseComments)
    pkgInfo, _ := doc.NewFromFiles(fset, []*ast.File{file}, "mypkg")

    // 需要同时解析 _test.go 文件
    testFile, _ := parser.ParseFile(fset, "myfile_test.go", nil, parser.ParseComments)
    pkgInfo, _ := doc.NewFromFiles(fset, []*ast.File{file, testFile}, "mypkg")
    ```

4. **误解 `Mode` 参数的作用:** `Mode` 参数用于控制文档提取的细节，例如是否包含未导出的声明或方法。不理解其含义可能导致提取的文档信息不完整或包含不需要的信息。需要查阅文档了解各个 `Mode` 值的具体作用。

5. **错误地处理 `NewFromFiles` 的返回值:** `NewFromFiles` 返回一个 `*Package` 和一个 `error`。 必须检查 `error` 是否为 `nil`，以确保文档提取成功。

总而言之，`go/doc` 包是 Go 语言中一个强大而重要的工具，用于提取和组织源代码文档。理解其工作原理和使用方法，能够帮助开发者更好地构建和维护 Go 语言项目，并生成清晰易懂的 API 文档。

Prompt: 
```
这是路径为go/src/go/doc/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package doc extracts source code documentation from a Go AST.
package doc

import (
	"fmt"
	"go/ast"
	"go/doc/comment"
	"go/token"
	"strings"
)

// Package is the documentation for an entire package.
type Package struct {
	Doc        string
	Name       string
	ImportPath string
	Imports    []string
	Filenames  []string
	Notes      map[string][]*Note

	// Deprecated: For backward compatibility Bugs is still populated,
	// but all new code should use Notes instead.
	Bugs []string

	// declarations
	Consts []*Value
	Types  []*Type
	Vars   []*Value
	Funcs  []*Func

	// Examples is a sorted list of examples associated with
	// the package. Examples are extracted from _test.go files
	// provided to NewFromFiles.
	Examples []*Example

	importByName map[string]string
	syms         map[string]bool
}

// Value is the documentation for a (possibly grouped) var or const declaration.
type Value struct {
	Doc   string
	Names []string // var or const names in declaration order
	Decl  *ast.GenDecl

	order int
}

// Type is the documentation for a type declaration.
type Type struct {
	Doc  string
	Name string
	Decl *ast.GenDecl

	// associated declarations
	Consts  []*Value // sorted list of constants of (mostly) this type
	Vars    []*Value // sorted list of variables of (mostly) this type
	Funcs   []*Func  // sorted list of functions returning this type
	Methods []*Func  // sorted list of methods (including embedded ones) of this type

	// Examples is a sorted list of examples associated with
	// this type. Examples are extracted from _test.go files
	// provided to NewFromFiles.
	Examples []*Example
}

// Func is the documentation for a func declaration.
type Func struct {
	Doc  string
	Name string
	Decl *ast.FuncDecl

	// methods
	// (for functions, these fields have the respective zero value)
	Recv  string // actual   receiver "T" or "*T" possibly followed by type parameters [P1, ..., Pn]
	Orig  string // original receiver "T" or "*T"
	Level int    // embedding level; 0 means not embedded

	// Examples is a sorted list of examples associated with this
	// function or method. Examples are extracted from _test.go files
	// provided to NewFromFiles.
	Examples []*Example
}

// A Note represents a marked comment starting with "MARKER(uid): note body".
// Any note with a marker of 2 or more upper case [A-Z] letters and a uid of
// at least one character is recognized. The ":" following the uid is optional.
// Notes are collected in the Package.Notes map indexed by the notes marker.
type Note struct {
	Pos, End token.Pos // position range of the comment containing the marker
	UID      string    // uid found with the marker
	Body     string    // note body text
}

// Mode values control the operation of [New] and [NewFromFiles].
type Mode int

const (
	// AllDecls says to extract documentation for all package-level
	// declarations, not just exported ones.
	AllDecls Mode = 1 << iota

	// AllMethods says to show all embedded methods, not just the ones of
	// invisible (unexported) anonymous fields.
	AllMethods

	// PreserveAST says to leave the AST unmodified. Originally, pieces of
	// the AST such as function bodies were nil-ed out to save memory in
	// godoc, but not all programs want that behavior.
	PreserveAST
)

// New computes the package documentation for the given package AST.
// New takes ownership of the AST pkg and may edit or overwrite it.
// To have the [Examples] fields populated, use [NewFromFiles] and include
// the package's _test.go files.
func New(pkg *ast.Package, importPath string, mode Mode) *Package {
	var r reader
	r.readPackage(pkg, mode)
	r.computeMethodSets()
	r.cleanupTypes()
	p := &Package{
		Doc:        r.doc,
		Name:       pkg.Name,
		ImportPath: importPath,
		Imports:    sortedKeys(r.imports),
		Filenames:  r.filenames,
		Notes:      r.notes,
		Bugs:       noteBodies(r.notes["BUG"]),
		Consts:     sortedValues(r.values, token.CONST),
		Types:      sortedTypes(r.types, mode&AllMethods != 0),
		Vars:       sortedValues(r.values, token.VAR),
		Funcs:      sortedFuncs(r.funcs, true),

		importByName: r.importByName,
		syms:         make(map[string]bool),
	}

	p.collectValues(p.Consts)
	p.collectValues(p.Vars)
	p.collectTypes(p.Types)
	p.collectFuncs(p.Funcs)

	return p
}

func (p *Package) collectValues(values []*Value) {
	for _, v := range values {
		for _, name := range v.Names {
			p.syms[name] = true
		}
	}
}

func (p *Package) collectTypes(types []*Type) {
	for _, t := range types {
		if p.syms[t.Name] {
			// Shouldn't be any cycles but stop just in case.
			continue
		}
		p.syms[t.Name] = true
		p.collectValues(t.Consts)
		p.collectValues(t.Vars)
		p.collectFuncs(t.Funcs)
		p.collectFuncs(t.Methods)
	}
}

func (p *Package) collectFuncs(funcs []*Func) {
	for _, f := range funcs {
		if f.Recv != "" {
			r := strings.TrimPrefix(f.Recv, "*")
			if i := strings.IndexByte(r, '['); i >= 0 {
				r = r[:i] // remove type parameters
			}
			p.syms[r+"."+f.Name] = true
		} else {
			p.syms[f.Name] = true
		}
	}
}

// NewFromFiles computes documentation for a package.
//
// The package is specified by a list of *ast.Files and corresponding
// file set, which must not be nil.
// NewFromFiles uses all provided files when computing documentation,
// so it is the caller's responsibility to provide only the files that
// match the desired build context. "go/build".Context.MatchFile can
// be used for determining whether a file matches a build context with
// the desired GOOS and GOARCH values, and other build constraints.
// The import path of the package is specified by importPath.
//
// Examples found in _test.go files are associated with the corresponding
// type, function, method, or the package, based on their name.
// If the example has a suffix in its name, it is set in the
// [Example.Suffix] field. [Examples] with malformed names are skipped.
//
// Optionally, a single extra argument of type [Mode] can be provided to
// control low-level aspects of the documentation extraction behavior.
//
// NewFromFiles takes ownership of the AST files and may edit them,
// unless the PreserveAST Mode bit is on.
func NewFromFiles(fset *token.FileSet, files []*ast.File, importPath string, opts ...any) (*Package, error) {
	// Check for invalid API usage.
	if fset == nil {
		panic(fmt.Errorf("doc.NewFromFiles: no token.FileSet provided (fset == nil)"))
	}
	var mode Mode
	switch len(opts) { // There can only be 0 or 1 options, so a simple switch works for now.
	case 0:
		// Nothing to do.
	case 1:
		m, ok := opts[0].(Mode)
		if !ok {
			panic(fmt.Errorf("doc.NewFromFiles: option argument type must be doc.Mode"))
		}
		mode = m
	default:
		panic(fmt.Errorf("doc.NewFromFiles: there must not be more than 1 option argument"))
	}

	// Collect .go and _test.go files.
	var (
		goFiles     = make(map[string]*ast.File)
		testGoFiles []*ast.File
	)
	for i := range files {
		f := fset.File(files[i].Pos())
		if f == nil {
			return nil, fmt.Errorf("file files[%d] is not found in the provided file set", i)
		}
		switch name := f.Name(); {
		case strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go"):
			goFiles[name] = files[i]
		case strings.HasSuffix(name, "_test.go"):
			testGoFiles = append(testGoFiles, files[i])
		default:
			return nil, fmt.Errorf("file files[%d] filename %q does not have a .go extension", i, name)
		}
	}

	// TODO(dmitshur,gri): A relatively high level call to ast.NewPackage with a simpleImporter
	// ast.Importer implementation is made below. It might be possible to short-circuit and simplify.

	// Compute package documentation.
	pkg, _ := ast.NewPackage(fset, goFiles, simpleImporter, nil) // Ignore errors that can happen due to unresolved identifiers.
	p := New(pkg, importPath, mode)
	classifyExamples(p, Examples(testGoFiles...))
	return p, nil
}

// simpleImporter returns a (dummy) package object named by the last path
// component of the provided package path (as is the convention for packages).
// This is sufficient to resolve package identifiers without doing an actual
// import. It never returns an error.
func simpleImporter(imports map[string]*ast.Object, path string) (*ast.Object, error) {
	pkg := imports[path]
	if pkg == nil {
		// note that strings.LastIndex returns -1 if there is no "/"
		pkg = ast.NewObj(ast.Pkg, path[strings.LastIndex(path, "/")+1:])
		pkg.Data = ast.NewScope(nil) // required by ast.NewPackage for dot-import
		imports[path] = pkg
	}
	return pkg, nil
}

// lookupSym reports whether the package has a given symbol or method.
//
// If recv == "", HasSym reports whether the package has a top-level
// const, func, type, or var named name.
//
// If recv != "", HasSym reports whether the package has a type
// named recv with a method named name.
func (p *Package) lookupSym(recv, name string) bool {
	if recv != "" {
		return p.syms[recv+"."+name]
	}
	return p.syms[name]
}

// lookupPackage returns the import path identified by name
// in the given package. If name uniquely identifies a single import,
// then lookupPackage returns that import.
// If multiple packages are imported as name, importPath returns "", false.
// Otherwise, if name is the name of p itself, importPath returns "", true,
// to signal a reference to p.
// Otherwise, importPath returns "", false.
func (p *Package) lookupPackage(name string) (importPath string, ok bool) {
	if path, ok := p.importByName[name]; ok {
		if path == "" {
			return "", false // multiple imports used the name
		}
		return path, true // found import
	}
	if p.Name == name {
		return "", true // allow reference to this package
	}
	return "", false // unknown name
}

// Parser returns a doc comment parser configured
// for parsing doc comments from package p.
// Each call returns a new parser, so that the caller may
// customize it before use.
func (p *Package) Parser() *comment.Parser {
	return &comment.Parser{
		LookupPackage: p.lookupPackage,
		LookupSym:     p.lookupSym,
	}
}

// Printer returns a doc comment printer configured
// for printing doc comments from package p.
// Each call returns a new printer, so that the caller may
// customize it before use.
func (p *Package) Printer() *comment.Printer {
	// No customization today, but having p.Printer()
	// gives us flexibility in the future, and it is convenient for callers.
	return &comment.Printer{}
}

// HTML returns formatted HTML for the doc comment text.
//
// To customize details of the HTML, use [Package.Printer]
// to obtain a [comment.Printer], and configure it
// before calling its HTML method.
func (p *Package) HTML(text string) []byte {
	return p.Printer().HTML(p.Parser().Parse(text))
}

// Markdown returns formatted Markdown for the doc comment text.
//
// To customize details of the Markdown, use [Package.Printer]
// to obtain a [comment.Printer], and configure it
// before calling its Markdown method.
func (p *Package) Markdown(text string) []byte {
	return p.Printer().Markdown(p.Parser().Parse(text))
}

// Text returns formatted text for the doc comment text,
// wrapped to 80 Unicode code points and using tabs for
// code block indentation.
//
// To customize details of the formatting, use [Package.Printer]
// to obtain a [comment.Printer], and configure it
// before calling its Text method.
func (p *Package) Text(text string) []byte {
	return p.Printer().Text(p.Parser().Parse(text))
}

"""



```