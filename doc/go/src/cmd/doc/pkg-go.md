Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding of the Request:**

The request asks for the functionalities of the `pkg.go` file within the `go/src/cmd/doc` directory. It also requests examples, command-line argument handling, and common mistakes. This indicates that the file is likely part of the `go doc` tool's implementation.

**2. High-Level Overview of `go doc`:**

Before diving into the code, it's helpful to recall what `go doc` does. It extracts and displays documentation for Go packages, types, functions, constants, and variables. This immediately suggests that the code will involve parsing Go source files, extracting comments, and formatting output.

**3. Identifying Key Data Structures:**

The first step in analyzing the code is to identify the core data structures and their roles. The `Package` struct stands out as central. Let's examine its fields:

* `writer io.Writer`:  Likely for directing output (e.g., to the console).
* `name string`: The package name.
* `userPath string`: The user-provided path, important for error messages and context.
* `pkg *ast.Package`:  The parsed Abstract Syntax Tree (AST) of the package. This is crucial for understanding the code's structure.
* `file *ast.File`: A merged AST representing the entire package.
* `doc *doc.Package`:  The `go/doc` package's representation of the documentation. This is where extracted comments and signatures are stored.
* `build *build.Package`: Information about the package's build context (import path, directory, etc.).
* `typedValue map[*doc.Value]bool`:  Potentially tracks constants/variables associated with specific types (a workaround for a `go/doc` limitation).
* `constructor map[*doc.Func]bool`:  Identifies functions that act as constructors.
* `fs *token.FileSet`: Used by the `go/printer` and `go/format` packages for source code formatting and position information.
* `buf pkgBuffer`: A custom buffer that adds the "package" clause at the beginning.

**4. Analyzing Key Functions and Methods:**

Next, let's examine the significant functions and methods, grouping them by functionality:

* **Output/Formatting:**
    * `ToText`:  Formats documentation text.
    * `pkgBuffer`:  Handles the "package" clause printing.
    * `Printf`, `flush`, `newlines`:  Methods for writing to the output buffer.
    * `emit`:  Prints AST nodes with optional comments.
    * `oneLineNode`, `oneLineNodeDepth`, `oneLineField`, `formatTypeParams`, `joinStrings`:  Functions for generating concise summaries of code elements.
    * `printHeader`: Formats section headers.

* **Documentation Extraction and Filtering:**
    * `parsePackage`:  Parses the Go source files and uses `go/doc` to extract documentation. The `include` function within `parsePackage` is important for understanding which files are considered.
    * `constsDoc`, `varsDoc`, `funcsDoc`, `typesDoc`, `packageDoc`: Functions to organize and print different documentation sections.
    * `valueSummary`, `funcSummary`, `typeSummary`:  Functions to print concise summaries of package elements.
    * `bugs`: Prints "BUG" comments.

* **Symbol Lookup:**
    * `findValues`, `findFuncs`, `findTypes`, `findTypeSpec`:  Functions to locate specific documented elements based on their names.
    * `symbolDoc`: Orchestrates the documentation output for a given symbol.
    * `valueDoc`, `typeDoc`: Functions for printing detailed documentation of values and types.
    * `printMethodDoc`, `printFieldDoc`: Specifically handle documentation for methods and struct fields.

* **Error Handling and Path Manipulation:**
    * `PackageError`, `Fatalf`: Custom error handling within the `doc` tool.
    * `prettyPath`, `trim`: Functions for generating user-friendly package paths in error messages.
    * `splitGopath`:  (Although not in the provided snippet, it's clear from the context that this function exists and is used by `prettyPath`).

* **Matching and Exported Status:**
    * `match`, `simpleFold`: Implement fuzzy matching for symbol names.
    * `isExported`:  Determines if a symbol is exported.

* **AST Manipulation:**
    * `trimUnexportedElems`, `trimUnexportedFields`:  Functions to filter out unexported members when displaying documentation (unless the `-u` flag is used).

**5. Inferring Go Language Features:**

Based on the imported packages (`go/ast`, `go/build`, `go/doc`, `go/parser`, `go/printer`, `go/format`), the code heavily utilizes:

* **Reflection and Type Information:** The `go/*` packages are fundamental for analyzing Go code structure and types.
* **Abstract Syntax Trees (ASTs):** The code manipulates AST nodes extensively to extract information and format output.
* **Comments as Documentation:** The `go/doc` package relies on specially formatted comments to generate documentation.
* **Package Management:** The `go/build` package helps understand package dependencies and location.
* **Formatting and Printing:**  The `go/format` and `go/printer` packages are used for generating well-formatted Go code snippets in the documentation.

**6. Command-Line Arguments (Inference):**

While the provided snippet doesn't explicitly show command-line argument parsing, we can infer some likely flags based on the code:

* `-u` or `--unexported`:  Based on `unexported` variable usage in `trimUnexportedElems`, this flag probably shows unexported members.
* `-src` or `--source`: Based on `showSrc` variable usage in `emit` and `parsePackage`, this likely displays the original source code instead of formatted documentation.
* `-all`: Based on `showAll` variable usage in `packageDoc` and other functions, this probably shows all documentation, including constants, variables, functions, and types.
* `-short`: Based on `short` variable usage, this might provide a shorter summary.
* Flags related to package and symbol selection (e.g., specifying a package or a specific symbol to document).
* potentially flags related to modules (`usingModules`).
* `showCmd`: Controls whether the package clause is shown for `main` packages.

**7. Identifying Potential User Mistakes:**

* **Incorrectly Formatted Comments:** If comments don't follow the `go doc` conventions, they won't be extracted correctly.
* **Misunderstanding Exported vs. Unexported:**  Users might be confused about why certain symbols don't appear in the documentation if they are unexported.
* **Assuming `go doc` Shows Implementation Details:** `go doc` focuses on the public API. Users might expect it to reveal internal implementation details.
* **Problems with GOPATH/Modules:** Incorrectly configured GOPATH or module settings can prevent `go doc` from finding packages.

**8. Iterative Refinement:**

The analysis process is often iterative. After the initial pass, reviewing the code again can reveal more nuanced details and connections between different parts of the code. For example, noticing the interplay between `typedValue` and the filtering logic in `constsDoc` and `varsDoc` gives a deeper understanding of the workaround being implemented.

By following these steps, we can systematically analyze the Go code snippet and arrive at a comprehensive understanding of its functionality, related Go features, likely command-line arguments, and potential user pitfalls.
这是 `go/src/cmd/doc/pkg.go` 文件的一部分，它主要负责**处理和格式化单个 Go 包的文档信息**，用于 `go doc` 命令的实现。

以下是它的一些关键功能：

**1. 包的表示和管理 (`Package` 结构体):**

*  `Package` 结构体是核心，它存储了从 Go 代码中解析出的关于一个包的所有信息，包括 AST (抽象语法树)、文档注释、构建信息等。
*  它持有用于输出的 `io.Writer`，方便将格式化后的文档写入不同的目标。
*  它还包含缓存 (`pkgBuffer`)，用于高效地构建输出字符串，并在首次写入时添加包声明。

**2. 文档解析和格式化:**

*  `parsePackage` 函数是关键的入口点，它接收一个 `build.Package` 结构体（包含包的构建信息），并使用 `go/parser` 解析 Go 源代码，然后使用 `go/doc` 包提取文档注释等信息。
*  `ToText` 方法使用 `go/doc` 包的 `Parser` 和 `Printer` 来处理和格式化文档文本，支持添加前缀和代码前缀。
*  `emit` 方法负责打印 AST 节点，可以选择包含或忽略注释，并使用 `go/format` 包进行代码格式化。
*  `oneLineNode` 系列方法 (`oneLineNode`, `oneLineNodeDepth`, `oneLineField`) 用于生成代码元素的单行摘要，方便在概览信息中使用。

**3. 文档内容的组织和输出:**

*  `packageDoc` 方法是生成包文档的入口，它根据不同的选项 (`showAll`, `short`, `showCmd`) 输出包的文档、常量、变量、函数、类型等信息。
*  `constsDoc`, `varsDoc`, `funcsDoc`, `typesDoc` 等方法分别负责输出特定类型的文档信息，并添加相应的标题。
*  `valueSummary`, `funcSummary`, `typeSummary` 用于生成各种元素的简要列表。
*  `packageClause` 方法负责打印包的导入路径声明。
*  `bugs` 方法用于输出代码中的 "BUG" 注释。

**4. 符号查找和文档输出:**

*  `findValues`, `findFuncs`, `findTypes` 等方法用于在解析出的文档信息中查找与给定符号匹配的常量、变量、函数或类型。
*  `symbolDoc` 方法根据给定的符号名称，查找并输出对应的文档信息，包括函数、常量、变量和类型。
*  `valueDoc`, `typeDoc` 方法用于输出特定常量、变量或类型的详细文档，包括关联的常量、变量、函数和方法。
*  `printMethodDoc`, `printFieldDoc` 用于输出特定类型的方法或字段的文档。

**5. 辅助功能:**

*  `prettyPath` 函数用于生成更友好的包路径，用于错误消息等。
*  `trim` 函数用于裁剪路径前缀。
*  `Fatalf` 方法是一个自定义的错误处理函数，用于在 `go doc` 命令执行过程中抛出错误，并可以被上层函数捕获，避免程序直接退出。
*  `match` 函数实现了一个大小写不敏感的匹配算法，用于匹配用户输入的符号名称和代码中的符号名称。
*  `trimUnexportedElems`, `trimUnexportedFields` 函数用于在输出文档时，根据选项过滤掉未导出的字段和方法。

**它是什么 go 语言功能的实现：**

这段代码是 `go doc` 命令行工具中用于处理和格式化 Go 包文档的核心部分。 `go doc` 工具允许开发者查看 Go 代码中的文档注释，而无需直接查看源代码。

**Go 代码举例说明：**

假设我们有一个名为 `mypackage` 的包，其代码如下：

```go
// mypackage 提供了示例功能。
package mypackage

// Version 是当前包的版本号。
const Version = "1.0.0"

// Add 将两个整数相加并返回结果。
func Add(a, b int) int {
	return a + b
}

// Calculator 结构体用于执行计算。
type Calculator struct {
	// factor 是一个用于乘法的因子。
	factor int
}

// NewCalculator 创建一个新的 Calculator 实例。
func NewCalculator(f int) *Calculator {
	return &Calculator{factor: f}
}

// Multiply 将给定的数字乘以 Calculator 的因子。
func (c *Calculator) Multiply(num int) int {
	return c.factor * num
}
```

当我们在命令行中执行 `go doc mypackage` 时，`pkg.go` 中的代码会被调用来处理 `mypackage`，并生成类似以下的输出：

```
package mypackage // import "example.com/mypackage"

mypackage 提供了示例功能。

CONSTANTS
    const Version = "1.0.0"
        Version 是当前包的版本号。

FUNCTIONS
    func Add(a int, b int) int
        Add 将两个整数相加并返回结果。

TYPES
    type Calculator struct {
        factor int
        // Has unexported fields.
    }
        Calculator 结构体用于执行计算。

    func NewCalculator(f int) *Calculator
        NewCalculator 创建一个新的 Calculator 实例。

    func (c *Calculator) Multiply(num int) int
        Multiply 将给定的数字乘以 Calculator 的因子。
```

**代码推理（带假设的输入与输出）：**

假设 `parsePackage` 函数接收到 `mypackage` 的 `build.Package` 信息，并且成功解析了源代码。

**输入 (简化的 `doc.Package` 结构体，由 `parsePackage` 生成)：**

```go
&doc.Package{
	Name: "mypackage",
	Doc:  "mypackage 提供了示例功能。",
	Consts: []*doc.Value{
		{
			Names: []string{"Version"},
			Doc:   "Version 是当前包的版本号。",
			Decl: &ast.GenDecl{
				Tok: token.CONST,
				Specs: []ast.Spec{
					&ast.ValueSpec{
						Names: []*ast.Ident{{Name: "Version"}},
						Type:  &ast.Ident{Name: "string"},
						Values: []ast.Expr{&ast.BasicLit{Kind: token.STRING, Value: `"1.0.0"`}},
					},
				},
			},
		},
	},
	Funcs: []*doc.Func{
		{
			Name: "Add",
			Doc:  "Add 将两个整数相加并返回结果。",
			Decl: &ast.FuncDecl{
				Name: &ast.Ident{Name: "Add"},
				Type: &ast.FuncType{
					Params: &ast.FieldList{
						List: []*ast.Field{
							{Names: []*ast.Ident{{Name: "a"}}, Type: &ast.Ident{Name: "int"}},
							{Names: []*ast.Ident{{Name: "b"}}, Type: &ast.Ident{Name: "int"}},
						},
					},
					Results: &ast.FieldList{
						List: []*ast.Field{{Type: &ast.Ident{Name: "int"}}},
					},
				},
			},
		},
		{
			Name: "NewCalculator",
			Doc:  "NewCalculator 创建一个新的 Calculator 实例。",
			Decl: &ast.FuncDecl{
				Name: &ast.Ident{Name: "NewCalculator"},
				Type: &ast.FuncType{
					Params: &ast.FieldList{
						List: []*ast.Field{{Names: []*ast.Ident{{Name: "f"}}, Type: &ast.Ident{Name: "int"}}},
					},
					Results: &ast.FieldList{
						List: []*ast.Field{{Type: &ast.StarExpr{X: &ast.Ident{Name: "Calculator"}}}},
					},
				},
			},
		},
	},
	Types: []*doc.Type{
		{
			Name: "Calculator",
			Doc:  "Calculator 结构体用于执行计算。",
			Decl: &ast.GenDecl{
				Tok: token.TYPE,
				Specs: []ast.Spec{
					&ast.TypeSpec{
						Name: &ast.Ident{Name: "Calculator"},
						Type: &ast.StructType{
							Fields: &ast.FieldList{
								List: []*ast.Field{{Names: []*ast.Ident{{Name: "factor"}}, Type: &ast.Ident{Name: "int"}, Doc: &ast.CommentGroup{}}},
							},
						},
					},
				},
			},
			Funcs: []*doc.Func{
				// NewCalculator 的信息会在这里
			},
			Methods: []*doc.Func{
				{
					Name: "Multiply",
					Doc:  "Multiply 将给定的数字乘以 Calculator 的因子。",
					Decl: &ast.FuncDecl{
						Recv: &ast.FieldList{List: []*ast.Field{{Names: []*ast.Ident{{Name: "c"}}, Type: &ast.StarExpr{X: &ast.Ident{Name: "Calculator"}}}}},
						Name: &ast.Ident{Name: "Multiply"},
						Type: &ast.FuncType{
							Params: &ast.FieldList{
								List: []*ast.Field{{Names: []*ast.Ident{{Name: "num"}}, Type: &ast.Ident{Name: "int"}}},
							},
							Results: &ast.FieldList{
								List: []*ast.Field{{Type: &ast.Ident{Name: "int"}}},
							},
						},
					},
				},
			},
		},
	},
}
```

**输出 (部分，由 `packageDoc` 和相关方法生成)：**

```
package mypackage // import "example.com/mypackage"

mypackage 提供了示例功能。

CONSTANTS
    const Version = "1.0.0"
        Version 是当前包的版本号。

FUNCTIONS
    func Add(a int, b int) int
        Add 将两个整数相加并返回结果。

TYPES
    type Calculator struct {
        factor int
        // Has unexported fields.
    }
        Calculator 结构体用于执行计算。

    func NewCalculator(f int) *Calculator
        NewCalculator 创建一个新的 Calculator 实例。

    func (c *Calculator) Multiply(num int) int
        Multiply 将给定的数字乘以 Calculator 的因子。
```

**命令行参数的具体处理：**

虽然这段代码本身没有直接处理命令行参数，但它依赖于上层调用者（`go/src/cmd/doc/doc.go` 中的 `main` 函数和 `do` 函数）来解析命令行参数，并将相关信息传递给 `parsePackage` 等函数。

可以推断出一些可能影响这段代码行为的命令行参数：

* **包路径：** 例如 `go doc mypackage`，`mypackage` 会作为参数传递给上层函数，最终影响 `parsePackage` 加载哪个包。
* **符号名称：** 例如 `go doc mypackage.Add`，`Add` 会作为符号传递，影响 `symbolDoc` 方法查找并输出 `Add` 函数的文档。
* **`-all` 标志：**  `showAll` 变量的值会根据 `-all` 标志设置，影响 `packageDoc` 方法输出所有类型的文档信息。
* **`-short` 标志：** `short` 变量的值会根据 `-short` 标志设置，影响 `packageDoc` 方法输出更简洁的摘要信息。
* **`-u` 标志：** `unexported` 变量的值会根据 `-u` 标志设置，影响 `trimUnexportedElems` 和 `trimUnexportedFields` 是否过滤未导出的成员。
* **`-src` 标志：** `showSrc` 变量的值会根据 `-src` 标志设置，影响 `emit` 方法是否直接打印源代码。
* **可能的模块相关标志：** 如果涉及到 Go Modules，可能会有相关的标志影响包的查找和导入路径的展示。

**使用者易犯错的点：**

1. **未导出的符号无法查看文档：**  `go doc` 默认只显示导出的（首字母大写）的类型、函数、常量和变量的文档。用户可能会尝试查看未导出符号的文档，但会发现无法找到。

   **例子：** 在上面的 `mypackage` 例子中，如果尝试执行 `go doc mypackage.factor`，则不会找到任何文档，因为 `factor` 字段是未导出的。

2. **错误的符号名称：**  用户可能会输入错误的包名或符号名，导致 `go doc` 无法找到对应的文档。

   **例子：** 如果输入 `go doc mypackge` (拼写错误) 或者 `go doc mypackage.Ad` (函数名拼写错误)，则会报错或找不到文档。

3. **对文档注释格式不熟悉：**  `go doc` 依赖于特定的文档注释格式（以 `//` 开头，对于包、类型、函数等需要紧跟在声明之前），如果注释格式不正确，`go doc` 可能无法正确提取和显示文档。

   **例子：** 如果将 `Add` 函数的注释写成 `/* Add 将两个整数相加并返回结果。 */`，`go doc` 默认情况下可能无法识别为文档注释。

4. **模块环境下的包路径理解：** 在使用 Go Modules 的项目中，用户可能需要使用完整的模块路径来指定要查看文档的包，而不是仅仅是包名。

   **例子：** 如果 `mypackage` 位于一个模块中，可能需要使用 `go doc example.com/mypackage` 来查看其文档。

总而言之，`go/src/cmd/doc/pkg.go` 是 `go doc` 工具的核心组成部分，负责将 Go 代码解析成结构化的文档信息，并根据不同的选项进行格式化和输出，方便开发者查阅 Go 代码的文档。

Prompt: 
```
这是路径为go/src/cmd/doc/pkg.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/doc"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	punchedCardWidth = 80
	indent           = "    "
)

type Package struct {
	writer      io.Writer    // Destination for output.
	name        string       // Package name, json for encoding/json.
	userPath    string       // String the user used to find this package.
	pkg         *ast.Package // Parsed package.
	file        *ast.File    // Merged from all files in the package
	doc         *doc.Package
	build       *build.Package
	typedValue  map[*doc.Value]bool // Consts and vars related to types.
	constructor map[*doc.Func]bool  // Constructors.
	fs          *token.FileSet      // Needed for printing.
	buf         pkgBuffer
}

func (pkg *Package) ToText(w io.Writer, text, prefix, codePrefix string) {
	d := pkg.doc.Parser().Parse(text)
	pr := pkg.doc.Printer()
	pr.TextPrefix = prefix
	pr.TextCodePrefix = codePrefix
	w.Write(pr.Text(d))
}

// pkgBuffer is a wrapper for bytes.Buffer that prints a package clause the
// first time Write is called.
type pkgBuffer struct {
	pkg     *Package
	printed bool // Prevent repeated package clauses.
	bytes.Buffer
}

func (pb *pkgBuffer) Write(p []byte) (int, error) {
	pb.packageClause()
	return pb.Buffer.Write(p)
}

func (pb *pkgBuffer) packageClause() {
	if !pb.printed {
		pb.printed = true
		// Only show package clause for commands if requested explicitly.
		if pb.pkg.pkg.Name != "main" || showCmd {
			pb.pkg.packageClause()
		}
	}
}

type PackageError string // type returned by pkg.Fatalf.

func (p PackageError) Error() string {
	return string(p)
}

// prettyPath returns a version of the package path that is suitable for an
// error message. It obeys the import comment if present. Also, since
// pkg.build.ImportPath is sometimes the unhelpful "" or ".", it looks for a
// directory name in GOROOT or GOPATH if that happens.
func (pkg *Package) prettyPath() string {
	path := pkg.build.ImportComment
	if path == "" {
		path = pkg.build.ImportPath
	}
	if path != "." && path != "" {
		return path
	}
	// Convert the source directory into a more useful path.
	// Also convert everything to slash-separated paths for uniform handling.
	path = filepath.Clean(filepath.ToSlash(pkg.build.Dir))
	// Can we find a decent prefix?
	if buildCtx.GOROOT != "" {
		goroot := filepath.Join(buildCtx.GOROOT, "src")
		if p, ok := trim(path, filepath.ToSlash(goroot)); ok {
			return p
		}
	}
	for _, gopath := range splitGopath() {
		if p, ok := trim(path, filepath.ToSlash(gopath)); ok {
			return p
		}
	}
	return path
}

// trim trims the directory prefix from the path, paying attention
// to the path separator. If they are the same string or the prefix
// is not present the original is returned. The boolean reports whether
// the prefix is present. That path and prefix have slashes for separators.
func trim(path, prefix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) {
		return path, false
	}
	if path == prefix {
		return path, true
	}
	if path[len(prefix)] == '/' {
		return path[len(prefix)+1:], true
	}
	return path, false // Textual prefix but not a path prefix.
}

// pkg.Fatalf is like log.Fatalf, but panics so it can be recovered in the
// main do function, so it doesn't cause an exit. Allows testing to work
// without running a subprocess. The log prefix will be added when
// logged in main; it is not added here.
func (pkg *Package) Fatalf(format string, args ...any) {
	panic(PackageError(fmt.Sprintf(format, args...)))
}

// parsePackage turns the build package we found into a parsed package
// we can then use to generate documentation.
func parsePackage(writer io.Writer, pkg *build.Package, userPath string) *Package {
	// include tells parser.ParseDir which files to include.
	// That means the file must be in the build package's GoFiles or CgoFiles
	// list only (no tag-ignored files, tests, swig or other non-Go files).
	include := func(info fs.FileInfo) bool {
		for _, name := range pkg.GoFiles {
			if name == info.Name() {
				return true
			}
		}
		for _, name := range pkg.CgoFiles {
			if name == info.Name() {
				return true
			}
		}
		return false
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkg.Dir, include, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}
	// Make sure they are all in one package.
	if len(pkgs) == 0 {
		log.Fatalf("no source-code package in directory %s", pkg.Dir)
	}
	if len(pkgs) > 1 {
		log.Fatalf("multiple packages in directory %s", pkg.Dir)
	}
	astPkg := pkgs[pkg.Name]

	// TODO: go/doc does not include typed constants in the constants
	// list, which is what we want. For instance, time.Sunday is of type
	// time.Weekday, so it is defined in the type but not in the
	// Consts list for the package. This prevents
	//	go doc time.Sunday
	// from finding the symbol. Work around this for now, but we
	// should fix it in go/doc.
	// A similar story applies to factory functions.
	mode := doc.AllDecls
	if showSrc {
		mode |= doc.PreserveAST // See comment for Package.emit.
	}
	docPkg := doc.New(astPkg, pkg.ImportPath, mode)
	typedValue := make(map[*doc.Value]bool)
	constructor := make(map[*doc.Func]bool)
	for _, typ := range docPkg.Types {
		docPkg.Consts = append(docPkg.Consts, typ.Consts...)
		docPkg.Vars = append(docPkg.Vars, typ.Vars...)
		docPkg.Funcs = append(docPkg.Funcs, typ.Funcs...)
		if isExported(typ.Name) {
			for _, value := range typ.Consts {
				typedValue[value] = true
			}
			for _, value := range typ.Vars {
				typedValue[value] = true
			}
			for _, fun := range typ.Funcs {
				// We don't count it as a constructor bound to the type
				// if the type itself is not exported.
				constructor[fun] = true
			}
		}
	}

	p := &Package{
		writer:      writer,
		name:        pkg.Name,
		userPath:    userPath,
		pkg:         astPkg,
		file:        ast.MergePackageFiles(astPkg, 0),
		doc:         docPkg,
		typedValue:  typedValue,
		constructor: constructor,
		build:       pkg,
		fs:          fset,
	}
	p.buf.pkg = p
	return p
}

func (pkg *Package) Printf(format string, args ...any) {
	fmt.Fprintf(&pkg.buf, format, args...)
}

func (pkg *Package) flush() {
	_, err := pkg.writer.Write(pkg.buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	pkg.buf.Reset() // Not needed, but it's a flush.
}

var newlineBytes = []byte("\n\n") // We never ask for more than 2.

// newlines guarantees there are n newlines at the end of the buffer.
func (pkg *Package) newlines(n int) {
	for !bytes.HasSuffix(pkg.buf.Bytes(), newlineBytes[:n]) {
		pkg.buf.WriteRune('\n')
	}
}

// emit prints the node. If showSrc is true, it ignores the provided comment,
// assuming the comment is in the node itself. Otherwise, the go/doc package
// clears the stuff we don't want to print anyway. It's a bit of a magic trick.
func (pkg *Package) emit(comment string, node ast.Node) {
	if node != nil {
		var arg any = node
		if showSrc {
			// Need an extra little dance to get internal comments to appear.
			arg = &printer.CommentedNode{
				Node:     node,
				Comments: pkg.file.Comments,
			}
		}
		err := format.Node(&pkg.buf, pkg.fs, arg)
		if err != nil {
			log.Fatal(err)
		}
		if comment != "" && !showSrc {
			pkg.newlines(1)
			pkg.ToText(&pkg.buf, comment, indent, indent+indent)
			pkg.newlines(2) // Blank line after comment to separate from next item.
		} else {
			pkg.newlines(1)
		}
	}
}

// oneLineNode returns a one-line summary of the given input node.
func (pkg *Package) oneLineNode(node ast.Node) string {
	const maxDepth = 10
	return pkg.oneLineNodeDepth(node, maxDepth)
}

// oneLineNodeDepth returns a one-line summary of the given input node.
// The depth specifies the maximum depth when traversing the AST.
func (pkg *Package) oneLineNodeDepth(node ast.Node, depth int) string {
	const dotDotDot = "..."
	if depth == 0 {
		return dotDotDot
	}
	depth--

	switch n := node.(type) {
	case nil:
		return ""

	case *ast.GenDecl:
		// Formats const and var declarations.
		trailer := ""
		if len(n.Specs) > 1 {
			trailer = " " + dotDotDot
		}

		// Find the first relevant spec.
		typ := ""
		for i, spec := range n.Specs {
			valueSpec := spec.(*ast.ValueSpec) // Must succeed; we can't mix types in one GenDecl.

			// The type name may carry over from a previous specification in the
			// case of constants and iota.
			if valueSpec.Type != nil {
				typ = fmt.Sprintf(" %s", pkg.oneLineNodeDepth(valueSpec.Type, depth))
			} else if len(valueSpec.Values) > 0 {
				typ = ""
			}

			if !isExported(valueSpec.Names[0].Name) {
				continue
			}
			val := ""
			if i < len(valueSpec.Values) && valueSpec.Values[i] != nil {
				val = fmt.Sprintf(" = %s", pkg.oneLineNodeDepth(valueSpec.Values[i], depth))
			}
			return fmt.Sprintf("%s %s%s%s%s", n.Tok, valueSpec.Names[0], typ, val, trailer)
		}
		return ""

	case *ast.FuncDecl:
		// Formats func declarations.
		name := n.Name.Name
		recv := pkg.oneLineNodeDepth(n.Recv, depth)
		if len(recv) > 0 {
			recv = "(" + recv + ") "
		}
		fnc := pkg.oneLineNodeDepth(n.Type, depth)
		fnc = strings.TrimPrefix(fnc, "func")
		return fmt.Sprintf("func %s%s%s", recv, name, fnc)

	case *ast.TypeSpec:
		sep := " "
		if n.Assign.IsValid() {
			sep = " = "
		}
		tparams := pkg.formatTypeParams(n.TypeParams, depth)
		return fmt.Sprintf("type %s%s%s%s", n.Name.Name, tparams, sep, pkg.oneLineNodeDepth(n.Type, depth))

	case *ast.FuncType:
		var params []string
		if n.Params != nil {
			for _, field := range n.Params.List {
				params = append(params, pkg.oneLineField(field, depth))
			}
		}
		needParens := false
		var results []string
		if n.Results != nil {
			needParens = needParens || len(n.Results.List) > 1
			for _, field := range n.Results.List {
				needParens = needParens || len(field.Names) > 0
				results = append(results, pkg.oneLineField(field, depth))
			}
		}

		tparam := pkg.formatTypeParams(n.TypeParams, depth)
		param := joinStrings(params)
		if len(results) == 0 {
			return fmt.Sprintf("func%s(%s)", tparam, param)
		}
		result := joinStrings(results)
		if !needParens {
			return fmt.Sprintf("func%s(%s) %s", tparam, param, result)
		}
		return fmt.Sprintf("func%s(%s) (%s)", tparam, param, result)

	case *ast.StructType:
		if n.Fields == nil || len(n.Fields.List) == 0 {
			return "struct{}"
		}
		return "struct{ ... }"

	case *ast.InterfaceType:
		if n.Methods == nil || len(n.Methods.List) == 0 {
			return "interface{}"
		}
		return "interface{ ... }"

	case *ast.FieldList:
		if n == nil || len(n.List) == 0 {
			return ""
		}
		if len(n.List) == 1 {
			return pkg.oneLineField(n.List[0], depth)
		}
		return dotDotDot

	case *ast.FuncLit:
		return pkg.oneLineNodeDepth(n.Type, depth) + " { ... }"

	case *ast.CompositeLit:
		typ := pkg.oneLineNodeDepth(n.Type, depth)
		if len(n.Elts) == 0 {
			return fmt.Sprintf("%s{}", typ)
		}
		return fmt.Sprintf("%s{ %s }", typ, dotDotDot)

	case *ast.ArrayType:
		length := pkg.oneLineNodeDepth(n.Len, depth)
		element := pkg.oneLineNodeDepth(n.Elt, depth)
		return fmt.Sprintf("[%s]%s", length, element)

	case *ast.MapType:
		key := pkg.oneLineNodeDepth(n.Key, depth)
		value := pkg.oneLineNodeDepth(n.Value, depth)
		return fmt.Sprintf("map[%s]%s", key, value)

	case *ast.CallExpr:
		fnc := pkg.oneLineNodeDepth(n.Fun, depth)
		var args []string
		for _, arg := range n.Args {
			args = append(args, pkg.oneLineNodeDepth(arg, depth))
		}
		return fmt.Sprintf("%s(%s)", fnc, joinStrings(args))

	case *ast.UnaryExpr:
		return fmt.Sprintf("%s%s", n.Op, pkg.oneLineNodeDepth(n.X, depth))

	case *ast.Ident:
		return n.Name

	default:
		// As a fallback, use default formatter for all unknown node types.
		buf := new(strings.Builder)
		format.Node(buf, pkg.fs, node)
		s := buf.String()
		if strings.Contains(s, "\n") {
			return dotDotDot
		}
		return s
	}
}

func (pkg *Package) formatTypeParams(list *ast.FieldList, depth int) string {
	if list.NumFields() == 0 {
		return ""
	}
	var tparams []string
	for _, field := range list.List {
		tparams = append(tparams, pkg.oneLineField(field, depth))
	}
	return "[" + joinStrings(tparams) + "]"
}

// oneLineField returns a one-line summary of the field.
func (pkg *Package) oneLineField(field *ast.Field, depth int) string {
	var names []string
	for _, name := range field.Names {
		names = append(names, name.Name)
	}
	if len(names) == 0 {
		return pkg.oneLineNodeDepth(field.Type, depth)
	}
	return joinStrings(names) + " " + pkg.oneLineNodeDepth(field.Type, depth)
}

// joinStrings formats the input as a comma-separated list,
// but truncates the list at some reasonable length if necessary.
func joinStrings(ss []string) string {
	var n int
	for i, s := range ss {
		n += len(s) + len(", ")
		if n > punchedCardWidth {
			ss = append(ss[:i:i], "...")
			break
		}
	}
	return strings.Join(ss, ", ")
}

// printHeader prints a header for the section named s, adding a blank line on each side.
func (pkg *Package) printHeader(s string) {
	pkg.Printf("\n%s\n\n", s)
}

// constsDoc prints all const documentation, if any, including a header.
// The one argument is the valueDoc registry.
func (pkg *Package) constsDoc(printed map[*ast.GenDecl]bool) {
	var header bool
	for _, value := range pkg.doc.Consts {
		// Constants and variables come in groups, and valueDoc prints
		// all the items in the group. We only need to find one exported symbol.
		for _, name := range value.Names {
			if isExported(name) && !pkg.typedValue[value] {
				if !header {
					pkg.printHeader("CONSTANTS")
					header = true
				}
				pkg.valueDoc(value, printed)
				break
			}
		}
	}
}

// varsDoc prints all var documentation, if any, including a header.
// Printed is the valueDoc registry.
func (pkg *Package) varsDoc(printed map[*ast.GenDecl]bool) {
	var header bool
	for _, value := range pkg.doc.Vars {
		// Constants and variables come in groups, and valueDoc prints
		// all the items in the group. We only need to find one exported symbol.
		for _, name := range value.Names {
			if isExported(name) && !pkg.typedValue[value] {
				if !header {
					pkg.printHeader("VARIABLES")
					header = true
				}
				pkg.valueDoc(value, printed)
				break
			}
		}
	}
}

// funcsDoc prints all func documentation, if any, including a header.
func (pkg *Package) funcsDoc() {
	var header bool
	for _, fun := range pkg.doc.Funcs {
		if isExported(fun.Name) && !pkg.constructor[fun] {
			if !header {
				pkg.printHeader("FUNCTIONS")
				header = true
			}
			pkg.emit(fun.Doc, fun.Decl)
		}
	}
}

// funcsDoc prints all type documentation, if any, including a header.
func (pkg *Package) typesDoc() {
	var header bool
	for _, typ := range pkg.doc.Types {
		if isExported(typ.Name) {
			if !header {
				pkg.printHeader("TYPES")
				header = true
			}
			pkg.typeDoc(typ)
		}
	}
}

// packageDoc prints the docs for the package.
func (pkg *Package) packageDoc() {
	pkg.Printf("") // Trigger the package clause; we know the package exists.
	if showAll || !short {
		pkg.ToText(&pkg.buf, pkg.doc.Doc, "", indent)
		pkg.newlines(1)
	}

	switch {
	case showAll:
		printed := make(map[*ast.GenDecl]bool) // valueDoc registry
		pkg.constsDoc(printed)
		pkg.varsDoc(printed)
		pkg.funcsDoc()
		pkg.typesDoc()

	case pkg.pkg.Name == "main" && !showCmd:
		// Show only package docs for commands.
		return

	default:
		if !short {
			pkg.newlines(2) // Guarantee blank line before the components.
		}
		pkg.valueSummary(pkg.doc.Consts, false)
		pkg.valueSummary(pkg.doc.Vars, false)
		pkg.funcSummary(pkg.doc.Funcs, false)
		pkg.typeSummary()
	}

	if !short {
		pkg.bugs()
	}
}

// packageClause prints the package clause.
func (pkg *Package) packageClause() {
	if short {
		return
	}
	importPath := pkg.build.ImportComment
	if importPath == "" {
		importPath = pkg.build.ImportPath
	}

	// If we're using modules, the import path derived from module code locations wins.
	// If we did a file system scan, we knew the import path when we found the directory.
	// But if we started with a directory name, we never knew the import path.
	// Either way, we don't know it now, and it's cheap to (re)compute it.
	if usingModules {
		for _, root := range codeRoots() {
			if pkg.build.Dir == root.dir {
				importPath = root.importPath
				break
			}
			if strings.HasPrefix(pkg.build.Dir, root.dir+string(filepath.Separator)) {
				suffix := filepath.ToSlash(pkg.build.Dir[len(root.dir)+1:])
				if root.importPath == "" {
					importPath = suffix
				} else {
					importPath = root.importPath + "/" + suffix
				}
				break
			}
		}
	}

	pkg.Printf("package %s // import %q\n\n", pkg.name, importPath)
	if !usingModules && importPath != pkg.build.ImportPath {
		pkg.Printf("WARNING: package source is installed in %q\n", pkg.build.ImportPath)
	}
}

// valueSummary prints a one-line summary for each set of values and constants.
// If all the types in a constant or variable declaration belong to the same
// type they can be printed by typeSummary, and so can be suppressed here.
func (pkg *Package) valueSummary(values []*doc.Value, showGrouped bool) {
	var isGrouped map[*doc.Value]bool
	if !showGrouped {
		isGrouped = make(map[*doc.Value]bool)
		for _, typ := range pkg.doc.Types {
			if !isExported(typ.Name) {
				continue
			}
			for _, c := range typ.Consts {
				isGrouped[c] = true
			}
			for _, v := range typ.Vars {
				isGrouped[v] = true
			}
		}
	}

	for _, value := range values {
		if !isGrouped[value] {
			if decl := pkg.oneLineNode(value.Decl); decl != "" {
				pkg.Printf("%s\n", decl)
			}
		}
	}
}

// funcSummary prints a one-line summary for each function. Constructors
// are printed by typeSummary, below, and so can be suppressed here.
func (pkg *Package) funcSummary(funcs []*doc.Func, showConstructors bool) {
	for _, fun := range funcs {
		// Exported functions only. The go/doc package does not include methods here.
		if isExported(fun.Name) {
			if showConstructors || !pkg.constructor[fun] {
				pkg.Printf("%s\n", pkg.oneLineNode(fun.Decl))
			}
		}
	}
}

// typeSummary prints a one-line summary for each type, followed by its constructors.
func (pkg *Package) typeSummary() {
	for _, typ := range pkg.doc.Types {
		for _, spec := range typ.Decl.Specs {
			typeSpec := spec.(*ast.TypeSpec) // Must succeed.
			if isExported(typeSpec.Name.Name) {
				pkg.Printf("%s\n", pkg.oneLineNode(typeSpec))
				// Now print the consts, vars, and constructors.
				for _, c := range typ.Consts {
					if decl := pkg.oneLineNode(c.Decl); decl != "" {
						pkg.Printf(indent+"%s\n", decl)
					}
				}
				for _, v := range typ.Vars {
					if decl := pkg.oneLineNode(v.Decl); decl != "" {
						pkg.Printf(indent+"%s\n", decl)
					}
				}
				for _, constructor := range typ.Funcs {
					if isExported(constructor.Name) {
						pkg.Printf(indent+"%s\n", pkg.oneLineNode(constructor.Decl))
					}
				}
			}
		}
	}
}

// bugs prints the BUGS information for the package.
// TODO: Provide access to TODOs and NOTEs as well (very noisy so off by default)?
func (pkg *Package) bugs() {
	if pkg.doc.Notes["BUG"] == nil {
		return
	}
	pkg.Printf("\n")
	for _, note := range pkg.doc.Notes["BUG"] {
		pkg.Printf("%s: %v\n", "BUG", note.Body)
	}
}

// findValues finds the doc.Values that describe the symbol.
func (pkg *Package) findValues(symbol string, docValues []*doc.Value) (values []*doc.Value) {
	for _, value := range docValues {
		for _, name := range value.Names {
			if match(symbol, name) {
				values = append(values, value)
			}
		}
	}
	return
}

// findFuncs finds the doc.Funcs that describes the symbol.
func (pkg *Package) findFuncs(symbol string) (funcs []*doc.Func) {
	for _, fun := range pkg.doc.Funcs {
		if match(symbol, fun.Name) {
			funcs = append(funcs, fun)
		}
	}
	return
}

// findTypes finds the doc.Types that describes the symbol.
// If symbol is empty, it finds all exported types.
func (pkg *Package) findTypes(symbol string) (types []*doc.Type) {
	for _, typ := range pkg.doc.Types {
		if symbol == "" && isExported(typ.Name) || match(symbol, typ.Name) {
			types = append(types, typ)
		}
	}
	return
}

// findTypeSpec returns the ast.TypeSpec within the declaration that defines the symbol.
// The name must match exactly.
func (pkg *Package) findTypeSpec(decl *ast.GenDecl, symbol string) *ast.TypeSpec {
	for _, spec := range decl.Specs {
		typeSpec := spec.(*ast.TypeSpec) // Must succeed.
		if symbol == typeSpec.Name.Name {
			return typeSpec
		}
	}
	return nil
}

// symbolDoc prints the docs for symbol. There may be multiple matches.
// If symbol matches a type, output includes its methods factories and associated constants.
// If there is no top-level symbol, symbolDoc looks for methods that match.
func (pkg *Package) symbolDoc(symbol string) bool {
	found := false
	// Functions.
	for _, fun := range pkg.findFuncs(symbol) {
		// Symbol is a function.
		decl := fun.Decl
		pkg.emit(fun.Doc, decl)
		found = true
	}
	// Constants and variables behave the same.
	values := pkg.findValues(symbol, pkg.doc.Consts)
	values = append(values, pkg.findValues(symbol, pkg.doc.Vars)...)
	printed := make(map[*ast.GenDecl]bool) // valueDoc registry
	for _, value := range values {
		pkg.valueDoc(value, printed)
		found = true
	}
	// Types.
	for _, typ := range pkg.findTypes(symbol) {
		pkg.typeDoc(typ)
		found = true
	}
	if !found {
		// See if there are methods.
		if !pkg.printMethodDoc("", symbol) {
			return false
		}
	}
	return true
}

// valueDoc prints the docs for a constant or variable. The printed map records
// which values have been printed already to avoid duplication. Otherwise, a
// declaration like:
//
//	const ( c = 1; C = 2 )
//
// … could be printed twice if the -u flag is set, as it matches twice.
func (pkg *Package) valueDoc(value *doc.Value, printed map[*ast.GenDecl]bool) {
	if printed[value.Decl] {
		return
	}
	// Print each spec only if there is at least one exported symbol in it.
	// (See issue 11008.)
	// TODO: Should we elide unexported symbols from a single spec?
	// It's an unlikely scenario, probably not worth the trouble.
	// TODO: Would be nice if go/doc did this for us.
	specs := make([]ast.Spec, 0, len(value.Decl.Specs))
	var typ ast.Expr
	for _, spec := range value.Decl.Specs {
		vspec := spec.(*ast.ValueSpec)

		// The type name may carry over from a previous specification in the
		// case of constants and iota.
		if vspec.Type != nil {
			typ = vspec.Type
		}

		for _, ident := range vspec.Names {
			if showSrc || isExported(ident.Name) {
				if vspec.Type == nil && vspec.Values == nil && typ != nil {
					// This a standalone identifier, as in the case of iota usage.
					// Thus, assume the type comes from the previous type.
					vspec.Type = &ast.Ident{
						Name:    pkg.oneLineNode(typ),
						NamePos: vspec.End() - 1,
					}
				}

				specs = append(specs, vspec)
				typ = nil // Only inject type on first exported identifier
				break
			}
		}
	}
	if len(specs) == 0 {
		return
	}
	value.Decl.Specs = specs
	pkg.emit(value.Doc, value.Decl)
	printed[value.Decl] = true
}

// typeDoc prints the docs for a type, including constructors and other items
// related to it.
func (pkg *Package) typeDoc(typ *doc.Type) {
	decl := typ.Decl
	spec := pkg.findTypeSpec(decl, typ.Name)
	trimUnexportedElems(spec)
	// If there are multiple types defined, reduce to just this one.
	if len(decl.Specs) > 1 {
		decl.Specs = []ast.Spec{spec}
	}
	pkg.emit(typ.Doc, decl)
	pkg.newlines(2)
	// Show associated methods, constants, etc.
	if showAll {
		printed := make(map[*ast.GenDecl]bool) // valueDoc registry
		// We can use append here to print consts, then vars. Ditto for funcs and methods.
		values := typ.Consts
		values = append(values, typ.Vars...)
		for _, value := range values {
			for _, name := range value.Names {
				if isExported(name) {
					pkg.valueDoc(value, printed)
					break
				}
			}
		}
		funcs := typ.Funcs
		funcs = append(funcs, typ.Methods...)
		for _, fun := range funcs {
			if isExported(fun.Name) {
				pkg.emit(fun.Doc, fun.Decl)
				if fun.Doc == "" {
					pkg.newlines(2)
				}
			}
		}
	} else {
		pkg.valueSummary(typ.Consts, true)
		pkg.valueSummary(typ.Vars, true)
		pkg.funcSummary(typ.Funcs, true)
		pkg.funcSummary(typ.Methods, true)
	}
}

// trimUnexportedElems modifies spec in place to elide unexported fields from
// structs and methods from interfaces (unless the unexported flag is set or we
// are asked to show the original source).
func trimUnexportedElems(spec *ast.TypeSpec) {
	if showSrc {
		return
	}
	switch typ := spec.Type.(type) {
	case *ast.StructType:
		typ.Fields = trimUnexportedFields(typ.Fields, false)
	case *ast.InterfaceType:
		typ.Methods = trimUnexportedFields(typ.Methods, true)
	}
}

// trimUnexportedFields returns the field list trimmed of unexported fields.
func trimUnexportedFields(fields *ast.FieldList, isInterface bool) *ast.FieldList {
	what := "methods"
	if !isInterface {
		what = "fields"
	}

	trimmed := false
	list := make([]*ast.Field, 0, len(fields.List))
	for _, field := range fields.List {
		// When printing fields we normally print field.Doc.
		// Here we are going to pass the AST to go/format,
		// which will print the comments from the AST,
		// not field.Doc which is from go/doc.
		// The two are similar but not identical;
		// for example, field.Doc does not include directives.
		// In order to consistently print field.Doc,
		// we replace the comment in the AST with field.Doc.
		// That will cause go/format to print what we want.
		// See issue #56592.
		if field.Doc != nil {
			doc := field.Doc
			text := doc.Text()

			trailingBlankLine := len(doc.List[len(doc.List)-1].Text) == 2
			if !trailingBlankLine {
				// Remove trailing newline.
				lt := len(text)
				if lt > 0 && text[lt-1] == '\n' {
					text = text[:lt-1]
				}
			}

			start := doc.List[0].Slash
			doc.List = doc.List[:0]
			for _, line := range strings.Split(text, "\n") {
				prefix := "// "
				if len(line) > 0 && line[0] == '\t' {
					prefix = "//"
				}
				doc.List = append(doc.List, &ast.Comment{
					Text: prefix + line,
				})
			}
			doc.List[0].Slash = start
		}

		names := field.Names
		if len(names) == 0 {
			// Embedded type. Use the name of the type. It must be of the form ident or
			// pkg.ident (for structs and interfaces), or *ident or *pkg.ident (structs only).
			// Or a type embedded in a constraint.
			// Nothing else is allowed.
			ty := field.Type
			if se, ok := field.Type.(*ast.StarExpr); !isInterface && ok {
				// The form *ident or *pkg.ident is only valid on
				// embedded types in structs.
				ty = se.X
			}
			constraint := false
			switch ident := ty.(type) {
			case *ast.Ident:
				if isInterface && ident.Name == "error" && ident.Obj == nil {
					// For documentation purposes, we consider the builtin error
					// type special when embedded in an interface, such that it
					// always gets shown publicly.
					list = append(list, field)
					continue
				}
				names = []*ast.Ident{ident}
			case *ast.SelectorExpr:
				// An embedded type may refer to a type in another package.
				names = []*ast.Ident{ident.Sel}
			default:
				// An approximation or union or type
				// literal in an interface.
				constraint = true
			}
			if names == nil && !constraint {
				// Can only happen if AST is incorrect. Safe to continue with a nil list.
				log.Print("invalid program: unexpected type for embedded field")
			}
		}
		// Trims if any is unexported. Good enough in practice.
		ok := true
		if !unexported {
			for _, name := range names {
				if !isExported(name.Name) {
					trimmed = true
					ok = false
					break
				}
			}
		}
		if ok {
			list = append(list, field)
		}
	}
	if !trimmed {
		return fields
	}
	unexportedField := &ast.Field{
		Type: &ast.Ident{
			// Hack: printer will treat this as a field with a named type.
			// Setting Name and NamePos to ("", fields.Closing-1) ensures that
			// when Pos and End are called on this field, they return the
			// position right before closing '}' character.
			Name:    "",
			NamePos: fields.Closing - 1,
		},
		Comment: &ast.CommentGroup{
			List: []*ast.Comment{{Text: fmt.Sprintf("// Has unexported %s.\n", what)}},
		},
	}
	return &ast.FieldList{
		Opening: fields.Opening,
		List:    append(list, unexportedField),
		Closing: fields.Closing,
	}
}

// printMethodDoc prints the docs for matches of symbol.method.
// If symbol is empty, it prints all methods for any concrete type
// that match the name. It reports whether it found any methods.
func (pkg *Package) printMethodDoc(symbol, method string) bool {
	types := pkg.findTypes(symbol)
	if types == nil {
		if symbol == "" {
			return false
		}
		pkg.Fatalf("symbol %s is not a type in package %s installed in %q", symbol, pkg.name, pkg.build.ImportPath)
	}
	found := false
	for _, typ := range types {
		if len(typ.Methods) > 0 {
			for _, meth := range typ.Methods {
				if match(method, meth.Name) {
					decl := meth.Decl
					pkg.emit(meth.Doc, decl)
					found = true
				}
			}
			continue
		}
		if symbol == "" {
			continue
		}
		// Type may be an interface. The go/doc package does not attach
		// an interface's methods to the doc.Type. We need to dig around.
		spec := pkg.findTypeSpec(typ.Decl, typ.Name)
		inter, ok := spec.Type.(*ast.InterfaceType)
		if !ok {
			// Not an interface type.
			continue
		}

		// Collect and print only the methods that match.
		var methods []*ast.Field
		for _, iMethod := range inter.Methods.List {
			// This is an interface, so there can be only one name.
			// TODO: Anonymous methods (embedding)
			if len(iMethod.Names) == 0 {
				continue
			}
			name := iMethod.Names[0].Name
			if match(method, name) {
				methods = append(methods, iMethod)
				found = true
			}
		}
		if found {
			pkg.Printf("type %s ", spec.Name)
			inter.Methods.List, methods = methods, inter.Methods.List
			err := format.Node(&pkg.buf, pkg.fs, inter)
			if err != nil {
				log.Fatal(err)
			}
			pkg.newlines(1)
			// Restore the original methods.
			inter.Methods.List = methods
		}
	}
	return found
}

// printFieldDoc prints the docs for matches of symbol.fieldName.
// It reports whether it found any field.
// Both symbol and fieldName must be non-empty or it returns false.
func (pkg *Package) printFieldDoc(symbol, fieldName string) bool {
	if symbol == "" || fieldName == "" {
		return false
	}
	types := pkg.findTypes(symbol)
	if types == nil {
		pkg.Fatalf("symbol %s is not a type in package %s installed in %q", symbol, pkg.name, pkg.build.ImportPath)
	}
	found := false
	numUnmatched := 0
	for _, typ := range types {
		// Type must be a struct.
		spec := pkg.findTypeSpec(typ.Decl, typ.Name)
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			// Not a struct type.
			continue
		}
		for _, field := range structType.Fields.List {
			// TODO: Anonymous fields.
			for _, name := range field.Names {
				if !match(fieldName, name.Name) {
					numUnmatched++
					continue
				}
				if !found {
					pkg.Printf("type %s struct {\n", typ.Name)
				}
				if field.Doc != nil {
					// To present indented blocks in comments correctly, process the comment as
					// a unit before adding the leading // to each line.
					docBuf := new(bytes.Buffer)
					pkg.ToText(docBuf, field.Doc.Text(), "", indent)
					scanner := bufio.NewScanner(docBuf)
					for scanner.Scan() {
						fmt.Fprintf(&pkg.buf, "%s// %s\n", indent, scanner.Bytes())
					}
				}
				s := pkg.oneLineNode(field.Type)
				lineComment := ""
				if field.Comment != nil {
					lineComment = fmt.Sprintf("  %s", field.Comment.List[0].Text)
				}
				pkg.Printf("%s%s %s%s\n", indent, name, s, lineComment)
				found = true
			}
		}
	}
	if found {
		if numUnmatched > 0 {
			pkg.Printf("\n    // ... other fields elided ...\n")
		}
		pkg.Printf("}\n")
	}
	return found
}

// match reports whether the user's symbol matches the program's.
// A lower-case character in the user's string matches either case in the program's.
// The program string must be exported.
func match(user, program string) bool {
	if !isExported(program) {
		return false
	}
	if matchCase {
		return user == program
	}
	for _, u := range user {
		p, w := utf8.DecodeRuneInString(program)
		program = program[w:]
		if u == p {
			continue
		}
		if unicode.IsLower(u) && simpleFold(u) == simpleFold(p) {
			continue
		}
		return false
	}
	return program == ""
}

// simpleFold returns the minimum rune equivalent to r
// under Unicode-defined simple case folding.
func simpleFold(r rune) rune {
	for {
		r1 := unicode.SimpleFold(r)
		if r1 <= r {
			return r1 // wrapped around, found min
		}
		r = r1
	}
}

"""



```