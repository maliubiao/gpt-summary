Response:
The user wants to understand the functionality of the provided Go code snippet. This code is a part of a linter for Go source code.

I need to identify the core purpose of this code and summarize its functionalities. The code defines structures like `Linter`, `Problem`, and `pkg`, and has methods like `Lint`, `LintFiles`, and `lint`. It appears to parse Go source code, analyze it for potential issues, and report these issues as `Problem` objects.

Here's a breakdown of the steps:

1. **Identify the main goal:** The package name and the `Linter` type clearly indicate this code is about linting Go code.

2. **Analyze key structures:**
   - `Linter`: The main type responsible for performing the linting.
   - `Problem`: Represents an issue found in the code. It contains information about the location, description, and potential fix.
   - `pkg`: Represents a Go package being analyzed, holding information about files, types, and reported problems.
   - `file`: Represents a single Go file being analyzed within a package.

3. **Analyze key methods:**
   - `Lint`: Lints a single source file.
   - `LintFiles`: Lints multiple files within a package.
   - `lint` (on `pkg`): Orchestrates the linting process for a package, including type checking and individual file linting.
   - `lint` (on `file`): Performs various checks on a single file, like checking package comments, imports, exported names, and other style conventions.
   - Methods starting with `lint...` within the `file` type are specific linting rules.

4. **Infer Go language features:**  The code uses `go/ast` for parsing and representing Go code, `go/token` for handling source code positions, and `go/types` for type checking.

5. **Identify potential command-line arguments (though not explicitly present in this snippet):** Based on its function, a linter would likely accept file paths or package names as input.

6. **Identify potential user errors:**  Users might incorrectly assume the linter catches all errors (it focuses on style and best practices), or they might not understand the specific rules the linter enforces.

7. **Summarize the functionalities.**
这是 `go/src/github.com/golang/lint/lint.go` 文件的第一部分，它实现了一个 Go 语言代码的静态分析工具（linter）。它的主要功能是检查 Go 源代码，并报告违反 Go 语言风格指南和常见错误实践的问题。

**功能归纳:**

1. **定义了 Linter 结构体:** `Linter` 结构体是进行代码检查的核心。虽然在这部分代码中它没有具体的字段，但它定义了 `Lint` 和 `LintFiles` 方法，表明其负责执行 lint 检查。

2. **定义了 Problem 结构体:** `Problem` 结构体用于表示在代码中发现的一个问题。它包含了问题的位置 (`Position`)、描述 (`Text`)、指向风格指南的链接 (`Link`)、置信度 (`Confidence`)、所在行文本 (`LineText`)、问题类别 (`Category`) 以及建议的修复方案 (`ReplacementLine`)。

3. **实现了按位置排序 Problem 的功能:** `byPosition` 类型实现了 `sort.Interface`，允许按照问题在源代码中的位置对 `Problem` 切片进行排序，方便用户查看和处理问题。

4. **提供了 Lint 方法:** `Lint` 方法接收文件名和源代码字节切片，并调用 `LintFiles` 方法进行单文件 lint 检查。

5. **提供了 LintFiles 方法:** `LintFiles` 方法接收一个文件名到源代码的映射，表示一个待检查的 Go 包。它负责解析这些文件，构建包的抽象语法树（AST），并调用包的 `lint` 方法执行实际的检查。

6. **实现了对生成代码的忽略:** `isGenerated` 函数判断一个文件是否是自动生成的代码，如果是，则跳过该文件的 lint 检查。这是为了避免对自动生成的代码产生不必要的警告。

7. **定义了 pkg 结构体:** `pkg` 结构体表示一个正在被 lint 的 Go 包。它包含了包的文件集合、类型信息、是否为 `main` 包等信息，并持有该包发现的所有 `Problem`。

8. **实现了包级别的 lint 检查:** `pkg` 结构体的 `lint` 方法负责对整个包进行 lint 检查。它包括类型检查 (`typeCheck`)、扫描实现了 `sort.Interface` 的类型 (`scanSortable`) 以及对每个文件进行 lint 检查。

9. **定义了 file 结构体:** `file` 结构体表示一个正在被 lint 的 Go 文件。它包含了文件的 AST、源代码、文件名以及所属的包。

10. **实现了文件级别的 lint 检查:** `file` 结构体的 `lint` 方法调用一系列以 `lint` 开头的方法，对文件的各个方面进行检查，例如包注释、导入语句、导出声明的文档、命名规范等。

11. **提供了方便生成 Problem 的方法:** `file` 结构体的 `errorf` 方法和 `pkg` 结构体的 `errorfAt` 方法用于创建并记录一个 `Problem` 实例。它们可以接收不同类型的参数，包括指向风格指南的链接和问题类别。

12. **实现了类型检查功能:** `pkg` 结构体的 `typeCheck` 方法使用 `go/types` 包进行类型检查，虽然这段代码中对类型检查错误的处理被注释掉了，但可以看出其目的是在 lint 过程中利用类型信息。

13. **提供了获取类型信息的方法:** `pkg` 结构体的 `typeOf` 方法用于获取表达式的类型信息。

14. **提供了判断是否为特定命名类型的方法:** `pkg` 结构体的 `isNamedType` 方法用于判断一个类型是否为指定的包和名称。

15. **提供了获取标识符所在作用域的方法:** `pkg` 结构体的 `scopeOf` 方法用于获取给定标识符所在的作用域。

16. **实现了扫描实现了 sort.Interface 的类型的功能:** `pkg` 结构体的 `scanSortable` 方法通过遍历包中的函数声明，查找接收者实现了 `Len`、`Less` 和 `Swap` 方法的类型，并将这些类型记录在 `sortable` 映射中。

17. **实现了判断是否为 main 包的功能:** `pkg` 和 `file` 结构体都提供了 `isMain` 方法来判断当前包或文件是否是 `main` 包。

18. **实现了对包注释的检查:** `file` 结构体的 `lintPackageComment` 方法检查包注释是否存在以及是否符合规范，例如是否以 "Package 包名 " 开头。

19. **实现了对空白导入的检查:** `file` 结构体的 `lintBlankImports` 方法检查非 `main` 包中是否存在没有注释的空白导入。

20. **实现了对导入语句的检查:** `file` 结构体的 `lintImports` 方法检查导入语句，例如禁止使用点导入。

21. **实现了对导出声明的文档注释的检查:** `file` 结构体的 `lintExported` 方法调用 `lintFuncDoc`、`lintTypeDoc` 和 `lintValueSpecDoc` 来检查导出的函数、类型、变量和常量的文档注释是否符合规范。

**Go 语言功能示例:**

这段代码大量使用了 Go 语言的标准库，特别是 `go/*` 系列的包，这些包是 Go 语言提供的用于处理 Go 源代码的工具。

* **`go/ast`:** 用于表示 Go 源代码的抽象语法树 (AST)。例如，`ast.File` 表示一个源文件，`ast.FuncDecl` 表示函数声明，`ast.Ident` 表示标识符等。
* **`go/parser`:** 用于将 Go 源代码解析成 AST。例如，`parser.ParseFile` 函数可以将一个 Go 源文件解析成 `ast.File`。
* **`go/token`:**  用于表示源代码中的词法单元和位置信息。例如，`token.FileSet` 用于管理文件集合，`token.Position` 用于表示源代码中的位置。
* **`go/types`:** 用于进行 Go 语言的类型检查和类型推断。例如，`types.Config` 用于配置类型检查器，`types.Info` 用于存储类型检查的结果。
* **`golang.org/x/tools/go/ast/astutil`:** 提供了一些操作 AST 的实用工具函数。
* **`golang.org/x/tools/go/gcexportdata`:**  用于从导出的数据中加载包的类型信息，用于支持类型检查。

**代码推理示例:**

假设我们有一个简单的 Go 文件 `example.go`:

```go
package example

// MyFunc is a function.
func MyFunc() {
	// ...
}
```

**假设输入:**

`filename`: "example.go"
`src`:  `[]byte("package example\n\n// MyFunc is a function.\nfunc MyFunc() {\n\t// ...\n}\n")`

**代码执行流程 (部分):**

1. `Linter` 的 `Lint` 方法会被调用，传入文件名和源代码。
2. `Lint` 方法调用 `LintFiles` 方法，创建一个包含该文件的 map。
3. `LintFiles` 方法创建一个 `pkg` 实例，并使用 `parser.ParseFile` 解析 `example.go` 的源代码，生成 `ast.File`。
4. `pkg` 的 `lint` 方法会被调用。
5. `pkg` 的 `lint` 方法可能会调用 `typeCheck` 进行类型检查。
6. `pkg` 的 `lint` 方法会遍历 `pkg.files` 中的每个 `file` 实例，并调用其 `lint` 方法。
7. `file` 的 `lint` 方法会调用 `lintExported` 方法来检查导出声明的文档。
8. 在 `lintExported` 中，当遍历到 `MyFunc` 的 `ast.FuncDecl` 节点时，`lintFuncDoc` 方法会被调用。
9. `lintFuncDoc` 检查 `MyFunc` 的文档注释是否存在且符合规范。由于 `MyFunc` 是导出的，且文档注释以 "MyFunc " 开头，因此不会报告错误。

**假设输出 (如果没有其他 lint 错误):**

`[]Problem(nil), nil` (表示没有发现问题)

**命令行参数:**

虽然这段代码本身没有直接处理命令行参数，但可以推断出，使用这个 linter 的命令行工具可能会接受以下参数：

* **要检查的 Go 文件或目录的路径:**  例如 `golint mypackage/myfile.go` 或 `golint mypackage`。
* **一些配置选项:**  虽然这段代码中没有体现，但实际的 linter 可能允许用户配置要检查的规则、忽略某些警告等。

**使用者易犯错的点:**

* **误解 lint 的作用:** 用户可能会认为 lint 工具可以发现所有的代码错误，包括逻辑错误。实际上，lint 主要关注代码风格和一些常见的错误模式，并不能替代单元测试或集成测试。
* **不理解 lint 规则:** 用户可能会对 lint 工具报告的某些警告感到困惑，因为他们不了解相关的 Go 语言风格指南或最佳实践。例如，对于导出的函数或类型缺少文档注释的警告，用户可能不清楚为什么需要添加文档注释。
* **忽略 lint 警告:**  用户可能会忽略 lint 工具的警告，认为这些警告不重要。然而，遵循 lint 的建议可以提高代码的可读性和可维护性，并减少潜在的错误。例如，忽略关于命名规范的警告可能会导致代码库的命名风格不一致。

总而言之，这段代码是 Go 语言静态分析工具的核心部分，它定义了 lint 检查的流程和数据结构，并实现了一些基本的检查功能。它依赖于 Go 语言提供的 AST 和类型检查等功能来实现代码的分析和问题报告。

Prompt: 
```
这是路径为go/src/github.com/golang/lint/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2013 The Go Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

// Package lint contains a linter for Go source code.
package lint // import "golang.org/x/lint"

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/gcexportdata"
)

const styleGuideBase = "https://golang.org/wiki/CodeReviewComments"

// A Linter lints Go source code.
type Linter struct {
}

// Problem represents a problem in some source code.
type Problem struct {
	Position   token.Position // position in source file
	Text       string         // the prose that describes the problem
	Link       string         // (optional) the link to the style guide for the problem
	Confidence float64        // a value in (0,1] estimating the confidence in this problem's correctness
	LineText   string         // the source line
	Category   string         // a short name for the general category of the problem

	// If the problem has a suggested fix (the minority case),
	// ReplacementLine is a full replacement for the relevant line of the source file.
	ReplacementLine string
}

func (p *Problem) String() string {
	if p.Link != "" {
		return p.Text + "\n\n" + p.Link
	}
	return p.Text
}

type byPosition []Problem

func (p byPosition) Len() int      { return len(p) }
func (p byPosition) Swap(i, j int) { p[i], p[j] = p[j], p[i] }

func (p byPosition) Less(i, j int) bool {
	pi, pj := p[i].Position, p[j].Position

	if pi.Filename != pj.Filename {
		return pi.Filename < pj.Filename
	}
	if pi.Line != pj.Line {
		return pi.Line < pj.Line
	}
	if pi.Column != pj.Column {
		return pi.Column < pj.Column
	}

	return p[i].Text < p[j].Text
}

// Lint lints src.
func (l *Linter) Lint(filename string, src []byte) ([]Problem, error) {
	return l.LintFiles(map[string][]byte{filename: src})
}

// LintFiles lints a set of files of a single package.
// The argument is a map of filename to source.
func (l *Linter) LintFiles(files map[string][]byte) ([]Problem, error) {
	pkg := &pkg{
		fset:  token.NewFileSet(),
		files: make(map[string]*file),
	}
	var pkgName string
	for filename, src := range files {
		if isGenerated(src) {
			continue // See issue #239
		}
		f, err := parser.ParseFile(pkg.fset, filename, src, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		if pkgName == "" {
			pkgName = f.Name.Name
		} else if f.Name.Name != pkgName {
			return nil, fmt.Errorf("%s is in package %s, not %s", filename, f.Name.Name, pkgName)
		}
		pkg.files[filename] = &file{
			pkg:      pkg,
			f:        f,
			fset:     pkg.fset,
			src:      src,
			filename: filename,
		}
	}
	if len(pkg.files) == 0 {
		return nil, nil
	}
	return pkg.lint(), nil
}

var (
	genHdr = []byte("// Code generated ")
	genFtr = []byte(" DO NOT EDIT.")
)

// isGenerated reports whether the source file is generated code
// according the rules from https://golang.org/s/generatedcode.
func isGenerated(src []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(src))
	for sc.Scan() {
		b := sc.Bytes()
		if bytes.HasPrefix(b, genHdr) && bytes.HasSuffix(b, genFtr) && len(b) >= len(genHdr)+len(genFtr) {
			return true
		}
	}
	return false
}

// pkg represents a package being linted.
type pkg struct {
	fset  *token.FileSet
	files map[string]*file

	typesPkg  *types.Package
	typesInfo *types.Info

	// sortable is the set of types in the package that implement sort.Interface.
	sortable map[string]bool
	// main is whether this is a "main" package.
	main bool

	problems []Problem
}

func (p *pkg) lint() []Problem {
	if err := p.typeCheck(); err != nil {
		/* TODO(dsymonds): Consider reporting these errors when golint operates on entire packages.
		if e, ok := err.(types.Error); ok {
			pos := p.fset.Position(e.Pos)
			conf := 1.0
			if strings.Contains(e.Msg, "can't find import: ") {
				// Golint is probably being run in a context that doesn't support
				// typechecking (e.g. package files aren't found), so don't warn about it.
				conf = 0
			}
			if conf > 0 {
				p.errorfAt(pos, conf, category("typechecking"), e.Msg)
			}

			// TODO(dsymonds): Abort if !e.Soft?
		}
		*/
	}

	p.scanSortable()
	p.main = p.isMain()

	for _, f := range p.files {
		f.lint()
	}

	sort.Sort(byPosition(p.problems))

	return p.problems
}

// file represents a file being linted.
type file struct {
	pkg      *pkg
	f        *ast.File
	fset     *token.FileSet
	src      []byte
	filename string
}

func (f *file) isTest() bool { return strings.HasSuffix(f.filename, "_test.go") }

func (f *file) lint() {
	f.lintPackageComment()
	f.lintImports()
	f.lintBlankImports()
	f.lintExported()
	f.lintNames()
	f.lintElses()
	f.lintRanges()
	f.lintErrorf()
	f.lintErrors()
	f.lintErrorStrings()
	f.lintReceiverNames()
	f.lintIncDec()
	f.lintErrorReturn()
	f.lintUnexportedReturn()
	f.lintTimeNames()
	f.lintContextKeyTypes()
	f.lintContextArgs()
}

type link string
type category string

// The variadic arguments may start with link and category types,
// and must end with a format string and any arguments.
// It returns the new Problem.
func (f *file) errorf(n ast.Node, confidence float64, args ...interface{}) *Problem {
	pos := f.fset.Position(n.Pos())
	if pos.Filename == "" {
		pos.Filename = f.filename
	}
	return f.pkg.errorfAt(pos, confidence, args...)
}

func (p *pkg) errorfAt(pos token.Position, confidence float64, args ...interface{}) *Problem {
	problem := Problem{
		Position:   pos,
		Confidence: confidence,
	}
	if pos.Filename != "" {
		// The file might not exist in our mapping if a //line directive was encountered.
		if f, ok := p.files[pos.Filename]; ok {
			problem.LineText = srcLine(f.src, pos)
		}
	}

argLoop:
	for len(args) > 1 { // always leave at least the format string in args
		switch v := args[0].(type) {
		case link:
			problem.Link = string(v)
		case category:
			problem.Category = string(v)
		default:
			break argLoop
		}
		args = args[1:]
	}

	problem.Text = fmt.Sprintf(args[0].(string), args[1:]...)

	p.problems = append(p.problems, problem)
	return &p.problems[len(p.problems)-1]
}

var newImporter = func(fset *token.FileSet) types.ImporterFrom {
	return gcexportdata.NewImporter(fset, make(map[string]*types.Package))
}

func (p *pkg) typeCheck() error {
	config := &types.Config{
		// By setting a no-op error reporter, the type checker does as much work as possible.
		Error:    func(error) {},
		Importer: newImporter(p.fset),
	}
	info := &types.Info{
		Types:  make(map[ast.Expr]types.TypeAndValue),
		Defs:   make(map[*ast.Ident]types.Object),
		Uses:   make(map[*ast.Ident]types.Object),
		Scopes: make(map[ast.Node]*types.Scope),
	}
	var anyFile *file
	var astFiles []*ast.File
	for _, f := range p.files {
		anyFile = f
		astFiles = append(astFiles, f.f)
	}
	pkg, err := config.Check(anyFile.f.Name.Name, p.fset, astFiles, info)
	// Remember the typechecking info, even if config.Check failed,
	// since we will get partial information.
	p.typesPkg = pkg
	p.typesInfo = info
	return err
}

func (p *pkg) typeOf(expr ast.Expr) types.Type {
	if p.typesInfo == nil {
		return nil
	}
	return p.typesInfo.TypeOf(expr)
}

func (p *pkg) isNamedType(typ types.Type, importPath, name string) bool {
	n, ok := typ.(*types.Named)
	if !ok {
		return false
	}
	tn := n.Obj()
	return tn != nil && tn.Pkg() != nil && tn.Pkg().Path() == importPath && tn.Name() == name
}

// scopeOf returns the tightest scope encompassing id.
func (p *pkg) scopeOf(id *ast.Ident) *types.Scope {
	var scope *types.Scope
	if obj := p.typesInfo.ObjectOf(id); obj != nil {
		scope = obj.Parent()
	}
	if scope == p.typesPkg.Scope() {
		// We were given a top-level identifier.
		// Use the file-level scope instead of the package-level scope.
		pos := id.Pos()
		for _, f := range p.files {
			if f.f.Pos() <= pos && pos < f.f.End() {
				scope = p.typesInfo.Scopes[f.f]
				break
			}
		}
	}
	return scope
}

func (p *pkg) scanSortable() {
	p.sortable = make(map[string]bool)

	// bitfield for which methods exist on each type.
	const (
		Len = 1 << iota
		Less
		Swap
	)
	nmap := map[string]int{"Len": Len, "Less": Less, "Swap": Swap}
	has := make(map[string]int)
	for _, f := range p.files {
		f.walk(func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				return true
			}
			// TODO(dsymonds): We could check the signature to be more precise.
			recv := receiverType(fn)
			if i, ok := nmap[fn.Name.Name]; ok {
				has[recv] |= i
			}
			return false
		})
	}
	for typ, ms := range has {
		if ms == Len|Less|Swap {
			p.sortable[typ] = true
		}
	}
}

func (p *pkg) isMain() bool {
	for _, f := range p.files {
		if f.isMain() {
			return true
		}
	}
	return false
}

func (f *file) isMain() bool {
	if f.f.Name.Name == "main" {
		return true
	}
	return false
}

// lintPackageComment checks package comments. It complains if
// there is no package comment, or if it is not of the right form.
// This has a notable false positive in that a package comment
// could rightfully appear in a different file of the same package,
// but that's not easy to fix since this linter is file-oriented.
func (f *file) lintPackageComment() {
	if f.isTest() {
		return
	}

	const ref = styleGuideBase + "#package-comments"
	prefix := "Package " + f.f.Name.Name + " "

	// Look for a detached package comment.
	// First, scan for the last comment that occurs before the "package" keyword.
	var lastCG *ast.CommentGroup
	for _, cg := range f.f.Comments {
		if cg.Pos() > f.f.Package {
			// Gone past "package" keyword.
			break
		}
		lastCG = cg
	}
	if lastCG != nil && strings.HasPrefix(lastCG.Text(), prefix) {
		endPos := f.fset.Position(lastCG.End())
		pkgPos := f.fset.Position(f.f.Package)
		if endPos.Line+1 < pkgPos.Line {
			// There isn't a great place to anchor this error;
			// the start of the blank lines between the doc and the package statement
			// is at least pointing at the location of the problem.
			pos := token.Position{
				Filename: endPos.Filename,
				// Offset not set; it is non-trivial, and doesn't appear to be needed.
				Line:   endPos.Line + 1,
				Column: 1,
			}
			f.pkg.errorfAt(pos, 0.9, link(ref), category("comments"), "package comment is detached; there should be no blank lines between it and the package statement")
			return
		}
	}

	if f.f.Doc == nil {
		f.errorf(f.f, 0.2, link(ref), category("comments"), "should have a package comment, unless it's in another file for this package")
		return
	}
	s := f.f.Doc.Text()
	if ts := strings.TrimLeft(s, " \t"); ts != s {
		f.errorf(f.f.Doc, 1, link(ref), category("comments"), "package comment should not have leading space")
		s = ts
	}
	// Only non-main packages need to keep to this form.
	if !f.pkg.main && !strings.HasPrefix(s, prefix) {
		f.errorf(f.f.Doc, 1, link(ref), category("comments"), `package comment should be of the form "%s..."`, prefix)
	}
}

// lintBlankImports complains if a non-main package has blank imports that are
// not documented.
func (f *file) lintBlankImports() {
	// In package main and in tests, we don't complain about blank imports.
	if f.pkg.main || f.isTest() {
		return
	}

	// The first element of each contiguous group of blank imports should have
	// an explanatory comment of some kind.
	for i, imp := range f.f.Imports {
		pos := f.fset.Position(imp.Pos())

		if !isBlank(imp.Name) {
			continue // Ignore non-blank imports.
		}
		if i > 0 {
			prev := f.f.Imports[i-1]
			prevPos := f.fset.Position(prev.Pos())
			if isBlank(prev.Name) && prevPos.Line+1 == pos.Line {
				continue // A subsequent blank in a group.
			}
		}

		// This is the first blank import of a group.
		if imp.Doc == nil && imp.Comment == nil {
			ref := ""
			f.errorf(imp, 1, link(ref), category("imports"), "a blank import should be only in a main or test package, or have a comment justifying it")
		}
	}
}

// lintImports examines import blocks.
func (f *file) lintImports() {
	for i, is := range f.f.Imports {
		_ = i
		if is.Name != nil && is.Name.Name == "." && !f.isTest() {
			f.errorf(is, 1, link(styleGuideBase+"#import-dot"), category("imports"), "should not use dot imports")
		}

	}
}

const docCommentsLink = styleGuideBase + "#doc-comments"

// lintExported examines the exported names.
// It complains if any required doc comments are missing,
// or if they are not of the right form. The exact rules are in
// lintFuncDoc, lintTypeDoc and lintValueSpecDoc; this function
// also tracks the GenDecl structure being traversed to permit
// doc comments for constants to be on top of the const block.
// It also complains if the names stutter when combined with
// the package name.
func (f *file) lintExported() {
	if f.isTest() {
		return
	}

	var lastGen *ast.GenDecl // last GenDecl entered.

	// Set of GenDecls that have already had missing comments flagged.
	genDeclMissingComments := make(map[*ast.GenDecl]bool)

	f.walk(func(node ast.Node) bool {
		switch v := node.(type) {
		case *ast.GenDecl:
			if v.Tok == token.IMPORT {
				return false
			}
			// token.CONST, token.TYPE or token.VAR
			lastGen = v
			return true
		case *ast.FuncDecl:
			f.lintFuncDoc(v)
			if v.Recv == nil {
				// Only check for stutter on functions, not methods.
				// Method names are not used package-qualified.
				f.checkStutter(v.Name, "func")
			}
			// Don't proceed inside funcs.
			return false
		case *ast.TypeSpec:
			// inside a GenDecl, which usually has the doc
			doc := v.Doc
			if doc == nil {
				doc = lastGen.Doc
			}
			f.lintTypeDoc(v, doc)
			f.checkStutter(v.Name, "type")
			// Don't proceed inside types.
			return false
		case *ast.ValueSpec:
			f.lintValueSpecDoc(v, lastGen, genDeclMissingComments)
			return false
		}
		return true
	})
}

var (
	allCapsRE = regexp.MustCompile(`^[A-Z0-9_]+$`)
	anyCapsRE = regexp.MustCompile(`[A-Z]`)
)

// knownNameExceptions is a set of names that are known to be exempt from naming checks.
// This is usually because they are constrained by having to match names in the
// standard library.
var knownNameExceptions = map[string]bool{
	"LastInsertId": true, // must match database/sql
	"kWh":          true,
}

func isInTopLevel(f *ast.File, ident *ast.Ident) bool {
	path, _ := astutil.PathEnclosingInterval(f, ident.Pos(), ident.End())
	for _, f := range path {
		switch f.(type) {
		case *ast.File, *ast.GenDecl, *ast.ValueSpec, *ast.Ident:
			continue
		}
		return false
	}
	return true
}

// lintNames examines all names in the file.
// It complains if any use underscores or incorrect known initialisms.
func (f *file) lintNames() {
	// Package names need slightly different handling than other names.
	if strings.Contains(f.f.Name.Name, "_") && !strings.HasSuffix(f.f.Name.Name, "_test") {
		f.errorf(f.f, 1, link("http://golang.org/doc/effective_go.html#package-names"), category("naming"), "don't use an underscore in package name")
	}
	if anyCapsRE.MatchString(f.f.Name.Name) {
		f.errorf(f.f, 1, link("http://golang.org/doc/effective_go.html#package-names"), category("mixed-caps"), "don't use MixedCaps in package name; %s should be %s", f.f.Name.Name, strings.ToLower(f.f.Name.Name))
	}

	check := func(id *ast.Ident, thing string) {
		if id.Name == "_" {
			return
		}
		if knownNameExceptions[id.Name] {
			return
		}

		// Handle two common styles from other languages that don't belong in Go.
		if len(id.Name) >= 5 && allCapsRE.MatchString(id.Name) && strings.Contains(id.Name, "_") {
			capCount := 0
			for _, c := range id.Name {
				if 'A' <= c && c <= 'Z' {
					capCount++
				}
			}
			if capCount >= 2 {
				f.errorf(id, 0.8, link(styleGuideBase+"#mixed-caps"), category("naming"), "don't use ALL_CAPS in Go names; use CamelCase")
				return
			}
		}
		if thing == "const" || (thing == "var" && isInTopLevel(f.f, id)) {
			if len(id.Name) > 2 && id.Name[0] == 'k' && id.Name[1] >= 'A' && id.Name[1] <= 'Z' {
				should := string(id.Name[1]+'a'-'A') + id.Name[2:]
				f.errorf(id, 0.8, link(styleGuideBase+"#mixed-caps"), category("naming"), "don't use leading k in Go names; %s %s should be %s", thing, id.Name, should)
			}
		}

		should := lintName(id.Name)
		if id.Name == should {
			return
		}

		if len(id.Name) > 2 && strings.Contains(id.Name[1:], "_") {
			f.errorf(id, 0.9, link("http://golang.org/doc/effective_go.html#mixed-caps"), category("naming"), "don't use underscores in Go names; %s %s should be %s", thing, id.Name, should)
			return
		}
		f.errorf(id, 0.8, link(styleGuideBase+"#initialisms"), category("naming"), "%s %s should be %s", thing, id.Name, should)
	}
	checkList := func(fl *ast.FieldList, thing string) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, id := range f.Names {
				check(id, thing)
			}
		}
	}
	f.walk(func(node ast.Node) bool {
		switch v := node.(type) {
		case *ast.AssignStmt:
			if v.Tok == token.ASSIGN {
				return true
			}
			for _, exp := range v.Lhs {
				if id, ok := exp.(*ast.Ident); ok {
					check(id, "var")
				}
			}
		case *ast.FuncDecl:
			if f.isTest() && (strings.HasPrefix(v.Name.Name, "Example") || strings.HasPrefix(v.Name.Name, "Test") || strings.HasPrefix(v.Name.Name, "Benchmark")) {
				return true
			}

			thing := "func"
			if v.Recv != nil {
				thing = "method"
			}

			// Exclude naming warnings for functions that are exported to C but
			// not exported in the Go API.
			// See https://github.com/golang/lint/issues/144.
			if ast.IsExported(v.Name.Name) || !isCgoExported(v) {
				check(v.Name, thing)
			}

			checkList(v.Type.Params, thing+" parameter")
			checkList(v.Type.Results, thing+" result")
		case *ast.GenDecl:
			if v.Tok == token.IMPORT {
				return true
			}
			var thing string
			switch v.Tok {
			case token.CONST:
				thing = "const"
			case token.TYPE:
				thing = "type"
			case token.VAR:
				thing = "var"
			}
			for _, spec := range v.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					check(s.Name, thing)
				case *ast.ValueSpec:
					for _, id := range s.Names {
						check(id, thing)
					}
				}
			}
		case *ast.InterfaceType:
			// Do not check interface method names.
			// They are often constrainted by the method names of concrete types.
			for _, x := range v.Methods.List {
				ft, ok := x.Type.(*ast.FuncType)
				if !ok { // might be an embedded interface name
					continue
				}
				checkList(ft.Params, "interface method parameter")
				checkList(ft.Results, "interface method result")
			}
		case *ast.RangeStmt:
			if v.Tok == token.ASSIGN {
				return true
			}
			if id, ok := v.Key.(*ast.Ident); ok {
				check(id, "range var")
			}
			if id, ok := v.Value.(*ast.Ident); ok {
				check(id, "range var")
			}
		case *ast.StructType:
			for _, f := range v.Fields.List {
				for _, id := range f.Names {
					check(id, "struct field")
				}
			}
		}
		return true
	})
}

// lintName returns a different name if it should be different.
func lintName(name string) (should string) {
	// Fast path for simple cases: "_" and all lowercase.
	if name == "_" {
		return name
	}
	allLower := true
	for _, r := range name {
		if !unicode.IsLower(r) {
			allLower = false
			break
		}
	}
	if allLower {
		return name
	}

	// Split camelCase at any lower->upper transition, and split on underscores.
	// Check each word for common initialisms.
	runes := []rune(name)
	w, i := 0, 0 // index of start of word, scan
	for i+1 <= len(runes) {
		eow := false // whether we hit the end of a word
		if i+1 == len(runes) {
			eow = true
		} else if runes[i+1] == '_' {
			// underscore; shift the remainder forward over any run of underscores
			eow = true
			n := 1
			for i+n+1 < len(runes) && runes[i+n+1] == '_' {
				n++
			}

			// Leave at most one underscore if the underscore is between two digits
			if i+n+1 < len(runes) && unicode.IsDigit(runes[i]) && unicode.IsDigit(runes[i+n+1]) {
				n--
			}

			copy(runes[i+1:], runes[i+n+1:])
			runes = runes[:len(runes)-n]
		} else if unicode.IsLower(runes[i]) && !unicode.IsLower(runes[i+1]) {
			// lower->non-lower
			eow = true
		}
		i++
		if !eow {
			continue
		}

		// [w,i) is a word.
		word := string(runes[w:i])
		if u := strings.ToUpper(word); commonInitialisms[u] {
			// Keep consistent case, which is lowercase only at the start.
			if w == 0 && unicode.IsLower(runes[w]) {
				u = strings.ToLower(u)
			}
			// All the common initialisms are ASCII,
			// so we can replace the bytes exactly.
			copy(runes[w:], []rune(u))
		} else if w > 0 && strings.ToLower(word) == word {
			// already all lowercase, and not the first word, so uppercase the first character.
			runes[w] = unicode.ToUpper(runes[w])
		}
		w = i
	}
	return string(runes)
}

// commonInitialisms is a set of common initialisms.
// Only add entries that are highly unlikely to be non-initialisms.
// For instance, "ID" is fine (Freudian code is rare), but "AND" is not.
var commonInitialisms = map[string]bool{
	"ACL":   true,
	"API":   true,
	"ASCII": true,
	"CPU":   true,
	"CSS":   true,
	"DNS":   true,
	"EOF":   true,
	"GUID":  true,
	"HTML":  true,
	"HTTP":  true,
	"HTTPS": true,
	"ID":    true,
	"IP":    true,
	"JSON":  true,
	"LHS":   true,
	"QPS":   true,
	"RAM":   true,
	"RHS":   true,
	"RPC":   true,
	"SLA":   true,
	"SMTP":  true,
	"SQL":   true,
	"SSH":   true,
	"TCP":   true,
	"TLS":   true,
	"TTL":   true,
	"UDP":   true,
	"UI":    true,
	"UID":   true,
	"UUID":  true,
	"URI":   true,
	"URL":   true,
	"UTF8":  true,
	"VM":    true,
	"XML":   true,
	"XMPP":  true,
	"XSRF":  true,
	"XSS":   true,
}

// lintTypeDoc examines the doc comment on a type.
// It complains if they are missing from an exported type,
// or if they are not of the standard form.
func (f *file) lintTypeDoc(t *ast.TypeSpec, doc *ast.CommentGroup) {
	if !ast.IsExported(t.Name.Name) {
		return
	}
	if doc == nil {
		f.errorf(t, 1, link(docCommentsLink), category("comments"), "exported type %v should have comment or be unexported", t.Name)
		return
	}

	s := doc.Text()
	articles := [...]string{"A", "An", "The"}
	for _, a := range articles {
		if strings.HasPrefix(s, a+" ") {
			s = s[len(a)+1:]
			break
		}
	}
	if !strings.HasPrefix(s, t.Name.Name+" ") {
		f.errorf(doc, 1, link(docCommentsLink), category("comments"), `comment on exported type %v should be of the form "%v ..." (with optional leading article)`, t.Name, t.Name)
	}
}

var commonMethods = map[string]bool{
	"Error":     true,
	"Read":      true,
	"ServeHTTP": true,
	"String":    true,
	"Write":     true,
	"Unwrap":    true,
}

// lintFuncDoc examines doc comments on functions and methods.
// It complains if they are missing, or not of the right form.
// It has specific exclusions for well-known methods (see commonMethods above).
func (f *file) lintFuncDoc(fn *ast.FuncDecl) {
	if !ast.IsExported(fn.Name.Name) {
		// func is unexported
		return
	}
	kind := "function"
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		// method
		kind = "method"
		recv := receiverType(fn)
		if !ast.IsExported(recv) {
			// receiver is unexported
			return
		}
		if commonMethods[name] {
			return
		}
		switch name {
		case "Len", "Less", "Swap":
			if f.pkg.sortable[recv] {
				return
			}
		}
		name = recv + "." + name
	}
	if fn.Doc == nil {
		f.errorf(fn, 1, link(docCommentsLink), category("comments"), "exported %s %s should have comment or be unexported", kind, name)
		return
	}
	s := fn.Doc.Text()
	prefix := fn.Name.Name + " "
	if !strings.HasPrefix(s, prefix) {
		f.errorf(fn.Doc, 1, link(docCommentsLink), category("comments"), `comment on exported %s %s should be of the form "%s..."`, kind, name, prefix)
	}
}

// lintValueSpecDoc examines package-global variables and constants.
// It complains if they are not individually declared,
// or if they are not suitably documented in the right form (unless they are in a block that is commented).
func (f *file) lintValueSpecDoc(vs *ast.ValueSpec, gd *ast.GenDecl, genDeclMissingComments map[*ast.GenDecl]bool) {
	kind := "var"
	if gd.Tok == token.CONST {
		kind = "const"
	}

	if len(vs.Names) > 1 {
		// Check that none are exported except for the first.
		for _, n := range vs.Names[1:] {
			if ast.IsExported(n.Name) {
				f.errorf(vs, 1, category("comments"), "exported %s %s should have its own declaration", kind, n.Name)
				return
			}
		}
	}

	// Only one name.
	name := vs.Names[0].Name
	if !ast.IsExported(name) {
		return
	}

	if vs.Doc == nil && gd.Doc == nil {
		if genDeclMissingComments[gd] {
			return
		}
		block := ""
		if kind == "const" && gd.Lparen.IsValid() {
			block = " (or a comment on this block)"
		}
		f.errorf(vs, 1, link(docCommentsLink), category("comments"), "exported %s %s should have comment%s or be unexported", kind, name, block)
		genDeclMissingComments[gd] = true
		return
	}
	// If this GenDecl has parens and a comment, we don't check its comment form.
	if gd.Lparen.IsValid() && gd.Doc != nil {
		return
	}
	// The relevant text to check will be on either vs.Doc or gd.Doc.
	// Use vs.Doc preferentially.
	doc := vs.Doc
	if doc == nil {
		doc = gd.Doc
	}
	prefix := name + " "
	if !strings.HasPrefix(doc.Text(), prefix) {
		f.errorf(doc, 1, link(docCommentsLink), category("comments"), `comment on exported %s %s should be of the form "%s..."`, kind, name, prefix)
	}
}

func (f *file) checkStutter(id *ast.Ident, thing string) {
	pkg, name := f.f.Name.Name, id.Name
	if !ast.IsExported(name) {
		// unexported name
		return
	}
	// A name stutters if the package name is a strict prefix
	// and the next character of the name starts a new word.
	if len(name) <= len(pkg) {
		// name is too short to stutter.
		// This permits the name to be the same as the package name.
		return
	}
	if !strings.EqualFold(pkg, name[:len(pkg)]) {
		return
	}
	// We can assume the name is well-formed UTF-8.
	// If the next rune after the package name is uppercase or an underscore
	// the it's starting a new word and thus this name stutters.
	rem := name[len(pkg):]
	if next, _ := utf8.DecodeRuneInString(rem); next == '_' || unicode.IsUpper(next) {
		f.errorf(id, 0.8, link(styleGuideBase+"#package-names"), category("naming"), "%s name will be used as %s.%s by other packages, and that stutters; consider calling this %s", thing, pkg, name, rem)
	}
}

// zeroLiteral is a set of ast.BasicLit values that are zero values.
// It is not exhaustive.
var zeroLiteral = map[string]bool{
	"false": true, // bool
	// runes
	`'\x00'`: true,
	`'\000'`: true,
	// strings
	`""`: true,
	"``": true,
	// numerics
	"0":   true,
	"0.":  true,
	"0.0": true,
	"0i":  true,
}

// lintElses examines else blocks. It complains about any else block whose if block ends in a return.
func (f *file) lintElses() {
	// We don't want to flag if { } else if { } else { } constructions.
	// They will appear as an IfStmt whose Else field is also an IfStmt.
	// Record such a node so we ignore it when we visit it.
	ignore := make(map[*ast.IfStmt]bool)

	f.walk(func(node ast.Node) bool {
		ifStmt, ok := node.(*ast.IfStmt)
		if !ok || ifStmt.Else == nil {
			return true
		}
		if elseif, ok := ifStmt.Else.(*ast.IfStmt); ok {
			ignore[elseif] = true
			return true
		}
		if ignore[ifStmt] {
			return true
		}
		if _, ok := ifStmt.Else.(*ast.BlockStmt); !ok {
			// only care about elses without conditions
			return true
		}
		if len(ifStmt.Body.List) == 0 {
			return true
		}
		shortDecl := false // does the if statement have a ":=" initialization statement?
		if ifStmt.Init != nil {
			if as, ok := ifStmt.Init.(*ast.AssignStmt); ok && as.Tok == token.DEFINE {
				shortDecl = true
			}
		}
		lastStmt := ifStmt.Body.List[len(ifStmt.Body.List)-1]
		if _, ok := lastStmt.(*ast.ReturnStmt); ok {
			extra := ""
			if shortDecl {
				extra = " (move short variable declaration to its own line if necessary)"
			}
			f.errorf(ifStmt.Else, 1, link(styleGuideBase+"#indent-error-flow"), category("indent"), "if block ends with a return statement, so drop this else and outdent its block"+extra)
		}
		return true
	})
}

// lintRanges examines range clauses. It complains about redundant constructions.
func (f *file) lintRanges() {
	f.walk(func(node ast.Node) bool {
		rs, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}

		if isIdent(rs.Key, "_") && (rs.Value == nil || isIdent(rs.Value, "_")) {
			p := f.errorf(rs.Key, 1, category("range-loop"), "should omit values from range; this loop is equivalent to `for range ...`")

			newRS := *rs // shallow copy
			newRS.Value = nil
			newRS.Key = nil
			p.ReplacementLine = f.firstLineOf(&newRS, rs)

			return true
		}

		if isIdent(rs.Value, "_") {
			p := f.errorf(rs.Value, 1, category("range-loop"), "should omit 2nd value from range; this loop is equivalent to `for %s %s range ...`", f.render(rs.Key), rs.Tok)

			newRS := *rs // shallow copy
			newRS.Value = nil
			p.ReplacementLine = f.firstLineOf(&newRS, rs)
		}

		return true
	})
}

// lintErrorf examines errors.New and testing.Error calls. It complains if its only argument is an fmt.Sprintf invocation.
func (f *file) lintErrorf() {
	f.walk(func(node ast.Node) bool {
		ce, ok := node.(*ast.CallExpr)
		if !ok || len(ce.Args) != 1 {
			return true
		}
		isErrorsNew := isPkgDot(ce.Fun, "errors", "New")
		var isTestingError bool
		se, ok := ce.Fun.(*ast.SelectorExpr)
		if ok && se.Sel.Name == "Error" {
			if typ := f.pkg.typeOf(se.X); typ != nil {
				isTestingError = typ.String() == "*testing.T"
			}
		}
		if !isErrorsNew && !isTestingError {
			return true
		}
		if !f.imports("errors") {
			return true
		}
		arg := ce.Args[0]
		ce, ok = arg.(*ast.CallExpr)
		if !ok || !isPkgDot(ce.Fun, "fmt", "Sprintf") {
			return true
		}
		errorfPrefix := "fmt"
		if isTestingError {
			errorfPrefix = f.render(se.X)
		}
		p := f.errorf(node, 1, category("errors"), "should replace %s(fmt.Sprintf(...)) with %s.Errorf(...)", f.render(se), errorfPrefix)

		m := f.srcLineWithMatch(ce, `^(.*)`+f.render(se)+`\(fmt\.Sprintf\((.*)\)\)(.*)$`)
		if m != nil {
			p.ReplacementLine = m[1] + errorfPrefix + ".Errorf(" + m[2] + ")" + m[3]
		}

		return true
	})
}

// lintErrors examines global error vars. It complains if they aren't named in the standard way.
func (f *file) lintErrors() {
	for _, decl := range f.f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			spec := spec.(*ast.ValueSpec)
			if len(spec.Names) != 1 || len(spec.Values) != 1 {
				continue
			}
			ce, ok := spec.Values[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			if !isPkgDot(ce.Fun, "errors", "New") && !isPkgDot(ce.Fun, "fmt", "Errorf") {
				continue
			}

			id := spec.Names[0]
			prefix := "err"
			if id.IsExported() {
				prefix = "Err"
			}
			if !strings.HasPrefix(id.Name, prefix) {
				f.errorf(id, 0.9, category("naming"), "error var %s should have name of the form %sFoo", id.Name, prefix)
			}
		}
	}
}

func lintErrorString(s string) (isClean bool, conf float64) {
	const basicConfidence = 0.8
	const capConfidence = basicConfidence - 0.2
	first, firstN := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if last == '.' || last == ':' || last == '!' || last == '\n' {
		return false, basicConfidence
	}
	if unicode.IsUpper(first) {
		// People use proper nouns and exported Go identifiers in error strings,
		// so decrease the confidence of warnings for capitalization.
		if len(s) <= firstN {
			return false, capConfidence
		}
		// Flag strings starting with something that doesn't look like an initialism.
		if second, _ := utf8.DecodeRuneInString(s[firstN:]); !unicode.IsUpper(second) {
			return false, capConfidence
		}
	}
	return true, 0
}

// lintErrorStrings examines error strings.
// It complains if they are capitalized or end in punctuation or a newline.
func (f *file) lintErrorStrings() {
	f.walk(func(node ast.Node) bool {
		ce, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !isPkgDot(ce.Fun, "errors", "New") && !isPkgDot(ce.Fun, "fmt", "Errorf") {
			return true
		}
		if len(ce.Args) < 1 {
			return true
		}
		str, ok := ce.Args[0].(*ast.BasicLit)
		if !ok || str.Kind != token.STRING {
			return true
		}
		s, _ := strconv.Unquote(str.Value) // can assume well-formed Go
		if s == "" {
			return true
		}
		clean, conf := lintErrorString(s)
		if clean {
			return true
		}

		f.errorf(str, conf, link(styleGuideBase+"#error-strings"), category("errors"),
			"error strings should not be capitalized or end with punctuation or a newline")
		return true
	})
}

// lintReceiverNames examines receiver names. It complains about inconsistent
// names used for the same type and names such as "this".
func (f *file) lintReceiverNames() {
	typeR
"""




```