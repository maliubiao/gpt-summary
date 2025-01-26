Response:
The user wants a summary of the functionality of the provided Go code. The code is a part of a linter, specifically focusing on static analysis to identify potential issues and style violations in Go code.

Here's a breakdown of the functionalities I can identify from the code:

1. **Core Linting Logic:** The `Linter` struct and its methods `Lint` and `LintFiles` are responsible for orchestrating the linting process. They parse Go source code, perform various checks, and return a list of `Problem` instances.
2. **Problem Representation:** The `Problem` struct defines how linting issues are represented, including their position, description, and potential fixes.
3. **File and Package Abstraction:** The `file` and `pkg` structs encapsulate the information needed to lint individual files and entire packages, respectively.
4. **Ignoring Generated Code:** The `isGenerated` function detects and skips linting of auto-generated code.
5. **Type Checking:** The code utilizes the `go/types` package to perform type checking and gather type information.
6. **Various Linter Checks:** The `file.lint()` method calls a series of specific linting checks, such as:
    - `lintPackageComment`: Checks for correct package comments.
    - `lintImports`: Checks for disallowed import styles (like dot imports).
    - `lintBlankImports`: Checks for the necessity and documentation of blank imports.
    - `lintExported`: Checks for missing or incorrectly formatted doc comments on exported identifiers.
    - `lintNames`: Checks for naming conventions (e.g., no underscores, correct initialisms).
    - `lintVarDecls`: Checks for redundant type declarations in variable declarations.
    - `lintElses`: Checks for unnecessary `else` blocks after `if` blocks ending with a `return`.
    - `lintRanges`: Checks for redundant second values in `range` loops.
    - `lintErrorf`: Suggests using `Errorf` instead of `Error(Sprintf(...))`.
    - `lintErrors`: Checks for standard naming conventions for error variables.
    - Other checks related to receiver names, increment/decrement operators, error returns, etc.
7. **Name Correction:** The `lintName` function attempts to automatically correct names to follow Go naming conventions.
8. **Helper Functions:** Several helper functions like `isPkgDot`, `receiverType`, `srcLine`, and `isIdent` assist in the linting process.

Based on this analysis, I can now formulate a summary of the code's functionality in Chinese.
这段Go语言代码是 `golint` 工具的核心组成部分，负责对Go源代码进行静态分析，以发现潜在的代码风格问题和错误。它主要的功能可以归纳为以下几点：

1. **定义了代码问题的表示形式:**  `Problem` 结构体用于表示在代码中发现的问题，包含了问题所在的文件位置 (`Position`)、描述 (`Text`)、相关的风格指南链接 (`Link`)、置信度 (`Confidence`)、问题所在行的文本 (`LineText`)、问题类别 (`Category`) 以及可能的修复建议 (`ReplacementLine`)。

2. **提供了代码扫描和问题收集的框架:**  `Linter` 结构体是代码检查器的核心，`Lint` 和 `LintFiles` 方法接收文件名和源代码，然后组织并执行一系列的检查，最终返回发现的 `Problem` 列表。

3. **实现了对生成代码的忽略:** `isGenerated` 函数用于判断源代码是否是自动生成的，如果是，则会跳过对其的检查。这避免了对工具生成的代码进行不必要的 linting。

4. **构建了代码的抽象表示:**  `pkg` 和 `file` 结构体分别代表待检查的包和文件，它们包含了 `go/ast` 包解析出的抽象语法树 (`ast.File`)、`go/token` 包的文件集 (`token.FileSet`) 和源代码等信息，方便后续的分析。

5. **集成了 Go 语言的类型检查:**  代码利用 `go/types` 包进行类型检查 (`typeCheck` 方法)，以便进行更深入的静态分析。虽然代码中包含了处理类型检查错误的注释部分，但实际的错误报告逻辑被注释掉了。

6. **实现了多种代码风格和潜在问题的检查规则:**  `file.lint()` 方法内部调用了一系列以 `lint` 开头的方法，这些方法各自负责检查不同的代码规范，例如：
    - `lintPackageComment`: 检查包注释是否符合规范。
    - `lintImports`: 检查 import 语句的使用，例如禁止使用点导入。
    - `lintBlankImports`: 检查空白导入是否必要且有注释说明。
    - `lintExported`: 检查导出标识符的文档注释是否缺失或格式错误。
    - `lintNames`: 检查标识符的命名是否符合 Go 语言的规范，例如不应包含下划线，以及对常见缩略词的处理。
    - `lintVarDecls`: 检查变量声明是否存在可以从右侧推断出来的冗余类型。
    - `lintElses`: 检查 `if` 语句块以 `return` 结尾时，是否可以移除 `else` 块。
    - `lintRanges`: 检查 `range` 循环中是否可以省略第二个返回值。
    - `lintErrorf`: 建议使用 `Errorf` 代替 `Error(Sprintf(...))`。
    - `lintErrors`: 检查全局错误变量的命名是否符合规范。
    - 以及其他关于接收者命名、自增自减操作、错误返回等方面的检查。

7. **提供了对标识符名称进行规范化建议的功能:** `lintName` 函数能够根据 Go 语言的命名约定，对给定的标识符名称提出修改建议。

总而言之，这段代码是 `golint` 工具中负责解析Go源代码并执行一系列静态分析检查的核心部分，旨在帮助开发者编写符合 Go 语言风格规范且潜在问题较少的代码。

**它可以被认为是 Go 语言代码风格检查器的一个基础框架和核心规则的实现。**

由于你要求用 Go 代码举例说明，并且涉及到代码推理，我们选择一个相对简单的功能进行演示：**检查 `if` 语句块以 `return` 结尾时的 `else` 块冗余性**。

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

func main() {
	src := `
package example

func foo(x int) int {
	if x > 0 {
		return x
	} else {
		return -x
	}
}

func bar(x int) int {
	if x > 0 {
		fmt.Println("positive")
	} else if x < 0 {
		return -x
	} else {
		return 0
	}
}
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "example.go", src, parser.ParseComments)
	if err != nil {
		fmt.Println("Error parsing code:", err)
		return
	}

	ast.Inspect(file, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Else == nil {
			return true
		}

		// 假设输入: 当前遍历到的 ifStmt 节点
		// 推理过程: 检查 else 是否是简单的 block 且 if block 以 return 结尾
		ifBlockEndsWithReturn := false
		if blockStmt, ok := ifStmt.Body.(*ast.BlockStmt); ok && len(blockStmt.List) > 0 {
			_, ifBlockEndsWithReturn = blockStmt.List[len(blockStmt.List)-1].(*ast.ReturnStmt)
		}

		_, elseIsBlock := ifStmt.Else.(*ast.BlockStmt)

		if ifBlockEndsWithReturn && elseIsBlock {
			start := fset.Position(ifStmt.Else.Pos())
			end := fset.Position(ifStmt.Else.End())
			fmt.Printf("发现冗余 else 块，位置: %s - %s\n", start, end)
			// 假设输出: 打印发现的冗余 else 块的位置
		}
		return true
	})
}
```

**假设输入:**  上述 `src` 变量中的 Go 代码。

**推理过程:** `ast.Inspect` 函数遍历抽象语法树。当遇到 `IfStmt` 节点时，代码会检查其 `Else` 分支是否是一个简单的代码块 (`*ast.BlockStmt`)，并且 `If` 分支的最后一个语句是否是 `return` 语句。

**假设输出:**  对于 `foo` 函数中的 `if-else` 结构，将会打印：

```
发现冗余 else 块，位置: example.go:6:5 - example.go:8:2
```

对于 `bar` 函数中的 `if-else if-else` 结构，由于 `else if` 的存在，不会被标记为冗余。

这段代码并没有涉及命令行参数的处理。但如果需要处理命令行参数，通常会使用 `flag` 包。例如，`golint` 工具可能有类似以下的参数来控制行为：

```go
package main

import (
	"flag"
	"fmt"
)

func main() {
	// 定义一个布尔类型的命令行参数，用于控制是否启用某个检查
	disableNamingCheck := flag.Bool("disable_naming", false, "禁用命名检查")

	// 解析命令行参数
	flag.Parse()

	fmt.Println("禁用命名检查:", *disableNamingCheck)

	// 在实际的 linting 过程中，会根据 disableNamingCheck 的值来决定是否执行命名检查
	if *disableNamingCheck {
		fmt.Println("命名检查已禁用")
	} else {
		fmt.Println("执行命名检查")
		// ... 执行命名检查的逻辑 ...
	}
}
```

在这个例子中，`-disable_naming` 就是一个命令行参数，用户可以通过 `go run main.go -disable_naming` 来运行程序并禁用命名检查。

**使用者易犯错的点（针对这段代码的功能）：**

一个常见的错误是 **对自动生成的代码进行不必要的 linting 或配置了错误的忽略规则**。例如，如果用户没有正确配置 `golint` 来忽略由 `stringer` 或 `mockgen` 等工具生成的代码，可能会收到大量的、不相关的 linting 警告。

**示例：** 假设有以下自动生成的代码：

```go
// Code generated by stringer -type=Status; DO NOT EDIT.

package example

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StatusOpen-0]
	_ = x[StatusClosed-1]
}

const _Status_name = "OpenClosed"

var _Status_index = [...]uint8{0, 4, 10}

func (i Status) String() string {
	if i < 0 || i >= Status(len(_Status_index)-1) {
		return "Status(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Status_name[_Status_index[i]:_Status_index[i+1]]
}
```

如果 `golint` 没有被配置为忽略包含 `"// Code generated "` 行的文件，那么它可能会报告一些在这个自动生成的文件中的“问题”，例如可能不符合命名规范的 `_Status_name` 和 `_Status_index` 变量。这并不是用户的代码错误，而是对生成代码的不必要检查。

总的来说，这段代码的核心功能是为 `golint` 工具提供了一个用于静态分析 Go 源代码的基础框架和一系列代码风格及潜在问题检查的规则。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/golang/lint/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
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
package lint

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
	f.lintVarDecls()
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

var allCapsRE = regexp.MustCompile(`^[A-Z0-9_]+$`)

// knownNameExceptions is a set of names that are known to be exempt from naming checks.
// This is usually because they are constrained by having to match names in the
// standard library.
var knownNameExceptions = map[string]bool{
	"LastInsertId": true, // must match database/sql
	"kWh":          true,
}

// lintNames examines all names in the file.
// It complains if any use underscores or incorrect known initialisms.
func (f *file) lintNames() {
	// Package names need slightly different handling than other names.
	if strings.Contains(f.f.Name.Name, "_") && !strings.HasSuffix(f.f.Name.Name, "_test") {
		f.errorf(f.f, 1, link("http://golang.org/doc/effective_go.html#package-names"), category("naming"), "don't use an underscore in package name")
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
			f.errorf(id, 0.8, link(styleGuideBase+"#mixed-caps"), category("naming"), "don't use ALL_CAPS in Go names; use CamelCase")
			return
		}
		if len(id.Name) > 2 && id.Name[0] == 'k' && id.Name[1] >= 'A' && id.Name[1] <= 'Z' {
			should := string(id.Name[1]+'a'-'A') + id.Name[2:]
			f.errorf(id, 0.8, link(styleGuideBase+"#mixed-caps"), category("naming"), "don't use leading k in Go names; %s %s should be %s", thing, id.Name, should)
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

// lintVarDecls examines variable declarations. It complains about declarations with
// redundant LHS types that can be inferred from the RHS.
func (f *file) lintVarDecls() {
	var lastGen *ast.GenDecl // last GenDecl entered.

	f.walk(func(node ast.Node) bool {
		switch v := node.(type) {
		case *ast.GenDecl:
			if v.Tok != token.CONST && v.Tok != token.VAR {
				return false
			}
			lastGen = v
			return true
		case *ast.ValueSpec:
			if lastGen.Tok == token.CONST {
				return false
			}
			if len(v.Names) > 1 || v.Type == nil || len(v.Values) == 0 {
				return false
			}
			rhs := v.Values[0]
			// An underscore var appears in a common idiom for compile-time interface satisfaction,
			// as in "var _ Interface = (*Concrete)(nil)".
			if isIdent(v.Names[0], "_") {
				return false
			}
			// If the RHS is a zero value, suggest dropping it.
			zero := false
			if lit, ok := rhs.(*ast.BasicLit); ok {
				zero = zeroLiteral[lit.Value]
			} else if isIdent(rhs, "nil") {
				zero = true
			}
			if zero {
				f.errorf(rhs, 0.9, category("zero-value"), "should drop = %s from declaration of var %s; it is the zero value", f.render(rhs), v.Names[0])
				return false
			}
			lhsTyp := f.pkg.typeOf(v.Type)
			rhsTyp := f.pkg.typeOf(rhs)

			if !validType(lhsTyp) || !validType(rhsTyp) {
				// Type checking failed (often due to missing imports).
				return false
			}

			if !types.Identical(lhsTyp, rhsTyp) {
				// Assignment to a different type is not redundant.
				return false
			}

			// The next three conditions are for suppressing the warning in situations
			// where we were unable to typecheck.

			// If the LHS type is an interface, don't warn, since it is probably a
			// concrete type on the RHS. Note that our feeble lexical check here
			// will only pick up interface{} and other literal interface types;
			// that covers most of the cases we care to exclude right now.
			if _, ok := v.Type.(*ast.InterfaceType); ok {
				return false
			}
			// If the RHS is an untyped const, only warn if the LHS type is its default type.
			if defType, ok := f.isUntypedConst(rhs); ok && !isIdent(v.Type, defType) {
				return false
			}

			f.errorf(v.Type, 0.8, category("type-inference"), "should omit type %s from declaration of var %s; it will be inferred from the right-hand side", f.render(v.Type), v.Names[0])
			return false
		}
		return true
	})
}

func validType(T types.Type) bool {
	return T != nil &&
		T != types.Typ[types.Invalid] &&
		!strings.Contains(T.String(), "invalid type") // good but not foolproof
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
		if ignore[ifStmt] {
			return true
		}
		if elseif, ok := ifStmt.Else.(*ast.IfStmt); ok {
			ignore[elseif] = true
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
		if rs.Value == nil {
			// for x = range m { ... }
			return true // single var form
		}
		if !isIdent(rs.Value, "_") {
			// for ?, y = range m { ... }
			return true
		}

		p := f.errorf(rs.Value, 1, category("range-loop"), "should omit 2nd value from range; this loop is equivalent to `for %s %s range ...`", f.render(rs.Key), rs.Tok)

		newRS := *rs // shallow copy
		newRS.Value = nil
		p.ReplacementLine = f.firstLineOf(&newRS, rs)

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
		// People use pro
"""




```