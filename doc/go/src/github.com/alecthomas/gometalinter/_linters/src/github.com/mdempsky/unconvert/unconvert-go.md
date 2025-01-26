Response:
我的思考过程如下：

1. **理解目标:** 目标是分析给定的 Go 代码片段的功能，并用 Go 代码举例说明其作用。 还需要考虑命令行参数、易错点等。

2. **代码概览:**  首先快速浏览代码，注意 `package main` 和 `func main()`，这表明它是一个可执行程序。  关注导入的包 (`import`)，这能提供一些关于程序功能的线索。 看到 `go/ast`, `go/parser`, `go/types`, `go/format` 等包，可以初步判断这个程序与 Go 源代码的解析、类型检查和格式化有关。

3. **核心功能识别:**  仔细阅读代码注释，特别是 `// Unconvert removes redundant type conversions from Go packages.`  这清晰地指明了程序的主要功能：移除 Go 代码中多余的类型转换。

4. **数据结构分析:**
    * `editSet`:  `map[token.Position]struct{}`，键是 `token.Position`，表示代码中某个位置，值是空结构体，说明这个 set 存储的是需要编辑的位置。
    * `fileToEditSet`: `map[string]editSet`，键是文件名，值是该文件中需要编辑的位置集合。 这说明程序处理的是多个文件。
    * `editor` 结构体：包含 `edits` (待删除的转换位置) 和 `file` (当前处理的文件信息)。
    * `visitor` 结构体：用于遍历 AST，查找和记录需要删除的类型转换。

5. **关键函数分析:**
    * `apply(file string, edits editSet)`:  接收文件名和需要编辑的位置集合，解析文件，遍历 AST，删除指定的类型转换，并格式化写回文件。
    * `editor.Visit(n ast.Node)` 和 `editor.rewrite(f *ast.Expr)`:  用于遍历 AST，找到类型转换表达式，并从 AST 中移除。 `rewrite` 是实际删除转换的地方。
    * `print(conversions []token.Position)`:  打印找到的多余类型转换的位置信息，并可选地显示代码行。
    * `computeEdits(importPaths []string, os, arch string, cgoEnabled bool)`:  这是核心的分析函数。它使用 `go/loader` 加载包，然后遍历 AST，使用 `visitor` 查找多余的类型转换。
    * `visitor.unconvert(call *ast.CallExpr)`:  判断 `call` 表达式是否是一个多余的类型转换。关键在于检查函数调用是否是类型转换，且源类型和目标类型是否相同。
    * `isSafeContext(t types.Type)`:  判断在特定上下文中移除类型转换是否安全，避免破坏代码的正确性。
    * `isUntypedValue(n ast.Expr, info *types.Info)`:  判断表达式是否是无类型的值，对于无类型的值，某些类型转换是允许的。
    * `mergeEdits(importPaths []string)`: 当使用 `-all` 标志时，会针对多个平台进行分析，并合并结果，只有在所有平台都认为可以删除的转换才会被删除。

6. **推理 Go 语言功能实现:**  通过分析 `visitor.unconvert` 函数，可以推断出它正在查找形如 `Type(expression)` 的类型转换，其中 `Type` 与 `expression` 的类型相同。

7. **Go 代码示例:**  基于上述推理，可以写出示例代码，展示 `unconvert` 要删除的冗余类型转换：
   ```go
   package main

   import "fmt"

   func main() {
       var i int = 10
       var f float64 = float64(i) // 多余的类型转换
       fmt.Println(f)
   }
   ```
   假设输入是包含此代码的文件，输出将是指出 `float64(i)` 是不必要的转换。

8. **命令行参数:**  浏览 `flag` 包的使用，可以列出程序支持的命令行参数：
    * `-all`: 检查所有 GOOS 和 GOARCH 组合。
    * `-apply`: 将修改应用到源文件。
    * `-cpuprofile`: 将 CPU 性能分析信息写入文件。
    * `-safe`: 更保守的模式。
    * `-v`: 详细输出。

9. **易犯错的点:** 仔细阅读代码中 `TODO` 注释和条件判断，可以发现 `-safe` 标志的存在以及关于处理 untyped 值的特殊情况。  这暗示了使用者可能不理解在某些特定上下文中（例如涉及到 untyped 值或需要保证类型安全的场景），`unconvert` 的行为可能需要谨慎。

10. **组织答案:** 将以上分析结果组织成清晰的中文答案，包括功能描述、Go 代码示例、命令行参数说明和易错点提示。  确保示例代码包含假设的输入和预期的输出。

通过以上步骤，我能够逐步理解代码的功能并生成最终的答案。  核心在于理解代码的目标，分析其数据结构和关键函数，并结合 Go 语言的知识进行推理和举例。

这段 Go 语言代码实现了一个名为 `unconvert` 的工具，其主要功能是**移除 Go 语言代码中冗余的类型转换**。

**具体功能列举:**

1. **解析 Go 语言源代码:** 使用 `go/parser` 包解析指定的 Go 语言源文件或包。
2. **类型检查:** 使用 `go/types` 包进行类型检查，以确定类型转换是否是冗余的。
3. **识别冗余类型转换:** 通过遍历抽象语法树 (AST)，查找形如 `Type(expression)` 的类型转换，并判断 `Type` 和 `expression` 的类型是否相同。
4. **报告冗余类型转换:**  将找到的冗余类型转换的位置（文件名、行号、列号）打印到控制台。可以通过 `-v` 标志显示包含冗余转换的代码行。
5. **应用修改 (可选):**  如果使用 `-apply` 标志，`unconvert` 会自动从源代码中删除这些冗余的类型转换。
6. **支持多种操作系统和架构 (通过 `-all` 标志):**  可以针对不同的操作系统 (GOOS) 和架构 (GOARCH) 组合进行检查，确保在各种环境下冗余的类型转换都被识别出来。
7. **性能分析 (通过 `-cpuprofile` 标志):**  可以生成 CPU 性能分析报告，用于调试和优化 `unconvert` 工具自身。
8. **提供更保守的模式 (通过 `-safe` 标志):**  在一个更保守的模式下运行，可能会跳过一些潜在的冗余转换，以避免误判。

**它是什么 Go 语言功能的实现？**

`unconvert` 工具是 Go 语言静态分析工具的一种，它利用 Go 语言提供的 `go/ast`、`go/parser` 和 `go/types` 等包，对代码进行结构化分析和语义分析，从而实现代码的自动化修改。

**Go 代码举例说明:**

假设我们有以下 Go 代码文件 `example.go`:

```go
package main

import "fmt"

func main() {
	var i int = 10
	var f float64 = float64(i) // 这里是一个冗余的类型转换
	fmt.Println(f)
}
```

**假设的输入和输出:**

**输入:**  执行命令 `unconvert example.go`

**输出:**

```
example.go:6:16: unnecessary conversion
	var f float64 = float64(i)
	               ^
```

**如果加上 `-apply` 标志:**

**输入:** 执行命令 `unconvert -apply example.go`

**输出:** (没有输出到控制台，但是 `example.go` 文件会被修改为)

```go
package main

import "fmt"

func main() {
	var i int = 10
	var f float64 = float64(i) // 这里之前是冗余的类型转换
	fmt.Println(f)
}
```

**注意:** 上面的输出是在未修改 `-apply` 的代码情况下，展示了如何报告冗余信息。如果使用了 `-apply`，文件内容会直接被修改。 正确的 `-apply` 后的 `example.go` 文件内容如下：

```go
package main

import "fmt"

func main() {
	var i int = 10
	var f float64 = float64(i)
	fmt.Println(f)
}
```

**修改后（`-apply` 生效）：**

```go
package main

import "fmt"

func main() {
	var i int = 10
	var f float64 = float64(i)
	fmt.Println(f)
}
```

**命令行参数的具体处理:**

* **`-all`**:  如果指定，`unconvert` 会针对 `plats` 变量中定义的所有操作系统和架构组合运行类型检查。这对于确保代码在不同平台上的兼容性很有用。它会合并所有平台的分析结果，只有在所有平台上都认为是冗余的转换才会被标记或删除。
* **`-apply`**:  如果指定，`unconvert` 在识别出冗余的类型转换后，会直接修改源文件，删除这些转换。
* **`-cpuprofile string`**:  指定一个文件名，`unconvert` 会将 CPU 性能分析信息写入该文件，用于性能调试。
* **`-safe`**:  如果指定，`unconvert` 会采取更保守的策略。这通常意味着它会避免删除某些可能存在争议的转换，即使这些转换在技术上可能是冗余的。这可以减少误判的可能性。
* **`-v`**:  如果指定，`unconvert` 会在控制台输出更详细的信息，例如包含冗余类型转换的代码行。

**使用者易犯错的点:**

* **过度依赖 `-apply` 标志而不进行代码审查:**  使用者可能会直接使用 `-apply` 标志来自动修改代码，而不仔细检查 `unconvert` 所做的更改。虽然 `unconvert` 的目标是删除冗余转换，但在某些复杂的情况下，可能会存在误判或者删除后影响代码可读性的情况。建议在应用修改后进行代码审查。
* **不理解 `-safe` 标志的含义:** 使用者可能不清楚 `-safe` 标志的作用，导致在某些情况下，一些本可以删除的冗余转换没有被识别出来。应该根据项目的需要选择是否使用 `-safe` 标志。
* **在不了解 `-all` 标志的情况下使用:** 使用者可能在不清楚其影响的情况下使用 `-all` 标志，导致针对多个平台进行不必要的分析，增加运行时间。只有在需要确保跨平台兼容性的情况下才需要使用此标志。

总而言之，`unconvert` 是一个有用的 Go 语言代码清理工具，可以帮助开发者移除代码中的冗余类型转换，提高代码的可读性和简洁性。但是，使用者应该理解其工作原理和各个命令行参数的作用，并谨慎使用 `-apply` 标志。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/github.com/mdempsky/unconvert/unconvert.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Unconvert removes redundant type conversions from Go packages.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"runtime/pprof"
	"sort"
	"sync"
	"unicode"

	"github.com/kisielk/gotool"
	"golang.org/x/text/width"
	"golang.org/x/tools/go/loader"
)

// Unnecessary conversions are identified by the position
// of their left parenthesis within a source file.

type editSet map[token.Position]struct{}

type fileToEditSet map[string]editSet

func apply(file string, edits editSet) {
	if len(edits) == 0 {
		return
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	// Note: We modify edits during the walk.
	v := editor{edits: edits, file: fset.File(f.Package)}
	ast.Walk(&v, f)
	if len(edits) != 0 {
		log.Printf("%s: missing edits %s", file, edits)
	}

	// TODO(mdempsky): Write to temporary file and rename.
	var buf bytes.Buffer
	err = format.Node(&buf, fset, f)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(file, buf.Bytes(), 0)
	if err != nil {
		log.Fatal(err)
	}
}

type editor struct {
	edits editSet
	file  *token.File
}

func (e *editor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return nil
	}
	v := reflect.ValueOf(n).Elem()
	for i, n := 0, v.NumField(); i < n; i++ {
		switch f := v.Field(i).Addr().Interface().(type) {
		case *ast.Expr:
			e.rewrite(f)
		case *[]ast.Expr:
			for i := range *f {
				e.rewrite(&(*f)[i])
			}
		}
	}
	return e
}

func (e *editor) rewrite(f *ast.Expr) {
	call, ok := (*f).(*ast.CallExpr)
	if !ok {
		return
	}

	pos := e.file.Position(call.Lparen)
	if _, ok := e.edits[pos]; !ok {
		return
	}
	*f = call.Args[0]
	delete(e.edits, pos)
}

var (
	cr = []byte{'\r'}
	nl = []byte{'\n'}
)

func print(conversions []token.Position) {
	var file string
	var lines [][]byte

	for _, pos := range conversions {
		fmt.Printf("%s:%d:%d: unnecessary conversion\n", pos.Filename, pos.Line, pos.Column)
		if *flagV {
			if pos.Filename != file {
				buf, err := ioutil.ReadFile(pos.Filename)
				if err != nil {
					log.Fatal(err)
				}
				file = pos.Filename
				lines = bytes.Split(buf, nl)
			}

			line := bytes.TrimSuffix(lines[pos.Line-1], cr)
			fmt.Printf("%s\n", line)

			// For files processed by cgo, Column is the
			// column location after cgo processing, which
			// may be different than the source column
			// that we want here. In lieu of a better
			// heuristic for detecting this case, at least
			// avoid panicking if column is out of bounds.
			if pos.Column <= len(line) {
				fmt.Printf("%s^\n", rub(line[:pos.Column-1]))
			}
		}
	}
}

// Rub returns a copy of buf with all non-whitespace characters replaced
// by spaces (like rubbing them out with white out).
func rub(buf []byte) []byte {
	// TODO(mdempsky): Handle combining characters?
	var res bytes.Buffer
	for _, r := range string(buf) {
		if unicode.IsSpace(r) {
			res.WriteRune(r)
			continue
		}
		switch width.LookupRune(r).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			res.WriteString("  ")
		default:
			res.WriteByte(' ')
		}
	}
	return res.Bytes()
}

var (
	flagAll        = flag.Bool("all", false, "type check all GOOS and GOARCH combinations")
	flagApply      = flag.Bool("apply", false, "apply edits to source files")
	flagCPUProfile = flag.String("cpuprofile", "", "write CPU profile to file")
	// TODO(mdempsky): Better description and maybe flag name.
	flagSafe = flag.Bool("safe", false, "be more conservative (experimental)")
	flagV    = flag.Bool("v", false, "verbose output")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: unconvert [flags] [package ...]\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if *flagCPUProfile != "" {
		f, err := os.Create(*flagCPUProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	importPaths := gotool.ImportPaths(flag.Args())
	if len(importPaths) == 0 {
		return
	}

	var m fileToEditSet
	if *flagAll {
		m = mergeEdits(importPaths)
	} else {
		m = computeEdits(importPaths, build.Default.GOOS, build.Default.GOARCH, build.Default.CgoEnabled)
	}

	if *flagApply {
		var wg sync.WaitGroup
		for f, e := range m {
			wg.Add(1)
			f, e := f, e
			go func() {
				defer wg.Done()
				apply(f, e)
			}()
		}
		wg.Wait()
	} else {
		var conversions []token.Position
		for _, positions := range m {
			for pos := range positions {
				conversions = append(conversions, pos)
			}
		}
		sort.Sort(byPosition(conversions))
		print(conversions)
		if len(conversions) > 0 {
			os.Exit(1)
		}
	}
}

var plats = [...]struct {
	goos, goarch string
}{
	// TODO(mdempsky): buildall.bash also builds linux-386-387 and linux-arm-arm5.
	{"android", "386"},
	{"android", "amd64"},
	{"android", "arm"},
	{"android", "arm64"},
	{"darwin", "386"},
	{"darwin", "amd64"},
	{"darwin", "arm"},
	{"darwin", "arm64"},
	{"dragonfly", "amd64"},
	{"freebsd", "386"},
	{"freebsd", "amd64"},
	{"freebsd", "arm"},
	{"linux", "386"},
	{"linux", "amd64"},
	{"linux", "arm"},
	{"linux", "arm64"},
	{"linux", "mips64"},
	{"linux", "mips64le"},
	{"linux", "ppc64"},
	{"linux", "ppc64le"},
	{"linux", "s390x"},
	{"nacl", "386"},
	{"nacl", "amd64p32"},
	{"nacl", "arm"},
	{"netbsd", "386"},
	{"netbsd", "amd64"},
	{"netbsd", "arm"},
	{"openbsd", "386"},
	{"openbsd", "amd64"},
	{"openbsd", "arm"},
	{"plan9", "386"},
	{"plan9", "amd64"},
	{"plan9", "arm"},
	{"solaris", "amd64"},
	{"windows", "386"},
	{"windows", "amd64"},
}

func mergeEdits(importPaths []string) fileToEditSet {
	m := make(fileToEditSet)
	for _, plat := range plats {
		for f, e := range computeEdits(importPaths, plat.goos, plat.goarch, false) {
			if e0, ok := m[f]; ok {
				for k := range e0 {
					if _, ok := e[k]; !ok {
						delete(e0, k)
					}
				}
			} else {
				m[f] = e
			}
		}
	}
	return m
}

type noImporter struct{}

func (noImporter) Import(path string) (*types.Package, error) {
	panic("golang.org/x/tools/go/loader said this wouldn't be called")
}

func computeEdits(importPaths []string, os, arch string, cgoEnabled bool) fileToEditSet {
	ctxt := build.Default
	ctxt.GOOS = os
	ctxt.GOARCH = arch
	ctxt.CgoEnabled = cgoEnabled

	var conf loader.Config
	conf.Build = &ctxt
	conf.TypeChecker.Importer = noImporter{}
	for _, importPath := range importPaths {
		conf.Import(importPath)
	}
	prog, err := conf.Load()
	if err != nil {
		log.Fatal(err)
	}

	type res struct {
		file  string
		edits editSet
	}
	ch := make(chan res)
	var wg sync.WaitGroup
	for _, pkg := range prog.InitialPackages() {
		for _, file := range pkg.Files {
			pkg, file := pkg, file
			wg.Add(1)
			go func() {
				defer wg.Done()
				v := visitor{pkg: pkg, file: conf.Fset.File(file.Package), edits: make(editSet)}
				ast.Walk(&v, file)
				ch <- res{v.file.Name(), v.edits}
			}()
		}
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	m := make(fileToEditSet)
	for r := range ch {
		m[r.file] = r.edits
	}
	return m
}

type step struct {
	n ast.Node
	i int
}

type visitor struct {
	pkg   *loader.PackageInfo
	file  *token.File
	edits editSet
	path  []step
}

func (v *visitor) Visit(node ast.Node) ast.Visitor {
	if node != nil {
		v.path = append(v.path, step{n: node})
	} else {
		n := len(v.path)
		v.path = v.path[:n-1]
		if n >= 2 {
			v.path[n-2].i++
		}
	}

	if call, ok := node.(*ast.CallExpr); ok {
		v.unconvert(call)
	}
	return v
}

func (v *visitor) unconvert(call *ast.CallExpr) {
	// TODO(mdempsky): Handle useless multi-conversions.

	// Conversions have exactly one argument.
	if len(call.Args) != 1 || call.Ellipsis != token.NoPos {
		return
	}
	ft, ok := v.pkg.Types[call.Fun]
	if !ok {
		fmt.Println("Missing type for function")
		return
	}
	if !ft.IsType() {
		// Function call; not a conversion.
		return
	}
	at, ok := v.pkg.Types[call.Args[0]]
	if !ok {
		fmt.Println("Missing type for argument")
		return
	}
	if !types.Identical(ft.Type, at.Type) {
		// A real conversion.
		return
	}
	if isUntypedValue(call.Args[0], &v.pkg.Info) {
		// Workaround golang.org/issue/13061.
		return
	}
	if *flagSafe && !v.isSafeContext(at.Type) {
		// TODO(mdempsky): Remove this message.
		fmt.Println("Skipped a possible type conversion because of -safe at", v.file.Position(call.Pos()))
		return
	}
	if v.isCgoCheckPointerContext() {
		// cmd/cgo generates explicit type conversions that
		// are often redundant when introducing
		// _cgoCheckPointer calls (issue #16).  Users can't do
		// anything about these, so skip over them.
		return
	}

	v.edits[v.file.Position(call.Lparen)] = struct{}{}
}

func (v *visitor) isCgoCheckPointerContext() bool {
	ctxt := &v.path[len(v.path)-2]
	if ctxt.i != 1 {
		return false
	}
	call, ok := ctxt.n.(*ast.CallExpr)
	if !ok {
		return false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "_cgoCheckPointer"
}

// isSafeContext reports whether the current context requires
// an expression of type t.
//
// TODO(mdempsky): That's a bad explanation.
func (v *visitor) isSafeContext(t types.Type) bool {
	ctxt := &v.path[len(v.path)-2]
	switch n := ctxt.n.(type) {
	case *ast.AssignStmt:
		pos := ctxt.i - len(n.Lhs)
		if pos < 0 {
			fmt.Println("Type conversion on LHS of assignment?")
			return false
		}
		if n.Tok == token.DEFINE {
			// Skip := assignments.
			return true
		}
		// We're a conversion in the pos'th element of n.Rhs.
		// Check that the corresponding element of n.Lhs is of type t.
		lt, ok := v.pkg.Types[n.Lhs[pos]]
		if !ok {
			fmt.Println("Missing type for LHS expression")
			return false
		}
		return types.Identical(t, lt.Type)
	case *ast.BinaryExpr:
		if n.Op == token.SHL || n.Op == token.SHR {
			if ctxt.i == 1 {
				// RHS of a shift is always safe.
				return true
			}
			// For the LHS, we should inspect up another level.
			fmt.Println("TODO(mdempsky): Handle LHS of shift expressions")
			return true
		}
		var other ast.Expr
		if ctxt.i == 0 {
			other = n.Y
		} else {
			other = n.X
		}
		ot, ok := v.pkg.Types[other]
		if !ok {
			fmt.Println("Missing type for other binop subexpr")
			return false
		}
		return types.Identical(t, ot.Type)
	case *ast.CallExpr:
		pos := ctxt.i - 1
		if pos < 0 {
			// Type conversion in the function subexpr is okay.
			return true
		}
		ft, ok := v.pkg.Types[n.Fun]
		if !ok {
			fmt.Println("Missing type for function expression")
			return false
		}
		sig, ok := ft.Type.(*types.Signature)
		if !ok {
			// "Function" is either a type conversion (ok) or a builtin (ok?).
			return true
		}
		params := sig.Params()
		var pt types.Type
		if sig.Variadic() && n.Ellipsis == token.NoPos && pos >= params.Len()-1 {
			pt = params.At(params.Len() - 1).Type().(*types.Slice).Elem()
		} else {
			pt = params.At(pos).Type()
		}
		return types.Identical(t, pt)
	case *ast.CompositeLit, *ast.KeyValueExpr:
		fmt.Println("TODO(mdempsky): Compare against value type of composite literal type at", v.file.Position(n.Pos()))
		return true
	case *ast.ReturnStmt:
		// TODO(mdempsky): Is there a better way to get the corresponding
		// return parameter type?
		var funcType *ast.FuncType
		for i := len(v.path) - 1; funcType == nil && i >= 0; i-- {
			switch f := v.path[i].n.(type) {
			case *ast.FuncDecl:
				funcType = f.Type
			case *ast.FuncLit:
				funcType = f.Type
			}
		}
		var typeExpr ast.Expr
		for i, j := ctxt.i, 0; j < len(funcType.Results.List); j++ {
			f := funcType.Results.List[j]
			if len(f.Names) == 0 {
				if i >= 1 {
					i--
					continue
				}
			} else {
				if i >= len(f.Names) {
					i -= len(f.Names)
					continue
				}
			}
			typeExpr = f.Type
			break
		}
		if typeExpr == nil {
			fmt.Println(ctxt)
		}
		pt, ok := v.pkg.Types[typeExpr]
		if !ok {
			fmt.Println("Missing type for return parameter at", v.file.Position(n.Pos()))
			return false
		}
		return types.Identical(t, pt.Type)
	case *ast.StarExpr, *ast.UnaryExpr:
		// TODO(mdempsky): I think these are always safe.
		return true
	case *ast.SwitchStmt:
		// TODO(mdempsky): I think this is always safe?
		return true
	default:
		// TODO(mdempsky): When can this happen?
		fmt.Printf("... huh, %T at %v\n", n, v.file.Position(n.Pos()))
		return true
	}
}

func isUntypedValue(n ast.Expr, info *types.Info) (res bool) {
	switch n := n.(type) {
	case *ast.BinaryExpr:
		switch n.Op {
		case token.SHL, token.SHR:
			// Shifts yield an untyped value if their LHS is untyped.
			return isUntypedValue(n.X, info)
		case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
			// Comparisons yield an untyped boolean value.
			return true
		case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
			token.AND, token.OR, token.XOR, token.AND_NOT,
			token.LAND, token.LOR:
			return isUntypedValue(n.X, info) && isUntypedValue(n.Y, info)
		}
	case *ast.UnaryExpr:
		switch n.Op {
		case token.ADD, token.SUB, token.NOT, token.XOR:
			return isUntypedValue(n.X, info)
		}
	case *ast.BasicLit:
		// Basic literals are always untyped.
		return true
	case *ast.ParenExpr:
		return isUntypedValue(n.X, info)
	case *ast.SelectorExpr:
		return isUntypedValue(n.Sel, info)
	case *ast.Ident:
		if obj, ok := info.Uses[n]; ok {
			if obj.Pkg() == nil && obj.Name() == "nil" {
				// The universal untyped zero value.
				return true
			}
			if b, ok := obj.Type().(*types.Basic); ok && b.Info()&types.IsUntyped != 0 {
				// Reference to an untyped constant.
				return true
			}
		}
	case *ast.CallExpr:
		if b, ok := asBuiltin(n.Fun, info); ok {
			switch b.Name() {
			case "real", "imag":
				return isUntypedValue(n.Args[0], info)
			case "complex":
				return isUntypedValue(n.Args[0], info) && isUntypedValue(n.Args[1], info)
			}
		}
	}

	return false
}

func asBuiltin(n ast.Expr, info *types.Info) (*types.Builtin, bool) {
	for {
		paren, ok := n.(*ast.ParenExpr)
		if !ok {
			break
		}
		n = paren.X
	}

	ident, ok := n.(*ast.Ident)
	if !ok {
		return nil, false
	}

	obj, ok := info.Uses[ident]
	if !ok {
		return nil, false
	}

	b, ok := obj.(*types.Builtin)
	return b, ok
}

type byPosition []token.Position

func (p byPosition) Len() int {
	return len(p)
}

func (p byPosition) Less(i, j int) bool {
	if p[i].Filename != p[j].Filename {
		return p[i].Filename < p[j].Filename
	}
	if p[i].Line != p[j].Line {
		return p[i].Line < p[j].Line
	}
	return p[i].Column < p[j].Column
}

func (p byPosition) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

"""



```