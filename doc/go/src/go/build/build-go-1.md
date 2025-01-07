Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `go/build/build.go` file.

Here's a breakdown of the code's key actions:

1. **File Processing**: Iterates through files in a directory, analyzing each `.go` file for imports, embed directives, and build constraints.
2. **Cgo Handling**: Detects and processes Cgo files, including saving `#cgo` directives.
3. **Test File Handling**: Differentiates between regular, test, and external test files and processes them accordingly.
4. **Build Tag Analysis**: Identifies build tags from `// +build` and `//go:build` comments and uses them to determine if a file should be included in the build.
5. **File Categorization**: Assigns files to different lists within a `Package` struct based on their type (e.g., `GoFiles`, `CgoFiles`, `TestGoFiles`).
6. **Import and Embed Tracking**: Collects import paths and embed patterns with their positions in the source code.
7. **Module Support**: Attempts to use the `go` command for module-aware dependency resolution.
8. **`#cgo` Directive Parsing**: Parses and stores `#cgo` directives for Cgo integration.
这段代码是 `go/src/go/build/build.go` 文件的一部分，其主要功能是**处理目录中的 Go 源代码文件，提取关键信息，并根据文件类型和构建约束将它们归类到不同的文件列表中，最终构建出一个 `Package` 对象**。

具体来说，它执行以下操作：

1. **识别和处理 Cgo 文件:**
   - 遍历目录中的所有 Go 文件。
   - 检查每个 Go 文件的 `import` 语句，如果发现导入了 "C"，则认为该文件是 Cgo 文件。
   - 对于 Cgo 文件，会提取 `#cgo` 指令，并将其保存到 `Package` 对象的 `CgoCFLAGS`、`CgoCPPFLAGS` 等字段中。
   - 在测试文件中使用 Cgo 会报错。
   - 如果 Cgo 功能被禁用，Cgo 文件将被忽略。

2. **识别和处理测试文件:**
   - 根据文件名后缀 `_test.go` 来区分测试文件。
   - 根据文件名是否以 `_` 开头来区分内部测试文件和外部测试文件（`isTest` 和 `isXTest`）。
   - 将不同类型的测试文件添加到 `Package` 对象的 `TestGoFiles` 或 `XTestGoFiles` 列表中。

3. **识别和处理普通 Go 文件:**
   - 将既不是 Cgo 文件也不是测试文件的 Go 文件添加到 `Package` 对象的 `GoFiles` 列表中。

4. **提取导入路径和 embed 模式:**
   - 对于每个 Go 文件，解析其 `import` 声明和 `//go:embed` 指令。
   - 将导入的包路径和 embed 模式及其在文件中的位置信息分别存储到 `importPos`、`testImportPos`、`xTestImportPos` 和 `embedPos`、`testEmbedPos`、`xTestEmbedPos` 这些 map 中。

5. **提取 `//go:directives`:**
   -  提取 Go 文件中的 `//go:directives` 指令，并将其存储到 `Package` 对象的 `Directives`、`TestDirectives` 或 `XTestDirectives` 中。

6. **处理构建标签 (build tags):**
   - 收集文件中出现的 `// +build` 和 `//go:build` 构建标签，并将它们添加到 `Package` 对象的 `AllTags` 列表中。

7. **归类其他类型的文件:**
   - 根据文件扩展名，将其他类型的文件（例如 `.c`、`.s` 等）添加到 `Package` 对象的相应列表中，例如 `CFiles`、`SFiles` 等。
   - `.S` 和 `.sx` 汇编文件只有在启用 Cgo 的情况下才会被包含。

8. **构建 `Package` 对象:**
   - 将收集到的文件名、导入路径、embed 模式、构建标签等信息存储到 `Package` 对象中。
   - 对导入路径和 embed 模式列表进行排序和去重。
   - 如果没有找到任何 Go 文件，则返回 `NoGoError` 错误。

**推理其实现的 Go 语言功能：**

这段代码是 Go 语言构建过程中的核心部分，它实现了以下 Go 语言功能的基础：

- **包管理:** 通过识别和收集导入路径，为后续的依赖解析和链接提供信息。
- **构建约束:** 通过处理 `// +build` 和 `//go:build` 标签，实现了条件编译的功能，允许根据不同的操作系统、架构或其他条件选择性地编译文件。
- **Cgo 支持:** 通过识别和处理 Cgo 文件以及 `#cgo` 指令，实现了 Go 代码与 C 代码的互操作。
- **测试支持:** 通过区分和处理测试文件，实现了 Go 语言的测试框架。
- **`//go:embed` 支持:** 通过解析 `//go:embed` 指令，实现了将静态资源嵌入到 Go 可执行文件中的功能。
- **`//go:directives` 支持:**  虽然代码中只是简单地收集了这些指令，但这是 Go 语言指令机制的一部分，可以用于代码生成或其他构建过程中的自定义行为。

**Go 代码举例说明 `//go:embed` 功能:**

假设有以下文件结构：

```
myproject/
├── main.go
└── static/
    └── data.txt
```

`data.txt` 文件内容：

```
This is some static data.
```

`main.go` 文件内容：

```go
package main

import (
	_ "embed"
	"fmt"
)

//go:embed static/data.txt
var data string

func main() {
	fmt.Println(data)
}
```

**假设的输入与输出：**

- **输入：** `build.go` 正在处理 `myproject` 目录。
- **输出：** `build.go` 会识别 `main.go` 文件中的 `//go:embed static/data.txt` 指令，并将 "static/data.txt" 添加到 `p.EmbedPatterns` 列表中，并记录其位置信息。最终，在构建过程中，`data.txt` 的内容会被嵌入到 `main.go` 的 `data` 变量中。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `go` 命令的更上层。但是，`build.go` 中使用的 `Context` 对象包含了从命令行参数（或环境变量）中提取的信息，例如：

- **`ctxt.GOOS` 和 `ctxt.GOARCH`:** 目标操作系统和架构，可以通过 `-os` 和 `-arch` 命令行参数或 `GOOS` 和 `GOARCH` 环境变量设置。
- **`ctxt.BuildTags`:**  构建标签，可以通过 `-tags` 命令行参数设置。
- **`ctxt.CgoEnabled`:** 是否启用 Cgo，可以通过 `-cgo` 命令行参数或 `CGO_ENABLED` 环境变量设置。

`build.go` 会利用这些信息来决定哪些文件应该被包含在构建过程中，例如通过 `goodOSArchFile` 函数判断文件名是否匹配当前的操作系统和架构。

**使用者易犯错的点：**

这段代码中涉及到 Cgo 的处理，一个常见的错误是**在测试文件中使用 Cgo**。Go 的测试框架对 Cgo 的支持有限，直接在测试文件中导入 "C" 可能会导致构建错误。

**例子：**

假设有一个测试文件 `my_test.go`:

```go
package mypackage

import "C" // 错误：在测试文件中使用 cgo

import "testing"

func TestSomething(t *testing.T) {
	// ...
}
```

运行 `go test` 命令将会报错，因为在测试文件中使用了 Cgo。正确的做法是将需要 Cgo 的代码放在非测试文件中，然后在测试文件中通过正常的 Go 包导入来使用它。

**归纳一下它的功能（第 2 部分）：**

这段代码（作为 `go/build/build.go` 的一部分）的主要功能是**在 Go 语言的构建过程中，负责扫描和分析目录中的源代码文件，提取关键的构建信息（如导入、embed、构建约束等），并根据文件的类型和构建条件将其归类到 `Package` 对象的不同字段中**。它为后续的编译、链接等构建步骤提供了必要的基础数据，并且支持 Go 语言的包管理、构建约束、Cgo 互操作、测试以及资源嵌入等核心功能。它不直接处理命令行参数，而是利用上层传递的构建上下文信息来完成文件分析和归类的工作。

Prompt: 
```
这是路径为go/src/go/build/build.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
or _, imp := range info.imports {
			if imp.path == "C" {
				if isTest {
					badGoFile(name, fmt.Errorf("use of cgo in test %s not supported", filename))
					continue
				}
				isCgo = true
				if imp.doc != nil {
					if err := ctxt.saveCgo(filename, p, imp.doc); err != nil {
						badGoFile(name, err)
					}
				}
			}
		}

		var fileList *[]string
		var importMap, embedMap map[string][]token.Position
		var directives *[]Directive
		switch {
		case isCgo:
			allTags["cgo"] = true
			if ctxt.CgoEnabled {
				fileList = &p.CgoFiles
				importMap = importPos
				embedMap = embedPos
				directives = &p.Directives
			} else {
				// Ignore imports and embeds from cgo files if cgo is disabled.
				fileList = &p.IgnoredGoFiles
			}
		case isXTest:
			fileList = &p.XTestGoFiles
			importMap = xTestImportPos
			embedMap = xTestEmbedPos
			directives = &p.XTestDirectives
		case isTest:
			fileList = &p.TestGoFiles
			importMap = testImportPos
			embedMap = testEmbedPos
			directives = &p.TestDirectives
		default:
			fileList = &p.GoFiles
			importMap = importPos
			embedMap = embedPos
			directives = &p.Directives
		}
		*fileList = append(*fileList, name)
		if importMap != nil {
			for _, imp := range info.imports {
				importMap[imp.path] = append(importMap[imp.path], fset.Position(imp.pos))
			}
		}
		if embedMap != nil {
			for _, emb := range info.embeds {
				embedMap[emb.pattern] = append(embedMap[emb.pattern], emb.pos)
			}
		}
		if directives != nil {
			*directives = append(*directives, info.directives...)
		}
	}

	for tag := range allTags {
		p.AllTags = append(p.AllTags, tag)
	}
	slices.Sort(p.AllTags)

	p.EmbedPatterns, p.EmbedPatternPos = cleanDecls(embedPos)
	p.TestEmbedPatterns, p.TestEmbedPatternPos = cleanDecls(testEmbedPos)
	p.XTestEmbedPatterns, p.XTestEmbedPatternPos = cleanDecls(xTestEmbedPos)

	p.Imports, p.ImportPos = cleanDecls(importPos)
	p.TestImports, p.TestImportPos = cleanDecls(testImportPos)
	p.XTestImports, p.XTestImportPos = cleanDecls(xTestImportPos)

	// add the .S/.sx files only if we are using cgo
	// (which means gcc will compile them).
	// The standard assemblers expect .s files.
	if len(p.CgoFiles) > 0 {
		p.SFiles = append(p.SFiles, Sfiles...)
		slices.Sort(p.SFiles)
	} else {
		p.IgnoredOtherFiles = append(p.IgnoredOtherFiles, Sfiles...)
		slices.Sort(p.IgnoredOtherFiles)
	}

	if badGoError != nil {
		return p, badGoError
	}
	if len(p.GoFiles)+len(p.CgoFiles)+len(p.TestGoFiles)+len(p.XTestGoFiles) == 0 {
		return p, &NoGoError{p.Dir}
	}
	return p, pkgerr
}

func fileListForExt(p *Package, ext string) *[]string {
	switch ext {
	case ".c":
		return &p.CFiles
	case ".cc", ".cpp", ".cxx":
		return &p.CXXFiles
	case ".m":
		return &p.MFiles
	case ".h", ".hh", ".hpp", ".hxx":
		return &p.HFiles
	case ".f", ".F", ".for", ".f90":
		return &p.FFiles
	case ".s", ".S", ".sx":
		return &p.SFiles
	case ".swig":
		return &p.SwigFiles
	case ".swigcxx":
		return &p.SwigCXXFiles
	case ".syso":
		return &p.SysoFiles
	}
	return nil
}

func uniq(list []string) []string {
	if list == nil {
		return nil
	}
	out := make([]string, len(list))
	copy(out, list)
	slices.Sort(out)
	uniq := out[:0]
	for _, x := range out {
		if len(uniq) == 0 || uniq[len(uniq)-1] != x {
			uniq = append(uniq, x)
		}
	}
	return uniq
}

var errNoModules = errors.New("not using modules")

// importGo checks whether it can use the go command to find the directory for path.
// If using the go command is not appropriate, importGo returns errNoModules.
// Otherwise, importGo tries using the go command and reports whether that succeeded.
// Using the go command lets build.Import and build.Context.Import find code
// in Go modules. In the long term we want tools to use go/packages (currently golang.org/x/tools/go/packages),
// which will also use the go command.
// Invoking the go command here is not very efficient in that it computes information
// about the requested package and all dependencies and then only reports about the requested package.
// Then we reinvoke it for every dependency. But this is still better than not working at all.
// See golang.org/issue/26504.
func (ctxt *Context) importGo(p *Package, path, srcDir string, mode ImportMode) error {
	// To invoke the go command,
	// we must not being doing special things like AllowBinary or IgnoreVendor,
	// and all the file system callbacks must be nil (we're meant to use the local file system).
	if mode&AllowBinary != 0 || mode&IgnoreVendor != 0 ||
		ctxt.JoinPath != nil || ctxt.SplitPathList != nil || ctxt.IsAbsPath != nil || ctxt.IsDir != nil || ctxt.HasSubdir != nil || ctxt.ReadDir != nil || ctxt.OpenFile != nil || !equal(ctxt.ToolTags, defaultToolTags) || !equal(ctxt.ReleaseTags, defaultReleaseTags) {
		return errNoModules
	}

	// If ctxt.GOROOT is not set, we don't know which go command to invoke,
	// and even if we did we might return packages in GOROOT that we wouldn't otherwise find
	// (because we don't know to search in 'go env GOROOT' otherwise).
	if ctxt.GOROOT == "" {
		return errNoModules
	}

	// Predict whether module aware mode is enabled by checking the value of
	// GO111MODULE and looking for a go.mod file in the source directory or
	// one of its parents. Running 'go env GOMOD' in the source directory would
	// give a canonical answer, but we'd prefer not to execute another command.
	go111Module := os.Getenv("GO111MODULE")
	switch go111Module {
	case "off":
		return errNoModules
	default: // "", "on", "auto", anything else
		// Maybe use modules.
	}

	if srcDir != "" {
		var absSrcDir string
		if filepath.IsAbs(srcDir) {
			absSrcDir = srcDir
		} else if ctxt.Dir != "" {
			return fmt.Errorf("go/build: Dir is non-empty, so relative srcDir is not allowed: %v", srcDir)
		} else {
			// Find the absolute source directory. hasSubdir does not handle
			// relative paths (and can't because the callbacks don't support this).
			var err error
			absSrcDir, err = filepath.Abs(srcDir)
			if err != nil {
				return errNoModules
			}
		}

		// If the source directory is in GOROOT, then the in-process code works fine
		// and we should keep using it. Moreover, the 'go list' approach below doesn't
		// take standard-library vendoring into account and will fail.
		if _, ok := ctxt.hasSubdir(filepath.Join(ctxt.GOROOT, "src"), absSrcDir); ok {
			return errNoModules
		}
	}

	// For efficiency, if path is a standard library package, let the usual lookup code handle it.
	if dir := ctxt.joinPath(ctxt.GOROOT, "src", path); ctxt.isDir(dir) {
		return errNoModules
	}

	// If GO111MODULE=auto, look to see if there is a go.mod.
	// Since go1.13, it doesn't matter if we're inside GOPATH.
	if go111Module == "auto" {
		var (
			parent string
			err    error
		)
		if ctxt.Dir == "" {
			parent, err = os.Getwd()
			if err != nil {
				// A nonexistent working directory can't be in a module.
				return errNoModules
			}
		} else {
			parent, err = filepath.Abs(ctxt.Dir)
			if err != nil {
				// If the caller passed a bogus Dir explicitly, that's materially
				// different from not having modules enabled.
				return err
			}
		}
		for {
			if f, err := ctxt.openFile(ctxt.joinPath(parent, "go.mod")); err == nil {
				buf := make([]byte, 100)
				_, err := f.Read(buf)
				f.Close()
				if err == nil || err == io.EOF {
					// go.mod exists and is readable (is a file, not a directory).
					break
				}
			}
			d := filepath.Dir(parent)
			if len(d) >= len(parent) {
				return errNoModules // reached top of file system, no go.mod
			}
			parent = d
		}
	}

	goCmd := filepath.Join(ctxt.GOROOT, "bin", "go")
	cmd := exec.Command(goCmd, "list", "-e", "-compiler="+ctxt.Compiler, "-tags="+strings.Join(ctxt.BuildTags, ","), "-installsuffix="+ctxt.InstallSuffix, "-f={{.Dir}}\n{{.ImportPath}}\n{{.Root}}\n{{.Goroot}}\n{{if .Error}}{{.Error}}{{end}}\n", "--", path)

	if ctxt.Dir != "" {
		cmd.Dir = ctxt.Dir
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cgo := "0"
	if ctxt.CgoEnabled {
		cgo = "1"
	}
	cmd.Env = append(cmd.Environ(),
		"GOOS="+ctxt.GOOS,
		"GOARCH="+ctxt.GOARCH,
		"GOROOT="+ctxt.GOROOT,
		"GOPATH="+ctxt.GOPATH,
		"CGO_ENABLED="+cgo,
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go/build: go list %s: %v\n%s\n", path, err, stderr.String())
	}

	f := strings.SplitN(stdout.String(), "\n", 5)
	if len(f) != 5 {
		return fmt.Errorf("go/build: importGo %s: unexpected output:\n%s\n", path, stdout.String())
	}
	dir := f[0]
	errStr := strings.TrimSpace(f[4])
	if errStr != "" && dir == "" {
		// If 'go list' could not locate the package (dir is empty),
		// return the same error that 'go list' reported.
		return errors.New(errStr)
	}

	// If 'go list' did locate the package, ignore the error.
	// It was probably related to loading source files, and we'll
	// encounter it ourselves shortly if the FindOnly flag isn't set.
	p.Dir = dir
	p.ImportPath = f[1]
	p.Root = f[2]
	p.Goroot = f[3] == "true"
	return nil
}

func equal(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	for i, xi := range x {
		if xi != y[i] {
			return false
		}
	}
	return true
}

// hasGoFiles reports whether dir contains any files with names ending in .go.
// For a vendor check we must exclude directories that contain no .go files.
// Otherwise it is not possible to vendor just a/b/c and still import the
// non-vendored a/b. See golang.org/issue/13832.
func hasGoFiles(ctxt *Context, dir string) bool {
	ents, _ := ctxt.readDir(dir)
	for _, ent := range ents {
		if !ent.IsDir() && strings.HasSuffix(ent.Name(), ".go") {
			return true
		}
	}
	return false
}

func findImportComment(data []byte) (s string, line int) {
	// expect keyword package
	word, data := parseWord(data)
	if string(word) != "package" {
		return "", 0
	}

	// expect package name
	_, data = parseWord(data)

	// now ready for import comment, a // or /* */ comment
	// beginning and ending on the current line.
	for len(data) > 0 && (data[0] == ' ' || data[0] == '\t' || data[0] == '\r') {
		data = data[1:]
	}

	var comment []byte
	switch {
	case bytes.HasPrefix(data, slashSlash):
		comment, _, _ = bytes.Cut(data[2:], newline)
	case bytes.HasPrefix(data, slashStar):
		var ok bool
		comment, _, ok = bytes.Cut(data[2:], starSlash)
		if !ok {
			// malformed comment
			return "", 0
		}
		if bytes.Contains(comment, newline) {
			return "", 0
		}
	}
	comment = bytes.TrimSpace(comment)

	// split comment into `import`, `"pkg"`
	word, arg := parseWord(comment)
	if string(word) != "import" {
		return "", 0
	}

	line = 1 + bytes.Count(data[:cap(data)-cap(arg)], newline)
	return strings.TrimSpace(string(arg)), line
}

var (
	slashSlash = []byte("//")
	slashStar  = []byte("/*")
	starSlash  = []byte("*/")
	newline    = []byte("\n")
)

// skipSpaceOrComment returns data with any leading spaces or comments removed.
func skipSpaceOrComment(data []byte) []byte {
	for len(data) > 0 {
		switch data[0] {
		case ' ', '\t', '\r', '\n':
			data = data[1:]
			continue
		case '/':
			if bytes.HasPrefix(data, slashSlash) {
				i := bytes.Index(data, newline)
				if i < 0 {
					return nil
				}
				data = data[i+1:]
				continue
			}
			if bytes.HasPrefix(data, slashStar) {
				data = data[2:]
				i := bytes.Index(data, starSlash)
				if i < 0 {
					return nil
				}
				data = data[i+2:]
				continue
			}
		}
		break
	}
	return data
}

// parseWord skips any leading spaces or comments in data
// and then parses the beginning of data as an identifier or keyword,
// returning that word and what remains after the word.
func parseWord(data []byte) (word, rest []byte) {
	data = skipSpaceOrComment(data)

	// Parse past leading word characters.
	rest = data
	for {
		r, size := utf8.DecodeRune(rest)
		if unicode.IsLetter(r) || '0' <= r && r <= '9' || r == '_' {
			rest = rest[size:]
			continue
		}
		break
	}

	word = data[:len(data)-len(rest)]
	if len(word) == 0 {
		return nil, nil
	}

	return word, rest
}

// MatchFile reports whether the file with the given name in the given directory
// matches the context and would be included in a [Package] created by [ImportDir]
// of that directory.
//
// MatchFile considers the name of the file and may use ctxt.OpenFile to
// read some or all of the file's content.
func (ctxt *Context) MatchFile(dir, name string) (match bool, err error) {
	info, err := ctxt.matchFile(dir, name, nil, nil, nil)
	return info != nil, err
}

var dummyPkg Package

// fileInfo records information learned about a file included in a build.
type fileInfo struct {
	name       string // full name including dir
	header     []byte
	fset       *token.FileSet
	parsed     *ast.File
	parseErr   error
	imports    []fileImport
	embeds     []fileEmbed
	directives []Directive
}

type fileImport struct {
	path string
	pos  token.Pos
	doc  *ast.CommentGroup
}

type fileEmbed struct {
	pattern string
	pos     token.Position
}

// matchFile determines whether the file with the given name in the given directory
// should be included in the package being constructed.
// If the file should be included, matchFile returns a non-nil *fileInfo (and a nil error).
// Non-nil errors are reserved for unexpected problems.
//
// If name denotes a Go program, matchFile reads until the end of the
// imports and returns that section of the file in the fileInfo's header field,
// even though it only considers text until the first non-comment
// for go:build lines.
//
// If allTags is non-nil, matchFile records any encountered build tag
// by setting allTags[tag] = true.
func (ctxt *Context) matchFile(dir, name string, allTags map[string]bool, binaryOnly *bool, fset *token.FileSet) (*fileInfo, error) {
	if strings.HasPrefix(name, "_") ||
		strings.HasPrefix(name, ".") {
		return nil, nil
	}

	i := strings.LastIndex(name, ".")
	if i < 0 {
		i = len(name)
	}
	ext := name[i:]

	if ext != ".go" && fileListForExt(&dummyPkg, ext) == nil {
		// skip
		return nil, nil
	}

	if !ctxt.goodOSArchFile(name, allTags) && !ctxt.UseAllFiles {
		return nil, nil
	}

	info := &fileInfo{name: ctxt.joinPath(dir, name), fset: fset}
	if ext == ".syso" {
		// binary, no reading
		return info, nil
	}

	f, err := ctxt.openFile(info.name)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(name, ".go") {
		err = readGoInfo(f, info)
		if strings.HasSuffix(name, "_test.go") {
			binaryOnly = nil // ignore //go:binary-only-package comments in _test.go files
		}
	} else {
		binaryOnly = nil // ignore //go:binary-only-package comments in non-Go sources
		info.header, err = readComments(f)
	}
	f.Close()
	if err != nil {
		return info, fmt.Errorf("read %s: %v", info.name, err)
	}

	// Look for go:build comments to accept or reject the file.
	ok, sawBinaryOnly, err := ctxt.shouldBuild(info.header, allTags)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if !ok && !ctxt.UseAllFiles {
		return nil, nil
	}

	if binaryOnly != nil && sawBinaryOnly {
		*binaryOnly = true
	}

	return info, nil
}

func cleanDecls(m map[string][]token.Position) ([]string, map[string][]token.Position) {
	all := make([]string, 0, len(m))
	for path := range m {
		all = append(all, path)
	}
	slices.Sort(all)
	return all, m
}

// Import is shorthand for Default.Import.
func Import(path, srcDir string, mode ImportMode) (*Package, error) {
	return Default.Import(path, srcDir, mode)
}

// ImportDir is shorthand for Default.ImportDir.
func ImportDir(dir string, mode ImportMode) (*Package, error) {
	return Default.ImportDir(dir, mode)
}

var (
	plusBuild = []byte("+build")

	goBuildComment = []byte("//go:build")

	errMultipleGoBuild = errors.New("multiple //go:build comments")
)

func isGoBuildComment(line []byte) bool {
	if !bytes.HasPrefix(line, goBuildComment) {
		return false
	}
	line = bytes.TrimSpace(line)
	rest := line[len(goBuildComment):]
	return len(rest) == 0 || len(bytes.TrimSpace(rest)) < len(rest)
}

// Special comment denoting a binary-only package.
// See https://golang.org/design/2775-binary-only-packages
// for more about the design of binary-only packages.
var binaryOnlyComment = []byte("//go:binary-only-package")

// shouldBuild reports whether it is okay to use this file,
// The rule is that in the file's leading run of // comments
// and blank lines, which must be followed by a blank line
// (to avoid including a Go package clause doc comment),
// lines beginning with '//go:build' are taken as build directives.
//
// The file is accepted only if each such line lists something
// matching the file. For example:
//
//	//go:build windows linux
//
// marks the file as applicable only on Windows and Linux.
//
// For each build tag it consults, shouldBuild sets allTags[tag] = true.
//
// shouldBuild reports whether the file should be built
// and whether a //go:binary-only-package comment was found.
func (ctxt *Context) shouldBuild(content []byte, allTags map[string]bool) (shouldBuild, binaryOnly bool, err error) {
	// Identify leading run of // comments and blank lines,
	// which must be followed by a blank line.
	// Also identify any //go:build comments.
	content, goBuild, sawBinaryOnly, err := parseFileHeader(content)
	if err != nil {
		return false, false, err
	}

	// If //go:build line is present, it controls.
	// Otherwise fall back to +build processing.
	switch {
	case goBuild != nil:
		x, err := constraint.Parse(string(goBuild))
		if err != nil {
			return false, false, fmt.Errorf("parsing //go:build line: %v", err)
		}
		shouldBuild = ctxt.eval(x, allTags)

	default:
		shouldBuild = true
		p := content
		for len(p) > 0 {
			line := p
			if i := bytes.IndexByte(line, '\n'); i >= 0 {
				line, p = line[:i], p[i+1:]
			} else {
				p = p[len(p):]
			}
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, slashSlash) || !bytes.Contains(line, plusBuild) {
				continue
			}
			text := string(line)
			if !constraint.IsPlusBuild(text) {
				continue
			}
			if x, err := constraint.Parse(text); err == nil {
				if !ctxt.eval(x, allTags) {
					shouldBuild = false
				}
			}
		}
	}

	return shouldBuild, sawBinaryOnly, nil
}

// parseFileHeader should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bazelbuild/bazel-gazelle
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname parseFileHeader
func parseFileHeader(content []byte) (trimmed, goBuild []byte, sawBinaryOnly bool, err error) {
	end := 0
	p := content
	ended := false       // found non-blank, non-// line, so stopped accepting //go:build lines
	inSlashStar := false // in /* */ comment

Lines:
	for len(p) > 0 {
		line := p
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line, p = line[:i], p[i+1:]
		} else {
			p = p[len(p):]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 && !ended { // Blank line
			// Remember position of most recent blank line.
			// When we find the first non-blank, non-// line,
			// this "end" position marks the latest file position
			// where a //go:build line can appear.
			// (It must appear _before_ a blank line before the non-blank, non-// line.
			// Yes, that's confusing, which is part of why we moved to //go:build lines.)
			// Note that ended==false here means that inSlashStar==false,
			// since seeing a /* would have set ended==true.
			end = len(content) - len(p)
			continue Lines
		}
		if !bytes.HasPrefix(line, slashSlash) { // Not comment line
			ended = true
		}

		if !inSlashStar && isGoBuildComment(line) {
			if goBuild != nil {
				return nil, nil, false, errMultipleGoBuild
			}
			goBuild = line
		}
		if !inSlashStar && bytes.Equal(line, binaryOnlyComment) {
			sawBinaryOnly = true
		}

	Comments:
		for len(line) > 0 {
			if inSlashStar {
				if i := bytes.Index(line, starSlash); i >= 0 {
					inSlashStar = false
					line = bytes.TrimSpace(line[i+len(starSlash):])
					continue Comments
				}
				continue Lines
			}
			if bytes.HasPrefix(line, slashSlash) {
				continue Lines
			}
			if bytes.HasPrefix(line, slashStar) {
				inSlashStar = true
				line = bytes.TrimSpace(line[len(slashStar):])
				continue Comments
			}
			// Found non-comment text.
			break Lines
		}
	}

	return content[:end], goBuild, sawBinaryOnly, nil
}

// saveCgo saves the information from the #cgo lines in the import "C" comment.
// These lines set CFLAGS, CPPFLAGS, CXXFLAGS and LDFLAGS and pkg-config directives
// that affect the way cgo's C code is built.
func (ctxt *Context) saveCgo(filename string, di *Package, cg *ast.CommentGroup) error {
	text := cg.Text()
	for _, line := range strings.Split(text, "\n") {
		orig := line

		// Line is
		//	#cgo [GOOS/GOARCH...] LDFLAGS: stuff
		//
		line = strings.TrimSpace(line)
		if len(line) < 5 || line[:4] != "#cgo" || (line[4] != ' ' && line[4] != '\t') {
			continue
		}

		// #cgo (nocallback|noescape) <function name>
		if fields := strings.Fields(line); len(fields) == 3 && (fields[1] == "nocallback" || fields[1] == "noescape") {
			continue
		}

		// Split at colon.
		line, argstr, ok := strings.Cut(strings.TrimSpace(line[4:]), ":")
		if !ok {
			return fmt.Errorf("%s: invalid #cgo line: %s", filename, orig)
		}

		// Parse GOOS/GOARCH stuff.
		f := strings.Fields(line)
		if len(f) < 1 {
			return fmt.Errorf("%s: invalid #cgo line: %s", filename, orig)
		}

		cond, verb := f[:len(f)-1], f[len(f)-1]
		if len(cond) > 0 {
			ok := false
			for _, c := range cond {
				if ctxt.matchAuto(c, nil) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}

		args, err := splitQuoted(argstr)
		if err != nil {
			return fmt.Errorf("%s: invalid #cgo line: %s", filename, orig)
		}
		for i, arg := range args {
			if arg, ok = expandSrcDir(arg, di.Dir); !ok {
				return fmt.Errorf("%s: malformed #cgo argument: %s", filename, arg)
			}
			args[i] = arg
		}

		switch verb {
		case "CFLAGS", "CPPFLAGS", "CXXFLAGS", "FFLAGS", "LDFLAGS":
			// Change relative paths to absolute.
			ctxt.makePathsAbsolute(args, di.Dir)
		}

		switch verb {
		case "CFLAGS":
			di.CgoCFLAGS = append(di.CgoCFLAGS, args...)
		case "CPPFLAGS":
			di.CgoCPPFLAGS = append(di.CgoCPPFLAGS, args...)
		case "CXXFLAGS":
			di.CgoCXXFLAGS = append(di.CgoCXXFLAGS, args...)
		case "FFLAGS":
			di.CgoFFLAGS = append(di.CgoFFLAGS, args...)
		case "LDFLAGS":
			di.CgoLDFLAGS = append(di.CgoLDFLAGS, args...)
		case "pkg-config":
			di.CgoPkgConfig = append(di.CgoPkgConfig, args...)
		default:
			return fmt.Errorf("%s: invalid #cgo verb: %s", filename, orig)
		}
	}
	return nil
}

// expandSrcDir expands any occurrence of ${SRCDIR}, making sure
// the result is safe for the shell.
func expandSrcDir(str string, srcdir string) (string, bool) {
	// "\" delimited paths cause safeCgoName to fail
	// so convert native paths with a different delimiter
	// to "/" before starting (eg: on windows).
	srcdir = filepath.ToSlash(srcdir)

	chunks := strings.Split(str, "${SRCDIR}")
	if len(chunks) < 2 {
		return str, safeCgoName(str)
	}
	ok := true
	for _, chunk := range chunks {
		ok = ok && (chunk == "" || safeCgoName(chunk))
	}
	ok = ok && (srcdir == "" || safeCgoName(srcdir))
	res := strings.Join(chunks, srcdir)
	return res, ok && res != ""
}

// makePathsAbsolute looks for compiler options that take paths and
// makes them absolute. We do this because through the 1.8 release we
// ran the compiler in the package directory, so any relative -I or -L
// options would be relative to that directory. In 1.9 we changed to
// running the compiler in the build directory, to get consistent
// build results (issue #19964). To keep builds working, we change any
// relative -I or -L options to be absolute.
//
// Using filepath.IsAbs and filepath.Join here means the results will be
// different on different systems, but that's OK: -I and -L options are
// inherently system-dependent.
func (ctxt *Context) makePathsAbsolute(args []string, srcDir string) {
	nextPath := false
	for i, arg := range args {
		if nextPath {
			if !filepath.IsAbs(arg) {
				args[i] = filepath.Join(srcDir, arg)
			}
			nextPath = false
		} else if strings.HasPrefix(arg, "-I") || strings.HasPrefix(arg, "-L") {
			if len(arg) == 2 {
				nextPath = true
			} else {
				if !filepath.IsAbs(arg[2:]) {
					args[i] = arg[:2] + filepath.Join(srcDir, arg[2:])
				}
			}
		}
	}
}

// NOTE: $ is not safe for the shell, but it is allowed here because of linker options like -Wl,$ORIGIN.
// We never pass these arguments to a shell (just to programs we construct argv for), so this should be okay.
// See golang.org/issue/6038.
// The @ is for OS X. See golang.org/issue/13720.
// The % is for Jenkins. See golang.org/issue/16959.
// The ! is because module paths may use them. See golang.org/issue/26716.
// The ~ and ^ are for sr.ht. See golang.org/issue/32260.
const safeString = "+-.,/0123456789=ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz:$@%! ~^"

func safeCgoName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < utf8.RuneSelf && strings.IndexByte(safeString, c) < 0 {
			return false
		}
	}
	return true
}

// splitQuoted splits the string s around each instance of one or more consecutive
// white space characters while taking into account quotes and escaping, and
// returns an array of substrings of s or an empty list if s contains only white space.
// Single quotes and double quotes are recognized to prevent splitting within the
// quoted region, and are removed from the resulting substrings. If a quote in s
// isn't closed err will be set and r will have the unclosed argument as the
// last element. The backslash is used for escaping.
//
// For example, the following string:
//
//	a b:"c d" 'e''f'  "g\""
//
// Would be parsed as:
//
//	[]string{"a", "b:c d", "ef", `g"`}
func splitQuoted(s string) (r []string, err error) {
	var args []string
	arg := make([]rune, len(s))
	escaped := false
	quoted := false
	quote := '\x00'
	i := 0
	for _, rune := range s {
		switch {
		case escaped:
			escaped = false
		case rune == '\\':
			escaped = true
			continue
		case quote != '\x00':
			if rune == quote {
				quote = '\x00'
				continue
			}
		case rune == '"' || rune == '\'':
			quoted = true
			quote = rune
			continue
		case unicode.IsSpace(rune):
			if quoted || i > 0 {
				quoted = false
				args = append(args, string(arg[:i]))
				i = 0
			}
			continue
		}
		arg[i] = rune
		i++
	}
	if quoted || i > 0 {
		args = append(args, string(arg[:i]))
	}
	if quote != 0 {
		err = errors.New("unclosed quote")
	} else if escaped {
		err = errors.New("unfinished escaping")
	}
	return args, err
}

// matchAuto interprets text as either a +build or //go:build expression (whichever works),
// reporting whether the expression matches the build context.
//
// matchAuto is only used for testing of tag evaluation
// and in #cgo lines, which accept either syntax.
func (ctxt *Context) matchAuto(text string, allTags map[string]bool) bool {
	if strings.ContainsAny(text, "&|()") {
		text = "//go:build " + text
	} else {
		text = "// +build " + text
	}
	x, err := constraint.Parse(text)
	if err != nil {
		return false
	}
	return ctxt.eval(x, allTags)
}

func (ctxt *Context) eval(x constraint.Expr, allTags map[string]bool) bool {
	return x.Eval(func(tag string) bool { return ctxt.matchTag(tag, allTags) })
}

// matchTag reports whether the name is one of:
//
//	cgo (if cgo is enabled)
//	$GOOS
//	$GOARCH
//	ctxt.Compiler
//	linux (if GOOS = android)
//	solaris (if GOOS = illumos)
//	darwin (if GOOS = ios)
//	unix (if this is a Unix GOOS)
//	boringcrypto (if GOEXPERIMENT=boringcrypto is enabled)
//	tag (if tag is listed in ctxt.BuildTags, ctxt.ToolTags, or ctxt.ReleaseTags)
//
// It records all consulted tags in allTags.
func (ctxt *Context) matchTag(name string, allTags map[string]bool) bool {
	if allTags != nil {
		allTags[name] = true
	}

	// special tags
	if ctxt.CgoEnabled && name == "cgo" {
		return true
	}
	if name == ctxt.GOOS || name == ctxt.GOARCH || name == ctxt.Compiler {
		return true
	}
	if ctxt.GOOS == "android" && name == "linux" {
		return true
	}
	if ctxt.GOOS == "illumos" && name == "solaris" {
		return true
	}
	if ctxt.GOOS == "ios" && name == "darwin" {
		return true
	}
	if name == "unix" && syslist.UnixOS[ctxt.GOOS] {
		return true
	}
	if name == "boringcrypto" {
		name = "goexperiment.boringcrypto" // boringcrypto is an old name for goexperiment.boringcrypto
	}

	// other tags
	for _, tag := range ctxt.BuildTags {
		if tag == name {
			return true
		}
	}
	for _, tag := range ctxt.ToolTags {
		if tag == name {
			return true
		}
	}
	for _, tag := range ctxt.ReleaseTags {
		if tag == name {
			return true
		}
	}

	return false
}

// goodOSArchFile returns false if the name contains a $GOOS or $GOARCH
// suffix which does not match the current system.
// The recognized name formats are:
//
//	name_$(GOOS).*
//	name_$(GOARCH).*
//	name_$(GOOS)_$(GOARCH).*
//	name_$(GOOS)_test.*
//	name_$(GOARCH)_test.*
//	name_$(GOOS)_$(GOARCH)_test.*
//
// Exceptions:
// if GOOS=android, then files with GOOS=linux are also matched.
// if GOOS=illumos, then files with GOOS=solaris are also matched.
// if GOOS=ios, then files with GOOS=darwin are also matched.
func (ctxt *Context) goodOSArchFile(name string, allTags map[string]bool) bool {
	name, _, _ = strings.Cut(name, ".")

	// Before Go 1.4, a file called "linux.go" would be equivalent to having a
	// build tag "linux" in that file. For Go 1.4 and beyond, we require this
	// auto-tagging to apply only to files with a non-empty prefix, so
	// "foo_linux.go" is tagged but "linux.go" is not. This allows new operating
	// systems, such as android, to arrive without breaking existing code with
	// innocuous source code in "android.go". The easiest fix: cut everything
	// in the name before the initial _.
	i := strings.Index(name, "_")
	if i < 0 {
		return true
	}
	name = name[i:] // ignore everything before first _

	l := strings.Split(name, "_")
	if n := len(l); n > 0 && l[n-1] == "test" {
		l = l[:n-1]
	}
	n := len(l)
	if n >= 2 && syslist.KnownOS[l[n-2]] && syslist.KnownArch[l[n-1]] {
		if allTags != nil {
			// In case we short-circuit on l[n-1].
			allTags[l[n-2]] = true
		}
		return ctxt.matchTag(l[n-1], allTags) && ctxt.matchTag(l[n-2], allTags)
	}
	if n >= 1 && (syslist.KnownOS[l[n-1]] || syslist.KnownArch[l[n-1]]) {
		return ctxt.matchTag(l[n-1], allTags)
	}
	return true
}

// ToolDir is the directory containing build tools.
var ToolDir = getToolDir()

// IsLocalImport reports whether the import path is
// a local import path, like ".", "..", "./foo", or "../foo".
func IsLocalImport(path string) bool {
	return path == "." || path == ".." ||
		strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../")
}

// ArchChar returns "?" and an error.
// In earlier versions of Go, the returned string was used to derive
// the compiler and linker tool names, the default object file suffix,
// and the default linker output name. As of Go 1.5, those strings
// no longer vary by architecture; they are compile, link, .o, and a.out, respectively.
func ArchChar(goarch string) (string, error) {
	return "?", errors.New("architecture letter no longer used")
}

"""




```