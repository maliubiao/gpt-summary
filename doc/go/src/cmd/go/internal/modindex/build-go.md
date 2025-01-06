Response: The user wants to understand the functionality of the provided Go code snippet from `go/src/cmd/go/internal/modindex/build.go`.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The package name `modindex` and the file name `build.go` suggest this code is related to building or indexing modules in Go. The initial comment mentions it's a modified copy of `go/build/build.go`, hinting at its role in understanding Go build contexts and package structures.

2. **Analyze Key Structures:** The `Context` struct is central. Its fields define the environment in which Go code is built. Understanding these fields is crucial. The `FileInfo` struct seems to hold information about individual Go files.

3. **Examine Key Functions:**
    * Functions like `getFileInfo` and `getConstraints` are likely responsible for extracting information from Go source files (imports, build constraints, etc.).
    * Functions related to `Context` (like `gopath`, `matchTag`, `goodOSArchFile`) deal with environment specifics and build decisions.
    * Functions like `saveCgo` handle Cgo directives.
    * Helper functions like `parseWord`, `skipSpaceOrComment`, `splitQuoted` perform low-level parsing of Go source code or build tags.

4. **Infer Functionality Based on Names and Types:**
    * `GOOS`, `GOARCH`, `GOROOT`, `GOPATH`: Clearly related to Go's environment variables.
    * `BuildTags`, `ToolTags`, `ReleaseTags`: Control conditional compilation.
    * `JoinPath`, `SplitPathList`, `IsDir`, `OpenFile`, `ReadDir`: Abstract the file system interactions, allowing for custom implementations.
    * `NoGoError`, `MultiplePackageError`: Define specific error conditions during package discovery.
    * `fileImport`, `fileEmbed`: Data structures to store parsed import and embed directives.

5. **Connect the Dots:**  The `Context` provides the environment, and functions like `getFileInfo` and `getConstraints` use this context to parse individual files. This information is likely used to build an index of modules, as the package name suggests.

6. **Identify Key Go Features:** The code heavily interacts with:
    * **Build Tags (`//go:build`, `// +build`):**  Conditional compilation.
    * **Cgo (`#cgo`):** Interfacing with C code.
    * **`go/ast` and `go/token`:** Parsing Go source code.
    * **`go/build`:**  The original package this code is based on, which deals with Go package building.
    * **File system operations:** Reading and analyzing files.

7. **Construct Examples:**  For the identified features, create simple Go code snippets demonstrating their usage in relation to the functions in the provided code. This involves showing how build tags affect file inclusion, how Cgo directives work, and how import comments are parsed.

8. **Address Command-Line Arguments (if applicable):** In this specific snippet, there's no direct command-line argument parsing within the shown code. However, the `Context` struct's fields are often populated based on command-line flags passed to the `go` command. It's important to highlight this connection.

9. **Identify Potential User Errors:**  Think about common mistakes users make when working with the features this code handles: incorrect build tag syntax, issues with Cgo setup, incorrect GOPATH, etc.

10. **Structure the Answer:**  Organize the findings into clear sections addressing the user's requests: functionality, feature implementation (with code examples), command-line argument handling (even if indirect), and common mistakes.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the `modindex` aspect.
* **Correction:** Realize the strong link to `go/build` and the core Go build process is essential to understanding.
* **Initial thought:**  Only describe the functions' purpose.
* **Refinement:**  Provide concrete examples of how these functions interact with Go language features.
* **Initial thought:**  Ignore the `Context` struct details.
* **Refinement:**  Recognize the `Context` is the central configuration and needs thorough explanation.

By following this systematic approach, combining code analysis with knowledge of Go's build system, and anticipating user needs, a comprehensive and helpful answer can be generated.
这段代码是 Go 语言 `cmd/go` 工具中 `modindex` 包的一部分，主要负责**构建模块索引**。 它是 `go/build` 包的一个轻微修改版本，移除了未使用的部分。模块索引是为了更高效地查找和管理 Go 模块信息而创建的。

以下是它的主要功能：

1. **定义构建上下文 (`Context`):**  `Context` 结构体定义了构建操作的上下文环境，包括目标操作系统 (`GOOS`)、目标架构 (`GOARCH`)、Go 根目录 (`GOROOT`)、Go 工作路径 (`GOPATH`)、工作目录 (`Dir`)、Cgo 是否启用 (`CgoEnabled`) 以及构建标签 (`BuildTags`, `ToolTags`, `ReleaseTags`) 等信息。这个上下文用于在构建过程中做出决策，例如选择哪些文件进行编译。

2. **读取和解析 Go 源文件信息 (`getFileInfo`):**  `getFileInfo` 函数读取指定的 Go 源文件，并提取出构建模块索引所需的信息，包括：
    * 文件内容头部 (用于查找 `//go:build` 或 `// +build` 构建约束)。
    * 抽象语法树 (`ast.File`)，用于分析导入 (`import`) 和嵌入 (`embed`) 声明。
    * 解析错误。
    * 导入路径 (`fileImport`)。
    * 嵌入模式 (`fileEmbed`)。
    * 指令 (`build.Directive`)。
    * 二进制专用标记 (`binaryOnly`)。
    * `//go:build` 构建约束字符串。
    * `// +build` 构建约束字符串列表。

3. **提取构建约束 (`getConstraints`):**  `getConstraints` 函数从文件头部注释中提取 `//go:build` 和 `// +build` 构建约束。它会解析这些约束，以确定文件是否应该被当前构建上下文包含。

4. **处理 Cgo 指令 (`saveCgo`):**  `saveCgo` 函数解析 `import "C"` 注释中的 `#cgo` 指令，这些指令用于指定 C 编译器和链接器的标志（如 `CFLAGS`, `LDFLAGS` 等）以及 `pkg-config` 的配置。它会根据当前的构建上下文来应用这些指令。

5. **匹配构建标签 (`matchTag`, `matchAuto`):**  `matchTag` 函数判断一个给定的标签是否与当前的构建上下文匹配。这包括检查 `GOOS`, `GOARCH`, `Compiler` 以及用户定义的 `BuildTags`, `ToolTags`, `ReleaseTags`。 `matchAuto` 函数可以解析并评估 `//go:build` 或 `// +build` 格式的构建约束表达式。

6. **判断文件是否适用于当前操作系统和架构 (`goodOSArchFile`):**  `goodOSArchFile` 函数根据文件名中的 `_GOOS` 和 `_GOARCH` 后缀判断文件是否适用于当前的操作系统和架构。例如，`file_linux.go` 只会在 `GOOS` 为 `linux` 时被考虑。

**它是什么 Go 语言功能的实现：**

这段代码是 **Go 模块构建系统** 的一部分实现，特别是关于如何解析和理解 Go 源文件中的构建约束以及 Cgo 指令，以便正确地构建模块索引。模块索引可以帮助 `go` 命令更快地找到模块及其依赖。

**Go 代码举例说明：**

假设我们有一个名为 `myfile.go` 的文件，内容如下：

```go
//go:build linux && amd64

package mypackage

import "fmt"

func Hello() {
	fmt.Println("Hello from Linux/AMD64")
}
```

以及另一个名为 `myfile_windows.go` 的文件：

```go
//go:build windows && amd64

package mypackage

import "fmt"

func Hello() {
	fmt.Println("Hello from Windows/AMD64")
}
```

当 `modindex/build.go` 中的代码处理这些文件时，基于不同的构建上下文，它会做出不同的判断：

**假设输入 (构建上下文 1):**

```go
ctxt := &Context{
	GOOS: "linux",
	GOARCH: "amd64",
}
```

**输出 (对于 `myfile.go`):**

`getFileInfo` 会解析 `myfile.go`， `getConstraints` 会提取 `//go:build linux && amd64`。 `ctxt.matchAuto("linux && amd64", nil)` 将返回 `true`。  因此，`myfile.go` 将被认为是适用于当前上下文的文件。

**输出 (对于 `myfile_windows.go`):**

`getFileInfo` 会解析 `myfile_windows.go`， `getConstraints` 会提取 `//go:build windows && amd64`。 `ctxt.matchAuto("windows && amd64", nil)` 将返回 `false`。 因此，`myfile_windows.go` 将被排除。

**假设输入 (构建上下文 2):**

```go
ctxt := &Context{
	GOOS: "windows",
	GOARCH: "amd64",
}
```

**输出 (对于 `myfile.go`):**

`ctxt.matchAuto("linux && amd64", nil)` 将返回 `false`。 `myfile.go` 将被排除。

**输出 (对于 `myfile_windows.go`):**

`ctxt.matchAuto("windows && amd64", nil)` 将返回 `true`。 `myfile_windows.go` 将被认为是适用于当前上下文的文件。

**Cgo 的例子：**

假设有一个文件 `cgo_example.go`:

```go
package mypackage

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lmylib
import "C"
*/
import "C"

func UseCFunction() {
	// ...
}
```

当 `getFileInfo` 处理这个文件时，会调用 `saveCgo`。

**假设输入 (构建上下文):**

```go
ctxt := &Context{} // 假设 GOOS 和 GOARCH 已经设置
pkgInfo := &build.Package{Dir: "/path/to/mypackage"}
fileContent := `
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lmylib
import "C"
`
```

**输出:**

`saveCgo` 函数会解析 `#cgo` 指令，并将 `CFLAGS` 和 `LDFLAGS` 添加到 `pkgInfo` 中。

```go
// 假设 saveCgo 执行后
fmt.Println(pkgInfo.CgoCFLAGS) // 输出: [-I/usr/include]
fmt.Println(pkgInfo.CgoLDFLAGS) // 输出: [-lmylib]
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。`Context` 结构体的字段通常由 `cmd/go` 工具的其他部分填充，这些部分负责解析用户在命令行中提供的选项，例如 `-os`, `-arch`, `-tags` 等。

例如，当用户运行 `go build -os=linux -arch=amd64 -tags=integration` 时，`cmd/go` 工具会解析这些参数，并创建一个相应的 `Context` 实例，其中 `GOOS` 被设置为 "linux"，`GOARCH` 被设置为 "amd64"，`BuildTags` 包含 "integration"。然后，这个 `Context` 实例会被传递给 `modindex` 包中的函数，以进行模块索引的构建。

**使用者易犯错的点：**

1. **构建标签语法错误：** 用户可能在 `//go:build` 或 `// +build` 注释中使用错误的语法，导致构建工具无法正确解析。例如，忘记使用 `&&` 或 `||` 连接多个条件，或者括号不匹配。

   ```go
   // 错误示例
   //go:build linux amd64  // 应该使用 &&
   ```

2. **Cgo 指令路径问题：** 在 `#cgo` 指令中指定的路径可能是相对路径，但在不同的构建环境下，这些相对路径的解释可能不同，导致编译失败。 最佳实践是使用绝对路径或 `${SRCDIR}` 变量。

   ```go
   // 潜在问题
   /*
   #cgo CFLAGS: -I../include // 如果构建目录不在包目录下，可能会出错
   */
   ```

3. **误解文件名后缀的含义：** 用户可能不清楚 `_GOOS` 和 `_GOARCH` 后缀的作用，导致某些文件在预期的平台上没有被编译。例如，期望 `myfile_linux.go` 在所有 Linux 系统上都编译，但忘记指定架构，或者目标架构不匹配文件名后缀。

4. **GOPATH 设置不正确：** 虽然 `modindex/build.go` 本身不直接处理 `GOPATH` 的设置，但错误的 `GOPATH` 配置会导致 `Context` 中的 `GOPATH` 字段不正确，从而影响模块的查找和构建。

这段代码是 Go 构建系统的重要组成部分，它确保了在不同的操作系统、架构和构建标签下，只有相关的代码才会被包含到最终的构建结果中，同时也处理了 C 代码的集成。理解其功能有助于开发者更好地掌握 Go 的构建过程和条件编译机制。

Prompt: 
```
这是路径为go/src/cmd/go/internal/modindex/build.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a lightly modified copy go/build/build.go with unused parts
// removed.

package modindex

import (
	"bytes"
	"cmd/go/internal/fsys"
	"cmd/go/internal/str"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/token"
	"internal/syslist"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A Context specifies the supporting context for a build.
type Context struct {
	GOARCH string // target architecture
	GOOS   string // target operating system
	GOROOT string // Go root
	GOPATH string // Go paths

	// Dir is the caller's working directory, or the empty string to use
	// the current directory of the running process. In module mode, this is used
	// to locate the main module.
	//
	// If Dir is non-empty, directories passed to Import and ImportDir must
	// be absolute.
	Dir string

	CgoEnabled  bool   // whether cgo files are included
	UseAllFiles bool   // use files regardless of //go:build lines, file names
	Compiler    string // compiler to assume when computing target paths

	// The build, tool, and release tags specify build constraints
	// that should be considered satisfied when processing +build lines.
	// Clients creating a new context may customize BuildTags, which
	// defaults to empty, but it is usually an error to customize ToolTags or ReleaseTags.
	// ToolTags defaults to build tags appropriate to the current Go toolchain configuration.
	// ReleaseTags defaults to the list of Go releases the current release is compatible with.
	// BuildTags is not set for the Default build Context.
	// In addition to the BuildTags, ToolTags, and ReleaseTags, build constraints
	// consider the values of GOARCH and GOOS as satisfied tags.
	// The last element in ReleaseTags is assumed to be the current release.
	BuildTags   []string
	ToolTags    []string
	ReleaseTags []string

	// The install suffix specifies a suffix to use in the name of the installation
	// directory. By default it is empty, but custom builds that need to keep
	// their outputs separate can set InstallSuffix to do so. For example, when
	// using the race detector, the go command uses InstallSuffix = "race", so
	// that on a Linux/386 system, packages are written to a directory named
	// "linux_386_race" instead of the usual "linux_386".
	InstallSuffix string

	// By default, Import uses the operating system's file system calls
	// to read directories and files. To read from other sources,
	// callers can set the following functions. They all have default
	// behaviors that use the local file system, so clients need only set
	// the functions whose behaviors they wish to change.

	// JoinPath joins the sequence of path fragments into a single path.
	// If JoinPath is nil, Import uses filepath.Join.
	JoinPath func(elem ...string) string

	// SplitPathList splits the path list into a slice of individual paths.
	// If SplitPathList is nil, Import uses filepath.SplitList.
	SplitPathList func(list string) []string

	// IsAbsPath reports whether path is an absolute path.
	// If IsAbsPath is nil, Import uses filepath.IsAbs.
	IsAbsPath func(path string) bool

	// IsDir reports whether the path names a directory.
	// If IsDir is nil, Import calls os.Stat and uses the result's IsDir method.
	IsDir func(path string) bool

	// HasSubdir reports whether dir is lexically a subdirectory of
	// root, perhaps multiple levels below. It does not try to check
	// whether dir exists.
	// If so, HasSubdir sets rel to a slash-separated path that
	// can be joined to root to produce a path equivalent to dir.
	// If HasSubdir is nil, Import uses an implementation built on
	// filepath.EvalSymlinks.
	HasSubdir func(root, dir string) (rel string, ok bool)

	// ReadDir returns a slice of fs.FileInfo, sorted by Name,
	// describing the content of the named directory.
	// If ReadDir is nil, Import uses ioutil.ReadDir.
	ReadDir func(dir string) ([]fs.FileInfo, error)

	// OpenFile opens a file (not a directory) for reading.
	// If OpenFile is nil, Import uses os.Open.
	OpenFile func(path string) (io.ReadCloser, error)
}

// joinPath calls ctxt.JoinPath (if not nil) or else filepath.Join.
func (ctxt *Context) joinPath(elem ...string) string {
	if f := ctxt.JoinPath; f != nil {
		return f(elem...)
	}
	return filepath.Join(elem...)
}

// splitPathList calls ctxt.SplitPathList (if not nil) or else filepath.SplitList.
func (ctxt *Context) splitPathList(s string) []string {
	if f := ctxt.SplitPathList; f != nil {
		return f(s)
	}
	return filepath.SplitList(s)
}

// isAbsPath calls ctxt.IsAbsPath (if not nil) or else filepath.IsAbs.
func (ctxt *Context) isAbsPath(path string) bool {
	if f := ctxt.IsAbsPath; f != nil {
		return f(path)
	}
	return filepath.IsAbs(path)
}

// isDir calls ctxt.IsDir (if not nil) or else uses fsys.Stat.
func isDir(path string) bool {
	fi, err := fsys.Stat(path)
	return err == nil && fi.IsDir()
}

// hasSubdir calls ctxt.HasSubdir (if not nil) or else uses
// the local file system to answer the question.
func (ctxt *Context) hasSubdir(root, dir string) (rel string, ok bool) {
	if f := ctxt.HasSubdir; f != nil {
		return f(root, dir)
	}

	// Try using paths we received.
	if rel, ok = hasSubdir(root, dir); ok {
		return
	}

	// Try expanding symlinks and comparing
	// expanded against unexpanded and
	// expanded against expanded.
	rootSym, _ := filepath.EvalSymlinks(root)
	dirSym, _ := filepath.EvalSymlinks(dir)

	if rel, ok = hasSubdir(rootSym, dir); ok {
		return
	}
	if rel, ok = hasSubdir(root, dirSym); ok {
		return
	}
	return hasSubdir(rootSym, dirSym)
}

// hasSubdir reports if dir is within root by performing lexical analysis only.
func hasSubdir(root, dir string) (rel string, ok bool) {
	root = str.WithFilePathSeparator(filepath.Clean(root))
	dir = filepath.Clean(dir)
	if !strings.HasPrefix(dir, root) {
		return "", false
	}
	return filepath.ToSlash(dir[len(root):]), true
}

// gopath returns the list of Go path directories.
func (ctxt *Context) gopath() []string {
	var all []string
	for _, p := range ctxt.splitPathList(ctxt.GOPATH) {
		if p == "" || p == ctxt.GOROOT {
			// Empty paths are uninteresting.
			// If the path is the GOROOT, ignore it.
			// People sometimes set GOPATH=$GOROOT.
			// Do not get confused by this common mistake.
			continue
		}
		if strings.HasPrefix(p, "~") {
			// Path segments starting with ~ on Unix are almost always
			// users who have incorrectly quoted ~ while setting GOPATH,
			// preventing it from expanding to $HOME.
			// The situation is made more confusing by the fact that
			// bash allows quoted ~ in $PATH (most shells do not).
			// Do not get confused by this, and do not try to use the path.
			// It does not exist, and printing errors about it confuses
			// those users even more, because they think "sure ~ exists!".
			// The go command diagnoses this situation and prints a
			// useful error.
			// On Windows, ~ is used in short names, such as c:\progra~1
			// for c:\program files.
			continue
		}
		all = append(all, p)
	}
	return all
}

var defaultToolTags, defaultReleaseTags []string

// NoGoError is the error used by Import to describe a directory
// containing no buildable Go source files. (It may still contain
// test files, files hidden by build tags, and so on.)
type NoGoError struct {
	Dir string
}

func (e *NoGoError) Error() string {
	return "no buildable Go source files in " + e.Dir
}

// MultiplePackageError describes a directory containing
// multiple buildable Go source files for multiple packages.
type MultiplePackageError struct {
	Dir      string   // directory containing files
	Packages []string // package names found
	Files    []string // corresponding files: Files[i] declares package Packages[i]
}

func (e *MultiplePackageError) Error() string {
	// Error string limited to two entries for compatibility.
	return fmt.Sprintf("found packages %s (%s) and %s (%s) in %s", e.Packages[0], e.Files[0], e.Packages[1], e.Files[1], e.Dir)
}

func nameExt(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return name[i:]
}

func fileListForExt(p *build.Package, ext string) *[]string {
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

var errNoModules = errors.New("not using modules")

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

var dummyPkg build.Package

// fileInfo records information learned about a file included in a build.
type fileInfo struct {
	name       string // full name including dir
	header     []byte
	fset       *token.FileSet
	parsed     *ast.File
	parseErr   error
	imports    []fileImport
	embeds     []fileEmbed
	directives []build.Directive

	// Additional fields added to go/build's fileinfo for the purposes of the modindex package.
	binaryOnly           bool
	goBuildConstraint    string
	plusBuildConstraints []string
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

var errNonSource = errors.New("non source file")

// getFileInfo extracts the information needed from each go file for the module
// index.
//
// If Name denotes a Go program, matchFile reads until the end of the
// Imports and returns that section of the file in the FileInfo's Header field,
// even though it only considers text until the first non-comment
// for +build lines.
//
// getFileInfo will return errNonSource if the file is not a source or object
// file and shouldn't even be added to IgnoredFiles.
func getFileInfo(dir, name string, fset *token.FileSet) (*fileInfo, error) {
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
		return nil, errNonSource
	}

	info := &fileInfo{name: filepath.Join(dir, name), fset: fset}
	if ext == ".syso" {
		// binary, no reading
		return info, nil
	}

	f, err := fsys.Open(info.name)
	if err != nil {
		return nil, err
	}

	// TODO(matloob) should we decide whether to ignore binary only here or earlier
	// when we create the index file?
	var ignoreBinaryOnly bool
	if strings.HasSuffix(name, ".go") {
		err = readGoInfo(f, info)
		if strings.HasSuffix(name, "_test.go") {
			ignoreBinaryOnly = true // ignore //go:binary-only-package comments in _test.go files
		}
	} else {
		info.header, err = readComments(f)
	}
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("read %s: %v", info.name, err)
	}

	// Look for +build comments to accept or reject the file.
	info.goBuildConstraint, info.plusBuildConstraints, info.binaryOnly, err = getConstraints(info.header)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}

	if ignoreBinaryOnly && info.binaryOnly {
		info.binaryOnly = false // override info.binaryOnly
	}

	return info, nil
}

func cleanDecls(m map[string][]token.Position) ([]string, map[string][]token.Position) {
	all := make([]string, 0, len(m))
	for path := range m {
		all = append(all, path)
	}
	sort.Strings(all)
	return all, m
}

var (
	bSlashSlash = []byte(slashSlash)
	bStarSlash  = []byte(starSlash)
	bSlashStar  = []byte(slashStar)
	bPlusBuild  = []byte("+build")

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

func getConstraints(content []byte) (goBuild string, plusBuild []string, binaryOnly bool, err error) {
	// Identify leading run of // comments and blank lines,
	// which must be followed by a blank line.
	// Also identify any //go:build comments.
	content, goBuildBytes, sawBinaryOnly, err := parseFileHeader(content)
	if err != nil {
		return "", nil, false, err
	}

	// If //go:build line is present, it controls, so no need to look for +build .
	// Otherwise, get plusBuild constraints.
	if goBuildBytes == nil {
		p := content
		for len(p) > 0 {
			line := p
			if i := bytes.IndexByte(line, '\n'); i >= 0 {
				line, p = line[:i], p[i+1:]
			} else {
				p = p[len(p):]
			}
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, bSlashSlash) || !bytes.Contains(line, bPlusBuild) {
				continue
			}
			text := string(line)
			if !constraint.IsPlusBuild(text) {
				continue
			}
			plusBuild = append(plusBuild, text)
		}
	}

	return string(goBuildBytes), plusBuild, sawBinaryOnly, nil
}

func parseFileHeader(content []byte) (trimmed, goBuild []byte, sawBinaryOnly bool, err error) {
	end := 0
	p := content
	ended := false       // found non-blank, non-// line, so stopped accepting // +build lines
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
			// where a // +build line can appear.
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
			if bytes.HasPrefix(line, bSlashSlash) {
				continue Lines
			}
			if bytes.HasPrefix(line, bSlashStar) {
				inSlashStar = true
				line = bytes.TrimSpace(line[len(bSlashStar):])
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
func (ctxt *Context) saveCgo(filename string, di *build.Package, text string) error {
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
//	boringcrypto
//	ctxt.Compiler
//	linux (if GOOS == android)
//	solaris (if GOOS == illumos)
//	tag (if tag is listed in ctxt.BuildTags or ctxt.ReleaseTags)
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

"""



```