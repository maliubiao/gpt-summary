Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Goal:**

The request asks for a functional summary of the provided Go code, specifically the `go/src/go/build/build.go` file. It also asks for specific inferences about Go language features, code examples, command-line handling, common mistakes, and finally, a concise summary of this first part.

**2. Initial Skim and Key Observations:**

A quick scan of the code reveals several important aspects:

* **Package `build`:** This immediately suggests functionality related to building Go projects.
* **`Context` struct:**  This appears to be a central configuration object holding build-related settings like GOOS, GOARCH, GOROOT, GOPATH, etc. The numerous function fields in `Context` related to file system operations (`JoinPath`, `IsDir`, `OpenFile`) are striking and suggest an abstraction layer over the standard `os` and `filepath` packages.
* **`Import` and `ImportDir` functions:** These names strongly imply functionality for locating and loading Go packages.
* **`Package` struct:** This likely represents the metadata and file information about a loaded Go package.
* **Error types (`NoGoError`, `MultiplePackageError`):** These indicate error conditions during package loading.
* **Build constraints and tags:** The mention of `BuildTags`, `ToolTags`, `ReleaseTags`, and the logic in `matchFile` hint at support for conditional compilation based on build constraints.
* **Cgo handling:**  The presence of `CgoEnabled` and fields like `CgoCFLAGS`, `CgoFiles` indicates support for incorporating C code.
* **Go directives:**  The `Directive` struct and fields like `Directives`, `EmbedPatterns` point to parsing and processing special comments in Go source files.
* **Vendor directory handling:** The `IgnoreVendor` flag and related logic highlight the implementation of Go's vendor directory mechanism.

**3. Deeper Dive and Functional Deduction:**

Based on the initial observations, we can start to deduce the functionalities:

* **Configuration Management:** The `Context` struct is clearly responsible for managing the build environment. This includes environment variables, target platform, and custom file system interactions. The default context initialization (`defaultContext`) confirms this.
* **Package Discovery and Loading:**  The `Import` and `ImportDir` functions are the core of package loading. They handle resolving import paths, searching through GOROOT and GOPATH, and respecting vendor directories. The error types indicate potential issues during this process.
* **Source File Analysis:** The `Package` struct contains lists of different types of source files (`.go`, `.c`, `.s`, etc.). This suggests the code analyzes the contents of package directories. The inclusion of `IgnoredGoFiles` and `InvalidGoFiles` indicates filtering and error detection.
* **Build Constraint Evaluation:** The logic around `matchFile`, along with the `BuildTags`, `ToolTags`, and `ReleaseTags` in the `Context`, signifies the implementation of Go's build constraint system.
* **Cgo Integration:** The `CgoEnabled` flag and related fields manage the inclusion of C code in Go packages.
* **Go Directive Processing:** The `Directive` struct suggests parsing and storing information from `//go:` comments. The `EmbedPatterns` field specifically points to handling the `//go:embed` directive.

**4. Illustrative Code Examples (Mental Simulation):**

At this stage, I'd mentally try to construct simple Go code snippets to demonstrate the inferred functionalities. For example:

* **`Context`:**  Imagine setting up a `Context` with custom `GOOS` and `GOARCH` to simulate cross-compilation.
* **`Import`:** Think about different import paths (standard library, GOPATH, local) and how `Import` would resolve them. Consider cases with vendor directories.
* **Build Constraints:**  Envision creating files with different `//go:build` tags and how the `Context`'s tags would affect which files are included.

**5. Command-Line Parameter Handling (Looking for Clues):**

While this specific code snippet doesn't directly handle command-line arguments, the presence of environment variable usage (like `GOPATH`, `GOROOT`, `CGO_ENABLED`) and the structure of the `Context` suggest that higher-level tools (like the `go` command) would populate the `Context` based on command-line flags and environment variables. The comments mentioning `cmd/go/internal/cfg.defaultGOPATH` reinforce this.

**6. Identifying Potential User Errors:**

Based on the functionality, I can anticipate common errors:

* **Incorrect GOPATH/GOROOT:** Setting these incorrectly is a classic Go mistake. The code itself has comments pointing to this.
* **Build constraint mismatches:**  Users might not fully understand how build tags work and create files that are unexpectedly excluded.
* **Vendor directory issues:**  Mismanaging or misunderstanding vendor directories can lead to unexpected dependency resolution.
* **Multiple packages in a directory:** The `MultiplePackageError` highlights this as a potential problem.

**7. Structuring the Answer:**

Finally, I'd organize the information into the requested sections: functionalities, Go feature implementation, code examples (with assumptions), command-line handling, common errors, and the concise summary of the first part. The focus is on clarity and providing concrete examples where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe `Context` is just about environment variables.
* **Correction:**  The function fields for file system operations indicate it's a broader abstraction layer, allowing for custom file system access.
* **Initial thought:**  `Import` just reads files.
* **Correction:** It's more about *locating* and *understanding* the structure of a Go package, including handling build constraints and vendor directories.
* **Realization:** The code *itself* doesn't directly handle command-line arguments, but it provides the *mechanism* that higher-level tools use.

By following these steps, combining code analysis with reasoning about the purpose and context of the code, we can arrive at a comprehensive and accurate understanding of the given Go code snippet.
这是对Go语言构建过程核心部分 `go/src/go/build/build.go` 的代码分析，主要关注其提供的功能。

**功能归纳 (第1部分):**

这段代码的核心功能是**定义了用于描述和加载Go包的结构体 (`Package` 和 `Context`) 以及相关的操作方法 (`Import`, `ImportDir`)**。它提供了一个可配置的环境 (`Context`)，用于查找、解析和表示Go源代码包的信息，以便后续的构建、测试或其他操作可以使用这些信息。

更具体地说，第1部分主要负责以下功能：

1. **定义构建上下文 (`Context`)**:
   -  `Context` 结构体封装了构建过程所需的各种配置信息，例如目标操作系统 (`GOOS`)、目标架构 (`GOARCH`)、Go根目录 (`GOROOT`)、Go路径 (`GOPATH`) 等。
   -  它还包含了控制构建行为的标志，如是否启用 CGO (`CgoEnabled`)，是否使用所有文件 (`UseAllFiles`)，以及编译器类型 (`Compiler`)。
   -  `Context` 还支持通过 `BuildTags`、`ToolTags` 和 `ReleaseTags` 来指定构建约束。
   -  最重要的是，`Context` 抽象了文件系统的操作，允许自定义文件访问方式，这使得 `go/build` 包可以在不同的环境中使用，而不仅仅依赖于标准的 `os` 和 `filepath` 包。

2. **定义Go包的结构 (`Package`)**:
   - `Package` 结构体用于存储一个Go包的各种元数据和文件信息，例如包名 (`Name`)、导入路径 (`ImportPath`)、源文件列表 (`GoFiles`, `CgoFiles` 等)、导入依赖 (`Imports`)、构建约束标签 (`AllTags`) 等。
   - 它还标识了包是否位于 Go 根目录 (`Goroot`)，以及编译后的对象文件路径 (`PkgObj`)。

3. **实现包的导入功能 (`Import`, `ImportDir`)**:
   - `Import` 函数是核心，它根据给定的导入路径 (`path`) 和源文件所在目录 (`srcDir`)，在指定的构建上下文 (`Context`) 中查找并加载对应的Go包。
   - 它会考虑 GOROOT、GOPATH 以及 vendor 目录来定位包。
   - `ImportDir` 是一个辅助函数，用于导入指定目录下的Go包。
   - `Import` 函数会解析 Go 源文件，提取包名、导入路径、构建约束等信息。
   - 它还会处理 `//go:embed` 指令和 import 注释。

4. **处理构建约束 (Build Constraints)**:
   -  代码中涉及到 `BuildTags`、`ToolTags` 和 `ReleaseTags`，以及 `matchFile` 函数（在后续部分），表明该代码实现了对 Go 语言构建约束的处理。这允许根据不同的构建环境选择不同的源文件。

5. **处理 CGO**:
   -  `CgoEnabled` 字段和 `CgoFiles` 等字段表明该代码能够识别和处理包含 C 代码的 Go 包。

6. **处理 `//go:embed` 指令**:
   -  `EmbedPatterns` 相关的字段表明代码能够解析并记录 `//go:embed` 指令中指定的模式。

7. **处理 import 注释**:
   -  通过 `ImportComment` 字段和相关的逻辑，代码能够解析 Go 源文件中的 import 注释 (例如 `package foo // import "example.com/foo"` )。

**Go语言功能实现推理及代码示例:**

基于这段代码，可以推断出它实现了 Go 语言的**包导入机制**和**构建约束**功能。

**包导入机制示例:**

假设我们有以下目录结构：

```
myproject/
├── main.go
└── mypackage/
    └── mypackage.go
```

`main.go` 的内容：

```go
package main

import "fmt"
import "myproject/mypackage"

func main() {
	fmt.Println(mypackage.Hello())
}
```

`mypackage/mypackage.go` 的内容：

```go
package mypackage

func Hello() string {
	return "Hello from mypackage!"
}
```

假设 `myproject` 位于你的 GOPATH 下的 `src` 目录中。

```go
package main

import (
	"fmt"
	"go/build"
	"os"
	"path/filepath"
)

func main() {
	// 创建一个默认的构建上下文
	ctxt := build.Default

	// 获取当前工作目录
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting working directory:", err)
		return
	}

	// 构建 mypackage 的绝对路径
	pkgDir := filepath.Join(cwd, "mypackage")

	// 导入 mypackage
	pkg, err := ctxt.ImportDir(pkgDir, 0)
	if err != nil {
		fmt.Println("Error importing package:", err)
		return
	}

	fmt.Println("Package Name:", pkg.Name)
	fmt.Println("Import Path:", pkg.ImportPath)
	fmt.Println("Go Files:", pkg.GoFiles)
}
```

**假设输入:** 上述的目录结构和代码。
**预期输出:**

```
Package Name: mypackage
Import Path: myproject/mypackage
Go Files: [mypackage.go]
```

**构建约束示例 (需要结合后续代码理解更完整):**

假设 `mypackage` 目录下有以下文件：

```
mypackage/
├── mypackage.go
├── mypackage_linux.go  // go:build linux
└── mypackage_windows.go // go:build windows
```

`mypackage.go` 内容：

```go
package mypackage

func OSMessage() string {
	return "Generic OS"
}
```

`mypackage_linux.go` 内容：

```go
//go:build linux

package mypackage

func OSMessage() string {
	return "Running on Linux"
}
```

`mypackage_windows.go` 内容：

```go
//go:build windows

package mypackage

func OSMessage() string {
	return "Running on Windows"
}
```

```go
package main

import (
	"fmt"
	"go/build"
	"runtime"
)

func main() {
	ctxt := build.Default

	// 可以自定义构建标签
	// ctxt.BuildTags = []string{"customtag"}

	pkg, err := ctxt.Import("myproject/mypackage", "", 0)
	if err != nil {
		fmt.Println("Error importing package:", err)
		return
	}

	fmt.Println("Package Name:", pkg.Name)
	fmt.Println("Import Path:", pkg.ImportPath)
	fmt.Println("Go Files:", pkg.GoFiles)

	// 根据当前的 GOOS 输出不同的消息
	fmt.Println(mypackage.OSMessage())
}
```

**假设输入:** 上述的目录结构和代码，运行在 Linux 系统上。
**预期输出:**

```
Package Name: mypackage
Import Path: myproject/mypackage
Go Files: [mypackage.go mypackage_linux.go]
Running on Linux
```

**假设输入:** 上述的目录结构和代码，运行在 Windows 系统上。
**预期输出:**

```
Package Name: mypackage
Import Path: myproject/mypackage
Go Files: [mypackage.go mypackage_windows.go]
Running on Windows
```

**命令行参数的具体处理:**

这段代码本身**并不直接处理命令行参数**。它定义了构建上下文和包的结构，以及如何查找和加载包。具体的命令行参数处理是在更上层的工具中进行的，例如 `go build`、`go run`、`go test` 等命令。

这些上层工具会读取命令行参数（例如 `-tags` 用于指定构建标签），并根据这些参数来初始化 `build.Context` 结构体，然后调用 `build.Import` 或 `build.ImportDir` 来加载包。

**使用者易犯错的点:**

* **GOPATH 设置错误:**  最常见的错误是用户没有正确设置 `GOPATH` 环境变量，或者将项目放置在 `GOPATH` 以外的位置，导致 `Import` 函数无法找到所需的包。

   **示例:** 用户将项目放在 `/home/user/myproject`，但 `GOPATH` 设置为 `/home/user/go`。当 `main.go` 中导入 `myproject/mypackage` 时，`build.Import` 将无法找到该包。

* **导入路径错误:**  使用错误的导入路径，例如大小写不匹配或路径不完整，会导致 `Import` 失败。

   **示例:**  实际包的路径是 `github.com/user/mypackage`，但在代码中误写为 `github.com/User/mypackage`。

* **构建约束理解错误:**  用户可能不理解构建约束的语法，导致某些文件意外地被包含或排除在构建过程中。

   **示例:**  用户想让某个文件只在 Linux 上编译，使用了 `//go:build linux`，但文件名不符合 Go 的构建规则（例如没有 `.go` 后缀），导致该文件被忽略。

* **Vendor 目录使用不当:**  在模块模式下，vendor 目录的使用方式与 GOPATH 模式不同，用户可能混淆这两种模式的导入行为。

   **示例:**  在模块模式下，如果依赖的包已经在 `go.mod` 文件中声明，直接导入即可，无需将依赖复制到 vendor 目录。用户可能手动将依赖复制到 vendor 目录，反而可能导致版本冲突或导入错误。

总而言之，这段 `go/src/go/build/build.go` 的第一部分为 Go 语言的构建过程奠定了基础，定义了核心的数据结构和操作，用于理解和表示 Go 代码的组织结构。后续的部分将在此基础上实现更复杂的构建逻辑。

### 提示词
```
这是路径为go/src/go/build/build.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package build

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/doc"
	"go/token"
	"internal/buildcfg"
	"internal/godebug"
	"internal/goroot"
	"internal/goversion"
	"internal/platform"
	"internal/syslist"
	"io"
	"io/fs"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
	_ "unsafe" // for linkname
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
	UseAllFiles bool   // use files regardless of go:build lines, file names
	Compiler    string // compiler to assume when computing target paths

	// The build, tool, and release tags specify build constraints
	// that should be considered satisfied when processing go:build lines.
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
	// If ReadDir is nil, Import uses os.ReadDir.
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

// isDir calls ctxt.IsDir (if not nil) or else uses os.Stat.
func (ctxt *Context) isDir(path string) bool {
	if f := ctxt.IsDir; f != nil {
		return f(path)
	}
	fi, err := os.Stat(path)
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
	const sep = string(filepath.Separator)
	root = filepath.Clean(root)
	if !strings.HasSuffix(root, sep) {
		root += sep
	}
	dir = filepath.Clean(dir)
	after, found := strings.CutPrefix(dir, root)
	if !found {
		return "", false
	}
	return filepath.ToSlash(after), true
}

// readDir calls ctxt.ReadDir (if not nil) or else os.ReadDir.
func (ctxt *Context) readDir(path string) ([]fs.DirEntry, error) {
	// TODO: add a fs.DirEntry version of Context.ReadDir
	if f := ctxt.ReadDir; f != nil {
		fis, err := f(path)
		if err != nil {
			return nil, err
		}
		des := make([]fs.DirEntry, len(fis))
		for i, fi := range fis {
			des[i] = fs.FileInfoToDirEntry(fi)
		}
		return des, nil
	}
	return os.ReadDir(path)
}

// openFile calls ctxt.OpenFile (if not nil) or else os.Open.
func (ctxt *Context) openFile(path string) (io.ReadCloser, error) {
	if fn := ctxt.OpenFile; fn != nil {
		return fn(path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err // nil interface
	}
	return f, nil
}

// isFile determines whether path is a file by trying to open it.
// It reuses openFile instead of adding another function to the
// list in Context.
func (ctxt *Context) isFile(path string) bool {
	f, err := ctxt.openFile(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
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

// SrcDirs returns a list of package source root directories.
// It draws from the current Go root and Go path but omits directories
// that do not exist.
func (ctxt *Context) SrcDirs() []string {
	var all []string
	if ctxt.GOROOT != "" && ctxt.Compiler != "gccgo" {
		dir := ctxt.joinPath(ctxt.GOROOT, "src")
		if ctxt.isDir(dir) {
			all = append(all, dir)
		}
	}
	for _, p := range ctxt.gopath() {
		dir := ctxt.joinPath(p, "src")
		if ctxt.isDir(dir) {
			all = append(all, dir)
		}
	}
	return all
}

// Default is the default Context for builds.
// It uses the GOARCH, GOOS, GOROOT, and GOPATH environment variables
// if set, or else the compiled code's GOARCH, GOOS, and GOROOT.
var Default Context = defaultContext()

// Keep consistent with cmd/go/internal/cfg.defaultGOPATH.
func defaultGOPATH() string {
	env := "HOME"
	if runtime.GOOS == "windows" {
		env = "USERPROFILE"
	} else if runtime.GOOS == "plan9" {
		env = "home"
	}
	if home := os.Getenv(env); home != "" {
		def := filepath.Join(home, "go")
		if filepath.Clean(def) == filepath.Clean(runtime.GOROOT()) {
			// Don't set the default GOPATH to GOROOT,
			// as that will trigger warnings from the go tool.
			return ""
		}
		return def
	}
	return ""
}

// defaultToolTags should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/gopherjs/gopherjs
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname defaultToolTags
var defaultToolTags []string

// defaultReleaseTags should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/gopherjs/gopherjs
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname defaultReleaseTags
var defaultReleaseTags []string

func defaultContext() Context {
	var c Context

	c.GOARCH = buildcfg.GOARCH
	c.GOOS = buildcfg.GOOS
	if goroot := runtime.GOROOT(); goroot != "" {
		c.GOROOT = filepath.Clean(goroot)
	}
	c.GOPATH = envOr("GOPATH", defaultGOPATH())
	c.Compiler = runtime.Compiler
	c.ToolTags = append(c.ToolTags, buildcfg.ToolTags...)

	defaultToolTags = append([]string{}, c.ToolTags...) // our own private copy

	// Each major Go release in the Go 1.x series adds a new
	// "go1.x" release tag. That is, the go1.x tag is present in
	// all releases >= Go 1.x. Code that requires Go 1.x or later
	// should say "go:build go1.x", and code that should only be
	// built before Go 1.x (perhaps it is the stub to use in that
	// case) should say "go:build !go1.x".
	// The last element in ReleaseTags is the current release.
	for i := 1; i <= goversion.Version; i++ {
		c.ReleaseTags = append(c.ReleaseTags, "go1."+strconv.Itoa(i))
	}

	defaultReleaseTags = append([]string{}, c.ReleaseTags...) // our own private copy

	env := os.Getenv("CGO_ENABLED")
	if env == "" {
		env = defaultCGO_ENABLED
	}
	switch env {
	case "1":
		c.CgoEnabled = true
	case "0":
		c.CgoEnabled = false
	default:
		// cgo must be explicitly enabled for cross compilation builds
		if runtime.GOARCH == c.GOARCH && runtime.GOOS == c.GOOS {
			c.CgoEnabled = platform.CgoSupported(c.GOOS, c.GOARCH)
			break
		}
		c.CgoEnabled = false
	}

	return c
}

func envOr(name, def string) string {
	s := os.Getenv(name)
	if s == "" {
		return def
	}
	return s
}

// An ImportMode controls the behavior of the Import method.
type ImportMode uint

const (
	// If FindOnly is set, Import stops after locating the directory
	// that should contain the sources for a package. It does not
	// read any files in the directory.
	FindOnly ImportMode = 1 << iota

	// If AllowBinary is set, Import can be satisfied by a compiled
	// package object without corresponding sources.
	//
	// Deprecated:
	// The supported way to create a compiled-only package is to
	// write source code containing a //go:binary-only-package comment at
	// the top of the file. Such a package will be recognized
	// regardless of this flag setting (because it has source code)
	// and will have BinaryOnly set to true in the returned Package.
	AllowBinary

	// If ImportComment is set, parse import comments on package statements.
	// Import returns an error if it finds a comment it cannot understand
	// or finds conflicting comments in multiple source files.
	// See golang.org/s/go14customimport for more information.
	ImportComment

	// By default, Import searches vendor directories
	// that apply in the given source directory before searching
	// the GOROOT and GOPATH roots.
	// If an Import finds and returns a package using a vendor
	// directory, the resulting ImportPath is the complete path
	// to the package, including the path elements leading up
	// to and including "vendor".
	// For example, if Import("y", "x/subdir", 0) finds
	// "x/vendor/y", the returned package's ImportPath is "x/vendor/y",
	// not plain "y".
	// See golang.org/s/go15vendor for more information.
	//
	// Setting IgnoreVendor ignores vendor directories.
	//
	// In contrast to the package's ImportPath,
	// the returned package's Imports, TestImports, and XTestImports
	// are always the exact import paths from the source files:
	// Import makes no attempt to resolve or check those paths.
	IgnoreVendor
)

// A Package describes the Go package found in a directory.
type Package struct {
	Dir           string   // directory containing package sources
	Name          string   // package name
	ImportComment string   // path in import comment on package statement
	Doc           string   // documentation synopsis
	ImportPath    string   // import path of package ("" if unknown)
	Root          string   // root of Go tree where this package lives
	SrcRoot       string   // package source root directory ("" if unknown)
	PkgRoot       string   // package install root directory ("" if unknown)
	PkgTargetRoot string   // architecture dependent install root directory ("" if unknown)
	BinDir        string   // command install directory ("" if unknown)
	Goroot        bool     // package found in Go root
	PkgObj        string   // installed .a file
	AllTags       []string // tags that can influence file selection in this directory
	ConflictDir   string   // this directory shadows Dir in $GOPATH
	BinaryOnly    bool     // cannot be rebuilt from source (has //go:binary-only-package comment)

	// Source files
	GoFiles           []string // .go source files (excluding CgoFiles, TestGoFiles, XTestGoFiles)
	CgoFiles          []string // .go source files that import "C"
	IgnoredGoFiles    []string // .go source files ignored for this build (including ignored _test.go files)
	InvalidGoFiles    []string // .go source files with detected problems (parse error, wrong package name, and so on)
	IgnoredOtherFiles []string // non-.go source files ignored for this build
	CFiles            []string // .c source files
	CXXFiles          []string // .cc, .cpp and .cxx source files
	MFiles            []string // .m (Objective-C) source files
	HFiles            []string // .h, .hh, .hpp and .hxx source files
	FFiles            []string // .f, .F, .for and .f90 Fortran source files
	SFiles            []string // .s source files
	SwigFiles         []string // .swig files
	SwigCXXFiles      []string // .swigcxx files
	SysoFiles         []string // .syso system object files to add to archive

	// Cgo directives
	CgoCFLAGS    []string // Cgo CFLAGS directives
	CgoCPPFLAGS  []string // Cgo CPPFLAGS directives
	CgoCXXFLAGS  []string // Cgo CXXFLAGS directives
	CgoFFLAGS    []string // Cgo FFLAGS directives
	CgoLDFLAGS   []string // Cgo LDFLAGS directives
	CgoPkgConfig []string // Cgo pkg-config directives

	// Test information
	TestGoFiles  []string // _test.go files in package
	XTestGoFiles []string // _test.go files outside package

	// Go directive comments (//go:zzz...) found in source files.
	Directives      []Directive
	TestDirectives  []Directive
	XTestDirectives []Directive

	// Dependency information
	Imports        []string                    // import paths from GoFiles, CgoFiles
	ImportPos      map[string][]token.Position // line information for Imports
	TestImports    []string                    // import paths from TestGoFiles
	TestImportPos  map[string][]token.Position // line information for TestImports
	XTestImports   []string                    // import paths from XTestGoFiles
	XTestImportPos map[string][]token.Position // line information for XTestImports

	// //go:embed patterns found in Go source files
	// For example, if a source file says
	//	//go:embed a* b.c
	// then the list will contain those two strings as separate entries.
	// (See package embed for more details about //go:embed.)
	EmbedPatterns        []string                    // patterns from GoFiles, CgoFiles
	EmbedPatternPos      map[string][]token.Position // line information for EmbedPatterns
	TestEmbedPatterns    []string                    // patterns from TestGoFiles
	TestEmbedPatternPos  map[string][]token.Position // line information for TestEmbedPatterns
	XTestEmbedPatterns   []string                    // patterns from XTestGoFiles
	XTestEmbedPatternPos map[string][]token.Position // line information for XTestEmbedPatternPos
}

// A Directive is a Go directive comment (//go:zzz...) found in a source file.
type Directive struct {
	Text string         // full line comment including leading slashes
	Pos  token.Position // position of comment
}

// IsCommand reports whether the package is considered a
// command to be installed (not just a library).
// Packages named "main" are treated as commands.
func (p *Package) IsCommand() bool {
	return p.Name == "main"
}

// ImportDir is like [Import] but processes the Go package found in
// the named directory.
func (ctxt *Context) ImportDir(dir string, mode ImportMode) (*Package, error) {
	return ctxt.Import(".", dir, mode)
}

// NoGoError is the error used by [Import] to describe a directory
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

var installgoroot = godebug.New("installgoroot")

// Import returns details about the Go package named by the import path,
// interpreting local import paths relative to the srcDir directory.
// If the path is a local import path naming a package that can be imported
// using a standard import path, the returned package will set p.ImportPath
// to that path.
//
// In the directory containing the package, .go, .c, .h, and .s files are
// considered part of the package except for:
//
//   - .go files in package documentation
//   - files starting with _ or . (likely editor temporary files)
//   - files with build constraints not satisfied by the context
//
// If an error occurs, Import returns a non-nil error and a non-nil
// *[Package] containing partial information.
func (ctxt *Context) Import(path string, srcDir string, mode ImportMode) (*Package, error) {
	p := &Package{
		ImportPath: path,
	}
	if path == "" {
		return p, fmt.Errorf("import %q: invalid import path", path)
	}

	var pkgtargetroot string
	var pkga string
	var pkgerr error
	suffix := ""
	if ctxt.InstallSuffix != "" {
		suffix = "_" + ctxt.InstallSuffix
	}
	switch ctxt.Compiler {
	case "gccgo":
		pkgtargetroot = "pkg/gccgo_" + ctxt.GOOS + "_" + ctxt.GOARCH + suffix
	case "gc":
		pkgtargetroot = "pkg/" + ctxt.GOOS + "_" + ctxt.GOARCH + suffix
	default:
		// Save error for end of function.
		pkgerr = fmt.Errorf("import %q: unknown compiler %q", path, ctxt.Compiler)
	}
	setPkga := func() {
		switch ctxt.Compiler {
		case "gccgo":
			dir, elem := pathpkg.Split(p.ImportPath)
			pkga = pkgtargetroot + "/" + dir + "lib" + elem + ".a"
		case "gc":
			pkga = pkgtargetroot + "/" + p.ImportPath + ".a"
		}
	}
	setPkga()

	binaryOnly := false
	if IsLocalImport(path) {
		pkga = "" // local imports have no installed path
		if srcDir == "" {
			return p, fmt.Errorf("import %q: import relative to unknown directory", path)
		}
		if !ctxt.isAbsPath(path) {
			p.Dir = ctxt.joinPath(srcDir, path)
		}
		// p.Dir directory may or may not exist. Gather partial information first, check if it exists later.
		// Determine canonical import path, if any.
		// Exclude results where the import path would include /testdata/.
		inTestdata := func(sub string) bool {
			return strings.Contains(sub, "/testdata/") || strings.HasSuffix(sub, "/testdata") || strings.HasPrefix(sub, "testdata/") || sub == "testdata"
		}
		if ctxt.GOROOT != "" {
			root := ctxt.joinPath(ctxt.GOROOT, "src")
			if sub, ok := ctxt.hasSubdir(root, p.Dir); ok && !inTestdata(sub) {
				p.Goroot = true
				p.ImportPath = sub
				p.Root = ctxt.GOROOT
				setPkga() // p.ImportPath changed
				goto Found
			}
		}
		all := ctxt.gopath()
		for i, root := range all {
			rootsrc := ctxt.joinPath(root, "src")
			if sub, ok := ctxt.hasSubdir(rootsrc, p.Dir); ok && !inTestdata(sub) {
				// We found a potential import path for dir,
				// but check that using it wouldn't find something
				// else first.
				if ctxt.GOROOT != "" && ctxt.Compiler != "gccgo" {
					if dir := ctxt.joinPath(ctxt.GOROOT, "src", sub); ctxt.isDir(dir) {
						p.ConflictDir = dir
						goto Found
					}
				}
				for _, earlyRoot := range all[:i] {
					if dir := ctxt.joinPath(earlyRoot, "src", sub); ctxt.isDir(dir) {
						p.ConflictDir = dir
						goto Found
					}
				}

				// sub would not name some other directory instead of this one.
				// Record it.
				p.ImportPath = sub
				p.Root = root
				setPkga() // p.ImportPath changed
				goto Found
			}
		}
		// It's okay that we didn't find a root containing dir.
		// Keep going with the information we have.
	} else {
		if strings.HasPrefix(path, "/") {
			return p, fmt.Errorf("import %q: cannot import absolute path", path)
		}

		if err := ctxt.importGo(p, path, srcDir, mode); err == nil {
			goto Found
		} else if err != errNoModules {
			return p, err
		}

		gopath := ctxt.gopath() // needed twice below; avoid computing many times

		// tried records the location of unsuccessful package lookups
		var tried struct {
			vendor []string
			goroot string
			gopath []string
		}

		// Vendor directories get first chance to satisfy import.
		if mode&IgnoreVendor == 0 && srcDir != "" {
			searchVendor := func(root string, isGoroot bool) bool {
				sub, ok := ctxt.hasSubdir(root, srcDir)
				if !ok || !strings.HasPrefix(sub, "src/") || strings.Contains(sub, "/testdata/") {
					return false
				}
				for {
					vendor := ctxt.joinPath(root, sub, "vendor")
					if ctxt.isDir(vendor) {
						dir := ctxt.joinPath(vendor, path)
						if ctxt.isDir(dir) && hasGoFiles(ctxt, dir) {
							p.Dir = dir
							p.ImportPath = strings.TrimPrefix(pathpkg.Join(sub, "vendor", path), "src/")
							p.Goroot = isGoroot
							p.Root = root
							setPkga() // p.ImportPath changed
							return true
						}
						tried.vendor = append(tried.vendor, dir)
					}
					i := strings.LastIndex(sub, "/")
					if i < 0 {
						break
					}
					sub = sub[:i]
				}
				return false
			}
			if ctxt.Compiler != "gccgo" && ctxt.GOROOT != "" && searchVendor(ctxt.GOROOT, true) {
				goto Found
			}
			for _, root := range gopath {
				if searchVendor(root, false) {
					goto Found
				}
			}
		}

		// Determine directory from import path.
		if ctxt.GOROOT != "" {
			// If the package path starts with "vendor/", only search GOROOT before
			// GOPATH if the importer is also within GOROOT. That way, if the user has
			// vendored in a package that is subsequently included in the standard
			// distribution, they'll continue to pick up their own vendored copy.
			gorootFirst := srcDir == "" || !strings.HasPrefix(path, "vendor/")
			if !gorootFirst {
				_, gorootFirst = ctxt.hasSubdir(ctxt.GOROOT, srcDir)
			}
			if gorootFirst {
				dir := ctxt.joinPath(ctxt.GOROOT, "src", path)
				if ctxt.Compiler != "gccgo" {
					isDir := ctxt.isDir(dir)
					binaryOnly = !isDir && mode&AllowBinary != 0 && pkga != "" && ctxt.isFile(ctxt.joinPath(ctxt.GOROOT, pkga))
					if isDir || binaryOnly {
						p.Dir = dir
						p.Goroot = true
						p.Root = ctxt.GOROOT
						goto Found
					}
				}
				tried.goroot = dir
			}
			if ctxt.Compiler == "gccgo" && goroot.IsStandardPackage(ctxt.GOROOT, ctxt.Compiler, path) {
				// TODO(bcmills): Setting p.Dir here is misleading, because gccgo
				// doesn't actually load its standard-library packages from this
				// directory. See if we can leave it unset.
				p.Dir = ctxt.joinPath(ctxt.GOROOT, "src", path)
				p.Goroot = true
				p.Root = ctxt.GOROOT
				goto Found
			}
		}
		for _, root := range gopath {
			dir := ctxt.joinPath(root, "src", path)
			isDir := ctxt.isDir(dir)
			binaryOnly = !isDir && mode&AllowBinary != 0 && pkga != "" && ctxt.isFile(ctxt.joinPath(root, pkga))
			if isDir || binaryOnly {
				p.Dir = dir
				p.Root = root
				goto Found
			}
			tried.gopath = append(tried.gopath, dir)
		}

		// If we tried GOPATH first due to a "vendor/" prefix, fall back to GOPATH.
		// That way, the user can still get useful results from 'go list' for
		// standard-vendored paths passed on the command line.
		if ctxt.GOROOT != "" && tried.goroot == "" {
			dir := ctxt.joinPath(ctxt.GOROOT, "src", path)
			if ctxt.Compiler != "gccgo" {
				isDir := ctxt.isDir(dir)
				binaryOnly = !isDir && mode&AllowBinary != 0 && pkga != "" && ctxt.isFile(ctxt.joinPath(ctxt.GOROOT, pkga))
				if isDir || binaryOnly {
					p.Dir = dir
					p.Goroot = true
					p.Root = ctxt.GOROOT
					goto Found
				}
			}
			tried.goroot = dir
		}

		// package was not found
		var paths []string
		format := "\t%s (vendor tree)"
		for _, dir := range tried.vendor {
			paths = append(paths, fmt.Sprintf(format, dir))
			format = "\t%s"
		}
		if tried.goroot != "" {
			paths = append(paths, fmt.Sprintf("\t%s (from $GOROOT)", tried.goroot))
		} else {
			paths = append(paths, "\t($GOROOT not set)")
		}
		format = "\t%s (from $GOPATH)"
		for _, dir := range tried.gopath {
			paths = append(paths, fmt.Sprintf(format, dir))
			format = "\t%s"
		}
		if len(tried.gopath) == 0 {
			paths = append(paths, "\t($GOPATH not set. For more details see: 'go help gopath')")
		}
		return p, fmt.Errorf("cannot find package %q in any of:\n%s", path, strings.Join(paths, "\n"))
	}

Found:
	if p.Root != "" {
		p.SrcRoot = ctxt.joinPath(p.Root, "src")
		p.PkgRoot = ctxt.joinPath(p.Root, "pkg")
		p.BinDir = ctxt.joinPath(p.Root, "bin")
		if pkga != "" {
			// Always set PkgTargetRoot. It might be used when building in shared
			// mode.
			p.PkgTargetRoot = ctxt.joinPath(p.Root, pkgtargetroot)

			// Set the install target if applicable.
			if !p.Goroot || (installgoroot.Value() == "all" && p.ImportPath != "unsafe" && p.ImportPath != "builtin") {
				if p.Goroot {
					installgoroot.IncNonDefault()
				}
				p.PkgObj = ctxt.joinPath(p.Root, pkga)
			}
		}
	}

	// If it's a local import path, by the time we get here, we still haven't checked
	// that p.Dir directory exists. This is the right time to do that check.
	// We can't do it earlier, because we want to gather partial information for the
	// non-nil *Package returned when an error occurs.
	// We need to do this before we return early on FindOnly flag.
	if IsLocalImport(path) && !ctxt.isDir(p.Dir) {
		if ctxt.Compiler == "gccgo" && p.Goroot {
			// gccgo has no sources for GOROOT packages.
			return p, nil
		}

		// package was not found
		return p, fmt.Errorf("cannot find package %q in:\n\t%s", p.ImportPath, p.Dir)
	}

	if mode&FindOnly != 0 {
		return p, pkgerr
	}
	if binaryOnly && (mode&AllowBinary) != 0 {
		return p, pkgerr
	}

	if ctxt.Compiler == "gccgo" && p.Goroot {
		// gccgo has no sources for GOROOT packages.
		return p, nil
	}

	dirs, err := ctxt.readDir(p.Dir)
	if err != nil {
		return p, err
	}

	var badGoError error
	badGoFiles := make(map[string]bool)
	badGoFile := func(name string, err error) {
		if badGoError == nil {
			badGoError = err
		}
		if !badGoFiles[name] {
			p.InvalidGoFiles = append(p.InvalidGoFiles, name)
			badGoFiles[name] = true
		}
	}

	var Sfiles []string // files with ".S"(capital S)/.sx(capital s equivalent for case insensitive filesystems)
	var firstFile, firstCommentFile string
	embedPos := make(map[string][]token.Position)
	testEmbedPos := make(map[string][]token.Position)
	xTestEmbedPos := make(map[string][]token.Position)
	importPos := make(map[string][]token.Position)
	testImportPos := make(map[string][]token.Position)
	xTestImportPos := make(map[string][]token.Position)
	allTags := make(map[string]bool)
	fset := token.NewFileSet()
	for _, d := range dirs {
		if d.IsDir() {
			continue
		}
		if d.Type() == fs.ModeSymlink {
			if ctxt.isDir(ctxt.joinPath(p.Dir, d.Name())) {
				// Symlinks to directories are not source files.
				continue
			}
		}

		name := d.Name()
		ext := nameExt(name)

		info, err := ctxt.matchFile(p.Dir, name, allTags, &p.BinaryOnly, fset)
		if err != nil && strings.HasSuffix(name, ".go") {
			badGoFile(name, err)
			continue
		}
		if info == nil {
			if strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
				// not due to build constraints - don't report
			} else if ext == ".go" {
				p.IgnoredGoFiles = append(p.IgnoredGoFiles, name)
			} else if fileListForExt(p, ext) != nil {
				p.IgnoredOtherFiles = append(p.IgnoredOtherFiles, name)
			}
			continue
		}

		// Going to save the file. For non-Go files, can stop here.
		switch ext {
		case ".go":
			// keep going
		case ".S", ".sx":
			// special case for cgo, handled at end
			Sfiles = append(Sfiles, name)
			continue
		default:
			if list := fileListForExt(p, ext); list != nil {
				*list = append(*list, name)
			}
			continue
		}

		data, filename := info.header, info.name

		if info.parseErr != nil {
			badGoFile(name, info.parseErr)
			// Fall through: we might still have a partial AST in info.parsed,
			// and we want to list files with parse errors anyway.
		}

		var pkg string
		if info.parsed != nil {
			pkg = info.parsed.Name.Name
			if pkg == "documentation" {
				p.IgnoredGoFiles = append(p.IgnoredGoFiles, name)
				continue
			}
		}

		isTest := strings.HasSuffix(name, "_test.go")
		isXTest := false
		if isTest && strings.HasSuffix(pkg, "_test") && p.Name != pkg {
			isXTest = true
			pkg = pkg[:len(pkg)-len("_test")]
		}

		if p.Name == "" {
			p.Name = pkg
			firstFile = name
		} else if pkg != p.Name {
			// TODO(#45999): The choice of p.Name is arbitrary based on file iteration
			// order. Instead of resolving p.Name arbitrarily, we should clear out the
			// existing name and mark the existing files as also invalid.
			badGoFile(name, &MultiplePackageError{
				Dir:      p.Dir,
				Packages: []string{p.Name, pkg},
				Files:    []string{firstFile, name},
			})
		}
		// Grab the first package comment as docs, provided it is not from a test file.
		if info.parsed != nil && info.parsed.Doc != nil && p.Doc == "" && !isTest && !isXTest {
			p.Doc = doc.Synopsis(info.parsed.Doc.Text())
		}

		if mode&ImportComment != 0 {
			qcom, line := findImportComment(data)
			if line != 0 {
				com, err := strconv.Unquote(qcom)
				if err != nil {
					badGoFile(name, fmt.Errorf("%s:%d: cannot parse import comment", filename, line))
				} else if p.ImportComment == "" {
					p.ImportComment = com
					firstCommentFile = name
				} else if p.ImportComment != com {
					badGoFile(name, fmt.Errorf("found import comments %q (%s) and %q (%s) in %s", p.ImportComment, firstCommentFile, com, name, p.Dir))
				}
			}
		}

		// Record imports and information about cgo.
		isCgo := false
		f
```