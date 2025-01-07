Response: Let's break down the thought process to understand the provided Go code snippet and fulfill the request.

**1. Initial Understanding of the Request:**

The request asks for:

* A summary of the code's functionality.
* If possible, identify the Go language feature it implements and provide an example.
* If code inference is involved, explain the assumptions, inputs, and outputs.
* Details on command-line argument handling (if applicable).
* Common mistakes users might make (if any).

**2. High-Level Analysis of the Code:**

The code imports standard Go libraries like `os`, `path/filepath`, `sync`, `testing`, and `time`, as well as internal packages like `cmd/compile/internal/syntax` and `cmd/compile/internal/types2`. The presence of `types2` and the function name `TestStdlib` strongly suggest that this code is testing the `types2` package, which is the new Go type checker.

**3. Deeper Dive into Key Functions and Data Structures:**

* **`TestStdlib(t *testing.T)`:** This is clearly a test function. It skips in short mode. It uses `testenv.MustHaveGoBuild(t)`, indicating it needs a working Go build environment. The core logic revolves around `walkPkgDirs` and a concurrent type-checking mechanism using goroutines and a wait group.

* **`stdlibChecker`:** This struct seems to manage the type-checking process. `dirFiles` stores non-test Go files for each directory. `pkgs` is a map to cache the results of type-checking, likely to avoid redundant work.

* **`futurePackage`:** This looks like a wrapper to handle asynchronous type-checking results, using a channel (`done`) to signal completion.

* **`getDirPackage(dir string)`:** This is the central function for getting a package. It uses a mutex to protect the `pkgs` map, checks the cache, and if the package isn't present, it initiates type-checking concurrently.

* **`typecheckFiles(path string, filenames []string, importer Importer)`:** This function does the actual parsing and type-checking of the Go files in a package. It uses the `Config` and `Check` methods from the `types2` package.

* **`walkPkgDirs(dir string, pkgh func(dir string, filenames []string), errh func(args ...interface{}))`:** This function recursively walks through directories to find Go packages.

* **`testTestDir(t *testing.T, path string, ignore ...string)`:** This function iterates through files in a directory, parses them, and type-checks them, potentially expecting errors based on comments within the files.

**4. Identifying the Core Functionality:**

Based on the above analysis, the primary function is to type-check the Go standard library (and potentially the `test` directory). It does this concurrently to speed up the process. The `types2` package is explicitly used for this.

**5. Inferring the Go Language Feature:**

The code directly tests the functionality of the `cmd/compile/internal/types2` package. This package *is* the implementation of the Go language's type system. Therefore, this code tests the **Go language's type checking mechanism**.

**6. Creating a Go Code Example:**

To demonstrate type checking, a simple example will suffice. The key is to show how the `types2` package is used to check code for type errors.

```go
package main

import (
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/types2"
	"fmt"
)

func main() {
	// Hypothetical input code with a type error
	src := `package main
           func main() {
               var x int = "hello"
               fmt.Println(x)
           }`

	// Parse the source code
	file, err := syntax.Parse("test.go", []byte(src), nil, 0)
	if err != nil {
		panic(err)
	}

	// Configure the type checker
	conf := types2.Config{
		Importer: types2.NewImporter(nil), // Basic importer for this example
		Error: func(err error) {
			fmt.Println("Type error:", err)
		},
	}

	// Check the code
	_, err = conf.Check("main", []*syntax.File{file}, nil)
	if err == nil {
		fmt.Println("No type errors found (this is unexpected)")
	}
}
```

**7. Explaining Code Inference (Assumptions, Inputs, Outputs):**

The inference is primarily based on the imported packages and the function names.

* **Assumption:** The code is part of the Go compiler's testing infrastructure.
* **Input:** The `TestStdlib` function implicitly takes the source code of the Go standard library as input by walking through the `GOROOT/src` directory. The `testTestDir` function takes paths to test directories.
* **Output:** The `TestStdlib` function reports errors (using `t.Errorf`) if any type-checking errors are found in the standard library. The `testTestDir` function also reports errors based on expectations defined in comments within the test files.

**8. Command-Line Argument Handling:**

The code itself doesn't directly handle command-line arguments. The `testing` package handles arguments for running tests (like `-short` or `-v`). The `testenv.MustHaveGoBuild(t)` ensures a Go build environment is available, which might involve looking at environment variables or command-line flags passed to the test execution.

**9. Common Mistakes:**

The most likely mistake users could make when *using* the `types2` package (which this code tests) is providing an incorrect or incomplete `Importer`. Type checking requires resolving dependencies between packages. If the `Importer` cannot find the necessary packages, type checking will fail.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the concurrency aspects. However, the core purpose is testing the type checker. The concurrency is an implementation detail to make the tests faster. It's important to prioritize the main functionality in the summary. Also, clearly distinguishing between *what the code does* and *what it tests* is crucial. The code *tests* the type checker, it doesn't directly *implement* the type checker itself (it uses the `types2` package which *is* the type checker).
这段代码是 Go 语言 `cmd/compile/internal/types2` 包的一部分，位于 `go/src/cmd/compile/internal/types2/stdlib_test.go` 文件中。它的主要功能是**测试 `types2` 包的类型检查器对 Go 标准库和一些测试代码的健壮性和正确性**。

更具体地说，它做了以下几件事情：

1. **遍历标准库目录:**  `TestStdlib` 函数会遍历 Go SDK 源代码目录 (`GOROOT/src`) 下的所有 Go 语言源文件（非测试文件）。
2. **并发类型检查:** 它使用并发的方式（goroutines 和 wait group）对每个标准库包进行类型检查。
3. **使用 `types2` 包进行类型检查:**  `getDirPackage` 和 `typecheckFiles` 函数利用 `cmd/compile/internal/types2` 包提供的 API (`Config` 和 `Check`) 对每个包的源文件进行语法分析和类型检查。
4. **自定义导入器:**  `stdlibChecker` 结构体实现了 `types2.Importer` 接口，用于在类型检查过程中解析和查找导入的包。它特别处理了 `unsafe` 包。
5. **处理 build 标签:** `firstComment` 函数会读取 Go 文件的第一个注释，用于检测 `go:build` 标签，并跳过包含此类标签的文件。
6. **测试特定的测试目录:** `TestStdTest` 和 `TestStdFixed` 函数针对 Go SDK 源代码目录下的 `test` 和 `test/fixedbugs` 目录中的特定文件进行类型检查，并能根据文件中的注释 (`// errorcheck`) 判断是否期望出现错误。
7. **检查 API 不变性:** `typecheckFiles` 函数还会进行一些额外的检查，例如确保所有非预声明的对象都有包信息。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码主要测试的是 **Go 语言的类型系统以及类型检查器的实现**。`cmd/compile/internal/types2` 包是 Go 编译器中新的类型检查器的实现。这段测试代码通过实际编译标准库的代码来验证这个新的类型检查器是否能正确地识别类型错误，处理各种语言特性，以及在并发场景下的稳定性。

**Go 代码举例说明:**

假设我们有一个简单的 Go 文件 `example.go`，内容如下：

```go
package main

import "fmt"

func main() {
	var x int = "hello" // 类型错误
	fmt.Println(x)
}
```

`stdlib_test.go` 中的相关函数（特别是 `typecheckFiles`）会像这样处理这个文件：

```go
// 假设 filename 是 "example.go"，内容如上

file, err := syntax.ParseFile("example.go", nil, nil, 0)
// ... 错误处理 ...

conf := Config{
    Error: func(err error) {
        fmt.Println("类型检查错误:", err) // 这里的 Error 函数会被调用
    },
    Importer: stdLibImporter,
    EnableAlias: true,
}
info := Info{Uses: make(map[*syntax.Name]Object)}
_, err = conf.Check("example", []*syntax.File{file}, &info)

// 输出将会包含类似以下的信息：
// 类型检查错误: example.go:5:6: cannot use "hello" (untyped string constant) as int value in assignment
```

**代码推理 - 假设的输入与输出:**

**假设输入:** `stdlib_test.go` 正在类型检查 `fmt` 包的 `print.go` 文件。

**过程推理:**

1. `walkPkgDirs` 函数会找到 `GOROOT/src/fmt` 目录。
2. `pkgFilenames` 函数会获取 `fmt` 包下的所有 Go 源文件（例如 `print.go`, `scan.go` 等）。
3. `TestStdlib` 函数会启动一个 goroutine 调用 `c.getDirPackage("GOROOT/src/fmt")`。
4. `getDirPackage` 会调用 `typecheckFiles("fmt", ["print.go", "scan.go", ...], c)`。
5. `typecheckFiles` 函数会：
   - 使用 `syntax.ParseFile` 解析 `print.go` 的内容，得到抽象语法树。
   - 创建一个 `types2.Config` 实例，设置错误处理函数和导入器 (`stdlibChecker`)。
   - 调用 `conf.Check("fmt", []*syntax.File{...}, &info)` 对 `print.go` 进行类型检查。
6. 如果 `print.go` 中存在类型错误，`conf.Error` 中定义的匿名函数会被调用，错误信息会被收集。
7. `getDirPackage` 函数返回 `fmt` 包的类型信息和可能的错误。
8. `TestStdlib` 函数检查返回的错误，如果没有错误，则继续处理下一个包。

**假设输出:** 如果 `fmt/print.go` 没有类型错误，`TestStdlib` 不会输出关于 `fmt` 包的错误信息。如果存在类型错误，`t.Errorf` 将会被调用，报告错误。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它作为一个 Go 测试文件，由 `go test` 命令执行。`go test` 命令有一些常用的参数，例如：

* `-v`:  显示更详细的测试输出。如果使用了 `-v`，`typecheckFiles` 函数会打印正在检查的包和文件名。
* `-short`:  运行时间较短的测试。如果使用了 `-short`，`TestStdlib` 和 `TestStdTest` 在某些情况下会跳过。
* `-run <regexp>`:  只运行匹配正则表达式的测试函数。
* `-tags <tags>`:  指定编译标签。

这些参数由 `testing` 包处理，而不是这段代码自身。

**使用者易犯错的点:**

作为测试代码，这段代码的使用者主要是 Go 核心开发团队的成员。一般开发者不会直接使用或修改它。但是，如果有人试图理解或修改 `types2` 包的类型检查逻辑，可能会犯以下错误：

1. **对并发理解不足:**  `TestStdlib` 使用了并发，如果对 goroutine 和 channel 的理解不足，可能会难以理解其执行流程和潜在的竞态条件。
2. **对 `types2` 包 API 不熟悉:**  直接修改或增加测试用例需要熟悉 `types2` 包的核心概念，如 `Config`, `Importer`, `Check`, `Object`, `Type` 等。
3. **忽略 build 标签的影响:**  某些标准库文件会使用 `//go:build` 标签来限定编译条件。如果修改了这些文件或添加了新的测试用例，需要注意 build 标签的影响，确保测试在正确的环境下运行。例如，`firstComment` 函数会跳过包含 `go:build` 标签的文件，这是为了避免在当前构建环境下不应该被编译的文件被类型检查。

总而言之，这段代码是 Go 语言类型系统测试的重要组成部分，它通过实际编译标准库代码来确保类型检查器的正确性和稳定性。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/stdlib_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file tests types2.Check by using it to
// typecheck the standard library and tests.

package types2_test

import (
	"bytes"
	"cmd/compile/internal/syntax"
	"errors"
	"fmt"
	"go/build"
	"internal/testenv"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	. "cmd/compile/internal/types2"
)

var stdLibImporter = defaultImporter()

func TestStdlib(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	testenv.MustHaveGoBuild(t)

	// Collect non-test files.
	dirFiles := make(map[string][]string)
	root := filepath.Join(testenv.GOROOT(t), "src")
	walkPkgDirs(root, func(dir string, filenames []string) {
		dirFiles[dir] = filenames
	}, t.Error)

	c := &stdlibChecker{
		dirFiles: dirFiles,
		pkgs:     make(map[string]*futurePackage),
	}

	start := time.Now()

	// Though we read files while parsing, type-checking is otherwise CPU bound.
	//
	// This doesn't achieve great CPU utilization as many packages may block
	// waiting for a common import, but in combination with the non-deterministic
	// map iteration below this should provide decent coverage of concurrent
	// type-checking (see golang/go#47729).
	cpulimit := make(chan struct{}, runtime.GOMAXPROCS(0))
	var wg sync.WaitGroup

	for dir := range dirFiles {
		dir := dir

		cpulimit <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				<-cpulimit
			}()

			_, err := c.getDirPackage(dir)
			if err != nil {
				t.Errorf("error checking %s: %v", dir, err)
			}
		}()
	}

	wg.Wait()

	if testing.Verbose() {
		fmt.Println(len(dirFiles), "packages typechecked in", time.Since(start))
	}
}

// stdlibChecker implements concurrent type-checking of the packages defined by
// dirFiles, which must define a closed set of packages (such as GOROOT/src).
type stdlibChecker struct {
	dirFiles map[string][]string // non-test files per directory; must be pre-populated

	mu   sync.Mutex
	pkgs map[string]*futurePackage // future cache of type-checking results
}

// A futurePackage is a future result of type-checking.
type futurePackage struct {
	done chan struct{} // guards pkg and err
	pkg  *Package
	err  error
}

func (c *stdlibChecker) Import(path string) (*Package, error) {
	panic("unimplemented: use ImportFrom")
}

func (c *stdlibChecker) ImportFrom(path, dir string, _ ImportMode) (*Package, error) {
	if path == "unsafe" {
		// unsafe cannot be type checked normally.
		return Unsafe, nil
	}

	p, err := build.Default.Import(path, dir, build.FindOnly)
	if err != nil {
		return nil, err
	}

	pkg, err := c.getDirPackage(p.Dir)
	if pkg != nil {
		// As long as pkg is non-nil, avoid redundant errors related to failed
		// imports. TestStdlib will collect errors once for each package.
		return pkg, nil
	}
	return nil, err
}

// getDirPackage gets the package defined in dir from the future cache.
//
// If this is the first goroutine requesting the package, getDirPackage
// type-checks.
func (c *stdlibChecker) getDirPackage(dir string) (*Package, error) {
	c.mu.Lock()
	fut, ok := c.pkgs[dir]
	if !ok {
		// First request for this package dir; type check.
		fut = &futurePackage{
			done: make(chan struct{}),
		}
		c.pkgs[dir] = fut
		files, ok := c.dirFiles[dir]
		c.mu.Unlock()
		if !ok {
			fut.err = fmt.Errorf("no files for %s", dir)
		} else {
			// Using dir as the package path here may be inconsistent with the behavior
			// of a normal importer, but is sufficient as dir is by construction unique
			// to this package.
			fut.pkg, fut.err = typecheckFiles(dir, files, c)
		}
		close(fut.done)
	} else {
		// Otherwise, await the result.
		c.mu.Unlock()
		<-fut.done
	}
	return fut.pkg, fut.err
}

// firstComment returns the contents of the first non-empty comment in
// the given file, "skip", or the empty string. No matter the present
// comments, if any of them contains a build tag, the result is always
// "skip". Only comments within the first 4K of the file are considered.
// TODO(gri) should only read until we see "package" token.
func firstComment(filename string) (first string) {
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()

	// read at most 4KB
	var buf [4 << 10]byte
	n, _ := f.Read(buf[:])
	src := bytes.NewBuffer(buf[:n])

	// TODO(gri) we need a better way to terminate CommentsDo
	defer func() {
		if p := recover(); p != nil {
			if s, ok := p.(string); ok {
				first = s
			}
		}
	}()

	syntax.CommentsDo(src, func(_, _ uint, text string) {
		if text[0] != '/' {
			return // not a comment
		}

		// extract comment text
		if text[1] == '*' {
			text = text[:len(text)-2]
		}
		text = strings.TrimSpace(text[2:])

		if strings.HasPrefix(text, "go:build ") {
			panic("skip")
		}
		if first == "" {
			first = text // text may be "" but that's ok
		}
		// continue as we may still see build tags
	})

	return
}

func testTestDir(t *testing.T, path string, ignore ...string) {
	files, err := os.ReadDir(path)
	if err != nil {
		// cmd/distpack deletes GOROOT/test, so skip the test if it isn't present.
		// cmd/distpack also requires GOROOT/VERSION to exist, so use that to
		// suppress false-positive skips.
		if _, err := os.Stat(filepath.Join(testenv.GOROOT(t), "test")); os.IsNotExist(err) {
			if _, err := os.Stat(filepath.Join(testenv.GOROOT(t), "VERSION")); err == nil {
				t.Skipf("skipping: GOROOT/test not present")
			}
		}
		t.Fatal(err)
	}

	excluded := make(map[string]bool)
	for _, filename := range ignore {
		excluded[filename] = true
	}

	for _, f := range files {
		// filter directory contents
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || excluded[f.Name()] {
			continue
		}

		// get per-file instructions
		expectErrors := false
		filename := filepath.Join(path, f.Name())
		goVersion := ""
		if comment := firstComment(filename); comment != "" {
			if strings.Contains(comment, "-goexperiment") {
				continue // ignore this file
			}
			fields := strings.Fields(comment)
			switch fields[0] {
			case "skip", "compiledir":
				continue // ignore this file
			case "errorcheck":
				expectErrors = true
				for _, arg := range fields[1:] {
					if arg == "-0" || arg == "-+" || arg == "-std" {
						// Marked explicitly as not expecting errors (-0),
						// or marked as compiling runtime/stdlib, which is only done
						// to trigger runtime/stdlib-only error output.
						// In both cases, the code should typecheck.
						expectErrors = false
						break
					}
					const prefix = "-lang="
					if strings.HasPrefix(arg, prefix) {
						goVersion = arg[len(prefix):]
					}
				}
			}
		}

		// parse and type-check file
		if testing.Verbose() {
			fmt.Println("\t", filename)
		}
		file, err := syntax.ParseFile(filename, nil, nil, 0)
		if err == nil {
			conf := Config{
				GoVersion: goVersion,
				Importer:  stdLibImporter,
			}
			_, err = conf.Check(filename, []*syntax.File{file}, nil)
		}

		if expectErrors {
			if err == nil {
				t.Errorf("expected errors but found none in %s", filename)
			}
		} else {
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func TestStdTest(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	if testing.Short() && testenv.Builder() == "" {
		t.Skip("skipping in short mode")
	}

	testTestDir(t, filepath.Join(testenv.GOROOT(t), "test"),
		"cmplxdivide.go", // also needs file cmplxdivide1.go - ignore
		"directive.go",   // tests compiler rejection of bad directive placement - ignore
		"directive2.go",  // tests compiler rejection of bad directive placement - ignore
		"embedfunc.go",   // tests //go:embed
		"embedvers.go",   // tests //go:embed
		"linkname2.go",   // types2 doesn't check validity of //go:xxx directives
		"linkname3.go",   // types2 doesn't check validity of //go:xxx directives
	)
}

func TestStdFixed(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	if testing.Short() && testenv.Builder() == "" {
		t.Skip("skipping in short mode")
	}

	testTestDir(t, filepath.Join(testenv.GOROOT(t), "test", "fixedbugs"),
		"bug248.go", "bug302.go", "bug369.go", // complex test instructions - ignore
		"bug398.go",      // types2 doesn't check for anonymous interface cycles (go.dev/issue/56103)
		"issue6889.go",   // gc-specific test
		"issue11362.go",  // canonical import path check
		"issue16369.go",  // types2 handles this correctly - not an issue
		"issue18459.go",  // types2 doesn't check validity of //go:xxx directives
		"issue18882.go",  // types2 doesn't check validity of //go:xxx directives
		"issue20027.go",  // types2 does not have constraints on channel element size
		"issue20529.go",  // types2 does not have constraints on stack size
		"issue22200.go",  // types2 does not have constraints on stack size
		"issue22200b.go", // types2 does not have constraints on stack size
		"issue25507.go",  // types2 does not have constraints on stack size
		"issue20780.go",  // types2 does not have constraints on stack size
		"issue42058a.go", // types2 does not have constraints on channel element size
		"issue42058b.go", // types2 does not have constraints on channel element size
		"issue48097.go",  // go/types doesn't check validity of //go:xxx directives, and non-init bodyless function
		"issue48230.go",  // go/types doesn't check validity of //go:xxx directives
		"issue49767.go",  // go/types does not have constraints on channel element size
		"issue49814.go",  // go/types does not have constraints on array size
		"issue56103.go",  // anonymous interface cycles; will be a type checker error in 1.22
		"issue52697.go",  // types2 does not have constraints on stack size

		// These tests requires runtime/cgo.Incomplete, which is only available on some platforms.
		// However, types2 does not know about build constraints.
		"bug514.go",
		"issue40954.go",
		"issue42032.go",
		"issue42076.go",
		"issue46903.go",
		"issue51733.go",
		"notinheap2.go",
		"notinheap3.go",
	)
}

func TestStdKen(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	testTestDir(t, filepath.Join(testenv.GOROOT(t), "test", "ken"))
}

// Package paths of excluded packages.
var excluded = map[string]bool{
	"builtin":                       true,
	"cmd/compile/internal/ssa/_gen": true,
}

// printPackageMu synchronizes the printing of type-checked package files in
// the typecheckFiles function.
//
// Without synchronization, package files may be interleaved during concurrent
// type-checking.
var printPackageMu sync.Mutex

// typecheckFiles typechecks the given package files.
func typecheckFiles(path string, filenames []string, importer Importer) (*Package, error) {
	// Parse package files.
	var files []*syntax.File
	for _, filename := range filenames {
		var errs []error
		errh := func(err error) { errs = append(errs, err) }
		file, err := syntax.ParseFile(filename, errh, nil, 0)
		if err != nil {
			return nil, errors.Join(errs...)
		}

		files = append(files, file)
	}

	if testing.Verbose() {
		printPackageMu.Lock()
		fmt.Println("package", files[0].PkgName.Value)
		for _, filename := range filenames {
			fmt.Println("\t", filename)
		}
		printPackageMu.Unlock()
	}

	// Typecheck package files.
	var errs []error
	conf := Config{
		Error: func(err error) {
			errs = append(errs, err)
		},
		Importer:    importer,
		EnableAlias: true,
	}
	info := Info{Uses: make(map[*syntax.Name]Object)}
	pkg, _ := conf.Check(path, files, &info)
	err := errors.Join(errs...)
	if err != nil {
		return pkg, err
	}

	// Perform checks of API invariants.

	// All Objects have a package, except predeclared ones.
	errorError := Universe.Lookup("error").Type().Underlying().(*Interface).ExplicitMethod(0) // (error).Error
	for id, obj := range info.Uses {
		predeclared := obj == Universe.Lookup(obj.Name()) || obj == errorError
		if predeclared == (obj.Pkg() != nil) {
			posn := id.Pos()
			if predeclared {
				return nil, fmt.Errorf("%s: predeclared object with package: %s", posn, obj)
			} else {
				return nil, fmt.Errorf("%s: user-defined object without package: %s", posn, obj)
			}
		}
	}

	return pkg, nil
}

// pkgFilenames returns the list of package filenames for the given directory.
func pkgFilenames(dir string, includeTest bool) ([]string, error) {
	ctxt := build.Default
	ctxt.CgoEnabled = false
	pkg, err := ctxt.ImportDir(dir, 0)
	if err != nil {
		if _, nogo := err.(*build.NoGoError); nogo {
			return nil, nil // no *.go files, not an error
		}
		return nil, err
	}
	if excluded[pkg.ImportPath] {
		return nil, nil
	}
	if slices.Contains(strings.Split(pkg.ImportPath, "/"), "_asm") {
		// Submodules where not all dependencies are available.
		// See go.dev/issue/46027.
		return nil, nil
	}
	var filenames []string
	for _, name := range pkg.GoFiles {
		filenames = append(filenames, filepath.Join(pkg.Dir, name))
	}
	if includeTest {
		for _, name := range pkg.TestGoFiles {
			filenames = append(filenames, filepath.Join(pkg.Dir, name))
		}
	}
	return filenames, nil
}

func walkPkgDirs(dir string, pkgh func(dir string, filenames []string), errh func(args ...interface{})) {
	w := walker{pkgh, errh}
	w.walk(dir)
}

type walker struct {
	pkgh func(dir string, filenames []string)
	errh func(args ...any)
}

func (w *walker) walk(dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		w.errh(err)
		return
	}

	// apply pkgh to the files in directory dir

	// Don't get test files as these packages are imported.
	pkgFiles, err := pkgFilenames(dir, false)
	if err != nil {
		w.errh(err)
		return
	}
	if pkgFiles != nil {
		w.pkgh(dir, pkgFiles)
	}

	// traverse subdirectories, but don't walk into testdata
	for _, f := range files {
		if f.IsDir() && f.Name() != "testdata" {
			w.walk(filepath.Join(dir, f.Name()))
		}
	}
}

"""



```