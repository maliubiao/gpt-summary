Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The first step is to understand the purpose of the code. The comment at the very beginning, "// This file tests types.Check by using it to typecheck the standard library and tests.", is the most crucial piece of information. This tells us the code is designed to test the `go/types` package itself by using it to type-check the Go standard library.

2. **Identify Key Functions and Structures:**  Scan the code for prominent function names and type definitions. This helps in identifying the major components and how they interact. Key things that stand out are:
    * `TestStdlib`:  Clearly the main test function for the standard library.
    * `stdlibChecker`:  A custom type with methods for managing and performing type-checking. The name suggests its core responsibility.
    * `futurePackage`:  A structure likely used for managing asynchronous type-checking results, given the use of `chan struct{}` and mutexes.
    * `getDirPackage`: A function associated with `stdlibChecker` which seems to handle retrieving and potentially initiating type-checking for a directory.
    * `typecheckFiles`:  The function that performs the actual parsing and type-checking of Go files.
    * `TestStdTest`, `TestStdFixed`, `TestStdKen`: Other test functions focused on specific subsets of the standard library's test code.
    * `walkPkgDirs`:  A utility function for traversing directories to find Go packages.
    * `pkgFilenames`: A function for retrieving the Go source files within a given directory.

3. **Trace the Execution Flow of `TestStdlib`:**  Since the goal is to understand the main functionality, start with the `TestStdlib` function.
    * It skips if running in short mode.
    * It uses `testenv.MustHaveGoBuild(t)` suggesting it needs a working Go build environment.
    * It collects non-test files from the Go standard library's `src` directory using `walkPkgDirs`.
    * It creates a `stdlibChecker`.
    * It uses goroutines and a semaphore (`cpulimit`) to concurrently type-check packages. This hints at performance testing and potentially uncovering concurrency issues in the type-checker.
    * Inside the goroutine, it calls `c.getDirPackage(dir)` to initiate type-checking for a specific directory.

4. **Analyze `stdlibChecker` and `getDirPackage`:**  The `stdlibChecker` structure holds the state for the type-checking process, notably the `dirFiles` and `pkgs` maps. The `pkgs` map stores `futurePackage`s. The `getDirPackage` function implements a pattern for concurrent access and lazy initialization. It checks if a package has already been requested. If not, it creates a `futurePackage`, starts the type-checking using `typecheckFiles`, and stores the result. This is a common pattern for avoiding redundant work in concurrent systems.

5. **Examine `typecheckFiles`:** This is the core type-checking logic.
    * It parses the Go files in a directory.
    * It uses the `go/types` package's `Config` and `Check` functions to perform type-checking.
    * It includes an error handler that collects type errors.
    * It performs some post-type-checking assertions about the `Object`s and their associated packages.

6. **Investigate the Other Test Functions:**  `TestStdTest`, `TestStdFixed`, and `TestStdKen` follow a similar pattern using the `testTestDir` helper function. This function reads files from a directory, parses them, and type-checks them, considering special comments for error expectations or skipping. This suggests these tests are more focused on specific scenarios or known issues.

7. **Identify Supporting Functions:**  `walkPkgDirs` and `pkgFilenames` are helper functions for locating the Go source files needed for type-checking. `firstComment` extracts information from the initial comments of a Go file, used to control how individual test files are processed (e.g., expecting errors, skipping).

8. **Infer the Go Feature Being Tested:**  Based on the analysis, the primary goal is clearly testing the `go/types` package's ability to correctly type-check valid Go code. The use of the standard library as input provides a large and complex codebase for testing. The concurrent execution aims to stress-test the type-checker.

9. **Construct Example Code:** To illustrate the `go/types` functionality, create a simple example that demonstrates the basic steps involved in parsing and type-checking Go code, similar to what `typecheckFiles` does. This involves creating a `token.FileSet`, parsing files with `parser.ParseFile`, configuring `types.Config`, and then calling `conf.Check`.

10. **Consider Command-Line Arguments:** The code uses `testing.Short()` and `testenv.Builder()`, which are influenced by Go's testing flags (e.g., `-short`). Explain how these flags affect the execution of the tests.

11. **Identify Potential Pitfalls:** Think about common mistakes users might make when trying to use `go/types` for type-checking. For example, forgetting to set up the `Importer` correctly, not handling errors properly, or misunderstanding the scope and purpose of the `Info` struct.

12. **Structure the Answer:** Organize the findings logically, starting with the overall functionality, then explaining the key components, providing the code example, discussing command-line arguments, and finally addressing potential pitfalls. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Might have initially focused too much on the concurrency aspects. Realized the *primary* goal is correctness testing of `go/types`, with concurrency being a secondary aspect for performance and stress testing.
* **Clarification on `Importer`:**  Recognized the importance of the `Importer` interface and how `importer.ForCompiler` is used to simulate the standard library's import behavior. This is crucial for correctly resolving dependencies during type-checking.
* **Emphasis on `types.Config`:**  Understood the role of `types.Config` in customizing the type-checking process (e.g., setting the `Importer`, handling errors).
* **Pinpointing the core `types.Check` function:**  Identified `conf.Check` as the central function performing the type analysis.

By following these steps, iteratively analyzing the code, and refining the understanding, we can arrive at a comprehensive explanation of the provided Go code.
这段代码是 Go 语言 `go/types` 包的一部分，专门用于**测试 `go/types.Check` 函数的正确性**。它通过对 Go 标准库的源代码进行类型检查来实现这一目标。

以下是代码的主要功能：

1. **遍历标准库源代码目录:** 它使用 `walkPkgDirs` 函数递归地遍历 Go 语言安装目录下的 `src` 目录，查找所有的 Go 源代码文件（非测试文件）。

2. **并发类型检查:**  它使用 goroutine 和信号量 (`cpulimit`) 并发地对找到的每个 Go 包进行类型检查。这样可以加速测试过程，并可能发现并发类型检查中潜在的问题。

3. **使用 `go/types.Config.Check` 进行类型检查:**  对于每个 Go 包，它使用 `go/parser` 解析源代码文件，然后使用 `go/types.Config.Check` 函数对这些文件进行类型检查。

4. **自定义导入器 (`stdlibChecker`):** 它实现了一个自定义的 `Importer` 接口 (`stdlibChecker`)，用于在类型检查过程中查找和导入依赖的包。这个自定义的导入器避免了重复导入相同的包，提高了效率。

5. **处理 `unsafe` 包:**  `unsafe` 包无法正常进行类型检查，代码中对其进行了特殊处理，直接返回 `types.Unsafe`。

6. **处理构建约束 (build tags):** `firstComment` 函数用于读取 Go 源文件的第一个非空注释，并检查其中是否包含构建标签。如果包含构建标签，则跳过该文件，因为 `go/types` 不会考虑构建约束。

7. **测试标准库的测试代码:**  `TestStdTest`, `TestStdFixed`, 和 `TestStdKen` 函数用于测试标准库中 `test`, `test/fixedbugs`, 和 `test/ken` 目录下的测试代码。这些函数使用 `testTestDir` 辅助函数来完成实际的测试。

8. **错误检查:** 代码会记录类型检查过程中遇到的错误。在测试标准库的测试代码时，它还会解析文件开头的注释，如果注释中包含 "errorcheck"，则期望类型检查会产生错误。

**它是什么 Go 语言功能的实现？**

这段代码主要测试的是 `go/types` 包提供的**静态类型检查**功能。`go/types` 包是 Go 语言工具链的一部分，用于分析 Go 代码的类型信息，包括：

* **类型推断:** 确定变量、常量、函数等的类型。
* **类型检查:** 验证代码是否符合 Go 语言的类型规则，例如，确保函数调用的参数类型与函数定义的参数类型匹配。
* **查找标识符的定义:** 确定代码中使用的标识符（变量名、函数名等）指向哪个声明。

**Go 代码举例说明：**

假设我们有以下简单的 Go 代码文件 `example.go`:

```go
package main

import "fmt"

func main() {
	var message string = "Hello, world!"
	fmt.Println(message)
	var count int = "not a number" // 故意引入类型错误
	fmt.Println(count)
}
```

我们可以使用 `go/types` 包来检查这个文件的类型错误：

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
)

func main() {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "example.go", nil, 0)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}

	config := types.Config{Importer: &types.StdImporter{}}
	info := &types.Info{
		Types: make(map[ast.Expr]types.TypeAndValue),
		Uses:  make(map[*ast.Ident]types.Object),
		Defs:  make(map[*ast.Ident]types.Object),
	}
	_, err = config.Check("example", fset, []*ast.File{file}, info)
	if err != nil {
		fmt.Println("类型检查错误:", err)
	} else {
		fmt.Println("类型检查通过!")
	}
}
```

**假设的输入与输出：**

* **输入:** `example.go` 文件包含上述代码。
* **输出:**  程序会输出：`类型检查错误: example.go:9:6: cannot convert "not a number" to type int`

**代码推理：**

在上面的例子中，`types.Config` 被配置为使用标准的导入器 (`types.StdImporter`)。 `config.Check` 函数接收文件名、文件集、抽象语法树 (`ast.File`) 和一个 `types.Info` 结构体作为参数。 `config.Check` 会分析代码，并将类型信息填充到 `info` 结构体中。由于 `example.go` 中存在将字符串赋值给 `int` 类型变量的错误，`config.Check` 会返回一个错误。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。但是，它使用了 `testing` 包，这意味着它可以通过 `go test` 命令来运行。 `go test` 命令本身有很多参数，例如：

* `-short`:  在短模式下运行测试，会跳过一些耗时的测试用例（例如 `TestStdlib` 在短模式下会被跳过）。
* `-v`:  显示更详细的测试输出。
* `-run <regexp>`:  只运行匹配正则表达式的测试用例。

例如，要运行所有的标准库类型检查测试，可以在 Go 语言源代码的 `go/types` 目录下执行：

```bash
go test
```

要运行详细模式的标准库类型检查测试：

```bash
go test -v
```

要只运行 `TestStdlib` 测试：

```bash
go test -run TestStdlib
```

**使用者易犯错的点：**

1. **忘记设置正确的 `Importer`:**  `go/types.Config` 需要一个 `Importer` 接口的实现来解析导入的包。如果忘记设置或设置了错误的 `Importer`，类型检查可能会失败或产生不准确的结果。例如，如果在一个不包含标准库源代码的环境中运行测试，并且没有提供正确的 `Importer`，就会出错。

   ```go
   // 错误示例：忘记设置 Importer
   config := types.Config{}
   // ...
   ```

2. **没有处理 `config.Check` 返回的错误:** `config.Check` 函数会返回一个 `error` 类型的值，表示类型检查过程中是否发生了错误。使用者需要检查并处理这个错误。

   ```go
   _, err := config.Check("example", fset, []*ast.File{file}, info)
   if err != nil {
       fmt.Println("类型检查失败:", err)
       // 正确的做法是处理错误
   }
   ```

3. **误解 `Info` 结构体的作用:** `types.Info` 结构体用于存储类型检查的结果，例如表达式的类型、标识符的定义等。使用者需要在调用 `config.Check` 之前初始化 `Info` 结构体，并在之后使用它来获取类型信息。

   ```go
   info := &types.Info{
       Types: make(map[ast.Expr]types.TypeAndValue),
       Uses:  make(map[*ast.Ident]types.Object),
       Defs:  make(map[*ast.Ident]types.Object),
   }
   _, err = config.Check("example", fset, []*ast.File{file}, info)
   // 现在可以通过 info.Types, info.Uses, info.Defs 访问类型信息
   ```

总而言之，这段代码是 `go/types` 包自身功能的一个重要测试，它通过对标准库的大量代码进行类型检查，确保了 `go/types.Check` 函数的正确性和健壮性。理解这段代码有助于我们更好地理解 `go/types` 包的工作原理以及如何使用它来进行 Go 代码的静态分析。

Prompt: 
```
这是路径为go/src/go/types/stdlib_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file tests types.Check by using it to
// typecheck the standard library and tests.

package types_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/scanner"
	"go/token"
	"internal/testenv"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	. "go/types"
)

// The cmd/*/internal packages may have been deleted as part of a binary
// release. Import from source instead.
//
// (See https://golang.org/issue/43232 and
// https://github.com/golang/build/blob/df58bbac082bc87c4a3cdfe336d1ffe60bbaa916/cmd/release/release.go#L533-L545.)
//
// Use the same importer for all std lib tests to
// avoid repeated importing of the same packages.
var stdLibImporter = importer.ForCompiler(token.NewFileSet(), "source", nil)

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
// "skip". Only comments before the "package" token and within the first
// 4K of the file are considered.
func firstComment(filename string) string {
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer f.Close()

	var src [4 << 10]byte // read at most 4KB
	n, _ := f.Read(src[:])

	var first string
	var s scanner.Scanner
	s.Init(fset.AddFile("", fset.Base(), n), src[:n], nil /* ignore errors */, scanner.ScanComments)
	for {
		_, tok, lit := s.Scan()
		switch tok {
		case token.COMMENT:
			// remove trailing */ of multi-line comment
			if lit[1] == '*' {
				lit = lit[:len(lit)-2]
			}
			contents := strings.TrimSpace(lit[2:])
			if strings.HasPrefix(contents, "go:build ") {
				return "skip"
			}
			if first == "" {
				first = contents // contents may be "" but that's ok
			}
			// continue as we may still see build tags

		case token.PACKAGE, token.EOF:
			return first
		}
	}
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

	fset := token.NewFileSet()
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
		file, err := parser.ParseFile(fset, filename, nil, 0)
		if err == nil {
			conf := Config{
				GoVersion: goVersion,
				Importer:  stdLibImporter,
			}
			_, err = conf.Check(filename, fset, []*ast.File{file}, nil)
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
		"linkname2.go",   // go/types doesn't check validity of //go:xxx directives
		"linkname3.go",   // go/types doesn't check validity of //go:xxx directives
	)
}

func TestStdFixed(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	if testing.Short() && testenv.Builder() == "" {
		t.Skip("skipping in short mode")
	}

	testTestDir(t, filepath.Join(testenv.GOROOT(t), "test", "fixedbugs"),
		"bug248.go", "bug302.go", "bug369.go", // complex test instructions - ignore
		"bug398.go",      // go/types doesn't check for anonymous interface cycles (go.dev/issue/56103)
		"issue6889.go",   // gc-specific test
		"issue11362.go",  // canonical import path check
		"issue16369.go",  // go/types handles this correctly - not an issue
		"issue18459.go",  // go/types doesn't check validity of //go:xxx directives
		"issue18882.go",  // go/types doesn't check validity of //go:xxx directives
		"issue20027.go",  // go/types does not have constraints on channel element size
		"issue20529.go",  // go/types does not have constraints on stack size
		"issue22200.go",  // go/types does not have constraints on stack size
		"issue22200b.go", // go/types does not have constraints on stack size
		"issue25507.go",  // go/types does not have constraints on stack size
		"issue20780.go",  // go/types does not have constraints on stack size
		"bug251.go",      // go.dev/issue/34333 which was exposed with fix for go.dev/issue/34151
		"issue42058a.go", // go/types does not have constraints on channel element size
		"issue42058b.go", // go/types does not have constraints on channel element size
		"issue48097.go",  // go/types doesn't check validity of //go:xxx directives, and non-init bodyless function
		"issue48230.go",  // go/types doesn't check validity of //go:xxx directives
		"issue49767.go",  // go/types does not have constraints on channel element size
		"issue49814.go",  // go/types does not have constraints on array size
		"issue56103.go",  // anonymous interface cycles; will be a type checker error in 1.22
		"issue52697.go",  // go/types does not have constraints on stack size

		// These tests requires runtime/cgo.Incomplete, which is only available on some platforms.
		// However, go/types does not know about build constraints.
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
	fset := token.NewFileSet()

	// Parse package files.
	var files []*ast.File
	for _, filename := range filenames {
		file, err := parser.ParseFile(fset, filename, nil, parser.AllErrors)
		if err != nil {
			return nil, err
		}

		files = append(files, file)
	}

	if testing.Verbose() {
		printPackageMu.Lock()
		fmt.Println("package", files[0].Name.Name)
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
		Importer: importer,
	}
	info := Info{Uses: make(map[*ast.Ident]Object)}
	pkg, _ := conf.Check(path, fset, files, &info)
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
			posn := fset.Position(id.Pos())
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

func walkPkgDirs(dir string, pkgh func(dir string, filenames []string), errh func(args ...any)) {
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