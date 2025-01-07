Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the code, explanation of the Go features it uses, illustrative examples, details on command-line argument handling (if any), and common pitfalls. The context is clearly about Go's testing framework.

2. **Initial Scan for Key Structures and Functions:**  A quick read reveals prominent types like `TestCover`, `testFuncs`, and functions like `TestPackagesFor`, `TestPackagesAndErrors`, `loadTestFuncs`, `formatTestmain`. These immediately suggest a focus on building and running tests.

3. **Deconstruct `TestPackagesAndErrors`:** This function appears central. Let's analyze its steps:
    * **Preloading Imports:** The `preloadImports` call hints at optimization or dependency management.
    * **Loading Test Imports:** The loops iterating through `p.TestImports` and `p.XTestImports` clearly handle loading dependencies for regular and external test files. The `loadImport` function is crucial here (though its implementation isn't in this snippet).
    * **Handling Embed Directives:** The calls to `resolveEmbed` point to the use of `//go:embed` for including files in the test binary.
    * **Creating `ptest` and `pxtest`:** The conditional creation of these packages based on the presence of test files is a key function. The code carefully copies and modifies package information.
    * **Building `pmain`:** The creation of a `main` package with `_testmain.go` as the entry point is fundamental to how `go test` works. The dependencies like `testing`, `os`, etc., are added.
    * **Coverage Instrumentation:**  The `cover` parameter and the conditional logic around it highlight the code's role in handling code coverage.
    * **`recompileForTest`:** This function's name and the comments around it suggest a complex process of adjusting dependencies for the test environment. The mention of import cycles is significant.
    * **`loadTestFuncs` and `formatTestmain`:**  These functions are responsible for scanning test files for test functions and generating the `_testmain.go` file.

4. **Identify Go Features:** As the analysis of `TestPackagesAndErrors` progresses, the relevant Go features become apparent:
    * **`go/ast` and Parsing:**  The code uses `go/parser` to analyze Go source files and `go/ast` to represent the syntax tree. This is key for finding test functions.
    * **`go/build`:**  The `build.Package` structure and related functions are used for managing package information, including imports and file locations.
    * **`context`:** The use of `context.Context` suggests support for cancellation and deadlines, important for potentially long-running test operations.
    * **Templates (`text/template` or `html/template`):**  The `lazytemplate.New` and `tmpl.Execute` calls indicate the use of templates for generating the `_testmain.go` file.
    * **Embedding (`//go:embed`):**  The `resolveEmbed` function clearly relates to the embed directive.
    * **Internal Packages:** The use of `internal/lazytemplate` and other `internal/` packages signifies parts of the Go toolchain's internal implementation.

5. **Infer Functionality:** Based on the structure and features, we can infer the core functionalities:
    * **Locating and Parsing Test Files:** The code finds files ending in `_test.go`.
    * **Identifying Test Functions:** It uses `go/ast` to recognize functions with specific signatures (e.g., `func TestX(t *testing.T)`).
    * **Generating `_testmain.go`:**  This file is dynamically created to act as the entry point for the test execution. It imports the package under test and its test files, and it calls the registered test functions.
    * **Handling Internal and External Tests:**  The separation of `ptest` and `pxtest` handles the different scoping and dependencies of internal and external test files.
    * **Code Coverage:** The `TestCover` struct and associated logic manage the instrumentation and reporting of code coverage.
    * **Dependency Management for Tests:** The `recompileForTest` function addresses the unique dependency requirements of the test environment.

6. **Construct Examples:**  To illustrate the functionality, concrete examples are needed. Thinking about the core tasks (running a simple test, an external test, a benchmark, an example, and using coverage) leads to the example code snippets and the `go test` commands.

7. **Address Command-Line Arguments:**  While the code snippet itself doesn't *directly* process command-line arguments, it's part of the `go test` command's implementation. Therefore, explaining how `go test` uses flags like `-cover`, `-coverpkg`, etc., is crucial.

8. **Identify Potential Pitfalls:**  Common errors users make when writing or running tests need to be highlighted. These often involve import cycles, incorrect test function signatures, issues with example output, and misunderstanding coverage.

9. **Structure the Output:**  Organize the findings logically with clear headings and explanations. Use code blocks for examples and format command-line instructions clearly.

10. **Review and Refine:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might have missed the significance of `recompileForTest` and its handling of import cycles, but further analysis and the comments in the code would highlight its importance. Similarly, connecting the code back to the `go test` command is essential for providing practical context.
这段代码是 Go 语言 `go test` 命令实现的一部分，位于 `go/src/cmd/go/internal/load/test.go` 文件中。它的主要功能是**加载和处理 Go 语言的测试文件，并生成用于执行测试的 `_testmain.go` 文件。**

更具体地说，它实现了以下功能：

1. **识别测试文件和测试函数:**  它会扫描指定包及其外部测试包（`_test` 后缀的包）中的 Go 文件，识别符合测试函数命名规范（例如 `TestXxx`, `BenchmarkXxx`, `ExampleXxx`）的函数。

2. **处理测试依赖:** 它会分析测试文件中的 `import` 语句，加载测试所需的依赖包。

3. **生成 `_testmain.go` 文件:**  这是一个临时的 Go 源文件，作为测试执行的入口点。它会导入被测试的包、测试包以及 `testing` 包，并注册找到的测试函数、基准测试函数、模糊测试目标和示例。

4. **处理代码覆盖率:**  如果启用了代码覆盖率（通过 `-cover` 或 `-coverpkg` 标志），它会生成相应的代码来收集覆盖率数据。

5. **处理 `TestMain` 函数:** 如果测试包中定义了 `TestMain` 函数，它会识别并将其作为测试的入口点。

**它可以被认为是 `go test` 命令中“加载测试用例”和“生成测试运行器”这两个关键步骤的实现。**

**Go 语言功能实现示例 (推理)：**

这段代码大量使用了 Go 的 `go/ast` 和 `go/parser` 包来分析 Go 源代码。

**假设输入:**  有一个名为 `mypackage` 的包，其目录结构如下：

```
mypackage/
├── mypackage.go
└── mypackage_test.go
```

`mypackage.go` 内容:

```go
package mypackage

func Add(a, b int) int {
	return a + b
}
```

`mypackage_test.go` 内容:

```go
package mypackage_test

import (
	"testing"
	"mypackage"
)

func TestAdd(t *testing.T) {
	result := mypackage.Add(2, 3)
	if result != 5 {
		t.Errorf("Add(2, 3) should be 5, but got %d", result)
	}
}
```

**代码推理:** `TestPackagesAndErrors` 函数会被调用，传入 `mypackage` 的信息。

**内部处理流程 (简化):**

1. **解析 `mypackage_test.go`:** 使用 `go/parser` 解析该文件，得到抽象语法树 (AST)。
2. **查找测试函数:** 遍历 AST，找到名为 `TestAdd` 且签名符合测试函数规范的函数。
3. **记录测试信息:** 将 `TestAdd` 函数的信息（包名、函数名）存储在 `testFuncs` 结构体中。
4. **生成 `_testmain.go` (部分):**  生成包含以下内容的代码片段（简化）：

```go
package main

import (
	"os"
	"reflect"
	"testing"
	"testing/internal/testdeps"
	_test "mypackage" // 假设不需要重命名
)

var tests = []testing.InternalTest{
	{"TestAdd", _test.TestAdd},
}

func main() {
	m := testing.MainStart(testdeps.TestDeps{}, tests, nil, nil, nil) // 忽略 benchmark, fuzz, example
	os.Exit(m.Run())
}
```

**输出 (实际上是内存中的数据结构，最终写入文件):**  一个 `_testmain.go` 文件的内容，如上所示。

**命令行参数的具体处理:**

虽然这段代码本身不直接处理命令行参数，但它会被 `go test` 命令调用，而 `go test` 命令会解析命令行参数。与这段代码相关的常见命令行参数包括：

* **`-cover`:**  启用代码覆盖率分析。这段代码中的 `TestCover` 结构体和相关的逻辑会根据这个标志来生成覆盖率收集的代码。
* **`-covermode=[set,count,atomic]`:**  指定代码覆盖率的模式。`TestCover.Mode` 会记录这个值。
* **`-coverpkg=pattern1,pattern2,...`:** 指定需要进行覆盖率分析的包。这段代码会根据这些模式加载指定的包，并在生成的 `_testmain.go` 中添加对这些包的引用，以便收集覆盖率数据。`TestCover.Pkgs` 和 `TestCover.Paths` 会记录这些信息。
* **`-run=regexp`:** 指定要运行的测试函数、基准测试函数或示例的正则表达式。虽然这段代码本身不执行过滤，但生成的 `_testmain.go` 文件会使用 `testing` 包的功能来根据这个正则表达式过滤要执行的测试。
* **`-bench=regexp`:** 指定要运行的基准测试函数的正则表达式。
* **`-fuzz=regexp`:** 指定要运行的模糊测试目标的正则表达式。
* **没有明确提及的参数，例如 `-v` (verbose)，也会影响 `go test` 的行为，但可能不会直接影响这段代码的核心逻辑，而更多影响 `testing` 包的执行。**

**使用者易犯错的点:**

1. **测试函数签名错误:**  Go 要求测试函数的签名必须是 `func TestXxx(t *testing.T)`，基准测试函数是 `func BenchmarkXxx(b *testing.B)`，示例函数是 `func ExampleXxx()` 或 `func ExampleXxx_suffix()`，模糊测试目标是 `func FuzzXxx(f *testing.F)`。如果签名不正确，这段代码可能无法识别这些函数，或者在后续的类型检查中报错。

   **例如:**

   ```go
   func TestAdd(t testing.T) { // 错误：t 的类型应该是 *testing.T
       // ...
   }
   ```

   这段代码中的 `isTestFunc` 函数会检查函数签名，如果发现错误，`checkTestFunc` 函数会返回错误信息。

2. **在内部测试和外部测试中重复定义测试函数:**  如果在一个包的内部测试文件 (`mypackage_test.go`，与包同名) 和外部测试文件 (`mypackage_other_test.go`，包名加上 `_test`) 中定义了同名的测试函数，可能会导致冲突或意外的行为。这段代码会分别处理内部和外部测试文件，并将它们的信息存储在不同的地方，但最终执行时可能会产生混淆。

3. **`TestMain` 函数的错误使用:**  `TestMain` 函数应该只在需要自定义测试执行流程时使用，并且其签名必须是 `func TestMain(m *testing.M)`。如果 `TestMain` 函数的实现有误（例如，没有调用 `m.Run()` 或 `os.Exit()`），会导致测试无法正常运行。

4. **代码覆盖率的误解:**  使用者可能会误解 `-coverpkg` 的作用范围，或者忘记添加必要的 `// +build go1.x` 注释来启用覆盖率。这段代码会根据 `-coverpkg` 加载指定的包，但如果指定的包路径不正确或无法加载，会导致覆盖率数据不完整。

总而言之，这段代码是 `go test` 命令中至关重要的一部分，它负责理解和组织测试代码，并生成测试执行所需的骨架代码。理解它的功能有助于开发者更好地理解 `go test` 的工作原理，并避免一些常见的错误。

Prompt: 
```
这是路径为go/src/cmd/go/internal/load/test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package load

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/doc"
	"go/parser"
	"go/token"
	"internal/lazytemplate"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"cmd/go/internal/cfg"
	"cmd/go/internal/fsys"
	"cmd/go/internal/str"
	"cmd/go/internal/trace"
)

var TestMainDeps = []string{
	// Dependencies for testmain.
	"os",
	"reflect",
	"testing",
	"testing/internal/testdeps",
}

type TestCover struct {
	Mode  string
	Local bool
	Pkgs  []*Package
	Paths []string
	Vars  []coverInfo
}

// TestPackagesFor is like TestPackagesAndErrors but it returns
// the package containing an error if the test packages or
// their dependencies have errors.
// Only test packages without errors are returned.
func TestPackagesFor(ctx context.Context, opts PackageOpts, p *Package, cover *TestCover) (pmain, ptest, pxtest, perr *Package) {
	pmain, ptest, pxtest = TestPackagesAndErrors(ctx, nil, opts, p, cover)
	for _, p1 := range []*Package{ptest, pxtest, pmain} {
		if p1 == nil {
			// pxtest may be nil
			continue
		}
		if p1.Error != nil {
			perr = p1
			break
		}
		if p1.Incomplete {
			ps := PackageList([]*Package{p1})
			for _, p := range ps {
				if p.Error != nil {
					perr = p
					break
				}
			}
			break
		}
	}
	if pmain.Error != nil || pmain.Incomplete {
		pmain = nil
	}
	if ptest.Error != nil || ptest.Incomplete {
		ptest = nil
	}
	if pxtest != nil && (pxtest.Error != nil || pxtest.Incomplete) {
		pxtest = nil
	}
	return pmain, ptest, pxtest, perr
}

// TestPackagesAndErrors returns three packages:
//   - pmain, the package main corresponding to the test binary (running tests in ptest and pxtest).
//   - ptest, the package p compiled with added "package p" test files.
//   - pxtest, the result of compiling any "package p_test" (external) test files.
//
// If the package has no "package p_test" test files, pxtest will be nil.
// If the non-test compilation of package p can be reused
// (for example, if there are no "package p" test files and
// package p need not be instrumented for coverage or any other reason),
// then the returned ptest == p.
//
// If done is non-nil, TestPackagesAndErrors will finish filling out the returned
// package structs in a goroutine and call done once finished. The members of the
// returned packages should not be accessed until done is called.
//
// The caller is expected to have checked that len(p.TestGoFiles)+len(p.XTestGoFiles) > 0,
// or else there's no point in any of this.
func TestPackagesAndErrors(ctx context.Context, done func(), opts PackageOpts, p *Package, cover *TestCover) (pmain, ptest, pxtest *Package) {
	ctx, span := trace.StartSpan(ctx, "load.TestPackagesAndErrors")
	defer span.Done()

	pre := newPreload()
	defer pre.flush()
	allImports := append([]string{}, p.TestImports...)
	allImports = append(allImports, p.XTestImports...)
	pre.preloadImports(ctx, opts, allImports, p.Internal.Build)

	var ptestErr, pxtestErr *PackageError
	var imports, ximports []*Package
	var stk ImportStack
	var testEmbed, xtestEmbed map[string][]string
	var incomplete bool
	stk.Push(ImportInfo{Pkg: p.ImportPath + " (test)"})
	rawTestImports := str.StringList(p.TestImports)
	for i, path := range p.TestImports {
		p1, err := loadImport(ctx, opts, pre, path, p.Dir, p, &stk, p.Internal.Build.TestImportPos[path], ResolveImport)
		if err != nil && ptestErr == nil {
			ptestErr = err
			incomplete = true
		}
		if p1.Incomplete {
			incomplete = true
		}
		p.TestImports[i] = p1.ImportPath
		imports = append(imports, p1)
	}
	var err error
	p.TestEmbedFiles, testEmbed, err = resolveEmbed(p.Dir, p.TestEmbedPatterns)
	if err != nil {
		ptestErr = &PackageError{
			ImportStack: stk.Copy(),
			Err:         err,
		}
		incomplete = true
		embedErr := err.(*EmbedError)
		ptestErr.setPos(p.Internal.Build.TestEmbedPatternPos[embedErr.Pattern])
	}
	stk.Pop()

	stk.Push(ImportInfo{Pkg: p.ImportPath + "_test"})
	pxtestNeedsPtest := false
	var pxtestIncomplete bool
	rawXTestImports := str.StringList(p.XTestImports)
	for i, path := range p.XTestImports {
		p1, err := loadImport(ctx, opts, pre, path, p.Dir, p, &stk, p.Internal.Build.XTestImportPos[path], ResolveImport)
		if err != nil && pxtestErr == nil {
			pxtestErr = err
		}
		if p1.Incomplete {
			pxtestIncomplete = true
		}
		if p1.ImportPath == p.ImportPath {
			pxtestNeedsPtest = true
		} else {
			ximports = append(ximports, p1)
		}
		p.XTestImports[i] = p1.ImportPath
	}
	p.XTestEmbedFiles, xtestEmbed, err = resolveEmbed(p.Dir, p.XTestEmbedPatterns)
	if err != nil && pxtestErr == nil {
		pxtestErr = &PackageError{
			ImportStack: stk.Copy(),
			Err:         err,
		}
		embedErr := err.(*EmbedError)
		pxtestErr.setPos(p.Internal.Build.XTestEmbedPatternPos[embedErr.Pattern])
	}
	pxtestIncomplete = pxtestIncomplete || pxtestErr != nil
	stk.Pop()

	// Test package.
	if len(p.TestGoFiles) > 0 || p.Name == "main" || cover != nil && cover.Local {
		ptest = new(Package)
		*ptest = *p
		if ptest.Error == nil {
			ptest.Error = ptestErr
		}
		ptest.Incomplete = ptest.Incomplete || incomplete
		ptest.ForTest = p.ImportPath
		ptest.GoFiles = nil
		ptest.GoFiles = append(ptest.GoFiles, p.GoFiles...)
		ptest.GoFiles = append(ptest.GoFiles, p.TestGoFiles...)
		ptest.Target = ""
		// Note: The preparation of the vet config requires that common
		// indexes in ptest.Imports and ptest.Internal.RawImports
		// all line up (but RawImports can be shorter than the others).
		// That is, for 0 ≤ i < len(RawImports),
		// RawImports[i] is the import string in the program text, and
		// Imports[i] is the expanded import string (vendoring applied or relative path expanded away).
		// Any implicitly added imports appear in Imports and Internal.Imports
		// but not RawImports (because they were not in the source code).
		// We insert TestImports, imports, and rawTestImports at the start of
		// these lists to preserve the alignment.
		// Note that p.Internal.Imports may not be aligned with p.Imports/p.Internal.RawImports,
		// but we insert at the beginning there too just for consistency.
		ptest.Imports = str.StringList(p.TestImports, p.Imports)
		ptest.Internal.Imports = append(imports, p.Internal.Imports...)
		ptest.Internal.RawImports = str.StringList(rawTestImports, p.Internal.RawImports)
		ptest.Internal.ForceLibrary = true
		ptest.Internal.BuildInfo = nil
		ptest.Internal.Build = new(build.Package)
		*ptest.Internal.Build = *p.Internal.Build
		m := map[string][]token.Position{}
		for k, v := range p.Internal.Build.ImportPos {
			m[k] = append(m[k], v...)
		}
		for k, v := range p.Internal.Build.TestImportPos {
			m[k] = append(m[k], v...)
		}
		ptest.Internal.Build.ImportPos = m
		if testEmbed == nil && len(p.Internal.Embed) > 0 {
			testEmbed = map[string][]string{}
		}
		maps.Copy(testEmbed, p.Internal.Embed)
		ptest.Internal.Embed = testEmbed
		ptest.EmbedFiles = str.StringList(p.EmbedFiles, p.TestEmbedFiles)
		ptest.Internal.OrigImportPath = p.Internal.OrigImportPath
		ptest.Internal.PGOProfile = p.Internal.PGOProfile
		ptest.Internal.Build.Directives = append(slices.Clip(p.Internal.Build.Directives), p.Internal.Build.TestDirectives...)
	} else {
		ptest = p
	}

	// External test package.
	if len(p.XTestGoFiles) > 0 {
		pxtest = &Package{
			PackagePublic: PackagePublic{
				Name:       p.Name + "_test",
				ImportPath: p.ImportPath + "_test",
				Root:       p.Root,
				Dir:        p.Dir,
				Goroot:     p.Goroot,
				GoFiles:    p.XTestGoFiles,
				Imports:    p.XTestImports,
				ForTest:    p.ImportPath,
				Module:     p.Module,
				Error:      pxtestErr,
				Incomplete: pxtestIncomplete,
				EmbedFiles: p.XTestEmbedFiles,
			},
			Internal: PackageInternal{
				LocalPrefix: p.Internal.LocalPrefix,
				Build: &build.Package{
					ImportPos:  p.Internal.Build.XTestImportPos,
					Directives: p.Internal.Build.XTestDirectives,
				},
				Imports:    ximports,
				RawImports: rawXTestImports,

				Asmflags:       p.Internal.Asmflags,
				Gcflags:        p.Internal.Gcflags,
				Ldflags:        p.Internal.Ldflags,
				Gccgoflags:     p.Internal.Gccgoflags,
				Embed:          xtestEmbed,
				OrigImportPath: p.Internal.OrigImportPath,
				PGOProfile:     p.Internal.PGOProfile,
			},
		}
		if pxtestNeedsPtest {
			pxtest.Internal.Imports = append(pxtest.Internal.Imports, ptest)
		}
	}

	// Arrange for testing.Testing to report true.
	ldflags := append(p.Internal.Ldflags, "-X", "testing.testBinary=1")
	gccgoflags := append(p.Internal.Gccgoflags, "-Wl,--defsym,testing.gccgoTestBinary=1")

	// Build main package.
	pmain = &Package{
		PackagePublic: PackagePublic{
			Name:       "main",
			Dir:        p.Dir,
			GoFiles:    []string{"_testmain.go"},
			ImportPath: p.ImportPath + ".test",
			Root:       p.Root,
			Imports:    str.StringList(TestMainDeps),
			Module:     p.Module,
		},
		Internal: PackageInternal{
			Build:          &build.Package{Name: "main"},
			BuildInfo:      p.Internal.BuildInfo,
			Asmflags:       p.Internal.Asmflags,
			Gcflags:        p.Internal.Gcflags,
			Ldflags:        ldflags,
			Gccgoflags:     gccgoflags,
			OrigImportPath: p.Internal.OrigImportPath,
			PGOProfile:     p.Internal.PGOProfile,
		},
	}

	pb := p.Internal.Build
	pmain.DefaultGODEBUG = defaultGODEBUG(pmain, pb.Directives, pb.TestDirectives, pb.XTestDirectives)
	if pmain.Internal.BuildInfo == nil || pmain.DefaultGODEBUG != p.DefaultGODEBUG {
		// Either we didn't generate build info for the package under test (because it wasn't package main), or
		// the DefaultGODEBUG used to build the test main package is different from the DefaultGODEBUG
		// used to build the package under test. If we didn't set build info for the package under test
		// pmain won't have buildinfo set (since we copy it from the package under test). If the default GODEBUG
		// used for the package under test is different from that of the test main, the BuildInfo assigned above from the package
		// under test incorrect for the test main package. Either set or correct pmain's build info.
		pmain.setBuildInfo(ctx, opts.AutoVCS)
	}

	// The generated main also imports testing, regexp, and os.
	// Also the linker introduces implicit dependencies reported by LinkerDeps.
	stk.Push(ImportInfo{Pkg: "testmain"})
	deps := TestMainDeps // cap==len, so safe for append
	if cover != nil && cfg.Experiment.CoverageRedesign {
		deps = append(deps, "internal/coverage/cfile")
	}
	ldDeps, err := LinkerDeps(p)
	if err != nil && pmain.Error == nil {
		pmain.Error = &PackageError{Err: err}
	}
	for _, d := range ldDeps {
		deps = append(deps, d)
	}
	for _, dep := range deps {
		if dep == ptest.ImportPath {
			pmain.Internal.Imports = append(pmain.Internal.Imports, ptest)
		} else {
			p1, err := loadImport(ctx, opts, pre, dep, "", nil, &stk, nil, 0)
			if err != nil && pmain.Error == nil {
				pmain.Error = err
				pmain.Incomplete = true
			}
			pmain.Internal.Imports = append(pmain.Internal.Imports, p1)
		}
	}
	stk.Pop()

	parallelizablePart := func() {
		if cover != nil && cover.Pkgs != nil && !cfg.Experiment.CoverageRedesign {
			// Add imports, but avoid duplicates.
			seen := map[*Package]bool{p: true, ptest: true}
			for _, p1 := range pmain.Internal.Imports {
				seen[p1] = true
			}
			for _, p1 := range cover.Pkgs {
				if seen[p1] {
					// Don't add duplicate imports.
					continue
				}
				seen[p1] = true
				pmain.Internal.Imports = append(pmain.Internal.Imports, p1)
			}
		}

		allTestImports := make([]*Package, 0, len(pmain.Internal.Imports)+len(imports)+len(ximports))
		allTestImports = append(allTestImports, pmain.Internal.Imports...)
		allTestImports = append(allTestImports, imports...)
		allTestImports = append(allTestImports, ximports...)
		setToolFlags(allTestImports...)

		// Do initial scan for metadata needed for writing _testmain.go
		// Use that metadata to update the list of imports for package main.
		// The list of imports is used by recompileForTest and by the loop
		// afterward that gathers t.Cover information.
		t, err := loadTestFuncs(p)
		if err != nil && pmain.Error == nil {
			pmain.setLoadPackageDataError(err, p.ImportPath, &stk, nil)
		}
		t.Cover = cover
		if len(ptest.GoFiles)+len(ptest.CgoFiles) > 0 {
			pmain.Internal.Imports = append(pmain.Internal.Imports, ptest)
			pmain.Imports = append(pmain.Imports, ptest.ImportPath)
			t.ImportTest = true
		}
		if pxtest != nil {
			pmain.Internal.Imports = append(pmain.Internal.Imports, pxtest)
			pmain.Imports = append(pmain.Imports, pxtest.ImportPath)
			t.ImportXtest = true
		}

		// Sort and dedup pmain.Imports.
		// Only matters for go list -test output.
		sort.Strings(pmain.Imports)
		w := 0
		for _, path := range pmain.Imports {
			if w == 0 || path != pmain.Imports[w-1] {
				pmain.Imports[w] = path
				w++
			}
		}
		pmain.Imports = pmain.Imports[:w]
		pmain.Internal.RawImports = str.StringList(pmain.Imports)

		// Replace pmain's transitive dependencies with test copies, as necessary.
		cycleErr := recompileForTest(pmain, p, ptest, pxtest)
		if cycleErr != nil {
			ptest.Error = cycleErr
			ptest.Incomplete = true
		}

		if cover != nil {
			if cfg.Experiment.CoverageRedesign {
				// Here ptest needs to inherit the proper coverage mode (since
				// it contains p's Go files), whereas pmain contains only
				// test harness code (don't want to instrument it, and
				// we don't want coverage hooks in the pkg init).
				ptest.Internal.Cover.Mode = p.Internal.Cover.Mode
				pmain.Internal.Cover.Mode = "testmain"
			}
			// Should we apply coverage analysis locally, only for this
			// package and only for this test? Yes, if -cover is on but
			// -coverpkg has not specified a list of packages for global
			// coverage.
			if cover.Local {
				ptest.Internal.Cover.Mode = cover.Mode

				if !cfg.Experiment.CoverageRedesign {
					var coverFiles []string
					coverFiles = append(coverFiles, ptest.GoFiles...)
					coverFiles = append(coverFiles, ptest.CgoFiles...)
					ptest.Internal.CoverVars = DeclareCoverVars(ptest, coverFiles...)
				}
			}

			if !cfg.Experiment.CoverageRedesign {
				for _, cp := range pmain.Internal.Imports {
					if len(cp.Internal.CoverVars) > 0 {
						t.Cover.Vars = append(t.Cover.Vars, coverInfo{cp, cp.Internal.CoverVars})
					}
				}
			}
		}

		data, err := formatTestmain(t)
		if err != nil && pmain.Error == nil {
			pmain.Error = &PackageError{Err: err}
			pmain.Incomplete = true
		}
		// Set TestmainGo even if it is empty: the presence of a TestmainGo
		// indicates that this package is, in fact, a test main.
		pmain.Internal.TestmainGo = &data
	}

	if done != nil {
		go func() {
			parallelizablePart()
			done()
		}()
	} else {
		parallelizablePart()
	}

	return pmain, ptest, pxtest
}

// recompileForTest copies and replaces certain packages in pmain's dependency
// graph. This is necessary for two reasons. First, if ptest is different than
// preal, packages that import the package under test should get ptest instead
// of preal. This is particularly important if pxtest depends on functionality
// exposed in test sources in ptest. Second, if there is a main package
// (other than pmain) anywhere, we need to set p.Internal.ForceLibrary and
// clear p.Internal.BuildInfo in the test copy to prevent link conflicts.
// This may happen if both -coverpkg and the command line patterns include
// multiple main packages.
func recompileForTest(pmain, preal, ptest, pxtest *Package) *PackageError {
	// The "test copy" of preal is ptest.
	// For each package that depends on preal, make a "test copy"
	// that depends on ptest. And so on, up the dependency tree.
	testCopy := map[*Package]*Package{preal: ptest}
	for _, p := range PackageList([]*Package{pmain}) {
		if p == preal {
			continue
		}
		// Copy on write.
		didSplit := p == pmain || p == pxtest || p == ptest
		split := func() {
			if didSplit {
				return
			}
			didSplit = true
			if testCopy[p] != nil {
				panic("recompileForTest loop")
			}
			p1 := new(Package)
			testCopy[p] = p1
			*p1 = *p
			p1.ForTest = preal.ImportPath
			p1.Internal.Imports = make([]*Package, len(p.Internal.Imports))
			copy(p1.Internal.Imports, p.Internal.Imports)
			p1.Imports = make([]string, len(p.Imports))
			copy(p1.Imports, p.Imports)
			p = p1
			p.Target = ""
			p.Internal.BuildInfo = nil
			p.Internal.ForceLibrary = true
			p.Internal.PGOProfile = preal.Internal.PGOProfile
		}

		// Update p.Internal.Imports to use test copies.
		for i, imp := range p.Internal.Imports {
			if p1 := testCopy[imp]; p1 != nil && p1 != imp {
				split()

				// If the test dependencies cause a cycle with pmain, this is
				// where it is introduced.
				// (There are no cycles in the graph until this assignment occurs.)
				p.Internal.Imports[i] = p1
			}
		}

		// Force main packages the test imports to be built as libraries.
		// Normal imports of main packages are forbidden by the package loader,
		// but this can still happen if -coverpkg patterns include main packages:
		// covered packages are imported by pmain. Linking multiple packages
		// compiled with '-p main' causes duplicate symbol errors.
		// See golang.org/issue/30907, golang.org/issue/34114.
		if p.Name == "main" && p != pmain && p != ptest {
			split()
		}
		// Split and attach PGO information to test dependencies if preal
		// is built with PGO.
		if preal.Internal.PGOProfile != "" && p.Internal.PGOProfile == "" {
			split()
		}
	}

	// Do search to find cycle.
	// importerOf maps each import path to its importer nearest to p.
	importerOf := map[*Package]*Package{}
	for _, p := range ptest.Internal.Imports {
		importerOf[p] = nil
	}

	// q is a breadth-first queue of packages to search for target.
	// Every package added to q has a corresponding entry in pathTo.
	//
	// We search breadth-first for two reasons:
	//
	// 	1. We want to report the shortest cycle.
	//
	// 	2. If p contains multiple cycles, the first cycle we encounter might not
	// 	   contain target. To ensure termination, we have to break all cycles
	// 	   other than the first.
	q := slices.Clip(ptest.Internal.Imports)
	for len(q) > 0 {
		p := q[0]
		q = q[1:]
		if p == ptest {
			// The stack is supposed to be in the order x imports y imports z.
			// We collect in the reverse order: z is imported by y is imported
			// by x, and then we reverse it.
			var stk ImportStack
			for p != nil {
				importer, ok := importerOf[p]
				if importer == nil && ok { // we set importerOf[p] == nil for the initial set of packages p that are imports of ptest
					importer = ptest
				}
				stk = append(stk, ImportInfo{
					Pkg: p.ImportPath,
					Pos: extractFirstImport(importer.Internal.Build.ImportPos[p.ImportPath]),
				})
				p = importerOf[p]
			}
			// complete the cycle: we set importer[p] = nil to break the cycle
			// in importerOf, it's an implicit importerOf[p] == pTest. Add it
			// back here since we reached nil in the loop above to demonstrate
			// the cycle as (for example) package p imports package q imports package r
			// imports package p.
			stk = append(stk, ImportInfo{
				Pkg: ptest.ImportPath,
			})
			slices.Reverse(stk)
			return &PackageError{
				ImportStack:   stk,
				Err:           errors.New("import cycle not allowed in test"),
				IsImportCycle: true,
			}
		}
		for _, dep := range p.Internal.Imports {
			if _, ok := importerOf[dep]; !ok {
				importerOf[dep] = p
				q = append(q, dep)
			}
		}
	}

	return nil
}

// isTestFunc tells whether fn has the type of a testing function. arg
// specifies the parameter type we look for: B, F, M or T.
func isTestFunc(fn *ast.FuncDecl, arg string) bool {
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 ||
		fn.Type.Params.List == nil ||
		len(fn.Type.Params.List) != 1 ||
		len(fn.Type.Params.List[0].Names) > 1 {
		return false
	}
	ptr, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	// We can't easily check that the type is *testing.M
	// because we don't know how testing has been imported,
	// but at least check that it's *M or *something.M.
	// Same applies for B, F and T.
	if name, ok := ptr.X.(*ast.Ident); ok && name.Name == arg {
		return true
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok && sel.Sel.Name == arg {
		return true
	}
	return false
}

// isTest tells whether name looks like a test (or benchmark, according to prefix).
// It is a Test (say) if there is a character after Test that is not a lower-case letter.
// We don't want TesticularCancer.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	rune, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(rune)
}

type coverInfo struct {
	Package *Package
	Vars    map[string]*CoverVar
}

// loadTestFuncs returns the testFuncs describing the tests that will be run.
// The returned testFuncs is always non-nil, even if an error occurred while
// processing test files.
func loadTestFuncs(ptest *Package) (*testFuncs, error) {
	t := &testFuncs{
		Package: ptest,
	}
	var err error
	for _, file := range ptest.TestGoFiles {
		if lerr := t.load(filepath.Join(ptest.Dir, file), "_test", &t.ImportTest, &t.NeedTest); lerr != nil && err == nil {
			err = lerr
		}
	}
	for _, file := range ptest.XTestGoFiles {
		if lerr := t.load(filepath.Join(ptest.Dir, file), "_xtest", &t.ImportXtest, &t.NeedXtest); lerr != nil && err == nil {
			err = lerr
		}
	}
	return t, err
}

// formatTestmain returns the content of the _testmain.go file for t.
func formatTestmain(t *testFuncs) ([]byte, error) {
	var buf bytes.Buffer
	tmpl := testmainTmpl
	if cfg.Experiment.CoverageRedesign {
		tmpl = testmainTmplNewCoverage
	}
	if err := tmpl.Execute(&buf, t); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type testFuncs struct {
	Tests       []testFunc
	Benchmarks  []testFunc
	FuzzTargets []testFunc
	Examples    []testFunc
	TestMain    *testFunc
	Package     *Package
	ImportTest  bool
	NeedTest    bool
	ImportXtest bool
	NeedXtest   bool
	Cover       *TestCover
}

// ImportPath returns the import path of the package being tested, if it is within GOPATH.
// This is printed by the testing package when running benchmarks.
func (t *testFuncs) ImportPath() string {
	pkg := t.Package.ImportPath
	if strings.HasPrefix(pkg, "_/") {
		return ""
	}
	if pkg == "command-line-arguments" {
		return ""
	}
	return pkg
}

// Covered returns a string describing which packages are being tested for coverage.
// If the covered package is the same as the tested package, it returns the empty string.
// Otherwise it is a comma-separated human-readable list of packages beginning with
// " in", ready for use in the coverage message.
func (t *testFuncs) Covered() string {
	if t.Cover == nil || t.Cover.Paths == nil {
		return ""
	}
	return " in " + strings.Join(t.Cover.Paths, ", ")
}

func (t *testFuncs) CoverSelectedPackages() string {
	if t.Cover == nil || t.Cover.Paths == nil {
		return `[]string{"` + t.Package.ImportPath + `"}`
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "[]string{")
	for k, p := range t.Cover.Pkgs {
		if k != 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, `"%s"`, p.ImportPath)
	}
	sb.WriteString("}")
	return sb.String()
}

// Tested returns the name of the package being tested.
func (t *testFuncs) Tested() string {
	return t.Package.Name
}

type testFunc struct {
	Package   string // imported package name (_test or _xtest)
	Name      string // function name
	Output    string // output, for examples
	Unordered bool   // output is allowed to be unordered.
}

var testFileSet = token.NewFileSet()

func (t *testFuncs) load(filename, pkg string, doImport, seen *bool) error {
	// Pass in the overlaid source if we have an overlay for this file.
	src, err := fsys.Open(filename)
	if err != nil {
		return err
	}
	defer src.Close()
	f, err := parser.ParseFile(testFileSet, filename, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return err
	}
	for _, d := range f.Decls {
		n, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if n.Recv != nil {
			continue
		}
		name := n.Name.String()
		switch {
		case name == "TestMain":
			if isTestFunc(n, "T") {
				t.Tests = append(t.Tests, testFunc{pkg, name, "", false})
				*doImport, *seen = true, true
				continue
			}
			err := checkTestFunc(n, "M")
			if err != nil {
				return err
			}
			if t.TestMain != nil {
				return errors.New("multiple definitions of TestMain")
			}
			t.TestMain = &testFunc{pkg, name, "", false}
			*doImport, *seen = true, true
		case isTest(name, "Test"):
			err := checkTestFunc(n, "T")
			if err != nil {
				return err
			}
			t.Tests = append(t.Tests, testFunc{pkg, name, "", false})
			*doImport, *seen = true, true
		case isTest(name, "Benchmark"):
			err := checkTestFunc(n, "B")
			if err != nil {
				return err
			}
			t.Benchmarks = append(t.Benchmarks, testFunc{pkg, name, "", false})
			*doImport, *seen = true, true
		case isTest(name, "Fuzz"):
			err := checkTestFunc(n, "F")
			if err != nil {
				return err
			}
			t.FuzzTargets = append(t.FuzzTargets, testFunc{pkg, name, "", false})
			*doImport, *seen = true, true
		}
	}
	ex := doc.Examples(f)
	sort.Slice(ex, func(i, j int) bool { return ex[i].Order < ex[j].Order })
	for _, e := range ex {
		*doImport = true // import test file whether executed or not
		if e.Output == "" && !e.EmptyOutput {
			// Don't run examples with no output.
			continue
		}
		t.Examples = append(t.Examples, testFunc{pkg, "Example" + e.Name, e.Output, e.Unordered})
		*seen = true
	}
	return nil
}

func checkTestFunc(fn *ast.FuncDecl, arg string) error {
	var why string
	if !isTestFunc(fn, arg) {
		why = fmt.Sprintf("must be: func %s(%s *testing.%s)", fn.Name.String(), strings.ToLower(arg), arg)
	}
	if fn.Type.TypeParams.NumFields() > 0 {
		why = "test functions cannot have type parameters"
	}
	if why != "" {
		pos := testFileSet.Position(fn.Pos())
		return fmt.Errorf("%s: wrong signature for %s, %s", pos, fn.Name.String(), why)
	}
	return nil
}

var testmainTmpl = lazytemplate.New("main", `
// Code generated by 'go test'. DO NOT EDIT.

package main

import (
	"os"
{{if .TestMain}}
	"reflect"
{{end}}
	"testing"
	"testing/internal/testdeps"

{{if .ImportTest}}
	{{if .NeedTest}}_test{{else}}_{{end}} {{.Package.ImportPath | printf "%q"}}
{{end}}
{{if .ImportXtest}}
	{{if .NeedXtest}}_xtest{{else}}_{{end}} {{.Package.ImportPath | printf "%s_test" | printf "%q"}}
{{end}}
{{if .Cover}}
{{range $i, $p := .Cover.Vars}}
	_cover{{$i}} {{$p.Package.ImportPath | printf "%q"}}
{{end}}
{{end}}
)

var tests = []testing.InternalTest{
{{range .Tests}}
	{"{{.Name}}", {{.Package}}.{{.Name}}},
{{end}}
}

var benchmarks = []testing.InternalBenchmark{
{{range .Benchmarks}}
	{"{{.Name}}", {{.Package}}.{{.Name}}},
{{end}}
}

var fuzzTargets = []testing.InternalFuzzTarget{
{{range .FuzzTargets}}
	{"{{.Name}}", {{.Package}}.{{.Name}}},
{{end}}
}

var examples = []testing.InternalExample{
{{range .Examples}}
	{"{{.Name}}", {{.Package}}.{{.Name}}, {{.Output | printf "%q"}}, {{.Unordered}}},
{{end}}
}

func init() {
	testdeps.ImportPath = {{.ImportPath | printf "%q"}}
}

{{if .Cover}}

// Only updated by init functions, so no need for atomicity.
var (
	coverCounters = make(map[string][]uint32)
	coverBlocks = make(map[string][]testing.CoverBlock)
)

func init() {
	{{range $i, $p := .Cover.Vars}}
	{{range $file, $cover := $p.Vars}}
	coverRegisterFile({{printf "%q" $cover.File}}, _cover{{$i}}.{{$cover.Var}}.Count[:], _cover{{$i}}.{{$cover.Var}}.Pos[:], _cover{{$i}}.{{$cover.Var}}.NumStmt[:])
	{{end}}
	{{end}}
}

func coverRegisterFile(fileName string, counter []uint32, pos []uint32, numStmts []uint16) {
	if 3*len(counter) != len(pos) || len(counter) != len(numStmts) {
		panic("coverage: mismatched sizes")
	}
	if coverCounters[fileName] != nil {
		// Already registered.
		return
	}
	coverCounters[fileName] = counter
	block := make([]testing.CoverBlock, len(counter))
	for i := range counter {
		block[i] = testing.CoverBlock{
			Line0: pos[3*i+0],
			Col0: uint16(pos[3*i+2]),
			Line1: pos[3*i+1],
			Col1: uint16(pos[3*i+2]>>16),
			Stmts: numStmts[i],
		}
	}
	coverBlocks[fileName] = block
}
{{end}}

func main() {
{{if .Cover}}
	testing.RegisterCover(testing.Cover{
		Mode: {{printf "%q" .Cover.Mode}},
		Counters: coverCounters,
		Blocks: coverBlocks,
		CoveredPackages: {{printf "%q" .Covered}},
	})
{{end}}
	m := testing.MainStart(testdeps.TestDeps{}, tests, benchmarks, fuzzTargets, examples)
{{with .TestMain}}
	{{.Package}}.{{.Name}}(m)
	os.Exit(int(reflect.ValueOf(m).Elem().FieldByName("exitCode").Int()))
{{else}}
	os.Exit(m.Run())
{{end}}
}

`)

var testmainTmplNewCoverage = lazytemplate.New("main", `
// Code generated by 'go test'. DO NOT EDIT.

package main

import (
	"os"
{{if .TestMain}}
	"reflect"
{{end}}
	"testing"
	"testing/internal/testdeps"
{{if .Cover}}
	"internal/coverage/cfile"
{{end}}

{{if .ImportTest}}
	{{if .NeedTest}}_test{{else}}_{{end}} {{.Package.ImportPath | printf "%q"}}
{{end}}
{{if .ImportXtest}}
	{{if .NeedXtest}}_xtest{{else}}_{{end}} {{.Package.ImportPath | printf "%s_test" | printf "%q"}}
{{end}}
)

var tests = []testing.InternalTest{
{{range .Tests}}
	{"{{.Name}}", {{.Package}}.{{.Name}}},
{{end}}
}

var benchmarks = []testing.InternalBenchmark{
{{range .Benchmarks}}
	{"{{.Name}}", {{.Package}}.{{.Name}}},
{{end}}
}

var fuzzTargets = []testing.InternalFuzzTarget{
{{range .FuzzTargets}}
	{"{{.Name}}", {{.Package}}.{{.Name}}},
{{end}}
}

var examples = []testing.InternalExample{
{{range .Examples}}
	{"{{.Name}}", {{.Package}}.{{.Name}}, {{.Output | printf "%q"}}, {{.Unordered}}},
{{end}}
}

func init() {
{{if .Cover}}
	testdeps.CoverMode = {{printf "%q" .Cover.Mode}}
	testdeps.Covered = {{printf "%q" .Covered}}
	testdeps.CoverSelectedPackages = {{printf "%s" .CoverSelectedPackages}}
	testdeps.CoverSnapshotFunc = cfile.Snapshot
	testdeps.CoverProcessTestDirFunc = cfile.ProcessCoverTestDir
	testdeps.CoverMarkProfileEmittedFunc = cfile.MarkProfileEmitted

{{end}}
	testdeps.ImportPath = {{.ImportPath | printf "%q"}}
}

func main() {
	m := testing.MainStart(testdeps.TestDeps{}, tests, benchmarks, fuzzTargets, examples)
{{with .TestMain}}
	{{.Package}}.{{.Name}}(m)
	os.Exit(int(reflect.ValueOf(m).Elem().FieldByName("exitCode").Int()))
{{else}}
	os.Exit(m.Run())
{{end}}
}

`)

"""



```