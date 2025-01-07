Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The primary request is to analyze a Go test file (`build_test.go`) and explain its functionality, using examples where possible.

2. **Initial Scan for Clues:**  The filename `build_test.go` immediately suggests this code is testing the `go/build` package. The import statement confirms this. Keywords like `Test...` are a strong indicator of testing functions.

3. **Analyzing `TestMain`:** This is the entry point for running tests in a package. It initializes `Default.GOROOT` and calls `m.Run()`, which executes the individual test functions. This is standard Go testing setup.

4. **Deconstructing Individual Test Functions (Core Logic):**  The bulk of the work is examining each `Test...` function. For each one:

   * **Identify the tested functionality:** Look at the function name (e.g., `TestMatch`, `TestDotSlashImport`). This provides a high-level clue.
   * **Examine the function body:**  Read through the code step by step. Look for calls to functions within the `build` package (e.g., `ctxt.matchAuto`, `ImportDir`, `Import`). These calls reveal what aspects of `go/build` are being tested.
   * **Understand the assertions:** The `t.Errorf` and `t.Fatalf` calls are crucial. They show what the test expects the output of the `build` package functions to be. Pay attention to the "want" values.
   * **Look for setup and teardown (though less prominent here):** This code mainly sets up the test conditions directly within each function.
   * **Identify the test cases:**  Many tests have multiple scenarios or inputs being tested (e.g., the `shouldBuildTests` slice). Analyze each test case and its expected outcome.

5. **Connecting Tests to `go/build` Features:** As you analyze the tests, you start to piece together the features of the `go/build` package being tested:

   * `TestMatch`:  Testing the logic for matching build tags based on OS, architecture, and custom tags.
   * `TestDotSlashImport`: Testing how relative imports (starting with `./`) are handled.
   * `TestEmptyImport`: Testing the behavior when an empty import path is given.
   * `TestEmptyFolderImport`: Testing the error returned when trying to import an empty directory.
   * `TestMultiplePackageImport`: Testing the handling of directories containing multiple packages.
   * `TestLocalDirectory`: Testing the import of the current directory.
   * `TestShouldBuild`: Testing the logic for determining whether a file should be included in a build based on `// +build` and `//go:build` directives.
   * `TestGoodOSArchFile` and `TestMatchFile`: Testing the matching of filenames based on OS and architecture.
   * `TestImportCmd`: Testing the import of packages within the Go standard library (specifically `cmd/internal/objfile`).
   * `TestExpandSrcDir` and `TestShellSafety`: Testing the expansion of `${SRCDIR}` in compiler flags.
   * `TestImportDirNotExist`: Testing the behavior when trying to import a non-existent directory.
   * `TestImportVendor`: Testing how vendoring is handled.
   * `TestImportPackageOutsideModule`: Testing import behavior in module mode without a `go.mod` file.
   * `TestIssue23594`:  Testing that documentation isn't incorrectly taken from test files.
   * `TestIssue56509`: Testing that invalid comments in non-Go files don't cause issues.
   * `TestMissingImportErrorRepetition`: Testing the format of error messages for missing imports.
   * `TestCgoImportsIgnored`: Testing that imports in cgo files are ignored when cgo is disabled.
   * `TestAllTags`: Testing that all relevant build tags are collected.
   * `TestAllTagsNonSourceFile`: Testing the handling of tags in non-source files.
   * `TestDirectives`: Testing the parsing of `//go:` directives.

6. **Inferring `go/build` Functionality and Providing Examples:**  Once you have a good understanding of what each test is verifying, you can start to infer the underlying functionality of the `go/build` package. Then, construct simple Go code examples that illustrate how these features are used. This involves creating `build.Context` instances and calling methods like `Import`, `ImportDir`, and potentially `MatchFile` (though the test shows internal usage of `matchAuto`).

7. **Identifying Command-Line Argument Handling (If Applicable):** Scan the code for interactions with `os.Args` or similar mechanisms for parsing command-line flags. In this specific code, `build_test.go` itself doesn't directly process command-line arguments. It tests the `go/build` package, which *is* used by the `go` command, but this test file focuses on the library's internal logic. Therefore, the answer should reflect that no direct command-line argument processing is present *in this test file*.

8. **Spotting Potential User Errors:** Think about how someone might misuse the `go/build` package based on the tests. For example:

   * Incorrectly structuring build tags.
   * Expecting imports to work in empty directories.
   * Being surprised by how vendoring affects import paths.
   * Not understanding the implications of module mode.

9. **Structuring the Answer:** Organize the information logically:

   * Start with a summary of the file's purpose.
   * List the key functionalities tested.
   * Provide Go code examples for important features.
   * Explain any command-line argument handling (or the lack thereof).
   * Highlight common pitfalls for users.

10. **Refinement and Review:** Read through your answer to ensure clarity, accuracy, and completeness. Make sure the Go code examples are correct and easy to understand.

By following this systematic approach, you can effectively analyze and explain the functionality of complex Go code like the provided `build_test.go` file.
这个 `go/src/go/build/build_test.go` 文件是 Go 语言 `go/build` 包的测试代码。它的主要功能是**验证 `go/build` 包的各种功能是否按预期工作**。`go/build` 包的核心职责是**理解 Go 源代码的结构和构建约束**，以便 `go` 命令能够正确地编译、链接和安装 Go 程序。

以下是该文件中测试的主要功能点，并附带 Go 代码示例：

**1. 构建标签匹配 (`TestMatch`)**

`go/build` 包需要能够根据构建标签（build tags）来判断某个文件是否应该被包含在构建过程中。构建标签通常在 Go 文件的头部注释中指定，例如 `// +build linux,amd64`。

* **功能说明:** 测试 `Context` 结构体的 `matchAuto` 方法，该方法用于判断给定的构建标签是否与当前的构建上下文匹配。构建上下文由 `GOOS`、`GOARCH` 和 `BuildTags` 等环境变量决定。

* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"go/build"
	"runtime"
)

func main() {
	ctxt := build.Default // 获取默认的构建上下文
	fmt.Println("Current OS:", runtime.GOOS)
	fmt.Println("Current Arch:", runtime.GOARCH)

	// 检查当前上下文是否匹配 "linux,amd64"
	matchLinuxAMD64 := ctxt.MatchBuildTags([]string{"linux", "amd64"})
	fmt.Println("Matches linux,amd64:", matchLinuxAMD64)

	// 修改构建标签并重新检查
	ctxt.BuildTags = []string{"customtag"}
	matchCustomTag := ctxt.MatchBuildTags([]string{"customtag"})
	fmt.Println("Matches customtag:", matchCustomTag)
}
```

* **假设输入与输出:**
    * 假设运行在 Linux/amd64 环境下。
    * 输出:
      ```
      Current OS: linux
      Current Arch: amd64
      Matches linux,amd64: true
      Matches customtag: true
      ```

**2. 相对路径导入 (`TestDotSlashImport`)**

在 Go 代码中，可以使用相对路径（例如 `./file`）来导入同一个包内的其他文件。

* **功能说明:** 测试 `ImportDir` 和 `Import` 函数处理以 `./` 开头的相对导入路径的能力。

* **Go 代码示例:**

```go
// 创建 testdata/other 目录和 testdata/other/file.go 文件
// testdata/other/file.go 内容:
// package file

// 创建 testdata/other/main.go 文件
// testdata/other/main.go 内容:
package main

import (
	"./file"
	"fmt"
)

func main() {
	fmt.Println("Imported file package")
}
```

```go
package main

import (
	"fmt"
	"go/build"
	"path/filepath"
)

func main() {
	pkg, err := build.ImportDir("testdata/other", 0)
	if err != nil {
		fmt.Println("Error importing directory:", err)
		return
	}
	fmt.Println("Imports in testdata/other:", pkg.Imports) // 应该包含 "./file"

	currentDir, _ := filepath.Abs("testdata/other")
	importedPkg, err := build.Import("./file", currentDir, 0)
	if err != nil {
		fmt.Println("Error importing ./file:", err)
		return
	}
	fmt.Println("Imported package name:", importedPkg.Name) // 应该为 "file"
}
```

* **假设输入与输出:** 假设当前目录下存在 `testdata/other` 目录和相应的文件。
    * 输出:
      ```
      Imports in testdata/other: [./file]
      Imported package name: file
      ```

**3. 空导入路径处理 (`TestEmptyImport`)**

测试当 `Import` 函数接收到空字符串作为导入路径时的行为。

* **功能说明:** 验证 `Import` 函数在接收到空导入路径时返回预期的错误和部分包信息。

* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"go/build"
	"os"
)

func main() {
	goroot := os.Getenv("GOROOT")
	pkg, err := build.Import("", goroot, build.FindOnly)
	if err != nil {
		fmt.Println("Error importing empty path:", err)
	}
	if pkg != nil {
		fmt.Println("Imported package path:", pkg.ImportPath) // 应该为空字符串
	}
}
```

* **假设输入与输出:**  假设 `GOROOT` 环境变量已设置。
    * 输出:
      ```
      Error importing empty path: cannot find package 
      Imported package path: 
      ```

**4. 空文件夹导入处理 (`TestEmptyFolderImport`)**

测试导入一个空目录时的行为。

* **功能说明:** 验证 `Import` 函数在尝试导入一个不包含 Go 源码文件的目录时返回 `NoGoError`。

* **Go 代码示例:**

```go
// 创建 testdata/empty 目录 (确保该目录为空)
package main

import (
	"fmt"
	"go/build"
)

func main() {
	_, err := build.ImportDir("testdata/empty", 0)
	if err != nil {
		fmt.Printf("Error importing empty directory: %T\n", err) // 应该输出 *build.NoGoError
	}
}
```

* **假设输入与输出:** 假设当前目录下存在一个空的 `testdata/empty` 目录。
    * 输出:
      ```
      Error importing empty directory: *build.NoGoError
      ```

**5. 多包目录导入处理 (`TestMultiplePackageImport`)**

测试当一个目录下包含多个 Go 包声明时的行为。

* **功能说明:** 验证 `Import` 函数在遇到包含多个包声明的目录时返回 `MultiplePackageError`。

* **Go 代码示例:**

```go
// 创建 testdata/multi 目录
// 创建 testdata/multi/file.go 内容:
// package main
//
// func main() {}

// 创建 testdata/multi/file_appengine.go 内容:
// // +build appengine
//
// package test_package

package main

import (
	"fmt"
	"go/build"
	"path/filepath"
)

func main() {
	_, err := build.ImportDir("testdata/multi", 0)
	if err != nil {
		fmt.Printf("Error importing multi-package directory: %T\n", err) // 应该输出 *build.MultiplePackageError

		mpe, ok := err.(*build.MultiplePackageError)
		if ok {
			fmt.Println("Multiple packages found:", mpe.Packages)
			fmt.Println("Files:", mpe.Files)
		}
	}
}
```

* **假设输入与输出:** 假设当前目录下存在 `testdata/multi` 目录和相应的文件。
    * 输出:
      ```
      Error importing multi-package directory: *build.MultiplePackageError
      Multiple packages found: [main test_package]
      Files: [file.go file_appengine.go]
      ```

**6. 本地目录导入 (`TestLocalDirectory`)**

测试导入当前工作目录的行为。

* **功能说明:** 验证 `ImportDir` 函数可以正确导入当前工作目录，并返回正确的导入路径。

* **Go 代码示例:**

```go
package main

import (
	"fmt"
	"go/build"
	"os"
)

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current directory:", err)
		return
	}

	pkg, err := build.ImportDir(cwd, 0)
	if err != nil {
		fmt.Println("Error importing current directory:", err)
		return
	}
	fmt.Println("Import path of current directory:", pkg.ImportPath) // 应该为 "go/build" (如果当前目录是 go/src/go/build)
}
```

* **假设输入与输出:** 假设在 `go/src/go/build` 目录下运行该代码。
    * 输出:
      ```
      Import path of current directory: go/build
      ```

**7. `// +build` 和 `//go:build` 指令解析 (`TestShouldBuild`)**

测试 `go/build` 包解析和理解构建约束指令的能力。

* **功能说明:** 验证 `shouldBuild` 函数能够正确判断一个文件是否应该被构建，基于文件中的 `// +build` 和 `//go:build` 指令以及当前的构建标签。

* **Go 代码示例:**  （此功能更偏向于内部逻辑测试，通常用户不会直接调用 `shouldBuild`，而是依赖 `go build` 命令）

假设有以下文件 `testdata/build_constraints.go`:

```go
// +build linux darwin
//go:build amd64

package main

import "fmt"

func main() {
	fmt.Println("This should only build on linux/amd64 or darwin/amd64")
}
```

`go/build` 包会根据当前的 `GOOS` 和 `GOARCH` 以及通过 `-tags` 传递的构建标签来判断是否应该编译此文件。

* **命令行参数处理:**

`go build` 命令会读取环境变量（如 `GOOS`, `GOARCH`）和命令行参数（如 `-tags`）来构建 `build.Context`。例如：

```bash
go build -tags="integration"  # 设置构建标签
GOOS=linux GOARCH=amd64 go build  # 设置 GOOS 和 GOARCH
```

`go/build` 包内部会解析这些信息并用于匹配文件中的构建约束。

* **使用者易犯错的点:**

   * **`// +build` 和 `//go:build` 混用且逻辑不清晰:**  容易导致构建行为与预期不符。例如：

     ```go
     // +build linux
     //go:build windows
     package main
     ```
     这个文件永远不会被构建，因为 `// +build` 和 `//go:build` 相当于逻辑与操作。

   * **构建标签拼写错误:**  如果构建标签拼写错误，匹配将失败。

   * **没有理解构建标签的逻辑运算符:**  `,` 表示 AND，空格表示 OR，`!` 表示 NOT。

     ```go
     // +build linux,amd64  // 必须同时满足 linux 和 amd64
     // +build linux darwin // 满足 linux 或 darwin 之一
     // +build !cgo       // 当 cgo 构建标签不存在时
     ```

   * **依赖隐含的构建标签:** 有些构建标签是隐含的，例如 `cgo`。如果没有正确配置 CGO 环境，可能会导致构建行为不一致。

**其他测试功能点:**

* **`TestGoodOSArchFile` 和 `TestMatchFile`:** 测试根据操作系统和架构匹配文件名的能力（例如 `file_linux.go`, `file_amd64.go`）。
* **`TestImportCmd`:** 测试导入标准库中的包的行为。
* **`TestExpandSrcDir` 和 `TestShellSafety`:** 测试展开 `${SRCDIR}` 环境变量的功能，这通常用于 CGO 的头文件路径等。
* **`TestImportDirNotExist`:** 测试导入不存在的目录时的错误处理。
* **`TestImportVendor` 和 `BenchmarkImportVendor`:** 测试对 Go Modules 中 vendor 目录的支持。
* **`TestImportPackageOutsideModule`:** 测试在 Go Modules 开启时，导入非模块依赖的行为。
* **`TestIssue23594` 和 `TestIssue56509`:**  针对特定 issue 的回归测试，确保之前修复的 bug 不会再次出现。
* **`TestMissingImportErrorRepetition`:** 测试当导入的包不存在时，错误信息的格式是否正确。
* **`TestCgoImportsIgnored`:** 测试在 CGO 被禁用时，CGO 文件中的导入是否被忽略。
* **`TestAllTags` 和 `TestAllTagsNonSourceFile`:** 测试 `Package.AllTags` 字段是否正确收集了所有相关的构建标签。
* **`TestDirectives`:** 测试解析 Go 文件中的 `//go:` 指令的能力。

总而言之，`go/src/go/build/build_test.go` 是一个非常全面的测试文件，覆盖了 `go/build` 包的各种核心功能，确保 `go` 命令能够正确地理解和处理 Go 源代码的结构和构建约束。

Prompt: 
```
这是路径为go/src/go/build/build_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package build

import (
	"fmt"
	"internal/testenv"
	"io"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	Default.GOROOT = testenv.GOROOT(nil)
	os.Exit(m.Run())
}

func TestMatch(t *testing.T) {
	ctxt := Default
	what := "default"
	match := func(tag string, want map[string]bool) {
		t.Helper()
		m := make(map[string]bool)
		if !ctxt.matchAuto(tag, m) {
			t.Errorf("%s context should match %s, does not", what, tag)
		}
		if !maps.Equal(m, want) {
			t.Errorf("%s tags = %v, want %v", tag, m, want)
		}
	}
	nomatch := func(tag string, want map[string]bool) {
		t.Helper()
		m := make(map[string]bool)
		if ctxt.matchAuto(tag, m) {
			t.Errorf("%s context should NOT match %s, does", what, tag)
		}
		if !maps.Equal(m, want) {
			t.Errorf("%s tags = %v, want %v", tag, m, want)
		}
	}

	match(runtime.GOOS+","+runtime.GOARCH, map[string]bool{runtime.GOOS: true, runtime.GOARCH: true})
	match(runtime.GOOS+","+runtime.GOARCH+",!foo", map[string]bool{runtime.GOOS: true, runtime.GOARCH: true, "foo": true})
	nomatch(runtime.GOOS+","+runtime.GOARCH+",foo", map[string]bool{runtime.GOOS: true, runtime.GOARCH: true, "foo": true})

	what = "modified"
	ctxt.BuildTags = []string{"foo"}
	match(runtime.GOOS+","+runtime.GOARCH, map[string]bool{runtime.GOOS: true, runtime.GOARCH: true})
	match(runtime.GOOS+","+runtime.GOARCH+",foo", map[string]bool{runtime.GOOS: true, runtime.GOARCH: true, "foo": true})
	nomatch(runtime.GOOS+","+runtime.GOARCH+",!foo", map[string]bool{runtime.GOOS: true, runtime.GOARCH: true, "foo": true})
	match(runtime.GOOS+","+runtime.GOARCH+",!bar", map[string]bool{runtime.GOOS: true, runtime.GOARCH: true, "bar": true})
	nomatch(runtime.GOOS+","+runtime.GOARCH+",bar", map[string]bool{runtime.GOOS: true, runtime.GOARCH: true, "bar": true})
}

func TestDotSlashImport(t *testing.T) {
	p, err := ImportDir("testdata/other", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Imports) != 1 || p.Imports[0] != "./file" {
		t.Fatalf("testdata/other: Imports=%v, want [./file]", p.Imports)
	}

	p1, err := Import("./file", "testdata/other", 0)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Name != "file" {
		t.Fatalf("./file: Name=%q, want %q", p1.Name, "file")
	}
	dir := filepath.Clean("testdata/other/file") // Clean to use \ on Windows
	if p1.Dir != dir {
		t.Fatalf("./file: Dir=%q, want %q", p1.Name, dir)
	}
}

func TestEmptyImport(t *testing.T) {
	p, err := Import("", testenv.GOROOT(t), FindOnly)
	if err == nil {
		t.Fatal(`Import("") returned nil error.`)
	}
	if p == nil {
		t.Fatal(`Import("") returned nil package.`)
	}
	if p.ImportPath != "" {
		t.Fatalf("ImportPath=%q, want %q.", p.ImportPath, "")
	}
}

func TestEmptyFolderImport(t *testing.T) {
	_, err := Import(".", "testdata/empty", 0)
	if _, ok := err.(*NoGoError); !ok {
		t.Fatal(`Import("testdata/empty") did not return NoGoError.`)
	}
}

func TestMultiplePackageImport(t *testing.T) {
	pkg, err := Import(".", "testdata/multi", 0)

	mpe, ok := err.(*MultiplePackageError)
	if !ok {
		t.Fatal(`Import("testdata/multi") did not return MultiplePackageError.`)
	}
	want := &MultiplePackageError{
		Dir:      filepath.FromSlash("testdata/multi"),
		Packages: []string{"main", "test_package"},
		Files:    []string{"file.go", "file_appengine.go"},
	}
	if !reflect.DeepEqual(mpe, want) {
		t.Errorf("err = %#v; want %#v", mpe, want)
	}

	// TODO(#45999): Since the name is ambiguous, pkg.Name should be left empty.
	if wantName := "main"; pkg.Name != wantName {
		t.Errorf("pkg.Name = %q; want %q", pkg.Name, wantName)
	}

	if wantGoFiles := []string{"file.go", "file_appengine.go"}; !slices.Equal(pkg.GoFiles, wantGoFiles) {
		t.Errorf("pkg.GoFiles = %q; want %q", pkg.GoFiles, wantGoFiles)
	}

	if wantInvalidFiles := []string{"file_appengine.go"}; !slices.Equal(pkg.InvalidGoFiles, wantInvalidFiles) {
		t.Errorf("pkg.InvalidGoFiles = %q; want %q", pkg.InvalidGoFiles, wantInvalidFiles)
	}
}

func TestLocalDirectory(t *testing.T) {
	if runtime.GOOS == "ios" {
		t.Skipf("skipping on %s/%s, no valid GOROOT", runtime.GOOS, runtime.GOARCH)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	p, err := ImportDir(cwd, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.ImportPath != "go/build" {
		t.Fatalf("ImportPath=%q, want %q", p.ImportPath, "go/build")
	}
}

var shouldBuildTests = []struct {
	name        string
	content     string
	tags        map[string]bool
	binaryOnly  bool
	shouldBuild bool
	err         error
}{
	{
		name: "Yes",
		content: "// +build yes\n\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true},
		shouldBuild: true,
	},
	{
		name: "Yes2",
		content: "//go:build yes\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true},
		shouldBuild: true,
	},
	{
		name: "Or",
		content: "// +build no yes\n\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true, "no": true},
		shouldBuild: true,
	},
	{
		name: "Or2",
		content: "//go:build no || yes\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true, "no": true},
		shouldBuild: true,
	},
	{
		name: "And",
		content: "// +build no,yes\n\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true, "no": true},
		shouldBuild: false,
	},
	{
		name: "And2",
		content: "//go:build no && yes\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true, "no": true},
		shouldBuild: false,
	},
	{
		name: "Cgo",
		content: "// +build cgo\n\n" +
			"// Copyright The Go Authors.\n\n" +
			"// This package implements parsing of tags like\n" +
			"// +build tag1\n" +
			"package build",
		tags:        map[string]bool{"cgo": true},
		shouldBuild: false,
	},
	{
		name: "Cgo2",
		content: "//go:build cgo\n" +
			"// Copyright The Go Authors.\n\n" +
			"// This package implements parsing of tags like\n" +
			"// +build tag1\n" +
			"package build",
		tags:        map[string]bool{"cgo": true},
		shouldBuild: false,
	},
	{
		name: "AfterPackage",
		content: "// Copyright The Go Authors.\n\n" +
			"package build\n\n" +
			"// shouldBuild checks tags given by lines of the form\n" +
			"// +build tag\n" +
			"//go:build tag\n" +
			"func shouldBuild(content []byte)\n",
		tags:        map[string]bool{},
		shouldBuild: true,
	},
	{
		name: "TooClose",
		content: "// +build yes\n" +
			"package main\n",
		tags:        map[string]bool{},
		shouldBuild: true,
	},
	{
		name: "TooClose2",
		content: "//go:build yes\n" +
			"package main\n",
		tags:        map[string]bool{"yes": true},
		shouldBuild: true,
	},
	{
		name: "TooCloseNo",
		content: "// +build no\n" +
			"package main\n",
		tags:        map[string]bool{},
		shouldBuild: true,
	},
	{
		name: "TooCloseNo2",
		content: "//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		shouldBuild: false,
	},
	{
		name: "BinaryOnly",
		content: "//go:binary-only-package\n" +
			"// +build yes\n" +
			"package main\n",
		tags:        map[string]bool{},
		binaryOnly:  true,
		shouldBuild: true,
	},
	{
		name: "BinaryOnly2",
		content: "//go:binary-only-package\n" +
			"//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		binaryOnly:  true,
		shouldBuild: false,
	},
	{
		name: "ValidGoBuild",
		content: "// +build yes\n\n" +
			"//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		shouldBuild: false,
	},
	{
		name: "MissingBuild2",
		content: "/* */\n" +
			"// +build yes\n\n" +
			"//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		shouldBuild: false,
	},
	{
		name: "Comment1",
		content: "/*\n" +
			"//go:build no\n" +
			"*/\n\n" +
			"package main\n",
		tags:        map[string]bool{},
		shouldBuild: true,
	},
	{
		name: "Comment2",
		content: "/*\n" +
			"text\n" +
			"*/\n\n" +
			"//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		shouldBuild: false,
	},
	{
		name: "Comment3",
		content: "/*/*/ /* hi *//* \n" +
			"text\n" +
			"*/\n\n" +
			"//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		shouldBuild: false,
	},
	{
		name: "Comment4",
		content: "/**///go:build no\n" +
			"package main\n",
		tags:        map[string]bool{},
		shouldBuild: true,
	},
	{
		name: "Comment5",
		content: "/**/\n" +
			"//go:build no\n" +
			"package main\n",
		tags:        map[string]bool{"no": true},
		shouldBuild: false,
	},
}

func TestShouldBuild(t *testing.T) {
	for _, tt := range shouldBuildTests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &Context{BuildTags: []string{"yes"}}
			tags := map[string]bool{}
			shouldBuild, binaryOnly, err := ctx.shouldBuild([]byte(tt.content), tags)
			if shouldBuild != tt.shouldBuild || binaryOnly != tt.binaryOnly || !maps.Equal(tags, tt.tags) || err != tt.err {
				t.Errorf("mismatch:\n"+
					"have shouldBuild=%v, binaryOnly=%v, tags=%v, err=%v\n"+
					"want shouldBuild=%v, binaryOnly=%v, tags=%v, err=%v",
					shouldBuild, binaryOnly, tags, err,
					tt.shouldBuild, tt.binaryOnly, tt.tags, tt.err)
			}
		})
	}
}

func TestGoodOSArchFile(t *testing.T) {
	ctx := &Context{BuildTags: []string{"linux"}, GOOS: "darwin"}
	m := map[string]bool{}
	want := map[string]bool{"linux": true}
	if !ctx.goodOSArchFile("hello_linux.go", m) {
		t.Errorf("goodOSArchFile(hello_linux.go) = false, want true")
	}
	if !maps.Equal(m, want) {
		t.Errorf("goodOSArchFile(hello_linux.go) tags = %v, want %v", m, want)
	}
}

type readNopCloser struct {
	io.Reader
}

func (r readNopCloser) Close() error {
	return nil
}

var (
	ctxtP9      = Context{GOARCH: "arm", GOOS: "plan9"}
	ctxtAndroid = Context{GOARCH: "arm", GOOS: "android"}
)

var matchFileTests = []struct {
	ctxt  Context
	name  string
	data  string
	match bool
}{
	{ctxtP9, "foo_arm.go", "", true},
	{ctxtP9, "foo1_arm.go", "// +build linux\n\npackage main\n", false},
	{ctxtP9, "foo_darwin.go", "", false},
	{ctxtP9, "foo.go", "", true},
	{ctxtP9, "foo1.go", "// +build linux\n\npackage main\n", false},
	{ctxtP9, "foo.badsuffix", "", false},
	{ctxtAndroid, "foo_linux.go", "", true},
	{ctxtAndroid, "foo_android.go", "", true},
	{ctxtAndroid, "foo_plan9.go", "", false},
	{ctxtAndroid, "android.go", "", true},
	{ctxtAndroid, "plan9.go", "", true},
	{ctxtAndroid, "plan9_test.go", "", true},
	{ctxtAndroid, "arm.s", "", true},
	{ctxtAndroid, "amd64.s", "", true},
}

func TestMatchFile(t *testing.T) {
	for _, tt := range matchFileTests {
		ctxt := tt.ctxt
		ctxt.OpenFile = func(path string) (r io.ReadCloser, err error) {
			if path != "x+"+tt.name {
				t.Fatalf("OpenFile asked for %q, expected %q", path, "x+"+tt.name)
			}
			return &readNopCloser{strings.NewReader(tt.data)}, nil
		}
		ctxt.JoinPath = func(elem ...string) string {
			return strings.Join(elem, "+")
		}
		match, err := ctxt.MatchFile("x", tt.name)
		if match != tt.match || err != nil {
			t.Fatalf("MatchFile(%q) = %v, %v, want %v, nil", tt.name, match, err, tt.match)
		}
	}
}

func TestImportCmd(t *testing.T) {
	if runtime.GOOS == "ios" {
		t.Skipf("skipping on %s/%s, no valid GOROOT", runtime.GOOS, runtime.GOARCH)
	}

	p, err := Import("cmd/internal/objfile", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(p.Dir), "src/cmd/internal/objfile") {
		t.Fatalf("Import cmd/internal/objfile returned Dir=%q, want %q", filepath.ToSlash(p.Dir), ".../src/cmd/internal/objfile")
	}
}

var (
	expandSrcDirPath = filepath.Join(string(filepath.Separator)+"projects", "src", "add")
)

var expandSrcDirTests = []struct {
	input, expected string
}{
	{"-L ${SRCDIR}/libs -ladd", "-L /projects/src/add/libs -ladd"},
	{"${SRCDIR}/add_linux_386.a -pthread -lstdc++", "/projects/src/add/add_linux_386.a -pthread -lstdc++"},
	{"Nothing to expand here!", "Nothing to expand here!"},
	{"$", "$"},
	{"$$", "$$"},
	{"${", "${"},
	{"$}", "$}"},
	{"$FOO ${BAR}", "$FOO ${BAR}"},
	{"Find me the $SRCDIRECTORY.", "Find me the $SRCDIRECTORY."},
	{"$SRCDIR is missing braces", "$SRCDIR is missing braces"},
}

func TestExpandSrcDir(t *testing.T) {
	for _, test := range expandSrcDirTests {
		output, _ := expandSrcDir(test.input, expandSrcDirPath)
		if output != test.expected {
			t.Errorf("%q expands to %q with SRCDIR=%q when %q is expected", test.input, output, expandSrcDirPath, test.expected)
		} else {
			t.Logf("%q expands to %q with SRCDIR=%q", test.input, output, expandSrcDirPath)
		}
	}
}

func TestShellSafety(t *testing.T) {
	tests := []struct {
		input, srcdir, expected string
		result                  bool
	}{
		{"-I${SRCDIR}/../include", "/projects/src/issue 11868", "-I/projects/src/issue 11868/../include", true},
		{"-I${SRCDIR}", "~wtf$@%^", "-I~wtf$@%^", true},
		{"-X${SRCDIR}/1,${SRCDIR}/2", "/projects/src/issue 11868", "-X/projects/src/issue 11868/1,/projects/src/issue 11868/2", true},
		{"-I/tmp -I/tmp", "/tmp2", "-I/tmp -I/tmp", true},
		{"-I/tmp", "/tmp/[0]", "-I/tmp", true},
		{"-I${SRCDIR}/dir", "/tmp/[0]", "-I/tmp/[0]/dir", false},
		{"-I${SRCDIR}/dir", "/tmp/go go", "-I/tmp/go go/dir", true},
		{"-I${SRCDIR}/dir dir", "/tmp/go", "-I/tmp/go/dir dir", true},
	}
	for _, test := range tests {
		output, ok := expandSrcDir(test.input, test.srcdir)
		if ok != test.result {
			t.Errorf("Expected %t while %q expands to %q with SRCDIR=%q; got %t", test.result, test.input, output, test.srcdir, ok)
		}
		if output != test.expected {
			t.Errorf("Expected %q while %q expands with SRCDIR=%q; got %q", test.expected, test.input, test.srcdir, output)
		}
	}
}

// Want to get a "cannot find package" error when directory for package does not exist.
// There should be valid partial information in the returned non-nil *Package.
func TestImportDirNotExist(t *testing.T) {
	testenv.MustHaveGoBuild(t) // Need 'go list' internally.
	ctxt := Default

	emptyDir := t.TempDir()

	ctxt.GOPATH = emptyDir
	ctxt.Dir = emptyDir

	tests := []struct {
		label        string
		path, srcDir string
		mode         ImportMode
	}{
		{"Import(full, 0)", "go/build/doesnotexist", "", 0},
		{"Import(local, 0)", "./doesnotexist", filepath.Join(ctxt.GOROOT, "src/go/build"), 0},
		{"Import(full, FindOnly)", "go/build/doesnotexist", "", FindOnly},
		{"Import(local, FindOnly)", "./doesnotexist", filepath.Join(ctxt.GOROOT, "src/go/build"), FindOnly},
	}

	defer os.Setenv("GO111MODULE", os.Getenv("GO111MODULE"))

	for _, GO111MODULE := range []string{"off", "on"} {
		t.Run("GO111MODULE="+GO111MODULE, func(t *testing.T) {
			os.Setenv("GO111MODULE", GO111MODULE)

			for _, test := range tests {
				p, err := ctxt.Import(test.path, test.srcDir, test.mode)

				errOk := (err != nil && strings.HasPrefix(err.Error(), "cannot find package"))
				wantErr := `"cannot find package" error`
				if test.srcDir == "" {
					if err != nil && strings.Contains(err.Error(), "is not in std") {
						errOk = true
					}
					wantErr = `"cannot find package" or "is not in std" error`
				}
				if !errOk {
					t.Errorf("%s got error: %q, want %s", test.label, err, wantErr)
				}
				// If an error occurs, build.Import is documented to return
				// a non-nil *Package containing partial information.
				if p == nil {
					t.Fatalf(`%s got nil p, want non-nil *Package`, test.label)
				}
				// Verify partial information in p.
				if p.ImportPath != "go/build/doesnotexist" {
					t.Errorf(`%s got p.ImportPath: %q, want "go/build/doesnotexist"`, test.label, p.ImportPath)
				}
			}
		})
	}
}

func TestImportVendor(t *testing.T) {
	testenv.MustHaveSource(t)

	t.Setenv("GO111MODULE", "off")

	ctxt := Default
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ctxt.GOPATH = filepath.Join(wd, "testdata/withvendor")
	p, err := ctxt.Import("c/d", filepath.Join(ctxt.GOPATH, "src/a/b"), 0)
	if err != nil {
		t.Fatalf("cannot find vendored c/d from testdata src/a/b directory: %v", err)
	}
	want := "a/vendor/c/d"
	if p.ImportPath != want {
		t.Fatalf("Import succeeded but found %q, want %q", p.ImportPath, want)
	}
}

func BenchmarkImportVendor(b *testing.B) {
	testenv.MustHaveSource(b)

	b.Setenv("GO111MODULE", "off")

	ctxt := Default
	wd, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	ctxt.GOPATH = filepath.Join(wd, "testdata/withvendor")
	dir := filepath.Join(ctxt.GOPATH, "src/a/b")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ctxt.Import("c/d", dir, 0)
		if err != nil {
			b.Fatalf("cannot find vendored c/d from testdata src/a/b directory: %v", err)
		}
	}
}

func TestImportVendorFailure(t *testing.T) {
	testenv.MustHaveSource(t)

	t.Setenv("GO111MODULE", "off")

	ctxt := Default
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ctxt.GOPATH = filepath.Join(wd, "testdata/withvendor")
	p, err := ctxt.Import("x.com/y/z", filepath.Join(ctxt.GOPATH, "src/a/b"), 0)
	if err == nil {
		t.Fatalf("found made-up package x.com/y/z in %s", p.Dir)
	}

	e := err.Error()
	if !strings.Contains(e, " (vendor tree)") {
		t.Fatalf("error on failed import does not mention GOROOT/src/vendor directory:\n%s", e)
	}
}

func TestImportVendorParentFailure(t *testing.T) {
	testenv.MustHaveSource(t)

	t.Setenv("GO111MODULE", "off")

	ctxt := Default
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	ctxt.GOPATH = filepath.Join(wd, "testdata/withvendor")
	// This import should fail because the vendor/c directory has no source code.
	p, err := ctxt.Import("c", filepath.Join(ctxt.GOPATH, "src/a/b"), 0)
	if err == nil {
		t.Fatalf("found empty parent in %s", p.Dir)
	}
	if p != nil && p.Dir != "" {
		t.Fatalf("decided to use %s", p.Dir)
	}
	e := err.Error()
	if !strings.Contains(e, " (vendor tree)") {
		t.Fatalf("error on failed import does not mention GOROOT/src/vendor directory:\n%s", e)
	}
}

// Check that a package is loaded in module mode if GO111MODULE=on, even when
// no go.mod file is present. It should fail to resolve packages outside std.
// Verifies golang.org/issue/34669.
func TestImportPackageOutsideModule(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	// Disable module fetching for this test so that 'go list' fails quickly
	// without trying to find the latest version of a module.
	t.Setenv("GOPROXY", "off")

	// Create a GOPATH in a temporary directory. We don't use testdata
	// because it's in GOROOT, which interferes with the module heuristic.
	gopath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(gopath, "src/example.com/p"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gopath, "src/example.com/p/p.go"), []byte("package p"), 0666); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GO111MODULE", "on")
	t.Setenv("GOPATH", gopath)
	ctxt := Default
	ctxt.GOPATH = gopath
	ctxt.Dir = filepath.Join(gopath, "src/example.com/p")

	want := "go.mod file not found in current directory or any parent directory"
	if _, err := ctxt.Import("example.com/p", gopath, FindOnly); err == nil {
		t.Fatal("importing package when no go.mod is present succeeded unexpectedly")
	} else if errStr := err.Error(); !strings.Contains(errStr, want) {
		t.Fatalf("error when importing package when no go.mod is present: got %q; want %q", errStr, want)
	} else {
		t.Logf(`ctxt.Import("example.com/p", _, FindOnly): %v`, err)
	}
}

// TestIssue23594 prevents go/build from regressing and populating Package.Doc
// from comments in test files.
func TestIssue23594(t *testing.T) {
	// Package testdata/doc contains regular and external test files
	// with comments attached to their package declarations. The names of the files
	// ensure that we see the comments from the test files first.
	p, err := ImportDir("testdata/doc", 0)
	if err != nil {
		t.Fatalf("could not import testdata: %v", err)
	}

	if p.Doc != "Correct" {
		t.Fatalf("incorrectly set .Doc to %q", p.Doc)
	}
}

// TestIssue56509 tests that go/build does not add non-go files to InvalidGoFiles
// when they have unparsable comments.
func TestIssue56509(t *testing.T) {
	// The directory testdata/bads contains a .s file that has an unparsable
	// comment. (go/build parses initial comments in non-go files looking for
	// //go:build or //+go build comments).
	p, err := ImportDir("testdata/bads", 0)
	if err == nil {
		t.Fatalf("could not import testdata/bads: %v", err)
	}

	if len(p.InvalidGoFiles) != 0 {
		t.Fatalf("incorrectly added non-go file to InvalidGoFiles")
	}
}

// TestMissingImportErrorRepetition checks that when an unknown package is
// imported, the package path is only shown once in the error.
// Verifies golang.org/issue/34752.
func TestMissingImportErrorRepetition(t *testing.T) {
	testenv.MustHaveGoBuild(t) // need 'go list' internally
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module m"), 0666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO111MODULE", "on")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GONOPROXY", "none")

	ctxt := Default
	ctxt.Dir = tmp

	pkgPath := "example.com/hello"
	_, err := ctxt.Import(pkgPath, tmp, FindOnly)
	if err == nil {
		t.Fatal("unexpected success")
	}

	// Don't count the package path with a URL like https://...?go-get=1.
	// See golang.org/issue/35986.
	errStr := strings.ReplaceAll(err.Error(), "://"+pkgPath+"?go-get=1", "://...?go-get=1")

	// Also don't count instances in suggested "go get" or similar commands
	// (see https://golang.org/issue/41576). The suggested command typically
	// follows a semicolon.
	errStr, _, _ = strings.Cut(errStr, ";")

	if n := strings.Count(errStr, pkgPath); n != 1 {
		t.Fatalf("package path %q appears in error %d times; should appear once\nerror: %v", pkgPath, n, err)
	}
}

// TestCgoImportsIgnored checks that imports in cgo files are not included
// in the imports list when cgo is disabled.
// Verifies golang.org/issue/35946.
func TestCgoImportsIgnored(t *testing.T) {
	ctxt := Default
	ctxt.CgoEnabled = false
	p, err := ctxt.ImportDir("testdata/cgo_disabled", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range p.Imports {
		if path == "should/be/ignored" {
			t.Errorf("found import %q in ignored cgo file", path)
		}
	}
}

// Issue #52053. Check that if there is a file x_GOOS_GOARCH.go that both
// GOOS and GOARCH show up in the Package.AllTags field. We test both the
// case where the file matches and where the file does not match.
// The latter case used to fail, incorrectly omitting GOOS.
func TestAllTags(t *testing.T) {
	ctxt := Default
	ctxt.GOARCH = "arm"
	ctxt.GOOS = "netbsd"
	p, err := ctxt.ImportDir("testdata/alltags", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"arm", "netbsd"}
	if !slices.Equal(p.AllTags, want) {
		t.Errorf("AllTags = %v, want %v", p.AllTags, want)
	}
	wantFiles := []string{"alltags.go", "x_netbsd_arm.go"}
	if !slices.Equal(p.GoFiles, wantFiles) {
		t.Errorf("GoFiles = %v, want %v", p.GoFiles, wantFiles)
	}

	ctxt.GOARCH = "amd64"
	ctxt.GOOS = "linux"
	p, err = ctxt.ImportDir("testdata/alltags", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.AllTags, want) {
		t.Errorf("AllTags = %v, want %v", p.AllTags, want)
	}
	wantFiles = []string{"alltags.go"}
	if !slices.Equal(p.GoFiles, wantFiles) {
		t.Errorf("GoFiles = %v, want %v", p.GoFiles, wantFiles)
	}
}

func TestAllTagsNonSourceFile(t *testing.T) {
	p, err := Default.ImportDir("testdata/non_source_tags", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AllTags) > 0 {
		t.Errorf("AllTags = %v, want empty", p.AllTags)
	}
}

func TestDirectives(t *testing.T) {
	p, err := ImportDir("testdata/directives", 0)
	if err != nil {
		t.Fatalf("could not import testdata: %v", err)
	}

	check := func(name string, list []Directive, want string) {
		if runtime.GOOS == "windows" {
			want = strings.ReplaceAll(want, "testdata/directives/", `testdata\\directives\\`)
		}
		t.Helper()
		s := fmt.Sprintf("%q", list)
		if s != want {
			t.Errorf("%s = %s, want %s", name, s, want)
		}
	}
	check("Directives", p.Directives,
		`[{"//go:main1" "testdata/directives/a.go:1:1"} {"//go:plant" "testdata/directives/eve.go:1:1"}]`)
	check("TestDirectives", p.TestDirectives,
		`[{"//go:test1" "testdata/directives/a_test.go:1:1"} {"//go:test2" "testdata/directives/b_test.go:1:1"}]`)
	check("XTestDirectives", p.XTestDirectives,
		`[{"//go:xtest1" "testdata/directives/c_test.go:1:1"} {"//go:xtest2" "testdata/directives/d_test.go:1:1"} {"//go:xtest3" "testdata/directives/d_test.go:2:1"}]`)
}

"""



```