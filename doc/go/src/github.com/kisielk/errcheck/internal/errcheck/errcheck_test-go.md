Response:
Let's break down the thought process for analyzing this Go test code.

1. **Identify the Core Purpose:** The filename `errcheck_test.go` and the package name `errcheck` strongly suggest this code is testing functionality related to checking for unchecked errors in Go code. The presence of `TestUnchecked`, `TestBlank`, and `TestAll` further reinforces this idea.

2. **Understand the Test Setup:** The `init()` function is crucial. It parses a test package (`testPackage`) and looks for specific comments (`UNCHECKED`, `BLANK`, `ASSERT`) within the Go files. This immediately tells us how the tests are structured: they mark locations where errors *should* be reported.

3. **Analyze the Test Functions:**
    * `TestUnchecked`:  The call to `test(t, 0)` suggests it checks for standard unchecked errors.
    * `TestBlank`: The call to `test(t, CheckBlank)` implies it checks for assignments to the blank identifier (`_ = someFunc()`).
    * `TestAll`: The call to `test(t, CheckAsserts|CheckBlank)` indicates it checks for both unchecked errors and blank identifier assignments, potentially also related to assertions (though the comment mentions it might not be fully independent yet).
    * `TestBuildTags`: This function clearly tests how the error checking tool handles build tags. It creates temporary files with different build tags and verifies that the correct number of errors are reported based on the tags used.
    * `TestWhitelist` and `TestIgnore`:  These function names suggest testing the ability to exclude or ignore certain error checks. The code for `TestWhitelist` is currently empty, but `TestIgnore` demonstrates ignoring errors based on package path and function name using regular expressions.
    * `TestWithoutGeneratedCode`:  This function tests the ability to skip error checking in files marked as "generated code".

4. **Examine the `test` Function:** This is the workhorse. It initializes a `Checker`, sets flags based on the test being run (`CheckAsserts`, `CheckBlank`), runs the error check on `testPackage`, and then compares the reported errors with the markers found in the `init()` function. This confirms the tool is correctly identifying the marked errors.

5. **Look for Supporting Data Structures and Types:**
    * `marker`:  This struct represents a location in the code (file and line number) where an error is expected.
    * `uncheckedMarkers`, `blankMarkers`, `assertMarkers`: These maps store the expected error locations based on the comments parsed in `init()`.
    * `flags` and the constants `CheckAsserts`, `CheckBlank`: These are used to control which types of errors are checked.

6. **Infer Functionality (errcheck tool):** Based on the tests, we can infer that the `errcheck` tool:
    * Scans Go code for unchecked errors.
    * Can be configured to also check for assignments to the blank identifier.
    * Might have functionality to check for unchecked errors related to assertions (though this seems less developed).
    * Respects Go build tags.
    * Allows whitelisting or ignoring specific errors.
    * Can be configured to ignore generated code.

7. **Consider Command-Line Arguments (Based on Inference):** Although the provided code doesn't directly show command-line parsing, the functionality tested strongly suggests the `errcheck` tool likely accepts arguments for:
    * Specifying the packages to check.
    * Enabling checking for blank identifier assignments.
    * Enabling checking for assertion-related errors.
    * Specifying build tags.
    * Providing a whitelist or ignore list (likely through files or command-line flags).
    * Enabling the "ignore generated code" feature.

8. **Identify Potential User Mistakes:** The test code highlights a few areas where users might make mistakes:
    * Not understanding how to use build tags with `errcheck`.
    * Incorrectly configuring the ignore list (e.g., using the non-vendored path when intending to ignore a vendored package).
    * Not realizing that generated code might be flagged if the "ignore generated code" option is not used.

9. **Structure the Answer:** Organize the findings into logical sections: 功能, 功能实现推理 (with code examples), 命令行参数处理, and 使用者易犯错的点.

10. **Refine and Elaborate:**  Add details to each section, providing code examples where appropriate and explaining the reasoning behind the inferences. Ensure the language is clear and easy to understand. For example, when discussing build tags, explain how they affect which files are processed. When discussing the ignore feature, illustrate the difference between vendored and non-vendored paths.

By following this systematic approach, we can effectively analyze the provided test code and accurately describe the functionality of the `errcheck` tool.
这段代码是 Go 语言 `errcheck` 工具的一部分，专门用于测试 `errcheck` 工具自身的功能。它通过编写各种包含“应该被检查到”和“不应该被检查到”的错误的代码示例，来验证 `errcheck` 是否能够正确地识别出未处理的错误。

**功能列举:**

1. **测试未检查的错误:**  `TestUnchecked` 函数测试 `errcheck` 工具是否能够检测到那些返回值是 `error` 类型，但没有被显式处理（例如，赋值给变量或用 `if err != nil` 判断）的函数调用。
2. **测试赋值给空白标识符的错误:** `TestBlank` 函数测试 `errcheck` 是否能够检测到将 `error` 类型的返回值赋值给空白标识符 `_` 的情况。这通常意味着开发者有意忽略了错误。
3. **测试所有错误类型:** `TestAll` 函数组合了 `TestUnchecked` 和 `TestBlank` 的测试，旨在验证 `errcheck` 同时检查多种类型的未处理错误。代码中的注释 `// TODO: CheckAsserts should work independently of CheckBlank` 表明可能未来还会加入对断言相关的错误检查。
4. **测试构建标签的处理:** `TestBuildTags` 函数测试 `errcheck` 工具是否能够正确地处理 Go 语言的构建标签（build tags）。它可以创建包含不同构建标签的临时文件，并验证 `errcheck` 在指定不同标签时，是否会检查到预期数量的错误。
5. **测试白名单功能 (占位符):** `TestWhitelist` 函数目前是空的，但其命名暗示了未来可能会测试 `errcheck` 工具的白名单功能，即允许用户指定某些特定的错误可以被忽略。
6. **测试忽略功能:** `TestIgnore` 函数测试 `errcheck` 工具的忽略功能。用户可以通过正则表达式指定某些包或函数产生的错误可以被忽略。这个测试用例模拟了忽略 vendor 目录下的包产生的错误。
7. **测试忽略生成代码的功能:** `TestWithoutGeneratedCode` 函数测试 `errcheck` 工具是否能够忽略由代码生成工具生成的代码中的错误。它通过在代码中添加 `// Code generated by protoc-gen-go. DO NOT EDIT.` 这样的注释来模拟生成代码。
8. **辅助测试的基础框架:**  `marker` 结构体和相关的 `newMarker` 和 `String` 方法用于方便地表示代码中的一个位置（文件名和行号）。`uncheckedMarkers`, `blankMarkers`, `assertMarkers` 这些 map 用于存储在测试用例代码中通过特殊注释（`UNCHECKED`, `BLANK`, `ASSERT`）标记的预期错误位置。`test` 函数是一个通用的测试函数，它根据传入的 `flags` 参数来执行不同类型的错误检查，并与预期的错误位置进行比较。

**Go 语言功能实现推理及代码举例:**

这段代码主要测试的是静态代码分析工具的功能，即在不运行代码的情况下检查代码中潜在的问题。`errcheck` 工具的核心功能是检查函数返回值中的 `error` 类型是否被妥善处理。

**未检查的错误 (TestUnchecked):**

假设 `testdata` 包中有一个文件 `unchecked.go`，内容如下：

```go
package testdata

import "fmt"

func mightFail() error {
	return fmt.Errorf("something went wrong")
}

func main() {
	mightFail() // UNCHECKED
}
```

`TestUnchecked` 的目的是确保 `errcheck` 能识别出 `mightFail()` 的返回值没有被处理。

**赋值给空白标识符的错误 (TestBlank):**

假设 `testdata` 包中有一个文件 `blank.go`，内容如下：

```go
package testdata

import "fmt"

func mightFail() error {
	return fmt.Errorf("something went wrong")
}

func main() {
	_ = mightFail() // BLANK
}
```

`TestBlank` 的目的是确保 `errcheck` 能识别出 `mightFail()` 的返回值被赋值给了空白标识符。

**构建标签的处理 (TestBuildTags):**

`TestBuildTags` 创建了带有不同构建标签的临时文件。例如，`custom1.go` 可能有 `// +build custom1` 这样的构建标签。当 `errcheck` 工具运行时，如果指定了 `-tags custom1`，那么 `custom1.go` 文件会被包含在分析中，否则会被忽略。

**代码推理及假设的输入与输出 (以 `TestUnchecked` 为例):**

**假设输入:**

* `testdata` 包的源代码中包含类似 `mightFail()` 这样的函数调用，其返回值未被处理，并且在该行注释了 `// UNCHECKED`。

**推理过程:**

1. `init()` 函数会加载 `testdata` 包，并解析源代码中的注释。
2. 它会找到 `unchecked.go` 文件中带有 `// UNCHECKED` 注释的那一行，并将该位置（文件名和行号）存储在 `uncheckedMarkers` map 中。
3. `TestUnchecked` 函数会调用 `test(t, 0)`。
4. `test` 函数会创建一个 `Checker` 实例，并调用其 `CheckPackages(testPackage)` 方法来分析 `testPackage`。
5. `Checker` 内部会分析 `mightFail()` 的调用，发现其返回值 `error` 未被处理。
6. `Checker` 会将这个未处理的错误记录下来。
7. `test` 函数会将 `Checker` 返回的错误信息与 `uncheckedMarkers` 中的预期错误位置进行比较。

**假设输出:**

如果 `errcheck` 正确地检测到了未处理的错误，`TestUnchecked` 将会通过。如果 `errcheck` 没有检测到，`TestUnchecked` 将会报告错误，指出期望在某个文件和行号找到未处理的错误，但实际没有找到。

**命令行参数的具体处理 (推断):**

虽然这段代码没有直接处理命令行参数，但根据其测试的功能，可以推断 `errcheck` 工具可能支持以下命令行参数：

* **指定要检查的包路径:** 例如 `errcheck ./...` 或 `errcheck github.com/your/package`。
* **控制是否检查赋值给空白标识符的错误:**  可能有一个类似 `-blank` 或 `-check-blank` 的 flag。
* **指定构建标签:**  可能有一个类似 `-tags "tag1,tag2"` 的 flag。
* **指定要忽略的包或函数:** 可能通过一个配置文件或者命令行参数，例如 `-ignore "package/path:FunctionName"` 或者使用正则表达式 `-ignore-pkg "regexp"` 和 `-ignore-func "regexp"`。
* **控制是否忽略生成代码:** 可能有一个类似 `-ignore-generated` 的 flag。

**使用者易犯错的点 (根据代码推断):**

1. **构建标签理解错误:**  使用者可能不清楚构建标签的作用，导致 `errcheck` 在分析时包含了或排除了他们不希望包含或排除的文件。例如，他们可能期望检查所有代码，但由于构建标签的限制，某些文件被跳过了。
    ```go
    // +build !custom

    package example

    import "fmt"

    func mightFail() error {
        return fmt.Errorf("this error might be missed")
    }

    func main() {
        mightFail() // 如果 errcheck 没有指定 -tags custom，这个错误可能不会被检测到
    }
    ```
2. **忽略规则配置错误:**  使用者可能在配置忽略规则时犯错，导致某些应该被检查的错误被意外地忽略了，或者某些不应该被忽略的错误被忽略了。例如，在 `TestIgnore` 中，区分了 vendored 和 non-vendored 的路径，使用者可能混淆这两者。
    ```bash
    # 假设使用者想忽略 vendor/github.com/testlog 包中的 Info 函数
    # 错误的忽略方式（如果 errcheck 在非 vendor 模式下运行）
    # errcheck -ignore "github.com/testlog:Info" ./...
    # 正确的忽略方式（假设 errcheck 在 vendor 模式下运行）
    # errcheck -ignore "github.com/testvendor/vendor/github.com/testlog:Info" ./...
    ```
3. **对 "空白标识符" 的理解不足:**  使用者可能不清楚将错误赋值给空白标识符的潜在风险，认为这是一种合法的忽略错误的方式，但 `errcheck` 会将其标记出来。
    ```go
    package main

    import "errors"

    func mightFail() error {
        return errors.New("something went wrong")
    }

    func main() {
        _ = mightFail() // 使用者可能认为这样可以忽略错误，但 errcheck 会标记
    }
    ```
4. **没有意识到生成代码会被检查:**  使用者可能没有意识到 `errcheck` 默认会检查生成代码，导致产生大量的误报。他们需要使用 `-ignore-generated` 参数来避免这种情况。

总而言之，这段测试代码揭示了 `errcheck` 工具的核心功能是静态分析 Go 代码以发现未处理的错误，并提供了针对不同场景和配置的测试用例。理解这些测试用例有助于更好地理解 `errcheck` 工具的功能和使用方法。

Prompt: 
```
这是路径为go/src/github.com/kisielk/errcheck/internal/errcheck/errcheck_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package errcheck

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"testing"

	"golang.org/x/tools/go/packages"
)

const testPackage = "github.com/kisielk/errcheck/testdata"

var (
	uncheckedMarkers map[marker]bool
	blankMarkers     map[marker]bool
	assertMarkers    map[marker]bool
)

type marker struct {
	file string
	line int
}

func newMarker(e UncheckedError) marker {
	return marker{e.Pos.Filename, e.Pos.Line}
}

func (m marker) String() string {
	return fmt.Sprintf("%s:%d", m.file, m.line)
}

func init() {
	uncheckedMarkers = make(map[marker]bool)
	blankMarkers = make(map[marker]bool)
	assertMarkers = make(map[marker]bool)

	cfg := &packages.Config{
		Mode:  packages.LoadSyntax,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, testPackage)
	if err != nil {
		panic(fmt.Errorf("failed to import test package: %v", err))
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			for _, comment := range file.Comments {
				text := comment.Text()
				pos := pkg.Fset.Position(comment.Pos())
				m := marker{pos.Filename, pos.Line}
				switch text {
				case "UNCHECKED\n":
					uncheckedMarkers[m] = true
				case "BLANK\n":
					blankMarkers[m] = true
				case "ASSERT\n":
					assertMarkers[m] = true
				}
			}
		}
	}
}

type flags uint

const (
	CheckAsserts flags = 1 << iota
	CheckBlank
)

// TestUnchecked runs a test against the example files and ensures all unchecked errors are caught.
func TestUnchecked(t *testing.T) {
	test(t, 0)
}

// TestBlank is like TestUnchecked but also ensures assignments to the blank identifier are caught.
func TestBlank(t *testing.T) {
	test(t, CheckBlank)
}

func TestAll(t *testing.T) {
	// TODO: CheckAsserts should work independently of CheckBlank
	test(t, CheckAsserts|CheckBlank)
}

func TestBuildTags(t *testing.T) {
	const (
		// uses "custom1" build tag and contains 1 unchecked error
		testBuildCustom1Tag = `
` + `// +build custom1

package custom

import "fmt"

func Print1() {
	// returns an error that is not checked
	fmt.Fprintln(nil)
}`
		// uses "custom2" build tag and contains 1 unchecked error
		testBuildCustom2Tag = `
` + `// +build custom2

package custom

import "fmt"

func Print2() {
	// returns an error that is not checked
	fmt.Fprintln(nil)
}`
		// included so that package is not empty when built without specifying tags
		testDoc = `
// Package custom contains code for testing build tags.
package custom
`
	)

	tmpGopath, err := ioutil.TempDir("", "testbuildtags")
	if err != nil {
		t.Fatalf("unable to create testbuildtags directory: %v", err)
	}
	testBuildTagsDir := path.Join(tmpGopath, "src", "github.com/testbuildtags")
	if err := os.MkdirAll(testBuildTagsDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	defer func() {
		os.RemoveAll(tmpGopath)
	}()

	if err := ioutil.WriteFile(path.Join(testBuildTagsDir, "go.mod"), []byte("module github.com/testbuildtags"), 0644); err != nil {
		t.Fatalf("Failed to write testbuildtags go.mod: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testBuildTagsDir, "custom1.go"), []byte(testBuildCustom1Tag), 0644); err != nil {
		t.Fatalf("Failed to write testbuildtags custom1: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testBuildTagsDir, "custom2.go"), []byte(testBuildCustom2Tag), 0644); err != nil {
		t.Fatalf("Failed to write testbuildtags custom2: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testBuildTagsDir, "doc.go"), []byte(testDoc), 0644); err != nil {
		t.Fatalf("Failed to write testbuildtags doc: %v", err)
	}

	cases := []struct {
		tags            []string
		numExpectedErrs int
	}{
		// with no tags specified, main is ignored and there are no errors
		{
			tags:            nil,
			numExpectedErrs: 0,
		},
		// specifying "custom1" tag includes file with 1 error
		{
			tags:            []string{"custom1"},
			numExpectedErrs: 1,
		},
		// specifying "custom1" and "custom2" tags includes 2 files with 1 error each
		{
			tags:            []string{"custom1", "custom2"},
			numExpectedErrs: 2,
		},
	}

	for i, currCase := range cases {
		checker := NewChecker()
		checker.Tags = currCase.tags

		loadPackages = func(cfg *packages.Config, paths ...string) ([]*packages.Package, error) {
			cfg.Env = append(os.Environ(),
				"GOPATH="+tmpGopath)
			cfg.Dir = testBuildTagsDir
			pkgs, err := packages.Load(cfg, paths...)
			return pkgs, err
		}
		err := checker.CheckPackages("github.com/testbuildtags")

		if currCase.numExpectedErrs == 0 {
			if err != nil {
				t.Errorf("Case %d: expected no errors, but got: %v", i, err)
			}
			continue
		}

		uerr, ok := err.(*UncheckedErrors)
		if !ok {
			t.Errorf("Case %d: wrong error type returned: %v", i, err)
			continue
		}

		if currCase.numExpectedErrs != len(uerr.Errors) {
			t.Errorf("Case %d:\nExpected: %d errors\nActual:   %d errors", i, currCase.numExpectedErrs, len(uerr.Errors))
		}
	}
}

func TestWhitelist(t *testing.T) {

}

func TestIgnore(t *testing.T) {
	const testVendorGoMod = `module github.com/testvendor

require github.com/testlog v0.0.0
`
	const testVendorMain = `
	package main

	import "github.com/testlog"

	func main() {
		// returns an error that is not checked
		testlog.Info()
	}`
	const testLog = `
	package testlog

	func Info() error {
		return nil
	}`

	// copy testvendor directory into directory for test
	tmpGopath, err := ioutil.TempDir("", "testvendor")
	if err != nil {
		t.Fatalf("unable to create testvendor directory: %v", err)
	}
	testVendorDir := path.Join(tmpGopath, "src", "github.com/testvendor")
	if err := os.MkdirAll(testVendorDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	defer func() {
		os.RemoveAll(tmpGopath)
	}()

	if err := ioutil.WriteFile(path.Join(testVendorDir, "go.mod"), []byte(testVendorGoMod), 0755); err != nil {
		t.Fatalf("Failed to write testvendor go.mod: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testVendorDir, "main.go"), []byte(testVendorMain), 0755); err != nil {
		t.Fatalf("Failed to write testvendor main: %v", err)
	}
	if err := os.MkdirAll(path.Join(testVendorDir, "vendor/github.com/testlog"), 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testVendorDir, "vendor/github.com/testlog/testlog.go"), []byte(testLog), 0755); err != nil {
		t.Fatalf("Failed to write testlog: %v", err)
	}

	cases := []struct {
		ignore          map[string]*regexp.Regexp
		numExpectedErrs int
	}{
		// basic case has one error
		{
			ignore:          nil,
			numExpectedErrs: 1,
		},
		// ignoring vendored import works
		{
			ignore: map[string]*regexp.Regexp{
				path.Join("github.com/testvendor/vendor/github.com/testlog"): regexp.MustCompile("Info"),
			},
		},
		// non-vendored path ignores vendored import
		{
			ignore: map[string]*regexp.Regexp{
				"github.com/testlog": regexp.MustCompile("Info"),
			},
		},
	}

	for i, currCase := range cases {
		checker := NewChecker()
		checker.Ignore = currCase.ignore
		loadPackages = func(cfg *packages.Config, paths ...string) ([]*packages.Package, error) {
			cfg.Env = append(os.Environ(),
				"GOPATH="+tmpGopath,
				"GOFLAGS=-mod=vendor")
			cfg.Dir = testVendorDir
			pkgs, err := packages.Load(cfg, paths...)
			return pkgs, err
		}
		err := checker.CheckPackages("github.com/testvendor")

		if currCase.numExpectedErrs == 0 {
			if err != nil {
				t.Errorf("Case %d: expected no errors, but got: %v", i, err)
			}
			continue
		}

		uerr, ok := err.(*UncheckedErrors)
		if !ok {
			t.Errorf("Case %d: wrong error type returned: %v", i, err)
			continue
		}

		if currCase.numExpectedErrs != len(uerr.Errors) {
			t.Errorf("Case %d:\nExpected: %d errors\nActual:   %d errors", i, currCase.numExpectedErrs, len(uerr.Errors))
		}
	}
}

func TestWithoutGeneratedCode(t *testing.T) {
	const testVendorGoMod = `module github.com/testvendor

require github.com/testlog v0.0.0
`
	const testVendorMain = `
	// Code generated by protoc-gen-go. DO NOT EDIT.
	package main

	import "github.com/testlog"

	func main() {
		// returns an error that is not checked
		testlog.Info()
	}`
	const testLog = `
	package testlog

	func Info() error {
		return nil
	}`

	// copy testvendor directory into directory for test
	tmpGopath, err := ioutil.TempDir("", "testvendor")
	if err != nil {
		t.Fatalf("unable to create testvendor directory: %v", err)
	}
	testVendorDir := path.Join(tmpGopath, "src", "github.com/testvendor")
	if err := os.MkdirAll(testVendorDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	defer func() {
		os.RemoveAll(tmpGopath)
	}()

	if err := ioutil.WriteFile(path.Join(testVendorDir, "go.mod"), []byte(testVendorGoMod), 0755); err != nil {
		t.Fatalf("Failed to write testvendor go.mod: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testVendorDir, "main.go"), []byte(testVendorMain), 0755); err != nil {
		t.Fatalf("Failed to write testvendor main: %v", err)
	}
	if err := os.MkdirAll(path.Join(testVendorDir, "vendor/github.com/testlog"), 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := ioutil.WriteFile(path.Join(testVendorDir, "vendor/github.com/testlog/testlog.go"), []byte(testLog), 0755); err != nil {
		t.Fatalf("Failed to write testlog: %v", err)
	}

	cases := []struct {
		withoutGeneratedCode bool
		numExpectedErrs      int
	}{
		// basic case has one error
		{
			withoutGeneratedCode: false,
			numExpectedErrs:      1,
		},
		// ignoring generated code works
		{
			withoutGeneratedCode: true,
			numExpectedErrs:      0,
		},
	}

	for i, currCase := range cases {
		checker := NewChecker()
		checker.WithoutGeneratedCode = currCase.withoutGeneratedCode
		loadPackages = func(cfg *packages.Config, paths ...string) ([]*packages.Package, error) {
			cfg.Env = append(os.Environ(),
				"GOPATH="+tmpGopath,
				"GOFLAGS=-mod=vendor")
			cfg.Dir = testVendorDir
			pkgs, err := packages.Load(cfg, paths...)
			return pkgs, err
		}
		err := checker.CheckPackages(path.Join("github.com/testvendor"))

		if currCase.numExpectedErrs == 0 {
			if err != nil {
				t.Errorf("Case %d: expected no errors, but got: %v", i, err)
			}
			continue
		}

		uerr, ok := err.(*UncheckedErrors)
		if !ok {
			t.Errorf("Case %d: wrong error type returned: %v", i, err)
			continue
		}

		if currCase.numExpectedErrs != len(uerr.Errors) {
			t.Errorf("Case %d:\nExpected: %d errors\nActual:   %d errors", i, currCase.numExpectedErrs, len(uerr.Errors))
		}
	}
}

func test(t *testing.T, f flags) {
	var (
		asserts bool = f&CheckAsserts != 0
		blank   bool = f&CheckBlank != 0
	)
	checker := NewChecker()
	checker.Asserts = asserts
	checker.Blank = blank
	checker.SetExclude(map[string]bool{
		fmt.Sprintf("(%s.ErrorMakerInterface).MakeNilError", testPackage): true,
	})
	err := checker.CheckPackages(testPackage)
	uerr, ok := err.(*UncheckedErrors)
	if !ok {
		t.Fatalf("wrong error type returned: %v", err)
	}

	numErrors := len(uncheckedMarkers)
	if blank {
		numErrors += len(blankMarkers)
	}
	if asserts {
		numErrors += len(assertMarkers)
	}

	if len(uerr.Errors) != numErrors {
		t.Errorf("got %d errors, want %d", len(uerr.Errors), numErrors)
	unchecked_loop:
		for k := range uncheckedMarkers {
			for _, e := range uerr.Errors {
				if newMarker(e) == k {
					continue unchecked_loop
				}
			}
			t.Errorf("Expected unchecked at %s", k)
		}
		if blank {
		blank_loop:
			for k := range blankMarkers {
				for _, e := range uerr.Errors {
					if newMarker(e) == k {
						continue blank_loop
					}
				}
				t.Errorf("Expected blank at %s", k)
			}
		}
		if asserts {
		assert_loop:
			for k := range assertMarkers {
				for _, e := range uerr.Errors {
					if newMarker(e) == k {
						continue assert_loop
					}
				}
				t.Errorf("Expected assert at %s", k)
			}
		}
	}

	for i, err := range uerr.Errors {
		m := marker{err.Pos.Filename, err.Pos.Line}
		if !uncheckedMarkers[m] && !blankMarkers[m] && !assertMarkers[m] {
			t.Errorf("%d: unexpected error: %v", i, err)
		}
	}
}

"""



```