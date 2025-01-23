Response: My thinking process to analyze the provided Go code (`check_test.go`) goes like this:

1. **Understand the Goal:** The file name `check_test.go` and the initial comments immediately suggest this is a testing file for a type checker. The comments mention comparing type checker errors against expected errors in the test files. This is the core functionality.

2. **Identify Key Functions:** I scan the code for functions that seem central to the testing process. `testFiles`, `testFilesImpl`, `testDirFiles`, `testDir`, and `testPkg` stand out. The `TestManual` function also looks significant as it seems to handle manual testing.

3. **Analyze `testFiles` and `testFilesImpl`:** These seem to be the main drivers of the type checking process.
    * `testFiles` calls `testFilesImpl` twice, once with `EnableAlias = true` and once with `false` (unless it's a manual test). This immediately tells me this test suite specifically checks the type checker's behavior with and without alias types enabled.
    * `testFilesImpl` takes filenames, source code, a column delta (for error position tolerance), a boolean for manual testing, and a variadic list of `Config` options. This suggests a configurable type checking process.

4. **Trace the Execution Flow:** I follow the execution within `testFilesImpl`:
    * **Parsing:** `parseFiles` is called to parse the Go source code into syntax trees. Error handling is present during parsing.
    * **Configuration:** A `Config` struct is initialized. The code shows setting up the importer, error handler, and applying provided options.
    * **Flag Parsing:** `parseFlags` extracts flags from the first line of the source file. This is how test cases can specify language versions or experiments.
    * **GOEXPERIMENT Handling:** The code demonstrates manipulating the `buildcfg.Experiment` for testing different Go experiment settings.
    * **Type Checking:** `conf.Check` is the core type checking invocation. It takes the package name, syntax trees, and an `Info` struct.
    * **Error Matching:**  This is a crucial part. The code extracts expected errors from comments in the source files (`/* ERROR ... */`). It then iterates through the errors reported by the type checker and attempts to match them against the expected errors, considering position (line and column with a tolerance). Regular expressions are supported for error matching using `/* ERRORx ... */`.

5. **Understand Supporting Functions:**
    * `parseFiles`: Handles parsing source files.
    * `unpackError`: Extracts the position and message from an error.
    * `absDiff`: Calculates the absolute difference between two unsigned integers (used for column delta).
    * `parseFlags`:  Parses command-line-like flags embedded in the source code.
    * `TestManual`:  Provides a way to manually test individual files or directories.
    * `testDirFiles`, `testDir`, `testPkg`: Functions for organizing and running tests on directories of Go files.
    * `withSizes`: A helper function to create a `Config` option for setting custom sizes.
    * `setGOEXPERIMENT`: Modifies the global `buildcfg.Experiment` for testing.

6. **Identify Go Language Features Tested:**  Based on the functionality, I can infer that this test suite is designed to check various aspects of the Go type system, including:
    * **Basic type checking:** Correct identification of type errors (e.g., undeclared variables).
    * **Constant evaluation:** Handling of constant overflows and excessively long constants.
    * **Type conversions and assignments:** Implicit and explicit conversions.
    * **Operator semantics:** Correct behavior of operators like shifts.
    * **Alias types:**  Testing with and without alias types enabled.
    * **Go language version compatibility:** Testing with different `-lang` flags.
    * **Go experiments:** Testing features gated by `goexperiment`.
    * **Error reporting:** Ensuring the type checker reports errors at the correct location with the expected messages.

7. **Construct Examples:**  Based on the identified features, I can create illustrative Go code snippets that would trigger the type checker and be used in the test suite. These examples would include the `/* ERROR ... */` annotations to specify the expected errors.

8. **Analyze Command-line Arguments:** The `flag` package is used to define command-line flags like `-halt` and `-verify`. `TestManual` also utilizes `flag.Args()` to get the filenames for manual testing.

9. **Identify Common Mistakes:** By examining the error matching logic and the configuration options, I can identify potential pitfalls for users writing tests, such as incorrect error message patterns or incorrect column positions.

By following these steps, I can systematically break down the code, understand its purpose, identify the Go language features it tests, and generate relevant examples and explanations. The key is to start with the high-level goal and gradually delve into the details of the implementation.

这段代码是 Go 语言编译器 `cmd/compile/internal/types2` 包的一部分，专门用于 **测试类型检查器** 的功能。它通过读取包含 Go 代码的测试文件，执行类型检查，并将类型检查器报告的错误与文件中预期的错误进行比较，以此验证类型检查器的正确性。

以下是它的主要功能点：

1. **加载和解析测试文件:**  `parseFiles` 函数负责读取指定的 Go 源代码文件，并使用 `cmd/compile/internal/syntax` 包将其解析为抽象语法树 (AST)。

2. **配置类型检查器:** `testFilesImpl` 函数中创建了一个 `Config` 结构体，用于配置类型检查器的行为。这包括设置导入器 (`Importer`)、错误处理函数 (`Error`) 以及是否启用别名类型 (`EnableAlias`) 等。

3. **从注释中提取预期错误:** 代码能够解析 Go 源代码文件中的特殊注释，例如 `/* ERROR "pattern" */` 或 `/* ERRORx "pattern" */`。这些注释指示了在特定代码位置预期出现的错误。`ERROR` 表示错误消息中应包含指定的子字符串，而 `ERRORx` 表示错误消息应匹配指定的正则表达式。

4. **执行类型检查:**  `conf.Check(pkgName, files, &info)`  是执行实际类型检查的核心调用。它会对解析后的 AST 进行类型推断、类型校验等操作。

5. **比较实际错误和预期错误:** 代码会收集类型检查器报告的错误，并与从注释中提取的预期错误进行比对。比对过程包括检查错误发生的位置（行号和列号，允许一定的列号偏差 `colDelta`）以及错误消息是否符合预期（子字符串匹配或正则表达式匹配）。

6. **处理命令行参数:**
   - `-halt`: 当类型检查器报告错误时立即停止测试。
   - `-verify`:  在手动测试模式下，不打印错误列表，而是验证报告的错误是否与 `ERROR` 注释匹配。
   - `-lang`:  指定要使用的 Go 语言版本。
   - `-goexperiment`: 设置 Go 实验性特性。
   - `-fakeImportC`: 模拟 `import "C"` 的行为。
   - `-gotypesalias`: 控制是否启用别名类型，可以设置为 "0" 来禁用。

7. **手动测试模式:** `TestManual` 函数允许用户手动指定要测试的 Go 文件或目录。这对于调试特定的类型检查问题非常有用。

8. **测试不同场景:**  代码中包含了针对各种类型检查场景的测试用例，例如常量溢出、索引越界、不同平台下的行为等。

**它是什么 Go 语言功能的实现？**

这个文件本身并不是某个特定 Go 语言功能的实现，而是 **Go 语言类型检查器** 的测试工具。它验证了 `cmd/compile/internal/types2` 包中实现的类型检查逻辑是否正确。

**Go 代码举例说明:**

假设我们有以下测试文件 `test.go`:

```go
package main

func main() {
	var x int
	y = x // ERROR "undeclared name: y"
}
```

当 `check_test.go` 的测试框架运行并处理这个文件时，它会：

1. 解析 `test.go`。
2. 执行类型检查。类型检查器会发现 `y` 未声明，并报告一个错误。
3. 提取 `test.go` 中第 5 行的注释 `// ERROR "undeclared name: y"`，表示期望在这个位置出现包含 "undeclared name: y" 子字符串的错误。
4. 比较类型检查器报告的错误信息和位置与预期。如果匹配，则该测试用例通过。

**代码推理与假设的输入与输出:**

假设 `check_test.go` 正在处理 `test.go` 文件，且 `colDelta` 设置为 0。

**输入:**

- `filenames`: `["test.go"]`
- `srcs`: `[][]byte{[]byte("package main\n\nfunc main() {\n\tvar x int\n\ty = x // ERROR \"undeclared name: y\"\n}\n")}`
- `colDelta`: 0

**输出:**

如果类型检查器正确地报告了错误，并且错误消息和位置与预期完全一致，则测试会通过，不会有明显的输出。

如果类型检查器没有报告错误，或者报告的错误消息或位置与预期不符，则 `check_test.go` 会通过 `t.Errorf` 等函数报告错误信息，例如：

```
--- FAIL: TestCheck (some_time)
    check_test.go:243: test.go:5:2: no error expected: "undeclared name: y"  // 如果没有报告错误
    check_test.go:279: test.go:5:1: unreported errors:                   // 如果预期有错误但没有报告
    check_test.go:281: test.go:5:1: undeclared name: y
```

**命令行参数的具体处理:**

- **`-halt`:** 如果在运行测试时使用了 `-halt` 标志，并且类型检查器遇到了错误，测试会立即终止，并抛出一个 panic。这可以通过 `*haltOnError` 变量来控制。
- **`-verify`:** 这个标志主要用于 `TestManual` 函数。当使用 `-verify` 时，`TestManual` 不会简单地列出类型检查器报告的错误，而是会尝试将这些错误与测试文件中的 `ERROR` 注释进行匹配。如果没有提供 `-verify`，`TestManual` 会打印出所有报告的错误。
- **`-lang version`:**  `parseFlags` 函数会解析 `-lang` 标志，并将指定的版本字符串赋值给 `conf.GoVersion`。这允许测试在模拟不同 Go 语言版本的情况下运行类型检查。例如，`go test -run Manual -- -lang=1.17 test.go` 会使用 Go 1.17 的语义进行类型检查。
- **`-goexperiment flags`:**  类似于 `-lang`，`parseFlags` 会解析 `-goexperiment` 标志，并使用 `setGOEXPERIMENT` 函数来设置 `buildcfg.Experiment`，从而启用或禁用实验性特性。例如，`go test -run TestCheck -- -goexperiment=rangefunc=1`。
- **`-fakeImportC`:**  如果设置了 `-fakeImportC` 标志，`conf.FakeImportC` 将被设置为 `true`。这会模拟 `import "C"` 的行为，允许在不实际编译 C 代码的情况下测试涉及 `unsafe` 包的代码。
- **`-gotypesalias value`:**  `parseFlags` 函数会解析 `-gotypesalias` 标志，并根据其值设置 `conf.EnableAlias`。如果 `value` 不是 "0"，则启用别名类型。

**使用者易犯错的点:**

1. **ERROR 注释格式不正确:**  `ERROR` 或 `ERRORx` 注释必须紧跟在报告错误的 token 之后，并且 `ERROR`/`ERRORx` 与模式之间、模式与结束注释符 `*/` 之间都必须有一个空格。模式本身必须是合法的 Go 字符串字面量（需要用双引号括起来）。

   ```go
   // 错误示例：
   _ = y /*ERROR"undeclared name: y"*/ // 缺少空格
   _ = y /* ERROR undeclared name: y */ // 模式没有用引号括起来

   // 正确示例：
   _ = y /* ERROR "undeclared name: y" */
   ```

2. **列号偏差超出容忍度:**  测试框架允许一定的列号偏差 (`colDelta`)。如果报告的错误列号与预期错误注释的位置列号之差超过了这个值，测试将失败。

3. **正则表达式错误:**  如果使用 `ERRORx` 注释，提供的正则表达式必须是有效的 Go 正则表达式。如果正则表达式有语法错误，测试框架会报错。

4. **期望的错误没有报告或报告了不期望的错误:**  测试框架会检查是否所有预期的错误都被报告了，以及是否报告了不应该出现的错误。如果存在不匹配的情况，测试将失败。

5. **手动测试时忘记使用 `--` 分隔标志:** 当使用 `go test -run Manual` 进行手动测试时，需要使用 `--` 来分隔 `go test` 的参数和传递给 `TestManual` 的文件名参数。

   ```bash
   go test -run Manual -- mytest.go  // 正确
   go test -run Manual mytest.go      // 错误，mytest.go 会被解析为 go test 的参数
   ```

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/check_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements a typechecker test harness. The packages specified
// in tests are typechecked. Error messages reported by the typechecker are
// compared against the errors expected in the test files.
//
// Expected errors are indicated in the test files by putting comments
// of the form /* ERROR pattern */ or /* ERRORx pattern */ (or a similar
// //-style line comment) immediately following the tokens where errors
// are reported. There must be exactly one blank before and after the
// ERROR/ERRORx indicator, and the pattern must be a properly quoted Go
// string.
//
// The harness will verify that each ERROR pattern is a substring of the
// error reported at that source position, and that each ERRORx pattern
// is a regular expression matching the respective error.
// Consecutive comments may be used to indicate multiple errors reported
// at the same position.
//
// For instance, the following test source indicates that an "undeclared"
// error should be reported for the undeclared variable x:
//
//	package p
//	func f() {
//		_ = x /* ERROR "undeclared" */ + 1
//	}

package types2_test

import (
	"bytes"
	"cmd/compile/internal/syntax"
	"flag"
	"fmt"
	"internal/buildcfg"
	"internal/testenv"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	. "cmd/compile/internal/types2"
)

var (
	haltOnError  = flag.Bool("halt", false, "halt on error")
	verifyErrors = flag.Bool("verify", false, "verify errors (rather than list them) in TestManual")
)

func parseFiles(t *testing.T, filenames []string, srcs [][]byte, mode syntax.Mode) ([]*syntax.File, []error) {
	var files []*syntax.File
	var errlist []error
	errh := func(err error) { errlist = append(errlist, err) }
	for i, filename := range filenames {
		base := syntax.NewFileBase(filename)
		r := bytes.NewReader(srcs[i])
		file, err := syntax.Parse(base, r, errh, nil, mode)
		if file == nil {
			t.Fatalf("%s: %s", filename, err)
		}
		files = append(files, file)
	}
	return files, errlist
}

func unpackError(err error) (syntax.Pos, string) {
	switch err := err.(type) {
	case syntax.Error:
		return err.Pos, err.Msg
	case Error:
		return err.Pos, err.Msg
	default:
		return nopos, err.Error()
	}
}

// absDiff returns the absolute difference between x and y.
func absDiff(x, y uint) uint {
	if x < y {
		return y - x
	}
	return x - y
}

// parseFlags parses flags from the first line of the given source if the line
// starts with "//" (line comment) followed by "-" (possibly with spaces
// between). Otherwise the line is ignored.
func parseFlags(src []byte, flags *flag.FlagSet) error {
	// we must have a line comment that starts with a "-"
	const prefix = "//"
	if !bytes.HasPrefix(src, []byte(prefix)) {
		return nil // first line is not a line comment
	}
	src = src[len(prefix):]
	if i := bytes.Index(src, []byte("-")); i < 0 || len(bytes.TrimSpace(src[:i])) != 0 {
		return nil // comment doesn't start with a "-"
	}
	end := bytes.Index(src, []byte("\n"))
	const maxLen = 256
	if end < 0 || end > maxLen {
		return fmt.Errorf("flags comment line too long")
	}

	return flags.Parse(strings.Fields(string(src[:end])))
}

// testFiles type-checks the package consisting of the given files, and
// compares the resulting errors with the ERROR annotations in the source.
// Except for manual tests, each package is type-checked twice, once without
// use of Alias types, and once with Alias types.
//
// The srcs slice contains the file content for the files named in the
// filenames slice. The colDelta parameter specifies the tolerance for position
// mismatch when comparing errors. The manual parameter specifies whether this
// is a 'manual' test.
//
// If provided, opts may be used to mutate the Config before type-checking.
func testFiles(t *testing.T, filenames []string, srcs [][]byte, colDelta uint, manual bool, opts ...func(*Config)) {
	enableAlias := true
	opts = append(opts, func(conf *Config) { conf.EnableAlias = enableAlias })
	testFilesImpl(t, filenames, srcs, colDelta, manual, opts...)
	if !manual {
		enableAlias = false
		testFilesImpl(t, filenames, srcs, colDelta, manual, opts...)
	}
}

func testFilesImpl(t *testing.T, filenames []string, srcs [][]byte, colDelta uint, manual bool, opts ...func(*Config)) {
	if len(filenames) == 0 {
		t.Fatal("no source files")
	}

	// parse files
	files, errlist := parseFiles(t, filenames, srcs, 0)
	pkgName := "<no package>"
	if len(files) > 0 {
		pkgName = files[0].PkgName.Value
	}
	listErrors := manual && !*verifyErrors
	if listErrors && len(errlist) > 0 {
		t.Errorf("--- %s:", pkgName)
		for _, err := range errlist {
			t.Error(err)
		}
	}

	// set up typechecker
	var conf Config
	conf.Trace = manual && testing.Verbose()
	conf.Importer = defaultImporter()
	conf.Error = func(err error) {
		if *haltOnError {
			defer panic(err)
		}
		if listErrors {
			t.Error(err)
			return
		}
		errlist = append(errlist, err)
	}

	// apply custom configuration
	for _, opt := range opts {
		opt(&conf)
	}

	// apply flag setting (overrides custom configuration)
	var goexperiment, gotypesalias string
	flags := flag.NewFlagSet("", flag.PanicOnError)
	flags.StringVar(&conf.GoVersion, "lang", "", "")
	flags.StringVar(&goexperiment, "goexperiment", "", "")
	flags.BoolVar(&conf.FakeImportC, "fakeImportC", false, "")
	flags.StringVar(&gotypesalias, "gotypesalias", "", "")
	if err := parseFlags(srcs[0], flags); err != nil {
		t.Fatal(err)
	}

	if goexperiment != "" {
		revert := setGOEXPERIMENT(goexperiment)
		defer revert()
	}

	// By default, gotypesalias is not set.
	if gotypesalias != "" {
		conf.EnableAlias = gotypesalias != "0"
	}

	// Provide Config.Info with all maps so that info recording is tested.
	info := Info{
		Types:        make(map[syntax.Expr]TypeAndValue),
		Instances:    make(map[*syntax.Name]Instance),
		Defs:         make(map[*syntax.Name]Object),
		Uses:         make(map[*syntax.Name]Object),
		Implicits:    make(map[syntax.Node]Object),
		Selections:   make(map[*syntax.SelectorExpr]*Selection),
		Scopes:       make(map[syntax.Node]*Scope),
		FileVersions: make(map[*syntax.PosBase]string),
	}

	// typecheck
	conf.Check(pkgName, files, &info)
	if listErrors {
		return
	}

	// collect expected errors
	errmap := make(map[string]map[uint][]syntax.Error)
	for i, filename := range filenames {
		if m := syntax.CommentMap(bytes.NewReader(srcs[i]), regexp.MustCompile("^ ERRORx? ")); len(m) > 0 {
			errmap[filename] = m
		}
	}

	// match against found errors
	var indices []int // list indices of matching errors, reused for each error
	for _, err := range errlist {
		gotPos, gotMsg := unpackError(err)

		// find list of errors for the respective error line
		filename := gotPos.Base().Filename()
		filemap := errmap[filename]
		line := gotPos.Line()
		var errList []syntax.Error
		if filemap != nil {
			errList = filemap[line]
		}

		// At least one of the errors in errList should match the current error.
		indices = indices[:0]
		for i, want := range errList {
			pattern, substr := strings.CutPrefix(want.Msg, " ERROR ")
			if !substr {
				var found bool
				pattern, found = strings.CutPrefix(want.Msg, " ERRORx ")
				if !found {
					panic("unreachable")
				}
			}
			unquoted, err := strconv.Unquote(strings.TrimSpace(pattern))
			if err != nil {
				t.Errorf("%s:%d:%d: invalid ERROR pattern (cannot unquote %s)", filename, line, want.Pos.Col(), pattern)
				continue
			}
			if substr {
				if !strings.Contains(gotMsg, unquoted) {
					continue
				}
			} else {
				rx, err := regexp.Compile(unquoted)
				if err != nil {
					t.Errorf("%s:%d:%d: %v", filename, line, want.Pos.Col(), err)
					continue
				}
				if !rx.MatchString(gotMsg) {
					continue
				}
			}
			indices = append(indices, i)
		}
		if len(indices) == 0 {
			t.Errorf("%s: no error expected: %q", gotPos, gotMsg)
			continue
		}
		// len(indices) > 0

		// If there are multiple matching errors, select the one with the closest column position.
		index := -1 // index of matching error
		var delta uint
		for _, i := range indices {
			if d := absDiff(gotPos.Col(), errList[i].Pos.Col()); index < 0 || d < delta {
				index, delta = i, d
			}
		}

		// The closest column position must be within expected colDelta.
		if delta > colDelta {
			t.Errorf("%s: got col = %d; want %d", gotPos, gotPos.Col(), errList[index].Pos.Col())
		}

		// eliminate from errList
		if n := len(errList) - 1; n > 0 {
			// not the last entry - slide entries down (don't reorder)
			copy(errList[index:], errList[index+1:])
			filemap[line] = errList[:n]
		} else {
			// last entry - remove errList from filemap
			delete(filemap, line)
		}

		// if filemap is empty, eliminate from errmap
		if len(filemap) == 0 {
			delete(errmap, filename)
		}
	}

	// there should be no expected errors left
	if len(errmap) > 0 {
		t.Errorf("--- %s: unreported errors:", pkgName)
		for filename, filemap := range errmap {
			for line, errList := range filemap {
				for _, err := range errList {
					t.Errorf("%s:%d:%d: %s", filename, line, err.Pos.Col(), err.Msg)
				}
			}
		}
	}
}

// boolFieldAddr(conf, name) returns the address of the boolean field conf.<name>.
// For accessing unexported fields.
func boolFieldAddr(conf *Config, name string) *bool {
	v := reflect.Indirect(reflect.ValueOf(conf))
	return (*bool)(v.FieldByName(name).Addr().UnsafePointer())
}

// setGOEXPERIMENT overwrites the existing buildcfg.Experiment with a new one
// based on the provided goexperiment string. Calling the result function
// (typically via defer), reverts buildcfg.Experiment to the prior value.
// For testing use, only.
func setGOEXPERIMENT(goexperiment string) func() {
	exp, err := buildcfg.ParseGOEXPERIMENT(runtime.GOOS, runtime.GOARCH, goexperiment)
	if err != nil {
		panic(err)
	}
	old := buildcfg.Experiment
	buildcfg.Experiment = *exp
	return func() { buildcfg.Experiment = old }
}

// TestManual is for manual testing of a package - either provided
// as a list of filenames belonging to the package, or a directory
// name containing the package files - after the test arguments
// (and a separating "--"). For instance, to test the package made
// of the files foo.go and bar.go, use:
//
//	go test -run Manual -- foo.go bar.go
//
// If no source arguments are provided, the file testdata/manual.go
// is used instead.
// Provide the -verify flag to verify errors against ERROR comments
// in the input files rather than having a list of errors reported.
// The accepted Go language version can be controlled with the -lang
// flag.
func TestManual(t *testing.T) {
	testenv.MustHaveGoBuild(t)

	filenames := flag.Args()
	if len(filenames) == 0 {
		filenames = []string{filepath.FromSlash("testdata/manual.go")}
	}

	info, err := os.Stat(filenames[0])
	if err != nil {
		t.Fatalf("TestManual: %v", err)
	}

	DefPredeclaredTestFuncs()
	if info.IsDir() {
		if len(filenames) > 1 {
			t.Fatal("TestManual: must have only one directory argument")
		}
		testDir(t, filenames[0], 0, true)
	} else {
		testPkg(t, filenames, 0, true)
	}
}

func TestLongConstants(t *testing.T) {
	format := `package longconst; const _ = %s /* ERROR "constant overflow" */; const _ = %s // ERROR "excessively long constant"`
	src := fmt.Sprintf(format, strings.Repeat("1", 9999), strings.Repeat("1", 10001))
	testFiles(t, []string{"longconst.go"}, [][]byte{[]byte(src)}, 0, false)
}

func withSizes(sizes Sizes) func(*Config) {
	return func(cfg *Config) {
		cfg.Sizes = sizes
	}
}

// TestIndexRepresentability tests that constant index operands must
// be representable as int even if they already have a type that can
// represent larger values.
func TestIndexRepresentability(t *testing.T) {
	const src = `package index; var s []byte; var _ = s[int64 /* ERRORx "int64\\(1\\) << 40 \\(.*\\) overflows int" */ (1) << 40]`
	testFiles(t, []string{"index.go"}, [][]byte{[]byte(src)}, 0, false, withSizes(&StdSizes{4, 4}))
}

func TestIssue47243_TypedRHS(t *testing.T) {
	// The RHS of the shift expression below overflows uint on 32bit platforms,
	// but this is OK as it is explicitly typed.
	const src = `package issue47243; var a uint64; var _ = a << uint64(4294967296)` // uint64(1<<32)
	testFiles(t, []string{"p.go"}, [][]byte{[]byte(src)}, 0, false, withSizes(&StdSizes{4, 4}))
}

func TestCheck(t *testing.T) {
	old := buildcfg.Experiment.RangeFunc
	defer func() {
		buildcfg.Experiment.RangeFunc = old
	}()
	buildcfg.Experiment.RangeFunc = true

	DefPredeclaredTestFuncs()
	testDirFiles(t, "../../../../internal/types/testdata/check", 50, false) // TODO(gri) narrow column tolerance
}
func TestSpec(t *testing.T) { testDirFiles(t, "../../../../internal/types/testdata/spec", 20, false) } // TODO(gri) narrow column tolerance
func TestExamples(t *testing.T) {
	testDirFiles(t, "../../../../internal/types/testdata/examples", 125, false)
} // TODO(gri) narrow column tolerance
func TestFixedbugs(t *testing.T) {
	testDirFiles(t, "../../../../internal/types/testdata/fixedbugs", 100, false)
}                            // TODO(gri) narrow column tolerance
func TestLocal(t *testing.T) { testDirFiles(t, "testdata/local", 0, false) }

func testDirFiles(t *testing.T, dir string, colDelta uint, manual bool) {
	testenv.MustHaveGoBuild(t)
	dir = filepath.FromSlash(dir)

	fis, err := os.ReadDir(dir)
	if err != nil {
		t.Error(err)
		return
	}

	for _, fi := range fis {
		path := filepath.Join(dir, fi.Name())

		// If fi is a directory, its files make up a single package.
		if fi.IsDir() {
			testDir(t, path, colDelta, manual)
		} else {
			t.Run(filepath.Base(path), func(t *testing.T) {
				testPkg(t, []string{path}, colDelta, manual)
			})
		}
	}
}

func testDir(t *testing.T, dir string, colDelta uint, manual bool) {
	fis, err := os.ReadDir(dir)
	if err != nil {
		t.Error(err)
		return
	}

	var filenames []string
	for _, fi := range fis {
		filenames = append(filenames, filepath.Join(dir, fi.Name()))
	}

	t.Run(filepath.Base(dir), func(t *testing.T) {
		testPkg(t, filenames, colDelta, manual)
	})
}

func testPkg(t *testing.T, filenames []string, colDelta uint, manual bool) {
	srcs := make([][]byte, len(filenames))
	for i, filename := range filenames {
		src, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("could not read %s: %v", filename, err)
		}
		srcs[i] = src
	}
	testFiles(t, filenames, srcs, colDelta, manual)
}
```