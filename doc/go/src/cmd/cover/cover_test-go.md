Response:
Let's break down the thought process for analyzing the provided Go code for `cover_test.go`.

**1. Initial Understanding - The "Why":**

The first step is to recognize that this is a test file (`_test.go`). It's not the actual `cmd/cover` code, but rather tests for it. This immediately tells us its purpose: to verify the functionality of the `cmd/cover` tool.

**2. Scanning Imports - The "What":**

Next, I scan the import statements:

* `bufio`, `bytes`:  Likely used for reading and manipulating file content.
* `cmdcover "cmd/cover"`:  This is the key import. It imports the actual `cmd/cover` package, allowing the tests to interact with its functionality directly.
* `flag`:  Indicates command-line flag handling is being tested.
* `fmt`:  Basic formatting for output.
* `go/ast`, `go/parser`, `go/token`:  Suggests the tests analyze Go source code structure, parsing it into an Abstract Syntax Tree (AST). This is a strong hint that `cmd/cover` deals with source code manipulation.
* `internal/testenv`:  Go's internal testing utilities, likely for executing commands and managing test environments.
* `log`, `os`, `os/exec`, `path/filepath`: Standard OS interaction, suggesting the tests create files, run external commands, and manage paths.
* `regexp`:  Regular expression matching, useful for verifying output formats.
* `strings`:  String manipulation.
* `sync`:  Concurrency primitives (like mutexes), potentially for managing temporary directories.
* `testing`:  The standard Go testing library.

**3. Examining Key Functions - The "How":**

I focus on the most prominent functions:

* `TestMain`:  This is the entry point for the tests. The code inside is complex, and it's clear it's doing some setup and potentially acting as the `cmd/cover` tool itself in some scenarios. The environment variable checks (`CMDCOVER_TOOLEXEC`, `CMDCOVER_TEST_RUN_MAIN`) are crucial for understanding how the tests are structured.
* `testcover`:  Returns the path to the `cmd/cover` binary. The comment clarifies it's reusing the test executable. This is an optimization for testing the tool in its built environment.
* `tempDir`: Creates temporary directories for tests, ensuring isolation.
* `TestCoverWithToolExec`:  Executes sub-tests using a `-toolexec` wrapper. This confirms that testing command-line invocation of `cmd/cover` is a focus.
* `TestCover`:  The core test function. It reads input, runs `testcover`, and checks the output. The manipulation of "LINE" placeholders indicates source code transformation.
* `TestDirectives`:  Specifically tests how compiler directives (`//go:`) are handled. The use of `go/parser` reinforces the idea of AST manipulation.
* `TestCoverFunc`, `testCoverHTML`, `testHtmlUnformatted`, `testFuncWithDuplicateLines`, `testMissingTrailingNewlineIssue58370`, `TestSrcPathWithNewline`: These are individual test cases, each focusing on a specific aspect of `cmd/cover`'s functionality or a potential edge case.

**4. Connecting the Dots - Inferring Functionality:**

Based on the imports and the function names/logic, I can start inferring the functionalities of `cmd/cover`:

* **Code Instrumentation:** The `TestCover` function clearly demonstrates the core functionality of `cmd/cover`. It takes Go source code, modifies it (the "LINE" replacement, adding the unformatted functions), and generates new Go code (`test_cover.go`). The variable name "thisNameMustBeVeryLongToCauseOverflowOfCounterIncrementStatementOntoNextLineForTest" suggests `cmd/cover` inserts counter increments for tracking code execution.
* **Coverage Reporting:**  The `-mode=count` and `-mode=set` flags in `TestCover`, along with the generation of `test_cover.go`, strongly suggest that `cmd/cover` is about generating code that tracks which lines/statements are executed. The `TestCoverFunc` and `testCoverHTML` functions further confirm this, as they test the generation of coverage reports in text and HTML formats.
* **Compiler Directive Handling:** `TestDirectives` is explicitly designed to verify that compiler directives are preserved and correctly positioned during the instrumentation process.
* **Command-Line Interface:** The numerous tests involving `testenv.Command` and flags like `-mode`, `-var`, `-o`, `-func`, `-html` demonstrate that `cmd/cover` is a command-line tool with various options.
* **Error Handling:**  The check for expected errors in `TestCover` with the invalid variable name shows the tests verify error conditions.
* **Handling Edge Cases:** The tests for unformatted code, duplicate line directives, and missing trailing newlines indicate a focus on robustly handling various real-world code scenarios.

**5. Formulating Examples and Explanations:**

Once the functionalities are understood, the next step is to generate clear explanations and illustrative Go code examples. This involves:

* **Summarizing the core function:** Briefly explain that `cmd/cover` instruments code to track coverage.
* **Demonstrating instrumentation:**  Show a simple input and the likely output, highlighting the inserted counter.
* **Illustrating command-line usage:**  Provide examples of how to use `cmd/cover` with different flags to generate different types of reports.
* **Identifying potential pitfalls:** Based on the tests, point out common errors, such as forgetting to run the instrumented code or misinterpreting the output.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe `cmd/cover` just analyzes code statically. **Correction:** The code instrumentation and execution clearly indicate a dynamic analysis approach.
* **Initial thought:**  The `TestMain` complexity is just test setup. **Correction:** Realizing that `TestMain` can *become* the `cmd/cover` tool explains the intricate logic around environment variables.
* **Focusing too much on individual test cases:**  Shift to understanding the broader purpose and grouping related tests to identify overarching functionalities.

By following this structured approach, combining code analysis with an understanding of testing principles, I can effectively analyze and explain the functionality of the given Go test code.
这段代码是 Go 语言 `cmd/cover` 工具的测试代码，它主要用于测试 `cmd/cover` 命令行的各种功能。`cmd/cover` 工具是 Go 自带的用于代码覆盖率分析的工具。

以下是根据代码推断出的 `cmd/cover` 的主要功能，并附带 Go 代码示例和命令行参数说明：

**`cmd/cover` 的主要功能:**

1. **代码覆盖率检测点的生成（Instrumentation）:** `cmd/cover` 能够读取 Go 源代码，并在代码中插入用于记录代码执行情况的计数器。这些计数器用于跟踪哪些代码行被执行过。

   **Go 代码示例（假设的输入 `testdata/test.go` 内容）：**

   ```go
   package mypackage

   func Add(a, b int) int {
       if a > 0 { // LINE
           return a + b
       }
       return b
   }

   func Subtract(a, b int) int { // LINE
       return a - b
   }
   ```

   **命令行参数和执行：**

   ```bash
   go test -covermode=count -coverpkg=mypackage ./...
   ```

   * `go test`:  运行测试。
   * `-covermode=count`:  指定覆盖率模式为计数模式，即记录每行代码执行的次数。其他模式还有 `set` (只记录是否执行过) 和 `atomic` (用于并发安全)。
   * `-coverpkg=mypackage`:  指定要进行覆盖率分析的包。
   * `./...`: 表示当前目录及其子目录下的所有包。

   **推理的输出 `testdata/test_cover.go` 内容（包含插入的覆盖率检测点）：**

   ```go
   package mypackage

   var CoverTest = struct {
       Count     []uint32
       Pos       []uint32
       NumStmt   []uint16
   }{
       Count: []uint32{0, 0, 0},
       Pos: []uint32{
           7, // mypackage/testdata/test.go:7
           12, // mypackage/testdata/test.go:12
           13, // mypackage/testdata/test.go:13
       },
       NumStmt: []uint16{2, 1, 1},
   }

   func Add(a, b int) int {
       if CoverTest.Count[0]++; a > 0 { // LINE
           return a + b
       }
       CoverTest.Count[1]++
       return b
   }

   func Subtract(a, b int) int { // LINE
       CoverTest.Count[2]++
       return a - b
   }
   ```

   **假设的输入与输出解释:**

   * 输入是简单的 Go 源代码。
   * `cmd/cover` 通过插入一个全局变量 `CoverTest` 和在每个可覆盖的代码块前增加计数器的方式来检测覆盖率。
   * `Pos` 数组存储了对应计数器代码行的位置信息。
   * `NumStmt` 数组存储了每个代码块包含的语句数量。

2. **生成覆盖率概要文件 (`-coverprofile`)：**  在运行带有覆盖率检测的测试后，`go test` 可以生成一个包含覆盖率信息的概要文件，通常以 `.out` 或 `.cov` 为扩展名。

   **命令行参数和执行：**

   ```bash
   go test -covermode=count -coverprofile=coverage.out ./...
   ```

   * `-coverprofile=coverage.out`: 指定覆盖率概要文件的输出路径为 `coverage.out`。

   **推理的 `coverage.out` 文件内容（示例）：**

   ```
   mode: count
   mypackage/testdata/test.go:7.15,9.14 1 1
   mypackage/testdata/test.go:12.33,13.14 1
   mypackage/testdata/test.go:17.34,19.14 0
   ```

   **假设的输入与输出解释:**

   * `mode: count`:  表示覆盖率模式。
   * 每一行代表一个代码块的覆盖率信息，格式为：`文件路径:起始位置,结束位置 执行次数 语句数量`。
   * 例如，`mypackage/testdata/test.go:7.15,9.14 1 1` 表示 `testdata/test.go` 文件中第 7 行到第 9 行的代码块被执行了 1 次，包含 1 条语句。

3. **生成覆盖率报告 (`-func`, `-html`)：** `cmd/cover` 可以读取覆盖率概要文件，并生成易于阅读的报告。

   * **`-func`：生成基于函数的覆盖率报告。**

     **命令行参数和执行：**

     ```bash
     go tool cover -func=coverage.out
     ```

     **推理的输出：**

     ```
     mypackage/testdata/test.go:7:    Add      100.0%
     mypackage/testdata/test.go:16:   Subtract 0.0%
     total:                                     50.0%
     ```

     **假设的输入与输出解释:**

     * 报告显示了每个函数的覆盖率百分比。

   * **`-html`：生成 HTML 格式的覆盖率报告。**  HTML 报告会高亮显示哪些代码行被覆盖到，哪些没有。

     **命令行参数和执行：**

     ```bash
     go tool cover -html=coverage.out -o coverage.html
     ```

     * `-html=coverage.out`: 指定输入的覆盖率概要文件。
     * `-o coverage.html`: 指定输出的 HTML 文件名为 `coverage.html`。

     **推理的输出：** 会生成一个 `coverage.html` 文件，用浏览器打开后可以看到带颜色标记的代码覆盖情况。

4. **处理编译器指令 (`//go:`)：** 从 `TestDirectives` 函数可以看出，`cmd/cover` 能够正确地保留和处理 Go 源代码中的编译器指令，例如 `//go:nosplit`、`//go:linkname` 等。

   **Go 代码示例（包含编译器指令）：**

   ```go
   package mypackage

   //go:nosplit
   func someFunction() {
       // ...
   }

   // This comment didn't appear in generated go code.
   //go:linkname some_name some_name
   func anotherFunction() {
       // ...
   }
   ```

   `cmd/cover` 生成的 instrumented 代码会保留这些指令，并确保它们的相对位置正确。

5. **处理未格式化的代码：** 从 `testHtmlUnformatted` 函数可以看出，`cmd/cover` 能够处理未经过 `gofmt` 格式化的代码。

6. **处理包含重复行号指令的代码：** 从 `testFuncWithDuplicateLines` 函数可以看出，`cmd/cover` 能够处理包含 `//line` 指令并且指令指向相同行号但语句数量不同的情况。

7. **处理文件末尾缺少换行符的情况：**  从 `testMissingTrailingNewlineIssue58370` 函数可以看出，`cmd/cover` 能够处理文件末尾缺少换行符的 Go 代码。

**命令行参数的具体处理：**

从测试代码中可以看出 `cmd/cover` 工具接受以下命令行参数（通过 `flag` 包处理）：

* **`-mode string`**:  指定覆盖率的模式，可选值有 `set`, `count`, `atomic`。
* **`-var string`**:  指定用于存储覆盖率数据的全局变量的名称。
* **`-o string`**:  指定输出 instrumented 代码的文件名。
* **`-func string`**:  指定覆盖率概要文件，并生成基于函数的覆盖率报告。
* **`-html string`**: 指定覆盖率概要文件，并生成 HTML 格式的覆盖率报告。
* **`-debug`**:  一个布尔标志，如果设置，则在测试运行后保留临时文件。

**使用者易犯错的点：**

1. **忘记运行 instrumented 的代码：**  使用者可能会使用 `go tool cover` 生成了 instrumented 的代码，但是忘记运行这些代码或者运行了原始的未经 instrument 的代码，导致无法生成覆盖率数据。

   **示例：**

   ```bash
   # 错误的做法
   go tool cover -mode=count -o=instrumented.go mypackage/mycode.go
   go run mypackage/mycode.go  # 运行的是原始代码，没有覆盖率数据生成
   go tool cover -func=coverage.out # coverage.out 文件不存在或为空
   ```

   **正确的做法：**

   ```bash
   go test -covermode=count -coverprofile=coverage.out mypackage  # 运行测试，自动进行 instrumentation 并生成概要文件
   go tool cover -func=coverage.out
   ```

2. **混淆 `-coverprofile` 和 `-o` 参数的用途：**  `-coverprofile` 是 `go test` 命令用于指定覆盖率概要文件输出路径的参数，而 `-o` 是 `go tool cover` 命令用于指定输出 instrumented 代码文件名的参数。

   **示例：**

   ```bash
   # 错误的理解
   go tool cover -mode=count -coverprofile=instrumented.go mypackage/mycode.go # 这里的 -coverprofile 用途错误

   # 正确的做法
   go test -covermode=count -coverprofile=coverage.out mypackage # 使用 go test 的 -coverprofile
   go tool cover -html=coverage.out  # 使用 go tool cover 的 -html
   ```

3. **对覆盖率模式理解不准确：**  不同的覆盖率模式 (`set`, `count`, `atomic`) 记录的信息不同，使用者需要根据实际需求选择合适的模式。例如，`atomic` 模式会对性能有一定影响，只在需要并发安全覆盖率分析时使用。

这段测试代码通过各种场景覆盖了 `cmd/cover` 工具的核心功能和边界情况，确保了该工具的稳定性和可靠性。

### 提示词
```
这是路径为go/src/cmd/cover/cover_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main_test

import (
	"bufio"
	"bytes"
	cmdcover "cmd/cover"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"internal/testenv"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const (
	// Data directory, also the package directory for the test.
	testdata = "testdata"
)

// testcover returns the path to the cmd/cover binary that we are going to
// test. At one point this was created via "go build"; we now reuse the unit
// test executable itself.
func testcover(t testing.TB) string {
	return testenv.Executable(t)
}

// testTempDir is a temporary directory created in TestMain.
var testTempDir string

// If set, this will preserve all the tmpdir files from the test run.
var debug = flag.Bool("debug", false, "keep tmpdir files for debugging")

// TestMain used here so that we can leverage the test executable
// itself as a cmd/cover executable; compare to similar usage in
// the cmd/go tests.
func TestMain(m *testing.M) {
	if os.Getenv("CMDCOVER_TOOLEXEC") != "" {
		// When CMDCOVER_TOOLEXEC is set, the test binary is also
		// running as a -toolexec wrapper.
		tool := strings.TrimSuffix(filepath.Base(os.Args[1]), ".exe")
		if tool == "cover" {
			// Inject this test binary as cmd/cover in place of the
			// installed tool, so that the go command's invocations of
			// cover produce coverage for the configuration in which
			// the test was built.
			os.Args = os.Args[1:]
			cmdcover.Main()
		} else {
			cmd := exec.Command(os.Args[1], os.Args[2:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	if os.Getenv("CMDCOVER_TEST_RUN_MAIN") != "" {
		// When CMDCOVER_TEST_RUN_MAIN is set, we're reusing the test
		// binary as cmd/cover. In this case we run the main func exported
		// via export_test.go, and exit; CMDCOVER_TEST_RUN_MAIN is set below
		// for actual test invocations.
		cmdcover.Main()
		os.Exit(0)
	}
	flag.Parse()
	topTmpdir, err := os.MkdirTemp("", "cmd-cover-test-")
	if err != nil {
		log.Fatal(err)
	}
	testTempDir = topTmpdir
	if !*debug {
		defer os.RemoveAll(topTmpdir)
	} else {
		fmt.Fprintf(os.Stderr, "debug: preserving tmpdir %s\n", topTmpdir)
	}
	os.Setenv("CMDCOVER_TEST_RUN_MAIN", "normal")
	os.Exit(m.Run())
}

var tdmu sync.Mutex
var tdcount int

func tempDir(t *testing.T) string {
	tdmu.Lock()
	dir := filepath.Join(testTempDir, fmt.Sprintf("%03d", tdcount))
	tdcount++
	if err := os.Mkdir(dir, 0777); err != nil {
		t.Fatal(err)
	}
	defer tdmu.Unlock()
	return dir
}

// TestCoverWithToolExec runs a set of subtests that all make use of a
// "-toolexec" wrapper program to invoke the cover test executable
// itself via "go test -cover".
func TestCoverWithToolExec(t *testing.T) {
	toolexecArg := "-toolexec=" + testcover(t)

	t.Run("CoverHTML", func(t *testing.T) {
		testCoverHTML(t, toolexecArg)
	})
	t.Run("HtmlUnformatted", func(t *testing.T) {
		testHtmlUnformatted(t, toolexecArg)
	})
	t.Run("FuncWithDuplicateLines", func(t *testing.T) {
		testFuncWithDuplicateLines(t, toolexecArg)
	})
	t.Run("MissingTrailingNewlineIssue58370", func(t *testing.T) {
		testMissingTrailingNewlineIssue58370(t, toolexecArg)
	})
}

// Execute this command sequence:
//
//	replace the word LINE with the line number < testdata/test.go > testdata/test_line.go
//	testcover -mode=count -var=CoverTest -o ./testdata/test_cover.go testdata/test_line.go
//	go run ./testdata/main.go ./testdata/test.go
func TestCover(t *testing.T) {
	testenv.MustHaveGoRun(t)
	t.Parallel()
	dir := tempDir(t)

	// Read in the test file (testTest) and write it, with LINEs specified, to coverInput.
	testTest := filepath.Join(testdata, "test.go")
	file, err := os.ReadFile(testTest)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(file, []byte("\n"))
	for i, line := range lines {
		lines[i] = bytes.ReplaceAll(line, []byte("LINE"), []byte(fmt.Sprint(i+1)))
	}

	// Add a function that is not gofmt'ed. This used to cause a crash.
	// We don't put it in test.go because then we would have to gofmt it.
	// Issue 23927.
	lines = append(lines, []byte("func unFormatted() {"),
		[]byte("\tif true {"),
		[]byte("\t}else{"),
		[]byte("\t}"),
		[]byte("}"))
	lines = append(lines, []byte("func unFormatted2(b bool) {if b{}else{}}"))

	coverInput := filepath.Join(dir, "test_line.go")
	if err := os.WriteFile(coverInput, bytes.Join(lines, []byte("\n")), 0666); err != nil {
		t.Fatal(err)
	}

	// testcover -mode=count -var=thisNameMustBeVeryLongToCauseOverflowOfCounterIncrementStatementOntoNextLineForTest -o ./testdata/test_cover.go testdata/test_line.go
	coverOutput := filepath.Join(dir, "test_cover.go")
	cmd := testenv.Command(t, testcover(t), "-mode=count", "-var=thisNameMustBeVeryLongToCauseOverflowOfCounterIncrementStatementOntoNextLineForTest", "-o", coverOutput, coverInput)
	run(cmd, t)

	cmd = testenv.Command(t, testcover(t), "-mode=set", "-var=Not_an-identifier", "-o", coverOutput, coverInput)
	err = cmd.Run()
	if err == nil {
		t.Error("Expected cover to fail with an error")
	}

	// Copy testmain to tmpdir, so that it is in the same directory
	// as coverOutput.
	testMain := filepath.Join(testdata, "main.go")
	b, err := os.ReadFile(testMain)
	if err != nil {
		t.Fatal(err)
	}
	tmpTestMain := filepath.Join(dir, "main.go")
	if err := os.WriteFile(tmpTestMain, b, 0444); err != nil {
		t.Fatal(err)
	}

	// go run ./testdata/main.go ./testdata/test.go
	cmd = testenv.Command(t, testenv.GoToolPath(t), "run", tmpTestMain, coverOutput)
	run(cmd, t)

	file, err = os.ReadFile(coverOutput)
	if err != nil {
		t.Fatal(err)
	}
	// compiler directive must appear right next to function declaration.
	if got, err := regexp.MatchString(".*\n//go:nosplit\nfunc someFunction().*", string(file)); err != nil || !got {
		t.Error("misplaced compiler directive")
	}
	// "go:linkname" compiler directive should be present.
	if got, err := regexp.MatchString(`.*go\:linkname some\_name some\_name.*`, string(file)); err != nil || !got {
		t.Error("'go:linkname' compiler directive not found")
	}

	// Other comments should be preserved too.
	c := ".*// This comment didn't appear in generated go code.*"
	if got, err := regexp.MatchString(c, string(file)); err != nil || !got {
		t.Errorf("non compiler directive comment %q not found", c)
	}
}

// TestDirectives checks that compiler directives are preserved and positioned
// correctly. Directives that occur before top-level declarations should remain
// above those declarations, even if they are not part of the block of
// documentation comments.
func TestDirectives(t *testing.T) {
	testenv.MustHaveExec(t)
	t.Parallel()

	// Read the source file and find all the directives. We'll keep
	// track of whether each one has been seen in the output.
	testDirectives := filepath.Join(testdata, "directives.go")
	source, err := os.ReadFile(testDirectives)
	if err != nil {
		t.Fatal(err)
	}
	sourceDirectives := findDirectives(source)

	// testcover -mode=atomic ./testdata/directives.go
	cmd := testenv.Command(t, testcover(t), "-mode=atomic", testDirectives)
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}

	// Check that all directives are present in the output.
	outputDirectives := findDirectives(output)
	foundDirective := make(map[string]bool)
	for _, p := range sourceDirectives {
		foundDirective[p.name] = false
	}
	for _, p := range outputDirectives {
		if found, ok := foundDirective[p.name]; !ok {
			t.Errorf("unexpected directive in output: %s", p.text)
		} else if found {
			t.Errorf("directive found multiple times in output: %s", p.text)
		}
		foundDirective[p.name] = true
	}
	for name, found := range foundDirective {
		if !found {
			t.Errorf("missing directive: %s", name)
		}
	}

	// Check that directives that start with the name of top-level declarations
	// come before the beginning of the named declaration and after the end
	// of the previous declaration.
	fset := token.NewFileSet()
	astFile, err := parser.ParseFile(fset, testDirectives, output, 0)
	if err != nil {
		t.Fatal(err)
	}

	prevEnd := 0
	for _, decl := range astFile.Decls {
		var name string
		switch d := decl.(type) {
		case *ast.FuncDecl:
			name = d.Name.Name
		case *ast.GenDecl:
			if len(d.Specs) == 0 {
				// An empty group declaration. We still want to check that
				// directives can be associated with it, so we make up a name
				// to match directives in the test data.
				name = "_empty"
			} else if spec, ok := d.Specs[0].(*ast.TypeSpec); ok {
				name = spec.Name.Name
			}
		}
		pos := fset.Position(decl.Pos()).Offset
		end := fset.Position(decl.End()).Offset
		if name == "" {
			prevEnd = end
			continue
		}
		for _, p := range outputDirectives {
			if !strings.HasPrefix(p.name, name) {
				continue
			}
			if p.offset < prevEnd || pos < p.offset {
				t.Errorf("directive %s does not appear before definition %s", p.text, name)
			}
		}
		prevEnd = end
	}
}

type directiveInfo struct {
	text   string // full text of the comment, not including newline
	name   string // text after //go:
	offset int    // byte offset of first slash in comment
}

func findDirectives(source []byte) []directiveInfo {
	var directives []directiveInfo
	directivePrefix := []byte("\n//go:")
	offset := 0
	for {
		i := bytes.Index(source[offset:], directivePrefix)
		if i < 0 {
			break
		}
		i++ // skip newline
		p := source[offset+i:]
		j := bytes.IndexByte(p, '\n')
		if j < 0 {
			// reached EOF
			j = len(p)
		}
		directive := directiveInfo{
			text:   string(p[:j]),
			name:   string(p[len(directivePrefix)-1 : j]),
			offset: offset + i,
		}
		directives = append(directives, directive)
		offset += i + j
	}
	return directives
}

// Makes sure that `cover -func=profile.cov` reports accurate coverage.
// Issue #20515.
func TestCoverFunc(t *testing.T) {
	// testcover -func ./testdata/profile.cov
	coverProfile := filepath.Join(testdata, "profile.cov")
	cmd := testenv.Command(t, testcover(t), "-func", coverProfile)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Logf("%s", ee.Stderr)
		}
		t.Fatal(err)
	}

	if got, err := regexp.Match(".*total:.*100.0.*", out); err != nil || !got {
		t.Logf("%s", out)
		t.Errorf("invalid coverage counts. got=(%v, %v); want=(true; nil)", got, err)
	}
}

// Check that cover produces correct HTML.
// Issue #25767.
func testCoverHTML(t *testing.T, toolexecArg string) {
	testenv.MustHaveGoRun(t)
	dir := tempDir(t)

	t.Parallel()

	// go test -coverprofile testdata/html/html.cov cmd/cover/testdata/html
	htmlProfile := filepath.Join(dir, "html.cov")
	cmd := testenv.Command(t, testenv.GoToolPath(t), "test", toolexecArg, "-coverprofile", htmlProfile, "cmd/cover/testdata/html")
	cmd.Env = append(cmd.Environ(), "CMDCOVER_TOOLEXEC=true")
	run(cmd, t)
	// testcover -html testdata/html/html.cov -o testdata/html/html.html
	htmlHTML := filepath.Join(dir, "html.html")
	cmd = testenv.Command(t, testcover(t), "-html", htmlProfile, "-o", htmlHTML)
	run(cmd, t)

	// Extract the parts of the HTML with comment markers,
	// and compare against a golden file.
	entireHTML, err := os.ReadFile(htmlHTML)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	scan := bufio.NewScanner(bytes.NewReader(entireHTML))
	in := false
	for scan.Scan() {
		line := scan.Text()
		if strings.Contains(line, "// START") {
			in = true
		}
		if in {
			fmt.Fprintln(&out, line)
		}
		if strings.Contains(line, "// END") {
			in = false
		}
	}
	if scan.Err() != nil {
		t.Error(scan.Err())
	}
	htmlGolden := filepath.Join(testdata, "html", "html.golden")
	golden, err := os.ReadFile(htmlGolden)
	if err != nil {
		t.Fatalf("reading golden file: %v", err)
	}
	// Ignore white space differences.
	// Break into lines, then compare by breaking into words.
	goldenLines := strings.Split(string(golden), "\n")
	outLines := strings.Split(out.String(), "\n")
	// Compare at the line level, stopping at first different line so
	// we don't generate tons of output if there's an inserted or deleted line.
	for i, goldenLine := range goldenLines {
		if i >= len(outLines) {
			t.Fatalf("output shorter than golden; stops before line %d: %s\n", i+1, goldenLine)
		}
		// Convert all white space to simple spaces, for easy comparison.
		goldenLine = strings.Join(strings.Fields(goldenLine), " ")
		outLine := strings.Join(strings.Fields(outLines[i]), " ")
		if outLine != goldenLine {
			t.Fatalf("line %d differs: got:\n\t%s\nwant:\n\t%s", i+1, outLine, goldenLine)
		}
	}
	if len(goldenLines) != len(outLines) {
		t.Fatalf("output longer than golden; first extra output line %d: %q\n", len(goldenLines)+1, outLines[len(goldenLines)])
	}
}

// Test HTML processing with a source file not run through gofmt.
// Issue #27350.
func testHtmlUnformatted(t *testing.T, toolexecArg string) {
	testenv.MustHaveGoRun(t)
	dir := tempDir(t)

	t.Parallel()

	htmlUDir := filepath.Join(dir, "htmlunformatted")
	htmlU := filepath.Join(htmlUDir, "htmlunformatted.go")
	htmlUTest := filepath.Join(htmlUDir, "htmlunformatted_test.go")
	htmlUProfile := filepath.Join(htmlUDir, "htmlunformatted.cov")
	htmlUHTML := filepath.Join(htmlUDir, "htmlunformatted.html")

	if err := os.Mkdir(htmlUDir, 0777); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(htmlUDir, "go.mod"), []byte("module htmlunformatted\n"), 0666); err != nil {
		t.Fatal(err)
	}

	const htmlUContents = `
package htmlunformatted

var g int

func F() {
//line x.go:1
	{ { F(); goto lab } }
lab:
}`

	const htmlUTestContents = `package htmlunformatted`

	if err := os.WriteFile(htmlU, []byte(htmlUContents), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(htmlUTest, []byte(htmlUTestContents), 0444); err != nil {
		t.Fatal(err)
	}

	// go test -covermode=count -coverprofile TMPDIR/htmlunformatted.cov
	cmd := testenv.Command(t, testenv.GoToolPath(t), "test", "-test.v", toolexecArg, "-covermode=count", "-coverprofile", htmlUProfile)
	cmd.Env = append(cmd.Environ(), "CMDCOVER_TOOLEXEC=true")
	cmd.Dir = htmlUDir
	run(cmd, t)

	// testcover -html TMPDIR/htmlunformatted.cov -o unformatted.html
	cmd = testenv.Command(t, testcover(t), "-html", htmlUProfile, "-o", htmlUHTML)
	cmd.Dir = htmlUDir
	run(cmd, t)
}

// lineDupContents becomes linedup.go in testFuncWithDuplicateLines.
const lineDupContents = `
package linedup

var G int

func LineDup(c int) {
	for i := 0; i < c; i++ {
//line ld.go:100
		if i % 2 == 0 {
			G++
		}
		if i % 3 == 0 {
			G++; G++
		}
//line ld.go:100
		if i % 4 == 0 {
			G++; G++; G++
		}
		if i % 5 == 0 {
			G++; G++; G++; G++
		}
	}
}
`

// lineDupTestContents becomes linedup_test.go in testFuncWithDuplicateLines.
const lineDupTestContents = `
package linedup

import "testing"

func TestLineDup(t *testing.T) {
	LineDup(100)
}
`

// Test -func with duplicate //line directives with different numbers
// of statements.
func testFuncWithDuplicateLines(t *testing.T, toolexecArg string) {
	testenv.MustHaveGoRun(t)
	dir := tempDir(t)

	t.Parallel()

	lineDupDir := filepath.Join(dir, "linedup")
	lineDupGo := filepath.Join(lineDupDir, "linedup.go")
	lineDupTestGo := filepath.Join(lineDupDir, "linedup_test.go")
	lineDupProfile := filepath.Join(lineDupDir, "linedup.out")

	if err := os.Mkdir(lineDupDir, 0777); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(lineDupDir, "go.mod"), []byte("module linedup\n"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lineDupGo, []byte(lineDupContents), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lineDupTestGo, []byte(lineDupTestContents), 0444); err != nil {
		t.Fatal(err)
	}

	// go test -cover -covermode count -coverprofile TMPDIR/linedup.out
	cmd := testenv.Command(t, testenv.GoToolPath(t), "test", toolexecArg, "-cover", "-covermode", "count", "-coverprofile", lineDupProfile)
	cmd.Env = append(cmd.Environ(), "CMDCOVER_TOOLEXEC=true")
	cmd.Dir = lineDupDir
	run(cmd, t)

	// testcover -func=TMPDIR/linedup.out
	cmd = testenv.Command(t, testcover(t), "-func", lineDupProfile)
	cmd.Dir = lineDupDir
	run(cmd, t)
}

func run(c *exec.Cmd, t *testing.T) {
	t.Helper()
	t.Log("running", c.Args)
	out, err := c.CombinedOutput()
	if len(out) > 0 {
		t.Logf("%s", out)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func runExpectingError(c *exec.Cmd, t *testing.T) string {
	t.Helper()
	t.Log("running", c.Args)
	out, err := c.CombinedOutput()
	if err == nil {
		return fmt.Sprintf("unexpected pass for %+v", c.Args)
	}
	return string(out)
}

// Test instrumentation of package that ends before an expected
// trailing newline following package clause. Issue #58370.
func testMissingTrailingNewlineIssue58370(t *testing.T, toolexecArg string) {
	testenv.MustHaveGoBuild(t)
	dir := tempDir(t)

	t.Parallel()

	noeolDir := filepath.Join(dir, "issue58370")
	noeolGo := filepath.Join(noeolDir, "noeol.go")
	noeolTestGo := filepath.Join(noeolDir, "noeol_test.go")

	if err := os.Mkdir(noeolDir, 0777); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(noeolDir, "go.mod"), []byte("module noeol\n"), 0666); err != nil {
		t.Fatal(err)
	}
	const noeolContents = `package noeol`
	if err := os.WriteFile(noeolGo, []byte(noeolContents), 0444); err != nil {
		t.Fatal(err)
	}
	const noeolTestContents = `
package noeol
import "testing"
func TestCoverage(t *testing.T) { }
`
	if err := os.WriteFile(noeolTestGo, []byte(noeolTestContents), 0444); err != nil {
		t.Fatal(err)
	}

	// go test -covermode atomic
	cmd := testenv.Command(t, testenv.GoToolPath(t), "test", toolexecArg, "-covermode", "atomic")
	cmd.Env = append(cmd.Environ(), "CMDCOVER_TOOLEXEC=true")
	cmd.Dir = noeolDir
	run(cmd, t)
}

func TestSrcPathWithNewline(t *testing.T) {
	testenv.MustHaveExec(t)
	t.Parallel()

	// srcPath is intentionally not clean so that the path passed to testcover
	// will not normalize the trailing / to a \ on Windows.
	srcPath := t.TempDir() + string(filepath.Separator) + "\npackage main\nfunc main() { panic(string([]rune{'u', 'h', '-', 'o', 'h'}))\n/*/main.go"
	mainSrc := ` package main

func main() {
	/* nothing here */
	println("ok")
}
`
	if err := os.MkdirAll(filepath.Dir(srcPath), 0777); err != nil {
		t.Skipf("creating directory with bogus path: %v", err)
	}
	if err := os.WriteFile(srcPath, []byte(mainSrc), 0666); err != nil {
		t.Skipf("writing file with bogus directory: %v", err)
	}

	cmd := testenv.Command(t, testcover(t), "-mode=atomic", srcPath)
	cmd.Stderr = new(bytes.Buffer)
	out, err := cmd.Output()
	t.Logf("%v:\n%s", cmd, out)
	t.Logf("stderr:\n%s", cmd.Stderr)
	if err == nil {
		t.Errorf("unexpected success; want failure due to newline in file path")
	}
}
```