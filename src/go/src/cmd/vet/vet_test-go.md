Response: Let's break down the thought process for analyzing the `vet_test.go` file.

**1. Initial Understanding - The Test File's Purpose**

The first thing I notice is the filename: `vet_test.go`. The `_test.go` suffix immediately tells me this is a Go test file. Combined with the `vet` part, it strongly suggests this file is testing the functionality of the `go vet` tool.

**2. `TestMain` Function - Key Entry Point**

The `TestMain` function is special in Go test files. It's the first function executed. The code within it is crucial for understanding the test setup.

* **`os.Getenv("GO_VETTEST_IS_VET") != ""`**: This checks for an environment variable. This is a common pattern in Go testing to control different execution modes. The comment "executes the test binary as the vet command if GO_VETTEST_IS_VET is set" confirms this.
* **`main()`**: This strongly indicates that when the environment variable is set, this test file *itself* is behaving as the `go vet` command.
* **`os.Exit(0)`**:  Exiting the program after `main()` is executed is standard practice for a command-line tool.
* **`os.Setenv("GO_VETTEST_IS_VET", "1")`**:  This sets the environment variable *before* running the actual tests with `m.Run()`. This suggests the tests might involve running `go vet` as a subprocess.

**Hypothesis 1:** This test file has two modes:
    * When `GO_VETTEST_IS_VET` is set, it acts like the `go vet` command itself.
    * Otherwise, it runs standard Go tests, potentially invoking the `go vet` command.

**3. Helper Functions - Understanding the Test Environment**

Next, I look at the helper functions:

* **`vetPath(t testing.TB) string`**: This function returns the path to the `vet` binary. The `testenv.Executable(t)` call suggests it's using the standard Go test environment to find the compiled test binary (which acts as `vet` in the special mode).
* **`vetCmd(t *testing.T, arg, pkg string) *exec.Cmd`**: This function constructs an `exec.Cmd` to run `go vet`. Key observations:
    * It uses `testenv.GoToolPath(t)` to get the path to the `go` tool.
    * It explicitly sets `-vettool=` to the path obtained from `vetPath(t)`. This confirms that the test is running the *current* build of the `vet` tool.
    * It appends `arg` and the package path to the command.
    * It sets the environment variables of the command to the current environment.

**Hypothesis 2:** The tests will involve running the `go vet` command as a subprocess, targeting specific test packages under `cmd/vet/testdata`.

**4. `TestVet` Function - The Core Tests**

The `TestVet` function seems to be the main test suite.

* **`t.Parallel()`**:  Indicates that individual test cases within `TestVet` can run in parallel.
* **`for _, pkg := range []string{...}`**:  This loop iterates through a list of packages under `testdata`. This strongly suggests that each package represents a specific `go vet` analyzer or a set of related checks.
* **`t.Run(pkg, func(t *testing.T) { ... })`**:  Standard Go subtest structure, allowing for grouping and individual execution of tests.
* **`cgoEnabled(t)`**:  Specific handling for the "cgo" package, skipping the test if CGO is not enabled.
* **`vetCmd(t, "-printfuncs=Warn,Warnf", pkg)`**:  Invokes `go vet` with the `-printfuncs` flag. This is a specific option of `go vet` to control which functions are considered for certain checks (like the `print` analyzer).
* **`filepath.Glob`**: Used to find `.go` and `.s` (assembly) files within the testdata package directory.
* **`errchk(cmd, files, t)`**: This function is responsible for checking the output of the `go vet` command against expected errors.

**Hypothesis 3:** The `TestVet` function runs `go vet` on various test packages and verifies that the expected errors (or lack thereof) are reported.

**5. Deeper Dive into `errchk` and `errorCheck`**

The `errchk` and `errorCheck` functions are crucial for understanding how the tests are validated.

* **`errchk`**: Executes the `go vet` command and passes the output to `errorCheck`. It handles potential `exec.ExitError`, logging the output if the command fails.
* **`errorCheck`**: This is the core validation logic. It compares the output of `go vet` with comments in the source files that start with `// ERROR` or `// ERRORAUTO`. This is a common technique for testing static analysis tools.

**Hypothesis 4:** The test cases define expected errors within the `.go` files themselves using special comments. `errorCheck` parses these comments and verifies that `go vet` produces the corresponding errors.

**6. `TestTags` Function - Handling Build Tags**

The `TestTags` function specifically tests the `-tags` argument of `go vet`. It verifies that `go vet` correctly includes or excludes files based on build tags.

**Hypothesis 5:** This test confirms that the `-tags` flag filters the files analyzed by `go vet` as expected.

**7. Special Cases: `loopclosure` and `stdversion`**

The `loopclosure` and `stdversion` tests use a different approach. They run `go vet` in a subdirectory (`testdata/rangeloop` and `testdata/stdversion`) and manipulate the output to match the expected format. The comments about Go versions and `go.mod` files indicate they are testing features that depend on the Go version.

**Hypothesis 6:** These tests are designed to check version-specific behaviors of `go vet`.

**8. `wantedErrors` Function - Parsing Error Expectations**

The `wantedErrors` function parses the `// ERROR` and `// ERRORAUTO` comments from the source files to extract the expected error messages and line numbers. The use of regular expressions is evident.

**Synthesis and Refinement:**

By examining the functions and their interactions, I can now synthesize a more complete understanding of the file's functionality. It's a sophisticated test suite for `go vet` that:

* Can run in two modes: as the `vet` command itself, or as a regular test suite.
* Executes `go vet` as a subprocess on various test packages.
* Validates the output of `go vet` by comparing it against expected error messages defined in comments within the test source files.
* Specifically tests various aspects of `go vet`, including individual analyzers, handling of build tags, and version-specific behaviors.

This detailed analysis allows me to generate a comprehensive explanation of the file's functions, provide code examples, and point out potential areas of confusion for users.
`go/src/cmd/vet/vet_test.go` 是 Go 语言 `vet` 工具的测试文件，它主要负责测试 `go vet` 工具的各种功能和检查项。

以下是该文件的主要功能分解：

**1. 模拟 `go vet` 命令执行:**

*   **`TestMain(m *testing.M)`:**  这个特殊的测试函数作为整个测试的入口点。它检查环境变量 `GO_VETTEST_IS_VET` 是否被设置。
    *   **如果设置了 `GO_VETTEST_IS_VET`:**  它会调用 `main()` 函数，这实际上会执行 `cmd/vet` 包中的 `main` 函数，使得这个测试二进制文件本身充当 `go vet` 命令。然后它会退出。
    *   **如果没有设置 `GO_VETTEST_IS_VET`:** 它会设置这个环境变量，并运行标准的 Go 测试 (`m.Run()`)。这意味着在正常的测试流程中，它会以子进程的方式调用自己（充当 `go vet`）。

**2. 提供运行 `go vet` 命令的辅助函数:**

*   **`vetPath(t testing.TB) string`:**  返回 `vet` 可执行文件的路径。在测试环境中，这通常是当前正在构建的测试二进制文件本身。
*   **`vetCmd(t *testing.T, arg, pkg string) *exec.Cmd`:**  创建一个 `exec.Cmd` 结构，用于执行 `go vet` 命令。
    *   它使用 `testenv.GoToolPath(t)` 获取 `go` 工具的路径。
    *   关键是它设置了 `-vettool=` 参数，指向 `vetPath(t)` 返回的路径，确保测试的是当前构建的 `vet` 工具。
    *   `arg` 参数允许传递额外的 `go vet` 命令行参数。
    *   `pkg` 参数指定要分析的包，这里指向 `cmd/vet/testdata` 目录下的子目录。

**3. 测试 `go vet` 的各种检查器 (Analyzers):**

*   **`TestVet(t *testing.T)`:** 这个函数包含了针对 `go vet` 不同检查器的测试用例。
    *   它遍历 `testdata` 目录下的多个子目录（例如 "appends", "assign", "atomic" 等），每个子目录对应一个或一组相关的 `go vet` 检查器。
    *   对于每个包，它会创建一个子测试 (`t.Run(pkg, ...)`），并在其中：
        *   调用 `vetCmd` 运行 `go vet`，通常会传递一些选项，例如 `-printfuncs=Warn,Warnf` 用于控制 `print` 检查器的行为。
        *   对于特定的测试（例如 "asm"），可能会设置额外的环境变量（例如 `GOOS` 和 `GOARCH`）。
        *   使用 `filepath.Glob` 找到测试数据包中的 `.go` 和 `.s` 文件。
        *   调用 `errchk` 函数来检查 `go vet` 的输出是否符合预期。

**4. 验证 `go vet` 的输出:**

*   **`errchk(c *exec.Cmd, files []string, t *testing.T)`:**  执行给定的 `exec.Cmd` 并检查其输出。
    *   它期望命令执行失败（因为 `go vet` 在发现问题时会返回非零退出码）。
    *   它将 `go vet` 的输出传递给 `errorCheck` 函数进行更详细的检查。
*   **`errorCheck(outStr string, wantAuto bool, fullshort ...string)`:**  这是核心的验证函数。
    *   它解析 `go vet` 的输出 (`outStr`)，并与源代码文件中的注释进行匹配。
    *   源代码中期望产生错误的行会包含类似 `// ERROR "regexp"` 或 `// ERRORAUTO "regexp"` 的注释。
    *   `errorCheck` 会检查：
        *   对于每一条包含 `// ERROR` 的注释的行，`go vet` 的输出中是否包含匹配该正则表达式的错误信息。
        *   `go vet` 的输出中是否存在没有在源代码中标记为错误的额外错误信息。
    *   `fullshort` 参数是一个包含文件完整路径和短名称的列表，用于在输出中替换完整路径为短名称，方便匹配。
*   **`splitOutput(out string, wantAuto bool) []string`:**  辅助函数，用于将 `go vet` 的输出按行分割，并处理多行错误信息的情况。
*   **`matchPrefix(s, prefix string) bool`:** 检查字符串 `s` 是否以给定的 `prefix` 开头，后跟一个冒号，可能前面还有目录名。
*   **`partitionStrings(prefix string, strs []string) (matched, unmatched []string)`:** 将字符串切片根据是否以给定的 `prefix` 开头进行分割。
*   **`wantedError` struct 和 `wantedErrors(file, short string)`:** 用于解析源代码文件中的 `// ERROR` 注释，提取预期的错误信息、正则表达式和行号。

**5. 测试命令行参数:**

*   **`TestTags(t *testing.T)`:**  专门测试 `-tags` 命令行参数的功能。
    *   它针对 `testdata/tagtest` 包运行 `go vet`，并使用不同的 `-tags` 参数。
    *   它验证了根据提供的构建标签，`go vet` 是否正确地包含了应该包含的文件，并排除了应该排除的文件。

**功能总结:**

总而言之，`go/src/cmd/vet/vet_test.go` 的主要功能是：

*   **作为一个测试框架，用于验证 `go vet` 工具的正确性。**
*   **模拟 `go vet` 命令的执行，方便在测试环境中使用。**
*   **针对 `go vet` 的各种检查器编写了详细的测试用例。**
*   **通过解析源代码中的特殊注释，验证 `go vet` 的输出是否符合预期。**
*   **测试了 `go vet` 的一些重要的命令行参数，例如 `-tags`。**

**它是什么 Go 语言功能的实现？**

这个测试文件本身并不是某个特定 Go 语言功能的实现，而是对 `go vet` 工具功能的测试。`go vet` 是 Go 语言工具链中的一个静态分析工具，用于检查 Go 源代码中潜在的错误、代码风格问题和可疑的构造。

**Go 代码举例说明:**

假设 `testdata/assign/assign.go` 中有以下代码：

```go
package assign

func _() {
	var x int
	x =  // ERROR "missing expression"
}
```

在 `TestVet` 函数中，当测试 "assign" 包时，`go vet` 会被执行，`errorCheck` 函数会读取 `assign.go` 文件，找到 `// ERROR "missing expression"` 的注释。然后，它会检查 `go vet` 的输出是否包含类似 `assign.go:4: missing expression` 的错误信息。

**假设的输入与输出（针对上面的例子）：**

*   **假设输入 (执行的命令):** `go vet -vettool=<path_to_test_binary> cmd/vet/testdata/assign`
*   **预期输出 (部分):** `assign.go:4: missing expression`

**命令行参数的具体处理:**

*   **`-vettool=<path>`:**  这个参数是测试框架自动添加的，用于指定要使用的 `vet` 工具的路径。这使得测试可以针对当前构建的 `vet` 工具进行。
*   **`-printfuncs=Warn,Warnf`:**  在某些测试用例中，例如测试 `print` 检查器时，会使用这个参数来告诉 `vet` 哪些函数应该被视为打印函数。
*   **`-tags=<tags>`:**  用于指定构建标签，`vet` 会根据这些标签选择要分析的文件。`TestTags` 函数会测试这个参数的正确性。

**使用者易犯错的点:**

*   **在 `errorCheck` 中编写错误的正则表达式:** 如果 `// ERROR` 注释中的正则表达式不正确，会导致测试失败，即使 `go vet` 的行为是正确的。
    *   **例子:** `// ERROR "mising expression"` (拼写错误) 可能无法匹配到 `go vet` 输出的 "missing expression"。
*   **`// ERROR` 注释的位置不正确:**  `errorCheck` 会检查注释所在行的下一个位置是否产生了预期的错误。如果注释放错行，测试也会失败。
*   **忘记更新测试用例:** 当修改 `go vet` 的行为或添加新的检查器时，需要相应地更新 `testdata` 目录下的测试文件和 `// ERROR` 注释，否则测试会变得不可靠。
*   **没有考虑到平台差异:**  某些 `vet` 检查器可能在不同的操作系统或架构上有不同的行为。测试用例需要考虑到这些差异，或者只在特定的平台上运行。

这个测试文件是 Go 语言 `vet` 工具质量保证的关键部分，通过大量的测试用例覆盖了 `vet` 的各种功能，确保了 `vet` 工具的稳定性和可靠性。

Prompt: 
```
这是路径为go/src/cmd/vet/vet_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"internal/testenv"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestMain executes the test binary as the vet command if
// GO_VETTEST_IS_VET is set, and runs the tests otherwise.
func TestMain(m *testing.M) {
	if os.Getenv("GO_VETTEST_IS_VET") != "" {
		main()
		os.Exit(0)
	}

	os.Setenv("GO_VETTEST_IS_VET", "1") // Set for subprocesses to inherit.
	os.Exit(m.Run())
}

// vetPath returns the path to the "vet" binary to run.
func vetPath(t testing.TB) string {
	return testenv.Executable(t)
}

func vetCmd(t *testing.T, arg, pkg string) *exec.Cmd {
	cmd := testenv.Command(t, testenv.GoToolPath(t), "vet", "-vettool="+vetPath(t), arg, path.Join("cmd/vet/testdata", pkg))
	cmd.Env = os.Environ()
	return cmd
}

func TestVet(t *testing.T) {
	t.Parallel()
	for _, pkg := range []string{
		"appends",
		"asm",
		"assign",
		"atomic",
		"bool",
		"buildtag",
		"cgo",
		"composite",
		"copylock",
		"deadcode",
		"directive",
		"httpresponse",
		"lostcancel",
		"method",
		"nilfunc",
		"print",
		"shift",
		"slog",
		"structtag",
		"testingpkg",
		// "testtag" has its own test
		"unmarshal",
		"unsafeptr",
		"unused",
	} {
		pkg := pkg
		t.Run(pkg, func(t *testing.T) {
			t.Parallel()

			// Skip cgo test on platforms without cgo.
			if pkg == "cgo" && !cgoEnabled(t) {
				return
			}

			cmd := vetCmd(t, "-printfuncs=Warn,Warnf", pkg)

			// The asm test assumes amd64.
			if pkg == "asm" {
				cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH=amd64")
			}

			dir := filepath.Join("testdata", pkg)
			gos, err := filepath.Glob(filepath.Join(dir, "*.go"))
			if err != nil {
				t.Fatal(err)
			}
			asms, err := filepath.Glob(filepath.Join(dir, "*.s"))
			if err != nil {
				t.Fatal(err)
			}
			var files []string
			files = append(files, gos...)
			files = append(files, asms...)

			errchk(cmd, files, t)
		})
	}

	// The loopclosure analyzer (aka "rangeloop" before CL 140578)
	// is a no-op for files whose version >= go1.22, so we use a
	// go.mod file in the rangeloop directory to "downgrade".
	//
	// TODO(adonovan): delete when go1.21 goes away.
	t.Run("loopclosure", func(t *testing.T) {
		cmd := testenv.Command(t, testenv.GoToolPath(t), "vet", "-vettool="+vetPath(t), ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		cmd.Dir = "testdata/rangeloop"
		cmd.Stderr = new(strings.Builder) // all vet output goes to stderr
		cmd.Run()
		stderr := cmd.Stderr.(fmt.Stringer).String()

		filename := filepath.FromSlash("testdata/rangeloop/rangeloop.go")

		// Unlike the tests above, which runs vet in cmd/vet/, this one
		// runs it in subdirectory, so the "full names" in the output
		// are in fact short "./rangeloop.go".
		// But we can't just pass "./rangeloop.go" as the "full name"
		// argument to errorCheck as it does double duty as both a
		// string that appears in the output, and as file name
		// openable relative to the test directory, containing text
		// expectations.
		//
		// So, we munge the file.
		stderr = strings.ReplaceAll(stderr, filepath.FromSlash("./rangeloop.go"), filename)

		if err := errorCheck(stderr, false, filename, filepath.Base(filename)); err != nil {
			t.Errorf("error check failed: %s", err)
			t.Log("vet stderr:\n", cmd.Stderr)
		}
	})

	// The stdversion analyzer requires a lower-than-tip go
	// version in its go.mod file for it to report anything.
	// So again we use a testdata go.mod file to "downgrade".
	t.Run("stdversion", func(t *testing.T) {
		cmd := testenv.Command(t, testenv.GoToolPath(t), "vet", "-vettool="+vetPath(t), ".")
		cmd.Env = append(os.Environ(), "GOWORK=off")
		cmd.Dir = "testdata/stdversion"
		cmd.Stderr = new(strings.Builder) // all vet output goes to stderr
		cmd.Run()
		stderr := cmd.Stderr.(fmt.Stringer).String()

		filename := filepath.FromSlash("testdata/stdversion/stdversion.go")

		// Unlike the tests above, which runs vet in cmd/vet/, this one
		// runs it in subdirectory, so the "full names" in the output
		// are in fact short "./rangeloop.go".
		// But we can't just pass "./rangeloop.go" as the "full name"
		// argument to errorCheck as it does double duty as both a
		// string that appears in the output, and as file name
		// openable relative to the test directory, containing text
		// expectations.
		//
		// So, we munge the file.
		stderr = strings.ReplaceAll(stderr, filepath.FromSlash("./stdversion.go"), filename)

		if err := errorCheck(stderr, false, filename, filepath.Base(filename)); err != nil {
			t.Errorf("error check failed: %s", err)
			t.Log("vet stderr:\n", cmd.Stderr)
		}
	})
}

func cgoEnabled(t *testing.T) bool {
	// Don't trust build.Default.CgoEnabled as it is false for
	// cross-builds unless CGO_ENABLED is explicitly specified.
	// That's fine for the builders, but causes commands like
	// 'GOARCH=386 go test .' to fail.
	// Instead, we ask the go command.
	cmd := testenv.Command(t, testenv.GoToolPath(t), "list", "-f", "{{context.CgoEnabled}}")
	out, _ := cmd.CombinedOutput()
	return string(out) == "true\n"
}

func errchk(c *exec.Cmd, files []string, t *testing.T) {
	output, err := c.CombinedOutput()
	if _, ok := err.(*exec.ExitError); !ok {
		t.Logf("vet output:\n%s", output)
		t.Fatal(err)
	}
	fullshort := make([]string, 0, len(files)*2)
	for _, f := range files {
		fullshort = append(fullshort, f, filepath.Base(f))
	}
	err = errorCheck(string(output), false, fullshort...)
	if err != nil {
		t.Errorf("error check failed: %s", err)
	}
}

// TestTags verifies that the -tags argument controls which files to check.
func TestTags(t *testing.T) {
	t.Parallel()
	for tag, wantFile := range map[string]int{
		"testtag":     1, // file1
		"x testtag y": 1,
		"othertag":    2,
	} {
		tag, wantFile := tag, wantFile
		t.Run(tag, func(t *testing.T) {
			t.Parallel()
			t.Logf("-tags=%s", tag)
			cmd := vetCmd(t, "-tags="+tag, "tagtest")
			output, err := cmd.CombinedOutput()

			want := fmt.Sprintf("file%d.go", wantFile)
			dontwant := fmt.Sprintf("file%d.go", 3-wantFile)

			// file1 has testtag and file2 has !testtag.
			if !bytes.Contains(output, []byte(filepath.Join("tagtest", want))) {
				t.Errorf("%s: %s was excluded, should be included", tag, want)
			}
			if bytes.Contains(output, []byte(filepath.Join("tagtest", dontwant))) {
				t.Errorf("%s: %s was included, should be excluded", tag, dontwant)
			}
			if t.Failed() {
				t.Logf("err=%s, output=<<%s>>", err, output)
			}
		})
	}
}

// All declarations below were adapted from test/run.go.

// errorCheck matches errors in outStr against comments in source files.
// For each line of the source files which should generate an error,
// there should be a comment of the form // ERROR "regexp".
// If outStr has an error for a line which has no such comment,
// this function will report an error.
// Likewise if outStr does not have an error for a line which has a comment,
// or if the error message does not match the <regexp>.
// The <regexp> syntax is Perl but it's best to stick to egrep.
//
// Sources files are supplied as fullshort slice.
// It consists of pairs: full path to source file and its base name.
func errorCheck(outStr string, wantAuto bool, fullshort ...string) (err error) {
	var errs []error
	out := splitOutput(outStr, wantAuto)
	// Cut directory name.
	for i := range out {
		for j := 0; j < len(fullshort); j += 2 {
			full, short := fullshort[j], fullshort[j+1]
			out[i] = strings.ReplaceAll(out[i], full, short)
		}
	}

	var want []wantedError
	for j := 0; j < len(fullshort); j += 2 {
		full, short := fullshort[j], fullshort[j+1]
		want = append(want, wantedErrors(full, short)...)
	}
	for _, we := range want {
		var errmsgs []string
		if we.auto {
			errmsgs, out = partitionStrings("<autogenerated>", out)
		} else {
			errmsgs, out = partitionStrings(we.prefix, out)
		}
		if len(errmsgs) == 0 {
			errs = append(errs, fmt.Errorf("%s:%d: missing error %q", we.file, we.lineNum, we.reStr))
			continue
		}
		matched := false
		n := len(out)
		for _, errmsg := range errmsgs {
			// Assume errmsg says "file:line: foo".
			// Cut leading "file:line: " to avoid accidental matching of file name instead of message.
			text := errmsg
			if _, suffix, ok := strings.Cut(text, " "); ok {
				text = suffix
			}
			if we.re.MatchString(text) {
				matched = true
			} else {
				out = append(out, errmsg)
			}
		}
		if !matched {
			errs = append(errs, fmt.Errorf("%s:%d: no match for %#q in:\n\t%s", we.file, we.lineNum, we.reStr, strings.Join(out[n:], "\n\t")))
			continue
		}
	}

	if len(out) > 0 {
		errs = append(errs, fmt.Errorf("Unmatched Errors:"))
		for _, errLine := range out {
			errs = append(errs, fmt.Errorf("%s", errLine))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	var buf strings.Builder
	fmt.Fprintf(&buf, "\n")
	for _, err := range errs {
		fmt.Fprintf(&buf, "%s\n", err.Error())
	}
	return errors.New(buf.String())
}

func splitOutput(out string, wantAuto bool) []string {
	// gc error messages continue onto additional lines with leading tabs.
	// Split the output at the beginning of each line that doesn't begin with a tab.
	// <autogenerated> lines are impossible to match so those are filtered out.
	var res []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSuffix(line, "\r") // normalize Windows output
		if strings.HasPrefix(line, "\t") {
			res[len(res)-1] += "\n" + line
		} else if strings.HasPrefix(line, "go tool") || strings.HasPrefix(line, "#") || !wantAuto && strings.HasPrefix(line, "<autogenerated>") {
			continue
		} else if strings.TrimSpace(line) != "" {
			res = append(res, line)
		}
	}
	return res
}

// matchPrefix reports whether s starts with file name prefix followed by a :,
// and possibly preceded by a directory name.
func matchPrefix(s, prefix string) bool {
	i := strings.Index(s, ":")
	if i < 0 {
		return false
	}
	j := strings.LastIndex(s[:i], "/")
	s = s[j+1:]
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return false
	}
	if s[len(prefix)] == ':' {
		return true
	}
	return false
}

func partitionStrings(prefix string, strs []string) (matched, unmatched []string) {
	for _, s := range strs {
		if matchPrefix(s, prefix) {
			matched = append(matched, s)
		} else {
			unmatched = append(unmatched, s)
		}
	}
	return
}

type wantedError struct {
	reStr   string
	re      *regexp.Regexp
	lineNum int
	auto    bool // match <autogenerated> line
	file    string
	prefix  string
}

var (
	errRx       = regexp.MustCompile(`// (?:GC_)?ERROR(NEXT)? (.*)`)
	errAutoRx   = regexp.MustCompile(`// (?:GC_)?ERRORAUTO(NEXT)? (.*)`)
	errQuotesRx = regexp.MustCompile(`"([^"]*)"`)
	lineRx      = regexp.MustCompile(`LINE(([+-])(\d+))?`)
)

// wantedErrors parses expected errors from comments in a file.
func wantedErrors(file, short string) (errs []wantedError) {
	cache := make(map[string]*regexp.Regexp)

	src, err := os.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		lineNum := i + 1
		if strings.Contains(line, "////") {
			// double comment disables ERROR
			continue
		}
		var auto bool
		m := errAutoRx.FindStringSubmatch(line)
		if m != nil {
			auto = true
		} else {
			m = errRx.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}
		if m[1] == "NEXT" {
			lineNum++
		}
		all := m[2]
		mm := errQuotesRx.FindAllStringSubmatch(all, -1)
		if mm == nil {
			log.Fatalf("%s:%d: invalid errchk line: %s", file, lineNum, line)
		}
		for _, m := range mm {
			replacedOnce := false
			rx := lineRx.ReplaceAllStringFunc(m[1], func(m string) string {
				if replacedOnce {
					return m
				}
				replacedOnce = true
				n := lineNum
				if strings.HasPrefix(m, "LINE+") {
					delta, _ := strconv.Atoi(m[5:])
					n += delta
				} else if strings.HasPrefix(m, "LINE-") {
					delta, _ := strconv.Atoi(m[5:])
					n -= delta
				}
				return fmt.Sprintf("%s:%d", short, n)
			})
			re := cache[rx]
			if re == nil {
				var err error
				re, err = regexp.Compile(rx)
				if err != nil {
					log.Fatalf("%s:%d: invalid regexp \"%#q\" in ERROR line: %v", file, lineNum, rx, err)
				}
				cache[rx] = re
			}
			prefix := fmt.Sprintf("%s:%d", short, lineNum)
			errs = append(errs, wantedError{
				reStr:   rx,
				re:      re,
				prefix:  prefix,
				auto:    auto,
				lineNum: lineNum,
				file:    short,
			})
		}
	}

	return
}

"""



```