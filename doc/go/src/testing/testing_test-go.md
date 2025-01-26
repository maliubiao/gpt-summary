Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding and Context:**

* **File Path:**  The first thing I notice is `go/src/testing/testing_test.go`. This immediately tells me this is part of the standard Go library's testing framework, specifically its own test suite. This means the code is designed to test the functionality of the `testing` package itself.
* **Package Name:** `package testing_test` confirms this is an external test package for `testing`. This is a common practice in Go to avoid import cycles.
* **Imports:**  Scanning the imports gives a high-level overview of the functionalities being tested. I see imports like `os`, `os/exec`, `time`, `sync`, `context`, `regexp`, `path/filepath`, and crucially, the `testing` package itself. The `internal/*` imports suggest testing of some internal mechanics as well.

**2. Analyzing `TestMain`:**

* **Purpose:**  The comment clearly states its purpose: to mimic a test without an explicit `TestMain` and to ensure the code path for `TestMain` execution is covered.
* **Race Condition Handling:** The code checks for an environment variable `GO_WANT_RACE_BEFORE_TESTS`. This hints at testing the race detector's behavior before the actual tests run. The comments about the "somewhat fundamental race" are important for understanding the limitations of race detection in the `TestMain` context.

**3. Deconstructing Individual Test Functions (Iterative Approach):**

I'd go through each `Test...` and `Benchmark...` function, trying to understand its specific purpose:

* **`TestTempDirInCleanup` & `TestTempDirInBenchmark`:**  These clearly test the behavior of `t.TempDir()` within `t.Cleanup()` and benchmarks. The assertions check if the temporary directory is correctly removed after the cleanup function runs.
* **`TestTempDir` & `testTempDir`:** These test the core functionality of `t.TempDir()`, ensuring it creates a temporary directory, that subsequent calls create different directories, and that the directory is cleaned up. The various subtest names in `TestTempDir` suggest testing with different path conventions.
* **`TestSetenv`:** This function focuses on `t.Setenv()`, verifying that it correctly sets environment variables for the duration of the test and restores the original values afterward. The different test cases cover setting existing, empty, and non-existent variables.
* **`expectParallelConflict` and `testWithParallel...` functions:** These are helper functions designed to test the behavior of `t.Parallel()` and the expected panic (`testing.ParallelConflict`) when it's called incorrectly (e.g., after other `t` methods).
* **`TestSetenvWithParallel...` & `TestChdirWithParallel...`:** These specifically test the interaction between `t.Setenv()` and `t.Chdir()` with `t.Parallel()`, expecting conflicts.
* **`TestChdir`:** This function tests the functionality of `t.Chdir()`, covering absolute and relative paths, and verifying that the current working directory is correctly changed and restored.
* **`TestTesting`:**  This checks the behavior of `testing.Testing()`, both within test functions and outside (in `init` and package variable initialization). It also demonstrates how `testing.Testing()` returns `false` when the code is run as a regular program.
* **`runTest`:** This is a crucial helper function for running tests as separate processes. It sets up specific flags (`-test.run`, `-test.bench`, `-test.v`, `-test.parallel`, `-test.benchtime`) and environment variables (`GO_WANT_HELPER_PROCESS`). Understanding this function is key to understanding many of the subsequent tests.
* **`doRace`:** This simple function deliberately creates a data race. It's used throughout the tests to verify the race detector's behavior.
* **`TestRaceReports`, `TestRaceName`, `TestRaceSubReports`, `TestRaceInCleanup`, `TestDeepSubtestRace`, `TestRaceDuringParallelFailsAllSubtests`, `TestRaceBeforeParallel`, `TestRaceBeforeTests`, `TestBenchmarkRace`, `TestBenchmarkRaceBLoop`, `TestBenchmarkSubRace`:** All these tests are designed to exercise the race detector in various scenarios: in regular tests, subtests, cleanup functions, parallel tests, and benchmarks. They rely heavily on `runTest` and `doRace`.
* **`TestRunningTests` & `TestRunningTestsInCleanup`:**  These tests focus on how the testing framework reports "running tests" when timeouts occur, particularly in scenarios involving parallel tests and cleanup functions. The `parseRunningTests` function is used to extract the names of the currently running tests from the output.
* **`TestConcurrentRun` & `TestParentRun`:** These are regression tests designed to prevent deadlocks that were previously identified.
* **`TestContext`:** This tests the behavior of `t.Context()`, ensuring that each test gets a new context and that contexts are canceled appropriately.
* **`TestBenchmarkBLoopIterationCorrect` & `TestBenchmarkBNIterationCorrect`:** These verify that the benchmark loop (`b.Loop()` and `for i < b.N`) runs the expected number of iterations based on the `-test.benchtime` flag.
* **`BenchmarkBLoopPrint` & `BenchmarkBNPrint`:** These are the benchmark functions used by the previous tests to generate output for analysis.

**4. Identifying Go Language Features:**

As I analyzed the code, I'd specifically note the Go features being demonstrated:

* **Testing Framework (`testing` package):**  This is the central focus, demonstrating how to write tests (`Test...` functions), benchmarks (`Benchmark...` functions), subtests (`t.Run`), setup/cleanup (`t.Cleanup`), temporary directories (`t.TempDir`), setting environment variables (`t.Setenv`), changing directories (`t.Chdir`), running tests in parallel (`t.Parallel`), skipping tests (`t.Skip`), logging (`t.Log`, `t.Logf`), error reporting (`t.Error`, `t.Errorf`, `t.Fatal`, `t.Fatalf`), and accessing the test context (`t.Context`).
* **Race Detection:** The extensive use of `doRace()` and checks for "race detected" in the output highlight the built-in race detection capabilities.
* **Subprocesses (`os/exec`):** The `runTest` function uses `os/exec` to execute the test binary itself, allowing for testing of command-line flags and environment variables.
* **Environment Variables (`os.Getenv`, `os.Setenv`, `os.Unsetenv`, `os.LookupEnv`):** Used extensively in `TestSetenv` and in controlling the test execution environment (e.g., `GO_WANT_HELPER_PROCESS`).
* **File System Operations (`os.MkdirTemp`, `os.Stat`, `os.ReadDir`, `path/filepath`):** Used in `TestTempDir` and `TestChdir`.
* **Concurrency (`sync`, `chan`, `go`):**  Demonstrated in the race condition examples and the `TestConcurrentRun` test.
* **Contexts (`context`):**  Tested in `TestContext`.
* **Regular Expressions (`regexp`):** Used for verifying output in several tests.

**5. Inferring Command-Line Parameters:**

By looking at how `runTest` constructs the command, I could deduce the purpose of flags like `-test.run`, `-test.bench`, `-test.v`, `-test.parallel`, and `-test.benchtime`. The `TestRaceBeforeTests` function explicitly sets the `GO_WANT_RACE_BEFORE_TESTS` environment variable, which implies it's a way to trigger race detection outside of the normal test execution.

**6. Identifying Potential Errors:**

The tests related to `t.Parallel()` and the `expectParallelConflict` function directly highlight common mistakes users might make when using parallel testing. The comments in `TestMain` about the race condition with the "PASS" message also point out a subtle potential issue.

**7. Structuring the Output:**

Finally, I'd organize my findings into the requested categories (functionality, Go feature examples, command-line arguments, common mistakes) and present them clearly in Chinese.
这段代码是 Go 语言标准库 `testing` 包的一部分，用于测试 `testing` 包自身的功能。它包含了一系列测试函数（以 `Test` 开头）和基准测试函数（以 `Benchmark` 开头），用来验证 `testing` 包提供的各种特性是否按预期工作。

以下是代码中主要功能的详细列举和说明：

**1. `TestMain` 函数:**

* **功能:**  这是测试包的可选入口点。如果没有 `TestMain` 函数，`testing` 包会直接运行所有的测试函数。这段代码提供了一个 `TestMain` 的示例，并演示了在所有测试运行前后执行代码的能力。
* **Go 语言功能实现:**  `TestMain` 是 `testing` 包的一个特殊功能，允许用户在测试执行的生命周期中插入自定义逻辑，例如设置全局状态或进行清理。
* **代码示例:**
```go
package mypackage_test

import "testing"
import "os"
import "fmt"

func TestMain(m *testing.M) {
	fmt.Println("Before all tests")
	exitCode := m.Run()
	fmt.Println("After all tests")
	os.Exit(exitCode)
}

func TestExample(t *testing.T) {
	// ... 一些测试代码
}
```
* **假设输入与输出:** 运行 `go test` 命令。
* **输出:** 控制台会先打印 "Before all tests"，然后运行所有测试，最后打印 "After all tests"。

**2. `TestTempDirInCleanup` 和 `TestTempDirInBenchmark` 函数:**

* **功能:**  测试 `t.TempDir()` 方法在 `t.Cleanup()` 函数和基准测试中的行为。`t.TempDir()` 用于创建一个临时的目录，该目录会在测试结束后自动删除。这些测试确保在 `Cleanup` 函数中调用 `t.TempDir()` 获取的目录在 `Cleanup` 执行后确实被删除了，并且在基准测试中也能正常工作。
* **Go 语言功能实现:**  测试 `testing.T` 和 `testing.B` 类型的 `TempDir` 和 `Cleanup` 方法。
* **代码示例 (`TestTempDirInCleanup`):**  代码本身已经提供了很好的示例。
* **假设输入与输出:** 运行包含此测试的测试包。
* **输出:** 如果目录没有被删除，测试会失败并打印错误信息。

**3. `TestTempDir` 和 `testTempDir` 函数:**

* **功能:**  测试 `t.TempDir()` 的基本功能，包括创建唯一的临时目录，以及在子测试中调用时也能正常工作。它还测试了不同命名方式的子测试是否影响 `TempDir` 的行为。
* **Go 语言功能实现:**  测试 `testing.T` 类型的 `TempDir` 方法以及子测试的创建。
* **代码示例:**  代码本身已经提供了很好的示例。
* **假设输入与输出:** 运行包含此测试的测试包。
* **输出:** 如果 `TempDir` 没有按预期创建和清理目录，测试会失败。

**4. `TestSetenv` 函数:**

* **功能:**  测试 `t.Setenv()` 方法，该方法用于在测试期间设置环境变量，并在测试结束后恢复原始值。它覆盖了设置已存在、空和不存在的环境变量的情况。
* **Go 语言功能实现:**  测试 `testing.T` 类型的 `Setenv` 方法。
* **代码示例:**
```go
func TestSetEnvExample(t *testing.T) {
	t.Setenv("MY_TEST_VAR", "test_value")
	if os.Getenv("MY_TEST_VAR") != "test_value" {
		t.Errorf("环境变量设置失败")
	}
	// 测试结束后，MY_TEST_VAR 的值会被恢复
}
```
* **假设输入与输出:**  运行包含此测试的测试包。在测试函数内部，环境变量 `MY_TEST_VAR` 的值会被临时设置为 "test_value"。测试结束后，它的值会恢复到运行测试之前的状态。

**5. 与 `t.Parallel()` 相关的测试函数 (`expectParallelConflict`, `testWithParallelAfter`, `testWithParallelBefore`, `testWithParallelParentBefore`, `testWithParallelGrandParentBefore`, `TestSetenvWithParallel...`, `TestChdirWithParallel...`):**

* **功能:**  这些函数测试 `t.Parallel()` 方法的使用限制。`t.Parallel()` 必须在测试函数内尽早调用，并且在调用 `t.Parallel()` 之后不能再调用某些修改测试状态的方法（如 `t.Setenv` 和 `t.Chdir`）。这些测试验证了违反这些规则会导致 panic。
* **Go 语言功能实现:**  测试 `testing.T` 类型的 `Parallel` 方法以及其与其他方法之间的交互限制。
* **代码示例 (`testWithParallelAfter`):**  代码本身已经提供了很好的示例。
* **假设输入与输出:**  运行包含这些测试的测试包。如果 `t.Parallel()` 被错误调用，测试会 panic 并被 `expectParallelConflict` 捕获。

**6. `TestChdir` 函数:**

* **功能:**  测试 `t.Chdir()` 方法，该方法用于在测试期间改变当前工作目录，并在测试结束后恢复原始目录。它测试了使用绝对路径、相对路径以及特殊路径 (".") 改变目录的情况。
* **Go 语言功能实现:**  测试 `testing.T` 类型的 `Chdir` 方法。
* **代码示例:**
```go
func TestChdirExample(t *testing.T) {
	originalDir, _ := os.Getwd()
	tempDir := t.TempDir()
	t.Chdir(tempDir)
	currentDir, _ := os.Getwd()
	if currentDir != tempDir {
		t.Errorf("切换目录失败")
	}
	// 测试结束后，工作目录会被恢复到 originalDir
}
```
* **假设输入与输出:**  运行包含此测试的测试包。测试函数内部，当前工作目录会被临时更改为 `t.TempDir()` 创建的目录。测试结束后，工作目录会被恢复。

**7. `TestTesting` 函数:**

* **功能:**  测试 `testing.Testing()` 函数。`testing.Testing()` 在运行测试时返回 `true`，在正常程序运行时返回 `false`。此测试验证了这一行为，包括在 `init` 函数和包变量初始化时的行为。
* **Go 语言功能实现:**  测试 `testing` 包的 `Testing` 函数。
* **代码示例:** 代码中已经提供了很好的示例，展示了在不同上下文中使用 `testing.Testing()`。
* **假设输入与输出:**  运行 `go test` 时，`testing.Testing()` 返回 `true`。编译并运行包含 `testingProg` 内容的独立 Go 程序时，它会打印 `false`。

**8. `runTest` 函数:**

* **功能:**  这是一个辅助函数，用于以特定的标志和环境变量运行测试二进制文件。这允许测试 `testing` 包本身如何处理不同的命令行参数和环境。
* **Go 语言功能实现:**  使用 `os/exec` 包来执行命令。
* **命令行参数处理:**
    * `-test.run=^` + `test` + `$`：指定要运行的测试函数或基准测试函数的正则表达式。
    * `-test.bench=` + `test`：指定要运行的基准测试函数的正则表达式。
    * `-test.v`：启用详细输出，显示所有测试的名称和结果。
    * `-test.parallel=2`：设置并行运行的测试数量。
    * `-test.benchtime=2x`：设置基准测试的运行时间或迭代次数。
* **环境变量处理:** 设置 `GO_WANT_HELPER_PROCESS=1`，用于区分主测试进程和辅助进程。

**9. 与 Race Detector 相关的测试函数 (`doRace`, `TestRaceReports`, `TestRaceName`, `TestRaceSubReports`, `TestRaceInCleanup`, `TestDeepSubtestRace`, `TestRaceDuringParallelFailsAllSubtests`, `TestRaceBeforeParallel`, `TestRaceBeforeTests`, `TestBenchmarkRace`, `TestBenchmarkRaceBLoop`, `TestBenchmarkSubRace`):**

* **功能:**  这些函数用于测试 Go 语言的 race detector 功能与 `testing` 包的集成。`doRace` 函数故意引入数据竞争。这些测试验证了 race detector 是否能在不同的测试场景（包括子测试、并行测试、清理函数和基准测试）中正确地检测到数据竞争。
* **Go 语言功能实现:**  依赖于 Go 语言内置的 race detector。需要在运行测试时加上 `-race` 标志来启用 race detector。
* **命令行参数处理:**  `TestRaceBeforeTests` 函数演示了通过设置环境变量 `GO_WANT_RACE_BEFORE_TESTS=1` 来在测试开始前触发 race 检测。通常，race 检测是在测试函数执行期间进行的。
* **假设输入与输出:**
    * **输入:** 运行 `go test -race` 命令。
    * **输出:** 如果检测到数据竞争，控制台会输出包含 "race detected" 的报告。例如：
    ```
    ==================
    WARNING: DATA RACE
    Write at 0x... by goroutine ...:
      main.doRace.func1()
          ...

    Previous read at 0x... by goroutine ...:
      main.doRace()
          ...
    ==================
    ```

**10. 与测试超时相关的测试函数 (`TestRunningTests`, `TestRunningTestsInCleanup`):**

* **功能:**  这些函数测试当测试超时时，`testing` 包如何报告正在运行的测试。它们特别关注并行测试和清理函数中的超时情况。
* **Go 语言功能实现:**  测试 `testing` 包的超时机制。
* **命令行参数处理:** 使用 `-test.timeout` 标志设置测试的超时时间。
* **代码示例 (`TestRunningTests`):**  代码本身演示了如何创建一个会超时的测试场景。
* **假设输入与输出:**
    * **输入:** 运行 `go test -timeout 10ms`。
    * **输出:** 如果测试超时，会输出类似以下的错误信息，其中 "running tests:" 部分列出了超时时正在运行的测试：
    ```
    --- FAIL: TestRunningTests (0.01s)
        testing_test.go:632:
            Command: [/path/to/testbinary -test.run=^TestRunningTests$ -test.timeout=10ms -test.parallel=4]
            exit status 2
            Stderr:
            panic: test timed out after 10ms

            running tests:
            	_/path/to/testing/testing_test.TestRunningTests/outer0/inner0
            	_/path/to/testing/testing_test.TestRunningTests/outer0/inner1
            	_/path/to/testing/testing_test.TestRunningTests/outer1/inner0
            	_/path/to/testing/testing_test.TestRunningTests/outer1/inner1

    FAIL
    ```

**11. 回归测试 (`TestConcurrentRun`, `TestParentRun`):**

* **功能:**  这些函数是回归测试，用于验证之前报告过的 bug 是否已修复，并且不会再次出现。例如，`TestConcurrentRun` 旨在防止在特定并发场景下发生死锁。

**12. `TestContext` 函数:**

* **功能:**  测试 `t.Context()` 方法，该方法返回与测试关联的 `context.Context`。它验证了每个测试都有自己的上下文，并且子测试不会继承父测试的已取消的上下文，以及测试结束后上下文会被取消。
* **Go 语言功能实现:**  测试 `testing.T` 类型的 `Context` 方法以及与 `context` 包的集成。

**13. 基准测试相关的函数 (`TestBenchmarkBLoopIterationCorrect`, `TestBenchmarkBNIterationCorrect`, `BenchmarkBLoopPrint`, `BenchmarkBNPrint`):**

* **功能:**  测试基准测试的迭代次数是否正确。`BenchmarkBLoopPrint` 使用 `b.Loop()`，`BenchmarkBNPrint` 使用 `for i < b.N`。测试验证了在指定 `-test.benchtime` 的情况下，基准测试运行的次数是否符合预期。
* **Go 语言功能实现:**  测试 `testing.B` 类型的 `Loop` 和 `N` 属性以及基准测试的运行机制。
* **命令行参数处理:**  `TestBenchmarkBLoopIterationCorrect` 和 `TestBenchmarkBNIterationCorrect` 通过 `runTest` 函数使用 `-test.benchtime` 参数来控制基准测试的运行时间。

**使用者易犯错的点 (从代码中推断):**

* **在 `t.Parallel()` 调用之后调用修改测试状态的方法:**  例如，在调用 `t.Parallel()` 后再调用 `t.Setenv` 或 `t.Chdir` 会导致 panic。这是因为并行运行的测试不应该修改共享的测试状态。
* **对 `t.Cleanup()` 的理解:**  `t.Cleanup()` 中注册的函数会在测试函数返回后执行。如果在 `Cleanup` 函数中访问测试作用域内的变量，需要注意闭包的捕获行为。`TestTempDirInCleanup` 测试就展示了在 `Cleanup` 中访问外部变量的情况。
* **Race Detector 的使用:**  忘记在运行需要检测数据竞争的测试时加上 `-race` 标志。

总的来说，这段代码是 `testing` 包自身测试套件的核心部分，它覆盖了 `testing` 包提供的各种功能，并使用了各种测试技术来确保这些功能的正确性和健壮性。通过阅读和理解这段代码，可以深入了解 Go 语言的测试机制以及如何编写高质量的测试。

Prompt: 
```
这是路径为go/src/testing/testing_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testing_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"internal/race"
	"internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// This is exactly what a test would do without a TestMain.
// It's here only so that there is at least one package in the
// standard library with a TestMain, so that code is executed.

func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_RACE_BEFORE_TESTS") == "1" {
		doRace()
	}

	m.Run()

	// Note: m.Run currently prints the final "PASS" line, so if any race is
	// reported here (after m.Run but before the process exits), it will print
	// "PASS", then print the stack traces for the race, then exit with nonzero
	// status.
	//
	// This is a somewhat fundamental race: because the race detector hooks into
	// the runtime at a very low level, no matter where we put the printing it
	// would be possible to report a race that occurs afterward. However, we could
	// theoretically move the printing after TestMain, which would at least do a
	// better job of diagnosing races in cleanup functions within TestMain itself.
}

func TestTempDirInCleanup(t *testing.T) {
	var dir string

	t.Run("test", func(t *testing.T) {
		t.Cleanup(func() {
			dir = t.TempDir()
		})
		_ = t.TempDir()
	})

	fi, err := os.Stat(dir)
	if fi != nil {
		t.Fatalf("Directory %q from user Cleanup still exists", dir)
	}
	if !os.IsNotExist(err) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestTempDirInBenchmark(t *testing.T) {
	testing.Benchmark(func(b *testing.B) {
		if !b.Run("test", func(b *testing.B) {
			// Add a loop so that the test won't fail. See issue 38677.
			for i := 0; i < b.N; i++ {
				_ = b.TempDir()
			}
		}) {
			t.Fatal("Sub test failure in a benchmark")
		}
	})
}

func TestTempDir(t *testing.T) {
	testTempDir(t)
	t.Run("InSubtest", testTempDir)
	t.Run("test/subtest", testTempDir)
	t.Run("test\\subtest", testTempDir)
	t.Run("test:subtest", testTempDir)
	t.Run("test/..", testTempDir)
	t.Run("../test", testTempDir)
	t.Run("test[]", testTempDir)
	t.Run("test*", testTempDir)
	t.Run("äöüéè", testTempDir)
}

func testTempDir(t *testing.T) {
	dirCh := make(chan string, 1)
	t.Cleanup(func() {
		// Verify directory has been removed.
		select {
		case dir := <-dirCh:
			fi, err := os.Stat(dir)
			if os.IsNotExist(err) {
				// All good
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Errorf("directory %q still exists: %v, isDir=%v", dir, fi, fi.IsDir())
		default:
			if !t.Failed() {
				t.Fatal("never received dir channel")
			}
		}
	})

	dir := t.TempDir()
	if dir == "" {
		t.Fatal("expected dir")
	}
	dir2 := t.TempDir()
	if dir == dir2 {
		t.Fatal("subsequent calls to TempDir returned the same directory")
	}
	if filepath.Dir(dir) != filepath.Dir(dir2) {
		t.Fatalf("calls to TempDir do not share a parent; got %q, %q", dir, dir2)
	}
	dirCh <- dir
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Errorf("dir %q is not a dir", dir)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) > 0 {
		t.Errorf("unexpected %d files in TempDir: %v", len(files), files)
	}

	glob := filepath.Join(dir, "*.txt")
	if _, err := filepath.Glob(glob); err != nil {
		t.Error(err)
	}
}

func TestSetenv(t *testing.T) {
	tests := []struct {
		name               string
		key                string
		initialValueExists bool
		initialValue       string
		newValue           string
	}{
		{
			name:               "initial value exists",
			key:                "GO_TEST_KEY_1",
			initialValueExists: true,
			initialValue:       "111",
			newValue:           "222",
		},
		{
			name:               "initial value exists but empty",
			key:                "GO_TEST_KEY_2",
			initialValueExists: true,
			initialValue:       "",
			newValue:           "222",
		},
		{
			name:               "initial value is not exists",
			key:                "GO_TEST_KEY_3",
			initialValueExists: false,
			initialValue:       "",
			newValue:           "222",
		},
	}

	for _, test := range tests {
		if test.initialValueExists {
			if err := os.Setenv(test.key, test.initialValue); err != nil {
				t.Fatalf("unable to set env: got %v", err)
			}
		} else {
			os.Unsetenv(test.key)
		}

		t.Run(test.name, func(t *testing.T) {
			t.Setenv(test.key, test.newValue)
			if os.Getenv(test.key) != test.newValue {
				t.Fatalf("unexpected value after t.Setenv: got %s, want %s", os.Getenv(test.key), test.newValue)
			}
		})

		got, exists := os.LookupEnv(test.key)
		if got != test.initialValue {
			t.Fatalf("unexpected value after t.Setenv cleanup: got %s, want %s", got, test.initialValue)
		}
		if exists != test.initialValueExists {
			t.Fatalf("unexpected value after t.Setenv cleanup: got %t, want %t", exists, test.initialValueExists)
		}
	}
}

func expectParallelConflict(t *testing.T) {
	want := testing.ParallelConflict
	if got := recover(); got != want {
		t.Fatalf("expected panic; got %#v want %q", got, want)
	}
}

func testWithParallelAfter(t *testing.T, fn func(*testing.T)) {
	defer expectParallelConflict(t)

	fn(t)
	t.Parallel()
}

func testWithParallelBefore(t *testing.T, fn func(*testing.T)) {
	defer expectParallelConflict(t)

	t.Parallel()
	fn(t)
}

func testWithParallelParentBefore(t *testing.T, fn func(*testing.T)) {
	t.Parallel()

	t.Run("child", func(t *testing.T) {
		defer expectParallelConflict(t)

		fn(t)
	})
}

func testWithParallelGrandParentBefore(t *testing.T, fn func(*testing.T)) {
	t.Parallel()

	t.Run("child", func(t *testing.T) {
		t.Run("grand-child", func(t *testing.T) {
			defer expectParallelConflict(t)

			fn(t)
		})
	})
}

func tSetenv(t *testing.T) {
	t.Setenv("GO_TEST_KEY_1", "value")
}

func TestSetenvWithParallelAfter(t *testing.T) {
	testWithParallelAfter(t, tSetenv)
}

func TestSetenvWithParallelBefore(t *testing.T) {
	testWithParallelBefore(t, tSetenv)
}

func TestSetenvWithParallelParentBefore(t *testing.T) {
	testWithParallelParentBefore(t, tSetenv)
}

func TestSetenvWithParallelGrandParentBefore(t *testing.T) {
	testWithParallelGrandParentBefore(t, tSetenv)
}

func tChdir(t *testing.T) {
	t.Chdir(t.TempDir())
}

func TestChdirWithParallelAfter(t *testing.T) {
	testWithParallelAfter(t, tChdir)
}

func TestChdirWithParallelBefore(t *testing.T) {
	testWithParallelBefore(t, tChdir)
}

func TestChdirWithParallelParentBefore(t *testing.T) {
	testWithParallelParentBefore(t, tChdir)
}

func TestChdirWithParallelGrandParentBefore(t *testing.T) {
	testWithParallelGrandParentBefore(t, tChdir)
}

func TestChdir(t *testing.T) {
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldDir)

	// The "relative" test case relies on tmp not being a symlink.
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(oldDir, tmp)
	if err != nil {
		// If GOROOT is on C: volume and tmp is on the D: volume, there
		// is no relative path between them, so skip that test case.
		rel = "skip"
	}

	for _, tc := range []struct {
		name, dir, pwd string
		extraChdir     bool
	}{
		{
			name: "absolute",
			dir:  tmp,
			pwd:  tmp,
		},
		{
			name: "relative",
			dir:  rel,
			pwd:  tmp,
		},
		{
			name: "current (absolute)",
			dir:  oldDir,
			pwd:  oldDir,
		},
		{
			name: "current (relative) with extra os.Chdir",
			dir:  ".",
			pwd:  oldDir,

			extraChdir: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dir == "skip" {
				t.Skipf("skipping test because there is no relative path between %s and %s", oldDir, tmp)
			}
			if !filepath.IsAbs(tc.pwd) {
				t.Fatalf("Bad tc.pwd: %q (must be absolute)", tc.pwd)
			}

			t.Chdir(tc.dir)

			newDir, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if newDir != tc.pwd {
				t.Fatalf("failed to chdir to %q: getwd: got %q, want %q", tc.dir, newDir, tc.pwd)
			}

			switch runtime.GOOS {
			case "windows", "plan9":
				// Windows and Plan 9 do not use the PWD variable.
			default:
				if pwd := os.Getenv("PWD"); pwd != tc.pwd {
					t.Fatalf("PWD: got %q, want %q", pwd, tc.pwd)
				}
			}

			if tc.extraChdir {
				os.Chdir("..")
			}
		})

		newDir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		if newDir != oldDir {
			t.Fatalf("failed to restore wd to %s: getwd: %s", oldDir, newDir)
		}
	}
}

// testingTrueInInit is part of TestTesting.
var testingTrueInInit = false

// testingTrueInPackageVarInit is part of TestTesting.
var testingTrueInPackageVarInit = testing.Testing()

// init is part of TestTesting.
func init() {
	if testing.Testing() {
		testingTrueInInit = true
	}
}

var testingProg = `
package main

import (
	"fmt"
	"testing"
)

func main() {
	fmt.Println(testing.Testing())
}
`

func TestTesting(t *testing.T) {
	if !testing.Testing() {
		t.Errorf("testing.Testing() == %t, want %t", testing.Testing(), true)
	}
	if !testingTrueInInit {
		t.Errorf("testing.Testing() called by init function == %t, want %t", testingTrueInInit, true)
	}
	if !testingTrueInPackageVarInit {
		t.Errorf("testing.Testing() variable initialized as %t, want %t", testingTrueInPackageVarInit, true)
	}

	if testing.Short() {
		t.Skip("skipping building a binary in short mode")
	}
	testenv.MustHaveGoRun(t)

	fn := filepath.Join(t.TempDir(), "x.go")
	if err := os.WriteFile(fn, []byte(testingProg), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := testenv.Command(t, testenv.GoToolPath(t), "run", fn)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v failed: %v\n%s", cmd, err, out)
	}

	s := string(bytes.TrimSpace(out))
	if s != "false" {
		t.Errorf("in non-test testing.Test() returned %q, want %q", s, "false")
	}
}

// runTest runs a helper test with -test.v, ignoring its exit status.
// runTest both logs and returns the test output.
func runTest(t *testing.T, test string) []byte {
	t.Helper()

	testenv.MustHaveExec(t)

	cmd := testenv.Command(t, testenv.Executable(t), "-test.run=^"+test+"$", "-test.bench="+test, "-test.v", "-test.parallel=2", "-test.benchtime=2x")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "GO_WANT_HELPER_PROCESS=1")
	out, err := cmd.CombinedOutput()
	t.Logf("%v: %v\n%s", cmd, err, out)

	return out
}

// doRace provokes a data race that generates a race detector report if run
// under the race detector and is otherwise benign.
func doRace() {
	var x int
	c1 := make(chan bool)
	go func() {
		x = 1 // racy write
		c1 <- true
	}()
	_ = x // racy read
	<-c1
}

func TestRaceReports(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		// Generate a race detector report in a sub test.
		t.Run("Sub", func(t *testing.T) {
			doRace()
		})
		return
	}

	out := runTest(t, "TestRaceReports")

	// We should see at most one race detector report.
	c := bytes.Count(out, []byte("race detected"))
	want := 0
	if race.Enabled {
		want = 1
	}
	if c != want {
		t.Errorf("got %d race reports, want %d", c, want)
	}
}

// Issue #60083. This used to fail on the race builder.
func TestRaceName(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		doRace()
		return
	}

	out := runTest(t, "TestRaceName")

	if regexp.MustCompile(`=== NAME\s*$`).Match(out) {
		t.Errorf("incorrectly reported test with no name")
	}
}

func TestRaceSubReports(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		t.Parallel()
		c1 := make(chan bool, 1)
		t.Run("sub", func(t *testing.T) {
			t.Run("subsub1", func(t *testing.T) {
				t.Parallel()
				doRace()
				c1 <- true
			})
			t.Run("subsub2", func(t *testing.T) {
				t.Parallel()
				doRace()
				<-c1
			})
		})
		doRace()
		return
	}

	out := runTest(t, "TestRaceSubReports")

	// There should be three race reports: one for each subtest, and one for the
	// race after the subtests complete. Note that because the subtests run in
	// parallel, the race stacks may both be printed in with one or the other
	// test's logs.
	cReport := bytes.Count(out, []byte("race detected during execution of test"))
	wantReport := 0
	if race.Enabled {
		wantReport = 3
	}
	if cReport != wantReport {
		t.Errorf("got %d race reports, want %d", cReport, wantReport)
	}

	// Regardless of when the stacks are printed, we expect each subtest to be
	// marked as failed, and that failure should propagate up to the parents.
	cFail := bytes.Count(out, []byte("--- FAIL:"))
	wantFail := 0
	if race.Enabled {
		wantFail = 4
	}
	if cFail != wantFail {
		t.Errorf(`got %d "--- FAIL:" lines, want %d`, cReport, wantReport)
	}
}

func TestRaceInCleanup(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		t.Cleanup(doRace)
		t.Parallel()
		t.Run("sub", func(t *testing.T) {
			t.Parallel()
			// No race should be reported for sub.
		})
		return
	}

	out := runTest(t, "TestRaceInCleanup")

	// There should be one race report, for the parent test only.
	cReport := bytes.Count(out, []byte("race detected during execution of test"))
	wantReport := 0
	if race.Enabled {
		wantReport = 1
	}
	if cReport != wantReport {
		t.Errorf("got %d race reports, want %d", cReport, wantReport)
	}

	// Only the parent test should be marked as failed.
	// (The subtest does not race, and should pass.)
	cFail := bytes.Count(out, []byte("--- FAIL:"))
	wantFail := 0
	if race.Enabled {
		wantFail = 1
	}
	if cFail != wantFail {
		t.Errorf(`got %d "--- FAIL:" lines, want %d`, cReport, wantReport)
	}
}

func TestDeepSubtestRace(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		t.Run("sub", func(t *testing.T) {
			t.Run("subsub", func(t *testing.T) {
				t.Run("subsubsub", func(t *testing.T) {
					doRace()
				})
			})
			doRace()
		})
		return
	}

	out := runTest(t, "TestDeepSubtestRace")

	c := bytes.Count(out, []byte("race detected during execution of test"))
	want := 0
	// There should be two race reports.
	if race.Enabled {
		want = 2
	}
	if c != want {
		t.Errorf("got %d race reports, want %d", c, want)
	}
}

func TestRaceDuringParallelFailsAllSubtests(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		var ready sync.WaitGroup
		ready.Add(2)
		done := make(chan struct{})
		go func() {
			ready.Wait()
			doRace() // This race happens while both subtests are running.
			close(done)
		}()

		t.Run("sub", func(t *testing.T) {
			t.Run("subsub1", func(t *testing.T) {
				t.Parallel()
				ready.Done()
				<-done
			})
			t.Run("subsub2", func(t *testing.T) {
				t.Parallel()
				ready.Done()
				<-done
			})
		})

		return
	}

	out := runTest(t, "TestRaceDuringParallelFailsAllSubtests")

	c := bytes.Count(out, []byte("race detected during execution of test"))
	want := 0
	// Each subtest should report the race independently.
	if race.Enabled {
		want = 2
	}
	if c != want {
		t.Errorf("got %d race reports, want %d", c, want)
	}
}

func TestRaceBeforeParallel(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		t.Run("sub", func(t *testing.T) {
			doRace()
			t.Parallel()
		})
		return
	}

	out := runTest(t, "TestRaceBeforeParallel")

	c := bytes.Count(out, []byte("race detected during execution of test"))
	want := 0
	// We should see one race detector report.
	if race.Enabled {
		want = 1
	}
	if c != want {
		t.Errorf("got %d race reports, want %d", c, want)
	}
}

func TestRaceBeforeTests(t *testing.T) {
	cmd := testenv.Command(t, testenv.Executable(t), "-test.run=^$")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "GO_WANT_RACE_BEFORE_TESTS=1")
	out, _ := cmd.CombinedOutput()
	t.Logf("%s", out)

	c := bytes.Count(out, []byte("race detected outside of test execution"))

	want := 0
	if race.Enabled {
		want = 1
	}
	if c != want {
		t.Errorf("got %d race reports; want %d", c, want)
	}
}

func TestBenchmarkRace(t *testing.T) {
	out := runTest(t, "BenchmarkRacy")
	c := bytes.Count(out, []byte("race detected during execution of test"))

	want := 0
	// We should see one race detector report.
	if race.Enabled {
		want = 1
	}
	if c != want {
		t.Errorf("got %d race reports; want %d", c, want)
	}
}

func TestBenchmarkRaceBLoop(t *testing.T) {
	out := runTest(t, "BenchmarkBLoopRacy")
	c := bytes.Count(out, []byte("race detected during execution of test"))

	want := 0
	// We should see one race detector report.
	if race.Enabled {
		want = 1
	}
	if c != want {
		t.Errorf("got %d race reports; want %d", c, want)
	}
}

func BenchmarkRacy(b *testing.B) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		b.Skipf("skipping intentionally-racy benchmark")
	}
	for i := 0; i < b.N; i++ {
		doRace()
	}
}

func BenchmarkBLoopRacy(b *testing.B) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		b.Skipf("skipping intentionally-racy benchmark")
	}
	for b.Loop() {
		doRace()
	}
}

func TestBenchmarkSubRace(t *testing.T) {
	out := runTest(t, "BenchmarkSubRacy")
	c := bytes.Count(out, []byte("race detected during execution of test"))

	want := 0
	// We should see 3 race detector reports:
	// one in the sub-bencmark, one in the parent afterward,
	// and one in b.Loop.
	if race.Enabled {
		want = 3
	}
	if c != want {
		t.Errorf("got %d race reports; want %d", c, want)
	}
}

func BenchmarkSubRacy(b *testing.B) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		b.Skipf("skipping intentionally-racy benchmark")
	}

	b.Run("non-racy", func(b *testing.B) {
		tot := 0
		for i := 0; i < b.N; i++ {
			tot++
		}
		_ = tot
	})

	b.Run("racy", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			doRace()
		}
	})

	b.Run("racy-bLoop", func(b *testing.B) {
		for b.Loop() {
			doRace()
		}
	})

	doRace() // should be reported separately
}

func TestRunningTests(t *testing.T) {
	t.Parallel()

	// Regression test for https://go.dev/issue/64404:
	// on timeout, the "running tests" message should not include
	// tests that are waiting on parked subtests.

	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		for i := 0; i < 2; i++ {
			t.Run(fmt.Sprintf("outer%d", i), func(t *testing.T) {
				t.Parallel()
				for j := 0; j < 2; j++ {
					t.Run(fmt.Sprintf("inner%d", j), func(t *testing.T) {
						t.Parallel()
						for {
							time.Sleep(1 * time.Millisecond)
						}
					})
				}
			})
		}
	}

	timeout := 10 * time.Millisecond
	for {
		cmd := testenv.Command(t, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout="+timeout.String(), "-test.parallel=4")
		cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%v:\n%s", cmd, out)
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}

		// Because the outer subtests (and TestRunningTests itself) are marked as
		// parallel, their test functions return (and are no longer “running”)
		// before the inner subtests are released to run and hang.
		// Only those inner subtests should be reported as running.
		want := []string{
			"TestRunningTests/outer0/inner0",
			"TestRunningTests/outer0/inner1",
			"TestRunningTests/outer1/inner0",
			"TestRunningTests/outer1/inner1",
		}

		got, ok := parseRunningTests(out)
		if slices.Equal(got, want) {
			break
		}
		if ok {
			t.Logf("found running tests:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		} else {
			t.Logf("no running tests found")
		}
		t.Logf("retrying with longer timeout")
		timeout *= 2
	}
}

func TestRunningTestsInCleanup(t *testing.T) {
	t.Parallel()

	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		for i := 0; i < 2; i++ {
			t.Run(fmt.Sprintf("outer%d", i), func(t *testing.T) {
				// Not parallel: we expect to see only one outer test,
				// stuck in cleanup after its subtest finishes.

				t.Cleanup(func() {
					for {
						time.Sleep(1 * time.Millisecond)
					}
				})

				for j := 0; j < 2; j++ {
					t.Run(fmt.Sprintf("inner%d", j), func(t *testing.T) {
						t.Parallel()
					})
				}
			})
		}
	}

	timeout := 10 * time.Millisecond
	for {
		cmd := testenv.Command(t, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout="+timeout.String())
		cmd.Env = append(cmd.Environ(), "GO_WANT_HELPER_PROCESS=1")
		out, err := cmd.CombinedOutput()
		t.Logf("%v:\n%s", cmd, out)
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatal(err)
		}

		// TestRunningTestsInCleanup is blocked in the call to t.Run,
		// but its test function has not yet returned so it should still
		// be considered to be running.
		// outer1 hasn't even started yet, so only outer0 and the top-level
		// test function should be reported as running.
		want := []string{
			"TestRunningTestsInCleanup",
			"TestRunningTestsInCleanup/outer0",
		}

		got, ok := parseRunningTests(out)
		if slices.Equal(got, want) {
			break
		}
		if ok {
			t.Logf("found running tests:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		} else {
			t.Logf("no running tests found")
		}
		t.Logf("retrying with longer timeout")
		timeout *= 2
	}
}

func parseRunningTests(out []byte) (runningTests []string, ok bool) {
	inRunningTests := false
	for _, line := range strings.Split(string(out), "\n") {
		if inRunningTests {
			// Package testing adds one tab, the panic printer adds another.
			if trimmed, ok := strings.CutPrefix(line, "\t\t"); ok {
				if name, _, ok := strings.Cut(trimmed, " "); ok {
					runningTests = append(runningTests, name)
					continue
				}
			}

			// This line is not the name of a running test.
			return runningTests, true
		}

		if strings.TrimSpace(line) == "running tests:" {
			inRunningTests = true
		}
	}

	return nil, false
}

func TestConcurrentRun(t *testing.T) {
	// Regression test for https://go.dev/issue/64402:
	// this deadlocked after https://go.dev/cl/506755.

	block := make(chan struct{})
	var ready, done sync.WaitGroup
	for i := 0; i < 2; i++ {
		ready.Add(1)
		done.Add(1)
		go t.Run("", func(*testing.T) {
			ready.Done()
			<-block
			done.Done()
		})
	}
	ready.Wait()
	close(block)
	done.Wait()
}

func TestParentRun(t1 *testing.T) {
	// Regression test for https://go.dev/issue/64402:
	// this deadlocked after https://go.dev/cl/506755.

	t1.Run("outer", func(t2 *testing.T) {
		t2.Log("Hello outer!")
		t1.Run("not_inner", func(t3 *testing.T) { // Note: this is t1.Run, not t2.Run.
			t3.Log("Hello inner!")
		})
	})
}

func TestContext(t *testing.T) {
	ctx := t.Context()
	if err := ctx.Err(); err != nil {
		t.Fatalf("expected non-canceled context, got %v", err)
	}

	var innerCtx context.Context
	t.Run("inner", func(t *testing.T) {
		innerCtx = t.Context()
		if err := innerCtx.Err(); err != nil {
			t.Fatalf("expected inner test to not inherit canceled context, got %v", err)
		}
	})
	t.Run("inner2", func(t *testing.T) {
		if !errors.Is(innerCtx.Err(), context.Canceled) {
			t.Fatal("expected context of sibling test to be canceled after its test function finished")
		}
	})

	t.Cleanup(func() {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal("expected context canceled before cleanup")
		}
	})
}

func TestBenchmarkBLoopIterationCorrect(t *testing.T) {
	out := runTest(t, "BenchmarkBLoopPrint")
	c := bytes.Count(out, []byte("Printing from BenchmarkBLoopPrint"))

	want := 2
	if c != want {
		t.Errorf("got %d loop iterations; want %d", c, want)
	}

	// b.Loop() will only rampup once.
	c = bytes.Count(out, []byte("Ramping up from BenchmarkBLoopPrint"))
	want = 1
	if c != want {
		t.Errorf("got %d loop rampup; want %d", c, want)
	}

	re := regexp.MustCompile(`BenchmarkBLoopPrint(-[0-9]+)?\s+2\s+[0-9]+\s+ns/op`)
	if !re.Match(out) {
		t.Error("missing benchmark output")
	}
}

func TestBenchmarkBNIterationCorrect(t *testing.T) {
	out := runTest(t, "BenchmarkBNPrint")
	c := bytes.Count(out, []byte("Printing from BenchmarkBNPrint"))

	// runTest sets benchtime=2x, with semantics specified in #32051 it should
	// run 3 times.
	want := 3
	if c != want {
		t.Errorf("got %d loop iterations; want %d", c, want)
	}

	// b.N style fixed iteration loop will rampup twice:
	// One in run1(), the other in launch
	c = bytes.Count(out, []byte("Ramping up from BenchmarkBNPrint"))
	want = 2
	if c != want {
		t.Errorf("got %d loop rampup; want %d", c, want)
	}
}

func BenchmarkBLoopPrint(b *testing.B) {
	b.Logf("Ramping up from BenchmarkBLoopPrint")
	for b.Loop() {
		b.Logf("Printing from BenchmarkBLoopPrint")
	}
}

func BenchmarkBNPrint(b *testing.B) {
	b.Logf("Ramping up from BenchmarkBNPrint")
	for i := 0; i < b.N; i++ {
		b.Logf("Printing from BenchmarkBNPrint")
	}
}

"""



```