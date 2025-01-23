Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Skim and Overall Purpose:**

The first step is to quickly read through the code to get a general idea of what it's doing. Keywords like "coverage", "emit", "test", and function names like `TestCoverageApis`, `testEmitToDir`, etc., strongly suggest this code is testing functionality related to Go's code coverage mechanism, specifically the part that *emits* the collected coverage data. The `internal/coverage/cfile` package name reinforces this.

**2. Identify Key Functions and Structures:**

Next, I look for the main entry point (`TestCoverageApis`) and the helper functions it calls. The `t.Run` calls within `TestCoverageApis` are crucial as they define individual test cases. I also note the presence of `buildHarness`, `runHarness`, `mkdir`, and `testForSpecificFunctions`. These are likely utility functions for setting up and executing test scenarios.

**3. Understand the Test Setup:**

The code builds a "harness" executable (`harness.exe`). This immediately tells me that the testing strategy involves running a separate Go program under different conditions to observe its coverage data output. The harness is built twice, once with `-covermode=atomic` and once without (or with `set`). This hints at testing different modes of coverage collection. The `t.TempDir()` suggests that the tests are designed to be isolated and not interfere with each other's file system operations.

**4. Analyze Individual Test Cases:**

Now I go through each `t.Run` block in `TestCoverageApis`:

* **`emitToDir` and `emitToWriter`:** These seem to be the core functionalities being tested: emitting coverage data to a directory and to a writer (likely an `io.Writer`).
* **`emitToNonexistentDir`, `emitToNilWriter`, `emitToFailingWriter`:** These are clearly testing error handling scenarios for the emission process.
* **`emitWithCounterClear`:** This suggests testing the functionality to clear the coverage counters after emitting data.
* **`emitToDirNonAtomic`, `emitToWriterNonAtomic`, `emitWithCounterClearNonAtomic`:** The "NonAtomic" suffix indicates testing the behavior when the harness is built without atomic coverage. The code comments and the error checking within these tests suggest that these operations might be expected to fail in non-atomic mode.

**5. Decipher Helper Functions:**

* **`buildHarness`:**  Compiles a Go program (the "harness") with specified `-covermode` and `-coverpkg` flags.
* **`runHarness`:** Executes the compiled harness program with specific command-line arguments (`-tp`, `-o`) and environment variables (`GOCOVERDIR`).
* **`mkdir`:** A simple utility for creating directories.
* **`updateGoCoverDir`:**  Modifies the environment to set or unset the `GOCOVERDIR` environment variable, which is important for controlling where coverage data is written.
* **`testForSpecificFunctions`:** Examines the output of `go tool covdata debugdump` to verify the presence or absence of coverage data for specific functions.
* **`upmergeCoverData`:** Merges coverage data from the harness execution back into the main test's coverage data, potentially to improve the coverage of the `internal/coverage/cfile` package itself.
* **`withAndWithoutRunner`:**  A helper to run a given test function twice, once with `GOCOVERDIR` set and once without.

**6. Infer Go Coverage Functionality:**

Based on the test cases and helper functions, I can infer the following about the Go coverage functionality being tested:

* **Emission to Directory:**  The ability to write coverage data to files within a specified directory.
* **Emission to Writer:** The ability to write coverage data to an `io.Writer`.
* **Atomic vs. Non-Atomic Coverage:**  Go supports different modes of coverage collection, and the tests verify behavior in both. Atomic coverage likely provides more accurate results in concurrent scenarios but might have performance overhead.
* **Counter Clearing:** The ability to reset coverage counters.
* **`GOCOVERDIR` Environment Variable:** This variable controls where coverage data files are written.
* **`go tool covdata`:**  A command-line tool for inspecting and manipulating coverage data.

**7. Construct Go Code Examples (Mental Execution and Synthesis):**

Now, I can construct concrete Go code examples. I think about how the harness program (`testdata/harness.go`, though not shown in the provided snippet) would use the `internal/coverage/cfile` package. The test names (like `emitToDir`, `emitToWriter`) directly correspond to hypothetical functions within that package.

For example, for `emitToDir`, I imagine a function like `cfile.WriteCountersDir(dir string) error`. For `emitToWriter`, I imagine `cfile.WriteCounters(w io.Writer) error`. The "counter clear" functionality suggests a function like `cfile.ClearCounters()`.

**8. Reason About Command-Line Arguments and Error Handling:**

The tests explicitly set `-covermode` and use `GOCOVERDIR`. I note these as important command-line arguments and environment variables. The error handling test cases highlight the expected failure scenarios.

**9. Identify Potential User Errors:**

Based on the tests, potential errors include:

* Trying to use the emission APIs when the program isn't built with `-cover`.
* Not understanding the difference between atomic and non-atomic coverage.
* Incorrectly setting or not setting the `GOCOVERDIR` environment variable.

**10. Structure the Answer:**

Finally, I organize my findings into a clear and structured answer, addressing each part of the prompt: functionality, Go code examples (with assumptions), command-line arguments, and potential user errors. I use clear headings and bullet points for readability.

This iterative process of skimming, identifying key elements, analyzing test cases, inferring functionality, and synthesizing examples allows for a comprehensive understanding of the code's purpose and the Go coverage features it tests.
这段代码是 Go 语言标准库 `internal/coverage/cfile` 包的一部分，它专注于测试代码覆盖率数据的**生成 (emit)** 功能。更具体地说，它测试了将覆盖率数据写入文件系统和写入 `io.Writer` 的各种场景。

**功能列举:**

1. **测试覆盖率数据写入目录:** 测试 `cfile` 包将覆盖率元数据和计数器数据写入指定目录的功能。它会检查是否生成了预期的文件。
2. **测试覆盖率数据写入 `io.Writer`:** 测试 `cfile` 包将覆盖率数据写入 `io.Writer` 接口的功能。它会通过检查输出中特定函数的覆盖率信息来验证数据是否正确写入。
3. **测试向不存在的目录写入覆盖率数据:** 验证当目标目录不存在时，`cfile` 包的处理行为，通常期望会成功，因为底层实现可能会创建目录。
4. **测试向 `nil` `io.Writer` 写入覆盖率数据:** 验证当提供 `nil` 的 `io.Writer` 时，`cfile` 包的处理行为，通常期望会成功，但不产生任何输出。
5. **测试向失败的 `io.Writer` 写入覆盖率数据:** 模拟一个写入时会发生错误的 `io.Writer`，并测试 `cfile` 包的错误处理机制。
6. **测试写入覆盖率数据并清除计数器:** 测试 `cfile` 包在写入覆盖率数据后清除内部计数器的功能，以确保后续的覆盖率收集从零开始。
7. **测试非原子模式下的覆盖率数据写入:**  Go 覆盖率支持原子 (atomic) 和非原子 (set) 两种模式。这些测试用例专门测试在以非原子模式构建的程序中调用 `cfile` 包的写入功能时是否会产生预期的错误。这表明在非原子模式下，某些写入操作可能是不允许的或者行为有所不同。
8. **测试在未使用 `-cover` 编译的二进制文件上调用覆盖率 API:**  验证当程序没有使用 `-cover` 标志编译时，调用 `cfile` 包的 API 是否会产生预期的错误。
9. **测试并发场景下的覆盖率数据生成 (解决 Issue 56006):**  模拟一个在覆盖率数据写入时仍有 Goroutine 在运行并更新计数器的场景，以确保不会发生数据竞争。这个测试需要使用 `-race` 标志来检测数据竞争。
10. **测试 `coverpkg=all` 导致的覆盖率数据截断问题 (解决 Issue 59563):**  验证在使用 `-coverpkg=all` 编译时，对于大型函数，覆盖率数据是否会被正确记录，而不会发生截断。

**Go 语言功能实现推断及代码示例:**

这段代码主要测试的是 Go 语言中用于生成代码覆盖率数据的内部 API。基于测试用例的名称和行为，我们可以推断 `internal/coverage/cfile` 包可能提供了以下功能：

```go
package cfile

import "io"

// WriteCountersDir 将覆盖率数据写入到指定目录下的文件中。
// metaFilePathPrefix 和 counterFilePathPrefix 可以用来指定元数据和计数器文件名的前缀。
func WriteCountersDir(dir string) error

// WriteCountersToWriter 将覆盖率数据写入到提供的 io.Writer。
func WriteCountersToWriter(w io.Writer) error

// ClearCounters 清除内部的覆盖率计数器。
func ClearCounters()
```

**假设的输入与输出示例 (针对 `testEmitToWriter`):**

**假设输入:**

* `harnessPath`: 指向编译后的测试辅助程序 (harness.exe) 的路径，该程序使用 `-covermode=atomic` 编译，并且包含了需要收集覆盖率的代码。
* `dir`: 一个临时目录，用于存放测试过程中生成的文件。

**`testdata/harness.go` (简化的假设内容):**

```go
package main

import (
	"fmt"
	"os"
	"internal/coverage/cfile"
)

func main() {
	tp := os.Getenv("TEST_TYPE")
	outputDir := os.Getenv("OUTPUT_DIR")

	switch tp {
	case "emitToWriter":
		err := cfile.WriteCountersToWriter(os.Stdout) // 假设写入到标准输出
		if err != nil {
			fmt.Fprintf(os.Stderr, "WriteCountersToWriter error: %v\n", err)
			os.Exit(1)
		}
	// ... 其他测试类型的处理
	}
}
```

**测试代码 (`emitdata_test.go` 中 `testEmitToWriter` 的一部分):**

```go
func testEmitToWriter(t *testing.T, harnessPath string, dir string) {
	// ...
	t.Run("emitToWriter", func(t *testing.T) {
		// ...
		rdir, edir := mktestdirs(t, tag, tp, dir)
		// 假设通过环境变量传递测试类型和输出目录
		cmd := exec.Command(harnessPath)
		cmd.Env = append(os.Environ(), "TEST_TYPE=emitToWriter", "OUTPUT_DIR="+edir)
		outputBytes, err := cmd.CombinedOutput()
		output := string(outputBytes)
		// ... 对 output 进行断言，检查是否包含了预期的覆盖率信息
		want := []string{"main", tp}
		avoid := []string{"final"}
		if msg := testForSpecificFunctions(t, edir, want, avoid); msg != "" {
			t.Errorf("coverage data from %q output match failed: %s", tp, msg)
		}
		// ...
	})
	// ...
}
```

**预期输出 (标准输出):**

假设 `harness.exe` 中包含了 `main` 函数和 `emitToWriter` 相关的代码，并且收集到了覆盖率数据，那么预期在标准输出中会包含类似以下格式的覆盖率信息（具体的格式可能会有所不同，但会包含函数名和覆盖率计数）：

```
Func:    main
File:    /path/to/harness.go
Count:   1

Func:    emitToWriter
File:    /path/to/harness.go
Count:   5
```

`testForSpecificFunctions` 函数会解析这个输出，并检查是否包含 `Func: main` 和 `Func: emitToWriter` 等信息。

**命令行参数处理:**

在代码中，并没有直接处理命令行参数，而是通过构建和运行单独的 "harness" 程序来进行测试。`buildHarness` 函数使用 `go build` 命令来编译 harness 程序，可以传递一些编译选项，例如 `-covermode` 和 `-coverpkg`：

* **`-covermode=atomic`**:  指定使用原子模式收集覆盖率数据，这种模式对于并发程序更加精确。
* **`-coverpkg=all`**:  指定对所有包进行覆盖率分析。

`runHarness` 函数在运行 harness 程序时，会设置一些环境变量，例如 `-tp` 用于指定 harness 程序执行的测试类型，`-o` 用于指定输出目录。这些实际上是传递给 harness 程序的参数，而不是 `emitdata_test.go` 本身。

**易犯错的点:**

1. **在非覆盖率模式下调用覆盖率 API:**  如果使用者在没有使用 `-cover` 标志编译的程序中调用 `internal/coverage/cfile` 的 API，会导致错误。测试用例 `TestApisOnNocoverBinary` 就是为了验证这种情况。
   * **示例:**  如果你的程序在编译时没有添加 `-cover` 标志，然后你尝试调用 `cfile.WriteCountersDir("/tmp/coverage")`，程序可能会 panic 或者返回错误。

2. **在非原子模式下尝试某些操作:**  在以非原子模式 (例如 `-covermode=set`) 编译的程序中，直接调用某些可能需要原子操作的覆盖率 API 可能会导致错误。测试用例 `testEmitToDirNonAtomic` 等就是为了验证这种情况。
   * **示例:**  如果你的程序使用 `go build -covermode=set ...` 编译，然后尝试调用 `cfile.WriteCountersDir()`，可能会得到类似 "WriteCountersDir invoked for program built without atomic coverage support" 的错误信息。

3. **不理解 `GOCOVERDIR` 环境变量的作用:**  `GOCOVERDIR` 环境变量用于指定覆盖率数据输出的根目录。如果未设置或者设置不当，可能会导致覆盖率数据无法找到或者写入到错误的位置。
   * **示例:**  如果你期望覆盖率数据输出到 `/my/coverage/data` 目录，你需要确保在运行测试或者程序时设置了 `GOCOVERDIR=/my/coverage/data`。

4. **数据竞争:**  在并发程序中，如果不正确地处理覆盖率数据的写入，可能会发生数据竞争。测试用例 `TestIssue56006EmitDataRaceCoverRunningGoroutine` 就是为了防止这种情况。

这段测试代码覆盖了 `internal/coverage/cfile` 包的多种使用场景和潜在的错误情况，帮助开发者确保覆盖率功能的正确性和健壮性。

### 提示词
```
这是路径为go/src/internal/coverage/cfile/emitdata_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cfile

import (
	"fmt"
	"internal/coverage"
	"internal/goexperiment"
	"internal/platform"
	"internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Set to true for debugging (linux only).
const fixedTestDir = false

func TestCoverageApis(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping test: too long for short mode")
	}
	if !goexperiment.CoverageRedesign {
		t.Skipf("skipping new coverage tests (experiment not enabled)")
	}
	testenv.MustHaveGoBuild(t)
	dir := t.TempDir()
	if fixedTestDir {
		dir = "/tmp/qqqzzz"
		os.RemoveAll(dir)
		mkdir(t, dir)
	}

	// Build harness. We need two copies of the harness, one built
	// with -covermode=atomic and one built non-atomic.
	bdir1 := mkdir(t, filepath.Join(dir, "build1"))
	hargs1 := []string{"-covermode=atomic", "-coverpkg=all"}
	atomicHarnessPath := buildHarness(t, bdir1, hargs1)
	nonAtomicMode := testing.CoverMode()
	if testing.CoverMode() == "atomic" {
		nonAtomicMode = "set"
	}
	bdir2 := mkdir(t, filepath.Join(dir, "build2"))
	hargs2 := []string{"-coverpkg=all", "-covermode=" + nonAtomicMode}
	nonAtomicHarnessPath := buildHarness(t, bdir2, hargs2)

	t.Logf("atomic harness path is %s", atomicHarnessPath)
	t.Logf("non-atomic harness path is %s", nonAtomicHarnessPath)

	// Sub-tests for each API we want to inspect, plus
	// extras for error testing.
	t.Run("emitToDir", func(t *testing.T) {
		t.Parallel()
		testEmitToDir(t, atomicHarnessPath, dir)
	})
	t.Run("emitToWriter", func(t *testing.T) {
		t.Parallel()
		testEmitToWriter(t, atomicHarnessPath, dir)
	})
	t.Run("emitToNonexistentDir", func(t *testing.T) {
		t.Parallel()
		testEmitToNonexistentDir(t, atomicHarnessPath, dir)
	})
	t.Run("emitToNilWriter", func(t *testing.T) {
		t.Parallel()
		testEmitToNilWriter(t, atomicHarnessPath, dir)
	})
	t.Run("emitToFailingWriter", func(t *testing.T) {
		t.Parallel()
		testEmitToFailingWriter(t, atomicHarnessPath, dir)
	})
	t.Run("emitWithCounterClear", func(t *testing.T) {
		t.Parallel()
		testEmitWithCounterClear(t, atomicHarnessPath, dir)
	})
	t.Run("emitToDirNonAtomic", func(t *testing.T) {
		t.Parallel()
		testEmitToDirNonAtomic(t, nonAtomicHarnessPath, nonAtomicMode, dir)
	})
	t.Run("emitToWriterNonAtomic", func(t *testing.T) {
		t.Parallel()
		testEmitToWriterNonAtomic(t, nonAtomicHarnessPath, nonAtomicMode, dir)
	})
	t.Run("emitWithCounterClearNonAtomic", func(t *testing.T) {
		t.Parallel()
		testEmitWithCounterClearNonAtomic(t, nonAtomicHarnessPath, nonAtomicMode, dir)
	})
}

// upmergeCoverData helps improve coverage data for this package
// itself. If this test itself is being invoked with "-cover", then
// what we'd like is for package coverage data (that is, coverage for
// routines in "runtime/coverage") to be incorporated into the test
// run from the "harness.exe" runs we've just done. We can accomplish
// this by doing a merge from the harness gocoverdir's to the test
// gocoverdir.
func upmergeCoverData(t *testing.T, gocoverdir string, mode string) {
	if testing.CoverMode() != mode {
		return
	}
	testGoCoverDir := os.Getenv("GOCOVERDIR")
	if testGoCoverDir == "" {
		return
	}
	args := []string{"tool", "covdata", "merge", "-pkg=runtime/coverage",
		"-o", testGoCoverDir, "-i", gocoverdir}
	t.Logf("up-merge of covdata from %s to %s", gocoverdir, testGoCoverDir)
	t.Logf("executing: go %+v", args)
	cmd := exec.Command(testenv.GoToolPath(t), args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("covdata merge failed (%v): %s", err, b)
	}
}

// buildHarness builds the helper program "harness.exe".
func buildHarness(t *testing.T, dir string, opts []string) string {
	harnessPath := filepath.Join(dir, "harness.exe")
	harnessSrc := filepath.Join("testdata", "harness.go")
	args := []string{"build", "-o", harnessPath}
	args = append(args, opts...)
	args = append(args, harnessSrc)
	//t.Logf("harness build: go %+v\n", args)
	cmd := exec.Command(testenv.GoToolPath(t), args...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed (%v): %s", err, b)
	}
	return harnessPath
}

func mkdir(t *testing.T, d string) string {
	t.Helper()
	if err := os.Mkdir(d, 0777); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	return d
}

// updateGoCoverDir updates the specified environment 'env' to set
// GOCOVERDIR to 'gcd' (if setGoCoverDir is TRUE) or removes
// GOCOVERDIR from the environment (if setGoCoverDir is false).
func updateGoCoverDir(env []string, gcd string, setGoCoverDir bool) []string {
	rv := []string{}
	found := false
	for _, v := range env {
		if strings.HasPrefix(v, "GOCOVERDIR=") {
			if !setGoCoverDir {
				continue
			}
			v = "GOCOVERDIR=" + gcd
			found = true
		}
		rv = append(rv, v)
	}
	if !found && setGoCoverDir {
		rv = append(rv, "GOCOVERDIR="+gcd)
	}
	return rv
}

func runHarness(t *testing.T, harnessPath string, tp string, setGoCoverDir bool, rdir, edir string) (string, error) {
	t.Logf("running: %s -tp %s -o %s with rdir=%s and GOCOVERDIR=%v", harnessPath, tp, edir, rdir, setGoCoverDir)
	cmd := exec.Command(harnessPath, "-tp", tp, "-o", edir)
	cmd.Dir = rdir
	cmd.Env = updateGoCoverDir(os.Environ(), rdir, setGoCoverDir)
	b, err := cmd.CombinedOutput()
	//t.Logf("harness run output: %s\n", string(b))
	return string(b), err
}

func testForSpecificFunctions(t *testing.T, dir string, want []string, avoid []string) string {
	args := []string{"tool", "covdata", "debugdump",
		"-live", "-pkg=command-line-arguments", "-i=" + dir}
	t.Logf("running: go %v\n", args)
	cmd := exec.Command(testenv.GoToolPath(t), args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("'go tool covdata failed (%v): %s", err, b)
	}
	output := string(b)
	rval := ""
	for _, f := range want {
		wf := "Func: " + f + "\n"
		if strings.Contains(output, wf) {
			continue
		}
		rval += fmt.Sprintf("error: output should contain %q but does not\n", wf)
	}
	for _, f := range avoid {
		wf := "Func: " + f + "\n"
		if strings.Contains(output, wf) {
			rval += fmt.Sprintf("error: output should not contain %q but does\n", wf)
		}
	}
	if rval != "" {
		t.Logf("=-= begin output:\n%s\n=-= end output\n", output)
	}
	return rval
}

func withAndWithoutRunner(f func(setit bool, tag string)) {
	// Run 'f' with and without GOCOVERDIR set.
	for i := 0; i < 2; i++ {
		tag := "x"
		setGoCoverDir := true
		if i == 0 {
			setGoCoverDir = false
			tag = "y"
		}
		f(setGoCoverDir, tag)
	}
}

func mktestdirs(t *testing.T, tag, tp, dir string) (string, string) {
	t.Helper()
	rdir := mkdir(t, filepath.Join(dir, tp+"-rdir-"+tag))
	edir := mkdir(t, filepath.Join(dir, tp+"-edir-"+tag))
	return rdir, edir
}

func testEmitToDir(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {
		tp := "emitToDir"
		rdir, edir := mktestdirs(t, tag, tp, dir)
		output, err := runHarness(t, harnessPath, tp,
			setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp emitDir': %v", err)
		}

		// Just check to make sure meta-data file and counter data file were
		// written. Another alternative would be to run "go tool covdata"
		// or equivalent, but for now, this is what we've got.
		dents, err := os.ReadDir(edir)
		if err != nil {
			t.Fatalf("os.ReadDir(%s) failed: %v", edir, err)
		}
		mfc := 0
		cdc := 0
		for _, e := range dents {
			if e.IsDir() {
				continue
			}
			if strings.HasPrefix(e.Name(), coverage.MetaFilePref) {
				mfc++
			} else if strings.HasPrefix(e.Name(), coverage.CounterFilePref) {
				cdc++
			}
		}
		wantmf := 1
		wantcf := 1
		if mfc != wantmf {
			t.Errorf("EmitToDir: want %d meta-data files, got %d\n", wantmf, mfc)
		}
		if cdc != wantcf {
			t.Errorf("EmitToDir: want %d counter-data files, got %d\n", wantcf, cdc)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitToWriter(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {
		tp := "emitToWriter"
		rdir, edir := mktestdirs(t, tag, tp, dir)
		output, err := runHarness(t, harnessPath, tp, setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp %s': %v", tp, err)
		}
		want := []string{"main", tp}
		avoid := []string{"final"}
		if msg := testForSpecificFunctions(t, edir, want, avoid); msg != "" {
			t.Errorf("coverage data from %q output match failed: %s", tp, msg)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitToNonexistentDir(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {
		tp := "emitToNonexistentDir"
		rdir, edir := mktestdirs(t, tag, tp, dir)
		output, err := runHarness(t, harnessPath, tp, setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp %s': %v", tp, err)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitToUnwritableDir(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {

		tp := "emitToUnwritableDir"
		rdir, edir := mktestdirs(t, tag, tp, dir)

		// Make edir unwritable.
		if err := os.Chmod(edir, 0555); err != nil {
			t.Fatalf("chmod failed: %v", err)
		}
		defer os.Chmod(edir, 0777)

		output, err := runHarness(t, harnessPath, tp, setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp %s': %v", tp, err)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitToNilWriter(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {
		tp := "emitToNilWriter"
		rdir, edir := mktestdirs(t, tag, tp, dir)
		output, err := runHarness(t, harnessPath, tp, setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp %s': %v", tp, err)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitToFailingWriter(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {
		tp := "emitToFailingWriter"
		rdir, edir := mktestdirs(t, tag, tp, dir)
		output, err := runHarness(t, harnessPath, tp, setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp %s': %v", tp, err)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitWithCounterClear(t *testing.T, harnessPath string, dir string) {
	withAndWithoutRunner(func(setGoCoverDir bool, tag string) {
		tp := "emitWithCounterClear"
		rdir, edir := mktestdirs(t, tag, tp, dir)
		output, err := runHarness(t, harnessPath, tp,
			setGoCoverDir, rdir, edir)
		if err != nil {
			t.Logf("%s", output)
			t.Fatalf("running 'harness -tp %s': %v", tp, err)
		}
		want := []string{tp, "postClear"}
		avoid := []string{"preClear", "main", "final"}
		if msg := testForSpecificFunctions(t, edir, want, avoid); msg != "" {
			t.Logf("%s", output)
			t.Errorf("coverage data from %q output match failed: %s", tp, msg)
		}
		upmergeCoverData(t, edir, "atomic")
		upmergeCoverData(t, rdir, "atomic")
	})
}

func testEmitToDirNonAtomic(t *testing.T, harnessPath string, naMode string, dir string) {
	tp := "emitToDir"
	tag := "nonatomdir"
	rdir, edir := mktestdirs(t, tag, tp, dir)
	output, err := runHarness(t, harnessPath, tp,
		true, rdir, edir)

	// We expect an error here.
	if err == nil {
		t.Logf("%s", output)
		t.Fatalf("running 'harness -tp %s': did not get expected error", tp)
	}

	got := strings.TrimSpace(string(output))
	want := "WriteCountersDir invoked for program built"
	if !strings.Contains(got, want) {
		t.Errorf("running 'harness -tp %s': got:\n%s\nwant: %s",
			tp, got, want)
	}
	upmergeCoverData(t, edir, naMode)
	upmergeCoverData(t, rdir, naMode)
}

func testEmitToWriterNonAtomic(t *testing.T, harnessPath string, naMode string, dir string) {
	tp := "emitToWriter"
	tag := "nonatomw"
	rdir, edir := mktestdirs(t, tag, tp, dir)
	output, err := runHarness(t, harnessPath, tp,
		true, rdir, edir)

	// We expect an error here.
	if err == nil {
		t.Logf("%s", output)
		t.Fatalf("running 'harness -tp %s': did not get expected error", tp)
	}

	got := strings.TrimSpace(string(output))
	want := "WriteCounters invoked for program built"
	if !strings.Contains(got, want) {
		t.Errorf("running 'harness -tp %s': got:\n%s\nwant: %s",
			tp, got, want)
	}

	upmergeCoverData(t, edir, naMode)
	upmergeCoverData(t, rdir, naMode)
}

func testEmitWithCounterClearNonAtomic(t *testing.T, harnessPath string, naMode string, dir string) {
	tp := "emitWithCounterClear"
	tag := "cclear"
	rdir, edir := mktestdirs(t, tag, tp, dir)
	output, err := runHarness(t, harnessPath, tp,
		true, rdir, edir)

	// We expect an error here.
	if err == nil {
		t.Logf("%s", output)
		t.Fatalf("running 'harness -tp %s' nonatomic: did not get expected error", tp)
	}

	got := strings.TrimSpace(string(output))
	want := "ClearCounters invoked for program built"
	if !strings.Contains(got, want) {
		t.Errorf("running 'harness -tp %s': got:\n%s\nwant: %s",
			tp, got, want)
	}

	upmergeCoverData(t, edir, naMode)
	upmergeCoverData(t, rdir, naMode)
}

func TestApisOnNocoverBinary(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping test: too long for short mode")
	}
	testenv.MustHaveGoBuild(t)
	dir := t.TempDir()

	// Build harness with no -cover.
	bdir := mkdir(t, filepath.Join(dir, "nocover"))
	edir := mkdir(t, filepath.Join(dir, "emitDirNo"))
	harnessPath := buildHarness(t, bdir, nil)
	output, err := runHarness(t, harnessPath, "emitToDir", false, edir, edir)
	if err == nil {
		t.Fatalf("expected error on TestApisOnNocoverBinary harness run")
	}
	const want = "not built with -cover"
	if !strings.Contains(output, want) {
		t.Errorf("error output does not contain %q: %s", want, output)
	}
}

func TestIssue56006EmitDataRaceCoverRunningGoroutine(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping test: too long for short mode")
	}
	if !goexperiment.CoverageRedesign {
		t.Skipf("skipping new coverage tests (experiment not enabled)")
	}

	// This test requires "go test -race -cover", meaning that we need
	// go build, go run, and "-race" support.
	testenv.MustHaveGoRun(t)
	if !platform.RaceDetectorSupported(runtime.GOOS, runtime.GOARCH) ||
		!testenv.HasCGO() {
		t.Skip("skipped due to lack of race detector support / CGO")
	}

	// This will run a program with -cover and -race where we have a
	// goroutine still running (and updating counters) at the point where
	// the test runtime is trying to write out counter data.
	cmd := exec.Command(testenv.GoToolPath(t), "test", "-cover", "-race")
	cmd.Dir = filepath.Join("testdata", "issue56006")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -cover -race failed: %v\n%s", err, b)
	}

	// Don't want to see any data races in output.
	avoid := []string{"DATA RACE"}
	for _, no := range avoid {
		if strings.Contains(string(b), no) {
			t.Logf("%s\n", string(b))
			t.Fatalf("found %s in test output, not permitted", no)
		}
	}
}

func TestIssue59563TruncatedCoverPkgAll(t *testing.T) {
	if testing.Short() {
		t.Skipf("skipping test: too long for short mode")
	}
	testenv.MustHaveGoRun(t)

	tmpdir := t.TempDir()
	ppath := filepath.Join(tmpdir, "foo.cov")

	cmd := exec.Command(testenv.GoToolPath(t), "test", "-coverpkg=all", "-coverprofile="+ppath)
	cmd.Dir = filepath.Join("testdata", "issue59563")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -cover failed: %v\n%s", err, b)
	}

	cmd = exec.Command(testenv.GoToolPath(t), "tool", "cover", "-func="+ppath)
	b, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go tool cover -func failed: %v", err)
	}

	lines := strings.Split(string(b), "\n")
	nfound := 0
	bad := false
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		// We're only interested in the specific function "large" for
		// the testcase being built. See the #59563 for details on why
		// size matters.
		if !(strings.HasPrefix(f[0], "internal/coverage/cfile/testdata/issue59563/repro.go") && strings.Contains(line, "large")) {
			continue
		}
		nfound++
		want := "100.0%"
		if f[len(f)-1] != want {
			t.Errorf("wanted %s got: %q\n", want, line)
			bad = true
		}
	}
	if nfound != 1 {
		t.Errorf("wanted 1 found, got %d\n", nfound)
		bad = true
	}
	if bad {
		t.Logf("func output:\n%s\n", string(b))
	}
}
```