Response:
My thinking process to analyze the provided Go code snippet goes like this:

1. **Understand the Context:** The comment at the beginning clearly states this is part of `go/src/cmd/covdata/tool_test.go`. This immediately tells me this is a testing file for the `covdata` command-line tool within the Go standard library. The `_test` suffix confirms this.

2. **Identify Key Functions and Structures:** I start by looking for top-level functions and types. `TestMain`, various `TestXxx` functions, and the `state` struct stand out. The `TestMain` function is special in Go testing and often handles setup and teardown.

3. **Analyze `TestMain`:**  This function does several important things:
    * **Checks for `CMDCOVDATA_TEST_RUN_MAIN`:** This environment variable acts as a flag. If set, it runs the actual `cmdcovdata.Main()`. This indicates the test is reusing the test binary itself as the `covdata` tool under test. This is a common pattern in Go's standard library testing.
    * **Parses Flags:** `flag.Parse()` suggests command-line flags are used in the testing framework.
    * **Creates a Temporary Directory:**  `os.MkdirTemp` is used for creating a temporary directory for the tests to work in. The `preserveTmp` flag controls whether this directory is deleted after the test.
    * **Sets the `CMDCOVDATA_TEST_RUN_MAIN` Environment Variable:** This is crucial for the reuse of the test binary.
    * **Runs the Tests:** `m.Run()` executes the individual test functions (like `TestCovTool`).

4. **Analyze `TestCovTool`:** This is the main test function.
    * **Checks for Prerequisites:** `testenv.MustHaveGoBuild` and `goexperiment.CoverageRedesign` suggest dependencies on having a Go build environment and a specific Go experiment being enabled.
    * **Creates a `state` struct:** This structure holds various paths and configurations needed for the tests, like temporary directories and executable paths.
    * **Builds Test Programs:** The `buildProg` function is called multiple times to compile instrumented Go programs (`prog1.go`, `prog2.go`) with different coverage modes. The `-cover` flag and `-covermode` are key here.
    * **Sets up Coverage Output Directories:** Multiple directories are created to simulate different coverage data outputs.
    * **Runs Instrumented Programs:** The compiled programs are executed with the `GOCOVERDIR` environment variable set, causing them to write coverage data to the created directories.
    * **Runs Subtests:**  The `t.Run` function defines a series of subtests (e.g., "MergeSimple", "Dump", "Percent"). This helps organize the tests logically.

5. **Analyze Helper Functions:** Functions like `tempDir`, `gobuild`, `emitFile`, `runToolOp`, `runDumpChecks`, and the various `testXxx` functions are essential for the testing logic.
    * **`tempDir`:**  Creates unique temporary subdirectories.
    * **`gobuild`:**  Compiles Go code using `go build`.
    * **`emitFile`:** Copies files, used to set up test program source code.
    * **`runToolOp`:**  Executes the `covdata` tool (which is the test binary itself) with specific commands and arguments. It captures the output.
    * **`runDumpChecks`:**  Analyzes the output of the `debugdump` command using regular expressions to verify the presence or absence of expected information.
    * **`testMergeSimple`, `testMergeSelect`, etc.:** These functions test specific functionalities of the `covdata` tool, like merging coverage profiles, dumping data, calculating percentages, and so on. They use `runToolOp` to invoke the tool and `runDumpChecks` or direct output analysis to verify the results.

6. **Identify the Core Functionality:** Based on the test names and the operations performed, it's clear this code tests various aspects of the `cmd/covdata` tool, which is responsible for manipulating Go coverage profiles. The main functionalities being tested are:
    * **Merging:** Combining coverage data from multiple runs.
    * **Dumping:** Inspecting the raw coverage data.
    * **Calculating Percentages:**  Getting overall coverage metrics.
    * **Listing Packages:** Identifying packages with coverage data.
    * **Formatting to Text:** Converting coverage data to a specific text format.
    * **Subtracting/Intersecting:** Performing set-like operations on coverage data.

7. **Infer Go Feature:** The code directly interacts with Go's built-in code coverage functionality. The use of `-cover`, `-covermode`, and the `GOCOVERDIR` environment variable are strong indicators. The `internal/coverage/pods` package suggests the underlying data structures used for representing coverage information.

8. **Code Examples:**  Based on the identified functionality, I can construct code examples that demonstrate how to use the `covdata` tool. This involves using the `go test -coverprofile` flag to generate coverage data and then using the `go tool covdata` command with different subcommands.

9. **Command-Line Arguments:** By examining the `runToolOp` function and the arguments passed to it in the `testXxx` functions, I can identify the various command-line flags and arguments supported by the `covdata` tool.

10. **Common Mistakes:**  I look for potential pitfalls a user might encounter, such as incorrect usage of flags, confusion about input/output directories, or misunderstanding the different merge modes. The `testCommandLineErrors` function provides hints about common error scenarios. The `testCounterClash` also highlights a specific scenario with incompatible coverage modes.

By following these steps, I can systematically dissect the code, understand its purpose, and extract the requested information about its functionality, the underlying Go feature, usage examples, command-line arguments, and potential user errors.
这是 `go/src/cmd/covdata/tool_test.go` 文件的一部分，它是一个 Go 语言实现的**测试文件**，专门用于测试 `cmd/covdata` 这个命令行工具的功能。

**`cmd/covdata` 的功能（通过测试代码推断）：**

从测试代码中，我们可以推断出 `cmd/covdata` 工具的主要功能是处理 Go 代码覆盖率数据。具体包括：

1. **合并覆盖率数据 (`merge` 命令):**  可以将多个覆盖率数据文件或目录合并成一个。支持不同的合并策略，例如简单的合并以及按程序合并 (`-pcombine` 标志)。
2. **转储覆盖率数据 (`debugdump` 命令):**  可以将覆盖率数据以可读的格式输出，包括覆盖的包、函数以及具体的代码块和计数器信息。
3. **计算覆盖率百分比 (`percent` 命令):**  计算指定包的覆盖率百分比。
4. **列出覆盖的包 (`pkglist` 命令):**  列出覆盖率数据中包含的包。
5. **格式化为文本格式 (`textfmt` 命令):**  将覆盖率数据转换为 `go test -coverprofile` 可以读取的文本格式。
6. **相减覆盖率数据 (`subtract` 命令):**  从一个覆盖率数据集中减去另一个数据集，找出前者有而后者没有覆盖到的部分。
7. **相交覆盖率数据 (`intersect` 命令):**  找出两个覆盖率数据集共同覆盖到的部分。

**Go 语言功能实现：Go 代码覆盖率**

`cmd/covdata` 工具是 Go 语言内置代码覆盖率功能的一部分。Go 提供了在测试期间收集代码覆盖率信息的能力。

**Go 代码举例说明：**

以下代码展示了如何生成和使用覆盖率数据，这与 `cmd/covdata` 工具处理的数据相关：

```go
// example.go
package main

import "fmt"

func add(a, b int) int {
	if a > 0 {
		return a + b
	}
	return b
}

func main() {
	fmt.Println(add(1, 2))
	fmt.Println(add(-1, 3))
}
```

要生成覆盖率数据，可以使用 `go test` 命令的 `-coverprofile` 标志：

```bash
go test -coverprofile=coverage.out
```

这将编译代码并在执行测试时收集覆盖率信息，并将结果保存到 `coverage.out` 文件中。

`cmd/covdata` 工具可以处理像 `coverage.out` 这样的文件，以及通过设置 `GOCOVERDIR` 环境变量生成的覆盖率数据目录。

**代码推理与假设的输入输出：**

以 `testMergeSimple` 函数为例，它测试了 `merge` 命令的基本功能。

**假设输入：**

* `indir1` 和 `indir2` 是包含覆盖率数据的两个目录。这些目录是通过运行使用 `-cover` 编译的程序并设置 `GOCOVERDIR` 生成的。假设这两个目录都包含对 `mainPkgPath` ("prog") 包的覆盖率数据，但可能覆盖了不同的执行路径。

**预期输出：**

* 合并后的覆盖率数据目录 `outdir` 包含合并后的覆盖率信息。`debugdump` 命令在该目录上的输出应该显示所有被覆盖到的函数（例如 "first", "second", "third"）。对于 "third" 函数，由于 `indir1` 和 `indir2` 的执行可能覆盖了不同的代码块，合并后的数据应该显示这些代码块都被执行过，即对应的计数器值不为零。

**命令行参数的具体处理：**

在 `runToolOp` 函数中，我们可以看到 `cmd/covdata` 工具的调用方式：

```go
cmd := testenv.Command(t, s.tool, args...)
```

这里的 `s.tool` 是测试二进制文件本身（因为 `TestMain` 中设置了 `CMDCOVDATA_TEST_RUN_MAIN`），`args` 是要传递给 `cmd/covdata` 工具的参数。

常见的命令行参数（通过测试代码推断）包括：

* **操作命令:**  如 `merge`, `debugdump`, `percent`, `pkglist`, `textfmt`, `subtract`, `intersect`。
* **`-i` (输入):** 指定一个或多个输入覆盖率数据文件或目录，多个输入用逗号分隔。例如 `-i=covdata0,covdata1`。
* **`-o` (输出):** 指定输出覆盖率数据文件或目录。例如 `-o=merged_covdata`。
* **`-pkg` (包):** 用于指定要操作的包。例如 `-pkg=main`。
* **`-live`:**  在 `debugdump` 中使用，表示以更详细的方式显示信息。
* **`-pcombine`:**  在 `merge` 命令中使用，指示按程序合并，这在合并来自不同编译的程序的覆盖率数据时很有用。
* **`-v`:**  在 `textfmt` 中使用，可能用于指定覆盖率模式（例如 "set", "atomic"）。

**使用者易犯错的点：**

1. **输入路径错误:**  指定不存在的输入文件或目录会导致错误。测试用例 `testCommandLineErrors` 中就测试了这种情况。
   ```
   runToolOp(t, s, "merge", []string{"-o", eoutdir, "-i", "not there"})
   ```
   如果 `not there` 路径不存在，`cmd/covdata merge` 将会报错。

2. **合并不同覆盖率模式的数据:**  `cmd/covdata` 支持不同的覆盖率模式，例如 "set" 和 "atomic"。尝试合并使用不同模式生成的覆盖率数据可能会导致问题或需要使用特定的标志（如 `-pcombine`）。测试用例 `testCounterClash` 模拟了这种情况，并验证了工具在检测到模式冲突时的行为。

3. **不理解 `-pcombine` 的作用:**  在合并来自不同程序的覆盖率数据时，简单地合并可能无法正确关联数据。`-pcombine` 标志指示工具尝试更智能地合并，但用户可能不理解其必要性或效果。

4. **输出目录已存在:**  如果指定 `-o` 的输出目录已经存在，某些操作可能会失败或产生意外结果，具体取决于操作和目录内容。测试代码通常会先创建空的临时目录来避免这个问题。

总而言之，`go/src/cmd/covdata/tool_test.go` 通过大量的测试用例，详细地验证了 `cmd/covdata` 工具在处理 Go 代码覆盖率数据时的各种功能和边界情况，为开发者提供了使用该工具的重要参考。

### 提示词
```
这是路径为go/src/cmd/covdata/tool_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main_test

import (
	cmdcovdata "cmd/covdata"
	"flag"
	"fmt"
	"internal/coverage/pods"
	"internal/goexperiment"
	"internal/testenv"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Top level tempdir for test.
var testTempDir string

// If set, this will preserve all the tmpdir files from the test run.
var preserveTmp = flag.Bool("preservetmp", false, "keep tmpdir files for debugging")

// TestMain used here so that we can leverage the test executable
// itself as a cmd/covdata executable; compare to similar usage in
// the cmd/go tests.
func TestMain(m *testing.M) {
	// When CMDCOVDATA_TEST_RUN_MAIN is set, we're reusing the test
	// binary as cmd/cover. In this case we run the main func exported
	// via export_test.go, and exit; CMDCOVDATA_TEST_RUN_MAIN is set below
	// for actual test invocations.
	if os.Getenv("CMDCOVDATA_TEST_RUN_MAIN") != "" {
		cmdcovdata.Main()
		os.Exit(0)
	}
	flag.Parse()
	topTmpdir, err := os.MkdirTemp("", "cmd-covdata-test-")
	if err != nil {
		log.Fatal(err)
	}
	testTempDir = topTmpdir
	if !*preserveTmp {
		defer os.RemoveAll(topTmpdir)
	} else {
		fmt.Fprintf(os.Stderr, "debug: preserving tmpdir %s\n", topTmpdir)
	}
	os.Setenv("CMDCOVDATA_TEST_RUN_MAIN", "true")
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

const debugtrace = false

func gobuild(t *testing.T, indir string, bargs []string) {
	t.Helper()

	if debugtrace {
		if indir != "" {
			t.Logf("in dir %s: ", indir)
		}
		t.Logf("cmd: %s %+v\n", testenv.GoToolPath(t), bargs)
	}
	cmd := testenv.Command(t, testenv.GoToolPath(t), bargs...)
	cmd.Dir = indir
	b, err := cmd.CombinedOutput()
	if len(b) != 0 {
		t.Logf("## build output:\n%s", b)
	}
	if err != nil {
		t.Fatalf("build error: %v", err)
	}
}

func emitFile(t *testing.T, dst, src string) {
	payload, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("error reading %q: %v", src, err)
	}
	if err := os.WriteFile(dst, payload, 0666); err != nil {
		t.Fatalf("writing %q: %v", dst, err)
	}
}

const mainPkgPath = "prog"

func buildProg(t *testing.T, prog string, dir string, tag string, flags []string) (string, string) {
	// Create subdirs.
	subdir := filepath.Join(dir, prog+"dir"+tag)
	if err := os.Mkdir(subdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", subdir, err)
	}
	depdir := filepath.Join(subdir, "dep")
	if err := os.Mkdir(depdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", depdir, err)
	}

	// Emit program.
	insrc := filepath.Join("testdata", prog+".go")
	src := filepath.Join(subdir, prog+".go")
	emitFile(t, src, insrc)
	indep := filepath.Join("testdata", "dep.go")
	dep := filepath.Join(depdir, "dep.go")
	emitFile(t, dep, indep)

	// Emit go.mod.
	mod := filepath.Join(subdir, "go.mod")
	modsrc := "\nmodule " + mainPkgPath + "\n\ngo 1.19\n"
	if err := os.WriteFile(mod, []byte(modsrc), 0666); err != nil {
		t.Fatal(err)
	}
	exepath := filepath.Join(subdir, prog+".exe")
	bargs := []string{"build", "-cover", "-o", exepath}
	bargs = append(bargs, flags...)
	gobuild(t, subdir, bargs)
	return exepath, subdir
}

type state struct {
	dir      string
	exedir1  string
	exedir2  string
	exedir3  string
	exepath1 string
	exepath2 string
	exepath3 string
	tool     string
	outdirs  [4]string
}

const debugWorkDir = false

func TestCovTool(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	if !goexperiment.CoverageRedesign {
		t.Skipf("stubbed out due to goexperiment.CoverageRedesign=false")
	}
	dir := tempDir(t)
	if testing.Short() {
		t.Skip()
	}
	if debugWorkDir {
		// debugging
		dir = "/tmp/qqq"
		os.RemoveAll(dir)
		os.Mkdir(dir, 0777)
	}

	s := state{
		dir: dir,
	}
	s.exepath1, s.exedir1 = buildProg(t, "prog1", dir, "", nil)
	s.exepath2, s.exedir2 = buildProg(t, "prog2", dir, "", nil)
	flags := []string{"-covermode=atomic"}
	s.exepath3, s.exedir3 = buildProg(t, "prog1", dir, "atomic", flags)

	// Reuse unit test executable as tool to be tested.
	s.tool = testenv.Executable(t)

	// Create a few coverage output dirs.
	for i := 0; i < 4; i++ {
		d := filepath.Join(dir, fmt.Sprintf("covdata%d", i))
		s.outdirs[i] = d
		if err := os.Mkdir(d, 0777); err != nil {
			t.Fatalf("can't create outdir %s: %v", d, err)
		}
	}

	// Run instrumented program to generate some coverage data output files,
	// as follows:
	//
	//   <tmp>/covdata0   -- prog1.go compiled -cover
	//   <tmp>/covdata1   -- prog1.go compiled -cover
	//   <tmp>/covdata2   -- prog1.go compiled -covermode=atomic
	//   <tmp>/covdata3   -- prog1.go compiled -covermode=atomic
	//
	for m := 0; m < 2; m++ {
		for k := 0; k < 2; k++ {
			args := []string{}
			if k != 0 {
				args = append(args, "foo", "bar")
			}
			for i := 0; i <= k; i++ {
				exepath := s.exepath1
				if m != 0 {
					exepath = s.exepath3
				}
				cmd := testenv.Command(t, exepath, args...)
				cmd.Env = append(cmd.Env, "GOCOVERDIR="+s.outdirs[m*2+k])
				b, err := cmd.CombinedOutput()
				if len(b) != 0 {
					t.Logf("## instrumented run output:\n%s", b)
				}
				if err != nil {
					t.Fatalf("instrumented run error: %v", err)
				}
			}
		}
	}

	// At this point we can fork off a bunch of child tests
	// to check different tool modes.
	t.Run("MergeSimple", func(t *testing.T) {
		t.Parallel()
		testMergeSimple(t, s, s.outdirs[0], s.outdirs[1], "set")
		testMergeSimple(t, s, s.outdirs[2], s.outdirs[3], "atomic")
	})
	t.Run("MergeSelect", func(t *testing.T) {
		t.Parallel()
		testMergeSelect(t, s, s.outdirs[0], s.outdirs[1], "set")
		testMergeSelect(t, s, s.outdirs[2], s.outdirs[3], "atomic")
	})
	t.Run("MergePcombine", func(t *testing.T) {
		t.Parallel()
		testMergeCombinePrograms(t, s)
	})
	t.Run("Dump", func(t *testing.T) {
		t.Parallel()
		testDump(t, s)
	})
	t.Run("Percent", func(t *testing.T) {
		t.Parallel()
		testPercent(t, s)
	})
	t.Run("PkgList", func(t *testing.T) {
		t.Parallel()
		testPkgList(t, s)
	})
	t.Run("Textfmt", func(t *testing.T) {
		t.Parallel()
		testTextfmt(t, s)
	})
	t.Run("Subtract", func(t *testing.T) {
		t.Parallel()
		testSubtract(t, s)
	})
	t.Run("Intersect", func(t *testing.T) {
		t.Parallel()
		testIntersect(t, s, s.outdirs[0], s.outdirs[1], "set")
		testIntersect(t, s, s.outdirs[2], s.outdirs[3], "atomic")
	})
	t.Run("CounterClash", func(t *testing.T) {
		t.Parallel()
		testCounterClash(t, s)
	})
	t.Run("TestEmpty", func(t *testing.T) {
		t.Parallel()
		testEmpty(t, s)
	})
	t.Run("TestCommandLineErrors", func(t *testing.T) {
		t.Parallel()
		testCommandLineErrors(t, s, s.outdirs[0])
	})
}

const showToolInvocations = true

func runToolOp(t *testing.T, s state, op string, args []string) []string {
	// Perform tool run.
	t.Helper()
	args = append([]string{op}, args...)
	if showToolInvocations {
		t.Logf("%s cmd is: %s %+v", op, s.tool, args)
	}
	cmd := testenv.Command(t, s.tool, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "## %s output: %s\n", op, b)
		t.Fatalf("%q run error: %v", op, err)
	}
	output := strings.TrimSpace(string(b))
	lines := strings.Split(output, "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	return lines
}

func testDump(t *testing.T, s state) {
	// Run the dumper on the two dirs we generated.
	dargs := []string{"-pkg=" + mainPkgPath, "-live", "-i=" + s.outdirs[0] + "," + s.outdirs[1]}
	lines := runToolOp(t, s, "debugdump", dargs)

	// Sift through the output to make sure it has some key elements.
	testpoints := []struct {
		tag string
		re  *regexp.Regexp
	}{
		{
			"args",
			regexp.MustCompile(`^data file .+ GOOS=.+ GOARCH=.+ program args: .+$`),
		},
		{
			"main package",
			regexp.MustCompile(`^Package path: ` + mainPkgPath + `\s*$`),
		},
		{
			"main function",
			regexp.MustCompile(`^Func: main\s*$`),
		},
	}

	bad := false
	for _, testpoint := range testpoints {
		found := false
		for _, line := range lines {
			if m := testpoint.re.FindStringSubmatch(line); m != nil {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("dump output regexp match failed for %q", testpoint.tag)
			bad = true
		}
	}
	if bad {
		dumplines(lines)
	}
}

func testPercent(t *testing.T, s state) {
	// Run the dumper on the two dirs we generated.
	dargs := []string{"-pkg=" + mainPkgPath, "-i=" + s.outdirs[0] + "," + s.outdirs[1]}
	lines := runToolOp(t, s, "percent", dargs)

	// Sift through the output to make sure it has the needful.
	testpoints := []struct {
		tag string
		re  *regexp.Regexp
	}{
		{
			"statement coverage percent",
			regexp.MustCompile(`coverage: \d+\.\d% of statements\s*$`),
		},
	}

	bad := false
	for _, testpoint := range testpoints {
		found := false
		for _, line := range lines {
			if m := testpoint.re.FindStringSubmatch(line); m != nil {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("percent output regexp match failed for %s", testpoint.tag)
			bad = true
		}
	}
	if bad {
		dumplines(lines)
	}
}

func testPkgList(t *testing.T, s state) {
	dargs := []string{"-i=" + s.outdirs[0] + "," + s.outdirs[1]}
	lines := runToolOp(t, s, "pkglist", dargs)

	want := []string{mainPkgPath, mainPkgPath + "/dep"}
	bad := false
	if len(lines) != 2 {
		t.Errorf("expect pkglist to return two lines")
		bad = true
	} else {
		for i := 0; i < 2; i++ {
			lines[i] = strings.TrimSpace(lines[i])
			if want[i] != lines[i] {
				t.Errorf("line %d want %s got %s", i, want[i], lines[i])
				bad = true
			}
		}
	}
	if bad {
		dumplines(lines)
	}
}

func testTextfmt(t *testing.T, s state) {
	outf := s.dir + "/" + "t.txt"
	dargs := []string{"-pkg=" + mainPkgPath, "-i=" + s.outdirs[0] + "," + s.outdirs[1],
		"-o", outf}
	lines := runToolOp(t, s, "textfmt", dargs)

	// No output expected.
	if len(lines) != 0 {
		dumplines(lines)
		t.Errorf("unexpected output from go tool covdata textfmt")
	}

	// Open and read the first few bits of the file.
	payload, err := os.ReadFile(outf)
	if err != nil {
		t.Errorf("opening %s: %v\n", outf, err)
	}
	lines = strings.Split(string(payload), "\n")
	want0 := "mode: set"
	if lines[0] != want0 {
		dumplines(lines[0:10])
		t.Errorf("textfmt: want %s got %s", want0, lines[0])
	}
	want1 := mainPkgPath + "/prog1.go:13.14,15.2 1 1"
	if lines[1] != want1 {
		dumplines(lines[0:10])
		t.Errorf("textfmt: want %s got %s", want1, lines[1])
	}
}

func dumplines(lines []string) {
	for i := range lines {
		fmt.Fprintf(os.Stderr, "%s\n", lines[i])
	}
}

type dumpCheck struct {
	tag     string
	re      *regexp.Regexp
	negate  bool
	nonzero bool
	zero    bool
}

// runDumpChecks examines the output of "go tool covdata debugdump"
// for a given output directory, looking for the presence or absence
// of specific markers.
func runDumpChecks(t *testing.T, s state, dir string, flags []string, checks []dumpCheck) {
	dargs := []string{"-i", dir}
	dargs = append(dargs, flags...)
	lines := runToolOp(t, s, "debugdump", dargs)
	if len(lines) == 0 {
		t.Fatalf("dump run produced no output")
	}

	bad := false
	for _, check := range checks {
		found := false
		for _, line := range lines {
			if m := check.re.FindStringSubmatch(line); m != nil {
				found = true
				if check.negate {
					t.Errorf("tag %q: unexpected match", check.tag)
					bad = true

				}
				if check.nonzero || check.zero {
					if len(m) < 2 {
						t.Errorf("tag %s: submatch failed (short m)", check.tag)
						bad = true
						continue
					}
					if m[1] == "" {
						t.Errorf("tag %s: submatch failed", check.tag)
						bad = true
						continue
					}
					i, err := strconv.Atoi(m[1])
					if err != nil {
						t.Errorf("tag %s: match Atoi failed on %s",
							check.tag, m[1])
						continue
					}
					if check.zero && i != 0 {
						t.Errorf("tag %s: match zero failed on %s",
							check.tag, m[1])
					} else if check.nonzero && i == 0 {
						t.Errorf("tag %s: match nonzero failed on %s",
							check.tag, m[1])
					}
				}
				break
			}
		}
		if !found && !check.negate {
			t.Errorf("dump output regexp match failed for %s", check.tag)
			bad = true
		}
	}
	if bad {
		fmt.Printf("output from 'dump' run:\n")
		dumplines(lines)
	}
}

func testMergeSimple(t *testing.T, s state, indir1, indir2, tag string) {
	outdir := filepath.Join(s.dir, "simpleMergeOut"+tag)
	if err := os.Mkdir(outdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", outdir, err)
	}

	// Merge the two dirs into a final result.
	ins := fmt.Sprintf("-i=%s,%s", indir1, indir2)
	out := fmt.Sprintf("-o=%s", outdir)
	margs := []string{ins, out}
	lines := runToolOp(t, s, "merge", margs)
	if len(lines) != 0 {
		t.Errorf("merge run produced %d lines of unexpected output", len(lines))
		dumplines(lines)
	}

	// We expect the merge tool to produce exactly two files: a meta
	// data file and a counter file. If we get more than just this one
	// pair, something went wrong.
	podlist, err := pods.CollectPods([]string{outdir}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(podlist) != 1 {
		t.Fatalf("expected 1 pod, got %d pods", len(podlist))
	}
	ncdfs := len(podlist[0].CounterDataFiles)
	if ncdfs != 1 {
		t.Fatalf("expected 1 counter data file, got %d", ncdfs)
	}

	// Sift through the output to make sure it has some key elements.
	// In particular, we want to see entries for all three functions
	// ("first", "second", and "third").
	testpoints := []dumpCheck{
		{
			tag: "first function",
			re:  regexp.MustCompile(`^Func: first\s*$`),
		},
		{
			tag: "second function",
			re:  regexp.MustCompile(`^Func: second\s*$`),
		},
		{
			tag: "third function",
			re:  regexp.MustCompile(`^Func: third\s*$`),
		},
		{
			tag:     "third function unit 0",
			re:      regexp.MustCompile(`^0: L23:C23 -- L24:C12 NS=1 = (\d+)$`),
			nonzero: true,
		},
		{
			tag:     "third function unit 1",
			re:      regexp.MustCompile(`^1: L27:C2 -- L28:C10 NS=2 = (\d+)$`),
			nonzero: true,
		},
		{
			tag:     "third function unit 2",
			re:      regexp.MustCompile(`^2: L24:C12 -- L26:C3 NS=1 = (\d+)$`),
			nonzero: true,
		},
	}
	flags := []string{"-live", "-pkg=" + mainPkgPath}
	runDumpChecks(t, s, outdir, flags, testpoints)
}

func testMergeSelect(t *testing.T, s state, indir1, indir2 string, tag string) {
	outdir := filepath.Join(s.dir, "selectMergeOut"+tag)
	if err := os.Mkdir(outdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", outdir, err)
	}

	// Merge two input dirs into a final result, but filter
	// based on package.
	ins := fmt.Sprintf("-i=%s,%s", indir1, indir2)
	out := fmt.Sprintf("-o=%s", outdir)
	margs := []string{"-pkg=" + mainPkgPath + "/dep", ins, out}
	lines := runToolOp(t, s, "merge", margs)
	if len(lines) != 0 {
		t.Errorf("merge run produced %d lines of unexpected output", len(lines))
		dumplines(lines)
	}

	// Dump the files in the merged output dir and examine the result.
	// We expect to see only the functions in package "dep".
	dargs := []string{"-i=" + outdir}
	lines = runToolOp(t, s, "debugdump", dargs)
	if len(lines) == 0 {
		t.Fatalf("dump run produced no output")
	}
	want := map[string]int{
		"Package path: " + mainPkgPath + "/dep": 0,
		"Func: Dep1":                            0,
		"Func: PDep":                            0,
	}
	bad := false
	for _, line := range lines {
		if v, ok := want[line]; ok {
			if v != 0 {
				t.Errorf("duplicate line %s", line)
				bad = true
				break
			}
			want[line] = 1
			continue
		}
		// no other functions or packages expected.
		if strings.HasPrefix(line, "Func:") || strings.HasPrefix(line, "Package path:") {
			t.Errorf("unexpected line: %s", line)
			bad = true
			break
		}
	}
	if bad {
		dumplines(lines)
	}
}

func testMergeCombinePrograms(t *testing.T, s state) {

	// Run the new program, emitting output into a new set
	// of outdirs.
	runout := [2]string{}
	for k := 0; k < 2; k++ {
		runout[k] = filepath.Join(s.dir, fmt.Sprintf("newcovdata%d", k))
		if err := os.Mkdir(runout[k], 0777); err != nil {
			t.Fatalf("can't create outdir %s: %v", runout[k], err)
		}
		args := []string{}
		if k != 0 {
			args = append(args, "foo", "bar")
		}
		cmd := testenv.Command(t, s.exepath2, args...)
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+runout[k])
		b, err := cmd.CombinedOutput()
		if len(b) != 0 {
			t.Logf("## instrumented run output:\n%s", b)
		}
		if err != nil {
			t.Fatalf("instrumented run error: %v", err)
		}
	}

	// Create out dir for -pcombine merge.
	moutdir := filepath.Join(s.dir, "mergeCombineOut")
	if err := os.Mkdir(moutdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", moutdir, err)
	}

	// Run a merge over both programs, using the -pcombine
	// flag to do maximal combining.
	ins := fmt.Sprintf("-i=%s,%s,%s,%s", s.outdirs[0], s.outdirs[1],
		runout[0], runout[1])
	out := fmt.Sprintf("-o=%s", moutdir)
	margs := []string{"-pcombine", ins, out}
	lines := runToolOp(t, s, "merge", margs)
	if len(lines) != 0 {
		t.Errorf("merge run produced unexpected output: %v", lines)
	}

	// We expect the merge tool to produce exactly two files: a meta
	// data file and a counter file. If we get more than just this one
	// pair, something went wrong.
	podlist, err := pods.CollectPods([]string{moutdir}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(podlist) != 1 {
		t.Fatalf("expected 1 pod, got %d pods", len(podlist))
	}
	ncdfs := len(podlist[0].CounterDataFiles)
	if ncdfs != 1 {
		t.Fatalf("expected 1 counter data file, got %d", ncdfs)
	}

	// Sift through the output to make sure it has some key elements.
	testpoints := []dumpCheck{
		{
			tag: "first function",
			re:  regexp.MustCompile(`^Func: first\s*$`),
		},
		{
			tag: "sixth function",
			re:  regexp.MustCompile(`^Func: sixth\s*$`),
		},
	}

	flags := []string{"-live", "-pkg=" + mainPkgPath}
	runDumpChecks(t, s, moutdir, flags, testpoints)
}

func testSubtract(t *testing.T, s state) {
	// Create out dir for subtract merge.
	soutdir := filepath.Join(s.dir, "subtractOut")
	if err := os.Mkdir(soutdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", soutdir, err)
	}

	// Subtract the two dirs into a final result.
	ins := fmt.Sprintf("-i=%s,%s", s.outdirs[0], s.outdirs[1])
	out := fmt.Sprintf("-o=%s", soutdir)
	sargs := []string{ins, out}
	lines := runToolOp(t, s, "subtract", sargs)
	if len(lines) != 0 {
		t.Errorf("subtract run produced unexpected output: %+v", lines)
	}

	// Dump the files in the subtract output dir and examine the result.
	dargs := []string{"-pkg=" + mainPkgPath, "-live", "-i=" + soutdir}
	lines = runToolOp(t, s, "debugdump", dargs)
	if len(lines) == 0 {
		t.Errorf("dump run produced no output")
	}

	// Vet the output.
	testpoints := []dumpCheck{
		{
			tag: "first function",
			re:  regexp.MustCompile(`^Func: first\s*$`),
		},
		{
			tag: "dep function",
			re:  regexp.MustCompile(`^Func: Dep1\s*$`),
		},
		{
			tag: "third function",
			re:  regexp.MustCompile(`^Func: third\s*$`),
		},
		{
			tag:  "third function unit 0",
			re:   regexp.MustCompile(`^0: L23:C23 -- L24:C12 NS=1 = (\d+)$`),
			zero: true,
		},
		{
			tag:     "third function unit 1",
			re:      regexp.MustCompile(`^1: L27:C2 -- L28:C10 NS=2 = (\d+)$`),
			nonzero: true,
		},
		{
			tag:  "third function unit 2",
			re:   regexp.MustCompile(`^2: L24:C12 -- L26:C3 NS=1 = (\d+)$`),
			zero: true,
		},
	}
	flags := []string{}
	runDumpChecks(t, s, soutdir, flags, testpoints)
}

func testIntersect(t *testing.T, s state, indir1, indir2, tag string) {
	// Create out dir for intersection.
	ioutdir := filepath.Join(s.dir, "intersectOut"+tag)
	if err := os.Mkdir(ioutdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", ioutdir, err)
	}

	// Intersect the two dirs into a final result.
	ins := fmt.Sprintf("-i=%s,%s", indir1, indir2)
	out := fmt.Sprintf("-o=%s", ioutdir)
	sargs := []string{ins, out}
	lines := runToolOp(t, s, "intersect", sargs)
	if len(lines) != 0 {
		t.Errorf("intersect run produced unexpected output: %+v", lines)
	}

	// Dump the files in the subtract output dir and examine the result.
	dargs := []string{"-pkg=" + mainPkgPath, "-live", "-i=" + ioutdir}
	lines = runToolOp(t, s, "debugdump", dargs)
	if len(lines) == 0 {
		t.Errorf("dump run produced no output")
	}

	// Vet the output.
	testpoints := []dumpCheck{
		{
			tag:    "first function",
			re:     regexp.MustCompile(`^Func: first\s*$`),
			negate: true,
		},
		{
			tag: "third function",
			re:  regexp.MustCompile(`^Func: third\s*$`),
		},
	}
	flags := []string{"-live"}
	runDumpChecks(t, s, ioutdir, flags, testpoints)
}

func testCounterClash(t *testing.T, s state) {
	// Create out dir.
	ccoutdir := filepath.Join(s.dir, "ccOut")
	if err := os.Mkdir(ccoutdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", ccoutdir, err)
	}

	// Try to merge covdata0 (from prog1.go -countermode=set) with
	// covdata1 (from prog1.go -countermode=atomic"). This should
	// work properly, but result in multiple meta-data files.
	ins := fmt.Sprintf("-i=%s,%s", s.outdirs[0], s.outdirs[3])
	out := fmt.Sprintf("-o=%s", ccoutdir)
	args := append([]string{}, "merge", ins, out, "-pcombine")
	if debugtrace {
		t.Logf("cc merge command is %s %v\n", s.tool, args)
	}
	cmd := testenv.Command(t, s.tool, args...)
	b, err := cmd.CombinedOutput()
	t.Logf("%% output: %s\n", string(b))
	if err != nil {
		t.Fatalf("clash merge failed: %v", err)
	}

	// Ask for a textual report from the two dirs. Here we have
	// to report the mode clash.
	out = "-o=" + filepath.Join(ccoutdir, "file.txt")
	args = append([]string{}, "textfmt", ins, out)
	if debugtrace {
		t.Logf("clash textfmt command is %s %v\n", s.tool, args)
	}
	cmd = testenv.Command(t, s.tool, args...)
	b, err = cmd.CombinedOutput()
	t.Logf("%% output: %s\n", string(b))
	if err == nil {
		t.Fatalf("expected mode clash")
	}
	got := string(b)
	want := "counter mode clash while reading meta-data"
	if !strings.Contains(got, want) {
		t.Errorf("counter clash textfmt: wanted %s got %s", want, got)
	}
}

func testEmpty(t *testing.T, s state) {

	// Create a new empty directory.
	empty := filepath.Join(s.dir, "empty")
	if err := os.Mkdir(empty, 0777); err != nil {
		t.Fatalf("can't create dir %s: %v", empty, err)
	}

	// Create out dir.
	eoutdir := filepath.Join(s.dir, "emptyOut")
	if err := os.Mkdir(eoutdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", eoutdir, err)
	}

	// Run various operations (merge, dump, textfmt, and so on)
	// using the empty directory. We're not interested in the output
	// here, just making sure that you can do these runs without
	// any error or crash.

	scenarios := []struct {
		tag  string
		args []string
	}{
		{
			tag:  "merge",
			args: []string{"merge", "-o", eoutdir},
		},
		{
			tag:  "textfmt",
			args: []string{"textfmt", "-o", filepath.Join(eoutdir, "foo.txt")},
		},
		{
			tag:  "func",
			args: []string{"func"},
		},
		{
			tag:  "pkglist",
			args: []string{"pkglist"},
		},
		{
			tag:  "debugdump",
			args: []string{"debugdump"},
		},
		{
			tag:  "percent",
			args: []string{"percent"},
		},
	}

	for _, x := range scenarios {
		ins := fmt.Sprintf("-i=%s", empty)
		args := append([]string{}, x.args...)
		args = append(args, ins)
		if false {
			t.Logf("cmd is %s %v\n", s.tool, args)
		}
		cmd := testenv.Command(t, s.tool, args...)
		b, err := cmd.CombinedOutput()
		t.Logf("%% output: %s\n", string(b))
		if err != nil {
			t.Fatalf("command %s %+v failed with %v",
				s.tool, x.args, err)
		}
	}
}

func testCommandLineErrors(t *testing.T, s state, outdir string) {

	// Create out dir.
	eoutdir := filepath.Join(s.dir, "errorsOut")
	if err := os.Mkdir(eoutdir, 0777); err != nil {
		t.Fatalf("can't create outdir %s: %v", eoutdir, err)
	}

	// Run various operations (merge, dump, textfmt, and so on)
	// using the empty directory. We're not interested in the output
	// here, just making sure that you can do these runs without
	// any error or crash.

	scenarios := []struct {
		tag  string
		args []string
		exp  string
	}{
		{
			tag:  "input missing",
			args: []string{"merge", "-o", eoutdir, "-i", "not there"},
			exp:  "error: reading inputs: ",
		},
		{
			tag:  "badv",
			args: []string{"textfmt", "-i", outdir, "-v=abc"},
		},
	}

	for _, x := range scenarios {
		args := append([]string{}, x.args...)
		if false {
			t.Logf("cmd is %s %v\n", s.tool, args)
		}
		cmd := testenv.Command(t, s.tool, args...)
		b, err := cmd.CombinedOutput()
		if err == nil {
			t.Logf("%% output: %s\n", string(b))
			t.Fatalf("command %s %+v unexpectedly succeeded",
				s.tool, x.args)
		} else {
			if !strings.Contains(string(b), x.exp) {
				t.Fatalf("command %s %+v:\ngot:\n%s\nwanted to see: %v\n",
					s.tool, x.args, string(b), x.exp)
			}
		}
	}
}
```