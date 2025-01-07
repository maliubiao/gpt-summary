Response:
Let's break down the thought process for analyzing this Go code snippet for `runtime-gdb_test.go`.

**1. Understanding the Goal:**

The filename `runtime-gdb_test.go` immediately signals that this code is testing the integration of the Go runtime with the GDB debugger. The suffix `_test.go` confirms it's a Go test file. Therefore, the primary goal is to verify that GDB can correctly inspect the state of a running Go program.

**2. Initial Code Scan - Identifying Key Areas:**

I'd first scan the imports and top-level declarations to get a broad overview.

* **Imports:**  `bytes`, `flag`, `fmt`, `internal/abi`, `internal/goexperiment`, `internal/testenv`, `os`, `os/exec`, `path/filepath`, `regexp`, `runtime`, `strconv`, `strings`, `testing`, `time`. These imports strongly suggest:
    * **Testing:**  `testing` is the core testing package.
    * **External Processes:** `os/exec` indicates interaction with external commands (likely GDB).
    * **String/Data Manipulation:** `bytes`, `strings`, `strconv`, `regexp` suggest parsing and processing GDB output.
    * **File System:** `os`, `path/filepath` are for file and directory operations (likely creating temporary files for test programs).
    * **Runtime Interaction:**  `runtime` is the target of the testing, providing access to Go's runtime features.
    * **Internal Packages:**  `internal/abi` and `internal/goexperiment` hint at testing features related to Go's internal workings and experimental features.

* **Top-Level Functions:**  The functions like `checkGdbEnvironment`, `checkGdbVersion`, `checkGdbPython`, `checkCleanBacktrace`, `checkPtraceScope` clearly indicate setup and validation steps before running the core tests. The test functions themselves (starting with `TestGdb...`) will contain the actual test logic.

* **Global Variables:**  `helloSource`, `backtraceSource`, `autotmpTypeSource`, `constsSource`, `panicSource`, `InfCallstackSource` are multiline strings containing Go source code. These are the programs being debugged.

**3. Analyzing Helper Functions:**

Now, let's examine the helper functions to understand their roles:

* **`checkGdbEnvironment`:** Skips tests on platforms where GDB is known to have issues with Go. This is crucial for reliable testing.
* **`checkGdbVersion`:**  Ensures a minimum GDB version is used, avoiding issues with older versions. Uses `exec.Command` to run `gdb --version`.
* **`checkGdbPython`:** Verifies that the GDB being used has Python support, which is needed for the Go runtime's GDB scripts.
* **`checkCleanBacktrace`:**  Parses and validates the format of a GDB backtrace. This ensures the backtrace output is structured as expected.
* **`checkPtraceScope`:** Checks the `ptrace_scope` kernel parameter on Linux. This is important because restrictions on `ptrace` can prevent GDB from attaching to processes. The comments explain the different `ptrace_scope` values and their implications.
* **`lastLine`:** Finds the line number containing `END_OF_PROGRAM` in a Go source file. This is used to set a breakpoint at the end of the program.
* **`gdbArgsFixup`:** Modifies GDB command-line arguments for Windows, adding double quotes around arguments with spaces. This addresses platform-specific requirements of GDB on Windows.

**4. Dissecting Test Functions (e.g., `TestGdbPython`):**

Let's focus on a key test function, `TestGdbPython`, to understand the testing methodology:

* **Setup:**
    * Calls helper functions (`checkGdbEnvironment`, `checkGdbVersion`, `checkGdbPython`, `checkPtraceScope`).
    * Creates a temporary directory (`t.TempDir()`).
    * Constructs a Go source file (using `helloSource`).
    * Locates a specific line containing "breakpoint" in the source code.
    * Compiles the Go source code using `go build`.

* **GDB Execution:**
    * Constructs a list of GDB command-line arguments (`args`). These arguments are critical. They include:
        * `-nx -q --batch`: Run GDB in non-interactive, quiet, and batch mode.
        * `-iex`:  Execute GDB commands *before* loading the executable. Used to load the Go runtime's GDB scripts.
        * `-ex`: Execute GDB commands. These include: setting breakpoints, running the program, printing variables, getting goroutine information, and obtaining backtraces.
    * Uses `exec.Command("gdb", args...)` to run GDB.

* **Output Analysis:**
    * Captures GDB's output (`got`).
    * Uses regular expressions (`regexp`) to extract specific blocks of output marked by `BEGIN ... END`.
    * Uses more regular expressions to verify the content of these blocks (e.g., the output of `info goroutines`, `print mapvar`, backtraces).

**5. Inferring Go Features Being Tested:**

By examining the GDB commands used in the test functions, we can infer the Go features being validated:

* **Goroutine Inspection (`info goroutines`):**  Verifies GDB's ability to list and inspect running goroutines.
* **Variable Inspection (`print ...`):**  Tests GDB's ability to display the values of different Go data types (maps, slices, strings, channels, pointers).
* **Local Variable Inspection (`info locals`):**  Ensures GDB can show the values of local variables within a function's scope.
* **Stack Traces (`goroutine ... bt`):**  Confirms GDB can generate correct stack backtraces for goroutines.
* **Stepping (`step` in `TestGdbAutotmpTypes`):** Validates GDB's ability to step through Go code.
* **Constant Inspection (`print main.aConstant` in `TestGdbConst`):** Checks if GDB can correctly display the values of Go constants.
* **Panic Handling (`TestGdbPanic`):**  Verifies that GDB can handle Go program crashes due to panics and provide useful debugging information.
* **CGO Callstacks (`TestGdbInfCallstack`):**  Specifically tests GDB's ability to handle stack frames in programs that use C code through CGO.

**6. Identifying Potential User Errors:**

As the code focuses on automated testing, it doesn't explicitly highlight common user errors. However, based on the nature of GDB and debugging, some likely user errors would be:

* **Incorrect GDB Version:** Using an older GDB version that doesn't fully support Go's debugging information. The `checkGdbVersion` function addresses this.
* **Missing Python Support in GDB:**  GDB without Python support won't be able to load the Go runtime's GDB scripts. `checkGdbPython` handles this.
* **`ptrace` Restrictions:** On Linux, if `ptrace_scope` is set too restrictively, GDB might not be able to attach to the Go process. `checkPtraceScope` detects this.
* **Typos in GDB Commands:**  Simple errors in typing GDB commands will obviously lead to issues.
* **Misunderstanding Go's Runtime Concepts:**  Not understanding how goroutines, channels, maps, etc., are implemented can make debugging confusing. The tests implicitly help validate the correctness of GDB's representation of these concepts.
* **Not Loading Go Runtime Scripts:** For effective Go debugging, the `runtime-gdb.py` script needs to be loaded into GDB. The tests demonstrate how this is done (`add-auto-load-safe-path` or `source`).

By following this breakdown, we can thoroughly understand the functionality of the `runtime-gdb_test.go` file and the Go features it aims to test.
这段代码是 Go 语言运行时（runtime）的一部分，专门用于测试 GDB（GNU Debugger）对 Go 程序的调试支持。它的主要功能是：

1. **环境检查:**  它会检查当前运行环境是否适合进行 GDB 测试，例如操作系统、架构以及 GDB 的版本。在某些已知存在问题的平台上会跳过测试。
2. **GDB 版本检查:**  它会验证 GDB 的版本是否满足最低要求，以确保测试的可靠性。因为旧版本的 GDB 可能存在与 Go 调试信息不兼容的问题。
3. **GDB Python 支持检查:**  它会检查 GDB 是否支持 Python 脚本，因为 Go 的 GDB 辅助功能是通过 Python 脚本实现的。
4. **`ptrace_scope` 检查 (Linux):** 在 Linux 系统上，它会检查内核参数 `ptrace_scope` 的值，如果该值阻止 GDB 附加到进程，则会跳过测试。
5. **构建测试程序:** 它会动态生成一些简单的 Go 语言测试程序，并使用 `go build` 命令进行编译。
6. **执行 GDB 命令并验证输出:**  它会启动 GDB，加载编译后的测试程序，并执行一系列 GDB 命令，例如设置断点、运行程序、打印变量、查看 goroutine 信息、获取堆栈跟踪等。然后，它会解析 GDB 的输出，并使用正则表达式来验证输出是否符合预期。
7. **测试各种 Go 语言特性:**  通过不同的测试用例，它会覆盖 Go 语言的各种特性在 GDB 中的调试情况，例如：
    * **基本类型和变量:**  测试打印不同类型的变量，包括基本类型、字符串、指针等。
    * **复合类型:**  测试打印 `map`、`slice`、`chan` 等复合类型。
    * **Goroutine 信息:**  测试 `info goroutines` 命令是否能正确显示 goroutine 的状态。
    * **堆栈跟踪:**  测试 `backtrace` 命令是否能正确显示 Go 程序的堆栈信息。
    * **常量:** 测试是否能打印 Go 语言的常量。
    * **Panic 处理:** 测试当 Go 程序发生 panic 时，GDB 是否能正确显示堆栈信息。
    * **CGO 支持:**  测试 GDB 对使用了 CGO 的程序的调试支持 (例如 `TestGdbPythonCgo` 和 `TestGdbInfCallstack`)。
    * **自动临时变量类型 (autotmp):**  测试 GDB 是否能正确识别和显示自动生成的临时变量的类型。

**以下是一些通过 Go 代码举例说明其测试功能的例子：**

**例子 1: 测试打印 map 变量**

```go
// 假设 helloSource 中定义了 mapvar
// ...
args := []string{
    // ... 其他 GDB 参数
    "-ex", "echo BEGIN print mapvar\n",
    "-ex", "print mapvar",
    "-ex", "echo END\n",
    // ...
}
// ... 执行 GDB 并获取输出

// 假设 GDB 的输出中包含 "BEGIN print mapvar" 和 "END" 之间的内容
blocks := map[string]string{}
// ... (从 GDB 输出中解析 blocks)

printMapvarRe1 := regexp.MustCompile(`^\$[0-9]+ = map\[string\]string = {\[(0x[0-9a-f]+\s+)?"abc"\] = (0x[0-9a-f]+\s+)?"def", \[(0x[0-9a-f]+\s+)?"ghi"\] = (0x[0-9a-f]+\s+)?"jkl"}$`)
printMapvarRe2 := regexp.MustCompile(`^\$[0-9]+ = map\[string\]string = {\[(0x[0-9a-f]+\s+)?"ghi"\] = (0x[0-9a-f]+\s+)?"jkl", \[(0x[0-9a-f]+\s+)?"abc"\] = (0x[0-9a-f]+\s+)?"def"}$`)
if bl := blocks["print mapvar"]; !printMapvarRe1.MatchString(bl) &&
    !printMapvarRe2.MatchString(bl) {
    // 如果 GDB 打印的 map 内容与预期不符，则测试失败
    t.Fatalf("print mapvar failed: %s", bl)
}
```

**假设输入:** `helloSource` 中 `mapvar` 被初始化为 `map["abc"] = "def"` 和 `map["ghi"] = "jkl"`。

**预期输出:** GDB 打印 `mapvar` 的输出应该类似于 `"$1 = map[string]string = {["abc"] = "def", ["ghi"] = "jkl"}"` (元素的顺序可能不同)。正则表达式 `printMapvarRe1` 和 `printMapvarRe2` 用于匹配这两种可能的顺序。

**例子 2: 测试 `info goroutines` 命令**

```go
// ...
args := []string{
    // ... 其他 GDB 参数
    "-ex", "echo BEGIN info goroutines\n",
    "-ex", "info goroutines",
    "-ex", "echo END\n",
    // ...
}
// ... 执行 GDB 并获取输出

// 假设 GDB 的输出中包含 "BEGIN info goroutines" 和 "END" 之间的内容
blocks := map[string]string{}
// ... (从 GDB 输出中解析 blocks)

infoGoroutinesRe := regexp.MustCompile(`\*\s+\d+\s+running\s+`)
if bl := blocks["info goroutines"]; !infoGoroutinesRe.MatchString(bl) {
    // 如果 info goroutines 的输出中没有包含运行中的 goroutine 信息，则测试失败
    t.Fatalf("info goroutines failed: %s", bl)
}
```

**假设输入:**  测试程序运行时至少有一个 goroutine 在运行（主 goroutine）。

**预期输出:** GDB 的 `info goroutines` 命令输出应该包含一行以 `*` 开头，包含 goroutine ID、状态（通常是 `running`）等信息的行。正则表达式 `infoGoroutinesRe` 用于匹配这种格式。

**命令行参数处理:**

这段代码本身并不直接处理用户在命令行输入的参数。它的主要作用是*运行* GDB 并验证其输出。 它使用了 `flag` 包，但主要是为了利用 Go 的测试框架，例如通过 `testing.Short()` 来判断是否运行简短测试。

GDB 的命令行参数是通过 `args` 变量构建的，例如：

* `-nx`:  以非交互模式运行 GDB。
* `-q`:  启动 GDB 时不显示介绍信息和版权信息。
* `--batch`: 在执行完所有命令后退出 GDB。
* `-iex <命令>`:  在加载可执行文件之前执行 GDB 命令。常用于加载 Go 的 GDB 辅助脚本。
* `-ex <命令>`:  执行 GDB 命令。
* `<可执行文件路径>`:  指定要调试的可执行文件。

例如，在 `TestGdbPython` 函数中，以下参数用于设置 GDB 环境并执行调试命令：

```go
args := []string{"-nx", "-q", "--batch",
    "-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"), // 加载 Go 的 GDB 辅助脚本
    "-ex", "set startup-with-shell off", // 关闭启动时执行 shell 命令
    "-ex", "set print thread-events off", // 关闭线程事件打印
    // ... 其他命令，例如设置断点、运行、打印变量等
    filepath.Join(dir, "a.exe"), // 要调试的可执行文件
}
```

**使用者易犯错的点 (虽然这段代码主要是测试，但可以推断出用户在使用 GDB 调试 Go 程序时可能遇到的问题):**

1. **GDB 版本过低:** 如果使用的 GDB 版本过旧，可能无法正确理解 Go 程序的调试信息，导致无法打印变量、查看堆栈等问题。
   * **例如:**  旧版本的 GDB 可能不支持 Go 语言特定的数据结构或调试信息格式。

2. **没有加载 Go 的 GDB 辅助脚本 (`runtime-gdb.py`):**  Go 的 GDB 辅助脚本提供了很多方便的命令和功能，例如打印 goroutine 信息。如果没有加载这个脚本，很多高级的 Go 调试功能将无法使用。
   * **例如:**  用户可能会尝试使用 `info goroutines` 命令，但如果脚本没有加载，GDB 将无法识别该命令。

3. **在不适合的平台上使用 GDB:**  在某些操作系统或架构上，GDB 可能存在已知的问题，导致调试不稳定或无法正常工作。
   * **例如:**  代码中 `checkGdbEnvironment` 函数会跳过在 Darwin (macOS) 上运行 GDB 测试。

4. **`ptrace_scope` 限制 (Linux):**  在 Linux 系统上，如果 `ptrace_scope` 设置为较高的值，普通用户可能无法使用 GDB 附加到 Go 进程。
   * **例如:**  如果 `ptrace_scope` 为 1 或更高，非特权用户尝试使用 GDB 附加到另一个进程可能会遇到 "Operation not permitted" 错误。

5. **误解 GDB 命令或 Go 的运行时机制:**  不熟悉 GDB 命令或者对 Go 的 goroutine、channel 等概念理解不足，可能导致调试时出现困惑或得到错误的结论。
   * **例如:**  用户可能不清楚 `goroutine <n> bt` 命令是用来查看特定 goroutine 的堆栈，而不是整个程序的堆栈。

这段测试代码通过自动化地检查 GDB 在各种场景下的行为，确保了 Go 语言的调试体验的质量和一致性。它模拟了用户在使用 GDB 调试 Go 程序时可能遇到的情况，并验证了 GDB 是否能够提供正确的调试信息。

Prompt: 
```
这是路径为go/src/runtime/runtime-gdb_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"bytes"
	"flag"
	"fmt"
	"internal/abi"
	"internal/goexperiment"
	"internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// NOTE: In some configurations, GDB will segfault when sent a SIGWINCH signal.
// Some runtime tests send SIGWINCH to the entire process group, so those tests
// must never run in parallel with GDB tests.
//
// See issue 39021 and https://sourceware.org/bugzilla/show_bug.cgi?id=26056.

func checkGdbEnvironment(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	switch runtime.GOOS {
	case "darwin":
		t.Skip("gdb does not work on darwin")
	case "netbsd":
		t.Skip("gdb does not work with threads on NetBSD; see https://golang.org/issue/22893 and https://gnats.netbsd.org/52548")
	case "linux":
		if runtime.GOARCH == "ppc64" {
			t.Skip("skipping gdb tests on linux/ppc64; see https://golang.org/issue/17366")
		}
		if runtime.GOARCH == "mips" {
			t.Skip("skipping gdb tests on linux/mips; see https://golang.org/issue/25939")
		}
		// Disable GDB tests on alpine until issue #54352 resolved.
		if strings.HasSuffix(testenv.Builder(), "-alpine") {
			t.Skip("skipping gdb tests on alpine; see https://golang.org/issue/54352")
		}
	case "freebsd":
		t.Skip("skipping gdb tests on FreeBSD; see https://golang.org/issue/29508")
	case "aix":
		if testing.Short() {
			t.Skip("skipping gdb tests on AIX; see https://golang.org/issue/35710")
		}
	case "plan9":
		t.Skip("there is no gdb on Plan 9")
	}
}

func checkGdbVersion(t *testing.T) {
	// Issue 11214 reports various failures with older versions of gdb.
	out, err := exec.Command("gdb", "--version").CombinedOutput()
	if err != nil {
		t.Skipf("skipping: error executing gdb: %v", err)
	}
	re := regexp.MustCompile(`([0-9]+)\.([0-9]+)`)
	matches := re.FindSubmatch(out)
	if len(matches) < 3 {
		t.Skipf("skipping: can't determine gdb version from\n%s\n", out)
	}
	major, err1 := strconv.Atoi(string(matches[1]))
	minor, err2 := strconv.Atoi(string(matches[2]))
	if err1 != nil || err2 != nil {
		t.Skipf("skipping: can't determine gdb version: %v, %v", err1, err2)
	}
	if major < 7 || (major == 7 && minor < 7) {
		t.Skipf("skipping: gdb version %d.%d too old", major, minor)
	}
	t.Logf("gdb version %d.%d", major, minor)
}

func checkGdbPython(t *testing.T) {
	if runtime.GOOS == "solaris" || runtime.GOOS == "illumos" {
		t.Skip("skipping gdb python tests on illumos and solaris; see golang.org/issue/20821")
	}
	args := []string{"-nx", "-q", "--batch", "-iex", "python import sys; print('go gdb python support')"}
	gdbArgsFixup(args)
	cmd := exec.Command("gdb", args...)
	out, err := cmd.CombinedOutput()

	if err != nil {
		t.Skipf("skipping due to issue running gdb: %v", err)
	}
	if strings.TrimSpace(string(out)) != "go gdb python support" {
		t.Skipf("skipping due to lack of python gdb support: %s", out)
	}
}

// checkCleanBacktrace checks that the given backtrace is well formed and does
// not contain any error messages from GDB.
func checkCleanBacktrace(t *testing.T, backtrace string) {
	backtrace = strings.TrimSpace(backtrace)
	lines := strings.Split(backtrace, "\n")
	if len(lines) == 0 {
		t.Fatalf("empty backtrace")
	}
	for i, l := range lines {
		if !strings.HasPrefix(l, fmt.Sprintf("#%v  ", i)) {
			t.Fatalf("malformed backtrace at line %v: %v", i, l)
		}
	}
	// TODO(mundaym): check for unknown frames (e.g. "??").
}

// checkPtraceScope checks the value of the kernel parameter ptrace_scope,
// skips the test when gdb cannot attach to the target process via ptrace.
// See issue 69932
//
// 0 - Default attach security permissions.
// 1 - Restricted attach. Only child processes plus normal permissions.
// 2 - Admin-only attach. Only executables with CAP_SYS_PTRACE.
// 3 - No attach. No process may call ptrace at all. Irrevocable.
func checkPtraceScope(t *testing.T) {
	if runtime.GOOS != "linux" {
		return
	}

	// If the Linux kernel does not have the YAMA module enabled,
	// there will be no ptrace_scope file, which does not affect the tests.
	path := "/proc/sys/kernel/yama/ptrace_scope"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("failed converting value to int: %v", err)
	}
	switch value {
	case 3:
		t.Skip("skipping ptrace: Operation not permitted")
	case 2:
		if os.Geteuid() != 0 {
			t.Skip("skipping ptrace: Operation not permitted with non-root user")
		}
	}
}

// NOTE: the maps below are allocated larger than abi.MapBucketCount
// to ensure that they are not "optimized out".

var helloSource = `
import "fmt"
import "runtime"
var gslice []string
// TODO(prattmic): Stack allocated maps initialized inline appear "optimized out" in GDB.
var smallmapvar map[string]string
func main() {
	smallmapvar = make(map[string]string)
	mapvar := make(map[string]string, ` + strconv.FormatInt(abi.OldMapBucketCount+9, 10) + `)
	slicemap := make(map[string][]string,` + strconv.FormatInt(abi.OldMapBucketCount+3, 10) + `)
    chanint := make(chan int, 10)
    chanstr := make(chan string, 10)
    chanint <- 99
	chanint <- 11
    chanstr <- "spongepants"
    chanstr <- "squarebob"
	smallmapvar["abc"] = "def"
	mapvar["abc"] = "def"
	mapvar["ghi"] = "jkl"
	slicemap["a"] = []string{"b","c","d"}
    slicemap["e"] = []string{"f","g","h"}
	strvar := "abc"
	ptrvar := &strvar
	slicevar := make([]string, 0, 16)
	slicevar = append(slicevar, mapvar["abc"])
	fmt.Println("hi")
	runtime.KeepAlive(ptrvar)
	_ = ptrvar // set breakpoint here
	gslice = slicevar
	fmt.Printf("%v, %v, %v\n", slicemap, <-chanint, <-chanstr)
	runtime.KeepAlive(smallmapvar)
	runtime.KeepAlive(mapvar)
}  // END_OF_PROGRAM
`

func lastLine(src []byte) int {
	eop := []byte("END_OF_PROGRAM")
	for i, l := range bytes.Split(src, []byte("\n")) {
		if bytes.Contains(l, eop) {
			return i
		}
	}
	return 0
}

func gdbArgsFixup(args []string) {
	if runtime.GOOS != "windows" {
		return
	}
	// On Windows, some gdb flavors expect -ex and -iex arguments
	// containing spaces to be double quoted.
	var quote bool
	for i, arg := range args {
		if arg == "-iex" || arg == "-ex" {
			quote = true
		} else if quote {
			if strings.ContainsRune(arg, ' ') {
				args[i] = `"` + arg + `"`
			}
			quote = false
		}
	}
}

func TestGdbPython(t *testing.T) {
	testGdbPython(t, false)
}

func TestGdbPythonCgo(t *testing.T) {
	if strings.HasPrefix(runtime.GOARCH, "mips") {
		testenv.SkipFlaky(t, 37794)
	}
	testGdbPython(t, true)
}

func testGdbPython(t *testing.T, cgo bool) {
	if cgo {
		testenv.MustHaveCGO(t)
	}

	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)
	checkGdbPython(t)
	checkPtraceScope(t)

	dir := t.TempDir()

	var buf bytes.Buffer
	buf.WriteString("package main\n")
	if cgo {
		buf.WriteString(`import "C"` + "\n")
	}
	buf.WriteString(helloSource)

	src := buf.Bytes()

	// Locate breakpoint line
	var bp int
	lines := bytes.Split(src, []byte("\n"))
	for i, line := range lines {
		if bytes.Contains(line, []byte("breakpoint")) {
			bp = i
			break
		}
	}

	err := os.WriteFile(filepath.Join(dir, "main.go"), src, 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	nLines := lastLine(src)

	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	args := []string{"-nx", "-q", "--batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "set startup-with-shell off",
		"-ex", "set print thread-events off",
	}
	if cgo {
		// When we build the cgo version of the program, the system's
		// linker is used. Some external linkers, like GNU gold,
		// compress the .debug_gdb_scripts into .zdebug_gdb_scripts.
		// Until gold and gdb can work together, temporarily load the
		// python script directly.
		args = append(args,
			"-ex", "source "+filepath.Join(testenv.GOROOT(t), "src", "runtime", "runtime-gdb.py"),
		)
	} else {
		args = append(args,
			"-ex", "info auto-load python-scripts",
		)
	}
	args = append(args,
		"-ex", "set python print-stack full",
		"-ex", fmt.Sprintf("br main.go:%d", bp),
		"-ex", "run",
		"-ex", "echo BEGIN info goroutines\n",
		"-ex", "info goroutines",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN print smallmapvar\n",
		"-ex", "print smallmapvar",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN print mapvar\n",
		"-ex", "print mapvar",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN print slicemap\n",
		"-ex", "print slicemap",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN print strvar\n",
		"-ex", "print strvar",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN print chanint\n",
		"-ex", "print chanint",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN print chanstr\n",
		"-ex", "print chanstr",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN info locals\n",
		"-ex", "info locals",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN goroutine 1 bt\n",
		"-ex", "goroutine 1 bt",
		"-ex", "echo END\n",
		"-ex", "echo BEGIN goroutine all bt\n",
		"-ex", "goroutine all bt",
		"-ex", "echo END\n",
		"-ex", "clear main.go:15", // clear the previous break point
		"-ex", fmt.Sprintf("br main.go:%d", nLines), // new break point at the end of main
		"-ex", "c",
		"-ex", "echo BEGIN goroutine 1 bt at the end\n",
		"-ex", "goroutine 1 bt",
		"-ex", "echo END\n",
		filepath.Join(dir, "a.exe"),
	)
	gdbArgsFixup(args)
	got, err := exec.Command("gdb", args...).CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")) // normalize line endings
	// Extract named BEGIN...END blocks from output
	partRe := regexp.MustCompile(`(?ms)^BEGIN ([^\n]*)\n(.*?)\nEND`)
	blocks := map[string]string{}
	for _, subs := range partRe.FindAllSubmatch(got, -1) {
		blocks[string(subs[1])] = string(subs[2])
	}

	infoGoroutinesRe := regexp.MustCompile(`\*\s+\d+\s+running\s+`)
	if bl := blocks["info goroutines"]; !infoGoroutinesRe.MatchString(bl) {
		t.Fatalf("info goroutines failed: %s", bl)
	}

	printSmallMapvarRe := regexp.MustCompile(`^\$[0-9]+ = map\[string\]string = {\[(0x[0-9a-f]+\s+)?"abc"\] = (0x[0-9a-f]+\s+)?"def"}$`)
	if bl := blocks["print smallmapvar"]; !printSmallMapvarRe.MatchString(bl) {
		t.Fatalf("print smallmapvar failed: %s", bl)
	}

	printMapvarRe1 := regexp.MustCompile(`^\$[0-9]+ = map\[string\]string = {\[(0x[0-9a-f]+\s+)?"abc"\] = (0x[0-9a-f]+\s+)?"def", \[(0x[0-9a-f]+\s+)?"ghi"\] = (0x[0-9a-f]+\s+)?"jkl"}$`)
	printMapvarRe2 := regexp.MustCompile(`^\$[0-9]+ = map\[string\]string = {\[(0x[0-9a-f]+\s+)?"ghi"\] = (0x[0-9a-f]+\s+)?"jkl", \[(0x[0-9a-f]+\s+)?"abc"\] = (0x[0-9a-f]+\s+)?"def"}$`)
	if bl := blocks["print mapvar"]; !printMapvarRe1.MatchString(bl) &&
		!printMapvarRe2.MatchString(bl) {
		t.Fatalf("print mapvar failed: %s", bl)
	}

	// 2 orders, and possible differences in spacing.
	sliceMapSfx1 := `map[string][]string = {["e"] = []string = {"f", "g", "h"}, ["a"] = []string = {"b", "c", "d"}}`
	sliceMapSfx2 := `map[string][]string = {["a"] = []string = {"b", "c", "d"}, ["e"] = []string = {"f", "g", "h"}}`
	if bl := strings.ReplaceAll(blocks["print slicemap"], "  ", " "); !strings.HasSuffix(bl, sliceMapSfx1) && !strings.HasSuffix(bl, sliceMapSfx2) {
		t.Fatalf("print slicemap failed: %s", bl)
	}

	chanIntSfx := `chan int = {99, 11}`
	if bl := strings.ReplaceAll(blocks["print chanint"], "  ", " "); !strings.HasSuffix(bl, chanIntSfx) {
		t.Fatalf("print chanint failed: %s", bl)
	}

	chanStrSfx := `chan string = {"spongepants", "squarebob"}`
	if bl := strings.ReplaceAll(blocks["print chanstr"], "  ", " "); !strings.HasSuffix(bl, chanStrSfx) {
		t.Fatalf("print chanstr failed: %s", bl)
	}

	strVarRe := regexp.MustCompile(`^\$[0-9]+ = (0x[0-9a-f]+\s+)?"abc"$`)
	if bl := blocks["print strvar"]; !strVarRe.MatchString(bl) {
		t.Fatalf("print strvar failed: %s", bl)
	}

	// The exact format of composite values has changed over time.
	// For issue 16338: ssa decompose phase split a slice into
	// a collection of scalar vars holding its fields. In such cases
	// the DWARF variable location expression should be of the
	// form "var.field" and not just "field".
	// However, the newer dwarf location list code reconstituted
	// aggregates from their fields and reverted their printing
	// back to its original form.
	// Only test that all variables are listed in 'info locals' since
	// different versions of gdb print variables in different
	// order and with differing amount of information and formats.

	if bl := blocks["info locals"]; !strings.Contains(bl, "slicevar") ||
		!strings.Contains(bl, "mapvar") ||
		!strings.Contains(bl, "strvar") {
		t.Fatalf("info locals failed: %s", bl)
	}

	// Check that the backtraces are well formed.
	checkCleanBacktrace(t, blocks["goroutine 1 bt"])
	checkCleanBacktrace(t, blocks["goroutine 1 bt at the end"])

	btGoroutine1Re := regexp.MustCompile(`(?m)^#0\s+(0x[0-9a-f]+\s+in\s+)?main\.main.+at`)
	if bl := blocks["goroutine 1 bt"]; !btGoroutine1Re.MatchString(bl) {
		t.Fatalf("goroutine 1 bt failed: %s", bl)
	}

	if bl := blocks["goroutine all bt"]; !btGoroutine1Re.MatchString(bl) {
		t.Fatalf("goroutine all bt failed: %s", bl)
	}

	btGoroutine1AtTheEndRe := regexp.MustCompile(`(?m)^#0\s+(0x[0-9a-f]+\s+in\s+)?main\.main.+at`)
	if bl := blocks["goroutine 1 bt at the end"]; !btGoroutine1AtTheEndRe.MatchString(bl) {
		t.Fatalf("goroutine 1 bt at the end failed: %s", bl)
	}
}

const backtraceSource = `
package main

//go:noinline
func aaa() bool { return bbb() }

//go:noinline
func bbb() bool { return ccc() }

//go:noinline
func ccc() bool { return ddd() }

//go:noinline
func ddd() bool { return f() }

//go:noinline
func eee() bool { return true }

var f = eee

func main() {
	_ = aaa()
}
`

// TestGdbBacktrace tests that gdb can unwind the stack correctly
// using only the DWARF debug info.
func TestGdbBacktrace(t *testing.T) {
	if runtime.GOOS == "netbsd" {
		testenv.SkipFlaky(t, 15603)
	}
	if flag.Lookup("test.parallel").Value.(flag.Getter).Get().(int) < 2 {
		// It is possible that this test will hang for a long time due to an
		// apparent GDB bug reported in https://go.dev/issue/37405.
		// If test parallelism is high enough, that might be ok: the other parallel
		// tests will finish, and then this test will finish right before it would
		// time out. However, if test are running sequentially, a hang in this test
		// would likely cause the remaining tests to run out of time.
		testenv.SkipFlaky(t, 37405)
	}

	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)
	checkPtraceScope(t)

	dir := t.TempDir()

	// Build the source code.
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(backtraceSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	// Execute gdb commands.
	start := time.Now()
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "set startup-with-shell off",
		"-ex", "break main.eee",
		"-ex", "run",
		"-ex", "backtrace",
		"-ex", "continue",
		filepath.Join(dir, "a.exe"),
	}
	gdbArgsFixup(args)
	cmd = testenv.Command(t, "gdb", args...)

	// Work around the GDB hang reported in https://go.dev/issue/37405.
	// Sometimes (rarely), the GDB process hangs completely when the Go program
	// exits, and we suspect that the bug is on the GDB side.
	//
	// The default Cancel function added by testenv.Command will mark the test as
	// failed if it is in danger of timing out, but we want to instead mark it as
	// skipped. Change the Cancel function to kill the process and merely log
	// instead of failing the test.
	//
	// (This approach does not scale: if the test parallelism is less than or
	// equal to the number of tests that run right up to the deadline, then the
	// remaining parallel tests are likely to time out. But as long as it's just
	// this one flaky test, it's probably fine..?)
	//
	// If there is no deadline set on the test at all, relying on the timeout set
	// by testenv.Command will cause the test to hang indefinitely, but that's
	// what “no deadline” means, after all — and it's probably the right behavior
	// anyway if someone is trying to investigate and fix the GDB bug.
	cmd.Cancel = func() error {
		t.Logf("GDB command timed out after %v: %v", time.Since(start), cmd)
		return cmd.Process.Kill()
	}

	got, err := cmd.CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		switch {
		case bytes.Contains(got, []byte("internal-error: wait returned unexpected status 0x0")):
			// GDB bug: https://sourceware.org/bugzilla/show_bug.cgi?id=28551
			testenv.SkipFlaky(t, 43068)
		case bytes.Contains(got, []byte("Couldn't get registers: No such process.")),
			bytes.Contains(got, []byte("Unable to fetch general registers.: No such process.")),
			bytes.Contains(got, []byte("reading register pc (#64): No such process.")):
			// GDB bug: https://sourceware.org/bugzilla/show_bug.cgi?id=9086
			testenv.SkipFlaky(t, 50838)
		case bytes.Contains(got, []byte("waiting for new child: No child processes.")):
			// GDB bug: Sometimes it fails to wait for a clone child.
			testenv.SkipFlaky(t, 60553)
		case bytes.Contains(got, []byte(" exited normally]\n")):
			// GDB bug: Sometimes the inferior exits fine,
			// but then GDB hangs.
			testenv.SkipFlaky(t, 37405)
		}
		t.Fatalf("gdb exited with error: %v", err)
	}

	// Check that the backtrace matches the source code.
	bt := []string{
		"eee",
		"ddd",
		"ccc",
		"bbb",
		"aaa",
		"main",
	}
	for i, name := range bt {
		s := fmt.Sprintf("#%v.*main\\.%v", i, name)
		re := regexp.MustCompile(s)
		if found := re.Find(got) != nil; !found {
			t.Fatalf("could not find '%v' in backtrace", s)
		}
	}
}

const autotmpTypeSource = `
package main

type astruct struct {
	a, b int
}

func main() {
	var iface interface{} = map[string]astruct{}
	var iface2 interface{} = []astruct{}
	println(iface, iface2)
}
`

// TestGdbAutotmpTypes ensures that types of autotmp variables appear in .debug_info
// See bug #17830.
func TestGdbAutotmpTypes(t *testing.T) {
	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)
	checkPtraceScope(t)

	if runtime.GOOS == "aix" && testing.Short() {
		t.Skip("TestGdbAutotmpTypes is too slow on aix/ppc64")
	}

	dir := t.TempDir()

	// Build the source code.
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(autotmpTypeSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-gcflags=all=-N -l", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	// Execute gdb commands.
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "set startup-with-shell off",
		// Some gdb may set scheduling-locking as "step" by default. This prevents background tasks
		// (e.g GC) from completing which may result in a hang when executing the step command.
		// See #49852.
		"-ex", "set scheduler-locking off",
		"-ex", "break main.main",
		"-ex", "run",
		"-ex", "step",
		"-ex", "info types astruct",
		filepath.Join(dir, "a.exe"),
	}
	gdbArgsFixup(args)
	got, err := exec.Command("gdb", args...).CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	sgot := string(got)

	// Check that the backtrace matches the source code.
	types := []string{
		"[]main.astruct",
		"main.astruct",
	}
	if goexperiment.SwissMap {
		types = append(types, []string{
			"groupReference<string,main.astruct>",
			"table<string,main.astruct>",
			"map<string,main.astruct>",
			"map<string,main.astruct> * map[string]main.astruct",
		}...)
	} else {
		types = append(types, []string{
			"bucket<string,main.astruct>",
			"hash<string,main.astruct>",
			"hash<string,main.astruct> * map[string]main.astruct",
		}...)
	}
	for _, name := range types {
		if !strings.Contains(sgot, name) {
			t.Fatalf("could not find %q in 'info typrs astruct' output", name)
		}
	}
}

const constsSource = `
package main

const aConstant int = 42
const largeConstant uint64 = ^uint64(0)
const minusOne int64 = -1

func main() {
	println("hello world")
}
`

func TestGdbConst(t *testing.T) {
	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)
	checkPtraceScope(t)

	dir := t.TempDir()

	// Build the source code.
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(constsSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-gcflags=all=-N -l", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	// Execute gdb commands.
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "set startup-with-shell off",
		"-ex", "break main.main",
		"-ex", "run",
		"-ex", "print main.aConstant",
		"-ex", "print main.largeConstant",
		"-ex", "print main.minusOne",
		"-ex", "print 'runtime.mSpanInUse'",
		"-ex", "print 'runtime._PageSize'",
		filepath.Join(dir, "a.exe"),
	}
	gdbArgsFixup(args)
	got, err := exec.Command("gdb", args...).CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	sgot := strings.ReplaceAll(string(got), "\r\n", "\n")

	if !strings.Contains(sgot, "\n$1 = 42\n$2 = 18446744073709551615\n$3 = -1\n$4 = 1 '\\001'\n$5 = 8192") {
		t.Fatalf("output mismatch")
	}
}

const panicSource = `
package main

import "runtime/debug"

func main() {
	debug.SetTraceback("crash")
	crash()
}

func crash() {
	panic("panic!")
}
`

// TestGdbPanic tests that gdb can unwind the stack correctly
// from SIGABRTs from Go panics.
func TestGdbPanic(t *testing.T) {
	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)
	checkPtraceScope(t)

	if runtime.GOOS == "windows" {
		t.Skip("no signals on windows")
	}

	dir := t.TempDir()

	// Build the source code.
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(panicSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	// Execute gdb commands.
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "set startup-with-shell off",
		"-ex", "run",
		"-ex", "backtrace",
		filepath.Join(dir, "a.exe"),
	}
	gdbArgsFixup(args)
	got, err := exec.Command("gdb", args...).CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	// Check that the backtrace matches the source code.
	bt := []string{
		`crash`,
		`main`,
	}
	for _, name := range bt {
		s := fmt.Sprintf("(#.* .* in )?main\\.%v", name)
		re := regexp.MustCompile(s)
		if found := re.Find(got) != nil; !found {
			t.Fatalf("could not find '%v' in backtrace", s)
		}
	}
}

const InfCallstackSource = `
package main
import "C"
import "time"

func loop() {
        for i := 0; i < 1000; i++ {
                time.Sleep(time.Millisecond*5)
        }
}

func main() {
        go loop()
        time.Sleep(time.Second * 1)
}
`

// TestGdbInfCallstack tests that gdb can unwind the callstack of cgo programs
// on arm64 platforms without endless frames of function 'crossfunc1'.
// https://golang.org/issue/37238
func TestGdbInfCallstack(t *testing.T) {
	checkGdbEnvironment(t)

	testenv.MustHaveCGO(t)
	if runtime.GOARCH != "arm64" {
		t.Skip("skipping infinite callstack test on non-arm64 arches")
	}

	t.Parallel()
	checkGdbVersion(t)
	checkPtraceScope(t)

	dir := t.TempDir()

	// Build the source code.
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(InfCallstackSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	// Execute gdb commands.
	// 'setg_gcc' is the first point where we can reproduce the issue with just one 'run' command.
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "set startup-with-shell off",
		"-ex", "break setg_gcc",
		"-ex", "run",
		"-ex", "backtrace 3",
		"-ex", "disable 1",
		"-ex", "continue",
		filepath.Join(dir, "a.exe"),
	}
	gdbArgsFixup(args)
	got, err := exec.Command("gdb", args...).CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	// Check that the backtrace matches
	// We check the 3 inner most frames only as they are present certainly, according to gcc_<OS>_arm64.c
	bt := []string{
		`setg_gcc`,
		`crosscall1`,
		`threadentry`,
	}
	for i, name := range bt {
		s := fmt.Sprintf("#%v.*%v", i, name)
		re := regexp.MustCompile(s)
		if found := re.Find(got) != nil; !found {
			t.Fatalf("could not find '%v' in backtrace", s)
		}
	}
}

"""



```