Response:
Let's break down the thought process for analyzing the Go code and fulfilling the request.

1. **Understand the Goal:** The core purpose of this code is to test GDB's ability to debug Go programs that have crashed and generated core dumps, specifically focusing on signal handling and crashes within C code called by Go.

2. **Identify Key Functions and Tests:**  Scan the code for function definitions, especially those starting with `Test...`. This immediately reveals the two main tests: `TestGdbCoreSignalBacktrace` and `TestGdbCoreCrashThreadBacktrace`. The function `canGenerateCore` appears to be a helper.

3. **Analyze `canGenerateCore`:**
   - Reads `/proc/sys/kernel/core_pattern` and `/proc/sys/kernel/core_uses_pid`.
   - Checks if core dumps are enabled and if the filename includes the PID.
   - This suggests the test environment needs to be configured correctly for core dumps.

4. **Analyze `TestGdbCoreSignalBacktrace`:**
   - **Setup:** Creates a temporary directory, writes a Go source file (`coreSignalSource`), and builds it. Crucially, it uses a pipe for communication with the child process.
   - **Child Process:** The `coreSignalSource` program sets `RLIMIT_CORE` to its maximum, indicating it intends to create a core dump upon crashing. It also closes a file descriptor passed via command-line argument – this is the synchronization mechanism.
   - **Triggering the Crash:**  The parent process signals the child process with `SIGABRT`, causing a controlled crash.
   - **Verification:** The parent process waits for the child to exit with `SIGABRT` and confirms a core dump was generated. It then uses `gdb` to analyze the core dump.
   - **GDB Interaction:** The `gdb` commands include setting an auto-load safe path for runtime symbols and requesting a backtrace.
   - **Backtrace Analysis:** The test uses regular expressions to verify the backtrace contains key elements like `runtime.sigtramp` (signal handler) and evidence of execution before and after the signal.
   - **Key Insight:** This test verifies GDB's ability to follow the execution flow through a signal handler in a core dump.

5. **Analyze `TestGdbCoreCrashThreadBacktrace`:**
   - **Setup:** Similar to the previous test, but the Go source file (`coreCrashThreadSource`) is different. It also uses `testenv.MustHaveCGO`, indicating interaction with C code.
   - **Child Process:** The `coreCrashThreadSource` program calls a C function `trigger_crash`, which deliberately dereferences a null pointer, causing a crash.
   - **Triggering the Crash:** The crash is triggered by the C code itself.
   - **Verification:** Similar to the previous test, it verifies the child exits with `SIGABRT` and a core dump is generated. `gdb` is used to analyze the core dump.
   - **GDB Interaction:** The `gdb` commands are the same as before.
   - **Backtrace Analysis:** The test verifies the backtrace contains `trigger_crash`, confirming GDB can pinpoint the crash location within the C code.
   - **Key Insight:** This test verifies GDB's ability to debug core dumps when the crash originates in C code called by Go.

6. **Identify Go Features Tested:** Based on the analysis, the key Go features being tested are:
   - **Signal Handling:**  `TestGdbCoreSignalBacktrace` explicitly tests this.
   - **Cgo:** `TestGdbCoreCrashThreadBacktrace` uses Cgo.
   - **Core Dumps:** Both tests rely on the ability to generate and analyze core dumps.
   - **Runtime Debugging Information:** The `-iex add-auto-load-safe-path` option highlights the importance of runtime debug symbols for GDB.

7. **Construct Go Code Examples:**  Create minimal Go examples illustrating the features being tested. This involves demonstrating signal handling with `signal.Notify` and Cgo with a simple C function call.

8. **Infer Command Line Arguments:** The `-pipe-fd` flag in `coreSignalSource` is the only explicit command-line argument being used. Explain its purpose in the synchronization logic.

9. **Identify Potential Pitfalls:**  Think about common errors when working with core dumps and GDB:
   - Incorrect core dump configuration (permissions, pattern).
   - Missing debug symbols.
   - GDB version incompatibility.

10. **Structure the Answer:** Organize the findings logically, addressing each point in the request: function description, feature identification, code examples, command-line arguments, and common mistakes. Use clear and concise language in Chinese.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus solely on the `gdb` commands.
* **Correction:** Realize the importance of the setup steps, especially the core dump generation and the interaction with the child process.
* **Initial thought:** Describe each line of code individually.
* **Correction:**  Focus on the overall functionality and the purpose of different code blocks.
* **Initial thought:** Assume the user has deep Go and GDB knowledge.
* **Correction:** Explain concepts clearly, even if they seem basic.
* **Initial thought:**  Provide very complex code examples.
* **Correction:** Simplify the examples to highlight the specific features being demonstrated.

By following this process, systematically analyzing the code, and refining the understanding, a comprehensive and accurate answer can be generated.
这是一个 Go 语言测试文件，路径为 `go/src/runtime/runtime-gdb_unix_test.go`。从文件名和内容来看，它的主要功能是**测试 GDB (GNU Debugger) 在 Unix 系统上调试 Go 运行时 (runtime) 时，处理核心转储 (core dump) 的能力，特别是涉及到信号处理和 Cgo 调用的场景**。

下面分别列举其功能并进行详细说明：

**1. 功能列举:**

* **`canGenerateCore(t *testing.T) bool`:**  检查当前系统环境是否能够生成 core dump。它会检查 `RLIMIT_CORE` 资源限制是否足够大，以及 `/proc/sys/kernel/core_pattern` 和 `/proc/sys/kernel/core_uses_pid` 的配置是否允许在当前目录下生成带有或不带进程 ID 的 `core` 文件。
* **`TestGdbCoreSignalBacktrace(t *testing.T)`:**  测试 GDB 是否能够正确地回溯通过信号处理程序的堆栈信息。这个测试会启动一个子进程，该子进程设置了允许生成 core dump 的资源限制，然后通过管道通知父进程它已准备就绪。父进程随后向子进程发送 `SIGABRT` 信号使其崩溃并生成 core dump。最后，父进程使用 GDB 加载可执行文件和 core dump 文件，执行 `backtrace` 命令，并检查输出是否包含预期的信号处理程序相关的堆栈帧。
* **`TestGdbCoreCrashThreadBacktrace(t *testing.T)`:** 测试当程序在 Cgo 调用的线程中崩溃时，GDB 是否能够正确地显示崩溃线程的堆栈信息。这个测试会启动一个子进程，该子进程调用一个会触发段错误的 C 函数。程序崩溃后，父进程使用 GDB 加载可执行文件和 core dump 文件，执行 `backtrace` 命令，并检查输出是否包含触发崩溃的 C 函数的堆栈帧。

**2. Go 语言功能实现推理与代码示例:**

这两个测试主要验证 Go 运行时在处理信号和与 C 代码交互时，调试信息的正确性，以便 GDB 能够有效地分析 core dump。涉及的 Go 语言功能包括：

* **信号处理 (Signal Handling):** `TestGdbCoreSignalBacktrace` 显式地测试了当 Go 程序接收到信号时的堆栈信息。Go 的 `runtime` 包负责处理这些信号。

   ```go
   package main

   import (
       "fmt"
       "os"
       "os/signal"
       "syscall"
   )

   func main() {
       // 接收 SIGINT 信号
       c := make(chan os.Signal, 1)
       signal.Notify(c, os.Interrupt, syscall.SIGTERM)
       go func() {
           s := <-c
           fmt.Println("收到信号:", s)
           // 在实际运行时，这里可能会触发 panic 或调用 os.Exit
           panic("程序退出")
       }()

       // 模拟程序运行
       fmt.Println("程序运行中...")
       select {} // 阻塞主 goroutine
   }
   ```

   **假设输入:** 运行上述代码，并在运行时按下 `Ctrl+C` 发送 `SIGINT` 信号。

   **预期输出:** 程序会打印 "收到信号: interrupt"，然后由于 `panic` 导致程序终止。如果生成了 core dump，GDB 应该能够显示 `panic` 时的堆栈信息。

* **Cgo:** `TestGdbCoreCrashThreadBacktrace` 测试了与 C 代码的交互。Go 允许调用 C 代码，这通过 `import "C"` 和特殊的注释来实现。

   ```go
   package main

   /*
   #include <stdio.h>
   void hello_from_c() {
       printf("Hello from C!\n");
   }
   */
   import "C"

   import "fmt"

   func main() {
       fmt.Println("Calling C function...")
       C.hello_from_c()
       fmt.Println("C function returned.")
   }
   ```

   **假设输入:** 运行上述代码。

   **预期输出:**
   ```
   Calling C function...
   Hello from C!
   C function returned.
   ```

   在 `TestGdbCoreCrashThreadBacktrace` 中，C 代码故意触发了一个段错误，目的是测试 GDB 能否定位到 core dump 中 C 代码的崩溃位置。

* **核心转储 (Core Dump):** 这两个测试都依赖于系统生成核心转储文件的能力。Go 运行时本身并不直接负责生成 core dump，而是依赖于操作系统的机制。测试代码通过设置 `RLIMIT_CORE` 来确保可以生成足够大的 core dump。

**3. 命令行参数的具体处理:**

在 `TestGdbCoreSignalBacktrace` 中，被测试的子进程（通过 `coreSignalSource` 生成）使用了以下命令行参数：

* **`-pipe-fd`:**  这个参数指定了一个文件描述符，用于父子进程之间的同步。父进程创建了一个管道，并将写端的文件描述符作为这个参数传递给子进程。子进程启动后，会立即关闭这个文件描述符，父进程通过读取管道来等待子进程准备就绪。

   ```go
   var pipeFD = flag.Int("pipe-fd", -1, "FD of write end of control pipe")

   func main() {
       flag.Parse()
       // ...
       if err := syscall.Close(*pipeFD); err != nil {
           panic(fmt.Sprintf("error closing control pipe fd %d: %v", *pipeFD, err))
       }
       // ...
   }
   ```

   父进程启动子进程的代码片段：

   ```go
   cmd = testenv.Command(t, "./a.exe", "-pipe-fd=3") // 假设文件描述符 3 是管道的写端
   cmd.Dir = dir
   cmd.ExtraFiles = []*os.File{w} // 将管道的写端添加到子进程的额外文件描述符中
   ```

   这里使用文件描述符 3 是因为标准输入、标准输出和标准错误分别占用了 0、1 和 2。

**4. 使用者易犯错的点:**

* **核心转储未启用或配置不当:**  用户可能在没有启用核心转储或者核心转储文件生成位置/命名规则与测试预期不符的情况下运行测试，导致测试失败。例如，`core_pattern` 可能配置为将 core 文件保存到其他目录或使用不同的命名规则，或者 `core_uses_pid` 的设置与测试期望不一致。
* **`RLIMIT_CORE` 设置过小:** 如果系统的 `RLIMIT_CORE` 限制设置得太小，可能无法生成包含足够调试信息的完整 core dump，从而影响 GDB 的分析。测试代码中会检查这个限制，如果太小则会跳过测试。
* **缺少调试符号:** GDB 需要程序的调试符号才能进行有效的回溯。如果构建可执行文件时没有包含调试信息（例如，使用 `-ldflags="-s -w"`），GDB 可能无法正确显示函数名和行号。测试代码通过 `add-auto-load-safe-path` 来指定 runtime 的符号文件路径。
* **GDB 版本不兼容:**  不同版本的 GDB 在处理 Go 语言的 core dump 时可能存在差异。测试代码中使用了 `checkGdbVersion(t)` 来检查 GDB 版本。
* **Cgo 环境未配置:** 对于 `TestGdbCoreCrashThreadBacktrace`，如果 Cgo 环境没有正确配置（例如，缺少必要的编译器或链接器），程序可能无法构建或运行。测试代码使用了 `testenv.MustHaveCGO(t)` 来确保 Cgo 可用。

**示例说明核心转储配置问题:**

假设用户的 `/proc/sys/kernel/core_pattern` 被配置为 `/tmp/core.%e.%p`，这意味着 core 文件会被保存到 `/tmp` 目录下，并且文件名包含可执行文件名和进程 ID。在这种情况下，`TestGdbCoreSignalBacktrace` 中的以下断言将会失败，因为它期望在当前目录下找到名为 `core` 或 `core.<pid>` 的文件：

```go
coreFile := "core"
if coreUsesPID {
    coreFile += fmt.Sprintf(".%d", pid)
}
// ...
args := []string{"-nx", "-batch",
    // ...
    filepath.Join(dir, "a.exe"),
    filepath.Join(dir, coreFile), // 这里假设 core 文件在当前目录
}
```

**总结:**

`go/src/runtime/runtime-gdb_unix_test.go` 是一组重要的集成测试，用于验证 Go 语言运行时在 Unix 系统上生成 core dump 并被 GDB 正确解析的能力，特别是针对信号处理和 Cgo 调用的场景。这些测试确保了 Go 语言的调试工具链在处理复杂崩溃情况下的可靠性。

### 提示词
```
这是路径为go/src/runtime/runtime-gdb_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package runtime_test

import (
	"bytes"
	"fmt"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"testing"
)

func canGenerateCore(t *testing.T) bool {
	// Ensure there is enough RLIMIT_CORE available to generate a full core.
	var lim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim)
	if err != nil {
		t.Fatalf("error getting rlimit: %v", err)
	}
	// Minimum RLIMIT_CORE max to allow. This is a conservative estimate.
	// Most systems allow infinity.
	const minRlimitCore = 100 << 20 // 100 MB
	if lim.Max < minRlimitCore {
		t.Skipf("RLIMIT_CORE max too low: %#+v", lim)
	}

	// Make sure core pattern will send core to the current directory.
	b, err := os.ReadFile("/proc/sys/kernel/core_pattern")
	if err != nil {
		t.Fatalf("error reading core_pattern: %v", err)
	}
	if string(b) != "core\n" {
		t.Skipf("Unexpected core pattern %q", string(b))
	}

	coreUsesPID := false
	b, err = os.ReadFile("/proc/sys/kernel/core_uses_pid")
	if err == nil {
		switch string(bytes.TrimSpace(b)) {
		case "0":
		case "1":
			coreUsesPID = true
		default:
			t.Skipf("unexpected core_uses_pid value %q", string(b))
		}
	}
	return coreUsesPID
}

const coreSignalSource = `
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
)

var pipeFD = flag.Int("pipe-fd", -1, "FD of write end of control pipe")

func enableCore() {
	debug.SetTraceback("crash")

	var lim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim)
	if err != nil {
		panic(fmt.Sprintf("error getting rlimit: %v", err))
	}
	lim.Cur = lim.Max
	fmt.Fprintf(os.Stderr, "Setting RLIMIT_CORE = %+#v\n", lim)
	err = syscall.Setrlimit(syscall.RLIMIT_CORE, &lim)
	if err != nil {
		panic(fmt.Sprintf("error setting rlimit: %v", err))
	}
}

func main() {
	flag.Parse()

	enableCore()

	// Ready to go. Notify parent.
	if err := syscall.Close(*pipeFD); err != nil {
		panic(fmt.Sprintf("error closing control pipe fd %d: %v", *pipeFD, err))
	}

	for {}
}
`

// TestGdbCoreSignalBacktrace tests that gdb can unwind the stack correctly
// through a signal handler in a core file
func TestGdbCoreSignalBacktrace(t *testing.T) {
	if runtime.GOOS != "linux" {
		// N.B. This test isn't fundamentally Linux-only, but it needs
		// to know how to enable/find core files on each OS.
		t.Skip("Test only supported on Linux")
	}
	if runtime.GOARCH != "386" && runtime.GOARCH != "amd64" {
		// TODO(go.dev/issue/25218): Other architectures use sigreturn
		// via VDSO, which we somehow don't handle correctly.
		t.Skip("Backtrace through signal handler only works on 386 and amd64")
	}

	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)

	coreUsesPID := canGenerateCore(t)

	// Build the source code.
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(coreSignalSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("error creating control pipe: %v", err)
	}
	defer r.Close()

	// Start the test binary.
	cmd = testenv.Command(t, "./a.exe", "-pipe-fd=3")
	cmd.Dir = dir
	cmd.ExtraFiles = []*os.File{w}
	var output bytes.Buffer
	cmd.Stdout = &output // for test logging
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("error starting test binary: %v", err)
	}
	w.Close()

	pid := cmd.Process.Pid

	// Wait for child to be ready.
	var buf [1]byte
	if _, err := r.Read(buf[:]); err != io.EOF {
		t.Fatalf("control pipe read get err %v want io.EOF", err)
	}

	// 💥
	if err := cmd.Process.Signal(os.Signal(syscall.SIGABRT)); err != nil {
		t.Fatalf("erroring signaling child: %v", err)
	}

	err = cmd.Wait()
	t.Logf("child output:\n%s", output.String())
	if err == nil {
		t.Fatalf("Wait succeeded, want SIGABRT")
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("Wait err got %T %v, want exec.ExitError", ee, ee)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("Sys got %T %v, want syscall.WaitStatus", ee.Sys(), ee.Sys())
	}
	if ws.Signal() != syscall.SIGABRT {
		t.Fatalf("Signal got %d want SIGABRT", ws.Signal())
	}
	if !ws.CoreDump() {
		t.Fatalf("CoreDump got %v want true", ws.CoreDump())
	}

	coreFile := "core"
	if coreUsesPID {
		coreFile += fmt.Sprintf(".%d", pid)
	}

	// Execute gdb commands.
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "backtrace",
		filepath.Join(dir, "a.exe"),
		filepath.Join(dir, coreFile),
	}
	cmd = testenv.Command(t, "gdb", args...)

	got, err := cmd.CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	// We don't know which thread the fatal signal will land on, but we can still check for basics:
	//
	// 1. A frame in the signal handler: runtime.sigtramp
	// 2. GDB detection of the signal handler: <signal handler called>
	// 3. A frame before the signal handler: this could be foo, or somewhere in the scheduler

	re := regexp.MustCompile(`#.* runtime\.sigtramp `)
	if found := re.Find(got) != nil; !found {
		t.Fatalf("could not find sigtramp in backtrace")
	}

	re = regexp.MustCompile("#.* <signal handler called>")
	loc := re.FindIndex(got)
	if loc == nil {
		t.Fatalf("could not find signal handler marker in backtrace")
	}
	rest := got[loc[1]:]

	// Look for any frames after the signal handler. We want to see
	// symbolized frames, not garbage unknown frames.
	//
	// Since the signal might not be delivered to the main thread we can't
	// look for main.main. Every thread should have a runtime frame though.
	re = regexp.MustCompile(`#.* runtime\.`)
	if found := re.Find(rest) != nil; !found {
		t.Fatalf("could not find runtime symbol in backtrace after signal handler:\n%s", rest)
	}
}

const coreCrashThreadSource = `
package main

/*
#cgo CFLAGS: -g -O0
#include <stdio.h>
#include <stddef.h>
void trigger_crash()
{
	int* ptr = NULL;
	*ptr = 1024;
}
*/
import "C"
import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
)

func enableCore() {
	debug.SetTraceback("crash")

	var lim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim)
	if err != nil {
		panic(fmt.Sprintf("error getting rlimit: %v", err))
	}
	lim.Cur = lim.Max
	fmt.Fprintf(os.Stderr, "Setting RLIMIT_CORE = %+#v\n", lim)
	err = syscall.Setrlimit(syscall.RLIMIT_CORE, &lim)
	if err != nil {
		panic(fmt.Sprintf("error setting rlimit: %v", err))
	}
}

func main() {
	flag.Parse()

	enableCore()

	C.trigger_crash()
}
`

// TestGdbCoreCrashThreadBacktrace tests that runtime could let the fault thread to crash process
// and make fault thread as number one thread while gdb in a core file
func TestGdbCoreCrashThreadBacktrace(t *testing.T) {
	if runtime.GOOS != "linux" {
		// N.B. This test isn't fundamentally Linux-only, but it needs
		// to know how to enable/find core files on each OS.
		t.Skip("Test only supported on Linux")
	}
	if runtime.GOARCH != "386" && runtime.GOARCH != "amd64" {
		// TODO(go.dev/issue/25218): Other architectures use sigreturn
		// via VDSO, which we somehow don't handle correctly.
		t.Skip("Backtrace through signal handler only works on 386 and amd64")
	}

	testenv.SkipFlaky(t, 65138)

	testenv.MustHaveCGO(t)
	checkGdbEnvironment(t)
	t.Parallel()
	checkGdbVersion(t)

	coreUsesPID := canGenerateCore(t)

	// Build the source code.
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	err := os.WriteFile(src, []byte(coreCrashThreadSource), 0644)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", "a.exe", "main.go")
	cmd.Dir = dir
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("building source %v\n%s", err, out)
	}

	// Start the test binary.
	cmd = testenv.Command(t, "./a.exe")
	cmd.Dir = dir
	var output bytes.Buffer
	cmd.Stdout = &output // for test logging
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		t.Fatalf("error starting test binary: %v", err)
	}

	pid := cmd.Process.Pid

	err = cmd.Wait()
	t.Logf("child output:\n%s", output.String())
	if err == nil {
		t.Fatalf("Wait succeeded, want SIGABRT")
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("Wait err got %T %v, want exec.ExitError", ee, ee)
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("Sys got %T %v, want syscall.WaitStatus", ee.Sys(), ee.Sys())
	}
	if ws.Signal() != syscall.SIGABRT {
		t.Fatalf("Signal got %d want SIGABRT", ws.Signal())
	}
	if !ws.CoreDump() {
		t.Fatalf("CoreDump got %v want true", ws.CoreDump())
	}

	coreFile := "core"
	if coreUsesPID {
		coreFile += fmt.Sprintf(".%d", pid)
	}

	// Execute gdb commands.
	args := []string{"-nx", "-batch",
		"-iex", "add-auto-load-safe-path " + filepath.Join(testenv.GOROOT(t), "src", "runtime"),
		"-ex", "backtrace",
		filepath.Join(dir, "a.exe"),
		filepath.Join(dir, coreFile),
	}
	cmd = testenv.Command(t, "gdb", args...)

	got, err := cmd.CombinedOutput()
	t.Logf("gdb output:\n%s", got)
	if err != nil {
		t.Fatalf("gdb exited with error: %v", err)
	}

	re := regexp.MustCompile(`#.* trigger_crash`)
	if found := re.Find(got) != nil; !found {
		t.Fatalf("could not find trigger_crash in backtrace")
	}
}
```