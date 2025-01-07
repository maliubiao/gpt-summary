Response:
Let's break down the thought process for analyzing this Go test file.

**1. Initial Scan and High-Level Understanding:**

* **File Path:** `go/src/runtime/signal_windows_test.go` immediately tells us this is a test file related to signal handling on Windows within the Go runtime.
* **Package:** `package runtime_test` confirms it's an external test for the `runtime` package. This is important because it means it tests the public interface and observable behavior, not internal details directly.
* **Imports:**  Standard Go testing imports (`testing`), OS interaction (`os/exec`, `path/filepath`), runtime information (`runtime`), string manipulation (`strings`), and Windows-specific syscalls (`syscall`). The `internal/testenv` import is a key indicator that this is part of the Go standard library's testing infrastructure.
* **Test Function Names:**  `TestVectoredHandlerExceptionInNonGoThread`, `TestVectoredHandlerDontCrashOnLibrary`, `TestCtrlHandler`, `TestLibraryCtrlHandler`, `TestIssue59213`. These names strongly suggest the test file focuses on:
    * Vectored Exception Handling (VEH) on Windows, especially when interacting with non-Go threads (like C/C++ DLLs).
    * Handling of console control events (Ctrl+C, closing the window).
    * Addressing specific issues (like issue #59213).

**2. Detailed Analysis of Each Test Function:**

* **`TestVectoredHandlerExceptionInNonGoThread`:**
    * **Goal:** Test how Go handles exceptions thrown in non-Go threads when using VEH.
    * **Mechanism:**
        * Builds a C DLL (`veh.dll`) that throws an exception.
        * Builds a Go executable that loads this DLL and potentially triggers the exception in a separate thread.
        * Runs the Go executable in two ways: in the same thread and in a new thread, expecting different outcomes.
        * Verifies the error messages and exit codes.
    * **Key Observations:** Use of `gcc`, building both a DLL and an executable, the "thread" command-line argument to the Go executable.

* **`TestVectoredHandlerDontCrashOnLibrary`:**
    * **Goal:**  Ensure that using a Go DLL from a C program doesn't cause crashes due to VEH interactions.
    * **Mechanism:**
        * Builds a Go DLL (`testwinlib.dll`) using `buildmode c-shared`.
        * Builds a C executable that links against this Go DLL.
        * Runs the C executable and checks its output, which reports counts of exceptions, continues, and unhandled events.
    * **Key Observations:**  `buildmode c-shared` is crucial here. The expected output varies slightly depending on the architecture, indicating platform-specific behavior related to exception handling.

* **`TestCtrlHandler`:**
    * **Goal:** Verify Go programs can gracefully handle console control events (like closing the console window).
    * **Mechanism:**
        * Builds a Go executable that's designed to handle signals.
        * Starts the executable in a *new* console window (`_CREATE_NEW_CONSOLE`).
        * Waits for the program to exit and checks if it received and handled `SIGTERM`.
    * **Key Observations:**  The use of `syscall.SysProcAttr` to create a new console window is significant. It simulates a user closing the window.

* **`TestLibraryCtrlHandler`:**
    * **Goal:**  Confirm that when a Go DLL is loaded by a C program, the *C program* can handle console control events, not the Go DLL itself interfering.
    * **Mechanism:**
        * Builds a simple Go DLL (`dummy.dll`).
        * Builds a C executable that loads the DLL.
        * Starts the C executable.
        * Uses `sendCtrlBreak` to simulate sending a Ctrl+Break signal to the C process.
        * Checks if the C program exits correctly.
    * **Key Observations:**  The use of `sendCtrlBreak` and the verification that the C program handles the signal.

* **`TestIssue59213`:**
    * **Goal:** Tests a specific reported issue related to TLS (Thread Local Storage) when Go is built as a DLL and used by a C program.
    * **Mechanism:**
        * Retrieves compiler and flags using `go env`.
        * Builds a Go DLL.
        * Builds a C executable that loads the Go DLL and calls a function within it.
        * Runs the C executable.
    * **Key Observations:** This test explicitly uses `go env` to obtain build environment information, highlighting a more complex integration scenario.

**3. Identifying Go Features and Providing Examples:**

Based on the test functions, the key Go features being tested are:

* **Signal Handling:**  Specifically on Windows, testing how Go responds to signals like `SIGTERM` triggered by console events.
* **Cgo:**  The tests heavily rely on Cgo to interact with C code and DLLs.
* **Building Shared Libraries (`buildmode c-shared`):** Testing the creation and use of Go DLLs from C programs.
* **Vectored Exception Handling (VEH):**  A Windows-specific mechanism for handling exceptions. The tests verify Go's interaction with VEH, especially in multi-language scenarios.

The code examples provided in the initial, concise answer directly illustrate these features.

**4. Identifying Potential Pitfalls:**

The analysis focused on common errors when working with these features, specifically around:

* **Incorrect `buildmode`:**  Forgetting or misconfiguring `buildmode c-shared`.
* **Signal handling in DLLs:** Misunderstanding who is responsible for handling signals (the host process, not the DLL by default).
* **Environment setup:** The tests themselves demonstrate the importance of `CGO_CFLAGS` and having the correct build tools installed.

**5. Structuring the Answer:**

The final step was to organize the information logically, starting with a summary of the file's purpose, then detailing the functionality of each test, explaining the relevant Go features with examples, and finally highlighting potential mistakes. The use of clear headings and bullet points makes the information easier to digest.
这段代码是 Go 语言运行时（runtime）包中关于 Windows 信号处理的测试代码。它主要用于验证 Go 程序在 Windows 系统上处理特定信号和异常的正确性，特别是与 C 代码互操作时的情况。

下面列举一下它的主要功能：

1. **测试在非 Go 线程中发生的向量化异常处理 (Vectored Exception Handling, VEH)：**  `TestVectoredHandlerExceptionInNonGoThread` 函数测试了当异常发生在非 Go 创建的线程中（例如，由 C 代码创建的线程）时，Go 的 VEH 机制是否能正确捕获并处理这些异常。

2. **测试当 Go 代码作为动态链接库 (DLL) 被加载时不崩溃：** `TestVectoredHandlerDontCrashOnLibrary` 函数验证了当 Go 代码被编译成 DLL 并被 C 程序加载时，Go 的异常处理机制不会导致程序崩溃。这涉及到 `-buildmode=c-shared` 编译选项。

3. **测试 Go 程序能否优雅地处理控制台关闭事件：** `TestCtrlHandler` 函数测试了 Go 程序是否能正确接收并处理控制台关闭事件（例如，用户点击窗口的关闭按钮），这通常会发送 `SIGTERM` 信号。

4. **测试 Go DLL 是否允许调用程序处理控制台事件：** `TestLibraryCtrlHandler` 函数测试了当 Go 代码编译成 DLL 被 C 程序加载时，控制台事件（例如 Ctrl+C 或 Ctrl+Break）是否能被宿主 C 程序处理，而不是被 Go DLL 内部的信号处理机制拦截。

5. **测试与 TLS (Thread Local Storage) 相关的特定问题 (Issue 59213)：** `TestIssue59213` 函数用于测试一个特定的 bugfix，该 bug 与 Go 代码作为 DLL 被 C 程序调用时，线程本地存储的初始化和使用有关。

**如果你能推理出它是什么 Go 语言功能的实现，请用 Go 代码举例说明：**

这段代码主要测试了 Go 语言的以下功能在 Windows 平台上的实现：

* **信号处理 (Signal Handling)：** Go 的 `os/signal` 包提供了处理操作系统信号的能力。在 Windows 上，虽然没有 POSIX 风格的信号，但 Go 会将一些 Windows 特有的事件映射到 `os.Signal` 类型。

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 创建一个接收 syscall.SIGTERM 信号的通道
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	fmt.Println("等待 SIGTERM 信号...")
	// 阻塞等待信号
	sig := <-sigChan
	fmt.Println("接收到信号:", sig)
}
```

* **Cgo 和构建共享库 (`buildmode c-shared`)：**  Cgo 允许 Go 代码调用 C 代码，反之亦然。`-buildmode=c-shared` 编译选项可以将 Go 代码编译成一个可以被 C 或 C++ 程序加载的动态链接库 (DLL)。

```go
// 在 testdata/testwinlibsignal/dummy.go 中 (编译成 DLL)
package main

import "C"

//export GoFunc
func GoFunc() {
	println("Hello from Go DLL!")
}

func main() {}
```

```c
// 在 testdata/testwinlibsignal/main.c 中 (加载 DLL 并调用 Go 函数)
#include <windows.h>
#include <stdio.h>

typedef void (*GoFuncType)();

int main() {
    HINSTANCE hGetProcIDDLL = LoadLibrary("dummy.dll");
    if (!hGetProcIDDLL) {
        fprintf(stderr, "Could not load the DLL.\n");
        return 1;
    }

    GoFuncType GoFunc = (GoFuncType)GetProcAddress(hGetProcIDDLL, "GoFunc");
    if (!GoFunc) {
        fprintf(stderr, "Could not locate GoFunc.\n");
        return 1;
    }

    printf("Calling Go function...\n");
    GoFunc();

    FreeLibrary(hGetProcIDDLL);
    return 0;
}
```

* **向量化异常处理 (Vectored Exception Handling, VEH)：**  这是 Windows 特有的异常处理机制。Go 运行时使用 VEH 来捕获和处理一些底层异常，例如访问无效内存地址。

**如果涉及代码推理，需要带上假设的输入与输出：**

以 `TestVectoredHandlerExceptionInNonGoThread` 为例：

**假设的输入：**

1. 编译好的 C DLL `veh.dll`，其中包含一个会抛出异常的代码。
2. 编译好的 Go 可执行文件 `test.exe`，它会加载 `veh.dll`，并在一个新线程中调用 DLL 中的函数，从而触发异常。

**假设的输出（当执行 `test.exe` 不带 `thread` 参数时）：**

```
Exception 0x2a ... (包含异常信息的输出)
```

因为 Go 代码在同一个线程中执行，异常会被 Go 的 VEH 捕获，并且程序会以非零状态码退出，输出包含异常信息。

**假设的输出（当执行 `test.exe thread` 时）：**

程序应该以退出码 `42` 退出。这是因为在 `testdata/testwinlibthrow/main.go` 中，当接收到特定信号或发生特定异常时，程序会被设计为以退出码 42 退出。这模拟了在非 Go 线程中发生的异常被 VEH 处理后，Go 程序的一种预期行为。

**如果涉及命令行参数的具体处理，请详细介绍一下：**

在 `TestVectoredHandlerExceptionInNonGoThread` 函数中，Go 可执行文件 `test.exe` 在测试中被调用时，有时会带上 `thread` 这个命令行参数：

```go
	// run test program in a new thread
	cmd = exec.Command(exe, "thread")
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
```

这个 `thread` 参数的具体处理逻辑在 `testdata/testwinlibthrow/main.go` 中：

```go
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

//export Throw
func Throw() {
	panic("throwing an exception")
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "thread" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Load the DLL
		dll, err := syscall.LoadDLL("veh.dll")
		if err != nil {
			fmt.Fprintf(os.Stderr, "LoadDLL failed: %v\n", err)
			os.Exit(1)
		}
		defer dll.Release()

		// Find the Throw procedure
		throwProc, err := dll.FindProc("Throw")
		if err != nil {
			fmt.Fprintf(os.Stderr, "FindProc failed: %v\n", err)
			os.Exit(1)
		}

		// Call the Throw procedure in a new goroutine (which will be a new OS thread)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "Recovered panic: %v\n%s", r, debug.Stack())
					os.Exit(42) // 假设的退出码
				}
			}()
			_, _, _ = throwProc.Call()
		}()

		// Wait for a while to allow the thread to execute
		time.Sleep(time.Second)
	} else {
		// Load the DLL
		dll, err := syscall.LoadDLL("veh.dll")
		if err != nil {
			fmt.Fprintf(os.Stderr, "LoadDLL failed: %v\n", err)
			os.Exit(1)
		}
		defer dll.Release()

		// Find the Throw procedure
		throwProc, err := dll.FindProc("Throw")
		if err != nil {
			fmt.Fprintf(os.Stderr, "FindProc failed: %v\n", err)
			os.Exit(1)
		}

		// Call the Throw procedure in the same goroutine
		_, _, err = throwProc.Call()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
```

当 `test.exe` 接收到 `thread` 参数时，它会创建一个新的操作系统线程来调用 C DLL 中的 `Throw` 函数，这个函数会抛出一个异常。这样做的目的是测试当异常发生在非 Go 创建的线程时，Go 的 VEH 机制是否能够正确处理。如果 *没有* `thread` 参数，`Throw` 函数会在主 Go 协程中被调用。

**如果有哪些使用者易犯错的点，请举例说明：**

1. **不正确的 `buildmode`：**  在需要生成 DLL 的场景下（例如 `TestVectoredHandlerDontCrashOnLibrary` 和 `TestLibraryCtrlHandler`），必须使用 `-buildmode=c-shared` 编译 Go 代码。忘记或错误地设置此选项会导致生成的不是一个标准的 DLL，从而导致加载失败或其他不可预测的行为。

   **错误示例：**
   ```bash
   go build -o mylib.dll mylib.go  // 缺少 -buildmode=c-shared
   ```

2. **在 DLL 中处理信号的误解：**  当 Go 代码被编译成 DLL 并被其他程序加载时，DLL 内部的信号处理机制可能不会像独立运行时那样工作。例如，发送给宿主进程的控制台事件默认由宿主进程处理，而不是 DLL。如果开发者期望 DLL 内部的信号处理函数能够捕获所有信号，可能会导致意外的行为。`TestLibraryCtrlHandler` 正是为了验证这种情况。

   **易错点：** 假设在 Go DLL 中设置了信号处理程序，希望能够捕获宿主程序的 Ctrl+C 事件。实际上，宿主程序可能已经有自己的处理方式，或者操作系统会将信号传递给宿主程序，而不是 DLL。

3. **Cgo 的环境配置问题：**  使用 Cgo 需要正确的 C 编译器环境。如果 `gcc` 等编译器没有安装或配置正确，Cgo 编译步骤将会失败。测试代码中使用了 `testenv.MustHaveCGO(t)` 和 `testenv.MustHaveExecPath(t, "gcc")` 来确保测试环境满足要求，但这在实际开发中是开发者需要注意的。

4. **Windows 路径分隔符：** 在跨平台开发时，容易混淆 Windows 和 Linux/macOS 的路径分隔符。在构建命令中，硬编码路径分隔符可能会导致在不同平台上失败。Go 的 `path/filepath` 包提供了跨平台的路径操作函数，应该优先使用。

这些测试用例覆盖了在 Windows 平台上使用 Go 语言进行底层编程和与 C 代码互操作时的一些关键场景，帮助确保 Go 运行时的稳定性和正确性。

Prompt: 
```
这是路径为go/src/runtime/signal_windows_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/testenv"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestVectoredHandlerExceptionInNonGoThread(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}
	if strings.HasPrefix(testenv.Builder(), "windows-amd64-2012") {
		testenv.SkipFlaky(t, 49681)
	}
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExecPath(t, "gcc")
	testprog.Lock()
	defer testprog.Unlock()
	dir := t.TempDir()

	// build c program
	dll := filepath.Join(dir, "veh.dll")
	cmd := exec.Command("gcc", "-shared", "-o", dll, "testdata/testwinlibthrow/veh.c")
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build c exe: %s\n%s", err, out)
	}

	// build go exe
	exe := filepath.Join(dir, "test.exe")
	cmd = exec.Command(testenv.GoToolPath(t), "build", "-o", exe, "testdata/testwinlibthrow/main.go")
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build go library: %s\n%s", err, out)
	}

	// run test program in same thread
	cmd = exec.Command(exe)
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err == nil {
		t.Fatal("error expected")
	}
	if _, ok := err.(*exec.ExitError); ok && len(out) > 0 {
		if !bytes.Contains(out, []byte("Exception 0x2a")) {
			t.Fatalf("unexpected failure while running executable: %s\n%s", err, out)
		}
	} else {
		t.Fatalf("unexpected error while running executable: %s\n%s", err, out)
	}
	// run test program in a new thread
	cmd = exec.Command(exe, "thread")
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err == nil {
		t.Fatal("error expected")
	}
	if err, ok := err.(*exec.ExitError); ok {
		if err.ExitCode() != 42 {
			t.Fatalf("unexpected failure while running executable: %s\n%s", err, out)
		}
	} else {
		t.Fatalf("unexpected error while running executable: %s\n%s", err, out)
	}
}

func TestVectoredHandlerDontCrashOnLibrary(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}
	if runtime.GOARCH == "arm" {
		//TODO: remove this skip and update testwinlib/main.c
		// once windows/arm supports c-shared buildmode.
		// See go.dev/issues/43800.
		t.Skip("this test can't run on windows/arm")
	}
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExecPath(t, "gcc")
	testprog.Lock()
	defer testprog.Unlock()
	dir := t.TempDir()

	// build go dll
	dll := filepath.Join(dir, "testwinlib.dll")
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", dll, "-buildmode", "c-shared", "testdata/testwinlib/main.go")
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build go library: %s\n%s", err, out)
	}

	// build c program
	exe := filepath.Join(dir, "test.exe")
	cmd = exec.Command("gcc", "-L"+dir, "-I"+dir, "-ltestwinlib", "-o", exe, "testdata/testwinlib/main.c")
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build c exe: %s\n%s", err, out)
	}

	// run test program
	cmd = exec.Command(exe)
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failure while running executable: %s\n%s", err, out)
	}
	var expectedOutput string
	if runtime.GOARCH == "arm64" || runtime.GOARCH == "arm" {
		// TODO: remove when windows/arm64 and windows/arm support SEH stack unwinding.
		expectedOutput = "exceptionCount: 1\ncontinueCount: 1\nunhandledCount: 0\n"
	} else {
		expectedOutput = "exceptionCount: 1\ncontinueCount: 1\nunhandledCount: 1\n"
	}
	// cleaning output
	cleanedOut := strings.ReplaceAll(string(out), "\r\n", "\n")
	if cleanedOut != expectedOutput {
		t.Errorf("expected output %q, got %q", expectedOutput, cleanedOut)
	}
}

func sendCtrlBreak(pid int) error {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return fmt.Errorf("LoadDLL: %v\n", err)
	}
	generateEvent, err := kernel32.FindProc("GenerateConsoleCtrlEvent")
	if err != nil {
		return fmt.Errorf("FindProc: %v\n", err)
	}
	result, _, err := generateEvent.Call(syscall.CTRL_BREAK_EVENT, uintptr(pid))
	if result == 0 {
		return fmt.Errorf("GenerateConsoleCtrlEvent: %v\n", err)
	}
	return nil
}

// TestCtrlHandler tests that Go can gracefully handle closing the console window.
// See https://golang.org/issues/41884.
func TestCtrlHandler(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	t.Parallel()

	// build go program
	exe := filepath.Join(t.TempDir(), "test.exe")
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", exe, "testdata/testwinsignal/main.go")
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build go exe: %v\n%s", err, out)
	}

	// run test program
	cmd = exec.Command(exe)
	var stdout strings.Builder
	var stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	inPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to create stdin pipe: %v", err)
	}
	// keep inPipe alive until the end of the test
	defer inPipe.Close()

	// in a new command window
	const _CREATE_NEW_CONSOLE = 0x00000010
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: _CREATE_NEW_CONSOLE,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// check child exited gracefully, did not timeout
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Program exited with error: %v\n%s", err, &stderr)
	}

	// check child received, handled SIGTERM
	if expected, got := syscall.SIGTERM.String(), strings.TrimSpace(stdout.String()); expected != got {
		t.Fatalf("Expected '%s' got: %s", expected, got)
	}
}

// TestLibraryCtrlHandler tests that Go DLL allows calling program to handle console control events.
// See https://golang.org/issues/35965.
func TestLibraryCtrlHandler(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("this test can only run on windows/amd64")
	}
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)
	testenv.MustHaveExecPath(t, "gcc")
	testprog.Lock()
	defer testprog.Unlock()
	dir := t.TempDir()

	// build go dll
	dll := filepath.Join(dir, "dummy.dll")
	cmd := exec.Command(testenv.GoToolPath(t), "build", "-o", dll, "-buildmode", "c-shared", "testdata/testwinlibsignal/dummy.go")
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build go library: %s\n%s", err, out)
	}

	// build c program
	exe := filepath.Join(dir, "test.exe")
	cmd = exec.Command("gcc", "-o", exe, "testdata/testwinlibsignal/main.c")
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build c exe: %s\n%s", err, out)
	}

	// run test program
	cmd = exec.Command(exe)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	outReader := bufio.NewReader(outPipe)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		if line, err := outReader.ReadString('\n'); err != nil {
			errCh <- fmt.Errorf("could not read stdout: %v", err)
		} else if strings.TrimSpace(line) != "ready" {
			errCh <- fmt.Errorf("unexpected message: %v", line)
		} else {
			errCh <- sendCtrlBreak(cmd.Process.Pid)
		}
	}()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Program exited with error: %v\n%s", err, &stderr)
	}
}

func TestIssue59213(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping windows only test")
	}
	if *flagQuick {
		t.Skip("-quick")
	}
	testenv.MustHaveGoBuild(t)
	testenv.MustHaveCGO(t)

	goEnv := func(arg string) string {
		cmd := testenv.Command(t, testenv.GoToolPath(t), "env", arg)
		cmd.Stderr = new(bytes.Buffer)

		line, err := cmd.Output()
		if err != nil {
			t.Fatalf("%v: %v\n%s", cmd, err, cmd.Stderr)
		}
		out := string(bytes.TrimSpace(line))
		t.Logf("%v: %q", cmd, out)
		return out
	}

	cc := goEnv("CC")
	cgoCflags := goEnv("CGO_CFLAGS")

	t.Parallel()

	tmpdir := t.TempDir()
	dllfile := filepath.Join(tmpdir, "test.dll")
	exefile := filepath.Join(tmpdir, "gotest.exe")

	// build go dll
	cmd := testenv.Command(t, testenv.GoToolPath(t), "build", "-o", dllfile, "-buildmode", "c-shared", "testdata/testwintls/main.go")
	out, err := testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build go library: %s\n%s", err, out)
	}

	// build c program
	cmd = testenv.Command(t, cc, "-o", exefile, "testdata/testwintls/main.c")
	testenv.CleanCmdEnv(cmd)
	cmd.Env = append(cmd.Env, "CGO_CFLAGS="+cgoCflags)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build c exe: %s\n%s", err, out)
	}

	// run test program
	cmd = testenv.Command(t, exefile, dllfile, "GoFunc")
	out, err = testenv.CleanCmdEnv(cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("failed: %s\n%s", err, out)
	}
}

"""



```