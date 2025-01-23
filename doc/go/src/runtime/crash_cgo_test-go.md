Response:
The user wants to understand the functionality of the provided Go code snippet. This code is a test file (`crash_cgo_test.go`) within the `runtime` package, specifically focusing on testing interactions between Go runtime and C code via CGO.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The file name `crash_cgo_test.go` and the presence of the `//go:build cgo` directive immediately suggest this file tests scenarios involving CGO, especially those related to crashes, signals, and callbacks.

2. **Analyze individual test functions:** Iterate through each `Test...` function and determine its intent based on the function name and the operations performed within it. Look for patterns like:
    * Calling `runTestProg`: This indicates execution of a separate program (likely `testprogcgo`) with specific arguments. The arguments often reveal the specific CGO feature being tested (e.g., "CgoCrashHandler", "CgoTraceback").
    * Comparing output: The tests often compare the output of `runTestProg` with expected strings ("OK\n", specific panic messages).
    * Conditional execution based on `runtime.GOOS`: Some tests are platform-specific due to CGO's dependency on OS features like signals and threads.
    * Using `t.Skip`:  This indicates that a test is skipped under certain conditions (OS, architecture, short mode).

3. **Group tests by functionality:**  Based on the individual test function analysis, group them into logical categories:
    * **Crash Handling:** Tests how Go handles crashes originating from C code.
    * **Signal Handling:** Focuses on signal interactions between Go and C, including signal delivery to Go code, signals in external threads, and signal masking.
    * **Tracebacks:** Verifies the generation of stack traces when errors occur in CGO contexts.
    * **Callbacks:** Examines scenarios where C code calls back into Go.
    * **Profiling:** Tests integration with profiling tools (pprof) in CGO scenarios.
    * **Race Detection:**  Checks for data races in CGO interactions.
    * **Memory Management:** Tests related to stack size and memory checks in CGO.
    * **Error Handling:**  Validates the handling of specific errors (e.g., EINTR).
    * **Goexit in CGO:** Tests the behavior of `runtime.Goexit` called from C code.
    * **Other CGO Features:**  Includes tests for features like `#cgo nocallback` and pointer escaping.

4. **Infer the underlying Go features:**  Connect the test scenarios to the underlying Go/CGO mechanisms. For example:
    * `TestCgoCrashHandler`: Tests the `runtime`'s ability to intercept and handle signals or exceptions raised in C code.
    * `TestCgoTraceback`:  Examines how the Go runtime constructs stack traces that include both Go and C function calls.
    * `TestCgoCallbackGC`: Relates to how the garbage collector handles callbacks from C to Go.
    * `TestCgoPprof`:  Tests the interaction between the Go profiler and C code.

5. **Provide illustrative Go code examples:**  For each identified Go feature, create a simplified example demonstrating its usage. This involves basic CGO setup, including importing "C" and making calls to C functions. The examples should be concise and focus on the specific feature.

6. **Address command-line arguments:** Analyze how the tests use `runTestProg` and its arguments. Note any environment variables being set (e.g., `GOTRACEBACK`, `GO_START_SIGPROF_THREAD`). Explain the purpose of these arguments in the context of the tests.

7. **Identify potential pitfalls:**  Consider common mistakes developers might make when working with CGO, based on the test scenarios. Examples include: forgetting to handle signals correctly, assuming Go's memory management applies directly to C memory, and not understanding the implications of threading in CGO.

8. **Structure the answer:** Organize the information clearly with headings and bullet points for readability. Start with a general overview, then delve into specific functionalities. Provide code examples and explanations in a logical flow.

9. **Review and refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Correct any errors or ambiguities. Ensure the language is clear and easy to understand for someone learning about CGO. For instance, initially, I might just list the tests. But the prompt asks for *functionality*. So, I need to group the tests and explain the broader CGO features they are testing. Also, initially, the code examples might be too complex. Simplify them to focus on the core CGO interaction.

By following these steps, a comprehensive and informative answer addressing all aspects of the user's request can be generated.
这段 Go 语言代码是 `go/src/runtime/crash_cgo_test.go` 文件的一部分，它主要用于测试 Go 运行时（runtime）与 C 代码通过 CGO 交互时，在发生崩溃、信号、回调等情况下的行为是否符合预期。

以下是其主要功能的详细列举：

**核心功能：测试 CGO 相关的崩溃处理和运行时行为**

1. **`TestCgoCrashHandler`**: 测试当 C 代码发生崩溃时，Go 运行时的崩溃处理机制是否能正常工作。这通常涉及到捕获信号并生成崩溃报告。

2. **`TestCgoSignalDeadlock`**: 测试在 CGO 环境下，信号处理是否可能导致死锁。这可能涉及到 Go 和 C 之间的信号交互。

3. **`TestCgoTraceback`**: 测试当 CGO 代码中发生错误或显式调用 `panic` 时，Go 运行时能否生成包含 C 代码调用栈的回溯信息（traceback）。

4. **`TestCgoCallbackGC`**: 测试当 C 代码回调到 Go 代码时，Go 的垃圾回收器（GC）是否能正确处理相关的对象和内存。

5. **`TestCgoExternalThreadPanic`**: 测试当 C 创建的外部线程发生 `panic` 时，Go 运行时能否捕获并报告这个 panic。

6. **`TestCgoExternalThreadSIGPROF`**: 测试当 C 创建的外部线程收到 `SIGPROF` 信号（用于性能分析）时，Go 运行时是否能正确处理。

7. **`TestCgoExternalThreadSignal`**: 测试当 C 创建的外部线程收到其他信号时，Go 运行时的行为。

8. **`TestCgoDLLImports`**:  （仅限 Windows）测试在使用 CGO 引入 DLL 时，相关的导入机制是否正常工作。

9. **`TestCgoExecSignalMask`**: 测试在使用 `os/exec` 执行包含 CGO 代码的程序时，信号掩码是否能被正确处理。

10. **`TestEnsureDropM`**:  测试在 CGO 调用期间，Go 调度器是否能正确地释放 M（操作系统线程）。这与线程管理有关。

11. **`TestCgoCheckBytes`**:  测试 CGO 的指针检查机制的性能影响。对比开启和关闭指针检查时的性能差异。

12. **`TestCgoPanicDeadlock`**: 测试在 CGO 调用过程中发生 `panic` 是否会导致死锁。

13. **`TestCgoCCodeSIGPROF`**: 测试当在 C 代码中发送 `SIGPROF` 信号时，Go 运行时的行为。

14. **`TestCgoPprofCallback`**: 测试在使用 `pprof` 进行性能分析时，CGO 回调函数的处理是否正常。

15. **`TestCgoCrashTraceback`**:  更具体地测试 C 代码崩溃时的回溯信息，可能涉及到符号化等。

16. **`TestCgoCrashTracebackGo`**: 测试在 C 代码中调用 Go 代码并导致 Go 代码崩溃时的回溯信息。

17. **`TestCgoTracebackContext`**: 测试 CGO 回溯信息的上下文信息是否正确。

18. **`TestCgoTracebackContextPreemption`**: 测试在 CGO 回溯过程中发生抢占时的上下文信息是否正确。

19. **`TestCgoPprof`, `TestCgoPprofPIE`, `TestCgoPprofThread`, `TestCgoPprofThreadNoTraceback`**:  一系列测试，使用 `pprof` 工具来分析包含 CGO 代码的程序的性能，涵盖了不同的构建模式和线程场景。

20. **`TestRaceProf`, `TestRaceSignal`**:  使用 Go 的 race detector 来检测 CGO 代码中可能存在的竞态条件。

21. **`TestCgoNumGoroutine`**: 测试在 CGO 环境下，`runtime.NumGoroutine()` 函数的返回值是否准确。

22. **`TestCatchPanic`**: 测试在 CGO 环境下，通过信号捕获 C 代码的 panic。

23. **`TestCgoLockOSThreadExit`**: 测试在锁定操作系统线程的 CGO 代码退出时的行为。

24. **`TestWindowsStackMemoryCgo`**: （仅限 Windows）测试 CGO 中 Windows 线程栈的内存使用情况。

25. **`TestSigStackSwapping`**: 测试信号栈的切换在 CGO 环境下是否正常工作。

26. **`TestCgoTracebackSigpanic`**: 测试在 C 代码中发生 `sigpanic` 时，Go 能否生成正确的调用栈信息。

27. **`TestCgoPanicCallback`**: 测试当 C 代码回调到 Go 代码并导致 Go 代码 panic 时的处理。

28. **`TestBigStackCallbackCgo`**: （仅限 Windows）测试 C 代码使用大线程栈回调到 Go 代码是否正常工作。

29. **`TestSegv`, `TestSegvInCgo`, `TgkillSegv`, `TgkillSegvInCgo`**: 测试 Go 程序或 CGO 代码中发生 `SIGSEGV` (段错误) 时的处理。`Tgkill` 变体是 Linux 特有的，用于测试向特定线程发送信号。

30. **`TestAbortInCgo`**: 测试 C 代码调用 `abort()` 时的处理。

31. **`TestEINTR`**: 测试 Go 运行时是否能正确处理由于信号中断 (EINTR) 而导致的系统调用失败。

32. **`TestNeedmDeadlock`**: 测试与 CGO 相关的 `needm` 调度是否会导致死锁。

33. **`TestCgoNoCallback`**: 测试使用 `#cgo nocallback` 标记的函数被回调时的行为，预期会报错。

34. **`TestCgoNoEscape`**: 测试 CGO 中指针的逃逸分析是否正确。

35. **`TestCgoEscapeWithMultiplePointers`**: 测试 CGO 中多个指针的逃逸分析。

36. **`TestCgoTracebackGoroutineProfile`**: 测试在 CGO 环境下获取 goroutine profile 的能力。

37. **`TestCgoSigfwd`**: 测试信号转发机制在 CGO 中的工作情况。

38. **`TestDestructorCallback`, `TestDestructorCallbackRace`**: 测试 CGO 中析构函数回调的机制，以及在高并发场景下的竞态条件。

39. **`TestEnsureBindM`**: 测试在 CGO 调用期间，Go 调度器是否能正确地绑定 M（操作系统线程）。

40. **`TestStackSwitchCallback`**: 测试在 CGO 回调中进行栈切换的功能。

41. **`TestCgoToGoCallGoexit`**: 测试从 C 代码调用 `runtime.Goexit()` 的行为。

**它是什么 Go 语言功能的实现？**

这段代码主要测试的是 Go 语言的 **CGO (C Go) 功能** 的实现。CGO 允许 Go 程序调用 C 代码，以及 C 代码回调到 Go 代码。这个测试文件侧重于 CGO 在异常情况下的健壮性和正确性，例如崩溃处理、信号传递、内存管理以及与性能分析工具的集成。

**Go 代码举例说明 CGO 功能：**

假设我们有一个简单的 C 代码文件 `hello.c`:

```c
#include <stdio.h>

void say_hello_from_c() {
    printf("Hello from C!\n");
}
```

以及一个 Go 代码文件 `main.go`:

```go
package main

// #cgo CFLAGS: -Wall -O2
// #include "hello.h"
import "C"

import "fmt"

func main() {
	fmt.Println("Calling C function...")
	C.say_hello_from_c()
	fmt.Println("C function finished.")
}
```

我们需要一个头文件 `hello.h`:

```c
#ifndef HELLO_H
#define HELLO_H

void say_hello_from_c();

#endif
```

**假设的输入与输出：**

1. **编译 C 代码：**  通常 CGO 会在构建 Go 代码时自动处理 C 代码的编译。
2. **构建并运行 Go 代码：** `go run main.go`

**预期输出：**

```
Calling C function...
Hello from C!
C function finished.
```

**代码推理：**

* `import "C"` 是 CGO 的关键。它使得我们可以调用 C 代码。
* 注释 `// #cgo CFLAGS: -Wall -O2` 指定了传递给 C 编译器的参数。
* 注释 `// #include "hello.h"` 类似于 C 的 `#include` 指令，声明了要使用的 C 函数。
* `C.say_hello_from_c()`  通过 `C.` 前缀调用了 C 函数 `say_hello_from_c`。

**命令行参数的具体处理：**

这些测试函数通常使用 `runTestProg` 函数来执行一个名为 `testprogcgo` 的辅助程序。 `runTestProg` 函数会处理以下步骤：

1. **构建 `testprogcgo`:**  如果尚未构建，会先构建这个程序。
2. **执行 `testprogcgo`:** 使用 `os/exec` 包执行 `testprogcgo`，并将传入的 `args` 作为命令行参数传递给它。
3. **获取输出:**  捕获 `testprogcgo` 程序的标准输出和标准错误。
4. **返回输出:** 将 `testprogcgo` 的标准输出作为字符串返回。

在这些测试中，`runTestProg` 的参数通常是：

* `t *testing.T`:  Go 测试框架的 testing 对象。
* `progName string`: 要执行的程序名，这里通常是 `"testprogcgo"` 或 `"testprog"`。
* `testName string`:  `testprogcgo` 程序中要执行的特定测试函数名。`testprogcgo` 内部会根据这个参数执行相应的 CGO 测试代码。
* `env ...string`:  可选的环境变量，以 `key=value` 的形式传递给 `testprogcgo` 程序。例如，`"GOTRACEBACK=system"` 用于控制崩溃时的回溯信息级别，`"GO_START_SIGPROF_THREAD=1"` 用于指示启动一个发送 `SIGPROF` 信号的线程。

**例如，在 `TestCgoExternalThreadSIGPROF` 中：**

```go
got := runTestProg(t, "testprogcgo", "CgoExternalThreadSIGPROF", "GO_START_SIGPROF_THREAD=1")
```

这里，`runTestProg` 会执行 `testprogcgo` 程序，并告诉它运行名为 "CgoExternalThreadSIGPROF" 的测试。同时，设置了环境变量 `GO_START_SIGPROF_THREAD=1`，这会影响 `testprogcgo` 内部的逻辑，使其启动一个额外的线程来发送 `SIGPROF` 信号，以便测试 Go 运行时在 CGO 环境下对此信号的处理。

**使用者易犯错的点：**

虽然这段代码是测试代码，但从中可以推断出 CGO 使用者容易犯错的点：

1. **不正确的信号处理:** 在 C 代码中直接处理信号，而没有考虑到 Go 运行时的信号处理机制，可能导致冲突或未定义的行为。例如，在 `TestCatchPanic` 中，测试了在 C 代码中安装早期的信号处理程序是否会影响 Go 的崩溃处理。

2. **C 和 Go 内存管理的混淆:** C 的内存需要手动管理，而 Go 使用垃圾回收。在 CGO 中传递指针时，需要特别注意内存的所有权和生命周期，避免悬挂指针或内存泄漏。 `TestCgoCheckBytes` 测试了 Go 的 CGO 指针检查机制，这正是为了帮助开发者避免这类错误。

3. **CGO 回调时的并发问题:** 当 C 代码回调到 Go 代码时，Go 的调度器可能会在不同的 Goroutine 上执行回调。如果 Go 代码没有做好并发安全措施，可能会出现数据竞争等问题。 `TestCgoCallbackGC` 和 `TestDestructorCallbackRace` 涉及到这类场景。

4. **CGO 中的线程安全问题:** C 代码可能不是线程安全的，如果在多个 Go Goroutine 中并发地调用同一个 C 函数，可能会引发问题。 `TestCgoExternalThreadPanic` 和 `TestCgoSignalDeadlock` 等测试关注了 CGO 与线程的交互。

5. **构建和链接问题:**  CGO 需要 C 编译器和链接器的支持。配置不当可能导致构建失败或运行时错误。`// #cgo CFLAGS:` 和 `// #cgo LDFLAGS:` 等指令用于指定编译和链接参数，如果使用不当也会导致问题。

总之，这段测试代码覆盖了 CGO 中许多关键和容易出错的场景，帮助确保 Go 运行时在与 C 代码交互时的稳定性和正确性。

### 提示词
```
这是路径为go/src/runtime/crash_cgo_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build cgo

package runtime_test

import (
	"fmt"
	"internal/goos"
	"internal/platform"
	"internal/testenv"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCgoCrashHandler(t *testing.T) {
	t.Parallel()
	testCrashHandler(t, true)
}

func TestCgoSignalDeadlock(t *testing.T) {
	// Don't call t.Parallel, since too much work going on at the
	// same time can cause the testprogcgo code to overrun its
	// timeouts (issue #18598).

	if testing.Short() && runtime.GOOS == "windows" {
		t.Skip("Skipping in short mode") // takes up to 64 seconds
	}
	got := runTestProg(t, "testprogcgo", "CgoSignalDeadlock")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got:\n%s", want, got)
	}
}

func TestCgoTraceback(t *testing.T) {
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "CgoTraceback")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got:\n%s", want, got)
	}
}

func TestCgoCallbackGC(t *testing.T) {
	t.Parallel()
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no pthreads on %s", runtime.GOOS)
	}
	if testing.Short() {
		switch {
		case runtime.GOOS == "dragonfly":
			t.Skip("see golang.org/issue/11990")
		case runtime.GOOS == "linux" && runtime.GOARCH == "arm":
			t.Skip("too slow for arm builders")
		case runtime.GOOS == "linux" && (runtime.GOARCH == "mips64" || runtime.GOARCH == "mips64le"):
			t.Skip("too slow for mips64x builders")
		}
	}
	got := runTestProg(t, "testprogcgo", "CgoCallbackGC")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got:\n%s", want, got)
	}
}

func TestCgoExternalThreadPanic(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "plan9" {
		t.Skipf("no pthreads on %s", runtime.GOOS)
	}
	got := runTestProg(t, "testprogcgo", "CgoExternalThreadPanic")
	want := "panic: BOOM"
	if !strings.Contains(got, want) {
		t.Fatalf("want failure containing %q. output:\n%s\n", want, got)
	}
}

func TestCgoExternalThreadSIGPROF(t *testing.T) {
	t.Parallel()
	// issue 9456.
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no pthreads on %s", runtime.GOOS)
	}

	got := runTestProg(t, "testprogcgo", "CgoExternalThreadSIGPROF", "GO_START_SIGPROF_THREAD=1")
	if want := "OK\n"; got != want {
		t.Fatalf("expected %q, but got:\n%s", want, got)
	}
}

func TestCgoExternalThreadSignal(t *testing.T) {
	t.Parallel()
	// issue 10139
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no pthreads on %s", runtime.GOOS)
	}

	got := runTestProg(t, "testprogcgo", "CgoExternalThreadSignal")
	if want := "OK\n"; got != want {
		if runtime.GOOS == "ios" && strings.Contains(got, "C signal did not crash as expected") {
			testenv.SkipFlaky(t, 59913)
		}
		t.Fatalf("expected %q, but got:\n%s", want, got)
	}
}

func TestCgoDLLImports(t *testing.T) {
	// test issue 9356
	if runtime.GOOS != "windows" {
		t.Skip("skipping windows specific test")
	}
	got := runTestProg(t, "testprogcgo", "CgoDLLImportsMain")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got %v", want, got)
	}
}

func TestCgoExecSignalMask(t *testing.T) {
	t.Parallel()
	// Test issue 13164.
	switch runtime.GOOS {
	case "windows", "plan9":
		t.Skipf("skipping signal mask test on %s", runtime.GOOS)
	}
	got := runTestProg(t, "testprogcgo", "CgoExecSignalMask", "GOTRACEBACK=system")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

func TestEnsureDropM(t *testing.T) {
	t.Parallel()
	// Test for issue 13881.
	switch runtime.GOOS {
	case "windows", "plan9":
		t.Skipf("skipping dropm test on %s", runtime.GOOS)
	}
	got := runTestProg(t, "testprogcgo", "EnsureDropM")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

// Test for issue 14387.
// Test that the program that doesn't need any cgo pointer checking
// takes about the same amount of time with it as without it.
func TestCgoCheckBytes(t *testing.T) {
	t.Parallel()
	// Make sure we don't count the build time as part of the run time.
	testenv.MustHaveGoBuild(t)
	exe, err := buildTestProg(t, "testprogcgo")
	if err != nil {
		t.Fatal(err)
	}

	// Try it 10 times to avoid flakiness.
	const tries = 10
	var tot1, tot2 time.Duration
	for i := 0; i < tries; i++ {
		cmd := testenv.CleanCmdEnv(exec.Command(exe, "CgoCheckBytes"))
		cmd.Env = append(cmd.Env, "GODEBUG=cgocheck=0", fmt.Sprintf("GO_CGOCHECKBYTES_TRY=%d", i))

		start := time.Now()
		cmd.Run()
		d1 := time.Since(start)

		cmd = testenv.CleanCmdEnv(exec.Command(exe, "CgoCheckBytes"))
		cmd.Env = append(cmd.Env, fmt.Sprintf("GO_CGOCHECKBYTES_TRY=%d", i))

		start = time.Now()
		cmd.Run()
		d2 := time.Since(start)

		if d1*20 > d2 {
			// The slow version (d2) was less than 20 times
			// slower than the fast version (d1), so OK.
			return
		}

		tot1 += d1
		tot2 += d2
	}

	t.Errorf("cgo check too slow: got %v, expected at most %v", tot2/tries, (tot1/tries)*20)
}

func TestCgoPanicDeadlock(t *testing.T) {
	t.Parallel()
	// test issue 14432
	got := runTestProg(t, "testprogcgo", "CgoPanicDeadlock")
	want := "panic: cgo error\n\n"
	if !strings.HasPrefix(got, want) {
		t.Fatalf("output does not start with %q:\n%s", want, got)
	}
}

func TestCgoCCodeSIGPROF(t *testing.T) {
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "CgoCCodeSIGPROF")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func TestCgoPprofCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode") // takes a full second
	}
	switch runtime.GOOS {
	case "windows", "plan9":
		t.Skipf("skipping cgo pprof callback test on %s", runtime.GOOS)
	}
	got := runTestProg(t, "testprogcgo", "CgoPprofCallback")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func TestCgoCrashTraceback(t *testing.T) {
	t.Parallel()
	switch platform := runtime.GOOS + "/" + runtime.GOARCH; platform {
	case "darwin/amd64":
	case "linux/amd64":
	case "linux/arm64":
	case "linux/ppc64le":
	default:
		t.Skipf("not yet supported on %s", platform)
	}
	got := runTestProg(t, "testprogcgo", "CrashTraceback")
	for i := 1; i <= 3; i++ {
		if !strings.Contains(got, fmt.Sprintf("cgo symbolizer:%d", i)) {
			t.Errorf("missing cgo symbolizer:%d", i)
		}
	}
}

func TestCgoCrashTracebackGo(t *testing.T) {
	t.Parallel()
	switch platform := runtime.GOOS + "/" + runtime.GOARCH; platform {
	case "darwin/amd64":
	case "linux/amd64":
	case "linux/arm64":
	case "linux/ppc64le":
	default:
		t.Skipf("not yet supported on %s", platform)
	}
	got := runTestProg(t, "testprogcgo", "CrashTracebackGo")
	for i := 1; i <= 3; i++ {
		want := fmt.Sprintf("main.h%d", i)
		if !strings.Contains(got, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestCgoTracebackContext(t *testing.T) {
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "TracebackContext")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func TestCgoTracebackContextPreemption(t *testing.T) {
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "TracebackContextPreemption")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func testCgoPprof(t *testing.T, buildArg, runArg, top, bottom string) {
	t.Parallel()
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "ppc64le" && runtime.GOARCH != "arm64") {
		t.Skipf("not yet supported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	testenv.MustHaveGoRun(t)

	exe, err := buildTestProg(t, "testprogcgo", buildArg)
	if err != nil {
		t.Fatal(err)
	}

	cmd := testenv.CleanCmdEnv(exec.Command(exe, runArg))
	got, err := cmd.CombinedOutput()
	if err != nil {
		if testenv.Builder() == "linux-amd64-alpine" {
			// See Issue 18243 and Issue 19938.
			t.Skipf("Skipping failing test on Alpine (golang.org/issue/18243). Ignoring error: %v", err)
		}
		t.Fatalf("%s\n\n%v", got, err)
	}
	fn := strings.TrimSpace(string(got))
	defer os.Remove(fn)

	for try := 0; try < 2; try++ {
		cmd := testenv.CleanCmdEnv(exec.Command(testenv.GoToolPath(t), "tool", "pprof", "-tagignore=ignore", "-traces"))
		// Check that pprof works both with and without explicit executable on command line.
		if try == 0 {
			cmd.Args = append(cmd.Args, exe, fn)
		} else {
			cmd.Args = append(cmd.Args, fn)
		}

		found := false
		for i, e := range cmd.Env {
			if strings.HasPrefix(e, "PPROF_TMPDIR=") {
				cmd.Env[i] = "PPROF_TMPDIR=" + os.TempDir()
				found = true
				break
			}
		}
		if !found {
			cmd.Env = append(cmd.Env, "PPROF_TMPDIR="+os.TempDir())
		}

		out, err := cmd.CombinedOutput()
		t.Logf("%s:\n%s", cmd.Args, out)
		if err != nil {
			t.Error(err)
			continue
		}

		trace := findTrace(string(out), top)
		if len(trace) == 0 {
			t.Errorf("%s traceback missing.", top)
			continue
		}
		if trace[len(trace)-1] != bottom {
			t.Errorf("invalid traceback origin: got=%v; want=[%s ... %s]", trace, top, bottom)
		}
	}
}

func TestCgoPprof(t *testing.T) {
	testCgoPprof(t, "", "CgoPprof", "cpuHog", "runtime.main")
}

func TestCgoPprofPIE(t *testing.T) {
	testCgoPprof(t, "-buildmode=pie", "CgoPprof", "cpuHog", "runtime.main")
}

func TestCgoPprofThread(t *testing.T) {
	testCgoPprof(t, "", "CgoPprofThread", "cpuHogThread", "cpuHogThread2")
}

func TestCgoPprofThreadNoTraceback(t *testing.T) {
	testCgoPprof(t, "", "CgoPprofThreadNoTraceback", "cpuHogThread", "runtime._ExternalCode")
}

func TestRaceProf(t *testing.T) {
	if !platform.RaceDetectorSupported(runtime.GOOS, runtime.GOARCH) {
		t.Skipf("skipping on %s/%s because race detector not supported", runtime.GOOS, runtime.GOARCH)
	}
	if runtime.GOOS == "windows" {
		t.Skipf("skipping: test requires pthread support")
		// TODO: Can this test be rewritten to use the C11 thread API instead?
	}

	testenv.MustHaveGoRun(t)

	// This test requires building various packages with -race, so
	// it's somewhat slow.
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}

	exe, err := buildTestProg(t, "testprogcgo", "-race")
	if err != nil {
		t.Fatal(err)
	}

	got, err := testenv.CleanCmdEnv(exec.Command(exe, "CgoRaceprof")).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	want := "OK\n"
	if string(got) != want {
		t.Errorf("expected %q got %s", want, got)
	}
}

func TestRaceSignal(t *testing.T) {
	if !platform.RaceDetectorSupported(runtime.GOOS, runtime.GOARCH) {
		t.Skipf("skipping on %s/%s because race detector not supported", runtime.GOOS, runtime.GOARCH)
	}
	if runtime.GOOS == "windows" {
		t.Skipf("skipping: test requires pthread support")
		// TODO: Can this test be rewritten to use the C11 thread API instead?
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		testenv.SkipFlaky(t, 60316)
	}

	t.Parallel()

	testenv.MustHaveGoRun(t)

	// This test requires building various packages with -race, so
	// it's somewhat slow.
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}

	exe, err := buildTestProg(t, "testprogcgo", "-race")
	if err != nil {
		t.Fatal(err)
	}

	got, err := testenv.CleanCmdEnv(testenv.Command(t, exe, "CgoRaceSignal")).CombinedOutput()
	if err != nil {
		t.Logf("%s\n", got)
		t.Fatal(err)
	}
	want := "OK\n"
	if string(got) != want {
		t.Errorf("expected %q got %s", want, got)
	}
}

func TestCgoNumGoroutine(t *testing.T) {
	switch runtime.GOOS {
	case "windows", "plan9":
		t.Skipf("skipping numgoroutine test on %s", runtime.GOOS)
	}
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "NumGoroutine")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func TestCatchPanic(t *testing.T) {
	t.Parallel()
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no signals on %s", runtime.GOOS)
	case "darwin":
		if runtime.GOARCH == "amd64" {
			t.Skipf("crash() on darwin/amd64 doesn't raise SIGABRT")
		}
	}

	testenv.MustHaveGoRun(t)

	exe, err := buildTestProg(t, "testprogcgo")
	if err != nil {
		t.Fatal(err)
	}

	for _, early := range []bool{true, false} {
		cmd := testenv.CleanCmdEnv(exec.Command(exe, "CgoCatchPanic"))
		// Make sure a panic results in a crash.
		cmd.Env = append(cmd.Env, "GOTRACEBACK=crash")
		if early {
			// Tell testprogcgo to install an early signal handler for SIGABRT
			cmd.Env = append(cmd.Env, "CGOCATCHPANIC_EARLY_HANDLER=1")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("testprogcgo CgoCatchPanic failed: %v\n%s", err, out)
		}
	}
}

func TestCgoLockOSThreadExit(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no pthreads on %s", runtime.GOOS)
	}
	t.Parallel()
	testLockOSThreadExit(t, "testprogcgo")
}

func TestWindowsStackMemoryCgo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping windows specific test")
	}
	testenv.SkipFlaky(t, 22575)
	o := runTestProg(t, "testprogcgo", "StackMemory")
	stackUsage, err := strconv.Atoi(o)
	if err != nil {
		t.Fatalf("Failed to read stack usage: %v", err)
	}
	if expected, got := 100<<10, stackUsage; got > expected {
		t.Fatalf("expected < %d bytes of memory per thread, got %d", expected, got)
	}
}

func TestSigStackSwapping(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no sigaltstack on %s", runtime.GOOS)
	}
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "SigStack")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func TestCgoTracebackSigpanic(t *testing.T) {
	// Test unwinding over a sigpanic in C code without a C
	// symbolizer. See issue #23576.
	if runtime.GOOS == "windows" {
		// On Windows if we get an exception in C code, we let
		// the Windows exception handler unwind it, rather
		// than injecting a sigpanic.
		t.Skip("no sigpanic in C on windows")
	}
	if runtime.GOOS == "ios" {
		testenv.SkipFlaky(t, 59912)
	}
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "TracebackSigpanic")
	t.Log(got)
	// We should see the function that calls the C function.
	want := "main.TracebackSigpanic"
	if !strings.Contains(got, want) {
		if runtime.GOOS == "android" && (runtime.GOARCH == "arm" || runtime.GOARCH == "arm64") {
			testenv.SkipFlaky(t, 58794)
		}
		t.Errorf("did not see %q in output", want)
	}
	// We shouldn't inject a sigpanic call. (see issue 57698)
	nowant := "runtime.sigpanic"
	if strings.Contains(got, nowant) {
		t.Errorf("unexpectedly saw %q in output", nowant)
	}
	// No runtime errors like "runtime: unexpected return pc".
	nowant = "runtime: "
	if strings.Contains(got, nowant) {
		t.Errorf("unexpectedly saw %q in output", nowant)
	}
}

func TestCgoPanicCallback(t *testing.T) {
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "PanicCallback")
	t.Log(got)
	want := "panic: runtime error: invalid memory address or nil pointer dereference"
	if !strings.Contains(got, want) {
		t.Errorf("did not see %q in output", want)
	}
	want = "panic_callback"
	if !strings.Contains(got, want) {
		t.Errorf("did not see %q in output", want)
	}
	want = "PanicCallback"
	if !strings.Contains(got, want) {
		t.Errorf("did not see %q in output", want)
	}
	// No runtime errors like "runtime: unexpected return pc".
	nowant := "runtime: "
	if strings.Contains(got, nowant) {
		t.Errorf("did not see %q in output", want)
	}
}

// Test that C code called via cgo can use large Windows thread stacks
// and call back in to Go without crashing. See issue #20975.
//
// See also TestBigStackCallbackSyscall.
func TestBigStackCallbackCgo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping windows specific test")
	}
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "BigStack")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q got %v", want, got)
	}
}

func nextTrace(lines []string) ([]string, []string) {
	var trace []string
	for n, line := range lines {
		if strings.HasPrefix(line, "---") {
			return trace, lines[n+1:]
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		// Last field contains the function name.
		trace = append(trace, fields[len(fields)-1])
	}
	return nil, nil
}

func findTrace(text, top string) []string {
	lines := strings.Split(text, "\n")
	_, lines = nextTrace(lines) // Skip the header.
	for len(lines) > 0 {
		var t []string
		t, lines = nextTrace(lines)
		if len(t) == 0 {
			continue
		}
		if t[0] == top {
			return t
		}
	}
	return nil
}

func TestSegv(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no signals on %s", runtime.GOOS)
	}

	for _, test := range []string{"Segv", "SegvInCgo", "TgkillSegv", "TgkillSegvInCgo"} {
		test := test

		// The tgkill variants only run on Linux.
		if runtime.GOOS != "linux" && strings.HasPrefix(test, "Tgkill") {
			continue
		}

		t.Run(test, func(t *testing.T) {
			if test == "SegvInCgo" && runtime.GOOS == "ios" {
				testenv.SkipFlaky(t, 59947) // Don't even try, in case it times out.
			}

			t.Parallel()
			prog := "testprog"
			if strings.HasSuffix(test, "InCgo") {
				prog = "testprogcgo"
			}
			got := runTestProg(t, prog, test)
			t.Log(got)
			want := "SIGSEGV"
			if !strings.Contains(got, want) {
				if runtime.GOOS == "darwin" && runtime.GOARCH == "amd64" && strings.Contains(got, "fatal: morestack on g0") {
					testenv.SkipFlaky(t, 39457)
				}
				t.Errorf("did not see %q in output", want)
			}

			// No runtime errors like "runtime: unknown pc".
			switch runtime.GOOS {
			case "darwin", "ios", "illumos", "solaris":
				// Runtime sometimes throws when generating the traceback.
				testenv.SkipFlaky(t, 49182)
			case "linux":
				if runtime.GOARCH == "386" {
					// Runtime throws when generating a traceback from
					// a VDSO call via asmcgocall.
					testenv.SkipFlaky(t, 50504)
				}
			}
			if test == "SegvInCgo" && strings.Contains(got, "unknown pc") {
				testenv.SkipFlaky(t, 50979)
			}

			for _, nowant := range []string{"fatal error: ", "runtime: "} {
				if strings.Contains(got, nowant) {
					if runtime.GOOS == "darwin" && strings.Contains(got, "0xb01dfacedebac1e") {
						// See the comment in signal_darwin_amd64.go.
						t.Skip("skipping due to Darwin handling of malformed addresses")
					}
					t.Errorf("unexpectedly saw %q in output", nowant)
				}
			}
		})
	}
}

func TestAbortInCgo(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows":
		// N.B. On Windows, C abort() causes the program to exit
		// without going through the runtime at all.
		t.Skipf("no signals on %s", runtime.GOOS)
	}

	t.Parallel()
	got := runTestProg(t, "testprogcgo", "Abort")
	t.Log(got)
	want := "SIGABRT"
	if !strings.Contains(got, want) {
		t.Errorf("did not see %q in output", want)
	}
	// No runtime errors like "runtime: unknown pc".
	nowant := "runtime: "
	if strings.Contains(got, nowant) {
		t.Errorf("did not see %q in output", want)
	}
}

// TestEINTR tests that we handle EINTR correctly.
// See issue #20400 and friends.
func TestEINTR(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no EINTR on %s", runtime.GOOS)
	case "linux":
		if runtime.GOARCH == "386" {
			// On linux-386 the Go signal handler sets
			// a restorer function that is not preserved
			// by the C sigaction call in the test,
			// causing the signal handler to crash when
			// returning the normal code. The test is not
			// architecture-specific, so just skip on 386
			// rather than doing a complicated workaround.
			t.Skip("skipping on linux-386; C sigaction does not preserve Go restorer")
		}
	}

	t.Parallel()
	output := runTestProg(t, "testprogcgo", "EINTR")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

// Issue #42207.
func TestNeedmDeadlock(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("no signals on %s", runtime.GOOS)
	}
	output := runTestProg(t, "testprogcgo", "NeedmDeadlock")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestCgoNoCallback(t *testing.T) {
	got := runTestProg(t, "testprogcgo", "CgoNoCallback")
	want := "function marked with #cgo nocallback called back into Go"
	if !strings.Contains(got, want) {
		t.Fatalf("did not see %q in output:\n%s", want, got)
	}
}

func TestCgoNoEscape(t *testing.T) {
	got := runTestProg(t, "testprogcgo", "CgoNoEscape")
	want := "OK\n"
	if got != want {
		t.Fatalf("want %s, got %s\n", want, got)
	}
}

// Issue #63739.
func TestCgoEscapeWithMultiplePointers(t *testing.T) {
	got := runTestProg(t, "testprogcgo", "CgoEscapeWithMultiplePointers")
	want := "OK\n"
	if got != want {
		t.Fatalf("output is %s; want %s", got, want)
	}
}

func TestCgoTracebackGoroutineProfile(t *testing.T) {
	output := runTestProg(t, "testprogcgo", "GoroutineProfile")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestCgoSigfwd(t *testing.T) {
	t.Parallel()
	if !goos.IsUnix {
		t.Skipf("no signals on %s", runtime.GOOS)
	}

	got := runTestProg(t, "testprogcgo", "CgoSigfwd", "GO_TEST_CGOSIGFWD=1")
	if want := "OK\n"; got != want {
		t.Fatalf("expected %q, but got:\n%s", want, got)
	}
}

func TestDestructorCallback(t *testing.T) {
	t.Parallel()
	got := runTestProg(t, "testprogcgo", "DestructorCallback")
	if want := "OK\n"; got != want {
		t.Errorf("expected %q, but got:\n%s", want, got)
	}
}

func TestDestructorCallbackRace(t *testing.T) {
	// This test requires building with -race,
	// so it's somewhat slow.
	if testing.Short() {
		t.Skip("skipping test in -short mode")
	}

	if !platform.RaceDetectorSupported(runtime.GOOS, runtime.GOARCH) {
		t.Skipf("skipping on %s/%s because race detector not supported", runtime.GOOS, runtime.GOARCH)
	}

	t.Parallel()

	exe, err := buildTestProg(t, "testprogcgo", "-race")
	if err != nil {
		t.Fatal(err)
	}

	got, err := testenv.CleanCmdEnv(exec.Command(exe, "DestructorCallback")).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	if want := "OK\n"; string(got) != want {
		t.Errorf("expected %q, but got:\n%s", want, got)
	}
}

func TestEnsureBindM(t *testing.T) {
	t.Parallel()
	switch runtime.GOOS {
	case "windows", "plan9":
		t.Skipf("skipping bindm test on %s", runtime.GOOS)
	}
	got := runTestProg(t, "testprogcgo", "EnsureBindM")
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

func TestStackSwitchCallback(t *testing.T) {
	t.Parallel()
	switch runtime.GOOS {
	case "windows", "plan9", "android", "ios", "openbsd": // no getcontext
		t.Skipf("skipping test on %s", runtime.GOOS)
	}
	got := runTestProg(t, "testprogcgo", "StackSwitchCallback")
	skip := "SKIP\n"
	if got == skip {
		t.Skip("skipping on musl/bionic libc")
	}
	want := "OK\n"
	if got != want {
		t.Errorf("expected %q, got %v", want, got)
	}
}

func TestCgoToGoCallGoexit(t *testing.T) {
	if runtime.GOOS == "plan9" || runtime.GOOS == "windows" {
		t.Skipf("no pthreads on %s", runtime.GOOS)
	}
	output := runTestProg(t, "testprogcgo", "CgoToGoCallGoexit")
	if !strings.Contains(output, "runtime.Goexit called in a thread that was not created by the Go runtime") {
		t.Fatalf("output should contain %s, got %s", "runtime.Goexit called in a thread that was not created by the Go runtime", output)
	}
}
```