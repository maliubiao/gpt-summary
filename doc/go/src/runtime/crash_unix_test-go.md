Response:
我的思考过程如下：

1. **理解目标：** 核心目标是分析给定的 Go 源代码文件 `crash_unix_test.go`，并解释其功能，特别是与 Go 语言的崩溃处理机制相关的部分。需要识别测试用例，并尝试理解其背后的测试意图。

2. **初步浏览代码结构：**  首先，我快速浏览了整个代码，注意到了以下几个关键点：
    * **`//go:build unix` 编译指令:**  这表明该文件中的测试仅在 Unix-like 系统上构建和运行。
    * **`package runtime_test`:**  说明这些测试是针对 `runtime` 包的。
    * **`import` 语句:**  导入了 `bytes`, `internal/testenv`, `io`, `os`, `os/exec`, `runtime`, `runtime/debug`, `strings`, `sync`, `syscall`, `testing`, `time`, `unsafe` 等包，这些包暗示了测试涉及文件操作、进程管理、信号处理、并发、底层系统调用等方面。
    * **大量的 `func Test...` 函数:**  这表明代码主要由测试函数组成。

3. **逐个分析测试函数：** 我开始逐个分析 `Test...` 开头的函数，尝试理解每个测试用例的目的。

    * **`TestBadOpen`:**  这个测试看起来很简单，它测试了在 `runtime.Open`, `runtime.Read`, `runtime.Write`, `runtime.Close` 等底层文件操作函数处理无效文件描述符时的错误码是否正确。
    * **`TestCrashDumpsAllThreads`:** 这个测试名称暗示了它与程序崩溃时转储所有线程堆栈信息有关。代码中使用了 `GOTRACEBACK=crash` 环境变量，并且发送了 `SIGQUIT` 信号，这进一步证实了这一点。测试期望在崩溃转储中看到所有相关线程的堆栈信息。
    * **`TestPanicSystemstack`:** 这个测试关注的是当程序在系统栈上发生 panic 时，`GOTRACEBACK=crash` 是否能正确打印系统栈和用户栈的信息。它创建了一个子进程，并在子进程中模拟这种情况。
    * **`TestSignalExitStatus`:**  这个测试验证了当程序收到信号终止时，返回的退出状态码是否正确地反映了该信号。
    * **`TestSignalIgnoreSIGTRAP`:**  这个测试检查程序是否能够忽略 `SIGTRAP` 信号。
    * **`TestSignalDuringExec`:**  这个测试似乎与在 `exec` 系统调用执行期间发送信号有关，并检查程序是否能正确处理。
    * **`TestSignalM`:**  这个测试看起来比较复杂，涉及到使用 `runtime.WaitForSigusr1` 和 `runtime.SendSigusr1`，暗示了测试 goroutine 如何等待和接收特定的用户定义信号。

4. **识别关键的 Go 语言功能：** 在分析测试用例的过程中，我识别出了几个关键的 Go 语言功能：

    * **`runtime` 包提供的底层接口:** 例如 `runtime.Open`, `runtime.Read`, `runtime.Write`, `runtime.Close`, `runtime.BlockOnSystemStack`, `runtime.GOMAXPROCS`, `runtime.WaitForSigusr1`, `runtime.SendSigusr1` 等。
    * **`syscall` 包提供的系统调用接口:** 例如 `syscall.SIGQUIT`, `syscall.SIGTERM`, `syscall.SIGUSR1`, `syscall.EBADF` 等。
    * **`os/exec` 包用于执行外部命令:**  例如用于启动子进程来模拟崩溃场景。
    * **`GOTRACEBACK` 环境变量:**  这是一个控制 Go 程序崩溃时输出信息的环境变量。
    * **信号处理:**  通过 `syscall` 包发送和接收信号。
    * **`runtime.LockOSThread` 和 `runtime.UnlockOSThread`:** 用于将 goroutine 绑定到特定的操作系统线程。

5. **推断实现的功能：** 基于对测试用例的理解，我推断出 `crash_unix_test.go` 主要测试了 Go 语言 runtime 包在 Unix 系统上的崩溃处理和信号处理机制，具体包括：

    * **错误处理:**  测试底层文件操作函数在遇到错误时的返回码。
    * **崩溃转储:**  测试 `GOTRACEBACK=crash` 环境变量是否能正确地转储所有线程的堆栈信息，包括用户栈和系统栈。
    * **信号处理:**  测试程序如何响应和处理各种信号，包括终止信号、用户定义信号等。
    * **在系统栈上运行代码:**  测试在系统栈上发生 panic 时的处理。

6. **构建代码示例：**  针对我推断出的功能，我构建了相应的 Go 代码示例，力求简洁明了地展示这些功能的使用方法和效果。

7. **推理代码的输入和输出：** 对于涉及到代码推理的测试（如 `TestCrashDumpsAllThreads` 和 `TestPanicSystemstack`），我尝试描述测试程序的输入（例如发送的信号）和预期的输出（例如崩溃转储包含特定信息）。

8. **解释命令行参数：**  我详细解释了 `GOTRACEBACK` 环境变量及其不同的取值对崩溃信息输出的影响。

9. **识别易犯错误点：**  我思考了在使用 `GOTRACEBACK` 时可能出现的误解或错误用法，例如没有设置环境变量导致无法获取详细的崩溃信息。

10. **组织答案并使用中文表达：** 最后，我将以上分析结果组织成结构清晰、易于理解的中文答案，并确保涵盖了所有要求。我使用了分点说明的方式，并针对每个测试用例和功能进行了详细的解释。

通过以上步骤，我完成了对 `crash_unix_test.go` 文件的分析和解释。整个过程是一个逐步深入、由表及里的过程，从初步了解代码结构到深入理解每个测试用例的目的，最终推断出其背后的 Go 语言功能实现。

这段Go语言代码是 `runtime` 包的一部分，专门用于在 Unix 系统上测试 Go 程序的崩溃处理和信号处理机制。它包含多个测试函数，旨在验证 Go runtime 在遇到各种错误和信号时的行为是否符合预期。

以下是它的主要功能：

1. **测试错误的文件操作:** `TestBadOpen` 函数测试了当使用 `runtime.Open`、`runtime.Read`、`runtime.Write` 和 `runtime.Close` 操作无效的文件描述符时，是否能得到正确的错误码（例如 `syscall.EBADF`）。这确保了 Go runtime 能够正确地处理底层的系统调用错误。

   ```go
   // 假设我们尝试打开一个不存在的文件
   fd := runtime.Open(unsafe.Pointer(&[]byte("/notreallyafile")[0]), 0, 0)
   // 预期输出：fd 的值为 -1，表示打开失败

   // 假设我们尝试读取一个无效的文件描述符
   var buf [32]byte
   r := runtime.Read(-1, unsafe.Pointer(&buf[0]), int32(len(buf)))
   // 预期输出：r 的值为 -int32(syscall.EBADF)，表示 "Bad file descriptor" 错误
   ```

2. **测试崩溃时转储所有线程的堆栈信息:** `TestCrashDumpsAllThreads` 函数验证了当程序因为收到 `SIGQUIT` 信号而崩溃时，Go runtime 是否能够转储所有 goroutine 的堆栈信息。它会启动一个子进程，该子进程创建多个 goroutine 并进入死循环，然后向子进程发送 `SIGQUIT` 信号使其崩溃。测试会检查崩溃转储信息中是否包含所有 goroutine 的堆栈跟踪。

   **推理的 Go 语言功能： `GOTRACEBACK` 环境变量**

   这个测试主要验证了 `GOTRACEBACK` 环境变量在设置为 `crash` 时的行为。当 `GOTRACEBACK=crash` 时，Go 程序在发生 panic 或收到某些信号（例如 `SIGQUIT`）时，会打印出所有 goroutine 的堆栈跟踪信息，这对于调试并发程序非常有用。

   **Go 代码示例：**

   ```go
   // 编译并运行一个简单的 Go 程序，该程序会故意 panic
   // 假设 testprog.go 包含以下代码：
   /*
   package main

   import "fmt"

   func main() {
       panic("故意触发 panic")
   }
   */

   cmd := exec.Command("go", "run", "testprog.go")
   cmd.Env = append(os.Environ(), "GOTRACEBACK=crash") // 设置环境变量
   output, err := cmd.CombinedOutput()

   if err != nil {
       fmt.Println("程序崩溃了：")
       fmt.Println(string(output)) // 输出应该包含详细的堆栈跟踪信息
   }
   ```

   **假设的输入与输出：**

   * **输入：** 运行编译后的 `testprog.go` 程序，并设置环境变量 `GOTRACEBACK=crash`。
   * **输出：** 如果程序发生 panic，控制台输出将会包含 `panic: 故意触发 panic` 以及详细的 goroutine 堆栈跟踪信息，指明 panic 发生的位置。

   **命令行参数处理：**

   `GOTRACEBACK` 是一个环境变量，而不是命令行参数。可以通过以下方式设置：

   * **在运行命令前设置环境变量：** `GOTRACEBACK=crash go run your_program.go`
   * **在代码中使用 `os.Setenv`：**  ```go os.Setenv("GOTRACEBACK", "crash") ```

3. **测试在系统栈上 panic 的处理:** `TestPanicSystemstack` 函数测试了当一个 goroutine 在执行系统调用或者 runtime 内部代码时发生 panic，`GOTRACEBACK=crash` 是否能正确地打印出系统栈和用户栈的信息。这对于诊断 runtime 内部的错误很有帮助。

   **推断的 Go 语言功能：`runtime.BlockOnSystemStack()`**

   `runtime.BlockOnSystemStack()` 函数会将当前的 goroutine 切换到系统栈上执行。这通常用于执行一些需要直接操作操作系统资源的低级操作。`TestPanicSystemstack` 测试了在这种情况下发生 panic 时，崩溃信息的完整性。

   **Go 代码示例：**

   ```go
   package main

   import (
       "fmt"
       "runtime"
   )

   func main() {
       runtime.LockOSThread() // 将当前 goroutine 绑定到操作系统线程
       defer runtime.UnlockOSThread()

       // 在系统栈上执行代码
       runtime.BlockOnSystemStack(func() {
           panic("在系统栈上触发 panic")
       })
   }
   ```

   **假设的输入与输出：**

   * **输入：** 运行上述代码，并设置环境变量 `GOTRACEBACK=crash`。
   * **输出：** 控制台输出会包含 `panic: 在系统栈上触发 panic`，以及包括系统栈和用户栈的详细堆栈跟踪信息。

4. **测试信号的退出状态:** `TestSignalExitStatus` 函数验证了当程序收到信号（例如 `SIGTERM`）而退出时，返回的退出状态码是否正确地反映了该信号。这确保了程序能够正确地报告其终止原因。

5. **测试忽略 `SIGTRAP` 信号:** `TestSignalIgnoreSIGTRAP` 函数检查程序是否能够忽略 `SIGTRAP` 信号。`SIGTRAP` 通常用于调试器，Go 程序在正常情况下应该能够忽略它。

6. **测试 `exec` 期间的信号处理:** `TestSignalDuringExec` 函数测试了在程序执行 `exec` 系统调用期间收到信号时的处理情况，确保程序行为的正确性。

7. **测试 `runtime.WaitForSigusr1` 和 `runtime.SendSigusr1`:** `TestSignalM` 函数测试了 `runtime.WaitForSigusr1` 和 `runtime.SendSigusr1` 这两个 runtime 提供的用于在 goroutine 之间发送和接收 `SIGUSR1` 信号的功能。这允许 goroutine 在不需要 cgo 的情况下进行进程内的信号通信。

   **Go 代码示例：**

   ```go
   package main

   import (
       "fmt"
       "runtime"
       "sync"
       "syscall"
   )

   func main() {
       runtime.LockOSThread()
       defer runtime.UnlockOSThread()

       r, w, err := runtime.Pipe()
       if err != nil {
           panic(err)
       }
       defer runtime.Close(r)
       defer runtime.Close(w)

       var wg sync.WaitGroup
       wg.Add(1)
       go func() {
           runtime.LockOSThread()
           defer runtime.UnlockOSThread()
           fmt.Println("等待 SIGUSR1...")
           runtime.WaitForSigusr1(r, w, func(mp *runtime.M) {
               fmt.Println("接收到 SIGUSR1")
           })
           wg.Done()
       }()

       // 等待一小段时间，确保子 goroutine 进入等待状态
       runtime.Gosched()

       // 获取子 goroutine 对应的 M
       var allMs []*runtime.M
       runtime.LockInternal(nil)
       runtime.Gentraceback(0, 0, 0, &allMs)
       runtime.UnlockInternal(nil)

       var targetM *runtime.M
       for _, m := range allMs {
           // 这里需要某种方式来识别目标 goroutine 的 M，例如通过 Goid 或其他标识
           // 简化起见，假设我们知道它是第二个 M
           // 这段代码只是为了演示概念，实际应用中需要更可靠的 M 识别方法
           // 注意：直接访问 runtime 内部结构可能不稳定
           if m.ID == 2 {
               targetM = m
               break
           }
       }

       if targetM != nil {
           fmt.Println("发送 SIGUSR1...")
           runtime.SendSigusr1(targetM)
       }

       wg.Wait()
       fmt.Println("程序结束")
   }
   ```

   **注意：**  直接操作 `runtime.M` 结构体是比较底层的操作，并且可能在 Go 的不同版本之间发生变化。在实际开发中，通常有更高级的并发控制方法。这个例子是为了演示 `runtime.WaitForSigusr1` 和 `runtime.SendSigusr1` 的使用。

**使用者易犯错的点：**

* **忘记设置 `GOTRACEBACK` 环境变量：**  在调试崩溃问题时，如果没有设置 `GOTRACEBACK=crash`，Go 程序默认只会输出简略的错误信息，不利于定位问题。使用者可能会忘记设置这个环境变量，导致无法获取详细的堆栈跟踪。

   **示例：** 假设一个程序发生了 panic，但是运行程序时没有设置 `GOTRACEBACK=crash`，输出可能只会是 `panic: your error message`，而没有具体的代码调用堆栈。

* **错误地理解 `runtime.LockOSThread` 的作用：**  `runtime.LockOSThread` 将 goroutine 绑定到特定的操作系统线程。如果不理解其作用，可能会在不需要绑定的场景下使用，或者在需要绑定的场景下忘记使用，导致程序出现意外行为，尤其是在涉及系统调用或信号处理时。

总而言之，`go/src/runtime/crash_unix_test.go` 是一组重要的测试，用于确保 Go runtime 在 Unix 系统上的崩溃处理和信号处理机制的正确性和稳定性。它覆盖了多种场景，并使用了 runtime 包提供的底层接口来模拟和验证这些行为。

Prompt: 
```
这是路径为go/src/runtime/crash_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package runtime_test

import (
	"bytes"
	"internal/testenv"
	"io"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func init() {
	if runtime.Sigisblocked(int(syscall.SIGQUIT)) {
		// We can't use SIGQUIT to kill subprocesses because
		// it's blocked. Use SIGKILL instead. See issue
		// #19196 for an example of when this happens.
		testenv.Sigquit = syscall.SIGKILL
	}
}

func TestBadOpen(t *testing.T) {
	// make sure we get the correct error code if open fails. Same for
	// read/write/close on the resulting -1 fd. See issue 10052.
	nonfile := []byte("/notreallyafile")
	fd := runtime.Open(&nonfile[0], 0, 0)
	if fd != -1 {
		t.Errorf("open(%q)=%d, want -1", nonfile, fd)
	}
	var buf [32]byte
	r := runtime.Read(-1, unsafe.Pointer(&buf[0]), int32(len(buf)))
	if got, want := r, -int32(syscall.EBADF); got != want {
		t.Errorf("read()=%d, want %d", got, want)
	}
	w := runtime.Write(^uintptr(0), unsafe.Pointer(&buf[0]), int32(len(buf)))
	if got, want := w, -int32(syscall.EBADF); got != want {
		t.Errorf("write()=%d, want %d", got, want)
	}
	c := runtime.Close(-1)
	if c != -1 {
		t.Errorf("close()=%d, want -1", c)
	}
}

func TestCrashDumpsAllThreads(t *testing.T) {
	if *flagQuick {
		t.Skip("-quick")
	}

	switch runtime.GOOS {
	case "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "illumos", "solaris":
	default:
		t.Skipf("skipping; not supported on %v", runtime.GOOS)
	}

	if runtime.GOOS == "openbsd" && (runtime.GOARCH == "arm" || runtime.GOARCH == "mips64" || runtime.GOARCH == "ppc64") {
		// This may be ncpu < 2 related...
		t.Skipf("skipping; test fails on %s/%s - see issue #42464", runtime.GOOS, runtime.GOARCH)
	}

	if runtime.Sigisblocked(int(syscall.SIGQUIT)) {
		t.Skip("skipping; SIGQUIT is blocked, see golang.org/issue/19196")
	}

	testenv.MustHaveGoBuild(t)

	if strings.Contains(os.Getenv("GOFLAGS"), "mayMoreStackPreempt") {
		// This test occasionally times out in this debug mode. This is probably
		// revealing a real bug in the scheduler, but since it seems to only
		// affect this test and this is itself a test of a debug mode, it's not
		// a high priority.
		testenv.SkipFlaky(t, 55160)
	}

	exe, err := buildTestProg(t, "testprog")
	if err != nil {
		t.Fatal(err)
	}

	cmd := testenv.Command(t, exe, "CrashDumpsAllThreads")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Dir = t.TempDir() // put any core file in tempdir
	cmd.Env = append(cmd.Env,
		"GOTRACEBACK=crash",
		// Set GOGC=off. Because of golang.org/issue/10958, the tight
		// loops in the test program are not preemptible. If GC kicks
		// in, it may lock up and prevent main from saying it's ready.
		"GOGC=off",
		// Set GODEBUG=asyncpreemptoff=1. If a thread is preempted
		// when it receives SIGQUIT, it won't show the expected
		// stack trace. See issue 35356.
		"GODEBUG=asyncpreemptoff=1",
	)

	var outbuf bytes.Buffer
	cmd.Stdout = &outbuf
	cmd.Stderr = &outbuf

	rp, wp, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rp.Close()

	cmd.ExtraFiles = []*os.File{wp}

	if err := cmd.Start(); err != nil {
		wp.Close()
		t.Fatalf("starting program: %v", err)
	}

	if err := wp.Close(); err != nil {
		t.Logf("closing write pipe: %v", err)
	}
	if _, err := rp.Read(make([]byte, 1)); err != nil {
		t.Fatalf("reading from pipe: %v", err)
	}

	if err := cmd.Process.Signal(syscall.SIGQUIT); err != nil {
		t.Fatalf("signal: %v", err)
	}

	// No point in checking the error return from Wait--we expect
	// it to fail.
	cmd.Wait()

	// We want to see a stack trace for each thread.
	// Before https://golang.org/cl/2811 running threads would say
	// "goroutine running on other thread; stack unavailable".
	out := outbuf.Bytes()
	n := bytes.Count(out, []byte("main.crashDumpsAllThreadsLoop("))
	if n != 4 {
		t.Errorf("found %d instances of main.crashDumpsAllThreadsLoop; expected 4", n)
		t.Logf("%s", out)
	}
}

func TestPanicSystemstack(t *testing.T) {
	// Test that GOTRACEBACK=crash prints both the system and user
	// stack of other threads.

	// The GOTRACEBACK=crash handler takes 0.1 seconds even if
	// it's not writing a core file and potentially much longer if
	// it is. Skip in short mode.
	if testing.Short() {
		t.Skip("Skipping in short mode (GOTRACEBACK=crash is slow)")
	}

	if runtime.Sigisblocked(int(syscall.SIGQUIT)) {
		t.Skip("skipping; SIGQUIT is blocked, see golang.org/issue/19196")
	}

	t.Parallel()
	cmd := exec.Command(os.Args[0], "testPanicSystemstackInternal")
	cmd = testenv.CleanCmdEnv(cmd)
	cmd.Dir = t.TempDir() // put any core file in tempdir
	cmd.Env = append(cmd.Env, "GOTRACEBACK=crash")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal("creating pipe: ", err)
	}
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		t.Fatal("starting command: ", err)
	}
	defer cmd.Process.Wait()
	defer cmd.Process.Kill()
	if err := pw.Close(); err != nil {
		t.Log("closing write pipe: ", err)
	}
	defer pr.Close()

	// Wait for "x\nx\n" to indicate almost-readiness.
	buf := make([]byte, 4)
	_, err = io.ReadFull(pr, buf)
	if err != nil || string(buf) != "x\nx\n" {
		t.Fatal("subprocess failed; output:\n", string(buf))
	}

	// The child blockers print "x\n" and then block on a lock. Receiving
	// those bytes only indicates that the child is _about to block_. Since
	// we don't have a way to know when it is fully blocked, sleep a bit to
	// make us less likely to lose the race and signal before the child
	// blocks.
	time.Sleep(100 * time.Millisecond)

	// Send SIGQUIT.
	if err := cmd.Process.Signal(syscall.SIGQUIT); err != nil {
		t.Fatal("signaling subprocess: ", err)
	}

	// Get traceback.
	tb, err := io.ReadAll(pr)
	if err != nil {
		t.Fatal("reading traceback from pipe: ", err)
	}

	// Traceback should have two testPanicSystemstackInternal's
	// and two blockOnSystemStackInternal's.
	userFunc := "testPanicSystemstackInternal"
	sysFunc := "blockOnSystemStackInternal"
	nUser := bytes.Count(tb, []byte(userFunc))
	nSys := bytes.Count(tb, []byte(sysFunc))
	if nUser != 2 || nSys != 2 {
		t.Fatalf("want %d user stack frames in %s and %d system stack frames in %s, got %d and %d:\n%s", 2, userFunc, 2, sysFunc, nUser, nSys, string(tb))
	}

	// Traceback should not contain "unexpected SPWRITE" when
	// unwinding the system stacks.
	if bytes.Contains(tb, []byte("unexpected SPWRITE")) {
		t.Errorf("unexpected \"unexpected SPWRITE\" in traceback:\n%s", tb)
	}
}

func init() {
	if len(os.Args) >= 2 && os.Args[1] == "testPanicSystemstackInternal" {
		// Complete any in-flight GCs and disable future ones. We're going to
		// block goroutines on runtime locks, which aren't ever preemptible for the
		// GC to scan them.
		runtime.GC()
		debug.SetGCPercent(-1)
		// Get two threads running on the system stack with
		// something recognizable in the stack trace.
		runtime.GOMAXPROCS(2)
		go testPanicSystemstackInternal()
		testPanicSystemstackInternal()
	}
}

func testPanicSystemstackInternal() {
	runtime.BlockOnSystemStack()
	os.Exit(1) // Should be unreachable.
}

func TestSignalExitStatus(t *testing.T) {
	testenv.MustHaveGoBuild(t)
	exe, err := buildTestProg(t, "testprog")
	if err != nil {
		t.Fatal(err)
	}
	err = testenv.CleanCmdEnv(exec.Command(exe, "SignalExitStatus")).Run()
	if err == nil {
		t.Error("test program succeeded unexpectedly")
	} else if ee, ok := err.(*exec.ExitError); !ok {
		t.Errorf("error (%v) has type %T; expected exec.ExitError", err, err)
	} else if ws, ok := ee.Sys().(syscall.WaitStatus); !ok {
		t.Errorf("error.Sys (%v) has type %T; expected syscall.WaitStatus", ee.Sys(), ee.Sys())
	} else if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Errorf("got %v; expected SIGTERM", ee)
	}
}

func TestSignalIgnoreSIGTRAP(t *testing.T) {
	if runtime.GOOS == "openbsd" {
		testenv.SkipFlaky(t, 49725)
	}

	output := runTestProg(t, "testprognet", "SignalIgnoreSIGTRAP")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestSignalDuringExec(t *testing.T) {
	switch runtime.GOOS {
	case "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd":
	default:
		t.Skipf("skipping test on %s", runtime.GOOS)
	}
	output := runTestProg(t, "testprognet", "SignalDuringExec")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestSignalM(t *testing.T) {
	r, w, errno := runtime.Pipe()
	if errno != 0 {
		t.Fatal(syscall.Errno(errno))
	}
	defer func() {
		runtime.Close(r)
		runtime.Close(w)
	}()
	runtime.Closeonexec(r)
	runtime.Closeonexec(w)

	var want, got int64
	var wg sync.WaitGroup
	ready := make(chan *runtime.M)
	wg.Add(1)
	go func() {
		runtime.LockOSThread()
		want, got = runtime.WaitForSigusr1(r, w, func(mp *runtime.M) {
			ready <- mp
		})
		runtime.UnlockOSThread()
		wg.Done()
	}()
	waitingM := <-ready
	runtime.SendSigusr1(waitingM)

	timer := time.AfterFunc(time.Second, func() {
		// Write 1 to tell WaitForSigusr1 that we timed out.
		bw := byte(1)
		if n := runtime.Write(uintptr(w), unsafe.Pointer(&bw), 1); n != 1 {
			t.Errorf("pipe write failed: %d", n)
		}
	})
	defer timer.Stop()

	wg.Wait()
	if got == -1 {
		t.Fatal("signalM signal not received")
	} else if want != got {
		t.Fatalf("signal sent to M %d, but received on M %d", want, got)
	}
}

"""



```