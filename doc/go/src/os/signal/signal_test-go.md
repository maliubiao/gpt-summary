Response:
Let's break down the thought process for analyzing this Go code snippet and generating the comprehensive answer.

1. **Understanding the Goal:** The core request is to analyze the given Go code (`signal_test.go`), identify its purpose, provide examples, and highlight potential pitfalls. The focus is on the `os/signal` package functionality being tested.

2. **Initial Code Scan - High-Level Purpose:**  The filename `signal_test.go` immediately suggests this code is a test suite for the `os/signal` package. The import statements confirm this, including imports for `os`, `syscall`, and `testing`. The presence of functions like `TestSignal`, `TestStop`, `TestNotifyContext`, etc., reinforces the idea of individual test cases for different aspects of signal handling.

3. **Identifying Key Functionality:**  Reading through the test functions reveals the core functionalities being tested:
    * **Basic Signal Notification (`TestSignal`):**  Testing the fundamental mechanism of registering a channel to receive specific signals and verifying their delivery.
    * **Stopping Signal Notifications (`TestStop`):** Checking that `Stop()` correctly unregisters a channel, preventing further signal delivery to it.
    * **Ignoring Signals (`TestIgnore`, `TestIgnored`):** Verifying the ability to ignore signals and the `Ignored()` function's correctness.
    * **Resetting Signal Handlers (`TestReset`):**  Testing the functionality of resetting signal handlers to their default behavior.
    * **Signal Handling under `nohup` (`TestNohup`, `TestDetectNohup`):**  Examining how the signal package interacts with the `nohup` utility, especially regarding `SIGHUP`.
    * **Stress Testing (`TestStress`):**  Confirming robustness under high signal volume.
    * **Cancellation and Context Integration (`TestCancel`, `TestNotifyContext*`):**  Exploring how signal notifications can be managed using contexts, including cancellation and stopping.
    * **Race Conditions (`TestAtomicStop`):** Specifically testing for potential race conditions when stopping signal notifications.
    * **Signal Delivery during Time-Related Operations (`TestTime`):** Checking for proper signal delivery even when the program is busy with time-related system calls.
    * **Tracing Compatibility (`TestSignalTrace`):**  Ensuring signal handling doesn't interfere with Go's tracing mechanism.

4. **Drilling Down - Function-Specific Analysis:**  For each test function, the process involves:
    * **Identifying the Core Assertion:** What specific aspect of signal handling is being validated?
    * **Analyzing the Setup:** How is the test environment prepared (e.g., creating channels, registering for signals)?
    * **Understanding the Trigger:** How is the signal being sent (usually `syscall.Kill`)?
    * **Examining the Verification:** How is the expected outcome checked (e.g., `waitSig`, checking channel receives, asserting error conditions)?

5. **Code Example Generation:**  Based on the identified functionalities, create concise Go code snippets that illustrate how to use the `os/signal` package. Focus on clarity and directness. For example, for basic notification, the example should show `Notify`, sending a signal, and receiving it.

6. **Input and Output (for Code Examples):**  Where applicable, provide example inputs (e.g., the signal to send) and the expected output (e.g., the received signal value). This makes the examples more concrete.

7. **Command-Line Parameter Handling:**  Look for the use of `flag` package. In this case, flags like `checkSighupIgnored`, `sendUncaughtSighup`, `dieFromSighup`, `check_notify_ctx`, and `ctx_notify_times` are used to control the test execution behavior. Document their purpose and usage.

8. **Identifying Potential Pitfalls:**  Think about common mistakes developers might make when using the `os/signal` package. This often involves:
    * **Forgetting to `Stop`:** Leading to resource leaks and unexpected signal handling.
    * **Unbuffered Channels:**  Causing blocking if signals are sent faster than they are processed.
    * **Race Conditions:**  Issues when stopping and receiving signals concurrently.
    * **Signal Masking:** While not explicitly shown in the core snippet, it's a relevant concept to mention as a potential advanced pitfall.
    * **Ignoring vs. Resetting:** Understanding the difference between these two actions.

9. **Structuring the Answer:** Organize the information logically with clear headings and bullet points. Start with a summary of the overall functionality, then detail each specific function/feature, providing code examples, input/output, and finally, discuss command-line parameters and potential pitfalls.

10. **Refinement and Language:** Ensure the language is clear, concise, and accurate. Use proper terminology and explain concepts effectively. The request specifically asked for Chinese, so the entire response should be in Chinese.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing too much on the individual test cases without synthesizing the broader functionalities. **Correction:** Group the tests by the feature they are testing.
* **Overlooking Command-Line Flags:** Initially missing the importance of the `flag` package usage. **Correction:**  Dedicate a section to explain the command-line parameters.
* **Not providing concrete examples:**  Describing the functionality without illustrating it with code. **Correction:** Add clear and concise Go code examples.
* **Assuming prior knowledge:**  Not explicitly defining concepts like "signal" or the purpose of `nohup`. **Correction:** Briefly explain these terms where relevant.

By following these steps and iteratively refining the analysis, a comprehensive and accurate answer like the example provided can be constructed.
这段代码是Go语言标准库 `os/signal` 包的一部分，专门用于进行**信号处理**的单元测试。它的主要功能是测试 `os/signal` 包中提供的各种 API 的正确性，确保 Go 程序能够正确地捕获和处理操作系统发送的信号。

具体来说，这段代码测试了以下 `os/signal` 包的功能：

1. **基本的信号通知 (`Notify`)**: 测试程序能否通过 `Notify` 函数注册对特定信号的监听，并在信号到达时收到通知。
2. **停止信号通知 (`Stop`)**: 测试程序能否通过 `Stop` 函数取消对特定通道的信号监听，之后该通道不再接收到相应的信号。
3. **忽略信号 (`Ignore`)**: 测试程序能否通过 `Ignore` 函数忽略特定的信号，使得这些信号不会传递给程序。
4. **重置信号处理 (`Reset`)**: 测试程序能否通过 `Reset` 函数将特定信号的处理方式恢复为默认行为（通常是终止程序）。
5. **检测 `nohup` 环境 (`TestDetectNohup`)**: 测试程序能否正确判断是否在 `nohup` 命令下运行，这会影响 `SIGHUP` 信号的处理方式。
6. **高并发下的信号处理 (`TestStress`)**: 测试在高并发发送信号的情况下，信号处理机制是否稳定可靠。
7. **取消信号监听 (`TestCancel`)**: 测试 `Reset` 和 `Ignore` 是否能正确取消通过 `Notify` 注册的信号监听。
8. **`Ignored` 函数的正确性 (`TestIgnored`)**: 测试 `Ignored` 函数能否正确检测信号是否被忽略。
9. **在 `nohup` 环境下处理 `SIGHUP` (`TestNohup`)**:  测试在 `nohup` 命令下，未捕获的 `SIGHUP` 信号不会导致程序退出。
10. **处理 `SIGCONT` 信号 (`TestSIGCONT`)**:  测试程序能否正确处理 `SIGCONT` 信号（通常用于进程继续运行）。
11. **停止信号通知的原子性 (`TestAtomicStop`)**: 测试在高并发的停止和接收信号的操作中，`Stop` 操作的原子性。
12. **在时间相关操作中处理信号 (`TestTime`)**: 测试在程序执行耗时的系统调用（如获取时间）时，信号处理是否正常。
13. **基于 Context 的信号通知 (`NotifyContext`)**: 测试通过 `NotifyContext` 函数，利用 `context.Context` 来管理信号的生命周期，实现信号接收的取消和超时等功能。
14. **追踪 (Trace) 和信号处理的兼容性 (`TestSignalTrace`)**: 测试在启用 Go 追踪功能时，信号处理是否正常工作。

**以下是用 Go 代码举例说明其中一些功能的实现：**

**1. 基本的信号通知 (`Notify`)**

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 创建一个接收 os.Signal 的 channel
	c := make(chan os.Signal, 1)

	// 注册监听 syscall.SIGINT 信号 (通常是 Ctrl+C)
	signal.Notify(c, syscall.SIGINT)
	defer signal.Stop(c, syscall.SIGINT) // 确保程序退出时停止监听

	fmt.Println("等待 SIGINT 信号...")

	// 阻塞等待信号
	s := <-c
	fmt.Println("接收到信号:", s)
}
```

**假设输入：** 在程序运行时按下 `Ctrl+C`。

**输出：**

```
等待 SIGINT 信号...
接收到信号: interrupt
```

**2. 停止信号通知 (`Stop`)**

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1) // 监听 SIGUSR1

	fmt.Println("开始监听 SIGUSR1...")

	// 发送 SIGUSR1 信号给自己
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)

	// 等待一段时间，应该能收到信号
	select {
	case s := <-c:
		fmt.Println("第一次接收到信号:", s)
	case <-time.After(time.Second):
		fmt.Println("第一次接收信号超时")
	}

	// 停止监听 SIGUSR1
	signal.Stop(c, syscall.SIGUSR1)

	fmt.Println("停止监听 SIGUSR1...")

	// 再次发送 SIGUSR1 信号给自己
	syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)

	// 再次等待一段时间，应该收不到信号
	select {
	case s := <-c:
		fmt.Println("第二次接收到信号:", s) // 不应该执行到这里
	case <-time.After(time.Second):
		fmt.Println("第二次接收信号超时，符合预期")
	}
}
```

**假设输入：** 无需外部输入，程序内部发送信号。

**输出：**

```
开始监听 SIGUSR1...
第一次接收到信号: user defined signal 1
停止监听 SIGUSR1...
第二次接收信号超时，符合预期
```

**3. 基于 Context 的信号通知 (`NotifyContext`)**

```go
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 创建一个带有取消功能的 Context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建一个监听 SIGINT 的 Context
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT)
	defer stop()

	fmt.Println("等待 SIGINT 信号或 Context 取消...")

	go func() {
		time.Sleep(5 * time.Second)
		fmt.Println("5秒后取消 Context")
		cancel() // 模拟外部取消 Context
	}()

	select {
	case <-sigCtx.Done():
		fmt.Println("信号 Context Done:", sigCtx.Err())
	case <-ctx.Done():
		fmt.Println("主 Context Done:", ctx.Err())
	}
}
```

**假设输入：** 程序运行后等待 5 秒。

**输出：**

```
等待 SIGINT 信号或 Context 取消...
5秒后取消 Context
主 Context Done: context canceled
```

**如果假设输入：** 在 5 秒内按下 `Ctrl+C`。

**输出：**

```
等待 SIGINT 信号或 Context 取消...
信号 Context Done: <nil>
```

**命令行参数的具体处理：**

这段测试代码中使用了 `flag` 包来定义一些命令行参数，这些参数主要用于控制测试的行为，例如：

* **`-check_sighup_ignored`**:  一个布尔类型的 flag，如果设置为 `true`，`TestDetectNohup` 测试会断言 `SIGHUP` 信号是否被忽略。这用于验证在 `nohup` 环境下的行为。
* **`-send_uncaught_sighup`**: 一个整数类型的 flag，用于 `TestStop` 测试中指定在何时发送未捕获的 `SIGHUP` 信号 (0: 不发送, 1: 注册前发送, 2: 取消注册后发送)。
* **`-die_from_sighup`**: 一个布尔类型的 flag，用于指示测试程序在接收到未捕获的 `SIGHUP` 信号时是否应该退出。
* **`-check_notify_ctx`**: 一个布尔类型的 flag，如果设置为 `true`，`TestNotifyContextNotifications` 测试会断言是否接收到了 `SIGINT` 信号。
* **`-ctx_notify_times`**: 一个整数类型的 flag，用于指定 `TestNotifyContextNotifications` 测试中应该接收到多少次 `SIGINT` 信号。

**使用示例：**

```bash
go test -v -run TestNohup ./signal  # 运行 TestNohup 测试
go test -v -run TestDetectNohup ./signal -check_sighup_ignored # 运行 TestDetectNohup 并检查 SIGHUP 是否被忽略
go test -v -run TestStop ./signal -send_uncaught_sighup=1 # 运行 TestStop 并在注册监听前发送 SIGHUP
```

**使用者易犯错的点：**

1. **忘记使用 `defer signal.Stop()`**:  如果在 `Notify` 注册了信号监听后，忘记在不再需要监听时调用 `Stop` 函数，可能会导致程序意外地继续处理信号，或者资源泄漏。

   ```go
   func main() {
       c := make(chan os.Signal, 1)
       signal.Notify(c, syscall.SIGINT)
       // ... 执行一些操作 ...
       // 忘记调用 signal.Stop(c, syscall.SIGINT)
   }
   ```

2. **使用无缓冲的 channel**: 如果使用无缓冲的 channel 来接收信号，并且信号产生的速度快于处理的速度，会导致发送信号的操作阻塞，可能影响程序的正常运行甚至导致死锁。通常建议使用带有缓冲的 channel。

   ```go
   func main() {
       c := make(chan os.Signal) // 无缓冲 channel
       signal.Notify(c, syscall.SIGINT)
       // 如果信号产生很快，且 <-c 没有及时消费，这里可能会阻塞
       <-c
   }
   ```

3. **在多个 goroutine 中监听同一个信号**:  如果在多个 goroutine 中使用 `Notify` 监听同一个信号，当信号到达时，只有一个 goroutine 会收到通知，这可能导致逻辑上的错误，如果期望所有 goroutine 都处理该信号。

   ```go
   func worker(id int, sigChan <-chan os.Signal) {
       s := <-sigChan
       fmt.Printf("Worker %d received signal: %v\n", id, s)
   }

   func main() {
       c := make(chan os.Signal, 1)
       signal.Notify(c, syscall.SIGINT)

       go worker(1, c)
       go worker(2, c)

       // 当收到 SIGINT 时，只有一个 worker 会收到信号
       // ...
   }
   ```

总而言之，这段测试代码全面地检验了 Go 语言 `os/signal` 包的功能，为确保 Go 程序能够可靠地处理操作系统信号提供了保障。理解这些测试用例有助于开发者更好地掌握信号处理的相关知识，并避免常见的错误。

Prompt: 
```
这是路径为go/src/os/signal/signal_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package signal

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"internal/testenv"
	"os"
	"os/exec"
	"runtime"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// settleTime is an upper bound on how long we expect signals to take to be
// delivered. Lower values make the test faster, but also flakier — especially
// on heavily loaded systems.
//
// The current value is set based on flakes observed in the Go builders.
var settleTime = 100 * time.Millisecond

// fatalWaitingTime is an absurdly long time to wait for signals to be
// delivered but, using it, we (hopefully) eliminate test flakes on the
// build servers. See #46736 for discussion.
var fatalWaitingTime = 30 * time.Second

func init() {
	if testenv.Builder() == "solaris-amd64-oraclerel" {
		// The solaris-amd64-oraclerel builder has been observed to time out in
		// TestNohup even with a 250ms settle time.
		//
		// Use a much longer settle time on that builder to try to suss out whether
		// the test is flaky due to builder slowness (which may mean we need a
		// longer GO_TEST_TIMEOUT_SCALE) or due to a dropped signal (which may
		// instead need a test-skip and upstream bug filed against the Solaris
		// kernel).
		//
		// See https://golang.org/issue/33174.
		settleTime = 5 * time.Second
	} else if runtime.GOOS == "linux" && strings.HasPrefix(runtime.GOARCH, "ppc64") {
		// Older linux kernels seem to have some hiccups delivering the signal
		// in a timely manner on ppc64 and ppc64le. When running on a
		// ppc64le/ubuntu 16.04/linux 4.4 host the time can vary quite
		// substantially even on an idle system. 5 seconds is twice any value
		// observed when running 10000 tests on such a system.
		settleTime = 5 * time.Second
	} else if s := os.Getenv("GO_TEST_TIMEOUT_SCALE"); s != "" {
		if scale, err := strconv.Atoi(s); err == nil {
			settleTime *= time.Duration(scale)
		}
	}
}

func waitSig(t *testing.T, c <-chan os.Signal, sig os.Signal) {
	t.Helper()
	waitSig1(t, c, sig, false)
}
func waitSigAll(t *testing.T, c <-chan os.Signal, sig os.Signal) {
	t.Helper()
	waitSig1(t, c, sig, true)
}

func waitSig1(t *testing.T, c <-chan os.Signal, sig os.Signal, all bool) {
	t.Helper()

	// Sleep multiple times to give the kernel more tries to
	// deliver the signal.
	start := time.Now()
	timer := time.NewTimer(settleTime / 10)
	defer timer.Stop()
	// If the caller notified for all signals on c, filter out SIGURG,
	// which is used for runtime preemption and can come at unpredictable times.
	// General user code should filter out all unexpected signals instead of just
	// SIGURG, but since os/signal is tightly coupled to the runtime it seems
	// appropriate to be stricter here.
	for time.Since(start) < fatalWaitingTime {
		select {
		case s := <-c:
			if s == sig {
				return
			}
			if !all || s != syscall.SIGURG {
				t.Fatalf("signal was %v, want %v", s, sig)
			}
		case <-timer.C:
			timer.Reset(settleTime / 10)
		}
	}
	t.Fatalf("timeout after %v waiting for %v", fatalWaitingTime, sig)
}

// quiesce waits until we can be reasonably confident that all pending signals
// have been delivered by the OS.
func quiesce() {
	// The kernel will deliver a signal as a thread returns
	// from a syscall. If the only active thread is sleeping,
	// and the system is busy, the kernel may not get around
	// to waking up a thread to catch the signal.
	// We try splitting up the sleep to give the kernel
	// many chances to deliver the signal.
	start := time.Now()
	for time.Since(start) < settleTime {
		time.Sleep(settleTime / 10)
	}
}

// Test that basic signal handling works.
func TestSignal(t *testing.T) {
	// Ask for SIGHUP
	c := make(chan os.Signal, 1)
	Notify(c, syscall.SIGHUP)
	defer Stop(c)

	// Send this process a SIGHUP
	t.Logf("sighup...")
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	waitSig(t, c, syscall.SIGHUP)

	// Ask for everything we can get. The buffer size has to be
	// more than 1, since the runtime might send SIGURG signals.
	// Using 10 is arbitrary.
	c1 := make(chan os.Signal, 10)
	Notify(c1)
	// Stop relaying the SIGURG signals. See #49724
	Reset(syscall.SIGURG)
	defer Stop(c1)

	// Send this process a SIGWINCH
	t.Logf("sigwinch...")
	syscall.Kill(syscall.Getpid(), syscall.SIGWINCH)
	waitSigAll(t, c1, syscall.SIGWINCH)

	// Send two more SIGHUPs, to make sure that
	// they get delivered on c1 and that not reading
	// from c does not block everything.
	t.Logf("sighup...")
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	waitSigAll(t, c1, syscall.SIGHUP)
	t.Logf("sighup...")
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	waitSigAll(t, c1, syscall.SIGHUP)

	// The first SIGHUP should be waiting for us on c.
	waitSig(t, c, syscall.SIGHUP)
}

func TestStress(t *testing.T) {
	dur := 3 * time.Second
	if testing.Short() {
		dur = 100 * time.Millisecond
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))

	sig := make(chan os.Signal, 1)
	Notify(sig, syscall.SIGUSR1)

	go func() {
		stop := time.After(dur)
		for {
			select {
			case <-stop:
				// Allow enough time for all signals to be delivered before we stop
				// listening for them.
				quiesce()
				Stop(sig)
				// According to its documentation, “[w]hen Stop returns, it in
				// guaranteed that c will receive no more signals.” So we can safely
				// close sig here: if there is a send-after-close race here, that is a
				// bug in Stop and we would like to detect it.
				close(sig)
				return

			default:
				syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
				runtime.Gosched()
			}
		}
	}()

	for range sig {
		// Receive signals until the sender closes sig.
	}
}

func testCancel(t *testing.T, ignore bool) {
	// Ask to be notified on c1 when a SIGWINCH is received.
	c1 := make(chan os.Signal, 1)
	Notify(c1, syscall.SIGWINCH)
	defer Stop(c1)

	// Ask to be notified on c2 when a SIGHUP is received.
	c2 := make(chan os.Signal, 1)
	Notify(c2, syscall.SIGHUP)
	defer Stop(c2)

	// Send this process a SIGWINCH and wait for notification on c1.
	syscall.Kill(syscall.Getpid(), syscall.SIGWINCH)
	waitSig(t, c1, syscall.SIGWINCH)

	// Send this process a SIGHUP and wait for notification on c2.
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	waitSig(t, c2, syscall.SIGHUP)

	// Ignore, or reset the signal handlers for, SIGWINCH and SIGHUP.
	// Either way, this should undo both calls to Notify above.
	if ignore {
		Ignore(syscall.SIGWINCH, syscall.SIGHUP)
		// Don't bother deferring a call to Reset: it is documented to undo Notify,
		// but its documentation says nothing about Ignore, and (as of the time of
		// writing) it empirically does not undo an Ignore.
	} else {
		Reset(syscall.SIGWINCH, syscall.SIGHUP)
	}

	// Send this process a SIGWINCH. It should be ignored.
	syscall.Kill(syscall.Getpid(), syscall.SIGWINCH)

	// If ignoring, Send this process a SIGHUP. It should be ignored.
	if ignore {
		syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
	}

	quiesce()

	select {
	case s := <-c1:
		t.Errorf("unexpected signal %v", s)
	default:
		// nothing to read - good
	}

	select {
	case s := <-c2:
		t.Errorf("unexpected signal %v", s)
	default:
		// nothing to read - good
	}

	// One or both of the signals may have been blocked for this process
	// by the calling process.
	// Discard any queued signals now to avoid interfering with other tests.
	Notify(c1, syscall.SIGWINCH)
	Notify(c2, syscall.SIGHUP)
	quiesce()
}

// Test that Reset cancels registration for listed signals on all channels.
func TestReset(t *testing.T) {
	testCancel(t, false)
}

// Test that Ignore cancels registration for listed signals on all channels.
func TestIgnore(t *testing.T) {
	testCancel(t, true)
}

// Test that Ignored correctly detects changes to the ignored status of a signal.
func TestIgnored(t *testing.T) {
	// Ask to be notified on SIGWINCH.
	c := make(chan os.Signal, 1)
	Notify(c, syscall.SIGWINCH)

	// If we're being notified, then the signal should not be ignored.
	if Ignored(syscall.SIGWINCH) {
		t.Errorf("expected SIGWINCH to not be ignored.")
	}
	Stop(c)
	Ignore(syscall.SIGWINCH)

	// We're no longer paying attention to this signal.
	if !Ignored(syscall.SIGWINCH) {
		t.Errorf("expected SIGWINCH to be ignored when explicitly ignoring it.")
	}

	Reset()
}

var checkSighupIgnored = flag.Bool("check_sighup_ignored", false, "if true, TestDetectNohup will fail if SIGHUP is not ignored.")

// Test that Ignored(SIGHUP) correctly detects whether it is being run under nohup.
func TestDetectNohup(t *testing.T) {
	if *checkSighupIgnored {
		if !Ignored(syscall.SIGHUP) {
			t.Fatal("SIGHUP is not ignored.")
		} else {
			t.Log("SIGHUP is ignored.")
		}
	} else {
		defer Reset()
		// Ugly: ask for SIGHUP so that child will not have no-hup set
		// even if test is running under nohup environment.
		// We have no intention of reading from c.
		c := make(chan os.Signal, 1)
		Notify(c, syscall.SIGHUP)
		if out, err := testenv.Command(t, os.Args[0], "-test.run=^TestDetectNohup$", "-check_sighup_ignored").CombinedOutput(); err == nil {
			t.Errorf("ran test with -check_sighup_ignored and it succeeded: expected failure.\nOutput:\n%s", out)
		}
		Stop(c)

		// Again, this time with nohup, assuming we can find it.
		_, err := os.Stat("/usr/bin/nohup")
		if err != nil {
			t.Skip("cannot find nohup; skipping second half of test")
		}
		Ignore(syscall.SIGHUP)
		os.Remove("nohup.out")
		out, err := testenv.Command(t, "/usr/bin/nohup", os.Args[0], "-test.run=^TestDetectNohup$", "-check_sighup_ignored").CombinedOutput()

		data, _ := os.ReadFile("nohup.out")
		os.Remove("nohup.out")
		if err != nil {
			// nohup doesn't work on new LUCI darwin builders due to the
			// type of launchd service the test run under. See
			// https://go.dev/issue/63875.
			if runtime.GOOS == "darwin" && strings.Contains(string(out), "nohup: can't detach from console: Inappropriate ioctl for device") {
				t.Skip("Skipping nohup test due to darwin builder limitation. See https://go.dev/issue/63875.")
			}

			t.Errorf("ran test with -check_sighup_ignored under nohup and it failed: expected success.\nError: %v\nOutput:\n%s%s", err, out, data)
		}
	}
}

var (
	sendUncaughtSighup = flag.Int("send_uncaught_sighup", 0, "send uncaught SIGHUP during TestStop")
	dieFromSighup      = flag.Bool("die_from_sighup", false, "wait to die from uncaught SIGHUP")
)

// Test that Stop cancels the channel's registrations.
func TestStop(t *testing.T) {
	sigs := []syscall.Signal{
		syscall.SIGWINCH,
		syscall.SIGHUP,
		syscall.SIGUSR1,
	}

	for _, sig := range sigs {
		sig := sig
		t.Run(fmt.Sprint(sig), func(t *testing.T) {
			// When calling Notify with a specific signal,
			// independent signals should not interfere with each other,
			// and we end up needing to wait for signals to quiesce a lot.
			// Test the three different signals concurrently.
			t.Parallel()

			// If the signal is not ignored, send the signal before registering a
			// channel to verify the behavior of the default Go handler.
			// If it's SIGWINCH or SIGUSR1 we should not see it.
			// If it's SIGHUP, maybe we'll die. Let the flag tell us what to do.
			mayHaveBlockedSignal := false
			if !Ignored(sig) && (sig != syscall.SIGHUP || *sendUncaughtSighup == 1) {
				syscall.Kill(syscall.Getpid(), sig)
				quiesce()

				// We don't know whether sig is blocked for this process; see
				// https://golang.org/issue/38165. Assume that it could be.
				mayHaveBlockedSignal = true
			}

			// Ask for signal
			c := make(chan os.Signal, 1)
			Notify(c, sig)

			// Send this process the signal again.
			syscall.Kill(syscall.Getpid(), sig)
			waitSig(t, c, sig)

			if mayHaveBlockedSignal {
				// We may have received a queued initial signal in addition to the one
				// that we sent after Notify. If so, waitSig may have observed that
				// initial signal instead of the second one, and we may need to wait for
				// the second signal to clear. Do that now.
				quiesce()
				select {
				case <-c:
				default:
				}
			}

			// Stop watching for the signal and send it again.
			// If it's SIGHUP, maybe we'll die. Let the flag tell us what to do.
			Stop(c)
			if sig != syscall.SIGHUP || *sendUncaughtSighup == 2 {
				syscall.Kill(syscall.Getpid(), sig)
				quiesce()

				select {
				case s := <-c:
					t.Errorf("unexpected signal %v", s)
				default:
					// nothing to read - good
				}

				// If we're going to receive a signal, it has almost certainly been
				// received by now. However, it may have been blocked for this process —
				// we don't know. Explicitly unblock it and wait for it to clear now.
				Notify(c, sig)
				quiesce()
				Stop(c)
			}
		})
	}
}

// Test that when run under nohup, an uncaught SIGHUP does not kill the program.
func TestNohup(t *testing.T) {
	// When run without nohup, the test should crash on an uncaught SIGHUP.
	// When run under nohup, the test should ignore uncaught SIGHUPs,
	// because the runtime is not supposed to be listening for them.
	// Either way, TestStop should still be able to catch them when it wants them
	// and then when it stops wanting them, the original behavior should resume.
	//
	// send_uncaught_sighup=1 sends the SIGHUP before starting to listen for SIGHUPs.
	// send_uncaught_sighup=2 sends the SIGHUP after no longer listening for SIGHUPs.
	//
	// Both should fail without nohup and succeed with nohup.

	t.Run("uncaught", func(t *testing.T) {
		// Ugly: ask for SIGHUP so that child will not have no-hup set
		// even if test is running under nohup environment.
		// We have no intention of reading from c.
		c := make(chan os.Signal, 1)
		Notify(c, syscall.SIGHUP)
		t.Cleanup(func() { Stop(c) })

		var subTimeout time.Duration
		if deadline, ok := t.Deadline(); ok {
			subTimeout = time.Until(deadline)
			subTimeout -= subTimeout / 10 // Leave 10% headroom for propagating output.
		}
		for i := 1; i <= 2; i++ {
			i := i
			t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
				t.Parallel()

				args := []string{
					"-test.v",
					"-test.run=^TestStop$",
					"-send_uncaught_sighup=" + strconv.Itoa(i),
					"-die_from_sighup",
				}
				if subTimeout != 0 {
					args = append(args, fmt.Sprintf("-test.timeout=%v", subTimeout))
				}
				out, err := testenv.Command(t, os.Args[0], args...).CombinedOutput()

				if err == nil {
					t.Errorf("ran test with -send_uncaught_sighup=%d and it succeeded: expected failure.\nOutput:\n%s", i, out)
				} else {
					t.Logf("test with -send_uncaught_sighup=%d failed as expected.\nError: %v\nOutput:\n%s", i, err, out)
				}
			})
		}
	})

	t.Run("nohup", func(t *testing.T) {
		// Skip the nohup test below when running in tmux on darwin, since nohup
		// doesn't work correctly there. See issue #5135.
		if runtime.GOOS == "darwin" && os.Getenv("TMUX") != "" {
			t.Skip("Skipping nohup test due to running in tmux on darwin")
		}

		// Again, this time with nohup, assuming we can find it.
		_, err := exec.LookPath("nohup")
		if err != nil {
			t.Skip("cannot find nohup; skipping second half of test")
		}

		var subTimeout time.Duration
		if deadline, ok := t.Deadline(); ok {
			subTimeout = time.Until(deadline)
			subTimeout -= subTimeout / 10 // Leave 10% headroom for propagating output.
		}
		for i := 1; i <= 2; i++ {
			i := i
			t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
				t.Parallel()

				// POSIX specifies that nohup writes to a file named nohup.out if standard
				// output is a terminal. However, for an exec.Cmd, standard output is
				// not a terminal — so we don't need to read or remove that file (and,
				// indeed, cannot even create it if the current user is unable to write to
				// GOROOT/src, such as when GOROOT is installed and owned by root).

				args := []string{
					os.Args[0],
					"-test.v",
					"-test.run=^TestStop$",
					"-send_uncaught_sighup=" + strconv.Itoa(i),
				}
				if subTimeout != 0 {
					args = append(args, fmt.Sprintf("-test.timeout=%v", subTimeout))
				}
				out, err := testenv.Command(t, "nohup", args...).CombinedOutput()

				if err != nil {
					// nohup doesn't work on new LUCI darwin builders due to the
					// type of launchd service the test run under. See
					// https://go.dev/issue/63875.
					if runtime.GOOS == "darwin" && strings.Contains(string(out), "nohup: can't detach from console: Inappropriate ioctl for device") {
						// TODO(go.dev/issue/63799): A false-positive in vet reports a
						// t.Skip here as invalid. Switch back to t.Skip once fixed.
						t.Logf("Skipping nohup test due to darwin builder limitation. See https://go.dev/issue/63875.")
						return
					}

					t.Errorf("ran test with -send_uncaught_sighup=%d under nohup and it failed: expected success.\nError: %v\nOutput:\n%s", i, err, out)
				} else {
					t.Logf("ran test with -send_uncaught_sighup=%d under nohup.\nOutput:\n%s", i, out)
				}
			})
		}
	})
}

// Test that SIGCONT works (issue 8953).
func TestSIGCONT(t *testing.T) {
	c := make(chan os.Signal, 1)
	Notify(c, syscall.SIGCONT)
	defer Stop(c)
	syscall.Kill(syscall.Getpid(), syscall.SIGCONT)
	waitSig(t, c, syscall.SIGCONT)
}

// Test race between stopping and receiving a signal (issue 14571).
func TestAtomicStop(t *testing.T) {
	if os.Getenv("GO_TEST_ATOMIC_STOP") != "" {
		atomicStopTestProgram(t)
		t.Fatal("atomicStopTestProgram returned")
	}

	testenv.MustHaveExec(t)

	// Call Notify for SIGINT before starting the child process.
	// That ensures that SIGINT is not ignored for the child.
	// This is necessary because if SIGINT is ignored when a
	// Go program starts, then it remains ignored, and closing
	// the last notification channel for SIGINT will switch it
	// back to being ignored. In that case the assumption of
	// atomicStopTestProgram, that it will either die from SIGINT
	// or have it be reported, breaks down, as there is a third
	// option: SIGINT might be ignored.
	cs := make(chan os.Signal, 1)
	Notify(cs, syscall.SIGINT)
	defer Stop(cs)

	const execs = 10
	for i := 0; i < execs; i++ {
		timeout := "0"
		if deadline, ok := t.Deadline(); ok {
			timeout = time.Until(deadline).String()
		}
		cmd := testenv.Command(t, os.Args[0], "-test.run=^TestAtomicStop$", "-test.timeout="+timeout)
		cmd.Env = append(os.Environ(), "GO_TEST_ATOMIC_STOP=1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			if len(out) > 0 {
				t.Logf("iteration %d: output %s", i, out)
			}
		} else {
			t.Logf("iteration %d: exit status %q: output: %s", i, err, out)
		}

		lost := bytes.Contains(out, []byte("lost signal"))
		if lost {
			t.Errorf("iteration %d: lost signal", i)
		}

		// The program should either die due to SIGINT,
		// or exit with success without printing "lost signal".
		if err == nil {
			if len(out) > 0 && !lost {
				t.Errorf("iteration %d: unexpected output", i)
			}
		} else {
			if ee, ok := err.(*exec.ExitError); !ok {
				t.Errorf("iteration %d: error (%v) has type %T; expected exec.ExitError", i, err, err)
			} else if ws, ok := ee.Sys().(syscall.WaitStatus); !ok {
				t.Errorf("iteration %d: error.Sys (%v) has type %T; expected syscall.WaitStatus", i, ee.Sys(), ee.Sys())
			} else if !ws.Signaled() || ws.Signal() != syscall.SIGINT {
				t.Errorf("iteration %d: got exit status %v; expected SIGINT", i, ee)
			}
		}
	}
}

// atomicStopTestProgram is run in a subprocess by TestAtomicStop.
// It tries to trigger a signal delivery race. This function should
// either catch a signal or die from it.
func atomicStopTestProgram(t *testing.T) {
	// This test won't work if SIGINT is ignored here.
	if Ignored(syscall.SIGINT) {
		fmt.Println("SIGINT is ignored")
		os.Exit(1)
	}

	const tries = 10

	timeout := 2 * time.Second
	if deadline, ok := t.Deadline(); ok {
		// Give each try an equal slice of the deadline, with one slice to spare for
		// cleanup.
		timeout = time.Until(deadline) / (tries + 1)
	}

	pid := syscall.Getpid()
	printed := false
	for i := 0; i < tries; i++ {
		cs := make(chan os.Signal, 1)
		Notify(cs, syscall.SIGINT)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			Stop(cs)
		}()

		syscall.Kill(pid, syscall.SIGINT)

		// At this point we should either die from SIGINT or
		// get a notification on cs. If neither happens, we
		// dropped the signal. It is given 2 seconds to
		// deliver, as needed for gccgo on some loaded test systems.

		select {
		case <-cs:
		case <-time.After(timeout):
			if !printed {
				fmt.Print("lost signal on tries:")
				printed = true
			}
			fmt.Printf(" %d", i)
		}

		wg.Wait()
	}
	if printed {
		fmt.Print("\n")
	}

	os.Exit(0)
}

func TestTime(t *testing.T) {
	// Test that signal works fine when we are in a call to get time,
	// which on some platforms is using VDSO. See issue #34391.
	dur := 3 * time.Second
	if testing.Short() {
		dur = 100 * time.Millisecond
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))

	sig := make(chan os.Signal, 1)
	Notify(sig, syscall.SIGUSR1)

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				// Allow enough time for all signals to be delivered before we stop
				// listening for them.
				quiesce()
				Stop(sig)
				// According to its documentation, “[w]hen Stop returns, it in
				// guaranteed that c will receive no more signals.” So we can safely
				// close sig here: if there is a send-after-close race, that is a bug in
				// Stop and we would like to detect it.
				close(sig)
				return

			default:
				syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
				runtime.Gosched()
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		for range sig {
			// Receive signals until the sender closes sig.
		}
		close(done)
	}()

	t0 := time.Now()
	for t1 := t0; t1.Sub(t0) < dur; t1 = time.Now() {
	} // hammering on getting time

	close(stop)
	<-done
}

var (
	checkNotifyContext = flag.Bool("check_notify_ctx", false, "if true, TestNotifyContext will fail if SIGINT is not received.")
	ctxNotifyTimes     = flag.Int("ctx_notify_times", 1, "number of times a SIGINT signal should be received")
)

func TestNotifyContextNotifications(t *testing.T) {
	if *checkNotifyContext {
		ctx, _ := NotifyContext(context.Background(), syscall.SIGINT)
		// We want to make sure not to be calling Stop() internally on NotifyContext() when processing a received signal.
		// Being able to wait for a number of received system signals allows us to do so.
		var wg sync.WaitGroup
		n := *ctxNotifyTimes
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				syscall.Kill(syscall.Getpid(), syscall.SIGINT)
				wg.Done()
			}()
		}
		wg.Wait()
		<-ctx.Done()
		fmt.Println("received SIGINT")
		// Sleep to give time to simultaneous signals to reach the process.
		// These signals must be ignored given stop() is not called on this code.
		// We want to guarantee a SIGINT doesn't cause a premature termination of the program.
		time.Sleep(settleTime)
		return
	}

	t.Parallel()
	testCases := []struct {
		name string
		n    int // number of times a SIGINT should be notified.
	}{
		{"once", 1},
		{"multiple", 10},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var subTimeout time.Duration
			if deadline, ok := t.Deadline(); ok {
				timeout := time.Until(deadline)
				if timeout < 2*settleTime {
					t.Fatalf("starting test with less than %v remaining", 2*settleTime)
				}
				subTimeout = timeout - (timeout / 10) // Leave 10% headroom for cleaning up subprocess.
			}

			args := []string{
				"-test.v",
				"-test.run=^TestNotifyContextNotifications$",
				"-check_notify_ctx",
				fmt.Sprintf("-ctx_notify_times=%d", tc.n),
			}
			if subTimeout != 0 {
				args = append(args, fmt.Sprintf("-test.timeout=%v", subTimeout))
			}
			out, err := testenv.Command(t, os.Args[0], args...).CombinedOutput()
			if err != nil {
				t.Errorf("ran test with -check_notify_ctx_notification and it failed with %v.\nOutput:\n%s", err, out)
			}
			if want := []byte("received SIGINT\n"); !bytes.Contains(out, want) {
				t.Errorf("got %q, wanted %q", out, want)
			}
		})
	}
}

func TestNotifyContextStop(t *testing.T) {
	Ignore(syscall.SIGHUP)
	if !Ignored(syscall.SIGHUP) {
		t.Errorf("expected SIGHUP to be ignored when explicitly ignoring it.")
	}

	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	c, stop := NotifyContext(parent, syscall.SIGHUP)
	defer stop()

	// If we're being notified, then the signal should not be ignored.
	if Ignored(syscall.SIGHUP) {
		t.Errorf("expected SIGHUP to not be ignored.")
	}

	if want, got := "signal.NotifyContext(context.Background.WithCancel, [hangup])", fmt.Sprint(c); want != got {
		t.Errorf("c.String() = %q, wanted %q", got, want)
	}

	stop()
	<-c.Done()
	if got := c.Err(); got != context.Canceled {
		t.Errorf("c.Err() = %q, want %q", got, context.Canceled)
	}
}

func TestNotifyContextCancelParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	c, stop := NotifyContext(parent, syscall.SIGINT)
	defer stop()

	if want, got := "signal.NotifyContext(context.Background.WithCancel, [interrupt])", fmt.Sprint(c); want != got {
		t.Errorf("c.String() = %q, want %q", got, want)
	}

	cancelParent()
	<-c.Done()
	if got := c.Err(); got != context.Canceled {
		t.Errorf("c.Err() = %q, want %q", got, context.Canceled)
	}
}

func TestNotifyContextPrematureCancelParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	cancelParent() // Prematurely cancel context before calling NotifyContext.
	c, stop := NotifyContext(parent, syscall.SIGINT)
	defer stop()

	if want, got := "signal.NotifyContext(context.Background.WithCancel, [interrupt])", fmt.Sprint(c); want != got {
		t.Errorf("c.String() = %q, want %q", got, want)
	}

	<-c.Done()
	if got := c.Err(); got != context.Canceled {
		t.Errorf("c.Err() = %q, want %q", got, context.Canceled)
	}
}

func TestNotifyContextSimultaneousStop(t *testing.T) {
	c, stop := NotifyContext(context.Background(), syscall.SIGINT)
	defer stop()

	if want, got := "signal.NotifyContext(context.Background, [interrupt])", fmt.Sprint(c); want != got {
		t.Errorf("c.String() = %q, want %q", got, want)
	}

	var wg sync.WaitGroup
	n := 10
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			stop()
			wg.Done()
		}()
	}
	wg.Wait()
	<-c.Done()
	if got := c.Err(); got != context.Canceled {
		t.Errorf("c.Err() = %q, want %q", got, context.Canceled)
	}
}

func TestNotifyContextStringer(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	c, stop := NotifyContext(parent, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	want := `signal.NotifyContext(context.Background.WithCancel, [hangup interrupt terminated])`
	if got := fmt.Sprint(c); got != want {
		t.Errorf("c.String() = %q, want %q", got, want)
	}
}

// #44193 test signal handling while stopping and starting the world.
func TestSignalTrace(t *testing.T) {
	done := make(chan struct{})
	quit := make(chan struct{})
	c := make(chan os.Signal, 1)
	Notify(c, syscall.SIGHUP)

	// Source and sink for signals busy loop unsynchronized with
	// trace starts and stops. We are ultimately validating that
	// signals and runtime.(stop|start)TheWorldGC are compatible.
	go func() {
		defer close(done)
		defer Stop(c)
		pid := syscall.Getpid()
		for {
			select {
			case <-quit:
				return
			default:
				syscall.Kill(pid, syscall.SIGHUP)
			}
			waitSig(t, c, syscall.SIGHUP)
		}
	}()

	for i := 0; i < 100; i++ {
		buf := new(bytes.Buffer)
		if err := trace.Start(buf); err != nil {
			t.Fatalf("[%d] failed to start tracing: %v", i, err)
		}
		trace.Stop()
		size := buf.Len()
		if size == 0 {
			t.Fatalf("[%d] trace is empty", i)
		}
	}
	close(quit)
	<-done
}

"""



```