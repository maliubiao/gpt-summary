Response:
The user wants a summary of the Go code snippet provided, which is part of the `exec_test.go` file in the `os/exec` package. This file primarily tests the functionality of the `exec.Cmd` struct and related functions for running external commands.

Here's a breakdown of the code's functionality:

1. **Focus on `Wait` Method:** The code heavily tests the `Wait` method of `exec.Cmd`, which is used to wait for a command to finish execution and retrieve its exit status.

2. **Cancellation and Timeouts:**  The tests explore how `Wait` behaves in conjunction with `context.Context` for cancellation and with `WaitDelay` for setting timeouts.

3. **Signal Handling:**  The tests examine how `Wait` interacts with different signals sent to the child process (e.g., `os.Kill`, `os.Interrupt`, `SIGQUIT`).

4. **Error Handling:** The tests cover various error scenarios, including:
    - The command exiting normally.
    - The command being killed.
    - The context being cancelled.
    - Custom `Cancel` functions and their errors.
    - The `ErrWaitDelay` error.
    - The precedence of errors between `Cancel` and the process itself.

5. **Concurrency:** There's a test for concurrent execution of commands to check for race conditions.

6. **Path Handling:**  One test verifies the correct handling of absolute paths when executing commands.

**Plan:**

1. Summarize the overall purpose of the code snippet.
2. Go through each `t.Run` block and describe its specific test case.
3. Identify the Go language features being tested.
4. Provide code examples to illustrate the tested features.
5. Explain any relevant command-line arguments used in the tests (implicitly within the `startHang` function).
6. Point out potential pitfalls for users based on the test cases.
这是 `go/src/os/exec/exec_test.go` 文件的第二部分，主要集中在测试 `exec.Cmd` 结构体中与进程等待和取消相关的行为，特别是 `Wait` 方法的功能。以下是该部分代码功能的归纳：

**功能归纳:**

这部分代码主要测试了 `exec.Cmd` 的 `Wait` 方法在不同场景下的行为，涵盖了以下几个核心方面：

1. **正常等待进程结束：** 测试了在没有取消信号和等待延迟的情况下，`Wait` 方法会阻塞直到子进程正常退出，并能正确获取退出状态码。
2. **等待延迟 (WaitDelay)：** 测试了设置 `WaitDelay` 后，即使父进程的 `Context` 被取消，`Wait` 方法也会等待指定的时间，并允许发送信号给子进程。
3. **通过取消信号终止进程：** 测试了当 `Context` 被取消且指定了取消函数发送 `os.Kill` 信号时，子进程会被立即终止，并且在 `WaitDelay` 之后 `Wait` 方法会返回。重点测试了这种情况下的错误类型。
4. **进程提前退出但留有子进程：** 测试了当主进程退出，但仍有子进程在向管道写入数据时，`Wait` 方法在 `WaitDelay` 时间后会返回 `exec.ErrWaitDelay` 错误，表明可能存在未读取完的输出。
5. **忽略取消信号的进程：** 测试了当子进程忽略接收到的取消信号（例如 `os.Interrupt`）时，`Wait` 方法会在 `WaitDelay` 后强制终止进程，并返回相应的错误。
6. **处理取消信号并正常退出的进程：** 测试了当子进程接收到取消信号并正常退出（退出码为0）时，`Wait` 方法会返回一个非空的错误，并且该错误是 `context.Context` 相关的错误，而不是子进程自身的错误。
7. **处理 SIGQUIT 信号：** 测试了当取消函数发送 `SIGQUIT` 信号时，子进程（Go 程序）会打印 goroutine dump 并以非零状态码退出，`Wait` 方法能够正确捕获这些信息。
8. **自定义 `Cancel` 函数的错误处理：**
    - 测试了当自定义的 `Cancel` 函数返回非 `os.ErrProcessDone` 错误时，如果子进程随后正常退出，`Wait` 方法会返回 `Cancel` 函数的错误。
    - 测试了当自定义的 `Cancel` 函数返回 `os.ErrProcessDone` 相关的错误时，`Wait` 方法会忽略这个错误，如果子进程正常退出则返回 `nil`。
    - 测试了当自定义的 `Cancel` 函数返回错误，但子进程在 `WaitDelay` 后被强制终止时，`Wait` 方法会返回 `exec.ExitError`，而不是 `Cancel` 函数的错误。
    - 测试了当自定义的 `Cancel` 函数返回 `os.ErrProcessDone` 相关的错误，但子进程实际并未结束且在 `WaitDelay` 后被强制终止时，`Wait` 方法会返回 `exec.ExitError`。
    - 测试了当自定义的 `Cancel` 函数返回错误，但子进程以非零状态码退出时，`Wait` 方法会返回子进程的 `exec.ExitError`，优先级高于 `Cancel` 函数的错误。
9. **并发执行测试：**  测试了并发地创建和执行多个子进程，以检测潜在的并发问题。
10. **路径并发访问测试：** 测试了在并发调用 `Cmd.String()` 和 `Cmd.Start()` 时是否会发生竞态条件。
11. **绝对路径执行测试：** 测试了使用绝对路径执行命令的情况，以及在修改 `Cmd.Path` 后的执行。

**Go 语言功能实现举例：**

这部分代码主要测试的是 `os/exec` 包中 `exec.Cmd` 结构体的 `Wait` 方法以及与 `context` 包的集成。

**示例 1：正常等待进程结束**

```go
package main

import (
	"fmt"
	"os/exec"
)

func main() {
	cmd := exec.Command("echo", "hello")
	err := cmd.Run() // Run 会自动调用 Start 和 Wait
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Command finished successfully")
	}
}
```

**假设输入：** 无

**预期输出：**
```
hello
Command finished successfully
```

**示例 2：使用 Context 取消进程**

```go
package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sleep", "5")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error:", err) // 可能输出 context deadline exceeded
	} else {
		fmt.Println("Command finished successfully")
	}
}
```

**假设输入：** 无

**预期输出：** 大约 1 秒后输出类似 `Error: context deadline exceeded`

**命令行参数处理：**

在测试代码中，`startHang` 函数被用来启动一个可以模拟各种挂起和信号处理行为的辅助程序。这个函数接受以下参数（虽然在提供的代码片段中没有直接定义，但可以从调用方式推断）：

- `ctx context.Context`:  用于控制子进程的生命周期。
- `waitDelay time.Duration`:  模拟进程的休眠时间。
- `sig os.Signal`:  要发送给子进程的信号。
- `killDelay time.Duration`:  在取消上下文后，发送 `os.Kill` 信号的延迟时间。
- `extraArgs ...string`: 传递给 `startHang` 辅助程序的额外参数。

`startHang` 辅助程序本身会解析这些参数，从而模拟不同的行为。例如，`-interrupt=true` 和 `-interrupt=false` 参数可能控制子进程是否处理 `SIGINT` 信号。`-subsleep=10m` 可能让子进程再启动一个休眠的子进程。`-probe=1ms` 可能让子进程以一定的频率向标准错误输出内容。

**使用者易犯错的点：**

一个常见的错误是**不正确处理 `Wait` 方法返回的错误**。例如，当设置了 `WaitDelay` 并且子进程在 `WaitDelay` 时间后才结束时，`Wait` 方法可能返回 `exec.ErrWaitDelay`，这表示输出可能不完整。使用者需要根据具体的业务逻辑来判断是否需要重试或采取其他措施。

```go
package main

import (
	"errors"
	"fmt"
	"os/exec"
	"time"
)

func main() {
	cmd := exec.Command("sleep", "0.1") // 快速退出的命令
	cmd.WaitDelay = 10 * time.Millisecond

	err := cmd.Run()
	if err != nil {
		if errors.Is(err, exec.ErrWaitDelay) {
			fmt.Println("Warning: Command finished after WaitDelay, output might be incomplete.")
		} else {
			fmt.Println("Error running command:", err)
		}
	} else {
		fmt.Println("Command finished successfully.")
	}
}
```

在这个例子中，即使 `sleep 0.1` 会很快结束，但如果设置了较小的 `WaitDelay`，就有可能返回 `exec.ErrWaitDelay`，使用者需要意识到这种情况。

另一个易错点是**没有正确处理 `Context` 的取消**。如果使用了 `CommandContext`，但没有检查 `Wait` 返回的错误是否是 `context.Canceled` 或 `context.DeadlineExceeded`，就可能无法得知进程是因为超时或被取消而退出的。

总结来说，这部分代码深入测试了 `exec.Cmd` 的进程等待和取消机制，确保在各种复杂场景下，`Wait` 方法的行为符合预期，并且能够提供足够的信息给调用者来处理子进程的状态和可能的错误。

Prompt: 
```
这是路径为go/src/os/exec/exec_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
// Control case: with no cancellation and no WaitDelay, we should wait for the
	// process to exit.
	t.Run("Wait", func(t *testing.T) {
		t.Parallel()
		cmd := startHang(t, context.Background(), 1*time.Millisecond, os.Kill, 0)
		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		if err != nil {
			t.Errorf("Wait: %v; want <nil>", err)
		}
		if ps := cmd.ProcessState; !ps.Exited() {
			t.Errorf("cmd did not exit: %v", ps)
		} else if code := ps.ExitCode(); code != 0 {
			t.Errorf("cmd.ProcessState.ExitCode() = %v; want 0", code)
		}
	})

	// With a very long WaitDelay and no Cancel function, we should wait for the
	// process to exit even if the command's Context is canceled.
	t.Run("WaitDelay", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skipf("skipping: os.Interrupt is not implemented on Windows")
		}
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cmd := startHang(t, ctx, tooLong, nil, tooLong, "-interrupt=true")
		cancel()

		time.Sleep(1 * time.Millisecond)
		// At this point cmd should still be running (because we passed nil to
		// startHang for the cancel signal). Sending it an explicit Interrupt signal
		// should succeed.
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Error(err)
		}

		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		// This program exits with status 0,
		// but pretty much always does so during the wait delay.
		// Since the Cmd itself didn't do anything to stop the process when the
		// context expired, a successful exit is valid (even if late) and does
		// not merit a non-nil error.
		if err != nil {
			t.Errorf("Wait: %v; want nil", err)
		}
		if ps := cmd.ProcessState; !ps.Exited() {
			t.Errorf("cmd did not exit: %v", ps)
		} else if code := ps.ExitCode(); code != 0 {
			t.Errorf("cmd.ProcessState.ExitCode() = %v; want 0", code)
		}
	})

	// If the context is canceled and the Cancel function sends os.Kill,
	// the process should be terminated immediately, and its output
	// pipes should be closed (causing Wait to return) after WaitDelay
	// even if a child process is still writing to them.
	t.Run("SIGKILL-hang", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cmd := startHang(t, ctx, tooLong, os.Kill, 10*time.Millisecond, "-subsleep=10m", "-probe=1ms")
		cancel()
		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		// This test should kill the child process after 10ms,
		// leaving a grandchild process writing probes in a loop.
		// The child process should be reported as failed,
		// and the grandchild will exit (or die by SIGPIPE) once the
		// stderr pipe is closed.
		if ee := new(*exec.ExitError); !errors.As(err, ee) {
			t.Errorf("Wait error = %v; want %T", err, *ee)
		}
	})

	// If the process exits with status 0 but leaves a child behind writing
	// to its output pipes, Wait should only wait for WaitDelay before
	// closing the pipes and returning.  Wait should return ErrWaitDelay
	// to indicate that the piped output may be incomplete even though the
	// command returned a “success” code.
	t.Run("Exit-hang", func(t *testing.T) {
		t.Parallel()

		cmd := startHang(t, context.Background(), 1*time.Millisecond, nil, 10*time.Millisecond, "-subsleep=10m", "-probe=1ms")
		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		// This child process should exit immediately,
		// leaving a grandchild process writing probes in a loop.
		// Since the child has no ExitError to report but we did not
		// read all of its output, Wait should return ErrWaitDelay.
		if !errors.Is(err, exec.ErrWaitDelay) {
			t.Errorf("Wait error = %v; want %T", err, exec.ErrWaitDelay)
		}
	})

	// If the Cancel function sends a signal that the process can handle, and it
	// handles that signal without actually exiting, then it should be terminated
	// after the WaitDelay.
	t.Run("SIGINT-ignored", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skipf("skipping: os.Interrupt is not implemented on Windows")
		}
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cmd := startHang(t, ctx, tooLong, os.Interrupt, 10*time.Millisecond, "-interrupt=false")
		cancel()
		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		// This command ignores SIGINT, sleeping until it is killed.
		// Wait should return the usual error for a killed process.
		if ee := new(*exec.ExitError); !errors.As(err, ee) {
			t.Errorf("Wait error = %v; want %T", err, *ee)
		}
	})

	// If the process handles the cancellation signal and exits with status 0,
	// Wait should report a non-nil error (because the process had to be
	// interrupted), and it should be a context error (because there is no error
	// to report from the child process itself).
	t.Run("SIGINT-handled", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skipf("skipping: os.Interrupt is not implemented on Windows")
		}
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cmd := startHang(t, ctx, tooLong, os.Interrupt, 0, "-interrupt=true")
		cancel()
		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		if !errors.Is(err, ctx.Err()) {
			t.Errorf("Wait error = %v; want %v", err, ctx.Err())
		}
		if ps := cmd.ProcessState; !ps.Exited() {
			t.Errorf("cmd did not exit: %v", ps)
		} else if code := ps.ExitCode(); code != 0 {
			t.Errorf("cmd.ProcessState.ExitCode() = %v; want 0", code)
		}
	})

	// If the Cancel function sends SIGQUIT, it should be handled in the usual
	// way: a Go program should dump its goroutines and exit with non-success
	// status. (We expect SIGQUIT to be a common pattern in real-world use.)
	t.Run("SIGQUIT", func(t *testing.T) {
		if quitSignal == nil {
			t.Skipf("skipping: SIGQUIT is not supported on %v", runtime.GOOS)
		}
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		cmd := startHang(t, ctx, tooLong, quitSignal, 0)
		cancel()
		err := cmd.Wait()
		t.Logf("stderr:\n%s", cmd.Stderr)
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		if ee := new(*exec.ExitError); !errors.As(err, ee) {
			t.Errorf("Wait error = %v; want %v", err, ctx.Err())
		}

		if ps := cmd.ProcessState; !ps.Exited() {
			t.Errorf("cmd did not exit: %v", ps)
		} else if code := ps.ExitCode(); code != 2 {
			// The default os/signal handler exits with code 2.
			t.Errorf("cmd.ProcessState.ExitCode() = %v; want 2", code)
		}

		if !strings.Contains(fmt.Sprint(cmd.Stderr), "\n\ngoroutine ") {
			t.Errorf("cmd.Stderr does not contain a goroutine dump")
		}
	})
}

func TestCancelErrors(t *testing.T) {
	t.Parallel()

	// If Cancel returns a non-ErrProcessDone error and the process
	// exits successfully, Wait should wrap the error from Cancel.
	t.Run("success after error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := helperCommandContext(t, ctx, "pipetest")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}

		errArbitrary := errors.New("arbitrary error")
		cmd.Cancel = func() error {
			stdin.Close()
			t.Logf("Cancel returning %v", errArbitrary)
			return errArbitrary
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cancel()

		err = cmd.Wait()
		t.Logf("[%d] %v", cmd.Process.Pid, err)
		if !errors.Is(err, errArbitrary) || err == errArbitrary {
			t.Errorf("Wait error = %v; want an error wrapping %v", err, errArbitrary)
		}
	})

	// If Cancel returns an error equivalent to ErrProcessDone,
	// Wait should ignore that error. (ErrProcessDone indicates that the
	// process was already done before we tried to interrupt it — maybe we
	// just didn't notice because Wait hadn't been called yet.)
	t.Run("success after ErrProcessDone", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := helperCommandContext(t, ctx, "pipetest")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}

		// We intentionally race Cancel against the process exiting,
		// but ensure that the process wins the race (and return ErrProcessDone
		// from Cancel to report that).
		interruptCalled := make(chan struct{})
		done := make(chan struct{})
		cmd.Cancel = func() error {
			close(interruptCalled)
			<-done
			t.Logf("Cancel returning an error wrapping ErrProcessDone")
			return fmt.Errorf("%w: stdout closed", os.ErrProcessDone)
		}

		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}

		cancel()
		<-interruptCalled
		stdin.Close()
		io.Copy(io.Discard, stdout) // reaches EOF when the process exits
		close(done)

		err = cmd.Wait()
		t.Logf("[%d] %v", cmd.Process.Pid, err)
		if err != nil {
			t.Errorf("Wait error = %v; want nil", err)
		}
	})

	// If Cancel returns an error and the process is killed after
	// WaitDelay, Wait should report the usual SIGKILL ExitError, not the
	// error from Cancel.
	t.Run("killed after error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := helperCommandContext(t, ctx, "pipetest")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stdin.Close()

		errArbitrary := errors.New("arbitrary error")
		var interruptCalled atomic.Bool
		cmd.Cancel = func() error {
			t.Logf("Cancel called")
			interruptCalled.Store(true)
			return errArbitrary
		}
		cmd.WaitDelay = 1 * time.Millisecond
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cancel()

		err = cmd.Wait()
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		// Ensure that Cancel actually had the opportunity to
		// return the error.
		if !interruptCalled.Load() {
			t.Errorf("Cancel was not called when the context was canceled")
		}

		// This test should kill the child process after 1ms,
		// To maximize compatibility with existing uses of exec.CommandContext, the
		// resulting error should be an exec.ExitError without additional wrapping.
		if _, ok := err.(*exec.ExitError); !ok {
			t.Errorf("Wait error = %v; want *exec.ExitError", err)
		}
	})

	// If Cancel returns ErrProcessDone but the process is not actually done
	// (and has to be killed), Wait should report the usual SIGKILL ExitError,
	// not the error from Cancel.
	t.Run("killed after spurious ErrProcessDone", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := helperCommandContext(t, ctx, "pipetest")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stdin.Close()

		var interruptCalled atomic.Bool
		cmd.Cancel = func() error {
			t.Logf("Cancel returning an error wrapping ErrProcessDone")
			interruptCalled.Store(true)
			return fmt.Errorf("%w: stdout closed", os.ErrProcessDone)
		}
		cmd.WaitDelay = 1 * time.Millisecond
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cancel()

		err = cmd.Wait()
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		// Ensure that Cancel actually had the opportunity to
		// return the error.
		if !interruptCalled.Load() {
			t.Errorf("Cancel was not called when the context was canceled")
		}

		// This test should kill the child process after 1ms,
		// To maximize compatibility with existing uses of exec.CommandContext, the
		// resulting error should be an exec.ExitError without additional wrapping.
		if ee, ok := err.(*exec.ExitError); !ok {
			t.Errorf("Wait error of type %T; want %T", err, ee)
		}
	})

	// If Cancel returns an error and the process exits with an
	// unsuccessful exit code, the process error should take precedence over the
	// Cancel error.
	t.Run("nonzero exit after error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := helperCommandContext(t, ctx, "stderrfail")
		stderr, err := cmd.StderrPipe()
		if err != nil {
			t.Fatal(err)
		}

		errArbitrary := errors.New("arbitrary error")
		interrupted := make(chan struct{})
		cmd.Cancel = func() error {
			close(interrupted)
			return errArbitrary
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cancel()
		<-interrupted
		io.Copy(io.Discard, stderr)

		err = cmd.Wait()
		t.Logf("[%d] %v", cmd.Process.Pid, err)

		if ee, ok := err.(*exec.ExitError); !ok || ee.ProcessState.ExitCode() != 1 {
			t.Errorf("Wait error = %v; want exit status 1", err)
		}
	})
}

// TestConcurrentExec is a regression test for https://go.dev/issue/61080.
//
// Forking multiple child processes concurrently would sometimes hang on darwin.
// (This test hung on a gomote with -count=100 after only a few iterations.)
func TestConcurrentExec(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// This test will spawn nHangs subprocesses that hang reading from stdin,
	// and nExits subprocesses that exit immediately.
	//
	// When issue #61080 was present, a long-lived "hang" subprocess would
	// occasionally inherit the fork/exec status pipe from an "exit" subprocess,
	// causing the parent process (which expects to see an EOF on that pipe almost
	// immediately) to unexpectedly block on reading from the pipe.
	var (
		nHangs       = runtime.GOMAXPROCS(0)
		nExits       = runtime.GOMAXPROCS(0)
		hangs, exits sync.WaitGroup
	)
	hangs.Add(nHangs)
	exits.Add(nExits)

	// ready is done when the goroutines have done as much work as possible to
	// prepare to create subprocesses. It isn't strictly necessary for the test,
	// but helps to increase the repro rate by making it more likely that calls to
	// syscall.StartProcess for the "hang" and "exit" goroutines overlap.
	var ready sync.WaitGroup
	ready.Add(nHangs + nExits)

	for i := 0; i < nHangs; i++ {
		go func() {
			defer hangs.Done()

			cmd := helperCommandContext(t, ctx, "pipetest")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				ready.Done()
				t.Error(err)
				return
			}
			cmd.Cancel = stdin.Close
			ready.Done()

			ready.Wait()
			if err := cmd.Start(); err != nil {
				if !errors.Is(err, context.Canceled) {
					t.Error(err)
				}
				return
			}

			cmd.Wait()
		}()
	}

	for i := 0; i < nExits; i++ {
		go func() {
			defer exits.Done()

			cmd := helperCommandContext(t, ctx, "exit", "0")
			ready.Done()

			ready.Wait()
			if err := cmd.Run(); err != nil {
				t.Error(err)
			}
		}()
	}

	exits.Wait()
	cancel()
	hangs.Wait()
}

// TestPathRace tests that [Cmd.String] can be called concurrently
// with [Cmd.Start].
func TestPathRace(t *testing.T) {
	cmd := helperCommand(t, "exit", "0")

	done := make(chan struct{})
	go func() {
		out, err := cmd.CombinedOutput()
		t.Logf("%v: %v\n%s", cmd, err, out)
		close(done)
	}()

	t.Logf("running in background: %v", cmd)
	<-done
}

func TestAbsPathExec(t *testing.T) {
	testenv.MustHaveExec(t)
	testenv.MustHaveGoBuild(t) // must have GOROOT/bin/{go,gofmt}

	// A simple exec of a full path should work.
	// Go 1.22 broke this on Windows, requiring ".exe"; see #66586.
	exe := filepath.Join(testenv.GOROOT(t), "bin/gofmt")
	cmd := exec.Command(exe)
	if cmd.Path != exe {
		t.Errorf("exec.Command(%#q) set Path=%#q", exe, cmd.Path)
	}
	err := cmd.Run()
	if err != nil {
		t.Errorf("using exec.Command(%#q): %v", exe, err)
	}

	cmd = &exec.Cmd{Path: exe}
	err = cmd.Run()
	if err != nil {
		t.Errorf("using exec.Cmd{Path: %#q}: %v", cmd.Path, err)
	}

	cmd = &exec.Cmd{Path: "gofmt", Dir: "/"}
	err = cmd.Run()
	if err == nil {
		t.Errorf("using exec.Cmd{Path: %#q}: unexpected success", cmd.Path)
	}

	// A simple exec after modifying Cmd.Path should work.
	// This broke on Windows. See go.dev/issue/68314.
	t.Run("modified", func(t *testing.T) {
		if exec.Command(filepath.Join(testenv.GOROOT(t), "bin/go")).Run() == nil {
			// The implementation of the test case below relies on the go binary
			// exiting with a non-zero exit code when run without any arguments.
			// In the unlikely case that changes, we need to use another binary.
			t.Fatal("test case needs updating to verify fix for go.dev/issue/68314")
		}
		exe1 := filepath.Join(testenv.GOROOT(t), "bin/go")
		exe2 := filepath.Join(testenv.GOROOT(t), "bin/gofmt")
		cmd := exec.Command(exe1)
		cmd.Path = exe2
		cmd.Args = []string{cmd.Path}
		err := cmd.Run()
		if err != nil {
			t.Error("ran wrong binary")
		}
	})
}

"""




```