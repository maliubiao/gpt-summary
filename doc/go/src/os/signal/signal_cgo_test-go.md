Response:
Let's break down the thought process to understand the provided Go code and answer the user's request.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the Go code snippet, specifically `go/src/os/signal/signal_cgo_test.go`. The request emphasizes:

* Listing the functions.
* Inferring the Go feature being tested.
* Providing Go code examples related to that feature (with assumptions for input/output if applicable).
* Explaining command-line argument handling.
* Pointing out common mistakes users might make.

**2. Initial Code Scan and High-Level Overview:**

I start by scanning the code for keywords and structural elements:

* `package signal_test`: This tells me it's a test file for the `signal` package.
* `//go:build ... && cgo`:  This indicates conditional compilation. The test is only run when the build constraints are met (specific operating systems and CGO enabled). This suggests the test interacts with system-level signals, likely involving C code.
* `import (...)`: The imports hint at the functionality:
    * `context`:  For managing timeouts and cancellations.
    * `encoding/binary`: For converting between binary data and numbers (likely for inter-process communication).
    * `internal/syscall/unix`: For low-level system calls.
    * `internal/testenv`:  For managing test environments (creating subprocesses).
    * `internal/testpty`:  A custom package for working with pseudo-terminals (PTYs). This is a major clue about the test's purpose.
    * `os`, `os/signal`, `runtime`, `strconv`, `syscall`, `testing`, `time`: Standard Go libraries related to OS interaction, signals, concurrency, and testing.
* `const (ptyFD = 3; controlFD = 4)`: These constants represent file descriptors, likely used for communication between processes. Since it's about PTYs and control, these probably represent the child end of the PTY and a control pipe.
* `func TestTerminalSignal(t *testing.T)`: This is the main test function. The name strongly suggests it's testing something related to terminal signals.
* The presence of `runSessionLeader` and `runStoppingChild` functions, along with the environment variable check `os.Getenv("GO_TEST_TERMINAL_SIGNALS")`, indicates the test involves multiple processes.

**3. Focusing on the `TestTerminalSignal` Function:**

I delve into the `TestTerminalSignal` function, as it's the entry point. I notice the conditional execution based on the `GO_TEST_TERMINAL_SIGNALS` environment variable. This confirms the multi-process nature of the test.

* **`lvl == ""` (Main Test Process):** This part sets up the PTY using `testpty.Open()`, creates pipes for communication (`controlR`, `controlW`), and uses `testenv.CommandContext` to start two subprocesses. The `SysProcAttr` with `Setsid`, `Setctty`, and `Ctty` is crucial, as it's related to creating a new session and controlling terminal. The main process reads the child PID from the pipe, sends a `^Z` character to the PTY, and then a `SIGCONT` signal. Finally, it writes a newline to the PTY.
* **`lvl == "1"` (`runSessionLeader`):** This subprocess ignores `SIGTTOU` (related to background processes accessing the controlling terminal). It sets itself as the foreground process group of the PTY using `unix.Tcsetpgrp`. It waits for the "stopping child" to be stopped, takes control of the PTY, waits a bit, gives the PTY back, and then signals that it's done.
* **`lvl == "2"` (`runStoppingChild`):** This subprocess writes a byte to the PTY, then attempts to read from it. The key idea is that this read will be interrupted when the process is stopped and resumed.

**4. Inferring the Go Feature:**

Based on the code analysis, especially the use of PTYs, signals (`SIGSTOP`, `SIGCONT`, `SIGTTOU`), and process groups, I can infer that this test is verifying how Go's `os` and `os/signal` packages handle signals when a program reading from a pseudo-terminal is stopped and then resumed (specifically, the `EINTR` error that might occur on some systems like Darwin). The code specifically mentions a regression test for issue #22838, which is about PTY reads returning `EINTR`.

**5. Creating a Go Code Example:**

To illustrate the feature, I would create a simplified example demonstrating how to read from a PTY and handle signals. This would involve:

* Opening a PTY.
* Reading from the PTY.
* Sending a `SIGSTOP` signal to the reading process.
* Sending a `SIGCONT` signal to resume the process.

The key would be to show how Go's standard library handles the `EINTR` error transparently, retrying the read operation.

**6. Analyzing Command-Line Arguments:**

The code itself doesn't directly parse command-line arguments using `flag` or similar. Instead, it uses environment variables (`GO_TEST_TERMINAL_SIGNALS`). The main test function uses `testenv.CommandContext` which implicitly passes down the test flags (like `-test.run` and `-test.timeout`).

**7. Identifying Potential Mistakes:**

The most likely mistake a user could make when dealing with terminal signals and PTYs is not correctly handling the `EINTR` error. On some systems, read and write operations can be interrupted by signals. Go's standard library generally handles this for you in many cases, but understanding the concept is important if you're working with low-level file descriptors or performing non-blocking I/O.

**8. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, addressing each point in the user's request. I use clear headings, bullet points, and code examples to make the information easy to understand. I also ensure the language is natural and avoids overly technical jargon where possible.

This methodical approach, starting with a high-level overview and then diving into specific parts of the code, allows me to understand the purpose and functionality of the provided Go snippet and address the user's request comprehensively.
这段Go语言代码是 `os/signal` 包的一个测试文件，专门用于测试在特定操作系统上（Darwin, Dragonfly, FreeBSD, Linux (非Android), NetBSD, OpenBSD）并且开启 CGO 的情况下，程序与伪终端（PTY）交互时，接收到信号（特别是 `SIGSTOP`）后的行为。

**功能列举:**

1. **模拟终端信号场景:**  该测试模拟了一个Go程序在一个 shell 中运行时，被用户按下 `Ctrl+Z` (发送 `SIGSTOP` 信号) 暂停，然后又用 `fg` 命令恢复运行的场景。
2. **测试 PTY 读取行为:**  它主要测试当一个 Go 程序在从伪终端读取数据时被 `SIGSTOP` 信号暂停并放入后台，然后再恢复到前台时，`read` 操作是否能正确处理中断并继续读取数据，而不会返回错误。
3. **回归测试:**  该测试是一个针对特定问题的回归测试，解决的是 [https://go.dev/issue/22838](https://go.dev/issue/22838) 中描述的问题。在 Darwin 系统上，当发生这种情况时，PTY 的读取操作会返回 `EINTR` 错误，而 Go 应该自动重试这个操作。
4. **多进程协作:**  为了模拟复杂的终端信号场景，测试使用了三个进程进行协作：
    * **主测试进程:**  负责创建伪终端，并启动两个子进程。
    * **`GO_TEST_TERMINAL_SIGNALS=1` 子进程:**  创建一个新的进程组和会话，并将伪终端作为其控制终端。该进程会忽略 `SIGTTOU` 信号，使其能够成为前台进程组。它负责从第二个子进程手中接管伪终端的前台控制。
    * **`GO_TEST_TERMINAL_SIGNALS=2` 子进程:**  作为初始的前台进程组，它会尝试从伪终端读取数据，然后会被 `SIGSTOP` 信号暂停。

**实现原理 (Go 代码举例说明):**

该测试的核心在于模拟 `SIGSTOP` 和 `SIGCONT` 信号对正在读取伪终端的进程的影响，并验证 Go 运行时是否能正确处理 `EINTR` 错误。

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func main() {
	// 假设我们有一个程序 'myprogram'，它会读取终端输入
	cmd := exec.Command("./myprogram")
	cmd.Stdin, _ = os.Open("/dev/tty") // 将终端作为输入
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting program:", err)
		return
	}

	time.Sleep(2 * time.Second) // 让程序运行一段时间

	// 模拟按下 Ctrl+Z 发送 SIGSTOP 信号
	fmt.Println("Sending SIGSTOP...")
	cmd.Process.Signal(syscall.SIGSTOP)

	time.Sleep(2 * time.Second) // 模拟程序暂停

	// 模拟使用 'fg' 命令发送 SIGCONT 信号
	fmt.Println("Sending SIGCONT...")
	cmd.Process.Signal(syscall.SIGCONT)

	time.Sleep(2 * time.Second) // 让程序继续运行

	fmt.Println("Waiting for program to finish...")
	cmd.Wait()
	fmt.Println("Program finished.")
}
```

**假设的 `myprogram` (简化版):**

```go
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Program started. Waiting for input...")
	input, _ := reader.ReadString('\n')
	fmt.Println("Received input:", input)
}
```

**假设的输入与输出:**

1. **运行主程序:**  主程序会启动 `myprogram`。
2. **`myprogram` 输出:**  `Program started. Waiting for input...`
3. **主程序输出:** `Sending SIGSTOP...`
4. **`myprogram` 暂停:**  此时 `myprogram` 进入暂停状态。
5. **主程序输出:** `Sending SIGCONT...`
6. **`myprogram` 恢复:**  `myprogram` 从暂停状态恢复。
7. **在终端中输入:**  用户在终端中输入一些文本，例如 "hello\n"。
8. **`myprogram` 输出:** `Received input: hello\n`
9. **主程序输出:** `Waiting for program to finish...` 和 `Program finished.`

**代码推理:**

测试代码的核心逻辑在于：

1. **创建 PTY:**  使用 `testpty.Open()` 创建一个伪终端。
2. **启动子进程:**  启动两个子进程，分别扮演不同的角色来模拟终端信号的处理过程。
3. **进程间通信:**  使用管道 (`controlR`, `controlW`) 在父子进程之间传递信息，例如子进程的 PID，以及同步信号处理的进度。
4. **发送 `SIGSTOP`:**  主进程通过向伪终端写入 `^Z` 字符来模拟用户在终端中按下 `Ctrl+Z`，从而向运行在前台的子进程发送 `SIGSTOP` 信号。
5. **切换前台进程组:**  `runSessionLeader` 子进程会尝试接管伪终端的前台进程组，这会触发一些系统行为，例如可能导致正在读取终端的进程收到 `EINTR` 错误。
6. **发送 `SIGCONT`:**  主进程发送 `SIGCONT` 信号来恢复被暂停的子进程。
7. **验证读取行为:**  测试期望当子进程恢复后，能够正确地从伪终端继续读取数据，即使之前因为 `SIGSTOP` 而可能遇到了 `EINTR` 错误。Go 的 `os` 包应该在底层自动处理这种 `EINTR` 错误并重试读取。

**命令行参数的具体处理:**

该测试文件本身并不直接处理命令行参数。它主要依赖 `go test` 命令的运行。

* **`-test.run`:**  用于指定要运行的测试函数，例如 `-test.run=^TestTerminalSignal$`。
* **`-test.timeout`:**  用于设置测试的超时时间。测试代码中会根据 `t.Deadline()` 来动态设置子进程的超时时间。
* **`GO_TEST_TERMINAL_SIGNALS` 环境变量:**  这个环境变量被用来区分不同的子进程角色，决定了每个子进程执行哪个分支的代码。

**使用者易犯错的点:**

虽然这段代码主要是测试框架内部使用的，但理解其背后的原理对于使用 `os/signal` 和处理终端信号的开发者仍然很重要。一个常见的错误是：

* **没有正确处理 `syscall.EINTR` 错误:** 在进行低级别的系统调用，例如读取文件描述符时，如果操作被信号中断，可能会返回 `syscall.EINTR` 错误。开发者需要意识到这种情况，并在必要时重试操作。虽然 Go 的 `os` 包在很多情况下会自动处理，但在某些特定的场景下，例如使用原始的文件描述符进行操作时，需要手动处理。

**示例说明 `syscall.EINTR` 的处理 (并非此测试直接展示，但与之相关):**

假设你直接使用 `syscall.Read` 从一个文件描述符读取数据：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	file, err := os.Open("mydata.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	fd := int(file.Fd())
	buffer := make([]byte, 1024)

	for {
		n, err := syscall.Read(fd, buffer)
		if err != nil {
			if err == syscall.EINTR {
				// 被信号中断，重试读取
				fmt.Println("Read interrupted by signal, retrying...")
				continue
			}
			fmt.Println("Error reading from file:", err)
			return
		}
		if n == 0 {
			// 文件读取完毕
			fmt.Println("End of file reached.")
			break
		}
		fmt.Printf("Read %d bytes: %s", n, string(buffer[:n]))
	}
}
```

在这个例子中，如果 `syscall.Read` 因为接收到信号而被中断，它会返回 `syscall.EINTR` 错误。正确的做法是检查这个错误，并重试读取操作。Go 的 `os` 包在内部就做了类似的错误处理，使得上层用户在大多数情况下不需要显式处理 `EINTR`。

总结来说，这段测试代码深入地测试了 Go 语言在处理终端信号和伪终端交互时的底层机制，确保了在复杂的信号场景下，程序的稳定性和正确性。

Prompt: 
```
这是路径为go/src/os/signal/signal_cgo_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (darwin || dragonfly || freebsd || (linux && !android) || netbsd || openbsd) && cgo

// Note that this test does not work on Solaris: issue #22849.
// Don't run the test on Android because at least some versions of the
// C library do not define the posix_openpt function.

package signal_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"internal/syscall/unix"
	"internal/testenv"
	"internal/testpty"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const (
	ptyFD     = 3 // child end of pty.
	controlFD = 4 // child end of control pipe.
)

// TestTerminalSignal tests that read from a pseudo-terminal does not return an
// error if the process is SIGSTOP'd and put in the background during the read.
//
// This test simulates stopping a Go process running in a shell with ^Z and
// then resuming with `fg`.
//
// This is a regression test for https://go.dev/issue/22838. On Darwin, PTY
// reads return EINTR when this occurs, and Go should automatically retry.
func TestTerminalSignal(t *testing.T) {
	// This test simulates stopping a Go process running in a shell with ^Z
	// and then resuming with `fg`. This sounds simple, but is actually
	// quite complicated.
	//
	// In principle, what we are doing is:
	// 1. Creating a new PTY parent/child FD pair.
	// 2. Create a child that is in the foreground process group of the PTY, and read() from that process.
	// 3. Stop the child with ^Z.
	// 4. Take over as foreground process group of the PTY from the parent.
	// 5. Make the child foreground process group again.
	// 6. Continue the child.
	//
	// On Darwin, step 4 results in the read() returning EINTR once the
	// process continues. internal/poll should automatically retry the
	// read.
	//
	// These steps are complicated by the rules around foreground process
	// groups. A process group cannot be foreground if it is "orphaned",
	// unless it masks SIGTTOU.  i.e., to be foreground the process group
	// must have a parent process group in the same session or mask SIGTTOU
	// (which we do). An orphaned process group cannot receive
	// terminal-generated SIGTSTP at all.
	//
	// Achieving this requires three processes total:
	// - Top-level process: this is the main test process and creates the
	// pseudo-terminal.
	// - GO_TEST_TERMINAL_SIGNALS=1: This process creates a new process
	// group and session. The PTY is the controlling terminal for this
	// session. This process masks SIGTTOU, making it eligible to be a
	// foreground process group. This process will take over as foreground
	// from subprocess 2 (step 4 above).
	// - GO_TEST_TERMINAL_SIGNALS=2: This process create a child process
	// group of subprocess 1, and is the original foreground process group
	// for the PTY. This subprocess is the one that is SIGSTOP'd.

	if runtime.GOOS == "dragonfly" {
		t.Skip("skipping: wait hangs on dragonfly; see https://go.dev/issue/56132")
	}

	scale := 1
	if s := os.Getenv("GO_TEST_TIMEOUT_SCALE"); s != "" {
		if sc, err := strconv.Atoi(s); err == nil {
			scale = sc
		}
	}
	pause := time.Duration(scale) * 10 * time.Millisecond

	lvl := os.Getenv("GO_TEST_TERMINAL_SIGNALS")
	switch lvl {
	case "":
		// Main test process, run code below.
		break
	case "1":
		runSessionLeader(t, pause)
		panic("unreachable")
	case "2":
		runStoppingChild()
		panic("unreachable")
	default:
		fmt.Fprintf(os.Stderr, "unknown subprocess level %s\n", lvl)
		os.Exit(1)
	}

	t.Parallel()

	pty, procTTYName, err := testpty.Open()
	if err != nil {
		ptyErr := err.(*testpty.PtyError)
		if ptyErr.FuncName == "posix_openpt" && ptyErr.Errno == syscall.EACCES {
			t.Skip("posix_openpt failed with EACCES, assuming chroot and skipping")
		}
		t.Fatal(err)
	}
	defer pty.Close()
	procTTY, err := os.OpenFile(procTTYName, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer procTTY.Close()

	// Control pipe. GO_TEST_TERMINAL_SIGNALS=2 send the PID of
	// GO_TEST_TERMINAL_SIGNALS=3 here. After SIGSTOP, it also writes a
	// byte to indicate that the foreground cycling is complete.
	controlR, controlW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	var (
		ctx     = context.Background()
		cmdArgs = []string{"-test.run=^TestTerminalSignal$"}
	)
	if deadline, ok := t.Deadline(); ok {
		d := time.Until(deadline)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		t.Cleanup(cancel)

		// We run the subprocess with an additional 20% margin to allow it to fail
		// and clean up gracefully if it times out.
		cmdArgs = append(cmdArgs, fmt.Sprintf("-test.timeout=%v", d*5/4))
	}

	cmd := testenv.CommandContext(t, ctx, os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "GO_TEST_TERMINAL_SIGNALS=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout // for logging
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{procTTY, controlW}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    ptyFD,
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	if err := procTTY.Close(); err != nil {
		t.Errorf("closing procTTY: %v", err)
	}

	if err := controlW.Close(); err != nil {
		t.Errorf("closing controlW: %v", err)
	}

	// Wait for first child to send the second child's PID.
	b := make([]byte, 8)
	n, err := controlR.Read(b)
	if err != nil {
		t.Fatalf("error reading child pid: %v\n", err)
	}
	if n != 8 {
		t.Fatalf("unexpected short read n = %d\n", n)
	}
	pid := binary.LittleEndian.Uint64(b[:])
	process, err := os.FindProcess(int(pid))
	if err != nil {
		t.Fatalf("unable to find child process: %v", err)
	}

	// Wait for the third child to write a byte indicating that it is
	// entering the read.
	b = make([]byte, 1)
	_, err = pty.Read(b)
	if err != nil {
		t.Fatalf("error reading from child: %v", err)
	}

	// Give the program time to enter the read call.
	// It doesn't matter much if we occasionally don't wait long enough;
	// we won't be testing what we want to test, but the overall test
	// will pass.
	time.Sleep(pause)

	t.Logf("Sending ^Z...")

	// Send a ^Z to stop the program.
	if _, err := pty.Write([]byte{26}); err != nil {
		t.Fatalf("writing ^Z to pty: %v", err)
	}

	// Wait for subprocess 1 to cycle the foreground process group.
	if _, err := controlR.Read(b); err != nil {
		t.Fatalf("error reading readiness: %v", err)
	}

	t.Logf("Sending SIGCONT...")

	// Restart the stopped program.
	if err := process.Signal(syscall.SIGCONT); err != nil {
		t.Fatalf("Signal(SIGCONT) got err %v want nil", err)
	}

	// Write some data for the program to read, which should cause it to
	// exit.
	if _, err := pty.Write([]byte{'\n'}); err != nil {
		t.Fatalf("writing %q to pty: %v", "\n", err)
	}

	t.Logf("Waiting for exit...")

	if err = cmd.Wait(); err != nil {
		t.Errorf("subprogram failed: %v", err)
	}
}

// GO_TEST_TERMINAL_SIGNALS=1 subprocess above.
func runSessionLeader(t *testing.T, pause time.Duration) {
	// "Attempts to use tcsetpgrp() from a process which is a
	// member of a background process group on a fildes associated
	// with its controlling terminal shall cause the process group
	// to be sent a SIGTTOU signal. If the calling thread is
	// blocking SIGTTOU signals or the process is ignoring SIGTTOU
	// signals, the process shall be allowed to perform the
	// operation, and no signal is sent."
	//  -https://pubs.opengroup.org/onlinepubs/9699919799/functions/tcsetpgrp.html
	//
	// We are changing the terminal to put us in the foreground, so
	// we must ignore SIGTTOU. We are also an orphaned process
	// group (see above), so we must mask SIGTTOU to be eligible to
	// become foreground at all.
	signal.Ignore(syscall.SIGTTOU)

	pty := os.NewFile(ptyFD, "pty")
	controlW := os.NewFile(controlFD, "control-pipe")

	var (
		ctx     = context.Background()
		cmdArgs = []string{"-test.run=^TestTerminalSignal$"}
	)
	if deadline, ok := t.Deadline(); ok {
		d := time.Until(deadline)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		t.Cleanup(cancel)

		// We run the subprocess with an additional 20% margin to allow it to fail
		// and clean up gracefully if it times out.
		cmdArgs = append(cmdArgs, fmt.Sprintf("-test.timeout=%v", d*5/4))
	}

	cmd := testenv.CommandContext(t, ctx, os.Args[0], cmdArgs...)
	cmd.Env = append(os.Environ(), "GO_TEST_TERMINAL_SIGNALS=2")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{pty}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Foreground: true,
		Ctty:       ptyFD,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "error starting second subprocess: %v\n", err)
		os.Exit(1)
	}

	fn := func() error {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(cmd.Process.Pid))
		_, err := controlW.Write(b[:])
		if err != nil {
			return fmt.Errorf("error writing child pid: %w", err)
		}

		// Wait for stop.
		var status syscall.WaitStatus
		for {
			_, err = syscall.Wait4(cmd.Process.Pid, &status, syscall.WUNTRACED, nil)
			if err != syscall.EINTR {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("error waiting for stop: %w", err)
		}

		if !status.Stopped() {
			return fmt.Errorf("unexpected wait status: %v", status)
		}

		// Take TTY.
		pgrp := int32(syscall.Getpgrp()) // assume that pid_t is int32
		if err := unix.Tcsetpgrp(ptyFD, pgrp); err != nil {
			return fmt.Errorf("error setting tty process group: %w", err)
		}

		// Give the kernel time to potentially wake readers and have
		// them return EINTR (darwin does this).
		time.Sleep(pause)

		// Give TTY back.
		pid := int32(cmd.Process.Pid) // assume that pid_t is int32
		if err := unix.Tcsetpgrp(ptyFD, pid); err != nil {
			return fmt.Errorf("error setting tty process group back: %w", err)
		}

		// Report that we are done and SIGCONT can be sent. Note that
		// the actual byte we send doesn't matter.
		if _, err := controlW.Write(b[:1]); err != nil {
			return fmt.Errorf("error writing readiness: %w", err)
		}

		return nil
	}

	err := fn()
	if err != nil {
		fmt.Fprintf(os.Stderr, "session leader error: %v\n", err)
		cmd.Process.Kill()
		// Wait for exit below.
	}

	werr := cmd.Wait()
	if werr != nil {
		fmt.Fprintf(os.Stderr, "error running second subprocess: %v\n", err)
	}

	if err != nil || werr != nil {
		os.Exit(1)
	}

	os.Exit(0)
}

// GO_TEST_TERMINAL_SIGNALS=2 subprocess above.
func runStoppingChild() {
	pty := os.NewFile(ptyFD, "pty")

	var b [1]byte
	if _, err := pty.Write(b[:]); err != nil {
		fmt.Fprintf(os.Stderr, "error writing byte to PTY: %v\n", err)
		os.Exit(1)
	}

	_, err := pty.Read(b[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if b[0] == '\n' {
		// This is what we expect
		fmt.Println("read newline")
	} else {
		fmt.Fprintf(os.Stderr, "read 1 unexpected byte: %q\n", b)
		os.Exit(1)
	}
	os.Exit(0)
}

"""



```