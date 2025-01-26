Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding and Purpose:**

The first step is to recognize the file path: `go/src/syscall/syscall_unix_test.go`. This immediately tells us:

* **Location:** This is a test file within the `syscall` package in the Go standard library.
* **Purpose:** It's designed to test the functionality of the `syscall` package on Unix-like operating systems. The `_test.go` suffix confirms this.
* **Focus:** The code will likely involve interacting with low-level system calls.

**2. Scanning for Key Functionality:**

I'll then quickly scan the code for function definitions and significant code blocks. Keywords like `func Test...`, `syscall.`, `exec.Command`, `net.`, and comments like `// Tests that below functions...` are good indicators.

**3. Analyzing Individual Test Functions:**

* **`TestFcntlFlock`:**  The name suggests it tests the `fcntl` system call, specifically the file locking mechanism (`Flock`). The comments confirm this, explaining the differences between glibc and raw syscalls. The structure of the test with a parent and child process using `exec.Command` is a common pattern for testing inter-process communication or resource sharing.

* **`TestPassFD`:** The name clearly indicates testing the passing of file descriptors over a Unix socket. The use of `syscall.Socketpair`, `net.FileConn`, and `syscall.ParseSocketControlMessage`/`syscall.ParseUnixRights` reinforces this. The parent/child process setup is again present. The AIX-specific skipping logic is a detail to note.

* **`passFDChild`:** This function is explicitly called by `TestPassFD` in the child process. It's responsible for creating a file, sending its file descriptor back to the parent using `WriteMsgUnix`, and handling potential errors.

* **`TestUnixRightsRoundtrip`:**  This test focuses on the `syscall.UnixRights`, `syscall.ParseSocketControlMessage`, and `syscall.ParseUnixRights` functions. The name "roundtrip" suggests it's verifying that a list of file descriptors can be encoded and decoded correctly.

* **`TestSeekFailure`:**  This is a simpler test checking the error handling of the `syscall.Seek` function with an invalid file descriptor.

* **`TestSetsockoptString`:**  This test checks if `syscall.SetsockoptString` handles empty strings correctly (specifically to prevent panics as mentioned in the comment).

* **`TestENFILETemporary`:** This is another simple test verifying that `syscall.ENFILE` is correctly identified as a temporary error.

* **The anonymous function `_()`:** This function doesn't perform a test. Instead, it's a compile-time check to ensure the consistency of certain `syscall` constants, structures, and function signatures across different Unix-like systems. This is a clever way to enforce API stability.

**4. Identifying Core Functionality:**

Based on the analyzed test functions, the core functionality being tested in this file revolves around:

* **File Locking:**  Using `fcntl` with `Flock_t`, `F_SETLK`, `F_GETLK`.
* **Passing File Descriptors:**  Over Unix domain sockets using `Socketpair`, `Sendmsg`/`Recvmsg` (implicitly through `WriteMsgUnix`/`ReadMsgUnix`), and ancillary data (socket control messages).
* **Socket Options:**  Setting socket options with strings.
* **Error Handling:**  Specifically testing error conditions for `Seek` and confirming the "temporary" nature of specific errors.
* **API Consistency:**  Ensuring the structure and signatures of specific `syscall` components are consistent.

**5. Inferring Go Language Features:**

The code heavily utilizes the `syscall` package, indicating testing of Go's low-level operating system interface. Key Go features demonstrated include:

* **Standard Library Testing:**  Using the `testing` package for writing unit tests.
* **Inter-process Communication:** Using `os/exec` to create and manage child processes for testing scenarios that require isolation or resource sharing.
* **File I/O:** Using `os.File` for file operations.
* **Networking:** Using `net` package for socket operations (specifically Unix domain sockets).
* **Error Handling:**  Checking for and handling errors returned by system calls.
* **Pointers and Structures:** Working with C-style structures like `Flock_t` using Go's `unsafe` mechanisms (though not explicitly visible in this snippet, the underlying `syscall` package uses it).
* **Compile-time Checks:**  Using the anonymous function `_()` for static type checking.

**6. Code Examples and Explanations:**

With the core functionality identified, I can now construct relevant Go code examples to illustrate the concepts. This involves selecting the most representative test functions and providing simplified versions or explanations.

**7. Identifying Potential User Errors:**

By understanding the tested functionalities, I can anticipate common mistakes users might make. For instance, with `FcntlFlock`, forgetting the distinction between glibc values and raw syscall values, or issues with shared resource management when using file locking. For passing file descriptors, improper handling of socket control messages or file descriptor ownership are potential pitfalls.

**8. Structuring the Answer:**

Finally, I'd organize the information into a clear and structured answer, addressing each part of the prompt:

* **Functionality Listing:** A concise list of the tested areas.
* **Go Feature Inference:**  Listing the relevant Go language features demonstrated.
* **Code Examples:** Providing practical Go code snippets with input/output explanations.
* **Command-line Argument Handling:**  Explaining any command-line parameters used (in this case, related to test execution).
* **Common Mistakes:** Pointing out potential user errors based on the tested scenarios.

This systematic approach allows for a comprehensive understanding and explanation of the provided Go test code.
这个Go语言源文件 `go/src/syscall/syscall_unix_test.go` 的主要功能是**测试 `syscall` 包在 Unix-like 系统上的实现是否正确且一致**。它通过编写单元测试来验证与底层操作系统交互相关的各种功能，包括但不限于：

**核心功能点:**

1. **程序调度优先级相关:**  测试 `syscall.Setpriority` 和 `syscall.Getpriority` 函数，以及相关的常量 `syscall.PRIO_USER`, `syscall.PRIO_PROCESS`, `syscall.PRIO_PGRP` 的定义是否正确。它验证了设置和获取进程、用户组或用户的调度优先级的能力。

2. **termios 相关常量:**  测试 `syscall.TCIFLUSH`, `syscall.TCIOFLUSH`, `syscall.TCOFLUSH` 这些用于控制终端 I/O 的常量是否定义正确。

3. **fcntl 文件锁相关:**
   - 测试 `syscall.Flock_t` 结构体的定义，确保其字段类型和顺序与操作系统一致。
   - 测试 `syscall.F_GETLK`, `syscall.F_SETLK`, `syscall.F_SETLKW` 这些用于文件锁操作的常量。
   - 特别地，`TestFcntlFlock` 函数还验证了 Go 直接使用原始系统调用值，而不是像 glibc 那样进行转换。它通过父子进程协作的方式，验证了锁的设置和查询功能。

4. **通过 Unix 套接字传递文件描述符:**
   - `TestPassFD` 函数测试了通过 Unix 域套接字在进程间传递文件描述符的能力。它创建一对套接字，启动一个子进程，子进程将一个文件的文件描述符发送回父进程，父进程再读取该文件。

5. **`syscall.UnixRights` 和相关函数:**
   - `TestUnixRightsRoundtrip` 测试了 `syscall.UnixRights` 函数（用于创建包含文件描述符的控制消息）、`syscall.ParseSocketControlMessage` 和 `syscall.ParseUnixRights` 函数的正确性。它验证了可以正确地将文件描述符列表编码到控制消息中，然后再解码出来。

6. **错误处理:**
   - `TestSeekFailure` 测试了 `syscall.Seek` 函数在遇到错误时的处理，特别是验证了错误信息不会导致程序崩溃。
   - `TestSetsockoptString` 测试了 `syscall.SetsockoptString` 函数在传入空字符串时的行为，防止出现 panic。
   - `TestENFILETemporary` 测试了 `syscall.ENFILE` 错误是否被正确地认为是临时错误。

**推理出的 Go 语言功能实现：**

这个测试文件主要测试的是 Go 语言标准库中 `syscall` 包对底层操作系统系统调用的封装。`syscall` 包允许 Go 程序直接调用操作系统提供的功能，例如文件操作、进程控制、网络通信等。

**Go 代码举例说明 (基于 `TestFcntlFlock`):**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	filename := "test.lock"
	fd, err := syscall.Open(filename, syscall.O_CREAT|syscall.O_RDWR, 0666)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer syscall.Close(fd)

	// 尝试获取写锁
	lock := syscall.Flock_t{
		Type: syscall.F_WRLCK,
		Whence: syscall.SEEK_SET,
		Start: 0,
		Len: 0, // 锁定整个文件
		Pid: int32(os.Getpid()),
	}

	err = syscall.FcntlFlock(uintptr(fd), syscall.F_SETLK, &lock)
	if err != nil {
		fmt.Println("尝试获取锁失败:", err)
		return
	}
	fmt.Println("成功获取锁")

	// 模拟持有锁一段时间
	fmt.Println("持有锁...")
	// time.Sleep(5 * time.Second)

	// 释放锁 (通常文件关闭会自动释放，但显式释放更清晰)
	lock.Type = syscall.F_UNLCK
	err = syscall.FcntlFlock(uintptr(fd), syscall.F_SETLK, &lock)
	if err != nil {
		fmt.Println("释放锁失败:", err)
		return
	}
	fmt.Println("成功释放锁")
}
```

**假设的输入与输出:**

假设 `test.lock` 文件不存在。

**输出:**

```
成功获取锁
持有锁...
成功释放锁
```

如果另一个进程在上述代码的 `// 模拟持有锁一段时间` 注释取消的情况下尝试获取写锁，它会因为 `syscall.F_SETLK` 的非阻塞特性而立即返回错误（`EAGAIN` 或 `EWOULDBLOCK`）。 如果使用 `syscall.F_SETLKW`，则会阻塞直到锁被释放。

**Go 代码举例说明 (基于 `TestPassFD`):**

```go
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	// 创建 Unix 域套接字对
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("创建套接字对失败:", err)
		return
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	// 创建一个临时文件
	tempFile, err := os.CreateTemp("", "example")
	if err != nil {
		fmt.Println("创建临时文件失败:", err)
		return
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	_, err = tempFile.WriteString("Hello from parent!\n")
	if err != nil {
		fmt.Println("写入文件失败:", err)
		return
	}

	// 将文件描述符发送到另一个套接字
	rights := syscall.UnixRights(int(tempFile.Fd()))
	var oob []byte = rights
	dummyData := []byte("send fd")
	_, _, err = syscall.SendmsgN(fds[0], dummyData, oob, nil, 0)
	if err != nil {
		fmt.Println("发送文件描述符失败:", err)
		return
	}

	// 在另一个套接字接收文件描述符
	oobRecv := make([]byte, syscall.CmsgSpace(4)) // 假设只发送一个 fd
	buf := make([]byte, 10)
	_, _, _, _, err = syscall.Recvmsg(fds[1], buf, oobRecv, 0)
	if err != nil {
		fmt.Println("接收文件描述符失败:", err)
		return
	}

	scms, err := syscall.ParseSocketControlMessage(oobRecv)
	if err != nil {
		fmt.Println("解析控制消息失败:", err)
		return
	}
	if len(scms) != 1 {
		fmt.Println("期望一个控制消息")
		return
	}
	scm := scms[0]
	recvFds, err := syscall.ParseUnixRights(&scm)
	if err != nil {
		fmt.Println("解析 Unix 权限失败:", err)
		return
	}
	if len(recvFds) != 1 {
		fmt.Println("期望接收到一个文件描述符")
		return
	}

	// 使用接收到的文件描述符
	receivedFile := os.NewFile(uintptr(recvFds[0]), "received")
	defer receivedFile.Close()
	receivedContent, err := os.ReadFile(receivedFile.Name())
	if err != nil {
		fmt.Println("读取接收到的文件失败:", err)
		return
	}
	fmt.Println("接收到的文件内容:", string(receivedContent))
}
```

**假设的输入与输出:**

无特定的命令行输入。

**输出:**

```
接收到的文件内容: Hello from parent!
```

**命令行参数的具体处理:**

在这个代码片段中，`TestPassFD` 函数的父进程会使用 `exec.Command` 来启动自身的另一个实例作为子进程，并传递参数 `-test.run=^TestPassFD$`。这指示子进程只运行名为 `TestPassFD` 的测试函数。

子进程还会通过环境变量 `GO_WANT_HELPER_PROCESS=1` 来标识自己是辅助进程。

`passFDChild` 函数会使用 `flag.Parse()` 来解析命令行参数，并期望获取一个参数，这个参数是父进程传递给子进程的临时目录路径。子进程在这个临时目录下创建文件。

**易犯错的点举例说明 (基于 `TestFcntlFlock`):**

一个常见的错误是**在多个 Goroutine 中不正确地使用文件锁**。例如，如果多个 Goroutine 试图对同一个文件执行加锁操作而没有适当的同步机制，可能会导致竞争条件和意外的行为。

```go
package main

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
)

func main() {
	filename := "test.lock"
	fd, err := syscall.Open(filename, syscall.O_CREAT|syscall.O_RDWR, 0666)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer syscall.Close(fd)

	var wg sync.WaitGroup
	numGoroutines := 2

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			lock := syscall.Flock_t{
				Type:   syscall.F_WRLCK,
				Whence: syscall.SEEK_SET,
				Start:  0,
				Len:    0,
				Pid:    int32(os.Getpid()),
			}

			fmt.Printf("Goroutine %d 尝试获取锁...\n", id)
			err := syscall.FcntlFlock(uintptr(fd), syscall.F_SETLKW, &lock) // 使用 F_SETLKW 会阻塞
			if err != nil {
				fmt.Printf("Goroutine %d 获取锁失败: %v\n", id, err)
				return
			}
			fmt.Printf("Goroutine %d 成功获取锁\n", id)
			time.Sleep(time.Second) // 模拟持有锁
			lock.Type = syscall.F_UNLCK
			err = syscall.FcntlFlock(uintptr(fd), syscall.F_SETLK, &lock)
			if err != nil {
				fmt.Printf("Goroutine %d 释放锁失败: %v\n", id, err)
				return
			}
			fmt.Printf("Goroutine %d 成功释放锁\n", id)
		}(i)
	}

	wg.Wait()
	fmt.Println("所有 Goroutine 完成")
}
```

在这个例子中，由于使用了 `syscall.F_SETLKW`，后尝试获取锁的 Goroutine 会阻塞，直到前一个 Goroutine 释放锁。如果没有使用 `sync.WaitGroup` 或其他同步机制来确保文件描述符在所有 Goroutine 完成前保持有效，可能会出现问题。另外，如果错误地使用了非阻塞的 `syscall.F_SETLK`，则第二个 Goroutine 很可能会获取锁失败并返回错误。

Prompt: 
```
这是路径为go/src/syscall/syscall_unix_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package syscall_test

import (
	"flag"
	"fmt"
	"internal/testenv"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Tests that below functions, structures and constants are consistent
// on all Unix-like systems.
func _() {
	// program scheduling priority functions and constants
	var (
		_ func(int, int, int) error   = syscall.Setpriority
		_ func(int, int) (int, error) = syscall.Getpriority
	)
	const (
		_ int = syscall.PRIO_USER
		_ int = syscall.PRIO_PROCESS
		_ int = syscall.PRIO_PGRP
	)

	// termios constants
	const (
		_ int = syscall.TCIFLUSH
		_ int = syscall.TCIOFLUSH
		_ int = syscall.TCOFLUSH
	)

	// fcntl file locking structure and constants
	var (
		_ = syscall.Flock_t{
			Type:   int16(0),
			Whence: int16(0),
			Start:  int64(0),
			Len:    int64(0),
			Pid:    int32(0),
		}
	)
	const (
		_ = syscall.F_GETLK
		_ = syscall.F_SETLK
		_ = syscall.F_SETLKW
	)
}

// TestFcntlFlock tests whether the file locking structure matches
// the calling convention of each kernel.
// On some Linux systems, glibc uses another set of values for the
// commands and translates them to the correct value that the kernel
// expects just before the actual fcntl syscall. As Go uses raw
// syscalls directly, it must use the real value, not the glibc value.
// Thus this test also verifies that the Flock_t structure can be
// roundtripped with F_SETLK and F_GETLK.
func TestFcntlFlock(t *testing.T) {
	if runtime.GOOS == "ios" {
		t.Skip("skipping; no child processes allowed on iOS")
	}
	flock := syscall.Flock_t{
		Type:  syscall.F_WRLCK,
		Start: 31415, Len: 271828, Whence: 1,
	}
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "" {
		// parent
		tempDir := t.TempDir()
		name := filepath.Join(tempDir, "TestFcntlFlock")
		fd, err := syscall.Open(name, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}
		// f takes ownership of fd, and will close it.
		//
		// N.B. This defer is also necessary to keep f alive
		// while we use its fd, preventing its finalizer from
		// executing.
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()

		if err := syscall.Ftruncate(int(f.Fd()), 1<<20); err != nil {
			t.Fatalf("Ftruncate(1<<20) failed: %v", err)
		}
		if err := syscall.FcntlFlock(f.Fd(), syscall.F_SETLK, &flock); err != nil {
			t.Fatalf("FcntlFlock(F_SETLK) failed: %v", err)
		}

		cmd := exec.Command(os.Args[0], "-test.run=^TestFcntlFlock$")
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		cmd.ExtraFiles = []*os.File{f}
		out, err := cmd.CombinedOutput()
		if len(out) > 0 || err != nil {
			t.Fatalf("child process: %q, %v", out, err)
		}
	} else {
		// child
		got := flock
		// make sure the child lock is conflicting with the parent lock
		got.Start--
		got.Len++
		if err := syscall.FcntlFlock(3, syscall.F_GETLK, &got); err != nil {
			t.Fatalf("FcntlFlock(F_GETLK) failed: %v", err)
		}
		flock.Pid = int32(syscall.Getppid())
		// Linux kernel always set Whence to 0
		flock.Whence = 0
		if got.Type == flock.Type && got.Start == flock.Start && got.Len == flock.Len && got.Pid == flock.Pid && got.Whence == flock.Whence {
			os.Exit(0)
		}
		t.Fatalf("FcntlFlock got %v, want %v", got, flock)
	}
}

// TestPassFD tests passing a file descriptor over a Unix socket.
//
// This test involved both a parent and child process. The parent
// process is invoked as a normal test, with "go test", which then
// runs the child process by running the current test binary with args
// "-test.run=^TestPassFD$" and an environment variable used to signal
// that the test should become the child process instead.
func TestPassFD(t *testing.T) {
	testenv.MustHaveExec(t)

	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		passFDChild()
		return
	}

	if runtime.GOOS == "aix" {
		// Unix network isn't properly working on AIX 7.2 with Technical Level < 2
		out, err := exec.Command("oslevel", "-s").Output()
		if err != nil {
			t.Skipf("skipping on AIX because oslevel -s failed: %v", err)
		}
		if len(out) < len("7200-XX-ZZ-YYMM") { // AIX 7.2, Tech Level XX, Service Pack ZZ, date YYMM
			t.Skip("skipping on AIX because oslevel -s hasn't the right length")
		}
		aixVer := string(out[:4])
		tl, err := strconv.Atoi(string(out[5:7]))
		if err != nil {
			t.Skipf("skipping on AIX because oslevel -s output cannot be parsed: %v", err)
		}
		if aixVer < "7200" || (aixVer == "7200" && tl < 2) {
			t.Skip("skipped on AIX versions previous to 7.2 TL 2")
		}

	}

	tempDir := t.TempDir()

	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	writeFile := os.NewFile(uintptr(fds[0]), "child-writes")
	readFile := os.NewFile(uintptr(fds[1]), "parent-reads")
	defer writeFile.Close()
	defer readFile.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestPassFD$", "--", tempDir)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	cmd.ExtraFiles = []*os.File{writeFile}

	out, err := cmd.CombinedOutput()
	if len(out) > 0 || err != nil {
		t.Fatalf("child process: %q, %v", out, err)
	}

	c, err := net.FileConn(readFile)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer c.Close()

	uc, ok := c.(*net.UnixConn)
	if !ok {
		t.Fatalf("unexpected FileConn type; expected UnixConn, got %T", c)
	}

	buf := make([]byte, 32) // expect 1 byte
	oob := make([]byte, 32) // expect 24 bytes
	closeUnix := time.AfterFunc(5*time.Second, func() {
		t.Logf("timeout reading from unix socket")
		uc.Close()
	})
	_, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatalf("ReadMsgUnix: %v", err)
	}
	closeUnix.Stop()

	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatalf("ParseSocketControlMessage: %v", err)
	}
	if len(scms) != 1 {
		t.Fatalf("expected 1 SocketControlMessage; got scms = %#v", scms)
	}
	scm := scms[0]
	gotFds, err := syscall.ParseUnixRights(&scm)
	if err != nil {
		t.Fatalf("syscall.ParseUnixRights: %v", err)
	}
	if len(gotFds) != 1 {
		t.Fatalf("wanted 1 fd; got %#v", gotFds)
	}

	f := os.NewFile(uintptr(gotFds[0]), "fd-from-child")
	defer f.Close()

	got, err := io.ReadAll(f)
	want := "Hello from child process!\n"
	if string(got) != want {
		t.Errorf("child process ReadAll: %q, %v; want %q", got, err, want)
	}
}

// passFDChild is the child process used by TestPassFD.
func passFDChild() {
	defer os.Exit(0)

	// Look for our fd. It should be fd 3, but we work around an fd leak
	// bug here (https://golang.org/issue/2603) to let it be elsewhere.
	var uc *net.UnixConn
	for fd := uintptr(3); fd <= 10; fd++ {
		f := os.NewFile(fd, "unix-conn")
		var ok bool
		netc, _ := net.FileConn(f)
		uc, ok = netc.(*net.UnixConn)
		if ok {
			break
		}
	}
	if uc == nil {
		fmt.Println("failed to find unix fd")
		return
	}

	// Make a file f to send to our parent process on uc.
	// We make it in tempDir, which our parent will clean up.
	flag.Parse()
	tempDir := flag.Arg(0)
	f, err := os.CreateTemp(tempDir, "")
	if err != nil {
		fmt.Printf("TempFile: %v", err)
		return
	}
	// N.B. This defer is also necessary to keep f alive
	// while we use its fd, preventing its finalizer from
	// executing.
	defer f.Close()

	f.Write([]byte("Hello from child process!\n"))
	f.Seek(0, io.SeekStart)

	rights := syscall.UnixRights(int(f.Fd()))
	dummyByte := []byte("x")
	n, oobn, err := uc.WriteMsgUnix(dummyByte, rights, nil)
	if err != nil {
		fmt.Printf("WriteMsgUnix: %v", err)
		return
	}
	if n != 1 || oobn != len(rights) {
		fmt.Printf("WriteMsgUnix = %d, %d; want 1, %d", n, oobn, len(rights))
		return
	}
}

// TestUnixRightsRoundtrip tests that UnixRights, ParseSocketControlMessage,
// and ParseUnixRights are able to successfully round-trip lists of file descriptors.
func TestUnixRightsRoundtrip(t *testing.T) {
	testCases := [...][][]int{
		{{42}},
		{{1, 2}},
		{{3, 4, 5}},
		{{}},
		{{1, 2}, {3, 4, 5}, {}, {7}},
	}
	for _, testCase := range testCases {
		b := []byte{}
		var n int
		for _, fds := range testCase {
			// Last assignment to n wins
			n = len(b) + syscall.CmsgLen(4*len(fds))
			b = append(b, syscall.UnixRights(fds...)...)
		}
		// Truncate b
		b = b[:n]

		scms, err := syscall.ParseSocketControlMessage(b)
		if err != nil {
			t.Fatalf("ParseSocketControlMessage: %v", err)
		}
		if len(scms) != len(testCase) {
			t.Fatalf("expected %v SocketControlMessage; got scms = %#v", len(testCase), scms)
		}
		for i, scm := range scms {
			gotFds, err := syscall.ParseUnixRights(&scm)
			if err != nil {
				t.Fatalf("ParseUnixRights: %v", err)
			}
			wantFds := testCase[i]
			if len(gotFds) != len(wantFds) {
				t.Fatalf("expected %v fds, got %#v", len(wantFds), gotFds)
			}
			for j, fd := range gotFds {
				if fd != wantFds[j] {
					t.Fatalf("expected fd %v, got %v", wantFds[j], fd)
				}
			}
		}
	}
}

func TestSeekFailure(t *testing.T) {
	_, err := syscall.Seek(-1, 0, io.SeekStart)
	if err == nil {
		t.Fatalf("Seek(-1, 0, 0) did not fail")
	}
	str := err.Error() // used to crash on Linux
	t.Logf("Seek: %v", str)
	if str == "" {
		t.Fatalf("Seek(-1, 0, 0) return error with empty message")
	}
}

func TestSetsockoptString(t *testing.T) {
	// should not panic on empty string, see issue #31277
	err := syscall.SetsockoptString(-1, 0, 0, "")
	if err == nil {
		t.Fatalf("SetsockoptString: did not fail")
	}
}

func TestENFILETemporary(t *testing.T) {
	if !syscall.ENFILE.Temporary() {
		t.Error("ENFILE is not treated as a temporary error")
	}
}

"""



```