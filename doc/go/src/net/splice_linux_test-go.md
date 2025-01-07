Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The core request is to analyze the functionality of the provided Go code, specifically focusing on its purpose, how it achieves it, potential issues, and provide illustrative examples. The file path `go/src/net/splice_linux_test.go` hints at testing functionality related to `splice` on Linux.

2. **Initial Scan for Keywords and Structure:**  I'll quickly scan the code for prominent keywords and structural elements:
    * `package net`:  Confirms this is part of the standard `net` package.
    * `//go:build linux`:  Indicates this code is only compiled on Linux.
    * `import`: Lists the dependencies, which include `internal/poll` (a key hint for system-level interaction), `io`, `os`, `strconv`, `sync`, `syscall`, and `testing`. `syscall` reinforces the system-level interaction idea.
    * `func TestSplice(t *testing.T)`:  This is the main testing function, suggesting the code's purpose is to test the `splice` functionality.
    * Several `t.Run(...)`:  Indicates sub-tests, focusing on different scenarios (tcp-to-tcp, unix-to-tcp, tcp-to-file, etc.).
    * `testSpliceToFile` and `testSplice`: These seem to be the primary test execution functions.
    * `spliceTestCase`: A struct likely used to parameterize the tests.
    * `hookSplice` and `spliceHook`:  These look like mechanisms for intercepting or observing the `splice` calls.
    * `BenchmarkSplice` and `BenchmarkSpliceFile`:  Functions for benchmarking the performance.
    * Calls to `spawnTestSocketPair` and `startTestSocketPeer`: These are likely helper functions to set up network connections for testing.
    * `io.Copy`:  A standard Go function for copying data, suggesting data transfer is the core operation being tested.

3. **Focus on the Core Functionality (Splice):** The repeated mention of "splice" and the file name itself strongly suggest this code tests the `splice` system call. The `internal/poll` package is the Go standard library's interface to low-level system calls related to I/O.

4. **Hypothesize the Purpose of `splice`:** Based on the name and context, I'd hypothesize that `splice` is a mechanism for efficiently transferring data between file descriptors, potentially without copying data through user space. The different test cases (tcp-to-tcp, unix-to-tcp, etc.) likely test this in various networking scenarios and with files.

5. **Analyze the Test Cases:** I'll examine the `testSplice` and `testSpliceToFile` functions and the `spliceTestCase` struct:
    * `spliceTestCase`:  Contains `upNet`, `downNet` (network types), `chunkSize`, `totalSize`, and `limitReadSize`. This suggests testing different network combinations, transfer sizes, and the interaction with `io.LimitedReader`.
    * The various `t.Run` calls within `testSplice` and `testSpliceToFile` represent different test scenarios (simple, multiple writes, big transfers, handling `LimitedReader`, etc.).

6. **Understand the Role of `hookSplice` and `spliceHook`:** The names and the code within these functions strongly suggest a mechanism for intercepting calls to the internal `pollSplice` function. This is a common technique in testing to verify that certain system calls are being made with the expected parameters. The `spliceHook` struct stores information about the intercepted call (file descriptors, data size, errors).

7. **Code Example Construction:**  To illustrate the `splice` functionality, I need a practical example. Since the code tests networking scenarios, a simple TCP connection example using `io.Copy` (which internally might use `splice`) would be appropriate. I'll demonstrate data transfer between two TCP connections.

8. **Command Line Argument Analysis:** The provided code doesn't seem to directly handle command-line arguments within the test functions themselves. The testing framework (`go test`) handles test execution. However, I should note that the `go test` command itself can take various flags (like `-v` for verbose output).

9. **Identifying Potential Pitfalls:** I need to think about common mistakes users might make when working with the `splice` functionality (even though it's mostly internal).
    * **Incorrect file descriptor types:**  `splice` has specific requirements for the types of file descriptors it can operate on.
    * **Kernel support:** `splice` is a Linux-specific system call, so portability is a concern.
    * **Error handling:**  Properly checking for errors during the `splice` operation is crucial.

10. **Review and Refine:** I'll reread the code and my analysis to ensure accuracy and completeness. I'll check if I've addressed all the points in the original prompt. I'll make sure the Go code example is clear and runnable and that the explanations are concise and easy to understand. I'll pay attention to phrasing and ensure the language is natural Chinese.

By following these steps, I can systematically analyze the Go code snippet and provide a comprehensive and accurate explanation of its functionality. The focus on identifying the core purpose (testing `splice`), analyzing the test structure, and understanding the role of the hooking mechanism is key to understanding this type of code.
这段 Go 语言代码是 `net` 包的一部分，专门用于在 Linux 系统上测试 `splice` 系统调用的相关功能。`splice` 是一种零拷贝机制，可以在两个文件描述符之间高效地移动数据，无需将数据在内核空间和用户空间之间来回复制。

以下是代码的主要功能点：

1. **测试 `splice` 在不同网络协议之间的工作情况:**
   - `tcp-to-tcp`: 测试 TCP 连接到 TCP 连接的数据传输。
   - `unix-to-tcp`: 测试 Unix 域 socket 连接到 TCP 连接的数据传输。
   - `tcp-to-unix`: 测试 TCP 连接到 Unix 域 socket 连接的数据传输。

2. **测试 `splice` 在网络连接到文件之间的工作情况:**
   - `tcp-to-file`: 测试 TCP 连接到普通文件（实际上是 `/dev/null`）的数据传输。
   - `unix-to-file`: 测试 Unix 域 socket 连接到普通文件的数据传输。

3. **测试 `splice` 在特定场景下的行为:**
   - `no-unixpacket`: 测试当源是 `unixpacket` 类型的 socket 时，`splice` 的行为（预期不会调用底层的 `poll.Splice`）。
   - `no-unixgram`: 测试当源是 `unixgram` 类型的 socket 时，`splice` 的行为（预期不会调用底层的 `poll.Splice`）。
   - 测试 `io.LimitedReader` 与 `splice` 的协同工作，包括是否正确地限制读取的字节数以及更新 `LimitedReader` 的 `N` 字段。
   - 测试当读取端已经到达 EOF (End-of-File) 时，`splice` 的处理情况。
   - 测试并发场景下使用 `splice` 的情况 (`issue25985`)。

4. **性能基准测试:**
   - `BenchmarkSplice`:  对不同网络协议组合（tcp-to-tcp, unix-to-tcp, tcp-to-unix）下的 `splice` 性能进行基准测试，并针对不同的数据块大小进行测试。
   - `BenchmarkSpliceFile`: 对网络连接到文件 (`/dev/null`) 的 `splice` 性能进行基准测试。

**代码实现的功能推理 (关于 `splice` 的使用):**

`splice` 系统调用通常用于在两个文件描述符之间直接移动数据，避免了用户空间缓冲区的中转，从而提高了效率。Go 语言的 `net` 包在某些情况下会利用 `splice` 来优化网络数据传输，特别是在使用 `io.Copy` 进行数据传输时。

**Go 代码举例说明 `splice` 的潜在使用 (假设):**

虽然这段测试代码本身没有直接展示如何调用 `splice`，但我们可以推断 `net` 包可能在 `io.Copy` 的内部实现中使用了 `splice`。以下是一个模拟的例子，展示了如何在 Go 中使用底层的 `syscall.Splice` (实际上 `net` 包会使用 `internal/poll` 包中的封装):

```go
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	// 创建一对 TCP 连接
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer ln.Close()
	addr := ln.Addr().String()

	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Println("Error dialing:", err)
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("Hello from client"))
		if err != nil {
			fmt.Println("Error writing:", err)
		}
	}()

	serverConn, err := ln.Accept()
	if err != nil {
		fmt.Println("Error accepting:", err)
		return
	}
	defer serverConn.Close()

	// 创建一个用于接收数据的文件
	tmpFile, err := os.CreateTemp("", "splice_test")
	if err != nil {
		fmt.Println("Error creating temp file:", err)
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// 获取文件描述符
	serverConnFd, err := getFd(serverConn)
	if err != nil {
		fmt.Println("Error getting server conn FD:", err)
		return
	}
	fileFd := int(tmpFile.Fd())

	// 使用 splice 将 socket 的数据传输到文件
	// 注意：这只是一个概念性的例子，实际 net 包会做更复杂的处理
	n, err := syscall.Splice(int(serverConnFd), nil, fileFd, nil, 1024, 0)
	if err != nil {
		fmt.Println("Error splicing:", err)
		return
	}
	fmt.Println("Splice transferred", n, "bytes")

	// 读取文件内容
	content := make([]byte, n)
	_, err = tmpFile.ReadAt(content, 0)
	if err != nil {
		fmt.Println("Error reading from file:", err)
		return
	}
	fmt.Println("File content:", string(content))
}

// 一个辅助函数，用于获取 net.Conn 的文件描述符
func getFd(conn net.Conn) (uintptr, error) {
	type hasFd interface {
		Fd() uintptr
	}
	if fdConn, ok := conn.(hasFd); ok {
		return fdConn.Fd(), nil
	}
	// 对于不是直接基于文件描述符的连接，可能需要更复杂的方法
	// 例如对于 tls.Conn，需要访问其内部的连接
	return 0, fmt.Errorf("cannot get file descriptor from connection")
}
```

**假设的输入与输出:**

在上面的例子中，假设 TCP 客户端成功连接并发送了 "Hello from client" 字符串。

**输出:**

```
Splice transferred 17 bytes
File content: Hello from client
```

**命令行参数:**

这段代码是测试代码，通常通过 `go test` 命令运行。`go test` 本身有很多命令行参数，例如：

- `-v`:  显示详细的测试输出。
- `-run <regexp>`:  运行匹配正则表达式的测试用例。例如，`go test -run TestSplice/tcp-to-tcp` 只运行 `TestSplice` 函数中名为 "tcp-to-tcp" 的子测试。
- `-bench <regexp>`: 运行匹配正则表达式的基准测试。例如，`go test -bench BenchmarkSplice`。
- `-count n`:  运行每个测试或基准测试 `n` 次。

**使用者易犯错的点 (虽然这段代码是测试代码，但可以推测使用 `splice` 相关的易错点):**

1. **不正确的 FD 类型:** `splice` 系统调用对源和目标的 FD 类型有要求。例如，通常要求至少有一个是 pipe 或者 socket。如果传递了不合适的 FD，`splice` 会返回错误。

   **例子 (假设尝试 splice 两个普通文件):**

   ```go
   // ... (创建两个普通文件 file1 和 file2) ...

   fd1, _ := syscall.Open(file1.Name(), syscall.O_RDONLY, 0)
   defer syscall.Close(fd1)
   fd2, _ := syscall.Open(file2.Name(), syscall.O_WRONLY, 0)
   defer syscall.Close(fd2)

   _, err := syscall.Splice(fd1, nil, fd2, nil, 1024, 0)
   if err != nil {
       fmt.Println("Splice error:", err) // 可能会得到 "Invalid argument" 错误
   }
   ```

2. **内核版本不支持:** `splice` 是 Linux 特有的系统调用，并且在一些较老的内核版本上可能行为不一致或者存在 bug。

3. **偏移量管理不当:** `splice` 允许指定输入和输出 FD 的偏移量。如果使用不当，可能会导致数据传输的位置错误或丢失数据。

4. **错误处理不充分:**  `splice` 调用可能会因为各种原因失败，例如中断、资源不足等。使用者需要检查返回值并妥善处理错误。

5. **与非阻塞 I/O 混淆:**  `splice` 本身是阻塞的。如果需要非阻塞的行为，可能需要配合 `select` 或 `poll` 等机制。

这段测试代码通过模拟各种网络场景和文件操作，来验证 `net` 包在底层使用 `splice` 时的正确性和性能。通过 `spliceHook` 结构体，它可以拦截并检查底层的 `poll.Splice` 调用，确保在预期的场景下调用了 `splice`，并且参数正确。

Prompt: 
```
这是路径为go/src/net/splice_linux_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux

package net

import (
	"internal/poll"
	"io"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"
)

func TestSplice(t *testing.T) {
	t.Run("tcp-to-tcp", func(t *testing.T) { testSplice(t, "tcp", "tcp") })
	if !testableNetwork("unixgram") {
		t.Skip("skipping unix-to-tcp tests")
	}
	t.Run("unix-to-tcp", func(t *testing.T) { testSplice(t, "unix", "tcp") })
	t.Run("tcp-to-unix", func(t *testing.T) { testSplice(t, "tcp", "unix") })
	t.Run("tcp-to-file", func(t *testing.T) { testSpliceToFile(t, "tcp", "file") })
	t.Run("unix-to-file", func(t *testing.T) { testSpliceToFile(t, "unix", "file") })
	t.Run("no-unixpacket", testSpliceNoUnixpacket)
	t.Run("no-unixgram", testSpliceNoUnixgram)
}

func testSpliceToFile(t *testing.T, upNet, downNet string) {
	t.Run("simple", spliceTestCase{upNet, downNet, 128, 128, 0}.testFile)
	t.Run("multipleWrite", spliceTestCase{upNet, downNet, 4096, 1 << 20, 0}.testFile)
	t.Run("big", spliceTestCase{upNet, downNet, 5 << 20, 1 << 30, 0}.testFile)
	t.Run("honorsLimitedReader", spliceTestCase{upNet, downNet, 4096, 1 << 20, 1 << 10}.testFile)
	t.Run("updatesLimitedReaderN", spliceTestCase{upNet, downNet, 1024, 4096, 4096 + 100}.testFile)
	t.Run("limitedReaderAtLimit", spliceTestCase{upNet, downNet, 32, 128, 128}.testFile)
}

func testSplice(t *testing.T, upNet, downNet string) {
	t.Run("simple", spliceTestCase{upNet, downNet, 128, 128, 0}.test)
	t.Run("multipleWrite", spliceTestCase{upNet, downNet, 4096, 1 << 20, 0}.test)
	t.Run("big", spliceTestCase{upNet, downNet, 5 << 20, 1 << 30, 0}.test)
	t.Run("honorsLimitedReader", spliceTestCase{upNet, downNet, 4096, 1 << 20, 1 << 10}.test)
	t.Run("updatesLimitedReaderN", spliceTestCase{upNet, downNet, 1024, 4096, 4096 + 100}.test)
	t.Run("limitedReaderAtLimit", spliceTestCase{upNet, downNet, 32, 128, 128}.test)
	t.Run("readerAtEOF", func(t *testing.T) { testSpliceReaderAtEOF(t, upNet, downNet) })
	t.Run("issue25985", func(t *testing.T) { testSpliceIssue25985(t, upNet, downNet) })
}

type spliceTestCase struct {
	upNet, downNet string

	chunkSize, totalSize int
	limitReadSize        int
}

func (tc spliceTestCase) test(t *testing.T) {
	hook := hookSplice(t)

	// We need to use the actual size for startTestSocketPeer when testing with LimitedReader,
	// otherwise the child process created in startTestSocketPeer will hang infinitely because of
	// the mismatch of data size to transfer.
	size := tc.totalSize
	if tc.limitReadSize > 0 {
		if tc.limitReadSize < size {
			size = tc.limitReadSize
		}
	}

	clientUp, serverUp := spawnTestSocketPair(t, tc.upNet)
	defer serverUp.Close()
	cleanup, err := startTestSocketPeer(t, clientUp, "w", tc.chunkSize, size)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup(t)
	clientDown, serverDown := spawnTestSocketPair(t, tc.downNet)
	defer serverDown.Close()
	cleanup, err = startTestSocketPeer(t, clientDown, "r", tc.chunkSize, size)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup(t)

	var r io.Reader = serverUp
	if tc.limitReadSize > 0 {
		r = &io.LimitedReader{
			N: int64(tc.limitReadSize),
			R: serverUp,
		}
		defer serverUp.Close()
	}
	n, err := io.Copy(serverDown, r)
	if err != nil {
		t.Fatal(err)
	}

	if want := int64(size); want != n {
		t.Errorf("want %d bytes spliced, got %d", want, n)
	}

	if tc.limitReadSize > 0 {
		wantN := 0
		if tc.limitReadSize > size {
			wantN = tc.limitReadSize - size
		}

		if n := r.(*io.LimitedReader).N; n != int64(wantN) {
			t.Errorf("r.N = %d, want %d", n, wantN)
		}
	}

	// poll.Splice is expected to be called when the source is not
	// a wrapper or the destination is TCPConn.
	if tc.limitReadSize == 0 || tc.downNet == "tcp" {
		// We should have called poll.Splice with the right file descriptor arguments.
		if n > 0 && !hook.called {
			t.Fatal("expected poll.Splice to be called")
		}

		verifySpliceFds(t, serverDown, hook, "dst")
		verifySpliceFds(t, serverUp, hook, "src")

		// poll.Splice is expected to handle the data transmission successfully.
		if !hook.handled || hook.written != int64(size) || hook.err != nil {
			t.Errorf("expected handled = true, written = %d, err = nil, but got handled = %t, written = %d, err = %v",
				size, hook.handled, hook.written, hook.err)
		}
	} else if hook.called {
		// poll.Splice will certainly not be called when the source
		// is a wrapper and the destination is not TCPConn.
		t.Errorf("expected poll.Splice not be called")
	}
}

func verifySpliceFds(t *testing.T, c Conn, hook *spliceHook, fdType string) {
	t.Helper()

	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("expected syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("syscall.Conn.SyscallConn error: %v", err)
	}
	var hookFd int
	switch fdType {
	case "src":
		hookFd = hook.srcfd
	case "dst":
		hookFd = hook.dstfd
	default:
		t.Fatalf("unknown fdType %q", fdType)
	}
	if err := rc.Control(func(fd uintptr) {
		if hook.called && hookFd != int(fd) {
			t.Fatalf("wrong %s file descriptor: got %d, want %d", fdType, hook.dstfd, int(fd))
		}
	}); err != nil {
		t.Fatalf("syscall.RawConn.Control error: %v", err)
	}
}

func (tc spliceTestCase) testFile(t *testing.T) {
	hook := hookSplice(t)

	// We need to use the actual size for startTestSocketPeer when testing with LimitedReader,
	// otherwise the child process created in startTestSocketPeer will hang infinitely because of
	// the mismatch of data size to transfer.
	actualSize := tc.totalSize
	if tc.limitReadSize > 0 {
		if tc.limitReadSize < actualSize {
			actualSize = tc.limitReadSize
		}
	}

	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	client, server := spawnTestSocketPair(t, tc.upNet)
	defer server.Close()

	cleanup, err := startTestSocketPeer(t, client, "w", tc.chunkSize, actualSize)
	if err != nil {
		client.Close()
		t.Fatal("failed to start splice client:", err)
	}
	defer cleanup(t)

	var r io.Reader = server
	if tc.limitReadSize > 0 {
		r = &io.LimitedReader{
			N: int64(tc.limitReadSize),
			R: r,
		}
	}

	got, err := io.Copy(f, r)
	if err != nil {
		t.Fatalf("failed to ReadFrom with error: %v", err)
	}

	// We shouldn't have called poll.Splice in TCPConn.WriteTo,
	// it's supposed to be called from File.ReadFrom.
	if got > 0 && hook.called {
		t.Error("expected not poll.Splice to be called")
	}

	if want := int64(actualSize); got != want {
		t.Errorf("got %d bytes, want %d", got, want)
	}
	if tc.limitReadSize > 0 {
		wantN := 0
		if tc.limitReadSize > actualSize {
			wantN = tc.limitReadSize - actualSize
		}

		if gotN := r.(*io.LimitedReader).N; gotN != int64(wantN) {
			t.Errorf("r.N = %d, want %d", gotN, wantN)
		}
	}
}

func testSpliceReaderAtEOF(t *testing.T, upNet, downNet string) {
	// UnixConn doesn't implement io.ReaderFrom, which will fail
	// the following test in asserting a UnixConn to be an io.ReaderFrom,
	// so skip this test.
	if downNet == "unix" {
		t.Skip("skipping test on unix socket")
	}

	hook := hookSplice(t)

	clientUp, serverUp := spawnTestSocketPair(t, upNet)
	defer clientUp.Close()
	clientDown, serverDown := spawnTestSocketPair(t, downNet)
	defer clientDown.Close()
	defer serverDown.Close()

	serverUp.Close()

	// We'd like to call net.spliceFrom here and check the handled return
	// value, but we disable splice on old Linux kernels.
	//
	// In that case, poll.Splice and net.spliceFrom return a non-nil error
	// and handled == false. We'd ideally like to see handled == true
	// because the source reader is at EOF, but if we're running on an old
	// kernel, and splice is disabled, we won't see EOF from net.spliceFrom,
	// because we won't touch the reader at all.
	//
	// Trying to untangle the errors from net.spliceFrom and match them
	// against the errors created by the poll package would be brittle,
	// so this is a higher level test.
	//
	// The following ReadFrom should return immediately, regardless of
	// whether splice is disabled or not. The other side should then
	// get a goodbye signal. Test for the goodbye signal.
	msg := "bye"
	go func() {
		serverDown.(io.ReaderFrom).ReadFrom(serverUp)
		io.WriteString(serverDown, msg)
	}()

	buf := make([]byte, 3)
	n, err := io.ReadFull(clientDown, buf)
	if err != nil {
		t.Errorf("clientDown: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("clientDown got %q, want %q", buf, msg)
	}

	// We should have called poll.Splice with the right file descriptor arguments.
	if n > 0 && !hook.called {
		t.Fatal("expected poll.Splice to be called")
	}

	verifySpliceFds(t, serverDown, hook, "dst")

	// poll.Splice is expected to handle the data transmission but fail
	// when working with a closed endpoint, return an error.
	if !hook.handled || hook.written > 0 || hook.err == nil {
		t.Errorf("expected handled = true, written = 0, err != nil, but got handled = %t, written = %d, err = %v",
			hook.handled, hook.written, hook.err)
	}
}

func testSpliceIssue25985(t *testing.T, upNet, downNet string) {
	front := newLocalListener(t, upNet)
	defer front.Close()
	back := newLocalListener(t, downNet)
	defer back.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	proxy := func() {
		src, err := front.Accept()
		if err != nil {
			return
		}
		dst, err := Dial(downNet, back.Addr().String())
		if err != nil {
			return
		}
		defer dst.Close()
		defer src.Close()
		go func() {
			io.Copy(src, dst)
			wg.Done()
		}()
		go func() {
			io.Copy(dst, src)
			wg.Done()
		}()
	}

	go proxy()

	toFront, err := Dial(upNet, front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	io.WriteString(toFront, "foo")
	toFront.Close()

	fromProxy, err := back.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer fromProxy.Close()

	_, err = io.ReadAll(fromProxy)
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait()
}

func testSpliceNoUnixpacket(t *testing.T) {
	clientUp, serverUp := spawnTestSocketPair(t, "unixpacket")
	defer clientUp.Close()
	defer serverUp.Close()
	clientDown, serverDown := spawnTestSocketPair(t, "tcp")
	defer clientDown.Close()
	defer serverDown.Close()
	// If splice called poll.Splice here, we'd get err == syscall.EINVAL
	// and handled == false.  If poll.Splice gets an EINVAL on the first
	// try, it assumes the kernel it's running on doesn't support splice
	// for unix sockets and returns handled == false. This works for our
	// purposes by somewhat of an accident, but is not entirely correct.
	//
	// What we want is err == nil and handled == false, i.e. we never
	// called poll.Splice, because we know the unix socket's network.
	_, err, handled := spliceFrom(serverDown.(*TCPConn).fd, serverUp)
	if err != nil || handled != false {
		t.Fatalf("got err = %v, handled = %t, want nil error, handled == false", err, handled)
	}
}

func testSpliceNoUnixgram(t *testing.T) {
	addr, err := ResolveUnixAddr("unixgram", testUnixAddr(t))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(addr.Name)
	up, err := ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	clientDown, serverDown := spawnTestSocketPair(t, "tcp")
	defer clientDown.Close()
	defer serverDown.Close()
	// Analogous to testSpliceNoUnixpacket.
	_, err, handled := spliceFrom(serverDown.(*TCPConn).fd, up)
	if err != nil || handled != false {
		t.Fatalf("got err = %v, handled = %t, want nil error, handled == false", err, handled)
	}
}

func BenchmarkSplice(b *testing.B) {
	testHookUninstaller.Do(uninstallTestHooks)

	b.Run("tcp-to-tcp", func(b *testing.B) { benchSplice(b, "tcp", "tcp") })
	b.Run("unix-to-tcp", func(b *testing.B) { benchSplice(b, "unix", "tcp") })
	b.Run("tcp-to-unix", func(b *testing.B) { benchSplice(b, "tcp", "unix") })
}

func benchSplice(b *testing.B, upNet, downNet string) {
	for i := 0; i <= 10; i++ {
		chunkSize := 1 << uint(i+10)
		tc := spliceTestCase{
			upNet:     upNet,
			downNet:   downNet,
			chunkSize: chunkSize,
		}

		b.Run(strconv.Itoa(chunkSize), tc.bench)
	}
}

func (tc spliceTestCase) bench(b *testing.B) {
	// To benchmark the genericReadFrom code path, set this to false.
	useSplice := true

	clientUp, serverUp := spawnTestSocketPair(b, tc.upNet)
	defer serverUp.Close()

	cleanup, err := startTestSocketPeer(b, clientUp, "w", tc.chunkSize, tc.chunkSize*b.N)
	if err != nil {
		b.Fatal(err)
	}
	defer cleanup(b)

	clientDown, serverDown := spawnTestSocketPair(b, tc.downNet)
	defer serverDown.Close()

	cleanup, err = startTestSocketPeer(b, clientDown, "r", tc.chunkSize, tc.chunkSize*b.N)
	if err != nil {
		b.Fatal(err)
	}
	defer cleanup(b)

	b.SetBytes(int64(tc.chunkSize))
	b.ResetTimer()

	if useSplice {
		_, err := io.Copy(serverDown, serverUp)
		if err != nil {
			b.Fatal(err)
		}
	} else {
		type onlyReader struct {
			io.Reader
		}
		_, err := io.Copy(serverDown, onlyReader{serverUp})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSpliceFile(b *testing.B) {
	b.Run("tcp-to-file", func(b *testing.B) { benchmarkSpliceFile(b, "tcp") })
	b.Run("unix-to-file", func(b *testing.B) { benchmarkSpliceFile(b, "unix") })
}

func benchmarkSpliceFile(b *testing.B, proto string) {
	for i := 0; i <= 10; i++ {
		size := 1 << (i + 10)
		bench := spliceFileBench{
			proto:     proto,
			chunkSize: size,
		}
		b.Run(strconv.Itoa(size), bench.benchSpliceFile)
	}
}

type spliceFileBench struct {
	proto     string
	chunkSize int
}

func (bench spliceFileBench) benchSpliceFile(b *testing.B) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	totalSize := b.N * bench.chunkSize

	client, server := spawnTestSocketPair(b, bench.proto)
	defer server.Close()

	cleanup, err := startTestSocketPeer(b, client, "w", bench.chunkSize, totalSize)
	if err != nil {
		client.Close()
		b.Fatalf("failed to start splice client: %v", err)
	}
	defer cleanup(b)

	b.ReportAllocs()
	b.SetBytes(int64(bench.chunkSize))
	b.ResetTimer()

	got, err := io.Copy(f, server)
	if err != nil {
		b.Fatalf("failed to ReadFrom with error: %v", err)
	}
	if want := int64(totalSize); got != want {
		b.Errorf("bytes sent mismatch, got: %d, want: %d", got, want)
	}
}

func hookSplice(t *testing.T) *spliceHook {
	t.Helper()

	h := new(spliceHook)
	h.install()
	t.Cleanup(h.uninstall)
	return h
}

type spliceHook struct {
	called bool
	dstfd  int
	srcfd  int
	remain int64

	written int64
	handled bool
	err     error

	original func(dst, src *poll.FD, remain int64) (int64, bool, error)
}

func (h *spliceHook) install() {
	h.original = pollSplice
	pollSplice = func(dst, src *poll.FD, remain int64) (int64, bool, error) {
		h.called = true
		h.dstfd = dst.Sysfd
		h.srcfd = src.Sysfd
		h.remain = remain
		h.written, h.handled, h.err = h.original(dst, src, remain)
		return h.written, h.handled, h.err
	}
}

func (h *spliceHook) uninstall() {
	pollSplice = h.original
}

"""



```