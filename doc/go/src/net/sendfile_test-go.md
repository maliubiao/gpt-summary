Response:
Let's break down the thought process for analyzing this Go code.

1. **Understand the Goal:** The request asks for an analysis of the Go code snippet from `go/src/net/sendfile_test.go`. Specifically, it wants to know the functionality, the underlying Go feature being tested, code examples, command-line argument handling (if any), and common mistakes.

2. **Initial Scan and Keyword Spotting:**  Read through the code, looking for key terms and patterns. Immediately, `sendfile`, `TestSendfile`, `expectSendfile`, `io.Copy`, `io.CopyN`, `os.Open`, `net.Dial`, `net.Listen`, `benchmark`, and file paths like `../testdata/Isaac.Newton-Opticks.txt` jump out. These strongly suggest the code is testing the `sendfile` system call within the Go `net` package.

3. **Identify Core Test Functions:** Notice the `TestSendfile` family of functions: `TestSendfile`, `TestSendfileWithExactLimit`, etc. These are clearly the main test cases. The function names themselves give clues about what's being tested (e.g., handling limits, large files).

4. **Analyze `expectSendfile`:** This function is crucial. It uses `poll.TestHookDidSendFile`. This pattern strongly indicates that this is a testing utility to check if the internal `poll.SendFile` function was called during the execution of another function (`f`). The logic verifies if `poll.SendFile` was called, if it handled the write, and if it was called with the expected file descriptor.

5. **Trace Data Flow in Test Cases:**  Pick a simple test case like `TestSendfile`. Follow the data flow:
    * A listener is created (`newLocalListener`).
    * A goroutine accepts a connection.
    * Inside the goroutine, a file is opened (`os.Open`).
    * `io.Copy` (or `io.CopyN` with a limit) is used to send the file contents over the connection.
    * On the client side, a connection is established (`Dial`).
    * The received data is read and its SHA256 hash is verified against a known value.
    * Error channels are used for communication between goroutines.

6. **Identify the Tested Feature:**  Based on the presence of `expectSendfile` and the use of `io.Copy` with files and network connections, the core functionality being tested is the Go runtime's optimization of using the `sendfile` system call (when available) to efficiently transfer data from a file to a network socket.

7. **Infer the Purpose of Different Test Cases:**
    * `TestSendfile`: Basic test to send an entire file.
    * `TestSendfileWithExactLimit`, `TestSendfileWithLimitLargerThanFile`: Tests different scenarios with the `io.CopyN` limit parameter.
    * `TestSendfileWithLargeFile`: Specifically tests handling large files, potentially hitting edge cases with `sendfile`.
    * `TestSendfileParts`: Sends the file in chunks using multiple `io.CopyN` calls.
    * `TestSendfileSeeked`: Tests sending data from a specific offset in the file.
    * `TestSendfilePipe`:  Verifies that `sendfile` doesn't incorrectly put a pipe into blocking mode.
    * `TestSendfileOnWriteTimeoutExceeded`: Checks how `sendfile` behaves when the connection has a write timeout.

8. **Look for Benchmarks:** The `BenchmarkSendFile` and `BenchmarkSendfileZeroBytes` functions indicate performance testing of the `sendfile` optimization.

9. **Command-Line Arguments:**  Scan the code for `flag` package usage. There are none, so this code doesn't directly process command-line arguments. However, `testing.Short()` is used, indicating the standard Go testing flags like `-short` are relevant.

10. **Potential Mistakes:**  Think about how a user might misuse the `io.Copy` or `io.CopyN` functions when dealing with network connections and files. For example, forgetting to handle errors, not setting appropriate deadlines, or making assumptions about the number of bytes transferred. The test for write timeouts also highlights a potential issue.

11. **Construct Examples:** Based on the understanding of the code, create illustrative examples showing how `io.Copy` can utilize `sendfile`. Include comments to explain the key aspects.

12. **Structure the Answer:** Organize the findings into the requested sections: Functionality, Go Feature Implementation, Code Examples, Command-Line Arguments, and Common Mistakes. Use clear and concise language.

13. **Review and Refine:** Read through the generated answer to ensure accuracy, completeness, and clarity. Double-check the code examples and explanations. Ensure the language is in Chinese as requested. For instance, initially, I might have just said "tests sendfile". But refining that to "测试 Go 语言 `net` 包中利用 `sendfile` 系统调用优化网络文件传输的功能" is more precise. Similarly, explaining the role of `expectSendfile` in detail is important.
这段Go语言代码是 `net` 包中 `sendfile_test.go` 文件的一部分，其主要功能是**测试 Go 语言 `net` 包中利用 `sendfile` 系统调用优化网络文件传输的功能**。

`sendfile` 是一种操作系统提供的系统调用，它允许将文件描述符指向的数据直接传输到另一个文件描述符（通常是 socket），而无需将数据复制到用户空间缓冲区。这可以显著提高文件传输的效率，尤其是在传输大文件时。

**功能列表:**

1. **测试 `io.Copy` 是否在合适的条件下使用了 `sendfile` 系统调用:**  代码中的核心目标是验证当使用 `io.Copy` 或 `io.CopyN` 将文件内容写入网络连接时，如果操作系统支持，Go 的网络库是否会智能地利用 `sendfile` 来优化传输。

2. **测试 `sendfile` 处理不同大小文件的情况:** 包含了对小文件、与指定限制大小相同的文件、大于限制大小的文件以及大文件的测试。

3. **测试 `sendfile` 处理文件部分内容的情况:** `TestSendfileParts` 测试了多次调用 `io.CopyN` 分批发送文件内容时 `sendfile` 的行为。

4. **测试 `sendfile` 处理文件指针偏移的情况:** `TestSendfileSeeked` 测试了在发送文件之前使用 `Seek` 方法移动文件指针后，`sendfile` 是否能正确处理。

5. **测试 `sendfile` 与管道 (pipe) 的交互:** `TestSendfilePipe` 确保在使用 `sendfile` 通过管道传输数据时，不会错误地将管道设置为阻塞模式。

6. **测试在连接写入超时的情况下 `sendfile` 的行为:** `TestSendfileOnWriteTimeoutExceeded` 验证了当网络连接写入超时时，使用 `sendfile` 是否能正确返回 `os.ErrDeadlineExceeded` 错误。

7. **性能基准测试:** `BenchmarkSendfileZeroBytes` 和 `BenchmarkSendFile` 用于评估使用 `sendfile` 的性能。

**Go 语言功能实现 (使用 `sendfile` 的场景) 以及代码举例:**

Go 的 `net` 包在内部对 `io.Copy` 和 `io.CopyN` 进行了优化，当满足特定条件时，会自动尝试使用 `sendfile` 系统调用。这些条件通常包括：

* **操作系统支持 `sendfile`:**  不同的操作系统对 `sendfile` 的支持程度不同。
* **源是 `os.File` (或其他实现了 `io.ReaderAt` 的类型):** `sendfile` 通常需要一个文件描述符作为源。
* **目标是 `net.TCPConn` (或其他网络连接类型):** `sendfile` 通常用于将数据发送到网络套接字。

**代码示例:**

```go
package main

import (
	"io"
	"net"
	"os"
)

func main() {
	// 创建一个监听器
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	// 打开一个用于发送的文件
	file, err := os.Open("large_file.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for {
		// 接受连接
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		// 使用 io.Copy 将文件内容发送到连接
		// 在满足操作系统和 Go 网络库的条件时，这里会自动尝试使用 sendfile
		_, err = io.Copy(conn, file)
		if err != nil {
			println("Error sending file:", err.Error())
		}
	}
}
```

**假设的输入与输出:**

* **输入:**  一个名为 `large_file.txt` 的大文件（例如，几百兆或几G）。客户端连接到服务器。
* **输出:**  客户端接收到 `large_file.txt` 的完整内容。  如果启用了详细的系统调用跟踪工具（例如 `strace` on Linux），可以看到 `sendfile` 系统调用被调用，并且传输的数据量与文件大小一致。

**代码推理 (关于 `expectSendfile` 函数):**

`expectSendfile` 函数是测试代码的关键辅助函数。它的作用是：

1. **检查当前平台是否支持 `sendfile`:** 通过 `supportsSendfile` 变量判断。如果不支持，则直接执行待测试的函数 `f`，不进行 `sendfile` 的检查。

2. **设置钩子函数 `poll.TestHookDidSendFile`:**  这个钩子函数会在内部的 `poll.SendFile` 函数被调用后执行。它可以捕获 `poll.SendFile` 的调用信息，例如目标文件描述符 (`dstFD`)、源文件描述符、写入的字节数、错误以及是否被 `sendfile` 处理了。

3. **执行待测试的函数 `f`:**  这个函数通常会包含调用 `io.Copy` 或 `io.CopyN` 的代码。

4. **验证 `poll.SendFile` 是否被调用以及是否处理了写入:**  `expectSendfile` 会检查 `poll.TestHookDidSendFile` 是否被调用，以及 `handled` 参数是否为 `true`，表示 `sendfile` 成功处理了这次写入。

5. **验证 `poll.SendFile` 的目标文件描述符是否正确:**  它会比较 `poll.SendFile` 接收到的目标文件描述符与预期连接的文件描述符。

**命令行参数的具体处理:**

这段代码本身是测试代码，并不直接处理命令行参数。但是，Go 的测试工具 `go test` 可以接收一些标准的命令行参数，例如：

* `-v`:  显示更详细的测试输出。
* `-run <正则表达式>`:  运行名称匹配指定正则表达式的测试函数。
* `-short`:  运行时间较短的测试，可能会跳过一些耗时的测试（例如 `TestSendfileWithLargeFile` 在 `-short` 模式下会被跳过）。
* `-count N`:  运行每个测试 N 次。

例如，要运行所有包含 "Sendfile" 字符串的测试，可以使用命令：

```bash
go test -v -run Sendfile
```

**使用者易犯错的点:**

由于这段代码是测试代码，它的“使用者”主要是 Go 语言的开发者或者网络库的维护者。以下是一些可能在编写类似测试或使用 `io.Copy` 进行网络文件传输时容易犯的错误：

1. **假设所有平台都支持 `sendfile`:**  开发者可能会错误地假设所有的操作系统都支持 `sendfile`，并依赖于这种优化。实际上，需要进行平台判断或者使用 Go 标准库提供的抽象，让 Go 自动选择合适的传输方式。

2. **没有正确处理错误:** 在使用 `io.Copy` 或 `io.CopyN` 时，如果没有检查和处理返回的错误，可能会导致数据传输不完整或者程序崩溃。

3. **不理解 `io.CopyN` 的行为:**  `io.CopyN` 会尝试读取 `n` 个字节，如果读取到的字节数小于 `n` 但没有发生错误（例如，到达文件末尾），它仍然会返回已读取的字节数和 `io.EOF` 错误。

4. **在高并发场景下未考虑连接的生命周期:**  在多客户端并发请求文件的场景下，需要正确管理网络连接的创建和关闭，避免资源泄漏。

**示例说明易犯错的点:**

```go
package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	// ... (listener setup as before) ...

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue // 忽略当前连接错误，继续监听
		}
		go handleConnection(conn) // 为每个连接启动一个 goroutine
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	file, err := os.Open("large_file.txt")
	if err != nil {
		fmt.Println("Open file error:", err)
		return
	}
	defer file.Close()

	// 错误示例：没有检查 io.Copy 的错误
	// _, err = io.Copy(conn, file) // 如果发生错误，这里会被忽略

	// 正确示例：检查并处理 io.Copy 的错误
	bytesSent, err := io.Copy(conn, file)
	if err != nil {
		fmt.Printf("Error sending file to %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	fmt.Printf("Successfully sent %d bytes to %s\n", bytesSent, conn.RemoteAddr())
}
```

总而言之，这段测试代码细致地检验了 Go 语言网络库在利用 `sendfile` 优化文件传输时的各种场景和边界情况，确保了其正确性和可靠性。对于开发者来说，理解这些测试背后的逻辑有助于更好地使用 Go 的网络库进行高效的文件传输。

### 提示词
```
这是路径为go/src/net/sendfile_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"internal/poll"
	"io"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	newton       = "../testdata/Isaac.Newton-Opticks.txt"
	newtonLen    = 567198
	newtonSHA256 = "d4a9ac22462b35e7821a4f2706c211093da678620a8f9997989ee7cf8d507bbd"
)

// expectSendfile runs f, and verifies that internal/poll.SendFile successfully handles
// a write to wantConn during f's execution.
//
// On platforms where supportsSendfile is false, expectSendfile runs f but does not
// expect a call to SendFile.
func expectSendfile(t *testing.T, wantConn Conn, f func()) {
	t.Helper()
	if !supportsSendfile {
		f()
		return
	}
	orig := poll.TestHookDidSendFile
	defer func() {
		poll.TestHookDidSendFile = orig
	}()
	var (
		called     bool
		gotHandled bool
		gotFD      *poll.FD
		gotErr     error
	)
	poll.TestHookDidSendFile = func(dstFD *poll.FD, src int, written int64, err error, handled bool) {
		if called {
			t.Error("internal/poll.SendFile called multiple times, want one call")
		}
		called = true
		gotHandled = handled
		gotFD = dstFD
		gotErr = err
	}
	f()
	if !called {
		t.Error("internal/poll.SendFile was not called, want it to be")
		return
	}
	if !gotHandled {
		t.Error("internal/poll.SendFile did not handle the write, want it to, error:", gotErr)
		return
	}
	if &wantConn.(*TCPConn).fd.pfd != gotFD {
		t.Error("internal.poll.SendFile called with unexpected FD")
	}
}

func TestSendfile(t *testing.T) { testSendfile(t, newton, newtonSHA256, newtonLen, 0) }
func TestSendfileWithExactLimit(t *testing.T) {
	testSendfile(t, newton, newtonSHA256, newtonLen, newtonLen)
}
func TestSendfileWithLimitLargerThanFile(t *testing.T) {
	testSendfile(t, newton, newtonSHA256, newtonLen, newtonLen*2)
}
func TestSendfileWithLargeFile(t *testing.T) {
	// Some platforms are not capable of handling large files with sendfile
	// due to limited system resource, so we only run this test on amd64 and
	// arm64 for the moment.
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("skipping on non-amd64 and non-arm64 platforms")
	}
	// Also skip it during short testing.
	if testing.Short() {
		t.Skip("Skip it during short testing")
	}

	// We're using 1<<31 - 1 as the chunk size for sendfile currently,
	// make an edge case file that is 1 byte bigger than that.
	f := createTempFile(t, 1<<31)
	// For big file like this, only verify the transmission of the file,
	// skip the content check.
	testSendfile(t, f.Name(), "", 1<<31, 0)
}
func testSendfile(t *testing.T, filePath, fileHash string, size, limit int64) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	errc := make(chan error, 1)
	go func(ln Listener) {
		// Wait for a connection.
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			close(errc)
			return
		}

		go func() {
			defer close(errc)
			defer conn.Close()

			f, err := os.Open(filePath)
			if err != nil {
				errc <- err
				return
			}
			defer f.Close()

			// Return file data using io.Copy, which should use
			// sendFile if available.
			var sbytes int64
			switch runtime.GOOS {
			case "windows":
				// Windows is not using sendfile for some reason:
				// https://go.dev/issue/67042
				sbytes, err = io.Copy(conn, f)
			default:
				expectSendfile(t, conn, func() {
					if limit > 0 {
						sbytes, err = io.CopyN(conn, f, limit)
						if err == io.EOF && limit > size {
							err = nil
						}
					} else {
						sbytes, err = io.Copy(conn, f)
					}
				})
			}
			if err != nil {
				errc <- err
				return
			}

			if sbytes != size {
				errc <- fmt.Errorf("sent %d bytes; expected %d", sbytes, size)
				return
			}
		}()
	}(ln)

	// Connect to listener to retrieve file and verify digest matches
	// expected.
	c, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	h := sha256.New()
	rbytes, err := io.Copy(h, c)
	if err != nil {
		t.Error(err)
	}

	if rbytes != size {
		t.Errorf("received %d bytes; expected %d", rbytes, size)
	}

	if len(fileHash) > 0 && hex.EncodeToString(h.Sum(nil)) != newtonSHA256 {
		t.Error("retrieved data hash did not match")
	}

	for err := range errc {
		t.Error(err)
	}
}

func TestSendfileParts(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	errc := make(chan error, 1)
	go func(ln Listener) {
		// Wait for a connection.
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			close(errc)
			return
		}

		go func() {
			defer close(errc)
			defer conn.Close()

			f, err := os.Open(newton)
			if err != nil {
				errc <- err
				return
			}
			defer f.Close()

			for i := 0; i < 3; i++ {
				// Return file data using io.CopyN, which should use
				// sendFile if available.
				expectSendfile(t, conn, func() {
					_, err = io.CopyN(conn, f, 3)
				})
				if err != nil {
					errc <- err
					return
				}
			}
		}()
	}(ln)

	c, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(c)

	if want, have := "Produced ", buf.String(); have != want {
		t.Errorf("unexpected server reply %q, want %q", have, want)
	}

	for err := range errc {
		t.Error(err)
	}
}

func TestSendfileSeeked(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	const seekTo = 65 << 10
	const sendSize = 10 << 10

	errc := make(chan error, 1)
	go func(ln Listener) {
		// Wait for a connection.
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			close(errc)
			return
		}

		go func() {
			defer close(errc)
			defer conn.Close()

			f, err := os.Open(newton)
			if err != nil {
				errc <- err
				return
			}
			defer f.Close()
			if _, err := f.Seek(seekTo, io.SeekStart); err != nil {
				errc <- err
				return
			}

			expectSendfile(t, conn, func() {
				_, err = io.CopyN(conn, f, sendSize)
			})
			if err != nil {
				errc <- err
				return
			}
		}()
	}(ln)

	c, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(c)

	if buf.Len() != sendSize {
		t.Errorf("Got %d bytes; want %d", buf.Len(), sendSize)
	}

	for err := range errc {
		t.Error(err)
	}
}

// Test that sendfile doesn't put a pipe into blocking mode.
func TestSendfilePipe(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "windows", "js", "wasip1":
		// These systems don't support deadlines on pipes.
		t.Skipf("skipping on %s", runtime.GOOS)
	}

	t.Parallel()

	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	defer r.Close()

	copied := make(chan bool)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// Accept a connection and copy 1 byte from the read end of
		// the pipe to the connection. This will call into sendfile.
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		// The comment above states that this should call into sendfile,
		// but empirically it doesn't seem to do so at this time.
		// If it does, or does on some platforms, this CopyN should be wrapped
		// in expectSendfile.
		_, err = io.CopyN(conn, r, 1)
		if err != nil {
			t.Error(err)
			return
		}
		// Signal the main goroutine that we've copied the byte.
		close(copied)
	}()

	wg.Add(1)
	go func() {
		// Write 1 byte to the write end of the pipe.
		defer wg.Done()
		_, err := w.Write([]byte{'a'})
		if err != nil {
			t.Error(err)
		}
	}()

	wg.Add(1)
	go func() {
		// Connect to the server started two goroutines up and
		// discard any data that it writes.
		defer wg.Done()
		conn, err := Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	// Wait for the byte to be copied, meaning that sendfile has
	// been called on the pipe.
	<-copied

	// Set a very short deadline on the read end of the pipe.
	if err := r.SetDeadline(time.Now().Add(time.Microsecond)); err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		// Wait for much longer than the deadline and write a byte
		// to the pipe.
		defer wg.Done()
		time.Sleep(50 * time.Millisecond)
		w.Write([]byte{'b'})
	}()

	// If this read does not time out, the pipe was incorrectly
	// put into blocking mode.
	_, err = r.Read(make([]byte, 1))
	if err == nil {
		t.Error("Read did not time out")
	} else if !os.IsTimeout(err) {
		t.Errorf("got error %v, expected a time out", err)
	}

	wg.Wait()
}

// Issue 43822: tests that returns EOF when conn write timeout.
func TestSendfileOnWriteTimeoutExceeded(t *testing.T) {
	ln := newLocalListener(t, "tcp")
	defer ln.Close()

	errc := make(chan error, 1)
	go func(ln Listener) (retErr error) {
		defer func() {
			errc <- retErr
			close(errc)
		}()

		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		// Set the write deadline in the past(1h ago). It makes
		// sure that it is always write timeout.
		if err := conn.SetWriteDeadline(time.Now().Add(-1 * time.Hour)); err != nil {
			return err
		}

		f, err := os.Open(newton)
		if err != nil {
			return err
		}
		defer f.Close()

		// We expect this to use sendfile, but as of the time this comment was written
		// poll.SendFile on an FD past its timeout can return an error indicating that
		// it didn't handle the operation, resulting in a non-sendfile retry.
		// So don't use expectSendfile here.
		_, err = io.Copy(conn, f)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}

		if err == nil {
			err = fmt.Errorf("expected ErrDeadlineExceeded, but got nil")
		}
		return err
	}(ln)

	conn, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		t.Fatalf("expected nil error, but got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected receive zero, but got %d byte(s)", n)
	}

	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSendfileZeroBytes(b *testing.B) {
	var (
		wg          sync.WaitGroup
		ctx, cancel = context.WithCancel(context.Background())
	)

	defer wg.Wait()

	ln := newLocalListener(b, "tcp")
	defer ln.Close()

	tempFile, err := os.CreateTemp(b.TempDir(), "test.txt")
	if err != nil {
		b.Fatalf("failed to create temp file: %v", err)
	}
	defer tempFile.Close()

	fileName := tempFile.Name()

	dataSize := b.N
	wg.Add(1)
	go func(f *os.File) {
		defer wg.Done()

		for i := 0; i < dataSize; i++ {
			if _, err := f.Write([]byte{1}); err != nil {
				b.Errorf("failed to write: %v", err)
				return
			}
			if i%1000 == 0 {
				f.Sync()
			}
		}
	}(tempFile)

	b.ResetTimer()
	b.ReportAllocs()

	wg.Add(1)
	go func(ln Listener, fileName string) {
		defer wg.Done()

		conn, err := ln.Accept()
		if err != nil {
			b.Errorf("failed to accept: %v", err)
			return
		}
		defer conn.Close()

		f, err := os.OpenFile(fileName, os.O_RDONLY, 0660)
		if err != nil {
			b.Errorf("failed to open file: %v", err)
			return
		}
		defer f.Close()

		for {
			if ctx.Err() != nil {
				return
			}

			if _, err := io.Copy(conn, f); err != nil {
				b.Errorf("failed to copy: %v", err)
				return
			}
		}
	}(ln, fileName)

	conn, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	n, err := io.CopyN(io.Discard, conn, int64(dataSize))
	if err != nil {
		b.Fatalf("failed to copy: %v", err)
	}
	if n != int64(dataSize) {
		b.Fatalf("expected %d copied bytes, but got %d", dataSize, n)
	}

	cancel()
}

func BenchmarkSendFile(b *testing.B) {
	if runtime.GOOS == "windows" {
		// TODO(panjf2000): Windows has not yet implemented FileConn,
		//		remove this when it's implemented in https://go.dev/issues/9503.
		b.Skipf("skipping on %s", runtime.GOOS)
	}

	b.Run("file-to-tcp", func(b *testing.B) { benchmarkSendFile(b, "tcp") })
	b.Run("file-to-unix", func(b *testing.B) { benchmarkSendFile(b, "unix") })
}

func benchmarkSendFile(b *testing.B, proto string) {
	for i := 0; i <= 10; i++ {
		size := 1 << (i + 10)
		bench := sendFileBench{
			proto:     proto,
			chunkSize: size,
		}
		b.Run(strconv.Itoa(size), bench.benchSendFile)
	}
}

type sendFileBench struct {
	proto     string
	chunkSize int
}

func (bench sendFileBench) benchSendFile(b *testing.B) {
	fileSize := b.N * bench.chunkSize
	f := createTempFile(b, int64(fileSize))

	client, server := spawnTestSocketPair(b, bench.proto)
	defer server.Close()

	cleanUp, err := startTestSocketPeer(b, client, "r", bench.chunkSize, fileSize)
	if err != nil {
		client.Close()
		b.Fatal(err)
	}
	defer cleanUp(b)

	b.ReportAllocs()
	b.SetBytes(int64(bench.chunkSize))
	b.ResetTimer()

	// Data go from file to socket via sendfile(2).
	sent, err := io.Copy(server, f)
	if err != nil {
		b.Fatalf("failed to copy data with sendfile, error: %v", err)
	}
	if sent != int64(fileSize) {
		b.Fatalf("bytes sent mismatch, got: %d, want: %d", sent, fileSize)
	}
}

func createTempFile(tb testing.TB, size int64) *os.File {
	f, err := os.CreateTemp(tb.TempDir(), "sendfile-bench")
	if err != nil {
		tb.Fatalf("failed to create temporary file: %v", err)
	}
	tb.Cleanup(func() {
		f.Close()
	})

	if _, err := io.CopyN(f, newRandReader(tb), size); err != nil {
		tb.Fatalf("failed to fill the file with random data: %v", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		tb.Fatalf("failed to rewind the file: %v", err)
	}

	return f
}

func newRandReader(tb testing.TB) io.Reader {
	seed := time.Now().UnixNano()
	tb.Logf("Deterministic RNG seed based on timestamp: 0x%x", seed)
	return rand.New(rand.NewSource(seed))
}
```