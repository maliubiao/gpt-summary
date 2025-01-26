Response:
Let's break down the thought process for analyzing this Go test file.

**1. Understanding the Goal:**

The core request is to understand the functionality of the provided Go code snippet, which is a test file (`readfrom_linux_test.go`). The emphasis is on identifying the features being tested, providing example usage, detailing any command-line argument handling (though unlikely in a test file like this), and pinpointing common mistakes.

**2. Initial Scan and Keyword Recognition:**

My first pass involves scanning for keywords and recognizable patterns. I see:

* `"testing"`:  Immediately tells me this is a test file.
* `func Test...`:  Indicates various test functions.
* `t.Run(...)`:  Shows the structure of subtests.
* `poll.Splice`, `poll.CopyFileRange`, `poll.SendFile`:  These are key syscall-related functions, hinting at the core functionality being tested. The `internal/poll` package connection is crucial.
* `io.Copy`, `io.LimitedReader`: Standard Go I/O operations.
* `net.Dial`, `net.Listen`:  Indicates network socket usage (TCP, Unix).
* `os.CreateTemp`, `os.Open`, `os.Create`: File system operations.
* `syscall.Open`: Direct system call, often used for lower-level file operations, especially with TTYs.
* `testpty.Open()`:  Clearly relates to pseudo-terminals.

**3. Deconstructing Test Functions:**

I then start examining each `Test...` function:

* **`TestSpliceFile`:**  The name strongly suggests testing the `splice` system call. The subtests "Basic-TCP," "Basic-Unix," "TCP-To-TTY," and "Limited" further clarify the scenarios being tested. The `testSpliceFile` helper function seems to be the core logic here.

* **`testSpliceFile`:**  This function sets up sockets (TCP or Unix) and a destination file. It populates the source socket with data and then uses `io.Copy` to transfer data to the file. The key observation is the hook on `poll.Splice`, confirming the intent to test this syscall. The `limit` parameter suggests testing partial transfers.

* **`testSpliceToTTY`:**  This specifically focuses on `splice` involving a TTY (pseudo-terminal). The code explicitly opens the TTY using `syscall.Open` to bypass non-blocking behavior, indicating a specific issue being addressed (likely the mentioned issue #59041).

* **`TestCopyFiles`, `testCopyFileRange`, `testSendfileOverCopyFileRange`:** These are clearly testing file copying functionalities, likely involving the `copy_file_range` and `sendfile` system calls. The naming conventions are very descriptive. The `newCopyFileRangeTest` and `newSendfileOverCopyFileRangeTest` helpers initialize the test environment and hook the relevant `poll` functions.

* **`TestProcCopy`:** Tests copying a file from `/proc`, likely to verify handling of special file systems.

* **`TestGetPollFDAndNetwork`:** Examines the `GetPollFDAndNetwork` function, which provides access to the underlying file descriptor and network type of a network connection.

**4. Identifying Core Functionality:**

By examining the test function names and the `poll` functions being hooked, I can confidently deduce the main functionalities being tested:

* **`splice` system call:** Efficiently transferring data between file descriptors (especially sockets and files) within the kernel.
* **`copy_file_range` system call:**  Efficiently copying data between files within the kernel.
* **`sendfile` system call:**  Efficiently sending data from a file descriptor (usually a file) to a socket.
* **Interactions with TTYs:**  Specifically testing how these efficient transfer mechanisms work when one of the endpoints is a TTY.
* **Accessing underlying file descriptors:** Testing the `GetPollFDAndNetwork` function.

**5. Constructing Examples and Explanations:**

Based on the code structure and the identified functionalities, I can create illustrative examples. For `splice`, the example shows copying data from a TCP socket to a file. For `copy_file_range`, the example demonstrates copying between two regular files.

**6. Reasoning about Inputs and Outputs:**

For the `splice` and `copy_file_range` examples, the "input" is the data in the source (either socket or file), and the "output" is the data written to the destination file. The size and the optional `limit` are important parameters affecting the transfer.

**7. Command-Line Arguments:**

I recognize that this is a *test* file. Test files in Go are typically run using `go test`. They don't usually involve custom command-line arguments in the way a regular application might. The tests themselves might parameterize behavior (like the `size` variable), but these are internal to the test code, not external command-line flags.

**8. Identifying Potential Mistakes:**

I consider common pitfalls related to the tested functionalities:

* **Incorrectly handling return values:** Not checking for errors from `io.Copy`, `splice`, or `copy_file_range`.
* **File descriptor management:** Not closing files or sockets properly, leading to resource leaks.
* **Understanding the limitations of `splice` and `copy_file_range`:**  These are kernel-level optimizations and might not be applicable in all scenarios (e.g., regular files on different file systems in some older kernels).
* **Blocking behavior with TTYs:** The `testSpliceToTTY` function specifically highlights the nuances of working with TTYs.

**9. Structuring the Answer:**

Finally, I organize the information logically, addressing each part of the original request: functionalities, example usage (with code and explanations), input/output reasoning, command-line arguments (and the fact that they aren't really applicable here), and common mistakes. Using clear headings and formatting makes the answer easier to understand.
这个Go语言测试文件 `go/src/os/readfrom_linux_test.go` 的主要功能是**测试在Linux系统上使用 `io.Copy` 将数据从各种来源读取并写入文件时，底层是否正确地使用了 `splice` 和 `copy_file_range` 等零拷贝系统调用，以及 `sendfile` 系统调用作为 `copy_file_range` 不可用时的回退机制。**

更具体地说，它测试了以下场景：

1. **`splice` 系统调用测试:**
   - **从TCP socket读取数据并写入文件:**  测试 `io.Copy` 能否利用 `splice` 系统调用高效地将数据从网络连接写入文件。
   - **从Unix domain socket读取数据并写入文件:**  类似于TCP，测试 `splice` 在Unix socket上的应用。
   - **从TCP/Unix socket读取数据并写入TTY (Teletypewriter):**  这是一个特殊的测试用例，用于验证在涉及TTY的情况下 `splice` 的行为，并且特别关注了 #59041 这个问题，该问题与向TTY写入数据块有关。
   - **限制传输大小:** 测试在限制读取大小的情况下 `splice` 的行为，例如只读取部分数据。

2. **`copy_file_range` 系统调用测试:**
   - **文件到文件拷贝:** 测试 `io.Copy` 能否利用 `copy_file_range` 系统调用高效地在文件之间复制数据。
   - **通过回退机制使用 `sendfile`:**  当 `copy_file_range` 不可用时（例如，在某些文件系统上），测试是否正确回退到 `sendfile` 系统调用。

3. **其他测试:**
   - **`/proc` 文件拷贝:**  测试拷贝 `/proc` 文件系统中的文件，这可以揭示对特殊文件系统的处理。
   - **`GetPollFDAndNetwork` 函数测试:** 测试 `GetPollFDAndNetwork` 函数，该函数用于获取与 `net.Conn` 相关的底层文件描述符和网络类型。

**Go 代码举例说明:**

以下是一些简化的代码示例，展示了这些测试所涵盖的 Go 语言功能：

**1. 使用 `io.Copy` 从 TCP socket 读取数据并写入文件（可能使用 `splice`）：**

```go
package main

import (
	"io"
	"net"
	"os"
)

func main() {
	// 模拟一个 TCP 服务器
	listener, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 创建一个用于写入的文件
	file, err := os.Create("output.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 从连接读取数据并写入文件，底层可能会使用 splice
	_, err = io.Copy(file, conn)
	if err != nil {
		panic(err)
	}
}
```

**假设输入与输出:**

* **输入:**  通过连接发送到 `localhost:8080` 的数据，例如字符串 "Hello, world!"。
* **输出:**  名为 `output.txt` 的文件，其内容为 "Hello, world!"。

**2. 使用 `io.Copy` 从一个文件复制到另一个文件（可能使用 `copy_file_range` 或 `sendfile`）：**

```go
package main

import (
	"io"
	"os"
)

func main() {
	// 创建一个源文件并写入数据
	src, err := os.Create("source.txt")
	if err != nil {
		panic(err)
	}
	_, err = src.WriteString("This is the source file.")
	if err != nil {
		panic(err)
	}
	src.Close()

	// 打开源文件用于读取
	source, err := os.Open("source.txt")
	if err != nil {
		panic(err)
	}
	defer source.Close()

	// 创建一个目标文件用于写入
	dest, err := os.Create("destination.txt")
	if err != nil {
		panic(err)
	}
	defer dest.Close()

	// 从源文件复制到目标文件，底层可能会使用 copy_file_range 或 sendfile
	_, err = io.Copy(dest, source)
	if err != nil {
		panic(err)
	}
}
```

**假设输入与输出:**

* **输入:** 名为 `source.txt` 的文件，内容为 "This is the source file."。
* **输出:** 名为 `destination.txt` 的文件，其内容为 "This is the source file."。

**代码推理 (结合测试代码):**

测试代码中的 `testSpliceFile` 和 `testCopyFile` 函数模拟了上述场景，并使用钩子 (`hookSpliceFile`, `hookCopyFileRange`, `hookSendFileOverCopyFileRange`) 来检测 `poll.Splice`, `poll.CopyFileRange` 和 `poll.SendFile` 是否被调用，以及调用时的参数是否正确。  例如，`testSpliceFile` 创建了一个 TCP 或 Unix socket 对，并将数据写入其中一个 socket。然后，它使用 `io.Copy` 将数据从另一个 socket 复制到一个文件中。通过 `hookSpliceFile`，它可以断言 `poll.Splice` 是否被调用，并且源和目标文件描述符是否正确。

**命令行参数的具体处理:**

这个测试文件本身 **不涉及** 命令行参数的具体处理。  它是一个测试文件，通过 `go test` 命令运行。`go test` 命令有一些标准参数（例如 `-v` 显示详细输出），但这些参数不是由测试文件本身定义的。

**使用者易犯错的点:**

虽然这个文件是测试代码，但它可以帮助我们理解使用 `io.Copy` 进行高效数据传输时的一些潜在问题：

1. **假设总是使用零拷贝:**  开发者可能会错误地假设 `io.Copy` 总是会使用 `splice` 或 `copy_file_range`。  实际上，是否使用这些系统调用取决于操作系统、文件类型和具体的场景。例如，跨越不同的文件系统可能无法使用 `copy_file_range`。

   **例子:**  如果开发者需要非常确定地使用零拷贝，他们可能需要显式地调用相关的系统调用（如果 Go 语言标准库直接暴露了这些接口，目前 Go 主要通过 `io.Copy` 内部优化）。

2. **忽略错误处理:**  与任何 I/O 操作一样，`io.Copy` 可能会返回错误。开发者容易忽略对 `io.Copy` 返回的错误进行适当处理。

   **例子:**

   ```go
   n, err := io.Copy(dst, src)
   if err != nil {
       // 必须处理错误，例如记录日志或返回错误
       panic(err) // 只是一个简单的例子，实际应用中不应直接 panic
   }
   println("Copied", n, "bytes")
   ```

3. **对 TTY 的特殊处理不了解:**  `testSpliceToTTY` 强调了向 TTY 写入数据时可能遇到的特殊情况。开发者可能需要了解 TTY 的缓冲和行处理机制，以及这如何影响数据传输。

   **例子:**  直接使用 `io.Copy` 向 TTY 写入大量数据可能不会像写入普通文件那样直接，可能会涉及到终端的控制序列和回显等问题。

4. **文件描述符泄漏:**  如果在 `io.Copy` 的过程中发生错误，并且没有正确关闭源或目标文件描述符，可能会导致资源泄漏。

   **例子:**  务必使用 `defer` 来确保文件和网络连接被正确关闭：

   ```go
   src, err := os.Open("source.txt")
   if err != nil {
       panic(err)
   }
   defer src.Close()

   dst, err := os.Create("destination.txt")
   if err != nil {
       panic(err)
   }
   defer dst.Close()

   _, err = io.Copy(dst, src)
   if err != nil {
       panic(err)
   }
   ```

总而言之，这个测试文件深入探讨了 Go 语言在 Linux 系统上利用底层系统调用进行高效数据传输的机制，并覆盖了多种场景，有助于开发者理解 `io.Copy` 的工作原理和潜在的注意事项。

Prompt: 
```
这是路径为go/src/os/readfrom_linux_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"bytes"
	"errors"
	"internal/poll"
	"internal/testpty"
	"io"
	"math/rand"
	"net"
	. "os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSpliceFile(t *testing.T) {
	sizes := []int{
		1,
		42,
		1025,
		syscall.Getpagesize() + 1,
		32769,
	}
	t.Run("Basic-TCP", func(t *testing.T) {
		for _, size := range sizes {
			t.Run(strconv.Itoa(size), func(t *testing.T) {
				testSpliceFile(t, "tcp", int64(size), -1)
			})
		}
	})
	t.Run("Basic-Unix", func(t *testing.T) {
		for _, size := range sizes {
			t.Run(strconv.Itoa(size), func(t *testing.T) {
				testSpliceFile(t, "unix", int64(size), -1)
			})
		}
	})
	t.Run("TCP-To-TTY", func(t *testing.T) {
		testSpliceToTTY(t, "tcp", 32768)
	})
	t.Run("Unix-To-TTY", func(t *testing.T) {
		testSpliceToTTY(t, "unix", 32768)
	})
	t.Run("Limited", func(t *testing.T) {
		t.Run("OneLess-TCP", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testSpliceFile(t, "tcp", int64(size), int64(size)-1)
				})
			}
		})
		t.Run("OneLess-Unix", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testSpliceFile(t, "unix", int64(size), int64(size)-1)
				})
			}
		})
		t.Run("Half-TCP", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testSpliceFile(t, "tcp", int64(size), int64(size)/2)
				})
			}
		})
		t.Run("Half-Unix", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testSpliceFile(t, "unix", int64(size), int64(size)/2)
				})
			}
		})
		t.Run("More-TCP", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testSpliceFile(t, "tcp", int64(size), int64(size)+1)
				})
			}
		})
		t.Run("More-Unix", func(t *testing.T) {
			for _, size := range sizes {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					testSpliceFile(t, "unix", int64(size), int64(size)+1)
				})
			}
		})
	})
}

func testSpliceFile(t *testing.T, proto string, size, limit int64) {
	dst, src, data, hook, cleanup := newSpliceFileTest(t, proto, size)
	defer cleanup()

	// If we have a limit, wrap the reader.
	var (
		r  io.Reader
		lr *io.LimitedReader
	)
	if limit >= 0 {
		lr = &io.LimitedReader{N: limit, R: src}
		r = lr
		if limit < int64(len(data)) {
			data = data[:limit]
		}
	} else {
		r = src
	}
	// Now call ReadFrom (through io.Copy), which will hopefully call poll.Splice
	n, err := io.Copy(dst, r)
	if err != nil {
		t.Fatal(err)
	}

	// We should have called poll.Splice with the right file descriptor arguments.
	if n > 0 && !hook.called {
		t.Fatal("expected to called poll.Splice")
	}
	if hook.called && hook.dstfd != int(dst.Fd()) {
		t.Fatalf("wrong destination file descriptor: got %d, want %d", hook.dstfd, dst.Fd())
	}
	sc, ok := src.(syscall.Conn)
	if !ok {
		t.Fatalf("server Conn is not a syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("server Conn SyscallConn error: %v", err)
	}
	if err = rc.Control(func(fd uintptr) {
		if hook.called && hook.srcfd != int(fd) {
			t.Fatalf("wrong source file descriptor: got %d, want %d", hook.srcfd, int(fd))
		}
	}); err != nil {
		t.Fatalf("server Conn Control error: %v", err)
	}

	// Check that the offsets after the transfer make sense, that the size
	// of the transfer was reported correctly, and that the destination
	// file contains exactly the bytes we expect it to contain.
	dstoff, err := dst.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if dstoff != int64(len(data)) {
		t.Errorf("dstoff = %d, want %d", dstoff, len(data))
	}
	if n != int64(len(data)) {
		t.Errorf("short ReadFrom: wrote %d bytes, want %d", n, len(data))
	}
	mustSeekStart(t, dst)
	mustContainData(t, dst, data)

	// If we had a limit, check that it was updated.
	if lr != nil {
		if want := limit - n; lr.N != want {
			t.Fatalf("didn't update limit correctly: got %d, want %d", lr.N, want)
		}
	}
}

// Issue #59041.
func testSpliceToTTY(t *testing.T, proto string, size int64) {
	var wg sync.WaitGroup

	// Call wg.Wait as the final deferred function,
	// because the goroutines may block until some of
	// the deferred Close calls.
	defer wg.Wait()

	pty, ttyName, err := testpty.Open()
	if err != nil {
		t.Skipf("skipping test because pty open failed: %v", err)
	}
	defer pty.Close()

	// Open the tty directly, rather than via OpenFile.
	// This bypasses the non-blocking support and is required
	// to recreate the problem in the issue (#59041).
	ttyFD, err := syscall.Open(ttyName, syscall.O_RDWR, 0)
	if err != nil {
		t.Skipf("skipping test because failed to open tty: %v", err)
	}
	defer syscall.Close(ttyFD)

	tty := NewFile(uintptr(ttyFD), "tty")
	defer tty.Close()

	client, server := createSocketPair(t, proto)

	data := bytes.Repeat([]byte{'a'}, int(size))

	wg.Add(1)
	go func() {
		defer wg.Done()
		// The problem (issue #59041) occurs when writing
		// a series of blocks of data. It does not occur
		// when all the data is written at once.
		for i := 0; i < len(data); i += 1024 {
			if _, err := client.Write(data[i : i+1024]); err != nil {
				// If we get here because the client was
				// closed, skip the error.
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("error writing to socket: %v", err)
				}
				return
			}
		}
		client.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32)
		for {
			if _, err := pty.Read(buf); err != nil {
				if err != io.EOF && !errors.Is(err, ErrClosed) {
					// An error here doesn't matter for
					// our test.
					t.Logf("error reading from pty: %v", err)
				}
				return
			}
		}
	}()

	// Close Client to wake up the writing goroutine if necessary.
	defer client.Close()

	_, err = io.Copy(tty, server)
	if err != nil {
		t.Fatal(err)
	}
}

var (
	copyFileTests = []copyFileTestFunc{newCopyFileRangeTest, newSendfileOverCopyFileRangeTest}
	copyFileHooks = []copyFileTestHook{hookCopyFileRange, hookSendFileOverCopyFileRange}
)

func testCopyFiles(t *testing.T, size, limit int64) {
	testCopyFileRange(t, size, limit)
	testSendfileOverCopyFileRange(t, size, limit)
}

func testCopyFileRange(t *testing.T, size int64, limit int64) {
	dst, src, data, hook, name := newCopyFileRangeTest(t, size)
	testCopyFile(t, dst, src, data, hook, limit, name)
}

func testSendfileOverCopyFileRange(t *testing.T, size int64, limit int64) {
	dst, src, data, hook, name := newSendfileOverCopyFileRangeTest(t, size)
	testCopyFile(t, dst, src, data, hook, limit, name)
}

// newCopyFileRangeTest initializes a new test for copy_file_range.
//
// It hooks package os' call to poll.CopyFileRange and returns the hook,
// so it can be inspected.
func newCopyFileRangeTest(t *testing.T, size int64) (dst, src *File, data []byte, hook *copyFileHook, name string) {
	t.Helper()

	name = "newCopyFileRangeTest"

	dst, src, data = newCopyFileTest(t, size)
	hook, _ = hookCopyFileRange(t)

	return
}

// newSendfileOverCopyFileRangeTest initializes a new test for sendfile over copy_file_range.
// It hooks package os' call to poll.SendFile and returns the hook,
// so it can be inspected.
func newSendfileOverCopyFileRangeTest(t *testing.T, size int64) (dst, src *File, data []byte, hook *copyFileHook, name string) {
	t.Helper()

	name = "newSendfileOverCopyFileRangeTest"

	dst, src, data = newCopyFileTest(t, size)
	hook, _ = hookSendFileOverCopyFileRange(t)

	return
}

// newSpliceFileTest initializes a new test for splice.
//
// It creates source sockets and destination file, and populates the source sockets
// with random data of the specified size. It also hooks package os' call
// to poll.Splice and returns the hook so it can be inspected.
func newSpliceFileTest(t *testing.T, proto string, size int64) (*File, net.Conn, []byte, *spliceFileHook, func()) {
	t.Helper()

	hook := hookSpliceFile(t)

	client, server := createSocketPair(t, proto)

	dst, err := CreateTemp(t.TempDir(), "dst-splice-file-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dst.Close() })

	randSeed := time.Now().Unix()
	t.Logf("random data seed: %d\n", randSeed)
	prng := rand.New(rand.NewSource(randSeed))
	data := make([]byte, size)
	prng.Read(data)

	done := make(chan struct{})
	go func() {
		client.Write(data)
		client.Close()
		close(done)
	}()

	return dst, server, data, hook, func() { <-done }
}

func hookCopyFileRange(t *testing.T) (hook *copyFileHook, name string) {
	name = "hookCopyFileRange"

	hook = new(copyFileHook)
	orig := *PollCopyFileRangeP
	t.Cleanup(func() {
		*PollCopyFileRangeP = orig
	})
	*PollCopyFileRangeP = func(dst, src *poll.FD, remain int64) (int64, bool, error) {
		hook.called = true
		hook.dstfd = dst.Sysfd
		hook.srcfd = src.Sysfd
		hook.written, hook.handled, hook.err = orig(dst, src, remain)
		return hook.written, hook.handled, hook.err
	}
	return
}

func hookSendFileOverCopyFileRange(t *testing.T) (*copyFileHook, string) {
	return hookSendFileTB(t), "hookSendFileOverCopyFileRange"
}

func hookSendFileTB(tb testing.TB) *copyFileHook {
	// Disable poll.CopyFileRange to force the fallback to poll.SendFile.
	originalCopyFileRange := *PollCopyFileRangeP
	*PollCopyFileRangeP = func(dst, src *poll.FD, remain int64) (written int64, handled bool, err error) {
		return 0, false, nil
	}

	hook := new(copyFileHook)
	orig := poll.TestHookDidSendFile
	tb.Cleanup(func() {
		*PollCopyFileRangeP = originalCopyFileRange
		poll.TestHookDidSendFile = orig
	})
	poll.TestHookDidSendFile = func(dstFD *poll.FD, src int, written int64, err error, handled bool) {
		hook.called = true
		hook.dstfd = dstFD.Sysfd
		hook.srcfd = src
		hook.written = written
		hook.err = err
		hook.handled = handled
	}
	return hook
}

func hookSpliceFile(t *testing.T) *spliceFileHook {
	h := new(spliceFileHook)
	h.install()
	t.Cleanup(h.uninstall)
	return h
}

type spliceFileHook struct {
	called bool
	dstfd  int
	srcfd  int
	remain int64

	written int64
	handled bool
	err     error

	original func(dst, src *poll.FD, remain int64) (int64, bool, error)
}

func (h *spliceFileHook) install() {
	h.original = *PollSpliceFile
	*PollSpliceFile = func(dst, src *poll.FD, remain int64) (int64, bool, error) {
		h.called = true
		h.dstfd = dst.Sysfd
		h.srcfd = src.Sysfd
		h.remain = remain
		h.written, h.handled, h.err = h.original(dst, src, remain)
		return h.written, h.handled, h.err
	}
}

func (h *spliceFileHook) uninstall() {
	*PollSpliceFile = h.original
}

// On some kernels copy_file_range fails on files in /proc.
func TestProcCopy(t *testing.T) {
	t.Parallel()

	const cmdlineFile = "/proc/self/cmdline"
	cmdline, err := ReadFile(cmdlineFile)
	if err != nil {
		t.Skipf("can't read /proc file: %v", err)
	}
	in, err := Open(cmdlineFile)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	outFile := filepath.Join(t.TempDir(), "cmdline")
	out, err := Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	copy, err := ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cmdline, copy) {
		t.Errorf("copy of %q got %q want %q\n", cmdlineFile, copy, cmdline)
	}
}

func TestGetPollFDAndNetwork(t *testing.T) {
	t.Run("tcp4", func(t *testing.T) { testGetPollFDAndNetwork(t, "tcp4") })
	t.Run("unix", func(t *testing.T) { testGetPollFDAndNetwork(t, "unix") })
}

func testGetPollFDAndNetwork(t *testing.T, proto string) {
	_, server := createSocketPair(t, proto)
	sc, ok := server.(syscall.Conn)
	if !ok {
		t.Fatalf("server Conn is not a syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("server SyscallConn error: %v", err)
	}
	if err = rc.Control(func(fd uintptr) {
		pfd, network := GetPollFDAndNetwork(server)
		if pfd == nil {
			t.Fatalf("GetPollFDAndNetwork didn't return poll.FD")
		}
		if string(network) != proto {
			t.Fatalf("GetPollFDAndNetwork returned wrong network, got: %s, want: %s", network, proto)
		}
		if pfd.Sysfd != int(fd) {
			t.Fatalf("GetPollFDAndNetwork returned wrong poll.FD, got: %d, want: %d", pfd.Sysfd, int(fd))
		}
		if !pfd.IsStream {
			t.Fatalf("expected IsStream to be true")
		}
		if err = pfd.Init(proto, true); err == nil {
			t.Fatalf("Init should have failed with the initialized poll.FD and return EEXIST error")
		}
	}); err != nil {
		t.Fatalf("server Control error: %v", err)
	}
}

"""



```