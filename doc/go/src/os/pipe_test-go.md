Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file name `pipe_test.go` and the package declaration `package os_test` immediately suggest that this code is for testing the `os` package's pipe functionality. The comment "// Test broken pipes on Unix systems." further narrows down the focus.

2. **Examine Imports:**  The imports provide hints about the functionalities being tested. We see:
    * `bufio`, `bytes`, `fmt`, `io`: Standard input/output operations, suggesting testing data flow through pipes.
    * `internal/testenv`: Likely for setting up test environments (like ensuring `exec` is available).
    * `os`: The target package itself.
    * `os/exec`:  Indicates testing interactions with child processes using pipes.
    * `os/signal`: Suggests testing how pipes interact with signals, particularly `SIGPIPE`.
    * `runtime`:  Used to determine the operating system, allowing for platform-specific testing.
    * `strconv`, `strings`:  Basic string and number conversions, potentially for parsing pipe limits.
    * `sync`:  Synchronization primitives, implying tests involving concurrency and potential race conditions.
    * `syscall`: Direct system calls, necessary for lower-level pipe operations and error code checks.
    * `testing`: The core Go testing framework.
    * `time`:  For introducing delays, useful in testing concurrency and timeouts.
    * `io/fs`: Working with file system errors.

3. **Analyze Individual Test Functions:** Go test files are structured around functions starting with `Test`. Let's examine each one:

    * **`TestEPIPE(t *testing.T)`:**  The name strongly suggests testing the `EPIPE` error, which occurs when writing to a closed pipe. The code confirms this by creating a pipe, closing the read end, and repeatedly writing to the write end, verifying that `EPIPE` (or its Windows equivalent) is returned.

    * **`TestStdPipe(t *testing.T)`:** This test is more complex. The environment variable checks (`GO_TEST_STD_PIPE_HELPER`) hint at a sub-process being executed. The test seems to be exploring how writing to closed standard output (stdout) and standard error (stderr) pipes behave, specifically checking for `SIGPIPE` signals. The loop involving `dest` 1, 2, and 3 likely tests different file descriptors.

    * **`testClosedPipeRace(t *testing.T, read bool)`:** The name "race" suggests this test aims to identify race conditions when closing one end of a pipe while the other end is being read from or written to. The `read` boolean parameter indicates two separate test cases. The logic to determine `limit` points to testing scenarios with large writes potentially exceeding pipe buffer sizes.

    * **`TestClosedPipeRaceRead(t *testing.T)` and `TestClosedPipeRaceWrite(t *testing.T)`:** These are simply wrappers calling `testClosedPipeRace` with the `read` parameter set appropriately.

    * **`TestReadNonblockingFd(t *testing.T)`:** The name indicates testing non-blocking file descriptors. The environment variable `GO_WANT_READ_NONBLOCKING_FD` and the `syscall.SetNonblock` call confirm this. The test seems to verify that reading from a non-blocking pipe with no data returns `EAGAIN`.

    * **`TestCloseWithBlockingReadByNewFile(t *testing.T)` and `TestCloseWithBlockingReadByFd(t *testing.T)`:** These tests, along with `testCloseWithBlockingRead`, focus on the interaction between closing a pipe and a blocking read operation. They ensure that closing the read end doesn't hang indefinitely if a read is in progress. The "ByNewFile" and "ByFd" suffixes likely refer to how the file descriptors are obtained, testing different code paths.

    * **`TestPipeEOF(t *testing.T)`:** This test, along with `testPipeEOF`, checks that when the write end of a pipe is closed, a blocking read on the read end returns `io.EOF`.

    * **`TestFdRace(t *testing.T)`:** The name "race" indicates a test for race conditions when calling the `Fd()` method of a pipe's write end concurrently.

    * **`TestFdReadRace(t *testing.T)`:** This test appears to be checking for a specific race condition where calling `Fd()` on a pipe's read end while a blocking `Read` operation is in progress could lead to a hang.

4. **Synthesize the Findings:**  Based on the individual test analysis, we can summarize the overall functionality of the code.

5. **Identify Go Features:** The tests extensively use `os.Pipe()`, demonstrating the core Go feature of creating pipes for inter-process communication or communication between goroutines. The use of `os/exec.Command` highlights Go's ability to manage and interact with external processes. The `signal` package showcases Go's support for handling operating system signals.

6. **Construct Code Examples:** For the key Go features identified (pipe creation and interaction with subprocesses), create concise and illustrative examples.

7. **Address Command-Line Arguments and Common Mistakes:**  The `TestStdPipe` function uses environment variables to control the behavior of a subprocess. This needs to be explained. The race conditions highlighted in several tests are potential pitfalls for users, so these should be mentioned as common mistakes.

8. **Refine and Structure:**  Organize the information logically, using clear headings and bullet points for readability. Ensure the language is clear, concise, and accurate.

Self-Correction/Refinement during the process:

* **Initial thought:** Maybe the `TestStdPipe` is just about testing writing to standard streams. **Correction:** The environment variable and sub-process logic indicate a more nuanced test involving signal handling and different file descriptors.
* **Initial thought:**  The race condition tests are just for internal purposes. **Correction:** Understanding these race conditions helps users avoid similar issues in their own concurrent code involving pipes.
* **Initial thought:** Just list the function names. **Correction:**  Explain the *purpose* of each test function for better understanding.
* **Focus on clarity:**  Ensure explanations are geared towards a user trying to understand the code's function, not just a dry technical description.

By following this systematic approach, we can effectively analyze and explain the provided Go code snippet.
这段Go语言代码文件 `go/src/os/pipe_test.go` 的主要功能是**测试 `os` 包中关于管道（pipe）操作的各种场景，特别是涉及 broken pipe（管道破裂）的情况**。它旨在验证在各种边缘情况下，Go 语言的管道机制是否能够正确地处理错误和信号。

以下是代码中各个测试函数的功能细分：

**1. `TestEPIPE(t *testing.T)`**

* **功能:**  测试向一个已经关闭了读端的管道写入数据时，是否会返回预期的 `EPIPE` 错误（在 Windows 上是特定的错误码）。
* **实现原理:**
    1. 创建一个管道 `r, w, err := os.Pipe()`。
    2. 关闭管道的读端 `r.Close()`。
    3. 循环多次向管道的写端 `w` 写入数据。
    4. 断言每次写入都会返回错误，并且该错误是 `syscall.EPIPE`（或 Windows 上的对应错误）。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }
       r.Close() // 关闭读端

       _, err = w.Write([]byte("hello"))
       if err != syscall.EPIPE {
           fmt.Printf("期望得到 EPIPE 错误，但得到了: %v\n", err)
       } else {
           fmt.Println("成功得到 EPIPE 错误")
       }
   }
   ```
* **假设的输入与输出:**  没有明确的输入，主要依赖于操作系统对关闭管道的处理。 输出是程序是否能捕获到 `EPIPE` 错误。

**2. `TestStdPipe(t *testing.T)`**

* **功能:** 测试当子进程的标准输出（stdout）、标准错误输出（stderr）或额外的文件描述符连接到一个已经关闭的管道时，会发生什么。特别是测试是否会收到 `SIGPIPE` 信号（在非 Windows 系统上）。
* **实现原理:**
    1. 使用环境变量 `GO_TEST_STD_PIPE_HELPER` 来控制子进程的行为：
        * `1`: 子进程尝试向标准输出写入。
        * `2`: 子进程尝试向标准错误输出写入。
        * `3`: 子进程尝试向文件描述符 3 写入。
    2. 在父进程中，先关闭管道的读端。
    3. 创建一个子进程，并将子进程的 stdout、stderr 或文件描述符 3 连接到父进程中已关闭的管道的写端。
    4. 运行子进程并检查其退出状态。
    5. 如果子进程尝试写入 stdout 或 stderr，并且没有设置 `GO_TEST_STD_PIPE_HELPER_SIGNAL`，则期望收到 `SIGPIPE` 信号导致进程终止。
    6. 如果设置了 `GO_TEST_STD_PIPE_HELPER_SIGNAL`，则子进程会捕获 `SIGPIPE`，并期望以正常状态退出。
    7. 对于文件描述符 3，期望写入失败并返回 `EPIPE` 错误，然后子进程正常退出。
* **命令行参数处理:**  这个测试本身不直接处理命令行参数。它通过设置环境变量来控制子进程的行为。
* **Go 代码示例 (子进程部分):**
   ```go
   package main

   import (
       "fmt"
       "os"
       "os/signal"
       "syscall"
   )

   func main() {
       if os.Getenv("GO_TEST_STD_PIPE_HELPER_SIGNAL") != "" {
           signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
       }
       switch os.Getenv("GO_TEST_STD_PIPE_HELPER") {
       case "1":
           os.Stdout.Write([]byte("stdout"))
       case "2":
           os.Stderr.Write([]byte("stderr"))
       case "3":
           f := os.NewFile(3, "fd3")
           if _, err := f.Write([]byte("3")); err != nil {
               fmt.Println("写入文件描述符 3 失败:", err)
           } else {
               os.Exit(3) // 成功写入则退出码为 3
           }
       default:
           panic("unrecognized value for GO_TEST_STD_PIPE_HELPER")
       }
       os.Exit(0) // 对于 stdout/stderr，正常退出表示父进程测试失败
   }
   ```
* **假设的输入与输出:** 父进程会设置不同的环境变量，子进程的输出取决于环境变量的值和管道的状态。父进程会检查子进程的退出状态和错误信息。

**3. `testClosedPipeRace(t *testing.T, read bool)`**

* **功能:** 测试在高并发情况下，当一个 goroutine 正在读取或写入管道时，另一个 goroutine 关闭管道的读端或写端是否会导致 race condition（竞争条件）。
* **实现原理:**
    1. 创建一个管道。
    2. 启动一个 goroutine，该 goroutine 会在短暂延迟后关闭管道的读端（如果 `read` 为 true）或写端（如果 `read` 为 false）。
    3. 主 goroutine 尝试读取（如果 `read` 为 true）或写入（如果 `read` 为 false）管道。
    4. 断言读取或写入操作会返回一个预期的错误，通常是 `fs.ErrClosed`。
* **Go 代码示例:** 难以用一个简洁的例子完全复现竞态条件，但可以展示基本思路：
   ```go
   package main

   import (
       "fmt"
       "os"
       "time"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }

       go func() {
           time.Sleep(10 * time.Millisecond)
           r.Close() // 或 w.Close()
       }()

       buf := make([]byte, 1)
       _, err = r.Read(buf) // 或 w.Write([]byte("data"))
       if err != nil {
           fmt.Println("读取/写入结果:", err)
       } else {
           fmt.Println("读取/写入意外成功")
       }
   }
   ```
* **假设的输入与输出:** 没有明确的输入，依赖于 goroutine 的调度和管道的关闭时机。 输出是读取或写入操作是否返回预期的错误。

**4. `TestClosedPipeRaceRead(t *testing.T)` 和 `TestClosedPipeRaceWrite(t *testing.T)`**

* **功能:**  分别是 `testClosedPipeRace` 的两个具体用例，分别测试在读取时关闭和在写入时关闭的情况。

**5. `TestReadNonblockingFd(t *testing.T)`**

* **功能:** 测试在非阻塞的文件描述符上进行读取操作，如果没有数据可读时，是否会返回 `EAGAIN` 错误。
* **实现原理:**
    1. 创建一个管道。
    2. 将管道的读端设置为非阻塞模式。
    3. 尝试从非阻塞的读端读取数据。
    4. 断言如果没有数据可读，应该返回 `syscall.EAGAIN` 错误。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }
       defer r.Close()
       defer w.Close()

       fd := syscallDescriptor(r.Fd())
       syscall.SetNonblock(fd, true)

       buf := make([]byte, 1)
       _, err = r.Read(buf)
       if err == syscall.EAGAIN {
           fmt.Println("读取非阻塞管道，得到 EAGAIN")
       } else if err != nil {
           fmt.Println("读取非阻塞管道出错:", err)
       } else {
           fmt.Println("读取非阻塞管道成功，读取到数据")
       }
   }

   // 辅助函数，用于获取文件描述符的底层表示
   func syscallDescriptor(fd uintptr) int {
       return int(fd)
   }
   ```
* **假设的输入与输出:** 如果在读取前管道中没有数据，则期望输出包含 "得到 EAGAIN"。

**6. `TestCloseWithBlockingReadByNewFile(t *testing.T)` 和 `TestCloseWithBlockingReadByFd(t *testing.T)`**

* **功能:** 测试当一个 goroutine 正在阻塞地读取管道时，关闭管道的读端是否能够正常中断读取操作，而不会导致死锁。
* **实现原理:**
    1. 创建一个管道。
    2. 启动一个 goroutine，该 goroutine 会阻塞地尝试从管道读取数据。
    3. 主 goroutine 在短暂延迟后关闭管道的读端。
    4. 断言读取操作会因为管道关闭而返回 `io.EOF` 或 `fs.ErrClosed` 错误。
* **`TestCloseWithBlockingReadByNewFile`**: 使用 `os.NewFile` 创建文件对象，确保是阻塞模式。
* **`TestCloseWithBlockingReadByFd`**:  直接使用 `os.Pipe` 创建的文件对象，并通过调用 `Fd()` 确保处于阻塞模式。
* **Go 代码示例 (两个测试共享 `testCloseWithBlockingRead` 函数):**
   ```go
   package main

   import (
       "fmt"
       "io"
       "os"
       "time"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }

       enteringRead := make(chan struct{})
       done := make(chan struct{})

       go func() {
           var b [1]byte
           close(enteringRead)
           _, err := r.Read(b[:])
           if err == io.EOF {
               fmt.Println("读取结束，得到 EOF")
           } else if err != nil {
               fmt.Println("读取出错:", err)
           } else {
               fmt.Println("读取意外成功")
           }
           close(done)
       }()

       <-enteringRead
       time.Sleep(10 * time.Millisecond)
       r.Close()
       w.Close() // 为了确保读取的 goroutine 能退出
       <-done
   }
   ```
* **假设的输入与输出:** 期望输出包含 "读取结束，得到 EOF" 或类似的表示管道已关闭的错误信息。

**7. `TestPipeEOF(t *testing.T)`**

* **功能:** 测试当管道的写端关闭后，阻塞在读端的读取操作会返回 `io.EOF`。
* **实现原理:**
    1. 创建一个管道。
    2. 启动一个 goroutine 向管道写入少量数据，然后关闭写端。
    3. 主 goroutine 阻塞地从管道读取数据。
    4. 断言在写端关闭后，读取操作会返回 `io.EOF`。
* **Go 代码示例 (共享 `testPipeEOF` 函数):**
   ```go
   package main

   import (
       "bufio"
       "bytes"
       "fmt"
       "io"
       "os"
       "time"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }

       write := make(chan int, 1)
       writerDone := make(chan struct{})

       go func() {
           defer close(writerDone)
           for i := range write {
               time.Sleep(10 * time.Millisecond)
               fmt.Fprintf(w, "line %d\n", i)
           }
           time.Sleep(10 * time.Millisecond)
           w.Close()
       }()

       rbuf := bufio.NewReader(r)
       for i := 0; i < 3; i++ {
           write <- i
           b, err := rbuf.ReadBytes('\n')
           if err != nil {
               fmt.Println("读取数据出错:", err)
               return
           }
           fmt.Printf("读取到: %s\n", bytes.TrimSpace(b))
       }

       close(write)
       b, err := rbuf.ReadBytes('\n')
       if err == io.EOF {
           fmt.Println("读取结束，得到 EOF")
       } else {
           fmt.Printf("读取结果: %q, %v\n", b, err)
       }

       r.Close()
       <-writerDone
   }
   ```
* **假设的输入与输出:**  先读取到写入的数据，最后会输出 "读取结束，得到 EOF"。

**8. `TestFdRace(t *testing.T)`**

* **功能:** 测试并发地调用管道写端的 `Fd()` 方法是否存在 race condition。
* **实现原理:**  创建多个 goroutine 并发地调用 `w.Fd()`，旨在发现潜在的并发访问问题。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "os"
       "sync"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }
       defer r.Close()
       defer w.Close()

       var wg sync.WaitGroup
       call := func() {
           defer wg.Done()
           w.Fd()
       }

       const tries = 100
       for i := 0; i < tries; i++ {
           wg.Add(1)
           go call()
       }
       wg.Wait()
       fmt.Println("并发调用 Fd() 完成")
   }
   ```
* **假设的输入与输出:** 如果没有 race condition，程序会正常结束并输出 "并发调用 Fd() 完成"。

**9. `TestFdReadRace(t *testing.T)`**

* **功能:** 测试当一个 goroutine 正在阻塞地读取管道时，另一个 goroutine 调用管道读端的 `Fd()` 方法是否存在 race condition。
* **实现原理:**
    1. 创建一个管道。
    2. 启动一个 goroutine 阻塞地读取管道。
    3. 另一个 goroutine 在短暂延迟后调用管道读端的 `Fd()` 方法。
    4. 随后，向管道写入数据并关闭读端，以解除读取 goroutine 的阻塞。
    5. 旨在检测在阻塞读取期间调用 `Fd()` 是否会导致问题。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "os"
       "sync"
       "time"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }
       defer r.Close()
       defer w.Close()

       const count = 10
       c := make(chan bool, 1)
       var wg sync.WaitGroup

       wg.Add(1)
       go func() {
           defer wg.Done()
           var buf [count]byte
           r.SetReadDeadline(time.Now().Add(time.Minute))
           c <- true
           if _, err := r.Read(buf[:]); os.IsTimeout(err) {
               fmt.Println("读取超时")
           } else if err != nil {
               fmt.Println("读取出错:", err)
           } else {
               fmt.Println("读取到数据")
           }
       }()

       wg.Add(1)
       go func() {
           defer wg.Done()
           <-c
           time.Sleep(10 * time.Millisecond)
           r.Fd() // 调用 Fd()

           w.Write(make([]byte, count))
           r.Close()
       }()

       wg.Wait()
       fmt.Println("测试完成")
   }
   ```
* **假设的输入与输出:**  程序应该能够正常结束，读取 goroutine 能够因为写入数据或关闭管道而退出，而不是一直阻塞。

**总结其功能:**

总而言之，`go/src/os/pipe_test.go` 这个文件全面地测试了 Go 语言中管道的各种行为，包括：

* **Broken Pipe 错误 (EPIPE):**  验证在写入已关闭读端的管道时是否能正确返回错误。
* **标准流的 Broken Pipe:**  测试子进程向已关闭的父进程标准流写入时的行为和信号处理。
* **并发场景下的管道操作:**  检查在高并发情况下关闭管道是否会导致 race condition。
* **非阻塞管道的读取:**  验证在非阻塞模式下读取空管道是否返回 `EAGAIN`。
* **阻塞读取与管道关闭:**  确保关闭管道能够中断阻塞的读取操作。
* **管道的 EOF 行为:**  验证当写端关闭后，读端会收到 `io.EOF`。
* **并发访问文件描述符:**  测试并发调用 `Fd()` 方法是否存在 race condition。

**易犯错的点 (使用者角度):**

* **忘记处理 `EPIPE` 错误:** 当一个进程向另一个已经关闭了读取端的管道写入数据时，会收到 `EPIPE` 信号（或错误）。如果程序没有正确处理这个信号或错误，可能会导致程序崩溃或行为异常。
   ```go
   package main

   import (
       "fmt"
       "os"
   )

   func main() {
       r, w, err := os.Pipe()
       if err != nil {
           fmt.Println("创建管道失败:", err)
           return
       }
       r.Close() // 假设读端被关闭

       _, err = w.Write([]byte("数据"))
       if err != nil {
           fmt.Println("写入管道出错:", err) // 应该处理 EPIPE 错误
       }
   }
   ```
* **在多 goroutine 环境下不注意管道的生命周期:**  如果一个 goroutine 持有管道的写端，而另一个 goroutine 意外关闭了读端，那么写操作可能会失败并返回 `EPIPE`。反之亦然。需要仔细管理管道的关闭时机。
* **对阻塞和非阻塞 I/O 的理解不足:** 在使用非阻塞 I/O 时，需要正确处理 `EAGAIN` 错误，并在没有数据可读时避免忙轮询。
* **在子进程中使用继承的文件描述符时未考虑父进程的管道状态:** 如果父进程关闭了管道的读端，而子进程仍然尝试向该管道的写端写入，子进程会收到 `SIGPIPE` 信号。

通过这些测试用例，Go 语言的开发者可以确保 `os` 包中的管道功能在各种情况下都能稳定可靠地工作。

Prompt: 
```
这是路径为go/src/os/pipe_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Test broken pipes on Unix systems.
//
//go:build !plan9 && !js && !wasip1

package os_test

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/testenv"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestEPIPE(t *testing.T) {
	// This test cannot be run in parallel because of a race similar
	// to the one reported in https://go.dev/issue/22315.
	//
	// Even though the pipe is opened with O_CLOEXEC, if another test forks in
	// between the call to os.Pipe and the call to r.Close, that child process can
	// retain an open copy of r's file descriptor until it execs. If one of our
	// Write calls occurs during that interval it can spuriously succeed,
	// buffering the write to the child's copy of the pipe (even though the child
	// will not actually read the buffered bytes).

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	expect := syscall.EPIPE
	if runtime.GOOS == "windows" {
		// 232 is Windows error code ERROR_NO_DATA, "The pipe is being closed".
		expect = syscall.Errno(232)
	}
	// Every time we write to the pipe we should get an EPIPE.
	for i := 0; i < 20; i++ {
		_, err = w.Write([]byte("hi"))
		if err == nil {
			t.Fatal("unexpected success of Write to broken pipe")
		}
		if pe, ok := err.(*fs.PathError); ok {
			err = pe.Err
		}
		if se, ok := err.(*os.SyscallError); ok {
			err = se.Err
		}
		if err != expect {
			t.Errorf("iteration %d: got %v, expected %v", i, err, expect)
		}
	}
}

func TestStdPipe(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Skip("Windows doesn't support SIGPIPE")
	}

	if os.Getenv("GO_TEST_STD_PIPE_HELPER") != "" {
		if os.Getenv("GO_TEST_STD_PIPE_HELPER_SIGNAL") != "" {
			signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
		}
		switch os.Getenv("GO_TEST_STD_PIPE_HELPER") {
		case "1":
			os.Stdout.Write([]byte("stdout"))
		case "2":
			os.Stderr.Write([]byte("stderr"))
		case "3":
			if _, err := os.NewFile(3, "3").Write([]byte("3")); err == nil {
				os.Exit(3)
			}
		default:
			panic("unrecognized value for GO_TEST_STD_PIPE_HELPER")
		}
		// For stdout/stderr, we should have crashed with a broken pipe error.
		// The caller will be looking for that exit status,
		// so just exit normally here to cause a failure in the caller.
		// For descriptor 3, a normal exit is expected.
		os.Exit(0)
	}

	testenv.MustHaveExec(t)
	// This test cannot be run in parallel due to the same race as for TestEPIPE.
	// (We expect a write to a closed pipe can fail, but a concurrent fork of a
	// child process can cause the pipe to unexpectedly remain open.)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Invoke the test program to run the test and write to a closed pipe.
	// If sig is false:
	// writing to stdout or stderr should cause an immediate SIGPIPE;
	// writing to descriptor 3 should fail with EPIPE and then exit 0.
	// If sig is true:
	// all writes should fail with EPIPE and then exit 0.
	for _, sig := range []bool{false, true} {
		for dest := 1; dest < 4; dest++ {
			cmd := testenv.Command(t, os.Args[0], "-test.run", "TestStdPipe")
			cmd.Stdout = w
			cmd.Stderr = w
			cmd.ExtraFiles = []*os.File{w}
			cmd.Env = append(os.Environ(), fmt.Sprintf("GO_TEST_STD_PIPE_HELPER=%d", dest))
			if sig {
				cmd.Env = append(cmd.Env, "GO_TEST_STD_PIPE_HELPER_SIGNAL=1")
			}
			if err := cmd.Run(); err == nil {
				if !sig && dest < 3 {
					t.Errorf("unexpected success of write to closed pipe %d sig %t in child", dest, sig)
				}
			} else if ee, ok := err.(*exec.ExitError); !ok {
				t.Errorf("unexpected exec error type %T: %v", err, err)
			} else if ws, ok := ee.Sys().(syscall.WaitStatus); !ok {
				t.Errorf("unexpected wait status type %T: %v", ee.Sys(), ee.Sys())
			} else if ws.Signaled() && ws.Signal() == syscall.SIGPIPE {
				if sig || dest > 2 {
					t.Errorf("unexpected SIGPIPE signal for descriptor %d sig %t", dest, sig)
				}
			} else {
				t.Errorf("unexpected exit status %v for descriptor %d sig %t", err, dest, sig)
			}
		}
	}

	// Test redirecting stdout but not stderr.  Issue 40076.
	cmd := testenv.Command(t, os.Args[0], "-test.run", "TestStdPipe")
	cmd.Stdout = w
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(cmd.Environ(), "GO_TEST_STD_PIPE_HELPER=1")
	if err := cmd.Run(); err == nil {
		t.Errorf("unexpected success of write to closed stdout")
	} else if ee, ok := err.(*exec.ExitError); !ok {
		t.Errorf("unexpected exec error type %T: %v", err, err)
	} else if ws, ok := ee.Sys().(syscall.WaitStatus); !ok {
		t.Errorf("unexpected wait status type %T: %v", ee.Sys(), ee.Sys())
	} else if !ws.Signaled() || ws.Signal() != syscall.SIGPIPE {
		t.Errorf("unexpected exit status %v for write to closed stdout", err)
	}
	if output := stderr.Bytes(); len(output) > 0 {
		t.Errorf("unexpected output on stderr: %s", output)
	}
}

func testClosedPipeRace(t *testing.T, read bool) {
	// This test cannot be run in parallel due to the same race as for TestEPIPE.
	// (We expect a write to a closed pipe can fail, but a concurrent fork of a
	// child process can cause the pipe to unexpectedly remain open.)

	limit := 1
	if !read {
		// Get the amount we have to write to overload a pipe
		// with no reader.
		limit = 131073
		if b, err := os.ReadFile("/proc/sys/fs/pipe-max-size"); err == nil {
			if i, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				limit = i + 1
			}
		}
		t.Logf("using pipe write limit of %d", limit)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	// Close the read end of the pipe in a goroutine while we are
	// writing to the write end, or vice-versa.
	go func() {
		// Give the main goroutine a chance to enter the Read or
		// Write call. This is sloppy but the test will pass even
		// if we close before the read/write.
		time.Sleep(20 * time.Millisecond)

		var err error
		if read {
			err = r.Close()
		} else {
			err = w.Close()
		}
		if err != nil {
			t.Error(err)
		}
	}()

	b := make([]byte, limit)
	if read {
		_, err = r.Read(b[:])
	} else {
		_, err = w.Write(b[:])
	}
	if err == nil {
		t.Error("I/O on closed pipe unexpectedly succeeded")
	} else if pe, ok := err.(*fs.PathError); !ok {
		t.Errorf("I/O on closed pipe returned unexpected error type %T; expected fs.PathError", pe)
	} else if pe.Err != fs.ErrClosed {
		t.Errorf("got error %q but expected %q", pe.Err, fs.ErrClosed)
	} else {
		t.Logf("I/O returned expected error %q", err)
	}
}

func TestClosedPipeRaceRead(t *testing.T) {
	testClosedPipeRace(t, true)
}

func TestClosedPipeRaceWrite(t *testing.T) {
	testClosedPipeRace(t, false)
}

// Issue 20915: Reading on nonblocking fd should not return "waiting
// for unsupported file type." Currently it returns EAGAIN; it is
// possible that in the future it will simply wait for data.
func TestReadNonblockingFd(t *testing.T) {
	switch runtime.GOOS {
	case "windows":
		t.Skip("Windows doesn't support SetNonblock")
	}
	if os.Getenv("GO_WANT_READ_NONBLOCKING_FD") == "1" {
		fd := syscallDescriptor(os.Stdin.Fd())
		syscall.SetNonblock(fd, true)
		defer syscall.SetNonblock(fd, false)
		_, err := os.Stdin.Read(make([]byte, 1))
		if err != nil {
			if perr, ok := err.(*fs.PathError); !ok || perr.Err != syscall.EAGAIN {
				t.Fatalf("read on nonblocking stdin got %q, should have gotten EAGAIN", err)
			}
		}
		os.Exit(0)
	}

	testenv.MustHaveExec(t)
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cmd := testenv.Command(t, os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(cmd.Environ(), "GO_WANT_READ_NONBLOCKING_FD=1")
	cmd.Stdin = r
	output, err := cmd.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Errorf("child process failed: %v", err)
	}
}

func TestCloseWithBlockingReadByNewFile(t *testing.T) {
	t.Parallel()

	var p [2]syscallDescriptor
	err := syscall.Pipe(p[:])
	if err != nil {
		t.Fatal(err)
	}
	// os.NewFile returns a blocking mode file.
	testCloseWithBlockingRead(t, os.NewFile(uintptr(p[0]), "reader"), os.NewFile(uintptr(p[1]), "writer"))
}

func TestCloseWithBlockingReadByFd(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Calling Fd will put the file into blocking mode.
	_ = r.Fd()
	testCloseWithBlockingRead(t, r, w)
}

// Test that we don't let a blocking read prevent a close.
func testCloseWithBlockingRead(t *testing.T, r, w *os.File) {
	var (
		enteringRead = make(chan struct{})
		done         = make(chan struct{})
	)
	go func() {
		var b [1]byte
		close(enteringRead)
		_, err := r.Read(b[:])
		if err == nil {
			t.Error("I/O on closed pipe unexpectedly succeeded")
		}

		if pe, ok := err.(*fs.PathError); ok {
			err = pe.Err
		}
		if err != io.EOF && err != fs.ErrClosed {
			t.Errorf("got %v, expected EOF or closed", err)
		}
		close(done)
	}()

	// Give the goroutine a chance to enter the Read
	// or Write call. This is sloppy but the test will
	// pass even if we close before the read/write.
	<-enteringRead
	time.Sleep(20 * time.Millisecond)

	if err := r.Close(); err != nil {
		t.Error(err)
	}
	// r.Close has completed, but since we assume r is in blocking mode that
	// probably didn't unblock the call to r.Read. Close w to unblock it.
	w.Close()
	<-done
}

func TestPipeEOF(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	testPipeEOF(t, r, w)
}

// testPipeEOF tests that when the write side of a pipe or FIFO is closed,
// a blocked Read call on the reader side returns io.EOF.
//
// This scenario previously failed to unblock the Read call on darwin.
// (See https://go.dev/issue/24164.)
func testPipeEOF(t *testing.T, r io.ReadCloser, w io.WriteCloser) {
	// parkDelay is an arbitrary delay we wait for a pipe-reader goroutine to park
	// before issuing the corresponding write. The test should pass no matter what
	// delay we use, but with a longer delay is has a higher chance of detecting
	// poller bugs.
	parkDelay := 10 * time.Millisecond
	if testing.Short() {
		parkDelay = 100 * time.Microsecond
	}
	writerDone := make(chan struct{})
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("error closing reader: %v", err)
		}
		<-writerDone
	}()

	write := make(chan int, 1)
	go func() {
		defer close(writerDone)

		for i := range write {
			time.Sleep(parkDelay)
			_, err := fmt.Fprintf(w, "line %d\n", i)
			if err != nil {
				t.Errorf("error writing to fifo: %v", err)
				return
			}
		}

		time.Sleep(parkDelay)
		if err := w.Close(); err != nil {
			t.Errorf("error closing writer: %v", err)
		}
	}()

	rbuf := bufio.NewReader(r)
	for i := 0; i < 3; i++ {
		write <- i
		b, err := rbuf.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s\n", bytes.TrimSpace(b))
	}

	close(write)
	b, err := rbuf.ReadBytes('\n')
	if err != io.EOF || len(b) != 0 {
		t.Errorf(`ReadBytes: %q, %v; want "", io.EOF`, b, err)
	}
}

// Issue 24481.
func TestFdRace(t *testing.T) {
	// This test starts 100 simultaneous goroutines, which could bury a more
	// interesting stack if this or some other test happens to panic. It is also
	// nearly instantaneous, so any latency benefit from running it in parallel
	// would be minimal.

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	var wg sync.WaitGroup
	call := func() {
		defer wg.Done()
		w.Fd()
	}

	const tries = 100
	for i := 0; i < tries; i++ {
		wg.Add(1)
		go call()
	}
	wg.Wait()
}

func TestFdReadRace(t *testing.T) {
	t.Parallel()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	const count = 10

	c := make(chan bool, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var buf [count]byte
		r.SetReadDeadline(time.Now().Add(time.Minute))
		c <- true
		if _, err := r.Read(buf[:]); os.IsTimeout(err) {
			t.Error("read timed out")
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-c
		// Give the other goroutine a chance to enter the Read.
		// It doesn't matter if this occasionally fails, the test
		// will still pass, it just won't test anything.
		time.Sleep(10 * time.Millisecond)
		r.Fd()

		// The bug was that Fd would hang until Read timed out.
		// If the bug is fixed, then writing to w and closing r here
		// will cause the Read to exit before the timeout expires.
		w.Write(make([]byte, count))
		r.Close()
	}()

	wg.Wait()
}

"""



```