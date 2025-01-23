Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `go/src/internal/poll/fd_unix.go` file and illustrate its purpose with examples. This involves identifying the main data structure, its methods, and how they interact with the operating system.

**2. Initial Scan and Keyword Identification:**

I'll first scan the code for keywords and prominent structures. I see:

* `package poll`:  This tells us it's part of a polling mechanism, likely for I/O operations.
* `FD struct`: This is clearly the central data structure. It holds information about a file descriptor.
* `Sysfd int`: A system file descriptor. This is the OS-level identifier.
* `Read`, `Write`, `Pread`, `Pwrite`, `Accept`, `ReadFrom`, `WriteTo`, `ReadMsg`, `WriteMsg`: These method names strongly suggest I/O operations.
* `syscall`: Interactions with the operating system's system calls.
* `pollDesc`:  Another struct, likely related to the polling mechanism.
* `isBlocking`: Indicates whether the file descriptor is in blocking or non-blocking mode.
* `incref`, `decref`:  Reference counting, crucial for managing the lifetime of the file descriptor.
* `fdMutex`:  A mutex to protect access to the file descriptor.

**3. Deconstructing the `FD` Struct:**

The `FD` struct is the heart of the file. I'll analyze its fields:

* **`fdmu fdMutex`**: Ensures thread-safe access to the underlying file descriptor, especially for `Read` and `Write`.
* **`Sysfd int`**:  The actual integer file descriptor from the OS. Immutable after initialization.
* **`SysFile`**:  An embedded struct (not shown in this snippet). I'll assume it holds platform-specific file information.
* **`pd pollDesc`**:  Manages the polling aspect. It's likely responsible for registering and waiting for I/O events.
* **`csema uint32`**: A semaphore used to signal when the file descriptor is closed. This is important for synchronizing the `Close` operation.
* **`isBlocking uint32`**:  Indicates blocking or non-blocking I/O.
* **`IsStream bool`**: Differentiates between stream-based (TCP) and packet-based (UDP) sockets. This influences how `Read` handles EOF.
* **`ZeroReadIsEOF bool`**:  For stream sockets, a zero-byte read means EOF. Not for message-based sockets.
* **`isFile bool`**:  Indicates whether it's a regular file or a socket.

**4. Analyzing Key Methods:**

Now I'll focus on the important methods and their functionalities:

* **`Init(net string, pollable bool)`**: Initializes the `FD`. Crucially, it sets up the polling mechanism (`pd.init`) if `pollable` is true. It handles the distinction between "file" and network connections.
* **`destroy()`**:  Closes the underlying file descriptor and releases the close semaphore. It's called when the reference count goes to zero.
* **`Close()`**: Decrements the reference count. If the count reaches zero, it calls `destroy`. It also unblocks any pending I/O operations using `pd.evict()`. The semaphore `csema` is used to wait until the actual close happens in non-blocking mode.
* **`SetBlocking()`**: Switches the file descriptor to blocking mode.
* **`Read(p []byte)`**: The core reading method. It uses the polling mechanism (`pd`) for non-blocking reads and falls back to direct system calls for blocking reads. It handles `EAGAIN` (try again) errors.
* **`Pread(p []byte, off int64)`**:  Performs a "pread" (read at a specific offset), which is independent of the current file pointer. It doesn't use the polling mechanism.
* **`ReadFrom(...)`**: Reads data from a socket, along with the source address. Uses the polling mechanism.
* **`ReadMsg(...)`**: Reads data, out-of-band data, and flags from a socket. Uses the polling mechanism.
* **`Write(p []byte)`**: The core writing method. Similar to `Read`, it uses the polling mechanism for non-blocking writes. It also has logic to handle large writes in chunks (`maxRW`).
* **`Pwrite(p []byte, off int64)`**: Performs a "pwrite" (write at a specific offset). Doesn't use polling.
* **`WriteTo(...)`**: Sends data to a specific socket address. Uses the polling mechanism.
* **`WriteMsg(...)`**: Sends data, out-of-band data, and address to a socket. Uses the polling mechanism.
* **`Accept()`**: Accepts a new connection on a listening socket. Uses the polling mechanism.
* **`DupCloseOnExec(fd int)` and `Dup()`**: Duplicates a file descriptor, optionally marking it as close-on-exec.
* **`WaitWrite()`**:  Waits until data can be written (used by the `net` package).
* **`RawRead/RawWrite()`**:  Provides a way to perform custom read/write operations while still using the polling mechanism.

**5. Inferring Go Functionality:**

Based on the methods, I can infer that this code is a fundamental part of Go's network and file I/O implementation. It provides the low-level mechanisms for reading and writing data to files and network sockets, handling both blocking and non-blocking I/O using a poll-based approach. It's likely used by higher-level packages like `net` and `os`.

**6. Creating Examples:**

To illustrate the functionality, I'll create simple examples demonstrating:

* Opening a file and reading/writing.
* Creating a network connection (TCP client/server) and sending/receiving data.
* Using non-blocking I/O with polling.

**7. Identifying Potential Pitfalls:**

I'll consider common mistakes users might make when working with file descriptors and I/O:

* **Forgetting to close file descriptors:**  Leads to resource leaks.
* **Mixing blocking and non-blocking I/O incorrectly:** Can lead to unexpected behavior or deadlocks.
* **Not handling `EAGAIN` errors correctly in non-blocking mode:**  Results in missed data or failed operations.
* **Incorrectly assuming `ZeroReadIsEOF` for all socket types.**

**8. Structuring the Answer:**

Finally, I'll structure the answer logically, starting with a general overview, then detailing the functionality of the `FD` struct and its methods. I'll include the Go code examples with explanations of the assumptions, inputs, and outputs. I'll also address potential pitfalls and explain any command-line parameter handling (although this specific code snippet doesn't directly handle command-line arguments).

This systematic approach allows me to thoroughly understand the code and provide a comprehensive and accurate answer to the prompt. It involves a combination of code reading, keyword analysis, logical deduction, and practical example creation.
这段代码是 Go 语言标准库 `internal/poll` 包中 `fd_unix.go` 文件的一部分。它定义了在 Unix-like 操作系统（包括 macOS, Linux 等）上进行文件和网络 I/O 操作的核心数据结构和方法。

**主要功能:**

1. **`FD` 结构体定义:**  定义了一个名为 `FD` 的结构体，用于封装一个文件描述符(`Sysfd`)以及与其相关的状态信息。这个结构体是 Go 语言网络和操作系统相关包（如 `net` 和 `os`）中用于表示网络连接或操作系统文件的基础。

2. **文件描述符管理:**  `FD` 结构体负责管理底层的系统文件描述符，包括其生命周期、引用计数以及关闭操作。

3. **阻塞与非阻塞 I/O:**  `FD` 结构体支持阻塞和非阻塞两种 I/O 模式，并通过 `SetBlocking` 方法进行切换。

4. **I/O 操作:**  提供了多种方法用于执行 I/O 操作，例如：
    * **`Read` 和 `Write`:**  实现 `io.Reader` 和 `io.Writer` 接口，用于读取和写入数据。
    * **`Pread` 和 `Pwrite`:**  在指定偏移量处读取和写入数据，不影响当前文件指针。
    * **`ReadFrom` 和 `WriteTo`:**  用于 UDP 等无连接协议的读取和写入操作，可以获取或指定源/目标地址。
    * **`ReadMsg` 和 `WriteMsg`:**  更底层的消息读取和写入操作，可以处理带外数据和标志。
    * **`Accept`:**  用于监听 socket 接受新的连接。

5. **I/O 多路复用 (Polling):**  通过内嵌的 `pd pollDesc` 结构体，实现了与 Go 运行时网络轮询器的集成。这使得在非阻塞模式下，可以高效地等待文件描述符变为可读或可写。

6. **错误处理:**  封装了底层的系统调用，并对常见的错误（如 `EINTR`, `EAGAIN`）进行处理，以便更好地与 Go 的错误模型集成。

7. **原子操作和同步:**  使用 `sync/atomic` 包中的原子操作和 `fdMutex` 来保证对 `FD` 结构体的并发安全访问。

**Go 语言功能实现推断:**

这段代码是 Go 语言 **网络编程** 和 **文件 I/O** 功能的基础实现。它为 `net` 包中的 `TCPConn`, `UDPConn`, `UnixConn` 等网络连接类型以及 `os` 包中的 `File` 类型提供了底层的 I/O 操作支持。

**Go 代码举例说明:**

以下代码示例展示了如何使用 `net` 包创建一个 TCP 服务端并进行数据读取，其中 `net` 包内部会使用 `internal/poll` 包的 `FD` 结构体。

```go
package main

import (
	"fmt"
	"io"
	"net"
	"time"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("读取错误:", err)
			}
			return
		}
		fmt.Printf("接收到数据: %s", buf[:n])
		_, err = conn.Write([]byte("已收到: " + string(buf[:n])))
		if err != nil {
			fmt.Println("写入错误:", err)
			return
		}
	}
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("监听错误:", err)
		return
	}
	defer listener.Close()
	fmt.Println("服务器已启动，监听端口 8080")

	for {
		conn, err := listener.Accept() // 内部会调用 poll.FD 的 Accept 方法
		if err != nil {
			fmt.Println("接受连接错误:", err)
			continue
		}
		fmt.Println("接受到来自", conn.RemoteAddr(), "的连接")
		go handleConnection(conn)
	}
}
```

**假设的输入与输出:**

1. **服务端启动:**  服务端程序启动后，会监听 `127.0.0.1:8080` 端口。

2. **客户端连接:**  当有客户端连接到该端口时，`listener.Accept()` 方法会返回一个新的 `net.Conn` 对象，该对象内部封装了一个 `poll.FD` 实例。

3. **客户端发送数据:**  假设客户端发送字符串 "Hello, Server!"。

4. **服务端接收数据:**  `conn.Read(buf)` 方法（内部会调用 `poll.FD` 的 `Read` 方法）会读取到客户端发送的数据。

5. **服务端输出:**  控制台会输出：`接收到数据: Hello, Server!`

6. **服务端发送响应:**  `conn.Write([]byte("已收到: Hello, Server!"))` 方法（内部会调用 `poll.FD` 的 `Write` 方法）会将响应数据发送回客户端。

7. **客户端接收响应:**  客户端会接收到服务端发送的 "已收到: Hello, Server!"。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并通过 `os.Args` 获取，然后传递给其他函数或结构体进行处理。在这个 `poll` 包的低层实现中，它更多关注的是文件描述符的操作，而不是应用程序级别的参数。

**使用者易犯错的点:**

1. **忘记关闭文件描述符:**  如果 `FD` 结构体对应的文件描述符没有被正确关闭（通常通过调用 `Close()` 方法），会导致资源泄漏，最终可能耗尽系统资源。例如：

   ```go
   // 错误示例：忘记关闭文件
   func readFile(filename string) {
       file, err := os.Open(filename)
       if err != nil {
           fmt.Println("打开文件失败:", err)
           return
       }
       // ... 读取文件内容，但是忘记调用 file.Close()
   }
   ```

2. **在阻塞和非阻塞模式下的误用:**  如果文件描述符被设置为非阻塞模式，但是代码仍然以阻塞的方式读取或写入，可能会导致意外的行为（例如立即返回错误）。反之亦然。

   ```go
   // 错误示例：在非阻塞 socket 上进行阻塞读取
   func readNonBlocking(conn net.Conn) {
       // 假设 conn 是一个非阻塞 socket
       buf := make([]byte, 1024)
       n, err := conn.Read(buf) // 如果没有数据可读，会立即返回错误 (EAGAIN/EWOULDBLOCK)
       if err != nil {
           fmt.Println("读取错误:", err)
           return
       }
       fmt.Println("读取到:", n, "字节")
   }
   ```
   正确的做法是在非阻塞模式下，需要配合使用轮询机制（如 `select`, `poll`, epoll）来等待文件描述符变为可读或可写。`internal/poll` 包内部已经处理了这些轮询机制。

3. **不理解 `ZeroReadIsEOF` 的含义:** 对于流式 socket (例如 TCP)，当 `Read` 方法返回 0 且没有错误时，表示连接已关闭（EOF）。但是对于消息型 socket (例如 UDP)，返回 0 可能只是表示接收到了一个空的数据包，并不意味着连接关闭。错误地假设所有 socket 都是流式的可能会导致逻辑错误。

总而言之，`go/src/internal/poll/fd_unix.go` 中的 `FD` 结构体及其相关方法是 Go 语言在 Unix-like 系统上进行底层 I/O 操作的关键组成部分，为上层网络和操作系统相关的包提供了基础支持。理解其功能有助于更深入地理解 Go 语言的 I/O 模型。

### 提示词
```
这是路径为go/src/internal/poll/fd_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix || (js && wasm) || wasip1

package poll

import (
	"internal/itoa"
	"internal/syscall/unix"
	"io"
	"sync/atomic"
	"syscall"
)

// FD is a file descriptor. The net and os packages use this type as a
// field of a larger type representing a network connection or OS file.
type FD struct {
	// Lock sysfd and serialize access to Read and Write methods.
	fdmu fdMutex

	// System file descriptor. Immutable until Close.
	Sysfd int

	// Platform dependent state of the file descriptor.
	SysFile

	// I/O poller.
	pd pollDesc

	// Semaphore signaled when file is closed.
	csema uint32

	// Non-zero if this file has been set to blocking mode.
	isBlocking uint32

	// Whether this is a streaming descriptor, as opposed to a
	// packet-based descriptor like a UDP socket. Immutable.
	IsStream bool

	// Whether a zero byte read indicates EOF. This is false for a
	// message based socket connection.
	ZeroReadIsEOF bool

	// Whether this is a file rather than a network socket.
	isFile bool
}

// Init initializes the FD. The Sysfd field should already be set.
// This can be called multiple times on a single FD.
// The net argument is a network name from the net package (e.g., "tcp"),
// or "file".
// Set pollable to true if fd should be managed by runtime netpoll.
func (fd *FD) Init(net string, pollable bool) error {
	fd.SysFile.init()

	// We don't actually care about the various network types.
	if net == "file" {
		fd.isFile = true
	}
	if !pollable {
		fd.isBlocking = 1
		return nil
	}
	err := fd.pd.init(fd)
	if err != nil {
		// If we could not initialize the runtime poller,
		// assume we are using blocking mode.
		fd.isBlocking = 1
	}
	return err
}

// Destroy closes the file descriptor. This is called when there are
// no remaining references.
func (fd *FD) destroy() error {
	// Poller may want to unregister fd in readiness notification mechanism,
	// so this must be executed before CloseFunc.
	fd.pd.close()

	err := fd.SysFile.destroy(fd.Sysfd)

	fd.Sysfd = -1
	runtime_Semrelease(&fd.csema)
	return err
}

// Close closes the FD. The underlying file descriptor is closed by the
// destroy method when there are no remaining references.
func (fd *FD) Close() error {
	if !fd.fdmu.increfAndClose() {
		return errClosing(fd.isFile)
	}

	// Unblock any I/O.  Once it all unblocks and returns,
	// so that it cannot be referring to fd.sysfd anymore,
	// the final decref will close fd.sysfd. This should happen
	// fairly quickly, since all the I/O is non-blocking, and any
	// attempts to block in the pollDesc will return errClosing(fd.isFile).
	fd.pd.evict()

	// The call to decref will call destroy if there are no other
	// references.
	err := fd.decref()

	// Wait until the descriptor is closed. If this was the only
	// reference, it is already closed. Only wait if the file has
	// not been set to blocking mode, as otherwise any current I/O
	// may be blocking, and that would block the Close.
	// No need for an atomic read of isBlocking, increfAndClose means
	// we have exclusive access to fd.
	if fd.isBlocking == 0 {
		runtime_Semacquire(&fd.csema)
	}

	return err
}

// SetBlocking puts the file into blocking mode.
func (fd *FD) SetBlocking() error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	// Atomic store so that concurrent calls to SetBlocking
	// do not cause a race condition. isBlocking only ever goes
	// from 0 to 1 so there is no real race here.
	atomic.StoreUint32(&fd.isBlocking, 1)
	return syscall.SetNonblock(fd.Sysfd, false)
}

// Darwin and FreeBSD can't read or write 2GB+ files at a time,
// even on 64-bit systems.
// The same is true of socket implementations on many systems.
// See golang.org/issue/7812 and golang.org/issue/16266.
// Use 1GB instead of, say, 2GB-1, to keep subsequent reads aligned.
const maxRW = 1 << 30

// Read implements io.Reader.
func (fd *FD) Read(p []byte) (int, error) {
	if err := fd.readLock(); err != nil {
		return 0, err
	}
	defer fd.readUnlock()
	if len(p) == 0 {
		// If the caller wanted a zero byte read, return immediately
		// without trying (but after acquiring the readLock).
		// Otherwise syscall.Read returns 0, nil which looks like
		// io.EOF.
		// TODO(bradfitz): make it wait for readability? (Issue 15735)
		return 0, nil
	}
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, err
	}
	if fd.IsStream && len(p) > maxRW {
		p = p[:maxRW]
	}
	for {
		n, err := ignoringEINTRIO(syscall.Read, fd.Sysfd, p)
		if err != nil {
			n = 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, err
	}
}

// Pread wraps the pread system call.
func (fd *FD) Pread(p []byte, off int64) (int, error) {
	// Call incref, not readLock, because since pread specifies the
	// offset it is independent from other reads.
	// Similarly, using the poller doesn't make sense for pread.
	if err := fd.incref(); err != nil {
		return 0, err
	}
	if fd.IsStream && len(p) > maxRW {
		p = p[:maxRW]
	}
	var (
		n   int
		err error
	)
	for {
		n, err = syscall.Pread(fd.Sysfd, p, off)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		n = 0
	}
	fd.decref()
	err = fd.eofError(n, err)
	return n, err
}

// ReadFrom wraps the recvfrom network call.
func (fd *FD) ReadFrom(p []byte) (int, syscall.Sockaddr, error) {
	if err := fd.readLock(); err != nil {
		return 0, nil, err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, nil, err
	}
	for {
		n, sa, err := syscall.Recvfrom(fd.Sysfd, p, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			n = 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, sa, err
	}
}

// ReadFromInet4 wraps the recvfrom network call for IPv4.
func (fd *FD) ReadFromInet4(p []byte, from *syscall.SockaddrInet4) (int, error) {
	if err := fd.readLock(); err != nil {
		return 0, err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, err
	}
	for {
		n, err := unix.RecvfromInet4(fd.Sysfd, p, 0, from)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			n = 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, err
	}
}

// ReadFromInet6 wraps the recvfrom network call for IPv6.
func (fd *FD) ReadFromInet6(p []byte, from *syscall.SockaddrInet6) (int, error) {
	if err := fd.readLock(); err != nil {
		return 0, err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, err
	}
	for {
		n, err := unix.RecvfromInet6(fd.Sysfd, p, 0, from)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			n = 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, err
	}
}

// ReadMsg wraps the recvmsg network call.
func (fd *FD) ReadMsg(p []byte, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
	if err := fd.readLock(); err != nil {
		return 0, 0, 0, nil, err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, 0, 0, nil, err
	}
	for {
		n, oobn, sysflags, sa, err := syscall.Recvmsg(fd.Sysfd, p, oob, flags)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			// TODO(dfc) should n and oobn be set to 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, oobn, sysflags, sa, err
	}
}

// ReadMsgInet4 is ReadMsg, but specialized for syscall.SockaddrInet4.
func (fd *FD) ReadMsgInet4(p []byte, oob []byte, flags int, sa4 *syscall.SockaddrInet4) (int, int, int, error) {
	if err := fd.readLock(); err != nil {
		return 0, 0, 0, err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, 0, 0, err
	}
	for {
		n, oobn, sysflags, err := unix.RecvmsgInet4(fd.Sysfd, p, oob, flags, sa4)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			// TODO(dfc) should n and oobn be set to 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, oobn, sysflags, err
	}
}

// ReadMsgInet6 is ReadMsg, but specialized for syscall.SockaddrInet6.
func (fd *FD) ReadMsgInet6(p []byte, oob []byte, flags int, sa6 *syscall.SockaddrInet6) (int, int, int, error) {
	if err := fd.readLock(); err != nil {
		return 0, 0, 0, err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return 0, 0, 0, err
	}
	for {
		n, oobn, sysflags, err := unix.RecvmsgInet6(fd.Sysfd, p, oob, flags, sa6)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			// TODO(dfc) should n and oobn be set to 0
			if err == syscall.EAGAIN && fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		}
		err = fd.eofError(n, err)
		return n, oobn, sysflags, err
	}
}

// Write implements io.Writer.
func (fd *FD) Write(p []byte) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, err
	}
	var nn int
	for {
		max := len(p)
		if fd.IsStream && max-nn > maxRW {
			max = nn + maxRW
		}
		n, err := ignoringEINTRIO(syscall.Write, fd.Sysfd, p[nn:max])
		if n > 0 {
			if n > max-nn {
				// This can reportedly happen when using
				// some VPN software. Issue #61060.
				// If we don't check this we will panic
				// with slice bounds out of range.
				// Use a more informative panic.
				panic("invalid return from write: got " + itoa.Itoa(n) + " from a write of " + itoa.Itoa(max-nn))
			}
			nn += n
		}
		if nn == len(p) {
			return nn, err
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrUnexpectedEOF
		}
	}
}

// Pwrite wraps the pwrite system call.
func (fd *FD) Pwrite(p []byte, off int64) (int, error) {
	// Call incref, not writeLock, because since pwrite specifies the
	// offset it is independent from other writes.
	// Similarly, using the poller doesn't make sense for pwrite.
	if err := fd.incref(); err != nil {
		return 0, err
	}
	defer fd.decref()
	var nn int
	for {
		max := len(p)
		if fd.IsStream && max-nn > maxRW {
			max = nn + maxRW
		}
		n, err := syscall.Pwrite(fd.Sysfd, p[nn:max], off+int64(nn))
		if err == syscall.EINTR {
			continue
		}
		if n > 0 {
			nn += n
		}
		if nn == len(p) {
			return nn, err
		}
		if err != nil {
			return nn, err
		}
		if n == 0 {
			return nn, io.ErrUnexpectedEOF
		}
	}
}

// WriteToInet4 wraps the sendto network call for IPv4 addresses.
func (fd *FD) WriteToInet4(p []byte, sa *syscall.SockaddrInet4) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, err
	}
	for {
		err := unix.SendtoInet4(fd.Sysfd, p, 0, sa)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
}

// WriteToInet6 wraps the sendto network call for IPv6 addresses.
func (fd *FD) WriteToInet6(p []byte, sa *syscall.SockaddrInet6) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, err
	}
	for {
		err := unix.SendtoInet6(fd.Sysfd, p, 0, sa)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
}

// WriteTo wraps the sendto network call.
func (fd *FD) WriteTo(p []byte, sa syscall.Sockaddr) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, err
	}
	for {
		err := syscall.Sendto(fd.Sysfd, p, 0, sa)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
}

// WriteMsg wraps the sendmsg network call.
func (fd *FD) WriteMsg(p []byte, oob []byte, sa syscall.Sockaddr) (int, int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, 0, err
	}
	for {
		n, err := syscall.SendmsgN(fd.Sysfd, p, oob, sa, 0)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return n, 0, err
		}
		return n, len(oob), err
	}
}

// WriteMsgInet4 is WriteMsg specialized for syscall.SockaddrInet4.
func (fd *FD) WriteMsgInet4(p []byte, oob []byte, sa *syscall.SockaddrInet4) (int, int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, 0, err
	}
	for {
		n, err := unix.SendmsgNInet4(fd.Sysfd, p, oob, sa, 0)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return n, 0, err
		}
		return n, len(oob), err
	}
}

// WriteMsgInet6 is WriteMsg specialized for syscall.SockaddrInet6.
func (fd *FD) WriteMsgInet6(p []byte, oob []byte, sa *syscall.SockaddrInet6) (int, int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, 0, err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return 0, 0, err
	}
	for {
		n, err := unix.SendmsgNInet6(fd.Sysfd, p, oob, sa, 0)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN && fd.pd.pollable() {
			if err = fd.pd.waitWrite(fd.isFile); err == nil {
				continue
			}
		}
		if err != nil {
			return n, 0, err
		}
		return n, len(oob), err
	}
}

// Accept wraps the accept network call.
func (fd *FD) Accept() (int, syscall.Sockaddr, string, error) {
	if err := fd.readLock(); err != nil {
		return -1, nil, "", err
	}
	defer fd.readUnlock()

	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return -1, nil, "", err
	}
	for {
		s, rsa, errcall, err := accept(fd.Sysfd)
		if err == nil {
			return s, rsa, "", err
		}
		switch err {
		case syscall.EINTR:
			continue
		case syscall.EAGAIN:
			if fd.pd.pollable() {
				if err = fd.pd.waitRead(fd.isFile); err == nil {
					continue
				}
			}
		case syscall.ECONNABORTED:
			// This means that a socket on the listen
			// queue was closed before we Accept()ed it;
			// it's a silly error, so try again.
			continue
		}
		return -1, nil, errcall, err
	}
}

// Fchmod wraps syscall.Fchmod.
func (fd *FD) Fchmod(mode uint32) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	return ignoringEINTR(func() error {
		return syscall.Fchmod(fd.Sysfd, mode)
	})
}

// Fstat wraps syscall.Fstat
func (fd *FD) Fstat(s *syscall.Stat_t) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	return ignoringEINTR(func() error {
		return syscall.Fstat(fd.Sysfd, s)
	})
}

// dupCloexecUnsupported indicates whether F_DUPFD_CLOEXEC is supported by the kernel.
var dupCloexecUnsupported atomic.Bool

// DupCloseOnExec dups fd and marks it close-on-exec.
func DupCloseOnExec(fd int) (int, string, error) {
	if syscall.F_DUPFD_CLOEXEC != 0 && !dupCloexecUnsupported.Load() {
		r0, err := unix.Fcntl(fd, syscall.F_DUPFD_CLOEXEC, 0)
		if err == nil {
			return r0, "", nil
		}
		switch err {
		case syscall.EINVAL, syscall.ENOSYS:
			// Old kernel, or js/wasm (which returns
			// ENOSYS). Fall back to the portable way from
			// now on.
			dupCloexecUnsupported.Store(true)
		default:
			return -1, "fcntl", err
		}
	}
	return dupCloseOnExecOld(fd)
}

// Dup duplicates the file descriptor.
func (fd *FD) Dup() (int, string, error) {
	if err := fd.incref(); err != nil {
		return -1, "", err
	}
	defer fd.decref()
	return DupCloseOnExec(fd.Sysfd)
}

// On Unix variants only, expose the IO event for the net code.

// WaitWrite waits until data can be written to fd.
func (fd *FD) WaitWrite() error {
	return fd.pd.waitWrite(fd.isFile)
}

// WriteOnce is for testing only. It makes a single write call.
func (fd *FD) WriteOnce(p []byte) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	return ignoringEINTRIO(syscall.Write, fd.Sysfd, p)
}

// RawRead invokes the user-defined function f for a read operation.
func (fd *FD) RawRead(f func(uintptr) bool) error {
	if err := fd.readLock(); err != nil {
		return err
	}
	defer fd.readUnlock()
	if err := fd.pd.prepareRead(fd.isFile); err != nil {
		return err
	}
	for {
		if f(uintptr(fd.Sysfd)) {
			return nil
		}
		if err := fd.pd.waitRead(fd.isFile); err != nil {
			return err
		}
	}
}

// RawWrite invokes the user-defined function f for a write operation.
func (fd *FD) RawWrite(f func(uintptr) bool) error {
	if err := fd.writeLock(); err != nil {
		return err
	}
	defer fd.writeUnlock()
	if err := fd.pd.prepareWrite(fd.isFile); err != nil {
		return err
	}
	for {
		if f(uintptr(fd.Sysfd)) {
			return nil
		}
		if err := fd.pd.waitWrite(fd.isFile); err != nil {
			return err
		}
	}
}

// ignoringEINTRIO is like ignoringEINTR, but just for IO calls.
func ignoringEINTRIO(fn func(fd int, p []byte) (int, error), fd int, p []byte) (int, error) {
	for {
		n, err := fn(fd, p)
		if err != syscall.EINTR {
			return n, err
		}
	}
}
```