Response:
The user wants a summary of the functionality of the provided Go code snippet. I need to analyze the code and identify its main responsibilities.

The code is part of the `internal/poll` package in Go, specifically for Windows. It deals with managing file descriptors (FDs) and performing asynchronous I/O operations using the Windows API, particularly the I/O Completion Ports (IOCP) mechanism.

Here's a breakdown of the key functionalities:

1. **Initialization:**  Initializes the Winsock library (WSA) and checks for the availability and safety of the `SetFileCompletionNotificationModes` API.
2. **FD Management:** Defines the `FD` struct to represent a file descriptor and provides methods for initializing, closing, and managing its lifecycle. It handles different types of file descriptors: network sockets, files, consoles, and pipes.
3. **Asynchronous I/O:** Implements asynchronous read and write operations using IOCP. It defines an `operation` struct to encapsulate the data needed for an async I/O operation. The `execIO` function handles the submission and completion of these operations.
4. **Synchronous I/O (for files and consoles):**  Provides implementations for synchronous read and write operations using standard Windows API calls like `ReadFile`, `WriteFile`, `ReadConsole`, and `WriteConsole`.
5. **Specific I/O Operations:**  Offers functions for various I/O operations like `Read`, `Write`, `Pread`, `Pwrite`, `ReadFrom`, `WriteTo`, `ReadMsg`, `WriteMsg`, `Accept`, `ConnectEx`, etc. These functions abstract the underlying Windows API calls.
6. **Error Handling:** Includes logic to handle errors returned by Windows API calls and manage the state of the file descriptor during operations.
7. **Platform-Specific Features:**  Utilizes Windows-specific syscalls and data structures (e.g., `syscall.Overlapped`, `syscall.WSABuf`, `windows.WSAMsg`).
8. **Optimization:**  Attempts to optimize I/O operations by using `SetFileCompletionNotificationModes` to avoid unnecessary calls to `GetQueuedCompletionStatus` for synchronous completions.

Therefore, the core function of this code is to provide a low-level abstraction for performing I/O operations on Windows file descriptors, supporting both synchronous and asynchronous models and handling the specifics of the Windows API.
这是 `go/src/internal/poll/fd_windows.go` 文件的一部分，它主要负责 **在 Windows 平台上对文件描述符 (FD) 进行管理和执行 I/O 操作**。

更具体地说，它实现了以下功能：

1. **初始化 Winsock 库 (WSA):**  `InitWSA` 函数负责加载和初始化 Windows 的 Winsock 库，这是进行网络编程的基础。它使用 `sync.OnceFunc` 确保只被调用一次。

2. **检查 `SetFileCompletionNotificationModes` API 的可用性:** `checkSetFileCompletionNotificationModes` 函数检测 Windows 系统是否支持 `SetFileCompletionNotificationModes` API 并且可以安全使用。这个 API 可以优化 I/O 操作，避免在同步完成时调用 `GetQueuedCompletionStatus`。

3. **定义 I/O 操作结构体 `operation`:**  `operation` 结构体封装了执行异步 I/O 操作所需的所有数据，包括 `syscall.Overlapped` 结构体（用于异步操作），运行时上下文，操作模式 (读或写)，以及用于网络操作的缓冲区、消息、地址等信息。

4. **初始化 `operation` 结构体中的缓冲区:**  `InitBuf` 和 `InitBufs` 函数用于初始化 `operation` 结构体中用于读写数据的缓冲区。`ClearBufs` 用于清除缓冲区指针，以便垃圾回收。

5. **初始化 `operation` 结构体中的消息:** `InitMsg` 函数用于初始化 `operation` 结构体中用于发送/接收消息（例如 UDP 数据包）的结构体，包括数据缓冲区和控制信息缓冲区。

6. **执行 I/O 操作的 `execIO` 函数:** `execIO` 函数是核心函数，它负责执行一个单独的 I/O 操作。它根据文件描述符的类型和系统能力，选择同步或异步方式执行 I/O。对于异步 I/O，它会提交请求到运行时网络轮询器 (runtime netpoll) 并等待完成。它还处理 I/O 操作的取消和超时。

7. **定义文件描述符结构体 `FD`:** `FD` 结构体代表一个文件描述符，包含了 Windows 文件句柄 `Sysfd`，用于读写操作的 `operation` 结构体 (`rop` 和 `wop`)，以及与运行时网络轮询器相关的 `pollDesc` 结构体。它还包含用于控制台 I/O 的缓冲区和其他标志位。

8. **初始化 `FD` 结构体:** `Init` 函数用于初始化 `FD` 结构体。它根据传入的网络类型 (例如 "tcp", "file", "console") 设置 `FD` 的类型和标志，并根据 `pollable` 参数决定是否将其添加到运行时网络轮询器中进行管理。

9. **销毁 `FD` 结构体:** `destroy` 函数负责关闭底层的 Windows 文件句柄，并清理相关的资源。

10. **关闭 `FD` 结构体:** `Close` 函数用于关闭文件描述符。它会递减引用计数，并在引用计数为零时调用 `destroy` 函数释放资源。

**总结一下它的功能：**

该代码片段是 Go 语言 `internal/poll` 包中用于 Windows 平台的关键部分，它提供了对文件描述符的抽象，并实现了在 Windows 上执行同步和异步 I/O 操作的基础设施。它处理了 Windows 特有的 API 调用和异步 I/O 完成机制，为 Go 的网络和文件 I/O 操作提供了底层支持。

由于这是第 1 部分，我们无法完全推理出它实现了什么完整的 Go 语言功能。但是，基于目前的代码，我们可以推断出它涉及到以下 Go 语言功能的实现：

* **网络编程 (net 包):**  `InitWSA` 的调用以及对 socket 类型文件描述符的处理表明它与 Go 的 `net` 包密切相关，用于实现 TCP、UDP 等网络连接。
* **文件 I/O (os 包):**  对 `file` 类型文件描述符的处理以及 `syscall.Read` 和 `syscall.Write` 的使用表明它也参与了 Go 的 `os` 包中文件 I/O 功能的实现。
* **控制台 I/O:**  对 `console` 类型文件描述符的处理以及 `ReadConsole` 和 `WriteConsole` 的使用表明它支持在 Windows 平台上进行控制台的读写操作。
* **管道 (pipe):**  对 `pipe` 类型文件描述符的处理表明它支持在 Windows 平台上使用管道进行进程间通信。
* **异步 I/O:**  `operation` 结构体和 `execIO` 函数的设计明显是为了支持异步 I/O 操作，这在高性能网络编程中至关重要。

由于没有完整的代码上下文，我们无法给出具体的 Go 代码示例来说明其功能。但是，我们可以假设一些场景，并基于代码片段进行推理：

**假设的场景：**  一个 Go 程序尝试创建一个 TCP 客户端连接到远程服务器。

**推断的内部流程：**

1. `net.Dial("tcp", "remotehost:port")` 会被调用。
2. 在内部，Go 的 `net` 包会创建一个底层的 socket，并调用 `internal/poll` 包的函数来初始化与该 socket 关联的文件描述符 (`FD`)。`FD.Init("tcp", true)` 可能会被调用，将该文件描述符注册到运行时网络轮询器。
3. 当调用 `conn.Read(buf)` 或 `conn.Write(buf)` 时，`internal/poll` 包中的 `FD.Read` 或 `FD.Write` 方法会被调用。
4. 对于网络 socket，这些方法会使用 `execIO` 函数来执行底层的 `syscall.WSARecv` 或 `syscall.WSASend` 操作，可能是异步的。

**假设的输入与输出 (针对 `FD.Read` 方法的 `execIO` 调用):**

**输入:**

* `o`: 一个指向 `operation` 结构体的指针，其中包含了要读取的数据的缓冲区信息。
* `submit`: 一个匿名函数，内部调用了 `syscall.WSARecv(o.fd.Sysfd, &o.buf, 1, &o.qty, &o.flags, &o.o, nil)`。
* `fd.Sysfd`:  一个有效的 socket 文件句柄。
* `o.buf`:  一个指向用于接收数据的 `syscall.WSABuf` 结构体的指针。

**可能的输出:**

* **成功读取:** 返回读取到的字节数 (例如 `n = 1024`) 和 `nil` 错误。
* **无数据可读 (但连接未关闭):** 如果是非阻塞 socket，可能会立即返回 `0` 和一个表示操作会稍后完成的错误 (例如 `syscall.EAGAIN`，虽然 Windows 上可能不是这个错误码，但概念类似)。对于阻塞 socket，会等待数据到达。
* **连接关闭:** 返回 `0` 和 `io.EOF` 错误。
* **其他错误:** 返回 `0` 和具体的系统调用错误 (例如网络连接错误)。

**使用者易犯错的点：**

由于这段代码是底层的实现，直接使用它的可能性不大。用户通常会通过 `net` 和 `os` 等标准库包来间接使用这些功能。 然而，理解其内部机制可以帮助用户避免一些与 I/O 操作相关的常见错误：

* **不正确的缓冲区大小:**  `maxRW` 常量的存在表明 Windows 的底层 I/O 操作可能对单次读写的最大数据量有限制。如果用户尝试读取或写入过大的缓冲区，可能会导致错误或性能问题。虽然上层库会处理这个问题，但理解这个限制有助于理解某些性能瓶颈。
* **阻塞与非阻塞 I/O 的混淆:**  `execIO` 函数涉及到异步 I/O 的处理。用户如果对非阻塞 I/O 的行为不熟悉，可能会在处理 `Read` 和 `Write` 等操作的返回值时出现逻辑错误，例如没有正确处理需要多次调用才能完成的操作。

由于这是第 1 部分，后续的代码可能会提供更多上下文信息，帮助我们更全面地理解其功能。

Prompt: 
```
这是路径为go/src/internal/poll/fd_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package poll

import (
	"errors"
	"internal/race"
	"internal/syscall/windows"
	"io"
	"sync"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

var (
	initErr error
	ioSync  uint64
)

// This package uses the SetFileCompletionNotificationModes Windows
// API to skip calling GetQueuedCompletionStatus if an IO operation
// completes synchronously. There is a known bug where
// SetFileCompletionNotificationModes crashes on some systems (see
// https://support.microsoft.com/kb/2568167 for details).

var useSetFileCompletionNotificationModes bool // determines is SetFileCompletionNotificationModes is present and safe to use

// checkSetFileCompletionNotificationModes verifies that
// SetFileCompletionNotificationModes Windows API is present
// on the system and is safe to use.
// See https://support.microsoft.com/kb/2568167 for details.
func checkSetFileCompletionNotificationModes() {
	err := syscall.LoadSetFileCompletionNotificationModes()
	if err != nil {
		return
	}
	protos := [2]int32{syscall.IPPROTO_TCP, 0}
	var buf [32]syscall.WSAProtocolInfo
	len := uint32(unsafe.Sizeof(buf))
	n, err := syscall.WSAEnumProtocols(&protos[0], &buf[0], &len)
	if err != nil {
		return
	}
	for i := int32(0); i < n; i++ {
		if buf[i].ServiceFlags1&syscall.XP1_IFS_HANDLES == 0 {
			return
		}
	}
	useSetFileCompletionNotificationModes = true
}

// InitWSA initiates the use of the Winsock DLL by the current process.
// It is called from the net package at init time to avoid
// loading ws2_32.dll when net is not used.
var InitWSA = sync.OnceFunc(func() {
	var d syscall.WSAData
	e := syscall.WSAStartup(uint32(0x202), &d)
	if e != nil {
		initErr = e
	}
	checkSetFileCompletionNotificationModes()
})

// operation contains superset of data necessary to perform all async IO.
type operation struct {
	// Used by IOCP interface, it must be first field
	// of the struct, as our code rely on it.
	o syscall.Overlapped

	// fields used by runtime.netpoll
	runtimeCtx uintptr
	mode       int32

	// fields used only by net package
	fd     *FD
	buf    syscall.WSABuf
	msg    windows.WSAMsg
	sa     syscall.Sockaddr
	rsa    *syscall.RawSockaddrAny
	rsan   int32
	handle syscall.Handle
	flags  uint32
	qty    uint32
	bufs   []syscall.WSABuf
}

func (o *operation) InitBuf(buf []byte) {
	o.buf.Len = uint32(len(buf))
	o.buf.Buf = nil
	if len(buf) != 0 {
		o.buf.Buf = &buf[0]
	}
}

func (o *operation) InitBufs(buf *[][]byte) {
	if o.bufs == nil {
		o.bufs = make([]syscall.WSABuf, 0, len(*buf))
	} else {
		o.bufs = o.bufs[:0]
	}
	for _, b := range *buf {
		if len(b) == 0 {
			o.bufs = append(o.bufs, syscall.WSABuf{})
			continue
		}
		for len(b) > maxRW {
			o.bufs = append(o.bufs, syscall.WSABuf{Len: maxRW, Buf: &b[0]})
			b = b[maxRW:]
		}
		if len(b) > 0 {
			o.bufs = append(o.bufs, syscall.WSABuf{Len: uint32(len(b)), Buf: &b[0]})
		}
	}
}

// ClearBufs clears all pointers to Buffers parameter captured
// by InitBufs, so it can be released by garbage collector.
func (o *operation) ClearBufs() {
	for i := range o.bufs {
		o.bufs[i].Buf = nil
	}
	o.bufs = o.bufs[:0]
}

func (o *operation) InitMsg(p []byte, oob []byte) {
	o.InitBuf(p)
	o.msg.Buffers = &o.buf
	o.msg.BufferCount = 1

	o.msg.Name = nil
	o.msg.Namelen = 0

	o.msg.Flags = 0
	o.msg.Control.Len = uint32(len(oob))
	o.msg.Control.Buf = nil
	if len(oob) != 0 {
		o.msg.Control.Buf = &oob[0]
	}
}

// execIO executes a single IO operation o. It submits and cancels
// IO in the current thread for systems where Windows CancelIoEx API
// is available. Alternatively, it passes the request onto
// runtime netpoll and waits for completion or cancels request.
func execIO(o *operation, submit func(o *operation) error) (int, error) {
	if o.fd.pd.runtimeCtx == 0 {
		return 0, errors.New("internal error: polling on unsupported descriptor type")
	}

	fd := o.fd
	// Notify runtime netpoll about starting IO.
	err := fd.pd.prepare(int(o.mode), fd.isFile)
	if err != nil {
		return 0, err
	}
	// Start IO.
	err = submit(o)
	switch err {
	case nil:
		// IO completed immediately
		if o.fd.skipSyncNotif {
			// No completion message will follow, so return immediately.
			return int(o.qty), nil
		}
		// Need to get our completion message anyway.
	case syscall.ERROR_IO_PENDING:
		// IO started, and we have to wait for its completion.
		err = nil
	default:
		return 0, err
	}
	// Wait for our request to complete.
	err = fd.pd.wait(int(o.mode), fd.isFile)
	if err == nil {
		err = windows.WSAGetOverlappedResult(fd.Sysfd, &o.o, &o.qty, false, &o.flags)
		// All is good. Extract our IO results and return.
		if err != nil {
			// More data available. Return back the size of received data.
			if err == syscall.ERROR_MORE_DATA || err == windows.WSAEMSGSIZE {
				return int(o.qty), err
			}
			return 0, err
		}
		return int(o.qty), nil
	}
	// IO is interrupted by "close" or "timeout"
	netpollErr := err
	switch netpollErr {
	case ErrNetClosing, ErrFileClosing, ErrDeadlineExceeded:
		// will deal with those.
	default:
		panic("unexpected runtime.netpoll error: " + netpollErr.Error())
	}
	// Cancel our request.
	err = syscall.CancelIoEx(fd.Sysfd, &o.o)
	// Assuming ERROR_NOT_FOUND is returned, if IO is completed.
	if err != nil && err != syscall.ERROR_NOT_FOUND {
		// TODO(brainman): maybe do something else, but panic.
		panic(err)
	}
	// Wait for cancellation to complete.
	fd.pd.waitCanceled(int(o.mode))
	err = windows.WSAGetOverlappedResult(fd.Sysfd, &o.o, &o.qty, false, &o.flags)
	if err != nil {
		if err == syscall.ERROR_OPERATION_ABORTED { // IO Canceled
			err = netpollErr
		}
		return 0, err
	}
	// We issued a cancellation request. But, it seems, IO operation succeeded
	// before the cancellation request run. We need to treat the IO operation as
	// succeeded (the bytes are actually sent/recv from network).
	return int(o.qty), nil
}

// FD is a file descriptor. The net and os packages embed this type in
// a larger type representing a network connection or OS file.
type FD struct {
	// Lock sysfd and serialize access to Read and Write methods.
	fdmu fdMutex

	// System file descriptor. Immutable until Close.
	Sysfd syscall.Handle

	// Read operation.
	rop operation
	// Write operation.
	wop operation

	// I/O poller.
	pd pollDesc

	// Used to implement pread/pwrite.
	l sync.Mutex

	// For console I/O.
	lastbits       []byte   // first few bytes of the last incomplete rune in last write
	readuint16     []uint16 // buffer to hold uint16s obtained with ReadConsole
	readbyte       []byte   // buffer to hold decoding of readuint16 from utf16 to utf8
	readbyteOffset int      // readbyte[readOffset:] is yet to be consumed with file.Read

	// Semaphore signaled when file is closed.
	csema uint32

	skipSyncNotif bool

	// Whether this is a streaming descriptor, as opposed to a
	// packet-based descriptor like a UDP socket.
	IsStream bool

	// Whether a zero byte read indicates EOF. This is false for a
	// message based socket connection.
	ZeroReadIsEOF bool

	// Whether this is a file rather than a network socket.
	isFile bool

	// The kind of this file.
	kind fileKind
}

// fileKind describes the kind of file.
type fileKind byte

const (
	kindNet fileKind = iota
	kindFile
	kindConsole
	kindPipe
)

// logInitFD is set by tests to enable file descriptor initialization logging.
var logInitFD func(net string, fd *FD, err error)

// Init initializes the FD. The Sysfd field should already be set.
// This can be called multiple times on a single FD.
// The net argument is a network name from the net package (e.g., "tcp"),
// or "file" or "console" or "dir".
// Set pollable to true if fd should be managed by runtime netpoll.
func (fd *FD) Init(net string, pollable bool) (string, error) {
	if initErr != nil {
		return "", initErr
	}

	switch net {
	case "file", "dir":
		fd.kind = kindFile
	case "console":
		fd.kind = kindConsole
	case "pipe":
		fd.kind = kindPipe
	case "tcp", "tcp4", "tcp6",
		"udp", "udp4", "udp6",
		"ip", "ip4", "ip6",
		"unix", "unixgram", "unixpacket":
		fd.kind = kindNet
	default:
		return "", errors.New("internal error: unknown network type " + net)
	}
	fd.isFile = fd.kind != kindNet

	var err error
	if pollable {
		// Only call init for a network socket.
		// This means that we don't add files to the runtime poller.
		// Adding files to the runtime poller can confuse matters
		// if the user is doing their own overlapped I/O.
		// See issue #21172.
		//
		// In general the code below avoids calling the execIO
		// function for non-network sockets. If some method does
		// somehow call execIO, then execIO, and therefore the
		// calling method, will return an error, because
		// fd.pd.runtimeCtx will be 0.
		err = fd.pd.init(fd)
	}
	if logInitFD != nil {
		logInitFD(net, fd, err)
	}
	if err != nil {
		return "", err
	}
	if pollable && useSetFileCompletionNotificationModes {
		// We do not use events, so we can skip them always.
		flags := uint8(syscall.FILE_SKIP_SET_EVENT_ON_HANDLE)
		switch net {
		case "tcp", "tcp4", "tcp6",
			"udp", "udp4", "udp6":
			flags |= syscall.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
		}
		err := syscall.SetFileCompletionNotificationModes(fd.Sysfd, flags)
		if err == nil && flags&syscall.FILE_SKIP_COMPLETION_PORT_ON_SUCCESS != 0 {
			fd.skipSyncNotif = true
		}
	}
	// Disable SIO_UDP_CONNRESET behavior.
	// http://support.microsoft.com/kb/263823
	switch net {
	case "udp", "udp4", "udp6":
		ret := uint32(0)
		flag := uint32(0)
		size := uint32(unsafe.Sizeof(flag))
		err := syscall.WSAIoctl(fd.Sysfd, syscall.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &ret, nil, 0)
		if err != nil {
			return "wsaioctl", err
		}
	}
	fd.rop.mode = 'r'
	fd.wop.mode = 'w'
	fd.rop.fd = fd
	fd.wop.fd = fd
	fd.rop.runtimeCtx = fd.pd.runtimeCtx
	fd.wop.runtimeCtx = fd.pd.runtimeCtx
	return "", nil
}

func (fd *FD) destroy() error {
	if fd.Sysfd == syscall.InvalidHandle {
		return syscall.EINVAL
	}
	// Poller may want to unregister fd in readiness notification mechanism,
	// so this must be executed before fd.CloseFunc.
	fd.pd.close()
	var err error
	switch fd.kind {
	case kindNet:
		// The net package uses the CloseFunc variable for testing.
		err = CloseFunc(fd.Sysfd)
	default:
		err = syscall.CloseHandle(fd.Sysfd)
	}
	fd.Sysfd = syscall.InvalidHandle
	runtime_Semrelease(&fd.csema)
	return err
}

// Close closes the FD. The underlying file descriptor is closed by
// the destroy method when there are no remaining references.
func (fd *FD) Close() error {
	if !fd.fdmu.increfAndClose() {
		return errClosing(fd.isFile)
	}
	if fd.kind == kindPipe {
		syscall.CancelIoEx(fd.Sysfd, nil)
	}
	// unblock pending reader and writer
	fd.pd.evict()
	err := fd.decref()
	// Wait until the descriptor is closed. If this was the only
	// reference, it is already closed.
	runtime_Semacquire(&fd.csema)
	return err
}

// Windows ReadFile and WSARecv use DWORD (uint32) parameter to pass buffer length.
// This prevents us reading blocks larger than 4GB.
// See golang.org/issue/26923.
const maxRW = 1 << 30 // 1GB is large enough and keeps subsequent reads aligned

// Read implements io.Reader.
func (fd *FD) Read(buf []byte) (int, error) {
	if err := fd.readLock(); err != nil {
		return 0, err
	}
	defer fd.readUnlock()

	if len(buf) > maxRW {
		buf = buf[:maxRW]
	}

	var n int
	var err error
	if fd.isFile {
		fd.l.Lock()
		defer fd.l.Unlock()
		switch fd.kind {
		case kindConsole:
			n, err = fd.readConsole(buf)
		default:
			n, err = syscall.Read(fd.Sysfd, buf)
			if fd.kind == kindPipe && err == syscall.ERROR_OPERATION_ABORTED {
				// Close uses CancelIoEx to interrupt concurrent I/O for pipes.
				// If the fd is a pipe and the Read was interrupted by CancelIoEx,
				// we assume it is interrupted by Close.
				err = ErrFileClosing
			}
		}
		if err != nil {
			n = 0
		}
	} else {
		o := &fd.rop
		o.InitBuf(buf)
		n, err = execIO(o, func(o *operation) error {
			return syscall.WSARecv(o.fd.Sysfd, &o.buf, 1, &o.qty, &o.flags, &o.o, nil)
		})
		if race.Enabled {
			race.Acquire(unsafe.Pointer(&ioSync))
		}
	}
	if len(buf) != 0 {
		err = fd.eofError(n, err)
	}
	return n, err
}

var ReadConsole = syscall.ReadConsole // changed for testing

// readConsole reads utf16 characters from console File,
// encodes them into utf8 and stores them in buffer b.
// It returns the number of utf8 bytes read and an error, if any.
func (fd *FD) readConsole(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	if fd.readuint16 == nil {
		// Note: syscall.ReadConsole fails for very large buffers.
		// The limit is somewhere around (but not exactly) 16384.
		// Stay well below.
		fd.readuint16 = make([]uint16, 0, 10000)
		fd.readbyte = make([]byte, 0, 4*cap(fd.readuint16))
	}

	for fd.readbyteOffset >= len(fd.readbyte) {
		n := cap(fd.readuint16) - len(fd.readuint16)
		if n > len(b) {
			n = len(b)
		}
		var nw uint32
		err := ReadConsole(fd.Sysfd, &fd.readuint16[:len(fd.readuint16)+1][len(fd.readuint16)], uint32(n), &nw, nil)
		if err != nil {
			return 0, err
		}
		uint16s := fd.readuint16[:len(fd.readuint16)+int(nw)]
		fd.readuint16 = fd.readuint16[:0]
		buf := fd.readbyte[:0]
		for i := 0; i < len(uint16s); i++ {
			r := rune(uint16s[i])
			if utf16.IsSurrogate(r) {
				if i+1 == len(uint16s) {
					if nw > 0 {
						// Save half surrogate pair for next time.
						fd.readuint16 = fd.readuint16[:1]
						fd.readuint16[0] = uint16(r)
						break
					}
					r = utf8.RuneError
				} else {
					r = utf16.DecodeRune(r, rune(uint16s[i+1]))
					if r != utf8.RuneError {
						i++
					}
				}
			}
			buf = utf8.AppendRune(buf, r)
		}
		fd.readbyte = buf
		fd.readbyteOffset = 0
		if nw == 0 {
			break
		}
	}

	src := fd.readbyte[fd.readbyteOffset:]
	var i int
	for i = 0; i < len(src) && i < len(b); i++ {
		x := src[i]
		if x == 0x1A { // Ctrl-Z
			if i == 0 {
				fd.readbyteOffset++
			}
			break
		}
		b[i] = x
	}
	fd.readbyteOffset += i
	return i, nil
}

// Pread emulates the Unix pread system call.
func (fd *FD) Pread(b []byte, off int64) (int, error) {
	if fd.kind == kindPipe {
		// Pread does not work with pipes
		return 0, syscall.ESPIPE
	}
	// Call incref, not readLock, because since pread specifies the
	// offset it is independent from other reads.
	if err := fd.incref(); err != nil {
		return 0, err
	}
	defer fd.decref()

	if len(b) > maxRW {
		b = b[:maxRW]
	}

	fd.l.Lock()
	defer fd.l.Unlock()
	curoffset, e := syscall.Seek(fd.Sysfd, 0, io.SeekCurrent)
	if e != nil {
		return 0, e
	}
	defer syscall.Seek(fd.Sysfd, curoffset, io.SeekStart)
	o := syscall.Overlapped{
		OffsetHigh: uint32(off >> 32),
		Offset:     uint32(off),
	}
	var done uint32
	e = syscall.ReadFile(fd.Sysfd, b, &done, &o)
	if e != nil {
		done = 0
		if e == syscall.ERROR_HANDLE_EOF {
			e = io.EOF
		}
	}
	if len(b) != 0 {
		e = fd.eofError(int(done), e)
	}
	return int(done), e
}

// ReadFrom wraps the recvfrom network call.
func (fd *FD) ReadFrom(buf []byte) (int, syscall.Sockaddr, error) {
	if len(buf) == 0 {
		return 0, nil, nil
	}
	if len(buf) > maxRW {
		buf = buf[:maxRW]
	}
	if err := fd.readLock(); err != nil {
		return 0, nil, err
	}
	defer fd.readUnlock()
	o := &fd.rop
	o.InitBuf(buf)
	n, err := execIO(o, func(o *operation) error {
		if o.rsa == nil {
			o.rsa = new(syscall.RawSockaddrAny)
		}
		o.rsan = int32(unsafe.Sizeof(*o.rsa))
		return syscall.WSARecvFrom(o.fd.Sysfd, &o.buf, 1, &o.qty, &o.flags, o.rsa, &o.rsan, &o.o, nil)
	})
	err = fd.eofError(n, err)
	if err != nil {
		return n, nil, err
	}
	sa, _ := o.rsa.Sockaddr()
	return n, sa, nil
}

// ReadFromInet4 wraps the recvfrom network call for IPv4.
func (fd *FD) ReadFromInet4(buf []byte, sa4 *syscall.SockaddrInet4) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if len(buf) > maxRW {
		buf = buf[:maxRW]
	}
	if err := fd.readLock(); err != nil {
		return 0, err
	}
	defer fd.readUnlock()
	o := &fd.rop
	o.InitBuf(buf)
	n, err := execIO(o, func(o *operation) error {
		if o.rsa == nil {
			o.rsa = new(syscall.RawSockaddrAny)
		}
		o.rsan = int32(unsafe.Sizeof(*o.rsa))
		return syscall.WSARecvFrom(o.fd.Sysfd, &o.buf, 1, &o.qty, &o.flags, o.rsa, &o.rsan, &o.o, nil)
	})
	err = fd.eofError(n, err)
	if err != nil {
		return n, err
	}
	rawToSockaddrInet4(o.rsa, sa4)
	return n, err
}

// ReadFromInet6 wraps the recvfrom network call for IPv6.
func (fd *FD) ReadFromInet6(buf []byte, sa6 *syscall.SockaddrInet6) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if len(buf) > maxRW {
		buf = buf[:maxRW]
	}
	if err := fd.readLock(); err != nil {
		return 0, err
	}
	defer fd.readUnlock()
	o := &fd.rop
	o.InitBuf(buf)
	n, err := execIO(o, func(o *operation) error {
		if o.rsa == nil {
			o.rsa = new(syscall.RawSockaddrAny)
		}
		o.rsan = int32(unsafe.Sizeof(*o.rsa))
		return syscall.WSARecvFrom(o.fd.Sysfd, &o.buf, 1, &o.qty, &o.flags, o.rsa, &o.rsan, &o.o, nil)
	})
	err = fd.eofError(n, err)
	if err != nil {
		return n, err
	}
	rawToSockaddrInet6(o.rsa, sa6)
	return n, err
}

// Write implements io.Writer.
func (fd *FD) Write(buf []byte) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	if fd.isFile {
		fd.l.Lock()
		defer fd.l.Unlock()
	}

	ntotal := 0
	for len(buf) > 0 {
		b := buf
		if len(b) > maxRW {
			b = b[:maxRW]
		}
		var n int
		var err error
		if fd.isFile {
			switch fd.kind {
			case kindConsole:
				n, err = fd.writeConsole(b)
			default:
				n, err = syscall.Write(fd.Sysfd, b)
				if fd.kind == kindPipe && err == syscall.ERROR_OPERATION_ABORTED {
					// Close uses CancelIoEx to interrupt concurrent I/O for pipes.
					// If the fd is a pipe and the Write was interrupted by CancelIoEx,
					// we assume it is interrupted by Close.
					err = ErrFileClosing
				}
			}
			if err != nil {
				n = 0
			}
		} else {
			if race.Enabled {
				race.ReleaseMerge(unsafe.Pointer(&ioSync))
			}
			o := &fd.wop
			o.InitBuf(b)
			n, err = execIO(o, func(o *operation) error {
				return syscall.WSASend(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, &o.o, nil)
			})
		}
		ntotal += n
		if err != nil {
			return ntotal, err
		}
		buf = buf[n:]
	}
	return ntotal, nil
}

// writeConsole writes len(b) bytes to the console File.
// It returns the number of bytes written and an error, if any.
func (fd *FD) writeConsole(b []byte) (int, error) {
	n := len(b)
	runes := make([]rune, 0, 256)
	if len(fd.lastbits) > 0 {
		b = append(fd.lastbits, b...)
		fd.lastbits = nil

	}
	for len(b) >= utf8.UTFMax || utf8.FullRune(b) {
		r, l := utf8.DecodeRune(b)
		runes = append(runes, r)
		b = b[l:]
	}
	if len(b) > 0 {
		fd.lastbits = make([]byte, len(b))
		copy(fd.lastbits, b)
	}
	// syscall.WriteConsole seems to fail, if given large buffer.
	// So limit the buffer to 16000 characters. This number was
	// discovered by experimenting with syscall.WriteConsole.
	const maxWrite = 16000
	for len(runes) > 0 {
		m := len(runes)
		if m > maxWrite {
			m = maxWrite
		}
		chunk := runes[:m]
		runes = runes[m:]
		uint16s := utf16.Encode(chunk)
		for len(uint16s) > 0 {
			var written uint32
			err := syscall.WriteConsole(fd.Sysfd, &uint16s[0], uint32(len(uint16s)), &written, nil)
			if err != nil {
				return 0, err
			}
			uint16s = uint16s[written:]
		}
	}
	return n, nil
}

// Pwrite emulates the Unix pwrite system call.
func (fd *FD) Pwrite(buf []byte, off int64) (int, error) {
	if fd.kind == kindPipe {
		// Pwrite does not work with pipes
		return 0, syscall.ESPIPE
	}
	// Call incref, not writeLock, because since pwrite specifies the
	// offset it is independent from other writes.
	if err := fd.incref(); err != nil {
		return 0, err
	}
	defer fd.decref()

	fd.l.Lock()
	defer fd.l.Unlock()
	curoffset, e := syscall.Seek(fd.Sysfd, 0, io.SeekCurrent)
	if e != nil {
		return 0, e
	}
	defer syscall.Seek(fd.Sysfd, curoffset, io.SeekStart)

	ntotal := 0
	for len(buf) > 0 {
		b := buf
		if len(b) > maxRW {
			b = b[:maxRW]
		}
		var n uint32
		o := syscall.Overlapped{
			OffsetHigh: uint32(off >> 32),
			Offset:     uint32(off),
		}
		e = syscall.WriteFile(fd.Sysfd, b, &n, &o)
		ntotal += int(n)
		if e != nil {
			return ntotal, e
		}
		buf = buf[n:]
		off += int64(n)
	}
	return ntotal, nil
}

// Writev emulates the Unix writev system call.
func (fd *FD) Writev(buf *[][]byte) (int64, error) {
	if len(*buf) == 0 {
		return 0, nil
	}
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()
	if race.Enabled {
		race.ReleaseMerge(unsafe.Pointer(&ioSync))
	}
	o := &fd.wop
	o.InitBufs(buf)
	n, err := execIO(o, func(o *operation) error {
		return syscall.WSASend(o.fd.Sysfd, &o.bufs[0], uint32(len(o.bufs)), &o.qty, 0, &o.o, nil)
	})
	o.ClearBufs()
	TestHookDidWritev(n)
	consume(buf, int64(n))
	return int64(n), err
}

// WriteTo wraps the sendto network call.
func (fd *FD) WriteTo(buf []byte, sa syscall.Sockaddr) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()

	if len(buf) == 0 {
		// handle zero-byte payload
		o := &fd.wop
		o.InitBuf(buf)
		o.sa = sa
		n, err := execIO(o, func(o *operation) error {
			return syscall.WSASendto(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, o.sa, &o.o, nil)
		})
		return n, err
	}

	ntotal := 0
	for len(buf) > 0 {
		b := buf
		if len(b) > maxRW {
			b = b[:maxRW]
		}
		o := &fd.wop
		o.InitBuf(b)
		o.sa = sa
		n, err := execIO(o, func(o *operation) error {
			return syscall.WSASendto(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, o.sa, &o.o, nil)
		})
		ntotal += int(n)
		if err != nil {
			return ntotal, err
		}
		buf = buf[n:]
	}
	return ntotal, nil
}

// WriteToInet4 is WriteTo, specialized for syscall.SockaddrInet4.
func (fd *FD) WriteToInet4(buf []byte, sa4 *syscall.SockaddrInet4) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()

	if len(buf) == 0 {
		// handle zero-byte payload
		o := &fd.wop
		o.InitBuf(buf)
		n, err := execIO(o, func(o *operation) error {
			return windows.WSASendtoInet4(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, sa4, &o.o, nil)
		})
		return n, err
	}

	ntotal := 0
	for len(buf) > 0 {
		b := buf
		if len(b) > maxRW {
			b = b[:maxRW]
		}
		o := &fd.wop
		o.InitBuf(b)
		n, err := execIO(o, func(o *operation) error {
			return windows.WSASendtoInet4(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, sa4, &o.o, nil)
		})
		ntotal += int(n)
		if err != nil {
			return ntotal, err
		}
		buf = buf[n:]
	}
	return ntotal, nil
}

// WriteToInet6 is WriteTo, specialized for syscall.SockaddrInet6.
func (fd *FD) WriteToInet6(buf []byte, sa6 *syscall.SockaddrInet6) (int, error) {
	if err := fd.writeLock(); err != nil {
		return 0, err
	}
	defer fd.writeUnlock()

	if len(buf) == 0 {
		// handle zero-byte payload
		o := &fd.wop
		o.InitBuf(buf)
		n, err := execIO(o, func(o *operation) error {
			return windows.WSASendtoInet6(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, sa6, &o.o, nil)
		})
		return n, err
	}

	ntotal := 0
	for len(buf) > 0 {
		b := buf
		if len(b) > maxRW {
			b = b[:maxRW]
		}
		o := &fd.wop
		o.InitBuf(b)
		n, err := execIO(o, func(o *operation) error {
			return windows.WSASendtoInet6(o.fd.Sysfd, &o.buf, 1, &o.qty, 0, sa6, &o.o, nil)
		})
		ntotal += int(n)
		if err != nil {
			return ntotal, err
		}
		buf = buf[n:]
	}
	return ntotal, nil
}

// Call ConnectEx. This doesn't need any locking, since it is only
// called when the descriptor is first created. This is here rather
// than in the net package so that it can use fd.wop.
func (fd *FD) ConnectEx(ra syscall.Sockaddr) error {
	o := &fd.wop
	o.sa = ra
	_, err := execIO(o, func(o *operation) error {
		return ConnectExFunc(o.fd.Sysfd, o.sa, nil, 0, nil, &o.o)
	})
	return err
}

func (fd *FD) acceptOne(s syscall.Handle, rawsa []syscall.RawSockaddrAny, o *operation) (string, error) {
	// Submit accept request.
	o.handle = s
	o.rsan = int32(unsafe.Sizeof(rawsa[0]))
	_, err := execIO(o, func(o *operation) error {
		return AcceptFunc(o.fd.Sysfd, o.handle, (*byte)(unsafe.Pointer(&rawsa[0])), 0, uint32(o.rsan), uint32(o.rsan), &o.qty, &o.o)
	})
	if err != nil {
		CloseFunc(s)
		return "acceptex", err
	}

	// Inherit properties of the listening socket.
	err = syscall.Setsockopt(s, syscall.SOL_SOCKET, syscall.SO_UPDATE_ACCEPT_CONTEXT, (*byte)(unsafe.Pointer(&fd.Sysfd)), int32(unsafe.Sizeof(fd.Sysfd)))
	if err != nil {
		CloseFunc(s)
		return "setsockopt", err
	}

	return "", nil
}

// Accept handles accepting a socket. The sysSocket parameter is used
// to allocate the net socket.
func (fd *FD) Accept(sysSocket func() (syscall.Handle, error)) (syscall.Handle, []syscall.RawSockaddrAny, uint32, string, error) {
	if err := fd.readLock(); err != nil {
		return syscall.InvalidHandle, nil, 0, "", err
	}
	defer fd.readUnlock()

	o := &fd.rop
	var rawsa [2]syscall.RawSockaddrAny
	for {
		s, err := sysSocket()
		if err != nil {
			return syscall.InvalidHandle, nil, 0, "", err
		}

		errcall, err := fd.acceptOne(s, rawsa[:], o)
		if err == nil {
			return s, rawsa[:], uint32(o.rsan), "", nil
		}

		// Sometimes we see WSAECONNRESET and ERROR_NETNAME_DELETED is
		// returned here. These happen if connection reset is received
		// before AcceptEx could complete. These errors relate to new
		// connection, not to AcceptEx, so ignore broken connection and
		// try AcceptEx again for more connections.
		errno, ok := err.(syscall.Errno)
		if !ok {
			return syscall.InvalidHandle, nil, 0, errcall, err
		}
		switch errno {
		case syscall.ERROR_NETNAME_DELETED, syscall.WSAECONNRESET:
			// ignore these and try again
		default:
			return syscall.InvalidHandle, nil, 0, errcall, err
		}
	}
}

// Seek wraps syscall.Seek.
func (fd *FD) Seek(offset int64, whence int) (int64, error) {
	if fd.kind == kindPipe {
		return 0, syscall.ESPIPE
	}
	if err := fd.incref(); err != nil {
		return 0, err
	}
	defer fd.decref()

	fd.l.Lock()
	defer fd.l.Unlock()

	return syscall.Seek(fd.Sysfd, offset, whence)
}

// Fchmod updates syscall.ByHandleFileInformation.Fileattributes when needed.
func (fd *FD) Fchmod(mode uint32) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()

	var d syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(fd.Sysfd, &d); err != nil {
		return err
	}
	attrs := d.FileAttributes
	if mode&syscall.S_IWRITE != 0 {
		attrs &^= syscall.FILE_ATTRIBUTE_READONLY
	} else {
		attrs |= syscall.FILE_ATTRIBUTE_READONLY
	}
	if attrs == d.FileAttributes {
		return nil
	}

	var du windows.FILE_BASIC_INFO
	du.FileAttributes = attrs
	return windows.SetFileInformationByHandle(fd.Sysfd, windows.FileBasicInfo, unsafe.Pointer(&du), uint32(unsafe.Sizeof(du)))
}

// Fchdir wraps syscall.Fchdir.
func (fd *FD) Fchdir() error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	return syscall.Fchdir(fd.Sysfd)
}

// GetFileType wraps syscall.GetFileType.
func (fd *FD) GetFileType() (uint32, error) {
	if err := fd.incref(); err != nil {
		return 0, err
	}
	defer fd.decref()
	return syscall.GetFileType(fd.Sysfd)
}

// GetFileInformationByHandle wraps GetFileInformationByHandle.
func (fd *FD) GetFileInformationByHandle(data *syscall.ByHandleFileInformation) error {
	if err := fd.incref(); err != nil {
		return err
	}
	defer fd.decref()
	return syscall.GetFileInformationByHandle(fd.Sysfd, data)
}

// RawRead invokes the user-defined function f for a read operation.
func (fd *FD) RawRead(f func(uintptr) bool) error {
	if err := fd.readLock(); err != nil {
		return err
	}
	defer fd.readUnlock()
	for {
		if f(uintptr(fd.Sysfd)) {
			return nil
		}

		// Use a zero-byte read as a way to get notified when this
		// socket is readable. h/t https://stackoverflow.com/a/42019668/332798
		o := &fd.rop
		o.InitBuf(nil)
		if !fd.IsStream {
			o.flags |= windows.MSG_PEEK
		}
		_, err := execIO(o, func(o *operation) error {
			return syscall.WSARecv(o.fd.Sysfd, &o.buf, 1, &o.qty, &o.flags, &o.o, nil)
		})
		if err == windows.WSAEMSGSIZE {
			// expected with a 0-byte peek, ignore.
		} else if err != nil {
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

	if f(uintptr(fd.Sysfd)) {
		return nil
	}

	// TODO(tmm1): find a way to detect socket writability
	return syscall.EWINDOWS
}

func sockaddrInet4ToRaw(rsa *syscall.RawSockaddrAny, sa *syscall.SockaddrInet4) int32 {
	*rsa = syscall.RawSockaddrAny{}
	raw := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
	raw.Family = syscall.AF_INET
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	raw.Addr = sa.Addr
	return int32(unsafe.Sizeof(*raw))
}

func sockaddrInet6ToRaw(rsa *syscall.RawSockaddrAny, sa *syscall.SockaddrInet6) int32 {
	*rsa = syscall.RawSockaddrAny{}
	raw := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
	raw.Family = syscall.AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	raw.Scope_id = sa.ZoneId
	raw.Addr = sa.Addr
	return int32(unsafe.Sizeof(*raw))
}

func rawToSockaddrInet4(rsa *syscall.RawSockaddrAny, sa *syscall.SockaddrInet4) {
	pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
	p := (*[2]byte)(unsafe.Pointer(&pp.Port))
	sa.Port = int(p[0])<<8 + int(p[1])
	sa.Addr = pp.Addr
}

func rawToSockaddrInet6(rsa *syscall.RawSockaddrAny, sa *syscall.SockaddrInet6) {
	pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
	p := (*[2]byte)(unsafe.Pointer(&pp.Port))
	sa.Port = int(p[0])<<8 + int(p[1])
	sa.ZoneId = pp.Scope_id
	sa.Addr = pp.Addr
}

func sockaddrToRaw(rsa *syscall.RawSockaddrAny, sa syscall.Sockaddr) (int32, error) {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		sz := sockaddrInet4ToRaw(rsa, sa)
		return sz, nil
	case *syscall.SockaddrInet6:
		sz := sockaddrInet6ToRaw(rsa, sa)
		return sz, nil
	default:
		return 0, syscall.EWINDOWS
	}
}

// ReadMsg wraps the WSARecvMsg network call.
func (fd *FD) ReadMsg(p []byte, oob []byte, flags int) (int, int, int, syscall.Sockaddr, error) {
	if err := fd.readLock(); err != nil {
		return 0, 0, 0, nil, err
	}
	defer fd.readUnlock()

	if len(p) > maxRW {
		p = p[:maxRW]
	}

	o := &fd.rop
	o.InitMsg(p, oob)
	if o.rsa == nil {
		o.rsa = new(syscall.RawSockaddrAny)
	}
	o.msg.Name = (syscall.Pointer)(unsafe.Pointer(o.rsa))
	o.msg.Namelen = int32(unsafe.Sizeof(*o.rsa))
	o.msg.Flags = uint32(flags)
	n, err := execIO(o, func(o *operation) error {
		return windows.WSARecvMsg(o.fd.Sysfd, &o.msg, &o.qty, &o.o, nil)
	})
	err = fd.eofError(n, err)
	var sa syscall.Sockaddr
	if err == nil {
		sa, err = o.rsa.Sockaddr()
	}
	return n, int(o.msg.Control.Len), int(o.msg.Flags), sa, err
}

// ReadMsgInet4 is ReadMsg, but specialized to return a syscall.SockaddrInet4.
func (fd *FD) ReadMsgInet4(p []byte, oob []byte, flags int, sa4 *syscall.SockaddrInet4) (int, int, int, error) {
	if err := fd.readLock(); err != nil {
		return 0, 0, 0, err
	}
	defer fd.readUnlock()

	if len(p) > maxRW {
		p = p[:maxRW]
	}

	o := &fd.rop
	o.InitMsg(p, oob)
	if o.rsa == nil {
		o.rsa = new(syscall.RawSockaddrAny)
	}
	o.msg.Name = (syscall.Pointer)(unsafe.Pointer(o.rsa))
	o.msg.Namelen = int32(unsafe.Sizeof(*o.rsa))
	o.msg.Flags = uint32(flags)
	n, err := execIO(o, func(o *operation) error {
		return windows.WSARecvMsg(o.fd.Sysfd, &o.msg, &o.qty, &o.o, nil)
	})
	err = fd.eofError(n, err)
	if err == nil {
		rawToSockaddrInet4(o.rsa, sa4)
	}
	return n, int(o.msg.Control.Len), int(o.msg.Flags), err
}

// ReadMsgInet6 is ReadMsg, but specialized to return a syscall.SockaddrInet6.
func (fd *FD) ReadMsgInet6(p []byte, oob []byte, flags int, sa6 *syscall.SockaddrInet6) (int, int, int, error) {
	if err := fd.readLock(); err != nil {
		return 0, 0, 0, err
	}
	defer fd.readUnlock()

	if len(p) > maxRW {
		p = p[:maxRW]
	}

	o := &fd.rop
	o.InitMsg(p, oob)
	if o.rsa == nil {
		o.rsa = new(syscall.RawSockaddrAny)
	}
	o.msg.Name = (syscall.Pointer)(unsafe.Pointer(o.rsa))
	o.msg.Namelen = int32(unsafe.Sizeof(*o.rsa))
	o.msg.Flags = uint32(flags)
	n, err := execIO(o, func(o *operation) error {
		return windows.WSARecvMsg(o.fd.Sysfd, &o.msg, &o.qty, &o.o, nil)
	})
	err = fd.eofError(n, err)
	if err == nil {
		rawToSockaddrInet6(o.rsa, sa6)
	}
	return n, int(o.msg.Control.Len), int(o.msg.Flags), err
}

// WriteMsg wraps the WSASendMsg network call.
func (fd *FD) WriteMsg(p []byte, oob []byte, sa syscall.Sockaddr) (int, int, error) {
	if len(p) > maxRW {
		return 0, 0, errors.New("packet is too large (only 1GB is allowed)")
	}

	if err := fd.writeLock(); err != nil {
		return 0, 0, err
	}
	defer fd.writeUnlock()

	o := &fd.wop
	o.InitMsg(p, oob)
	if sa != nil {
		if o.rsa == nil {
			o.rsa = new(syscall.RawSockaddrAny)
		}
		len, err := sockaddrToRaw(o.rsa, sa)
		if err !
"""




```