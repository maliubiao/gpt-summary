Response:
Let's break down the thought process for analyzing the provided Go code snippet from `netpoll_windows.go`.

**1. Initial Understanding: Context is Key**

The file name `netpoll_windows.go` immediately suggests this code handles network polling on Windows. "Netpoll" generally refers to a mechanism for efficiently monitoring multiple network sockets for readability or writability. The `runtime` package location indicates this is low-level code integral to Go's concurrency and I/O management.

**2. High-Level Functionality Scan:**

I'll read through the code, focusing on function names, constants, and global variables. This helps identify the major components:

* **Constants:** `_DWORD_MAX`, `_INVALID_HANDLE_VALUE`, `netpollSourceReady`, `netpollSourceBreak`, `netpollSourceTimer`, `sourceBits`, `sourceMasks`. These suggest constants related to Windows API values and internal identifiers for different netpoll events.
* **Functions:** `packNetpollKey`, `unpackNetpollSource`, `pollOperationFromOverlappedEntry`, `netpollinit`, `netpollIsPollDescriptor`, `netpollopen`, `netpollclose`, `netpollarm`, `netpollBreak`, `netpoll`, `netpollQueueTimer`. These are the active parts of the code, hinting at initialization, managing file descriptors, breaking the poll, the main polling loop, and timer management.
* **Variables:** `iocphandle`, `netpollWakeSig`. These are global state variables likely representing the I/O Completion Port handle and a signal for breaking the poll.
* **Structures:** `pollOperation`, `overlappedEntry`. These define the data structures used in the Windows API interactions and internal bookkeeping.

**3. Deeper Dive into Key Functions:**

Now, I'll focus on the more complex and crucial functions to understand their logic:

* **`packNetpollKey` and `unpackNetpollSource`:** These functions clearly deal with packing and unpacking data into a `uintptr`. The comments and the use of `sourceBits` and `sourceMasks` indicate a way to combine a "source" (like `netpollSourceReady`) and a `pollDesc` pointer into a single value. This is likely an optimization or a requirement of the underlying Windows API. The conditional logic based on `goarch.PtrSize` suggests different packing strategies for 32-bit and 64-bit architectures.
* **`pollOperationFromOverlappedEntry`:** This function attempts to extract a `pollOperation` from an `overlappedEntry`. The checks involving `e.key` and the `pollDesc` pointer strongly suggest this is how the Go runtime associates asynchronous I/O results with the corresponding network operations.
* **`netpollinit`:**  This looks like the initialization step, creating an I/O Completion Port using `_CreateIoCompletionPort`.
* **`netpollopen`:** This function associates a file descriptor (`fd`) with the I/O Completion Port, which is the core of registering a socket for asynchronous I/O. The use of `packNetpollKey` reinforces the connection between the socket and internal Go data.
* **`netpollBreak`:** This function seems designed to interrupt the `netpoll` function. The use of `_PostQueuedCompletionStatus` suggests it's sending a special message to the I/O Completion Port. The `netpollWakeSig` appears to prevent redundant wake-up calls.
* **`netpoll`:** This is the heart of the netpoller. The call to `_GetQueuedCompletionStatusEx` is the central point where the Go runtime waits for I/O events. The logic for handling different `unpackNetpollSource` values indicates how different types of events (ready sockets, breaks, timers) are processed. The timer logic involving `netpollQueueTimer` adds complexity, indicating an optimization for handling timeouts.
* **`netpollQueueTimer`:** This function deals with setting up a high-resolution timer using Windows API calls like `_SetWaitableTimer` and `_NtAssociateWaitCompletionPacket`. The handling of `STATUS_PENDING` is interesting, suggesting a possible race condition that's being handled.

**4. Connecting to Go Concepts and Examples:**

Based on the analysis, I can start connecting the code to higher-level Go concepts:

* **Goroutines and Networking:** This code is fundamental to how Go manages concurrent network operations. When a goroutine performs a blocking network call (e.g., `conn.Read()`), the underlying implementation uses this `netpoll` mechanism to wait for the socket to become ready without blocking the entire OS thread.
* **I/O Multiplexing:** The use of an I/O Completion Port (IOCP) is a clear indication of I/O multiplexing. This allows a single thread to efficiently monitor multiple file descriptors.
* **Non-blocking I/O:** The asynchronous nature of IOCP enables non-blocking I/O operations. The Go runtime initiates an operation and gets notified when it completes.

**Constructing the Go Example:**

To illustrate the functionality, I'll create a simple example demonstrating a network connection and how the `netpoll` mechanism would be involved behind the scenes:

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()
	fmt.Println("Listening on:", addr)

	go func() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Println("Dial error:", err)
			return
		}
		defer conn.Close()
		_, err = conn.Write([]byte("Hello from client"))
		if err != nil {
			fmt.Println("Write error:", err)
		}
	}()

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Simulate a timeout scenario
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Read error:", err) // Could be a timeout error
	} else {
		fmt.Printf("Received: %s\n", buffer[:n])
	}

	time.Sleep(1 * time.Second) // Allow time for the client to finish
}
```

In this example, when `ln.Accept()` or `conn.Read()` is called, the Go runtime, under the hood, interacts with the `netpoll` mechanism (specifically `netpoll_windows.go` on Windows) to wait for the connection or data to become available. The timeout set by `conn.SetReadDeadline` would involve the timer functionality implemented in `netpollQueueTimer`.

**5. Identifying Potential Pitfalls:**

I'll consider what mistakes a developer might make that relate to this low-level code, even though they don't directly interact with it:

* **Incorrectly assuming blocking behavior:** Developers might misunderstand that network operations in Go are generally non-blocking at the OS level, thanks to `netpoll`. This might lead to inefficient code if they try to implement their own polling mechanisms.
* **Not handling timeouts correctly:** While Go provides abstractions for timeouts, misunderstanding how `netpoll` handles them could lead to unexpected behavior or resource leaks in very low-level scenarios.

**6. Review and Refine:**

Finally, I'll review my analysis to ensure clarity, accuracy, and completeness. I'll double-check the connections between the code and Go's high-level features and ensure the example code is relevant. I'll also make sure the explanation of potential pitfalls is clear and concise.

This structured approach, starting from a high-level understanding and progressively diving deeper, allows for a comprehensive analysis of complex code like the provided `netpoll_windows.go` snippet.
这段代码是 Go 语言运行时环境在 Windows 平台下实现网络轮询 (netpoll) 的一部分。网络轮询是 Go 语言实现高效并发网络编程的关键机制，它允许一个或少量线程同时监听多个网络连接的事件，例如连接就绪、数据可读、数据可写等。

以下是该代码片段的主要功能：

1. **I/O 完成端口 (IOCP) 的管理:**
   - `iocphandle`:  存储着 Windows I/O 完成端口的句柄。IOCP 是 Windows 提供的一种高效异步 I/O 机制。
   - `netpollinit()`: 初始化网络轮询器，创建一个新的 I/O 完成端口。这是 Go 语言网络库在启动时需要执行的操作。
   - `netpollIsPollDescriptor(fd uintptr) bool`:  检查给定的文件描述符 `fd` 是否是 IOCP 的句柄。

2. **文件描述符与 IOCP 的关联:**
   - `netpollopen(fd uintptr, pd *pollDesc) int32`:  将给定的文件描述符 `fd` 注册到 IOCP。`pd` 是一个指向 `pollDesc` 结构的指针，该结构包含了与该文件描述符相关的 Go 运行时状态信息。  此函数使用 `CreateIoCompletionPort` Windows API 将文件描述符与 IOCP 关联起来。
   - `netpollclose(fd uintptr) int32`:  虽然函数存在，但在 Windows 的 IOCP 模型下，关闭文件描述符会自动将其从 IOCP 中移除，因此这个函数目前没有实际操作。

3. **网络事件的触发与处理:**
   - `netpollBreak()`:  用于唤醒正在 `netpoll()` 中等待的 goroutine。它通过向 IOCP 投递一个特殊的完成状态来实现，从而中断 `GetQueuedCompletionStatusEx` 的阻塞。`netpollWakeSig` 用于避免重复唤醒。
   - `netpoll(delay int64) (gList, int32)`:  这是网络轮询的核心函数。它使用 `GetQueuedCompletionStatusEx` Windows API 从 IOCP 队列中获取已完成的 I/O 操作。
     - `delay`:  指定等待事件的最长时间。负数表示无限等待，0 表示非阻塞轮询，正数表示等待的纳秒数。
     - 返回值:
       - `gList`:  一个等待运行的 goroutine 列表。当网络事件发生时，相应的 goroutine 会被添加到这个列表中。
       - `int32`:  一个用于调整 `netpollWaiters` 计数器的增量值。
   - `overlappedEntry`:  表示从 `GetQueuedCompletionStatusEx` 返回的一个完成状态条目，包含了完成的键 (key)、`OVERLAPPED` 结构指针、内部状态和传输的字节数。
   - `pollOperation`:  Go 运行时内部用于跟踪正在进行的网络操作的结构，包含了指向 `overlapped` 结构和 `pollDesc` 结构的指针，以及操作模式 (读或写)。
   - `pollOperationFromOverlappedEntry(e *overlappedEntry) *pollOperation`:  从 `overlappedEntry` 中提取 `pollOperation` 结构。通过检查 `e.key` 是否与 `pollOperation.pd` 匹配来验证条目的有效性。
   - `unpackNetpollSource(key uintptr) uint8`:  从 IOCP 返回的 key 中解包出事件的来源 (例如 `netpollSourceReady`, `netpollSourceBreak`, `netpollSourceTimer`)。
   - `packNetpollKey(source uint8, pd *pollDesc) uintptr`:  将事件来源和 `pollDesc` 指针打包成一个 `uintptr` 值，用于设置 IOCP 完成状态的 key。这允许 `netpoll` 函数区分不同的事件类型。

4. **定时器支持 (用于实现网络操作的超时):**
   - `netpollQueueTimer(delay int64) (signaled bool)`:  用于设置一个定时器，在指定的 `delay` 时间后唤醒 `netpoll`。它使用了 Windows 的 `SetWaitableTimer` 和 `NtAssociateWaitCompletionPacket` API。
   - `netpollSourceTimer`:  一个常量，表示定时器事件的来源。
   - 当 `netpoll` 被定时器唤醒时，它会检查 `unpackNetpollSource(e.key)` 是否为 `netpollSourceTimer`。

5. **内部常量和辅助函数:**
   - `_DWORD_MAX`, `_INVALID_HANDLE_VALUE`:  Windows API 中常用的常量。
   - `sourceBits`, `sourceMasks`:  用于在 key 中存储事件来源信息的位掩码。

**可以推理出它是什么 Go 语言功能的实现:**

这段代码是 Go 语言 **网络 I/O 多路复用** (I/O multiplexing) 功能在 Windows 平台下的底层实现。它使用了 Windows 特有的 I/O 完成端口 (IOCP) 技术，使得 Go 可以在一个或少数几个系统线程上高效地管理大量的并发网络连接。

**Go 代码示例:**

以下是一个简单的 TCP 服务器示例，它在底层使用了 `netpoll_windows.go` 中的机制：

```go
package main

import (
	"fmt"
	"net"
	"time"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 设置读取超时
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}
	fmt.Printf("Received: %s\n", buffer[:n])
	_, err = conn.Write([]byte("Hello from server"))
	if err != nil {
		fmt.Println("Error writing:", err)
	}
}

func main() {
	listener, err := net.Listen("tcp", "localhost:0") // 监听本地任意可用端口
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Listening on:", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting:", err)
			continue
		}
		go handleConnection(conn) // 为每个连接启动一个 goroutine
	}
}
```

**假设的输入与输出（针对 `netpoll` 函数）：**

假设当前有一个 TCP 连接在 `pd` 指向的 `pollDesc` 结构中注册，并且客户端发送了一些数据。

**输入：** `netpoll(0)` （非阻塞轮询）

**输出：**
- `gList`:  包含与该 TCP 连接关联的 goroutine 的列表。由于数据已到达，`netpollready` 函数会被调用，并将等待该连接可读的 goroutine 放入 `gList` 中。
- `delta`:  可能是 1，表示有一个新的可运行的 goroutine 被添加到列表中。

**输入：** `netpoll(-1)` （无限等待）

**输出（当有连接变为可读或可写时）：**
- `gList`:  包含已就绪连接的 goroutine 列表。
- `delta`:  相应的计数器增量。

**输入：** `netpoll(1000000)` （等待 1 毫秒）

**输出（如果在 1 毫秒内没有事件发生）：**
- `gList`: 空列表。
- `delta`: 0。

**如果涉及命令行参数的具体处理，请详细介绍一下：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 包中的 `main` 函数或者通过 `flag` 等标准库进行。 `netpoll_windows.go` 是 Go 运行时的一部分，负责底层的网络事件轮询，它并不关心用户在命令行中传递了什么参数。

**有哪些使用者易犯错的点，请举例说明，没有则不必说明：**

普通 Go 开发者通常不会直接与 `netpoll_windows.go` 交互。 这是 Go 运行时内部的实现细节。 然而，理解其背后的原理可以帮助开发者更好地理解 Go 的并发模型和网络编程：

1. **误解阻塞行为:**  新手可能会认为在 `conn.Read()` 或 `conn.Accept()` 等操作时，当前的操作系统线程会直接阻塞。实际上，Go 运行时会使用 `netpoll` 将这些操作注册到 IOCP，使得 Goroutine 可以被挂起，而底层的系统线程可以继续处理其他任务。理解这一点有助于理解 Go 如何利用少量线程实现高并发。

2. **忽视超时设置的重要性:** 虽然 `netpollQueueTimer` 提供了超时机制，但开发者仍然需要在高层代码中正确设置和处理超时。例如，在使用 `SetDeadline`、`SetReadDeadline` 或 `SetWriteDeadline` 时，需要意识到这些超时最终会通过 `netpoll` 的定时器机制来实现。  忘记设置超时可能导致程序在网络出现问题时永久阻塞。

总而言之，`go/src/runtime/netpoll_windows.go` 是 Go 语言在 Windows 平台上实现高效并发网络编程的关键组成部分，它利用 Windows 的 IOCP 机制来监听和处理网络事件，使得 Go 程序能够以较小的资源消耗处理大量的并发网络连接。

### 提示词
```
这是路径为go/src/runtime/netpoll_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/goarch"
	"internal/runtime/atomic"
	"unsafe"
)

const _DWORD_MAX = 0xffffffff

const _INVALID_HANDLE_VALUE = ^uintptr(0)

// Sources are used to identify the event that created an overlapped entry.
// The source values are arbitrary. There is no risk of collision with user
// defined values because the only way to set the key of an overlapped entry
// is using the iocphandle, which is not accessible to user code.
const (
	netpollSourceReady = iota + 1
	netpollSourceBreak
	netpollSourceTimer
)

const (
	// sourceBits is the number of bits needed to represent a source.
	// 4 bits can hold 16 different sources, which is more than enough.
	// It is set to a low value so the overlapped entry key can
	// contain as much bits as possible for the pollDesc pointer.
	sourceBits  = 4 // 4 bits can hold 16 different sources, which is more than enough.
	sourceMasks = 1<<sourceBits - 1
)

// packNetpollKey creates a key from a source and a tag.
// Bits that don't fit in the result are discarded.
func packNetpollKey(source uint8, pd *pollDesc) uintptr {
	// TODO: Consider combining the source with pd.fdseq to detect stale pollDescs.
	if source > (1<<sourceBits)-1 {
		// Also fail on 64-bit systems, even though it can hold more bits.
		throw("runtime: source value is too large")
	}
	if goarch.PtrSize == 4 {
		return uintptr(unsafe.Pointer(pd))<<sourceBits | uintptr(source)
	}
	return uintptr(taggedPointerPack(unsafe.Pointer(pd), uintptr(source)))
}

// unpackNetpollSource returns the source packed key.
func unpackNetpollSource(key uintptr) uint8 {
	if goarch.PtrSize == 4 {
		return uint8(key & sourceMasks)
	}
	return uint8(taggedPointer(key).tag())
}

// pollOperation must be the same as beginning of internal/poll.operation.
// Keep these in sync.
type pollOperation struct {
	// used by windows
	_ overlapped
	// used by netpoll
	pd   *pollDesc
	mode int32
}

// pollOperationFromOverlappedEntry returns the pollOperation contained in
// e. It can return nil if the entry is not from internal/poll.
// See go.dev/issue/58870
func pollOperationFromOverlappedEntry(e *overlappedEntry) *pollOperation {
	if e.ov == nil {
		return nil
	}
	op := (*pollOperation)(unsafe.Pointer(e.ov))
	// Check that the key matches the pollDesc pointer.
	var keyMatch bool
	if goarch.PtrSize == 4 {
		keyMatch = e.key&^sourceMasks == uintptr(unsafe.Pointer(op.pd))<<sourceBits
	} else {
		keyMatch = (*pollDesc)(taggedPointer(e.key).pointer()) == op.pd
	}
	if !keyMatch {
		return nil
	}
	return op
}

// overlappedEntry contains the information returned by a call to GetQueuedCompletionStatusEx.
// https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped_entry
type overlappedEntry struct {
	key      uintptr
	ov       *overlapped
	internal uintptr
	qty      uint32
}

var (
	iocphandle uintptr = _INVALID_HANDLE_VALUE // completion port io handle

	netpollWakeSig atomic.Uint32 // used to avoid duplicate calls of netpollBreak
)

func netpollinit() {
	iocphandle = stdcall4(_CreateIoCompletionPort, _INVALID_HANDLE_VALUE, 0, 0, _DWORD_MAX)
	if iocphandle == 0 {
		println("runtime: CreateIoCompletionPort failed (errno=", getlasterror(), ")")
		throw("runtime: netpollinit failed")
	}
}

func netpollIsPollDescriptor(fd uintptr) bool {
	return fd == iocphandle
}

func netpollopen(fd uintptr, pd *pollDesc) int32 {
	key := packNetpollKey(netpollSourceReady, pd)
	if stdcall4(_CreateIoCompletionPort, fd, iocphandle, key, 0) == 0 {
		return int32(getlasterror())
	}
	return 0
}

func netpollclose(fd uintptr) int32 {
	// nothing to do
	return 0
}

func netpollarm(pd *pollDesc, mode int) {
	throw("runtime: unused")
}

func netpollBreak() {
	// Failing to cas indicates there is an in-flight wakeup, so we're done here.
	if !netpollWakeSig.CompareAndSwap(0, 1) {
		return
	}

	key := packNetpollKey(netpollSourceBreak, nil)
	if stdcall4(_PostQueuedCompletionStatus, iocphandle, 0, key, 0) == 0 {
		println("runtime: netpoll: PostQueuedCompletionStatus failed (errno=", getlasterror(), ")")
		throw("runtime: netpoll: PostQueuedCompletionStatus failed")
	}
}

// netpoll checks for ready network connections.
// Returns a list of goroutines that become runnable,
// and a delta to add to netpollWaiters.
// This must never return an empty list with a non-zero delta.
//
// delay < 0: blocks indefinitely
// delay == 0: does not block, just polls
// delay > 0: block for up to that many nanoseconds
func netpoll(delay int64) (gList, int32) {
	if iocphandle == _INVALID_HANDLE_VALUE {
		return gList{}, 0
	}

	var entries [64]overlappedEntry
	var wait uint32
	var toRun gList
	mp := getg().m

	if delay >= 1e15 {
		// An arbitrary cap on how long to wait for a timer.
		// 1e15 ns == ~11.5 days.
		delay = 1e15
	}

	if delay > 0 && mp.waitIocpHandle != 0 {
		// GetQueuedCompletionStatusEx doesn't use a high resolution timer internally,
		// so we use a separate higher resolution timer associated with a wait completion
		// packet to wake up the poller. Note that the completion packet can be delivered
		// to another thread, and the Go scheduler expects netpoll to only block up to delay,
		// so we still need to use a timeout with GetQueuedCompletionStatusEx.
		// TODO: Improve the Go scheduler to support non-blocking timers.
		signaled := netpollQueueTimer(delay)
		if signaled {
			// There is a small window between the SetWaitableTimer and the NtAssociateWaitCompletionPacket
			// where the timer can expire. We can return immediately in this case.
			return gList{}, 0
		}
	}
	if delay < 0 {
		wait = _INFINITE
	} else if delay == 0 {
		wait = 0
	} else if delay < 1e6 {
		wait = 1
	} else {
		wait = uint32(delay / 1e6)
	}
	n := len(entries) / int(gomaxprocs)
	if n < 8 {
		n = 8
	}
	if delay != 0 {
		mp.blocked = true
	}
	if stdcall6(_GetQueuedCompletionStatusEx, iocphandle, uintptr(unsafe.Pointer(&entries[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), uintptr(wait), 0) == 0 {
		mp.blocked = false
		errno := getlasterror()
		if errno == _WAIT_TIMEOUT {
			return gList{}, 0
		}
		println("runtime: GetQueuedCompletionStatusEx failed (errno=", errno, ")")
		throw("runtime: netpoll failed")
	}
	mp.blocked = false
	delta := int32(0)
	for i := 0; i < n; i++ {
		e := &entries[i]
		switch unpackNetpollSource(e.key) {
		case netpollSourceReady:
			op := pollOperationFromOverlappedEntry(e)
			if op == nil {
				// Entry from outside the Go runtime and internal/poll, ignore.
				continue
			}
			// Entry from internal/poll.
			mode := op.mode
			if mode != 'r' && mode != 'w' {
				println("runtime: GetQueuedCompletionStatusEx returned net_op with invalid mode=", mode)
				throw("runtime: netpoll failed")
			}
			delta += netpollready(&toRun, op.pd, mode)
		case netpollSourceBreak:
			netpollWakeSig.Store(0)
			if delay == 0 {
				// Forward the notification to the blocked poller.
				netpollBreak()
			}
		case netpollSourceTimer:
			// TODO: We could avoid calling NtCancelWaitCompletionPacket for expired wait completion packets.
		default:
			println("runtime: GetQueuedCompletionStatusEx returned net_op with invalid key=", e.key)
			throw("runtime: netpoll failed")
		}
	}
	return toRun, delta
}

// netpollQueueTimer queues a timer to wake up the poller after the given delay.
// It returns true if the timer expired during this call.
func netpollQueueTimer(delay int64) (signaled bool) {
	const (
		STATUS_SUCCESS   = 0x00000000
		STATUS_PENDING   = 0x00000103
		STATUS_CANCELLED = 0xC0000120
	)
	mp := getg().m
	// A wait completion packet can only be associated with one timer at a time,
	// so we need to cancel the previous one if it exists. This wouldn't be necessary
	// if the poller would only be woken up by the timer, in which case the association
	// would be automatically canceled, but it can also be woken up by other events,
	// such as a netpollBreak, so we can get to this point with a timer that hasn't
	// expired yet. In this case, the completion packet can still be picked up by
	// another thread, so defer the cancellation until it is really necessary.
	errno := stdcall2(_NtCancelWaitCompletionPacket, mp.waitIocpHandle, 1)
	switch errno {
	case STATUS_CANCELLED:
		// STATUS_CANCELLED is returned when the associated timer has already expired,
		// in which automatically cancels the wait completion packet.
		fallthrough
	case STATUS_SUCCESS:
		dt := -delay / 100 // relative sleep (negative), 100ns units
		if stdcall6(_SetWaitableTimer, mp.waitIocpTimer, uintptr(unsafe.Pointer(&dt)), 0, 0, 0, 0) == 0 {
			println("runtime: SetWaitableTimer failed; errno=", getlasterror())
			throw("runtime: netpoll failed")
		}
		key := packNetpollKey(netpollSourceTimer, nil)
		if errno := stdcall8(_NtAssociateWaitCompletionPacket, mp.waitIocpHandle, iocphandle, mp.waitIocpTimer, key, 0, 0, 0, uintptr(unsafe.Pointer(&signaled))); errno != 0 {
			println("runtime: NtAssociateWaitCompletionPacket failed; errno=", errno)
			throw("runtime: netpoll failed")
		}
	case STATUS_PENDING:
		// STATUS_PENDING is returned if the wait operation can't be canceled yet.
		// This can happen if this thread was woken up by another event, such as a netpollBreak,
		// and the timer expired just while calling NtCancelWaitCompletionPacket, in which case
		// this call fails to cancel the association to avoid a race condition.
		// This is a rare case, so we can just avoid using the high resolution timer this time.
	default:
		println("runtime: NtCancelWaitCompletionPacket failed; errno=", errno)
		throw("runtime: netpoll failed")
	}
	return signaled
}
```