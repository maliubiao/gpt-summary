Response:
Let's break down the thought process for analyzing the provided Go code snippet for `netpoll.go`.

1. **Understand the Goal:** The request asks for the functionality of the code, its role in Go, code examples, command-line arguments (if any), and common pitfalls.

2. **Initial Scan for Keywords and Comments:** Quickly read through the code, looking for comments and function names that give clues about its purpose. Keywords like "poller," "fd," "goroutine," "ready," "wait," "timeout," "close," "epoll," "kqueue," "timer" jump out. The initial comment block is very informative.

3. **Identify Key Data Structures:** Notice the central `pollDesc` struct. Its fields like `rg`, `wg`, `lock`, `rt`, `wt`, `rd`, `wd`, and `closing` strongly suggest it's managing the state of file descriptors for network I/O operations. The `pollCache` struct is also important, seemingly for managing a pool of `pollDesc` objects.

4. **Analyze Key Functions (Based on the Initial Comment):** The comment block explicitly lists essential functions. Focus on understanding the purpose of each:
    * `netpollinit()`: Initialization.
    * `netpollopen(fd, pd)`:  Arming notifications for a file descriptor. The term "edge-triggered" is significant (although not explained in the provided code).
    * `netpollclose(fd)`: Disabling notifications.
    * `netpoll(delta)`: The core polling function, handling blocking/non-blocking behavior.
    * `netpollBreak()`: Waking up the poller.
    * `netpollIsPollDescriptor(fd)`: Checking if a file descriptor is used by the poller.

5. **Trace the Flow of Operations (Hypothetical):** Imagine a simple network operation like accepting a connection. How would these functions be involved?
    * A new socket is created (file descriptor).
    * `netpollopen` would be called to register the socket with the poller.
    * `netpoll` would be called periodically to check for ready sockets.
    * When a connection arrives, `netpollready` would be called by the platform-specific implementation.
    * `netpollready` would unblock the goroutine waiting to accept.
    * When the socket is no longer needed, `netpollclose` would be called.

6. **Connect to Go's Concurrency Model:** The presence of `rg` and `wg` semaphores, the interaction with goroutines (passing `g` pointers), and functions like `gopark` and `goready` clearly link this code to Go's concurrency mechanisms. The `netpollWaiters` variable suggests a way for the scheduler to know if there's I/O to wait on.

7. **Infer Go Feature:** Based on the above, it's highly likely this code implements the **network poller**, which is a core component for handling asynchronous network I/O in Go. This enables goroutines to wait efficiently for network events without blocking operating system threads.

8. **Construct Code Examples:** Create simple examples that demonstrate the use of network operations that would rely on this code. A basic TCP server or client using `net.Listen` and `net.Dial` is a good starting point. Emphasize how Go manages concurrency behind the scenes.

9. **Address Command-Line Arguments:** Carefully review the code for any explicit handling of command-line arguments. In this snippet, there are none. State this explicitly.

10. **Identify Common Mistakes:** Think about how developers might misuse network I/O in Go. Forgetting to set deadlines, not handling errors correctly, or misunderstanding the non-blocking nature of asynchronous operations are common issues. Relate these back to the concepts in the code (e.g., deadlines and error handling via `netpollcheckerr`).

11. **Structure the Answer:** Organize the findings into logical sections: Functionality, Go Feature, Code Example, Command-Line Arguments, Common Mistakes. Use clear and concise language.

12. **Refine and Elaborate:** Review the answer for clarity and completeness. Explain any technical terms that might not be immediately obvious (like "edge-triggered"). Expand on the "why" behind certain design choices if possible (e.g., the use of non-GC memory).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this is just about file I/O. **Correction:** The focus on "network poller," `epoll`, `kqueue`, and the use cases in the comments strongly point to *network* I/O specifically.
* **Initial thought:** The `pollDesc` is just a simple data structure. **Correction:** The internal state management with `pdNil`, `pdReady`, `pdWait`, and the atomic operations reveal a more complex synchronization mechanism.
* **Concern:**  The code doesn't directly call `epoll_wait` or `kqueue`. **Resolution:** The comments clearly state that this is the *platform-independent* part. The platform-specific implementations are separate.

By following this methodical process, combining code analysis with an understanding of operating system and concurrency concepts, a comprehensive and accurate answer can be constructed.
这段Go语言代码是 `runtime` 包中 `netpoll.go` 文件的一部分，它实现了 Go 运行时环境中的**网络轮询器（Network Poller）**的核心逻辑。这个轮询器是 Go 语言实现高效异步非阻塞网络 I/O 的关键组件。

以下是它的主要功能：

1. **定义了平台无关的网络轮询器接口:**
   - 代码中定义了一些函数签名，例如 `netpollinit`，`netpollopen`，`netpollclose`，`netpoll`，`netpollBreak`，`netpollIsPollDescriptor`。这些函数的具体实现依赖于不同的操作系统（例如 Linux 的 epoll，macOS 的 kqueue，Windows 的 IOCP 等）。
   - 这部分代码抽象出了网络轮询器的通用行为，使得 Go 语言的网络库可以在不同的操作系统上运行，而无需修改上层代码。

2. **管理网络连接的状态:**
   - `pollDesc` 结构体是核心的数据结构，它存储了与一个文件描述符（通常是 socket）相关的状态信息，例如读写就绪信号量 (`rg`, `wg`)，关闭状态 (`closing`)，读写超时时间 (`rd`, `wd`) 等。
   - `pollCache` 用于管理 `pollDesc` 对象的缓存，避免频繁的内存分配和回收。

3. **实现 Goroutine 的阻塞和唤醒:**
   - 当一个 Goroutine 需要等待网络连接可读或可写时，它会被阻塞在 `pollDesc` 的 `rg` 或 `wg` 信号量上。
   - 当底层操作系统报告文件描述符就绪时，平台相关的 `netpollready` 函数会被调用，它会唤醒等待在该文件描述符上的 Goroutine。

4. **处理网络 I/O 的超时:**
   - `pollDesc` 中存储了读写超时时间 (`rd`, `wd`)。
   - `netpollSetDeadline` 函数用于设置超时时间。
   - 当超时时间到达时，相应的 Goroutine 会被唤醒。

5. **处理文件描述符的关闭:**
   - `poll_runtime_pollClose` 函数负责关闭文件描述符，并清理相关的 `pollDesc` 资源。
   - 在关闭过程中，会确保没有 Goroutine 仍然阻塞在该文件描述符上。

6. **提供与 `internal/poll` 包的接口:**
   - 代码中使用了 `//go:linkname` 指令，将 `runtime` 包中的函数链接到 `internal/poll` 包中的函数，例如 `poll_runtime_pollOpen`，`poll_runtime_pollReset`，`poll_runtime_pollWait` 等。
   - `internal/poll` 包提供了更上层的、与操作系统无关的网络 I/O 抽象，而 `runtime/netpoll.go` 负责与底层操作系统进行交互。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言实现**异步非阻塞网络 I/O** 的核心基础设施。它支撑着 Go 标准库中的 `net` 包，使得用户可以编写高效的网络应用程序。

**Go 代码举例说明:**

以下是一个简单的 TCP 服务器的例子，它在底层使用了 `netpoll.go` 中的机制：

```go
package main

import (
	"fmt"
	"net"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			return
		}
		fmt.Printf("Received: %s", buf[:n])
		_, err = conn.Write([]byte("Hello from server!\n"))
		if err != nil {
			fmt.Println("Write error:", err)
			return
		}
	}
}

func main() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Listening on :8080")
	for {
		conn, err := listener.Accept() // 这一步会阻塞，直到有新的连接到来
		if err != nil {
			fmt.Println("Error accepting:", err)
			continue
		}
		go handleConnection(conn)
	}
}
```

**代码推理 (假设的输入与输出):**

当 `listener.Accept()` 被调用时：

1. **假设输入:** 没有新的连接到来。
2. **代码推理:**
   - `listener.Accept()` 底层会调用 `internal/poll` 包的相关函数，最终会调用到 `runtime/netpoll.go` 中的 `poll_runtime_pollWait` 函数。
   - `poll_runtime_pollWait` 函数会检查文件描述符（listener 的 socket）的状态，如果当前没有就绪的连接，则会调用 `netpollblock` 函数。
   - `netpollblock` 函数会将当前的 Goroutine 阻塞，等待网络轮询器通知文件描述符就绪。具体来说，它会将 `pollDesc` 中与读操作相关的信号量 (`rg`) 设置为 `pdWait`，并将当前 Goroutine 挂起。
   - 底层的操作系统轮询机制（例如 epoll）会监听 listener 的 socket。
3. **假设输入:**  有新的连接到来。
4. **代码推理:**
   - 操作系统轮询器检测到 listener 的 socket 上有新的连接事件。
   - 操作系统会通知 Go 运行时环境。
   - 平台相关的 `netpollready` 函数会被调用，它会找到与 listener 的 socket 关联的 `pollDesc`。
   - `netpollready` 会调用 `netpollunblock` 函数，将阻塞在 `rg` 上的 Goroutine 唤醒，并将 `rg` 的状态设置为 `pdReady`。
   - 被唤醒的 Goroutine 会继续执行 `listener.Accept()` 的后续操作，例如创建新的 `net.Conn` 对象。
5. **输出:** `listener.Accept()` 返回一个新的 `net.Conn` 对象，代表了新建立的连接。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数或者使用了 `flag` 等标准库的更上层代码中。`netpoll.go` 专注于底层的网络事件处理。

**使用者易犯错的点:**

虽然开发者通常不会直接与 `runtime/netpoll.go` 交互，但理解其工作原理有助于避免一些常见的网络编程错误：

1. **没有设置超时时间:** 如果在进行网络 I/O 操作时没有设置合适的超时时间，可能会导致 Goroutine 永久阻塞，例如在 `conn.Read()` 或 `conn.Write()` 时，如果对端没有响应，Goroutine 将会一直等待。Go 的 `net` 包提供了 `SetDeadline`，`SetReadDeadline` 和 `SetWriteDeadline` 等方法来设置超时。

   **错误示例:**

   ```go
   conn, err := net.Dial("tcp", "some.unresponsive.server:80")
   if err != nil {
       // ... handle error
   }
   defer conn.Close()
   buf := make([]byte, 1024)
   _, err = conn.Read(buf) // 如果服务器无响应，这里会一直阻塞
   if err != nil {
       // ... handle error
   }
   ```

   **正确示例:**

   ```go
   conn, err := net.Dial("tcp", "some.unresponsive.server:80")
   if err != nil {
       // ... handle error
   }
   defer conn.Close()
   conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // 设置 5 秒读取超时
   buf := make([]byte, 1024)
   _, err = conn.Read(buf)
   if err != nil {
       if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
           fmt.Println("Read timed out")
       } else {
           // ... handle other errors
       }
   }
   ```

2. **不正确地处理网络错误:** 网络操作可能会因为各种原因失败，例如连接被关闭，网络中断等。开发者应该仔细检查返回的 `error`，并采取适当的措施，例如重试，关闭连接等。忽略错误可能导致程序行为异常。

3. **在高并发场景下资源泄漏:** 虽然 `pollCache` 帮助管理 `pollDesc`，但在极端高并发场景下，如果大量的连接被快速创建和销毁，可能会导致短暂的资源压力。正确地管理连接生命周期，避免不必要的连接创建和保持，是优化高并发网络应用的关键。

理解 `runtime/netpoll.go` 的工作原理可以帮助开发者更好地理解 Go 语言的并发模型和网络编程机制，从而编写出更健壮和高效的网络应用程序。

### 提示词
```
这是路径为go/src/runtime/netpoll.go的go语言实现的一部分， 请列举一下它的功能, 　
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

//go:build unix || (js && wasm) || wasip1 || windows

package runtime

import (
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

// Integrated network poller (platform-independent part).
// A particular implementation (epoll/kqueue/port/AIX/Windows)
// must define the following functions:
//
// func netpollinit()
//     Initialize the poller. Only called once.
//
// func netpollopen(fd uintptr, pd *pollDesc) int32
//     Arm edge-triggered notifications for fd. The pd argument is to pass
//     back to netpollready when fd is ready. Return an errno value.
//
// func netpollclose(fd uintptr) int32
//     Disable notifications for fd. Return an errno value.
//
// func netpoll(delta int64) (gList, int32)
//     Poll the network. If delta < 0, block indefinitely. If delta == 0,
//     poll without blocking. If delta > 0, block for up to delta nanoseconds.
//     Return a list of goroutines built by calling netpollready,
//     and a delta to add to netpollWaiters when all goroutines are ready.
//     This must never return an empty list with a non-zero delta.
//
// func netpollBreak()
//     Wake up the network poller, assumed to be blocked in netpoll.
//
// func netpollIsPollDescriptor(fd uintptr) bool
//     Reports whether fd is a file descriptor used by the poller.

// Error codes returned by runtime_pollReset and runtime_pollWait.
// These must match the values in internal/poll/fd_poll_runtime.go.
const (
	pollNoError        = 0 // no error
	pollErrClosing     = 1 // descriptor is closed
	pollErrTimeout     = 2 // I/O timeout
	pollErrNotPollable = 3 // general error polling descriptor
)

// pollDesc contains 2 binary semaphores, rg and wg, to park reader and writer
// goroutines respectively. The semaphore can be in the following states:
//
//	pdReady - io readiness notification is pending;
//	          a goroutine consumes the notification by changing the state to pdNil.
//	pdWait - a goroutine prepares to park on the semaphore, but not yet parked;
//	         the goroutine commits to park by changing the state to G pointer,
//	         or, alternatively, concurrent io notification changes the state to pdReady,
//	         or, alternatively, concurrent timeout/close changes the state to pdNil.
//	G pointer - the goroutine is blocked on the semaphore;
//	            io notification or timeout/close changes the state to pdReady or pdNil respectively
//	            and unparks the goroutine.
//	pdNil - none of the above.
const (
	pdNil   uintptr = 0
	pdReady uintptr = 1
	pdWait  uintptr = 2
)

const pollBlockSize = 4 * 1024

// Network poller descriptor.
//
// No heap pointers.
type pollDesc struct {
	_     sys.NotInHeap
	link  *pollDesc      // in pollcache, protected by pollcache.lock
	fd    uintptr        // constant for pollDesc usage lifetime
	fdseq atomic.Uintptr // protects against stale pollDesc

	// atomicInfo holds bits from closing, rd, and wd,
	// which are only ever written while holding the lock,
	// summarized for use by netpollcheckerr,
	// which cannot acquire the lock.
	// After writing these fields under lock in a way that
	// might change the summary, code must call publishInfo
	// before releasing the lock.
	// Code that changes fields and then calls netpollunblock
	// (while still holding the lock) must call publishInfo
	// before calling netpollunblock, because publishInfo is what
	// stops netpollblock from blocking anew
	// (by changing the result of netpollcheckerr).
	// atomicInfo also holds the eventErr bit,
	// recording whether a poll event on the fd got an error;
	// atomicInfo is the only source of truth for that bit.
	atomicInfo atomic.Uint32 // atomic pollInfo

	// rg, wg are accessed atomically and hold g pointers.
	// (Using atomic.Uintptr here is similar to using guintptr elsewhere.)
	rg atomic.Uintptr // pdReady, pdWait, G waiting for read or pdNil
	wg atomic.Uintptr // pdReady, pdWait, G waiting for write or pdNil

	lock    mutex // protects the following fields
	closing bool
	rrun    bool      // whether rt is running
	wrun    bool      // whether wt is running
	user    uint32    // user settable cookie
	rseq    uintptr   // protects from stale read timers
	rt      timer     // read deadline timer
	rd      int64     // read deadline (a nanotime in the future, -1 when expired)
	wseq    uintptr   // protects from stale write timers
	wt      timer     // write deadline timer
	wd      int64     // write deadline (a nanotime in the future, -1 when expired)
	self    *pollDesc // storage for indirect interface. See (*pollDesc).makeArg.
}

// pollInfo is the bits needed by netpollcheckerr, stored atomically,
// mostly duplicating state that is manipulated under lock in pollDesc.
// The one exception is the pollEventErr bit, which is maintained only
// in the pollInfo.
type pollInfo uint32

const (
	pollClosing = 1 << iota
	pollEventErr
	pollExpiredReadDeadline
	pollExpiredWriteDeadline
	pollFDSeq // 20 bit field, low 20 bits of fdseq field
)

const (
	pollFDSeqBits = 20                   // number of bits in pollFDSeq
	pollFDSeqMask = 1<<pollFDSeqBits - 1 // mask for pollFDSeq
)

func (i pollInfo) closing() bool              { return i&pollClosing != 0 }
func (i pollInfo) eventErr() bool             { return i&pollEventErr != 0 }
func (i pollInfo) expiredReadDeadline() bool  { return i&pollExpiredReadDeadline != 0 }
func (i pollInfo) expiredWriteDeadline() bool { return i&pollExpiredWriteDeadline != 0 }

// info returns the pollInfo corresponding to pd.
func (pd *pollDesc) info() pollInfo {
	return pollInfo(pd.atomicInfo.Load())
}

// publishInfo updates pd.atomicInfo (returned by pd.info)
// using the other values in pd.
// It must be called while holding pd.lock,
// and it must be called after changing anything
// that might affect the info bits.
// In practice this means after changing closing
// or changing rd or wd from < 0 to >= 0.
func (pd *pollDesc) publishInfo() {
	var info uint32
	if pd.closing {
		info |= pollClosing
	}
	if pd.rd < 0 {
		info |= pollExpiredReadDeadline
	}
	if pd.wd < 0 {
		info |= pollExpiredWriteDeadline
	}
	info |= uint32(pd.fdseq.Load()&pollFDSeqMask) << pollFDSeq

	// Set all of x except the pollEventErr bit.
	x := pd.atomicInfo.Load()
	for !pd.atomicInfo.CompareAndSwap(x, (x&pollEventErr)|info) {
		x = pd.atomicInfo.Load()
	}
}

// setEventErr sets the result of pd.info().eventErr() to b.
// We only change the error bit if seq == 0 or if seq matches pollFDSeq
// (issue #59545).
func (pd *pollDesc) setEventErr(b bool, seq uintptr) {
	mSeq := uint32(seq & pollFDSeqMask)
	x := pd.atomicInfo.Load()
	xSeq := (x >> pollFDSeq) & pollFDSeqMask
	if seq != 0 && xSeq != mSeq {
		return
	}
	for (x&pollEventErr != 0) != b && !pd.atomicInfo.CompareAndSwap(x, x^pollEventErr) {
		x = pd.atomicInfo.Load()
		xSeq := (x >> pollFDSeq) & pollFDSeqMask
		if seq != 0 && xSeq != mSeq {
			return
		}
	}
}

type pollCache struct {
	lock  mutex
	first *pollDesc
	// PollDesc objects must be type-stable,
	// because we can get ready notification from epoll/kqueue
	// after the descriptor is closed/reused.
	// Stale notifications are detected using seq variable,
	// seq is incremented when deadlines are changed or descriptor is reused.
}

var (
	netpollInitLock mutex
	netpollInited   atomic.Uint32

	pollcache      pollCache
	netpollWaiters atomic.Uint32
)

// netpollWaiters is accessed in tests
//go:linkname netpollWaiters

//go:linkname poll_runtime_pollServerInit internal/poll.runtime_pollServerInit
func poll_runtime_pollServerInit() {
	netpollGenericInit()
}

func netpollGenericInit() {
	if netpollInited.Load() == 0 {
		lockInit(&netpollInitLock, lockRankNetpollInit)
		lockInit(&pollcache.lock, lockRankPollCache)
		lock(&netpollInitLock)
		if netpollInited.Load() == 0 {
			netpollinit()
			netpollInited.Store(1)
		}
		unlock(&netpollInitLock)
	}
}

func netpollinited() bool {
	return netpollInited.Load() != 0
}

//go:linkname poll_runtime_isPollServerDescriptor internal/poll.runtime_isPollServerDescriptor

// poll_runtime_isPollServerDescriptor reports whether fd is a
// descriptor being used by netpoll.
func poll_runtime_isPollServerDescriptor(fd uintptr) bool {
	return netpollIsPollDescriptor(fd)
}

//go:linkname poll_runtime_pollOpen internal/poll.runtime_pollOpen
func poll_runtime_pollOpen(fd uintptr) (*pollDesc, int) {
	pd := pollcache.alloc()
	lock(&pd.lock)
	wg := pd.wg.Load()
	if wg != pdNil && wg != pdReady {
		throw("runtime: blocked write on free polldesc")
	}
	rg := pd.rg.Load()
	if rg != pdNil && rg != pdReady {
		throw("runtime: blocked read on free polldesc")
	}
	pd.fd = fd
	if pd.fdseq.Load() == 0 {
		// The value 0 is special in setEventErr, so don't use it.
		pd.fdseq.Store(1)
	}
	pd.closing = false
	pd.setEventErr(false, 0)
	pd.rseq++
	pd.rg.Store(pdNil)
	pd.rd = 0
	pd.wseq++
	pd.wg.Store(pdNil)
	pd.wd = 0
	pd.self = pd
	pd.publishInfo()
	unlock(&pd.lock)

	errno := netpollopen(fd, pd)
	if errno != 0 {
		pollcache.free(pd)
		return nil, int(errno)
	}
	return pd, 0
}

//go:linkname poll_runtime_pollClose internal/poll.runtime_pollClose
func poll_runtime_pollClose(pd *pollDesc) {
	if !pd.closing {
		throw("runtime: close polldesc w/o unblock")
	}
	wg := pd.wg.Load()
	if wg != pdNil && wg != pdReady {
		throw("runtime: blocked write on closing polldesc")
	}
	rg := pd.rg.Load()
	if rg != pdNil && rg != pdReady {
		throw("runtime: blocked read on closing polldesc")
	}
	netpollclose(pd.fd)
	pollcache.free(pd)
}

func (c *pollCache) free(pd *pollDesc) {
	// pd can't be shared here, but lock anyhow because
	// that's what publishInfo documents.
	lock(&pd.lock)

	// Increment the fdseq field, so that any currently
	// running netpoll calls will not mark pd as ready.
	fdseq := pd.fdseq.Load()
	fdseq = (fdseq + 1) & (1<<taggedPointerBits - 1)
	pd.fdseq.Store(fdseq)

	pd.publishInfo()

	unlock(&pd.lock)

	lock(&c.lock)
	pd.link = c.first
	c.first = pd
	unlock(&c.lock)
}

// poll_runtime_pollReset, which is internal/poll.runtime_pollReset,
// prepares a descriptor for polling in mode, which is 'r' or 'w'.
// This returns an error code; the codes are defined above.
//
//go:linkname poll_runtime_pollReset internal/poll.runtime_pollReset
func poll_runtime_pollReset(pd *pollDesc, mode int) int {
	errcode := netpollcheckerr(pd, int32(mode))
	if errcode != pollNoError {
		return errcode
	}
	if mode == 'r' {
		pd.rg.Store(pdNil)
	} else if mode == 'w' {
		pd.wg.Store(pdNil)
	}
	return pollNoError
}

// poll_runtime_pollWait, which is internal/poll.runtime_pollWait,
// waits for a descriptor to be ready for reading or writing,
// according to mode, which is 'r' or 'w'.
// This returns an error code; the codes are defined above.
//
//go:linkname poll_runtime_pollWait internal/poll.runtime_pollWait
func poll_runtime_pollWait(pd *pollDesc, mode int) int {
	errcode := netpollcheckerr(pd, int32(mode))
	if errcode != pollNoError {
		return errcode
	}
	// As for now only Solaris, illumos, AIX and wasip1 use level-triggered IO.
	if GOOS == "solaris" || GOOS == "illumos" || GOOS == "aix" || GOOS == "wasip1" {
		netpollarm(pd, mode)
	}
	for !netpollblock(pd, int32(mode), false) {
		errcode = netpollcheckerr(pd, int32(mode))
		if errcode != pollNoError {
			return errcode
		}
		// Can happen if timeout has fired and unblocked us,
		// but before we had a chance to run, timeout has been reset.
		// Pretend it has not happened and retry.
	}
	return pollNoError
}

//go:linkname poll_runtime_pollWaitCanceled internal/poll.runtime_pollWaitCanceled
func poll_runtime_pollWaitCanceled(pd *pollDesc, mode int) {
	// This function is used only on windows after a failed attempt to cancel
	// a pending async IO operation. Wait for ioready, ignore closing or timeouts.
	for !netpollblock(pd, int32(mode), true) {
	}
}

//go:linkname poll_runtime_pollSetDeadline internal/poll.runtime_pollSetDeadline
func poll_runtime_pollSetDeadline(pd *pollDesc, d int64, mode int) {
	lock(&pd.lock)
	if pd.closing {
		unlock(&pd.lock)
		return
	}
	rd0, wd0 := pd.rd, pd.wd
	combo0 := rd0 > 0 && rd0 == wd0
	if d > 0 {
		d += nanotime()
		if d <= 0 {
			// If the user has a deadline in the future, but the delay calculation
			// overflows, then set the deadline to the maximum possible value.
			d = 1<<63 - 1
		}
	}
	if mode == 'r' || mode == 'r'+'w' {
		pd.rd = d
	}
	if mode == 'w' || mode == 'r'+'w' {
		pd.wd = d
	}
	pd.publishInfo()
	combo := pd.rd > 0 && pd.rd == pd.wd
	rtf := netpollReadDeadline
	if combo {
		rtf = netpollDeadline
	}
	if !pd.rrun {
		if pd.rd > 0 {
			// Copy current seq into the timer arg.
			// Timer func will check the seq against current descriptor seq,
			// if they differ the descriptor was reused or timers were reset.
			pd.rt.modify(pd.rd, 0, rtf, pd.makeArg(), pd.rseq)
			pd.rrun = true
		}
	} else if pd.rd != rd0 || combo != combo0 {
		pd.rseq++ // invalidate current timers
		if pd.rd > 0 {
			pd.rt.modify(pd.rd, 0, rtf, pd.makeArg(), pd.rseq)
		} else {
			pd.rt.stop()
			pd.rrun = false
		}
	}
	if !pd.wrun {
		if pd.wd > 0 && !combo {
			pd.wt.modify(pd.wd, 0, netpollWriteDeadline, pd.makeArg(), pd.wseq)
			pd.wrun = true
		}
	} else if pd.wd != wd0 || combo != combo0 {
		pd.wseq++ // invalidate current timers
		if pd.wd > 0 && !combo {
			pd.wt.modify(pd.wd, 0, netpollWriteDeadline, pd.makeArg(), pd.wseq)
		} else {
			pd.wt.stop()
			pd.wrun = false
		}
	}
	// If we set the new deadline in the past, unblock currently pending IO if any.
	// Note that pd.publishInfo has already been called, above, immediately after modifying rd and wd.
	delta := int32(0)
	var rg, wg *g
	if pd.rd < 0 {
		rg = netpollunblock(pd, 'r', false, &delta)
	}
	if pd.wd < 0 {
		wg = netpollunblock(pd, 'w', false, &delta)
	}
	unlock(&pd.lock)
	if rg != nil {
		netpollgoready(rg, 3)
	}
	if wg != nil {
		netpollgoready(wg, 3)
	}
	netpollAdjustWaiters(delta)
}

//go:linkname poll_runtime_pollUnblock internal/poll.runtime_pollUnblock
func poll_runtime_pollUnblock(pd *pollDesc) {
	lock(&pd.lock)
	if pd.closing {
		throw("runtime: unblock on closing polldesc")
	}
	pd.closing = true
	pd.rseq++
	pd.wseq++
	var rg, wg *g
	pd.publishInfo()
	delta := int32(0)
	rg = netpollunblock(pd, 'r', false, &delta)
	wg = netpollunblock(pd, 'w', false, &delta)
	if pd.rrun {
		pd.rt.stop()
		pd.rrun = false
	}
	if pd.wrun {
		pd.wt.stop()
		pd.wrun = false
	}
	unlock(&pd.lock)
	if rg != nil {
		netpollgoready(rg, 3)
	}
	if wg != nil {
		netpollgoready(wg, 3)
	}
	netpollAdjustWaiters(delta)
}

// netpollready is called by the platform-specific netpoll function.
// It declares that the fd associated with pd is ready for I/O.
// The toRun argument is used to build a list of goroutines to return
// from netpoll. The mode argument is 'r', 'w', or 'r'+'w' to indicate
// whether the fd is ready for reading or writing or both.
//
// This returns a delta to apply to netpollWaiters.
//
// This may run while the world is stopped, so write barriers are not allowed.
//
//go:nowritebarrier
func netpollready(toRun *gList, pd *pollDesc, mode int32) int32 {
	delta := int32(0)
	var rg, wg *g
	if mode == 'r' || mode == 'r'+'w' {
		rg = netpollunblock(pd, 'r', true, &delta)
	}
	if mode == 'w' || mode == 'r'+'w' {
		wg = netpollunblock(pd, 'w', true, &delta)
	}
	if rg != nil {
		toRun.push(rg)
	}
	if wg != nil {
		toRun.push(wg)
	}
	return delta
}

func netpollcheckerr(pd *pollDesc, mode int32) int {
	info := pd.info()
	if info.closing() {
		return pollErrClosing
	}
	if (mode == 'r' && info.expiredReadDeadline()) || (mode == 'w' && info.expiredWriteDeadline()) {
		return pollErrTimeout
	}
	// Report an event scanning error only on a read event.
	// An error on a write event will be captured in a subsequent
	// write call that is able to report a more specific error.
	if mode == 'r' && info.eventErr() {
		return pollErrNotPollable
	}
	return pollNoError
}

func netpollblockcommit(gp *g, gpp unsafe.Pointer) bool {
	r := atomic.Casuintptr((*uintptr)(gpp), pdWait, uintptr(unsafe.Pointer(gp)))
	if r {
		// Bump the count of goroutines waiting for the poller.
		// The scheduler uses this to decide whether to block
		// waiting for the poller if there is nothing else to do.
		netpollAdjustWaiters(1)
	}
	return r
}

func netpollgoready(gp *g, traceskip int) {
	goready(gp, traceskip+1)
}

// returns true if IO is ready, or false if timed out or closed
// waitio - wait only for completed IO, ignore errors
// Concurrent calls to netpollblock in the same mode are forbidden, as pollDesc
// can hold only a single waiting goroutine for each mode.
func netpollblock(pd *pollDesc, mode int32, waitio bool) bool {
	gpp := &pd.rg
	if mode == 'w' {
		gpp = &pd.wg
	}

	// set the gpp semaphore to pdWait
	for {
		// Consume notification if already ready.
		if gpp.CompareAndSwap(pdReady, pdNil) {
			return true
		}
		if gpp.CompareAndSwap(pdNil, pdWait) {
			break
		}

		// Double check that this isn't corrupt; otherwise we'd loop
		// forever.
		if v := gpp.Load(); v != pdReady && v != pdNil {
			throw("runtime: double wait")
		}
	}

	// need to recheck error states after setting gpp to pdWait
	// this is necessary because runtime_pollUnblock/runtime_pollSetDeadline/deadlineimpl
	// do the opposite: store to closing/rd/wd, publishInfo, load of rg/wg
	if waitio || netpollcheckerr(pd, mode) == pollNoError {
		gopark(netpollblockcommit, unsafe.Pointer(gpp), waitReasonIOWait, traceBlockNet, 5)
	}
	// be careful to not lose concurrent pdReady notification
	old := gpp.Swap(pdNil)
	if old > pdWait {
		throw("runtime: corrupted polldesc")
	}
	return old == pdReady
}

// netpollunblock moves either pd.rg (if mode == 'r') or
// pd.wg (if mode == 'w') into the pdReady state.
// This returns any goroutine blocked on pd.{rg,wg}.
// It adds any adjustment to netpollWaiters to *delta;
// this adjustment should be applied after the goroutine has
// been marked ready.
func netpollunblock(pd *pollDesc, mode int32, ioready bool, delta *int32) *g {
	gpp := &pd.rg
	if mode == 'w' {
		gpp = &pd.wg
	}

	for {
		old := gpp.Load()
		if old == pdReady {
			return nil
		}
		if old == pdNil && !ioready {
			// Only set pdReady for ioready. runtime_pollWait
			// will check for timeout/cancel before waiting.
			return nil
		}
		new := pdNil
		if ioready {
			new = pdReady
		}
		if gpp.CompareAndSwap(old, new) {
			if old == pdWait {
				old = pdNil
			} else if old != pdNil {
				*delta -= 1
			}
			return (*g)(unsafe.Pointer(old))
		}
	}
}

func netpolldeadlineimpl(pd *pollDesc, seq uintptr, read, write bool) {
	lock(&pd.lock)
	// Seq arg is seq when the timer was set.
	// If it's stale, ignore the timer event.
	currentSeq := pd.rseq
	if !read {
		currentSeq = pd.wseq
	}
	if seq != currentSeq {
		// The descriptor was reused or timers were reset.
		unlock(&pd.lock)
		return
	}
	delta := int32(0)
	var rg *g
	if read {
		if pd.rd <= 0 || !pd.rrun {
			throw("runtime: inconsistent read deadline")
		}
		pd.rd = -1
		pd.publishInfo()
		rg = netpollunblock(pd, 'r', false, &delta)
	}
	var wg *g
	if write {
		if pd.wd <= 0 || !pd.wrun && !read {
			throw("runtime: inconsistent write deadline")
		}
		pd.wd = -1
		pd.publishInfo()
		wg = netpollunblock(pd, 'w', false, &delta)
	}
	unlock(&pd.lock)
	if rg != nil {
		netpollgoready(rg, 0)
	}
	if wg != nil {
		netpollgoready(wg, 0)
	}
	netpollAdjustWaiters(delta)
}

func netpollDeadline(arg any, seq uintptr, delta int64) {
	netpolldeadlineimpl(arg.(*pollDesc), seq, true, true)
}

func netpollReadDeadline(arg any, seq uintptr, delta int64) {
	netpolldeadlineimpl(arg.(*pollDesc), seq, true, false)
}

func netpollWriteDeadline(arg any, seq uintptr, delta int64) {
	netpolldeadlineimpl(arg.(*pollDesc), seq, false, true)
}

// netpollAnyWaiters reports whether any goroutines are waiting for I/O.
func netpollAnyWaiters() bool {
	return netpollWaiters.Load() > 0
}

// netpollAdjustWaiters adds delta to netpollWaiters.
func netpollAdjustWaiters(delta int32) {
	if delta != 0 {
		netpollWaiters.Add(delta)
	}
}

func (c *pollCache) alloc() *pollDesc {
	lock(&c.lock)
	if c.first == nil {
		const pdSize = unsafe.Sizeof(pollDesc{})
		n := pollBlockSize / pdSize
		if n == 0 {
			n = 1
		}
		// Must be in non-GC memory because can be referenced
		// only from epoll/kqueue internals.
		mem := persistentalloc(n*pdSize, 0, &memstats.other_sys)
		for i := uintptr(0); i < n; i++ {
			pd := (*pollDesc)(add(mem, i*pdSize))
			lockInit(&pd.lock, lockRankPollDesc)
			pd.rt.init(nil, nil)
			pd.wt.init(nil, nil)
			pd.link = c.first
			c.first = pd
		}
	}
	pd := c.first
	c.first = pd.link
	unlock(&c.lock)
	return pd
}

// makeArg converts pd to an interface{}.
// makeArg does not do any allocation. Normally, such
// a conversion requires an allocation because pointers to
// types which embed internal/runtime/sys.NotInHeap (which pollDesc is)
// must be stored in interfaces indirectly. See issue 42076.
func (pd *pollDesc) makeArg() (i any) {
	x := (*eface)(unsafe.Pointer(&i))
	x._type = pdType
	x.data = unsafe.Pointer(&pd.self)
	return
}

var (
	pdEface any    = (*pollDesc)(nil)
	pdType  *_type = efaceOf(&pdEface)._type
)
```