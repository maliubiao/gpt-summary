Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Keywords:**

First, I quickly scanned the code looking for familiar Go networking terms and keywords. Things that jumped out:

* `package net` and import statements like `context`, `io`, `os`, `sync`, `syscall`, `time`. This immediately told me it's related to network functionality.
* `// Fake networking for js/wasm and wasip1/wasm.` in the comment. This is a crucial piece of information, indicating it's not a real network implementation but a simulation for specific environments.
* `fakeSockAddr`, `fakeNetFD`, `packetQueue`. These custom types suggest the implementation is creating its own networking abstractions.
* `sync.Map`, `atomic.Int32`. These point towards concurrent operations and managing shared state.
* Functions like `socket`, `fakeListen`, `fakeConnect`, `Read`, `Write`, `Close`, `accept`. These are standard network operation names.
* Error types like `os.NewSyscallError`, `AddrError`, `os.ErrDeadlineExceeded`, `ErrClosed`. These indicate how errors are handled.
* The `//go:build js || wasip1` build constraint confirms the target environments.

**2. Deeper Dive into Key Structures:**

Next, I focused on understanding the core data structures:

* **`fakeSockAddr`:** Represents a network address (family and string representation). This is the key for identifying sockets in the `sockets` map.
* **`fakeNetFD`:**  This is the central fake file descriptor. It contains:
    * `fd *netFD`:  A reference to the real `net.netFD` (likely to maintain compatibility with the standard library).
    * `assignedPort`:  Manages port allocation.
    * `queue *packetQueue`:  Crucial for managing incoming and outgoing data. This signals that the implementation is likely packet-based, even for stream-oriented sockets.
    * `peer *netFD`:  For connection-oriented protocols, this points to the other end of the connection.
    * `readDeadline`, `writeDeadline`:  Manage timeouts.
    * `incoming`, `incomingFull`, `incomingEmpty`:  For managing the accept queue of listening sockets.
* **`packetQueue`:** Implements a FIFO queue for packets, using Go channels for synchronization. This is where the actual data transfer logic resides. The states (`empty`, `ready`, `full`) and the `packet` structure are essential to understand how data is buffered and managed.

**3. Tracing the Execution Flow (Mental Simulation):**

I mentally traced the execution of key functions, considering the build constraint:

* **`socket()`:** This is the entry point for creating a socket. It determines whether it's a listening or connecting socket. The important thing is that it uses `newFakeNetFD`.
* **`fakeListen()`:**  For listening sockets. It registers the socket in the `sockets` map and initializes the accept queues.
* **`fakeConnect()`:** For connecting sockets. It looks up the target listener in `sockets`, creates a new `netFD` for the connection, and adds it to the listener's accept queue.
* **`Read()` and `Write()`:** These operate on the `packetQueue` of the `fakeNetFD`. The `peer` field is used to find the destination queue for `Write()`.
* **`accept()`:**  Retrieves accepted connections from the listener's queues.
* **`Close()`:**  Handles cleanup, including removing entries from `sockets` and `fakePorts`, and closing channels.

**4. Identifying Key Functionality:**

Based on the structures and function behavior, I could deduce the core functionalities:

* **Fake Socket Creation:** Simulates `socket()` for `js` and `wasip1`.
* **Fake Listening:**  Simulates the `Listen()` and `Accept()` behavior for stream-oriented sockets.
* **Fake Connection Establishment:** Simulates the `Connect()` behavior.
* **In-Memory Packet Queuing:** The `packetQueue` is the core of the data transfer mechanism.
* **Deadline Management:**  The `deadlineTimer` handles read and write timeouts.
* **Address Handling:** The `fakeSockAddr` and related logic manage simulated network addresses.

**5. Inferring the Purpose (Rationale):**

The "Fake networking for js/wasm and wasip1/wasm" comment is the biggest clue. These environments have limited or different networking capabilities compared to a standard OS. Therefore, this code provides a *mock* implementation that allows:

* **Testing:**  Other Go packages that rely on networking can be tested in these environments without needing a real network connection.
* **Compatibility:** It bridges the gap between standard Go networking APIs and the capabilities of these specific platforms.

**6. Generating Examples and Identifying Potential Pitfalls:**

With a good understanding of the code's function, I could then generate illustrative Go code examples demonstrating basic usage patterns (listening, connecting, sending, receiving).

I also considered common errors someone might make when using this *fake* implementation, particularly the limitations compared to real networking (e.g., no actual network traffic, everything is in-memory, limited error conditions).

**7. Structuring the Answer:**

Finally, I organized my findings into a clear and structured answer, addressing all the prompts in the request:

* **Functionality List:**  A concise summary of what the code does.
* **Go Feature Implementation:** Identifying this as a mock/stub implementation for specific environments.
* **Code Examples:**  Illustrative examples with clear inputs and expected outputs.
* **Assumptions and Outputs (for code reasoning):** Explicitly stating the context of the examples.
* **Command-line Arguments:**  Not applicable in this case, so explicitly stated that.
* **Common Mistakes:** Highlighting potential areas of confusion for users.
* **Language:**  Ensuring the entire answer is in Chinese as requested.

This iterative process of scanning, analyzing structures, tracing execution, inferring purpose, and finally generating examples allowed me to thoroughly understand and explain the provided Go code snippet.
这段代码是 Go 语言 `net` 包的一部分，专门为 `js/wasm` 和 `wasip1/wasm` 平台提供的**伪造（fake）网络功能**实现。其主要目的是**允许其他依赖网络功能的 Go 包在这些没有完整网络支持的环境下进行测试**。

以下是其功能的详细列举：

**核心功能：**

1. **伪造 Socket 创建 (`socket` 函数):**
   - 模拟 `syscall.Socket` 系统调用，创建一个可以进行 I/O 操作的伪造网络文件描述符 (`netFD`)。
   - 支持 `SOCK_STREAM` (TCP), `SOCK_SEQPACKET`, 和 `SOCK_DGRAM` (UDP) 等 socket 类型。
   - 可以用于创建监听 socket ( `raddr` 为 `nil`) 或连接 socket ( `raddr` 不为 `nil`)。
   - 针对 `js/wasm` 和 `wasip1/wasm` 平台，不支持某些底层 socket 控制操作 (`ctrlCtxFn` 不为 `nil` 时会返回 `ENOTSUP` 错误)。

2. **伪造监听 (`fakeListen` 函数):**
   - 模拟 `listen` 系统调用，使一个 socket 进入监听状态。
   - 将监听 socket 的地址 (`laddr`) 与其对应的 `netFD` 存储在全局 `sockets` map 中，键是 `fakeSockAddr` 结构体。
   - 为 TCP/SEQPACKET socket 创建用于管理待接受连接的 channel (`incoming`, `incomingFull`, `incomingEmpty`)。
   - 为 UDP socket 创建 `packetQueue` 用于缓存接收到的数据包。
   - 如果监听地址已经被占用，会返回 `EADDRINUSE` 错误。

3. **伪造连接 (`fakeConnect` 函数):**
   - 模拟 `connect` 系统调用，连接到一个远程地址 (`raddr`)。
   - 首先查找目标地址对应的监听 socket 是否存在于 `sockets` map 中。
   - 如果是 TCP/SEQPACKET 连接，会创建一个新的 `netFD` 代表连接，并将其添加到监听 socket 的待接受连接队列中。
   - 如果连接超时或目标地址不存在，会返回相应的错误 (例如 `ECONNREFUSED`, `ETIMEDOUT`)。
   - 对于 UDP 连接，只是将本地地址绑定，并将 `isConnected` 标记为 true。

4. **伪造数据读写 (`fakeNetFD` 的 `Read`, `Write`, `readFrom`, `writeTo` 等方法):**
   - **`Read`:** 从 socket 的接收队列 (`packetQueue`) 中读取数据。
   - **`Write`:** 将数据写入到连接的另一端的接收队列中。
   - **`readFrom`:** 用于无连接的 socket (如 UDP)，从接收队列中读取数据和发送方地址。
   - **`writeTo`:** 用于无连接的 socket，将数据发送到指定的地址。
   - 使用 `packetQueue` 来缓冲数据包，模拟网络数据传输。

5. **伪造关闭 (`fakeNetFD` 的 `Close`, `closeRead`, `closeWrite` 方法):**
   - **`Close`:** 关闭 socket，释放资源。从 `sockets` 和 `fakePorts` map 中移除记录，关闭相关的 channel 和队列。
   - **`closeRead`:** 关闭 socket 的读方向。
   - **`closeWrite`:** 关闭 socket 的写方向。

6. **伪造接受连接 (`fakeNetFD` 的 `accept` 方法):**
   - 模拟 `accept` 系统调用，从监听 socket 的待接受连接队列中取出一个已连接的 socket。
   - 如果队列为空且设置了读取截止时间，会返回 `os.ErrDeadlineExceeded` 错误。

7. **伪造截止时间设置 (`fakeNetFD` 的 `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline` 方法):**
   - 模拟设置 socket 的读写操作截止时间。
   - 使用 `deadlineTimer` 结构体来管理超时。

8. **地址管理 (`fakeSockAddr` 结构体和相关函数):**
   - 使用 `fakeSockAddr` 结构体来表示伪造的网络地址，包含地址族和字符串表示。
   - `fakeAddr` 函数用于将 `sockaddr` 接口转换为 `fakeSockAddr`。
   - `validateResolvedAddr` 函数用于验证地址的有效性。
   - `matchIPFamily` 函数用于根据地址族匹配 IP 地址。
   - `assignFakeAddr` 函数用于为 socket 分配伪造的本地地址和端口。

9. **端口管理 (`fakePorts` 和 `nextPortCounter`):**
   - 使用 `sync.Map` 类型的 `fakePorts` 来存储已分配的端口及其对应的 `netFD`，防止端口冲突。
   - `nextPortCounter` 使用原子操作生成递增的端口号。

10. **数据包队列 (`packetQueue` 结构体):**
    - 使用 channel 实现的 FIFO 队列，用于缓冲网络数据包。
    - 支持设置读取缓冲区大小限制 (`readBufferBytes`)。
    - 模拟数据包的发送和接收。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `net` 包中网络功能的**一个轻量级的、仅在内存中模拟的实现**，专门用于 `js/wasm` 和 `wasip1/wasm` 平台。它**不是一个真正的网络协议栈**，不会进行实际的网络通信。

**Go 代码举例说明：**

以下代码演示了如何使用这些伪造的网络功能创建一个 TCP 监听器，接受一个连接，并进行简单的读写操作。

```go
//go:build js || wasip1

package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// 监听本地 8080 端口
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("监听失败:", err)
		return
	}
	defer ln.Close()
	fmt.Println("监听在", ln.Addr())

	// 接受连接
	conn, err := ln.Accept()
	if err != nil {
		fmt.Println("接受连接失败:", err)
		return
	}
	defer conn.Close()
	fmt.Println("接受到来自", conn.RemoteAddr(), "的连接")

	// 从连接中读取数据
	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second)) // 设置读取截止时间
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("读取数据失败:", err)
		return
	}
	fmt.Printf("接收到数据: %s\n", buf[:n])

	// 向连接中写入数据
	message := "Hello from server!"
	conn.SetWriteDeadline(time.Now().Add(time.Second)) // 设置写入截止时间
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("写入数据失败:", err)
		return
	}
	fmt.Println("发送数据:", message)
}
```

**假设的输入与输出：**

由于这是一个伪造的网络实现，没有实际的网络交互，所以输入和输出主要体现在代码逻辑的执行和数据的内存传递上。

**假设的场景：**  在 `js/wasm` 或 `wasip1/wasm` 环境下运行上述代码。

**输出：**

```
监听在 127.0.0.1:8080
接受到来自 127.0.0.1:xxxxx 的连接  // xxxxx 是一个动态分配的端口
读取数据失败: read tcp 127.0.0.1:8080->127.0.0.1:xxxxx: i/o timeout
发送数据: Hello from server!
```

**解释：**

1. `net.Listen` 会调用 `fakeListen` 创建一个伪造的监听 socket。
2. 当有代码尝试连接到 `127.0.0.1:8080` 时（例如，在同一个程序中或者另一个伪造的网络连接），`ln.Accept` 会调用 `fakeNetFD` 的 `accept` 方法，从内部的队列中取出连接。
3. 由于示例代码中没有发起实际的连接请求，`conn.Read` 会因为设置了读取截止时间而超时。
4. `conn.Write` 会将数据写入到连接的另一端的接收队列中（如果存在）。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。它主要提供的是网络操作的基础功能。上层应用如果需要处理命令行参数，需要自己实现。

**使用者易犯错的点：**

1. **误以为是真正的网络连接：**  最大的错误是认为这段代码会建立实际的网络连接。所有操作都发生在内存中，不会发送到网络上。
2. **依赖真实网络的功能：** 某些真实的 socket 选项或系统调用可能没有被完全模拟，例如底层的网络协议细节、ICMP 等。
3. **性能考量：** 虽然是内存操作，但在高并发场景下，仍然需要注意锁的使用和数据结构的效率。
4. **错误处理的差异：** 伪造的网络实现可能会返回与真实网络操作不同的错误码或错误信息。
5. **截止时间和超时：** 理解 `deadlineTimer` 的工作方式，避免因为错误的截止时间设置导致程序行为不符合预期。例如，在没有数据可读时立即设置一个很短的读取截止时间会导致立即超时。

总而言之，这段代码为特定的 Go 语言运行环境提供了一个基本的、用于测试目的的伪造网络功能，使用者需要清楚其局限性，避免将其用于需要真实网络交互的场景。

Prompt: 
```
这是路径为go/src/net/net_fake.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fake networking for js/wasm and wasip1/wasm.
// It is intended to allow tests of other package to pass.

//go:build js || wasip1

package net

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	sockets         sync.Map // fakeSockAddr → *netFD
	fakePorts       sync.Map // int (port #) → *netFD
	nextPortCounter atomic.Int32
)

const defaultBuffer = 65535

type fakeSockAddr struct {
	family  int
	address string
}

func fakeAddr(sa sockaddr) fakeSockAddr {
	return fakeSockAddr{
		family:  sa.family(),
		address: sa.String(),
	}
}

// socket returns a network file descriptor that is ready for
// I/O using the fake network.
func socket(ctx context.Context, net string, family, sotype, proto int, ipv6only bool, laddr, raddr sockaddr, ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*netFD, error) {
	if raddr != nil && ctrlCtxFn != nil {
		return nil, os.NewSyscallError("socket", syscall.ENOTSUP)
	}
	switch sotype {
	case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET, syscall.SOCK_DGRAM:
	default:
		return nil, os.NewSyscallError("socket", syscall.ENOTSUP)
	}

	fd := &netFD{
		family: family,
		sotype: sotype,
		net:    net,
	}
	fd.fakeNetFD = newFakeNetFD(fd)

	if raddr == nil {
		if err := fakeListen(fd, laddr); err != nil {
			fd.Close()
			return nil, err
		}
		return fd, nil
	}

	if err := fakeConnect(ctx, fd, laddr, raddr); err != nil {
		fd.Close()
		return nil, err
	}
	return fd, nil
}

func validateResolvedAddr(net string, family int, sa sockaddr) error {
	validateIP := func(ip IP) error {
		switch family {
		case syscall.AF_INET:
			if len(ip) != 4 {
				return &AddrError{
					Err:  "non-IPv4 address",
					Addr: ip.String(),
				}
			}
		case syscall.AF_INET6:
			if len(ip) != 16 {
				return &AddrError{
					Err:  "non-IPv6 address",
					Addr: ip.String(),
				}
			}
		default:
			panic("net: unexpected address family in validateResolvedAddr")
		}
		return nil
	}

	switch net {
	case "tcp", "tcp4", "tcp6":
		sa, ok := sa.(*TCPAddr)
		if !ok {
			return &AddrError{
				Err:  "non-TCP address for " + net + " network",
				Addr: sa.String(),
			}
		}
		if err := validateIP(sa.IP); err != nil {
			return err
		}
		if sa.Port <= 0 || sa.Port >= 1<<16 {
			return &AddrError{
				Err:  "port out of range",
				Addr: sa.String(),
			}
		}
		return nil

	case "udp", "udp4", "udp6":
		sa, ok := sa.(*UDPAddr)
		if !ok {
			return &AddrError{
				Err:  "non-UDP address for " + net + " network",
				Addr: sa.String(),
			}
		}
		if err := validateIP(sa.IP); err != nil {
			return err
		}
		if sa.Port <= 0 || sa.Port >= 1<<16 {
			return &AddrError{
				Err:  "port out of range",
				Addr: sa.String(),
			}
		}
		return nil

	case "unix", "unixgram", "unixpacket":
		sa, ok := sa.(*UnixAddr)
		if !ok {
			return &AddrError{
				Err:  "non-Unix address for " + net + " network",
				Addr: sa.String(),
			}
		}
		if sa.Name != "" {
			i := len(sa.Name) - 1
			for i > 0 && !os.IsPathSeparator(sa.Name[i]) {
				i--
			}
			for i > 0 && os.IsPathSeparator(sa.Name[i]) {
				i--
			}
			if i <= 0 {
				return &AddrError{
					Err:  "unix socket name missing path component",
					Addr: sa.Name,
				}
			}
			if _, err := os.Stat(sa.Name[:i+1]); err != nil {
				return &AddrError{
					Err:  err.Error(),
					Addr: sa.Name,
				}
			}
		}
		return nil

	default:
		return &AddrError{
			Err:  syscall.EAFNOSUPPORT.Error(),
			Addr: sa.String(),
		}
	}
}

func matchIPFamily(family int, addr sockaddr) sockaddr {
	convertIP := func(ip IP) IP {
		switch family {
		case syscall.AF_INET:
			return ip.To4()
		case syscall.AF_INET6:
			return ip.To16()
		default:
			return ip
		}
	}

	switch addr := addr.(type) {
	case *TCPAddr:
		ip := convertIP(addr.IP)
		if ip == nil || len(ip) == len(addr.IP) {
			return addr
		}
		return &TCPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
	case *UDPAddr:
		ip := convertIP(addr.IP)
		if ip == nil || len(ip) == len(addr.IP) {
			return addr
		}
		return &UDPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
	default:
		return addr
	}
}

type fakeNetFD struct {
	fd           *netFD
	assignedPort int // 0 if no port has been assigned for this socket

	queue         *packetQueue // incoming packets
	peer          *netFD       // connected peer (for outgoing packets); nil for listeners and PacketConns
	readDeadline  atomic.Pointer[deadlineTimer]
	writeDeadline atomic.Pointer[deadlineTimer]

	fakeAddr fakeSockAddr // cached fakeSockAddr equivalent of fd.laddr

	// The incoming channels hold incoming connections that have not yet been accepted.
	// All of these channels are 1-buffered.
	incoming      chan []*netFD // holds the queue when it has >0 but <SOMAXCONN pending connections; closed when the Listener is closed
	incomingFull  chan []*netFD // holds the queue when it has SOMAXCONN pending connections
	incomingEmpty chan bool     // holds true when the incoming queue is empty
}

func newFakeNetFD(fd *netFD) *fakeNetFD {
	ffd := &fakeNetFD{fd: fd}
	ffd.readDeadline.Store(newDeadlineTimer(noDeadline))
	ffd.writeDeadline.Store(newDeadlineTimer(noDeadline))
	return ffd
}

func (ffd *fakeNetFD) Read(p []byte) (n int, err error) {
	n, _, err = ffd.queue.recvfrom(ffd.readDeadline.Load(), p, false, nil)
	return n, err
}

func (ffd *fakeNetFD) Write(p []byte) (nn int, err error) {
	peer := ffd.peer
	if peer == nil {
		if ffd.fd.raddr == nil {
			return 0, os.NewSyscallError("write", syscall.ENOTCONN)
		}
		peeri, _ := sockets.Load(fakeAddr(ffd.fd.raddr.(sockaddr)))
		if peeri == nil {
			return 0, os.NewSyscallError("write", syscall.ECONNRESET)
		}
		peer = peeri.(*netFD)
		if peer.queue == nil {
			return 0, os.NewSyscallError("write", syscall.ECONNRESET)
		}
	}

	if peer.fakeNetFD == nil {
		return 0, os.NewSyscallError("write", syscall.EINVAL)
	}
	return peer.queue.write(ffd.writeDeadline.Load(), p, ffd.fd.laddr.(sockaddr))
}

func (ffd *fakeNetFD) Close() (err error) {
	if ffd.fakeAddr != (fakeSockAddr{}) {
		sockets.CompareAndDelete(ffd.fakeAddr, ffd.fd)
	}

	if ffd.queue != nil {
		if closeErr := ffd.queue.closeRead(); err == nil {
			err = closeErr
		}
	}
	if ffd.peer != nil {
		if closeErr := ffd.peer.queue.closeWrite(); err == nil {
			err = closeErr
		}
	}
	ffd.readDeadline.Load().Reset(noDeadline)
	ffd.writeDeadline.Load().Reset(noDeadline)

	if ffd.incoming != nil {
		var (
			incoming []*netFD
			ok       bool
		)
		select {
		case _, ok = <-ffd.incomingEmpty:
		case incoming, ok = <-ffd.incoming:
		case incoming, ok = <-ffd.incomingFull:
		}
		if ok {
			// Sends on ffd.incoming require a receive first.
			// Since we successfully received, no other goroutine may
			// send on it at this point, and we may safely close it.
			close(ffd.incoming)

			for _, c := range incoming {
				c.Close()
			}
		}
	}

	if ffd.assignedPort != 0 {
		fakePorts.CompareAndDelete(ffd.assignedPort, ffd.fd)
	}

	return err
}

func (ffd *fakeNetFD) closeRead() error {
	return ffd.queue.closeRead()
}

func (ffd *fakeNetFD) closeWrite() error {
	if ffd.peer == nil {
		return os.NewSyscallError("closeWrite", syscall.ENOTCONN)
	}
	return ffd.peer.queue.closeWrite()
}

func (ffd *fakeNetFD) accept(laddr Addr) (*netFD, error) {
	if ffd.incoming == nil {
		return nil, os.NewSyscallError("accept", syscall.EINVAL)
	}

	var (
		incoming []*netFD
		ok       bool
	)
	expired := ffd.readDeadline.Load().expired
	select {
	case <-expired:
		return nil, os.ErrDeadlineExceeded
	case incoming, ok = <-ffd.incoming:
		if !ok {
			return nil, ErrClosed
		}
		select {
		case <-expired:
			ffd.incoming <- incoming
			return nil, os.ErrDeadlineExceeded
		default:
		}
	case incoming, ok = <-ffd.incomingFull:
		select {
		case <-expired:
			ffd.incomingFull <- incoming
			return nil, os.ErrDeadlineExceeded
		default:
		}
	}

	peer := incoming[0]
	incoming = incoming[1:]
	if len(incoming) == 0 {
		ffd.incomingEmpty <- true
	} else {
		ffd.incoming <- incoming
	}
	return peer, nil
}

func (ffd *fakeNetFD) SetDeadline(t time.Time) error {
	err1 := ffd.SetReadDeadline(t)
	err2 := ffd.SetWriteDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}

func (ffd *fakeNetFD) SetReadDeadline(t time.Time) error {
	dt := ffd.readDeadline.Load()
	if !dt.Reset(t) {
		ffd.readDeadline.Store(newDeadlineTimer(t))
	}
	return nil
}

func (ffd *fakeNetFD) SetWriteDeadline(t time.Time) error {
	dt := ffd.writeDeadline.Load()
	if !dt.Reset(t) {
		ffd.writeDeadline.Store(newDeadlineTimer(t))
	}
	return nil
}

const maxPacketSize = 65535

type packet struct {
	buf       []byte
	bufOffset int
	next      *packet
	from      sockaddr
}

func (p *packet) clear() {
	p.buf = p.buf[:0]
	p.bufOffset = 0
	p.next = nil
	p.from = nil
}

var packetPool = sync.Pool{
	New: func() any { return new(packet) },
}

type packetQueueState struct {
	head, tail      *packet // unqueued packets
	nBytes          int     // number of bytes enqueued in the packet buffers starting from head
	readBufferBytes int     // soft limit on nbytes; no more packets may be enqueued when the limit is exceeded
	readClosed      bool    // true if the reader of the queue has stopped reading
	writeClosed     bool    // true if the writer of the queue has stopped writing; the reader sees either io.EOF or syscall.ECONNRESET when they have read all buffered packets
	noLinger        bool    // if true, the reader sees ECONNRESET instead of EOF
}

// A packetQueue is a set of 1-buffered channels implementing a FIFO queue
// of packets.
type packetQueue struct {
	empty chan packetQueueState // contains configuration parameters when the queue is empty and not closed
	ready chan packetQueueState // contains the packets when non-empty or closed
	full  chan packetQueueState // contains the packets when buffer is full and not closed
}

func newPacketQueue(readBufferBytes int) *packetQueue {
	pq := &packetQueue{
		empty: make(chan packetQueueState, 1),
		ready: make(chan packetQueueState, 1),
		full:  make(chan packetQueueState, 1),
	}
	pq.put(packetQueueState{
		readBufferBytes: readBufferBytes,
	})
	return pq
}

func (pq *packetQueue) get() packetQueueState {
	var q packetQueueState
	select {
	case q = <-pq.empty:
	case q = <-pq.ready:
	case q = <-pq.full:
	}
	return q
}

func (pq *packetQueue) put(q packetQueueState) {
	switch {
	case q.readClosed || q.writeClosed:
		pq.ready <- q
	case q.nBytes >= q.readBufferBytes:
		pq.full <- q
	case q.head == nil:
		if q.nBytes > 0 {
			defer panic("net: put with nil packet list and nonzero nBytes")
		}
		pq.empty <- q
	default:
		pq.ready <- q
	}
}

func (pq *packetQueue) closeRead() error {
	q := pq.get()
	q.readClosed = true
	pq.put(q)
	return nil
}

func (pq *packetQueue) closeWrite() error {
	q := pq.get()
	q.writeClosed = true
	pq.put(q)
	return nil
}

func (pq *packetQueue) setLinger(linger bool) error {
	q := pq.get()
	defer func() { pq.put(q) }()

	if q.writeClosed {
		return ErrClosed
	}
	q.noLinger = !linger
	return nil
}

func (pq *packetQueue) write(dt *deadlineTimer, b []byte, from sockaddr) (n int, err error) {
	for {
		dn := len(b)
		if dn > maxPacketSize {
			dn = maxPacketSize
		}

		dn, err = pq.send(dt, b[:dn], from, true)
		n += dn
		if err != nil {
			return n, err
		}

		b = b[dn:]
		if len(b) == 0 {
			return n, nil
		}
	}
}

func (pq *packetQueue) send(dt *deadlineTimer, b []byte, from sockaddr, block bool) (n int, err error) {
	if from == nil {
		return 0, os.NewSyscallError("send", syscall.EINVAL)
	}
	if len(b) > maxPacketSize {
		return 0, os.NewSyscallError("send", syscall.EMSGSIZE)
	}

	var q packetQueueState
	var full chan packetQueueState
	if !block {
		full = pq.full
	}

	select {
	case <-dt.expired:
		return 0, os.ErrDeadlineExceeded

	case q = <-full:
		pq.put(q)
		return 0, os.NewSyscallError("send", syscall.ENOBUFS)

	case q = <-pq.empty:
	case q = <-pq.ready:
	}
	defer func() { pq.put(q) }()

	// Don't allow a packet to be sent if the deadline has expired,
	// even if the select above chose a different branch.
	select {
	case <-dt.expired:
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if q.writeClosed {
		return 0, ErrClosed
	} else if q.readClosed && q.nBytes >= q.readBufferBytes {
		return 0, os.NewSyscallError("send", syscall.ECONNRESET)
	}

	p := packetPool.Get().(*packet)
	p.buf = append(p.buf[:0], b...)
	p.from = from

	if q.head == nil {
		q.head = p
	} else {
		q.tail.next = p
	}
	q.tail = p
	q.nBytes += len(p.buf)

	return len(b), nil
}

func (pq *packetQueue) recvfrom(dt *deadlineTimer, b []byte, wholePacket bool, checkFrom func(sockaddr) error) (n int, from sockaddr, err error) {
	var q packetQueueState
	var empty chan packetQueueState
	if len(b) == 0 {
		// For consistency with the implementation on Unix platforms,
		// allow a zero-length Read to proceed if the queue is empty.
		// (Without this, TestZeroByteRead deadlocks.)
		empty = pq.empty
	}

	select {
	case <-dt.expired:
		return 0, nil, os.ErrDeadlineExceeded
	case q = <-empty:
	case q = <-pq.ready:
	case q = <-pq.full:
	}
	defer func() { pq.put(q) }()

	if q.readClosed {
		return 0, nil, ErrClosed
	}

	p := q.head
	if p == nil {
		switch {
		case q.writeClosed:
			if q.noLinger {
				return 0, nil, os.NewSyscallError("recvfrom", syscall.ECONNRESET)
			}
			return 0, nil, io.EOF
		case len(b) == 0:
			return 0, nil, nil
		default:
			// This should be impossible: pq.full should only contain a non-empty list,
			// pq.ready should either contain a non-empty list or indicate that the
			// connection is closed, and we should only receive from pq.empty if
			// len(b) == 0.
			panic("net: nil packet list from non-closed packetQueue")
		}
	}

	select {
	case <-dt.expired:
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}

	if checkFrom != nil {
		if err := checkFrom(p.from); err != nil {
			return 0, nil, err
		}
	}

	n = copy(b, p.buf[p.bufOffset:])
	from = p.from
	if wholePacket || p.bufOffset+n == len(p.buf) {
		q.head = p.next
		q.nBytes -= len(p.buf)
		p.clear()
		packetPool.Put(p)
	} else {
		p.bufOffset += n
	}

	return n, from, nil
}

// setReadBuffer sets a soft limit on the number of bytes available to read
// from the pipe.
func (pq *packetQueue) setReadBuffer(bytes int) error {
	if bytes <= 0 {
		return os.NewSyscallError("setReadBuffer", syscall.EINVAL)
	}
	q := pq.get() // Use the queue as a lock.
	q.readBufferBytes = bytes
	pq.put(q)
	return nil
}

type deadlineTimer struct {
	timer   chan *time.Timer
	expired chan struct{}
}

func newDeadlineTimer(deadline time.Time) *deadlineTimer {
	dt := &deadlineTimer{
		timer:   make(chan *time.Timer, 1),
		expired: make(chan struct{}),
	}
	dt.timer <- nil
	dt.Reset(deadline)
	return dt
}

// Reset attempts to reset the timer.
// If the timer has already expired, Reset returns false.
func (dt *deadlineTimer) Reset(deadline time.Time) bool {
	timer := <-dt.timer
	defer func() { dt.timer <- timer }()

	if deadline.Equal(noDeadline) {
		if timer != nil && timer.Stop() {
			timer = nil
		}
		return timer == nil
	}

	d := time.Until(deadline)
	if d < 0 {
		// Ensure that a deadline in the past takes effect immediately.
		defer func() { <-dt.expired }()
	}

	if timer == nil {
		timer = time.AfterFunc(d, func() { close(dt.expired) })
		return true
	}
	if !timer.Stop() {
		return false
	}
	timer.Reset(d)
	return true
}

func sysSocket(family, sotype, proto int) (int, error) {
	return 0, os.NewSyscallError("sysSocket", syscall.ENOSYS)
}

func fakeListen(fd *netFD, laddr sockaddr) (err error) {
	wrapErr := func(err error) error {
		if errno, ok := err.(syscall.Errno); ok {
			err = os.NewSyscallError("listen", errno)
		}
		if errors.Is(err, syscall.EADDRINUSE) {
			return err
		}
		if laddr != nil {
			if _, ok := err.(*AddrError); !ok {
				err = &AddrError{
					Err:  err.Error(),
					Addr: laddr.String(),
				}
			}
		}
		return err
	}

	ffd := newFakeNetFD(fd)
	defer func() {
		if fd.fakeNetFD != ffd {
			// Failed to register listener; clean up.
			ffd.Close()
		}
	}()

	if err := ffd.assignFakeAddr(matchIPFamily(fd.family, laddr)); err != nil {
		return wrapErr(err)
	}

	ffd.fakeAddr = fakeAddr(fd.laddr.(sockaddr))
	switch fd.sotype {
	case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET:
		ffd.incoming = make(chan []*netFD, 1)
		ffd.incomingFull = make(chan []*netFD, 1)
		ffd.incomingEmpty = make(chan bool, 1)
		ffd.incomingEmpty <- true
	case syscall.SOCK_DGRAM:
		ffd.queue = newPacketQueue(defaultBuffer)
	default:
		return wrapErr(syscall.EINVAL)
	}

	fd.fakeNetFD = ffd
	if _, dup := sockets.LoadOrStore(ffd.fakeAddr, fd); dup {
		fd.fakeNetFD = nil
		return wrapErr(syscall.EADDRINUSE)
	}

	return nil
}

func fakeConnect(ctx context.Context, fd *netFD, laddr, raddr sockaddr) error {
	wrapErr := func(err error) error {
		if errno, ok := err.(syscall.Errno); ok {
			err = os.NewSyscallError("connect", errno)
		}
		if errors.Is(err, syscall.EADDRINUSE) {
			return err
		}
		if terr, ok := err.(interface{ Timeout() bool }); !ok || !terr.Timeout() {
			// For consistency with the net implementation on other platforms,
			// if we don't need to preserve the Timeout-ness of err we should
			// wrap it in an AddrError. (Unfortunately we can't wrap errors
			// that convey structured information, because AddrError reduces
			// the wrapped Err to a flat string.)
			if _, ok := err.(*AddrError); !ok {
				err = &AddrError{
					Err:  err.Error(),
					Addr: raddr.String(),
				}
			}
		}
		return err
	}

	if fd.isConnected {
		return wrapErr(syscall.EISCONN)
	}
	if ctx.Err() != nil {
		return wrapErr(syscall.ETIMEDOUT)
	}

	fd.raddr = matchIPFamily(fd.family, raddr)
	if err := validateResolvedAddr(fd.net, fd.family, fd.raddr.(sockaddr)); err != nil {
		return wrapErr(err)
	}

	if err := fd.fakeNetFD.assignFakeAddr(laddr); err != nil {
		return wrapErr(err)
	}
	fd.fakeNetFD.queue = newPacketQueue(defaultBuffer)

	switch fd.sotype {
	case syscall.SOCK_DGRAM:
		if ua, ok := fd.laddr.(*UnixAddr); !ok || ua.Name != "" {
			fd.fakeNetFD.fakeAddr = fakeAddr(fd.laddr.(sockaddr))
			if _, dup := sockets.LoadOrStore(fd.fakeNetFD.fakeAddr, fd); dup {
				return wrapErr(syscall.EADDRINUSE)
			}
		}
		fd.isConnected = true
		return nil

	case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET:
	default:
		return wrapErr(syscall.EINVAL)
	}

	fa := fakeAddr(raddr)
	lni, ok := sockets.Load(fa)
	if !ok {
		return wrapErr(syscall.ECONNREFUSED)
	}
	ln := lni.(*netFD)
	if ln.sotype != fd.sotype {
		return wrapErr(syscall.EPROTOTYPE)
	}
	if ln.incoming == nil {
		return wrapErr(syscall.ECONNREFUSED)
	}

	peer := &netFD{
		family:      ln.family,
		sotype:      ln.sotype,
		net:         ln.net,
		laddr:       ln.laddr,
		raddr:       fd.laddr,
		isConnected: true,
	}
	peer.fakeNetFD = newFakeNetFD(fd)
	peer.fakeNetFD.queue = newPacketQueue(defaultBuffer)
	defer func() {
		if fd.peer != peer {
			// Failed to connect; clean up.
			peer.Close()
		}
	}()

	var incoming []*netFD
	select {
	case <-ctx.Done():
		return wrapErr(syscall.ETIMEDOUT)
	case ok = <-ln.incomingEmpty:
	case incoming, ok = <-ln.incoming:
	}
	if !ok {
		return wrapErr(syscall.ECONNREFUSED)
	}

	fd.isConnected = true
	fd.peer = peer
	peer.peer = fd

	incoming = append(incoming, peer)
	if len(incoming) >= listenerBacklog() {
		ln.incomingFull <- incoming
	} else {
		ln.incoming <- incoming
	}
	return nil
}

func (ffd *fakeNetFD) assignFakeAddr(addr sockaddr) error {
	validate := func(sa sockaddr) error {
		if err := validateResolvedAddr(ffd.fd.net, ffd.fd.family, sa); err != nil {
			return err
		}
		ffd.fd.laddr = sa
		return nil
	}

	assignIP := func(addr sockaddr) error {
		var (
			ip   IP
			port int
			zone string
		)
		switch addr := addr.(type) {
		case *TCPAddr:
			if addr != nil {
				ip = addr.IP
				port = addr.Port
				zone = addr.Zone
			}
		case *UDPAddr:
			if addr != nil {
				ip = addr.IP
				port = addr.Port
				zone = addr.Zone
			}
		default:
			return validate(addr)
		}

		if ip == nil {
			ip = IPv4(127, 0, 0, 1)
		}
		switch ffd.fd.family {
		case syscall.AF_INET:
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
		case syscall.AF_INET6:
			if ip16 := ip.To16(); ip16 != nil {
				ip = ip16
			}
		}
		if ip == nil {
			return syscall.EINVAL
		}

		if port == 0 {
			var prevPort int32
			portWrapped := false
			nextPort := func() (int, bool) {
				for {
					port := nextPortCounter.Add(1)
					if port <= 0 || port >= 1<<16 {
						// nextPortCounter ran off the end of the port space.
						// Bump it back into range.
						for {
							if nextPortCounter.CompareAndSwap(port, 0) {
								break
							}
							if port = nextPortCounter.Load(); port >= 0 && port < 1<<16 {
								break
							}
						}
						if portWrapped {
							// This is the second wraparound, so we've scanned the whole port space
							// at least once already and it's time to give up.
							return 0, false
						}
						portWrapped = true
						prevPort = 0
						continue
					}

					if port <= prevPort {
						// nextPortCounter has wrapped around since the last time we read it.
						if portWrapped {
							// This is the second wraparound, so we've scanned the whole port space
							// at least once already and it's time to give up.
							return 0, false
						} else {
							portWrapped = true
						}
					}

					prevPort = port
					return int(port), true
				}
			}

			for {
				var ok bool
				port, ok = nextPort()
				if !ok {
					ffd.assignedPort = 0
					return syscall.EADDRINUSE
				}

				ffd.assignedPort = int(port)
				if _, dup := fakePorts.LoadOrStore(ffd.assignedPort, ffd.fd); !dup {
					break
				}
			}
		}

		switch addr.(type) {
		case *TCPAddr:
			return validate(&TCPAddr{IP: ip, Port: port, Zone: zone})
		case *UDPAddr:
			return validate(&UDPAddr{IP: ip, Port: port, Zone: zone})
		default:
			panic("unreachable")
		}
	}

	switch ffd.fd.net {
	case "tcp", "tcp4", "tcp6":
		if addr == nil {
			return assignIP(new(TCPAddr))
		}
		return assignIP(addr)

	case "udp", "udp4", "udp6":
		if addr == nil {
			return assignIP(new(UDPAddr))
		}
		return assignIP(addr)

	case "unix", "unixgram", "unixpacket":
		uaddr, ok := addr.(*UnixAddr)
		if !ok && addr != nil {
			return &AddrError{
				Err:  "non-Unix address for " + ffd.fd.net + " network",
				Addr: addr.String(),
			}
		}
		if uaddr == nil {
			return validate(&UnixAddr{Net: ffd.fd.net})
		}
		return validate(&UnixAddr{Net: ffd.fd.net, Name: uaddr.Name})

	default:
		return &AddrError{
			Err:  syscall.EAFNOSUPPORT.Error(),
			Addr: addr.String(),
		}
	}
}

func (ffd *fakeNetFD) readFrom(p []byte) (n int, sa syscall.Sockaddr, err error) {
	if ffd.queue == nil {
		return 0, nil, os.NewSyscallError("readFrom", syscall.EINVAL)
	}

	n, from, err := ffd.queue.recvfrom(ffd.readDeadline.Load(), p, true, nil)

	if from != nil {
		// Convert the net.sockaddr to a syscall.Sockaddr type.
		var saErr error
		sa, saErr = from.sockaddr(ffd.fd.family)
		if err == nil {
			err = saErr
		}
	}

	return n, sa, err
}

func (ffd *fakeNetFD) readFromInet4(p []byte, sa *syscall.SockaddrInet4) (n int, err error) {
	n, _, err = ffd.queue.recvfrom(ffd.readDeadline.Load(), p, true, func(from sockaddr) error {
		fromSA, err := from.sockaddr(syscall.AF_INET)
		if err != nil {
			return err
		}
		if fromSA == nil {
			return os.NewSyscallError("readFromInet4", syscall.EINVAL)
		}
		*sa = *(fromSA.(*syscall.SockaddrInet4))
		return nil
	})
	return n, err
}

func (ffd *fakeNetFD) readFromInet6(p []byte, sa *syscall.SockaddrInet6) (n int, err error) {
	n, _, err = ffd.queue.recvfrom(ffd.readDeadline.Load(), p, true, func(from sockaddr) error {
		fromSA, err := from.sockaddr(syscall.AF_INET6)
		if err != nil {
			return err
		}
		if fromSA == nil {
			return os.NewSyscallError("readFromInet6", syscall.EINVAL)
		}
		*sa = *(fromSA.(*syscall.SockaddrInet6))
		return nil
	})
	return n, err
}

func (ffd *fakeNetFD) readMsg(p []byte, oob []byte, flags int) (n, oobn, retflags int, sa syscall.Sockaddr, err error) {
	if flags != 0 {
		return 0, 0, 0, nil, os.NewSyscallError("readMsg", syscall.ENOTSUP)
	}
	n, sa, err = ffd.readFrom(p)
	return n, 0, 0, sa, err
}

func (ffd *fakeNetFD) readMsgInet4(p []byte, oob []byte, flags int, sa *syscall.SockaddrInet4) (n, oobn, retflags int, err error) {
	if flags != 0 {
		return 0, 0, 0, os.NewSyscallError("readMsgInet4", syscall.ENOTSUP)
	}
	n, err = ffd.readFromInet4(p, sa)
	return n, 0, 0, err
}

func (ffd *fakeNetFD) readMsgInet6(p []byte, oob []byte, flags int, sa *syscall.SockaddrInet6) (n, oobn, retflags int, err error) {
	if flags != 0 {
		return 0, 0, 0, os.NewSyscallError("readMsgInet6", syscall.ENOTSUP)
	}
	n, err = ffd.readFromInet6(p, sa)
	return n, 0, 0, err
}

func (ffd *fakeNetFD) writeMsg(p []byte, oob []byte, sa syscall.Sockaddr) (n int, oobn int, err error) {
	if len(oob) > 0 {
		return 0, 0, os.NewSyscallError("writeMsg", syscall.ENOTSUP)
	}
	n, err = ffd.writeTo(p, sa)
	return n, 0, err
}

func (ffd *fakeNetFD) writeMsgInet4(p []byte, oob []byte, sa *syscall.SockaddrInet4) (n int, oobn int, err error) {
	return ffd.writeMsg(p, oob, sa)
}

func (ffd *fakeNetFD) writeMsgInet6(p []byte, oob []byte, sa *syscall.SockaddrInet6) (n int, oobn int, err error) {
	return ffd.writeMsg(p, oob, sa)
}

func (ffd *fakeNetFD) writeTo(p []byte, sa syscall.Sockaddr) (n int, err error) {
	raddr := ffd.fd.raddr
	if sa != nil {
		if ffd.fd.isConnected {
			return 0, os.NewSyscallError("writeTo", syscall.EISCONN)
		}
		raddr = ffd.fd.addrFunc()(sa)
	}
	if raddr == nil {
		return 0, os.NewSyscallError("writeTo", syscall.EINVAL)
	}

	peeri, _ := sockets.Load(fakeAddr(raddr.(sockaddr)))
	if peeri == nil {
		if len(ffd.fd.net) >= 3 && ffd.fd.net[:3] == "udp" {
			return len(p), nil
		}
		return 0, os.NewSyscallError("writeTo", syscall.ECONNRESET)
	}
	peer := peeri.(*netFD)
	if peer.queue == nil {
		if len(ffd.fd.net) >= 3 && ffd.fd.net[:3] == "udp" {
			return len(p), nil
		}
		return 0, os.NewSyscallError("writeTo", syscall.ECONNRESET)
	}

	block := true
	if len(ffd.fd.net) >= 3 && ffd.fd.net[:3] == "udp" {
		block = false
	}
	return peer.queue.send(ffd.writeDeadline.Load(), p, ffd.fd.laddr.(sockaddr), block)
}

func (ffd *fakeNetFD) writeToInet4(p []byte, sa *syscall.SockaddrInet4) (n int, err error) {
	return ffd.writeTo(p, sa)
}

func (ffd *fakeNetFD) writeToInet6(p []byte, sa *syscall.SockaddrInet6) (n int, err error) {
	return ffd.writeTo(p, sa)
}

func (ffd *fakeNetFD) dup() (f *os.File, err error) {
	return nil, os.NewSyscallError("dup", syscall.ENOSYS)
}

func (ffd *fakeNetFD) setReadBuffer(bytes int) error {
	if ffd.queue == nil {
		return os.NewSyscallError("setReadBuffer", syscall.EINVAL)
	}
	ffd.queue.setReadBuffer(bytes)
	return nil
}

func (ffd *fakeNetFD) setWriteBuffer(bytes int) error {
	return os.NewSyscallError("setWriteBuffer", syscall.ENOTSUP)
}

func (ffd *fakeNetFD) setLinger(sec int) error {
	if sec < 0 || ffd.peer == nil {
		return os.NewSyscallError("setLinger", syscall.EINVAL)
	}
	ffd.peer.queue.setLinger(sec > 0)
	return nil
}

"""



```