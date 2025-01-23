Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Initial Skim and Identification of Key Areas:**

The first step is a quick read-through to get a general sense of the code's purpose. Keywords like `syscall`, `socket`, `mmap`, `signal`, `error`, and standard I/O file descriptors (`Stdin`, `Stdout`, `Stderr`) immediately jump out. The `//go:build ...` comment at the top signals that this code is platform-specific, targeting Unix-like operating systems.

This initial skim suggests the file deals with:

* **System Calls:**  Interacting with the operating system kernel.
* **File I/O:**  Reading and writing to file descriptors.
* **Memory Management:**  Specifically, memory mapping (`mmap`, `munmap`).
* **Networking:**  Socket operations (bind, connect, send, receive, etc.).
* **Signal Handling:**  Dealing with operating system signals.
* **Error Handling:**  Representing and naming system errors.

**2. Detailed Analysis of Code Blocks:**

Now, let's examine specific sections:

* **Constants (Stdin, Stdout, Stderr):** These are standard file descriptors, easily recognizable.

* **Error Handling (`errEAGAIN`, `errEINVAL`, `errENOENT`, `errnoErr`, `ErrnoName`):**  The code is explicitly handling common error conditions by pre-allocating error objects. `errnoErr` aims to reduce allocations by returning the same error instance for common errors. `ErrnoName` suggests a mapping from error numbers to names.

* **Signal Handling (`signalNameMapOnce`, `signalNameMap`, `SignalName`, `SignalNum`):** Similar to error handling, there's a mechanism to map signal numbers to names and vice-versa. The `sync.Once` ensures the map is initialized only once.

* **Memory Mapping (`mmapper`, `Mmap`, `Munmap`, `MmapPtr`, `MunmapPtr`):** This is a crucial section. The `mmapper` struct encapsulates the state and functions for memory mapping. The `Mmap` and `Munmap` functions provide a higher-level interface to the underlying `mmap` and `munmap` system calls. The `MmapPtr` and `MunmapPtr` variants likely allow specifying the memory address.

* **File I/O (`Read`, `Write`, `Pread`, `Pwrite`):** These functions wrap the standard `read` and `write` system calls, and the inclusion of `raceenabled` suggests they are integrated with Go's race detector.

* **Sockets (`Sockaddr`, `SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`, `Bind`, `Connect`, `Getpeername`, `Getsockopt...`, `Recvfrom`, `Recvmsg`, `Sendmsg`, `SendmsgN`, `Send`, `Sendto`, `Setsockopt...`, `Socket`, `Socketpair`):**  This is a large block dealing with various socket operations. The `Sockaddr` interface and its concrete implementations for different address families (IPv4, IPv6, Unix) are key. The `Getsockopt` and `Setsockopt` functions are for querying and setting socket options. `Recvfrom`, `Recvmsg`, `Sendmsg`, and their variants handle sending and receiving data over sockets.

* **Utility Functions (`clen`, `emptyIovecs`):** These are helper functions for common tasks, like finding the length of a null-terminated byte slice and checking if a slice of `Iovec` is empty.

* **Other Functions (`CloseOnExec`, `SetNonblock`, `Exec`, `Lutimes`, `Setrlimit`):** These cover additional system-level operations like setting the close-on-exec flag, setting non-blocking mode, executing a new process, modifying timestamps, and setting resource limits.

**3. Identifying Go Feature Implementations:**

Based on the analysis, it's clear this code is fundamental to how Go interacts with the underlying operating system for several core functionalities:

* **Error Handling:** The `error` interface and how system call errors are represented.
* **Signal Handling:** The `os/signal` package relies on these lower-level signal mechanisms.
* **Memory Management:** The `mmap` functionality is used by various parts of the Go runtime and standard library.
* **Networking:** The `net` package builds upon these socket-related functions to provide a platform-independent networking API.
* **File I/O:** The `os` package's file operations use these underlying system calls.
* **Process Control:**  The `os/exec` package uses `Exec`.

**4. Constructing Examples and Explanations:**

Now, we can start formulating examples and explanations for each identified area. The key is to demonstrate *how* these low-level functions are used in higher-level Go code.

* **Example for `errnoErr` and `ErrnoName`:** Show how a system call error is captured and how to get its name.
* **Example for `SignalNum` and `SignalName`:** Demonstrate converting between signal names and numbers.
* **Example for `Mmap` and `Munmap`:** Illustrate mapping a file into memory.
* **Example for socket functions:** Show basic socket creation, binding, listening, and accepting connections.
* **Example for `Exec`:**  Demonstrate launching a new process.

**5. Identifying Potential Pitfalls:**

Consider common mistakes developers might make when using these low-level functions:

* **Incorrectly handling errors:**  Not checking the error return value.
* **Memory mapping issues:** Forgetting to unmap memory, leading to resource leaks.
* **Socket programming complexities:**  Dealing with different address families, byte order, and socket options.
* **Signal handling intricacies:**  Understanding signal masking and interrupt handling.

**6. Refinement and Organization:**

Finally, organize the information logically, ensuring clear explanations and well-structured examples. Use code blocks for the examples and clearly separate different functionalities. The initial breakdown helps in organizing the information effectively. Use headings and bullet points for readability.

By following these steps, we can systematically analyze the given Go code snippet and provide a comprehensive explanation of its functionalities, associated Go features, and potential pitfalls. The key is to move from a general understanding to a detailed examination of each part, connecting it to broader Go concepts and providing practical examples.
这段代码是 Go 语言标准库 `syscall` 包在 Unix-like 系统上的底层实现的一部分，路径表明它是 `golang.org/x/sys/unix` 包的 vendor 版本，用于与操作系统内核进行交互。 它主要提供了以下功能：

**1. 定义标准文件描述符:**

* `Stdin = 0`:  标准输入文件描述符。
* `Stdout = 1`: 标准输出文件描述符。
* `Stderr = 2`: 标准错误输出文件描述符。

**2. 优化常用错误的分配:**

* 定义了 `errEAGAIN`, `errEINVAL`, `errENOENT` 等变量，并用 `syscall.EAGAIN` 等进行初始化。
* `errnoErr` 函数用于返回这些预先分配的 `error` 值，以避免在运行时频繁分配内存，提高性能。

**3. 提供错误码和信号名的转换:**

* `ErrnoName(e syscall.Errno) string`:  接收一个 `syscall.Errno` 类型的错误码，返回其对应的错误名称字符串。它依赖于一个名为 `errorList` 的全局变量（未在此代码片段中），该变量应该包含了错误码和名称的映射关系，并通过二分查找来高效查找。
* `SignalName(s syscall.Signal) string`: 接收一个 `syscall.Signal` 类型的信号，返回其对应的信号名称字符串。它依赖于一个名为 `signalList` 的全局变量（未在此代码片段中），该变量应该包含了信号和名称的映射关系，并通过二分查找来高效查找。
* `SignalNum(s string) syscall.Signal`: 接收一个信号名称字符串（例如 "SIGINT"），返回对应的 `syscall.Signal` 值。它内部使用一个 `signalNameMap` 来存储信号名称和信号值的映射关系，并使用 `sync.Once` 来确保 `signalNameMap` 只被初始化一次。

**4. 提供内存映射 (mmap) 的管理:**

* 定义了一个 `mmapper` 结构体，用于管理通过 `mmap` 系统调用映射的内存区域。
    * `active map[*byte][]byte`: 存储活跃的内存映射，键是指向映射末尾字节的指针，值是整个映射的字节切片。
    * `mmap func(addr, length uintptr, prot, flags, fd int, offset int64) (uintptr, error)`:  一个函数类型，指向实际的 `mmap` 系统调用实现。
    * `munmap func(addr uintptr, length uintptr) error`: 一个函数类型，指向实际的 `munmap` 系统调用实现。
* `mmapper` 结构体提供了 `Mmap` 和 `Munmap` 方法，用于进行内存映射和取消映射。
* 提供了全局的 `mapper` 实例，以及方便使用的 `Mmap` 和 `Munmap` 函数，它们调用 `mapper` 实例的方法。
* `MmapPtr` 和 `MunmapPtr` 允许指定映射的起始地址。

**5. 提供基础的 I/O 操作:**

* `Read(fd int, p []byte) (n int, err error)`:  封装了底层的 `read` 系统调用，用于从文件描述符 `fd` 读取数据到字节切片 `p` 中。如果启用了竞态检测 (`raceenabled`)，还会进行相关的竞态检测操作。
* `Write(fd int, p []byte) (n int, err error)`: 封装了底层的 `write` 系统调用，用于将字节切片 `p` 的数据写入到文件描述符 `fd` 中。如果启用了竞态检测 (`raceenabled`)，还会进行相关的竞态检测操作。
* `Pread(fd int, p []byte, offset int64) (n int, err error)`: 封装了底层的 `pread` 系统调用，用于从文件描述符 `fd` 的指定偏移量 `offset` 读取数据到字节切片 `p` 中，而不会改变文件指针。如果启用了竞态检测 (`raceenabled`)，还会进行相关的竞态检测操作。
* `Pwrite(fd int, p []byte, offset int64) (n int, err error)`: 封装了底层的 `pwrite` 系统调用，用于将字节切片 `p` 的数据写入到文件描述符 `fd` 的指定偏移量 `offset`，而不会改变文件指针。如果启用了竞态检测 (`raceenabled`)，还会进行相关的竞态检测操作。

**6. 提供 Socket 相关的操作:**

* 定义了 `Sockaddr` 接口，用于表示 socket 地址。
* 提供了 `SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix` 等结构体，分别实现了 IPv4、IPv6 和 Unix 域 socket 的地址表示。
* 提供了 `Bind`, `Connect`, `Getpeername` 等函数，分别封装了 `bind`, `connect`, `getpeername` 等系统调用，用于进行 socket 绑定、连接和获取对端地址。
* 提供了 `Getsockopt...` 系列函数，用于获取各种 socket 选项的值，例如 `GetsockoptByte`, `GetsockoptInt`, `GetsockoptLinger` 等。
* 提供了 `Recvfrom`, `Recvmsg`, `RecvmsgBuffers` 等函数，用于从 socket 接收数据。
* 提供了 `Sendmsg`, `SendmsgN`, `SendmsgBuffers`, `Send`, `Sendto` 等函数，用于向 socket 发送数据。
* 提供了 `Setsockopt...` 系列函数，用于设置各种 socket 选项的值，例如 `SetsockoptByte`, `SetsockoptInt`, `SetsockoptLinger` 等。
* `Socket(domain, typ, proto int) (fd int, err error)`: 封装了底层的 `socket` 系统调用，用于创建 socket。
* `Socketpair(domain, typ, proto int) (fd [2]int, err error)`: 封装了底层的 `socketpair` 系统调用，用于创建一对相互连接的 socket。
* `SocketDisableIPv6 bool`: 一个用于测试的全局变量，如果设置为 `true`，则创建 IPv6 socket 将返回 `EAFNOSUPPORT` 错误。

**7. 提供其他系统调用相关的封装:**

* `CloseOnExec(fd int)`:  封装了 `fcntl` 系统调用，设置文件描述符 `fd` 的 `FD_CLOEXEC` 标志，使其在 `exec` 后自动关闭。
* `SetNonblock(fd int, nonblocking bool) (err error)`: 封装了 `fcntl` 系统调用，设置文件描述符 `fd` 的非阻塞模式。
* `Exec(argv0 string, argv []string, envv []string) error`: 封装了 `syscall.Exec`，用于执行一个新的程序。
* `Lutimes(path string, tv []Timeval) error`: 封装了 `UtimesNanoAt` 系统调用，用于设置符号链接的访问和修改时间。
* `Setrlimit(resource int, rlim *Rlimit) error`: 封装了 `syscall.Setrlimit`，用于设置进程的资源限制。

**8. 提供辅助函数:**

* `clen(n []byte) int`: 返回字节切片 `n` 中第一个空字节的索引，如果不存在空字节，则返回切片的长度。
* `emptyIovecs(iov []Iovec) bool`: 检查 `Iovec` 切片是否为空（即所有元素的长度都为 0）。

**这段代码是 Go 语言 `os` 和 `net` 等高级包实现底层功能的基础。** 开发者通常不会直接使用这个包中的函数，而是使用更高级别的抽象，例如 `os.File`, `net.Conn` 等。

**代码示例（推理出 `SignalNum` 的使用场景）:**

假设我们想要根据信号名称字符串 "SIGINT" 获取对应的信号值，可以这样做：

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"syscall"
)

func main() {
	signalName := "SIGINT"
	sig := unix.SignalNum(signalName)
	if sig == 0 {
		fmt.Printf("未找到名为 %s 的信号\n", signalName)
	} else {
		fmt.Printf("信号 %s 的值为: %v\n", signalName, sig)
		// 假设 SIGINT 的值为 syscall.SIGINT
		if sig == syscall.SIGINT {
			fmt.Println("这确实是 SIGINT 信号")
		}
	}
}

// 假设的输入: 无 (直接在代码中指定信号名)
// 假设的输出:
// 信号 SIGINT 的值为: interrupt
// 这确实是 SIGINT 信号
```

**代码示例（推理出 `Mmap` 和 `Munmap` 的使用场景）:**

假设我们想要将一个文件映射到内存中进行读取：

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	filename := "test.txt"
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("获取文件信息失败:", err)
		return
	}
	fileSize := int(fileInfo.Size())

	// 将文件映射到内存
	data, err := unix.Mmap(int(file.Fd()), 0, fileSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		fmt.Println("内存映射失败:", err)
		return
	}
	defer unix.Munmap(data)

	// 读取映射的内存
	fmt.Printf("文件内容: %s\n", string(data))

	// 假设 test.txt 文件内容为 "Hello, mmap!"
	// 假设的输入:  当前目录下存在名为 test.txt 的文件，内容为 "Hello, mmap!"
	// 假设的输出:
	// 文件内容: Hello, mmap!
}
```

**易犯错的点 (涉及代码推理):**

在使用 `Mmap` 和 `Munmap` 时，一个常见的错误是**忘记调用 `Munmap` 释放内存**。 如果映射的内存没有被取消映射，即使文件对象被关闭，这部分内存仍然会被占用，导致内存泄漏。

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	filename := "test.txt"
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("获取文件信息失败:", err)
		return
	}
	fileSize := int(fileInfo.Size())

	// 将文件映射到内存
	data, err := unix.Mmap(int(file.Fd()), 0, fileSize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		fmt.Println("内存映射失败:", err)
		return
	}
	// 错误示例：忘记调用 unix.Munmap(data)

	fmt.Printf("文件内容: %s\n", string(data))
	// 在这个示例中，即使 file.Close() 被调用，映射的内存可能仍然没有被释放，导致资源泄漏。
}
```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。 命令行参数的处理通常发生在 `main` 函数中，可以使用 `os.Args` 获取，然后根据需要传递给其他函数。 如果这个文件中的函数需要根据命令行参数执行不同的操作，那么这些参数需要在调用这些函数时作为参数传递进去。

例如，如果有一个使用 socket 的程序，可能需要从命令行参数获取监听的端口号：

```go
package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("用法: go run main.go <端口号>")
		return
	}

	portStr := os.Args[1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Println("无效的端口号:", err)
		return
	}

	// 使用从命令行获取的端口号创建监听器
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Println("监听失败:", err)
		return
	}
	defer ln.Close()

	fmt.Printf("监听端口: %d\n", port)
	// ... 接收连接等操作 ...
}
```

总而言之，这段 `syscall_unix.go` 文件是 Go 语言与 Unix-like 系统内核交互的桥梁，提供了执行底层系统调用的能力，是构建更高级抽象的基础。 开发者通常不会直接使用它，但理解其功能有助于深入理解 Go 语言的运行机制。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package unix

import (
	"bytes"
	"sort"
	"sync"
	"syscall"
	"unsafe"
)

var (
	Stdin  = 0
	Stdout = 1
	Stderr = 2
)

// Do the interface allocations only once for common
// Errno values.
var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)

var (
	signalNameMapOnce sync.Once
	signalNameMap     map[string]syscall.Signal
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
	case EINVAL:
		return errEINVAL
	case ENOENT:
		return errENOENT
	}
	return e
}

// ErrnoName returns the error name for error number e.
func ErrnoName(e syscall.Errno) string {
	i := sort.Search(len(errorList), func(i int) bool {
		return errorList[i].num >= e
	})
	if i < len(errorList) && errorList[i].num == e {
		return errorList[i].name
	}
	return ""
}

// SignalName returns the signal name for signal number s.
func SignalName(s syscall.Signal) string {
	i := sort.Search(len(signalList), func(i int) bool {
		return signalList[i].num >= s
	})
	if i < len(signalList) && signalList[i].num == s {
		return signalList[i].name
	}
	return ""
}

// SignalNum returns the syscall.Signal for signal named s,
// or 0 if a signal with such name is not found.
// The signal name should start with "SIG".
func SignalNum(s string) syscall.Signal {
	signalNameMapOnce.Do(func() {
		signalNameMap = make(map[string]syscall.Signal, len(signalList))
		for _, signal := range signalList {
			signalNameMap[signal.name] = signal.num
		}
	})
	return signalNameMap[s]
}

// clen returns the index of the first NULL byte in n or len(n) if n contains no NULL byte.
func clen(n []byte) int {
	i := bytes.IndexByte(n, 0)
	if i == -1 {
		i = len(n)
	}
	return i
}

// Mmap manager, for use by operating system-specific implementations.

type mmapper struct {
	sync.Mutex
	active map[*byte][]byte // active mappings; key is last byte in mapping
	mmap   func(addr, length uintptr, prot, flags, fd int, offset int64) (uintptr, error)
	munmap func(addr uintptr, length uintptr) error
}

func (m *mmapper) Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	if length <= 0 {
		return nil, EINVAL
	}

	// Map the requested memory.
	addr, errno := m.mmap(0, uintptr(length), prot, flags, fd, offset)
	if errno != nil {
		return nil, errno
	}

	// Use unsafe to convert addr into a []byte.
	b := unsafe.Slice((*byte)(unsafe.Pointer(addr)), length)

	// Register mapping in m and return it.
	p := &b[cap(b)-1]
	m.Lock()
	defer m.Unlock()
	m.active[p] = b
	return b, nil
}

func (m *mmapper) Munmap(data []byte) (err error) {
	if len(data) == 0 || len(data) != cap(data) {
		return EINVAL
	}

	// Find the base of the mapping.
	p := &data[cap(data)-1]
	m.Lock()
	defer m.Unlock()
	b := m.active[p]
	if b == nil || &b[0] != &data[0] {
		return EINVAL
	}

	// Unmap the memory and update m.
	if errno := m.munmap(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); errno != nil {
		return errno
	}
	delete(m.active, p)
	return nil
}

func Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	return mapper.Mmap(fd, offset, length, prot, flags)
}

func Munmap(b []byte) (err error) {
	return mapper.Munmap(b)
}

func MmapPtr(fd int, offset int64, addr unsafe.Pointer, length uintptr, prot int, flags int) (ret unsafe.Pointer, err error) {
	xaddr, err := mapper.mmap(uintptr(addr), length, prot, flags, fd, offset)
	return unsafe.Pointer(xaddr), err
}

func MunmapPtr(addr unsafe.Pointer, length uintptr) (err error) {
	return mapper.munmap(uintptr(addr), length)
}

func Read(fd int, p []byte) (n int, err error) {
	n, err = read(fd, p)
	if raceenabled {
		if n > 0 {
			raceWriteRange(unsafe.Pointer(&p[0]), n)
		}
		if err == nil {
			raceAcquire(unsafe.Pointer(&ioSync))
		}
	}
	return
}

func Write(fd int, p []byte) (n int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	n, err = write(fd, p)
	if raceenabled && n > 0 {
		raceReadRange(unsafe.Pointer(&p[0]), n)
	}
	return
}

func Pread(fd int, p []byte, offset int64) (n int, err error) {
	n, err = pread(fd, p, offset)
	if raceenabled {
		if n > 0 {
			raceWriteRange(unsafe.Pointer(&p[0]), n)
		}
		if err == nil {
			raceAcquire(unsafe.Pointer(&ioSync))
		}
	}
	return
}

func Pwrite(fd int, p []byte, offset int64) (n int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	n, err = pwrite(fd, p, offset)
	if raceenabled && n > 0 {
		raceReadRange(unsafe.Pointer(&p[0]), n)
	}
	return
}

// For testing: clients can set this flag to force
// creation of IPv6 sockets to return EAFNOSUPPORT.
var SocketDisableIPv6 bool

// Sockaddr represents a socket address.
type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len _Socklen, err error) // lowercase; only we can define Sockaddrs
}

// SockaddrInet4 implements the Sockaddr interface for AF_INET type sockets.
type SockaddrInet4 struct {
	Port int
	Addr [4]byte
	raw  RawSockaddrInet4
}

// SockaddrInet6 implements the Sockaddr interface for AF_INET6 type sockets.
type SockaddrInet6 struct {
	Port   int
	ZoneId uint32
	Addr   [16]byte
	raw    RawSockaddrInet6
}

// SockaddrUnix implements the Sockaddr interface for AF_UNIX type sockets.
type SockaddrUnix struct {
	Name string
	raw  RawSockaddrUnix
}

func Bind(fd int, sa Sockaddr) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return bind(fd, ptr, n)
}

func Connect(fd int, sa Sockaddr) (err error) {
	ptr, n, err := sa.sockaddr()
	if err != nil {
		return err
	}
	return connect(fd, ptr, n)
}

func Getpeername(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getpeername(fd, &rsa, &len); err != nil {
		return
	}
	return anyToSockaddr(fd, &rsa)
}

func GetsockoptByte(fd, level, opt int) (value byte, err error) {
	var n byte
	vallen := _Socklen(1)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return n, err
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	var n int32
	vallen := _Socklen(4)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return int(n), err
}

func GetsockoptInet4Addr(fd, level, opt int) (value [4]byte, err error) {
	vallen := _Socklen(4)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&value[0]), &vallen)
	return value, err
}

func GetsockoptIPMreq(fd, level, opt int) (*IPMreq, error) {
	var value IPMreq
	vallen := _Socklen(SizeofIPMreq)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptIPv6Mreq(fd, level, opt int) (*IPv6Mreq, error) {
	var value IPv6Mreq
	vallen := _Socklen(SizeofIPv6Mreq)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptIPv6MTUInfo(fd, level, opt int) (*IPv6MTUInfo, error) {
	var value IPv6MTUInfo
	vallen := _Socklen(SizeofIPv6MTUInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptICMPv6Filter(fd, level, opt int) (*ICMPv6Filter, error) {
	var value ICMPv6Filter
	vallen := _Socklen(SizeofICMPv6Filter)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptLinger(fd, level, opt int) (*Linger, error) {
	var linger Linger
	vallen := _Socklen(SizeofLinger)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&linger), &vallen)
	return &linger, err
}

func GetsockoptTimeval(fd, level, opt int) (*Timeval, error) {
	var tv Timeval
	vallen := _Socklen(unsafe.Sizeof(tv))
	err := getsockopt(fd, level, opt, unsafe.Pointer(&tv), &vallen)
	return &tv, err
}

func GetsockoptUint64(fd, level, opt int) (value uint64, err error) {
	var n uint64
	vallen := _Socklen(8)
	err = getsockopt(fd, level, opt, unsafe.Pointer(&n), &vallen)
	return n, err
}

func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if n, err = recvfrom(fd, p, flags, &rsa, &len); err != nil {
		return
	}
	if rsa.Addr.Family != AF_UNSPEC {
		from, err = anyToSockaddr(fd, &rsa)
	}
	return
}

// Recvmsg receives a message from a socket using the recvmsg system call. The
// received non-control data will be written to p, and any "out of band"
// control data will be written to oob. The flags are passed to recvmsg.
//
// The results are:
//   - n is the number of non-control data bytes read into p
//   - oobn is the number of control data bytes read into oob; this may be interpreted using [ParseSocketControlMessage]
//   - recvflags is flags returned by recvmsg
//   - from is the address of the sender
//
// If the underlying socket type is not SOCK_DGRAM, a received message
// containing oob data and a single '\0' of non-control data is treated as if
// the message contained only control data, i.e. n will be zero on return.
func Recvmsg(fd int, p, oob []byte, flags int) (n, oobn int, recvflags int, from Sockaddr, err error) {
	var iov [1]Iovec
	if len(p) > 0 {
		iov[0].Base = &p[0]
		iov[0].SetLen(len(p))
	}
	var rsa RawSockaddrAny
	n, oobn, recvflags, err = recvmsgRaw(fd, iov[:], oob, flags, &rsa)
	// source address is only specified if the socket is unconnected
	if rsa.Addr.Family != AF_UNSPEC {
		from, err = anyToSockaddr(fd, &rsa)
	}
	return
}

// RecvmsgBuffers receives a message from a socket using the recvmsg system
// call. This function is equivalent to Recvmsg, but non-control data read is
// scattered into the buffers slices.
func RecvmsgBuffers(fd int, buffers [][]byte, oob []byte, flags int) (n, oobn int, recvflags int, from Sockaddr, err error) {
	iov := make([]Iovec, len(buffers))
	for i := range buffers {
		if len(buffers[i]) > 0 {
			iov[i].Base = &buffers[i][0]
			iov[i].SetLen(len(buffers[i]))
		} else {
			iov[i].Base = (*byte)(unsafe.Pointer(&_zero))
		}
	}
	var rsa RawSockaddrAny
	n, oobn, recvflags, err = recvmsgRaw(fd, iov, oob, flags, &rsa)
	if err == nil && rsa.Addr.Family != AF_UNSPEC {
		from, err = anyToSockaddr(fd, &rsa)
	}
	return
}

// Sendmsg sends a message on a socket to an address using the sendmsg system
// call. This function is equivalent to SendmsgN, but does not return the
// number of bytes actually sent.
func Sendmsg(fd int, p, oob []byte, to Sockaddr, flags int) (err error) {
	_, err = SendmsgN(fd, p, oob, to, flags)
	return
}

// SendmsgN sends a message on a socket to an address using the sendmsg system
// call. p contains the non-control data to send, and oob contains the "out of
// band" control data. The flags are passed to sendmsg. The number of
// non-control bytes actually written to the socket is returned.
//
// Some socket types do not support sending control data without accompanying
// non-control data. If p is empty, and oob contains control data, and the
// underlying socket type is not SOCK_DGRAM, p will be treated as containing a
// single '\0' and the return value will indicate zero bytes sent.
//
// The Go function Recvmsg, if called with an empty p and a non-empty oob,
// will read and ignore this additional '\0'.  If the message is received by
// code that does not use Recvmsg, or that does not use Go at all, that code
// will need to be written to expect and ignore the additional '\0'.
//
// If you need to send non-empty oob with p actually empty, and if the
// underlying socket type supports it, you can do so via a raw system call as
// follows:
//
//	msg := &unix.Msghdr{
//	    Control: &oob[0],
//	}
//	msg.SetControllen(len(oob))
//	n, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(msg)), flags)
func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (n int, err error) {
	var iov [1]Iovec
	if len(p) > 0 {
		iov[0].Base = &p[0]
		iov[0].SetLen(len(p))
	}
	var ptr unsafe.Pointer
	var salen _Socklen
	if to != nil {
		ptr, salen, err = to.sockaddr()
		if err != nil {
			return 0, err
		}
	}
	return sendmsgN(fd, iov[:], oob, ptr, salen, flags)
}

// SendmsgBuffers sends a message on a socket to an address using the sendmsg
// system call. This function is equivalent to SendmsgN, but the non-control
// data is gathered from buffers.
func SendmsgBuffers(fd int, buffers [][]byte, oob []byte, to Sockaddr, flags int) (n int, err error) {
	iov := make([]Iovec, len(buffers))
	for i := range buffers {
		if len(buffers[i]) > 0 {
			iov[i].Base = &buffers[i][0]
			iov[i].SetLen(len(buffers[i]))
		} else {
			iov[i].Base = (*byte)(unsafe.Pointer(&_zero))
		}
	}
	var ptr unsafe.Pointer
	var salen _Socklen
	if to != nil {
		ptr, salen, err = to.sockaddr()
		if err != nil {
			return 0, err
		}
	}
	return sendmsgN(fd, iov, oob, ptr, salen, flags)
}

func Send(s int, buf []byte, flags int) (err error) {
	return sendto(s, buf, flags, nil, 0)
}

func Sendto(fd int, p []byte, flags int, to Sockaddr) (err error) {
	var ptr unsafe.Pointer
	var salen _Socklen
	if to != nil {
		ptr, salen, err = to.sockaddr()
		if err != nil {
			return err
		}
	}
	return sendto(fd, p, flags, ptr, salen)
}

func SetsockoptByte(fd, level, opt int, value byte) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(&value), 1)
}

func SetsockoptInt(fd, level, opt int, value int) (err error) {
	var n = int32(value)
	return setsockopt(fd, level, opt, unsafe.Pointer(&n), 4)
}

func SetsockoptInet4Addr(fd, level, opt int, value [4]byte) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(&value[0]), 4)
}

func SetsockoptIPMreq(fd, level, opt int, mreq *IPMreq) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), SizeofIPMreq)
}

func SetsockoptIPv6Mreq(fd, level, opt int, mreq *IPv6Mreq) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), SizeofIPv6Mreq)
}

func SetsockoptICMPv6Filter(fd, level, opt int, filter *ICMPv6Filter) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(filter), SizeofICMPv6Filter)
}

func SetsockoptLinger(fd, level, opt int, l *Linger) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(l), SizeofLinger)
}

func SetsockoptString(fd, level, opt int, s string) (err error) {
	var p unsafe.Pointer
	if len(s) > 0 {
		p = unsafe.Pointer(&[]byte(s)[0])
	}
	return setsockopt(fd, level, opt, p, uintptr(len(s)))
}

func SetsockoptTimeval(fd, level, opt int, tv *Timeval) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(tv), unsafe.Sizeof(*tv))
}

func SetsockoptUint64(fd, level, opt int, value uint64) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(&value), 8)
}

func Socket(domain, typ, proto int) (fd int, err error) {
	if domain == AF_INET6 && SocketDisableIPv6 {
		return -1, EAFNOSUPPORT
	}
	fd, err = socket(domain, typ, proto)
	return
}

func Socketpair(domain, typ, proto int) (fd [2]int, err error) {
	var fdx [2]int32
	err = socketpair(domain, typ, proto, &fdx)
	if err == nil {
		fd[0] = int(fdx[0])
		fd[1] = int(fdx[1])
	}
	return
}

var ioSync int64

func CloseOnExec(fd int) { fcntl(fd, F_SETFD, FD_CLOEXEC) }

func SetNonblock(fd int, nonblocking bool) (err error) {
	flag, err := fcntl(fd, F_GETFL, 0)
	if err != nil {
		return err
	}
	if (flag&O_NONBLOCK != 0) == nonblocking {
		return nil
	}
	if nonblocking {
		flag |= O_NONBLOCK
	} else {
		flag &= ^O_NONBLOCK
	}
	_, err = fcntl(fd, F_SETFL, flag)
	return err
}

// Exec calls execve(2), which replaces the calling executable in the process
// tree. argv0 should be the full path to an executable ("/bin/ls") and the
// executable name should also be the first argument in argv (["ls", "-l"]).
// envv are the environment variables that should be passed to the new
// process (["USER=go", "PWD=/tmp"]).
func Exec(argv0 string, argv []string, envv []string) error {
	return syscall.Exec(argv0, argv, envv)
}

// Lutimes sets the access and modification times tv on path. If path refers to
// a symlink, it is not dereferenced and the timestamps are set on the symlink.
// If tv is nil, the access and modification times are set to the current time.
// Otherwise tv must contain exactly 2 elements, with access time as the first
// element and modification time as the second element.
func Lutimes(path string, tv []Timeval) error {
	if tv == nil {
		return UtimesNanoAt(AT_FDCWD, path, nil, AT_SYMLINK_NOFOLLOW)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return UtimesNanoAt(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW)
}

// emptyIovecs reports whether there are no bytes in the slice of Iovec.
func emptyIovecs(iov []Iovec) bool {
	for i := range iov {
		if iov[i].Len > 0 {
			return false
		}
	}
	return true
}

// Setrlimit sets a resource limit.
func Setrlimit(resource int, rlim *Rlimit) error {
	// Just call the syscall version, because as of Go 1.21
	// it will affect starting a new process.
	return syscall.Setrlimit(resource, (*syscall.Rlimit)(rlim))
}
```