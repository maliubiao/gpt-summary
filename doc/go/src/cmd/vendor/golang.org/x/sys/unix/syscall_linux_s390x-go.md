Response:
Let's break down the thought process for answering the request about the `syscall_linux_s390x.go` file.

**1. Initial Understanding of the Request:**

The request asks for a functional breakdown of the provided Go code snippet. Key aspects to cover are:

*   Listing the functions and their purpose.
*   Identifying the higher-level Go functionality these low-level calls enable.
*   Providing Go code examples demonstrating usage.
*   Highlighting potential pitfalls for users.

**2. Analyzing the Code Structure:**

The code is structured as a Go package (`unix`) and primarily consists of:

*   `//sys` and `//sysnb` directives: These are crucial. They indicate direct system call bindings. `//sys` implies a potentially blocking call, while `//sysnb` suggests a non-blocking one. This is the core of the file's functionality.
*   Import statement: `unsafe` is imported, signaling direct memory manipulation, which is common in syscall interactions.
*   Go functions wrapping syscalls:  These provide a more Go-friendly interface to the underlying system calls (e.g., `Time`).
*   Helper functions: Functions like `setTimespec`, `setTimeval`, and the socket call wrappers are examples.
*   Platform-specific logic: The `//go:build s390x && linux` comment confirms this file is specific to the s390x architecture on Linux.
*   Socket call indirection: The code has a section dedicated to handling socket calls via `SYS_SOCKETCALL`, which is a characteristic of s390x Linux.
*   Struct method implementations: Methods like `PC()`, `SetPC()`, `SetLen()` on various struct types are present.

**3. Deconstructing Functionality - Iterative Approach:**

I'd go through the code line by line (or in logical blocks) and perform the following:

*   **Identify syscalls:**  Look for `//sys` and `//sysnb`. Note the function name, the arguments, and the underlying system call number (if provided).
*   **Determine function purpose:** Based on the syscall name and arguments, deduce the function's role (e.g., `EpollWait` is for waiting on epoll events, `Fstat` retrieves file status). Refer to Linux man pages if needed for unfamiliar syscalls.
*   **Group related functions:** Notice patterns. Many functions deal with file operations (stat, chown, truncate), time, and networking.
*   **Focus on unique aspects:** The socket call indirection is a significant feature of this architecture and needs specific attention. The `mmap` implementation is also specific.
*   **Consider the Go abstraction:** How do these low-level calls enable higher-level Go features?  For example, `Fstat` is used by `os.Stat`. EpollWait is part of the Go network poller.

**4. Generating Examples (Trial and Error/Known Patterns):**

For each category of functions, think about how they are used in common Go scenarios:

*   **File operations:**  `os.Stat`, `os.Chown`, `os.Truncate`, `os.Rename`, `io.Copy` (potentially using `sendfile`).
*   **Networking:** `net.Listen`, `net.Dial`, `net.Accept`, `socket.SetOption`, `socket.Receive`, `socket.Send`. The socket call wrappers directly translate to these.
*   **Time:** `time.Now()` (which internally uses `Gettimeofday`).
*   **Memory mapping:**  `syscall.Mmap`.
*   **Process control:**  `syscall.Pause`, though less commonly used directly.
*   **Resource limits:** `syscall.Getrlimit`.

For the examples, I'd choose simple, illustrative cases. Include necessary imports.

**5. Identifying Potential Pitfalls:**

Think about common mistakes developers make when dealing with low-level system calls:

*   **Incorrect error handling:**  Forgetting to check the `err` return value.
*   **Incorrect argument types/sizes:** Especially when dealing with pointers and lengths.
*   **Understanding syscall behavior:**  Not knowing the nuances of a particular syscall (e.g., the meaning of flags in `EpollWait`).
*   **Platform-specific behavior:**  Assuming behavior is consistent across architectures. The socket call indirection is a prime example of something specific to s390x.
*   **Direct memory manipulation:**  Using `unsafe` requires careful handling to avoid memory corruption.

**6. Structuring the Output:**

Organize the information logically:

*   Start with a general overview of the file's purpose.
*   Categorize functions by their area of concern (file I/O, networking, etc.).
*   Provide clear explanations of each function's role.
*   Present well-commented Go code examples.
*   Detail any architecture-specific behaviors (like the socket call indirection).
*   List common pitfalls with illustrative examples.

**Self-Correction/Refinement during the process:**

*   **Realization:** Initially, I might just list the syscalls without explaining their Go equivalents. I'd then realize the request asks for the *Go functionality* and add those connections.
*   **Simplification:**  For complex syscalls with many options (like `EpollWait`), I'd focus on a basic, common use case in the example.
*   **Clarity:**  If an explanation is unclear, rephrase it or add more detail. For instance, explicitly mentioning the role of `unsafe.Pointer` in syscalls.
*   **Completeness:** Double-check if all the functions in the snippet have been addressed.

By following these steps, combining direct code analysis with an understanding of operating system concepts and Go's standard library, one can effectively address the request and provide a comprehensive explanation of the `syscall_linux_s390x.go` file.
这个Go语言源文件 `syscall_linux_s390x.go` 是 Go 语言标准库 `syscall` 包的一部分，专门为 Linux 操作系统在 s390x (System/390 architecture 64-bit) 架构上提供底层系统调用接口。

**它的主要功能是：**

1. **定义和暴露系统调用函数:** 文件中通过 `//sys` 和 `//sysnb` 注释定义了一系列与 Linux 系统调用对应的 Go 函数。
    *   `//sys` 表示该系统调用可能会阻塞 (blocking)。
    *   `//sysnb` 表示该系统调用是非阻塞的 (non-blocking)。
    这些函数直接映射到 Linux 内核提供的系统调用接口，允许 Go 程序执行底层的操作系统操作。

2. **提供平台特定的系统调用实现:** 由于不同的操作系统和架构的系统调用号和调用方式可能不同，这个文件为 s390x 架构下的 Linux 提供了特定的实现细节，例如：
    *   一些系统调用使用了不同的名称 (`SYS_FADVISE64`, `SYS_NEWFSTATAT`, `SYS_PREAD64`, `SYS_PWRITE64`, `SYS_LSEEK`)。
    *   `mmap` 系统调用在 s390x Linux 上需要通过一个结构体传递参数。
    *   Socket 相关的系统调用需要通过 `SYS_SOCKETCALL` 进行间接调用。

3. **定义与系统调用相关的常量和数据结构:** 虽然这个文件中没有直接定义常量和结构体，但它依赖于 `syscall` 包中定义的通用结构体 (如 `Stat_t`, `EpollEvent`, `Timeval` 等)，并可能在其他地方定义了 s390x 特定的常量。

**它是什么Go语言功能的实现？**

这个文件是 Go 语言 `syscall` 包中提供操作系统底层接口功能的具体实现。 `syscall` 包允许 Go 程序直接与操作系统内核交互，执行诸如文件操作、进程管理、网络通信等底层任务。

**Go 代码示例：**

以下是一些基于该文件中定义的系统调用的 Go 代码示例：

**示例 1: 文件状态 (使用 `Fstat`)**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	file, err := os.Open("example.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	fd := int(file.Fd())
	var stat syscall.Stat_t
	err = syscall.Fstat(fd, &stat)
	if err != nil {
		fmt.Println("Error getting file status:", err)
		return
	}

	fmt.Printf("File size: %d bytes\n", stat.Size)
}
```

**假设输入:**  当前目录下存在一个名为 `example.txt` 的文件，大小为 1024 字节。

**预期输出:**

```
File size: 1024 bytes
```

**代码解释:**

1. `os.Open("example.txt")` 打开文件，并获取 `os.File` 对象。
2. `file.Fd()` 获取文件描述符。
3. `syscall.Fstat(fd, &stat)` 调用 `Fstat` 系统调用，将文件描述符 `fd` 对应的文件状态信息填充到 `stat` 结构体中。
4. `stat.Size` 包含了文件的大小。

**示例 2: 创建目录 (使用 `Fstatat`)**

虽然文件中没有直接创建目录的系统调用，但 `Fstatat` 可以用于检查目录是否存在。我们可以结合其他系统调用（例如 `Mkdirat`，如果存在于其他文件中）来说明概念。假设我们有 `Mkdirat`。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	dirname := "new_directory"
	dirfd := syscall.AT_FDCWD // 使用当前工作目录

	// 假设 syscall 包中有 Mkdirat 的定义 (实际可能在其他平台特定的文件中)
	// err := syscall.Mkdirat(dirfd, dirname, 0755)
	// if err != nil {
	// 	fmt.Println("Error creating directory:", err)
	// 	return
	// }

	var stat syscall.Stat_t
	err := syscall.Fstatat(dirfd, dirname, &stat, 0)
	if err != nil {
		fmt.Println("Directory not found (or other error):", err)
		return
	}

	fmt.Printf("Directory '%s' exists.\n", dirname)
}
```

**假设输入:** 当前工作目录下存在一个名为 `new_directory` 的目录。

**预期输出:**

```
Directory 'new_directory' exists.
```

**代码解释:**

1. `syscall.AT_FDCWD` 表示使用当前工作目录的文件描述符。
2. `syscall.Fstatat(dirfd, dirname, &stat, 0)` 调用 `Fstatat` 系统调用，检查指定目录是否存在。如果存在，则填充 `stat` 结构体，否则返回错误。

**示例 3: 发送数据到套接字 (使用 `sendto`)**

```go
package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func main() {
	conn, err := net.Dial("udp", "127.0.0.1:8080")
	if err != nil {
		fmt.Println("Error dialing:", err)
		return
	}
	defer conn.Close()

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		fmt.Println("Not a UDP connection")
		return
	}

	file, err := udpConn.File()
	if err != nil {
		fmt.Println("Error getting file descriptor:", err)
		return
	}
	defer file.Close()

	fd := int(file.Fd())
	message := []byte("Hello, UDP!")
	addr := &syscall.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{127, 0, 0, 1},
	}
	addrPtr := (*syscall.RawSockaddrAny)(unsafe.Pointer(addr))
	addrLen := syscall.Socklen(syscall.SizeofSockaddrInet4)

	err = syscall.Sendto(fd, message, 0, addrPtr, addrLen)
	if err != nil {
		fmt.Println("Error sending data:", err)
		return
	}

	fmt.Println("Data sent successfully.")
}
```

**假设输入:**  有一个 UDP 服务监听在 `127.0.0.1:8080`。

**预期输出:**

```
Data sent successfully.
```

**代码解释:**

1. `net.Dial("udp", "127.0.0.1:8080")` 创建一个 UDP 连接。
2. 获取底层的 socket 文件描述符。
3. 创建一个 `syscall.SockaddrInet4` 结构体，包含目标地址和端口。
4. `syscall.Sendto` 使用文件描述符、消息内容、标志、目标地址和地址长度来发送数据。  **注意:**  这里为了直接使用 `syscall.Sendto`，需要进行一些类型转换。在实际的 Go 网络编程中，通常会使用 `net` 包提供的更高级的 API。

**命令行参数的具体处理:**

这个代码文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并可能使用 `os.Args` 或 `flag` 包进行解析。  `syscall` 包提供的功能是操作系统级别的，不涉及用户层面的命令行参数解析。

**使用者易犯错的点：**

1. **错误处理:** 直接使用系统调用容易忽略错误处理。每个系统调用都会返回一个 `error`，必须仔细检查以确保程序健壮性。

    ```go
    // 错误的做法：
    syscall.Fstat(fd, &stat) // 没有检查错误

    // 正确的做法：
    err := syscall.Fstat(fd, &stat)
    if err != nil {
        fmt.Println("Error:", err)
        // 进行错误处理
    }
    ```

2. **平台差异:**  直接使用 `syscall` 的代码可能不具备跨平台性。不同的操作系统可能有不同的系统调用号、参数和行为。这个文件本身就是针对特定平台 (Linux s390x) 的。

3. **不正确的参数:** 系统调用对参数类型、大小和含义有严格的要求。传递错误的参数可能导致程序崩溃或产生未定义的行为。例如，`sendto` 函数需要正确设置 `Sockaddr` 结构体和地址长度。

4. **资源管理:**  某些系统调用涉及到资源的申请和释放 (例如，文件描述符、内存映射)。不正确的资源管理可能导致资源泄漏。

5. **竞态条件和同步问题:**  在多线程或并发环境下使用系统调用时，需要注意竞态条件和同步问题，确保数据的一致性。

6. **不必要的直接系统调用:**  Go 语言的标准库提供了很多高级抽象 (例如 `os`, `net`, `io` 包)，它们在底层可能使用了 `syscall`，但提供了更安全、更易用、更跨平台的接口。直接使用 `syscall` 通常只在需要非常底层的控制或访问标准库未暴露的功能时才考虑。

7. **对 `unsafe` 包的误用:**  在涉及指针操作 (如 socket 地址) 时，可能会用到 `unsafe` 包。不正确地使用 `unsafe` 可能导致内存安全问题。例如，不正确的类型转换或访问越界内存。

总之，`go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux_s390x.go` 是 Go 语言在 Linux s390x 架构上与操作系统内核交互的桥梁，它暴露了底层的系统调用接口，但同时也需要开发者具备一定的操作系统和底层编程知识，并注意潜在的错误和陷阱。在大多数情况下，建议使用 Go 标准库提供的高级抽象来完成任务。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux_s390x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build s390x && linux

package unix

import (
	"unsafe"
)

//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error)
//sys	Fadvise(fd int, offset int64, length int64, advice int) (err error) = SYS_FADVISE64
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fstat(fd int, stat *Stat_t) (err error)
//sys	Fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) = SYS_NEWFSTATAT
//sys	Fstatfs(fd int, buf *Statfs_t) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (euid int)
//sysnb	Getgid() (gid int)
//sysnb	Getrlimit(resource int, rlim *Rlimit) (err error)
//sysnb	Getuid() (uid int)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Lstat(path string, stat *Stat_t) (err error)
//sys	Pause() (err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = SYS_PREAD64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = SYS_PWRITE64
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)
//sys	Seek(fd int, offset int64, whence int) (off int64, err error) = SYS_LSEEK
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error)
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error)
//sys	setfsgid(gid int) (prev int, err error)
//sys	setfsuid(uid int) (prev int, err error)
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)
//sys	Stat(path string, stat *Stat_t) (err error)
//sys	Statfs(path string, buf *Statfs_t) (err error)
//sys	SyncFileRange(fd int, off int64, n int64, flags int) (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Ustat(dev int, ubuf *Ustat_t) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)
//sysnb	setgroups(n int, list *_Gid_t) (err error)

//sys	futimesat(dirfd int, path string, times *[2]Timeval) (err error)
//sysnb	Gettimeofday(tv *Timeval) (err error)

func Time(t *Time_t) (tt Time_t, err error) {
	var tv Timeval
	err = Gettimeofday(&tv)
	if err != nil {
		return 0, err
	}
	if t != nil {
		*t = Time_t(tv.Sec)
	}
	return Time_t(tv.Sec), nil
}

//sys	Utime(path string, buf *Utimbuf) (err error)
//sys	utimes(path string, times *[2]Timeval) (err error)

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: sec, Usec: usec}
}

func Ioperm(from int, num int, on int) (err error) {
	return ENOSYS
}

func Iopl(level int) (err error) {
	return ENOSYS
}

func (r *PtraceRegs) PC() uint64 { return r.Psw.Addr }

func (r *PtraceRegs) SetPC(pc uint64) { r.Psw.Addr = pc }

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint64(length)
}

func (msghdr *Msghdr) SetIovlen(length int) {
	msghdr.Iovlen = uint64(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint64(length)
}

func (rsa *RawSockaddrNFCLLCP) SetServiceNameLen(length int) {
	rsa.Service_name_len = uint64(length)
}

// Linux on s390x uses the old mmap interface, which requires arguments to be passed in a struct.
// mmap2 also requires arguments to be passed in a struct; it is currently not exposed in <asm/unistd.h>.
func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error) {
	mmap_args := [6]uintptr{addr, length, uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset)}
	r0, _, e1 := Syscall(SYS_MMAP, uintptr(unsafe.Pointer(&mmap_args[0])), 0, 0)
	xaddr = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// On s390x Linux, all the socket calls go through an extra indirection.
// The arguments to the underlying system call (SYS_SOCKETCALL) are the
// number below and a pointer to an array of uintptr.
const (
	// see linux/net.h
	netSocket      = 1
	netBind        = 2
	netConnect     = 3
	netListen      = 4
	netAccept      = 5
	netGetSockName = 6
	netGetPeerName = 7
	netSocketPair  = 8
	netSend        = 9
	netRecv        = 10
	netSendTo      = 11
	netRecvFrom    = 12
	netShutdown    = 13
	netSetSockOpt  = 14
	netGetSockOpt  = 15
	netSendMsg     = 16
	netRecvMsg     = 17
	netAccept4     = 18
	netRecvMMsg    = 19
	netSendMMsg    = 20
)

func accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (int, error) {
	args := [4]uintptr{uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags)}
	fd, _, err := Syscall(SYS_SOCKETCALL, netAccept4, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return 0, err
	}
	return int(fd), nil
}

func getsockname(s int, rsa *RawSockaddrAny, addrlen *_Socklen) error {
	args := [3]uintptr{uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen))}
	_, _, err := RawSyscall(SYS_SOCKETCALL, netGetSockName, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func getpeername(s int, rsa *RawSockaddrAny, addrlen *_Socklen) error {
	args := [3]uintptr{uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen))}
	_, _, err := RawSyscall(SYS_SOCKETCALL, netGetPeerName, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func socketpair(domain int, typ int, flags int, fd *[2]int32) error {
	args := [4]uintptr{uintptr(domain), uintptr(typ), uintptr(flags), uintptr(unsafe.Pointer(fd))}
	_, _, err := RawSyscall(SYS_SOCKETCALL, netSocketPair, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) error {
	args := [3]uintptr{uintptr(s), uintptr(addr), uintptr(addrlen)}
	_, _, err := Syscall(SYS_SOCKETCALL, netBind, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) error {
	args := [3]uintptr{uintptr(s), uintptr(addr), uintptr(addrlen)}
	_, _, err := Syscall(SYS_SOCKETCALL, netConnect, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func socket(domain int, typ int, proto int) (int, error) {
	args := [3]uintptr{uintptr(domain), uintptr(typ), uintptr(proto)}
	fd, _, err := RawSyscall(SYS_SOCKETCALL, netSocket, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return 0, err
	}
	return int(fd), nil
}

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) error {
	args := [5]uintptr{uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen))}
	_, _, err := Syscall(SYS_SOCKETCALL, netGetSockOpt, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) error {
	args := [5]uintptr{uintptr(s), uintptr(level), uintptr(name), uintptr(val), vallen}
	_, _, err := Syscall(SYS_SOCKETCALL, netSetSockOpt, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func recvfrom(s int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (int, error) {
	var base uintptr
	if len(p) > 0 {
		base = uintptr(unsafe.Pointer(&p[0]))
	}
	args := [6]uintptr{uintptr(s), base, uintptr(len(p)), uintptr(flags), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen))}
	n, _, err := Syscall(SYS_SOCKETCALL, netRecvFrom, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return 0, err
	}
	return int(n), nil
}

func sendto(s int, p []byte, flags int, to unsafe.Pointer, addrlen _Socklen) error {
	var base uintptr
	if len(p) > 0 {
		base = uintptr(unsafe.Pointer(&p[0]))
	}
	args := [6]uintptr{uintptr(s), base, uintptr(len(p)), uintptr(flags), uintptr(to), uintptr(addrlen)}
	_, _, err := Syscall(SYS_SOCKETCALL, netSendTo, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func recvmsg(s int, msg *Msghdr, flags int) (int, error) {
	args := [3]uintptr{uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags)}
	n, _, err := Syscall(SYS_SOCKETCALL, netRecvMsg, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return 0, err
	}
	return int(n), nil
}

func sendmsg(s int, msg *Msghdr, flags int) (int, error) {
	args := [3]uintptr{uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags)}
	n, _, err := Syscall(SYS_SOCKETCALL, netSendMsg, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return 0, err
	}
	return int(n), nil
}

func Listen(s int, n int) error {
	args := [2]uintptr{uintptr(s), uintptr(n)}
	_, _, err := Syscall(SYS_SOCKETCALL, netListen, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

func Shutdown(s, how int) error {
	args := [2]uintptr{uintptr(s), uintptr(how)}
	_, _, err := Syscall(SYS_SOCKETCALL, netShutdown, uintptr(unsafe.Pointer(&args)), 0)
	if err != 0 {
		return err
	}
	return nil
}

//sys	kexecFileLoad(kernelFd int, initrdFd int, cmdlineLen int, cmdline string, flags int) (err error)

func KexecFileLoad(kernelFd int, initrdFd int, cmdline string, flags int) error {
	cmdlineLen := len(cmdline)
	if cmdlineLen > 0 {
		// Account for the additional NULL byte added by
		// BytePtrFromString in kexecFileLoad. The kexec_file_load
		// syscall expects a NULL-terminated string.
		cmdlineLen++
	}
	return kexecFileLoad(kernelFd, initrdFd, cmdlineLen, cmdline, flags)
}
```