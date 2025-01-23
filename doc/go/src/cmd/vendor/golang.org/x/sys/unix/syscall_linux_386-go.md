Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - Context is Key:**

The first line is crucial: "这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux_386.go的go语言实现的一部分". This tells us:

* **Location:** It's part of the `golang.org/x/sys/unix` package, specifically for Linux on the 386 architecture. This means it deals with low-level system calls.
* **Purpose:** It's about interfacing with the Linux kernel's system call interface. It's *not* application-level code.

**2. Dissecting the Code - Top-Down Approach:**

I start by scanning the code for key elements:

* **`//go:build 386 && linux`:**  This confirms the architectural and OS specificity. It's a build constraint.
* **`package unix`:** This is the package declaration, reinforcing the low-level system interaction.
* **`import ("unsafe")`:** The presence of `unsafe` immediately signals direct memory manipulation and interaction with C-like structures. This reinforces the system call nature.
* **Function Definitions:** I look for the functions and their signatures. I notice two initial helper functions: `setTimespec` and `setTimeval`. These seem to be for creating `Timespec` and `Timeval` structures, which are common in system calls dealing with time.
* **`//sys` and `//sysnb` Comments:**  These are extremely important. They are directives for the Go compiler's `syscall` package to generate the necessary assembly code for making system calls. I note the pattern: `//sys <FunctionName>(...) (...) = SYS_<SYSTEM_CALL_NAME>`. The `nb` likely means "no blocking".
* **Constants:**  The `_SOCKET`, `_BIND`, etc., constants point to specific socket-related system call numbers.
* **`mmap` function:** This is a direct wrapper around `mmap2`, indicating a slightly different system call variant is being used.
* **`rlimit32` struct and related functions:**  This signals handling of resource limits.
* **`Seek` function:** This is a wrapper around a lower-level `seek` function.
* **Socket-related functions:** There's a block of functions like `accept4`, `getsockname`, `bind`, `connect`, etc. These are clearly wrappers around socket system calls.
* **`Fstatfs`, `Statfs`:** These are for file system statistics.
* **Methods on structs:** The methods on `PtraceRegs`, `Iovec`, `Msghdr`, `Cmsghdr`, and `RawSockaddrNFCLLCP` suggest manipulating fields of structures that are passed to system calls.

**3. Categorizing Functionality:**

Based on the above observations, I start grouping the functions by their likely purpose:

* **Time Handling:** `setTimespec`, `setTimeval`, `Gettimeofday`, `Time`, `Utime`, `utimes`.
* **File Operations:** `Fadvise`, `Fchown`, `Fstat`, `Fstatat`, `Ftruncate`, `Lchown`, `Lstat`, `pread`, `pwrite`, `Renameat`, `sendfile`, `SyncFileRange`, `Truncate`, `Ustat`, `futimesat`.
* **Process/User ID Operations:** `Getegid`, `Geteuid`, `Getgid`, `Getuid`, `setfsgid`, `setfsuid`, `getgroups`, `setgroups`.
* **Memory Management:** `mmap`, `mmap2`.
* **Resource Limits:** `Getrlimit`.
* **File Descriptor Control:** `EpollWait`, `Select`.
* **Low-Level System Control:** `Ioperm`, `Iopl`, `Pause`.
* **Socket Operations:**  The block of `socketcall` based functions.
* **File System Statistics:** `Fstatfs`, `Statfs`.
* **Structure Manipulation:** Methods on structs.

**4. Inferring Go Features and Providing Examples:**

Now I connect the identified functionalities to Go features and try to illustrate with code examples. The key here is recognizing the pattern of system call wrappers.

* **System Calls:** The `//sys` comments are the most direct evidence. I choose a common one like `Fstat` and show how it maps to the underlying system call and how a Go program would use it. I also consider the error handling aspect.
* **Time Handling:** The `setTimespec` and `setTimeval` functions and the presence of functions like `Gettimeofday` clearly point to time-related operations. I show how these could be used to interact with system time.
* **File Operations:**  Functions like `Open`, `Read`, `Write` are common, but these low-level functions provide more granular control. I illustrate `Ftruncate` to show how file sizes can be manipulated directly using a file descriptor.
* **Socket Programming:** The numerous `socketcall` functions are a dead giveaway. I demonstrate a basic socket creation and binding example.
* **Memory Mapping:** The `mmap` function directly corresponds to memory mapping. I provide a basic example of mapping a file into memory.
* **Resource Limits:**  `Getrlimit` is self-explanatory. I show how to retrieve resource limits.

**5. Considering Edge Cases and Potential Errors:**

This part requires thinking about how these low-level functions are used and what could go wrong.

* **Incorrect File Descriptors:**  A common error.
* **Invalid Memory Addresses/Lengths:**  Especially relevant for `mmap` and functions dealing with pointers.
* **Permissions Issues:** Many of these calls are subject to permissions.
* **Socket Programming Errors:**  Incorrect addresses, ports, protocols, etc.

**6. Review and Refine:**

Finally, I review my analysis to ensure accuracy, clarity, and completeness. I check if the examples are correct and if the explanations are easy to understand. I consider if I've missed any key aspects of the code. For instance, I initially might have overlooked the significance of the `unsafe` package and then realize its crucial role in system call interactions.

This systematic approach, starting with understanding the context, dissecting the code, categorizing functionality, connecting to Go features, and considering potential issues, allows for a comprehensive analysis of the given code snippet.
这段代码是 Go 语言标准库 `syscall` 包的一部分，专门为 Linux 操作系统在 386 架构上提供系统调用接口。它定义了一些与操作系统内核交互的底层函数。

**功能列表:**

1. **时间相关:**
   - `setTimespec`: 创建 `Timespec` 结构，用于表示秒和纳秒的时间。
   - `setTimeval`: 创建 `Timeval` 结构，用于表示秒和微秒的时间。
   - `Gettimeofday`: 获取当前时间。
   - `Time`: 获取当前时间 (以 `Time_t` 类型返回)。
   - `Utime`: 修改文件的访问和修改时间。
   - `utimes`: 修改文件的访问和修改时间，精度更高。
   - `futimesat`: 修改相对于目录文件描述符的文件的访问和修改时间。

2. **文件操作 (支持 64 位文件系统和 32 位 UID/GID):**
   - `Fadvise`: 向内核提供关于文件访问模式的建议，以优化 I/O 操作。
   - `Fchown`: 修改文件所有者和所属组。
   - `Fstat`: 获取文件状态信息。
   - `Fstatat`: 获取相对于目录文件描述符的文件状态信息。
   - `Ftruncate`: 截断文件至指定长度。
   - `Lchown`: 修改符号链接的所有者和所属组。
   - `Lstat`: 获取符号链接指向的文件状态信息。
   - `pread`: 在指定偏移量处读取文件内容。
   - `pwrite`: 在指定偏移量处写入文件内容。
   - `Renameat`: 原子地重命名相对于目录文件描述符的文件。
   - `sendfile`: 在两个文件描述符之间高效传输数据。
   - `SyncFileRange`: 将文件指定范围的数据同步到磁盘。
   - `Truncate`: 截断文件至指定长度。
   - `Ustat`: 获取文件系统的状态信息 (已过时，不推荐使用)。

3. **进程/用户/组 ID 相关 (32 位):**
   - `Getegid`: 获取有效组 ID。
   - `Geteuid`: 获取有效用户 ID。
   - `Getgid`: 获取组 ID。
   - `Getuid`: 获取用户 ID。
   - `setfsgid`: 设置文件系统组 ID。
   - `setfsuid`: 设置文件系统用户 ID。
   - `getgroups`: 获取当前进程所属的组 ID 列表。
   - `setgroups`: 设置当前进程所属的组 ID 列表。

4. **内存管理:**
   - `mmap2`: 将文件或设备映射到内存 (支持指定页偏移)。
   - `mmap`: `mmap2` 的包装，确保偏移量是页大小的倍数。

5. **资源限制:**
   - `Getrlimit`: 获取进程的资源限制。

6. **文件描述符多路复用:**
   - `EpollWait`: 等待 epoll 事件发生。
   - `Select`: 等待一组文件描述符上的事件。

7. **低级系统控制:**
   - `Ioperm`: 设置进程的 I/O 端口权限。
   - `Iopl`: 设置进程的 I/O 特权级别。
   - `Pause`: 暂停进程执行，直到收到信号。

8. **文件指针操作:**
   - `Seek`: 修改文件偏移量。

9. **Socket 相关:**
   - `accept4`: 接受一个连接。
   - `getsockname`: 获取与套接字关联的本地地址。
   - `getpeername`: 获取与套接字连接的远程地址。
   - `socketpair`: 创建一对已连接的套接字。
   - `bind`: 将套接字绑定到本地地址。
   - `connect`: 连接到远程地址。
   - `socket`: 创建一个套接字。
   - `getsockopt`: 获取套接字选项的值。
   - `setsockopt`: 设置套接字选项的值。
   - `recvfrom`: 从套接字接收数据。
   - `sendto`: 向指定地址发送数据。
   - `recvmsg`: 从套接字接收消息。
   - `sendmsg`: 向套接字发送消息。
   - `Listen`: 监听连接。
   - `Shutdown`: 关闭套接字的部分或全部连接。

10. **文件系统统计:**
    - `Fstatfs`: 获取与文件描述符关联的文件系统的统计信息。
    - `Statfs`: 获取指定路径的文件系统的统计信息。

11. **结构体辅助方法:**
    - `(*PtraceRegs) PC()`: 获取 `PtraceRegs` 结构中的程序计数器 (PC)。
    - `(*PtraceRegs) SetPC(pc uint64)`: 设置 `PtraceRegs` 结构中的程序计数器。
    - `(*Iovec) SetLen(length int)`: 设置 `Iovec` 结构中的长度。
    - `(*Msghdr) SetControllen(length int)`: 设置 `Msghdr` 结构中的控制消息长度。
    - `(*Msghdr) SetIovlen(length int)`: 设置 `Msghdr` 结构中的 I/O 向量长度。
    - `(*Cmsghdr) SetLen(length int)`: 设置 `Cmsghdr` 结构中的长度。
    - `(*RawSockaddrNFCLLCP) SetServiceNameLen(length int)`: 设置 `RawSockaddrNFCLLCP` 结构中的服务名称长度。

**Go 语言功能实现示例:**

这个文件中的函数主要是对 Linux 系统调用的直接封装，用于在 Go 语言中调用这些底层操作。

**示例 1: 使用 `Fstat` 获取文件信息**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	fileInfo, err := os.Stat("test.txt")
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}

	fd, err := syscall.Open("test.txt", syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	var stat syscall.Stat_t
	err = syscall.Fstat(fd, &stat)
	if err != nil {
		fmt.Println("Error getting file stat:", err)
		return
	}

	fmt.Println("File size from os.Stat:", fileInfo.Size())
	fmt.Println("File size from syscall.Fstat:", stat.Size)

	// 假设输入: 存在一个名为 test.txt 的文件，大小为 1024 字节。
	// 输出:
	// File size from os.Stat: 1024
	// File size from syscall.Fstat: 1024
}
```

**示例 2: 使用 `mmap` 将文件映射到内存**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}

	pageSize := os.Getpagesize()
	mmapLength := (fileInfo.Size() + int64(pageSize) - 1) / int64(pageSize) * int64(pageSize) // 向上取整到页大小的倍数

	data, err := syscall.Mmap(int(file.Fd()), 0, int(mmapLength), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		fmt.Println("Error mmapping file:", err)
		return
	}
	defer syscall.Munmap(data)

	// 读取映射的内存
	content := (*[0xffffffff]byte)(unsafe.Pointer(&data[0]))[:fileInfo.Size()]
	fmt.Println("File content (first 10 bytes):", string(content[:10]))

	// 假设输入: test.txt 文件包含 "Hello World!"
	// 输出: File content (first 10 bytes): Hello Worl
}
```

**代码推理:**

例如 `setTimespec` 和 `setTimeval` 函数，它们接收 `int64` 类型的秒和纳秒/微秒，并将其转换为 `int32` 类型存储到 `Timespec` 和 `Timeval` 结构体中。这可能是因为底层的系统调用接口使用的是 32 位整数来表示时间值。

**假设输入:** `sec = 1678886400`, `nsec = 500`
**输出:** `Timespec{Sec: 1678886400, Nsec: 500}`

**假设输入:** `sec = 1678886400`, `usec = 1000`
**输出:** `Timeval{Sec: 1678886400, Usec: 1000}`

**命令行参数处理:**

这个文件本身不直接处理命令行参数。它提供的功能是更底层的系统调用接口，上层 Go 代码可以使用这些接口来实现需要处理命令行参数的功能。例如，`os` 包中的函数会使用这里的系统调用来完成文件操作，而 `os` 包可能会解析命令行参数来确定要操作的文件路径等。

**使用者易犯错的点:**

1. **不正确的类型转换:**  在与系统调用交互时，需要非常注意数据类型的匹配。例如，将 64 位的值错误地转换为 32 位可能会导致数据丢失或溢出。在 `setTimespec` 和 `setTimeval` 中，虽然输入是 `int64`，但最终存储的是 `int32`，如果传入的值超出 `int32` 的范围，就会发生截断。

   ```go
   ts := syscall.SetTimespec(10000000000, 500) // 100亿秒远超 int32 的范围
   fmt.Println(ts.Sec) // 输出会是一个意想不到的小数字
   ```

2. **错误的参数传递:** 系统调用的参数通常是指针，需要确保传递的指针指向有效的内存地址，并且内存布局与系统调用期望的结构体一致。

3. **忽略错误返回值:**  系统调用通常会返回错误码。必须检查这些错误码，并进行适当的处理，否则可能会导致程序行为异常。

4. **不了解底层的限制:**  例如，`mmap` 的偏移量必须是页大小的倍数，如果不满足这个条件，系统调用会返回错误。

5. **混淆同步和异步操作:** 一些系统调用是阻塞的，而另一些可以通过特定的标志设置为非阻塞的。混淆这些模式可能导致程序hang住或无法及时响应。

总而言之，这个文件是 Go 语言与 Linux 内核交互的桥梁，它提供了对底层系统调用的直接访问。使用这些函数需要对操作系统原理和系统调用有深入的理解，并小心处理各种细节，以避免潜在的错误。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux_386.go的go语言实现的一部分， 请列举一下它的功能, 　
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

//go:build 386 && linux

package unix

import (
	"unsafe"
)

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: int32(sec), Nsec: int32(nsec)}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: int32(sec), Usec: int32(usec)}
}

// 64-bit file system and 32-bit uid calls
// (386 default is 32-bit file system and 16-bit uid).
//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error)
//sys	Fadvise(fd int, offset int64, length int64, advice int) (err error) = SYS_FADVISE64_64
//sys	Fchown(fd int, uid int, gid int) (err error) = SYS_FCHOWN32
//sys	Fstat(fd int, stat *Stat_t) (err error) = SYS_FSTAT64
//sys	Fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) = SYS_FSTATAT64
//sys	Ftruncate(fd int, length int64) (err error) = SYS_FTRUNCATE64
//sysnb	Getegid() (egid int) = SYS_GETEGID32
//sysnb	Geteuid() (euid int) = SYS_GETEUID32
//sysnb	Getgid() (gid int) = SYS_GETGID32
//sysnb	Getuid() (uid int) = SYS_GETUID32
//sys	Ioperm(from int, num int, on int) (err error)
//sys	Iopl(level int) (err error)
//sys	Lchown(path string, uid int, gid int) (err error) = SYS_LCHOWN32
//sys	Lstat(path string, stat *Stat_t) (err error) = SYS_LSTAT64
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = SYS_PREAD64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = SYS_PWRITE64
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) = SYS_SENDFILE64
//sys	setfsgid(gid int) (prev int, err error) = SYS_SETFSGID32
//sys	setfsuid(uid int) (prev int, err error) = SYS_SETFSUID32
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int, err error)
//sys	Stat(path string, stat *Stat_t) (err error) = SYS_STAT64
//sys	SyncFileRange(fd int, off int64, n int64, flags int) (err error)
//sys	Truncate(path string, length int64) (err error) = SYS_TRUNCATE64
//sys	Ustat(dev int, ubuf *Ustat_t) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error) = SYS_GETGROUPS32
//sysnb	setgroups(n int, list *_Gid_t) (err error) = SYS_SETGROUPS32
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error) = SYS__NEWSELECT

//sys	mmap2(addr uintptr, length uintptr, prot int, flags int, fd int, pageOffset uintptr) (xaddr uintptr, err error)
//sys	Pause() (err error)

func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error) {
	page := uintptr(offset / 4096)
	if offset != int64(page)*4096 {
		return 0, EINVAL
	}
	return mmap2(addr, length, prot, flags, fd, page)
}

type rlimit32 struct {
	Cur uint32
	Max uint32
}

//sysnb	getrlimit(resource int, rlim *rlimit32) (err error) = SYS_GETRLIMIT

const rlimInf32 = ^uint32(0)
const rlimInf64 = ^uint64(0)

func Getrlimit(resource int, rlim *Rlimit) (err error) {
	err = Prlimit(0, resource, nil, rlim)
	if err != ENOSYS {
		return err
	}

	rl := rlimit32{}
	err = getrlimit(resource, &rl)
	if err != nil {
		return
	}

	if rl.Cur == rlimInf32 {
		rlim.Cur = rlimInf64
	} else {
		rlim.Cur = uint64(rl.Cur)
	}

	if rl.Max == rlimInf32 {
		rlim.Max = rlimInf64
	} else {
		rlim.Max = uint64(rl.Max)
	}
	return
}

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	newoffset, errno := seek(fd, offset, whence)
	if errno != 0 {
		return 0, errno
	}
	return newoffset, nil
}

//sys	futimesat(dirfd int, path string, times *[2]Timeval) (err error)
//sysnb	Gettimeofday(tv *Timeval) (err error)
//sysnb	Time(t *Time_t) (tt Time_t, err error)
//sys	Utime(path string, buf *Utimbuf) (err error)
//sys	utimes(path string, times *[2]Timeval) (err error)

// On x86 Linux, all the socket calls go through an extra indirection,
// I think because the 5-register system call interface can't handle
// the 6-argument calls like sendto and recvfrom. Instead the
// arguments to the underlying system call are the number below
// and a pointer to an array of uintptr. We hide the pointer in the
// socketcall assembly to avoid allocation on every system call.

const (
	// see linux/net.h
	_SOCKET      = 1
	_BIND        = 2
	_CONNECT     = 3
	_LISTEN      = 4
	_ACCEPT      = 5
	_GETSOCKNAME = 6
	_GETPEERNAME = 7
	_SOCKETPAIR  = 8
	_SEND        = 9
	_RECV        = 10
	_SENDTO      = 11
	_RECVFROM    = 12
	_SHUTDOWN    = 13
	_SETSOCKOPT  = 14
	_GETSOCKOPT  = 15
	_SENDMSG     = 16
	_RECVMSG     = 17
	_ACCEPT4     = 18
	_RECVMMSG    = 19
	_SENDMMSG    = 20
)

func accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error) {
	fd, e := socketcall(_ACCEPT4, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func getsockname(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, e := rawsocketcall(_GETSOCKNAME, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func getpeername(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, e := rawsocketcall(_GETPEERNAME, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func socketpair(domain int, typ int, flags int, fd *[2]int32) (err error) {
	_, e := rawsocketcall(_SOCKETPAIR, uintptr(domain), uintptr(typ), uintptr(flags), uintptr(unsafe.Pointer(fd)), 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, e := socketcall(_BIND, uintptr(s), uintptr(addr), uintptr(addrlen), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, e := socketcall(_CONNECT, uintptr(s), uintptr(addr), uintptr(addrlen), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func socket(domain int, typ int, proto int) (fd int, err error) {
	fd, e := rawsocketcall(_SOCKET, uintptr(domain), uintptr(typ), uintptr(proto), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error) {
	_, e := socketcall(_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e != 0 {
		err = e
	}
	return
}

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, e := socketcall(_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), vallen, 0)
	if e != 0 {
		err = e
	}
	return
}

func recvfrom(s int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error) {
	var base uintptr
	if len(p) > 0 {
		base = uintptr(unsafe.Pointer(&p[0]))
	}
	n, e := socketcall(_RECVFROM, uintptr(s), base, uintptr(len(p)), uintptr(flags), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)))
	if e != 0 {
		err = e
	}
	return
}

func sendto(s int, p []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error) {
	var base uintptr
	if len(p) > 0 {
		base = uintptr(unsafe.Pointer(&p[0]))
	}
	_, e := socketcall(_SENDTO, uintptr(s), base, uintptr(len(p)), uintptr(flags), uintptr(to), uintptr(addrlen))
	if e != 0 {
		err = e
	}
	return
}

func recvmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	n, e := socketcall(_RECVMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func sendmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	n, e := socketcall(_SENDMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func Listen(s int, n int) (err error) {
	_, e := socketcall(_LISTEN, uintptr(s), uintptr(n), 0, 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func Shutdown(s, how int) (err error) {
	_, e := socketcall(_SHUTDOWN, uintptr(s), uintptr(how), 0, 0, 0, 0)
	if e != 0 {
		err = e
	}
	return
}

func Fstatfs(fd int, buf *Statfs_t) (err error) {
	_, _, e := Syscall(SYS_FSTATFS64, uintptr(fd), unsafe.Sizeof(*buf), uintptr(unsafe.Pointer(buf)))
	if e != 0 {
		err = e
	}
	return
}

func Statfs(path string, buf *Statfs_t) (err error) {
	pathp, err := BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, e := Syscall(SYS_STATFS64, uintptr(unsafe.Pointer(pathp)), unsafe.Sizeof(*buf), uintptr(unsafe.Pointer(buf)))
	if e != 0 {
		err = e
	}
	return
}

func (r *PtraceRegs) PC() uint64 { return uint64(uint32(r.Eip)) }

func (r *PtraceRegs) SetPC(pc uint64) { r.Eip = int32(pc) }

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint32(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint32(length)
}

func (msghdr *Msghdr) SetIovlen(length int) {
	msghdr.Iovlen = uint32(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint32(length)
}

func (rsa *RawSockaddrNFCLLCP) SetServiceNameLen(length int) {
	rsa.Service_name_len = uint32(length)
}
```