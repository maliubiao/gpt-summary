Response:
Let's break down the thought process for answering the request about the Go syscall file.

**1. Understanding the Request:**

The core request is to analyze a specific Go file (`syscall_linux_s390x.go`) and explain its functionality. The request also asks for specific elaborations:

* **Function Listing:** Enumerate the functions provided.
* **Go Feature Inference:**  Deduce which high-level Go features these syscalls support.
* **Code Examples:** Illustrate usage with Go code, including assumptions about inputs and outputs.
* **Command-line Arguments:** Explain how command-line arguments might be involved (if applicable).
* **Common Mistakes:** Identify potential pitfalls for users.
* **Language:**  Answer in Chinese.

**2. Initial Analysis of the Code:**

The file is located within the `syscall` package and targets the `linux/s390x` architecture. This immediately tells us it's a low-level interface to the Linux kernel for IBM System z (s390x) systems. The naming convention of the functions (e.g., `Dup2`, `EpollWait`, `Stat`) strongly suggests they are direct wrappers around corresponding Linux system calls.

**3. Function Categorization and Feature Inference:**

I'd iterate through the defined functions and group them based on their apparent purpose. This helps in deducing the higher-level Go features they enable:

* **File I/O:**  `Dup2`, `Fchown`, `Fstat`, `fstatat`, `Fstatfs`, `Ftruncate`, `Lchown`, `Lstat`, `pread`, `pwrite`, `Renameat`, `Seek`, `sendfile`, `SyncFileRange`, `Truncate`, `Ustat`, `futimesat`, `Utime`, `utimes`. These clearly relate to file manipulation and information retrieval. **Inferred Go Features:** File operations (opening, reading, writing, metadata access, etc.).
* **Process Management:** `Pause`. This is a basic process control mechanism. **Inferred Go Features:**  Potentially related to signal handling or basic synchronization.
* **User and Group IDs:** `Getegid`, `Geteuid`, `Getgid`, `Getuid`, `Setfsgid`, `Setfsuid`, `getgroups`, `_SYS_setgroups`. These deal with user and group identity. **Inferred Go Features:**  User/group management, permissions.
* **Time:** `Gettimeofday`, `Time`. Self-explanatory. **Inferred Go Features:** Time management.
* **Memory Management:** `mmap`. Direct memory mapping. **Inferred Go Features:**  Advanced memory control, potentially for shared memory or device access.
* **Networking:** `accept4`, `getsockname`, `getpeername`, `socketpair`, `bind`, `connect`, `socket`, `getsockopt`, `setsockopt`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `Listen`, `Shutdown`, the constants `_SOCKET`, `_BIND`, etc., and the `socketcall`/`rawsocketcall` functions. This is a substantial section dedicated to networking. **Inferred Go Features:** Socket programming (TCP, UDP, etc.).
* **Polling/Events:** `EpollWait`, `InotifyInit`, `Select`. These handle event notification. **Inferred Go Features:**  Asynchronous I/O, event-driven programming.
* **System Calls:** The `//sys` directives themselves indicate direct system call invocation. The constants like `_SYS_clone3`, `_SYS_faccessat2`, `_SYS_fchmodat2`  confirm this.

**4. Code Example Construction:**

For each category, I would choose a representative function and create a basic Go code snippet. Crucially, the examples need to be:

* **Clear and Concise:** Easy to understand.
* **Illustrative:** Demonstrate the function's core purpose.
* **With Assumptions:** Explicitly state the assumed inputs and expected outputs. This is vital for demonstrating the function's behavior in a testable way. For instance, when showing `Stat`, assume a file exists and show how the `Stat_t` struct is populated.

**5. Command-line Arguments:**

I considered if any of the presented functions directly process command-line arguments. The syscalls themselves don't inherently do this. Command-line arguments are usually handled at a higher level by the `os` package in Go. Therefore, I concluded that direct command-line argument handling wasn't a primary function of *this specific file*.

**6. Identifying Common Mistakes:**

This requires thinking about potential errors developers might make when using these low-level functions:

* **Incorrect Error Handling:**  Forgetting to check the `err` return value is a classic mistake.
* **Pointer Usage:** Incorrectly using `unsafe.Pointer` can lead to crashes or memory corruption. This is particularly relevant for the socket-related functions.
* **Buffer Sizes:** Not allocating enough space for buffers when using functions like `recvfrom` or `getgroups`.
* **Understanding System Call Semantics:**  Not fully grasping the nuances of the underlying system calls can lead to unexpected behavior. For example, the different file descriptor types in `fstatat`.

**7. Structuring the Answer in Chinese:**

Finally, I would organize the information logically and translate it into clear and accurate Chinese. This involves:

* **Introduction:** Briefly stating the file's purpose.
* **Function Listing:** Providing a straightforward list.
* **Feature Deduction:** Explaining the higher-level Go features enabled by the syscalls.
* **Code Examples:** Presenting the Go code snippets with assumptions and outputs.
* **Command-line Arguments:** Addressing this point (or lack thereof).
* **Common Mistakes:** Listing potential pitfalls.
* **Conclusion:**  A brief summary.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe I should explain the `//sys` directive in detail.
* **Correction:** While important, focusing on the *functionality* is more aligned with the prompt. I can briefly mention that `//sys` links to the assembly.
* **Initial Thought:** Should I explain all the socket constants?
* **Correction:** Listing them is sufficient; explaining each one would make the answer too long. Focus on the general networking capability.
* **Initial Thought:** How detailed should the code examples be?
* **Correction:** Keep them short and focused on demonstrating the syscall's purpose. Overly complex examples will be confusing.

By following this structured thought process, including categorizing, inferring, exemplifying, and considering potential errors, I can construct a comprehensive and accurate answer to the request. The key is to move from the low-level details of the code to the higher-level Go concepts it enables.
这是一个Go语言的源代码文件，路径为 `go/src/syscall/syscall_linux_s390x.go`。 从文件名和路径可以推断，这个文件是Go语言标准库中 `syscall` 包的一部分，专门为 Linux 操作系统在 s390x (IBM System z) 架构上提供系统调用接口。

**功能列表:**

这个文件定义了许多Go函数，这些函数是对 Linux 内核提供的系统调用的封装。 它们的功能包括：

* **文件和目录操作:**
    * `Dup2`: 复制文件描述符。
    * `Fchown`: 修改文件描述符对应文件的所有者。
    * `Fstat`: 获取文件描述符对应文件的状态信息。
    * `fstatat`: 获取相对于目录文件描述符的文件的状态信息。
    * `Fstatfs`: 获取文件描述符对应文件系统的信息。
    * `Ftruncate`: 截断文件描述符对应文件到指定长度。
    * `Lchown`: 修改符号链接的所有者。
    * `Lstat`: 获取符号链接的状态信息。
    * `Renameat`: 原子地重命名文件或目录。
    * `Seek`: 改变文件描述符的读写偏移量。
    * `sendfile`: 在两个文件描述符之间高效地传输数据。
    * `SyncFileRange`: 将文件的一部分强制同步到磁盘。
    * `Truncate`: 截断文件到指定长度。
    * `Ustat`: 返回文件系统的状态信息（已过时）。
    * `futimesat`: 修改相对于目录文件描述符的文件的访问和修改时间。
    * `Utime`: 修改文件的访问和修改时间。
    * `utimes`: 修改文件的访问和修改时间，精度更高。
* **进程控制:**
    * `Pause`: 暂停进程执行直到收到信号。
* **用户和组管理:**
    * `Getegid`: 获取有效组ID。
    * `Geteuid`: 获取有效用户ID。
    * `Getgid`: 获取组ID。
    * `Getuid`: 获取用户ID。
    * `Setfsgid`: 设置用于文件系统访问的组ID。
    * `Setfsuid`: 设置用于文件系统访问的用户ID。
    * `getgroups`: 获取当前进程所属的所有组ID。
    * `_SYS_setgroups`: 设置当前进程的附加组ID (常量，在其他地方定义)。
* **时间:**
    * `Gettimeofday`: 获取当前时间。
    * `Time`: 获取当前时间 (内部调用 `Gettimeofday`)。
* **内存管理:**
    * `mmap`: 将文件或设备映射到内存。
* **网络:**
    * `EpollWait`: 等待 epoll 事件。
    * `InotifyInit`: 初始化 inotify 文件系统事件监控机制。
    * `Select`:  等待多个文件描述符上的事件。
    * `accept4`: 接受一个socket连接，并可以设置一些标志。
    * `getsockname`: 获取socket的本地地址。
    * `getpeername`: 获取连接的socket的对端地址。
    * `socketpair`: 创建一对已连接的、无名的socket。
    * `bind`: 将socket绑定到特定的地址和端口。
    * `connect`: 连接到指定的socket地址。
    * `socket`: 创建一个socket。
    * `getsockopt`: 获取socket选项的值。
    * `setsockopt`: 设置socket选项的值。
    * `recvfrom`: 从socket接收数据。
    * `sendto`: 发送数据到指定的socket地址。
    * `recvmsg`: 从socket接收消息。
    * `sendmsg`: 发送消息到socket。
    * `Listen`: 监听socket连接。
    * `Shutdown`: 关闭socket连接的读或写端。
    * `socketcall`:  s390x 特定的 socket 系统调用入口点。
    * `rawsocketcall`: s390x 特定的原始 socket 系统调用入口点。
    * 常量 `_SOCKET`, `_BIND`, `_CONNECT`, 等等：定义了 `socketcall` 中 `call` 参数的取值，用于区分不同的 socket 系统调用。
* **其他:**
    * `pread`: 从指定偏移量读取文件描述符。
    * `pwrite`: 从指定偏移量写入文件描述符。
    * `Splice`: 在两个文件描述符之间移动数据，零拷贝。
    * `Ustat_t`, `Timeval`, `Timespec`, `Utimbuf`, `Stat_t`, `Statfs_t`, `_Gid_t`, `EpollEvent`, `FdSet`, `PtraceRegs`, `Iovec`, `Msghdr`, `Cmsghdr`, `RawSockaddrAny`, `_Socklen`, `Time_t`: 定义了与系统调用相关的结构体类型。
    * `setTimespec`, `setTimeval`: 辅助函数，用于创建 `Timespec` 和 `Timeval` 结构体。

**Go语言功能实现推理与代码示例:**

这个文件主要实现了 Go 语言中 `syscall` 包提供的系统调用接口。 `syscall` 包允许 Go 程序直接调用操作系统底层的系统调用，这对于需要高性能或者访问特定操作系统功能的场景非常有用。

**1. 文件状态获取 (以 `Stat` 为例):**

这个文件中的 `Stat` 函数封装了 Linux 的 `stat` 系统调用，用于获取文件的元数据信息，如大小、权限、修改时间等。

```go
package main

import (
	"fmt"
	"syscall"
	"time"
)

func main() {
	filename := "test.txt" // 假设存在一个名为 test.txt 的文件
	var stat syscall.Stat_t

	err := syscall.Stat(filename, &stat)
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}

	fmt.Println("File size:", stat.Size)
	fmt.Println("File mode:", stat.Mode)
	fmt.Println("Last modification time:", time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec))
}

// 假设输入：当前目录下存在一个名为 test.txt 的文件，内容随意。
// 假设输出：
// File size: <test.txt 的文件大小>
// File mode: <test.txt 的文件权限，例如 -rw-r--r-->
// Last modification time: <test.txt 的最后修改时间>
```

**2. 创建和监听 Socket (以 `socket`, `bind`, `Listen` 为例):**

这些函数封装了创建网络连接的基础系统调用。

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	// 创建一个 TCP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 绑定到地址和端口
	addr := syscall.SockaddrInet4{Port: 8080}
	copy(addr.Addr[:], net.ParseIP("0.0.0.0").To4())
	err = syscall.Bind(fd, &addr)
	if err != nil {
		fmt.Println("Error binding socket:", err)
		return
	}

	// 开始监听连接
	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		fmt.Println("Error listening on socket:", err)
		return
	}

	fmt.Println("Listening on port 8080...")

	// 注意：这里只是演示了 socket 的创建、绑定和监听，实际的网络编程还需要处理连接。
}

// 假设输入： 无特定的输入，只是执行代码。
// 假设输出： 程序成功执行，并在 8080 端口监听连接。 （不会有标准输出，除非发生错误）
```

**涉及代码推理:**

* **`Time` 函数:**  `Time` 函数内部调用了 `Gettimeofday` 系统调用来获取当前时间，并将结果转换为 Go 的 `time.Time` 类型。 这展示了如何利用底层的系统调用来提供更高级别的抽象。
* **Socket 调用 (`socketcall`, `rawsocketcall`):** 在 s390x 架构上，许多 socket 相关的系统调用通过 `socketcall` 或 `rawsocketcall` 函数进行间接调用。 这些函数接收一个表示具体 socket 操作的数字 (`call`) 和一系列参数。 例如，创建 socket 时，`call` 的值会是 `_SOCKET`。

**命令行参数的具体处理:**

在这个文件中，并没有直接处理命令行参数的代码。 命令行参数的处理通常在 `main` 函数中使用 `os.Args` 来完成。 `syscall` 包提供的功能是更底层的操作，它们可以被用来实现处理命令行参数的更高级功能，例如，可以使用文件操作相关的系统调用来读取配置文件，而配置文件的路径可能来源于命令行参数。

**使用者易犯错的点:**

* **错误处理:** 调用系统调用时，务必检查返回的 `error` 值。 系统调用失败时，`error` 会包含错误信息。 忽略错误可能导致程序行为异常或崩溃。

   ```go
   fd, err := syscall.Open("nonexistent.txt", syscall.O_RDONLY, 0)
   if err != nil {
       fmt.Println("Error opening file:", err) // 正确处理错误
       // ... 采取相应的错误处理措施
   }
   defer syscall.Close(fd) // 即使 Open 失败，这里也需要注意
   ```

* **平台差异:**  `syscall` 包中的某些函数和常量在不同的操作系统和架构上可能有所不同。  `syscall_linux_s390x.go` 中的代码是特定于 Linux 和 s390x 架构的。  如果你的代码需要在不同的平台上运行，你需要使用条件编译或者其他跨平台的方式来处理。

* **不安全的指针操作:**  一些系统调用需要传递指针参数。 在 Go 中使用 `unsafe.Pointer` 需要非常小心，以避免内存安全问题。

* **对底层机制的理解不足:**  直接使用系统调用需要对操作系统底层的机制有较好的理解，例如文件描述符、信号、网络协议等。  不理解这些概念可能会导致误用。

总而言之，`go/src/syscall/syscall_linux_s390x.go` 文件是 Go 语言在 Linux s390x 架构上与操作系统内核交互的桥梁，它提供了对大量底层系统调用的封装，使得 Go 程序能够执行各种操作系统级别的任务。  使用这个包需要谨慎，并充分理解相关的操作系统概念和错误处理机制。

Prompt: 
```
这是路径为go/src/syscall/syscall_linux_s390x.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package syscall

import "unsafe"

const (
	_SYS_setgroups  = SYS_SETGROUPS
	_SYS_clone3     = 435
	_SYS_faccessat2 = 439
	_SYS_fchmodat2  = 452
)

//sys	Dup2(oldfd int, newfd int) (err error)
//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fstat(fd int, stat *Stat_t) (err error)
//sys	fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) = SYS_NEWFSTATAT
//sys	Fstatfs(fd int, buf *Statfs_t) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (euid int)
//sysnb	Getgid() (gid int)
//sysnb	Getuid() (uid int)
//sysnb	InotifyInit() (fd int, err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Lstat(path string, stat *Stat_t) (err error)
//sys	Pause() (err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = SYS_PREAD64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = SYS_PWRITE64
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)
//sys	Seek(fd int, offset int64, whence int) (off int64, err error) = SYS_LSEEK
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error)
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error)
//sys	Setfsgid(gid int) (err error)
//sys	Setfsuid(uid int) (err error)
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)
//sys	Stat(path string, stat *Stat_t) (err error)
//sys	Statfs(path string, buf *Statfs_t) (err error)
//sys	SyncFileRange(fd int, off int64, n int64, flags int) (err error) = SYS_SYNC_FILE_RANGE
//sys	Truncate(path string, length int64) (err error)
//sys	Ustat(dev int, ubuf *Ustat_t) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)

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
// The arguments to the underlying system call are the number below
// and a pointer to an array of uintptr.  We hide the pointer in the
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

func socketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (n int, err Errno)
func rawsocketcall(call int, a0, a1, a2, a3, a4, a5 uintptr) (n int, err Errno)

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

func (r *PtraceRegs) PC() uint64 { return r.Psw.Addr }

func (r *PtraceRegs) SetPC(pc uint64) { r.Psw.Addr = pc }

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint64(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint64(length)
}

"""



```