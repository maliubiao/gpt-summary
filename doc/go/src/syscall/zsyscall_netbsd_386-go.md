Response:
Let's break down the thought process for analyzing this Go syscall file.

1. **Understanding the Context:** The first line is crucial: `// mksyscall.pl -l32 -netbsd -tags netbsd,386 syscall_bsd.go syscall_netbsd.go syscall_netbsd_386.go`. This immediately tells us:
    * **Tool:** `mksyscall.pl` - This is a Perl script used by Go to generate syscall bindings. It's important because it explains why the code says "DO NOT EDIT".
    * **Architecture:** `-l32` means 32-bit architecture.
    * **Operating System:** `-netbsd` specifies NetBSD.
    * **Tags:** `netbsd,386` are build tags, meaning this file is only included when building for NetBSD on a 386 architecture.
    * **Input Files:** `syscall_bsd.go`, `syscall_netbsd.go` are likely input files for the `mksyscall.pl` script. This suggests a layered approach to syscall definitions.

2. **Core Functionality Identification:** Scan through the function names. Many of them are instantly recognizable as standard POSIX system calls: `getgroups`, `setgroups`, `wait4`, `accept`, `bind`, `connect`, `socket`, `getsockopt`, `setsockopt`, `getpeername`, `getsockname`, `shutdown`, `socketpair`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `kevent`, `utimes`, `futimes`, `fcntl`, `ioctl`, `pipe2`, `paccept`, `getdents`, `access`, `adjtime`, `chdir`, `chflags`, `chmod`, `chown`, `chroot`, `close`, `dup`, `dup2`, `fchdir`, `fchflags`, `fchmod`, `fchown`, `flock`, `fpathconf`, `fstat`, `fsync`, `ftruncate`, `getegid`, `geteuid`, `getgid`, `getpgid`, `getpgrp`, `getpid`, `getppid`, `getpriority`, `getrlimit`, `getrusage`, `getsid`, `gettimeofday`, `getuid`, `issetugid`, `kill`, `kqueue`, `lchown`, `link`, `listen`, `lstat`, `mkdir`, `mkfifo`, `mknod`, `nanosleep`, `open`, `pathconf`, `pread`, `pwrite`, `read`, `readlink`, `rename`, `revoke`, `rmdir`, `seek`, `select`, `setegid`, `seteuid`, `setgid`, `setpgid`, `setpriority`, `setregid`, `setreuid`, `setrlimit`, `setsid`, `settimeofday`, `setuid`, `stat`, `symlink`, `sync`, `truncate`, `umask`, `unlink`, `unmount`, `write`, `mmap`, `munmap`, `readlen`, `utimensat`, `getcwd`, `sysctl`.

3. **Categorization of Functionality:**  Group the identified syscalls into logical categories:
    * **Process Management:** `getpid`, `getppid`, `getpgid`, `setpgid`, `getsid`, `setsid`, `kill`, `wait4`, `getpriority`, `setpriority`, `getrlimit`, `setrlimit`, `getrusage`
    * **File System Operations:** `open`, `close`, `read`, `write`, `pread`, `pwrite`, `lseek` (as `Seek`), `stat`, `fstat`, `lstat`, `mkdir`, `rmdir`, `link`, `unlink`, `symlink`, `readlink`, `rename`, `chmod`, `fchmod`, `chown`, `fchown`, `lchown`, `truncate`, `ftruncate`, `access`, `chdir`, `fchdir`, `chroot`, `mkfifo`, `mknod`, `utimes`, `futimes`, `pathconf`, `fpathconf`, `revoke`, `sync`, `unmount`, `getdents`, `getcwd`, `utimensat`
    * **Networking:** `socket`, `bind`, `listen`, `accept`, `connect`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `getsockopt`, `setsockopt`, `getpeername`, `getsockname`, `shutdown`, `socketpair`, `paccept`
    * **User and Group Management:** `getuid`, `geteuid`, `getgid`, `getegid`, `setuid`, `seteuid`, `setgid`, `setegid`, `getgroups`, `setgroups`, `issetugid`, `setregid`, `setreuid`
    * **Memory Management:** `mmap`, `munmap`
    * **Time and Scheduling:** `nanosleep`, `gettimeofday`, `settimeofday`, `adjtime`
    * **Inter-Process Communication (IPC) and Signals:** `pipe2`, `select`, `kevent` (similar to `epoll` or `poll`),  The `sigset` in `paccept` also hints at signal handling.
    * **File Locking:** `flock`
    * **File Descriptor Manipulation:** `dup`, `dup2`, `fcntl`
    * **System Information:** `sysctl`
    * **Permissions:** `umask`, `chflags`, `fchflags`
    * **Miscellaneous:** `ioctl`

4. **Inferring Go Functionality:**  Based on the identified syscalls, we can infer the Go language features they implement:
    * **File I/O:** `os` package functions like `Open`, `Create`, `Read`, `Write`, `Stat`, `Chmod`, `Chown`, `Remove`, `Rename`, `Mkdir`, etc.
    * **Networking:** `net` package functions like `Dial`, `Listen`, `Accept`, `Read`, `Write`, `SetDeadline`, `ListenConfig.Listen`, socket options.
    * **Process Control:** `os/exec` package for running commands, `syscall` package's process-related functions, `os.ForkExec` (though not directly visible here).
    * **User and Group Management:** Functions in the `os/user` and `syscall` packages.
    * **Memory Mapping:** `syscall.Mmap` and `syscall.Munmap`.
    * **Time:** `time` package functions like `Sleep`, getting and setting system time.
    * **Inter-Process Communication:** `os.Pipe`, network sockets.
    * **System Information:** Accessing kernel parameters through `syscall.Sysctl`.

5. **Code Examples and Reasoning:** For each inferred Go feature, provide a concise example using the corresponding `syscall` function. The key is to demonstrate the connection between the high-level Go API and the low-level syscall.

    * **Example: Getting the process ID:** Show how `syscall.Getpid()` is used. Input and output are straightforward.
    * **Example: Opening a file:** Illustrate the use of `syscall.Open()`, highlighting the flags and permissions. Provide a scenario with an input path and expected output (file descriptor or error).
    * **Example: Creating a socket and binding:** Demonstrate `syscall.Socket()` and `syscall.Bind()`, showing how to construct the socket address.

6. **Command-Line Argument Processing:**  While this specific file doesn't directly handle command-line arguments,  think about *how* these syscalls might be used in programs that *do* process arguments. For instance:

    *  A program taking a file path as an argument would likely use `syscall.Open`, `syscall.Stat`, etc.
    *  A network server taking a port number would use `syscall.Socket`, `syscall.Bind`.
    *  A process monitoring tool taking a PID would use `syscall.Kill`, `syscall.Getpgid`.

7. **Common Mistakes:** Consider potential pitfalls when using these low-level syscalls directly (though usually, developers use the higher-level Go packages):

    * **Incorrectly using pointers:**  `unsafe.Pointer` requires careful handling.
    * **Mismatched data types:**  Go's type system needs to align with the system call's expectations.
    * **Ignoring error handling:** Syscalls return errors that must be checked.
    * **Security vulnerabilities:** Incorrect permissions or handling of file paths can lead to issues.

8. **Review and Refine:**  Read through the generated answer to ensure clarity, accuracy, and completeness. Make sure the examples are correct and easy to understand. Ensure the categories of functionality are well-defined and cover the majority of the syscalls.

This systematic approach helps in dissecting the code, understanding its purpose, and relating it to higher-level Go concepts. The initial understanding of the code generation process is key to avoiding misinterpretations.
这个go语言文件 `go/src/syscall/zsyscall_netbsd_386.go` 是Go标准库中 `syscall` 包的一部分，它为运行在 **NetBSD 386** 架构上的Go程序提供了与操作系统内核进行交互的底层接口。它本质上是对NetBSD内核提供的系统调用（system calls）的Go语言封装。

**主要功能：**

该文件中的每一个函数都对应着一个NetBSD内核的系统调用。这些函数允许Go程序执行各种操作系统级别的操作，例如：

1. **进程管理:**
   - `getgroups`, `setgroups`: 获取和设置进程的附属组ID列表。
   - `wait4`: 等待子进程状态改变。
   - `getpid`, `getppid`, `getpgid`, `setpgid`, `getsid`, `setsid`: 获取和设置进程、父进程、进程组ID和会话ID。
   - `kill`: 向进程发送信号。
   - `getpriority`, `setpriority`: 获取和设置进程优先级。
   - `getrlimit`, `setrlimit`: 获取和设置进程资源限制。
   - `getrusage`: 获取进程及其子进程的资源使用情况。

2. **文件和目录操作:**
   - `open`, `close`: 打开和关闭文件描述符。
   - `read`, `write`: 从/向文件描述符读取和写入数据。
   - `pread`, `pwrite`: 在指定偏移量处读取和写入文件。
   - `lseek` (封装为 `Seek`): 改变文件偏移量。
   - `stat`, `fstat`, `lstat`: 获取文件或文件描述符的状态信息。
   - `mkdir`, `rmdir`: 创建和删除目录。
   - `link`, `unlink`: 创建硬链接和删除文件。
   - `symlink`: 创建符号链接。
   - `readlink`: 读取符号链接的目标。
   - `rename`: 重命名文件或目录。
   - `chmod`, `fchmod`: 修改文件权限。
   - `chown`, `fchown`, `lchown`: 修改文件所有者和所属组。
   - `truncate`, `ftruncate`: 截断文件到指定长度。
   - `access`: 检查文件访问权限。
   - `chdir`, `fchdir`: 改变当前工作目录。
   - `chroot`: 改变进程的根目录。
   - `mkfifo`: 创建命名管道。
   - `mknod`: 创建特殊文件（设备节点等）。
   - `utimes`, `futimes`, `utimensat`: 修改文件的访问和修改时间。
   - `pathconf`, `fpathconf`: 获取与文件路径或文件描述符相关的配置信息。
   - `revoke`: 吊销对文件或目录的访问权限。
   - `sync`: 将内存中的文件数据同步到磁盘。
   - `unmount`: 卸载文件系统。
   - `getdents`: 读取目录条目。
   - `getcwd`: 获取当前工作目录。

3. **网络操作:**
   - `socket`: 创建一个socket。
   - `bind`: 将socket绑定到特定的地址和端口。
   - `listen`: 监听socket连接。
   - `accept`, `paccept`: 接受socket连接。
   - `connect`: 连接到远程socket。
   - `sendto`, `recvfrom`: 在无连接的socket上发送和接收数据。
   - `sendmsg`, `recvmsg`: 在socket上发送和接收消息。
   - `getsockopt`, `setsockopt`: 获取和设置socket选项。
   - `getpeername`, `getsockname`: 获取连接的对端地址和本地socket地址。
   - `shutdown`: 关闭socket的发送或接收方向。
   - `socketpair`: 创建一对已连接的socket。

4. **内存管理:**
   - `mmap`: 将文件或设备映射到内存。
   - `munmap`: 取消内存映射。

5. **时间相关:**
   - `nanosleep`: 使当前线程休眠指定的纳秒数。
   - `gettimeofday`, `settimeofday`: 获取和设置系统时间。
   - `adjtime`: 微调系统时钟。

6. **信号处理:** (虽然这个文件本身不直接处理信号，但 `paccept` 函数涉及到 `sigmask` 参数，用于在接受连接时阻塞某些信号)

7. **文件描述符控制:**
   - `dup`, `dup2`: 复制文件描述符。
   - `fcntl`: 执行各种文件控制操作，如修改文件状态标志、获取/设置文件锁等。
   - `flock`: 对文件施加咨询锁。

8. **设备和I/O控制:**
   - `ioctl`, `ioctlPtr`: 执行设备特定的控制操作。
   - `pipe2`: 创建管道。

9. **系统信息:**
   - `sysctl`: 获取和设置内核参数。

**Go语言功能的实现推断与举例：**

这个文件是Go标准库中实现各种操作系统相关功能的基石。很多 `os` 包、 `net` 包等高级功能最终都会调用到这里定义的系统调用。

**例子 1: 读取文件内容**

假设我们要读取一个文件的内容，Go语言的 `os` 包提供了 `os.ReadFile` 函数。这个函数最终会调用到 `syscall` 包中的 `Open` 和 `Read` 函数。

```go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	filename := "test.txt"
	// 假设文件存在并包含 "Hello, NetBSD!"

	// 使用 syscall.Open 打开文件
	fd, err := syscall.Open(filename, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	// 使用 syscall.Read 读取文件内容
	buf := make([]byte, 100)
	n, err := syscall.Read(fd, buf)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", n, string(buf[:n]))

	// 使用高级的 os.ReadFile
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error using os.ReadFile:", err)
		return
	}
	fmt.Printf("os.ReadFile content: %s\n", string(content))
}
```

**假设的输入与输出:**

如果 `test.txt` 文件中包含 "Hello, NetBSD!"，那么使用 `syscall.Read` 的输出将是：

```
Read 13 bytes: Hello, NetBSD!
```

使用 `os.ReadFile` 的输出将是：

```
os.ReadFile content: Hello, NetBSD!
```

**例子 2: 创建一个TCP监听器**

Go的 `net` 包提供了 `net.Listen` 函数来创建网络监听器。这个函数底层会调用 `syscall.Socket`, `syscall.Bind`, 和 `syscall.Listen`。

```go
package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func main() {
	addr := "127.0.0.1:8080"

	// 使用 syscall 创建 socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	// 构造 sockaddr_in 结构体
	sockaddr := syscall.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{127, 0, 0, 1},
	}

	// 使用 syscall 绑定地址
	err = syscall.Bind(fd, (*syscall.RawSockaddr)(unsafe.Pointer(&sockaddr)), syscall.SizeofSockaddrInet4)
	if err != nil {
		fmt.Println("Error binding socket:", err)
		return
	}

	// 使用 syscall 监听端口
	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		fmt.Println("Error listening on socket:", err)
		return
	}

	fmt.Println("Socket listening on", addr)

	// 使用高级的 net.Listen
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("Error using net.Listen:", err)
		return
	}
	defer ln.Close()
	fmt.Println("net.Listen is also working on", addr)

	// ... 后续可以进行 accept 操作 ...
}
```

**命令行参数处理:**

这个文件本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，可以使用 `os.Args` 获取。 然而，这些系统调用是构建处理命令行参数的基础。例如，程序可能使用 `syscall.Open` 打开命令行参数指定的文件。

**使用者易犯错的点：**

直接使用 `syscall` 包的函数需要非常小心，因为它们是底层接口，错误的使用容易导致程序崩溃或安全问题。

1. **不正确的类型转换和指针使用:** 很多 `syscall` 函数涉及到 `unsafe.Pointer`，如果类型转换不正确，会导致内存访问错误。例如，传递了错误的结构体大小或者指向了无效的内存地址。

2. **忽略错误处理:** 系统调用通常会返回错误码，必须检查这些错误并进行相应的处理。忽略错误会导致程序在遇到问题时无法正确处理。

3. **不理解系统调用的语义:** 每个系统调用都有其特定的行为和限制，不理解其语义可能导致意想不到的结果。例如，错误地使用文件权限参数或者socket选项。

4. **资源泄漏:**  比如打开文件后忘记关闭 (`syscall.Close`)，或者映射内存后忘记取消映射 (`syscall.Munmap`)，会导致资源泄漏。

5. **并发安全问题:** 在多线程或并发环境中直接使用某些系统调用可能存在竞态条件，需要进行适当的同步处理。

总而言之，`go/src/syscall/zsyscall_netbsd_386.go` 是Go语言在 NetBSD 386 平台上与操作系统内核交互的桥梁，它提供了丰富的底层接口，是构建更高级抽象的基础。虽然直接使用它需要谨慎，但理解它的功能有助于深入理解Go语言的运行机制和操作系统原理。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_netbsd_386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// mksyscall.pl -l32 -netbsd -tags netbsd,386 syscall_bsd.go syscall_netbsd.go syscall_netbsd_386.go
// Code generated by the command above; DO NOT EDIT.

//go:build netbsd && 386

package syscall

import "unsafe"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getgroups(ngid int, gid *_Gid_t) (n int, err error) {
	r0, _, e1 := RawSyscall(SYS_GETGROUPS, uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setgroups(ngid int, gid *_Gid_t) (err error) {
	_, _, e1 := RawSyscall(SYS_SETGROUPS, uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func wait4(pid int, wstatus *_C_int, options int, rusage *Rusage) (wpid int, err error) {
	r0, _, e1 := Syscall6(SYS_WAIT4, uintptr(pid), uintptr(unsafe.Pointer(wstatus)), uintptr(options), uintptr(unsafe.Pointer(rusage)), 0, 0)
	wpid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error) {
	r0, _, e1 := Syscall(SYS_ACCEPT, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := Syscall(SYS_BIND, uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := Syscall(SYS_CONNECT, uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socket(domain int, typ int, proto int) (fd int, err error) {
	r0, _, e1 := RawSyscall(SYS_SOCKET, uintptr(domain), uintptr(typ), uintptr(proto))
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error) {
	_, _, e1 := Syscall6(SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := Syscall6(SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := RawSyscall(SYS_GETPEERNAME, uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := RawSyscall(SYS_GETSOCKNAME, uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Shutdown(s int, how int) (err error) {
	_, _, e1 := Syscall(SYS_SHUTDOWN, uintptr(s), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socketpair(domain int, typ int, proto int, fd *[2]int32) (err error) {
	_, _, e1 := RawSyscall6(SYS_SOCKETPAIR, uintptr(domain), uintptr(typ), uintptr(proto), uintptr(unsafe.Pointer(fd)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall6(SYS_RECVFROM, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(flags), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall6(SYS_SENDTO, uintptr(s), uintptr(_p0), uintptr(len(buf)), uintptr(flags), uintptr(to), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func recvmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := Syscall(SYS_RECVMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := Syscall(SYS_SENDMSG, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func kevent(kq int, change unsafe.Pointer, nchange int, event unsafe.Pointer, nevent int, timeout *Timespec) (n int, err error) {
	r0, _, e1 := Syscall6(SYS_KEVENT, uintptr(kq), uintptr(change), uintptr(nchange), uintptr(event), uintptr(nevent), uintptr(unsafe.Pointer(timeout)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func utimes(path string, timeval *[2]Timeval) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UTIMES, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(timeval)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func futimes(fd int, timeval *[2]Timeval) (err error) {
	_, _, e1 := Syscall(SYS_FUTIMES, uintptr(fd), uintptr(unsafe.Pointer(timeval)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r0, _, e1 := Syscall(SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(arg))
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fcntlPtr(fd int, cmd int, arg unsafe.Pointer) (val int, err error) {
	r0, _, e1 := Syscall(SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(arg))
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ioctl(fd int, req int, arg int) (err error) {
	_, _, e1 := RawSyscall(SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) {
	_, _, e1 := RawSyscall(SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pipe2(p *[2]_C_int, flags int) (err error) {
	_, _, e1 := RawSyscall(SYS_PIPE2, uintptr(unsafe.Pointer(p)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func paccept(fd int, rsa *RawSockaddrAny, addrlen *_Socklen, sigmask *sigset, flags int) (nfd int, err error) {
	r0, _, e1 := Syscall6(SYS_PACCEPT, uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(unsafe.Pointer(sigmask)), uintptr(flags), 0)
	nfd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getdents(fd int, buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_GETDENTS, uintptr(fd), uintptr(_p0), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Access(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_ACCESS, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Adjtime(delta *Timeval, olddelta *Timeval) (err error) {
	_, _, e1 := Syscall(SYS_ADJTIME, uintptr(unsafe.Pointer(delta)), uintptr(unsafe.Pointer(olddelta)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chdir(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_CHDIR, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chflags(path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_CHFLAGS, uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chmod(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_CHMOD, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chown(path string, uid int, gid int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_CHOWN, uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chroot(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_CHROOT, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Close(fd int) (err error) {
	_, _, e1 := Syscall(SYS_CLOSE, uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup(fd int) (nfd int, err error) {
	r0, _, e1 := Syscall(SYS_DUP, uintptr(fd), 0, 0)
	nfd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup2(from int, to int) (err error) {
	_, _, e1 := Syscall(SYS_DUP2, uintptr(from), uintptr(to), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchdir(fd int) (err error) {
	_, _, e1 := Syscall(SYS_FCHDIR, uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchflags(fd int, flags int) (err error) {
	_, _, e1 := Syscall(SYS_FCHFLAGS, uintptr(fd), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchmod(fd int, mode uint32) (err error) {
	_, _, e1 := Syscall(SYS_FCHMOD, uintptr(fd), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchown(fd int, uid int, gid int) (err error) {
	_, _, e1 := Syscall(SYS_FCHOWN, uintptr(fd), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Flock(fd int, how int) (err error) {
	_, _, e1 := Syscall(SYS_FLOCK, uintptr(fd), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fpathconf(fd int, name int) (val int, err error) {
	r0, _, e1 := Syscall(SYS_FPATHCONF, uintptr(fd), uintptr(name), 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstat(fd int, stat *Stat_t) (err error) {
	_, _, e1 := Syscall(SYS_FSTAT, uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fsync(fd int) (err error) {
	_, _, e1 := Syscall(SYS_FSYNC, uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := Syscall6(SYS_FTRUNCATE, uintptr(fd), 0, uintptr(length), uintptr(length>>32), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _, _ := RawSyscall(SYS_GETEGID, 0, 0, 0)
	egid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (uid int) {
	r0, _, _ := RawSyscall(SYS_GETEUID, 0, 0, 0)
	uid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _, _ := RawSyscall(SYS_GETGID, 0, 0, 0)
	gid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpgid(pid int) (pgid int, err error) {
	r0, _, e1 := RawSyscall(SYS_GETPGID, uintptr(pid), 0, 0)
	pgid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpgrp() (pgrp int) {
	r0, _, _ := RawSyscall(SYS_GETPGRP, 0, 0, 0)
	pgrp = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpid() (pid int) {
	r0, _, _ := RawSyscall(SYS_GETPID, 0, 0, 0)
	pid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getppid() (ppid int) {
	r0, _, _ := RawSyscall(SYS_GETPPID, 0, 0, 0)
	ppid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpriority(which int, who int) (prio int, err error) {
	r0, _, e1 := Syscall(SYS_GETPRIORITY, uintptr(which), uintptr(who), 0)
	prio = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := RawSyscall(SYS_GETRLIMIT, uintptr(which), uintptr(unsafe.Pointer(lim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrusage(who int, rusage *Rusage) (err error) {
	_, _, e1 := RawSyscall(SYS_GETRUSAGE, uintptr(who), uintptr(unsafe.Pointer(rusage)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getsid(pid int) (sid int, err error) {
	r0, _, e1 := RawSyscall(SYS_GETSID, uintptr(pid), 0, 0)
	sid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Gettimeofday(tv *Timeval) (err error) {
	_, _, e1 := RawSyscall(SYS_GETTIMEOFDAY, uintptr(unsafe.Pointer(tv)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _, _ := RawSyscall(SYS_GETUID, 0, 0, 0)
	uid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Issetugid() (tainted bool) {
	r0, _, _ := Syscall(SYS_ISSETUGID, 0, 0, 0)
	tainted = bool(r0 != 0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kill(pid int, signum Signal) (err error) {
	_, _, e1 := Syscall(SYS_KILL, uintptr(pid), uintptr(signum), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kqueue() (fd int, err error) {
	r0, _, e1 := Syscall(SYS_KQUEUE, 0, 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Lchown(path string, uid int, gid int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_LCHOWN, uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Link(path string, link string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(link)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_LINK, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Listen(s int, backlog int) (err error) {
	_, _, e1 := Syscall(SYS_LISTEN, uintptr(s), uintptr(backlog), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Lstat(path string, stat *Stat_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_LSTAT, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mkdir(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_MKDIR, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mkfifo(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_MKFIFO, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mknod(path string, mode uint32, dev int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_MKNOD, uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(dev))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Nanosleep(time *Timespec, leftover *Timespec) (err error) {
	_, _, e1 := Syscall(SYS_NANOSLEEP, uintptr(unsafe.Pointer(time)), uintptr(unsafe.Pointer(leftover)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Open(path string, mode int, perm uint32) (fd int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := Syscall(SYS_OPEN, uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(perm))
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Pathconf(path string, name int) (val int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := Syscall(SYS_PATHCONF, uintptr(unsafe.Pointer(_p0)), uintptr(name), 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pread(fd int, p []byte, offset int64) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall6(SYS_PREAD, uintptr(fd), uintptr(_p0), uintptr(len(p)), 0, uintptr(offset), uintptr(offset>>32))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pwrite(fd int, p []byte, offset int64) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall6(SYS_PWRITE, uintptr(fd), uintptr(_p0), uintptr(len(p)), 0, uintptr(offset), uintptr(offset>>32))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func read(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_READ, uintptr(fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Readlink(path string, buf []byte) (n int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 unsafe.Pointer
	if len(buf) > 0 {
		_p1 = unsafe.Pointer(&buf[0])
	} else {
		_p1 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_READLINK, uintptr(unsafe.Pointer(_p0)), uintptr(_p1), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Rename(from string, to string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(from)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(to)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_RENAME, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Revoke(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_REVOKE, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Rmdir(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_RMDIR, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	r0, r1, e1 := Syscall6(SYS_LSEEK, uintptr(fd), 0, uintptr(offset), uintptr(offset>>32), uintptr(whence), 0)
	newoffset = int64(int64(r1)<<32 | int64(r0))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Select(n int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (err error) {
	_, _, e1 := Syscall6(SYS_SELECT, uintptr(n), uintptr(unsafe.Pointer(r)), uintptr(unsafe.Pointer(w)), uintptr(unsafe.Pointer(e)), uintptr(unsafe.Pointer(timeout)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setegid(egid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETEGID, uintptr(egid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Seteuid(euid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETEUID, uintptr(euid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setgid(gid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETGID, uintptr(gid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setpgid(pid int, pgid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETPGID, uintptr(pid), uintptr(pgid), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setpriority(which int, who int, prio int) (err error) {
	_, _, e1 := Syscall(SYS_SETPRIORITY, uintptr(which), uintptr(who), uintptr(prio))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setregid(rgid int, egid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETREGID, uintptr(rgid), uintptr(egid), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setreuid(ruid int, euid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETREUID, uintptr(ruid), uintptr(euid), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := RawSyscall(SYS_SETRLIMIT, uintptr(which), uintptr(unsafe.Pointer(lim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setsid() (pid int, err error) {
	r0, _, e1 := RawSyscall(SYS_SETSID, 0, 0, 0)
	pid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Settimeofday(tp *Timeval) (err error) {
	_, _, e1 := RawSyscall(SYS_SETTIMEOFDAY, uintptr(unsafe.Pointer(tp)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setuid(uid int) (err error) {
	_, _, e1 := RawSyscall(SYS_SETUID, uintptr(uid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Stat(path string, stat *Stat_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_STAT, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Symlink(path string, link string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(link)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_SYMLINK, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Sync() (err error) {
	_, _, e1 := Syscall(SYS_SYNC, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Truncate(path string, length int64) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_TRUNCATE, uintptr(unsafe.Pointer(_p0)), 0, uintptr(length), uintptr(length>>32), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Umask(newmask int) (oldmask int) {
	r0, _, _ := Syscall(SYS_UMASK, uintptr(newmask), 0, 0)
	oldmask = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unlink(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UNLINK, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unmount(path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UNMOUNT, uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func write(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_WRITE, uintptr(fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error) {
	r0, _, e1 := Syscall9(SYS_MMAP, uintptr(addr), uintptr(length), uintptr(prot), uintptr(flag), uintptr(fd), 0, uintptr(pos), uintptr(pos>>32), 0)
	ret = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func munmap(addr uintptr, length uintptr) (err error) {
	_, _, e1 := Syscall(SYS_MUNMAP, uintptr(addr), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func readlen(fd int, buf *byte, nbuf int) (n int, err error) {
	r0, _, e1 := Syscall(SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(buf)), uintptr(nbuf))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func utimensat(dirfd int, path string, times *[2]Timespec, flag int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_UTIMENSAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)), uintptr(flag), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getcwd(buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS___GETCWD, uintptr(_p0), uintptr(len(buf)), 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) {
	var _p0 unsafe.Pointer
	if len(mib) > 0 {
		_p0 = unsafe.Pointer(&mib[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall6(SYS___SYSCTL, uintptr(_p0), uintptr(len(mib)), uintptr(unsafe.Pointer(old)), uintptr(unsafe.Pointer(oldlen)), uintptr(unsafe.Pointer(new)), uintptr(newlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

"""



```