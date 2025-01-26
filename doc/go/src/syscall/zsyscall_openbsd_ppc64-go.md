Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Context:** The first line is crucial: `// mksyscall.pl -openbsd -libc -tags openbsd,ppc64 syscall_bsd.go syscall_openbsd.go syscall_openbsd_libc.go syscall_openbsd_ppc64.go`. This tells us that this file is *auto-generated* using `mksyscall.pl`. The `-openbsd` and `-libc` flags indicate it's for OpenBSD and uses the C standard library. The `-tags openbsd,ppc64` specify the build constraints. Knowing it's auto-generated suggests its primary function is to provide low-level system call interfaces.

2. **Identifying the Core Pattern:**  Scanning through the code, a consistent pattern emerges:
    * A Go function (e.g., `getgroups`).
    * A call to `rawSyscall` or `syscall` (and sometimes `syscall6`).
    * The use of `abi.FuncPCABI0(libc_function_name_trampoline)`.
    * A `libc_function_name_trampoline` function definition (which is empty).
    * A `//go:cgo_import_dynamic libc_function_name function_name "libc.so"` directive.

3. **Deconstructing the Pattern:**
    * **Go Function:** This is the high-level Go interface that programmers will use.
    * **`rawSyscall`/`syscall`/`syscall6`:** These are Go's built-in functions for making system calls. The number after `syscall` indicates the number of arguments passed to the underlying system call.
    * **`abi.FuncPCABI0(libc_function_name_trampoline)`:** This is how Go calls into dynamically loaded C functions. It gets the memory address of the trampoline function.
    * **`libc_function_name_trampoline`:** This is a placeholder function. It doesn't contain any code. Its purpose is to have a symbol that `abi.FuncPCABI0` can resolve.
    * **`//go:cgo_import_dynamic ...`:** This is the key directive for CGo dynamic linking. It tells the Go compiler to dynamically load the C function (e.g., `getgroups`) from the specified shared library (`libc.so`). The `libc_getgroups` is the Go name for the imported function, and `getgroups` is the actual name in the C library.

4. **Inferring the Functionality:** Based on the pattern, each Go function in this file serves as a wrapper around a corresponding C library function. These C library functions are typically system calls or closely related low-level functions. The names of the Go functions (e.g., `getgroups`, `setgroups`, `wait4`, `accept`, `bind`) strongly suggest their purpose based on standard Unix/POSIX APIs.

5. **Formulating the High-Level Function Summary:** The primary function of this code is to provide access to various OpenBSD system calls for Go programs running on the `ppc64` architecture. It uses CGo's dynamic linking feature to interface with the standard C library.

6. **Providing Examples (and the thought process behind them):** To illustrate how these functions are used, we need to connect them to higher-level Go functionalities.
    * **`getgroups` and `setgroups`:** These relate to user group management. The `os` package in Go likely uses these internally. An example would involve getting the current user's groups.
    * **`wait4`:** This is for waiting for a child process to terminate. The `os/exec` package comes to mind. An example would be running a command and waiting for it to finish.
    * **Socket functions (`accept`, `bind`, `connect`, `socket`, etc.):** These are fundamental for network programming. The `net` package uses these. Examples involve creating a server socket and accepting connections.
    * **File system operations (`utimes`, `futimes`, `fcntl`, `ioctl`, `open`, `close`, `read`, `write`, etc.):** The `os` package provides higher-level abstractions, but at the core, it uses these system calls. Examples involve opening, reading, and writing files.

7. **Addressing Potential Pitfalls:**  Consider common issues when working with system calls:
    * **Error Handling:**  System calls return error codes. The Go code handles this using `errnoErr`. It's important for users to check the returned `error`.
    * **Pointer Usage:**  Many functions involve `unsafe.Pointer`. Incorrect pointer usage can lead to crashes or undefined behavior. This needs to be highlighted as a potential source of errors.
    * **Platform Specificity:** This code is specifically for OpenBSD on `ppc64`. Users shouldn't expect it to work on other platforms.

8. **Structuring the Answer:** Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Provide details on the functionality of the individual functions, grouping them by area (process management, networking, file system, etc.).
    * Give concrete Go code examples to demonstrate usage.
    * Address potential errors users might make.
    * Conclude with a final summary.

9. **Refinement and Language:**  Ensure the language is clear, concise, and uses appropriate terminology. For instance, explaining "system call," "CGo," and "dynamic linking" if necessary. Also, double-check the accuracy of the information.

By following these steps, we can effectively analyze the given Go code snippet and provide a comprehensive and informative answer. The key is to recognize the underlying patterns and connect them to the broader context of system programming in Go.这个 `go/src/syscall/zsyscall_openbsd_ppc64.go` 文件是 Go 语言标准库中 `syscall` 包的一部分，专门为 OpenBSD 操作系统在 `ppc64` (PowerPC 64-bit) 架构上提供系统调用接口。

**功能归纳：**

该文件定义了一系列 Go 函数，这些函数是对 OpenBSD 系统提供的 C 语言系统调用的封装。它通过 CGo 的动态链接特性 (`//go:cgo_import_dynamic`)，将 Go 函数与 OpenBSD 系统库 (`libc.so`) 中的同名 C 函数连接起来。

**具体功能列举：**

该文件中的每个函数都对应一个 OpenBSD 的系统调用，主要涵盖了以下功能领域：

* **进程管理:**
    * `getgroups`: 获取当前进程的组成员 ID 列表。
    * `setgroups`: 设置当前进程的组成员 ID 列表。
    * `wait4`: 等待子进程状态改变。
    * `getpgid`: 获取指定进程的进程组 ID。
    * `getpgrp`: 获取当前进程的进程组 ID。
    * `getpid`: 获取当前进程的进程 ID。
    * `getppid`: 获取当前进程的父进程 ID。
    * `getpriority`: 获取指定进程的调度优先级。
    * `kill`: 向指定进程发送信号。
    * `getsid`: 获取指定进程的会话 ID。

* **文件系统操作:**
    * `accept`, `accept4`: 接受 socket 连接。
    * `bind`: 将 socket 绑定到本地地址。
    * `connect`: 连接到指定 socket 地址。
    * `socket`: 创建 socket。
    * `getsockopt`, `setsockopt`: 获取和设置 socket 选项。
    * `getpeername`: 获取连接到 socket 的对端地址。
    * `getsockname`: 获取 socket 自身的地址。
    * `shutdown`: 关闭 socket 连接的一部分或全部。
    * `socketpair`: 创建一对已连接的 socket。
    * `recvfrom`: 从 socket 接收数据，并获取发送端地址。
    * `sendto`: 向指定 socket 地址发送数据。
    * `recvmsg`, `sendmsg`: 通过 socket 发送和接收复杂消息。
    * `utimes`, `futimes`: 修改文件或文件描述符指向文件的访问和修改时间。
    * `fcntl`, `fcntlPtr`:  执行文件控制操作，例如修改文件描述符的属性。
    * `ioctl`, `ioctlPtr`: 执行设备特定的 I/O 控制操作。
    * `pipe2`: 创建管道。
    * `getdents`: 读取目录项。
    * `access`: 检查调用进程是否可以访问某个文件。
    * `chdir`: 改变当前工作目录。
    * `chflags`, `fchflags`: 修改文件的标志位。
    * `chmod`, `fchmod`: 修改文件的权限。
    * `chown`, `fchown`, `lchown`: 修改文件的所有者和所属组。
    * `chroot`: 改变进程的根目录。
    * `close`: 关闭文件描述符。
    * `dup`, `dup2`, `dup3`: 复制文件描述符。
    * `fchdir`: 将当前工作目录更改为由文件描述符引用的目录。
    * `flock`: 对文件加锁或解锁。
    * `fpathconf`, `pathconf`: 获取与文件或路径相关的配置信息。
    * `fstat`, `lstat`: 获取文件状态信息。
    * `fstatfs`: 获取文件系统的信息。
    * `fsync`: 将文件数据同步到磁盘。
    * `ftruncate`: 截断文件到指定长度。
    * `link`: 创建硬链接。
    * `listen`: 监听 socket 连接。
    * `mkdir`: 创建目录。
    * `mkfifo`: 创建命名管道 (FIFO)。
    * `mknod`: 创建特殊文件（设备文件等）。
    * `open`: 打开文件。
    * `pread`, `pwrite`: 在指定偏移量处读写文件。
    * `read`: 读取文件。
    * `readlink`: 读取符号链接的目标。
    * `rename`: 重命名文件或目录。
    * `revoke`: 撤销对文件系统的访问。
    * `rmdir`: 删除目录。

* **时间和日期:**
    * `adjtime`: 调整系统时间。
    * `nanosleep`: 睡眠指定的时间。
    * `gettimeofday`: 获取当前时间。

* **用户和组:**
    * `getegid`: 获取有效组 ID。
    * `geteuid`: 获取有效用户 ID。
    * `getgid`: 获取组 ID。
    * `getuid`: 获取用户 ID。
    * `issetugid`: 检查进程的有效用户 ID 或有效组 ID 是否与实际用户 ID 或实际组 ID 不同。

* **资源限制:**
    * `getrlimit`: 获取进程的资源限制。
    * `getrusage`: 获取进程的资源使用情况。

* **事件通知:**
    * `kevent`, `kqueue`:  用于事件通知的机制 (OpenBSD 的 kqueue)。

* **其他:**
    * `select`:  I/O 多路复用。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言 `syscall` 包在 OpenBSD 和 `ppc64` 架构下的具体实现。 `syscall` 包提供了访问底层操作系统调用的能力，使得 Go 程序可以直接与操作系统内核交互。 这对于需要进行系统级编程，例如网络编程、文件操作、进程控制等非常重要。

**Go 代码举例说明：**

以下是一些使用该文件中函数的 Go 代码示例：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 获取当前进程的组 ID 列表
	ngid := 0
	var gids []syscall.Gid_t
	n, err := syscall.Getgroups(ngid, nil)
	if err != nil {
		fmt.Println("获取组数量失败:", err)
		return
	}
	gids = make([]syscall.Gid_t, n)
	n, err = syscall.Getgroups(n, &gids[0])
	if err != nil {
		fmt.Println("获取组 ID 列表失败:", err)
		return
	}
	fmt.Println("当前进程的组 ID:", gids)

	// 创建一个 socket
	domain := syscall.AF_INET
	typ := syscall.SOCK_STREAM
	proto := 0
	fd, err := syscall.Socket(domain, typ, proto)
	if err != nil {
		fmt.Println("创建 socket 失败:", err)
		return
	}
	fmt.Println("创建的 socket 文件描述符:", fd)
	syscall.Close(fd) // 关闭 socket

	// 打开一个文件
	path := "/tmp/test.txt"
	mode := syscall.O_RDWR | syscall.O_CREATE
	perm := uint32(0644)
	fd, err = syscall.Open(path, mode, perm)
	if err != nil {
		fmt.Println("打开文件失败:", err)
		return
	}
	fmt.Println("打开的文件描述符:", fd)
	syscall.Close(fd) // 关闭文件
}
```

**假设的输入与输出：**

* **`syscall.Getgroups(0, nil)`:**
    * **假设输入:**  `ngid = 0`, `gid = nil`
    * **可能输出:** `n = 2`, `err = nil` (表示当前用户属于 2 个组)

* **`syscall.Getgroups(2, &gids[0])`:**
    * **假设输入:** `ngid = 2`, `gid` 指向一个长度为 2 的 `syscall.Gid_t` 数组的内存地址。
    * **可能输出:** `n = 2`, `err = nil`, `gids = [{100} {200}]` (表示用户的组 ID 为 100 和 200)

* **`syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)`:**
    * **假设输入:** `domain = 2` (syscall.AF_INET), `typ = 1` (syscall.SOCK_STREAM), `proto = 0`
    * **可能输出:** `fd = 3`, `err = nil` (成功创建了一个 TCP socket，文件描述符为 3)

* **`syscall.Open("/tmp/test.txt", syscall.O_RDWR|syscall.O_CREATE, 0644)`:**
    * **假设输入:** `path = "/tmp/test.txt"`, `mode` 为读写并创建， `perm = 0644`
    * **可能输出:** `fd = 3`, `err = nil` (成功打开或创建了文件，文件描述符为 3) 或者 `fd = -1`, `err = syscall.ENOENT` (如果父目录不存在)

**命令行参数的具体处理：**

这个文件本身不直接处理命令行参数。 它提供的函数是对系统调用的封装，系统调用是操作系统内核提供的接口，不涉及命令行参数的处理。 命令行参数的处理通常发生在用户空间的应用程序中。

**使用者易犯错的点：**

* **错误处理：** 系统调用可能会失败，并返回错误码。 必须检查 `err` 返回值，并进行适当的错误处理。  忽略错误会导致程序行为不可预测。
    ```go
    fd, err := syscall.Open("/nonexistent", syscall.O_RDONLY, 0)
    if err != nil {
        fmt.Println("打开文件失败:", err) // 应该处理错误
    }
    ```

* **平台依赖：** 这个文件是针对 OpenBSD 和 `ppc64` 架构的。  直接使用这些函数编写的代码在其他操作系统或架构上可能无法编译或运行。 应该使用 `syscall` 包中更通用的函数，或者使用带有平台判断的编译标签。

* **不安全的指针操作：**  很多系统调用涉及使用 `unsafe.Pointer`。 不正确地使用指针可能导致程序崩溃或安全漏洞。  需要非常小心地处理涉及 `unsafe.Pointer` 的操作。

* **理解系统调用语义：**  需要理解底层系统调用的具体行为和参数含义。 错误的参数传递会导致系统调用失败或产生意外的结果。 例如，对于文件操作，需要了解不同的 `O_` 开头的标志位的含义。

**总结：**

`go/src/syscall/zsyscall_openbsd_ppc64.go` 文件的主要功能是为 Go 程序提供在 OpenBSD 操作系统和 `ppc64` 架构上直接调用系统调用的能力。 它通过 CGo 将 Go 函数映射到 OpenBSD 的 C 语言系统调用，使得 Go 开发者可以进行底层的系统编程。 使用者需要注意错误处理、平台依赖性和不安全指针操作等问题。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_openbsd_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksyscall.pl -openbsd -libc -tags openbsd,ppc64 syscall_bsd.go syscall_openbsd.go syscall_openbsd_libc.go syscall_openbsd_ppc64.go
// Code generated by the command above; DO NOT EDIT.

//go:build openbsd && ppc64

package syscall

import "unsafe"
import "internal/abi"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getgroups(ngid int, gid *_Gid_t) (n int, err error) {
	r0, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getgroups_trampoline), uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getgroups_trampoline()

//go:cgo_import_dynamic libc_getgroups getgroups "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setgroups(ngid int, gid *_Gid_t) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setgroups_trampoline), uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setgroups_trampoline()

//go:cgo_import_dynamic libc_setgroups setgroups "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func wait4(pid int, wstatus *_C_int, options int, rusage *Rusage) (wpid int, err error) {
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_wait4_trampoline), uintptr(pid), uintptr(unsafe.Pointer(wstatus)), uintptr(options), uintptr(unsafe.Pointer(rusage)), 0, 0)
	wpid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_wait4_trampoline()

//go:cgo_import_dynamic libc_wait4 wait4 "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_accept_trampoline), uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_accept_trampoline()

//go:cgo_import_dynamic libc_accept accept "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_bind_trampoline), uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_bind_trampoline()

//go:cgo_import_dynamic libc_bind bind "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_connect_trampoline), uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_connect_trampoline()

//go:cgo_import_dynamic libc_connect connect "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socket(domain int, typ int, proto int) (fd int, err error) {
	r0, _, e1 := rawSyscall(abi.FuncPCABI0(libc_socket_trampoline), uintptr(domain), uintptr(typ), uintptr(proto))
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_socket_trampoline()

//go:cgo_import_dynamic libc_socket socket "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error) {
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_getsockopt_trampoline), uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getsockopt_trampoline()

//go:cgo_import_dynamic libc_getsockopt getsockopt "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_setsockopt_trampoline), uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setsockopt_trampoline()

//go:cgo_import_dynamic libc_setsockopt setsockopt "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getpeername_trampoline), uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getpeername_trampoline()

//go:cgo_import_dynamic libc_getpeername getpeername "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getsockname_trampoline), uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getsockname_trampoline()

//go:cgo_import_dynamic libc_getsockname getsockname "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Shutdown(s int, how int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_shutdown_trampoline), uintptr(s), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_shutdown_trampoline()

//go:cgo_import_dynamic libc_shutdown shutdown "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socketpair(domain int, typ int, proto int, fd *[2]int32) (err error) {
	_, _, e1 := rawSyscall6(abi.FuncPCABI0(libc_socketpair_trampoline), uintptr(domain), uintptr(typ), uintptr(proto), uintptr(unsafe.Pointer(fd)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_socketpair_trampoline()

//go:cgo_import_dynamic libc_socketpair socketpair "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_recvfrom_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(flags), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_recvfrom_trampoline()

//go:cgo_import_dynamic libc_recvfrom recvfrom "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_sendto_trampoline), uintptr(s), uintptr(_p0), uintptr(len(buf)), uintptr(flags), uintptr(to), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_sendto_trampoline()

//go:cgo_import_dynamic libc_sendto sendto "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func recvmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_recvmsg_trampoline), uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_recvmsg_trampoline()

//go:cgo_import_dynamic libc_recvmsg recvmsg "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_sendmsg_trampoline), uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_sendmsg_trampoline()

//go:cgo_import_dynamic libc_sendmsg sendmsg "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func kevent(kq int, change unsafe.Pointer, nchange int, event unsafe.Pointer, nevent int, timeout *Timespec) (n int, err error) {
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_kevent_trampoline), uintptr(kq), uintptr(change), uintptr(nchange), uintptr(event), uintptr(nevent), uintptr(unsafe.Pointer(timeout)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_kevent_trampoline()

//go:cgo_import_dynamic libc_kevent kevent "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func utimes(path string, timeval *[2]Timeval) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_utimes_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(timeval)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_utimes_trampoline()

//go:cgo_import_dynamic libc_utimes utimes "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func futimes(fd int, timeval *[2]Timeval) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_futimes_trampoline), uintptr(fd), uintptr(unsafe.Pointer(timeval)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_futimes_trampoline()

//go:cgo_import_dynamic libc_futimes futimes "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_fcntl_trampoline), uintptr(fd), uintptr(cmd), uintptr(arg))
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fcntl_trampoline()

//go:cgo_import_dynamic libc_fcntl fcntl "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fcntlPtr(fd int, cmd int, arg unsafe.Pointer) (val int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_fcntl_trampoline), uintptr(fd), uintptr(cmd), uintptr(arg))
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ioctl(fd int, req int, arg int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_ioctl_trampoline), uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_ioctl_trampoline()

//go:cgo_import_dynamic libc_ioctl ioctl "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_ioctl_trampoline), uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pipe2(p *[2]_C_int, flags int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_pipe2_trampoline), uintptr(unsafe.Pointer(p)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_pipe2_trampoline()

//go:cgo_import_dynamic libc_pipe2 pipe2 "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept4(fd int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (nfd int, err error) {
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_accept4_trampoline), uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
	nfd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_accept4_trampoline()

//go:cgo_import_dynamic libc_accept4 accept4 "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getdents(fd int, buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_getdents_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getdents_trampoline()

//go:cgo_import_dynamic libc_getdents getdents "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Access(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_access_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_access_trampoline()

//go:cgo_import_dynamic libc_access access "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Adjtime(delta *Timeval, olddelta *Timeval) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_adjtime_trampoline), uintptr(unsafe.Pointer(delta)), uintptr(unsafe.Pointer(olddelta)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_adjtime_trampoline()

//go:cgo_import_dynamic libc_adjtime adjtime "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chdir(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_chdir_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_chdir_trampoline()

//go:cgo_import_dynamic libc_chdir chdir "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chflags(path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_chflags_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_chflags_trampoline()

//go:cgo_import_dynamic libc_chflags chflags "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chmod(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_chmod_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_chmod_trampoline()

//go:cgo_import_dynamic libc_chmod chmod "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chown(path string, uid int, gid int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_chown_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_chown_trampoline()

//go:cgo_import_dynamic libc_chown chown "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chroot(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_chroot_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_chroot_trampoline()

//go:cgo_import_dynamic libc_chroot chroot "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Close(fd int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_close_trampoline), uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_close_trampoline()

//go:cgo_import_dynamic libc_close close "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup(fd int) (nfd int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_dup_trampoline), uintptr(fd), 0, 0)
	nfd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_dup_trampoline()

//go:cgo_import_dynamic libc_dup dup "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup2(from int, to int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_dup2_trampoline), uintptr(from), uintptr(to), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_dup2_trampoline()

//go:cgo_import_dynamic libc_dup2 dup2 "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func dup3(from int, to int, flags int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_dup3_trampoline), uintptr(from), uintptr(to), uintptr(flags))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_dup3_trampoline()

//go:cgo_import_dynamic libc_dup3 dup3 "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchdir(fd int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchdir_trampoline), uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchdir_trampoline()

//go:cgo_import_dynamic libc_fchdir fchdir "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchflags(fd int, flags int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchflags_trampoline), uintptr(fd), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchflags_trampoline()

//go:cgo_import_dynamic libc_fchflags fchflags "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchmod(fd int, mode uint32) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchmod_trampoline), uintptr(fd), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchmod_trampoline()

//go:cgo_import_dynamic libc_fchmod fchmod "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchown(fd int, uid int, gid int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchown_trampoline), uintptr(fd), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchown_trampoline()

//go:cgo_import_dynamic libc_fchown fchown "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Flock(fd int, how int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_flock_trampoline), uintptr(fd), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_flock_trampoline()

//go:cgo_import_dynamic libc_flock flock "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fpathconf(fd int, name int) (val int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_fpathconf_trampoline), uintptr(fd), uintptr(name), 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fpathconf_trampoline()

//go:cgo_import_dynamic libc_fpathconf fpathconf "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstat(fd int, stat *Stat_t) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fstat_trampoline), uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fstat_trampoline()

//go:cgo_import_dynamic libc_fstat fstat "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstatfs(fd int, stat *Statfs_t) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fstatfs_trampoline), uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fstatfs_trampoline()

//go:cgo_import_dynamic libc_fstatfs fstatfs "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fsync(fd int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fsync_trampoline), uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fsync_trampoline()

//go:cgo_import_dynamic libc_fsync fsync "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_ftruncate_trampoline), uintptr(fd), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_ftruncate_trampoline()

//go:cgo_import_dynamic libc_ftruncate ftruncate "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getegid_trampoline), 0, 0, 0)
	egid = int(r0)
	return
}

func libc_getegid_trampoline()

//go:cgo_import_dynamic libc_getegid getegid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (uid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_geteuid_trampoline), 0, 0, 0)
	uid = int(r0)
	return
}

func libc_geteuid_trampoline()

//go:cgo_import_dynamic libc_geteuid geteuid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getgid_trampoline), 0, 0, 0)
	gid = int(r0)
	return
}

func libc_getgid_trampoline()

//go:cgo_import_dynamic libc_getgid getgid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpgid(pid int) (pgid int, err error) {
	r0, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getpgid_trampoline), uintptr(pid), 0, 0)
	pgid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getpgid_trampoline()

//go:cgo_import_dynamic libc_getpgid getpgid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpgrp() (pgrp int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getpgrp_trampoline), 0, 0, 0)
	pgrp = int(r0)
	return
}

func libc_getpgrp_trampoline()

//go:cgo_import_dynamic libc_getpgrp getpgrp "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpid() (pid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getpid_trampoline), 0, 0, 0)
	pid = int(r0)
	return
}

func libc_getpid_trampoline()

//go:cgo_import_dynamic libc_getpid getpid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getppid() (ppid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getppid_trampoline), 0, 0, 0)
	ppid = int(r0)
	return
}

func libc_getppid_trampoline()

//go:cgo_import_dynamic libc_getppid getppid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpriority(which int, who int) (prio int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_getpriority_trampoline), uintptr(which), uintptr(who), 0)
	prio = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getpriority_trampoline()

//go:cgo_import_dynamic libc_getpriority getpriority "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getrlimit_trampoline), uintptr(which), uintptr(unsafe.Pointer(lim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getrlimit_trampoline()

//go:cgo_import_dynamic libc_getrlimit getrlimit "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrusage(who int, rusage *Rusage) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getrusage_trampoline), uintptr(who), uintptr(unsafe.Pointer(rusage)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getrusage_trampoline()

//go:cgo_import_dynamic libc_getrusage getrusage "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getsid(pid int) (sid int, err error) {
	r0, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getsid_trampoline), uintptr(pid), 0, 0)
	sid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getsid_trampoline()

//go:cgo_import_dynamic libc_getsid getsid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Gettimeofday(tv *Timeval) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_gettimeofday_trampoline), uintptr(unsafe.Pointer(tv)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_gettimeofday_trampoline()

//go:cgo_import_dynamic libc_gettimeofday gettimeofday "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getuid_trampoline), 0, 0, 0)
	uid = int(r0)
	return
}

func libc_getuid_trampoline()

//go:cgo_import_dynamic libc_getuid getuid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Issetugid() (tainted bool) {
	r0, _, _ := syscall(abi.FuncPCABI0(libc_issetugid_trampoline), 0, 0, 0)
	tainted = bool(r0 != 0)
	return
}

func libc_issetugid_trampoline()

//go:cgo_import_dynamic libc_issetugid issetugid "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kill(pid int, signum Signal) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_kill_trampoline), uintptr(pid), uintptr(signum), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_kill_trampoline()

//go:cgo_import_dynamic libc_kill kill "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kqueue() (fd int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_kqueue_trampoline), 0, 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_kqueue_trampoline()

//go:cgo_import_dynamic libc_kqueue kqueue "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Lchown(path string, uid int, gid int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_lchown_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_lchown_trampoline()

//go:cgo_import_dynamic libc_lchown lchown "libc.so"

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
	_, _, e1 := syscall(abi.FuncPCABI0(libc_link_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_link_trampoline()

//go:cgo_import_dynamic libc_link link "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Listen(s int, backlog int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_listen_trampoline), uintptr(s), uintptr(backlog), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_listen_trampoline()

//go:cgo_import_dynamic libc_listen listen "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Lstat(path string, stat *Stat_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_lstat_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_lstat_trampoline()

//go:cgo_import_dynamic libc_lstat lstat "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mkdir(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_mkdir_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mkdir_trampoline()

//go:cgo_import_dynamic libc_mkdir mkdir "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mkfifo(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_mkfifo_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mkfifo_trampoline()

//go:cgo_import_dynamic libc_mkfifo mkfifo "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mknod(path string, mode uint32, dev int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_mknod_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(dev))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mknod_trampoline()

//go:cgo_import_dynamic libc_mknod mknod "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Nanosleep(time *Timespec, leftover *Timespec) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_nanosleep_trampoline), uintptr(unsafe.Pointer(time)), uintptr(unsafe.Pointer(leftover)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_nanosleep_trampoline()

//go:cgo_import_dynamic libc_nanosleep nanosleep "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Open(path string, mode int, perm uint32) (fd int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_open_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(perm))
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_open_trampoline()

//go:cgo_import_dynamic libc_open open "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Pathconf(path string, name int) (val int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_pathconf_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(name), 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_pathconf_trampoline()

//go:cgo_import_dynamic libc_pathconf pathconf "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pread(fd int, p []byte, offset int64) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_pread_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_pread_trampoline()

//go:cgo_import_dynamic libc_pread pread "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pwrite(fd int, p []byte, offset int64) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_pwrite_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_pwrite_trampoline()

//go:cgo_import_dynamic libc_pwrite pwrite "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func read(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_read_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_read_trampoline()

//go:cgo_import_dynamic libc_read read "libc.so"

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
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_readlink_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(_p1), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_readlink_trampoline()

//go:cgo_import_dynamic libc_readlink readlink "libc.so"

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
	_, _, e1 := syscall(abi.FuncPCABI0(libc_rename_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_rename_trampoline()

//go:cgo_import_dynamic libc_rename rename "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Revoke(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_revoke_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_revoke_trampoline()

//go:cgo_import_dynamic libc_revoke revoke "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Rmdir(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_rmdir_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_rmdir_trampoline()

//go:cgo_import_dynamic libc_rmdir rmdir "libc.so"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Select(n int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (err error) {
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_select_trampoline), uintptr(n), uintptr(unsafe.Pointer(r)), uintptr(unsafe.Poi
"""




```