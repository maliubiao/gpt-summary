Response:
Let's break down the thought process for answering the prompt.

1. **Understanding the Core Request:** The request asks for the functionality of a Go file (`zsyscall_openbsd_386.go`), specifically focusing on what it *does* and how it relates to Go features. It also has constraints like providing Go code examples, handling assumptions, explaining command-line parameters (though less relevant here), and noting common mistakes (also less relevant). The "Part 1" constraint means I should only cover the functionality present in the given code snippet.

2. **Initial Analysis of the File:**  The filename itself gives a strong hint: `zsyscall_openbsd_386.go`. This immediately suggests it's related to system calls for the OpenBSD operating system on a 386 architecture. The "z" prefix often indicates auto-generated code.

3. **Examining the Generated Code Header:** The first lines confirm the auto-generated nature: `// mksyscall.pl ... syscall_openbsd_386.go`. This tells us the code is created by a tool (`mksyscall.pl`) based on some definitions (likely in the other `syscall_*.go` files mentioned). The `//go:build openbsd && 386` line is crucial. It's a Go build tag, meaning this code will *only* be compiled and included when building for OpenBSD on a 386 architecture.

4. **Analyzing Individual Functions:** The bulk of the file consists of Go functions. A consistent pattern emerges for each function:

   * **Go Function Declaration:** `func getgroups(ngid int, gid *_Gid_t) (n int, err error)` -  A standard Go function with parameters and return values.
   * **`rawSyscall` or `syscall` Call:**  This is the core action. These functions (or `syscall6` in some cases) are part of the `syscall` package and are the bridge to the operating system's system calls. The first argument to `rawSyscall` (or `syscall`, `syscall6`) is crucial: `abi.FuncPCABI0(libc_getgroups_trampoline)`.
   * **Trampoline Function:** `func libc_getgroups_trampoline()` - This is an empty function. Its purpose is revealed by the next part.
   * **`//go:cgo_import_dynamic` Directive:** `//go:cgo_import_dynamic libc_getgroups getgroups "libc.so"` -  This is the key. It's a Cgo directive telling the Go compiler to dynamically link to the `getgroups` function from the `libc.so` library at runtime. The `libc_getgroups` name is the symbol in the shared library, and the `getgroups` name is the Go function it's linked to.
   * **Error Handling:**  The `if e1 != 0 { err = errnoErr(e1) }` block is standard Go error handling for system calls. `e1` typically holds the error number returned by the system call.

5. **Identifying the Functionality:**  Based on the pattern, each Go function in this file is essentially a wrapper around a corresponding C library function. The names are very similar (e.g., `getgroups` in Go maps to `getgroups` in `libc`). Therefore, the functionality of each Go function directly corresponds to the functionality of the C library function it wraps.

6. **Inferring the Go Feature:**  The use of `rawSyscall`, `syscall`, `syscall6`, `unsafe.Pointer`, and `//go:cgo_import_dynamic` strongly suggests that this code is implementing the Go standard library's `syscall` package for the specific OpenBSD/386 platform. It's how Go allows direct interaction with the operating system's kernel.

7. **Providing Go Code Examples:** To illustrate how these functions are used, I need to provide examples of calling the corresponding functions from the `syscall` package. Since the provided code *implements* the low-level functions, the examples will use the *same* function names (e.g., `syscall.Getgroups`).

8. **Handling Assumptions and Inputs/Outputs:** For the examples, I need to make some assumptions about the input values and describe the potential outputs, including error conditions. For example, when calling `syscall.Getgroups`, I assume a buffer size and a pointer to store the group IDs. The output will be the number of groups retrieved and a potential error.

9. **Command-Line Parameters:** The code itself doesn't directly process command-line arguments. This is more handled in the `main` function of a Go program. Therefore, this section is not very relevant to this specific code snippet.

10. **Common Mistakes:**  While there aren't specific *programming errors* readily apparent in this generated code, potential mistakes arise when *using* these syscall wrappers. For instance, incorrect buffer sizes, passing nil pointers when not allowed, or misunderstanding error codes are common issues.

11. **Summarizing the Functionality (Part 1):**  The final step for part 1 is to summarize the observations. The key points are: it's auto-generated, platform-specific, uses Cgo to wrap C library functions, and provides access to low-level system calls for tasks like process management, file system operations, and networking.

12. **Self-Correction/Refinement:**  Initially, I might focus too much on the individual syscalls. It's important to step back and see the bigger picture: this file is *part* of the Go runtime's interface to the operating system. The "trampoline" functions and `go:cgo_import_dynamic` are the crucial implementation details that explain *how* this interaction happens. Also, remember the prompt specifies "Part 1", so only include the functionality visible in the provided snippet. Don't speculate about what might be in other parts of the file.
这个go语言文件 `go/src/syscall/zsyscall_openbsd_386.go` 的主要功能是**为 OpenBSD 操作系统在 386 架构上提供系统调用的 Go 语言绑定 (bindings)**。

具体来说，它做了以下几件事：

1. **定义 Go 函数作为系统调用的接口:**  文件中定义了一系列的 Go 函数，例如 `getgroups`, `setgroups`, `wait4`, `accept`, `bind` 等。这些函数的命名通常与底层的 C 库函数名相同或非常相似。

2. **使用 `rawSyscall` 和 `syscall` 执行底层系统调用:**  这些 Go 函数的内部实现会调用 `syscall` 包提供的 `rawSyscall`, `syscall` 或 `syscall6` 函数。这些函数是 Go 语言与操作系统内核进行交互的低级接口。它们负责将 Go 的参数转换为操作系统期望的格式，并执行实际的系统调用。

3. **处理系统调用的返回值和错误:**  系统调用执行后，`rawSyscall` 和 `syscall` 会返回结果和一个错误码。Go 的绑定函数会将这些返回值转换为 Go 的类型（例如，将整数的返回值转换为 `int`，将错误码转换为 `error` 类型）。`errnoErr` 函数用于将非零的错误码转换为 Go 的 `error` 对象。

4. **利用 Cgo 进行动态链接:**  每个 Go 绑定函数都对应着一个名为 `libc_<函数名>_trampoline` 的空函数，以及一个 `//go:cgo_import_dynamic` 指令。这个指令指示 Go 的 Cgo 工具在运行时动态链接 C 库 (`libc.so`) 中对应的函数。例如，`//go:cgo_import_dynamic libc_getgroups getgroups "libc.so"`  表示将 C 库中的 `getgroups` 函数链接到 Go 中的 `libc_getgroups_trampoline`。  `abi.FuncPCABI0` 用于获取这个 trampoline 函数的地址。

**它是什么go语言功能的实现？**

这个文件是 Go 语言 `syscall` 标准库的一部分，用于实现与操作系统底层交互的功能。它允许 Go 程序执行操作系统提供的各种服务，例如进程管理、文件操作、网络通信等。

**Go 代码举例说明:**

以下代码演示了如何使用 `syscall` 包中的 `Getgroups` 函数，该函数对应于 `zsyscall_openbsd_386.go` 文件中的 `getgroups` 函数。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 假设当前进程最多属于 10 个组
	const ngroups = 10
	var gids [ngroups]uint32

	n, err := syscall.Getgroups(ngroups, (*syscall.Gid_t)(unsafe.Pointer(&gids[0])))
	if err != nil {
		fmt.Println("获取组 ID 失败:", err)
		return
	}

	fmt.Printf("当前进程所属的组 ID (%d 个):\n", n)
	for i := 0; i < n; i++ {
		fmt.Println(gids[i])
	}
}
```

**假设的输入与输出:**

假设当前用户的进程属于 2 个组，其组 ID 分别为 100 和 200。

**输入:** `ngroups = 10` (指定缓冲区大小)

**输出:**

```
当前进程所属的组 ID (2 个):
100
200
```

如果发生错误，例如提供的缓冲区大小不足以容纳所有的组 ID，则输出可能如下：

```
获取组 ID 失败: too many groups
```

**涉及代码推理:**

在 `getgroups` 函数中，`rawSyscall` 被调用，它会将 `ngid` (Go 的 `int`) 和 `gid` (`*_Gid_t`，实际上是指向 `uint32` 数组的指针) 作为参数传递给底层的系统调用。 系统调用执行后，会将获取到的组 ID 写入到 `gid` 指向的内存中，并返回实际获取到的组的数量。 Go 的代码会将这个返回值和可能的错误码返回给调用者。

**命令行参数的具体处理:**

这个文件中的代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，可以使用 `os` 包的 `Args` 变量来访问。

**归纳一下它的功能 (第1部分):**

这个 `zsyscall_openbsd_386.go` 文件的第 1 部分主要负责提供了一系列 Go 函数，这些函数是对 OpenBSD 操作系统在 386 架构上提供的部分系统调用的封装。它通过 `rawSyscall`/`syscall` 与操作系统内核交互，并利用 Cgo 的动态链接特性来调用 C 库中的对应函数。 它的核心功能是**作为 Go 语言程序访问底层操作系统服务的桥梁**。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_openbsd_386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksyscall.pl -l32 -openbsd -libc -tags openbsd,386 syscall_bsd.go syscall_openbsd.go syscall_openbsd_libc.go syscall_openbsd_386.go
// Code generated by the command above; DO NOT EDIT.

//go:build openbsd && 386

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
	_, _, e1 := syscall(abi.FuncPCABI0(libc_ftruncate_trampoline), uintptr(fd), uintptr(length), uintptr(length>>32))
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
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_pread_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), uintptr(offset>>32), 0)
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
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_pwrite_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), uintptr(offset>>32), 0)
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
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_select_trampoline), uintp
"""




```