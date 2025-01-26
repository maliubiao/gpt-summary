Response:
The user wants to understand the functionality of a Go source code file.
This file is located at `go/src/syscall/zsyscall_darwin_arm64.go`.
The file name suggests it contains system call implementations for the Darwin operating system on the ARM64 architecture.

I need to:
1. List the functions present in the code.
2. Infer the Go language feature each function implements (if possible).
3. Provide Go code examples demonstrating the usage of these features.
4. Include assumed inputs and outputs for code examples.
5. Explain any command-line argument processing (unlikely in this syscall file).
6. Identify potential user errors.
7. Summarize the functionality of the provided code snippet for part 1.

Based on the function names, it seems like this file implements various system calls related to:

- Process management (e.g., `getgroups`, `setgroups`, `wait4`, `kill`)
- Networking (e.g., `accept`, `bind`, `connect`, `socket`, `getsockopt`, `setsockopt`, `sendto`, `recvfrom`)
- File system operations (e.g., `utimes`, `futimes`, `open`, `close`, `read`, `write`, `mkdir`, `chmod`, `chown`)
- Memory management (e.g., `mlock`, `munlock`, `mprotect`)
- Security (e.g., `access`)
- Inter-process communication (e.g., `pipe`, `socketpair`)
- System information (e.g., `getpid`, `getuid`, `getgid`)
- I/O control (e.g., `ioctl`, `fcntl`)
- Directory operations (e.g., `chdir`, `chroot`)

Each function in the file appears to be a thin wrapper around a raw system call. It takes Go-specific types as arguments, converts them to the appropriate types for the system call, makes the system call using `rawSyscall` or `syscall`, and then converts the results back to Go types, including handling potential errors.

The `//go:cgo_import_dynamic` directives indicate that these system calls are dynamically linked from the system library (`/usr/lib/libSystem.B.dylib`).

For the Go code examples, I will choose a few representative functions from different categories.
这个Go语言源文件 `go/src/syscall/zsyscall_darwin_arm64.go` 的主要功能是 **为在 Darwin (macOS, iOS, etc.) 操作系统上运行的 ARM64 架构的 Go 程序提供系统调用接口**。

具体来说，它做了以下几件事：

1. **定义了 Go 函数来封装底层的 Darwin 系统调用。** 例如，`getgroups` 函数封装了底层的 `getgroups` 系统调用。这些 Go 函数接收 Go 语言的数据类型作为参数，并返回 Go 语言的数据类型。

2. **使用了 `rawSyscall` 和 `syscall` 函数来执行实际的系统调用。**  `rawSyscall` 和 `syscall` 是 Go 语言 `syscall` 包提供的用于直接调用操作系统底层系统调用的函数。

3. **处理了系统调用的返回值和错误。** 如果系统调用返回错误，这些 Go 函数会将错误码转换为 Go 语言的 `error` 类型。

4. **通过 `//go:cgo_import_dynamic` 指令实现了动态链接。**  这意味着这些系统调用的具体实现在运行时会从系统库 `/usr/lib/libSystem.B.dylib` 中动态加载。  这允许 Go 程序使用操作系统提供的底层功能。

**它可以被认为是 Go 语言标准库中 `syscall` 包在 Darwin ARM64 平台上的具体实现。** 它使得 Go 程序员可以使用更符合 Go 语言习惯的方式来调用操作系统提供的功能，而无需直接处理底层的系统调用细节。

**它可以实现的 Go 语言功能示例：**

以下举例说明了 `getgroups` 和 `wait4` 这两个系统调用在 Go 语言中的使用方式。

**示例 1: 获取当前进程所属的用户组 ID 列表 (`getgroups`)**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 假设当前进程属于用户组 100 和 200
	const expectedGroups = 2

	gids := make([]syscall.Gid_t, expectedGroups)
	n, err := syscall.Getgroups(expectedGroups, &gids[0])
	if err != nil {
		fmt.Println("获取用户组 ID 失败:", err)
		return
	}

	fmt.Printf("当前进程所属的用户组 ID 数量: %d\n", n)
	fmt.Printf("用户组 ID 列表: %v\n", gids[:n])

	// 假设输出:
	// 当前进程所属的用户组 ID 数量: 2
	// 用户组 ID 列表: [100 200]
}
```

**解释:**

- `syscall.Getgroups(expectedGroups, &gids[0])` 调用了文件中定义的 `getgroups` 函数。
- `expectedGroups` 是我们预期的用户组数量。
- `gids` 是一个用于存储用户组 ID 的 `syscall.Gid_t` 类型的切片。
- `&gids[0]` 将切片的第一个元素的地址传递给 `getgroups` 函数。
- 函数返回实际获取的用户组数量 `n` 和可能出现的错误 `err`。

**示例 2: 等待子进程结束 (`wait4`)**

```go
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func main() {
	// 假设我们启动了一个子进程执行 "sleep 1" 命令
	cmd := exec.Command("sleep", "1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		fmt.Println("启动子进程失败:", err)
		return
	}

	pid := cmd.Process.Pid
	fmt.Printf("子进程 PID: %d\n", pid)

	var wstatus syscall.WaitStatus
	var rusage syscall.Rusage

	// 等待子进程结束
	wpid, err := syscall.Wait4(pid, &wstatus, 0, &rusage)
	if err != nil {
		fmt.Println("等待子进程失败:", err)
		return
	}

	fmt.Printf("等待到的进程 PID: %d\n", wpid)
	fmt.Printf("子进程退出状态: %v\n", wstatus)
	fmt.Printf("子进程资源使用情况: %+v\n", rusage)

	// 假设输出 (实际输出会包含资源使用信息):
	// 子进程 PID: 12345
	// 等待到的进程 PID: 12345
	// 子进程退出状态: exit status 0
	// 子进程资源使用情况: ...
}
```

**解释:**

- `syscall.Wait4(pid, &wstatus, 0, &rusage)` 调用了文件中定义的 `wait4` 函数。
- `pid` 是要等待的子进程的 PID。
- `wstatus` 是一个用于存储子进程退出状态的变量。
- `rusage` 是一个用于存储子进程资源使用情况的变量。
- 函数返回等待到的进程的 PID (`wpid`) 和可能出现的错误 (`err`)。

**涉及的 Go 语言功能:**

这个文件主要涉及 Go 语言的 **系统调用 (syscall)** 功能，它是 Go 语言与操作系统底层交互的关键部分。 它依赖于 `unsafe` 包进行指针操作，并使用 `internal/abi` 和 `runtime` 包进行底层的函数调用和运行时管理。 `go:build` 标签用于指定该文件只在 `darwin` 操作系统且架构为 `arm64` 时编译。

**命令行参数处理:**

这个文件本身不直接处理命令行参数。 它提供的功能是为其他 Go 代码提供系统调用的接口，那些调用这些接口的 Go 代码可能会处理命令行参数。

**功能归纳 (针对提供的代码片段 - 第 1 部分):**

这个代码片段（第 1 部分）的主要功能是 **定义了一系列 Go 函数，这些函数封装了 Darwin 操作系统在 ARM64 架构上的一些核心系统调用，主要涵盖了进程管理、网络操作和基本的文件操作。** 它通过 `rawSyscall` 和 `syscall` 将 Go 语言的调用桥接到操作系统的底层实现，并负责处理错误转换。  这些函数构成了 Go 语言 `syscall` 包在特定平台上的基础 building blocks。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_darwin_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksyscall.pl -darwin -tags darwin,arm64 syscall_bsd.go syscall_darwin.go syscall_darwin_arm64.go
// Code generated by the command above; DO NOT EDIT.

//go:build darwin && arm64

package syscall

import "unsafe"
import "internal/abi"
import "runtime"

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

//go:cgo_import_dynamic libc_getgroups getgroups "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setgroups(ngid int, gid *_Gid_t) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setgroups_trampoline), uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setgroups_trampoline()

//go:cgo_import_dynamic libc_setgroups setgroups "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_wait4 wait4 "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_accept accept "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_bind_trampoline), uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_bind_trampoline()

//go:cgo_import_dynamic libc_bind bind "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_connect_trampoline), uintptr(s), uintptr(addr), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_connect_trampoline()

//go:cgo_import_dynamic libc_connect connect "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_socket socket "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error) {
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_getsockopt_trampoline), uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getsockopt_trampoline()

//go:cgo_import_dynamic libc_getsockopt getsockopt "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_setsockopt_trampoline), uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setsockopt_trampoline()

//go:cgo_import_dynamic libc_setsockopt setsockopt "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getpeername_trampoline), uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getpeername_trampoline()

//go:cgo_import_dynamic libc_getpeername getpeername "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getsockname_trampoline), uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getsockname_trampoline()

//go:cgo_import_dynamic libc_getsockname getsockname "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Shutdown(s int, how int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_shutdown_trampoline), uintptr(s), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_shutdown_trampoline()

//go:cgo_import_dynamic libc_shutdown shutdown "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socketpair(domain int, typ int, proto int, fd *[2]int32) (err error) {
	_, _, e1 := rawSyscall6(abi.FuncPCABI0(libc_socketpair_trampoline), uintptr(domain), uintptr(typ), uintptr(proto), uintptr(unsafe.Pointer(fd)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_socketpair_trampoline()

//go:cgo_import_dynamic libc_socketpair socketpair "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_recvfrom recvfrom "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_sendto sendto "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_recvmsg recvmsg "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_sendmsg sendmsg "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_kevent kevent "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_utimes utimes "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func futimes(fd int, timeval *[2]Timeval) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_futimes_trampoline), uintptr(fd), uintptr(unsafe.Pointer(timeval)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_futimes_trampoline()

//go:cgo_import_dynamic libc_futimes futimes "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_fcntl fcntl "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_ioctl ioctl "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_ioctl_trampoline), uintptr(fd), uintptr(req), uintptr(arg))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pipe(p *[2]int32) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_pipe_trampoline), uintptr(unsafe.Pointer(p)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_pipe_trampoline()

//go:cgo_import_dynamic libc_pipe pipe "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_utimensat_trampoline), uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_utimensat_trampoline()

//go:cgo_import_dynamic libc_utimensat utimensat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func kill(pid int, signum int, posix int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_kill_trampoline), uintptr(pid), uintptr(signum), uintptr(posix))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_kill_trampoline()

//go:cgo_import_dynamic libc_kill kill "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_access access "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Adjtime(delta *Timeval, olddelta *Timeval) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_adjtime_trampoline), uintptr(unsafe.Pointer(delta)), uintptr(unsafe.Pointer(olddelta)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_adjtime_trampoline()

//go:cgo_import_dynamic libc_adjtime adjtime "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_chdir chdir "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_chflags chflags "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_chmod chmod "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_chown chown "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_chroot chroot "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Close(fd int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_close_trampoline), uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_close_trampoline()

//go:cgo_import_dynamic libc_close close "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func closedir(dir uintptr) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_closedir_trampoline), uintptr(dir), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_closedir_trampoline()

//go:cgo_import_dynamic libc_closedir closedir "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_dup dup "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup2(from int, to int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_dup2_trampoline), uintptr(from), uintptr(to), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_dup2_trampoline()

//go:cgo_import_dynamic libc_dup2 dup2 "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Exchangedata(path1 string, path2 string, options int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path1)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(path2)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_exchangedata_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(options))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_exchangedata_trampoline()

//go:cgo_import_dynamic libc_exchangedata exchangedata "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchdir(fd int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchdir_trampoline), uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchdir_trampoline()

//go:cgo_import_dynamic libc_fchdir fchdir "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchflags(fd int, flags int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchflags_trampoline), uintptr(fd), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchflags_trampoline()

//go:cgo_import_dynamic libc_fchflags fchflags "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchmod(fd int, mode uint32) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchmod_trampoline), uintptr(fd), uintptr(mode), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchmod_trampoline()

//go:cgo_import_dynamic libc_fchmod fchmod "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchown(fd int, uid int, gid int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fchown_trampoline), uintptr(fd), uintptr(uid), uintptr(gid))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fchown_trampoline()

//go:cgo_import_dynamic libc_fchown fchown "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Flock(fd int, how int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_flock_trampoline), uintptr(fd), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_flock_trampoline()

//go:cgo_import_dynamic libc_flock flock "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_fpathconf fpathconf "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fsync(fd int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fsync_trampoline), uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fsync_trampoline()

//go:cgo_import_dynamic libc_fsync fsync "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_ftruncate_trampoline), uintptr(fd), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_ftruncate_trampoline()

//go:cgo_import_dynamic libc_ftruncate ftruncate "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getdtablesize() (size int) {
	r0, _, _ := syscall(abi.FuncPCABI0(libc_getdtablesize_trampoline), 0, 0, 0)
	size = int(r0)
	return
}

func libc_getdtablesize_trampoline()

//go:cgo_import_dynamic libc_getdtablesize getdtablesize "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getegid_trampoline), 0, 0, 0)
	egid = int(r0)
	return
}

func libc_getegid_trampoline()

//go:cgo_import_dynamic libc_getegid getegid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (uid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_geteuid_trampoline), 0, 0, 0)
	uid = int(r0)
	return
}

func libc_geteuid_trampoline()

//go:cgo_import_dynamic libc_geteuid geteuid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getgid_trampoline), 0, 0, 0)
	gid = int(r0)
	return
}

func libc_getgid_trampoline()

//go:cgo_import_dynamic libc_getgid getgid "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_getpgid getpgid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpgrp() (pgrp int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getpgrp_trampoline), 0, 0, 0)
	pgrp = int(r0)
	return
}

func libc_getpgrp_trampoline()

//go:cgo_import_dynamic libc_getpgrp getpgrp "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpid() (pid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getpid_trampoline), 0, 0, 0)
	pid = int(r0)
	return
}

func libc_getpid_trampoline()

//go:cgo_import_dynamic libc_getpid getpid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getppid() (ppid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getppid_trampoline), 0, 0, 0)
	ppid = int(r0)
	return
}

func libc_getppid_trampoline()

//go:cgo_import_dynamic libc_getppid getppid "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_getpriority getpriority "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getrlimit_trampoline), uintptr(which), uintptr(unsafe.Pointer(lim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getrlimit_trampoline()

//go:cgo_import_dynamic libc_getrlimit getrlimit "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrusage(who int, rusage *Rusage) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_getrusage_trampoline), uintptr(who), uintptr(unsafe.Pointer(rusage)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getrusage_trampoline()

//go:cgo_import_dynamic libc_getrusage getrusage "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_getsid getsid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_getuid_trampoline), 0, 0, 0)
	uid = int(r0)
	return
}

func libc_getuid_trampoline()

//go:cgo_import_dynamic libc_getuid getuid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Issetugid() (tainted bool) {
	r0, _, _ := rawSyscall(abi.FuncPCABI0(libc_issetugid_trampoline), 0, 0, 0)
	tainted = bool(r0 != 0)
	return
}

func libc_issetugid_trampoline()

//go:cgo_import_dynamic libc_issetugid issetugid "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_kqueue kqueue "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_lchown lchown "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_link link "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Listen(s int, backlog int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_listen_trampoline), uintptr(s), uintptr(backlog), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_listen_trampoline()

//go:cgo_import_dynamic libc_listen listen "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_mkdir mkdir "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_mkfifo mkfifo "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_mknod mknod "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mlock(b []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_mlock_trampoline), uintptr(_p0), uintptr(len(b)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mlock_trampoline()

//go:cgo_import_dynamic libc_mlock mlock "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mlockall(flags int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_mlockall_trampoline), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mlockall_trampoline()

//go:cgo_import_dynamic libc_mlockall mlockall "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mprotect(b []byte, prot int) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_mprotect_trampoline), uintptr(_p0), uintptr(len(b)), uintptr(prot))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mprotect_trampoline()

//go:cgo_import_dynamic libc_mprotect mprotect "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func msync(b []byte, flags int) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_msync_trampoline), uintptr(_p0), uintptr(len(b)), uintptr(flags))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_msync_trampoline()

//go:cgo_import_dynamic libc_msync msync "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Munlock(b []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_munlock_trampoline), uintptr(_p0), uintptr(len(b)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_munlock_trampoline()

//go:cgo_import_dynamic libc_munlock munlock "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Munlockall() (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_munlockall_trampoline), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_munlockall_trampoline()

//go:cgo_import_dynamic libc_munlockall munlockall "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_open open "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_pathconf pathconf "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_pread pread "/usr/lib/libSystem.B.dylib"

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

//go:cgo_import_dynamic libc_pwrite pwrite "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func read(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_read_trampoline), uintptr(
"""




```