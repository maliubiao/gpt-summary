Response:
My thought process for analyzing the provided Go code snippet and answering the request goes through these stages:

1. **Understand the Goal:** The request asks for a summary of the functionality of the given Go code, which is a part of the `syscall` package for Linux. It also encourages providing examples, explaining code reasoning, and highlighting potential pitfalls. The "Part 1" indication suggests more is coming.

2. **Identify the Core Purpose:** The first few lines clearly state this file deals with "Linux system calls." This is the fundamental function: providing Go interfaces to interact with the Linux kernel's system call interface.

3. **Break Down the Code:** I start scanning the code from top to bottom, identifying key sections and their roles:

    * **Imports:**  Note the imported packages (`internal/itoa`, `internal/runtime/syscall`, `runtime`, `unsafe`). This indicates interaction with Go's internals and the usage of unsafe operations (which is expected for system call interactions).

    * **`//go:linkname` directives:** Recognize that these are crucial for connecting Go functions to internal runtime functions (`runtime_entersyscall`, `runtime_exitsyscall`). This signals the handling of system call entry and exit.

    * **`RawSyscall` and `RawSyscall6`:**  These are the low-level entry points to make raw system calls. The comments about `//go:uintptrkeepalive`, `//go:nosplit`, and `//go:norace` highlight the intricacies and safety considerations involved.

    * **`Syscall` and `Syscall6`:** These are higher-level wrappers around the raw system calls, incorporating the `runtime_entersyscall` and `runtime_exitsyscall` logic. The comment about race conditions with `RawSyscall` is important.

    * **"Wrapped" Functions:** This is a significant section. It contains Go functions that provide more convenient and idiomatic ways to perform common file system operations (like `Access`, `Chmod`, `Open`, `Mkdir`, etc.). These functions often call lower-level system calls, sometimes with added logic (e.g., `Faccessat` handling of flags).

    * **`isGroupMember` and `isCapDacOverrideSet`:** These are utility functions used within the "Wrapped" functions, demonstrating some internal logic for privilege and access checks.

    * **`//sys` directives:** These are directives for the `mksyscall` tool. They indicate which system calls are being directly mapped and how their Go signatures look.

    * **Socket Address Structures:**  The definitions and methods for `SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix`, etc., are crucial for network programming. The `sockaddr()` methods are for converting these Go structures to the raw socket address format required by the system calls.

    * **`Accept`, `Getsockname`, `Setsockopt`, `recvmsgRaw`, `sendmsgN`:**  These are functions related to socket operations.

    * **Ptrace Functions:**  The `Ptrace...` functions expose the powerful and complex `ptrace` system call for debugging and process inspection.

    * **Other System Call Wrappers:** The remaining part of the code includes wrappers for various other system calls (e.g., `Reboot`, `Mount`, file manipulation, process management).

    * **`AllThreadsSyscall`:** This is a special function for executing a system call on all Go runtime threads, used for operations affecting global process state.

    * **Cgo Integration:** The mentions of `cgo_libc_setgroups`, `cgo_libc_setegid`, etc., indicate conditional behavior based on whether the program is linked with C code (using cgo).

4. **Identify Key Functionality Categories:**  Based on the breakdown, I group the functionality into logical categories:

    * **Raw System Call Access:**  The `RawSyscall` and `RawSyscall6` functions.
    * **Standard System Call Wrappers:** `Syscall` and `Syscall6` with entry/exit handling.
    * **Higher-Level Convenience Wrappers:**  Functions like `Open`, `Chmod`, `Mkdir`, etc.
    * **File System Operations:**  A large portion of the "Wrapped" functions.
    * **Socket Programming:**  Socket address structures and related functions like `Accept`, `Bind`, `Connect`, etc.
    * **Process Management:**  Functions like `Wait4`, and some direct system call wrappers like `Kill`, `Getpid`.
    * **Debugging and Tracing:** The `Ptrace...` functions.
    * **Security and Permissions:**  Functions like `Access`, `isGroupMember`, and `Set...` functions.
    * **Time and Date:** Functions like `Nanosleep`, `Settimeofday`.
    * **Inter-Process Communication (IPC):** `Pipe`, though more could be present in other parts.
    * **Other System Calls:**  A collection of less common but still necessary system call wrappers.
    * **Internal Runtime Interaction:** The `runtime_entersyscall`, `runtime_exitsyscall`, and `AllThreadsSyscall` mechanisms.
    * **Cgo Integration:** Handling cases where the program uses C code.

5. **Synthesize the Summary:** I combine the identified categories into a concise summary, highlighting the main purpose and the breadth of functionalities covered by the code.

6. **Address the Specific Questions (Mentally):**  While not explicitly writing the examples and details for all questions in this "Part 1" stage, I mentally note where such information would be relevant. For example, when discussing `Faccessat`, I consider how the flags are handled differently than the basic `access` system call. For `RawSyscall`, I think about the potential for misuse if arguments are not correctly set.

7. **Focus on "Part 1":**  Since the prompt specifies "Part 1," I concentrate on summarizing the *overall* functionality without delving too deeply into specific examples or error scenarios. I keep those for the subsequent parts.

8. **Review and Refine:**  I reread my summary to ensure clarity, accuracy, and completeness based on the provided code snippet. I check if it directly answers the "归纳一下它的功能" (summarize its function) part of the request.
这段代码是 Go 语言 `syscall` 包中针对 Linux 系统的实现部分，主要功能是提供 **Go 语言程序调用 Linux 系统调用的接口**。它定义了一些 Go 函数，这些函数最终会调用到 Linux 内核提供的系统调用，从而让 Go 程序能够执行底层的操作系统操作。

**具体功能归纳:**

1. **定义了调用 Linux 系统调用的底层机制:**
   - 提供了 `RawSyscall` 和 `RawSyscall6` 函数，允许直接发起带有不同数量参数的原始系统调用。
   - 使用 `runtimesyscall.Syscall6` 与 Go 运行时系统进行交互，执行实际的系统调用。
   - 使用 `runtime_entersyscall` 和 `runtime_exitsyscall` 来标记系统调用的进入和退出，这对于 Go 运行时进行调度和管理很重要。

2. **封装了常用的 Linux 系统调用:**
   - 提供了一系列以大写字母开头的 Go 函数（如 `Access`, `Chmod`, `Open`, `Readlink`, `Mkdir`, `Unlink` 等），这些函数是对底层系统调用的更友好、更符合 Go 语言习惯的封装。
   - 这些封装函数通常会处理一些类型转换、错误处理以及参数的预处理，使得 Go 程序员更容易使用。

3. **处理了不同版本的系统调用和特性:**
   - 例如，`Faccessat` 函数会尝试使用 `faccessat2`（如果可用），并处理 `faccessat2` 不存在的情况，回退到使用 `faccessat` 并手动模拟 `flags` 参数的行为。

4. **提供了与文件系统操作相关的系统调用接口:**
   - 包括文件权限修改（`Chmod`, `Fchmodat`），文件所有权修改（`Chown`, `Fchownat`），文件创建与打开（`Creat`, `Open`, `Openat`），文件链接（`Link`, `Symlink`），文件删除与重命名（`Unlink`, `Rmdir`, `Rename`），以及文件属性修改（`Utimes`, `UtimesNano`, `Futimes`, `Futimesat`）。

5. **提供了与目录操作相关的系统调用接口:**
   - 包括创建目录 (`Mkdir`, `Mkdirat`)，读取目录项 (`Getdents`, `ReadDirent`)，获取当前工作目录 (`Getwd`)。

6. **提供了与进程管理相关的系统调用接口:**
   - 包括等待子进程结束 (`Wait4`)，创建管道 (`Pipe`, `Pipe2`)。

7. **提供了与权限管理相关的系统调用接口:**
   - 包括获取和设置用户组 ID (`Getgroups`, `Setgroups`)，检查是否是某个用户组的成员 (`isGroupMember`)。

8. **提供了与 epoll 相关的系统调用接口:**
   - 包括创建 epoll 实例 (`EpollCreate`, `EpollCreate1`)。 （这部分代码未完全展示，但根据函数名可以推断）

9. **提供了与 socket 相关的系统调用接口:**
   - 包括 socket 地址结构的定义 (`SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix` 等) 及其与底层 `RawSockaddrAny` 之间的转换。
   - 提供了 `Accept`, `Accept4`, `Getsockname` 等 socket 操作相关的函数。

10. **提供了与 ptrace 相关的系统调用接口:**
    - 包括 `PtracePeekText`, `PtracePeekData`, `PtracePokeText`, `PtracePokeData`, `PtraceGetRegs`, `PtraceSetRegs` 等，用于进程跟踪和调试。

11. **提供了一些其他的系统调用接口:**
    - 例如 `Reboot`, `Mount` 等。

12. **处理了与 Cgo 的交互:**
    - 代码中出现 `cgo_libc_setgroups` 等变量，说明在使用了 Cgo 的情况下，某些系统调用的实现可能会有所不同，会调用 C 库中的函数。

**推理其实现的 Go 语言功能：**

基于代码中的函数名和参数，可以推断出它实现了以下 Go 语言功能：

* **文件 I/O 操作:**  `Open`, `Read`, `Write`, `Close` (未完全展示，但必然存在于 `syscall` 包中)。
* **文件和目录操作:** `Create`, `Mkdir`, `Remove`, `Rename`, `Stat`, `Lstat`, `Chmod`, `Chown`, `Symlink`, `Readlink`, `Getwd` 等。
* **进程管理:** `Fork`, `Exec`, `Wait`, `Kill`, `Getpid`, `Getppid`, `Setpgid`, `Setsid` 等。
* **网络编程:** `Socket`, `Bind`, `Listen`, `Accept`, `Connect`, `Send`, `Recv`, `Setsockopt`, `Getsockopt` 等。
* **信号处理:**  `Signal`, `Signalfd` (未完全展示，但 `Kill` 函数的 `Signal` 参数暗示了这一点)。
* **时间相关操作:** `Nanotime`, `Now`, `Sleep` (部分通过 `Nanosleep` 实现)。
* **调试和跟踪:**  通过 `ptrace` 相关函数实现。

**Go 代码举例说明:**

假设我们想创建一个新的文件并写入一些内容，可以使用 `syscall` 包中的 `Open` 和 `Write` 函数：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	path := "test.txt"
	mode := syscall.O_CREAT | syscall.O_WRONLY | syscall.O_TRUNC
	perm := uint32(0644) // 权限为 rw-r--r--

	fd, err := syscall.Open(path, mode, perm)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	message := "Hello, syscall!"
	buffer := unsafe.Slice(unsafe.StringData(message), len(message))

	n, err := syscall.Write(fd, buffer)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	fmt.Printf("Wrote %d bytes to file.\n", n)
}
```

**假设的输入与输出:**

* **输入:**  执行上述 Go 代码。
* **输出:**
   - 如果成功，会在当前目录下创建一个名为 `test.txt` 的文件，内容为 "Hello, syscall!"。控制台输出 "Wrote 14 bytes to file."。
   - 如果失败（例如，没有创建文件的权限），控制台会输出相应的错误信息，如 "Error opening file: permission denied"。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并可以使用 `os.Args` 获取。如果系统调用涉及到路径等参数，那些参数可能是从命令行参数或其他途径获取的。

**使用者易犯错的点:**

由于这段代码是 `syscall` 包的底层实现，直接使用它的用户（通常是其他更高级的包的开发者）容易犯以下错误：

* **不正确的错误处理:**  系统调用返回的是 `Errno` 类型的错误码，需要正确地将其转换为 Go 的 `error` 类型并进行判断。
* **不安全的指针操作:**  `syscall` 包中涉及到 `unsafe.Pointer` 的使用，如果使用不当，可能导致程序崩溃或安全问题。
* **对系统调用语义的理解不足:**  不同的系统调用有不同的行为和限制，需要仔细阅读 Linux 的 man page 以确保正确使用。
* **忽略平台差异:**  `syscall_linux.go` 是特定于 Linux 的实现，在其他操作系统上可能无法工作。Go 提供了平台无关的 `syscall` 包接口，但底层的实现是平台相关的。
* **不正确的权限设置:**  在创建文件、修改权限等操作时，需要设置正确的权限 `mode`。
* **文件描述符管理不当:**  打开的文件描述符需要在使用完毕后及时关闭，否则可能导致资源泄漏。

**总结 "Part 1" 的功能:**

这段 `go/src/syscall/syscall_linux.go` 代码是 Go 语言 `syscall` 包在 Linux 平台上的核心实现，它提供了：

* **直接调用 Linux 系统调用的能力**，包括原始的 `RawSyscall` 和带有运行时管理的 `Syscall`。
* **大量常用 Linux 系统调用的 Go 语言封装**，覆盖了文件系统操作、进程管理、网络编程、权限管理、调试跟踪等多个方面。
* **处理了不同系统调用版本和特性的兼容性问题**。
* **为 Go 程序与 Linux 操作系统底层交互提供了基础**。

Prompt: 
```
这是路径为go/src/syscall/syscall_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Linux system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and
// wrap it in our own nicer implementation.

package syscall

import (
	"internal/itoa"
	runtimesyscall "internal/runtime/syscall"
	"runtime"
	"unsafe"
)

// Pull in entersyscall/exitsyscall for Syscall/Syscall6.
//
// Note that this can't be a push linkname because the runtime already has a
// nameless linkname to export to assembly here and in x/sys. Additionally,
// entersyscall fetches the caller PC and SP and thus can't have a wrapper
// inbetween.

//go:linkname runtime_entersyscall runtime.entersyscall
func runtime_entersyscall()

//go:linkname runtime_exitsyscall runtime.exitsyscall
func runtime_exitsyscall()

// N.B. For the Syscall functions below:
//
// //go:uintptrkeepalive because the uintptr argument may be converted pointers
// that need to be kept alive in the caller.
//
// //go:nosplit because stack copying does not account for uintptrkeepalive, so
// the stack must not grow. Stack copying cannot blindly assume that all
// uintptr arguments are pointers, because some values may look like pointers,
// but not really be pointers, and adjusting their value would break the call.
//
// //go:norace, on RawSyscall, to avoid race instrumentation if RawSyscall is
// called after fork, or from a signal handler.
//
// //go:linkname to ensure ABI wrappers are generated for external callers
// (notably x/sys/unix assembly).

//go:uintptrkeepalive
//go:nosplit
//go:norace
//go:linkname RawSyscall
func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	return RawSyscall6(trap, a1, a2, a3, 0, 0, 0)
}

//go:uintptrkeepalive
//go:nosplit
//go:norace
//go:linkname RawSyscall6
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	var errno uintptr
	r1, r2, errno = runtimesyscall.Syscall6(trap, a1, a2, a3, a4, a5, a6)
	err = Errno(errno)
	return
}

//go:uintptrkeepalive
//go:nosplit
//go:linkname Syscall
func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	runtime_entersyscall()
	// N.B. Calling RawSyscall here is unsafe with atomic coverage
	// instrumentation and race mode.
	//
	// Coverage instrumentation will add a sync/atomic call to RawSyscall.
	// Race mode will add race instrumentation to sync/atomic. Race
	// instrumentation requires a P, which we no longer have.
	//
	// RawSyscall6 is fine because it is implemented in assembly and thus
	// has no coverage instrumentation.
	//
	// This is typically not a problem in the runtime because cmd/go avoids
	// adding coverage instrumentation to the runtime in race mode.
	r1, r2, err = RawSyscall6(trap, a1, a2, a3, 0, 0, 0)
	runtime_exitsyscall()
	return
}

//go:uintptrkeepalive
//go:nosplit
//go:linkname Syscall6
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	runtime_entersyscall()
	r1, r2, err = RawSyscall6(trap, a1, a2, a3, a4, a5, a6)
	runtime_exitsyscall()
	return
}

func rawSyscallNoError(trap, a1, a2, a3 uintptr) (r1, r2 uintptr)
func rawVforkSyscall(trap, a1, a2, a3 uintptr) (r1 uintptr, err Errno)

/*
 * Wrapped
 */

func Access(path string, mode uint32) (err error) {
	return Faccessat(_AT_FDCWD, path, mode, 0)
}

func Chmod(path string, mode uint32) (err error) {
	return Fchmodat(_AT_FDCWD, path, mode, 0)
}

func Chown(path string, uid int, gid int) (err error) {
	return Fchownat(_AT_FDCWD, path, uid, gid, 0)
}

func Creat(path string, mode uint32) (fd int, err error) {
	return Open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)
}

func EpollCreate(size int) (fd int, err error) {
	if size <= 0 {
		return -1, EINVAL
	}
	return EpollCreate1(0)
}

func isGroupMember(gid int) bool {
	groups, err := Getgroups()
	if err != nil {
		return false
	}

	for _, g := range groups {
		if g == gid {
			return true
		}
	}
	return false
}

func isCapDacOverrideSet() bool {
	const _CAP_DAC_OVERRIDE = 1
	var c caps
	c.hdr.version = _LINUX_CAPABILITY_VERSION_3

	_, _, err := RawSyscall(SYS_CAPGET, uintptr(unsafe.Pointer(&c.hdr)), uintptr(unsafe.Pointer(&c.data[0])), 0)

	return err == 0 && c.data[0].effective&capToMask(_CAP_DAC_OVERRIDE) != 0
}

//sys	faccessat(dirfd int, path string, mode uint32) (err error)
//sys	faccessat2(dirfd int, path string, mode uint32, flags int) (err error) = _SYS_faccessat2

func Faccessat(dirfd int, path string, mode uint32, flags int) (err error) {
	if flags == 0 {
		return faccessat(dirfd, path, mode)
	}

	// Attempt to use the newer faccessat2, which supports flags directly,
	// falling back if it doesn't exist.
	//
	// Don't attempt on Android, which does not allow faccessat2 through
	// its seccomp policy [1] on any version of Android as of 2022-12-20.
	//
	// [1] https://cs.android.com/android/platform/superproject/+/master:bionic/libc/SECCOMP_BLOCKLIST_APP.TXT;l=4;drc=dbb8670dfdcc677f7e3b9262e93800fa14c4e417
	if runtime.GOOS != "android" {
		if err := faccessat2(dirfd, path, mode, flags); err != ENOSYS && err != EPERM {
			return err
		}
	}

	// The Linux kernel faccessat system call does not take any flags.
	// The glibc faccessat implements the flags itself; see
	// https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/faccessat.c;hb=HEAD
	// Because people naturally expect syscall.Faccessat to act
	// like C faccessat, we do the same.

	if flags & ^(_AT_SYMLINK_NOFOLLOW|_AT_EACCESS) != 0 {
		return EINVAL
	}

	var st Stat_t
	if err := fstatat(dirfd, path, &st, flags&_AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}

	mode &= 7
	if mode == 0 {
		return nil
	}

	// Fallback to checking permission bits.
	var uid int
	if flags&_AT_EACCESS != 0 {
		uid = Geteuid()
		if uid != 0 && isCapDacOverrideSet() {
			// If CAP_DAC_OVERRIDE is set, file access check is
			// done by the kernel in the same way as for root
			// (see generic_permission() in the Linux sources).
			uid = 0
		}
	} else {
		uid = Getuid()
	}

	if uid == 0 {
		if mode&1 == 0 {
			// Root can read and write any file.
			return nil
		}
		if st.Mode&0111 != 0 {
			// Root can execute any file that anybody can execute.
			return nil
		}
		return EACCES
	}

	var fmode uint32
	if uint32(uid) == st.Uid {
		fmode = (st.Mode >> 6) & 7
	} else {
		var gid int
		if flags&_AT_EACCESS != 0 {
			gid = Getegid()
		} else {
			gid = Getgid()
		}

		if uint32(gid) == st.Gid || isGroupMember(int(st.Gid)) {
			fmode = (st.Mode >> 3) & 7
		} else {
			fmode = st.Mode & 7
		}
	}

	if fmode&mode == mode {
		return nil
	}

	return EACCES
}

//sys	fchmodat(dirfd int, path string, mode uint32) (err error)
//sys	fchmodat2(dirfd int, path string, mode uint32, flags int) (err error) = _SYS_fchmodat2

func Fchmodat(dirfd int, path string, mode uint32, flags int) error {
	// Linux fchmodat doesn't support the flags parameter, but fchmodat2 does.
	// Try fchmodat2 if flags are specified.
	if flags != 0 {
		err := fchmodat2(dirfd, path, mode, flags)
		if err == ENOSYS {
			// fchmodat2 isn't available. If the flags are known to be valid,
			// return EOPNOTSUPP to indicate that fchmodat doesn't support them.
			if flags&^(_AT_SYMLINK_NOFOLLOW|_AT_EMPTY_PATH) != 0 {
				return EINVAL
			} else if flags&(_AT_SYMLINK_NOFOLLOW|_AT_EMPTY_PATH) != 0 {
				return EOPNOTSUPP
			}
		}
		return err
	}
	return fchmodat(dirfd, path, mode)
}

//sys	linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) (err error)

func Link(oldpath string, newpath string) (err error) {
	return linkat(_AT_FDCWD, oldpath, _AT_FDCWD, newpath, 0)
}

func Mkdir(path string, mode uint32) (err error) {
	return Mkdirat(_AT_FDCWD, path, mode)
}

func Mknod(path string, mode uint32, dev int) (err error) {
	return Mknodat(_AT_FDCWD, path, mode, dev)
}

func Open(path string, mode int, perm uint32) (fd int, err error) {
	return openat(_AT_FDCWD, path, mode|O_LARGEFILE, perm)
}

//sys	openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)

func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	return openat(dirfd, path, flags|O_LARGEFILE, mode)
}

func Pipe(p []int) error {
	return Pipe2(p, 0)
}

//sysnb pipe2(p *[2]_C_int, flags int) (err error)

func Pipe2(p []int, flags int) error {
	if len(p) != 2 {
		return EINVAL
	}
	var pp [2]_C_int
	err := pipe2(&pp, flags)
	if err == nil {
		p[0] = int(pp[0])
		p[1] = int(pp[1])
	}
	return err
}

//sys	readlinkat(dirfd int, path string, buf []byte) (n int, err error)

func Readlink(path string, buf []byte) (n int, err error) {
	return readlinkat(_AT_FDCWD, path, buf)
}

func Rename(oldpath string, newpath string) (err error) {
	return Renameat(_AT_FDCWD, oldpath, _AT_FDCWD, newpath)
}

func Rmdir(path string) error {
	return unlinkat(_AT_FDCWD, path, _AT_REMOVEDIR)
}

//sys	symlinkat(oldpath string, newdirfd int, newpath string) (err error)

func Symlink(oldpath string, newpath string) (err error) {
	return symlinkat(oldpath, _AT_FDCWD, newpath)
}

func Unlink(path string) error {
	return unlinkat(_AT_FDCWD, path, 0)
}

//sys	unlinkat(dirfd int, path string, flags int) (err error)

func Unlinkat(dirfd int, path string) error {
	return unlinkat(dirfd, path, 0)
}

func Utimes(path string, tv []Timeval) (err error) {
	if len(tv) != 2 {
		return EINVAL
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flag int) (err error)

func UtimesNano(path string, ts []Timespec) (err error) {
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(_AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

func Futimesat(dirfd int, path string, tv []Timeval) (err error) {
	if len(tv) != 2 {
		return EINVAL
	}
	return futimesat(dirfd, path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func Futimes(fd int, tv []Timeval) (err error) {
	// Believe it or not, this is the best we can do on Linux
	// (and is what glibc does).
	return Utimes("/proc/self/fd/"+itoa.Itoa(fd), tv)
}

const ImplementsGetwd = true

//sys	Getcwd(buf []byte) (n int, err error)

func Getwd() (wd string, err error) {
	var buf [PathMax]byte
	n, err := Getcwd(buf[0:])
	if err != nil {
		return "", err
	}
	// Getcwd returns the number of bytes written to buf, including the NUL.
	if n < 1 || n > len(buf) || buf[n-1] != 0 {
		return "", EINVAL
	}
	// In some cases, Linux can return a path that starts with the
	// "(unreachable)" prefix, which can potentially be a valid relative
	// path. To work around that, return ENOENT if path is not absolute.
	if buf[0] != '/' {
		return "", ENOENT
	}

	return string(buf[0 : n-1]), nil
}

func Getgroups() (gids []int, err error) {
	n, err := getgroups(0, nil)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	// Sanity check group count. Max is 1<<16 on Linux.
	if n < 0 || n > 1<<20 {
		return nil, EINVAL
	}

	a := make([]_Gid_t, n)
	n, err = getgroups(n, &a[0])
	if err != nil {
		return nil, err
	}
	gids = make([]int, n)
	for i, v := range a[0:n] {
		gids[i] = int(v)
	}
	return
}

var cgo_libc_setgroups unsafe.Pointer // non-nil if cgo linked.

func Setgroups(gids []int) (err error) {
	n := uintptr(len(gids))
	if n == 0 {
		if cgo_libc_setgroups == nil {
			if _, _, e1 := AllThreadsSyscall(_SYS_setgroups, 0, 0, 0); e1 != 0 {
				err = errnoErr(e1)
			}
			return
		}
		if ret := cgocaller(cgo_libc_setgroups, 0, 0); ret != 0 {
			err = errnoErr(Errno(ret))
		}
		return
	}

	a := make([]_Gid_t, len(gids))
	for i, v := range gids {
		a[i] = _Gid_t(v)
	}
	if cgo_libc_setgroups == nil {
		if _, _, e1 := AllThreadsSyscall(_SYS_setgroups, n, uintptr(unsafe.Pointer(&a[0])), 0); e1 != 0 {
			err = errnoErr(e1)
		}
		return
	}
	if ret := cgocaller(cgo_libc_setgroups, n, uintptr(unsafe.Pointer(&a[0]))); ret != 0 {
		err = errnoErr(Errno(ret))
	}
	return
}

type WaitStatus uint32

// Wait status is 7 bits at bottom, either 0 (exited),
// 0x7F (stopped), or a signal number that caused an exit.
// The 0x80 bit is whether there was a core dump.
// An extra number (exit code, signal causing a stop)
// is in the high bits. At least that's the idea.
// There are various irregularities. For example, the
// "continued" status is 0xFFFF, distinguishing itself
// from stopped via the core dump bit.

const (
	mask    = 0x7F
	core    = 0x80
	exited  = 0x00
	stopped = 0x7F
	shift   = 8
)

func (w WaitStatus) Exited() bool { return w&mask == exited }

func (w WaitStatus) Signaled() bool { return w&mask != stopped && w&mask != exited }

func (w WaitStatus) Stopped() bool { return w&0xFF == stopped }

func (w WaitStatus) Continued() bool { return w == 0xFFFF }

func (w WaitStatus) CoreDump() bool { return w.Signaled() && w&core != 0 }

func (w WaitStatus) ExitStatus() int {
	if !w.Exited() {
		return -1
	}
	return int(w>>shift) & 0xFF
}

func (w WaitStatus) Signal() Signal {
	if !w.Signaled() {
		return -1
	}
	return Signal(w & mask)
}

func (w WaitStatus) StopSignal() Signal {
	if !w.Stopped() {
		return -1
	}
	return Signal(w>>shift) & 0xFF
}

func (w WaitStatus) TrapCause() int {
	if w.StopSignal() != SIGTRAP {
		return -1
	}
	return int(w>>shift) >> 8
}

//sys	wait4(pid int, wstatus *_C_int, options int, rusage *Rusage) (wpid int, err error)

func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	var status _C_int
	wpid, err = wait4(pid, &status, options, rusage)
	if wstatus != nil {
		*wstatus = WaitStatus(status)
	}
	return
}

func Mkfifo(path string, mode uint32) (err error) {
	return Mknod(path, mode|S_IFIFO, 0)
}

func (sa *SockaddrInet4) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet4, nil
}

func (sa *SockaddrInet6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Port < 0 || sa.Port > 0xFFFF {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_INET6
	p := (*[2]byte)(unsafe.Pointer(&sa.raw.Port))
	p[0] = byte(sa.Port >> 8)
	p[1] = byte(sa.Port)
	sa.raw.Scope_id = sa.ZoneId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrInet6, nil
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n > len(sa.raw.Path) {
		return nil, 0, EINVAL
	}
	if n == len(sa.raw.Path) && name[0] != '@' {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_UNIX
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = int8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := _Socklen(2)
	if n > 0 {
		sl += _Socklen(n) + 1
	}
	if sa.raw.Path[0] == '@' || (sa.raw.Path[0] == 0 && sl > 3) {
		// Check sl > 3 so we don't change unnamed socket behavior.
		sa.raw.Path[0] = 0
		// Don't count trailing NUL for abstract address.
		sl--
	}

	return unsafe.Pointer(&sa.raw), sl, nil
}

type SockaddrLinklayer struct {
	Protocol uint16
	Ifindex  int
	Hatype   uint16
	Pkttype  uint8
	Halen    uint8
	Addr     [8]byte
	raw      RawSockaddrLinklayer
}

func (sa *SockaddrLinklayer) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_PACKET
	sa.raw.Protocol = sa.Protocol
	sa.raw.Ifindex = int32(sa.Ifindex)
	sa.raw.Hatype = sa.Hatype
	sa.raw.Pkttype = sa.Pkttype
	sa.raw.Halen = sa.Halen
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrLinklayer, nil
}

type SockaddrNetlink struct {
	Family uint16
	Pad    uint16
	Pid    uint32
	Groups uint32
	raw    RawSockaddrNetlink
}

func (sa *SockaddrNetlink) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_NETLINK
	sa.raw.Pad = sa.Pad
	sa.raw.Pid = sa.Pid
	sa.raw.Groups = sa.Groups
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNetlink, nil
}

func anyToSockaddr(rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_NETLINK:
		pp := (*RawSockaddrNetlink)(unsafe.Pointer(rsa))
		sa := new(SockaddrNetlink)
		sa.Family = pp.Family
		sa.Pad = pp.Pad
		sa.Pid = pp.Pid
		sa.Groups = pp.Groups
		return sa, nil

	case AF_PACKET:
		pp := (*RawSockaddrLinklayer)(unsafe.Pointer(rsa))
		sa := new(SockaddrLinklayer)
		sa.Protocol = pp.Protocol
		sa.Ifindex = int(pp.Ifindex)
		sa.Hatype = pp.Hatype
		sa.Pkttype = pp.Pkttype
		sa.Halen = pp.Halen
		sa.Addr = pp.Addr
		return sa, nil

	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}

		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		sa.Name = string(unsafe.Slice((*byte)(unsafe.Pointer(&pp.Path[0])), n))
		return sa, nil

	case AF_INET:
		pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.Addr = pp.Addr
		return sa, nil

	case AF_INET6:
		pp := (*RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		sa.Addr = pp.Addr
		return sa, nil
	}
	return nil, EAFNOSUPPORT
}

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	return Accept4(fd, 0)
}

func Accept4(fd int, flags int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept4(fd, &rsa, &len, flags)
	if err != nil {
		return
	}
	if len > SizeofSockaddrAny {
		panic("RawSockaddrAny too small")
	}
	sa, err = anyToSockaddr(&rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

func Getsockname(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getsockname(fd, &rsa, &len); err != nil {
		return
	}
	return anyToSockaddr(&rsa)
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

func GetsockoptIPMreqn(fd, level, opt int) (*IPMreqn, error) {
	var value IPMreqn
	vallen := _Socklen(SizeofIPMreqn)
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

func GetsockoptUcred(fd, level, opt int) (*Ucred, error) {
	var value Ucred
	vallen := _Socklen(SizeofUcred)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func SetsockoptIPMreqn(fd, level, opt int, mreq *IPMreqn) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), unsafe.Sizeof(*mreq))
}

func recvmsgRaw(fd int, p, oob []byte, flags int, rsa *RawSockaddrAny) (n, oobn int, recvflags int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(rsa))
	msg.Namelen = uint32(SizeofSockaddrAny)
	var iov Iovec
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
	}
	var dummy byte
	if len(oob) > 0 {
		if len(p) == 0 {
			var sockType int
			sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
			if err != nil {
				return
			}
			// receive at least one normal byte
			if sockType != SOCK_DGRAM {
				iov.Base = &dummy
				iov.SetLen(1)
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1
	if n, err = recvmsg(fd, &msg, flags); err != nil {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)
	return
}

func sendmsgN(fd int, p, oob []byte, ptr unsafe.Pointer, salen _Socklen, flags int) (n int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(ptr)
	msg.Namelen = uint32(salen)
	var iov Iovec
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
	}
	var dummy byte
	if len(oob) > 0 {
		if len(p) == 0 {
			var sockType int
			sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
			if err != nil {
				return 0, err
			}
			// send at least one normal byte
			if sockType != SOCK_DGRAM {
				iov.Base = &dummy
				iov.SetLen(1)
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	msg.Iov = &iov
	msg.Iovlen = 1
	if n, err = sendmsg(fd, &msg, flags); err != nil {
		return 0, err
	}
	if len(oob) > 0 && len(p) == 0 {
		n = 0
	}
	return n, nil
}

// BindToDevice binds the socket associated with fd to device.
func BindToDevice(fd int, device string) (err error) {
	return SetsockoptString(fd, SOL_SOCKET, SO_BINDTODEVICE, device)
}

//sys	ptrace(request int, pid int, addr uintptr, data uintptr) (err error)
//sys	ptracePtr(request int, pid int, addr uintptr, data unsafe.Pointer) (err error) = SYS_PTRACE

func ptracePeek(req int, pid int, addr uintptr, out []byte) (count int, err error) {
	// The peek requests are machine-size oriented, so we wrap it
	// to retrieve arbitrary-length data.

	// The ptrace syscall differs from glibc's ptrace.
	// Peeks returns the word in *data, not as the return value.

	var buf [sizeofPtr]byte

	// Leading edge. PEEKTEXT/PEEKDATA don't require aligned
	// access (PEEKUSER warns that it might), but if we don't
	// align our reads, we might straddle an unmapped page
	// boundary and not get the bytes leading up to the page
	// boundary.
	n := 0
	if addr%sizeofPtr != 0 {
		err = ptracePtr(req, pid, addr-addr%sizeofPtr, unsafe.Pointer(&buf[0]))
		if err != nil {
			return 0, err
		}
		n += copy(out, buf[addr%sizeofPtr:])
		out = out[n:]
	}

	// Remainder.
	for len(out) > 0 {
		// We use an internal buffer to guarantee alignment.
		// It's not documented if this is necessary, but we're paranoid.
		err = ptracePtr(req, pid, addr+uintptr(n), unsafe.Pointer(&buf[0]))
		if err != nil {
			return n, err
		}
		copied := copy(out, buf[0:])
		n += copied
		out = out[copied:]
	}

	return n, nil
}

func PtracePeekText(pid int, addr uintptr, out []byte) (count int, err error) {
	return ptracePeek(PTRACE_PEEKTEXT, pid, addr, out)
}

func PtracePeekData(pid int, addr uintptr, out []byte) (count int, err error) {
	return ptracePeek(PTRACE_PEEKDATA, pid, addr, out)
}

func ptracePoke(pokeReq int, peekReq int, pid int, addr uintptr, data []byte) (count int, err error) {
	// As for ptracePeek, we need to align our accesses to deal
	// with the possibility of straddling an invalid page.

	// Leading edge.
	n := 0
	if addr%sizeofPtr != 0 {
		var buf [sizeofPtr]byte
		err = ptracePtr(peekReq, pid, addr-addr%sizeofPtr, unsafe.Pointer(&buf[0]))
		if err != nil {
			return 0, err
		}
		n += copy(buf[addr%sizeofPtr:], data)
		word := *((*uintptr)(unsafe.Pointer(&buf[0])))
		err = ptrace(pokeReq, pid, addr-addr%sizeofPtr, word)
		if err != nil {
			return 0, err
		}
		data = data[n:]
	}

	// Interior.
	for len(data) > sizeofPtr {
		word := *((*uintptr)(unsafe.Pointer(&data[0])))
		err = ptrace(pokeReq, pid, addr+uintptr(n), word)
		if err != nil {
			return n, err
		}
		n += sizeofPtr
		data = data[sizeofPtr:]
	}

	// Trailing edge.
	if len(data) > 0 {
		var buf [sizeofPtr]byte
		err = ptracePtr(peekReq, pid, addr+uintptr(n), unsafe.Pointer(&buf[0]))
		if err != nil {
			return n, err
		}
		copy(buf[0:], data)
		word := *((*uintptr)(unsafe.Pointer(&buf[0])))
		err = ptrace(pokeReq, pid, addr+uintptr(n), word)
		if err != nil {
			return n, err
		}
		n += len(data)
	}

	return n, nil
}

func PtracePokeText(pid int, addr uintptr, data []byte) (count int, err error) {
	return ptracePoke(PTRACE_POKETEXT, PTRACE_PEEKTEXT, pid, addr, data)
}

func PtracePokeData(pid int, addr uintptr, data []byte) (count int, err error) {
	return ptracePoke(PTRACE_POKEDATA, PTRACE_PEEKDATA, pid, addr, data)
}

const (
	_NT_PRSTATUS = 1
)

func PtraceGetRegs(pid int, regsout *PtraceRegs) (err error) {
	var iov Iovec
	iov.Base = (*byte)(unsafe.Pointer(regsout))
	iov.SetLen(int(unsafe.Sizeof(*regsout)))
	return ptracePtr(PTRACE_GETREGSET, pid, uintptr(_NT_PRSTATUS), unsafe.Pointer(&iov))
}

func PtraceSetRegs(pid int, regs *PtraceRegs) (err error) {
	var iov Iovec
	iov.Base = (*byte)(unsafe.Pointer(regs))
	iov.SetLen(int(unsafe.Sizeof(*regs)))
	return ptracePtr(PTRACE_SETREGSET, pid, uintptr(_NT_PRSTATUS), unsafe.Pointer(&iov))
}

func PtraceSetOptions(pid int, options int) (err error) {
	return ptrace(PTRACE_SETOPTIONS, pid, 0, uintptr(options))
}

func PtraceGetEventMsg(pid int) (msg uint, err error) {
	var data _C_long
	err = ptracePtr(PTRACE_GETEVENTMSG, pid, 0, unsafe.Pointer(&data))
	msg = uint(data)
	return
}

func PtraceCont(pid int, signal int) (err error) {
	return ptrace(PTRACE_CONT, pid, 0, uintptr(signal))
}

func PtraceSyscall(pid int, signal int) (err error) {
	return ptrace(PTRACE_SYSCALL, pid, 0, uintptr(signal))
}

func PtraceSingleStep(pid int) (err error) { return ptrace(PTRACE_SINGLESTEP, pid, 0, 0) }

func PtraceAttach(pid int) (err error) { return ptrace(PTRACE_ATTACH, pid, 0, 0) }

func PtraceDetach(pid int) (err error) { return ptrace(PTRACE_DETACH, pid, 0, 0) }

//sys	reboot(magic1 uint, magic2 uint, cmd int, arg string) (err error)

func Reboot(cmd int) (err error) {
	return reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, "")
}

func ReadDirent(fd int, buf []byte) (n int, err error) {
	return Getdents(fd, buf)
}

func direntIno(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Ino), unsafe.Sizeof(Dirent{}.Ino))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	reclen, ok := direntReclen(buf)
	if !ok {
		return 0, false
	}
	return reclen - uint64(unsafe.Offsetof(Dirent{}.Name)), true
}

//sys	mount(source string, target string, fstype string, flags uintptr, data *byte) (err error)

func Mount(source string, target string, fstype string, flags uintptr, data string) (err error) {
	// Certain file systems get rather angry and EINVAL if you give
	// them an empty string of data, rather than NULL.
	if data == "" {
		return mount(source, target, fstype, flags, nil)
	}
	datap, err := BytePtrFromString(data)
	if err != nil {
		return err
	}
	return mount(source, target, fstype, flags, datap)
}

// Sendto
// Recvfrom
// Socketpair

/*
 * Direct access
 */
//sys	Acct(path string) (err error)
//sys	Adjtimex(buf *Timex) (state int, err error)
//sys	Chdir(path string) (err error)
//sys	Chroot(path string) (err error)
//sys	Close(fd int) (err error)
//sys	Dup(oldfd int) (fd int, err error)
//sys	Dup3(oldfd int, newfd int, flags int) (err error)
//sysnb	EpollCreate1(flag int) (fd int, err error)
//sysnb	EpollCtl(epfd int, op int, fd int, event *EpollEvent) (err error)
//sys	Fallocate(fd int, mode uint32, off int64, len int64) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	fcntl(fd int, cmd int, arg int) (val int, err error)
//sys	Fdatasync(fd int) (err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fsync(fd int) (err error)
//sys	Getdents(fd int, buf []byte) (n int, err error) = SYS_GETDENTS64
//sysnb	Getpgid(pid int) (pgid int, err error)

func Getpgrp() (pid int) {
	pid, _ = Getpgid(0)
	return
}

//sysnb	Getpid() (pid int)
//sysnb	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (prio int, err error)
//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Gettid() (tid int)
//sys	Getxattr(path string, attr string, dest []byte) (sz int, err error)
//sys	InotifyAddWatch(fd int, pathname string, mask uint32) (watchdesc int, err error)
//sysnb	InotifyInit1(flags int) (fd int, err error)
//sysnb	InotifyRmWatch(fd int, watchdesc uint32) (success int, err error)
//sysnb	Kill(pid int, sig Signal) (err error)
//sys	Klogctl(typ int, buf []byte) (n int, err error) = SYS_SYSLOG
//sys	Listxattr(path string, dest []byte) (sz int, err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mknodat(dirfd int, path string, mode uint32, dev int) (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	PivotRoot(newroot string, putold string) (err error) = SYS_PIVOT_ROOT
//sysnb prlimit1(pid int, resource int, newlimit *Rlimit, old *Rlimit) (err error) = SYS_PRLIMIT64
//sys	read(fd int, p []byte) (n int, err error)
//sys	Removexattr(path string, attr string) (err error)
//sys	Setdomainname(p []byte) (err error)
//sys	Sethostname(p []byte) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tv *Timeval) (err error)

// Provided by runtime.syscall_runtime_doAllThreadsSyscall which stops the
// world and invokes the syscall on each OS thread. Once this function returns,
// all threads are in sync.
//
//go:uintptrescapes
func runtime_doAllThreadsSyscall(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr)

// AllThreadsSyscall performs a syscall on each OS thread of the Go
// runtime. It first invokes the syscall on one thread. Should that
// invocation fail, it returns immediately with the error status.
// Otherwise, it invokes the syscall on all of the remaining threads
// in parallel. It will terminate the program if it observes any
// invoked syscall's return value differs from that of the first
// invocation.
//
// AllThreadsSyscall is intended for emulating simultaneous
// process-wide state changes that require consistently modifying
// per-thread state of the Go runtime.
//
// AllThreadsSyscall is unaware of any threads that are launched
// explicitly by cgo linked code, so the function always returns
// [ENOTSUP] in binaries that use cgo.
//
//go:uintptrescapes
func AllThreadsSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno) {
	if cgo_libc_setegid != nil {
		return minus1, minus1, ENOTSUP
	}
	r1, r2, errno := runtime_doAllThreadsSyscall(trap, a1, a2, a3, 0, 0, 0)
	return r1, r2, Errno(errno)
}

// AllThreadsSyscall6 is like [AllThreadsSyscall], but extended to six
// arguments.
//
//go:uintptrescapes
func AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno) {
	if cgo_libc_setegid != nil {
		return minus1, minus1, ENOTSUP
	}
	r1, r2, errno := runtime_doAllThreadsSyscall(trap, a1, a2, a3, a4, a5, a6)
	return r1, r2, Errno(errno)
}

// linked by runtime.cgocall.go
//
//go:uintptrescapes
func cgocaller(unsafe.Pointer, ...uintptr) uintptr

var cgo_libc_setegid unsafe.Pointer // non-nil if cgo linked.

const minus1 = ^uintptr(0)

func Setegid(egid int) (err error) {
	if cgo_libc_setegid == nil {
		if _, _, e1 := AllThreadsSyscall(SYS_SETRESGID, minus1, uintptr(egid), minus1); e1 != 0 {
			err = errnoErr(e1)
		}
	} else if ret := cgocaller(cgo_libc_setegid, uintptr(egid)); ret != 0 {
		err = errnoErr(Errno(ret))
	}
	return
}

var cgo_libc_seteuid unsafe.Pointer // non-nil if cgo linked.

func Seteuid(euid int) (err error) {
	if cgo_libc_seteuid == nil {
		if _, _, e1 := AllThreadsSyscall(SYS_SETRESUID, minus1, uintptr(euid), minus1); e1 != 0 {
			err = errnoErr(e1)
		}
	} else if ret := cgocaller(cgo_libc_seteuid, uintptr(euid)); ret != 0 {
		err = errnoErr(Errno(ret))
	}
	return
}

var cgo_libc_setgid unsafe.Pointer // non-nil if cgo linked.

func Setgid(gid int) (err error) {
	if cgo_libc_setgid == nil {
		if _, _, e1 := AllThreadsSyscall(sys_SETGID, uintptr(gid), 0, 0); e1 != 0 {
			err = errnoErr(e1)
		}
	} else if ret := cgocaller(cgo_libc_setgid, uintptr(gid)); ret != 0 {
		err = errnoErr(Errno(ret)
"""




```