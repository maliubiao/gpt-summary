Response:
Let's break down the thought process for analyzing this Go file and generating the response.

**1. Understanding the Goal:**

The core request is to analyze the provided Go code (`syscall_aix.go`) and explain its purpose, provide examples, and highlight potential pitfalls. The key is to identify the functionalities and their relationship to the underlying operating system (AIX in this case).

**2. Initial Scan and Keyword Recognition:**

My first step is a quick scan of the code, looking for obvious keywords and patterns:

* **`package syscall`:**  This immediately tells me it's about interacting with the operating system's system calls.
* **`//sys` comments:** These are crucial. They indicate direct system call bindings, likely used by `mksyscall`.
* **`func Syscall`, `func RawSyscall`:** These are low-level functions for making system calls.
* **Constant definitions (e.g., `TIOCSCTTY`, `SYS_EXECVE`):**  These represent system call numbers or flags.
* **Function names like `Access`, `Pipe`, `Readlink`, `Utimes`:** These suggest higher-level wrappers around system calls, providing a more Go-like interface.
* **Struct definitions (e.g., `StTimespec_t`, `Dirent`):** These represent data structures used in system calls.
* **Socket-related functions (`bind`, `connect`, `accept`, `sendto`, `recvfrom`):**  Indicates network functionality.
* **Ptrace-related functions (`PtracePeekText`, `PtracePokeData`):**  Suggests debugging and process control capabilities.
* **Wait-related structures and functions (`WaitStatus`, `Wait4`):**  Deals with process lifecycle management.
* **Mmap-related functions (`Mmap`, `Munmap`):**  Indicates memory mapping capabilities.
* **Error handling (`err Errno`):**  A standard Go pattern for indicating errors.

**3. Grouping and Categorizing Functionality:**

Based on the keywords and function names, I start grouping related code blocks:

* **Low-level syscalls:** `Syscall`, `RawSyscall`, `rawSyscall6`, `syscall6`.
* **System call wrappers:** Functions like `Access`, `Pipe`, `Readlink`, `Utimes`, etc., which use the `//sys` directives.
* **File system operations:**  `Access`, `Open`, `Readlink`, `Unlinkat`, `Mkdir`, `Rmdir`, `Rename`, `Stat`, `Fstat`, `Truncate`.
* **Process management:** `Wait4`, `Kill`, `Getpid`, `Getppid`, `Setpgid`.
* **Networking:** `socket`, `bind`, `connect`, `listen`, `accept`, `sendto`, `recvfrom`, `getsockopt`, `setsockopt`.
* **Memory management:** `Mmap`, `Munmap`.
* **Ptrace (debugging):** `PtraceAttach`, `PtraceDetach`, `PtracePeekText`, `PtracePokeData`, `PtraceCont`.
* **Time-related:** `Utimes`, `UtimesNano`, `Gettimeofday`.
* **User and Group IDs:** `Getuid`, `Getgid`, `Setuid`, `Setgid`, `Getgroups`, `Setgroups`.

**4. Analyzing `//sys` Directives:**

The `//sys` comments are the most direct link to the system calls. I look for patterns:

* `//sys fcntl(...)`:  This indicates a direct binding to the `fcntl` system call. The comments about `F_DUP2FD` being problematic on AIX are important for understanding potential issues.
* `//sys pipe(...)`: Binding to the `pipe` system call.
* `//sys readlink(...)`: Binding to `readlink`.
* And so on...

**5. Inferring Go Functionality:**

By looking at the wrappers around the `//sys` calls, I can infer the corresponding Go functionalities:

* `Access` -> Checking file accessibility.
* `Pipe` -> Creating a pipe for inter-process communication.
* `Readlink` -> Reading the target of a symbolic link.
* `Utimes` and `UtimesNano` -> Modifying file access and modification times.
* `Getwd` -> Getting the current working directory.
* `Socket` and related functions -> The `net` package's underlying implementation for network operations.
* `Wait4` -> The `os/exec` and `os` packages' implementation for waiting for child processes.
* `Mmap` and `Munmap` -> The `os` package's memory mapping functionality.
* `Ptrace` functions -> The `syscall` package's (and potentially `debug/gosym`'s) support for debugging.

**6. Crafting Examples:**

Once I understand the functionality, I create simple, illustrative Go code examples. These examples should be:

* **Concise:** Easy to understand.
* **Relevant:** Directly demonstrate the functionality being explained.
* **Correct:**  Use the correct function names and parameters.
* **Include assumptions/inputs/outputs:**  This helps clarify how the code works.

**7. Identifying Potential Pitfalls:**

This requires looking for edge cases, platform-specific limitations, and common mistakes:

* **`fcntl` and `F_DUP2FD`:** The comment directly points to this.
* **`AF_LOCAL` constant:**  The code explicitly notes its absence on AIX. This is important for socket programming.
* **`getgroups` limit:**  The code has a sanity check on the number of groups, indicating a potential limitation.
* **`getsockname` bug:** The comment highlights a potential issue with AIX's `getsockname` implementation.
* **Error handling:**  Emphasizing the importance of checking the `err` return value is crucial.

**8. Structuring the Response:**

Finally, I organize the information logically:

* **Overall Purpose:** Start with a high-level summary.
* **Key Functionalities:**  List and describe the major categories of functions.
* **Go Feature Implementation (with Examples):**  Connect the code to higher-level Go features and provide illustrative examples with assumptions and outputs.
* **Command-Line Arguments:**  Note if any of the functions directly process command-line arguments (in this case, not really).
* **Common Mistakes:** List and explain potential errors users might make.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This is just low-level system call stuff."  **Correction:** Realize the presence of wrappers and the connection to higher-level Go features.
* **Wondering about `//sysnb`:** Research or recall that `nb` likely means "no blocking," often for system calls that could potentially block.
* **Realizing the need for context:** The comments within the code are essential for understanding *why* certain things are done (e.g., the `fcntl` workaround).
* **Ensuring clarity in examples:**  Make sure the examples are not too complex and clearly demonstrate the intended functionality.

By following these steps, combining code analysis with knowledge of operating system concepts and Go programming, I can arrive at a comprehensive and informative answer like the example provided in the prompt.
这个 `go/src/syscall/syscall_aix.go` 文件是 Go 语言标准库 `syscall` 包在 AIX 操作系统上的实现部分。它的主要功能是提供 Go 程序与 AIX 操作系统底层系统调用交互的接口。

以下是该文件中的主要功能点：

**1. 系统调用原始接口:**

*   定义了 `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6` 这四个函数，它们是 Go 程序进行系统调用的最底层入口。
    *   `Syscall` 和 `Syscall6` 内部可能会进行一些处理，例如检查错误码等。
    *   `RawSyscall` 和 `RawSyscall6` 则更直接地调用系统调用，不进行额外的处理。
*   定义了 `rawSyscall6` 和 `syscall6` 这两个在运行时 (runtime) 包中实现的函数，它们是实际执行系统调用的底层函数。

**2. 系统调用号常量:**

*   定义了一些系统调用号常量，例如 `SYS_EXECVE`, `SYS_FCNTL`。这些常量用于在调用底层系统调用函数时指定要执行的具体系统调用。

**3. 常量定义:**

*   定义了一些与 AIX 相关的常量，例如 `F_DUPFD_CLOEXEC`, `AF_LOCAL` (注意这里指出 AIX 上不存在 `AF_LOCAL`，而是使用 `AF_UNIX`)。

**4. 时间相关结构体方法:**

*   为 `StTimespec_t` 结构体定义了 `Unix()` 和 `Nano()` 方法，用于将该结构体表示的时间转换为 Unix 时间戳（秒和纳秒）。

**5. 系统调用封装 (Wrappers):**

*   提供了一系列 Go 函数，作为对底层系统调用的封装，提供了更方便、更符合 Go 语言习惯的接口。这些封装函数通常会处理错误，并将系统调用返回值转换为 Go 语言的类型。
    *   例如，`Access` 函数封装了 `Faccessat` 系统调用，用于检查文件的访问权限。
    *   `Pipe` 函数封装了 `pipe` 系统调用，用于创建一个管道。
    *   `Readlink` 函数封装了 `readlink` 系统调用，用于读取符号链接的目标。
    *   `Utimes` 和 `UtimesNano` 函数封装了修改文件访问和修改时间的系统调用。
    *   `Getwd` 函数封装了 `getcwd` 系统调用，用于获取当前工作目录。
    *   与套接字 (Socket) 相关的 `bind`, `connect`, `listen`, `accept`, `sendto`, `recvfrom` 等函数。
    *   与进程管理相关的 `Wait4` 函数。
    *   与 `ptrace` 相关的函数，用于进程调试。

**6. 特定的系统调用处理和兼容性处理:**

*   **`fcntl` 函数的特殊处理:** 注释指出 AIX 上 `fcntl` 不能使用 `F_DUP2FD` 命令，因此直接使用了 `Dup2` 系统调用来替代。这体现了针对 AIX 平台的特殊处理。
*   **`getgroups` 的限制:** 代码中对 `getgroups` 返回的组数量进行了检查，限制在 1000 以内，这可能是 AIX 平台的一个限制。
*   **`getsockname` 的问题:** 代码注释提到某些版本的 AIX 在 `getsockname` 中存在 bug，可能导致 `sa.Len` 未正确设置，因此在 `getLen` 方法中进行了特殊处理。
*   **`sendfile` 的占位:**  `sendfile` 函数直接返回 `ENOSYS`，表示该系统调用在 AIX 上未实现或者暂未支持。

**7. 辅助函数和结构体:**

*   定义了一些辅助函数，例如 `direntIno`, `direntReclen`, `direntNamlen` 用于解析目录项 (`Dirent`) 结构。
*   定义了用于表示系统调用参数和返回值的结构体，例如 `Timeval`, `Timespec`, `Stat_t`, `Rusage`, `RawSockaddrAny` 等。
*   定义了 `WaitStatus` 类型及其相关方法，用于解析 `wait4` 系统调用的状态返回值。
*   定义了 `mmapper` 结构体和 `Mmap`, `Munmap` 函数，用于内存映射。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言标准库 `syscall` 包在 AIX 操作系统上的底层实现。`syscall` 包是 Go 语言提供操作系统底层接口的核心包，它允许 Go 程序执行诸如文件操作、进程管理、网络编程等需要与操作系统内核交互的操作。

**Go 代码举例说明:**

以下是一些使用 `syscall` 包（依赖于 `syscall_aix.go` 的实现）的 Go 代码示例：

**示例 1: 文件访问检查**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	path := "/tmp/test.txt" // 假设存在这个文件

	// 检查文件是否存在且可读
	err := syscall.Access(path, syscall.R_OK)
	if err == nil {
		fmt.Printf("文件 %s 存在且可读\n", path)
	} else {
		fmt.Printf("文件 %s 不可读或不存在: %v\n", path, err)
	}

	// 检查文件是否可写
	err = syscall.Access(path, syscall.W_OK)
	if err == nil {
		fmt.Printf("文件 %s 可写\n", path)
	} else {
		fmt.Printf("文件 %s 不可写: %v\n", path, err)
	}
}

// 假设输入：/tmp/test.txt 文件存在且具有读写权限
// 预期输出：
// 文件 /tmp/test.txt 存在且可读
// 文件 /tmp/test.txt 可写

// 假设输入：/tmp/test.txt 文件不存在
// 预期输出：
// 文件 /tmp/test.txt 不可读或不存在: no such file or directory
// 文件 /tmp/test.txt 不可写: no such file or directory
```

**示例 2: 创建和使用管道**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	fds := make([]int, 2)
	err := syscall.Pipe(fds)
	if err != nil {
		fmt.Printf("创建管道失败: %v\n", err)
		return
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	// 向管道写入数据
	message := "Hello from pipe!"
	buf := unsafe.Slice(unsafe.StringData(message), len(message))
	n, err := syscall.Write(fds[1], buf)
	if err != nil {
		fmt.Printf("写入管道失败: %v\n", err)
		return
	}
	fmt.Printf("写入了 %d 字节到管道\n", n)

	// 从管道读取数据
	readBuf := make([]byte, 100)
	n, err = syscall.Read(fds[0], readBuf)
	if err != nil {
		fmt.Printf("从管道读取失败: %v\n", err)
		return
	}
	fmt.Printf("从管道读取了 %d 字节: %s\n", n, string(readBuf[:n]))
}

// 假设输入：无
// 预期输出：
// 写入了 16 字节到管道
// 从管道读取了 16 字节: Hello from pipe!
```

**示例 3: 获取当前工作目录**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	wd, err := syscall.Getwd()
	if err != nil {
		fmt.Printf("获取当前工作目录失败: %v\n", err)
		return
	}
	fmt.Printf("当前工作目录: %s\n", wd)
}

// 假设输入：当前工作目录为 /home/user
// 预期输出：
// 当前工作目录: /home/user
```

**命令行参数处理:**

这个文件本身并没有直接处理命令行参数的功能。命令行参数的处理通常发生在 `main` 函数中，或者通过 `flag` 等标准库包进行。`syscall` 包提供的功能是与操作系统进行交互，而不是解析程序的输入。

**使用者易犯错的点:**

1. **错误处理:**  调用 `syscall` 包中的函数时，务必检查返回的 `error` 值。系统调用失败是很常见的，如果没有正确处理错误，可能会导致程序崩溃或行为异常。

    ```go
    fd, err := syscall.Open("/nonexistent_file", syscall.O_RDONLY, 0)
    if err != nil {
        fmt.Println("打开文件失败:", err) // 正确处理错误
        // ...
    }
    defer syscall.Close(fd) // 即使打开失败，也应该确保资源清理
    ```

2. **平台差异:**  `syscall` 包的实现是平台相关的。在 AIX 上运行的代码可能无法在 Linux 或 Windows 上直接运行，反之亦然。需要注意不同平台系统调用的差异和常量定义的不同。例如，代码中明确指出了 `AF_LOCAL` 在 AIX 上不存在。

3. **理解系统调用语义:**  使用 `syscall` 包需要对底层的操作系统概念和系统调用有一定的了解。例如，了解文件描述符、权限、信号等概念。不理解系统调用的行为可能导致不正确的用法。

4. **不安全的指针操作:**  `syscall` 包中经常涉及到 `unsafe.Pointer` 的使用，这需要非常小心。错误的指针操作可能导致内存错误甚至程序崩溃。

5. **缓冲区大小:**  在使用需要缓冲区的系统调用（例如 `readlink`, `getcwd`）时，需要正确管理缓冲区的大小，避免缓冲区溢出或读取不足。例如 `Getwd` 函数的实现就展示了如何动态调整缓冲区大小来获取完整路径。

6. **`fcntl` 的 AIX 特性:**  正如代码中注释所说，直接使用 `fcntl` 的 `F_DUP2FD` 在 AIX 上是不可靠的。使用者需要了解这些平台特定的限制，并采取相应的替代方案（如使用 `Dup2`）。

总而言之，`go/src/syscall/syscall_aix.go` 是 Go 语言连接 AIX 操作系统内核的桥梁，它提供了执行底层操作的能力，但也要求使用者具备一定的操作系统知识并谨慎处理错误。

Prompt: 
```
这是路径为go/src/syscall/syscall_aix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Aix system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and
// wrap it in our own nicer implementation.

package syscall

import (
	"unsafe"
)

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)

// Implemented in runtime/syscall_aix.go.
func rawSyscall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func syscall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)

// Constant expected by package but not supported
const (
	_ = iota
	TIOCSCTTY
	SYS_EXECVE
	SYS_FCNTL
)

const (
	F_DUPFD_CLOEXEC = 0
	// AF_LOCAL doesn't exist on AIX
	AF_LOCAL = AF_UNIX

	_F_DUP2FD_CLOEXEC = 0
)

func (ts *StTimespec_t) Unix() (sec int64, nsec int64) {
	return int64(ts.Sec), int64(ts.Nsec)
}

func (ts *StTimespec_t) Nano() int64 {
	return int64(ts.Sec)*1e9 + int64(ts.Nsec)
}

/*
 * Wrapped
 */

func Access(path string, mode uint32) (err error) {
	return Faccessat(_AT_FDCWD, path, mode, 0)
}

// fcntl must never be called with cmd=F_DUP2FD because it doesn't work on AIX
// There is no way to create a custom fcntl and to keep //sys fcntl easily,
// because we need fcntl name for its libc symbol. This is linked with the script.
// But, as fcntl is currently not exported and isn't called with F_DUP2FD,
// it doesn't matter.
//sys	fcntl(fd int, cmd int, arg int) (val int, err error)
//sys	Dup2(old int, new int) (err error)

//sysnb pipe(p *[2]_C_int) (err error)

func Pipe(p []int) (err error) {
	if len(p) != 2 {
		return EINVAL
	}
	var pp [2]_C_int
	err = pipe(&pp)
	if err == nil {
		p[0] = int(pp[0])
		p[1] = int(pp[1])
	}
	return
}

//sys	readlink(path string, buf []byte, bufSize uint64) (n int, err error)

func Readlink(path string, buf []byte) (n int, err error) {
	s := uint64(len(buf))
	return readlink(path, buf, s)
}

//sys	utimes(path string, times *[2]Timeval) (err error)

func Utimes(path string, tv []Timeval) error {
	if len(tv) != 2 {
		return EINVAL
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flag int) (err error)

func UtimesNano(path string, ts []Timespec) error {
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(_AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

//sys	unlinkat(dirfd int, path string, flags int) (err error)

func Unlinkat(dirfd int, path string) (err error) {
	return unlinkat(dirfd, path, 0)
}

//sys	getcwd(buf *byte, size uint64) (err error)

const ImplementsGetwd = true

func Getwd() (ret string, err error) {
	for len := uint64(4096); ; len *= 2 {
		b := make([]byte, len)
		err := getcwd(&b[0], len)
		if err == nil {
			n := clen(b[:])
			if n < 1 {
				return "", EINVAL
			}
			return string(b[:n]), nil
		}
		if err != ERANGE {
			return "", err
		}
	}
}

func Getcwd(buf []byte) (n int, err error) {
	err = getcwd(&buf[0], uint64(len(buf)))
	if err == nil {
		i := 0
		for buf[i] != 0 {
			i++
		}
		n = i + 1
	}
	return
}

//sysnb	getgroups(ngid int, gid *_Gid_t) (n int, err error)
//sysnb	setgroups(ngid int, gid *_Gid_t) (err error)

func Getgroups() (gids []int, err error) {
	n, err := getgroups(0, nil)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	// Sanity check group count. Max is 16 on BSD.
	if n < 0 || n > 1000 {
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

func Setgroups(gids []int) (err error) {
	if len(gids) == 0 {
		return setgroups(0, nil)
	}

	a := make([]_Gid_t, len(gids))
	for i, v := range gids {
		a[i] = _Gid_t(v)
	}
	return setgroups(len(a), &a[0])
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

func Gettimeofday(tv *Timeval) (err error) {
	err = gettimeofday(tv, nil)
	return
}

// TODO
func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	return -1, ENOSYS
}

//sys	getdirent(fd int, buf []byte) (n int, err error)

func ReadDirent(fd int, buf []byte) (n int, err error) {
	return getdirent(fd, buf)
}

//sys  wait4(pid _Pid_t, status *_C_int, options int, rusage *Rusage) (wpid _Pid_t, err error)

func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (wpid int, err error) {
	var status _C_int
	var r _Pid_t
	err = ERESTART
	// AIX wait4 may return with ERESTART errno, while the process is still
	// active.
	for err == ERESTART {
		r, err = wait4(_Pid_t(pid), &status, options, rusage)
	}
	wpid = int(r)
	if wstatus != nil {
		*wstatus = WaitStatus(status)
	}
	return
}

//sys	fsyncRange(fd int, how int, start int64, length int64) (err error) = fsync_range

func Fsync(fd int) error {
	return fsyncRange(fd, O_SYNC, 0, 0)
}

/*
 * Socket
 */
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys   Getkerninfo(op int32, where uintptr, size uintptr, arg int64) (i int32, err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
//sys	Listen(s int, backlog int) (err error)
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
//sys	socket(domain int, typ int, proto int) (fd int, err error)
//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error)
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sys	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error)
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error)
//sys	Shutdown(s int, how int) (err error)

// In order to use msghdr structure with Control, Controllen in golang.org/x/net,
// nrecvmsg and nsendmsg must be used.
//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error) = nrecvmsg
//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error) = nsendmsg

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

func (sa *RawSockaddrUnix) setLen(n int) {
	sa.Len = uint8(3 + n) // 2 for Family, Len; 1 for NUL.
}

func (sa *SockaddrUnix) sockaddr() (unsafe.Pointer, _Socklen, error) {
	name := sa.Name
	n := len(name)
	if n > len(sa.raw.Path) {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_UNIX
	sa.raw.setLen(n)
	for i := 0; i < n; i++ {
		sa.raw.Path[i] = uint8(name[i])
	}
	// length is family (uint16), name, NUL.
	sl := _Socklen(2)
	if n > 0 {
		sl += _Socklen(n) + 1
	}

	return unsafe.Pointer(&sa.raw), sl, nil
}

func Getsockname(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getsockname(fd, &rsa, &len); err != nil {
		return
	}
	return anyToSockaddr(&rsa)
}

//sys	accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error)

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept(fd, &rsa, &len)
	if err != nil {
		return
	}
	sa, err = anyToSockaddr(&rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
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
		var sockType int
		sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
		if err != nil {
			return
		}
		// receive at least one normal byte
		if sockType != SOCK_DGRAM && len(p) == 0 {
			iov.Base = &dummy
			iov.SetLen(1)
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
		var sockType int
		sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
		if err != nil {
			return 0, err
		}
		// send at least one normal byte
		if sockType != SOCK_DGRAM && len(p) == 0 {
			iov.Base = &dummy
			iov.SetLen(1)
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

func (sa *RawSockaddrUnix) getLen() (int, error) {
	// Some versions of AIX have a bug in getsockname (see IV78655).
	// We can't rely on sa.Len being set correctly.
	n := SizeofSockaddrUnix - 3 // subtract leading Family, Len, terminating NUL.
	for i := 0; i < n; i++ {
		if sa.Path[i] == 0 {
			n = i
			break
		}
	}
	return n, nil
}

func anyToSockaddr(rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)
		n, err := pp.getLen()
		if err != nil {
			return nil, err
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
		sa.Addr = pp.Addr
		return sa, nil
	}
	return nil, EAFNOSUPPORT
}

type SockaddrDatalink struct {
	Len    uint8
	Family uint8
	Index  uint16
	Type   uint8
	Nlen   uint8
	Alen   uint8
	Slen   uint8
	Data   [120]uint8
	raw    RawSockaddrDatalink
}

/*
 * Wait
 */

type WaitStatus uint32

func (w WaitStatus) Stopped() bool { return w&0x40 != 0 }
func (w WaitStatus) StopSignal() Signal {
	if !w.Stopped() {
		return -1
	}
	return Signal(w>>8) & 0xFF
}

func (w WaitStatus) Exited() bool { return w&0xFF == 0 }
func (w WaitStatus) ExitStatus() int {
	if !w.Exited() {
		return -1
	}
	return int((w >> 8) & 0xFF)
}

func (w WaitStatus) Signaled() bool { return w&0x40 == 0 && w&0xFF != 0 }
func (w WaitStatus) Signal() Signal {
	if !w.Signaled() {
		return -1
	}
	return Signal(w>>16) & 0xFF
}

func (w WaitStatus) Continued() bool { return w&0x01000000 != 0 }

func (w WaitStatus) CoreDump() bool { return w&0x80 == 0x80 }

func (w WaitStatus) TrapCause() int { return -1 }

/*
 * ptrace
 */

//sys	Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)
//sys	ptrace64(request int, id int64, addr int64, data int, buff uintptr) (err error)
//sys	ptrace64Ptr(request int, id int64, addr int64, data int, buff unsafe.Pointer) (err error) = ptrace64

func raw_ptrace(request int, pid int, addr *byte, data *byte) Errno {
	if request == PTRACE_TRACEME {
		// Convert to AIX ptrace call.
		err := ptrace64(PT_TRACE_ME, 0, 0, 0, 0)
		if err != nil {
			return err.(Errno)
		}
		return 0
	}
	return ENOSYS
}

func ptracePeek(pid int, addr uintptr, out []byte) (count int, err error) {
	n := 0
	for len(out) > 0 {
		bsize := len(out)
		if bsize > 1024 {
			bsize = 1024
		}
		err = ptrace64Ptr(PT_READ_BLOCK, int64(pid), int64(addr), bsize, unsafe.Pointer(&out[0]))
		if err != nil {
			return 0, err
		}
		addr += uintptr(bsize)
		n += bsize
		out = out[n:]
	}
	return n, nil
}

func PtracePeekText(pid int, addr uintptr, out []byte) (count int, err error) {
	return ptracePeek(pid, addr, out)
}

func PtracePeekData(pid int, addr uintptr, out []byte) (count int, err error) {
	return ptracePeek(pid, addr, out)
}

func ptracePoke(pid int, addr uintptr, data []byte) (count int, err error) {
	n := 0
	for len(data) > 0 {
		bsize := len(data)
		if bsize > 1024 {
			bsize = 1024
		}
		err = ptrace64Ptr(PT_WRITE_BLOCK, int64(pid), int64(addr), bsize, unsafe.Pointer(&data[0]))
		if err != nil {
			return 0, err
		}
		addr += uintptr(bsize)
		n += bsize
		data = data[n:]
	}
	return n, nil
}

func PtracePokeText(pid int, addr uintptr, data []byte) (count int, err error) {
	return ptracePoke(pid, addr, data)
}

func PtracePokeData(pid int, addr uintptr, data []byte) (count int, err error) {
	return ptracePoke(pid, addr, data)
}

func PtraceCont(pid int, signal int) (err error) {
	return ptrace64(PT_CONTINUE, int64(pid), 1, signal, 0)
}

func PtraceSingleStep(pid int) (err error) { return ptrace64(PT_STEP, int64(pid), 1, 0, 0) }

func PtraceAttach(pid int) (err error) { return ptrace64(PT_ATTACH, int64(pid), 0, 0, 0) }

func PtraceDetach(pid int) (err error) { return ptrace64(PT_DETACH, int64(pid), 0, 0, 0) }

/*
 * Direct access
 */

//sys	Acct(path string) (err error)
//sys	Chdir(path string) (err error)
//sys	Chmod(path string, mode uint32) (err error)
//sys	Chown(path string, uid int, gid int) (err error)
//sys	Chroot(path string) (err error)
//sys	Close(fd int) (err error)
//sys	Dup(fd int) (nfd int, err error)
//sys	Faccessat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchmodat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	Fpathconf(fd int, name int) (val int, err error)
//sys	Fstat(fd int, stat *Stat_t) (err error)
//sys	Fstatfs(fd int, buf *Statfs_t) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sysnb	Getgid() (gid int)
//sysnb	Getpid() (pid int)
//sys	Geteuid() (euid int)
//sys	Getegid() (egid int)
//sys	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (n int, err error)
//sysnb	Getrlimit(which int, lim *Rlimit) (err error)
//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Getuid() (uid int)
//sys	Kill(pid int, signum Signal) (err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Lstat(path string, stat *Stat_t) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mknodat(dirfd int, path string, mode uint32, dev int) (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error)
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Reboot(how int) (err error)
//sys	Rename(from string, to string) (err error)
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)
//sys	Rmdir(path string) (err error)
//sys	Seek(fd int, offset int64, whence int) (newoffset int64, err error) = lseek
//sysnb	Setegid(egid int) (err error)
//sysnb	Seteuid(euid int) (err error)
//sysnb	Setgid(gid int) (err error)
//sysnb	Setuid(uid int) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	setrlimit(which int, lim *Rlimit) (err error)
//sys	Stat(path string, stat *Stat_t) (err error)
//sys	Statfs(path string, buf *Statfs_t) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Umask(newmask int) (oldmask int)
//sys	Unlink(path string) (err error)
//sysnb	Uname(buf *Utsname) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys	writev(fd int, iovecs []Iovec) (n uintptr, err error)

//sys	gettimeofday(tv *Timeval, tzp *Timezone) (err error)

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: sec, Usec: int32(usec)}
}

func readlen(fd int, buf *byte, nbuf int) (n int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_read)), 3, uintptr(fd), uintptr(unsafe.Pointer(buf)), uintptr(nbuf), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

/*
 * Map
 */

var mapper = &mmapper{
	active: make(map[*byte][]byte),
	mmap:   mmap,
	munmap: munmap,
}

//sys	mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys	munmap(addr uintptr, length uintptr) (err error)

func Mmap(fd int, offset int64, length int, prot int, flags int) (data []byte, err error) {
	return mapper.Mmap(fd, offset, length, prot, flags)
}

func Munmap(b []byte) (err error) {
	return mapper.Munmap(b)
}

"""



```