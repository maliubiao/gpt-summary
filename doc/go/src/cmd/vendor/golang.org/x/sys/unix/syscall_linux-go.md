Response:
Let's break down the thought process for analyzing the provided Go code snippet and answering the request.

**1. Understanding the Goal:**

The core request is to understand the functionality of a specific Go file (`syscall_linux.go`) within the `golang.org/x/sys/unix` package. The prompt emphasizes identifying the implemented Go language features, providing examples, explaining any command-line parameter handling (less relevant here), noting potential errors, and summarizing the overall functionality.

**2. Initial Scan and Keyword Spotting:**

The first step is a quick scan of the code, looking for keywords and patterns:

* **`package unix`:**  Indicates this code is part of the `unix` package, likely providing low-level system call interfaces.
* **`//sys` comments:** These are crucial. They signal direct system call bindings, often with lowercase names and wrapper functions. This immediately tells us a major function is bridging Go code to Linux kernel system calls.
* **Function names like `Access`, `Chmod`, `Open`, `Readlink`, etc.:** These strongly suggest file system operations.
* **Function names like `EpollCreate`, `Poll`, `Ppoll`:** These point towards I/O multiplexing and event handling.
* **Function names like `Pipe`, `Pipe2`:** Indicate inter-process communication mechanisms.
* **Function names like `Getwd`, `Getgroups`, `Setgroups`:** Suggest process and user management.
* **Function names like `Wait4`, `Waitid`:**  Relate to process lifecycle and status.
* **Structures and methods related to `Sockaddr...`:**  Clearly involve network socket address handling.
* **Function names like `Ptrace...`:** Indicate process tracing and debugging capabilities.
* **Function names like `Keyctl...`:** Suggest interaction with the Linux kernel keyring.
* **Function names like `Mount`, `MountSetattr`:** Point to file system mounting operations.

**3. Categorizing Functionality:**

Based on the keyword spotting, we can start grouping functions into logical categories:

* **File System Operations:**  `Access`, `Chmod`, `Chown`, `Creat`, `Open`, `Readlink`, `Rename`, `Rmdir`, `Link`, `Symlink`, `Unlink`, `Utimes`, `Mkdir`, `Mknod`, `Mkfifo`. The presence of `...at` variants (e.g., `Fchmodat`, `Openat`) suggests path resolution relative to file descriptors.
* **I/O Multiplexing/Event Handling:** `EpollCreate`, `Poll`, `Ppoll`, `InotifyInit`, `FanotifyInit`.
* **Inter-Process Communication:** `Pipe`, `Pipe2`.
* **Process Management:** `Wait4`, `Waitid`, `Getwd`, `Getgroups`, `Setgroups`.
* **Socket Handling:** The extensive `Sockaddr...` structures and related functions for converting them to raw sockaddr pointers. This implies support for various socket families (INET, INET6, UNIX, PACKET, NETLINK, etc.). Functions like `Accept`, `Accept4`, `Getsockname`, `Getsockopt...`, `Setsockopt...`, `BindToDevice`.
* **Process Tracing and Debugging:** `Ptrace...`.
* **Kernel Keyring Management:** `Keyctl...`.
* **File System Mounting:** `Mount`, `MountSetattr`.
* **Other System Calls:**  A collection of more specialized system calls like `Acct`, `Adjtimex`, `Capget`, `Capset`, `Chroot`, `Clock...`, `Close`, `Dup`, `Exit`, `Fallocate`, `Fdatasync`, `Fsync`, `Getrandom`, `Kill`, `Klogctl`, `MemfdCreate`, `Nanosleep`, `Prctl`, `Reboot`, `Sendfile`, etc.

**4. Analyzing Specific Function Implementations (Wrapper Functions and Direct Syscalls):**

* **Wrapper Functions:** Notice the pattern where functions like `Access(path string, mode uint32)` call the `Faccessat` function with `AT_FDCWD`. This indicates the provided code offers higher-level, more convenient wrappers around lower-level system calls. The `AT_FDCWD` usage implies operating relative to the current working directory.
* **Direct Syscalls:** The `//sys` comments mark direct bindings to Linux system calls. For example, `//sys	FanotifyInit(flags uint, event_f_flags uint) (fd int, err error)`. The Go tool `mksyscall` (mentioned in the comments) likely generates the necessary low-level glue code.

**5. Identifying Go Language Features:**

* **Functions:** The core building blocks.
* **Error Handling:** The consistent `(ret ... , err error)` return pattern.
* **Strings:** Used for paths and other text-based arguments.
* **Slices (`[]byte`, `[]int`, `[]PollFd`, etc.):** Used for buffers and collections.
* **Structs:** Used to represent data structures like `Timespec`, `PollFd`, `Sockaddr...`, `Rusage`, `WaitStatus`, etc.
* **Pointers (`*Timespec`, `unsafe.Pointer`):** Necessary for interacting with low-level system calls that often require memory addresses. The `unsafe` package is used for direct memory manipulation, highlighting the low-level nature of this code.
* **Constants:**  Like `AT_FDCWD`, `O_CREAT`, `SIGTRAP`, etc., representing system-defined values.
* **Method Receivers:**  Used to add methods to types like `WaitStatus` and `Sockaddr...`.
* **Comments:**  Used to document the code and provide directives to `mksyscall`.

**6. Developing Examples and Hypothetical Inputs/Outputs:**

For key functionalities, craft simple Go code examples:

* **File System:** `unix.Access("myfile.txt", unix.R_OK)` (checking read permission). Hypothetical Input: "myfile.txt" exists and is readable. Output: `nil` (no error).
* **Sockets:**  Demonstrate creating a socket, binding, and listening using `unix.Socket`, `unix.Bind`, and `unix.Listen`. Show how to create a `unix.SockaddrInet4`.
* **Pipes:**  Illustrate creating a pipe with `unix.Pipe`.

**7. Considering Potential Errors:**

Look for common error scenarios:

* **Invalid arguments:**  Passing incorrect values for `mode`, `flags`, etc. (e.g., `EpollCreate(0)`).
* **File not found/permissions issues:** Errors when accessing files.
* **Socket binding errors:** Address already in use.
* **Incorrect buffer sizes:** When reading from or writing to files or sockets.
* **Type mismatches with `ioctl`:** The code itself mentions this as a potential issue.

**8. Summarizing Functionality:**

Synthesize the findings into a concise summary, emphasizing the key purposes of the file: providing Go interfaces to Linux system calls for file system operations, I/O multiplexing, process management, networking, process tracing, kernel keyring, and more.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just a bunch of system call wrappers."
* **Correction:** "It's more than just direct wrappers. Many functions provide higher-level abstractions by combining multiple system calls or providing default arguments (like using `AT_FDCWD`)."
* **Realization:** The `Sockaddr` implementations are complex and handle the nuances of different address families. Need to highlight this as a core function.
* **Understanding `mksyscall`:**  Recognizing the importance of the `//sys` comments and the role of the `mksyscall` tool in generating the low-level system call interface.

By following these steps, we can systematically analyze the code and generate a comprehensive answer that addresses all aspects of the prompt.
这是对路径为 `go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux.go` 的 Go 语言实现的一部分的分析，它主要提供了 **Linux 系统调用的 Go 语言接口**。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **系统调用的封装:** 它定义了许多 Go 函数，这些函数是对底层 Linux 系统调用的封装。这些封装通常会处理一些细节，例如字符串到 `*byte` 的转换，以及错误码的转换。

2. **文件和目录操作:**  提供了诸如 `Access` (检查权限), `Chmod` (修改权限), `Chown` (修改所有者), `Creat` (创建文件), `Open` (打开文件), `Readlink` (读取符号链接), `Rename` (重命名), `Rmdir` (删除目录), `Link` (创建硬链接), `Symlink` (创建符号链接), `Unlink` (删除文件), `Utimes` (修改时间戳), `Mkdir` (创建目录), `Mknod` (创建设备文件或命名管道), `Mkfifo` (创建命名管道) 等操作。

3. **I/O 多路复用:** 提供了 `EpollCreate` (创建 epoll 实例), `Poll` 和 `Ppoll` (等待一组文件描述符上的事件) 的 Go 接口。

4. **进程管理:** 提供了 `Wait4` 和 `Waitid` (等待子进程状态变化), `Getwd` (获取当前工作目录), `Getgroups` (获取用户所属的组 ID), `Setgroups` (设置用户所属的组 ID) 等功能。

5. **管道:** 提供了 `Pipe` 和 `Pipe2` (创建管道) 的接口。

6. **套接字地址结构:** 定义了各种 `Sockaddr` 结构体，用于表示不同网络协议族 (如 IPv4, IPv6, Unix 域套接字, Bluetooth, CAN 等) 的套接字地址。并实现了 `sockaddr()` 方法，用于将这些 Go 结构体转换为底层系统调用所需的 `unsafe.Pointer` 和长度。

7. **套接字操作 (部分):** 提供了 `Accept` 和 `Accept4` (接受连接), `Getsockname` (获取套接字本地地址), `Getsockopt...` (获取套接字选项), `Setsockopt...` (设置套接字选项), `BindToDevice` (绑定套接字到指定网络设备) 等套接字相关操作的接口。

8. **进程跟踪 (ptrace):**  提供了一系列的 `Ptrace...` 函数，用于进程跟踪和调试，例如 `PtracePeekText`, `PtracePokeText`, `PtraceGetRegs`, `PtraceSetOptions` 等。

9. **内核密钥环 (keyctl):** 提供了一系列的 `Keyctl...` 函数，用于与 Linux 内核密钥环交互，例如 `KeyctlAddKey`, `KeyctlGetKeyringID`, `KeyctlSearch` 等。

10. **文件系统挂载:** 提供了 `Mount` 和 `MountSetattr` 函数，用于挂载文件系统。

11. **其他系统调用:** 还包含了一些其他的系统调用封装，例如 `Reboot`, `Sendfile` 等。

**它是什么 Go 语言功能的实现，并用 Go 代码举例说明:**

这部分代码主要利用 Go 语言的以下功能来实现系统调用接口：

* **`syscall` 包:**  `import "syscall"` 引入了 Go 标准库的 `syscall` 包，该包提供了访问底层操作系统原语的接口。虽然这部分代码没有直接大量使用 `syscall.Syscall` 等原始方法，但它构建在 `syscall` 包提供的基础之上。
* **`unsafe` 包:** `import "unsafe"` 允许进行不安全的指针操作，这对于与 C 语言风格的系统调用接口交互是必要的，因为系统调用通常需要传递原始的内存地址。例如，`Sockaddr` 结构体的 `sockaddr()` 方法就使用了 `unsafe.Pointer` 来获取底层 C 结构体的指针。
* **函数:**  将每个系统调用或者一组相关操作封装成 Go 函数。
* **错误处理:**  使用 Go 的标准错误处理模式，函数通常返回 `(ret, err error)`，其中 `err` 是一个 `error` 类型的值，用于指示操作是否成功。
* **字符串和字节切片:**  在 Go 中处理路径和缓冲区通常使用字符串 (`string`) 和字节切片 (`[]byte`)，代码中会进行必要的转换，例如使用 `BytePtrFromString` 将 Go 字符串转换为 C 风格的 `*byte` 指针。
* **结构体:**  使用结构体 (`struct`) 来映射底层的 C 语言结构体，例如 `Timespec`, `PollFd`, `SockaddrInet4` 等。
* **方法:**  为结构体定义方法 (`func (r *Receiver) MethodName(...)`)，例如 `Sockaddr` 接口的实现就使用了方法。
* **`//sys` 指令:**  这是一个特殊的注释，用于指示 `mksyscall` 工具生成系统调用的桩代码。例如：
  ```go
  //sys	openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)
  ```
  这行注释告诉 `mksyscall` 工具生成一个名为 `openat` 的 Go 函数，它直接调用底层的 `openat` 系统调用。

**Go 代码举例说明:**

**例子 1: 创建并写入文件**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func main() {
	filename := "test.txt"
	mode := uint32(0644) // 权限
	fd, err := unix.Creat(filename, mode)
	if err != nil {
		fmt.Println("创建文件失败:", err)
		return
	}
	defer unix.Close(fd)

	data := []byte("Hello, world!\n")
	_, err = unix.Write(fd, data)
	if err != nil {
		fmt.Println("写入文件失败:", err)
		return
	}

	fmt.Println("文件创建并写入成功")
}
```

**假设的输入与输出:**

* **输入:**  执行上述 Go 代码。
* **输出:**
  * 如果成功创建并写入文件，控制台输出 "文件创建并写入成功"。
  * 如果失败，控制台输出相应的错误信息，例如 "创建文件失败: ..." 或 "写入文件失败: ..."。
  * 会在当前目录下创建一个名为 `test.txt` 的文件，内容为 "Hello, world!\n"。

**例子 2: 获取当前工作目录**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func main() {
	wd, err := unix.Getwd()
	if err != nil {
		fmt.Println("获取当前工作目录失败:", err)
		return
	}
	fmt.Println("当前工作目录:", wd)
}
```

**假设的输入与输出:**

* **输入:** 执行上述 Go 代码。
* **输出:** 控制台输出 "当前工作目录: /path/to/your/current/directory"，其中 `/path/to/your/current/directory` 是你执行该程序的当前工作目录的实际路径。

**涉及代码推理 (例子 1):**

1. `unix.Creat(filename, mode)`:  调用了 `syscall_linux.go` 中定义的 `Creat` 函数。
2. `Creat` 函数内部会调用 `Open(path, O_CREAT|O_WRONLY|O_TRUNC, mode)`，这实际上是对 `openat` 系统调用的封装，使用了 `O_CREAT` (如果文件不存在则创建), `O_WRONLY` (以只写方式打开), `O_TRUNC` (如果文件存在则截断) 这些标志。
3. 如果 `Creat` 成功，会返回新创建文件的文件描述符 `fd`。
4. `unix.Write(fd, data)`: 调用了 `syscall_linux.go` 中 (未在此部分展示，但在同一文件中) 定义的 `Write` 函数，将 `data` 写入到文件描述符 `fd` 指向的文件中。
5. `unix.Close(fd)`:  调用了 `syscall_linux.go` 中定义的 `Close` 函数，关闭文件描述符。

**涉及命令行参数的具体处理:**

这部分代码本身主要关注系统调用接口的定义和封装，**不直接处理命令行参数**。命令行参数的处理通常发生在应用程序的 `main` 函数或其他更高级别的代码中。

**使用者易犯错的点:**

1. **权限不足:**  执行文件操作 (如创建、修改) 或某些系统调用可能需要特定的权限。如果权限不足，会返回类似 `EPERM` (Operation not permitted) 的错误。

   ```go
   // 假设当前用户没有写入权限
   _, err := unix.Creat("protected_file.txt", 0600)
   if err == unix.EPERM {
       fmt.Println("权限不足")
   }
   ```

2. **文件或目录不存在:**  尝试操作不存在的文件或目录会导致错误。

   ```go
   err := unix.Unlink("non_existent_file.txt")
   if err == unix.ENOENT {
       fmt.Println("文件不存在")
   }
   ```

3. **套接字地址结构不正确:**  在使用套接字相关函数时，需要正确填充 `Sockaddr` 结构体的各个字段，否则会导致 `EINVAL` (Invalid argument) 等错误。例如，端口号超出范围。

   ```go
   addr := &unix.SockaddrInet4{
       Port: 70000, // 端口号超出 0-65535 的范围
   }
   // ... 在调用 bind 或 connect 时可能会出错
   ```

4. **不正确的标志或模式:**  传递给系统调用的标志或模式参数必须是有效的。例如，`Open` 函数的 `mode` 参数必须是 `O_RDONLY`、`O_WRONLY`、`O_RDWR` 等之一的组合。

   ```go
   _, err := unix.Open("myfile.txt", 0xFFFFFFFF, 0) // 错误的 mode
   if err == unix.EINVAL {
       fmt.Println("无效的参数")
   }
   ```

5. **忘记处理错误:**  系统调用可能会失败，必须始终检查返回的 `error` 值，并采取适当的措施。

6. **不安全地使用 `unsafe` 包:**  直接操作指针是危险的，需要非常小心，确保内存安全和类型安全。

**总结:**

这部分 `syscall_linux.go` 代码是 Go 语言标准库中用于与 Linux 操作系统进行底层交互的关键部分。它通过封装 Linux 系统调用，为 Go 程序员提供了在 Linux 系统上进行文件操作、进程管理、网络编程、进程跟踪等操作的能力。理解这部分代码的功能对于编写需要直接与操作系统交互的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_linux.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
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

package unix

import (
	"encoding/binary"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

/*
 * Wrapped
 */

func Access(path string, mode uint32) (err error) {
	return Faccessat(AT_FDCWD, path, mode, 0)
}

func Chmod(path string, mode uint32) (err error) {
	return Fchmodat(AT_FDCWD, path, mode, 0)
}

func Chown(path string, uid int, gid int) (err error) {
	return Fchownat(AT_FDCWD, path, uid, gid, 0)
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

//sys	FanotifyInit(flags uint, event_f_flags uint) (fd int, err error)
//sys	fanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname *byte) (err error)

func FanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname string) (err error) {
	if pathname == "" {
		return fanotifyMark(fd, flags, mask, dirFd, nil)
	}
	p, err := BytePtrFromString(pathname)
	if err != nil {
		return err
	}
	return fanotifyMark(fd, flags, mask, dirFd, p)
}

//sys	fchmodat(dirfd int, path string, mode uint32) (err error)
//sys	fchmodat2(dirfd int, path string, mode uint32, flags int) (err error)

func Fchmodat(dirfd int, path string, mode uint32, flags int) error {
	// Linux fchmodat doesn't support the flags parameter, but fchmodat2 does.
	// Try fchmodat2 if flags are specified.
	if flags != 0 {
		err := fchmodat2(dirfd, path, mode, flags)
		if err == ENOSYS {
			// fchmodat2 isn't available. If the flags are known to be valid,
			// return EOPNOTSUPP to indicate that fchmodat doesn't support them.
			if flags&^(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH) != 0 {
				return EINVAL
			} else if flags&(AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH) != 0 {
				return EOPNOTSUPP
			}
		}
		return err
	}
	return fchmodat(dirfd, path, mode)
}

func InotifyInit() (fd int, err error) {
	return InotifyInit1(0)
}

//sys	ioctl(fd int, req uint, arg uintptr) (err error) = SYS_IOCTL
//sys	ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) = SYS_IOCTL

// ioctl itself should not be exposed directly, but additional get/set functions
// for specific types are permissible. These are defined in ioctl.go and
// ioctl_linux.go.
//
// The third argument to ioctl is often a pointer but sometimes an integer.
// Callers should use ioctlPtr when the third argument is a pointer and ioctl
// when the third argument is an integer.
//
// TODO: some existing code incorrectly uses ioctl when it should use ioctlPtr.

//sys	Linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) (err error)

func Link(oldpath string, newpath string) (err error) {
	return Linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0)
}

func Mkdir(path string, mode uint32) (err error) {
	return Mkdirat(AT_FDCWD, path, mode)
}

func Mknod(path string, mode uint32, dev int) (err error) {
	return Mknodat(AT_FDCWD, path, mode, dev)
}

func Open(path string, mode int, perm uint32) (fd int, err error) {
	return openat(AT_FDCWD, path, mode|O_LARGEFILE, perm)
}

//sys	openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)

func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	return openat(dirfd, path, flags|O_LARGEFILE, mode)
}

//sys	openat2(dirfd int, path string, open_how *OpenHow, size int) (fd int, err error)

func Openat2(dirfd int, path string, how *OpenHow) (fd int, err error) {
	return openat2(dirfd, path, how, SizeofOpenHow)
}

func Pipe(p []int) error {
	return Pipe2(p, 0)
}

//sysnb	pipe2(p *[2]_C_int, flags int) (err error)

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

//sys	ppoll(fds *PollFd, nfds int, timeout *Timespec, sigmask *Sigset_t) (n int, err error)

func Ppoll(fds []PollFd, timeout *Timespec, sigmask *Sigset_t) (n int, err error) {
	if len(fds) == 0 {
		return ppoll(nil, 0, timeout, sigmask)
	}
	return ppoll(&fds[0], len(fds), timeout, sigmask)
}

func Poll(fds []PollFd, timeout int) (n int, err error) {
	var ts *Timespec
	if timeout >= 0 {
		ts = new(Timespec)
		*ts = NsecToTimespec(int64(timeout) * 1e6)
	}
	return Ppoll(fds, ts, nil)
}

//sys	Readlinkat(dirfd int, path string, buf []byte) (n int, err error)

func Readlink(path string, buf []byte) (n int, err error) {
	return Readlinkat(AT_FDCWD, path, buf)
}

func Rename(oldpath string, newpath string) (err error) {
	return Renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath)
}

func Rmdir(path string) error {
	return Unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
}

//sys	Symlinkat(oldpath string, newdirfd int, newpath string) (err error)

func Symlink(oldpath string, newpath string) (err error) {
	return Symlinkat(oldpath, AT_FDCWD, newpath)
}

func Unlink(path string) error {
	return Unlinkat(AT_FDCWD, path, 0)
}

//sys	Unlinkat(dirfd int, path string, flags int) (err error)

func Utimes(path string, tv []Timeval) error {
	if tv == nil {
		err := utimensat(AT_FDCWD, path, nil, 0)
		if err != ENOSYS {
			return err
		}
		return utimes(path, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	var ts [2]Timespec
	ts[0] = NsecToTimespec(TimevalToNsec(tv[0]))
	ts[1] = NsecToTimespec(TimevalToNsec(tv[1]))
	err := utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
	if err != ENOSYS {
		return err
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)

func UtimesNano(path string, ts []Timespec) error {
	return UtimesNanoAt(AT_FDCWD, path, ts, 0)
}

func UtimesNanoAt(dirfd int, path string, ts []Timespec, flags int) error {
	if ts == nil {
		return utimensat(dirfd, path, nil, flags)
	}
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(dirfd, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), flags)
}

func Futimesat(dirfd int, path string, tv []Timeval) error {
	if tv == nil {
		return futimesat(dirfd, path, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return futimesat(dirfd, path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func Futimes(fd int, tv []Timeval) (err error) {
	// Believe it or not, this is the best we can do on Linux
	// (and is what glibc does).
	return Utimes("/proc/self/fd/"+strconv.Itoa(fd), tv)
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

func (w WaitStatus) Signal() syscall.Signal {
	if !w.Signaled() {
		return -1
	}
	return syscall.Signal(w & mask)
}

func (w WaitStatus) StopSignal() syscall.Signal {
	if !w.Stopped() {
		return -1
	}
	return syscall.Signal(w>>shift) & 0xFF
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

//sys	Waitid(idType int, id int, info *Siginfo, options int, rusage *Rusage) (err error)

func Mkfifo(path string, mode uint32) error {
	return Mknod(path, mode|S_IFIFO, 0)
}

func Mkfifoat(dirfd int, path string, mode uint32) error {
	return Mknodat(dirfd, path, mode|S_IFIFO, 0)
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
	if n >= len(sa.raw.Path) {
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

// SockaddrLinklayer implements the Sockaddr interface for AF_PACKET type sockets.
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

// SockaddrNetlink implements the Sockaddr interface for AF_NETLINK type sockets.
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

// SockaddrHCI implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the HCI protocol.
type SockaddrHCI struct {
	Dev     uint16
	Channel uint16
	raw     RawSockaddrHCI
}

func (sa *SockaddrHCI) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	sa.raw.Dev = sa.Dev
	sa.raw.Channel = sa.Channel
	return unsafe.Pointer(&sa.raw), SizeofSockaddrHCI, nil
}

// SockaddrL2 implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the L2CAP protocol.
type SockaddrL2 struct {
	PSM      uint16
	CID      uint16
	Addr     [6]uint8
	AddrType uint8
	raw      RawSockaddrL2
}

func (sa *SockaddrL2) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	psm := (*[2]byte)(unsafe.Pointer(&sa.raw.Psm))
	psm[0] = byte(sa.PSM)
	psm[1] = byte(sa.PSM >> 8)
	for i := 0; i < len(sa.Addr); i++ {
		sa.raw.Bdaddr[i] = sa.Addr[len(sa.Addr)-1-i]
	}
	cid := (*[2]byte)(unsafe.Pointer(&sa.raw.Cid))
	cid[0] = byte(sa.CID)
	cid[1] = byte(sa.CID >> 8)
	sa.raw.Bdaddr_type = sa.AddrType
	return unsafe.Pointer(&sa.raw), SizeofSockaddrL2, nil
}

// SockaddrRFCOMM implements the Sockaddr interface for AF_BLUETOOTH type sockets
// using the RFCOMM protocol.
//
// Server example:
//
//	fd, _ := Socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)
//	_ = unix.Bind(fd, &unix.SockaddrRFCOMM{
//		Channel: 1,
//		Addr:    [6]uint8{0, 0, 0, 0, 0, 0}, // BDADDR_ANY or 00:00:00:00:00:00
//	})
//	_ = Listen(fd, 1)
//	nfd, sa, _ := Accept(fd)
//	fmt.Printf("conn addr=%v fd=%d", sa.(*unix.SockaddrRFCOMM).Addr, nfd)
//	Read(nfd, buf)
//
// Client example:
//
//	fd, _ := Socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)
//	_ = Connect(fd, &SockaddrRFCOMM{
//		Channel: 1,
//		Addr:    [6]byte{0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc}, // CC:BB:AA:33:22:11
//	})
//	Write(fd, []byte(`hello`))
type SockaddrRFCOMM struct {
	// Addr represents a bluetooth address, byte ordering is little-endian.
	Addr [6]uint8

	// Channel is a designated bluetooth channel, only 1-30 are available for use.
	// Since Linux 2.6.7 and further zero value is the first available channel.
	Channel uint8

	raw RawSockaddrRFCOMM
}

func (sa *SockaddrRFCOMM) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_BLUETOOTH
	sa.raw.Channel = sa.Channel
	sa.raw.Bdaddr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrRFCOMM, nil
}

// SockaddrCAN implements the Sockaddr interface for AF_CAN type sockets.
// The RxID and TxID fields are used for transport protocol addressing in
// (CAN_TP16, CAN_TP20, CAN_MCNET, and CAN_ISOTP), they can be left with
// zero values for CAN_RAW and CAN_BCM sockets as they have no meaning.
//
// The SockaddrCAN struct must be bound to the socket file descriptor
// using Bind before the CAN socket can be used.
//
//	// Read one raw CAN frame
//	fd, _ := Socket(AF_CAN, SOCK_RAW, CAN_RAW)
//	addr := &SockaddrCAN{Ifindex: index}
//	Bind(fd, addr)
//	frame := make([]byte, 16)
//	Read(fd, frame)
//
// The full SocketCAN documentation can be found in the linux kernel
// archives at: https://www.kernel.org/doc/Documentation/networking/can.txt
type SockaddrCAN struct {
	Ifindex int
	RxID    uint32
	TxID    uint32
	raw     RawSockaddrCAN
}

func (sa *SockaddrCAN) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_CAN
	sa.raw.Ifindex = int32(sa.Ifindex)
	rx := (*[4]byte)(unsafe.Pointer(&sa.RxID))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i] = rx[i]
	}
	tx := (*[4]byte)(unsafe.Pointer(&sa.TxID))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i+4] = tx[i]
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrCAN, nil
}

// SockaddrCANJ1939 implements the Sockaddr interface for AF_CAN using J1939
// protocol (https://en.wikipedia.org/wiki/SAE_J1939). For more information
// on the purposes of the fields, check the official linux kernel documentation
// available here: https://www.kernel.org/doc/Documentation/networking/j1939.rst
type SockaddrCANJ1939 struct {
	Ifindex int
	Name    uint64
	PGN     uint32
	Addr    uint8
	raw     RawSockaddrCAN
}

func (sa *SockaddrCANJ1939) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Ifindex < 0 || sa.Ifindex > 0x7fffffff {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_CAN
	sa.raw.Ifindex = int32(sa.Ifindex)
	n := (*[8]byte)(unsafe.Pointer(&sa.Name))
	for i := 0; i < 8; i++ {
		sa.raw.Addr[i] = n[i]
	}
	p := (*[4]byte)(unsafe.Pointer(&sa.PGN))
	for i := 0; i < 4; i++ {
		sa.raw.Addr[i+8] = p[i]
	}
	sa.raw.Addr[12] = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrCAN, nil
}

// SockaddrALG implements the Sockaddr interface for AF_ALG type sockets.
// SockaddrALG enables userspace access to the Linux kernel's cryptography
// subsystem. The Type and Name fields specify which type of hash or cipher
// should be used with a given socket.
//
// To create a file descriptor that provides access to a hash or cipher, both
// Bind and Accept must be used. Once the setup process is complete, input
// data can be written to the socket, processed by the kernel, and then read
// back as hash output or ciphertext.
//
// Here is an example of using an AF_ALG socket with SHA1 hashing.
// The initial socket setup process is as follows:
//
//	// Open a socket to perform SHA1 hashing.
//	fd, _ := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
//	addr := &unix.SockaddrALG{Type: "hash", Name: "sha1"}
//	unix.Bind(fd, addr)
//	// Note: unix.Accept does not work at this time; must invoke accept()
//	// manually using unix.Syscall.
//	hashfd, _, _ := unix.Syscall(unix.SYS_ACCEPT, uintptr(fd), 0, 0)
//
// Once a file descriptor has been returned from Accept, it may be used to
// perform SHA1 hashing. The descriptor is not safe for concurrent use, but
// may be re-used repeatedly with subsequent Write and Read operations.
//
// When hashing a small byte slice or string, a single Write and Read may
// be used:
//
//	// Assume hashfd is already configured using the setup process.
//	hash := os.NewFile(hashfd, "sha1")
//	// Hash an input string and read the results. Each Write discards
//	// previous hash state. Read always reads the current state.
//	b := make([]byte, 20)
//	for i := 0; i < 2; i++ {
//	    io.WriteString(hash, "Hello, world.")
//	    hash.Read(b)
//	    fmt.Println(hex.EncodeToString(b))
//	}
//	// Output:
//	// 2ae01472317d1935a84797ec1983ae243fc6aa28
//	// 2ae01472317d1935a84797ec1983ae243fc6aa28
//
// For hashing larger byte slices, or byte streams such as those read from
// a file or socket, use Sendto with MSG_MORE to instruct the kernel to update
// the hash digest instead of creating a new one for a given chunk and finalizing it.
//
//	// Assume hashfd and addr are already configured using the setup process.
//	hash := os.NewFile(hashfd, "sha1")
//	// Hash the contents of a file.
//	f, _ := os.Open("/tmp/linux-4.10-rc7.tar.xz")
//	b := make([]byte, 4096)
//	for {
//	    n, err := f.Read(b)
//	    if err == io.EOF {
//	        break
//	    }
//	    unix.Sendto(hashfd, b[:n], unix.MSG_MORE, addr)
//	}
//	hash.Read(b)
//	fmt.Println(hex.EncodeToString(b))
//	// Output: 85cdcad0c06eef66f805ecce353bec9accbeecc5
//
// For more information, see: http://www.chronox.de/crypto-API/crypto/userspace-if.html.
type SockaddrALG struct {
	Type    string
	Name    string
	Feature uint32
	Mask    uint32
	raw     RawSockaddrALG
}

func (sa *SockaddrALG) sockaddr() (unsafe.Pointer, _Socklen, error) {
	// Leave room for NUL byte terminator.
	if len(sa.Type) > len(sa.raw.Type)-1 {
		return nil, 0, EINVAL
	}
	if len(sa.Name) > len(sa.raw.Name)-1 {
		return nil, 0, EINVAL
	}

	sa.raw.Family = AF_ALG
	sa.raw.Feat = sa.Feature
	sa.raw.Mask = sa.Mask

	copy(sa.raw.Type[:], sa.Type)
	copy(sa.raw.Name[:], sa.Name)

	return unsafe.Pointer(&sa.raw), SizeofSockaddrALG, nil
}

// SockaddrVM implements the Sockaddr interface for AF_VSOCK type sockets.
// SockaddrVM provides access to Linux VM sockets: a mechanism that enables
// bidirectional communication between a hypervisor and its guest virtual
// machines.
type SockaddrVM struct {
	// CID and Port specify a context ID and port address for a VM socket.
	// Guests have a unique CID, and hosts may have a well-known CID of:
	//  - VMADDR_CID_HYPERVISOR: refers to the hypervisor process.
	//  - VMADDR_CID_LOCAL: refers to local communication (loopback).
	//  - VMADDR_CID_HOST: refers to other processes on the host.
	CID   uint32
	Port  uint32
	Flags uint8
	raw   RawSockaddrVM
}

func (sa *SockaddrVM) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_VSOCK
	sa.raw.Port = sa.Port
	sa.raw.Cid = sa.CID
	sa.raw.Flags = sa.Flags

	return unsafe.Pointer(&sa.raw), SizeofSockaddrVM, nil
}

type SockaddrXDP struct {
	Flags        uint16
	Ifindex      uint32
	QueueID      uint32
	SharedUmemFD uint32
	raw          RawSockaddrXDP
}

func (sa *SockaddrXDP) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_XDP
	sa.raw.Flags = sa.Flags
	sa.raw.Ifindex = sa.Ifindex
	sa.raw.Queue_id = sa.QueueID
	sa.raw.Shared_umem_fd = sa.SharedUmemFD

	return unsafe.Pointer(&sa.raw), SizeofSockaddrXDP, nil
}

// This constant mirrors the #define of PX_PROTO_OE in
// linux/if_pppox.h. We're defining this by hand here instead of
// autogenerating through mkerrors.sh because including
// linux/if_pppox.h causes some declaration conflicts with other
// includes (linux/if_pppox.h includes linux/in.h, which conflicts
// with netinet/in.h). Given that we only need a single zero constant
// out of that file, it's cleaner to just define it by hand here.
const px_proto_oe = 0

type SockaddrPPPoE struct {
	SID    uint16
	Remote []byte
	Dev    string
	raw    RawSockaddrPPPoX
}

func (sa *SockaddrPPPoE) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if len(sa.Remote) != 6 {
		return nil, 0, EINVAL
	}
	if len(sa.Dev) > IFNAMSIZ-1 {
		return nil, 0, EINVAL
	}

	*(*uint16)(unsafe.Pointer(&sa.raw[0])) = AF_PPPOX
	// This next field is in host-endian byte order. We can't use the
	// same unsafe pointer cast as above, because this value is not
	// 32-bit aligned and some architectures don't allow unaligned
	// access.
	//
	// However, the value of px_proto_oe is 0, so we can use
	// encoding/binary helpers to write the bytes without worrying
	// about the ordering.
	binary.BigEndian.PutUint32(sa.raw[2:6], px_proto_oe)
	// This field is deliberately big-endian, unlike the previous
	// one. The kernel expects SID to be in network byte order.
	binary.BigEndian.PutUint16(sa.raw[6:8], sa.SID)
	copy(sa.raw[8:14], sa.Remote)
	for i := 14; i < 14+IFNAMSIZ; i++ {
		sa.raw[i] = 0
	}
	copy(sa.raw[14:], sa.Dev)
	return unsafe.Pointer(&sa.raw), SizeofSockaddrPPPoX, nil
}

// SockaddrTIPC implements the Sockaddr interface for AF_TIPC type sockets.
// For more information on TIPC, see: http://tipc.sourceforge.net/.
type SockaddrTIPC struct {
	// Scope is the publication scopes when binding service/service range.
	// Should be set to TIPC_CLUSTER_SCOPE or TIPC_NODE_SCOPE.
	Scope int

	// Addr is the type of address used to manipulate a socket. Addr must be
	// one of:
	//  - *TIPCSocketAddr: "id" variant in the C addr union
	//  - *TIPCServiceRange: "nameseq" variant in the C addr union
	//  - *TIPCServiceName: "name" variant in the C addr union
	//
	// If nil, EINVAL will be returned when the structure is used.
	Addr TIPCAddr

	raw RawSockaddrTIPC
}

// TIPCAddr is implemented by types that can be used as an address for
// SockaddrTIPC. It is only implemented by *TIPCSocketAddr, *TIPCServiceRange,
// and *TIPCServiceName.
type TIPCAddr interface {
	tipcAddrtype() uint8
	tipcAddr() [12]byte
}

func (sa *TIPCSocketAddr) tipcAddr() [12]byte {
	var out [12]byte
	copy(out[:], (*(*[unsafe.Sizeof(TIPCSocketAddr{})]byte)(unsafe.Pointer(sa)))[:])
	return out
}

func (sa *TIPCSocketAddr) tipcAddrtype() uint8 { return TIPC_SOCKET_ADDR }

func (sa *TIPCServiceRange) tipcAddr() [12]byte {
	var out [12]byte
	copy(out[:], (*(*[unsafe.Sizeof(TIPCServiceRange{})]byte)(unsafe.Pointer(sa)))[:])
	return out
}

func (sa *TIPCServiceRange) tipcAddrtype() uint8 { return TIPC_SERVICE_RANGE }

func (sa *TIPCServiceName) tipcAddr() [12]byte {
	var out [12]byte
	copy(out[:], (*(*[unsafe.Sizeof(TIPCServiceName{})]byte)(unsafe.Pointer(sa)))[:])
	return out
}

func (sa *TIPCServiceName) tipcAddrtype() uint8 { return TIPC_SERVICE_ADDR }

func (sa *SockaddrTIPC) sockaddr() (unsafe.Pointer, _Socklen, error) {
	if sa.Addr == nil {
		return nil, 0, EINVAL
	}
	sa.raw.Family = AF_TIPC
	sa.raw.Scope = int8(sa.Scope)
	sa.raw.Addrtype = sa.Addr.tipcAddrtype()
	sa.raw.Addr = sa.Addr.tipcAddr()
	return unsafe.Pointer(&sa.raw), SizeofSockaddrTIPC, nil
}

// SockaddrL2TPIP implements the Sockaddr interface for IPPROTO_L2TP/AF_INET sockets.
type SockaddrL2TPIP struct {
	Addr   [4]byte
	ConnId uint32
	raw    RawSockaddrL2TPIP
}

func (sa *SockaddrL2TPIP) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_INET
	sa.raw.Conn_id = sa.ConnId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrL2TPIP, nil
}

// SockaddrL2TPIP6 implements the Sockaddr interface for IPPROTO_L2TP/AF_INET6 sockets.
type SockaddrL2TPIP6 struct {
	Addr   [16]byte
	ZoneId uint32
	ConnId uint32
	raw    RawSockaddrL2TPIP6
}

func (sa *SockaddrL2TPIP6) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_INET6
	sa.raw.Conn_id = sa.ConnId
	sa.raw.Scope_id = sa.ZoneId
	sa.raw.Addr = sa.Addr
	return unsafe.Pointer(&sa.raw), SizeofSockaddrL2TPIP6, nil
}

// SockaddrIUCV implements the Sockaddr interface for AF_IUCV sockets.
type SockaddrIUCV struct {
	UserID string
	Name   string
	raw    RawSockaddrIUCV
}

func (sa *SockaddrIUCV) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Family = AF_IUCV
	// These are EBCDIC encoded by the kernel, but we still need to pad them
	// with blanks. Initializing with blanks allows the caller to feed in either
	// a padded or an unpadded string.
	for i := 0; i < 8; i++ {
		sa.raw.Nodeid[i] = ' '
		sa.raw.User_id[i] = ' '
		sa.raw.Name[i] = ' '
	}
	if len(sa.UserID) > 8 || len(sa.Name) > 8 {
		return nil, 0, EINVAL
	}
	for i, b := range []byte(sa.UserID[:]) {
		sa.raw.User_id[i] = int8(b)
	}
	for i, b := range []byte(sa.Name[:]) {
		sa.raw.Name[i] = int8(b)
	}
	return unsafe.Pointer(&sa.raw), SizeofSockaddrIUCV, nil
}

type SockaddrNFC struct {
	DeviceIdx   uint32
	TargetIdx   uint32
	NFCProtocol uint32
	raw         RawSockaddrNFC
}

func (sa *SockaddrNFC) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Sa_family = AF_NFC
	sa.raw.Dev_idx = sa.DeviceIdx
	sa.raw.Target_idx = sa.TargetIdx
	sa.raw.Nfc_protocol = sa.NFCProtocol
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNFC, nil
}

type SockaddrNFCLLCP struct {
	DeviceIdx      uint32
	TargetIdx      uint32
	NFCProtocol    uint32
	DestinationSAP uint8
	SourceSAP      uint8
	ServiceName    string
	raw            RawSockaddrNFCLLCP
}

func (sa *SockaddrNFCLLCP) sockaddr() (unsafe.Pointer, _Socklen, error) {
	sa.raw.Sa_family = AF_NFC
	sa.raw.Dev_idx = sa.DeviceIdx
	sa.raw.Target_idx = sa.TargetIdx
	sa.raw.Nfc_protocol = sa.NFCProtocol
	sa.raw.Dsap = sa.DestinationSAP
	sa.raw.Ssap = sa.SourceSAP
	if len(sa.ServiceName) > len(sa.raw.Service_name) {
		return nil, 0, EINVAL
	}
	copy(sa.raw.Service_name[:], sa.ServiceName)
	sa.raw.SetServiceNameLen(len(sa.ServiceName))
	return unsafe.Pointer(&sa.raw), SizeofSockaddrNFCLLCP, nil
}

var socketProtocol = func(fd int) (int, error) {
	return GetsockoptInt(fd, SOL_SOCKET, SO_PROTOCOL)
}

func anyToSockaddr(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
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
		proto, err := socketProtocol(fd)
		if err != nil {
			return nil, err
		}

		switch proto {
		case IPPROTO_L2TP:
			pp := (*RawSockaddrL2TPIP)(unsafe.Pointer(rsa))
			sa := new(SockaddrL2TPIP)
			sa.ConnId = pp.Conn_id
			sa.Addr = pp.Addr
			return sa, nil
		default:
			pp := (*RawSockaddrInet4)(unsafe.Pointer(rsa))
			sa := new(SockaddrInet4)
			p := (*[2]byte)(unsafe.Pointer(&pp.Port))
			sa.Port = int(p[0])<<8 + int(p[1])
			sa.Addr = pp.Addr
			return sa, nil
		}

	case AF_INET6:
		proto, err := socketProtocol(fd)
		if err != nil {
			return nil, err
		}

		switch proto {
		case IPPROTO_L2TP:
			pp := (*RawSockaddrL2TPIP6)(unsafe.Pointer(rsa))
			sa := new(SockaddrL2TPIP6)
			sa.ConnId = pp.Conn_id
			sa.ZoneId = pp.Scope_id
			sa.Addr = pp.Addr
			return sa, nil
		default:
			pp := (*RawSockaddrInet6)(unsafe.Pointer(rsa))
			sa := new(SockaddrInet6)
			p := (*[2]byte)(unsafe.Pointer(&pp.Port))
			sa.Port = int(p[0])<<8 + int(p[1])
			sa.ZoneId = pp.Scope_id
			sa.Addr = pp.Addr
			return sa, nil
		}

	case AF_VSOCK:
		pp := (*RawSockaddrVM)(unsafe.Pointer(rsa))
		sa := &SockaddrVM{
			CID:   pp.Cid,
			Port:  pp.Port,
			Flags: pp.Flags,
		}
		return sa, nil
	case AF_BLUETOOTH:
		proto, err := socketProtocol(fd)
		if err != nil {
			return nil, err
		}
		// only BTPROTO_L2CAP and BTPROTO_RFCOMM can accept connections
		switch proto {
		case BTPROTO_L2CAP:
			pp := (*RawSockaddrL2)(unsafe.Pointer(rsa))
			sa := &SockaddrL2{
				PSM:      pp.Psm,
				CID:      pp.Cid,
				Addr:     pp.Bdaddr,
				AddrType: pp.Bdaddr_type,
			}
			return sa, nil
		case BTPROTO_RFCOMM:
			pp := (*RawSockaddrRFCOMM)(unsafe.Pointer(rsa))
			sa := &SockaddrRFCOMM{
				Channel: pp.Channel,
				Addr:    pp.Bdaddr,
			}
			return sa, nil
		}
	case AF_XDP:
		pp := (*RawSockaddrXDP)(unsafe.Pointer(rsa))
		sa := &SockaddrXDP{
			Flags:        pp.Flags,
			Ifindex:      pp.Ifindex,
			QueueID:      pp.Queue_id,
			SharedUmemFD: pp.Shared_umem_fd,
		}
		return sa, nil
	case AF_PPPOX:
		pp := (*RawSockaddrPPPoX)(unsafe.Pointer(rsa))
		if binary.BigEndian.Uint32(pp[2:6]) != px_proto_oe {
			return nil, EINVAL
		}
		sa := &SockaddrPPPoE{
			SID:    binary.BigEndian.Uint16(pp[6:8]),
			Remote: pp[8:14],
		}
		for i := 14; i < 14+IFNAMSIZ; i++ {
			if pp[i] == 0 {
				sa.Dev = string(pp[14:i])
				break
			}
		}
		return sa, nil
	case AF_TIPC:
		pp := (*RawSockaddrTIPC)(unsafe.Pointer(rsa))

		sa := &SockaddrTIPC{
			Scope: int(pp.Scope),
		}

		// Determine which union variant is present in pp.Addr by checking
		// pp.Addrtype.
		switch pp.Addrtype {
		case TIPC_SERVICE_RANGE:
			sa.Addr = (*TIPCServiceRange)(unsafe.Pointer(&pp.Addr))
		case TIPC_SERVICE_ADDR:
			sa.Addr = (*TIPCServiceName)(unsafe.Pointer(&pp.Addr))
		case TIPC_SOCKET_ADDR:
			sa.Addr = (*TIPCSocketAddr)(unsafe.Pointer(&pp.Addr))
		default:
			return nil, EINVAL
		}

		return sa, nil
	case AF_IUCV:
		pp := (*RawSockaddrIUCV)(unsafe.Pointer(rsa))

		var user [8]byte
		var name [8]byte

		for i := 0; i < 8; i++ {
			user[i] = byte(pp.User_id[i])
			name[i] = byte(pp.Name[i])
		}

		sa := &SockaddrIUCV{
			UserID: string(user[:]),
			Name:   string(name[:]),
		}
		return sa, nil

	case AF_CAN:
		proto, err := socketProtocol(fd)
		if err != nil {
			return nil, err
		}

		pp := (*RawSockaddrCAN)(unsafe.Pointer(rsa))

		switch proto {
		case CAN_J1939:
			sa := &SockaddrCANJ1939{
				Ifindex: int(pp.Ifindex),
			}
			name := (*[8]byte)(unsafe.Pointer(&sa.Name))
			for i := 0; i < 8; i++ {
				name[i] = pp.Addr[i]
			}
			pgn := (*[4]byte)(unsafe.Pointer(&sa.PGN))
			for i := 0; i < 4; i++ {
				pgn[i] = pp.Addr[i+8]
			}
			addr := (*[1]byte)(unsafe.Pointer(&sa.Addr))
			addr[0] = pp.Addr[12]
			return sa, nil
		default:
			sa := &SockaddrCAN{
				Ifindex: int(pp.Ifindex),
			}
			rx := (*[4]byte)(unsafe.Pointer(&sa.RxID))
			for i := 0; i < 4; i++ {
				rx[i] = pp.Addr[i]
			}
			tx := (*[4]byte)(unsafe.Pointer(&sa.TxID))
			for i := 0; i < 4; i++ {
				tx[i] = pp.Addr[i+4]
			}
			return sa, nil
		}
	case AF_NFC:
		proto, err := socketProtocol(fd)
		if err != nil {
			return nil, err
		}
		switch proto {
		case NFC_SOCKPROTO_RAW:
			pp := (*RawSockaddrNFC)(unsafe.Pointer(rsa))
			sa := &SockaddrNFC{
				DeviceIdx:   pp.Dev_idx,
				TargetIdx:   pp.Target_idx,
				NFCProtocol: pp.Nfc_protocol,
			}
			return sa, nil
		case NFC_SOCKPROTO_LLCP:
			pp := (*RawSockaddrNFCLLCP)(unsafe.Pointer(rsa))
			if uint64(pp.Service_name_len) > uint64(len(pp.Service_name)) {
				return nil, EINVAL
			}
			sa := &SockaddrNFCLLCP{
				DeviceIdx:      pp.Dev_idx,
				TargetIdx:      pp.Target_idx,
				NFCProtocol:    pp.Nfc_protocol,
				DestinationSAP: pp.Dsap,
				SourceSAP:      pp.Ssap,
				ServiceName:    string(pp.Service_name[:pp.Service_name_len]),
			}
			return sa, nil
		default:
			return nil, EINVAL
		}
	}
	return nil, EAFNOSUPPORT
}

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept4(fd, &rsa, &len, 0)
	if err != nil {
		return
	}
	sa, err = anyToSockaddr(fd, &rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
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
	sa, err = anyToSockaddr(fd, &rsa)
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
	return anyToSockaddr(fd, &rsa)
}

func GetsockoptIPMreqn(fd, level, opt int) (*IPMreqn, error) {
	var value IPMreqn
	vallen := _Socklen(SizeofIPMreqn)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptUcred(fd, level, opt int) (*Ucred, error) {
	var value Ucred
	vallen := _Socklen(SizeofUcred)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptTCPInfo(fd, level, opt int) (*TCPInfo, error) {
	var value TCPInfo
	vallen := _Socklen(SizeofTCPInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

// GetsockoptTCPCCVegasInfo returns algorithm specific congestion control information for a socket using the "vegas"
// algorithm.
//
// The socket's congestion control algorighm can be retrieved via [GetsockoptString] with the [TCP_CONGESTION] option:
//
//	algo, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
func GetsockoptTCPCCVegasInfo(fd, level, opt int) (*TCPVegasInfo, error) {
	var value [SizeofTCPCCInfo / 4]uint32 // ensure proper alignment
	vallen := _Socklen(SizeofTCPCCInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value[0]), &vallen)
	out := (*TCPVegasInfo)(unsafe.Pointer(&value[0]))
	return out, err
}

// GetsockoptTCPCCDCTCPInfo returns algorithm specific congestion control information for a socket using the "dctp"
// algorithm.
//
// The socket's congestion control algorighm can be retrieved via [GetsockoptString] with the [TCP_CONGESTION] option:
//
//	algo, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
func GetsockoptTCPCCDCTCPInfo(fd, level, opt int) (*TCPDCTCPInfo, error) {
	var value [SizeofTCPCCInfo / 4]uint32 // ensure proper alignment
	vallen := _Socklen(SizeofTCPCCInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value[0]), &vallen)
	out := (*TCPDCTCPInfo)(unsafe.Pointer(&value[0]))
	return out, err
}

// GetsockoptTCPCCBBRInfo returns algorithm specific congestion control information for a socket using the "bbr"
// algorithm.
//
// The socket's congestion control algorighm can be retrieved via [GetsockoptString] with the [TCP_CONGESTION] option:
//
//	algo, err := unix.GetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
func GetsockoptTCPCCBBRInfo(fd, level, opt int) (*TCPBBRInfo, error) {
	var value [SizeofTCPCCInfo / 4]uint32 // ensure proper alignment
	vallen := _Socklen(SizeofTCPCCInfo)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value[0]), &vallen)
	out := (*TCPBBRInfo)(unsafe.Pointer(&value[0]))
	return out, err
}

// GetsockoptString returns the string value of the socket option opt for the
// socket associated with fd at the given socket level.
func GetsockoptString(fd, level, opt int) (string, error) {
	buf := make([]byte, 256)
	vallen := _Socklen(len(buf))
	err := getsockopt(fd, level, opt, unsafe.Pointer(&buf[0]), &vallen)
	if err != nil {
		if err == ERANGE {
			buf = make([]byte, vallen)
			err = getsockopt(fd, level, opt, unsafe.Pointer(&buf[0]), &vallen)
		}
		if err != nil {
			return "", err
		}
	}
	return ByteSliceToString(buf[:vallen]), nil
}

func GetsockoptTpacketStats(fd, level, opt int) (*TpacketStats, error) {
	var value TpacketStats
	vallen := _Socklen(SizeofTpacketStats)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func GetsockoptTpacketStatsV3(fd, level, opt int) (*TpacketStatsV3, error) {
	var value TpacketStatsV3
	vallen := _Socklen(SizeofTpacketStatsV3)
	err := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, err
}

func SetsockoptIPMreqn(fd, level, opt int, mreq *IPMreqn) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), unsafe.Sizeof(*mreq))
}

func SetsockoptPacketMreq(fd, level, opt int, mreq *PacketMreq) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), unsafe.Sizeof(*mreq))
}

// SetsockoptSockFprog attaches a classic BPF or an extended BPF program to a
// socket to filter incoming packets.  See 'man 7 socket' for usage information.
func SetsockoptSockFprog(fd, level, opt int, fprog *SockFprog) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(fprog), unsafe.Sizeof(*fprog))
}

func SetsockoptCanRawFilter(fd, level, opt int, filter []CanFilter) error {
	var p unsafe.Pointer
	if len(filter) > 0 {
		p = unsafe.Pointer(&filter[0])
	}
	return setsockopt(fd, level, opt, p, uintptr(len(filter)*SizeofCanFilter))
}

func SetsockoptTpacketReq(fd, level, opt int, tp *TpacketReq) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(tp), unsafe.Sizeof(*tp))
}

func SetsockoptTpacketReq3(fd, level, opt int, tp *TpacketReq3) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(tp), unsafe.Sizeof(*tp))
}

func SetsockoptTCPRepairOpt(fd, level, opt int, o []TCPRepairOpt) (err error) {
	if len(o) == 0 {
		return EINVAL
	}
	return setsockopt(fd, level, opt, unsafe.Pointer(&o[0]), uintptr(SizeofTCPRepairOpt*len(o)))
}

func SetsockoptTCPMD5Sig(fd, level, opt int, s *TCPMD5Sig) error {
	return setsockopt(fd, level, opt, unsafe.Pointer(s), unsafe.Sizeof(*s))
}

// Keyctl Commands (http://man7.org/linux/man-pages/man2/keyctl.2.html)

// KeyctlInt calls keyctl commands in which each argument is an int.
// These commands are KEYCTL_REVOKE, KEYCTL_CHOWN, KEYCTL_CLEAR, KEYCTL_LINK,
// KEYCTL_UNLINK, KEYCTL_NEGATE, KEYCTL_SET_REQKEY_KEYRING, KEYCTL_SET_TIMEOUT,
// KEYCTL_ASSUME_AUTHORITY, KEYCTL_SESSION_TO_PARENT, KEYCTL_REJECT,
// KEYCTL_INVALIDATE, and KEYCTL_GET_PERSISTENT.
//sys	KeyctlInt(cmd int, arg2 int, arg3 int, arg4 int, arg5 int) (ret int, err error) = SYS_KEYCTL

// KeyctlBuffer calls keyctl commands in which the third and fourth
// arguments are a buffer and its length, respectively.
// These commands are KEYCTL_UPDATE, KEYCTL_READ, and KEYCTL_INSTANTIATE.
//sys	KeyctlBuffer(cmd int, arg2 int, buf []byte, arg5 int) (ret int, err error) = SYS_KEYCTL

// KeyctlString calls keyctl commands which return a string.
// These commands are KEYCTL_DESCRIBE and KEYCTL_GET_SECURITY.
func KeyctlString(cmd int, id int) (string, error) {
	// We must loop as the string data may change in between the syscalls.
	// We could allocate a large buffer here to reduce the chance that the
	// syscall needs to be called twice; however, this is unnecessary as
	// the performance loss is negligible.
	var buffer []byte
	for {
		// Try to fill the buffer with data
		length, err := KeyctlBuffer(cmd, id, buffer, 0)
		if err != nil {
			return "", err
		}

		// Check if the data was written
		if length <= len(buffer) {
			// Exclude the null terminator
			return string(buffer[:length-1]), nil
		}

		// Make a bigger buffer if needed
		buffer = make([]byte, length)
	}
}

// Keyctl commands with special signatures.

// KeyctlGetKeyringID implements the KEYCTL_GET_KEYRING_ID command.
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_get_keyring_ID.3.html
func KeyctlGetKeyringID(id int, create bool) (ringid int, err error) {
	createInt := 0
	if create {
		createInt = 1
	}
	return KeyctlInt(KEYCTL_GET_KEYRING_ID, id, createInt, 0, 0)
}

// KeyctlSetperm implements the KEYCTL_SETPERM command. The perm value is the
// key handle permission mask as described in the "keyctl setperm" section of
// http://man7.org/linux/man-pages/man1/keyctl.1.html.
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_setperm.3.html
func KeyctlSetperm(id int, perm uint32) error {
	_, err := KeyctlInt(KEYCTL_SETPERM, id, int(perm), 0, 0)
	return err
}

//sys	keyctlJoin(cmd int, arg2 string) (ret int, err error) = SYS_KEYCTL

// KeyctlJoinSessionKeyring implements the KEYCTL_JOIN_SESSION_KEYRING command.
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_join_session_keyring.3.html
func KeyctlJoinSessionKeyring(name string) (ringid int, err error) {
	return keyctlJoin(KEYCTL_JOIN_SESSION_KEYRING, name)
}

//sys	keyctlSearch(cmd int, arg2 int, arg3 string, arg4 string, arg5 int) (ret int, err error) = SYS_KEYCTL

// KeyctlSearch implements the KEYCTL_SEARCH command.
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_search.3.html
func KeyctlSearch(ringid int, keyType, description string, destRingid int) (id int, err error) {
	return keyctlSearch(KEYCTL_SEARCH, ringid, keyType, description, destRingid)
}

//sys	keyctlIOV(cmd int, arg2 int, payload []Iovec, arg5 int) (err error) = SYS_KEYCTL

// KeyctlInstantiateIOV implements the KEYCTL_INSTANTIATE_IOV command. This
// command is similar to KEYCTL_INSTANTIATE, except that the payload is a slice
// of Iovec (each of which represents a buffer) instead of a single buffer.
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_instantiate_iov.3.html
func KeyctlInstantiateIOV(id int, payload []Iovec, ringid int) error {
	return keyctlIOV(KEYCTL_INSTANTIATE_IOV, id, payload, ringid)
}

//sys	keyctlDH(cmd int, arg2 *KeyctlDHParams, buf []byte) (ret int, err error) = SYS_KEYCTL

// KeyctlDHCompute implements the KEYCTL_DH_COMPUTE command. This command
// computes a Diffie-Hellman shared secret based on the provide params. The
// secret is written to the provided buffer and the returned size is the number
// of bytes written (returning an error if there is insufficient space in the
// buffer). If a nil buffer is passed in, this function returns the minimum
// buffer length needed to store the appropriate data. Note that this differs
// from KEYCTL_READ's behavior which always returns the requested payload size.
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_dh_compute.3.html
func KeyctlDHCompute(params *KeyctlDHParams, buffer []byte) (size int, err error) {
	return keyctlDH(KEYCTL_DH_COMPUTE, params, buffer)
}

// KeyctlRestrictKeyring implements the KEYCTL_RESTRICT_KEYRING command. This
// command limits the set of keys that can be linked to the keyring, regardless
// of keyring permissions. The command requires the "setattr" permission.
//
// When called with an empty keyType the command locks the keyring, preventing
// any further keys from being linked to the keyring.
//
// The "asymmetric" keyType defines restrictions requiring key payloads to be
// DER encoded X.509 certificates signed by keys in another keyring. Restrictions
// for "asymmetric" include "builtin_trusted", "builtin_and_secondary_trusted",
// "key_or_keyring:<key>", and "key_or_keyring:<key>:chain".
//
// As of Linux 4.12, only the "asymmetric" keyType defines type-specific
// restrictions.
//
// See the full documentation at:
// http://man7.org/linux/man-pages/man3/keyctl_restrict_keyring.3.html
// http://man7.org/linux/man-pages/man2/keyctl.2.html
func KeyctlRestrictKeyring(ringid int, keyType string, restriction string) error {
	if keyType == "" {
		return keyctlRestrictKeyring(KEYCTL_RESTRICT_KEYRING, ringid)
	}
	return keyctlRestrictKeyringByType(KEYCTL_RESTRICT_KEYRING, ringid, keyType, restriction)
}

//sys	keyctlRestrictKeyringByType(cmd int, arg2 int, keyType string, restriction string) (err error) = SYS_KEYCTL
//sys	keyctlRestrictKeyring(cmd int, arg2 int) (err error) = SYS_KEYCTL

func recvmsgRaw(fd int, iov []Iovec, oob []byte, flags int, rsa *RawSockaddrAny) (n, oobn int, recvflags int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(rsa))
	msg.Namelen = uint32(SizeofSockaddrAny)
	var dummy byte
	if len(oob) > 0 {
		if emptyIovecs(iov) {
			var sockType int
			sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
			if err != nil {
				return
			}
			// receive at least one normal byte
			if sockType != SOCK_DGRAM {
				var iova [1]Iovec
				iova[0].Base = &dummy
				iova[0].SetLen(1)
				iov = iova[:]
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	if len(iov) > 0 {
		msg.Iov = &iov[0]
		msg.SetIovlen(len(iov))
	}
	if n, err = recvmsg(fd, &msg, flags); err != nil {
		return
	}
	oobn = int(msg.Controllen)
	recvflags = int(msg.Flags)
	return
}

func sendmsgN(fd int, iov []Iovec, oob []byte, ptr unsafe.Pointer, salen _Socklen, flags int) (n int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(ptr)
	msg.Namelen = uint32(salen)
	var dummy byte
	var empty bool
	if len(oob) > 0 {
		empty = emptyIovecs(iov)
		if empty {
			var sockType int
			sockType, err = GetsockoptInt(fd, SOL_SOCKET, SO_TYPE)
			if err != nil {
				return 0, err
			}
			// send at least one normal byte
			if sockType != SOCK_DGRAM {
				var iova [1]Iovec
				iova[0].Base = &dummy
				iova[0].SetLen(1)
				iov = iova[:]
			}
		}
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	if len(iov) > 0 {
		msg.Iov = &iov[0]
		msg.SetIovlen(len(iov))
	}
	if n, err = sendmsg(fd, &msg, flags); err != nil {
		return 0, err
	}
	if len(oob) > 0 && empty {
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

	var buf [SizeofPtr]byte

	// Leading edge. PEEKTEXT/PEEKDATA don't require aligned
	// access (PEEKUSER warns that it might), but if we don't
	// align our reads, we might straddle an unmapped page
	// boundary and not get the bytes leading up to the page
	// boundary.
	n := 0
	if addr%SizeofPtr != 0 {
		err = ptracePtr(req, pid, addr-addr%SizeofPtr, unsafe.Pointer(&buf[0]))
		if err != nil {
			return 0, err
		}
		n += copy(out, buf[addr%SizeofPtr:])
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

func PtracePeekUser(pid int, addr uintptr, out []byte) (count int, err error) {
	return ptracePeek(PTRACE_PEEKUSR, pid, addr, out)
}

func ptracePoke(pokeReq int, peekReq int, pid int, addr uintptr, data []byte) (count int, err error) {
	// As for ptracePeek, we need to align our accesses to deal
	// with the possibility of straddling an invalid page.

	// Leading edge.
	n := 0
	if addr%SizeofPtr != 0 {
		var buf [SizeofPtr]byte
		err = ptracePtr(peekReq, pid, addr-addr%SizeofPtr, unsafe.Pointer(&buf[0]))
		if err != nil {
			return 0, err
		}
		n += copy(buf[addr%SizeofPtr:], data)
		word := *((*uintptr)(unsafe.Pointer(&buf[0])))
		err = ptrace(pokeReq, pid, addr-addr%SizeofPtr, word)
		if err != nil {
			return 0, err
		}
		data = data[n:]
	}

	// Interior.
	for len(data) > SizeofPtr {
		word := *((*uintptr)(unsafe.Pointer(&data[0])))
		err = ptrace(pokeReq, pid, addr+uintptr(n), word)
		if err != nil {
			return n, err
		}
		n += SizeofPtr
		data = data[SizeofPtr:]
	}

	// Trailing edge.
	if len(data) > 0 {
		var buf [SizeofPtr]byte
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

func PtracePokeUser(pid int, addr uintptr, data []byte) (count int, err error) {
	return ptracePoke(PTRACE_POKEUSR, PTRACE_PEEKUSR, pid, addr, data)
}

// elfNT_PRSTATUS is a copy of the debug/elf.NT_PRSTATUS constant so
// x/sys/unix doesn't need to depend on debug/elf and thus
// compress/zlib, debug/dwarf, and other packages.
const elfNT_PRSTATUS = 1

func PtraceGetRegs(pid int, regsout *PtraceRegs) (err error) {
	var iov Iovec
	iov.Base = (*byte)(unsafe.Pointer(regsout))
	iov.SetLen(int(unsafe.Sizeof(*regsout)))
	return ptracePtr(PTRACE_GETREGSET, pid, uintptr(elfNT_PRSTATUS), unsafe.Pointer(&iov))
}

func PtraceSetRegs(pid int, regs *PtraceRegs) (err error) {
	var iov Iovec
	iov.Base = (*byte)(unsafe.Pointer(regs))
	iov.SetLen(int(unsafe.Sizeof(*regs)))
	return ptracePtr(PTRACE_SETREGSET, pid, uintptr(elfNT_PRSTATUS), unsafe.Pointer(&iov))
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

func PtraceInterrupt(pid int) (err error) { return ptrace(PTRACE_INTERRUPT, pid, 0, 0) }

func PtraceAttach(pid int) (err error) { return ptrace(PTRACE_ATTACH, pid, 0, 0) }

func PtraceSeize(pid int) (err error) { return ptrace(PTRACE_SEIZE, pid, 0, 0) }

func PtraceDetach(pid int) (err error) { return ptrace(PTRACE_DETACH, pid, 0, 0) }

//sys	reboot(magic1 uint, magic2 uint, cmd int, arg string) (err error)

func Reboot(cmd int) (err error) {
	return reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, "")
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

//sys	mountSetattr(dirfd int, pathname string, flags uint, attr *MountAttr, size uintptr) (err error) = SYS_MOUNT_SETATTR

// MountSetattr is a wrapper for mount_setattr(2).
// https://man7.org/linux/man-pages/man2/mount_setattr.2.html
//
// Requires kernel >= 5.12.
func MountSetattr(dirfd int, pathname string, flags uint, attr *MountAttr) error {
	return mountSetattr(dirfd, pathname, flags, attr, unsafe.Sizeof(*attr))
}

func Sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	return sendfile(outfd, infd, offset, count)
}

// Sendto
// Recvfrom
// Socketpair

/*
 * Direct access
 */
//sys	Acct(path string) (err error)
//sys	AddKey(keyType string, description string, payload []byte, ringid int) (id int, err error)
//sys	Adjtimex(buf *Timex) (state int, err error)
//sysnb	Capget(hdr *CapUserHeader, data *CapUserData) (err error)
//sysnb	Capset(hdr *CapUserHeader, data *CapUserData) (err error)
//sys	Chdir(path string) (err error)
//sys	Chroot(path string) (err error)
//sys	ClockAdjtime(clockid int32, buf *Timex) (state int, err error)
//sys	ClockGetres(clockid int32, res *Timespec) (err error)
//sys	ClockGettime(clockid int32, time *Timespec) (err error)
//sys	ClockSettime(clockid int32, time *Timespec) (err error)
//sys	ClockNanosleep(clockid int32, flags int, request *Timespec, remain *Timespec) (err error)
//sys	Close(fd int) (err error)
//sys	CloseRange(first uint, last uint, flags uint) (err error)
//sys	CopyFileRange(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int, err error)
//sys	DeleteModule(name string, flags int) (err error)
//sys	Dup(oldfd int) (fd int, err error)

func Dup2(oldfd, newfd int) error {
	return Dup3(oldfd, newfd, 0)
}

//sys	Dup3(oldfd int, newfd int, flags int) (err error)
//sysnb	EpollCreate1(flag int) (fd int, err error)
//sysnb	EpollCtl(epfd int, op int, fd int, event *EpollEvent) (err error)
//sys	Eventfd(initval uint, flags int) (fd int, err error) = SYS_EVENTFD2
//sys	Exit(code int) = SYS_EXIT_GROUP
//sys	Fallocate(fd int, mode uint32, off int64, len int64) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	Fdatasync(fd int) (err error)
//sys	Fgetxattr(fd int, attr string, dest []byte) (sz int, err error)
//sys	FinitModule(fd int, params string, flags int) (err error)
//sys	Flistxattr(fd int, dest []byte) (sz int, err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fremovexattr(fd int, attr string) (err error)
//sys	Fsetxattr(fd int, attr string, dest []byte, flags int) (err error)
//sys	Fsync(fd int) (err error)
//sys	Fsmount(fd int, flags int, mountAttrs int) (fsfd int, err error)
//sys	Fsopen(fsName string, flags int) (fd int, err error)
//sys	Fspick(dirfd int, pathName string, flags int) (fd int, err error)

//sys	fsconfig(fd int, cmd uint, key *byte, value *byte, aux int) (err error)

func fsconfigCommon(fd int, cmd uint, key string, value *byte, aux int) (err error) {
	var keyp *byte
	if keyp, err = BytePtrFromString(key); err != nil {
		return
	}
	return fsconfig(fd, cmd, keyp, value, aux)
}

// FsconfigSetFlag is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_SET_FLAG.
//
// fd is the filesystem context to act upon.
// key the parameter key to set.
func FsconfigSetFlag(fd int, key string) (err error) {
	return fsconfigCommon(fd, FSCONFIG_SET_FLAG, key, nil, 0)
}

// FsconfigSetString is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_SET_STRING.
//
// fd is the filesystem context to act upon.
// key the parameter key to set.
// value is the parameter value to set.
func FsconfigSetString(fd int, key string, value string) (err error) {
	var valuep *byte
	if valuep, err = BytePtrFromString(value); err != nil {
		return
	}
	return fsconfigCommon(fd, FSCONFIG_SET_STRING, key, valuep, 0)
}

// FsconfigSetBinary is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_SET_BINARY.
//
// fd is the filesystem context to act upon.
// key the parameter key to set.
// value is the parameter value to set.
func FsconfigSetBinary(fd int, key string, value []byte) (err error) {
	if len(value) == 0 {
		return EINVAL
	}
	return fsconfigCommon(fd, FSCONFIG_SET_BINARY, key, &value[0], len(value))
}

// FsconfigSetPath is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_SET_PATH.
//
// fd is the filesystem context to act upon.
// key the parameter key to set.
// path is a non-empty path for specified key.
// atfd is a file descriptor at which to start lookup from or AT_FDCWD.
func FsconfigSetPath(fd int, key string, path string, atfd int) (err error) {
	var valuep *byte
	if valuep, err = BytePtrFromString(path); err != nil {
		return
	}
	return fsconfigCommon(fd, FSCONFIG_SET_PATH, key, valuep, atfd)
}

// FsconfigSetPathEmpty is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_SET_PATH_EMPTY. The same as
// FconfigSetPath but with AT_PATH_EMPTY implied.
func FsconfigSetPathEmpty(fd int, key string, path string, atfd int) (err error) {
	var valuep *byte
	if valuep, err = BytePtrFromString(path); err != nil {
		return
	}
	return fsconfigCommon(fd, FSCONFIG_SET_PATH_EMPTY, key, valuep, atfd)
}

// FsconfigSetFd is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_SET_FD.
//
// fd is the filesystem context to act upon.
// key the parameter key to set.
// value is a file descriptor to be assigned to specified key.
func FsconfigSetFd(fd int, key string, value int) (err error) {
	return fsconfigCommon(fd, FSCONFIG_SET_FD, key, nil, value)
}

// FsconfigCreate is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_CMD_CREATE.
//
// fd is the filesystem context to act upon.
func FsconfigCreate(fd int) (err error) {
	return fsconfig(fd, FSCONFIG_CMD_CREATE, nil, nil, 0)
}

// FsconfigReconfigure is equivalent to fsconfig(2) called
// with cmd == FSCONFIG_CMD_RECONFIGURE.
//
// fd is the filesystem context to act upon.
func FsconfigReconfigure(fd int) (err error) {
	return fsconfig(fd, FSCONFIG_CMD_RECONFIGURE, nil, nil, 0)
}

//sys	Getdents(fd int, buf []byte) (n int, err error) = SYS_GETDENTS64
//sysnb	Getpgid(pid int) (pgid int, err error)

func Getpgrp() (pid int) {
	pid, _ = Getpgid(0)
	return
}

//sysnb	Getpid() (pid int)
//sysnb	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (prio int, err error)

func Getrandom(buf []byte, flags int) (n int, err error) {
	vdsoRet, supported := vgetrandom(buf, uint32(flags))
	if supported {
		if vdsoRet < 0 {
			return 0, errnoErr(syscall.Errno(-vdsoRet))
		}
		return vdsoRet, nil
	}
	var p *byte
	if len(buf) > 0 {
		p = &buf[0]
	}
	r, _, e := Syscall(SYS_GETRANDOM, uintptr(unsafe.Pointer(p)), uintptr(len(buf)), uintptr(flags))
	if e != 0 {
		return 0, errnoErr(e)
	}
	return int(r), nil
}

//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Getsid(pid int) (sid int, err error)
//sysnb	Gettid() (tid int)
//sys	Getxattr(path string, attr string, dest []byte) (sz int, err error)
//sys	InitModule(moduleImage []byte, params string) (err error)
//sys	InotifyAddWatch(fd int, pathname string, mask uint32) (watchdesc int, err error)
//sysnb	InotifyInit1(flags int) (fd int, err error)
//sysnb	InotifyRmWatch(fd int, watchdesc uint32) (success int, err error)
//sysnb	Kill(pid int, sig syscall.Signal) (err error)
//sys	Klogctl(typ int, buf []byte) (n int, err error) = SYS_SYSLOG
//sys	Lgetxattr(path string, attr string, dest []byte) (sz int, err error)
//sys	Listxattr(path string, dest []byte) (sz int, err error)
//sys	Llistxattr(path string, dest []byte) (sz int, err error)
//sys	Lremovexattr(path string, attr string) (err error)
//sys	Lsetxattr(path string, attr string, data []byte, flags int) (err error)
//sys	MemfdCreate(name string, flags int) (fd int, err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mknodat(dirfd int, path string, mode uint32, dev int) (err error)
//sys	MoveMount(fromDirfd int, fromPathName string, toDirfd int, toPathName string, flags int) (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	OpenTree(dfd int, fileName string, flags uint) (r int, err error)
//sys	PerfEventOpen(attr *PerfEventAttr, pid int, cpu int, groupFd int, flags int) (fd int, err error)
//sys	PivotRoot(newroot string, putold string) (err error) = SYS_PIVOT_ROOT
//sys	Prctl(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) (err error)
//sys	pselect6(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *sigset_argpack) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Removexattr(path string, attr string) (err error)
//sys	Renameat2(olddirfd int, oldpath string, newdirfd int, newpath string, flags uint) (err error)
//sys	RequestKey(keyType string, description string, callback string, destRingid int) (id int, err error)
//sys	Setdomainname(p []byte) (err error)
//sys	Sethostname(p []byte) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tv *Timeval) (err error)
//sys	Setns(fd int, nstype int) (err error)

//go:linkname syscall_prlimit syscall.prlimit
func syscall_prlimit(pid, resource int, newlimit, old *syscall.Rlimit) error

func Prlimit(pid, resource int, newlimit, old *Rlimit) error {
	// Just call the syscall version, because as of Go 1.21
	// it will affect starting a new process.
	return syscall_prlimit(pid, resource, (*syscall.Rlimit)(newlimit), (*syscall.Rlimit)(old))
}

// PrctlRetInt performs a prctl operation specified by option and further
// optional arguments arg2 through arg5 depending on option. It returns a
// non-negative integer that is returned by the prctl syscall.
func PrctlRetInt(option int, arg2 uintptr, arg3 uintptr, arg4 uintptr, arg5 uintptr) (int, error) {
	ret, _, err := Syscall6(SYS_PRCTL, uintptr(option), uintptr(arg2), uintptr(arg3), uintptr(arg4), uintptr(arg5), 0)
	if err != 0 {
		return 0, err
	}
	return int(ret), nil
}

func Setuid(uid int) (err error) {
	return syscall.Setuid(uid)
}

func Setgid(gid int) (err error) {
	return syscall.Setgid(gid)
}

func Setreuid(ruid, euid int) (err error) {
	return syscall.Setreuid(ruid, euid)
}

func Setregid(rgid, egid int) (err error) {
	return syscall.Setregid(rgid, egid)
}

func Setresuid(ruid, euid, suid int) (err error) {
	return syscall.Setresuid(ruid, euid, suid)
}

func Setresgid(rgid, egid, sgid int) (err error) {
	return syscall.Setresgid(rgid, egid, sgid)
}

// SetfsgidRetGid sets fsgid for current thread and returns previous fsgid set.
// setfsgid(2) will return a non-nil error only if its caller lacks CAP_SETUID capability.
// If the call fails due to other reasons, current fsgid will be returned.
func SetfsgidRetGid(gid int) (int, error) {
	return setfsgid(gid)
}

// SetfsuidRetUid sets fsuid for current thread and returns previous fsuid set.
// setfsgid(2) will return a non-nil error only if its caller lacks CAP_SETUID capability
// If the call fails due to other reasons, current fsuid will be returned.
func SetfsuidRetUid(uid int) (int, error) {
	return setfsuid(uid)
}

func Setfsgid(gid int) error {
	_, err := setfsgid(gid)
	return err
}

func Setfsuid(uid int) error {
	_, err := setfsuid(uid)
	return err
}

func Signalfd(fd int, sigmask *Sigset_t, flags int) (newfd int, err error) {
	return signalfd(fd, s
"""




```