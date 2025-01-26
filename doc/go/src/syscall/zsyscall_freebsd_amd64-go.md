Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understanding the Context:** The first line `// mksyscall.pl -tags freebsd,amd64 syscall_bsd.go syscall_freebsd.go syscall_freebsd_amd64.go` and the `//go:build freebsd && amd64` comment are crucial. They immediately tell us this file is auto-generated (`DO NOT EDIT`) and specifically for the FreeBSD operating system on the AMD64 architecture. This means the functions in this file are likely system calls specific to that environment.

2. **Identifying the Core Mechanism:**  Scanning through the function bodies, a recurring pattern emerges: `RawSyscall`, `Syscall`, and `Syscall6`. These are Go's mechanisms for directly interacting with the operating system kernel. The first argument to these functions is always a constant starting with `SYS_`. This strongly suggests that each function in this file is a Go wrapper around a specific FreeBSD system call.

3. **Analyzing Individual Functions (Pattern Recognition):**  Now we can go through each function and identify the system call it's wrapping. The naming convention is generally helpful: `getgroups` likely corresponds to the `getgroups` system call, `setgroups` to `setgroups`, and so on.

4. **Mapping Go Functions to System Calls:** For each function, we can make a direct mapping between the Go function name and the `SYS_` constant. This gives us the core functionality.

5. **Inferring Go Language Features:**  Since these are system call wrappers, they enable various operating system functionalities within Go. We can categorize these features:

    * **Process Management:**  Functions like `getgroups`, `setgroups`, `wait4`, `getpid`, `getppid`, `kill`, `setpgid`, `setsid`, `getpriority`, `setpriority`, `getrlimit`, `setrlimit`, `getrusage`. These clearly relate to managing processes, their groups, sessions, and resource limits.

    * **File System Operations:**  A large group includes `open`, `close`, `read`, `write`, `link`, `unlink`, `mkdir`, `rmdir`, `rename`, `chmod`, `chown`, `truncate`, `stat`, `lstat`, `fstat`, `access`, `chdir`, `chroot`, `utimes`, `futimes`, `pread`, `pwrite`, `readlink`, `symlink`, `mkfifo`, `mknodat`, `pathconf`, `fpathconf`, `statfs`, `fstatfs`, `fsync`, `flock`, `undelete`. These are the fundamental operations for interacting with the file system.

    * **Networking:**  Functions like `socket`, `bind`, `listen`, `accept`, `connect`, `sendto`, `recvfrom`, `getsockopt`, `setsockopt`, `getpeername`, `getsockname`, `shutdown`, `socketpair`, `recvmsg`, `sendmsg`, `accept4`. These deal with creating and managing network connections.

    * **Time and Scheduling:**  Functions like `nanosleep`, `gettimeofday`, `settimeofday`, `adjtime`. These are related to controlling time and scheduling.

    * **Memory Management:**  `mmap`, `munmap` are clearly about memory mapping.

    * **Inter-Process Communication (IPC) and Signals:** `pipe2`, `kill`, `kevent`, `select`. These enable communication and event notification between processes.

    * **User and Group IDs:** `getuid`, `geteuid`, `getgid`, `getegid`, `setuid`, `seteuid`, `setgid`, `setegid`, `setregid`, `setreuid`, `issetugid`. These are for managing user and group identities.

    * **Terminal/Device Control:** `ioctl`, `fcntl`. These provide low-level control over file descriptors and devices.

    * **Current Working Directory:** `getcwd`.

    * **System Information/Control:** `sysctl`, `getdtablesize`.

6. **Providing Go Code Examples:**  Once the functionality is understood, we can demonstrate how to use the corresponding higher-level Go packages that utilize these system calls. For instance, `os.Getpid()` uses the `Getpid` system call, `os.Open()` uses `Open`, `net.Listen()` uses `socket`, `bind`, and `listen`, and so on. The examples should illustrate basic usage and the relationship to the system calls.

7. **Inferring Input/Output (if applicable):**  For functions that manipulate data (like `read`, `write`, `recvfrom`, `sendto`), we can hypothesize inputs and outputs to show how data flows. For example, `read` takes a file descriptor and a byte slice and returns the number of bytes read and potentially an error.

8. **Command-Line Arguments (if applicable):**  While these functions themselves don't directly process command-line arguments, some higher-level Go functions that *use* them might. For example, the `os.Open()` function, which relies on the `Open` syscall, might be called with a filename provided as a command-line argument.

9. **Identifying Common Mistakes:**  Thinking about how these low-level functions are used, we can identify potential pitfalls. For example, forgetting to check for errors after a syscall is a common mistake, as is incorrect handling of memory when using pointers. Network programming with sockets also has its own set of common errors (incorrect addresses, ports, etc.).

10. **Structuring the Answer:** Finally, organize the findings into a clear and structured answer, addressing each part of the prompt. Use headings and bullet points for readability. Explain the purpose of the file, its generation process, and then detail the functionality of the included system calls with examples.

**Self-Correction/Refinement during the process:**

* Initially, I might just list the functions without grouping them. Realizing the large number of functions, I'd then group them by functionality (process management, file system, networking, etc.) to make the answer more organized.
* For code examples, I'd start with very simple cases and then consider adding more complex scenarios if needed for clarity.
* When considering common mistakes, I'd think about the typical errors developers encounter when working with system calls or the higher-level abstractions that use them.

By following these steps, combining code analysis with knowledge of operating system concepts and Go's standard library, we can effectively understand and explain the purpose and functionality of the given Go code snippet.
这是路径为 `go/src/syscall/zsyscall_freebsd_amd64.go` 的 Go 语言实现的一部分，它定义了在 FreeBSD 操作系统（amd64 架构）上直接调用系统调用的底层函数。

**功能列表:**

该文件中的每一个 Go 函数都对应一个 FreeBSD 系统调用。以下是这些函数的功能概述：

* **进程管理:**
    * `getgroups`: 获取当前进程所属的组 ID 列表。
    * `setgroups`: 设置当前进程所属的组 ID 列表。
    * `wait4`: 等待子进程状态改变。
    * `Getdtablesize`: 获取进程可以打开的最大文件描述符数量。
    * `Getegid`: 获取有效组 ID。
    * `Geteuid`: 获取有效用户 ID。
    * `Getgid`: 获取组 ID。
    * `Getpgid`: 获取进程组 ID。
    * `Getpgrp`: 获取当前进程组 ID。
    * `Getpid`: 获取当前进程 ID。
    * `Getppid`: 获取父进程 ID。
    * `Getpriority`: 获取进程的调度优先级。
    * `Getrlimit`: 获取进程的资源限制。
    * `Getrusage`: 获取进程的资源使用情况。
    * `Getsid`: 获取会话 ID。
    * `Kill`: 向进程发送信号。
    * `Setegid`: 设置有效组 ID。
    * `Seteuid`: 设置有效用户 ID。
    * `Setgid`: 设置组 ID。
    * `Setlogin`: 设置登录名。
    * `Setpgid`: 设置进程组 ID。
    * `Setpriority`: 设置进程的调度优先级。
    * `Setregid`: 设置真实和有效的组 ID。
    * `Setreuid`: 设置真实和有效的用户 ID。
    * `setrlimit`: 设置进程的资源限制。
    * `Setsid`: 创建一个新的会话。
    * `Setuid`: 设置用户 ID。

* **文件系统操作:**
    * `accept`: 接受一个 socket 连接。
    * `bind`: 将 socket 绑定到一个地址。
    * `connect`: 连接到一个 socket 地址。
    * `socket`: 创建一个 socket。
    * `getsockopt`: 获取 socket 选项。
    * `setsockopt`: 设置 socket 选项。
    * `getpeername`: 获取连接的另一端的地址。
    * `getsockname`: 获取 socket 自身的地址。
    * `Shutdown`: 关闭 socket 的读写端。
    * `socketpair`: 创建一对已连接的 socket。
    * `recvfrom`: 从 socket 接收数据。
    * `sendto`: 向 socket 发送数据。
    * `recvmsg`: 从 socket 接收消息。
    * `sendmsg`: 向 socket 发送消息。
    * `utimes`: 修改文件的访问和修改时间。
    * `futimes`: 修改文件描述符对应文件的访问和修改时间。
    * `fcntl`: 对文件描述符执行各种操作。
    * `fcntlPtr`:  `fcntl` 的一个变体，接受 `unsafe.Pointer` 类型的参数。
    * `ioctl`: 对设备执行控制操作。
    * `ioctlPtr`: `ioctl` 的一个变体，接受 `unsafe.Pointer` 类型的参数。
    * `pipe2`: 创建一个管道。
    * `Access`: 检查用户是否对文件有指定的访问权限。
    * `Chdir`: 改变当前工作目录。
    * `Chflags`: 修改文件的标志。
    * `Chmod`: 修改文件的权限。
    * `Chown`: 修改文件的所有者。
    * `Chroot`: 改变进程的根目录。
    * `Close`: 关闭文件描述符。
    * `Dup`: 复制文件描述符。
    * `Dup2`: 将一个文件描述符复制到另一个指定的文件描述符。
    * `Fchdir`: 将当前工作目录更改为由文件描述符表示的目录。
    * `Fchflags`: 修改文件描述符对应文件的标志。
    * `Fchmod`: 修改文件描述符对应文件的权限。
    * `Fchown`: 修改文件描述符对应文件的所有者。
    * `Flock`: 对文件加锁或解锁。
    * `Fpathconf`: 获取与文件描述符关联的配置信息。
    * `Fstat`: 获取文件描述符对应文件的状态信息。
    * `Fstatat`: 相对于目录文件描述符获取文件的状态信息。
    * `Fstatfs`: 获取文件描述符对应文件系统的信息。
    * `Fsync`: 将文件描述符的所有修改过的元数据和文件数据刷新到存储设备。
    * `Ftruncate`: 将文件描述符对应文件截断为指定长度。
    * `getdirentries`: 读取目录项。
    * `Link`: 创建一个硬链接。
    * `Listen`: 监听 socket 连接。
    * `Mkdir`: 创建一个目录。
    * `Mkfifo`: 创建一个 FIFO 特殊文件（命名管道）。
    * `mknodat`: 相对于目录文件描述符创建一个文件节点。
    * `Open`: 打开一个文件。
    * `Pathconf`: 获取与路径名关联的配置信息。
    * `pread`: 从指定偏移量读取文件。
    * `pwrite`: 从指定偏移量写入文件。
    * `read`: 从文件描述符读取数据。
    * `Readlink`: 读取符号链接的目标。
    * `Rename`: 重命名文件或目录。
    * `Revoke`: 撤销对文件的访问权限。
    * `Rmdir`: 删除一个空目录。
    * `Seek`: 改变文件描述符的偏移量。
    * `Statfs`: 获取文件系统的信息。
    * `Symlink`: 创建一个符号链接。
    * `Sync`: 将所有修改过的块缓冲区刷新到磁盘。
    * `Truncate`: 将文件截断为指定长度。
    * `Umask`: 设置文件模式创建掩码。
    * `Undelete`: 恢复已删除的文件。
    * `Unlink`: 删除一个文件的链接。
    * `Unmount`: 卸载文件系统。
    * `write`: 向文件描述符写入数据。
    * `utimensat`: 相对于目录文件描述符修改文件的访问和修改时间。
    * `getcwd`: 获取当前工作目录。

* **内存管理:**
    * `mmap`: 将文件或设备映射到内存。
    * `munmap`: 取消内存映射。

* **内核事件:**
    * `kevent`: 监控文件事件。
    * `Kqueue`: 创建一个内核事件队列。

* **时间相关:**
    * `Nanosleep`: 让当前进程休眠一段时间。
    * `Gettimeofday`: 获取当前时间。
    * `Settimeofday`: 设置系统时间。
    * `Adjtime`: 微调系统时钟。

* **其他:**
    * `Select`: 同步 I/O 多路复用。
    * `Issetugid`: 检查进程的有效用户 ID 或组 ID 是否与真实用户 ID 或组 ID 不同。
    * `sysctl`: 获取或设置内核参数。

**Go 语言功能的实现推理与代码示例:**

这个文件中的函数是 Go 语言 `syscall` 包的基础，它提供了直接访问操作系统系统调用的能力。  更高层次的 Go 标准库，例如 `os` 和 `net` 包，会在内部使用 `syscall` 包提供的这些函数来实现其功能。

例如，`os.Getpid()` 函数实际上会调用 `syscall.Getpid()` 系统调用：

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	pid := os.Getpid()
	fmt.Printf("当前进程的 PID: %d\n", pid)
}
```

**假设的输入与输出 (以 `read` 系统调用为例):**

假设我们有一个文件 "test.txt"，内容为 "Hello, World!"。

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
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("打开文件错误:", err)
		return
	}
	defer file.Close()

	fd := int(file.Fd())
	buffer := make([]byte, 10) // 读取 10 个字节
	n, err := syscall.Read(fd, buffer)
	if err != nil {
		fmt.Println("读取文件错误:", err)
		return
	}

	fmt.Printf("读取了 %d 个字节\n", n)
	fmt.Printf("读取的内容: %s\n", string(buffer[:n]))
}
```

**假设输入:** 文件 "test.txt" 存在且内容为 "Hello, World!"。
**假设输出:**
```
读取了 10 个字节
读取的内容: Hello, Worl
```

**命令行参数的具体处理:**

这个文件中的函数本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并传递给其他函数。例如，`os.Open()` 函数可以接收从命令行读取的文件名作为参数，然后在内部调用 `syscall.Open()`。

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("请提供文件名作为参数")
		return
	}
	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println("打开文件错误:", err)
		return
	}
	defer file.Close()
	fmt.Println("成功打开文件:", filename)
}
```

在这个例子中，`os.Args[1]` 获取命令行提供的第一个参数（文件名），然后传递给 `os.Open()`，而 `os.Open()` 最终会调用 `syscall.Open()`。

**使用者易犯错的点 (以 `syscall.Read` 为例):**

1. **缓冲区大小不足:** 如果提供的缓冲区 `p` 的大小小于实际需要读取的数据量，`syscall.Read` 只会读取部分数据。使用者需要根据预期的数据量合理设置缓冲区大小。

   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       file, _ := os.Create("small.txt")
       file.WriteString("This is a long string")
       file.Close()

       f, _ := os.Open("small.txt")
       defer f.Close()
       fd := int(f.Fd())
       buf := make([]byte, 5) // 缓冲区太小
       n, err := syscall.Read(fd, buf)
       if err != nil {
           fmt.Println(err)
       }
       fmt.Printf("读取了 %d 字节: %s\n", n, string(buf[:n])) // 只读取了 "This "
   }
   ```

2. **忘记检查错误:** 系统调用可能会失败，例如文件不存在、权限不足等。使用者必须检查 `syscall.Read` 返回的 `err` 值，并进行适当的错误处理。

   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       f, err := os.Open("nonexistent.txt")
       if err != nil {
           fmt.Println("打开文件失败:", err)
           return
       }
       defer f.Close()
       fd := int(f.Fd())
       buf := make([]byte, 10)
       n, err := syscall.Read(fd, buf) //  对已失败的文件描述符进行操作
       // 应该检查 err 的值
       fmt.Printf("读取了 %d 字节\n", n)
   }
   ```

3. **不正确地处理返回值:** `syscall.Read` 返回读取的字节数。使用者需要使用这个返回值来确定实际读取了多少数据，而不是直接使用整个缓冲区。

   ```go
   package main

   import (
       "fmt"
       "os"
       "syscall"
   )

   func main() {
       file, _ := os.Create("short.txt")
       file.WriteString("Short")
       file.Close()

       f, _ := os.Open("short.txt")
       defer f.Close()
       fd := int(f.Fd())
       buf := make([]byte, 10)
       n, err := syscall.Read(fd, buf)
       if err != nil {
           fmt.Println(err)
       }
       fmt.Printf("读取的内容: %s\n", string(buf)) // 错误：可能包含未初始化的部分
       fmt.Printf("读取的内容: %s\n", string(buf[:n])) // 正确
   }
   ```

总之，这个 `zsyscall_freebsd_amd64.go` 文件是 Go 语言与 FreeBSD 内核交互的桥梁，它提供了访问底层系统调用的能力，是构建更高级抽象的基础。直接使用这些函数需要对操作系统原理和系统调用有深入的理解，并小心处理错误和内存安全。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_freebsd_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// mksyscall.pl -tags freebsd,amd64 syscall_bsd.go syscall_freebsd.go syscall_freebsd_amd64.go
// Code generated by the command above; DO NOT EDIT.

//go:build freebsd && amd64

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

func Fstatat(fd int, path string, stat *Stat_t, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_FSTATAT, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstatfs(fd int, stat *Statfs_t) (err error) {
	_, _, e1 := Syscall(SYS_FSTATFS, uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
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
	_, _, e1 := Syscall(SYS_FTRUNCATE, uintptr(fd), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getdirentries(fd int, buf []byte, basep *uint64) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall6(SYS_GETDIRENTRIES, uintptr(fd), uintptr(_p0), uintptr(len(buf)), uintptr(unsafe.Pointer(basep)), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getdtablesize() (size int) {
	r0, _, _ := Syscall(SYS_GETDTABLESIZE, 0, 0, 0)
	size = int(r0)
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

func mknodat(fd int, path string, mode uint32, dev uint64) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_MKNODAT, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(dev), 0, 0)
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
	r0, _, e1 := Syscall6(SYS_PREAD, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), 0, 0)
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
	r0, _, e1 := Syscall6(SYS_PWRITE, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), 0, 0)
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
	r0, _, e1 := Syscall(SYS_LSEEK, uintptr(fd), uintptr(offset), uintptr(whence))
	newoffset = int64(r0)
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

func Setlogin(name string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(name)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_SETLOGIN, uintptr(unsafe.Pointer(_p0)), 0, 0)
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

func Statfs(path string, stat *Statfs_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_STATFS, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
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
	_, _, e1 := Syscall(SYS_TRUNCATE, uintptr(unsafe.Pointer(_p0)), uintptr(length), 0)
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

func Undelete(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UNDELETE, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
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
	r0, _, e1 := Syscall6(SYS_MMAP, uintptr(addr), uintptr(length), uintptr(prot), uintptr(flag), uintptr(fd), uintptr(pos))
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

func accept4(fd int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (nfd int, err error) {
	r0, _, e1 := Syscall6(SYS_ACCEPT4, uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
	nfd = int(r0)
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