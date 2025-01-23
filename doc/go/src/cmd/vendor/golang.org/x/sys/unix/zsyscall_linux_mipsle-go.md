Response:
Let's break down the thought process for analyzing the Go syscall file.

1. **Identify the Purpose:** The filename `zsyscall_linux_mipsle.go` and the build tag `//go:build linux && mipsle` immediately tell us this file contains syscall implementations specifically for the Linux operating system on the MIPS Little-Endian architecture. The "zsyscall" prefix likely indicates it's an auto-generated file. The comment at the top confirms this, mentioning `mksyscall.go`.

2. **High-Level Overview:** The code consists of numerous Go functions. Each function has a consistent structure:
    * A comment indicating it's auto-generated.
    * A function signature with parameters and return values (often `error` or `(int, error)` or `(int64, error)`).
    * A call to `Syscall`, `Syscall6`, `Syscall9`, or `RawSyscall`/`RawSyscallNoError`.
    * Error handling using `errnoErr`.

3. **Function-by-Function Analysis (Iterative Approach):**  Go through each function, trying to understand what system call it wraps.

    * **`fanotifyMark`**: The name suggests it deals with the `fanotify` system call, which is related to file access notifications. The parameters hint at marking files/directories for monitoring.

    * **`Fallocate`**: The name clearly indicates file allocation. The parameters `mode`, `off`, and `len` are typical for this type of operation.

    * **`Tee`**: This likely implements the `tee` system call for copying data between file descriptors.

    * **`EpollWait`**:  The name strongly suggests this is the `epoll_wait` system call, used for efficient event notification on multiple file descriptors. The `events []EpollEvent` parameter confirms this.

    * **`Fadvise`**: This looks like `fadvise`, providing hints to the kernel about expected file access patterns.

    * **`Fchown`**: Likely `fchown`, changing the owner and group of a file given its file descriptor.

    * **`Ftruncate`**:  Probably `ftruncate`, resizing a file to a specified length.

    * **`Getegid`, `Geteuid`, `Getgid`, `Getuid`**: These are straightforward: get effective/real GID/UID. The `RawSyscallNoError` suggests these are simple system calls that don't usually return errors.

    * **`Lchown`**:  Similar to `Fchown` but takes a path, indicating it's `lchown` for changing ownership of symbolic links.

    * **`Listen`**: This is clearly the `listen` system call for making a socket listen for incoming connections.

    * **`pread`, `pwrite`**: These are the "positional" read and write system calls (`pread64`, `pwrite64`), allowing reads/writes at a specific offset without changing the file descriptor's offset.

    * **`Renameat`**: The "at" suffix suggests a version that takes directory file descriptors, so it's `renameat`.

    * **`Select`**: This is the classic `select` system call for multiplexing I/O.

    * **`sendfile`**: Efficiently copies data between file descriptors.

    * **`setfsgid`, `setfsuid`**: Set the file system GID/UID.

    * **`Shutdown`**:  Shuts down part or all of a full-duplex connection.

    * **`Splice`**:  Moves data between two file descriptors without copying through user space.

    * **`SyncFileRange`**:  Flushes a specific range of a file to disk.

    * **`Truncate`**: Resizes a file given its path.

    * **`Ustat`**:  Gets file system statistics (less common).

    * **Socket-related functions (`accept4`, `bind`, `connect`, `getgroups`, `setgroups`, `getsockopt`, `setsockopt`, `socket`, `socketpair`, `getpeername`, `getsockname`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`): These are the standard socket system calls.

    * **Memory and Time related functions (`Ioperm`, `Iopl`, `futimesat`, `Gettimeofday`, `Time`, `Utime`, `utimes`, `Lstat`, `Fstat`, `Fstatat`, `Stat`, `Pause`, `mmap2`): These cover I/O port permissions, time manipulation, and file/filesystem stat information.

    * **Resource Limits (`getrlimit`)**.

    * **`Alarm`**:  Sets a timer to deliver a signal.

4. **Inferring Go Functionality:** Based on the identified system calls, we can infer the corresponding Go functionalities. For example, `EpollWait` is part of Go's `syscall` package and used for I/O multiplexing. Socket functions are used by Go's `net` package. File operations are often used with Go's `os` package.

5. **Code Examples:**  Construct simple Go examples demonstrating the usage of a few selected functions. Focus on common or interesting ones like `EpollWait`, `Tee`, and file operations.

6. **Command-Line Parameters:**  Analyze the `go run` command at the top of the file. This shows how the file was generated using `mksyscall`. Explain the meaning of the flags (`-l32`, `-arm`, `-tags`).

7. **Common Mistakes:**  Think about potential pitfalls when using low-level syscalls. Focus on memory management (passing pointers), error handling, and platform-specific behavior. The `EpollWait` example highlights the need to correctly size the event slice.

8. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Double-check the explanations and code examples. Ensure the language is precise and avoids jargon where possible. For example, be clear about the difference between file descriptor and file path based operations.

This systematic approach, combining code examination with knowledge of system call functionalities, allows for a comprehensive understanding of the provided Go code. The iterative nature of analyzing each function individually, then grouping them by category (file I/O, networking, etc.), makes the task manageable.这个Go语言文件 `zsyscall_linux_mipsle.go` 是 Go 标准库 `syscall` 包的一部分，它为运行在 Linux 操作系统且 CPU 架构为 MIPS Little-Endian (mipsle) 的系统提供了系统调用的底层接口。

**功能列表:**

这个文件定义了一系列 Go 函数，每个函数都对应一个特定的 Linux 系统调用。这些函数的主要功能是：

1. **文件操作:**
   - `Fallocate`:  在文件中预分配空间。
   - `Ftruncate`:  将文件截断为指定长度 (通过文件描述符)。
   - `SyncFileRange`: 将文件的一部分数据同步到磁盘。
   - `Truncate`: 将文件截断为指定长度 (通过文件路径)。
   - `pread`:  在指定偏移量读取文件数据，不改变文件偏移量。
   - `pwrite`: 在指定偏移量写入文件数据，不改变文件偏移量。
   - `sendfile`:  在两个文件描述符之间高效地复制数据。

2. **文件监控:**
   - `fanotifyMark`: 用于向 fanotify 文件事件通知系统添加或删除监控标记。

3. **进程/用户/组管理:**
   - `Fchown`:  更改文件的所有者和组 (通过文件描述符)。
   - `Getegid`: 获取当前进程的有效组ID。
   - `Geteuid`: 获取当前进程的有效用户ID。
   - `Getgid`: 获取当前进程的组ID。
   - `Getuid`: 获取当前进程的用户ID。
   - `Lchown`:  更改文件的所有者和组，如果是符号链接，则更改链接本身。
   - `setfsgid`: 设置文件系统组ID。
   - `setfsuid`: 设置文件系统用户ID。
   - `getgroups`: 获取进程所属的所有组ID。
   - `setgroups`: 设置进程所属的组ID。

4. **I/O 多路复用:**
   - `EpollWait`: 等待 epoll 实例上的事件。
   - `Select`:  等待多个文件描述符上的 I/O 事件。

5. **Socket 网络:**
   - `Listen`:  监听 socket 上的连接。
   - `accept4`: 接受 socket 连接，并可以设置一些标志。
   - `bind`: 将 socket 绑定到特定的地址和端口。
   - `connect`: 连接到指定地址的 socket。
   - `getsockopt`: 获取 socket 选项。
   - `setsockopt`: 设置 socket 选项。
   - `socket`: 创建一个 socket。
   - `socketpair`: 创建一对连接的、匿名的 socket。
   - `getpeername`: 获取连接到 socket 的对端的地址。
   - `getsockname`: 获取 socket 自身的地址。
   - `recvfrom`: 从 socket 接收数据，并获取发送端的地址。
   - `sendto`: 向指定地址的 socket 发送数据。
   - `recvmsg`: 从 socket 接收消息。
   - `sendmsg`: 向 socket 发送消息。
   - `Shutdown`: 关闭 socket 的发送或接收端。

6. **管道操作:**
   - `Tee`:  在两个文件描述符之间复制数据。
   - `Splice`: 在两个文件描述符之间移动数据，无需在用户空间中复制。

7. **内存管理:**
   - `mmap2`:  将文件或设备映射到内存。

8. **文件系统信息:**
   - `Lstat`: 获取文件或符号链接的状态信息，不追踪符号链接。
   - `Fstat`: 获取已打开文件的状态信息。
   - `Fstatat`: 获取相对于目录文件描述符的文件的状态信息。
   - `Stat`: 获取文件的状态信息。
   - `Ustat`: 获取文件系统统计信息 (已废弃，不推荐使用)。

9. **时间操作:**
   - `Gettimeofday`: 获取当前时间。
   - `Time`: 获取当前时间戳。
   - `Utime`: 设置文件的访问和修改时间。
   - `utimes`: 设置文件的访问和修改时间。
   - `futimesat`: 设置相对于目录文件描述符的文件的访问和修改时间。

10. **I/O 端口操作 (特权操作):**
    - `Ioperm`: 设置进程的 I/O 端口权限。
    - `Iopl`: 设置进程的 I/O 权限级别。

11. **文件建议:**
    - `Fadvise`: 向内核提供关于文件访问模式的建议。

12. **重命名:**
    - `Renameat`: 相对于目录文件描述符重命名文件。

13. **资源限制:**
    - `getrlimit`: 获取进程的资源限制。

14. **信号:**
    - `Alarm`: 设置一个定时器，在指定时间后发送一个 SIGALRM 信号。
    - `Pause`:  等待直到接收到一个信号。

**Go 语言功能的实现 (举例说明):**

这个文件中的函数是 Go 语言 `syscall` 包中对应系统调用的直接映射。更上层的 Go 标准库，例如 `os` 和 `net` 包，会使用这些底层的 `syscall` 函数来实现更高级的功能。

**示例 1: 文件读取**

假设我们要读取一个文件的一部分内容，可以使用 `pread` 系统调用。

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
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	fd := int(file.Fd())
	offset := int64(5)
	length := 10
	buffer := make([]byte, length)

	n, err := syscall.Pread(fd, buffer, offset)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	fmt.Printf("Read %d bytes: %s\n", n, string(buffer[:n]))
}
```

**假设输入 (test.txt):**

```
0123456789abcdefghij
```

**输出:**

```
Read 10 bytes: 56789abcdef
```

在这个例子中，`os.Open` 打开文件，我们获取了文件的文件描述符。然后，我们使用 `syscall.Pread` 函数，它在底层调用了 `pread` 系统调用来读取从偏移量 5 开始的 10 个字节的数据。

**示例 2: 创建并监听 Socket**

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
	rawAddr, _ := syscall.SockaddrInet4Ptr(&addr)

	err = syscall.Bind(fd, rawAddr)
	if err != nil {
		fmt.Println("Error binding socket:", err)
		return
	}

	// 监听连接
	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		fmt.Println("Error listening on socket:", err)
		return
	}

	fmt.Println("Listening on port 8080...")
}
```

这个例子展示了如何使用底层的 `syscall.Socket`, `syscall.Bind`, 和 `syscall.Listen` 函数来创建一个 TCP socket 并监听连接。这与 `net.Listen("tcp", ":8080")` 在底层实现上是相关的。

**命令行参数处理:**

此代码片段本身不直接处理命令行参数。它是一个提供系统调用接口的底层库。  命令行参数的处理通常发生在更上层的应用程序代码中。

然而，文件开头的注释 `// go run mksyscall.go -l32 -arm -tags linux,mipsle syscall_linux.go syscall_linux_mipsx.go syscall_linux_alarm.go`  展示了如何使用 `mksyscall.go` 工具来生成这个文件。

* `mksyscall.go`:  Go 自带的一个工具，用于根据定义生成系统调用的 Go 代码。
* `-l32`:  指定生成 32 位系统的系统调用代码。
* `-arm`:  **注意:** 这里看起来有些不一致，`-arm` 通常用于 ARM 架构，而文件名和 build tag 指明了 `mipsle` (MIPS Little-Endian)。 这可能是个错误或者构建脚本中存在某些特定配置。在实际针对 mipsle 构建时，这个参数应该与目标架构匹配。
* `-tags linux,mipsle`:  指定生成的代码应该包含 `linux` 和 `mipsle` 的 build tags，这意味着这段代码只会在 Linux 系统且 CPU 架构为 MIPS Little-Endian 时编译。
* `syscall_linux.go syscall_linux_mipsx.go syscall_linux_alarm.go`: 这些是 `mksyscall` 工具读取的输入文件，其中包含了系统调用的定义。

**使用者易犯错的点:**

1. **错误处理:** 直接使用 `syscall` 包中的函数时，必须显式地检查返回的 `error`。忽略错误会导致程序行为不可预测。

   ```go
   fd, err := syscall.Open("nonexistent_file", syscall.O_RDONLY, 0)
   if err != nil {
       // 必须处理错误，例如打印日志或返回错误
       fmt.Println("Error opening file:", err)
       return
   }
   defer syscall.Close(fd)
   ```

2. **平台依赖性:**  `syscall` 包中的代码是平台相关的。这段代码只在 Linux 的 MIPS Little-Endian 系统上有效。在其他系统上使用可能会导致编译错误或运行时错误。

3. **unsafe.Pointer 的使用:** 许多 `syscall` 函数需要使用 `unsafe.Pointer` 来传递指针。不正确地使用 `unsafe.Pointer` 可能会导致内存安全问题。例如，确保传递的指针指向的内存是有效的，并且生命周期足够长。

4. **参数传递错误:** 系统调用的参数类型和含义与 Go 的类型可能不完全一致。例如，socket 地址结构体需要正确地填充。

   ```go
   var addr syscall.SockaddrInet4
   addr.Port = 8080
   copy(addr.Addr[:], net.ParseIP("127.0.0.1").To4()) // 确保 IP 地址正确转换
   rawAddr, _ := syscall.SockaddrInet4Ptr(&addr)
   syscall.Connect(fd, rawAddr)
   ```

5. **资源管理:**  使用完文件描述符、socket 等资源后，必须手动关闭它们，否则会导致资源泄漏。通常使用 `defer syscall.Close(fd)` 来确保资源被释放。

总而言之，`zsyscall_linux_mipsle.go` 文件是 Go 语言与 Linux 内核在 MIPS Little-Endian 架构上进行交互的桥梁，提供了执行底层系统调用的能力。直接使用这个包需要对操作系统原理和系统调用有深入的理解，并且需要谨慎处理错误和资源管理。 上层的标准库通常提供了更安全和便捷的接口来完成相同的任务。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsyscall_linux_mipsle.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run mksyscall.go -l32 -arm -tags linux,mipsle syscall_linux.go syscall_linux_mipsx.go syscall_linux_alarm.go
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build linux && mipsle

package unix

import (
	"syscall"
	"unsafe"
)

var _ syscall.Errno

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname *byte) (err error) {
	_, _, e1 := Syscall6(SYS_FANOTIFY_MARK, uintptr(fd), uintptr(flags), uintptr(mask), uintptr(mask>>32), uintptr(dirFd), uintptr(unsafe.Pointer(pathname)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fallocate(fd int, mode uint32, off int64, len int64) (err error) {
	_, _, e1 := Syscall6(SYS_FALLOCATE, uintptr(fd), uintptr(mode), uintptr(off), uintptr(off>>32), uintptr(len), uintptr(len>>32))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Tee(rfd int, wfd int, len int, flags int) (n int64, err error) {
	r0, r1, e1 := Syscall6(SYS_TEE, uintptr(rfd), uintptr(wfd), uintptr(len), uintptr(flags), 0, 0)
	n = int64(int64(r1)<<32 | int64(r0))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(events) > 0 {
		_p0 = unsafe.Pointer(&events[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall6(SYS_EPOLL_WAIT, uintptr(epfd), uintptr(_p0), uintptr(len(events)), uintptr(msec), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fadvise(fd int, offset int64, length int64, advice int) (err error) {
	_, _, e1 := Syscall9(SYS_FADVISE64, uintptr(fd), 0, uintptr(offset), uintptr(offset>>32), uintptr(length), uintptr(length>>32), uintptr(advice), 0, 0)
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

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := Syscall6(SYS_FTRUNCATE64, uintptr(fd), 0, uintptr(length), uintptr(length>>32), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _ := RawSyscallNoError(SYS_GETEGID, 0, 0, 0)
	egid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (euid int) {
	r0, _ := RawSyscallNoError(SYS_GETEUID, 0, 0, 0)
	euid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _ := RawSyscallNoError(SYS_GETGID, 0, 0, 0)
	gid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _ := RawSyscallNoError(SYS_GETUID, 0, 0, 0)
	uid = int(r0)
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

func Listen(s int, n int) (err error) {
	_, _, e1 := Syscall(SYS_LISTEN, uintptr(s), uintptr(n), 0)
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
	r0, _, e1 := Syscall6(SYS_PREAD64, uintptr(fd), uintptr(_p0), uintptr(len(p)), 0, uintptr(offset), uintptr(offset>>32))
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
	r0, _, e1 := Syscall6(SYS_PWRITE64, uintptr(fd), uintptr(_p0), uintptr(len(p)), 0, uintptr(offset), uintptr(offset>>32))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(oldpath)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(newpath)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_RENAMEAT, uintptr(olddirfd), uintptr(unsafe.Pointer(_p0)), uintptr(newdirfd), uintptr(unsafe.Pointer(_p1)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error) {
	r0, _, e1 := Syscall6(SYS__NEWSELECT, uintptr(nfd), uintptr(unsafe.Pointer(r)), uintptr(unsafe.Pointer(w)), uintptr(unsafe.Pointer(e)), uintptr(unsafe.Pointer(timeout)), 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	r0, _, e1 := Syscall6(SYS_SENDFILE64, uintptr(outfd), uintptr(infd), uintptr(unsafe.Pointer(offset)), uintptr(count), 0, 0)
	written = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setfsgid(gid int) (prev int, err error) {
	r0, _, e1 := Syscall(SYS_SETFSGID, uintptr(gid), 0, 0)
	prev = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setfsuid(uid int) (prev int, err error) {
	r0, _, e1 := Syscall(SYS_SETFSUID, uintptr(uid), 0, 0)
	prev = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Shutdown(fd int, how int) (err error) {
	_, _, e1 := Syscall(SYS_SHUTDOWN, uintptr(fd), uintptr(how), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int, err error) {
	r0, _, e1 := Syscall6(SYS_SPLICE, uintptr(rfd), uintptr(unsafe.Pointer(roff)), uintptr(wfd), uintptr(unsafe.Pointer(woff)), uintptr(len), uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func SyncFileRange(fd int, off int64, n int64, flags int) (err error) {
	_, _, e1 := Syscall9(SYS_SYNC_FILE_RANGE, uintptr(fd), 0, uintptr(off), uintptr(off>>32), uintptr(n), uintptr(n>>32), uintptr(flags), 0, 0)
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
	_, _, e1 := Syscall6(SYS_TRUNCATE64, uintptr(unsafe.Pointer(_p0)), 0, uintptr(length), uintptr(length>>32), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Ustat(dev int, ubuf *Ustat_t) (err error) {
	_, _, e1 := Syscall(SYS_USTAT, uintptr(dev), uintptr(unsafe.Pointer(ubuf)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error) {
	r0, _, e1 := Syscall6(SYS_ACCEPT4, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
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

func getgroups(n int, list *_Gid_t) (nn int, err error) {
	r0, _, e1 := RawSyscall(SYS_GETGROUPS, uintptr(n), uintptr(unsafe.Pointer(list)), 0)
	nn = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setgroups(n int, list *_Gid_t) (err error) {
	_, _, e1 := RawSyscall(SYS_SETGROUPS, uintptr(n), uintptr(unsafe.Pointer(list)), 0)
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

func socket(domain int, typ int, proto int) (fd int, err error) {
	r0, _, e1 := RawSyscall(SYS_SOCKET, uintptr(domain), uintptr(typ), uintptr(proto))
	fd = int(r0)
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

func Ioperm(from int, num int, on int) (err error) {
	_, _, e1 := Syscall(SYS_IOPERM, uintptr(from), uintptr(num), uintptr(on))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Iopl(level int) (err error) {
	_, _, e1 := Syscall(SYS_IOPL, uintptr(level), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func futimesat(dirfd int, path string, times *[2]Timeval) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_FUTIMESAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)))
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

func Time(t *Time_t) (tt Time_t, err error) {
	r0, _, e1 := RawSyscall(SYS_TIME, uintptr(unsafe.Pointer(t)), 0, 0)
	tt = Time_t(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Utime(path string, buf *Utimbuf) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UTIME, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(buf)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func utimes(path string, times *[2]Timeval) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UTIMES, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)), 0)
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
	_, _, e1 := Syscall(SYS_LSTAT64, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstat(fd int, stat *Stat_t) (err error) {
	_, _, e1 := Syscall(SYS_FSTAT64, uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_FSTATAT64, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), uintptr(flags), 0, 0)
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
	_, _, e1 := Syscall(SYS_STAT64, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Pause() (err error) {
	_, _, e1 := Syscall(SYS_PAUSE, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func mmap2(addr uintptr, length uintptr, prot int, flags int, fd int, pageOffset uintptr) (xaddr uintptr, err error) {
	r0, _, e1 := Syscall6(SYS_MMAP2, uintptr(addr), uintptr(length), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(pageOffset))
	xaddr = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getrlimit(resource int, rlim *rlimit32) (err error) {
	_, _, e1 := RawSyscall(SYS_GETRLIMIT, uintptr(resource), uintptr(unsafe.Pointer(rlim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Alarm(seconds uint) (remaining uint, err error) {
	r0, _, e1 := Syscall(SYS_ALARM, uintptr(seconds), 0, 0)
	remaining = uint(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}
```