Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Observation & Context:**

The first thing to notice is the file path: `go/src/syscall/syscall_linux_loong64.go`. This immediately tells us several key pieces of information:

* **Location:** It's part of the Go standard library (`syscall` package).
* **Platform Specificity:** The `linux_loong64` suffix indicates this code is specifically for the Linux operating system on the LoongArch 64-bit architecture. This is crucial – the system calls defined here are specific to this platform.
* **Purpose:** The `syscall` package is responsible for providing a low-level interface to the operating system's system calls. This means the code will likely define functions that directly interact with the kernel.

**2. Scanning for Keywords and Patterns:**

Next, a quick scan reveals several important keywords and patterns:

* **`// Copyright` and `// license`:**  Standard Go boilerplate, confirming it's open-source.
* **`package syscall`:**  Confirms the package.
* **`import "unsafe"`:** This is a strong indicator of low-level operations. `unsafe` allows Go code to interact with memory directly, which is often necessary when dealing with system calls.
* **`const (...)`:**  Defines constants. The names like `_SYS_setgroups`, `_SYS_clone3` and their values suggest these are likely system call numbers.
* **`//sys ... = SYS_...`:** This is a special comment syntax used by Go's `syscall` package (specifically the `mksyscall` tool) to generate the actual system call wrappers. This is a *huge* clue. It means the lines following `//sys` are declarations of Go functions that map to specific Linux system calls.
* **`//sysnb ...`:**  Similar to `//sys`, but likely indicates non-blocking system calls or that the Go wrapper doesn't block. This needs verification (and in this case,  it's more about the Go wrapper not inherently blocking, but the underlying syscall might).
* **Function signatures with `int`, `int64`, `uintptr`, `unsafe.Pointer`, and types like `Stat_t`, `EpollEvent`, etc.:** These are typical types used when interacting with system calls, representing file descriptors, pointers to memory structures, and system-specific data structures.
* **Helper functions like `makedev`, `timespecFromStatxTimestamp`:** These functions perform conversions and manipulations of system-level data structures.
* **Capitalized function names like `EpollWait`, `Fchown`, `Stat`, `Listen`:**  These are the Go functions that wrap the system calls.

**3. Deduction and Inference - Connecting the Dots:**

Based on the keywords and patterns, we can start to infer the functionality:

* **System Call Wrappers:** The `//sys` lines are the core functionality. They provide Go functions that directly invoke Linux system calls. Examples: `EpollWait` wraps the `epoll_pwait` system call, `Fchown` wraps `fchown`, etc.
* **File System Operations:** Many functions like `Fstat`, `Stat`, `Lstat`, `Ftruncate`, `Renameat`, `Fchown`, `Lchown`, `Statfs`, `Truncate`, `futimesat`, `Utime`, `Utimes` clearly deal with file system interactions. They get file information, modify ownership, truncate files, rename files, etc.
* **Socket Programming:** Functions like `Listen`, `accept4`, `bind`, `connect`, `getsockopt`, `setsockopt`, `socket`, `socketpair`, `getpeername`, `getsockname`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg` are standard building blocks for network programming using sockets.
* **Process Management/Signals (Indirectly):**  `_SYS_clone3` suggests process creation. `pselect` and `ppoll` are related to waiting for events on file descriptors and potentially handling signals. The `sigset_t` type confirms signal-related operations.
* **Memory Mapping:** `mmap` is for memory mapping files or devices into process memory.
* **Time Management:** `Gettimeofday`, `Time`, `setTimespec`, `setTimeval` deal with getting and setting time.
* **Polling/Waiting for Events:** `EpollWait`, `Select`, `ppoll`, `Pause` are for waiting for events on file descriptors, crucial for I/O multiplexing.
* **Device Management:** `makedev` converts major and minor device numbers.
* **Inotify:** `InotifyInit` suggests support for the Linux inotify subsystem for file system event notification.

**4. Illustrative Code Examples (Mental Model & Refinement):**

Now, to solidify the understanding, let's think about how these functions would be used in Go code.

* **File Stat:** To get information about a file, you'd use `Stat`:
   ```go
   var stat syscall.Stat_t
   err := syscall.Stat("/tmp/myfile.txt", &stat)
   if err != nil {
       // handle error
   }
   fmt.Println(stat.Size)
   ```
* **Opening a Socket and Listening:**
   ```go
   fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
   if err != nil {
       // handle error
   }
   // ... bind the socket ...
   err = syscall.Listen(fd, 10)
   if err != nil {
       // handle error
   }
   ```
* **Using `select` for I/O multiplexing:**
   ```go
   var rSet syscall.FdSet
   syscall.FD_SET(socketFD, &rSet)
   timeout := &syscall.Timeval{Sec: 5, Usec: 0}
   n, err := syscall.Select(socketFD+1, &rSet, nil, nil, timeout)
   if err != nil {
       // handle error
   }
   if n > 0 && syscall.FD_ISSET(socketFD, &rSet) {
       // data available on socketFD
   }
   ```

**5. Considering Potential Errors:**

What could go wrong when using these functions?

* **Incorrect File Descriptors:** Passing invalid file descriptors to functions like `Fstat`, `read`, `write` is a common error.
* **Permission Issues:** Operations like `Chown`, `Mkdir` can fail due to insufficient permissions.
* **Invalid Paths:** Providing incorrect or non-existent file paths to functions like `Stat`, `Open` will cause errors.
* **Socket Errors:**  Network programming is prone to errors like "connection refused," "address already in use," etc. Incorrectly setting up socket addresses is a frequent mistake.
* **Incorrect Flags:** Many system calls take flags as arguments. Using the wrong flags can lead to unexpected behavior.
* **Buffer Overflows (less common in Go due to its memory safety, but possible with `unsafe`):** If you're manually dealing with memory using `unsafe.Pointer`, you need to be careful about buffer sizes.

**6. Structuring the Answer:**

Finally, organize the information into a clear and comprehensive answer, covering the requested aspects:

* **Functionality Listing:**  Group the functions by their purpose (file system, sockets, etc.).
* **Go Code Examples:** Provide concrete examples demonstrating the usage of key functions, including input and expected output (or at least a description of the expected behavior).
* **Code Reasoning (when applicable):** For more complex functions like `makedev` or the `fstatat` family, explain the logic and the underlying system concepts.
* **Command-Line Arguments (Not Applicable in This Snippet):**  Note that this code snippet doesn't directly handle command-line arguments.
* **Common Mistakes:** Provide specific examples of errors users might encounter.

This methodical approach, from high-level observation to detailed analysis and example construction, allows for a thorough understanding and explanation of the given Go code snippet.
这段Go语言代码是 `syscall` 包在 Linux 系统上，LoongArch 64 位架构下的实现。它主要负责提供 Go 语言程序与 Linux 内核进行交互的底层接口，也就是所谓的系统调用。

**功能列举:**

这段代码定义和实现了以下功能：

1. **系统调用常量定义:**
   - `_SYS_setgroups`, `_SYS_clone3`, `_SYS_faccessat2`, `_SYS_fchmodat2`:  定义了一些特定的系统调用号。这些常量在后续的系统调用包装函数中使用。

2. **系统调用包装函数:**
   - 代码中使用 `//sys` 和 `//sysnb` 注释来声明 Go 函数，这些函数实际上是对 Linux 系统调用的封装。`//sys` 表示可能阻塞的系统调用，`//sysnb` 通常表示不会立即阻塞的系统调用（但这并不意味着底层的系统调用永远不会阻塞，而是 Go 的包装层不会引入额外的阻塞）。
   - 列举一些关键的系统调用包装函数及其对应的 Linux 系统调用：
     - `EpollWait`: `SYS_EPOLL_PWAIT` (等待 epoll 事件)
     - `Fchown`: `fchown` (修改文件拥有者)
     - `Fstatfs`: `fstatfs` (获取文件系统统计信息)
     - `Ftruncate`: `ftruncate` (截断文件)
     - `Getegid`, `Geteuid`, `Getgid`, `Getuid`: `getegid`, `geteuid`, `getgid`, `getuid` (获取用户和组 ID)
     - `Listen`: `listen` (监听 socket 连接)
     - `pread`: `pread64` (在指定偏移量读取文件)
     - `pwrite`: `pwrite64` (在指定偏移量写入文件)
     - `Renameat`: `renameat2` (原子地重命名文件)
     - `Seek`: `lseek` (设置文件偏移量)
     - `sendfile`: `sendfile` (在文件描述符之间高效传输数据)
     - `Setfsgid`, `Setfsuid`: `setfsgid`, `setfsuid` (设置文件系统用户和组 ID)
     - `Shutdown`: `shutdown` (关闭 socket 连接的一部分或全部)
     - `Splice`: `splice` (在两个文件描述符之间移动数据，无需用户空间拷贝)
     - `statx`: `statx` (获取文件状态信息，功能更强大)
     - `Statfs`: `statfs` (获取文件系统统计信息)
     - `SyncFileRange`: `sync_file_range` (将文件的一部分同步到磁盘)
     - `Truncate`: `truncate` (截断文件)
     - `accept4`: `accept4` (接受 socket 连接，可以设置标志)
     - `bind`: `bind` (绑定 socket 地址)
     - `connect`: `connect` (连接 socket)
     - `getgroups`: `getgroups` (获取用户所属的组 ID 列表)
     - `getsockopt`, `setsockopt`: `getsockopt`, `setsockopt` (获取和设置 socket 选项)
     - `socket`, `socketpair`: `socket`, `socketpair` (创建 socket)
     - `getpeername`, `getsockname`: `getpeername`, `getsockname` (获取连接的对端和本地 socket 地址)
     - `recvfrom`, `sendto`: `recvfrom`, `sendto` (在 socket 上发送和接收数据报)
     - `recvmsg`, `sendmsg`: `recvmsg`, `sendmsg` (在 socket 上发送和接收消息，支持控制信息)
     - `mmap`: `mmap` (将文件或设备映射到内存)
     - `pselect`: `pselect6` (带超时的多路复用 I/O，可以屏蔽信号)
     - `Gettimeofday`: `gettimeofday` (获取当前时间)
     - `ppoll`: `ppoll` (带超时的多路复用 I/O，可以设置信号掩码)

3. **辅助函数:**
   - `makedev`: 将主设备号和次设备号组合成一个 `dev_t` 类型的值，这是 Linux 中表示设备文件的标准方式。
   - `timespecFromStatxTimestamp`: 将 `statxTimestamp` 结构体转换为 `Timespec` 结构体，用于表示时间。
   - `fstatat`:  实现了 `fstatat` 系统调用的逻辑，可以基于目录文件描述符和路径获取文件状态。`Fstatat`, `Fstat`, `Stat`, `Lstat` 等函数都是基于 `fstatat` 实现的。
   - `Select`:  基于 `pselect` 实现了 `select` 系统调用，用于 I/O 多路复用。
   - `setTimespec`, `setTimeval`:  创建 `Timespec` 和 `Timeval` 结构体的辅助函数。
   - `futimesat`, `utimes`:  实现了设置文件访问和修改时间的函数，使用了 `utimensat` 系统调用。
   - `Time`: 获取当前时间。
   - `Utime`: 基于 `Utimbuf` 结构体设置文件访问和修改时间。
   - `InotifyInit`: 初始化 inotify 文件系统事件监控机制。
   - `Pause`: 使程序暂停执行，直到收到信号。

4. **类型和方法:**
   - `sigset_t`:  表示信号集，用于信号处理。
   - `PtraceRegs` 的 `GetEra` 和 `SetEra` 方法：用于访问和修改 ptrace 寄存器结构体中的 `Era` 字段，这与 LoongArch 架构的异常返回地址寄存器有关。
   - `Iovec`, `Msghdr`, `Cmsghdr` 的 `SetLen` 和 `SetControllen` 方法：用于设置这些结构体中表示长度的字段。

**推断的 Go 语言功能实现 (举例):**

这段代码是 `syscall` 包的一部分，而 `syscall` 包是 Go 语言与操作系统底层交互的基础。例如，很多标准库中的文件操作、网络编程等功能都依赖于 `syscall` 包提供的接口。

**示例 1: 获取文件大小**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	filename := "/tmp/test.txt" // 假设存在这个文件
	var stat syscall.Stat_t
	err := syscall.Stat(filename, &stat)
	if err != nil {
		fmt.Println("Error getting file info:", err)
		return
	}
	fmt.Printf("File size of %s: %d bytes\n", filename, stat.Size)
}
```

**假设的输入与输出:**

假设 `/tmp/test.txt` 文件存在且大小为 1024 字节。

**输出:**

```
File size of /tmp/test.txt: 1024 bytes
```

**代码推理:**

`syscall.Stat` 函数内部会调用这段代码中的 `Stat` 函数，最终会通过 `statx` 系统调用获取文件的元数据，并将文件大小存储在 `stat.Size` 字段中。

**示例 2: 创建一个 TCP 监听器**

```go
package main

import (
	"fmt"
	"net"
	"syscall"
)

func main() {
	addr := &syscall.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{0, 0, 0, 0}, // 监听所有 IP 地址
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("Error creating socket:", err)
		return
	}
	defer syscall.Close(fd)

	err = syscall.Bind(fd, addr)
	if err != nil {
		fmt.Println("Error binding socket:", err)
		return
	}

	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		fmt.Println("Error listening on socket:", err)
		return
	}

	fmt.Println("Listening on port 8080")

	// ... 接收连接的代码 ...
}
```

**假设的输入与输出:**

这段代码本身不涉及输入，运行后会在 8080 端口开始监听 TCP 连接。

**代码推理:**

`syscall.Socket`, `syscall.Bind`, `syscall.Listen` 这些函数直接对应了代码中定义的系统调用包装函数，它们最终会调用 Linux 内核的 `socket`, `bind`, `listen` 系统调用。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并可能传递给使用 `syscall` 包的更高级别的函数。例如，如果一个程序需要打开用户在命令行中指定的文件，它会先解析命令行参数，然后将文件名传递给 `os.Open` 或类似的函数，而 `os.Open` 最终会调用 `syscall.Open`。

**使用者易犯错的点:**

1. **错误的文件描述符:**  在使用文件描述符 (如 `fd` 来自 `syscall.Open`) 时，如果文件描述符无效（例如，文件已被关闭），则调用相关的系统调用会返回错误。

   ```go
   fd, err := syscall.Open("/tmp/test.txt", syscall.O_RDONLY, 0)
   if err != nil {
       // 处理打开错误
   }
   syscall.Close(fd) // 关闭文件

   // 错误：尝试在已关闭的文件描述符上操作
   var buf [10]byte
   n, err := syscall.Read(fd, buf[:]) // 这是一个错误的操作
   if err != nil {
       fmt.Println("Read error:", err) // 可能会输出 "bad file descriptor"
   }
   ```

2. **不正确的错误处理:** 系统调用返回错误时，`err` 变量不为 `nil`。开发者必须检查并妥善处理这些错误，否则程序可能会出现未定义的行为。

   ```go
   _, err := syscall.Open("/nonexistent_file.txt", syscall.O_RDONLY, 0)
   // 易错点：没有检查 err
   // ... 后续代码可能会基于一个无效的文件描述符进行操作 ...

   if err != nil {
       fmt.Println("Open error:", err) // 正确的做法是检查错误
   }
   ```

3. **不安全的类型转换 (与 `unsafe` 包一起使用时):** 虽然这段代码中 `unsafe` 包的使用相对安全，但在其他涉及 `syscall` 和 `unsafe` 的代码中，不正确的指针转换或内存访问可能导致程序崩溃或安全漏洞。

4. **忽略系统调用特定的语义和限制:** 不同的系统调用有不同的参数要求、返回值和错误码。开发者需要查阅相关文档，了解每个系统调用的具体行为。例如，`sendto` 需要正确的 socket 地址结构，而 `mmap` 需要合适的标志和权限。

这段代码是 Go 语言与 Linux 内核交互的基石，理解其功能对于进行底层的系统编程至关重要。

Prompt: 
```
这是路径为go/src/syscall/syscall_linux_loong64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
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

//sys	EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error) = SYS_EPOLL_PWAIT
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fstatfs(fd int, buf *Statfs_t) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (euid int)
//sysnb	Getgid() (gid int)
//sysnb	Getuid() (uid int)
//sys	Listen(s int, n int) (err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error) = SYS_PREAD64
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error) = SYS_PWRITE64
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error) = SYS_RENAMEAT2
//sys	Seek(fd int, offset int64, whence int) (off int64, err error) = SYS_LSEEK
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error)
//sys	Setfsgid(gid int) (err error)
//sys	Setfsuid(uid int) (err error)
//sys	Shutdown(fd int, how int) (err error)
//sys	Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)
//sys	statx(dirfd int, path string, flags int, mask int, stat *statx_t) (err error)

// makedev makes C dev_t from major and minor numbers the glibc way:
// 0xMMMM_MMMM 0xmmmm_mmmm -> 0xMMMM_Mmmm_mmmM_MMmm
func makedev(major uint32, minor uint32) uint64 {
	majorH := uint64(major >> 12)
	majorL := uint64(major & 0xfff)
	minorH := uint64(minor >> 8)
	minorL := uint64(minor & 0xff)
	return (majorH << 44) | (minorH << 20) | (majorL << 8) | minorL
}

func timespecFromStatxTimestamp(x statxTimestamp) Timespec {
	return Timespec{
		Sec:  x.Sec,
		Nsec: int64(x.Nsec),
	}
}

func fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) {
	var r statx_t
	// Do it the glibc way, add AT_NO_AUTOMOUNT.
	if err = statx(dirfd, path, _AT_NO_AUTOMOUNT|flags, _STATX_BASIC_STATS, &r); err != nil {
		return err
	}

	stat.Dev = makedev(r.Dev_major, r.Dev_minor)
	stat.Ino = r.Ino
	stat.Mode = uint32(r.Mode)
	stat.Nlink = r.Nlink
	stat.Uid = r.Uid
	stat.Gid = r.Gid
	stat.Rdev = makedev(r.Rdev_major, r.Rdev_minor)
	// hope we don't get to process files so large to overflow these size
	// fields...
	stat.Size = int64(r.Size)
	stat.Blksize = int32(r.Blksize)
	stat.Blocks = int64(r.Blocks)
	stat.Atim = timespecFromStatxTimestamp(r.Atime)
	stat.Mtim = timespecFromStatxTimestamp(r.Mtime)
	stat.Ctim = timespecFromStatxTimestamp(r.Ctime)

	return nil
}

func Fstatat(fd int, path string, stat *Stat_t, flags int) (err error) {
	return fstatat(fd, path, stat, flags)
}

func Fstat(fd int, stat *Stat_t) (err error) {
	return fstatat(fd, "", stat, _AT_EMPTY_PATH)
}

func Stat(path string, stat *Stat_t) (err error) {
	return fstatat(_AT_FDCWD, path, stat, 0)
}

func Lchown(path string, uid int, gid int) (err error) {
	return Fchownat(_AT_FDCWD, path, uid, gid, _AT_SYMLINK_NOFOLLOW)
}

func Lstat(path string, stat *Stat_t) (err error) {
	return fstatat(_AT_FDCWD, path, stat, _AT_SYMLINK_NOFOLLOW)
}

//sys	Statfs(path string, buf *Statfs_t) (err error)
//sys	SyncFileRange(fd int, off int64, n int64, flags int) (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error)
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error)
//sysnb	getgroups(n int, list *_Gid_t) (nn int, err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error)
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)
//sysnb	socket(domain int, typ int, proto int) (fd int, err error)
//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error)
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sysnb	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error)
//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error)
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error)
//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error)
//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error)
//sys	mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error)

type sigset_t struct {
	X__val [16]uint64
}

//sys	pselect(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timespec, sigmask *sigset_t) (n int, err error) = SYS_PSELECT6

func Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error) {
	var ts *Timespec
	if timeout != nil {
		ts = &Timespec{Sec: timeout.Sec, Nsec: timeout.Usec * 1000}
	}
	return pselect(nfd, r, w, e, ts, nil)
}

//sysnb	Gettimeofday(tv *Timeval) (err error)

func setTimespec(sec, nsec int64) Timespec {
	return Timespec{Sec: sec, Nsec: nsec}
}

func setTimeval(sec, usec int64) Timeval {
	return Timeval{Sec: sec, Usec: usec}
}

func futimesat(dirfd int, path string, tv *[2]Timeval) (err error) {
	if tv == nil {
		return utimensat(dirfd, path, nil, 0)
	}

	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return utimensat(dirfd, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

func Time(t *Time_t) (Time_t, error) {
	var tv Timeval
	err := Gettimeofday(&tv)
	if err != nil {
		return 0, err
	}
	if t != nil {
		*t = Time_t(tv.Sec)
	}
	return Time_t(tv.Sec), nil
}

func Utime(path string, buf *Utimbuf) error {
	tv := []Timeval{
		{Sec: buf.Actime},
		{Sec: buf.Modtime},
	}
	return Utimes(path, tv)
}

func utimes(path string, tv *[2]Timeval) (err error) {
	if tv == nil {
		return utimensat(_AT_FDCWD, path, nil, 0)
	}

	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return utimensat(_AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
}

func (r *PtraceRegs) GetEra() uint64 { return r.Era }

func (r *PtraceRegs) SetEra(era uint64) { r.Era = era }

func (iov *Iovec) SetLen(length int) {
	iov.Len = uint64(length)
}

func (msghdr *Msghdr) SetControllen(length int) {
	msghdr.Controllen = uint64(length)
}

func (cmsg *Cmsghdr) SetLen(length int) {
	cmsg.Len = uint64(length)
}

func InotifyInit() (fd int, err error) {
	return InotifyInit1(0)
}

//sys	ppoll(fds *pollFd, nfds int, timeout *Timespec, sigmask *sigset_t) (n int, err error)

func Pause() error {
	_, err := ppoll(nil, 0, nil, nil)
	return err
}

"""



```