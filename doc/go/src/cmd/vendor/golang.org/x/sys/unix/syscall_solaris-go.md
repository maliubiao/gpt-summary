Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The initial comment clearly states "Solaris system calls." This immediately tells us the file's primary function is to interact with the Solaris operating system kernel. The `package unix` also reinforces this, indicating it's part of a system-level interaction library.

2. **Recognize `//sys` and `//sysnb`:**  These are special directives for the `mksyscall` tool. This is a crucial piece of information. It means this file *doesn't* contain the actual low-level system call implementations. Instead, it defines the *signatures* and some higher-level Go wrappers. The real implementation is elsewhere (likely in assembly or a C stub). The "nb" likely signifies "no blocking," hinting at non-blocking versions of calls where applicable.

3. **Categorize Functionality:** Scan through the code, looking for patterns and groupings of functions. Some initial categories emerge:

    * **Basic System Calls:**  Functions with `//sys` or `//sysnb` prefixes like `pipe`, `getgroups`, `read`, `write`, etc. These directly map to Solaris system calls.
    * **Socket-Related Functions:** Structures like `SockaddrDatalink`, `SockaddrInet4`, `SockaddrInet6`, `SockaddrUnix` and functions like `Getsockname`, `Accept`, `Sendfile`, `Bind`, `Connect`, `Socket`, `Recvfrom`, `Sendto`, etc. These deal with network communication.
    * **File and Directory Operations:** Functions like `Getwd`, `ReadDirent`, `Utimes`, `Fcntl`, `Open`, `Mkdir`, `Rename`, `Unlink`, etc. These manage the file system.
    * **Process Management:** Functions like `Wait4`, `Getpid`, `Kill`, `Exit`, `Getpriority`, `Setpriority`, `Setsid`, `Getgroups`, `Setgroups`. These manage processes.
    * **Time-Related Functions:**  `ClockGettime`, `Gettimeofday`, `Nanosleep`, `Adjtime`.
    * **Memory Management:** `Madvise`, `Mlock`, `Mlockall`, `Mprotect`, `Msync`, `Munlock`, `Munlockall`, `mmap`, `munmap`.
    * **Event Ports:**  The `EventPort` struct and related functions (`NewEventPort`, `AssociatePath`, `GetOne`, `Get`). This is a Solaris-specific mechanism for event notification.
    * **IO Control (`ioctl`):**  Functions related to `ioctl` for device interaction.
    * **Message Queues (`putmsg`, `getmsg`):**  Functions for inter-process communication using message queues.
    * **Device Management (`Mkdev`, `Major`, `Minor`):**  Functions for manipulating device numbers.

4. **Focus on Examples (Crucial for Understanding):** The prompt specifically asks for Go code examples. For each category, think of a simple, illustrative use case. This is where practical knowledge of system programming comes in handy.

    * **`pipe`:** A classic example of inter-process communication. Create a pipe, write to one end, read from the other.
    * **`Getwd`:** Straightforward – get the current working directory.
    * **`Accept`:**  A basic server setup – listen on a port and accept a connection.
    * **`Wait4`:**  Demonstrate waiting for a child process to finish.
    * **`NewEventPort` and `AssociatePath`:**  Show how to set up monitoring for file changes.

5. **Address Specific Prompt Requirements:**

    * **Go Language Feature:** Try to connect the functions to broader Go concepts. For example, system calls underpin Go's standard library (e.g., `os` package). The event port functionality is a more specialized feature.
    * **Code Reasoning (Input/Output):** For the examples, define clear inputs (e.g., a file path, a socket address) and expected outputs (e.g., the file descriptor, the contents of a directory).
    * **Command-Line Arguments:**  Since this code is a library, it doesn't directly handle command-line arguments. Note this explicitly. However, functions like `Open` or `Chdir` *could* be used in programs that *do* process command-line arguments.
    * **Common Mistakes:** Think about potential pitfalls. For system calls, these often involve incorrect usage of pointers, buffer sizes, or error handling. The event port's association/dissociation logic is a good candidate for potential misuse.

6. **Structure the Answer:** Organize the findings logically. Start with a high-level overview, then delve into specific functionalities, providing examples for each. Address the prompt's points (features, examples, reasoning, arguments, mistakes) systematically.

7. **Refine and Elaborate:** Review the answer for clarity and completeness. Ensure the code examples are correct and easy to understand. Add details where necessary to explain the purpose and usage of each function or group of functions. For instance, explain the role of `mksyscall`.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file *contains* the assembly for the system calls. **Correction:** The `//sys` and `//sysnb` directives indicate that `mksyscall` generates the stubs. The actual implementation is elsewhere.
* **Realization:** Some functions are wrappers around the direct system calls (e.g., `Pipe` around `pipe`). Highlight this pattern.
* **Considering common mistakes:** Initially, I might only think of generic programming errors. **Correction:** Focus on errors specific to system calls, like incorrect pointer usage or forgetting to check error returns. The event port's lifecycle management is also a good area for potential mistakes.

By following these steps, combining general programming knowledge with an understanding of operating system concepts, and paying close attention to the prompt's requirements, a comprehensive and accurate analysis can be generated.
这段代码是 Go 语言 `syscall` 包在 Solaris 操作系统上的一个实现文件 (`syscall_solaris.go`)。它的主要功能是**提供了 Go 程序访问 Solaris 系统调用的接口**。它定义了 Go 函数，这些函数最终会调用到 Solaris 内核提供的系统调用，从而让 Go 程序能够执行底层的操作系统操作。

更具体来说，它的功能可以列举如下：

1. **定义了与 Solaris 系统调用对应的 Go 函数签名:**  例如，`//sysnb pipe(p *[2]_C_int) (n int, err error)` 就声明了一个名为 `pipe` 的 Go 函数，它对应着 Solaris 的 `pipe` 系统调用。`//sysnb` 注释表明这是一个非阻塞的系统调用。

2. **提供了 Go 语言风格的包装函数:**  例如，`Pipe(p []int)` 函数是对底层 `pipe` 系统调用的一个封装。它处理了 Go 语言的切片类型和错误处理方式，使得调用更加方便。

3. **定义了与 Solaris 特定的数据结构:**  例如 `SockaddrDatalink`、`RawSockaddrAny` 等结构体，用于在 Go 和 Solaris 系统调用之间传递数据。

4. **实现了跨平台的抽象:**  虽然这个文件是 Solaris 特定的，但它与其他操作系统特定的 `syscall_*.go` 文件一起，为 Go 开发者提供了一套统一的 `syscall` 包接口，使得开发者可以在不同平台上使用相似的代码进行系统调用。

5. **处理了底层的细节:** 例如，在 `sockaddr()` 方法中，它将 Go 的 `SockaddrInet4` 等结构体转换为 Solaris 系统调用期望的 `RawSockaddrInet4` 等结构体。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言标准库中 `syscall` 包的一部分实现。 `syscall` 包是 Go 语言与操作系统底层交互的关键部分，它允许 Go 程序执行诸如文件操作、进程管理、网络编程等操作，这些都依赖于操作系统提供的系统调用。

**Go 代码举例说明:**

以下是一些使用这段代码中定义的函数的例子：

**示例 1: 创建管道 (Pipe)**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// 创建一个管道
	p := make([]int, 2)
	err := syscall.Pipe(p)
	if err != nil {
		fmt.Println("创建管道失败:", err)
		return
	}
	fmt.Printf("管道读端: %d, 写端: %d\n", p[0], p[1])

	// 假设的输入与输出：
	// 输入：无
	// 输出：例如：管道读端: 3, 写端: 4 (具体的数字会根据系统分配而变化)

	// 关闭管道
	syscall.Close(p[0])
	syscall.Close(p[1])
}
```

**示例 2: 获取当前工作目录 (Getwd)**

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	// 获取当前工作目录
	wd, err := syscall.Getwd()
	if err != nil {
		fmt.Println("获取当前工作目录失败:", err)
		return
	}
	fmt.Println("当前工作目录:", wd)

	// 假设的输入与输出：
	// 输入：无
	// 输出：例如：当前工作目录: /home/user
}
```

**示例 3: 创建并监听一个 TCP Socket (socket, bind, listen, accept)**

```go
package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func main() {
	// 创建一个 TCP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("创建 socket 失败:", err)
		return
	}
	defer syscall.Close(fd)

	// 绑定地址和端口
	addr := syscall.SockaddrInet4{
		Port: 8080,
		Addr: [4]byte{0, 0, 0, 0}, // 监听所有地址
	}
	rawAddr, _, err := addr.Sockaddr()
	if err != nil {
		fmt.Println("创建 Sockaddr 失败:", err)
		return
	}
	err = syscall.Bind(fd, rawAddr, uint32(unsafe.Sizeof(addr)))
	if err != nil {
		fmt.Println("绑定地址失败:", err)
		return
	}

	// 监听端口
	err = syscall.Listen(fd, 10) // backlog 设置为 10
	if err != nil {
		fmt.Println("监听端口失败:", err)
		return
	}

	fmt.Println("服务器正在监听端口 8080...")

	// 接受连接 (这里只是简单展示，实际应用中需要循环处理)
	nfd, sa, err := syscall.Accept(fd)
	if err != nil {
		fmt.Println("接受连接失败:", err)
		return
	}
	defer syscall.Close(nfd)

	switch sa.(type) {
	case *syscall.SockaddrInet4:
		ipv4Addr := sa.(*syscall.SockaddrInet4)
		fmt.Printf("接收到来自 %v 的连接\n", net.IPv4(ipv4Addr.Addr[0], ipv4Addr.Addr[1], ipv4Addr.Addr[2], ipv4Addr.Addr[3]))
	case *syscall.SockaddrInet6:
		ipv6Addr := sa.(*syscall.SockaddrInet6)
		fmt.Printf("接收到来自 %v 的连接\n", ipv6Addr.Addr)
	default:
		fmt.Println("接收到未知类型的连接")
	}

	// 假设的输入与输出：
	// 输入：使用另一个程序连接到 127.0.0.1:8080
	// 输出：例如：服务器正在监听端口 8080...
	//           接收到来自 127.0.0.1 的连接 (或者对应的 IPv6 地址)
}
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，通过 `os.Args` 获取。  然而，这段代码提供的系统调用接口可以被用来构建需要处理命令行参数的程序。例如，一个需要读取命令行指定文件的程序，会使用 `syscall.Open` 函数打开文件，而文件名可能来源于命令行参数。

**使用者易犯错的点:**

1. **错误处理不当:** 系统调用通常会返回错误码。开发者需要仔细检查 `err` 返回值，并根据错误类型进行处理。忽略错误可能导致程序行为异常甚至崩溃。

   ```go
   fd, err := syscall.Open("/nonexistent_file", syscall.O_RDONLY, 0)
   if err != nil {
       // 正确的做法：检查并处理错误
       fmt.Println("打开文件失败:", err)
       // ... 进行相应的错误处理 ...
   } else {
       defer syscall.Close(fd)
       // ... 使用文件 ...
   }
   ```

2. **不正确的参数传递:**  系统调用对参数的类型、大小和含义有严格的要求。传递错误的参数（例如，错误的指针、不正确的缓冲区大小）会导致系统调用失败，甚至可能引发安全问题。

   例如，在使用 `syscall.Read` 读取数据时，需要确保提供的缓冲区 `p` 有足够的空间容纳读取的数据。

   ```go
   buf := make([]byte, 10)
   n, err := syscall.Read(fd, buf)
   if err != nil {
       fmt.Println("读取失败:", err)
   } else {
       fmt.Printf("读取了 %d 字节: %s\n", n, string(buf[:n]))
   }
   ```

3. **资源泄漏:**  例如，打开的文件描述符、分配的内存等资源，在使用完毕后需要显式释放。忘记关闭文件描述符会导致资源泄漏，最终可能耗尽系统资源。

   ```go
   fd, err := syscall.Open("myfile.txt", syscall.O_RDONLY, 0)
   if err != nil {
       // ... 错误处理 ...
       return
   }
   defer syscall.Close(fd) // 确保文件描述符被关闭

   // ... 使用文件 ...
   ```

4. **并发安全问题:** 在多线程或 Goroutine 环境下使用系统调用时，需要注意并发安全。某些系统调用可能不是线程安全的，需要使用互斥锁等同步机制来保护共享资源。  虽然 `syscall` 包本身通常是线程安全的，但它操作的底层资源可能不是。

5. **平台差异:** 不同的操作系统可能有不同的系统调用和行为。直接使用 `syscall` 包编写的代码可能不具备良好的跨平台性。建议尽量使用 Go 标准库中更高级别的抽象（例如 `os` 包、`net` 包），它们会在底层处理平台差异。

6. **对 `mksyscall` 的理解不足:**  开发者可能不理解 `//sys` 和 `//sysnb` 的作用，以及 `mksyscall` 工具如何生成底层的系统调用 Stub 代码。这可能导致对 `syscall` 包的内部工作原理理解不足。

这段 `syscall_solaris.go` 文件是 Go 语言连接 Solaris 操作系统内核的桥梁，理解它的功能对于进行底层的系统编程至关重要。但同时也需要注意使用系统调用时可能遇到的各种陷阱。

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_solaris.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Solaris system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and wrap
// it in our own nicer implementation, either here or in
// syscall_solaris.go or syscall_unix.go.

package unix

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Implemented in runtime/syscall_solaris.go.
type syscallFunc uintptr

func rawSysvicall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)
func sysvicall6(trap, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

// SockaddrDatalink implements the Sockaddr interface for AF_LINK type sockets.
type SockaddrDatalink struct {
	Family uint16
	Index  uint16
	Type   uint8
	Nlen   uint8
	Alen   uint8
	Slen   uint8
	Data   [244]int8
	raw    RawSockaddrDatalink
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

//sysnb	pipe(p *[2]_C_int) (n int, err error)

func Pipe(p []int) (err error) {
	if len(p) != 2 {
		return EINVAL
	}
	var pp [2]_C_int
	n, err := pipe(&pp)
	if n != 0 {
		return err
	}
	if err == nil {
		p[0] = int(pp[0])
		p[1] = int(pp[1])
	}
	return nil
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

//sys	getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) = libsocket.getsockname

func Getsockname(fd int) (sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	if err = getsockname(fd, &rsa, &len); err != nil {
		return
	}
	return anyToSockaddr(fd, &rsa)
}

// GetsockoptString returns the string value of the socket option opt for the
// socket associated with fd at the given socket level.
func GetsockoptString(fd, level, opt int) (string, error) {
	buf := make([]byte, 256)
	vallen := _Socklen(len(buf))
	err := getsockopt(fd, level, opt, unsafe.Pointer(&buf[0]), &vallen)
	if err != nil {
		return "", err
	}
	return ByteSliceToString(buf[:vallen]), nil
}

const ImplementsGetwd = true

//sys	Getcwd(buf []byte) (n int, err error)

func Getwd() (wd string, err error) {
	var buf [PathMax]byte
	// Getcwd will return an error if it failed for any reason.
	_, err = Getcwd(buf[0:])
	if err != nil {
		return "", err
	}
	n := clen(buf[:])
	if n < 1 {
		return "", EINVAL
	}
	return string(buf[:n]), nil
}

/*
 * Wrapped
 */

//sysnb	getgroups(ngid int, gid *_Gid_t) (n int, err error)
//sysnb	setgroups(ngid int, gid *_Gid_t) (err error)

func Getgroups() (gids []int, err error) {
	n, err := getgroups(0, nil)
	// Check for error and sanity check group count. Newer versions of
	// Solaris allow up to 1024 (NGROUPS_MAX).
	if n < 0 || n > 1024 {
		if err != nil {
			return nil, err
		}
		return nil, EINVAL
	} else if n == 0 {
		return nil, nil
	}

	a := make([]_Gid_t, n)
	n, err = getgroups(n, &a[0])
	if n == -1 {
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

// ReadDirent reads directory entries from fd and writes them into buf.
func ReadDirent(fd int, buf []byte) (n int, err error) {
	// Final argument is (basep *uintptr) and the syscall doesn't take nil.
	// TODO(rsc): Can we use a single global basep for all calls?
	return Getdents(fd, buf, new(uintptr))
}

// Wait status is 7 bits at bottom, either 0 (exited),
// 0x7F (stopped), or a signal number that caused an exit.
// The 0x80 bit is whether there was a core dump.
// An extra number (exit code, signal causing a stop)
// is in the high bits.

type WaitStatus uint32

const (
	mask  = 0x7F
	core  = 0x80
	shift = 8

	exited  = 0
	stopped = 0x7F
)

func (w WaitStatus) Exited() bool { return w&mask == exited }

func (w WaitStatus) ExitStatus() int {
	if w&mask != exited {
		return -1
	}
	return int(w >> shift)
}

func (w WaitStatus) Signaled() bool { return w&mask != stopped && w&mask != 0 }

func (w WaitStatus) Signal() syscall.Signal {
	sig := syscall.Signal(w & mask)
	if sig == stopped || sig == 0 {
		return -1
	}
	return sig
}

func (w WaitStatus) CoreDump() bool { return w.Signaled() && w&core != 0 }

func (w WaitStatus) Stopped() bool { return w&mask == stopped && syscall.Signal(w>>shift) != SIGSTOP }

func (w WaitStatus) Continued() bool { return w&mask == stopped && syscall.Signal(w>>shift) == SIGSTOP }

func (w WaitStatus) StopSignal() syscall.Signal {
	if !w.Stopped() {
		return -1
	}
	return syscall.Signal(w>>shift) & 0xFF
}

func (w WaitStatus) TrapCause() int { return -1 }

//sys	wait4(pid int32, statusp *_C_int, options int, rusage *Rusage) (wpid int32, err error)

func Wait4(pid int, wstatus *WaitStatus, options int, rusage *Rusage) (int, error) {
	var status _C_int
	rpid, err := wait4(int32(pid), &status, options, rusage)
	wpid := int(rpid)
	if wpid == -1 {
		return wpid, err
	}
	if wstatus != nil {
		*wstatus = WaitStatus(status)
	}
	return wpid, nil
}

//sys	gethostname(buf []byte) (n int, err error)

func Gethostname() (name string, err error) {
	var buf [MaxHostNameLen]byte
	n, err := gethostname(buf[:])
	if n != 0 {
		return "", err
	}
	n = clen(buf[:])
	if n < 1 {
		return "", EFAULT
	}
	return string(buf[:n]), nil
}

//sys	utimes(path string, times *[2]Timeval) (err error)

func Utimes(path string, tv []Timeval) (err error) {
	if tv == nil {
		return utimes(path, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return utimes(path, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

//sys	utimensat(fd int, path string, times *[2]Timespec, flag int) (err error)

func UtimesNano(path string, ts []Timespec) error {
	if ts == nil {
		return utimensat(AT_FDCWD, path, nil, 0)
	}
	if len(ts) != 2 {
		return EINVAL
	}
	return utimensat(AT_FDCWD, path, (*[2]Timespec)(unsafe.Pointer(&ts[0])), 0)
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

//sys	fcntl(fd int, cmd int, arg int) (val int, err error)

// FcntlInt performs a fcntl syscall on fd with the provided command and argument.
func FcntlInt(fd uintptr, cmd, arg int) (int, error) {
	valptr, _, errno := sysvicall6(uintptr(unsafe.Pointer(&procfcntl)), 3, uintptr(fd), uintptr(cmd), uintptr(arg), 0, 0, 0)
	var err error
	if errno != 0 {
		err = errno
	}
	return int(valptr), err
}

// FcntlFlock performs a fcntl syscall for the F_GETLK, F_SETLK or F_SETLKW command.
func FcntlFlock(fd uintptr, cmd int, lk *Flock_t) error {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&procfcntl)), 3, uintptr(fd), uintptr(cmd), uintptr(unsafe.Pointer(lk)), 0, 0, 0)
	if e1 != 0 {
		return e1
	}
	return nil
}

//sys	futimesat(fildes int, path *byte, times *[2]Timeval) (err error)

func Futimesat(dirfd int, path string, tv []Timeval) error {
	pathp, err := BytePtrFromString(path)
	if err != nil {
		return err
	}
	if tv == nil {
		return futimesat(dirfd, pathp, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return futimesat(dirfd, pathp, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

// Solaris doesn't have an futimes function because it allows NULL to be
// specified as the path for futimesat. However, Go doesn't like
// NULL-style string interfaces, so this simple wrapper is provided.
func Futimes(fd int, tv []Timeval) error {
	if tv == nil {
		return futimesat(fd, nil, nil)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	return futimesat(fd, nil, (*[2]Timeval)(unsafe.Pointer(&tv[0])))
}

func anyToSockaddr(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
	switch rsa.Addr.Family {
	case AF_UNIX:
		pp := (*RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(SockaddrUnix)
		// Assume path ends at NUL.
		// This is not technically the Solaris semantics for
		// abstract Unix domain sockets -- they are supposed
		// to be uninterpreted fixed-size binary blobs -- but
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

//sys	accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error) = libsocket.accept

func Accept(fd int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = accept(fd, &rsa, &len)
	if nfd == -1 {
		return
	}
	sa, err = anyToSockaddr(fd, &rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

//sys	recvmsg(s int, msg *Msghdr, flags int) (n int, err error) = libsocket.__xnet_recvmsg

func recvmsgRaw(fd int, iov []Iovec, oob []byte, flags int, rsa *RawSockaddrAny) (n, oobn int, recvflags int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(rsa))
	msg.Namelen = uint32(SizeofSockaddrAny)
	var dummy byte
	if len(oob) > 0 {
		// receive at least one normal byte
		if emptyIovecs(iov) {
			var iova [1]Iovec
			iova[0].Base = &dummy
			iova[0].SetLen(1)
			iov = iova[:]
		}
		msg.Accrightslen = int32(len(oob))
	}
	if len(iov) > 0 {
		msg.Iov = &iov[0]
		msg.SetIovlen(len(iov))
	}
	if n, err = recvmsg(fd, &msg, flags); n == -1 {
		return
	}
	oobn = int(msg.Accrightslen)
	return
}

//sys	sendmsg(s int, msg *Msghdr, flags int) (n int, err error) = libsocket.__xnet_sendmsg

func sendmsgN(fd int, iov []Iovec, oob []byte, ptr unsafe.Pointer, salen _Socklen, flags int) (n int, err error) {
	var msg Msghdr
	msg.Name = (*byte)(unsafe.Pointer(ptr))
	msg.Namelen = uint32(salen)
	var dummy byte
	var empty bool
	if len(oob) > 0 {
		// send at least one normal byte
		empty = emptyIovecs(iov)
		if empty {
			var iova [1]Iovec
			iova[0].Base = &dummy
			iova[0].SetLen(1)
			iov = iova[:]
		}
		msg.Accrightslen = int32(len(oob))
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

//sys	acct(path *byte) (err error)

func Acct(path string) (err error) {
	if len(path) == 0 {
		// Assume caller wants to disable accounting.
		return acct(nil)
	}

	pathp, err := BytePtrFromString(path)
	if err != nil {
		return err
	}
	return acct(pathp)
}

//sys	__makedev(version int, major uint, minor uint) (val uint64)

func Mkdev(major, minor uint32) uint64 {
	return __makedev(NEWDEV, uint(major), uint(minor))
}

//sys	__major(version int, dev uint64) (val uint)

func Major(dev uint64) uint32 {
	return uint32(__major(NEWDEV, dev))
}

//sys	__minor(version int, dev uint64) (val uint)

func Minor(dev uint64) uint32 {
	return uint32(__minor(NEWDEV, dev))
}

/*
 * Expose the ioctl function
 */

//sys	ioctlRet(fd int, req int, arg uintptr) (ret int, err error) = libc.ioctl
//sys	ioctlPtrRet(fd int, req int, arg unsafe.Pointer) (ret int, err error) = libc.ioctl

func ioctl(fd int, req int, arg uintptr) (err error) {
	_, err = ioctlRet(fd, req, arg)
	return err
}

func ioctlPtr(fd int, req int, arg unsafe.Pointer) (err error) {
	_, err = ioctlPtrRet(fd, req, arg)
	return err
}

func IoctlSetTermio(fd int, req int, value *Termio) error {
	return ioctlPtr(fd, req, unsafe.Pointer(value))
}

func IoctlGetTermio(fd int, req int) (*Termio, error) {
	var value Termio
	err := ioctlPtr(fd, req, unsafe.Pointer(&value))
	return &value, err
}

//sys	poll(fds *PollFd, nfds int, timeout int) (n int, err error)

func Poll(fds []PollFd, timeout int) (n int, err error) {
	if len(fds) == 0 {
		return poll(nil, 0, timeout)
	}
	return poll(&fds[0], len(fds), timeout)
}

func Sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	return sendfile(outfd, infd, offset, count)
}

/*
 * Exposed directly
 */
//sys	Access(path string, mode uint32) (err error)
//sys	Adjtime(delta *Timeval, olddelta *Timeval) (err error)
//sys	Chdir(path string) (err error)
//sys	Chmod(path string, mode uint32) (err error)
//sys	Chown(path string, uid int, gid int) (err error)
//sys	Chroot(path string) (err error)
//sys	ClockGettime(clockid int32, time *Timespec) (err error)
//sys	Close(fd int) (err error)
//sys	Creat(path string, mode uint32) (fd int, err error)
//sys	Dup(fd int) (nfd int, err error)
//sys	Dup2(oldfd int, newfd int) (err error)
//sys	Exit(code int)
//sys	Faccessat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchmodat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	Fdatasync(fd int) (err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fpathconf(fd int, name int) (val int, err error)
//sys	Fstat(fd int, stat *Stat_t) (err error)
//sys	Fstatat(fd int, path string, stat *Stat_t, flags int) (err error)
//sys	Fstatvfs(fd int, vfsstat *Statvfs_t) (err error)
//sys	Getdents(fd int, buf []byte, basep *uintptr) (n int, err error)
//sysnb	Getgid() (gid int)
//sysnb	Getpid() (pid int)
//sysnb	Getpgid(pid int) (pgid int, err error)
//sysnb	Getpgrp() (pgid int, err error)
//sys	Geteuid() (euid int)
//sys	Getegid() (egid int)
//sys	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (n int, err error)
//sysnb	Getrlimit(which int, lim *Rlimit) (err error)
//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Getsid(pid int) (sid int, err error)
//sysnb	Gettimeofday(tv *Timeval) (err error)
//sysnb	Getuid() (uid int)
//sys	Kill(pid int, signum syscall.Signal) (err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Listen(s int, backlog int) (err error) = libsocket.__xnet_llisten
//sys	Lstat(path string, stat *Stat_t) (err error)
//sys	Madvise(b []byte, advice int) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	Mkfifoat(dirfd int, path string, mode uint32) (err error)
//sys	Mknod(path string, mode uint32, dev int) (err error)
//sys	Mknodat(dirfd int, path string, mode uint32, dev int) (err error)
//sys	Mlock(b []byte) (err error)
//sys	Mlockall(flags int) (err error)
//sys	Mprotect(b []byte, prot int) (err error)
//sys	Msync(b []byte, flags int) (err error)
//sys	Munlock(b []byte) (err error)
//sys	Munlockall() (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error)
//sys	Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error)
//sys	Pathconf(path string, name int) (val int, err error)
//sys	Pause() (err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error)
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Readlink(path string, buf []byte) (n int, err error)
//sys	Rename(from string, to string) (err error)
//sys	Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)
//sys	Rmdir(path string) (err error)
//sys	Seek(fd int, offset int64, whence int) (newoffset int64, err error) = lseek
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error)
//sysnb	Setegid(egid int) (err error)
//sysnb	Seteuid(euid int) (err error)
//sysnb	Setgid(gid int) (err error)
//sys	Sethostname(p []byte) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Setuid(uid int) (err error)
//sys	Shutdown(s int, how int) (err error) = libsocket.shutdown
//sys	Stat(path string, stat *Stat_t) (err error)
//sys	Statvfs(path string, vfsstat *Statvfs_t) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Sync() (err error)
//sys	Sysconf(which int) (n int64, err error)
//sysnb	Times(tms *Tms) (ticks uintptr, err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Fsync(fd int) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sys	Umask(mask int) (oldmask int)
//sysnb	Uname(buf *Utsname) (err error)
//sys	Unmount(target string, flags int) (err error) = libc.umount
//sys	Unlink(path string) (err error)
//sys	Unlinkat(dirfd int, path string, flags int) (err error)
//sys	Ustat(dev int, ubuf *Ustat_t) (err error)
//sys	Utime(path string, buf *Utimbuf) (err error)
//sys	bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) = libsocket.__xnet_bind
//sys	connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) = libsocket.__xnet_connect
//sys	mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys	munmap(addr uintptr, length uintptr) (err error)
//sys	sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) = libsendfile.sendfile
//sys	sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error) = libsocket.__xnet_sendto
//sys	socket(domain int, typ int, proto int) (fd int, err error) = libsocket.__xnet_socket
//sysnb	socketpair(domain int, typ int, proto int, fd *[2]int32) (err error) = libsocket.__xnet_socketpair
//sys	write(fd int, p []byte) (n int, err error)
//sys	getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error) = libsocket.__xnet_getsockopt
//sysnb	getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) = libsocket.getpeername
//sys	setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) = libsocket.setsockopt
//sys	recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error) = libsocket.recvfrom

// Event Ports

type fileObjCookie struct {
	fobj   *fileObj
	cookie interface{}
}

// EventPort provides a safe abstraction on top of Solaris/illumos Event Ports.
type EventPort struct {
	port  int
	mu    sync.Mutex
	fds   map[uintptr]*fileObjCookie
	paths map[string]*fileObjCookie
	// The user cookie presents an interesting challenge from a memory management perspective.
	// There are two paths by which we can discover that it is no longer in use:
	// 1. The user calls port_dissociate before any events fire
	// 2. An event fires and we return it to the user
	// The tricky situation is if the event has fired in the kernel but
	// the user hasn't requested/received it yet.
	// If the user wants to port_dissociate before the event has been processed,
	// we should handle things gracefully. To do so, we need to keep an extra
	// reference to the cookie around until the event is processed
	// thus the otherwise seemingly extraneous "cookies" map
	// The key of this map is a pointer to the corresponding fCookie
	cookies map[*fileObjCookie]struct{}
}

// PortEvent is an abstraction of the port_event C struct.
// Compare Source against PORT_SOURCE_FILE or PORT_SOURCE_FD
// to see if Path or Fd was the event source. The other will be
// uninitialized.
type PortEvent struct {
	Cookie interface{}
	Events int32
	Fd     uintptr
	Path   string
	Source uint16
	fobj   *fileObj
}

// NewEventPort creates a new EventPort including the
// underlying call to port_create(3c).
func NewEventPort() (*EventPort, error) {
	port, err := port_create()
	if err != nil {
		return nil, err
	}
	e := &EventPort{
		port:    port,
		fds:     make(map[uintptr]*fileObjCookie),
		paths:   make(map[string]*fileObjCookie),
		cookies: make(map[*fileObjCookie]struct{}),
	}
	return e, nil
}

//sys	port_create() (n int, err error)
//sys	port_associate(port int, source int, object uintptr, events int, user *byte) (n int, err error)
//sys	port_dissociate(port int, source int, object uintptr) (n int, err error)
//sys	port_get(port int, pe *portEvent, timeout *Timespec) (n int, err error)
//sys	port_getn(port int, pe *portEvent, max uint32, nget *uint32, timeout *Timespec) (n int, err error)

// Close closes the event port.
func (e *EventPort) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	err := Close(e.port)
	if err != nil {
		return err
	}
	e.fds = nil
	e.paths = nil
	e.cookies = nil
	return nil
}

// PathIsWatched checks to see if path is associated with this EventPort.
func (e *EventPort) PathIsWatched(path string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, found := e.paths[path]
	return found
}

// FdIsWatched checks to see if fd is associated with this EventPort.
func (e *EventPort) FdIsWatched(fd uintptr) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, found := e.fds[fd]
	return found
}

// AssociatePath wraps port_associate(3c) for a filesystem path including
// creating the necessary file_obj from the provided stat information.
func (e *EventPort) AssociatePath(path string, stat os.FileInfo, events int, cookie interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, found := e.paths[path]; found {
		return fmt.Errorf("%v is already associated with this Event Port", path)
	}
	fCookie, err := createFileObjCookie(path, stat, cookie)
	if err != nil {
		return err
	}
	_, err = port_associate(e.port, PORT_SOURCE_FILE, uintptr(unsafe.Pointer(fCookie.fobj)), events, (*byte)(unsafe.Pointer(fCookie)))
	if err != nil {
		return err
	}
	e.paths[path] = fCookie
	e.cookies[fCookie] = struct{}{}
	return nil
}

// DissociatePath wraps port_dissociate(3c) for a filesystem path.
func (e *EventPort) DissociatePath(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	f, ok := e.paths[path]
	if !ok {
		return fmt.Errorf("%v is not associated with this Event Port", path)
	}
	_, err := port_dissociate(e.port, PORT_SOURCE_FILE, uintptr(unsafe.Pointer(f.fobj)))
	// If the path is no longer associated with this event port (ENOENT)
	// we should delete it from our map. We can still return ENOENT to the caller.
	// But we need to save the cookie
	if err != nil && err != ENOENT {
		return err
	}
	if err == nil {
		// dissociate was successful, safe to delete the cookie
		fCookie := e.paths[path]
		delete(e.cookies, fCookie)
	}
	delete(e.paths, path)
	return err
}

// AssociateFd wraps calls to port_associate(3c) on file descriptors.
func (e *EventPort) AssociateFd(fd uintptr, events int, cookie interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, found := e.fds[fd]; found {
		return fmt.Errorf("%v is already associated with this Event Port", fd)
	}
	fCookie, err := createFileObjCookie("", nil, cookie)
	if err != nil {
		return err
	}
	_, err = port_associate(e.port, PORT_SOURCE_FD, fd, events, (*byte)(unsafe.Pointer(fCookie)))
	if err != nil {
		return err
	}
	e.fds[fd] = fCookie
	e.cookies[fCookie] = struct{}{}
	return nil
}

// DissociateFd wraps calls to port_dissociate(3c) on file descriptors.
func (e *EventPort) DissociateFd(fd uintptr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.fds[fd]
	if !ok {
		return fmt.Errorf("%v is not associated with this Event Port", fd)
	}
	_, err := port_dissociate(e.port, PORT_SOURCE_FD, fd)
	if err != nil && err != ENOENT {
		return err
	}
	if err == nil {
		// dissociate was successful, safe to delete the cookie
		fCookie := e.fds[fd]
		delete(e.cookies, fCookie)
	}
	delete(e.fds, fd)
	return err
}

func createFileObjCookie(name string, stat os.FileInfo, cookie interface{}) (*fileObjCookie, error) {
	fCookie := new(fileObjCookie)
	fCookie.cookie = cookie
	if name != "" && stat != nil {
		fCookie.fobj = new(fileObj)
		bs, err := ByteSliceFromString(name)
		if err != nil {
			return nil, err
		}
		fCookie.fobj.Name = (*int8)(unsafe.Pointer(&bs[0]))
		s := stat.Sys().(*syscall.Stat_t)
		fCookie.fobj.Atim.Sec = s.Atim.Sec
		fCookie.fobj.Atim.Nsec = s.Atim.Nsec
		fCookie.fobj.Mtim.Sec = s.Mtim.Sec
		fCookie.fobj.Mtim.Nsec = s.Mtim.Nsec
		fCookie.fobj.Ctim.Sec = s.Ctim.Sec
		fCookie.fobj.Ctim.Nsec = s.Ctim.Nsec
	}
	return fCookie, nil
}

// GetOne wraps port_get(3c) and returns a single PortEvent.
func (e *EventPort) GetOne(t *Timespec) (*PortEvent, error) {
	pe := new(portEvent)
	_, err := port_get(e.port, pe, t)
	if err != nil {
		return nil, err
	}
	p := new(PortEvent)
	e.mu.Lock()
	defer e.mu.Unlock()
	err = e.peIntToExt(pe, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// peIntToExt converts a cgo portEvent struct into the friendlier PortEvent
// NOTE: Always call this function while holding the e.mu mutex
func (e *EventPort) peIntToExt(peInt *portEvent, peExt *PortEvent) error {
	if e.cookies == nil {
		return fmt.Errorf("this EventPort is already closed")
	}
	peExt.Events = peInt.Events
	peExt.Source = peInt.Source
	fCookie := (*fileObjCookie)(unsafe.Pointer(peInt.User))
	_, found := e.cookies[fCookie]

	if !found {
		panic("unexpected event port address; may be due to kernel bug; see https://go.dev/issue/54254")
	}
	peExt.Cookie = fCookie.cookie
	delete(e.cookies, fCookie)

	switch peInt.Source {
	case PORT_SOURCE_FD:
		peExt.Fd = uintptr(peInt.Object)
		// Only remove the fds entry if it exists and this cookie matches
		if fobj, ok := e.fds[peExt.Fd]; ok {
			if fobj == fCookie {
				delete(e.fds, peExt.Fd)
			}
		}
	case PORT_SOURCE_FILE:
		peExt.fobj = fCookie.fobj
		peExt.Path = BytePtrToString((*byte)(unsafe.Pointer(peExt.fobj.Name)))
		// Only remove the paths entry if it exists and this cookie matches
		if fobj, ok := e.paths[peExt.Path]; ok {
			if fobj == fCookie {
				delete(e.paths, peExt.Path)
			}
		}
	}
	return nil
}

// Pending wraps port_getn(3c) and returns how many events are pending.
func (e *EventPort) Pending() (int, error) {
	var n uint32 = 0
	_, err := port_getn(e.port, nil, 0, &n, nil)
	return int(n), err
}

// Get wraps port_getn(3c) and fills a slice of PortEvent.
// It will block until either min events have been received
// or the timeout has been exceeded. It will return how many
// events were actually received along with any error information.
func (e *EventPort) Get(s []PortEvent, min int, timeout *Timespec) (int, error) {
	if min == 0 {
		return 0, fmt.Errorf("need to request at least one event or use Pending() instead")
	}
	if len(s) < min {
		return 0, fmt.Errorf("len(s) (%d) is less than min events requested (%d)", len(s), min)
	}
	got := uint32(min)
	max := uint32(len(s))
	var err error
	ps := make([]portEvent, max)
	_, err = port_getn(e.port, &ps[0], max, &got, timeout)
	// got will be trustworthy with ETIME, but not any other error.
	if err != nil && err != ETIME {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	valid := 0
	for i := 0; i < int(got); i++ {
		err2 := e.peIntToExt(&ps[i], &s[i])
		if err2 != nil {
			if valid == 0 && err == nil {
				// If err2 is the only error and there are no valid events
				// to return, return it to the caller.
				err = err2
			}
			break
		}
		valid = i + 1
	}
	return valid, err
}

//sys	putmsg(fd int, clptr *strbuf, dataptr *strbuf, flags int) (err error)

func Putmsg(fd int, cl []byte, data []byte, flags int) (err error) {
	var clp, datap *strbuf
	if len(cl) > 0 {
		clp = &strbuf{
			Len: int32(len(cl)),
			Buf: (*int8)(unsafe.Pointer(&cl[0])),
		}
	}
	if len(data) > 0 {
		datap = &strbuf{
			Len: int32(len(data)),
			Buf: (*int8)(unsafe.Pointer(&data[0])),
		}
	}
	return putmsg(fd, clp, datap, flags)
}

//sys	getmsg(fd int, clptr *strbuf, dataptr *strbuf, flags *int) (err error)

func Getmsg(fd int, cl []byte, data []byte) (retCl []byte, retData []byte, flags int, err error) {
	var clp, datap *strbuf
	if len(cl) > 0 {
		clp = &strbuf{
			Maxlen: int32(len(cl)),
			Buf:    (*int8)(unsafe.Pointer(&cl[0])),
		}
	}
	if len(data) > 0 {
		datap = &strbuf{
			Maxlen: int32(len(data)),
			Buf:    (*int8)(unsafe.Pointer(&data[0])),
		}
	}

	if err = getmsg(fd, clp, datap, &flags); err != nil {
		return nil, nil, 0, err
	}

	if len(cl) > 0 {
		retCl = cl[:clp.Len]
	}
	if len(data) > 0 {
		retData = data[:datap.Len]
	}
	return retCl, retData, flags, nil
}

func IoctlSetIntRetInt(fd int, req int, arg int) (int, error) {
	return ioctlRet(fd, req, uintptr(arg))
}

func IoctlSetString(fd int, req int, val string) error {
	bs := make([]byte, len(val)+1)
	copy(bs[:len(bs)-1], val)
	err := ioctlPtr(fd, req, unsafe.Pointer(&bs[0]))
	runtime.KeepAlive(&bs[0])
	return err
}

// Lifreq Helpers

func (l *Lifreq) SetName(name string) error {
	if len(name) >= len(l.Name) {
		return fmt.Errorf("name cannot be more than %d characters", len(l.Name)-1)
	}
	for i := range name {
		l.Name[i] = int8(name[i])
	}
	return nil
}

func (l *Lifreq) SetLifruInt(d int) {
	*(*int)(unsafe.Pointer(&l.Lifru[0])) = d
}

func (l *Lifreq) GetLifruInt() int {
	return *(*int)(unsafe.Pointer(&l.Lifru[0]))
}

func (l *Lifreq) SetLifruUint(d uint) {
	*(*uint)(unsafe.Pointer(&l.Lifru[0])) = d
}

func (l *Lifreq) GetLifruUint() uint {
	return *(*uint)(unsafe.Pointer(&l.Lifru[0]))
}

func IoctlLifreq(fd int, req int, l *Lifreq) error {
	return ioctlPtr(fd, req, unsafe.Pointer(l))
}

// Strioctl Helpers

func (s *Strioctl) SetInt(i int) {
	s.Len = int32(unsafe.Sizeof(i))
	s.Dp = (*int8)(unsafe.Pointer(&i))
}

func IoctlSetStrioctlRetInt(fd int, req int, s *Strioctl) (int, error) {
	return ioctlPtrRet(fd, req, unsafe.Pointer(s))
}
```