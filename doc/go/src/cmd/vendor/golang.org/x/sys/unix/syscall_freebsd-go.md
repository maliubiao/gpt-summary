Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding & Context:**

* **File Path:** `go/src/cmd/vendor/golang.org/x/sys/unix/syscall_freebsd.go` immediately tells us this is part of the Go standard library's low-level system call interface for FreeBSD. The `vendor` directory suggests it's a vendored dependency, likely for specific versions or to isolate it.
* **Copyright & License:** Standard Go copyright and BSD license. Indicates it's open-source and part of the core Go project.
* **`//sys` Comments:** These are crucial. They are directives for the `mksyscall` tool, indicating that the following Go function is a direct mapping to a FreeBSD system call. This immediately tells us the *primary* function of the file: to provide access to FreeBSD system calls.
* **`package unix`:** This confirms it's part of the `syscall` package (aliased as `unix` for clarity on non-Unix systems or when specifically targeting Unix-like systems).
* **Imports:** `errors`, `sync`, and `unsafe` are common for low-level system programming in Go. `errors` for standard error handling, `sync` likely for the `sync.Once` used for `osreldate`, and `unsafe` for direct memory manipulation (essential for interacting with C-style system calls).

**2. High-Level Functionality Identification:**

The presence of `//sys` lines is the biggest clue. The file's main purpose is to provide Go wrappers around FreeBSD system calls. This means it:

* **Provides a Go interface to FreeBSD kernel functions.**  Think of it as a translation layer between Go's memory management and type system and the FreeBSD kernel's ABI.
* **Handles low-level operations:** File I/O, process management, networking, etc., as those are the kinds of things system calls typically handle.

**3. Deeper Dive into Specific Code Blocks:**

* **`osreldateOnce` & `supportsABI`:**  This is clearly for checking the FreeBSD version. The `sync.Once` ensures the `SysctlUint32` call happens only once. This suggests some functions might be conditionally available based on the OS version.
* **`SockaddrDatalink` & `anyToSockaddrGOOS`:** Deals with network socket addresses, specifically the `AF_LINK` family. The `anyToSockaddrGOOS` returning `EAFNOSUPPORT` suggests this file might not fully implement all socket address types, or this function is a placeholder.
* **`nametomib`:** This function translates a string (like "kern.hostname") into a Management Information Base (MIB) array, used for the `sysctl` system call. The comment about `CTL_MAXNAME + 2` is a critical observation for anyone maintaining this code.
* **`direntIno`, `direntReclen`, `direntNamlen`:** These functions extract specific fields from a directory entry (`Dirent` struct), likely used by functions like `Getdents`.
* **`Pipe` & `Pipe2`:**  Standard functions for creating pipes for inter-process communication.
* **`GetsockoptIPMreqn` & `SetsockoptIPMreqn`:** Get and set IP multicast options on sockets.
* **`GetsockoptXucred`:** Retrieves credentials of a peer connected to a Unix domain socket.
* **`Accept4`:**  Accepts a new connection on a socket with additional flags (like `O_CLOEXEC`). The interaction with `anyToSockaddr` is important.
* **`Getcwd`:** Gets the current working directory.
* **`Getfsstat`:** Retrieves file system statistics.
* **`ioctl` & `ioctlPtr`:**  General-purpose system call for device-specific operations.
* **`sysctl`:**  The core system call for retrieving and setting kernel parameters. The `Uname` function heavily relies on this.
* **`Uname`:**  Retrieves system information (OS name, hostname, etc.). The handling of `ENOMEM` is a notable detail.
* **`Stat`, `Lstat`, `Fstatat`:** Functions for getting file metadata.
* **`Getdents`, `Getdirentries`:**  Read directory entries. The handling of 32-bit vs. 64-bit systems for `basep` is a critical platform-specific consideration.
* **`Mknod` & `Mknodat`:** Create special file system nodes (devices, etc.).
* **`Sendfile`:** Efficiently copies data between file descriptors.
* **`ptrace` family:**  Functions for process tracing and debugging.
* **`Dup3`:** Duplicates a file descriptor with more control over flags.
* **The large block of `//sys` functions:** This is a comprehensive list of FreeBSD system calls exposed by this file.

**4. Identifying Go Feature Implementation:**

The core feature being implemented is **interfacing with the FreeBSD operating system kernel**. This is achieved through the `syscall` package and the `mksyscall` tool. The code provides the raw building blocks for higher-level Go functionalities related to the OS.

**5. Code Examples and Reasoning (Iterative Process):**

For each function group (file I/O, networking, process management), think of a common use case and how these low-level functions would be used. For example:

* **File I/O:**  `Open`, `Read`, `Write`, `Close` are fundamental.
* **Networking:** `Socket`, `Bind`, `Listen`, `Accept`, `Connect`, `Send`, `Recv`. The code shows some socket options (`GetsockoptIPMreqn`).
* **Process Management:** `Fork`, `Exec`, `Wait`, `Kill`. The `ptrace` functions are clearly for debugging.

Then, construct simple Go examples using the functions exposed in the file. The key is to show the mapping between the Go code and the underlying system call.

**6. Command-Line Arguments:**

Focus on system calls that might directly involve command-line arguments, such as process execution (`Exec`). Explain how these arguments are passed down to the kernel.

**7. Common Mistakes:**

Think about the low-level nature of the code. What are typical errors when dealing with system calls?

* **Incorrect error handling:** Not checking return values.
* **Buffer overflows:**  Incorrectly sized buffers for system calls.
* **Resource leaks:** Forgetting to `Close` file descriptors.
* **Incorrect use of flags and options:**  Misunderstanding the meaning of parameters to system calls.

**8. Refinement and Organization:**

Structure the answer logically, starting with the overall purpose and then diving into specifics. Use headings and bullet points for clarity. Provide clear explanations for code examples and assumptions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just wraps system calls."  **Refinement:**  It also includes utility functions like `nametomib` and version checking, demonstrating additional logic beyond simple wrappers.
* **Initial thought:** "Just list the `//sys` functions." **Refinement:**  Group them by functionality and provide context for their use.
* **Code Example Check:** Ensure the code examples compile and demonstrate the intended functionality. For instance, initially, I might have forgotten to handle errors in the `os.Open` example.

By following this structured approach, analyzing the code snippets, considering the context, and iteratively refining the understanding, we can arrive at a comprehensive and accurate answer.
这个文件 `go/src/cmd/vendor/golang.org/x/sys/unix/syscall_freebsd.go` 是 Go 语言标准库中 `syscall` 包的一部分，专门用于 **FreeBSD 操作系统**。它的主要功能是 **提供 Go 语言访问 FreeBSD 系统调用的接口**。

更具体来说，它的功能可以列举如下：

1. **定义 FreeBSD 特定的数据结构:**  例如 `SockaddrDatalink` 用于表示 AF_LINK 类型的 socket 地址。
2. **提供辅助函数:**  例如 `supportsABI` 用于检查 FreeBSD 版本是否支持特定的 ABI，`nametomib` 用于将系统控制名称转换为 MIB（Management Information Base）数组，以及 `direntIno`、`direntReclen`、`direntNamlen` 用于解析目录项结构。
3. **实现系统调用的 Go 封装:**  通过 `//sys` 注释，`mksyscall` 工具会根据这些注释生成实际的系统调用桩代码。这些封装函数（例如 `Pipe`, `Getcwd`, `ioctl`, `sysctl`, `Uname`, `Stat` 等）使得 Go 程序能够调用底层的 FreeBSD 系统调用。
4. **处理 FreeBSD 特有的系统调用细节:** 例如，`Getdirentries` 函数处理了 32 位和 64 位系统上 `basep` 参数的差异。
5. **提供了一些更高级别的辅助函数:**  例如 `Pipe` 函数是对 `pipe2` 系统调用的封装，提供了更简洁的接口。 `GetsockoptIPMreqn` 和 `SetsockoptIPMreqn` 用于处理 IP 多播相关的 socket 选项。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言 **操作系统接口 (Operating System Interface)** 的一部分，更具体地说是针对 **FreeBSD 平台的系统调用接口**的实现。  Go 语言的 `syscall` 包旨在提供一个与平台无关的方式来访问底层操作系统功能，而像 `syscall_freebsd.go` 这样的文件就是针对特定平台的实现细节。

**Go 代码举例说明:**

假设我们需要获取当前进程的 PID (Process ID)。在 FreeBSD 上，这可以通过 `getpid()` 系统调用实现。  `syscall_freebsd.go` 文件中已经定义了 `//sysnb	Getpid() (pid int)`，这意味着 Go 程序可以通过 `unix.Getpid()` 来调用这个系统调用。

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func main() {
	pid := unix.Getpid()
	fmt.Printf("当前进程的 PID: %d\n", pid)
}
```

**假设输入与输出:**

* **输入:** 无，`unix.Getpid()` 不需要任何参数。
* **输出:** 当前运行该 Go 程序的进程的 PID，例如 `当前进程的 PID: 12345`。

**涉及代码推理 (以 `nametomib` 为例):**

`nametomib` 函数的功能是将一个类似 `"kern.hostname"` 的字符串转换为表示该系统控制信息的 MIB 数组。

```go
func nametomib(name string) (mib []_C_int, err error) {
	const siz = unsafe.Sizeof(mib[0])

	var buf [CTL_MAXNAME + 2]_C_int
	n := uintptr(CTL_MAXNAME) * siz

	p := (*byte)(unsafe.Pointer(&buf[0]))
	bytes, err := ByteSliceFromString(name)
	if err != nil {
		return nil, err
	}

	// Magic sysctl: "setting" 0.3 to a string name
	// lets you read back the array of integers form.
	if err = sysctl([]_C_int{0, 3}, p, &n, &bytes[0], uintptr(len(name))); err != nil {
		return nil, err
	}
	return buf[0 : n/siz], nil
}
```

**假设输入与输出:**

* **输入:** `name = "kern.hostname"`
* **输出:**  `mib` 将会是一个 `[]_C_int` 类型的切片，包含对应 `"kern.hostname"` 的 MIB 数组。例如，在某些 FreeBSD 系统上，它可能是 `[]_C_int{1, 6, 1}`。  `err` 如果执行成功则为 `nil`。

**代码推理:**

1. **`const siz = unsafe.Sizeof(mib[0])`:**  获取 `_C_int` 类型的大小。
2. **`var buf [CTL_MAXNAME + 2]_C_int`:**  声明一个足够大的缓冲区来存储 MIB 数组。`CTL_MAXNAME` 是一个常量，表示 MIB 名称的最大长度。这里加 2 的原因在注释中解释了，是为了防止内核写入超出预期范围。
3. **`n := uintptr(CTL_MAXNAME) * siz`:**  计算缓冲区的最大字节数。
4. **`p := (*byte)(unsafe.Pointer(&buf[0]))`:**  获取缓冲区首地址的 `byte` 指针。
5. **`bytes, err := ByteSliceFromString(name)`:** 将输入的字符串转换为字节切片。
6. **`sysctl([]_C_int{0, 3}, p, &n, &bytes[0], uintptr(len(name)))`:**  这是关键步骤。它调用了 `sysctl` 系统调用，使用了 `[0, 3]` 这个特殊的 MIB。根据注释，这是一种 "magic" 的用法，可以将字符串形式的系统控制名称转换为 MIB 数组。
    * `[]_C_int{0, 3}`:  指定了操作类型。
    * `p`: 指向用于接收 MIB 数组的缓冲区。
    * `&n`: 指向表示缓冲区大小的变量。在调用前设置了最大值，调用后会被更新为实际写入的字节数。
    * `&bytes[0]`: 指向包含系统控制名称的字节切片。
    * `uintptr(len(name))`: 系统控制名称的长度。
7. **`return buf[0 : n/siz], nil`:**  返回从缓冲区中读取的 MIB 数组切片。切片的长度通过实际读取的字节数 `n` 除以 `_C_int` 的大小计算得到。

**涉及命令行参数的具体处理:**

这个文件中大部分函数是直接对系统调用的封装，本身不直接处理命令行参数。命令行参数的处理通常发生在更上层的应用代码中，然后这些参数可能会被传递给这里定义的系统调用封装函数。

例如，`os.Open` 函数最终会调用到 `unix.Open`，而 `os.Open` 接收的文件路径参数，就是从命令行或者程序内部传递过来的。

如果涉及到需要传递命令行参数给子进程的系统调用，例如 `Exec`，那么参数的处理如下：

```go
// 在 syscall_freebsd.go 中可能有类似这样的定义 (实际的定义可能在 syscall_unix.go 或 syscall_bsd.go 中)
//sys	execve(path string, argv []string, envv []string) (err error)

// 上层调用示例
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	// 假设要执行的命令是 "ls -l /tmp"
	argv := []string{"ls", "-l", "/tmp"}
	envv := os.Environ() // 获取当前环境变量

	err := unix.Exec("/bin/ls", argv, envv)
	if err != nil {
		fmt.Println("执行 execve 失败:", err)
	}
}
```

在这个例子中：

* **`"/bin/ls"`:**  是要执行的程序路径。
* **`argv`:**  是一个字符串切片，包含了传递给 `ls` 命令的参数，包括命令本身。
* **`envv`:**  是一个字符串切片，包含了要传递给子进程的环境变量。

当 `unix.Exec` 被调用时，这些参数会被传递给底层的 `execve` 系统调用。

**使用者易犯错的点 (以 `ioctl` 为例):**

`ioctl` 是一个非常灵活但也很容易出错的系统调用，因为它允许进行各种设备特定的操作。

**易犯错的点：不理解 `req` 和 `arg` 的含义和正确用法。**

* **错误示例:**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"unsafe"
)

func main() {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR, 0)
	if err != nil {
		fmt.Println("打开设备失败:", err)
		return
	}
	defer unix.Close(fd)

	// 尝试设置终端为非阻塞模式 (假设这是一个错误的请求码)
	err = unix.Ioctl(fd, unix.FIONBIO, 1) // 错误地将 int 作为 uintptr 传递
	if err != nil {
		fmt.Println("ioctl 失败:", err)
	}
}
```

**解释:**

* `ioctl` 函数的签名是 `ioctl(fd int, req uint, arg uintptr) (err error)`.
* `req` 参数是一个与特定设备相关的请求码，定义了要执行的操作。
* `arg` 参数的类型是 `uintptr`，它可以是一个整数值，也可以是一个指向内存的指针，具体取决于 `req` 的值。

在上面的错误示例中，假设 `unix.FIONBIO` 是用于设置非阻塞模式的请求码，它通常需要一个指向整数的指针作为 `arg`，而不是直接传递整数值。  正确的做法可能需要使用 `unsafe.Pointer` 将整数的地址转换为 `uintptr`。

**正确的示例 (可能需要根据具体的 `ioctl` 请求码进行调整):**

```go
package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"unsafe"
)

func main() {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR, 0)
	if err != nil {
		fmt.Println("打开设备失败:", err)
		return
	}
	defer unix.Close(fd)

	// 正确设置终端为非阻塞模式 (假设 FIONBIO 需要指向 int 的指针)
	var nonblocking int = 1
	_, _, err = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.FIONBIO, uintptr(unsafe.Pointer(&nonblocking)))
	if err != 0 {
		fmt.Println("ioctl 失败:", err)
	}
}
```

**总结 `ioctl` 易犯错的点:**

* **不理解 `req` 的含义:** 不同的 `req` 值对应不同的操作，需要查阅相关的设备驱动程序文档或头文件。
* **`arg` 类型不匹配:**  根据 `req` 的不同，`arg` 可能是整数、指向结构体的指针、指向整数的指针等。传递错误的类型会导致不可预测的行为甚至程序崩溃。
* **缓冲区大小错误:** 如果 `ioctl` 需要读写数据到用户空间缓冲区，需要确保缓冲区的大小足够。
* **权限问题:** 某些 `ioctl` 操作可能需要特定的权限。

总而言之，`go/src/cmd/vendor/golang.org/x/sys/unix/syscall_freebsd.go` 是 Go 语言与 FreeBSD 操作系统交互的桥梁，它通过封装系统调用，使得 Go 程序能够利用 FreeBSD 提供的底层功能。理解其功能和潜在的错误点对于编写可靠的、与操作系统紧密集成的 Go 程序至关重要。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/syscall_freebsd.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009,2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// FreeBSD system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and wrap
// it in our own nicer implementation, either here or in
// syscall_bsd.go or syscall_unix.go.

package unix

import (
	"errors"
	"sync"
	"unsafe"
)

// See https://www.freebsd.org/doc/en_US.ISO8859-1/books/porters-handbook/versions.html.
var (
	osreldateOnce sync.Once
	osreldate     uint32
)

func supportsABI(ver uint32) bool {
	osreldateOnce.Do(func() { osreldate, _ = SysctlUint32("kern.osreldate") })
	return osreldate >= ver
}

// SockaddrDatalink implements the Sockaddr interface for AF_LINK type sockets.
type SockaddrDatalink struct {
	Len    uint8
	Family uint8
	Index  uint16
	Type   uint8
	Nlen   uint8
	Alen   uint8
	Slen   uint8
	Data   [46]int8
	raw    RawSockaddrDatalink
}

func anyToSockaddrGOOS(fd int, rsa *RawSockaddrAny) (Sockaddr, error) {
	return nil, EAFNOSUPPORT
}

// Translate "kern.hostname" to []_C_int{0,1,2,3}.
func nametomib(name string) (mib []_C_int, err error) {
	const siz = unsafe.Sizeof(mib[0])

	// NOTE(rsc): It seems strange to set the buffer to have
	// size CTL_MAXNAME+2 but use only CTL_MAXNAME
	// as the size. I don't know why the +2 is here, but the
	// kernel uses +2 for its own implementation of this function.
	// I am scared that if we don't include the +2 here, the kernel
	// will silently write 2 words farther than we specify
	// and we'll get memory corruption.
	var buf [CTL_MAXNAME + 2]_C_int
	n := uintptr(CTL_MAXNAME) * siz

	p := (*byte)(unsafe.Pointer(&buf[0]))
	bytes, err := ByteSliceFromString(name)
	if err != nil {
		return nil, err
	}

	// Magic sysctl: "setting" 0.3 to a string name
	// lets you read back the array of integers form.
	if err = sysctl([]_C_int{0, 3}, p, &n, &bytes[0], uintptr(len(name))); err != nil {
		return nil, err
	}
	return buf[0 : n/siz], nil
}

func direntIno(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Fileno), unsafe.Sizeof(Dirent{}.Fileno))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Namlen), unsafe.Sizeof(Dirent{}.Namlen))
}

func Pipe(p []int) (err error) {
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

func GetsockoptIPMreqn(fd, level, opt int) (*IPMreqn, error) {
	var value IPMreqn
	vallen := _Socklen(SizeofIPMreqn)
	errno := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, errno
}

func SetsockoptIPMreqn(fd, level, opt int, mreq *IPMreqn) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), unsafe.Sizeof(*mreq))
}

// GetsockoptXucred is a getsockopt wrapper that returns an Xucred struct.
// The usual level and opt are SOL_LOCAL and LOCAL_PEERCRED, respectively.
func GetsockoptXucred(fd, level, opt int) (*Xucred, error) {
	x := new(Xucred)
	vallen := _Socklen(SizeofXucred)
	err := getsockopt(fd, level, opt, unsafe.Pointer(x), &vallen)
	return x, err
}

func Accept4(fd, flags int) (nfd int, sa Sockaddr, err error) {
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

//sys	Getcwd(buf []byte) (n int, err error) = SYS___GETCWD

func Getfsstat(buf []Statfs_t, flags int) (n int, err error) {
	var (
		_p0     unsafe.Pointer
		bufsize uintptr
	)
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
		bufsize = unsafe.Sizeof(Statfs_t{}) * uintptr(len(buf))
	}
	r0, _, e1 := Syscall(SYS_GETFSSTAT, uintptr(_p0), bufsize, uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

//sys	ioctl(fd int, req uint, arg uintptr) (err error) = SYS_IOCTL
//sys	ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error) = SYS_IOCTL

//sys	sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) = SYS___SYSCTL

func Uname(uname *Utsname) error {
	mib := []_C_int{CTL_KERN, KERN_OSTYPE}
	n := unsafe.Sizeof(uname.Sysname)
	// Suppress ENOMEM errors to be compatible with the C library __xuname() implementation.
	if err := sysctl(mib, &uname.Sysname[0], &n, nil, 0); err != nil && !errors.Is(err, ENOMEM) {
		return err
	}

	mib = []_C_int{CTL_KERN, KERN_HOSTNAME}
	n = unsafe.Sizeof(uname.Nodename)
	if err := sysctl(mib, &uname.Nodename[0], &n, nil, 0); err != nil && !errors.Is(err, ENOMEM) {
		return err
	}

	mib = []_C_int{CTL_KERN, KERN_OSRELEASE}
	n = unsafe.Sizeof(uname.Release)
	if err := sysctl(mib, &uname.Release[0], &n, nil, 0); err != nil && !errors.Is(err, ENOMEM) {
		return err
	}

	mib = []_C_int{CTL_KERN, KERN_VERSION}
	n = unsafe.Sizeof(uname.Version)
	if err := sysctl(mib, &uname.Version[0], &n, nil, 0); err != nil && !errors.Is(err, ENOMEM) {
		return err
	}

	// The version might have newlines or tabs in it, convert them to
	// spaces.
	for i, b := range uname.Version {
		if b == '\n' || b == '\t' {
			if i == len(uname.Version)-1 {
				uname.Version[i] = 0
			} else {
				uname.Version[i] = ' '
			}
		}
	}

	mib = []_C_int{CTL_HW, HW_MACHINE}
	n = unsafe.Sizeof(uname.Machine)
	if err := sysctl(mib, &uname.Machine[0], &n, nil, 0); err != nil && !errors.Is(err, ENOMEM) {
		return err
	}

	return nil
}

func Stat(path string, st *Stat_t) (err error) {
	return Fstatat(AT_FDCWD, path, st, 0)
}

func Lstat(path string, st *Stat_t) (err error) {
	return Fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW)
}

func Getdents(fd int, buf []byte) (n int, err error) {
	return Getdirentries(fd, buf, nil)
}

func Getdirentries(fd int, buf []byte, basep *uintptr) (n int, err error) {
	if basep == nil || unsafe.Sizeof(*basep) == 8 {
		return getdirentries(fd, buf, (*uint64)(unsafe.Pointer(basep)))
	}
	// The syscall needs a 64-bit base. On 32-bit machines
	// we can't just use the basep passed in. See #32498.
	var base uint64 = uint64(*basep)
	n, err = getdirentries(fd, buf, &base)
	*basep = uintptr(base)
	if base>>32 != 0 {
		// We can't stuff the base back into a uintptr, so any
		// future calls would be suspect. Generate an error.
		// EIO is allowed by getdirentries.
		err = EIO
	}
	return
}

func Mknod(path string, mode uint32, dev uint64) (err error) {
	return Mknodat(AT_FDCWD, path, mode, dev)
}

func Sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	if raceenabled {
		raceReleaseMerge(unsafe.Pointer(&ioSync))
	}
	return sendfile(outfd, infd, offset, count)
}

//sys	ptrace(request int, pid int, addr uintptr, data int) (err error)
//sys	ptracePtr(request int, pid int, addr unsafe.Pointer, data int) (err error) = SYS_PTRACE

func PtraceAttach(pid int) (err error) {
	return ptrace(PT_ATTACH, pid, 0, 0)
}

func PtraceCont(pid int, signal int) (err error) {
	return ptrace(PT_CONTINUE, pid, 1, signal)
}

func PtraceDetach(pid int) (err error) {
	return ptrace(PT_DETACH, pid, 1, 0)
}

func PtraceGetFpRegs(pid int, fpregsout *FpReg) (err error) {
	return ptracePtr(PT_GETFPREGS, pid, unsafe.Pointer(fpregsout), 0)
}

func PtraceGetRegs(pid int, regsout *Reg) (err error) {
	return ptracePtr(PT_GETREGS, pid, unsafe.Pointer(regsout), 0)
}

func PtraceIO(req int, pid int, offs uintptr, out []byte, countin int) (count int, err error) {
	ioDesc := PtraceIoDesc{
		Op:   int32(req),
		Offs: offs,
	}
	if countin > 0 {
		_ = out[:countin] // check bounds
		ioDesc.Addr = &out[0]
	} else if out != nil {
		ioDesc.Addr = (*byte)(unsafe.Pointer(&_zero))
	}
	ioDesc.SetLen(countin)

	err = ptracePtr(PT_IO, pid, unsafe.Pointer(&ioDesc), 0)
	return int(ioDesc.Len), err
}

func PtraceLwpEvents(pid int, enable int) (err error) {
	return ptrace(PT_LWP_EVENTS, pid, 0, enable)
}

func PtraceLwpInfo(pid int, info *PtraceLwpInfoStruct) (err error) {
	return ptracePtr(PT_LWPINFO, pid, unsafe.Pointer(info), int(unsafe.Sizeof(*info)))
}

func PtracePeekData(pid int, addr uintptr, out []byte) (count int, err error) {
	return PtraceIO(PIOD_READ_D, pid, addr, out, SizeofLong)
}

func PtracePeekText(pid int, addr uintptr, out []byte) (count int, err error) {
	return PtraceIO(PIOD_READ_I, pid, addr, out, SizeofLong)
}

func PtracePokeData(pid int, addr uintptr, data []byte) (count int, err error) {
	return PtraceIO(PIOD_WRITE_D, pid, addr, data, SizeofLong)
}

func PtracePokeText(pid int, addr uintptr, data []byte) (count int, err error) {
	return PtraceIO(PIOD_WRITE_I, pid, addr, data, SizeofLong)
}

func PtraceSetRegs(pid int, regs *Reg) (err error) {
	return ptracePtr(PT_SETREGS, pid, unsafe.Pointer(regs), 0)
}

func PtraceSingleStep(pid int) (err error) {
	return ptrace(PT_STEP, pid, 1, 0)
}

func Dup3(oldfd, newfd, flags int) error {
	if oldfd == newfd || flags&^O_CLOEXEC != 0 {
		return EINVAL
	}
	how := F_DUP2FD
	if flags&O_CLOEXEC != 0 {
		how = F_DUP2FD_CLOEXEC
	}
	_, err := fcntl(oldfd, how, newfd)
	return err
}

/*
 * Exposed directly
 */
//sys	Access(path string, mode uint32) (err error)
//sys	Adjtime(delta *Timeval, olddelta *Timeval) (err error)
//sys	CapEnter() (err error)
//sys	capRightsGet(version int, fd int, rightsp *CapRights) (err error) = SYS___CAP_RIGHTS_GET
//sys	capRightsLimit(fd int, rightsp *CapRights) (err error)
//sys	Chdir(path string) (err error)
//sys	Chflags(path string, flags int) (err error)
//sys	Chmod(path string, mode uint32) (err error)
//sys	Chown(path string, uid int, gid int) (err error)
//sys	Chroot(path string) (err error)
//sys	ClockGettime(clockid int32, time *Timespec) (err error)
//sys	Close(fd int) (err error)
//sys	Dup(fd int) (nfd int, err error)
//sys	Dup2(from int, to int) (err error)
//sys	Exit(code int)
//sys	ExtattrGetFd(fd int, attrnamespace int, attrname string, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrSetFd(fd int, attrnamespace int, attrname string, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrDeleteFd(fd int, attrnamespace int, attrname string) (err error)
//sys	ExtattrListFd(fd int, attrnamespace int, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrGetFile(file string, attrnamespace int, attrname string, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrSetFile(file string, attrnamespace int, attrname string, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrDeleteFile(file string, attrnamespace int, attrname string) (err error)
//sys	ExtattrListFile(file string, attrnamespace int, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrGetLink(link string, attrnamespace int, attrname string, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrSetLink(link string, attrnamespace int, attrname string, data uintptr, nbytes int) (ret int, err error)
//sys	ExtattrDeleteLink(link string, attrnamespace int, attrname string) (err error)
//sys	ExtattrListLink(link string, attrnamespace int, data uintptr, nbytes int) (ret int, err error)
//sys	Fadvise(fd int, offset int64, length int64, advice int) (err error) = SYS_POSIX_FADVISE
//sys	Faccessat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchflags(fd int, flags int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchmodat(dirfd int, path string, mode uint32, flags int) (err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fpathconf(fd int, name int) (val int, err error)
//sys	Fstat(fd int, stat *Stat_t) (err error)
//sys	Fstatat(fd int, path string, stat *Stat_t, flags int) (err error)
//sys	Fstatfs(fd int, stat *Statfs_t) (err error)
//sys	Fsync(fd int) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
//sys	getdirentries(fd int, buf []byte, basep *uint64) (n int, err error)
//sys	Getdtablesize() (size int)
//sysnb	Getegid() (egid int)
//sysnb	Geteuid() (uid int)
//sysnb	Getgid() (gid int)
//sysnb	Getpgid(pid int) (pgid int, err error)
//sysnb	Getpgrp() (pgrp int)
//sysnb	Getpid() (pid int)
//sysnb	Getppid() (ppid int)
//sys	Getpriority(which int, who int) (prio int, err error)
//sysnb	Getrlimit(which int, lim *Rlimit) (err error)
//sysnb	Getrusage(who int, rusage *Rusage) (err error)
//sysnb	Getsid(pid int) (sid int, err error)
//sysnb	Gettimeofday(tv *Timeval) (err error)
//sysnb	Getuid() (uid int)
//sys	Issetugid() (tainted bool)
//sys	Kill(pid int, signum syscall.Signal) (err error)
//sys	Kqueue() (fd int, err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Linkat(pathfd int, path string, linkfd int, link string, flags int) (err error)
//sys	Listen(s int, backlog int) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkdirat(dirfd int, path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	Mknodat(fd int, path string, mode uint32, dev uint64) (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error)
//sys	Openat(fdat int, path string, mode int, perm uint32) (fd int, err error)
//sys	Pathconf(path string, name int) (val int, err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error)
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Readlink(path string, buf []byte) (n int, err error)
//sys	Readlinkat(dirfd int, path string, buf []byte) (n int, err error)
//sys	Rename(from string, to string) (err error)
//sys	Renameat(fromfd int, from string, tofd int, to string) (err error)
//sys	Revoke(path string) (err error)
//sys	Rmdir(path string) (err error)
//sys	Seek(fd int, offset int64, whence int) (newoffset int64, err error) = SYS_LSEEK
//sys	Select(nfd int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (n int, err error)
//sysnb	Setegid(egid int) (err error)
//sysnb	Seteuid(euid int) (err error)
//sysnb	Setgid(gid int) (err error)
//sys	Setlogin(name string) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	Setresgid(rgid int, egid int, sgid int) (err error)
//sysnb	Setresuid(ruid int, euid int, suid int) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tp *Timeval) (err error)
//sysnb	Setuid(uid int) (err error)
//sys	Statfs(path string, stat *Statfs_t) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Symlinkat(oldpath string, newdirfd int, newpath string) (err error)
//sys	Sync() (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Umask(newmask int) (oldmask int)
//sys	Undelete(path string) (err error)
//sys	Unlink(path string) (err error)
//sys	Unlinkat(dirfd int, path string, flags int) (err error)
//sys	Unmount(path string, flags int) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys	mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys	munmap(addr uintptr, length uintptr) (err error)
//sys	accept4(fd int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (nfd int, err error)
//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)

"""



```