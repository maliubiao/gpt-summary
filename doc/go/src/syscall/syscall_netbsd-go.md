Response:
Let's break down the thought process for analyzing the provided Go code snippet from `syscall_netbsd.go`.

**1. Initial Understanding of the Context:**

The first line `// go/src/syscall/syscall_netbsd.go` immediately tells us this is part of the Go standard library, specifically dealing with system calls on NetBSD. The comments at the beginning reinforce this, mentioning "NetBSD system calls" and the use of `mksyscall`.

**2. Identifying Key Components:**

I scanned the code looking for distinct blocks and keywords. The following stood out:

* **`package syscall`:** This is the package declaration, indicating the purpose of the code.
* **`import "unsafe"`:** The `unsafe` package suggests low-level operations and direct memory manipulation, which is expected for system call interaction.
* **`func Syscall(...)`, `func Syscall6(...)`, etc.:** These are the fundamental building blocks for making system calls. The numbers (3, 6, 9) likely indicate the number of arguments passed to the underlying system call.
* **`func RawSyscall(...)`, `func RawSyscall6(...)`:** Similar to the `Syscall` functions, but likely providing a more direct, less abstracted interface to system calls.
* **`const _SYS_DUP3 = SYS_DUP3`, `_F_DUP2FD_CLOEXEC = 0`:** These are constants, likely mapping Go-level constants to underlying NetBSD system call numbers or flags.
* **`type SockaddrDatalink struct { ... }`:** This defines a structure, probably representing a NetBSD-specific socket address type.
* **`func sysctlNodes(...)`, `func nametomib(...)`:** These functions seem to implement logic related to the `sysctl` system call, allowing querying and manipulating kernel parameters.
* **`func direntIno(...)`, `func direntReclen(...)`, `func direntNamlen(...)`:** These functions are helpers for extracting information from directory entry structures (`Dirent`).
* **`func Pipe(...)`, `func Pipe2(...)`:** These functions are for creating pipes, with `Pipe2` offering more control via flags.
* **`func Accept4(...)`, `func paccept(...)`:** These functions handle accepting network connections, with `paccept` being the lower-level system call.
* **`func Getdirentries(...)`, `func getdents(...)`:** These functions are for reading directory entries.
* **`func sendfile(...)`:** This function is marked as `ENOSYS`, indicating it's not yet implemented on NetBSD.
* **A large block of `//sys` comments:** This is a crucial part. The `//sys` directive is a marker for the `mksyscall` tool. Each line defines a Go function that directly maps to a corresponding NetBSD system call.

**3. Inferring Functionality:**

Based on the identified components, I started inferring the functionalities:

* **Core System Call Interface:** The `Syscall`, `RawSyscall` family of functions provides the raw interface for invoking system calls.
* **File and Directory Operations:**  Functions like `Open`, `Read`, `Write`, `Close`, `Mkdir`, `Rmdir`, `Link`, `Unlink`, `Rename`, `Stat`, `Lstat`, `Fstat`, `Getdirentries` are all standard file and directory operations.
* **Process Management:** Functions like `Getpid`, `Getppid`, `Kill`, `Fork` (though not explicitly present but implied by `syscall` usage), `Exec` (similarly implied), `Wait` (also implied), `Getpriority`, `Setpriority`, `Getpgid`, `Setpgid`, `Getsid`, `Setsid`.
* **Networking:** Functions like `Socket`, `Bind`, `Listen`, `Accept`, `Connect`, `Sendto`, `Recvfrom`, `Getsockopt`, `Setsockopt` (while not all directly in this snippet, the presence of `SockaddrDatalink` and `Accept4` strongly suggests networking support).
* **Memory Management:** `Mmap`, `Munmap`.
* **Time and Scheduling:** `Gettimeofday`, `Settimeofday`, `Nanosleep`, `Adjtime`.
* **Security and Permissions:** `Access`, `Chmod`, `Chown`, `Chflags`, `Fchmod`, `Fchown`, `Setuid`, `Setgid`, `Setreuid`, `Setregid`, `Umask`.
* **Pipes:** `Pipe`, `Pipe2`.
* **Sysctl:** The `sysctlNodes` and `nametomib` functions clearly implement interaction with the NetBSD `sysctl` mechanism.

**4. Connecting to Go Language Features:**

I then linked the identified functionalities to common Go language usage patterns:

* **File I/O:** The file and directory operations map directly to functions in the `os` package (e.g., `os.Open`, `os.ReadFile`, `os.Mkdir`).
* **Process Management:**  The process-related system calls are used by the `os/exec` and `syscall` packages for creating and managing processes.
* **Networking:** The networking functions form the basis for the `net` package's socket programming capabilities.
* **Memory Mapping:** `Mmap` is used in scenarios requiring direct memory access to files or devices.
* **Time Operations:** The time-related system calls are used by the `time` package.
* **Sysctl:**  While not as commonly directly exposed in high-level Go code, it's useful for system introspection and configuration.

**5. Generating Examples (Mental Simulation and Refinement):**

For each key functionality, I mentally constructed simple Go code examples. For instance, for `Open` and `Read`:

```go
// Hypothetical usage based on the syscall.Open and syscall.Read
fd, err := syscall.Open("/tmp/test.txt", syscall.O_RDONLY, 0)
if err != nil { /* handle error */ }
defer syscall.Close(fd)
buffer := make([]byte, 100)
n, err := syscall.Read(fd, buffer)
if err != nil { /* handle error */ }
println(string(buffer[:n]))
```

I did similar mental exercises for other functions, considering the necessary arguments, return values, and potential error scenarios.

**6. Identifying Potential Pitfalls:**

Considering how these system calls are used, I thought about common mistakes:

* **Incorrect Error Handling:**  Forgetting to check the `err` return value.
* **File Descriptor Management:** Not closing file descriptors after use (leading to resource leaks).
* **Permissions Issues:**  Trying to perform operations without the necessary privileges.
* **Incorrect Argument Types/Values:** Passing invalid flags or arguments to system calls.
* **Buffer Overflows (Less likely in Go due to its safety features, but possible when dealing with byte slices and underlying C structures).**

**7. Structuring the Answer:**

Finally, I organized my findings into a clear and structured answer, following the prompt's requirements:

* **List of Functionalities:** Grouping related system calls into logical categories.
* **Go Language Feature Implementation:**  Connecting the system calls to higher-level Go packages and providing illustrative examples.
* **Code Reasoning (with Hypotheses):**  Explaining the purpose of functions like `sysctlNodes` and `nametomib` and providing hypothetical usage with assumed inputs and outputs.
* **Command-Line Arguments:** Noting that the code itself doesn't directly handle command-line arguments but that the underlying system calls might be used by programs that do.
* **Common Mistakes:** Providing concrete examples of potential errors.

This systematic approach, moving from the general context to specific details, inferring functionality, connecting to higher-level concepts, and considering practical usage, allowed me to generate a comprehensive and accurate answer to the prompt.
这段代码是 Go 语言 `syscall` 包中针对 NetBSD 操作系统实现的一部分。它的主要功能是提供对 NetBSD 系统调用的底层访问接口。更具体地说，它做了以下几件事：

**1. 定义和声明系统调用函数:**

*   代码中定义了 `Syscall`, `Syscall6`, `Syscall9`, `RawSyscall`, `RawSyscall6` 这些函数。这些是 Go 语言中调用操作系统底层系统调用的核心函数。
    *   `Syscall` 系列函数用于执行系统调用，并处理返回值和错误。它们接收系统调用号（`trap` 或 `num`）以及系统调用所需的参数 (`a1`, `a2`, `a3` 等)。
    *   `RawSyscall` 系列函数类似于 `Syscall`，但可能提供更底层的访问，绕过某些 Go 语言的封装和处理。

**2. 定义 NetBSD 特定的常量:**

*   `_SYS_DUP3 = SYS_DUP3` 和 `_F_DUP2FD_CLOEXEC = 0` 定义了一些与 NetBSD 系统调用相关的常量。例如，`_SYS_DUP3` 可能代表 `dup3` 系统调用的编号。

**3. 定义 NetBSD 特定的数据结构:**

*   `SockaddrDatalink` 结构体定义了 NetBSD 中数据链路层套接字地址的格式。这在网络编程中用于处理与物理网络接口相关的地址信息。

**4. 实现辅助函数，封装系统调用:**

*   **`sysctlNodes(mib []_C_int) (nodes []Sysctlnode, err error)`:**  这个函数封装了 `sysctl` 系统调用，用于获取指定 MIB（Management Information Base）下的所有子节点的列表。它首先查询所需缓冲区的大小，然后分配缓冲区并获取实际的节点信息。
*   **`nametomib(name string) (mib []_C_int, err error)`:** 这个函数将 `sysctl` 的名字（例如 "kern.hostname"）转换为对应的 MIB 数组。它通过调用 `sysctlNodes` 递归地查找每个组件，构建出完整的 MIB。
*   **`direntIno(buf []byte) (uint64, bool)`， `direntReclen(buf []byte) (uint64, bool)`， `direntNamlen(buf []byte) (uint64, bool)`:** 这些函数用于从表示目录项 (`Dirent`) 的字节数组中提取 inode 号、记录长度和名称长度。
*   **`Pipe(p []int) (err error)` 和 `Pipe2(p []int, flags int) error`:**  这两个函数用于创建管道，`Pipe2` 允许指定额外的标志。它们最终会调用底层的 `pipe2` 系统调用。
*   **`Accept4(fd int, flags int) (nfd int, sa Sockaddr, err error)` 和 `paccept(...)`:** 这两个函数用于接受新的网络连接。`Accept4` 是一个更高级的封装，它调用底层的 `paccept` 系统调用，并将返回的原始套接字地址转换为 Go 的 `Sockaddr` 类型。
*   **`Getdirentries(fd int, buf []byte, basep *uintptr) (n int, err error)` 和 `getdents(...)`:** 这两个函数用于读取目录项。`Getdirentries` 是 Go 语言中使用的函数名，它调用底层的 `getdents` 系统调用。

**5. 直接暴露的系统调用封装:**

*   代码中通过 `//sys` 注释声明了大量的系统调用封装函数，例如 `Access`, `Chdir`, `Open`, `Read`, `Write` 等等。`mksyscall` 工具会解析这些注释，并生成相应的 Go 代码，将这些 Go 函数与底层的 NetBSD 系统调用关联起来。`//sysnb` 表示这是一个不会阻塞的系统调用 (non-blocking)。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言中 **系统调用 (syscall)** 功能在 NetBSD 操作系统上的具体实现。Go 语言的 `syscall` 包提供了一种与操作系统内核进行交互的底层方式。它允许 Go 程序直接调用操作系统提供的功能，例如文件操作、进程管理、网络通信等。

**Go 代码示例：**

以下是一些基于这段代码功能的 Go 代码示例：

**示例 1：使用 `sysctl` 获取主机名**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	mib, err := syscall.Sysctl("kern.hostname")
	if err != nil {
		fmt.Println("Error getting hostname:", err)
		return
	}
	fmt.Println("Hostname:", mib) // 输出的是字节切片

	// 将字节切片转换为字符串（假设主机名是 UTF-8 编码）
	mibStr := (*[1 << 20]byte)(unsafe.Pointer(&mib[0]))[:len(mib)-1] // 移除末尾的 null 字节
	fmt.Println("Hostname (string):", string(mibStr))
}
```

**假设输入与输出：**

假设 NetBSD 系统的 hostname 是 "my-netbsd-host"。

*   **nametomib("kern.hostname") 的假设输入:**  字符串 "kern.hostname"
*   **nametomib("kern.hostname") 的假设输出:**  一个 `[]_C_int` 切片，例如 `[1, 2]`, 其中 `1` 和 `2` 是 `kern` 和 `hostname` 在 MIB 树中的编号。
*   **sysctl 获取 "kern.hostname" 的假设输出 (mib):**  一个字节切片，例如 `[109, 121, 45, 110, 101, 116, 98, 115, 100, 45, 104, 111, 115, 116, 0]` (代表 "my-netbsd-host" 加上一个 null 终止符)。

**示例 2：使用 `Pipe` 创建管道并进行读写**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	p := make([]int, 2)
	err := syscall.Pipe(p)
	if err != nil {
		fmt.Println("Error creating pipe:", err)
		return
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])

	message := "Hello from pipe!"
	buf := unsafe.Slice(unsafe.StringData(message), len(message))
	n, err := syscall.Write(p[1], buf)
	if err != nil {
		fmt.Println("Error writing to pipe:", err)
		return
	}
	fmt.Println("Bytes written:", n)

	readBuf := make([]byte, 100)
	rn, err := syscall.Read(p[0], readBuf)
	if err != nil {
		fmt.Println("Error reading from pipe:", err)
		return
	}
	fmt.Println("Bytes read:", rn)
	fmt.Println("Message read:", string(readBuf[:rn]))
}
```

**假设输入与输出：**

*   **syscall.Pipe(p):** 假设成功创建管道，`p` 会被填充两个文件描述符，例如 `p = [3, 4]`, 其中 `3` 是读端，`4` 是写端。
*   **syscall.Write(p[1], ...):** 假设成功写入，返回写入的字节数，例如 `n = 16` (长度为 "Hello from pipe!").
*   **syscall.Read(p[0], ...):** 假设成功读取，返回读取的字节数，例如 `rn = 16`，并且 `readBuf` 的前 16 个字节会包含 "Hello from pipe!".

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，使用 `os.Args` 切片来获取。但是，这段代码提供的系统调用接口可以被用来实现与命令行参数相关的操作，例如：

*   **`Open`:**  打开命令行参数指定的文件。
*   **`Stat` 或 `Lstat`:** 获取命令行参数指定的文件或目录的信息。
*   **`Mkdir` 或 `Rmdir`:**  创建或删除命令行参数指定的目录。

**使用者易犯错的点：**

1. **错误处理不足:**  直接调用系统调用容易出错，必须仔细检查 `err` 返回值。忘记处理错误会导致程序崩溃或行为异常。

    ```go
    fd, err := syscall.Open("/nonexistent_file", syscall.O_RDONLY, 0)
    // 如果不检查 err，后续使用 fd 会导致错误。
    if err != nil {
        fmt.Println("Error opening file:", err)
        return
    }
    defer syscall.Close(fd)
    ```

2. **文件描述符管理不当:**  打开的文件描述符需要在使用后显式关闭，否则会导致资源泄漏。

    ```go
    fd, _ := syscall.Open("/tmp/test.txt", syscall.O_RDONLY, 0)
    // ... 使用 fd ...
    // 忘记 syscall.Close(fd)
    ```

3. **不正确的参数传递:**  系统调用对参数类型和值有严格的要求。传递错误的参数类型或值会导致系统调用失败。例如，权限不足时尝试创建文件。

    ```go
    // 尝试在没有权限的目录下创建文件
    fd, err := syscall.Open("/root/new_file.txt", syscall.O_CREAT|syscall.O_WRONLY, 0644)
    if err != nil {
        fmt.Println("Error creating file:", err) // 可能会收到 EACCES (Permission denied) 错误
    }
    ```

4. **对 `unsafe` 包的滥用:**  涉及到 `unsafe` 包的操作需要格外小心，因为它们绕过了 Go 语言的类型安全检查，容易导致内存错误。例如，在 `sysctl` 示例中，将字节切片转换为字符串时需要谨慎处理切片的长度和内存安全。

这段代码是 Go 语言与 NetBSD 操作系统交互的基石，为更高级别的 Go 标准库和第三方库提供了底层的能力。理解这段代码的功能有助于深入理解 Go 语言的运行机制以及操作系统的工作原理。

Prompt: 
```
这是路径为go/src/syscall/syscall_netbsd.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009,2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// NetBSD system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and wrap
// it in our own nicer implementation, either here or in
// syscall_bsd.go or syscall_unix.go.

package syscall

import "unsafe"

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func Syscall9(num, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)

const (
	_SYS_DUP3         = SYS_DUP3
	_F_DUP2FD_CLOEXEC = 0
)

type SockaddrDatalink struct {
	Len    uint8
	Family uint8
	Index  uint16
	Type   uint8
	Nlen   uint8
	Alen   uint8
	Slen   uint8
	Data   [12]int8
	raw    RawSockaddrDatalink
}

func sysctlNodes(mib []_C_int) (nodes []Sysctlnode, err error) {
	var olen uintptr

	// Get a list of all sysctl nodes below the given MIB by performing
	// a sysctl for the given MIB with CTL_QUERY appended.
	mib = append(mib, CTL_QUERY)
	qnode := Sysctlnode{Flags: SYSCTL_VERS_1}
	qp := (*byte)(unsafe.Pointer(&qnode))
	sz := unsafe.Sizeof(qnode)
	if err = sysctl(mib, nil, &olen, qp, sz); err != nil {
		return nil, err
	}

	// Now that we know the size, get the actual nodes.
	nodes = make([]Sysctlnode, olen/sz)
	np := (*byte)(unsafe.Pointer(&nodes[0]))
	if err = sysctl(mib, np, &olen, qp, sz); err != nil {
		return nil, err
	}

	return nodes, nil
}

func nametomib(name string) (mib []_C_int, err error) {
	// Split name into components.
	var parts []string
	last := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			parts = append(parts, name[last:i])
			last = i + 1
		}
	}
	parts = append(parts, name[last:])

	// Discover the nodes and construct the MIB OID.
	for partno, part := range parts {
		nodes, err := sysctlNodes(mib)
		if err != nil {
			return nil, err
		}
		for _, node := range nodes {
			n := make([]byte, 0)
			for i := range node.Name {
				if node.Name[i] != 0 {
					n = append(n, byte(node.Name[i]))
				}
			}
			if string(n) == part {
				mib = append(mib, _C_int(node.Num))
				break
			}
		}
		if len(mib) != partno+1 {
			return nil, EINVAL
		}
	}

	return mib, nil
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

//sys paccept(fd int, rsa *RawSockaddrAny, addrlen *_Socklen, sigmask *sigset, flags int) (nfd int, err error)

func Accept4(fd, flags int) (nfd int, sa Sockaddr, err error) {
	var rsa RawSockaddrAny
	var len _Socklen = SizeofSockaddrAny
	nfd, err = paccept(fd, &rsa, &len, nil, flags)
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

//sys getdents(fd int, buf []byte) (n int, err error)

func Getdirentries(fd int, buf []byte, basep *uintptr) (n int, err error) {
	return getdents(fd, buf)
}

// TODO, see golang.org/issue/5847
func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	return -1, ENOSYS
}

/*
 * Exposed directly
 */
//sys	Access(path string, mode uint32) (err error)
//sys	Adjtime(delta *Timeval, olddelta *Timeval) (err error)
//sys	Chdir(path string) (err error)
//sys	Chflags(path string, flags int) (err error)
//sys	Chmod(path string, mode uint32) (err error)
//sys	Chown(path string, uid int, gid int) (err error)
//sys	Chroot(path string) (err error)
//sys	Close(fd int) (err error)
//sys	Dup(fd int) (nfd int, err error)
//sys	Dup2(from int, to int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchflags(fd int, flags int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fpathconf(fd int, name int) (val int, err error)
//sys	Fstat(fd int, stat *Stat_t) (err error)
//sys	Fsync(fd int) (err error)
//sys	Ftruncate(fd int, length int64) (err error)
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
//sys	Kill(pid int, signum Signal) (err error)
//sys	Kqueue() (fd int, err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Listen(s int, backlog int) (err error)
//sys	Lstat(path string, stat *Stat_t) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	Mknod(path string, mode uint32, dev int) (err error)
//sys	Nanosleep(time *Timespec, leftover *Timespec) (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error)
//sys	Pathconf(path string, name int) (val int, err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error)
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	Readlink(path string, buf []byte) (n int, err error)
//sys	Rename(from string, to string) (err error)
//sys	Revoke(path string) (err error)
//sys	Rmdir(path string) (err error)
//sys	Seek(fd int, offset int64, whence int) (newoffset int64, err error) = SYS_LSEEK
//sys	Select(n int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (err error)
//sysnb	Setegid(egid int) (err error)
//sysnb	Seteuid(euid int) (err error)
//sysnb	Setgid(gid int) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	setrlimit(which int, lim *Rlimit) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tp *Timeval) (err error)
//sysnb	Setuid(uid int) (err error)
//sys	Stat(path string, stat *Stat_t) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Sync() (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Umask(newmask int) (oldmask int)
//sys	Unlink(path string) (err error)
//sys	Unmount(path string, flags int) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys	mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys	munmap(addr uintptr, length uintptr) (err error)
//sys	readlen(fd int, buf *byte, nbuf int) (n int, err error) = SYS_READ
//sys	utimensat(dirfd int, path string, times *[2]Timespec, flag int) (err error)
//sys	getcwd(buf []byte) (n int, err error) = SYS___GETCWD
//sys	sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) = SYS___SYSCTL

"""



```