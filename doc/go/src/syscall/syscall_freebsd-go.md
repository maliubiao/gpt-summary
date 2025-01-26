Response:
Let's break down the thought process for analyzing this Go file and generating the comprehensive answer.

1. **Understand the Goal:** The core request is to analyze a Go source file (`syscall_freebsd.go`) and explain its purpose, provide examples, identify potential pitfalls, and detail command-line interactions (if any). The output should be in Chinese.

2. **Initial Scan and Keyword Recognition:**  Quickly read through the file, looking for key terms and patterns.
    * `// Copyright`: Standard copyright notice, not functionally relevant to the core request but good to acknowledge.
    * `// FreeBSD system calls`: This is the most crucial piece of information. It immediately tells us the file is about interacting with the FreeBSD operating system kernel.
    * `//sys`:  This prefix on many lines is a very strong indicator of how system calls are defined in Go's `syscall` package. It triggers the `mksyscall` tool.
    * `package syscall`:  Confirms this is part of the standard `syscall` package.
    * `import "unsafe"`: Signals direct memory manipulation and interaction with C-like data structures.
    * Function names like `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6`: These are the low-level primitives for making system calls.
    * Data structures like `SockaddrDatalink`, `IPMreqn`, `Statfs_t`, `Stat_t`, `Dirent`, `Timeval`, `Timespec`, `Rlimit`, `Rusage`, `FdSet`, `RawSockaddrAny`: These represent data structures used in system calls.
    * Function names like `Pipe`, `Pipe2`, `GetsockoptIPMreqn`, `SetsockoptIPMreqn`, `Accept4`, `Getfsstat`, `Stat`, `Lstat`, `Getdirentries`, `Mknod`, `nametomib`: These are higher-level Go functions that likely wrap the lower-level system calls.

3. **Categorize Functionality:**  Based on the keywords and function names, start grouping functionalities:
    * **Low-level System Call Interface:**  `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6`. These are the foundation.
    * **Networking:** `SockaddrDatalink`, `GetsockoptIPMreqn`, `SetsockoptIPMreqn`, `Accept4`. These deal with socket-related operations.
    * **File System Operations:** `Stat`, `Lstat`, `Fstat`, `Fstatat`, `Getdirentries`, `Mknod`, `Mkdir`, `Mkfifo`, `Open`, `Readlink`, `Rename`, `Rmdir`, `Unlink`, `Truncate`, `Undelete`, `Mmap`, `Munmap`.
    * **Process Management:** `Getpid`, `Getppid`, `Kill`, `Getpriority`, `Setpriority`, `Getpgid`, `Setpgid`, `Getsid`, `Setsid`.
    * **Time and Date:** `Adjtime`, `Gettimeofday`, `Settimeofday`, `Nanosleep`, `Utimensat`.
    * **User and Group IDs:** `Getuid`, `Getgid`, `Geteuid`, `Getegid`, `Setuid`, `Setgid`, `Seteuid`, `Setegid`, `Setregid`, `Setreuid`.
    * **Resource Limits:** `Getrlimit`, `Setrlimit`.
    * **Pipes:** `Pipe`, `Pipe2`.
    * **System Information:** `Getdtablesize`, `Issetugid`, `Statfs`, `Getfsstat`, `Pathconf`, `Fpathconf`, `Sysctl`, `Getcwd`.
    * **File Descriptors:** `Close`, `Dup`, `Dup2`, `Fsync`.
    * **Directory Changes:** `Chdir`, `Fchdir`, `Chroot`.
    * **Permissions and Ownership:** `Chmod`, `Fchmod`, `Chown`, `Fchown`, `Lchown`, `Umask`.
    * **File Locking:** `Flock`.
    * **Symbolic Links:** `Symlink`.
    * **Mounting:** `Mount`, `Unmount`. (Note: `Mount` is not present in the provided snippet, but it's a common system call and related to `Unmount`).
    * **Miscellaneous:** `Access`, `Chflags`, `Fchflags`, `Revoke`, `Select`, `Setlogin`, `Sync`.

4. **Explain Core Functionality:** Describe the purpose of the file as providing Go interfaces to FreeBSD system calls. Emphasize the role of `//sys` and `mksyscall`.

5. **Provide Examples:** Choose a few representative functions and demonstrate their usage with Go code. Include:
    * A simple file system operation (e.g., `Stat`).
    * A networking operation (e.g., `Getaddrinfo` – although not directly in this snippet, it's a common networking function and demonstrates the concept of using system calls). If no direct networking function is easily demonstratable from the snippet alone, consider demonstrating `Pipe`.
    * A process management operation (e.g., `Getpid`).
    * **Crucially, include assumptions about input and expected output.** This makes the examples concrete.

6. **Address Command-Line Arguments:** Carefully review the listed functions. Most of these are direct system call wrappers and don't involve explicit command-line arguments within the *Go code itself*. However, the *programs* that use these syscalls are often invoked with command-line arguments. Explain this distinction. If there's a function that *does* process command-line arguments (like a theoretical wrapper around `execve`), explain that specifically.

7. **Identify Common Mistakes:** Think about potential errors developers might make when using system calls:
    * Incorrect error handling (not checking the `err` return value).
    * Incorrectly sizing buffers for system calls that return data.
    * Misunderstanding the meaning of return values (e.g., file descriptors).
    * Security vulnerabilities (e.g., path injection).

8. **Structure the Answer:** Organize the information logically with clear headings and bullet points. Use code blocks for examples.

9. **Refine and Translate:** Ensure the language is clear, concise, and accurate. Translate the entire answer into Chinese. Pay attention to technical terms and ensure they are translated correctly.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the `//sys` lines.
* **Correction:** Realize that the helper functions (`nametomib`, `direntIno`, `Pipe`, etc.) are also important functionalities provided by this file and should be explained.
* **Initial thought:** Assume command-line arguments are directly processed within this file.
* **Correction:** Recognize that this file provides *system call interfaces*. The command-line argument processing happens in the *applications* that use these interfaces. Clarify this distinction.
* **Initial thought:**  Provide very basic examples.
* **Correction:** Enhance the examples by including assumed inputs and expected outputs to make them more illustrative.
* **Initial thought:** Briefly mention error handling.
* **Correction:**  Elaborate on common error handling mistakes as this is a crucial aspect of using system calls correctly.

By following these steps, including the iterative refinement, we can arrive at a comprehensive and accurate answer that addresses all aspects of the user's request.
好的，让我们来分析一下 `go/src/syscall/syscall_freebsd.go` 文件的功能。

**功能概述**

这个文件是 Go 语言标准库 `syscall` 包中针对 FreeBSD 操作系统的实现部分。它的核心功能是为 Go 语言程序提供访问 FreeBSD 系统调用的接口。

**具体功能分解**

1. **系统调用原始接口:**
   - `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6`: 这四个函数是 Go 程序直接发起系统调用的底层入口。它们允许 Go 程序执行 FreeBSD 内核提供的各种操作。
   - `trap`:  系统调用号，用于标识要执行的具体系统调用。
   - `a1`, `a2`, `a3`, `a4`, `a5`, `a6`:  系统调用的参数。
   - 返回值 `r1`, `r2`: 系统调用返回的结果。
   - 返回值 `err Errno`:  如果系统调用失败，则返回错误码。

2. **数据结构定义:**
   - `SockaddrDatalink`:  定义了数据链路层套接字地址结构，用于网络编程。
   - 其他数据结构（如 `IPMreqn`, `Statfs_t`, `Stat_t`, `Dirent`, `Timeval` 等）：定义了与各种系统调用相关的内核数据结构，方便 Go 程序与内核进行数据交互。

3. **辅助函数:**
   - `nametomib(name string) (mib []_C_int, err error)`:  将字符串形式的系统控制变量名（例如 "kern.hostname"）转换为内核可以理解的 Management Information Base (MIB) 数组。这个函数内部调用了 `sysctl` 系统调用。
   - `direntIno(buf []byte) (uint64, bool)`, `direntReclen(buf []byte) (uint64, bool)`, `direntNamlen(buf []byte) (uint64, bool)`: 这些函数用于解析从 `getdirentries` 系统调用返回的目录项信息。它们从字节切片中读取 inode 号、记录长度和文件名长度。
   - `Pipe(p []int) error`: 创建一个管道，返回两个文件描述符，分别用于读和写。它是 `Pipe2` 的简化版本。
   - `Pipe2(p []int, flags int) error`: 创建一个管道，可以指定额外的标志位（例如 `O_NONBLOCK`）。
   - `GetsockoptIPMreqn`, `SetsockoptIPMreqn`:  用于获取和设置 IP 组播成员关系选项。
   - `Accept4`:  接受一个新的连接，并可以设置一些标志位，例如 `SOCK_NONBLOCK` 和 `SOCK_CLOEXEC`。
   - `Getfsstat`: 获取文件系统状态信息。
   - `Stat`, `Lstat`:  获取文件或目录的状态信息。`Lstat` 不会跟随符号链接。
   - `Getdirentries`: 读取目录项。
   - `Mknod`: 创建一个特殊的文件节点（设备文件、命名管道等）。

4. **系统调用包装函数 (以 `//sys` 开头的函数):**
   - 这些函数是 Go 语言通过 `mksyscall` 工具自动生成的系统调用包装器。`mksyscall` 工具会解析 `//sys` 行，生成调用底层 `Syscall` 或 `Syscall6` 的代码，并处理参数的转换和错误处理。
   - 例子：`//sys	Access(path string, mode uint32) (err error)`  会生成一个名为 `Access` 的 Go 函数，该函数接受路径和模式作为参数，并调用底层的 `access` 系统调用。
   - 这些包装函数提供了更符合 Go 语言习惯的接口，例如，错误信息会转换为 `error` 类型。

**Go 语言功能实现推理与代码示例**

这个文件是 `syscall` 包针对 FreeBSD 的底层实现，它本身不直接实现特定的高级 Go 语言功能。相反，它是许多更高级功能的基石。例如：

**示例：文件操作 (基于 `Stat` 系统调用)**

假设我们要获取一个文件的信息（例如，大小和修改时间）。`syscall_freebsd.go` 中的 `Stat` 函数为我们提供了这个能力。

```go
package main

import (
	"fmt"
	"syscall"
	"time"
)

func main() {
	filename := "my_file.txt" // 假设存在名为 my_file.txt 的文件

	var stat syscall.Stat_t
	err := syscall.Stat(filename, &stat)
	if err != nil {
		fmt.Println("Error getting file stats:", err)
		return
	}

	fmt.Println("File size:", stat.Size)
	fmt.Println("Modification time:", time.Unix(stat.Mtimespec.Sec, stat.Mtimespec.Nsec))
}
```

**假设的输入与输出:**

假设 `my_file.txt` 存在，大小为 1024 字节，最后修改时间是 2023年10月27日 10:00:00。

**可能的输出:**

```
File size: 1024
Modification time: 2023-10-27 10:00:00 +0800 CST
```

在这个例子中，`syscall.Stat` 函数实际上调用了 FreeBSD 的 `stat` 系统调用，而 `syscall_freebsd.go` 文件中的 `Stat` 函数就是这个调用的 Go 语言接口。

**示例：创建管道 (基于 `Pipe` 系统调用)**

假设我们需要在两个并发的 Go 例程之间进行通信，可以使用管道。

```go
package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func main() {
	fds := make([]int, 2)
	err := syscall.Pipe(fds)
	if err != nil {
		fmt.Println("Error creating pipe:", err)
		return
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])

	reader := os.NewFile(uintptr(fds[0]), "pipe reader")
	writer := os.NewFile(uintptr(fds[1]), "pipe writer")

	message := "Hello from the writer!"
	go func() {
		_, err := writer.WriteString(message + "\n")
		if err != nil {
			fmt.Println("Writer error:", err)
		}
		writer.Close()
	}()

	buf := make([]byte, 100)
	n, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		fmt.Println("Reader error:", err)
		return
	}
	fmt.Printf("Received: %s", buf[:n])
}
```

**可能的输出:**

```
Received: Hello from the writer!
```

在这个例子中，`syscall.Pipe(fds)` 调用了 `syscall_freebsd.go` 中实现的 `Pipe` 函数，该函数最终会调用 FreeBSD 的 `pipe` 系统调用。

**命令行参数处理**

`syscall_freebsd.go` 文件本身不直接处理命令行参数。它提供的函数是更底层的系统调用接口。命令行参数的处理通常发生在更上层的应用程序代码中，应用程序可能会使用 `os` 包中的功能来解析命令行参数，并基于这些参数调用 `syscall` 包提供的函数。

例如，一个程序可能会使用 `os.Args` 获取命令行参数，然后根据参数指定的路径调用 `syscall.Stat` 来获取文件信息。

**使用者易犯错的点**

1. **错误处理不当:** 系统调用可能会失败，返回错误码。使用者必须检查 `err` 返回值并进行适当的处理。忽略错误可能导致程序行为不可预测。

   ```go
   fd, err := syscall.Open("non_existent_file.txt", syscall.O_RDONLY, 0)
   if err != nil {
       // 正确处理错误
       fmt.Println("Error opening file:", err)
   } else {
       syscall.Close(fd)
   }
   ```

2. **不正确的参数传递:** 系统调用期望特定类型和大小的参数。如果传递了错误的参数，可能导致程序崩溃或产生意外行为。例如，传递了不正确的标志位，或者缓冲区大小不足。

3. **资源泄漏:**  例如，打开文件后没有及时关闭 (`syscall.Close`)，可能导致文件描述符耗尽。

4. **数据结构理解不足:**  与系统调用交互时，需要理解内核数据结构的布局和含义。例如，解析 `getdirentries` 返回的目录项信息时，需要正确读取各个字段。

5. **平台差异:**  系统调用在不同操作系统上的行为可能存在差异。直接使用 `syscall` 包的程序可能不具备跨平台性。建议尽可能使用更高级的、平台无关的 Go 标准库功能。

总而言之，`go/src/syscall/syscall_freebsd.go` 是 Go 语言与 FreeBSD 操作系统内核交互的桥梁，它提供了访问底层系统调用的能力，是构建更高级系统编程功能的基础。使用者需要理解系统调用的工作原理，并谨慎处理错误和参数，以确保程序的正确性和健壮性。

Prompt: 
```
这是路径为go/src/syscall/syscall_freebsd.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

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

package syscall

import "unsafe"

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)

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

func GetsockoptIPMreqn(fd, level, opt int) (*IPMreqn, error) {
	var value IPMreqn
	vallen := _Socklen(SizeofIPMreqn)
	errno := getsockopt(fd, level, opt, unsafe.Pointer(&value), &vallen)
	return &value, errno
}

func SetsockoptIPMreqn(fd, level, opt int, mreq *IPMreqn) (err error) {
	return setsockopt(fd, level, opt, unsafe.Pointer(mreq), unsafe.Sizeof(*mreq))
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
	sa, err = anyToSockaddr(&rsa)
	if err != nil {
		Close(nfd)
		nfd = 0
	}
	return
}

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

func Stat(path string, st *Stat_t) (err error) {
	return Fstatat(_AT_FDCWD, path, st, 0)
}

func Lstat(path string, st *Stat_t) (err error) {
	return Fstatat(_AT_FDCWD, path, st, _AT_SYMLINK_NOFOLLOW)
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
	return mknodat(_AT_FDCWD, path, mode, dev)
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
//sys	Kill(pid int, signum Signal) (err error)
//sys	Kqueue() (fd int, err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Listen(s int, backlog int) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	mknodat(fd int, path string, mode uint32, dev uint64) (err error)
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
//sys	Setlogin(name string) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	setrlimit(which int, lim *Rlimit) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tp *Timeval) (err error)
//sysnb	Setuid(uid int) (err error)
//sys	Statfs(path string, stat *Statfs_t) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Sync() (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Umask(newmask int) (oldmask int)
//sys	Undelete(path string) (err error)
//sys	Unlink(path string) (err error)
//sys	Unmount(path string, flags int) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys   mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys   munmap(addr uintptr, length uintptr) (err error)
//sys	readlen(fd int, buf *byte, nbuf int) (n int, err error) = SYS_READ
//sys	accept4(fd int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (nfd int, err error)
//sys	utimensat(dirfd int, path string, times *[2]Timespec, flag int) (err error)
//sys	getcwd(buf []byte) (n int, err error) = SYS___GETCWD
//sys	sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) = SYS___SYSCTL

"""



```