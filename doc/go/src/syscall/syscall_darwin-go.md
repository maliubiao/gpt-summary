Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first line `// go/src/syscall/syscall_darwin.go` immediately tells us this file is part of the Go standard library, specifically dealing with system calls on Darwin-based operating systems (macOS, iOS, etc.). The comments at the beginning reinforce this, mentioning "Darwin system calls" and its role in generating system call stubs.

2. **Identify Key Components:** Scan the code for major elements:
    * **Import statements:**  `internal/abi` and `unsafe`. This indicates interaction with low-level ABI details and potentially direct memory manipulation.
    * **`Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6`:** These are fundamental functions for making system calls. The `6` likely signifies variants taking more arguments. The "Raw" prefix suggests less processing or wrapping.
    * **Data Structures:** `SockaddrDatalink` stands out as a structure related to network interfaces.
    * **Functions:**  A large number of functions, many with lowercase names that look like system calls (e.g., `pipe`, `kill`, `access`). The `//sys` comments are a crucial clue about how these are generated. Functions like `nametomib`, `direntIno`, `PtraceAttach`, `Pipe`, `Getfsstat`, `Kill` seem to be higher-level wrappers or utilities.
    * **`init()` function:**  This indicates initialization logic.
    * **Trampolines and `go:cgo_import_dynamic`:**  This signals the use of C code or libraries. The trampolines likely act as bridges.
    * **`go:linkname`:**  This is a compiler directive for linking to symbols in other packages.

3. **Analyze Functionality by Category:**  Group the identified components by their likely purpose:

    * **Core System Call Invocation:**  The `Syscall` and `RawSyscall` functions are the foundation. They take a `trap` (system call number) and arguments. The return values `r1`, `r2`, and `err` are standard for Go system calls.

    * **Data Structure Handling:** `SockaddrDatalink` is a specific data structure for network addresses. The `nametomib` function seems to convert a string like "kern.hostname" into a Management Information Base (MIB) array, which is used with system calls like `sysctl`.

    * **Directory and File Operations:**  Functions like `pipe`, `Getfsstat`, `Access`, `Chdir`, `Open`, `Read`, `Write`, `Mkdir`, `Rmdir`, `Rename`, `Link`, `Unlink`, `Truncate`, `Umask`, `Readlink`, `Getdirentries`, `fdopendir`, `readdir_r`, `closedir` clearly relate to file system interactions. The `Dirent` related functions suggest parsing directory entries.

    * **Process Management:** `Kill`, `Fork`, `Execve`, `Exit`, `Getpid`, `Getppid`, `Getpgid`, `Setpgid`, `Getsid`, `Setsid`, `PtraceAttach`, `PtraceDetach` are all standard process management system calls or wrappers.

    * **Memory Management:** `Mlock`, `Mlockall`, `Mprotect`, `Msync`, `Munlock`, `Munlockall`, `Mmap`, `Munmap` deal with memory locking and mapping.

    * **Time and Resource Management:**  `Adjtime`, `Getrlimit`, `Setrlimit`, `Getrusage`, `Getpriority`, `Setpriority`, `Settimeofday` fall into this category.

    * **Networking:**  `Listen`, and the presence of `SockaddrDatalink` point to networking functionality, although this file doesn't contain the core socket system calls (likely in `syscall_bsd.go`).

    * **Security/Permissions:** `Chflags`, `Chmod`, `Chown`, `Lchown`, `Revoke`, `Setuid`, `Setgid`, `Setegid`, `Setaeuid`, `Issetugid` relate to file permissions and user/group IDs.

    * **Low-level Primitives:**  Functions like `Dup`, `Dup2`, `Close`, `Select`, `Kqueue` are fundamental operating system primitives.

4. **Focus on Specific Examples and Reasoning:**

    * **`nametomib`:** The comments clearly explain its purpose. The code uses `sysctl` with a specific MIB `[0, 3]` to perform the conversion. A concrete example with input and expected output (the MIB array) is possible.

    * **`Pipe`:**  The code shows how the `pipe` system call is wrapped to return a Go slice of `int` instead of an array of `int32`. An example demonstrating its use is straightforward.

    * **`Getdirentries`:** The comment about simulating it with `fdopendir`, `readdir_r`, and `closedir` is key. The logic involving `Seek` to track progress is an important detail for understanding its implementation.

    * **`Kill`:**  The wrapper function clarifies the purpose of the `posix` argument in the underlying system call.

5. **Identify Potential Pitfalls:**  Consider areas where developers might make mistakes:

    * **Incorrect `pipe` slice length:** The `Pipe` function explicitly checks for a length of 2.
    * **Misunderstanding `Getdirentries` behavior:** The simulation might not be perfectly transparent, especially if the directory is modified concurrently.

6. **Explain `//sys` and Code Generation:** Emphasize the role of `mksyscall` in generating the low-level system call stubs based on the `//sys` directives. Explain how this simplifies the process of interfacing with the kernel.

7. **Structure the Answer:** Organize the findings logically with clear headings and bullet points for readability. Use code examples to illustrate specific functionalities and potential errors. Ensure the language is clear and concise.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "Are all the lowercase functions direct system calls?"  **Correction:** The comments and the `Kill` example show that some are wrappers around system calls with additional logic.
* **Initial thought:** "Just list all the functions." **Refinement:** Grouping functions by their purpose makes the explanation much clearer.
* **Initial thought:** "Just describe what each function does individually." **Refinement:** Providing examples and explaining the *why* behind certain implementations (like the `Getdirentries` simulation) is more insightful.
* **Consider the target audience:** The request mentions "go语言功能的实现," suggesting a developer audience. Therefore, focusing on practical implications and potential issues is valuable.
这段代码是 Go 语言标准库中 `syscall` 包在 Darwin (macOS, iOS 等) 操作系统上的实现部分，主要负责与 Darwin 内核进行交互，执行底层的系统调用。

**主要功能列举：**

1. **系统调用入口:**  定义了 `Syscall`, `Syscall6`, `RawSyscall`, `RawSyscall6` 这几个核心函数，它们是 Go 程序发起系统调用的基本入口点。这些函数会将 Go 的调用转换为操作系统内核能够理解的指令。`RawSyscall` 系列通常用于更底层的系统调用，可能绕过 Go 运行时的一些处理。

2. **系统调用封装:**  代码中定义了大量的函数，例如 `Pipe`, `Kill`, `Access`, `Chdir`, `Open`, `Read`, `Write` 等等，这些函数是对底层系统调用的封装。它们提供了更方便、类型安全的 Go 接口来使用系统调用。

3. **数据结构定义:**  定义了与操作系统交互所需的数据结构，例如 `SockaddrDatalink` (用于数据链路层套接字地址)， `Dirent` (目录项)，`Statfs_t` (文件系统状态) 等。

4. **辅助函数:** 提供了一些辅助函数，用于处理与系统调用相关的数据转换和操作。例如：
    * `nametomib`: 将形如 "kern.hostname" 的字符串转换为 `sysctl` 系统调用所需的 MIB (Management Information Base) 数组。
    * `direntIno`, `direntReclen`, `direntNamlen`: 从目录项的字节数组中提取 inode 号、记录长度和名称长度。
    * `PtraceAttach`, `PtraceDetach`: 用于进程跟踪的 `ptrace` 系统调用的封装。
    * `Pipe`: 创建管道的封装。
    * `Getfsstat`: 获取文件系统状态信息的封装。

5. **特殊处理和兼容性:**  代码中包含一些针对 Darwin 系统的特殊处理，例如 `Getdirentries` 函数的实现方式，它使用 `fdopendir`, `readdir_r`, `closedir` 来模拟 `Getdirentries` 的行为。这可能是因为 Darwin 系统上 `Getdirentries` 的行为与其他 Unix 系统有所不同。

6. **与 C 代码的交互:**  通过 `//go:cgo_import_dynamic` 和 trampoline 函数 (如 `libc_getfsstat_trampoline`)，实现了与 C 动态链接库中函数的交互。这允许 Go 代码调用 C 标准库中的函数。

**Go 语言功能的实现示例 (基于推理):**

**1. `os.Hostname()` 的部分实现 (基于 `nametomib` 和 `sysctl`):**

假设 `os.Hostname()` 函数在 Darwin 系统上会使用 `sysctl` 系统调用来获取主机名。  `syscall_darwin.go` 中的 `nametomib` 函数很可能被 `os.Hostname()` 间接调用。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	mib, err := syscall.Nametomib("kern.hostname")
	if err != nil {
		fmt.Println("Error getting MIB:", err)
		return
	}

	buf := make([]byte, 256) // 假设主机名不会超过 256 字节
	n := uintptr(len(buf))

	_, _, err = syscall.Syscall6(
		syscall.SYS_SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n)),
		0,
		0,
	)
	if err != 0 {
		fmt.Println("Error calling sysctl:", err)
		return
	}

	hostname := string(buf[:n])
	fmt.Println("Hostname:", hostname)
}

// 假设的输入: 无 (直接调用系统调用)
// 假设的输出:  取决于系统的主机名，例如 "My-MacBook-Pro.local"
```

**解释:**

* `syscall.Nametomib("kern.hostname")` 将字符串 "kern.hostname" 转换为 `sysctl` 系统调用所需的 MIB 数组。
* `syscall.SYS_SYSCTL` 是 `sysctl` 系统调用的编号 (在实际的 `syscall_darwin.go` 或相关文件中定义)。
* `unsafe.Pointer(&mib[0])` 和 `uintptr(len(mib))`  传递 MIB 数组的地址和长度。
* `unsafe.Pointer(&buf[0])` 和 `uintptr(unsafe.Pointer(&n))`  传递用于接收主机名的缓冲区地址和长度的指针。
* 系统调用执行后，主机名会被写入 `buf` 中，`n` 会更新为实际写入的字节数。

**2. `os.Mkdir()` 的部分实现 (基于 `Mkdir`):**

`os.Mkdir()` 函数用于创建目录。在 Darwin 系统上，它很可能直接调用了 `syscall_darwin.go` 中定义的 `Mkdir` 函数。

```go
package main

import (
	"fmt"
	"syscall"
	"os"
)

func main() {
	path := "test_dir"
	mode := os.FileMode(0755) // 权限设置为 755

	err := syscall.Mkdir(path, uint32(mode))
	if err != nil {
		fmt.Println("Error creating directory:", err)
	} else {
		fmt.Println("Directory created successfully")
		os.Remove(path) // 清理
	}
}

// 假设的输入: path = "test_dir", mode = 0755
// 假设的输出:  如果创建成功，则无错误，并会在当前目录下创建名为 "test_dir" 的目录。
//            如果创建失败 (例如权限不足)，则会返回对应的错误信息。
```

**解释:**

* `syscall.Mkdir(path, uint32(mode))` 直接调用了 `syscall_darwin.go` 中定义的 `Mkdir` 系统调用封装。
* `path` 是要创建的目录路径。
* `uint32(mode)` 将 Go 的 `os.FileMode` 类型转换为 `Mkdir` 系统调用所需的 `uint32` 类型的权限掩码。

**命令行参数处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，可以使用 `os.Args` 获取命令行参数，并使用 `flag` 包进行解析。  `syscall` 包提供的功能是更底层的，它主要负责执行操作系统提供的服务。

**易犯错的点 (使用者):**

1. **错误地使用 `Syscall` 和 `RawSyscall`:**  直接使用 `Syscall` 或 `RawSyscall` 需要非常了解底层的系统调用约定和参数，容易出错。通常应该使用 Go 标准库中提供的更高级别的封装函数 (如 `os.Open`, `os.Read` 等)。

   ```go
   // 错误示例：直接使用 Syscall，可能传递错误的参数类型或数量
   // fd, _, err := syscall.Syscall(syscall.SYS_OPEN, ...) // 很可能出错
   ```

2. **不正确的错误处理:**  系统调用返回的 `err` 是 `syscall.Errno` 类型，需要进行正确的类型断言和错误码判断。

   ```go
   fd, _, err := syscall.Open("nonexistent_file", syscall.O_RDONLY, 0)
   if err != nil {
       if err == syscall.ENOENT { // 正确判断文件不存在的错误
           fmt.Println("File not found")
       } else {
           fmt.Println("Error opening file:", err)
       }
   }
   ```

3. **内存安全问题:**  在使用涉及指针和内存操作的系统调用时 (例如 `mmap`)，需要格外小心，避免内存越界或使用无效指针。

4. **忽略平台差异:**  直接使用 `syscall` 包中的函数时，需要注意不同操作系统之间的系统调用编号和行为可能存在差异。这段 `syscall_darwin.go` 就是针对 Darwin 系统的实现，在其他系统上可能需要使用不同的文件。

5. **不理解 `//sys` 指令:**  开发者可能会尝试直接修改或调用带有 `//sys` 指令的函数，但不明白这些函数实际上是由 `mksyscall` 工具生成的，直接修改可能会导致编译错误或运行时问题。

总而言之，`go/src/syscall/syscall_darwin.go` 是 Go 语言在 Darwin 系统上与操作系统内核交互的桥梁，它定义了底层的系统调用接口和相关的数据结构，为上层 Go 标准库和应用程序提供了访问操作系统功能的途径。 开发者通常不直接使用这个文件中的大部分函数，而是通过 `os`，`io`，`net` 等更高级别的包来间接使用其功能。

Prompt: 
```
这是路径为go/src/syscall/syscall_darwin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009,2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Darwin system calls.
// This file is compiled as ordinary Go code,
// but it is also input to mksyscall,
// which parses the //sys lines and generates system call stubs.
// Note that sometimes we use a lowercase //sys name and wrap
// it in our own nicer implementation, either here or in
// syscall_bsd.go or syscall_unix.go.

package syscall

import (
	"internal/abi"
	"unsafe"
)

func Syscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func Syscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall(trap, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func RawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)

var dupTrampoline = abi.FuncPCABI0(libc_dup2_trampoline)

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
	return readInt(buf, unsafe.Offsetof(Dirent{}.Ino), unsafe.Sizeof(Dirent{}.Ino))
}

func direntReclen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Reclen), unsafe.Sizeof(Dirent{}.Reclen))
}

func direntNamlen(buf []byte) (uint64, bool) {
	return readInt(buf, unsafe.Offsetof(Dirent{}.Namlen), unsafe.Sizeof(Dirent{}.Namlen))
}

func PtraceAttach(pid int) (err error) { return ptrace(PT_ATTACH, pid, 0, 0) }
func PtraceDetach(pid int) (err error) { return ptrace(PT_DETACH, pid, 0, 0) }

//sysnb pipe(p *[2]int32) (err error)

func Pipe(p []int) (err error) {
	if len(p) != 2 {
		return EINVAL
	}
	var q [2]int32
	err = pipe(&q)
	if err == nil {
		p[0] = int(q[0])
		p[1] = int(q[1])
	}
	return
}

func Getfsstat(buf []Statfs_t, flags int) (n int, err error) {
	var _p0 unsafe.Pointer
	var bufsize uintptr
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
		bufsize = unsafe.Sizeof(Statfs_t{}) * uintptr(len(buf))
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_getfsstat_trampoline), uintptr(_p0), bufsize, uintptr(flags))
	n = int(r0)
	if e1 != 0 {
		err = e1
	}
	return
}

func libc_getfsstat_trampoline()

//go:cgo_import_dynamic libc_getfsstat getfsstat "/usr/lib/libSystem.B.dylib"

// utimensat should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/tetratelabs/wazero
//
// See go.dev/issue/67401.
//
//go:linkname utimensat

//sys	utimensat(dirfd int, path string, times *[2]Timespec, flags int) (err error)

/*
 * Wrapped
 */

//sys	kill(pid int, signum int, posix int) (err error)

func Kill(pid int, signum Signal) (err error) { return kill(pid, int(signum), 1) }

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
//sys	closedir(dir uintptr) (err error)
//sys	Dup(fd int) (nfd int, err error)
//sys	Dup2(from int, to int) (err error)
//sys	Exchangedata(path1 string, path2 string, options int) (err error)
//sys	Fchdir(fd int) (err error)
//sys	Fchflags(fd int, flags int) (err error)
//sys	Fchmod(fd int, mode uint32) (err error)
//sys	Fchown(fd int, uid int, gid int) (err error)
//sys	Flock(fd int, how int) (err error)
//sys	Fpathconf(fd int, name int) (val int, err error)
//sys	Fsync(fd int) (err error)
//  Fsync is not called for os.File.Sync(). Please see internal/poll/fd_fsync_darwin.go
//sys	Ftruncate(fd int, length int64) (err error)
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
//sysnb	Getuid() (uid int)
//sysnb	Issetugid() (tainted bool)
//sys	Kqueue() (fd int, err error)
//sys	Lchown(path string, uid int, gid int) (err error)
//sys	Link(path string, link string) (err error)
//sys	Listen(s int, backlog int) (err error)
//sys	Mkdir(path string, mode uint32) (err error)
//sys	Mkfifo(path string, mode uint32) (err error)
//sys	Mknod(path string, mode uint32, dev int) (err error)
//sys	Mlock(b []byte) (err error)
//sys	Mlockall(flags int) (err error)
//sys	Mprotect(b []byte, prot int) (err error)
//sys	msync(b []byte, flags int) (err error)
//sys	Munlock(b []byte) (err error)
//sys	Munlockall() (err error)
//sys	Open(path string, mode int, perm uint32) (fd int, err error)
//sys	Pathconf(path string, name int) (val int, err error)
//sys	pread(fd int, p []byte, offset int64) (n int, err error)
//sys	pwrite(fd int, p []byte, offset int64) (n int, err error)
//sys	read(fd int, p []byte) (n int, err error)
//sys	readdir_r(dir uintptr, entry *Dirent, result **Dirent) (res Errno)
//sys	Readlink(path string, buf []byte) (n int, err error)
//sys	Rename(from string, to string) (err error)
//sys	Revoke(path string) (err error)
//sys	Rmdir(path string) (err error)
//sys	Seek(fd int, offset int64, whence int) (newoffset int64, err error) = SYS_lseek
//sys	Select(n int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (err error)
//sys	Setegid(egid int) (err error)
//sysnb	Seteuid(euid int) (err error)
//sysnb	Setgid(gid int) (err error)
//sys	Setlogin(name string) (err error)
//sysnb	Setpgid(pid int, pgid int) (err error)
//sys	Setpriority(which int, who int, prio int) (err error)
//sys	Setprivexec(flag int) (err error)
//sysnb	Setregid(rgid int, egid int) (err error)
//sysnb	Setreuid(ruid int, euid int) (err error)
//sysnb	setrlimit(which int, lim *Rlimit) (err error)
//sysnb	Setsid() (pid int, err error)
//sysnb	Settimeofday(tp *Timeval) (err error)
//sysnb	Setuid(uid int) (err error)
//sys	Symlink(path string, link string) (err error)
//sys	Sync() (err error)
//sys	Truncate(path string, length int64) (err error)
//sys	Umask(newmask int) (oldmask int)
//sys	Undelete(path string) (err error)
//sys	Unlink(path string) (err error)
//sys	Unmount(path string, flags int) (err error)
//sys	write(fd int, p []byte) (n int, err error)
//sys	writev(fd int, iovecs []Iovec) (cnt uintptr, err error)
//sys   mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)
//sys   munmap(addr uintptr, length uintptr) (err error)
//sysnb fork() (pid int, err error)
//sysnb execve(path *byte, argv **byte, envp **byte) (err error)
//sysnb exit(res int) (err error)
//sys	sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error)
//sys   unlinkat(fd int, path string, flags int) (err error)
//sys   openat(fd int, path string, flags int, perm uint32) (fdret int, err error)
//sys	getcwd(buf []byte) (n int, err error)

func init() {
	execveDarwin = execve
}

func fdopendir(fd int) (dir uintptr, err error) {
	r0, _, e1 := syscallPtr(abi.FuncPCABI0(libc_fdopendir_trampoline), uintptr(fd), 0, 0)
	dir = r0
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fdopendir_trampoline()

//go:cgo_import_dynamic libc_fdopendir fdopendir "/usr/lib/libSystem.B.dylib"

func readlen(fd int, buf *byte, nbuf int) (n int, err error) {
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_read_trampoline), uintptr(fd), uintptr(unsafe.Pointer(buf)), uintptr(nbuf))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func Getdirentries(fd int, buf []byte, basep *uintptr) (n int, err error) {
	// Simulate Getdirentries using fdopendir/readdir_r/closedir.
	// We store the number of entries to skip in the seek
	// offset of fd. See issue #31368.
	// It's not the full required semantics, but should handle the case
	// of calling Getdirentries or ReadDirent repeatedly.
	// It won't handle assigning the results of lseek to *basep, or handle
	// the directory being edited underfoot.
	skip, err := Seek(fd, 0, 1 /* SEEK_CUR */)
	if err != nil {
		return 0, err
	}

	// We need to duplicate the incoming file descriptor
	// because the caller expects to retain control of it, but
	// fdopendir expects to take control of its argument.
	// Just Dup'ing the file descriptor is not enough, as the
	// result shares underlying state. Use openat to make a really
	// new file descriptor referring to the same directory.
	fd2, err := openat(fd, ".", O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	d, err := fdopendir(fd2)
	if err != nil {
		Close(fd2)
		return 0, err
	}
	defer closedir(d)

	var cnt int64
	for {
		var entry Dirent
		var entryp *Dirent
		e := readdir_r(d, &entry, &entryp)
		if e != 0 {
			return n, errnoErr(e)
		}
		if entryp == nil {
			break
		}
		if skip > 0 {
			skip--
			cnt++
			continue
		}
		reclen := int(entry.Reclen)
		if reclen > len(buf) {
			// Not enough room. Return for now.
			// The counter will let us know where we should start up again.
			// Note: this strategy for suspending in the middle and
			// restarting is O(n^2) in the length of the directory. Oh well.
			break
		}
		// Copy entry into return buffer.
		copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&entry)), reclen))
		buf = buf[reclen:]
		n += reclen
		cnt++
	}
	// Set the seek offset of the input fd to record
	// how many files we've already returned.
	_, err = Seek(fd, cnt, 0 /* SEEK_SET */)
	if err != nil {
		return n, err
	}

	return n, nil
}

// Implemented in the runtime package (runtime/sys_darwin.go)
func syscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func syscall6X(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)
func rawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err Errno)
func syscallPtr(fn, a1, a2, a3 uintptr) (r1, r2 uintptr, err Errno)

"""



```