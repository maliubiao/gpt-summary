Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Context:**

* **File Path:** `go/src/syscall/zsyscall_linux_386.go` - This immediately tells us we're dealing with low-level system calls in Go, specifically for Linux on a 386 architecture. The "zsyscall" prefix often indicates automatically generated or platform-specific system call wrappers.
* **Generated Code Comments:** The repeated "// mksyscall.pl..." and "// THIS FILE IS GENERATED..." are strong indicators that this code is *not* meant to be manually edited. A script has created it. This is crucial for understanding its nature.
* **`//go:build linux && 386`:** This build constraint confirms the platform specificity.

**2. Identifying the Core Functionality:**

* **Function Signatures:**  The code consists of many function definitions. Observe the pattern: `func functionName(args...) (returnValues...)`. These are the building blocks.
* **`syscall.Syscall` and `syscall.Syscall6`:**  These are the key functions. They are the Go standard library's interface to making raw system calls. The numbers 6 indicate the number of arguments being passed to the underlying system call.
* **`unsafe.Pointer`:** This keyword appears frequently, signaling direct interaction with memory addresses. This is necessary for passing data structures and pointers to the kernel.
* **`BytePtrFromString`:**  This function converts Go strings into C-style null-terminated byte pointers, which is the format expected by many system calls.
* **`errnoErr`:** This function likely converts the raw error code returned by the system call into a Go `error` value.
* **`SYS_*` and `_SYS_*` Constants:** These uppercase constants represent the numerical identifiers of specific Linux system calls. They are what `Syscall` uses to know *which* system call to execute.

**3. Inferring the Purpose of Individual Functions:**

* **Focus on the function names:** Many names clearly correspond to standard POSIX/Linux system calls (e.g., `faccessat`, `openat`, `linkat`, `readlinkat`, `unlinkat`, `mkdirat`, `renameat`, `chdir`, `chroot`, `close`, `read`, `write`, etc.).
* **Look at the arguments:** The argument types (e.g., `int`, `string`, `uint32`, `[]byte`) and names provide clues about the system call's purpose. For example, functions with `dirfd` and `path` strongly suggest operations relative to a directory file descriptor.
* **Examine the `Syscall` arguments:** The arguments passed to `Syscall` (or `Syscall6`) directly correspond to the arguments of the underlying Linux system call. You can often guess the mapping (e.g., `dirfd` maps to the first argument of `SYS_FACCESSAT`).

**4. Reasoning About the Overall Goal:**

* **System Call Wrapping:** The consistent pattern of converting Go types to types suitable for system calls and then invoking `Syscall` strongly indicates that this file provides Go wrappers around Linux system calls.
* **Platform and Architecture Specificity:** The file name and build constraints emphasize that this is a very specific implementation for Linux/386.

**5. Constructing Examples (Mental Walkthrough):**

* **`openat` Example:** I know `openat` opens a file relative to a directory file descriptor. The Go function takes `dirfd`, `path`, `flags`, and `mode`. I can imagine a scenario where I want to open a file named "myfile.txt" within a directory represented by the file descriptor `dfd`. The `flags` would specify read-only, and `mode` would set the permissions if the file is created.
* **`read` Example:**  This is simpler. It reads data from a file descriptor into a byte slice. I can visualize reading 1024 bytes from a file opened earlier.

**6. Addressing Specific Questions from the Prompt:**

* **Listing Functionality:** This becomes a matter of enumerating the identified system call wrappers.
* **Inferring Go Feature:**  The primary Go feature being implemented is the `syscall` package's ability to interact with the operating system kernel.
* **Code Examples:**  Simple examples demonstrating the use of a few key functions are needed.
* **Command-Line Arguments:** The `mksyscall.pl` command at the top is the relevant command. Its purpose is to generate this very file.
* **Common Mistakes:** Consider potential errors related to file descriptors (invalid, closed), permissions, and buffer handling.

**7. Structuring the Answer:**

* **Start with the big picture:** Explain that it's a low-level system call interface for Linux/386.
* **List the functionalities:** Group them logically (file operations, process management, etc.).
* **Provide a detailed example:** Choose a representative function like `openat` and illustrate its usage.
* **Explain the code generation aspect:** Mention `mksyscall.pl`.
* **Address potential pitfalls:**  Give examples of common errors.
* **Conclude with the summary:** Reiterate the main function of the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Is this just a random collection of functions?"  *Correction:* The consistent use of `Syscall` and the file naming convention point to a system call interface.
* **Thinking about examples:** "Should I provide examples for every function?" *Correction:*  Focus on one or two key examples to illustrate the concept.
* **Considering the audience:**  "Does the user understand system calls?" *Refinement:*  Provide a brief explanation of what system calls are.

By following these steps, which involve understanding the context, identifying patterns, inferring purpose, and providing concrete examples, one can effectively analyze and explain the functionality of this Go code snippet.
好的，让我们来分析一下你提供的这段 Go 语言代码。

**功能归纳：**

这段代码是 Go 语言标准库 `syscall` 包的一部分，专门针对 Linux 操作系统在 386 架构下的系统调用实现。它的主要功能是**为 Go 程序提供直接调用 Linux 系统调用的能力**。

具体来说，这段代码定义了一系列 Go 函数，**每一个函数都对应一个特定的 Linux 系统调用**。这些 Go 函数作为桥梁，将 Go 语言的数据类型和调用方式转换为 Linux 系统调用所需的格式，并处理系统调用的返回值和错误。

**详细功能列表：**

这段代码中实现的系统调用涵盖了多种操作，主要可以分为以下几类：

1. **文件和目录操作:**
    *   `faccessat`, `faccessat2`: 检查用户对文件的访问权限。
    *   `fchmodat`, `fchmodat2`: 修改文件的权限。
    *   `linkat`: 创建硬链接。
    *   `openat`: 打开或创建文件。
    *   `readlinkat`: 读取符号链接指向的路径。
    *   `symlinkat`: 创建符号链接。
    *   `unlinkat`: 删除文件。
    *   `utimensat`: 修改文件的访问和修改时间。
    *   `Getcwd`: 获取当前工作目录。
    *   `Fallocate`:  为一个打开的文件预分配空间。
    *   `Fchmod`: 修改文件的权限（通过文件描述符）。
    *   `Fchownat`: 修改文件的所有者和组（相对于目录文件描述符）。
    *   `Fdatasync`: 将文件数据同步到磁盘。
    *   `Flock`: 对文件加锁或解锁。
    *   `Fsync`: 将文件数据和元数据同步到磁盘。
    *   `Getdents`: 读取目录项。
    *   `Getxattr`: 获取扩展属性。
    *   `InotifyAddWatch`, `InotifyInit1`, `InotifyRmWatch`, `InotifyInit`: 用于监控文件系统事件 (inotify)。
    *   `Listxattr`: 列出扩展属性。
    *   `Mkdirat`: 创建目录。
    *   `Mknodat`: 创建设备文件。
    *   `Renameat`: 重命名文件或目录。
    *   `Removexattr`: 删除扩展属性。
    *   `Setxattr`: 设置扩展属性。
    *   `Truncate`: 截断文件到指定长度。
    *   `Fstat`, `fstatat`: 获取文件状态信息。
    *   `Ftruncate`: 截断文件到指定长度（通过文件描述符）。

2. **进程管理:**
    *   `wait4`: 等待子进程状态改变。
    *   `ptrace`, `ptracePtr`: 用于进程跟踪和调试。
    *   `reboot`: 重启系统。
    *   `Acct`: 启用或禁用进程记账。
    *   `Adjtimex`: 调整系统时钟。
    *   `Chdir`, `Fchdir`: 改变当前工作目录。
    *   `Chroot`: 改变进程的根目录。
    *   `Close`: 关闭文件描述符。
    *   `Dup`, `Dup3`, `Dup2`: 复制文件描述符。
    *   `ExitThread`: 终止当前线程。
    *   `Getpgid`: 获取进程组 ID。
    *   `Getpid`, `Getppid`, `Gettid`: 获取进程 ID、父进程 ID 和线程 ID。
    *   `Getpriority`: 获取进程优先级。
    *   `Getrusage`: 获取进程或线程的资源使用情况。
    *   `Kill`, `Tgkill`: 发送信号给进程或线程。
    *   `Nanosleep`: 使当前进程睡眠指定的时间。
    *   `Pause`: 使当前进程休眠直到接收到信号。
    *   `PivotRoot`: 将进程的根目录移动到新的位置。
    *   `Prlimit1`: 获取或设置进程资源限制。
    *   `Setdomainname`, `Sethostname`: 设置域名和主机名。
    *   `Setpgid`, `Setsid`: 设置进程组 ID 和会话 ID。
    *   `Settimeofday`: 设置系统时间。
    *   `Setpriority`: 设置进程优先级。
    *   `Umask`: 设置文件模式创建屏蔽字。
    *   `Uname`: 获取系统信息。
    *   `Unshare`: 解除进程的部分执行上下文共享。
    *   `Getegid`, `Geteuid`, `Getgid`, `Getuid`: 获取有效的和实际的用户和组 ID。
    *   `Setfsgid`, `Setfsuid`: 设置用于文件系统访问的用户和组 ID。
    *   `getgroups`: 获取当前进程所属的用户组列表。

3. **内存管理:**
    *   `munmap`: 取消映射内存区域。
    *   `Madvise`: 向内核提供关于内存使用的建议。
    *   `Mprotect`: 修改内存区域的保护属性。
    *   `Mlock`, `Munlock`, `Mlockall`, `Munlockall`: 锁定和解锁内存页。

4. **设备和文件系统:**
    *   `mount`: 挂载文件系统。
    *   `Unmount`: 卸载文件系统。
    *   `Sync`: 将所有文件系统缓冲区刷新到磁盘。
    *   `Sysinfo`: 获取系统信息。
    *   `Ustat`: 获取文件系统状态信息。

5. **管道和 I/O:**
    *   `pipe2`: 创建管道。
    *   `read`, `write`, `pread`, `pwrite`, `readlen`: 读写文件。
    *   `Tee`: 在两个文件描述符之间复制数据。
    *   `Sendfile`: 在两个文件描述符之间高效地复制数据。
    *   `Splice`: 在两个文件描述符之间移动数据。
    *   `SyncFileRange`: 同步文件指定范围的数据到磁盘。
    *   `Select`:  监控多个文件描述符的事件。

6. **其他:**
    *   `fcntl`:  对文件描述符执行各种控制操作。
    *   `Klogctl`: 控制内核日志记录。
    *   `Ioperm`, `Iopl`: 设置 I/O 端口权限。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `syscall` 包在 Linux 386 架构下的底层实现。`syscall` 包提供了一种与操作系统内核进行交互的方式，允许 Go 程序执行底层的系统调用。这对于需要进行操作系统级操作（例如文件操作、进程管理、网络编程等）的程序至关重要。

**Go 代码举例说明:**

假设我们要使用 `openat` 系统调用在一个相对于目录文件描述符的路径下打开一个文件。

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	dirPath := "/tmp"
	fileName := "test.txt"
	flags := syscall.O_RDWR | syscall.O_CREATE // 读写，如果不存在则创建
	mode := uint32(0644)                   // 文件权限

	// 打开目录
	dirFd, err := syscall.Open(dirPath, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		fmt.Println("Error opening directory:", err)
		return
	}
	defer syscall.Close(dirFd)

	// 使用 openat 打开文件
	fd, err := syscall.Openat(int(dirFd), fileName, flags, mode)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer syscall.Close(fd)

	fmt.Printf("File '%s' opened successfully with file descriptor: %d\n", fileName, fd)

	// 假设要写入一些数据
	message := "Hello, world!\n"
	_, err = syscall.Write(fd, unsafe.Slice(unsafe.StringData(message), len(message)))
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	fmt.Println("Data written to file.")
}
```

**假设的输入与输出:**

*   **假设输入:** 目录 `/tmp` 存在，并且用户有权限在该目录下创建文件。
*   **预期输出:**
    ```
    File 'test.txt' opened successfully with file descriptor: 3
    Data written to file.
    ```
    （文件描述符的具体数值可能会有所不同）

**涉及命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。它的主要作用是提供 Go 函数来调用系统调用。命令行参数的处理通常发生在 Go 程序的 `main` 函数中，可以使用 `os.Args` 或 `flag` 包来解析。

然而，注意到代码的开头有一行注释：

```
// mksyscall.pl -l32 -tags linux,386 syscall_linux.go syscall_linux_386.go
```

这表明该文件是通过一个名为 `mksyscall.pl` 的 Perl 脚本生成的。这个脚本可能接受一些命令行参数，例如 `-l32` (指定 32 位架构) 和 `-tags linux,386` (指定构建标签)。这些参数用于控制脚本的行为，例如生成针对特定架构和操作系统的系统调用绑定代码。

**使用者易犯错的点：**

1. **错误的文件描述符:**  传递无效或已关闭的文件描述符会导致系统调用失败。
    ```go
    fd := -1 // 错误的描述符
    _, err := syscall.Read(fd, make([]byte, 10))
    if err != nil {
        fmt.Println("Read error:", err) // 输出 "Read error: bad file descriptor"
    }
    ```

2. **不正确的权限:** 尝试执行需要特定权限的操作（例如打开只读文件进行写入）会导致错误。
    ```go
    fd, _ := syscall.Open("/tmp/readonly.txt", syscall.O_RDONLY, 0)
    defer syscall.Close(fd)
    _, err := syscall.Write(fd, []byte("some data"))
    if err != nil {
        fmt.Println("Write error:", err) // 输出 "Write error: permission denied"
    }
    ```

3. **缓冲区大小不足:** 在 `read` 或 `readlinkat` 等操作中，提供的缓冲区可能不足以容纳所有数据。
    ```go
    fd, _ := syscall.Open("/etc/hostname", syscall.O_RDONLY, 0)
    defer syscall.Close(fd)
    buf := make([]byte, 5) // 小缓冲区
    n, _ := syscall.Read(fd, buf)
    fmt.Println(string(buf[:n])) // 可能只读取了主机名的一部分
    ```

4. **忘记处理错误:** 系统调用可能会失败，忽略错误会导致程序行为异常。
    ```go
    _, err := syscall.Unlink("/nonexistent_file") // 假设文件不存在
    // 没有检查 err，如果文件不存在，程序可能继续执行，但实际操作并未成功
    ```

5. **不安全地使用 `unsafe.Pointer`:**  直接操作内存指针是危险的，需要谨慎处理，确保类型安全和内存安全。

**总结其功能（针对第1部分）：**

这段 `go/src/syscall/zsyscall_linux_386.go` 代码是 Go 语言标准库中 `syscall` 包在 Linux 操作系统 386 架构下的具体实现。它通过定义一系列 Go 函数，封装了大量的 Linux 系统调用，使得 Go 程序能够与 Linux 内核进行底层交互，执行文件操作、进程管理、内存管理等各种系统级任务。它是由 `mksyscall.pl` 脚本自动生成的，并针对特定的操作系统和架构进行了优化。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_linux_386.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksyscall.pl -l32 -tags linux,386 syscall_linux.go syscall_linux_386.go
// Code generated by the command above; DO NOT EDIT.

//go:build linux && 386

package syscall

import "unsafe"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func faccessat(dirfd int, path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_FACCESSAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func faccessat2(dirfd int, path string, mode uint32, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(_SYS_faccessat2, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fchmodat(dirfd int, path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_FCHMODAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fchmodat2(dirfd int, path string, mode uint32, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(_SYS_fchmodat2, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func linkat(olddirfd int, oldpath string, newdirfd int, newpath string, flags int) (err error) {
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
	_, _, e1 := Syscall6(SYS_LINKAT, uintptr(olddirfd), uintptr(unsafe.Pointer(_p0)), uintptr(newdirfd), uintptr(unsafe.Pointer(_p1)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := Syscall6(SYS_OPENAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(flags), uintptr(mode), 0, 0)
	fd = int(r0)
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

func readlinkat(dirfd int, path string, buf []byte) (n int, err error) {
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
	r0, _, e1 := Syscall6(SYS_READLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(_p1), uintptr(len(buf)), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func symlinkat(oldpath string, newdirfd int, newpath string) (err error) {
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
	_, _, e1 := Syscall(SYS_SYMLINKAT, uintptr(unsafe.Pointer(_p0)), uintptr(newdirfd), uintptr(unsafe.Pointer(_p1)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func unlinkat(dirfd int, path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UNLINKAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(flags))
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

func Getcwd(buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_GETCWD, uintptr(_p0), uintptr(len(buf)), 0)
	n = int(r0)
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

func ptrace(request int, pid int, addr uintptr, data uintptr) (err error) {
	_, _, e1 := Syscall6(SYS_PTRACE, uintptr(request), uintptr(pid), uintptr(addr), uintptr(data), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ptracePtr(request int, pid int, addr uintptr, data unsafe.Pointer) (err error) {
	_, _, e1 := Syscall6(SYS_PTRACE, uintptr(request), uintptr(pid), uintptr(addr), uintptr(data), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func reboot(magic1 uint, magic2 uint, cmd int, arg string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(arg)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_REBOOT, uintptr(magic1), uintptr(magic2), uintptr(cmd), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func mount(source string, target string, fstype string, flags uintptr, data *byte) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(source)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(target)
	if err != nil {
		return
	}
	var _p2 *byte
	_p2, err = BytePtrFromString(fstype)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_MOUNT, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(unsafe.Pointer(_p2)), uintptr(flags), uintptr(unsafe.Pointer(data)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Acct(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_ACCT, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Adjtimex(buf *Timex) (state int, err error) {
	r0, _, e1 := Syscall(SYS_ADJTIMEX, uintptr(unsafe.Pointer(buf)), 0, 0)
	state = int(r0)
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

func Dup(oldfd int) (fd int, err error) {
	r0, _, e1 := Syscall(SYS_DUP, uintptr(oldfd), 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup3(oldfd int, newfd int, flags int) (err error) {
	_, _, e1 := Syscall(SYS_DUP3, uintptr(oldfd), uintptr(newfd), uintptr(flags))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func EpollCreate1(flag int) (fd int, err error) {
	r0, _, e1 := RawSyscall(SYS_EPOLL_CREATE1, uintptr(flag), 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func EpollCtl(epfd int, op int, fd int, event *EpollEvent) (err error) {
	_, _, e1 := RawSyscall6(SYS_EPOLL_CTL, uintptr(epfd), uintptr(op), uintptr(fd), uintptr(unsafe.Pointer(event)), 0, 0)
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

func Fchdir(fd int) (err error) {
	_, _, e1 := Syscall(SYS_FCHDIR, uintptr(fd), 0, 0)
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

func Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_FCHOWNAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid), uintptr(flags), 0)
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

func Fdatasync(fd int) (err error) {
	_, _, e1 := Syscall(SYS_FDATASYNC, uintptr(fd), 0, 0)
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

func Fsync(fd int) (err error) {
	_, _, e1 := Syscall(SYS_FSYNC, uintptr(fd), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getdents(fd int, buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_GETDENTS64, uintptr(fd), uintptr(_p0), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
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

func Getpid() (pid int) {
	r0, _ := rawSyscallNoError(SYS_GETPID, 0, 0, 0)
	pid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getppid() (ppid int) {
	r0, _ := rawSyscallNoError(SYS_GETPPID, 0, 0, 0)
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

func Getrusage(who int, rusage *Rusage) (err error) {
	_, _, e1 := RawSyscall(SYS_GETRUSAGE, uintptr(who), uintptr(unsafe.Pointer(rusage)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Gettid() (tid int) {
	r0, _ := rawSyscallNoError(SYS_GETTID, 0, 0, 0)
	tid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getxattr(path string, attr string, dest []byte) (sz int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(attr)
	if err != nil {
		return
	}
	var _p2 unsafe.Pointer
	if len(dest) > 0 {
		_p2 = unsafe.Pointer(&dest[0])
	} else {
		_p2 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall6(SYS_GETXATTR, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(_p2), uintptr(len(dest)), 0, 0)
	sz = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func InotifyAddWatch(fd int, pathname string, mask uint32) (watchdesc int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(pathname)
	if err != nil {
		return
	}
	r0, _, e1 := Syscall(SYS_INOTIFY_ADD_WATCH, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(mask))
	watchdesc = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func InotifyInit1(flags int) (fd int, err error) {
	r0, _, e1 := RawSyscall(SYS_INOTIFY_INIT1, uintptr(flags), 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func InotifyRmWatch(fd int, watchdesc uint32) (success int, err error) {
	r0, _, e1 := RawSyscall(SYS_INOTIFY_RM_WATCH, uintptr(fd), uintptr(watchdesc), 0)
	success = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kill(pid int, sig Signal) (err error) {
	_, _, e1 := RawSyscall(SYS_KILL, uintptr(pid), uintptr(sig), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Klogctl(typ int, buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_SYSLOG, uintptr(typ), uintptr(_p0), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Listxattr(path string, dest []byte) (sz int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 unsafe.Pointer
	if len(dest) > 0 {
		_p1 = unsafe.Pointer(&dest[0])
	} else {
		_p1 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := Syscall(SYS_LISTXATTR, uintptr(unsafe.Pointer(_p0)), uintptr(_p1), uintptr(len(dest)))
	sz = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mkdirat(dirfd int, path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_MKDIRAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mknodat(dirfd int, path string, mode uint32, dev int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_MKNODAT, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(dev), 0, 0)
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

func PivotRoot(newroot string, putold string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(newroot)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(putold)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_PIVOT_ROOT, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func prlimit1(pid int, resource int, newlimit *Rlimit, old *Rlimit) (err error) {
	_, _, e1 := RawSyscall6(SYS_PRLIMIT64, uintptr(pid), uintptr(resource), uintptr(unsafe.Pointer(newlimit)), uintptr(unsafe.Pointer(old)), 0, 0)
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

func Removexattr(path string, attr string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(attr)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_REMOVEXATTR, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setdomainname(p []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall(SYS_SETDOMAINNAME, uintptr(_p0), uintptr(len(p)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Sethostname(p []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall(SYS_SETHOSTNAME, uintptr(_p0), uintptr(len(p)), 0)
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

func Setsid() (pid int, err error) {
	r0, _, e1 := RawSyscall(SYS_SETSID, 0, 0, 0)
	pid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Settimeofday(tv *Timeval) (err error) {
	_, _, e1 := RawSyscall(SYS_SETTIMEOFDAY, uintptr(unsafe.Pointer(tv)), 0, 0)
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

func Setxattr(path string, attr string, data []byte, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	_p1, err = BytePtrFromString(attr)
	if err != nil {
		return
	}
	var _p2 unsafe.Pointer
	if len(data) > 0 {
		_p2 = unsafe.Pointer(&data[0])
	} else {
		_p2 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall6(SYS_SETXATTR, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(_p2), uintptr(len(data)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Sync() {
	Syscall(SYS_SYNC, 0, 0, 0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Sysinfo(info *Sysinfo_t) (err error) {
	_, _, e1 := RawSyscall(SYS_SYSINFO, uintptr(unsafe.Pointer(info)), 0, 0)
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

func Tgkill(tgid int, tid int, sig Signal) (err error) {
	_, _, e1 := RawSyscall(SYS_TGKILL, uintptr(tgid), uintptr(tid), uintptr(sig))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Times(tms *Tms) (ticks uintptr, err error) {
	r0, _, e1 := RawSyscall(SYS_TIMES, uintptr(unsafe.Pointer(tms)), 0, 0)
	ticks = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Umask(mask int) (oldmask int) {
	r0, _ := rawSyscallNoError(SYS_UMASK, uintptr(mask), 0, 0)
	oldmask = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Uname(buf *Utsname) (err error) {
	_, _, e1 := RawSyscall(SYS_UNAME, uintptr(unsafe.Pointer(buf)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unmount(target string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(target)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_UMOUNT2, uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unshare(flags int) (err error) {
	_, _, e1 := Syscall(SYS_UNSHARE, uintptr(flags), 0, 0)
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

func exitThread(code int) (err error) {
	_, _, e1 := Syscall(SYS_EXIT, uintptr(code), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func readlen(fd int, p *byte, np int) (n int, err error) {
	r0, _, e1 := Syscall(SYS_READ, uintptr(fd), uintptr(unsafe.Pointer(p)), uintptr(np))
	n = int(r0)
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

func Madvise(b []byte, advice int) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall(SYS_MADVISE, uintptr(_p0), uintptr(len(b)), uintptr(advice))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mprotect(b []byte, prot int) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall(SYS_MPROTECT, uintptr(_p0), uintptr(len(b)), uintptr(prot))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mlock(b []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall(SYS_MLOCK, uintptr(_p0), uintptr(len(b)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Munlock(b []byte) (err error) {
	var _p0 unsafe.Pointer
	if len(b) > 0 {
		_p0 = unsafe.Pointer(&b[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := Syscall(SYS_MUNLOCK, uintptr(_p0), uintptr(len(b)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mlockall(flags int) (err error) {
	_, _, e1 := Syscall(SYS_MLOCKALL, uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Munlockall() (err error) {
	_, _, e1 := Syscall(SYS_MUNLOCKALL, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup2(oldfd int, newfd int) (err error) {
	_, _, e1 := Syscall(SYS_DUP2, uintptr(oldfd), uintptr(newfd), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchown(fd int, uid int, gid int) (err error) {
	_, _, e1 := Syscall(SYS_FCHOWN32, uintptr(fd), uintptr(uid), uintptr(gid))
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

func fstatat(dirfd int, path string, stat *Stat_t, flags int) (err error) {
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

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := Syscall(SYS_FTRUNCATE64, uintptr(fd), uintptr(length), uintptr(length>>32))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _ := rawSyscallNoError(SYS_GETEGID32, 0, 0, 0)
	egid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (euid int) {
	r0, _ := rawSyscallNoError(SYS_GETEUID32, 0, 0, 0)
	euid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _ := rawSyscallNoError(SYS_GETGID32, 0, 0, 0)
	gid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _ := rawSyscallNoError(SYS_GETUID32, 0, 0, 0)
	uid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func InotifyInit() (fd int, err error) {
	r0, _, e1 := RawSyscall(SYS_INOTIFY_INIT, 0, 0, 0)
	fd = int(r0)
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

func Pause() (err error) {
	_, _, e1 := Syscall(SYS_PAUSE, 0, 0, 0)
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
	r0, _, e1 := Syscall6(SYS_PREAD64, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), uintptr(offset>>32), 0)
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
	r0, _, e1 := Syscall6(SYS_PWRITE64, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), uintptr(offset>>32), 0)
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

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	r0, _, e1 := Syscall6(SYS_SENDFILE64, uintptr(outfd), uintptr(infd), uintptr(unsafe.Pointer(offset)), uintptr(count), 0, 0)
	written = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setfsgid(gid int) (err error) {
	_, _, e1 := Syscall(SYS_SETFSGID32, uintptr(gid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setfsuid(uid int) (err error) {
	_, _, e1 := Syscall(SYS_SETFSUID32, uintptr(uid), 0, 0)
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
	_, _, e1 := Syscall6(SYS_SYNC_FILE_RANGE, uintptr(fd), uintptr(off), uintptr(off>>32), uintptr(n), uintptr(n>>32), uintptr(flags))
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
	_, _, e1 := Syscall(SYS_TRUNCATE64, uintptr(unsafe.Pointer(_p0)), uintptr(length), uintptr(length>>32))
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

func getgroups(n int, list *_Gid_t) (nn int, err error) {
	r0, _, e1 := RawSyscall(SYS_GETGROUPS32, uintptr(n), uintptr(unsafe.Pointer(list)), 0)
	nn = int(r0)
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

func mmap2(addr uintptr, length uintptr, prot int, flags int, fd int, pageOffset uintptr) (xaddr uintptr, 
"""




```