Response:
The user wants a summary of the functionality provided by the Go code snippet. This is the second part of a two-part question, so I should focus on the functions present in this specific snippet.

The code appears to be a series of Go functions that directly call underlying C library functions. Each Go function corresponds to a system call or a C library function.

I need to:
1. List the functions and briefly describe what they do.
2. Identify the general Go feature being implemented (syscalls).
3. Provide a Go code example demonstrating the use of one of these functions.
4. Indicate if any functions involve command-line argument processing (unlikely in this snippet).
5. Point out common mistakes users might make (e.g., incorrect buffer sizes for read/readlink).
6. Finally, summarize the overall functionality of this *part* of the file.
这是路径为go/src/syscall/zsyscall_darwin_arm64.go的go语言实现的一部分的第2部分。 与第1部分类似，这个部分也定义了一系列 Go 函数，这些函数是对 Darwin (macOS/iOS) 操作系统在 ARM64 架构下的系统调用或 C 库函数的封装。 这些函数使得 Go 程序能够直接与操作系统内核交互，执行底层操作。

**以下是这个部分包含的功能归纳：**

* **文件和目录操作：**
    * `Read(fd int, p []byte) (n int, err error)`: 从文件描述符 `fd` 中读取数据到字节切片 `p` 中。
    * `Readdir_r(dir uintptr, entry *Dirent, result **Dirent) (res Errno)`:  读取目录项（这是一个较低级别的目录读取函数，通常不直接使用）。
    * `Readlink(path string, buf []byte) (n int, err error)`: 读取符号链接 `path` 的目标路径到字节切片 `buf` 中。
    * `Rename(from string, to string) (err error)`: 重命名文件或目录。
    * `Rmdir(path string) (err error)`: 删除空目录。
    * `Seek(fd int, offset int64, whence int) (newoffset int64, err error)`: 改变文件描述符 `fd` 的读写偏移量。
    * `Symlink(path string, link string) (err error)`: 创建一个指向 `path` 的符号链接 `link`。
    * `Truncate(path string, length int64) (err error)`: 将文件截断到指定的 `length`。
    * `Undelete(path string) (err error)`: 尝试恢复已删除的文件（操作系统支持的情况下）。
    * `Unlink(path string) (err error)`: 删除文件。
    * `Unmount(path string, flags int) (err error)`: 卸载文件系统。
    * `Write(fd int, p []byte) (n int, err error)`: 将字节切片 `p` 的数据写入到文件描述符 `fd` 中。
    * `Writev(fd int, iovecs []Iovec) (cnt uintptr, err error)`:  将多个缓冲区的数据写入到文件描述符 `fd` 中。
    * `Mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error)`: 将文件或设备映射到内存中。
    * `Munmap(addr uintptr, length uintptr) (err error)`: 取消内存映射。
    * `Unlinkat(fd int, path string, flags int) (err error)`:  在相对于目录文件描述符 `fd` 的位置删除文件。
    * `Openat(fd int, path string, flags int, perm uint32) (fdret int, err error)`: 在相对于目录文件描述符 `fd` 的位置打开文件。
    * `Getwd(buf []byte) (n int, err error)`: 获取当前工作目录。

* **进程和用户管理：**
    * `Revoke(path string) (err error)`: 撤销访问权限。
    * `Select(n int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (err error)`:  I/O 多路复用，等待多个文件描述符上的事件。
    * `Setegid(egid int) (err error)`: 设置有效组 ID。
    * `Seteuid(euid int) (err error)`: 设置有效用户 ID。
    * `Setgid(gid int) (err error)`: 设置组 ID。
    * `Setlogin(name string) (err error)`: 设置登录名。
    * `Setpgid(pid int, pgid int) (err error)`: 设置进程组 ID。
    * `Setpriority(which int, who int, prio int) (err error)`: 设置进程优先级。
    * `Setprivexec(flag int) (err error)`:  设置特权执行模式。
    * `Setregid(rgid int, egid int) (err error)`: 设置实际和有效组 ID。
    * `Setreuid(ruid int, euid int) (err error)`: 设置实际和有效用户 ID。
    * `Setrlimit(which int, lim *Rlimit) (err error)`: 设置进程资源限制。
    * `Setsid() (pid int, err error)`: 创建一个新的会话并设置进程组 ID。
    * `Settimeofday(tp *Timeval) (err error)`: 设置系统时间。
    * `Setuid(uid int) (err error)`: 设置用户 ID。
    * `Fork() (pid int, err error)`: 创建一个新的进程（子进程）。
    * `Execve(path *byte, argv **byte, envp **byte) (err error)`: 执行一个新的程序。
    * `Exit(res int) (err error)`: 终止当前进程。

* **系统信息和控制：**
    * `Sync() (err error)`: 将所有缓存的磁盘数据同步到磁盘。
    * `Umask(newmask int) (oldmask int)`: 设置文件创建掩码。
    * `Sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error)`: 获取或设置系统信息。
    * `Gettimeofday(tp *Timeval) (err error)`: 获取当前时间。

* **文件状态：**
    * `Fstat(fd int, stat *Stat_t) (err error)`: 获取文件描述符 `fd` 指向的文件的状态信息。
    * `Fstatfs(fd int, stat *Statfs_t) (err error)`: 获取文件描述符 `fd` 指向的文件系统的信息。
    * `Lstat(path string, stat *Stat_t) (err error)`: 获取文件 `path` 的状态信息，如果是符号链接，则返回链接自身的状态。
    * `Stat(path string, stat *Stat_t) (err error)`: 获取文件 `path` 的状态信息。
    * `Statfs(path string, stat *Statfs_t) (err error)`: 获取文件 `path` 所在文件系统的信息。
    * `Fstatat(fd int, path string, stat *Stat_t, flags int) (err error)`: 获取相对于目录文件描述符 `fd` 的文件的状态信息。

* **调试：**
    * `Ptrace(request int, pid int, addr uintptr, data uintptr) (err error)`: 提供进程跟踪和调试功能（在 iOS 上会 panic）。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言 `syscall` 标准库的一部分，它使用了 **cgo** 技术来调用底层的 C 语言函数。 Go 语言通过 `syscall` 包提供了一种与操作系统底层交互的方式，使得 Go 程序可以执行如文件操作、进程管理、网络编程等需要直接调用操作系统接口的任务。

**Go 代码举例说明:**

以下示例展示了如何使用 `Read` 函数从文件中读取数据：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
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
	buffer := make([]byte, 100)
	n, err := syscall.Read(fd, buffer)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	fmt.Printf("Read %d bytes: %s\n", n, string(buffer[:n]))
}
```

**假设输入与输出:**

假设 `test.txt` 文件内容为 "Hello, world!"。

**输出:**

```
Read 13 bytes: Hello, world!
```

**命令行参数的具体处理:**

这个代码片段本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并通过 `os.Args` 获取。这些 `syscall` 包中的函数通常接收文件路径、文件描述符等作为参数，这些参数的值可能来自于命令行参数处理的结果。

**使用者易犯错的点:**

* **缓冲区大小不足 (针对 `Read` 和 `Readlink` 等函数):**  如果提供的缓冲区 `buf` 的大小小于实际读取到的数据长度，会导致数据丢失或截断。
    ```go
    package main

    import (
        "fmt"
        "os"
        "syscall"
    )

    func main() {
        filename := "large_file.txt" // 假设这个文件很大
        file, err := os.Open(filename)
        if err != nil {
            fmt.Println("Error opening file:", err)
            return
        }
        defer file.Close()

        fd := int(file.Fd())
        buffer := make([]byte, 5) // 缓冲区很小
        n, err := syscall.Read(fd, buffer)
        if err != nil {
            fmt.Println("Error reading file:", err)
            return
        }
        fmt.Printf("Read %d bytes: %s\n", n, string(buffer[:n])) // 可能只读取了文件的前 5 个字节
    }
    ```

**功能归纳 (针对此部分):**

总而言之，这个代码片段是 Go 语言 `syscall` 库在 Darwin ARM64 架构下实现的一部分，它提供了一系列与文件系统、进程管理、用户管理以及系统信息相关的底层操作接口。 通过这些接口，Go 程序可以直接调用 Darwin 操作系统的系统调用或 C 库函数，从而实现更底层的系统交互。 这部分代码的核心功能是为 Go 语言提供了在 Darwin ARM64 平台上执行各种系统级任务的能力。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_darwin_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_read_trampoline()

//go:cgo_import_dynamic libc_read read "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func readdir_r(dir uintptr, entry *Dirent, result **Dirent) (res Errno) {
	r0, _, _ := syscall(abi.FuncPCABI0(libc_readdir_r_trampoline), uintptr(dir), uintptr(unsafe.Pointer(entry)), uintptr(unsafe.Pointer(result)))
	res = Errno(r0)
	return
}

func libc_readdir_r_trampoline()

//go:cgo_import_dynamic libc_readdir_r readdir_r "/usr/lib/libSystem.B.dylib"

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
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_readlink_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(_p1), uintptr(len(buf)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_readlink_trampoline()

//go:cgo_import_dynamic libc_readlink readlink "/usr/lib/libSystem.B.dylib"

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
	_, _, e1 := syscall(abi.FuncPCABI0(libc_rename_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_rename_trampoline()

//go:cgo_import_dynamic libc_rename rename "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Revoke(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_revoke_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_revoke_trampoline()

//go:cgo_import_dynamic libc_revoke revoke "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Rmdir(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_rmdir_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_rmdir_trampoline()

//go:cgo_import_dynamic libc_rmdir rmdir "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	r0, _, e1 := syscallX(abi.FuncPCABI0(libc_lseek_trampoline), uintptr(fd), uintptr(offset), uintptr(whence))
	newoffset = int64(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_lseek_trampoline()

//go:cgo_import_dynamic libc_lseek lseek "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Select(n int, r *FdSet, w *FdSet, e *FdSet, timeout *Timeval) (err error) {
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_select_trampoline), uintptr(n), uintptr(unsafe.Pointer(r)), uintptr(unsafe.Pointer(w)), uintptr(unsafe.Pointer(e)), uintptr(unsafe.Pointer(timeout)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_select_trampoline()

//go:cgo_import_dynamic libc_select select "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setegid(egid int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_setegid_trampoline), uintptr(egid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setegid_trampoline()

//go:cgo_import_dynamic libc_setegid setegid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Seteuid(euid int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_seteuid_trampoline), uintptr(euid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_seteuid_trampoline()

//go:cgo_import_dynamic libc_seteuid seteuid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setgid(gid int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setgid_trampoline), uintptr(gid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setgid_trampoline()

//go:cgo_import_dynamic libc_setgid setgid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setlogin(name string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(name)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_setlogin_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setlogin_trampoline()

//go:cgo_import_dynamic libc_setlogin setlogin "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setpgid(pid int, pgid int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setpgid_trampoline), uintptr(pid), uintptr(pgid), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setpgid_trampoline()

//go:cgo_import_dynamic libc_setpgid setpgid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setpriority(which int, who int, prio int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_setpriority_trampoline), uintptr(which), uintptr(who), uintptr(prio))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setpriority_trampoline()

//go:cgo_import_dynamic libc_setpriority setpriority "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setprivexec(flag int) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_setprivexec_trampoline), uintptr(flag), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setprivexec_trampoline()

//go:cgo_import_dynamic libc_setprivexec setprivexec "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setregid(rgid int, egid int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setregid_trampoline), uintptr(rgid), uintptr(egid), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setregid_trampoline()

//go:cgo_import_dynamic libc_setregid setregid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setreuid(ruid int, euid int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setreuid_trampoline), uintptr(ruid), uintptr(euid), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setreuid_trampoline()

//go:cgo_import_dynamic libc_setreuid setreuid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setrlimit_trampoline), uintptr(which), uintptr(unsafe.Pointer(lim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setrlimit_trampoline()

//go:cgo_import_dynamic libc_setrlimit setrlimit "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setsid() (pid int, err error) {
	r0, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setsid_trampoline), 0, 0, 0)
	pid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setsid_trampoline()

//go:cgo_import_dynamic libc_setsid setsid "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Settimeofday(tp *Timeval) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_settimeofday_trampoline), uintptr(unsafe.Pointer(tp)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_settimeofday_trampoline()

//go:cgo_import_dynamic libc_settimeofday settimeofday "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setuid(uid int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_setuid_trampoline), uintptr(uid), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_setuid_trampoline()

//go:cgo_import_dynamic libc_setuid setuid "/usr/lib/libSystem.B.dylib"

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
	_, _, e1 := syscall(abi.FuncPCABI0(libc_symlink_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_symlink_trampoline()

//go:cgo_import_dynamic libc_symlink symlink "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Sync() (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_sync_trampoline), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_sync_trampoline()

//go:cgo_import_dynamic libc_sync sync "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Truncate(path string, length int64) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_truncate_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_truncate_trampoline()

//go:cgo_import_dynamic libc_truncate truncate "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Umask(newmask int) (oldmask int) {
	r0, _, _ := syscall(abi.FuncPCABI0(libc_umask_trampoline), uintptr(newmask), 0, 0)
	oldmask = int(r0)
	return
}

func libc_umask_trampoline()

//go:cgo_import_dynamic libc_umask umask "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Undelete(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_undelete_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_undelete_trampoline()

//go:cgo_import_dynamic libc_undelete undelete "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unlink(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_unlink_trampoline), uintptr(unsafe.Pointer(_p0)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_unlink_trampoline()

//go:cgo_import_dynamic libc_unlink unlink "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unmount(path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_unmount_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_unmount_trampoline()

//go:cgo_import_dynamic libc_unmount unmount "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func write(fd int, p []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(p) > 0 {
		_p0 = unsafe.Pointer(&p[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_write_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(p)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_write_trampoline()

//go:cgo_import_dynamic libc_write write "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func writev(fd int, iovecs []Iovec) (cnt uintptr, err error) {
	var _p0 unsafe.Pointer
	if len(iovecs) > 0 {
		_p0 = unsafe.Pointer(&iovecs[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscallX(abi.FuncPCABI0(libc_writev_trampoline), uintptr(fd), uintptr(_p0), uintptr(len(iovecs)))
	cnt = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_writev_trampoline()

//go:cgo_import_dynamic libc_writev writev "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func mmap(addr uintptr, length uintptr, prot int, flag int, fd int, pos int64) (ret uintptr, err error) {
	r0, _, e1 := syscall6X(abi.FuncPCABI0(libc_mmap_trampoline), uintptr(addr), uintptr(length), uintptr(prot), uintptr(flag), uintptr(fd), uintptr(pos))
	ret = uintptr(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_mmap_trampoline()

//go:cgo_import_dynamic libc_mmap mmap "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func munmap(addr uintptr, length uintptr) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_munmap_trampoline), uintptr(addr), uintptr(length), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_munmap_trampoline()

//go:cgo_import_dynamic libc_munmap munmap "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fork() (pid int, err error) {
	r0, _, e1 := rawSyscall(abi.FuncPCABI0(libc_fork_trampoline), 0, 0, 0)
	pid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fork_trampoline()

//go:cgo_import_dynamic libc_fork fork "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func execve(path *byte, argv **byte, envp **byte) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_execve_trampoline), uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(argv)), uintptr(unsafe.Pointer(envp)))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_execve_trampoline()

//go:cgo_import_dynamic libc_execve execve "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func exit(res int) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_exit_trampoline), uintptr(res), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_exit_trampoline()

//go:cgo_import_dynamic libc_exit exit "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sysctl(mib []_C_int, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error) {
	var _p0 unsafe.Pointer
	if len(mib) > 0 {
		_p0 = unsafe.Pointer(&mib[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_sysctl_trampoline), uintptr(_p0), uintptr(len(mib)), uintptr(unsafe.Pointer(old)), uintptr(unsafe.Pointer(oldlen)), uintptr(unsafe.Pointer(new)), uintptr(newlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_sysctl_trampoline()

//go:cgo_import_dynamic libc_sysctl sysctl "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func unlinkat(fd int, path string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_unlinkat_trampoline), uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(flags))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_unlinkat_trampoline()

//go:cgo_import_dynamic libc_unlinkat unlinkat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func openat(fd int, path string, flags int, perm uint32) (fdret int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := syscall6(abi.FuncPCABI0(libc_openat_trampoline), uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(flags), uintptr(perm), 0, 0)
	fdret = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_openat_trampoline()

//go:cgo_import_dynamic libc_openat openat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getcwd(buf []byte) (n int, err error) {
	var _p0 unsafe.Pointer
	if len(buf) > 0 {
		_p0 = unsafe.Pointer(&buf[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	r0, _, e1 := syscall(abi.FuncPCABI0(libc_getcwd_trampoline), uintptr(_p0), uintptr(len(buf)), 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_getcwd_trampoline()

//go:cgo_import_dynamic libc_getcwd getcwd "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstat(fd int, stat *Stat_t) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fstat_trampoline), uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fstat_trampoline()

//go:cgo_import_dynamic libc_fstat fstat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstatfs(fd int, stat *Statfs_t) (err error) {
	_, _, e1 := syscall(abi.FuncPCABI0(libc_fstatfs_trampoline), uintptr(fd), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fstatfs_trampoline()

//go:cgo_import_dynamic libc_fstatfs fstatfs "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Gettimeofday(tp *Timeval) (err error) {
	_, _, e1 := rawSyscall(abi.FuncPCABI0(libc_gettimeofday_trampoline), uintptr(unsafe.Pointer(tp)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_gettimeofday_trampoline()

//go:cgo_import_dynamic libc_gettimeofday gettimeofday "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Lstat(path string, stat *Stat_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_lstat_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_lstat_trampoline()

//go:cgo_import_dynamic libc_lstat lstat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Stat(path string, stat *Stat_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_stat_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_stat_trampoline()

//go:cgo_import_dynamic libc_stat stat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Statfs(path string, stat *Statfs_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall(abi.FuncPCABI0(libc_statfs_trampoline), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_statfs_trampoline()

//go:cgo_import_dynamic libc_statfs statfs "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fstatat(fd int, path string, stat *Stat_t, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_fstatat_trampoline), uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_fstatat_trampoline()

//go:cgo_import_dynamic libc_fstatat fstatat "/usr/lib/libSystem.B.dylib"

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

//go:nosplit
func ptrace(request int, pid int, addr uintptr, data uintptr) (err error) {
	if runtime.GOOS == "ios" {
		panic("unimplemented")
	}
	_, _, e1 := syscall6(abi.FuncPCABI0(libc_ptrace_trampoline), uintptr(request), uintptr(pid), uintptr(addr), uintptr(data), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func libc_ptrace_trampoline()

//go:cgo_import_dynamic libc_ptrace ptrace "/usr/lib/libSystem.B.dylib"

"""




```