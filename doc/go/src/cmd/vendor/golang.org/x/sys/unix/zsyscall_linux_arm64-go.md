Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Obvious Observations:**

* **File Path and Build Tags:** The filename `zsyscall_linux_arm64.go` and the build tags `//go:build linux && arm64` immediately tell us this code is specific to the Linux operating system running on the ARM64 architecture. The `zsyscall` prefix suggests it's auto-generated, likely for system calls.
* **"DO NOT EDIT" Comments:**  These prominent comments reinforce the idea of auto-generation and strongly advise against manual modification.
* **`package unix`:**  This indicates the code belongs to the `unix` package, which provides low-level access to operating system primitives.
* **`import` Statements:**  The imports of `syscall` and `unsafe` are crucial. `syscall` is the standard Go package for making system calls, and `unsafe` is used for direct memory manipulation, which is common when interacting with OS interfaces.
* **Function Structure:**  All the functions follow a similar pattern:
    * Call `Syscall`, `Syscall6`, or `RawSyscall` (or `RawSyscallNoError`).
    * Pass constants like `SYS_FANOTIFY_MARK`.
    * Handle the return values, especially `e1` which seems to represent an error number.
    * Use `errnoErr(e1)` to convert the error number to a Go `error`.
* **"THIS FILE IS GENERATED..." Comments:** These repeating comments confirm the auto-generated nature of each function.

**2. Understanding the Core Mechanism:**

* **System Calls:** The consistent use of `Syscall`, `Syscall6`, and related functions strongly points to this code being a wrapper around Linux system calls. These functions are the fundamental way a program interacts with the operating system kernel.
* **`unsafe.Pointer`:** The frequent use of `unsafe.Pointer` suggests that the Go code needs to pass raw memory addresses to the kernel, which is typical for system calls that deal with structures or data buffers.
* **Mapping to System Call Numbers:**  The `SYS_...` constants (e.g., `SYS_FANOTIFY_MARK`) are likely defined elsewhere (in `syscall_linux.go` as the `go run` command indicates) and represent the numerical identifiers of specific Linux system calls.

**3. Function-by-Function Analysis (Example - `fanotifyMark`):**

* **Function Signature:** `func fanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname *byte) (err error)` - The parameter types suggest interaction with file systems and events. `pathname *byte` hints at a C-style string.
* **`Syscall6(SYS_FANOTIFY_MARK, ...)`:** This confirms it's a system call. The `6` indicates it takes 6 arguments.
* **Argument Mapping:** The Go function arguments are directly passed as `uintptr` to the `Syscall6` function. This is the standard way to pass arguments of various types to system calls in Go's `syscall` package.
* **Error Handling:** The `if e1 != 0` block handles errors returned by the system call.

**4. Generalizing the Functionalities:**

After analyzing a few functions, the pattern becomes clear. Each function in this file provides a Go-friendly interface to a specific Linux system call. The function name often directly corresponds to the system call name (e.g., `fanotifyMark` -> `FANOTIFY_MARK`).

**5. Inferring Go Language Features and Providing Examples:**

Based on the identified system calls, we can infer the Go language features they enable. For example:

* **File Operations:** `Fallocate`, `Ftruncate`, `Fstat`, `Fstatat`, `Truncate`, `pread`, `pwrite`, `sendfile`, `SyncFileRange`. These map to Go's file I/O operations in the `os` and `io` packages.
* **Process Management:** `Getegid`, `Geteuid`, `Getgid`, `Getuid`, `setfsgid`, `setfsuid`, `getrlimit`, `setgroups`, `getgroups`. These relate to user and group IDs and resource limits, often used with `os/user` and `syscall` package functionality in Go.
* **Networking:** `Listen`, `accept4`, `bind`, `connect`, `getsockopt`, `setsockopt`, `socket`, `socketpair`, `getpeername`, `getsockname`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`, `Shutdown`. These are the foundation for Go's `net` package.
* **Memory Management:** `mmap`, `MemfdSecret`. These are related to memory mapping and secret memory regions.
* **Event Handling:** `EpollWait`, `fanotifyMark`. These are used for efficient event notification, often employed in asynchronous I/O operations.

**6. Addressing Potential Errors (Focusing on `unsafe.Pointer`):**

The use of `unsafe.Pointer` is the most obvious area for potential errors. Incorrect usage can lead to crashes or memory corruption. The key is to emphasize the need for careful handling of memory allocation and lifetimes when using these functions indirectly.

**7. Considering the `go run` Command:**

The `go run mksyscall.go -tags linux,arm64 syscall_linux.go syscall_linux_arm64.go` command reveals the code generation process. `mksyscall.go` is a tool that likely parses `syscall_linux.go` (which probably contains the definitions of the `SYS_...` constants and potentially the function signatures) and generates the architecture-specific `zsyscall_linux_arm64.go` file.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it's just random system call wrappers.
* **Correction:**  Recognize the patterns and the systematic nature of the code, suggesting it's auto-generated and covers a range of common OS functionalities.
* **Initial thought:**  Focus solely on direct usage.
* **Refinement:**  Realize the importance of explaining how these low-level functions underpin higher-level Go functionalities.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive explanation of its purpose and functionality. The focus is on understanding the core mechanism (system calls), identifying patterns, and connecting the low-level code to higher-level Go concepts.
The Go code snippet you provided is a part of the `syscall` package within the Go standard library (or an extended version of it in `golang.org/x/sys/unix`). Specifically, it's the architecture-specific implementation for Linux on ARM64 (`linux && arm64`).

Here's a breakdown of its functionality:

**Core Functionality:**

This file provides **low-level Go bindings to specific Linux system calls** for the ARM64 architecture. Each function in this file corresponds to a system call defined by the Linux kernel. These functions allow Go programs to directly interact with the operating system kernel, enabling operations that are not directly exposed by higher-level Go packages.

**Detailed Function Listing and Inferred Go Functionality:**

Let's go through each function and infer its purpose and how it might be used in Go.

* **`fanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname *byte) (err error)`:**
    * **Linux Syscall:** `SYS_FANOTIFY_MARK`
    * **Functionality:**  Used to add, remove, or modify fanotify marks on files or directories. Fanotify provides a mechanism for content-based event notification.
    * **Go Functionality:** This would be used by Go packages that need to monitor file system events with more granularity than `fsnotify`, potentially for security or advanced file management tasks.

* **`Fallocate(fd int, mode uint32, off int64, len int64) (err error)`:**
    * **Linux Syscall:** `SYS_FALLOCATE`
    * **Functionality:**  Preallocates space for a file on disk. This can improve performance by preventing fragmentation and ensuring space is available.
    * **Go Functionality:**  This could be used by Go programs that need to manage disk space efficiently, such as database systems or large file processors. You might find higher-level wrappers in packages dealing with storage.

* **`Tee(rfd int, wfd int, len int, flags int) (n int64, err error)`:**
    * **Linux Syscall:** `SYS_TEE`
    * **Functionality:**  Copies data from one file descriptor to another without the need to transfer data to userspace. Often used in pipelines.
    * **Go Functionality:**  Go's `io.Pipe()` and related functions might internally utilize this for efficient data transfer between processes or goroutines.

* **`EpollWait(epfd int, events []EpollEvent, msec int) (n int, err error)`:**
    * **Linux Syscall:** `SYS_EPOLL_PWAIT` (note: the constant is `SYS_EPOLL_PWAIT`, not `SYS_EPOLL_WAIT` which is an older version)
    * **Functionality:**  Waits for events on file descriptors that have been added to an epoll instance. This is a highly efficient mechanism for multiplexing I/O events.
    * **Go Functionality:**  The `net` package and the `syscall` package itself use `epoll` under the hood for efficient handling of network connections and file descriptor monitoring.

* **`Fadvise(fd int, offset int64, length int64, advice int) (err error)`:**
    * **Linux Syscall:** `SYS_FADVISE64`
    * **Functionality:**  Provides advice to the kernel about the expected access patterns of a file. This allows the kernel to optimize its caching and prefetching strategies.
    * **Go Functionality:**  Go's `os` package might indirectly use this to hint at file access patterns for performance improvements.

* **`Fchown(fd int, uid int, gid int) (err error)`:**
    * **Linux Syscall:** `SYS_FCHOWN`
    * **Functionality:**  Changes the owner and group of a file referenced by its file descriptor.
    * **Go Functionality:**  The `os` package's `Chown` and `Lchown` functions likely use this system call (or its path-based counterpart) internally.

* **`Fstat(fd int, stat *Stat_t) (err error)`:**
    * **Linux Syscall:** `SYS_FSTAT`
    * **Functionality:**  Retrieves information about a file referenced by its file descriptor. This information includes file size, permissions, modification times, etc.
    * **Go Functionality:**  The `os` package's `Stat` and `Lstat` functions use this system call internally.

* **`Fstatat(fd int, path string, stat *Stat_t, flags int) (err error)`:**
    * **Linux Syscall:** `SYS_FSTATAT`
    * **Functionality:** Similar to `Fstat`, but allows specifying a relative path starting from a directory file descriptor. This is useful to avoid race conditions when working with paths.
    * **Go Functionality:**  Used internally by `os` package functions when dealing with relative paths or in scenarios where atomicity is important.

* **`Fstatfs(fd int, buf *Statfs_t) (err error)`:**
    * **Linux Syscall:** `SYS_FSTATFS`
    * **Functionality:**  Retrieves information about a file system, such as free space, total space, and block size, given a file descriptor.
    * **Go Functionality:**  The `syscall` package provides functions like `Statfs` that wrap this system call.

* **`Ftruncate(fd int, length int64) (err error)`:**
    * **Linux Syscall:** `SYS_FTRUNCATE`
    * **Functionality:**  Truncates a file to a specified length, given its file descriptor.
    * **Go Functionality:**  The `os` package's `Truncate` function uses this system call internally when a file descriptor is available.

* **`Getegid() (egid int)`:**
    * **Linux Syscall:** `SYS_GETEGID`
    * **Functionality:**  Gets the effective group ID of the calling process.
    * **Go Functionality:**  The `os` package's `Getegid` function directly wraps this.

* **`Geteuid() (euid int)`:**
    * **Linux Syscall:** `SYS_GETEUID`
    * **Functionality:**  Gets the effective user ID of the calling process.
    * **Go Functionality:**  The `os` package's `Geteuid` function directly wraps this.

* **`Getgid() (gid int)`:**
    * **Linux Syscall:** `SYS_GETGID`
    * **Functionality:**  Gets the real group ID of the calling process.
    * **Go Functionality:**  The `os` package's `Getgid` function directly wraps this.

* **`getrlimit(resource int, rlim *Rlimit) (err error)`:**
    * **Linux Syscall:** `SYS_GETRLIMIT`
    * **Functionality:**  Gets resource limits for the calling process, such as the maximum number of open files.
    * **Go Functionality:** The `syscall` package provides `Getrlimit` to access these limits.

* **`Getuid() (uid int)`:**
    * **Linux Syscall:** `SYS_GETUID`
    * **Functionality:**  Gets the real user ID of the calling process.
    * **Go Functionality:**  The `os` package's `Getuid` function directly wraps this.

* **`Listen(s int, n int) (err error)`:**
    * **Linux Syscall:** `SYS_LISTEN`
    * **Functionality:**  Marks a socket as a passive socket, ready to accept incoming connections.
    * **Go Functionality:**  The `net` package's `Listen` function uses this system call internally when creating TCP or Unix domain socket listeners.

* **`MemfdSecret(flags int) (fd int, err error)`:**
    * **Linux Syscall:** `SYS_MEMFD_SECRET`
    * **Functionality:** Creates a file descriptor to an anonymous memory region that is only accessible to the creating process and is not swapped out to disk. Useful for storing secrets.
    * **Go Functionality:** This is a more specialized system call, likely used by security-sensitive Go applications or libraries that need to manage secrets in memory securely.

* **`pread(fd int, p []byte, offset int64) (n int, err error)`:**
    * **Linux Syscall:** `SYS_PREAD64`
    * **Functionality:**  Reads data from a file descriptor at a specified offset without changing the file offset.
    * **Go Functionality:** The `io` package's `ReadAt` interface and its implementations (like `os.File`) use this system call.

* **`pwrite(fd int, p []byte, offset int64) (n int, err error)`:**
    * **Linux Syscall:** `SYS_PWRITE64`
    * **Functionality:**  Writes data to a file descriptor at a specified offset without changing the file offset.
    * **Go Functionality:** The `io` package's `WriteAt` interface and its implementations use this system call.

* **`Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) (err error)`:**
    * **Linux Syscall:** `SYS_RENAMEAT`
    * **Functionality:** Renames a file, allowing specification of the source and destination directories using file descriptors. This helps avoid race conditions.
    * **Go Functionality:** The `os` package's `Rename` function likely uses this internally, especially when dealing with relative paths or for better atomicity.

* **`Seek(fd int, offset int64, whence int) (off int64, err error)`:**
    * **Linux Syscall:** `SYS_LSEEK`
    * **Functionality:**  Changes the current file offset of a file descriptor.
    * **Go Functionality:** The `io` package's `Seeker` interface and its implementations (like `os.File`) use this system call.

* **`sendfile(outfd int, infd int, offset *int64, count int) (written int, err error)`:**
    * **Linux Syscall:** `SYS_SENDFILE`
    * **Functionality:**  Efficiently copies data between two file descriptors, often used for network transfers. It avoids copying data through userspace.
    * **Go Functionality:** The `net` package might use this for optimized socket communication, especially when serving static files or proxying connections.

* **`setfsgid(gid int) (prev int, err error)`:**
    * **Linux Syscall:** `SYS_SETFSGID`
    * **Functionality:** Sets the filesystem group ID of the calling process. This affects file access permissions.
    * **Go Functionality:**  Used in specialized scenarios where process credentials need to be adjusted for file system operations.

* **`setfsuid(uid int) (prev int, err error)`:**
    * **Linux Syscall:** `SYS_SETFSUID`
    * **Functionality:** Sets the filesystem user ID of the calling process. This affects file access permissions.
    * **Go Functionality:** Used in specialized scenarios where process credentials need to be adjusted for file system operations.

* **`Shutdown(fd int, how int) (err error)`:**
    * **Linux Syscall:** `SYS_SHUTDOWN`
    * **Functionality:**  Shuts down part or all of a full-duplex connection associated with a socket.
    * **Go Functionality:** The `net` package's `Conn.Close()` method for sockets often uses this system call internally.

* **`Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error)`:**
    * **Linux Syscall:** `SYS_SPLICE`
    * **Functionality:**  Moves data between two file descriptors without copying between kernel and userspace. It's a more general version of `tee` and `sendfile`.
    * **Go Functionality:** Potentially used for very efficient data transfer in networking or file processing scenarios.

* **`Statfs(path string, buf *Statfs_t) (err error)`:**
    * **Linux Syscall:** `SYS_STATFS`
    * **Functionality:** Retrieves information about a file system, such as free space, total space, and block size, given a path.
    * **Go Functionality:** The `syscall` package provides the `Statfs` function.

* **`SyncFileRange(fd int, off int64, n int64, flags int) (err error)`:**
    * **Linux Syscall:** `SYS_SYNC_FILE_RANGE`
    * **Functionality:**  Synchronizes a specific range of a file to disk. This provides more control over data persistence than a simple `sync()`.
    * **Go Functionality:** Used in applications that need fine-grained control over data flushing to disk, like databases or critical data writers.

* **`Truncate(path string, length int64) (err error)`:**
    * **Linux Syscall:** `SYS_TRUNCATE`
    * **Functionality:**  Truncates a file to a specified length, given its path.
    * **Go Functionality:** The `os` package's `Truncate` function uses this system call.

* **Socket and Network Related Calls (`accept4`, `bind`, `connect`, `getgroups`, `setgroups`, `getsockopt`, `setsockopt`, `socket`, `socketpair`, `getpeername`, `getsockname`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`):**
    * **Linux Syscalls:** Various `SYS_...` related to networking.
    * **Functionality:** These are fundamental system calls for network programming, covering socket creation, binding to addresses, connecting to remote hosts, setting socket options, sending and receiving data, etc.
    * **Go Functionality:**  The entire `net` package in Go is built upon these system calls. Functions like `net.Listen`, `net.Dial`, `net.Accept`, `net.Conn.Read`, `net.Conn.Write`, and methods for setting socket options ultimately rely on these low-level system calls.

* **`mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error)`:**
    * **Linux Syscall:** `SYS_MMAP`
    * **Functionality:**  Maps a file or device into the address space of the calling process. This allows direct memory access to file contents, which can be very efficient.
    * **Go Functionality:** The `syscall` package provides the `Mmap` function. Used for memory-mapped files and shared memory.

* **`Gettimeofday(tv *Timeval) (err error)`:**
    * **Linux Syscall:** `SYS_GETTIMEOFDAY`
    * **Functionality:**  Gets the current time with microsecond precision.
    * **Go Functionality:**  The `time` package in Go internally uses more modern mechanisms like `clock_gettime`, but older code or specific use cases might still involve this.

* **`kexecFileLoad(kernelFd int, initrdFd int, cmdlineLen int, cmdline string, flags int) (err error)`:**
    * **Linux Syscall:** `SYS_KEXEC_FILE_LOAD`
    * **Functionality:**  Loads a new kernel for execution. This is typically used by bootloaders or system management tools.
    * **Go Functionality:** This is a very low-level system call, rarely used directly in typical Go applications. It would be used by systems-level software.

**Illustrative Go Code Example (Using `Fstat`):**

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	fileInfo, err := os.Stat("my_file.txt") // High-level Go function
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	statT, ok := fileInfo.Sys().(*syscall.Stat_t) // Accessing the underlying syscall.Stat_t
	if !ok {
		fmt.Println("Could not get syscall.Stat_t")
		return
	}

	fmt.Printf("File Size (from os.Stat): %d bytes\n", fileInfo.Size())
	fmt.Printf("File Size (from syscall.Stat_t): %d bytes\n", statT.Size)

	// Using the low-level Fstat directly (requires opening the file)
	file, err := os.Open("my_file.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	var rawStat syscall.Stat_t
	err = syscall.Fstat(int(file.Fd()), &rawStat) // Calling the low-level Fstat
	if err != nil {
		fmt.Println("Error from Fstat:", err)
		return
	}
	fmt.Printf("File Size (from syscall.Fstat): %d bytes\n", rawStat.Size)
}
```

**Assumptions for the Example:**

* A file named "my_file.txt" exists in the same directory.

**Output of the Example:**

The output would show the file size obtained using both the high-level `os.Stat` and the low-level `syscall.Fstat`, demonstrating how the higher-level functions utilize the underlying system calls.

**Command-Line Parameter Handling:**

This specific code snippet doesn't directly handle command-line parameters. The comment `// go run mksyscall.go -tags linux,arm64 syscall_linux.go syscall_linux_arm64.go` shows how this file is *generated*. The `mksyscall.go` program takes arguments:

* `-tags linux,arm64`:  Build tags specifying the target operating system and architecture.
* `syscall_linux.go`:  Likely contains the definitions of the system call numbers (e.g., `SYS_FSTAT`) and potentially some shared structures.
* `syscall_linux_arm64.go`: The output file where the generated Go bindings are written.

The `mksyscall.go` tool parses the `syscall_linux.go` file and, based on the target architecture, generates the architecture-specific `zsyscall_...go` file.

**Common Mistakes for Users:**

* **Incorrectly using `unsafe.Pointer`:** Many of these functions involve `unsafe.Pointer`. Incorrect usage, such as passing pointers to stack-allocated variables that go out of scope, or incorrect casting, can lead to crashes or memory corruption.
    ```go
    // Incorrect: Passing a pointer to a local variable that might not live long enough
    func badExample() {
        var buffer [1024]byte
        n, err := syscall.Read(fd, buffer[:]) // Higher-level, safer
        // syscall.recvfrom(fd, unsafe.Pointer(&buffer[0]), ...) // Lower-level, requires careful management
        _ = n
        _ = err
    }
    ```
* **Ignoring Error Handling:** System calls can fail. Always check the `err` return value.
    ```go
    fd, err := syscall.Open("nonexistent_file.txt", syscall.O_RDONLY, 0)
    if err != nil {
        fmt.Println("Error opening file:", err) // Important to handle the error
        return
    }
    defer syscall.Close(fd)
    ```
* **Assuming Cross-Platform Compatibility:**  Functions in this file are specific to Linux on ARM64. Code using these directly will not be portable to other operating systems or architectures. Use the higher-level abstractions in the standard library (`os`, `io`, `net`) for portable code.
* **Incorrectly interpreting return values:**  Pay close attention to the meaning of return values (e.g., the number of bytes read/written, file descriptors).

In summary, this file provides the raw interface to interact with the Linux kernel on ARM64. While powerful, direct use of these functions requires a good understanding of operating system concepts and careful attention to memory management and error handling. Higher-level Go packages build upon these primitives to provide safer and more portable abstractions.

### 提示词
```
这是路径为go/src/cmd/vendor/golang.org/x/sys/unix/zsyscall_linux_arm64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// go run mksyscall.go -tags linux,arm64 syscall_linux.go syscall_linux_arm64.go
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build linux && arm64

package unix

import (
	"syscall"
	"unsafe"
)

var _ syscall.Errno

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fanotifyMark(fd int, flags uint, mask uint64, dirFd int, pathname *byte) (err error) {
	_, _, e1 := Syscall6(SYS_FANOTIFY_MARK, uintptr(fd), uintptr(flags), uintptr(mask), uintptr(dirFd), uintptr(unsafe.Pointer(pathname)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fallocate(fd int, mode uint32, off int64, len int64) (err error) {
	_, _, e1 := Syscall6(SYS_FALLOCATE, uintptr(fd), uintptr(mode), uintptr(off), uintptr(len), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Tee(rfd int, wfd int, len int, flags int) (n int64, err error) {
	r0, _, e1 := Syscall6(SYS_TEE, uintptr(rfd), uintptr(wfd), uintptr(len), uintptr(flags), 0, 0)
	n = int64(r0)
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
	r0, _, e1 := Syscall6(SYS_EPOLL_PWAIT, uintptr(epfd), uintptr(_p0), uintptr(len(events)), uintptr(msec), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fadvise(fd int, offset int64, length int64, advice int) (err error) {
	_, _, e1 := Syscall6(SYS_FADVISE64, uintptr(fd), uintptr(offset), uintptr(length), uintptr(advice), 0, 0)
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

func Fstatfs(fd int, buf *Statfs_t) (err error) {
	_, _, e1 := Syscall(SYS_FSTATFS, uintptr(fd), uintptr(unsafe.Pointer(buf)), 0)
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

func getrlimit(resource int, rlim *Rlimit) (err error) {
	_, _, e1 := RawSyscall(SYS_GETRLIMIT, uintptr(resource), uintptr(unsafe.Pointer(rlim)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _ := RawSyscallNoError(SYS_GETUID, 0, 0, 0)
	uid = int(r0)
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

func MemfdSecret(flags int) (fd int, err error) {
	r0, _, e1 := Syscall(SYS_MEMFD_SECRET, uintptr(flags), 0, 0)
	fd = int(r0)
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
	r0, _, e1 := Syscall6(SYS_PREAD64, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), 0, 0)
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
	r0, _, e1 := Syscall6(SYS_PWRITE64, uintptr(fd), uintptr(_p0), uintptr(len(p)), uintptr(offset), 0, 0)
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

func Seek(fd int, offset int64, whence int) (off int64, err error) {
	r0, _, e1 := Syscall(SYS_LSEEK, uintptr(fd), uintptr(offset), uintptr(whence))
	off = int64(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	r0, _, e1 := Syscall6(SYS_SENDFILE, uintptr(outfd), uintptr(infd), uintptr(unsafe.Pointer(offset)), uintptr(count), 0, 0)
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

func Splice(rfd int, roff *int64, wfd int, woff *int64, len int, flags int) (n int64, err error) {
	r0, _, e1 := Syscall6(SYS_SPLICE, uintptr(rfd), uintptr(unsafe.Pointer(roff)), uintptr(wfd), uintptr(unsafe.Pointer(woff)), uintptr(len), uintptr(flags))
	n = int64(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Statfs(path string, buf *Statfs_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := Syscall(SYS_STATFS, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(buf)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func SyncFileRange(fd int, off int64, n int64, flags int) (err error) {
	_, _, e1 := Syscall6(SYS_SYNC_FILE_RANGE, uintptr(fd), uintptr(off), uintptr(n), uintptr(flags), 0, 0)
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

func mmap(addr uintptr, length uintptr, prot int, flags int, fd int, offset int64) (xaddr uintptr, err error) {
	r0, _, e1 := Syscall6(SYS_MMAP, uintptr(addr), uintptr(length), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset))
	xaddr = uintptr(r0)
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

func kexecFileLoad(kernelFd int, initrdFd int, cmdlineLen int, cmdline string, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(cmdline)
	if err != nil {
		return
	}
	_, _, e1 := Syscall6(SYS_KEXEC_FILE_LOAD, uintptr(kernelFd), uintptr(initrdFd), uintptr(cmdlineLen), uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}
```