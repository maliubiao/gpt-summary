Response:
Let's break down the thought process for answering the request about `zsyscall_aix_ppc64.go`.

**1. Understanding the Core Question:**

The central task is to explain the *functionality* of the provided Go code snippet. The prompt also asks for deeper insights like what Go feature it implements, examples, command-line handling (if applicable), and common pitfalls. Finally, it specifically asks for a summary of the functionality for this first part.

**2. Initial Analysis - What is this file?**

The filename `zsyscall_aix_ppc64.go` and the build constraint `//go:build aix && ppc64` immediately tell us this is a platform-specific file. Specifically, it's for the AIX operating system running on the ppc64 architecture. The `syscall` package name is a strong indicator it deals with system calls.

**3. Dissecting the Code - The `//go:cgo_import_dynamic` Lines:**

These lines are the most important part for understanding the file's function. The pattern is clear:

```go
//go:cgo_import_dynamic libc_fcntl fcntl "libc.a/shr_64.o"
```

This syntax signifies that the Go code is importing functions dynamically from the shared library `libc.a/shr_64.o`. `libc_fcntl` is the internal Go name for the imported function, `fcntl` is the name of the function in the C library, and `"libc.a/shr_64.o"` specifies the library to load from.

*Key Inference:* This file is a bridge between Go code and the C standard library (`libc`) on AIX/ppc64. It allows Go programs to directly invoke C functions related to system operations.

**4. Identifying the Imported Functions:**

Scanning the list of `//go:cgo_import_dynamic` lines reveals a wide range of standard POSIX system calls and C library functions. These include:

* **File I/O:** `fcntl`, `open`, `close`, `read`, `write`, `pread`, `pwrite`, `lseek`, `truncate`, `ftruncate`, `dup`, `dup2`, `link`, `unlink`, `rename`, `mkdir`, `rmdir`, `stat`, `fstat`, `lstat`, `symlink`, `readlink`
* **Process Management:** `fork` (implied, though not directly listed - will need to verify if present in part 2 or elsewhere), `execve` (implied), `wait4`, `kill`, `getpid`, `getppid`, `getuid`, `geteuid`, `getgid`, `getegid`, `setuid`, `seteuid`, `setgid`, `setegid`, `getpriority`, `setpriority`, `getrlimit`, `setrlimit`, `acct`, `reboot`, `chroot`
* **Directory and File System Operations:** `chdir`, `fchdir`, `chmod`, `fchmod`, `chown`, `fchown`, `lchown`, `umask`, `pathconf`, `fpathconf`, `statfs`, `fstatfs`, `utimes`, `utimensat`, `unlinkat`, `mkdirat`, `mknodat`, `renameat`, `faccessat`
* **Networking:** `socket`, `bind`, `connect`, `listen`, `accept`, `sendto`, `recvfrom`, `getsockopt`, `setsockopt`, `getpeername`, `getsockname`, `shutdown`, `socketpair`, `nrecvmsg`, `nsendmsg`
* **Memory Management:** `mmap`, `munmap`
* **Time:** `gettimeofday`
* **Groups:** `getgroups`, `setgroups`
* **Other:** `ptrace64`, `getdirent`, `getkerninfo`, `uname`, `writev`

**5. Understanding the `//go:linkname` Directives:**

These lines, like `//go:linkname libc_fcntl libc_fcntl`, essentially alias the Go identifier (`libc_fcntl`) to itself. While seemingly redundant *in this specific context*, they are crucial when the Go name differs from the C function name. In this generated code, they serve as a way to explicitly map the Go variable name (holding the function pointer) to the imported symbol.

**6. Analyzing the Function Wrappers:**

The code then defines Go functions like `fcntl(fd int, cmd int, arg int) (val int, err error)`. These functions act as thin wrappers around the dynamically loaded C functions.

*Key Mechanism:*  The `syscall6` (and `rawSyscall6`) function is the core of the system call invocation. It takes the function pointer (obtained from the dynamic import), the number of arguments, and the arguments themselves. It then executes the system call and returns the results, including any error information.

**7. Inferring the Go Feature:**

Based on the above analysis, the primary Go feature being implemented here is **access to operating system system calls**. The `syscall` package is designed to provide this low-level interface. The use of `cgo` with dynamic linking allows Go to interact with pre-compiled C code in a way that's efficient and doesn't require recompiling the C library.

**8. Constructing an Example (fcntl):**

To illustrate how this is used, an example using `fcntl` to set a file descriptor to non-blocking mode is a good choice, as it's a common use case. The example should demonstrate the interaction between the Go `syscall` package and the underlying C function.

**9. Considering Command-Line Arguments:**

In this specific code snippet, there's no direct handling of command-line arguments. This file is about low-level system calls, not application-level argument parsing. So, the answer correctly states this.

**10. Identifying Potential Pitfalls:**

Working directly with system calls can be error-prone. Common issues include:

* **Incorrect Error Handling:**  Forgetting to check the `err` return value.
* **Data Type Mismatches:**  Passing incorrect data types or sizes between Go and C.
* **Platform Differences:**  System calls and their arguments can vary across operating systems.
* **Security Risks:**  Incorrectly using system calls can lead to vulnerabilities.
* **Understanding Errno:**  The `errnoErr` function is important for translating C-style error codes into Go errors.

**11. Summarizing the Functionality for Part 1:**

The summary needs to be concise and capture the essence of the file's purpose. It should highlight the bridging role between Go and the AIX libc.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Is this just a listing of system calls?
* **Correction:** No, it's *importing* and providing Go wrappers for these system calls. The `//go:cgo_import_dynamic` lines are the key.
* **Initial thought:** Does it handle signals?
* **Correction:** While `kill` is present, signal *handling* is a higher-level concept usually dealt with in the `os/signal` package. This file provides the basic mechanism to send signals.
* **Double-checking:**  Are all these functions actually *system calls*? Some, like `getcwd`, are C library functions, but still part of the low-level operating system interface. The `syscall` package often includes these as well.

By following this detailed analysis and refinement process, we can generate a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下你提供的这段 Go 语言代码。

**功能归纳：**

这段代码的主要功能是**为 Go 语言的 `syscall` 包提供在 AIX (操作系统) 和 ppc64 (处理器架构) 平台上的系统调用接口。**

具体来说，它做了以下几件事情：

1. **声明构建约束：**  `//go:build aix && ppc64` 表明此文件仅在 `aix` 和 `ppc64` 标签同时满足时才会被编译。这确保了代码的平台特定性。
2. **导入 `unsafe` 包：** `import "unsafe"` 表明代码中会涉及到不安全的操作，通常用于与 C 代码进行交互。
3. **动态导入 C 库函数：**  大量的 `//go:cgo_import_dynamic` 指令是核心。这些指令指示 `cgo` 工具从 AIX 系统上的共享库 `libc.a/shr_64.o` 中动态加载指定的 C 函数。
    *  `libc_fcntl fcntl "libc.a/shr_64.o"`  例如，这行代码声明了一个名为 `libc_fcntl` 的 Go 变量（类型为 `libcFunc`），并将其链接到 C 库中名为 `fcntl` 的函数。
    *  列出的函数包括各种常见的 POSIX 系统调用，例如文件操作 (`fcntl`, `open`, `read`, `write`, `close`)、进程管理 (`fork` (虽然这里没直接列出，但通常 syscall 包会涉及), `execve` (同上), `wait4`, `kill`)、网络编程 (`socket`, `bind`, `connect`, `accept`) 等等。
4. **声明 C 函数的 Go 表示：**  `type libcFunc uintptr` 定义了一个类型 `libcFunc`，它本质上是一个指向 C 函数的指针。
5. **声明用于存储 C 函数地址的 Go 变量：** `var (...) libcFunc` 声明了一系列变量，每个变量对应一个动态导入的 C 函数。这些变量将在运行时存储 C 函数的地址。
6. **定义 Go 包装函数：**  对于每个动态导入的 C 函数，代码都定义了一个相应的 Go 函数作为包装。
    *  例如，`func fcntl(fd int, cmd int, arg int) (val int, err error) { ... }` 是对 C 函数 `fcntl` 的一个 Go 包装。
    *  这些包装函数使用 `syscall6` 或 `rawSyscall6` 函数来实际调用底层的 C 函数。
    *  `unsafe.Pointer(&libc_fcntl)`  获取动态加载的 `fcntl` 函数的地址。
    *  `syscall6(..., uintptr(fd), uintptr(cmd), uintptr(arg), ...)`  将 Go 的参数转换为 `uintptr` 并传递给底层的系统调用函数。
    *  如果 C 函数调用返回错误（`e1 != 0`），则将错误码转换为 Go 的 `error` 类型。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 Go 语言中 **`syscall` 包** 的一部分实现。`syscall` 包提供了对底层操作系统系统调用的访问能力。在不同的操作系统和处理器架构上，系统调用的实现细节是不同的，因此 `syscall` 包需要针对每个平台提供特定的实现。

**Go 代码举例说明：**

假设你想在 AIX/ppc64 上使用 `fcntl` 系统调用来获取一个文件描述符的标志：

```go
package main

import (
	"fmt"
	"os"
	"syscall"
)

func main() {
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	fd := int(file.Fd()) // 获取文件描述符

	// 获取文件描述符标志
	flags, err := syscall.Fcntl(fd, syscall.F_GETFL, 0)
	if err != nil {
		fmt.Println("Error getting file flags:", err)
		return
	}

	fmt.Printf("File flags for test.txt: %o\n", flags)

	// 假设要设置文件描述符为非阻塞模式
	newFlags := flags | syscall.O_NONBLOCK
	_, err = syscall.Fcntl(fd, syscall.F_SETFL, newFlags)
	if err != nil {
		fmt.Println("Error setting file flags:", err)
		return
	}

	fmt.Println("File set to non-blocking mode.")
}
```

**假设的输入与输出：**

假设 `test.txt` 文件存在，并且其初始的文件描述符标志（可以通过 `stat` 命令查看）为 `0` (只读模式)。

* **输入:** 运行上述 Go 程序。
* **输出:**
  ```
  File flags for test.txt: 0
  File set to non-blocking mode.
  ```

**代码推理：**

1. `os.Open("test.txt")` 会打开文件，并返回一个 `os.File` 对象。
2. `file.Fd()` 获取该文件的文件描述符，类型为 `uintptr`，需要转换为 `int`。
3. `syscall.Fcntl(fd, syscall.F_GETFL, 0)` 调用 `syscall` 包提供的 `Fcntl` 函数，实际上会调用 `zsyscall_aix_ppc64.go` 中定义的 `fcntl` 包装函数，最终执行 AIX 系统的 `fcntl` 系统调用，传递 `F_GETFL` 命令来获取文件描述符的标志。
4. 返回的 `flags` 是一个整数，表示文件描述符的标志。
5. `syscall.Fcntl(fd, syscall.F_SETFL, newFlags)` 再次调用 `Fcntl`，这次传递 `F_SETFL` 命令和新的标志（加上了 `syscall.O_NONBLOCK`）来设置文件描述符为非阻塞模式。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。它提供的只是系统调用的底层接口。 命令行参数的处理通常在 `main` 函数中使用 `os.Args` 或 `flag` 包进行。

**使用者易犯错的点：**

1. **错误处理不足：**  调用 `syscall` 包中的函数，务必检查返回的 `error` 值。系统调用很容易失败，例如文件不存在、权限不足等。忽略错误可能导致程序行为异常。
   ```go
   _, err := syscall.Open("nonexistent.txt", syscall.O_RDONLY, 0)
   if err != nil { // 必须检查 err
       fmt.Println("Error opening file:", err)
   }
   ```
2. **平台差异性理解不足：** 不同的操作系统，甚至同一操作系统的不同版本，系统调用的编号、参数和行为可能存在差异。直接使用 `syscall` 包需要了解目标平台的系统调用规范。
3. **不安全操作的风险：** `syscall` 包涉及 `unsafe` 操作，如果使用不当，可能导致内存错误、程序崩溃甚至安全漏洞。例如，不正确地使用指针或分配内存。
4. **常量值的理解：** `syscall` 包中定义了很多与系统调用相关的常量（例如 `syscall.O_RDONLY`, `syscall.F_GETFL`）。需要查阅相关文档理解这些常量的含义。
5. **结构体定义：** 一些系统调用需要传递特定的结构体作为参数（例如 `stat` 系统调用需要传递 `syscall.Stat_t` 结构体）。需要确保结构体的定义与目标平台一致。

**这段代码的功能归纳（针对第1部分）：**

这段 Go 语言代码是 `syscall` 包在 AIX/ppc64 平台上的底层实现。它通过 `cgo` 机制动态链接到 AIX 的 C 标准库，并为一系列常用的 POSIX 系统调用提供了 Go 语言的包装函数。这使得 Go 程序能够在 AIX/ppc64 系统上执行底层的操作系统操作，例如文件操作、进程管理和网络编程。

Prompt: 
```
这是路径为go/src/syscall/zsyscall_aix_ppc64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksyscall_libc.pl -aix -tags aix,ppc64 syscall_aix.go syscall_aix_ppc64.go
// Code generated by the command above; DO NOT EDIT.

//go:build aix && ppc64

package syscall

import "unsafe"

//go:cgo_import_dynamic libc_fcntl fcntl "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Dup2 dup2 "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_pipe pipe "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_readlink readlink "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_utimes utimes "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_utimensat utimensat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_unlinkat unlinkat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_getcwd getcwd "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_getgroups getgroups "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_setgroups setgroups "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_getdirent getdirent "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_wait4 wait4 "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_fsync_range fsync_range "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_bind bind "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_connect connect "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getkerninfo getkerninfo "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_getsockopt getsockopt "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Listen listen "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_setsockopt setsockopt "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_socket socket "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_socketpair socketpair "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_getpeername getpeername "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_getsockname getsockname "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_recvfrom recvfrom "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_sendto sendto "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Shutdown shutdown "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_nrecvmsg nrecvmsg "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_nsendmsg nsendmsg "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_accept accept "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Openat openat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_ptrace64 ptrace64 "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Acct acct "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Chdir chdir "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Chmod chmod "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Chown chown "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Chroot chroot "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Close close "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Dup dup "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Faccessat faccessat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fchdir fchdir "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fchmod fchmod "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fchmodat fchmodat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fchown fchown "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fchownat fchownat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fpathconf fpathconf "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fstat fstat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Fstatfs fstatfs "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Ftruncate ftruncate "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getgid getgid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getpid getpid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Geteuid geteuid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getegid getegid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getppid getppid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getpriority getpriority "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getrlimit getrlimit "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getrusage getrusage "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Getuid getuid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Kill kill "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Lchown lchown "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Link link "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Lstat lstat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Mkdir mkdir "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Mkdirat mkdirat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Mknodat mknodat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Open open "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_pread pread "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_pwrite pwrite "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_read read "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Reboot reboot "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Rename rename "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Renameat renameat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Rmdir rmdir "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_lseek lseek "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setegid setegid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Seteuid seteuid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setgid setgid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setuid setuid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setpgid setpgid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setpriority setpriority "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setregid setregid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Setreuid setreuid "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_setrlimit setrlimit "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Stat stat "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Statfs statfs "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Symlink symlink "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Truncate truncate "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Umask umask "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Unlink unlink "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_Uname uname "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_write write "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_writev writev "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_gettimeofday gettimeofday "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_mmap mmap "libc.a/shr_64.o"
//go:cgo_import_dynamic libc_munmap munmap "libc.a/shr_64.o"

//go:linkname libc_fcntl libc_fcntl
//go:linkname libc_Dup2 libc_Dup2
//go:linkname libc_pipe libc_pipe
//go:linkname libc_readlink libc_readlink
//go:linkname libc_utimes libc_utimes
//go:linkname libc_utimensat libc_utimensat
//go:linkname libc_unlinkat libc_unlinkat
//go:linkname libc_getcwd libc_getcwd
//go:linkname libc_getgroups libc_getgroups
//go:linkname libc_setgroups libc_setgroups
//go:linkname libc_getdirent libc_getdirent
//go:linkname libc_wait4 libc_wait4
//go:linkname libc_fsync_range libc_fsync_range
//go:linkname libc_bind libc_bind
//go:linkname libc_connect libc_connect
//go:linkname libc_Getkerninfo libc_Getkerninfo
//go:linkname libc_getsockopt libc_getsockopt
//go:linkname libc_Listen libc_Listen
//go:linkname libc_setsockopt libc_setsockopt
//go:linkname libc_socket libc_socket
//go:linkname libc_socketpair libc_socketpair
//go:linkname libc_getpeername libc_getpeername
//go:linkname libc_getsockname libc_getsockname
//go:linkname libc_recvfrom libc_recvfrom
//go:linkname libc_sendto libc_sendto
//go:linkname libc_Shutdown libc_Shutdown
//go:linkname libc_nrecvmsg libc_nrecvmsg
//go:linkname libc_nsendmsg libc_nsendmsg
//go:linkname libc_accept libc_accept
//go:linkname libc_Openat libc_Openat
//go:linkname libc_ptrace64 libc_ptrace64
//go:linkname libc_Acct libc_Acct
//go:linkname libc_Chdir libc_Chdir
//go:linkname libc_Chmod libc_Chmod
//go:linkname libc_Chown libc_Chown
//go:linkname libc_Chroot libc_Chroot
//go:linkname libc_Close libc_Close
//go:linkname libc_Dup libc_Dup
//go:linkname libc_Faccessat libc_Faccessat
//go:linkname libc_Fchdir libc_Fchdir
//go:linkname libc_Fchmod libc_Fchmod
//go:linkname libc_Fchmodat libc_Fchmodat
//go:linkname libc_Fchown libc_Fchown
//go:linkname libc_Fchownat libc_Fchownat
//go:linkname libc_Fpathconf libc_Fpathconf
//go:linkname libc_Fstat libc_Fstat
//go:linkname libc_Fstatfs libc_Fstatfs
//go:linkname libc_Ftruncate libc_Ftruncate
//go:linkname libc_Getgid libc_Getgid
//go:linkname libc_Getpid libc_Getpid
//go:linkname libc_Geteuid libc_Geteuid
//go:linkname libc_Getegid libc_Getegid
//go:linkname libc_Getppid libc_Getppid
//go:linkname libc_Getpriority libc_Getpriority
//go:linkname libc_Getrlimit libc_Getrlimit
//go:linkname libc_Getrusage libc_Getrusage
//go:linkname libc_Getuid libc_Getuid
//go:linkname libc_Kill libc_Kill
//go:linkname libc_Lchown libc_Lchown
//go:linkname libc_Link libc_Link
//go:linkname libc_Lstat libc_Lstat
//go:linkname libc_Mkdir libc_Mkdir
//go:linkname libc_Mkdirat libc_Mkdirat
//go:linkname libc_Mknodat libc_Mknodat
//go:linkname libc_Open libc_Open
//go:linkname libc_pread libc_pread
//go:linkname libc_pwrite libc_pwrite
//go:linkname libc_read libc_read
//go:linkname libc_Reboot libc_Reboot
//go:linkname libc_Rename libc_Rename
//go:linkname libc_Renameat libc_Renameat
//go:linkname libc_Rmdir libc_Rmdir
//go:linkname libc_lseek libc_lseek
//go:linkname libc_Setegid libc_Setegid
//go:linkname libc_Seteuid libc_Seteuid
//go:linkname libc_Setgid libc_Setgid
//go:linkname libc_Setuid libc_Setuid
//go:linkname libc_Setpgid libc_Setpgid
//go:linkname libc_Setpriority libc_Setpriority
//go:linkname libc_Setregid libc_Setregid
//go:linkname libc_Setreuid libc_Setreuid
//go:linkname libc_setrlimit libc_setrlimit
//go:linkname libc_Stat libc_Stat
//go:linkname libc_Statfs libc_Statfs
//go:linkname libc_Symlink libc_Symlink
//go:linkname libc_Truncate libc_Truncate
//go:linkname libc_Umask libc_Umask
//go:linkname libc_Unlink libc_Unlink
//go:linkname libc_Uname libc_Uname
//go:linkname libc_write libc_write
//go:linkname libc_writev libc_writev
//go:linkname libc_gettimeofday libc_gettimeofday
//go:linkname libc_mmap libc_mmap
//go:linkname libc_munmap libc_munmap

type libcFunc uintptr

var (
	libc_fcntl,
	libc_Dup2,
	libc_pipe,
	libc_readlink,
	libc_utimes,
	libc_utimensat,
	libc_unlinkat,
	libc_getcwd,
	libc_getgroups,
	libc_setgroups,
	libc_getdirent,
	libc_wait4,
	libc_fsync_range,
	libc_bind,
	libc_connect,
	libc_Getkerninfo,
	libc_getsockopt,
	libc_Listen,
	libc_setsockopt,
	libc_socket,
	libc_socketpair,
	libc_getpeername,
	libc_getsockname,
	libc_recvfrom,
	libc_sendto,
	libc_Shutdown,
	libc_nrecvmsg,
	libc_nsendmsg,
	libc_accept,
	libc_Openat,
	libc_ptrace64,
	libc_Acct,
	libc_Chdir,
	libc_Chmod,
	libc_Chown,
	libc_Chroot,
	libc_Close,
	libc_Dup,
	libc_Faccessat,
	libc_Fchdir,
	libc_Fchmod,
	libc_Fchmodat,
	libc_Fchown,
	libc_Fchownat,
	libc_Fpathconf,
	libc_Fstat,
	libc_Fstatfs,
	libc_Ftruncate,
	libc_Getgid,
	libc_Getpid,
	libc_Geteuid,
	libc_Getegid,
	libc_Getppid,
	libc_Getpriority,
	libc_Getrlimit,
	libc_Getrusage,
	libc_Getuid,
	libc_Kill,
	libc_Lchown,
	libc_Link,
	libc_Lstat,
	libc_Mkdir,
	libc_Mkdirat,
	libc_Mknodat,
	libc_Open,
	libc_pread,
	libc_pwrite,
	libc_read,
	libc_Reboot,
	libc_Rename,
	libc_Renameat,
	libc_Rmdir,
	libc_lseek,
	libc_Setegid,
	libc_Seteuid,
	libc_Setgid,
	libc_Setuid,
	libc_Setpgid,
	libc_Setpriority,
	libc_Setregid,
	libc_Setreuid,
	libc_setrlimit,
	libc_Stat,
	libc_Statfs,
	libc_Symlink,
	libc_Truncate,
	libc_Umask,
	libc_Unlink,
	libc_Uname,
	libc_write,
	libc_writev,
	libc_gettimeofday,
	libc_mmap,
	libc_munmap libcFunc
)

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_fcntl)), 3, uintptr(fd), uintptr(cmd), uintptr(arg), 0, 0, 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup2(old int, new int) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Dup2)), 2, uintptr(old), uintptr(new), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pipe(p *[2]_C_int) (err error) {
	_, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_pipe)), 1, uintptr(unsafe.Pointer(p)), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func readlink(path string, buf []byte, bufSize uint64) (n int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	if len(buf) > 0 {
		_p1 = &buf[0]
	}
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_readlink)), 4, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(len(buf)), uintptr(bufSize), 0, 0)
	n = int(r0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_utimes)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)), 0, 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_utimensat)), 4, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)), uintptr(flag), 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_unlinkat)), 3, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(flags), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getcwd(buf *byte, size uint64) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_getcwd)), 2, uintptr(unsafe.Pointer(buf)), uintptr(size), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getgroups(ngid int, gid *_Gid_t) (n int, err error) {
	r0, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_getgroups)), 2, uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0, 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setgroups(ngid int, gid *_Gid_t) (err error) {
	_, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_setgroups)), 2, uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getdirent(fd int, buf []byte) (n int, err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_getdirent)), 3, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func wait4(pid _Pid_t, status *_C_int, options int, rusage *Rusage) (wpid _Pid_t, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_wait4)), 4, uintptr(pid), uintptr(unsafe.Pointer(status)), uintptr(options), uintptr(unsafe.Pointer(rusage)), 0, 0)
	wpid = _Pid_t(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fsyncRange(fd int, how int, start int64, length int64) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_fsync_range)), 4, uintptr(fd), uintptr(how), uintptr(start), uintptr(length), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_bind)), 3, uintptr(s), uintptr(addr), uintptr(addrlen), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_connect)), 3, uintptr(s), uintptr(addr), uintptr(addrlen), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getkerninfo(op int32, where uintptr, size uintptr, arg int64) (i int32, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Getkerninfo)), 4, uintptr(op), uintptr(where), uintptr(size), uintptr(arg), 0, 0)
	i = int32(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *_Socklen) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_getsockopt)), 5, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Listen(s int, backlog int) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Listen)), 2, uintptr(s), uintptr(backlog), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_setsockopt)), 5, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socket(domain int, typ int, proto int) (fd int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_socket)), 3, uintptr(domain), uintptr(typ), uintptr(proto), 0, 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func socketpair(domain int, typ int, proto int, fd *[2]int32) (err error) {
	_, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_socketpair)), 4, uintptr(domain), uintptr(typ), uintptr(proto), uintptr(unsafe.Pointer(fd)), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getpeername(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_getpeername)), 3, uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getsockname(fd int, rsa *RawSockaddrAny, addrlen *_Socklen) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_getsockname)), 3, uintptr(fd), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func recvfrom(fd int, p []byte, flags int, from *RawSockaddrAny, fromlen *_Socklen) (n int, err error) {
	var _p0 *byte
	if len(p) > 0 {
		_p0 = &p[0]
	}
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_recvfrom)), 6, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(p)), uintptr(flags), uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(fromlen)))
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendto(s int, buf []byte, flags int, to unsafe.Pointer, addrlen _Socklen) (err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_sendto)), 6, uintptr(s), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(flags), uintptr(to), uintptr(addrlen))
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Shutdown(s int, how int) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Shutdown)), 2, uintptr(s), uintptr(how), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func recvmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_nrecvmsg)), 3, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_nsendmsg)), 3, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_accept)), 3, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), 0, 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Openat)), 4, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(flags), uintptr(mode), 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ptrace64(request int, id int64, addr int64, data int, buff uintptr) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_ptrace64)), 5, uintptr(request), uintptr(id), uintptr(addr), uintptr(data), uintptr(buff), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func ptrace64Ptr(request int, id int64, addr int64, data int, buff unsafe.Pointer) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_ptrace64)), 5, uintptr(request), uintptr(id), uintptr(addr), uintptr(data), uintptr(buff), 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Acct)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Chdir)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chmod(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Chmod)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Chown(path string, uid int, gid int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Chown)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid), 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Chroot)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Close(fd int) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Close)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup(fd int) (nfd int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Dup)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	nfd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Faccessat(dirfd int, path string, mode uint32, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Faccessat)), 4, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchdir(fd int) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fchdir)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchmod(fd int, mode uint32) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fchmod)), 2, uintptr(fd), uintptr(mode), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchmodat(dirfd int, path string, mode uint32, flags int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fchmodat)), 4, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchown(fd int, uid int, gid int) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fchown)), 3, uintptr(fd), uintptr(uid), uintptr(gid), 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fchownat)), 5, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fpathconf(fd int, name int) (val int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fpathconf)), 2, uintptr(fd), uintptr(name), 0, 0, 0, 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstat(fd int, stat *Stat_t) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fstat)), 2, uintptr(fd), uintptr(unsafe.Pointer(stat)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstatfs(fd int, buf *Statfs_t) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Fstatfs)), 2, uintptr(fd), uintptr(unsafe.Pointer(buf)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Ftruncate)), 2, uintptr(fd), uintptr(length), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _, _ := rawSyscall6(uintptr(unsafe.Pointer(&libc_Getgid)), 0, 0, 0, 0, 0, 0, 0)
	gid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpid() (pid int) {
	r0, _, _ := rawSyscall6(uintptr(unsafe.Pointer(&libc_Getpid)), 0, 0, 0, 0, 0, 0, 0)
	pid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (euid int) {
	r0, _, _ := syscall6(uintptr(unsafe.Pointer(&libc_Geteuid)), 0, 0, 0, 0, 0, 0, 0)
	euid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _, _ := syscall6(uintptr(unsafe.Pointer(&libc_Getegid)), 0, 0, 0, 0, 0, 0, 0)
	egid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getppid() (ppid int) {
	r0, _, _ := syscall6(uintptr(unsafe.Pointer(&libc_Getppid)), 0, 0, 0, 0, 0, 0, 0)
	ppid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpriority(which int, who int) (n int, err error) {
	r0, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Getpriority)), 2, uintptr(which), uintptr(who), 0, 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_Getrlimit)), 2, uintptr(which), uintptr(unsafe.Pointer(lim)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrusage(who int, rusage *Rusage) (err error) {
	_, _, e1 := rawSyscall6(uintptr(unsafe.Pointer(&libc_Getrusage)), 2, uintptr(who), uintptr(unsafe.Pointer(rusage)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _, _ := rawSyscall6(uintptr(unsafe.Pointer(&libc_Getuid)), 0, 0, 0, 0, 0, 0, 0)
	uid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kill(pid int, signum Signal) (err error) {
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Kill)), 2, uintptr(pid), uintptr(signum), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Lchown(path string, uid int, gid int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Lchown)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Link(path string, link string) (err error) {
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Link)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0, 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Lstat)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mkdir(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Mkdir)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0, 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Mkdirat)), 3, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0, 0, 0)
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
	_, _, e1 := syscall6(uintptr(unsafe.Pointer(&libc_Mknodat)), 4, uintptr(dirfd), uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(dev), 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

f
"""




```