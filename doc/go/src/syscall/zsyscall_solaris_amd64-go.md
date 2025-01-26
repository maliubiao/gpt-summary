Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The first line `// mksyscall_libc.pl -solaris -tags solaris,amd64 syscall_solaris.go syscall_solaris_amd64.go` is crucial. It tells us this file is *generated* by a Perl script (`mksyscall_libc.pl`). It's specific to the `solaris` operating system and the `amd64` architecture. The `-tags solaris,amd64` further confirms this and suggests the use of build tags.

2. **Identify the Core Mechanism:** The `//go:cgo_import_dynamic` directives are the next key element. These lines are how Go interfaces with C code. Specifically, they are dynamically linking functions from shared libraries (like `libc.so` and `libsocket.so`). The format is `//go:cgo_import_dynamic <go_name> <c_name> <library>`. This establishes a mapping between Go identifiers and C function names.

3. **Recognize the Pattern:**  Notice the repetitive structure: many `//go:cgo_import_dynamic` lines followed by corresponding `//go:linkname` lines and then a list of `libcFunc` variables. This pattern strongly suggests this code is creating Go wrappers around standard C library functions.

4. **Infer Functionality (High-Level):**  Based on the imported functions (e.g., `pipe2`, `accept4`, `getcwd`, `chdir`, `open`, `read`, `write`, etc.), we can deduce that this file provides access to fundamental operating system functionalities on Solaris. These are the basic building blocks for interacting with the file system, processes, and network.

5. **Infer Functionality (Specific Examples):** Look at individual imported functions:
    * `pipe2`:  Likely related to creating pipes for inter-process communication.
    * `accept4`:  Almost certainly for accepting incoming network connections.
    * `getcwd`:  Getting the current working directory.
    * `open`, `read`, `write`:  Fundamental file I/O operations.
    * `mkdir`, `rmdir`:  Directory manipulation.
    * `kill`:  Sending signals to processes.

6. **Understand `go:linkname`:** The `//go:linkname` directives like `//go:linkname libc_pipe2 libc_pipe2` indicate that the Go function named `libc_pipe2` (declared as a `libcFunc`) will be linked to the C function `libc_pipe2`. This is part of the dynamic linking process.

7. **Understand the `libcFunc` Type:**  `type libcFunc uintptr` means `libcFunc` is a type alias for `uintptr`. In this context, it represents the memory address of the dynamically loaded C function.

8. **Analyze the `var` Block:** The `var` block declares variables like `libc_pipe2`, `libc_accept4`, etc., all of type `libcFunc`. These variables will hold the addresses of the corresponding C functions after dynamic linking.

9. **Examine the Go Functions:**  The subsequent Go functions (`pipe2`, `accept4`, `Getcwd`, etc.) are the Go-level wrappers around the C functions. They use `rawSysvicall6` or `sysvicall6` (which are likely lower-level Go functions for making system calls) to invoke the dynamically linked C functions. They handle error conversion from the C world (represented by the `e1` variable) to Go's `error` type using `errnoErr`.

10. **Synthesize the Purpose:** Combining all these observations, the core purpose of this file is to provide a Go interface to standard C system calls on Solaris/amd64. This allows Go programs running on this platform to interact directly with the operating system kernel.

11. **Address Specific Questions (based on the analysis):**
    * **Functionality:** List the types of system calls covered (file system, process, network, etc.).
    * **Go Feature:** Explain that it's about C interoperation using `cgo` and dynamic linking. Provide a simple example demonstrating the use of one of the wrapped functions (like `os.Getwd()`, which internally might use `Getcwd`).
    * **Code Inference:** Point out the `rawSysvicall6` and `sysvicall6` and explain their role in making system calls. Mention the error handling. Hypothesize input/output for a simple function like `Getcwd`.
    * **Command-line Arguments:**  Note that the generation script itself has command-line arguments (`-solaris`, `-tags`). Emphasize that the *generated* code doesn't directly process command-line arguments for the *user*.
    * **Common Mistakes:**  Explain that users typically don't interact with this low-level file directly. Mistakes would occur at a higher level of the Go standard library. Mention potential issues with incorrect usage of pointers or understanding the mapping between Go and C types if someone *were* to interact with this level directly (though it's generally discouraged).
    * **Summary:** Concisely state that it's a low-level interface to C system calls for Solaris/amd64.

12. **Structure the Answer:** Organize the information logically using the prompts as a guide. Use clear and concise language. Provide code examples where requested.

This iterative process of examining the code, identifying patterns, making inferences, and then synthesizing the information leads to a comprehensive understanding of the file's purpose and functionality.
```chinese
这是路径为go/src/syscall/zsyscall_solaris_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

好的，让我们来分析一下 `go/src/syscall/zsyscall_solaris_amd64.go` 的这部分代码。

**功能列举:**

这部分代码的主要功能是：

1. **声明并动态链接Solaris系统调用:** 它使用 `//go:cgo_import_dynamic` 指令，声明了一系列将在运行时动态链接的 C 函数。这些 C 函数来自 Solaris 操作系统上的共享库，例如 `libc.so` 和 `libsocket.so`。这些函数名都是标准的 POSIX 系统调用，如 `pipe2`, `accept4`, `getcwd`, `read`, `write` 等。

2. **创建Go语言对这些系统调用的封装:**  每一行 `//go:cgo_import_dynamic libc_<系统调用名> <系统调用名> "<库名>"` 都声明了一个 Go 变量（例如 `libc_pipe2`）来表示对应的 C 函数地址。

3. **使用 `//go:linkname` 将Go内部函数链接到动态链接的C函数:**  `//go:linkname libc_pipe2 libc_pipe2` 这样的指令将 Go 语言内部使用的函数（很可能在同一个 `syscall` 包的其他文件中定义）与动态加载的 C 函数地址关联起来。

4. **定义 Go 语言的系统调用包装函数:** 在 `var` 声明之后，你会看到一系列的 Go 函数（例如 `pipe2`, `accept4`, `Getcwd` 等）。这些函数是 Go 语言对底层 C 系统调用的封装。它们通常会接收 Go 语言的数据类型作为参数，并将这些参数转换为 C 语言可以理解的格式，然后调用动态链接的 C 函数。

5. **处理系统调用返回的错误:** 这些 Go 封装函数会检查 C 函数的返回值，如果表示有错误发生，则将其转换为 Go 语言的 `error` 类型。

**推理 Go 语言功能实现:**

从代码结构和导入的函数来看，这个文件是 Go 语言 `syscall` 包的一部分，专门负责在 Solaris 操作系统（且架构为 amd64）上提供访问底层操作系统功能的接口。

**具体来说，它实现了 Go 语言的系统调用功能。**  Go 语言的 `os` 包和 `net` 包等标准库在底层会调用 `syscall` 包提供的函数来执行文件操作、进程管理、网络通信等任务。

**Go 代码示例:**

假设你想创建一个管道，在 Go 语言中你会这样做：

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Println("创建管道失败:", err)
		return
	}
	fmt.Println("管道读取端文件描述符:", r.Fd())
	fmt.Println("管道写入端文件描述符:", w.Fd())
	r.Close()
	w.Close()
}
```

**代码推理:**

当我们调用 `os.Pipe()` 时，Go 的标准库内部会调用 `syscall` 包中与创建管道相关的函数。在这个 `zsyscall_solaris_amd64.go` 文件中，很可能最终会调用到名为 `pipe2` 的 Go 函数（对应于 C 的 `pipe2` 系统调用）。

**假设的输入与输出:**

对于 `pipe2` 函数，假设我们调用它：

```go
var p [2]_C_int // _C_int 是 cgo 定义的 C int 类型
flags := 0
err := pipe2(&p, flags)
```

**假设的输入:**
* `p`: 一个未初始化的 `[2]_C_int` 数组的指针。
* `flags`: 整数 0，表示默认行为。

**假设的输出:**
* 如果成功，`err` 将为 `nil`，并且 `p[0]` 和 `p[1]` 将分别包含管道读取端和写入端的文件描述符。
* 如果失败，`err` 将包含一个描述错误的 `error` 对象。

**命令行参数:**

这部分代码本身并不直接处理命令行参数。  命令行参数的处理通常发生在 `main` 函数或者使用 `flag` 标准库的地方。

但是，请注意文件开头的注释：

```
// mksyscall_libc.pl -solaris -tags solaris,amd64 syscall_solaris.go syscall_solaris_amd64.go
```

这表明这个 `zsyscall_solaris_amd64.go` 文件是由一个名为 `mksyscall_libc.pl` 的 Perl 脚本生成的。这个 Perl 脚本在生成代码时使用了 `-solaris` 和 `-tags solaris,amd64` 这样的命令行参数。这些参数告诉脚本要为 Solaris 平台和 amd64 架构生成系统调用相关的代码，并设置相应的构建标签。

**使用者易犯错的点:**

一般的 Go 开发者不太会直接与 `zsyscall_solaris_amd64.go` 这样的底层文件打交道。他们通常会使用 `os`、`net` 等更高级的包。

如果开发者需要使用 `syscall` 包，一个常见的错误是：

1. **不正确地使用指针和类型转换:**  由于涉及到与 C 代码的交互，需要格外注意 Go 和 C 之间数据类型的转换，以及正确地使用指针。例如，传递不正确的指针类型或大小，可能导致程序崩溃或出现未定义的行为。

2. **忽略错误处理:** 系统调用可能会失败，务必检查 `syscall` 函数返回的 `error` 值。

**归纳一下它的功能 (第1部分):**

这部分 `zsyscall_solaris_amd64.go` 代码是 Go 语言 `syscall` 包在 Solaris 操作系统和 amd64 架构下的具体实现。它的核心功能是通过 `cgo` 的动态链接特性，将 Go 语言的函数与 Solaris 系统的 C 语言系统调用关联起来，从而为 Go 程序提供访问底层操作系统功能的桥梁。它定义了与各种系统调用对应的 Go 函数封装，并负责处理系统调用的返回值和错误。
```
Prompt: 
```
这是路径为go/src/syscall/zsyscall_solaris_amd64.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// mksyscall_libc.pl -solaris -tags solaris,amd64 syscall_solaris.go syscall_solaris_amd64.go
// Code generated by the command above; DO NOT EDIT.

//go:build solaris && amd64

package syscall

import "unsafe"

//go:cgo_import_dynamic libc_pipe2 pipe2 "libc.so"
//go:cgo_import_dynamic libc_accept4 accept4 "libsocket.so"
//go:cgo_import_dynamic libc_Getcwd getcwd "libc.so"
//go:cgo_import_dynamic libc_getgroups getgroups "libc.so"
//go:cgo_import_dynamic libc_setgroups setgroups "libc.so"
//go:cgo_import_dynamic libc_fcntl fcntl "libc.so"
//go:cgo_import_dynamic libc_accept accept "libsocket.so"
//go:cgo_import_dynamic libc___xnet_sendmsg __xnet_sendmsg "libsocket.so"
//go:cgo_import_dynamic libc_Access access "libc.so"
//go:cgo_import_dynamic libc_Adjtime adjtime "libc.so"
//go:cgo_import_dynamic libc_Chdir chdir "libc.so"
//go:cgo_import_dynamic libc_Chmod chmod "libc.so"
//go:cgo_import_dynamic libc_Chown chown "libc.so"
//go:cgo_import_dynamic libc_Chroot chroot "libc.so"
//go:cgo_import_dynamic libc_Close close "libc.so"
//go:cgo_import_dynamic libc_Dup dup "libc.so"
//go:cgo_import_dynamic libc_Fchdir fchdir "libc.so"
//go:cgo_import_dynamic libc_Fchmod fchmod "libc.so"
//go:cgo_import_dynamic libc_Fchown fchown "libc.so"
//go:cgo_import_dynamic libc_Fpathconf fpathconf "libc.so"
//go:cgo_import_dynamic libc_Fstat fstat "libc.so"
//go:cgo_import_dynamic libc_Getdents getdents "libc.so"
//go:cgo_import_dynamic libc_Getgid getgid "libc.so"
//go:cgo_import_dynamic libc_Getpid getpid "libc.so"
//go:cgo_import_dynamic libc_Geteuid geteuid "libc.so"
//go:cgo_import_dynamic libc_Getegid getegid "libc.so"
//go:cgo_import_dynamic libc_Getppid getppid "libc.so"
//go:cgo_import_dynamic libc_Getpriority getpriority "libc.so"
//go:cgo_import_dynamic libc_Getrlimit getrlimit "libc.so"
//go:cgo_import_dynamic libc_Getrusage getrusage "libc.so"
//go:cgo_import_dynamic libc_Gettimeofday gettimeofday "libc.so"
//go:cgo_import_dynamic libc_Getuid getuid "libc.so"
//go:cgo_import_dynamic libc_Kill kill "libc.so"
//go:cgo_import_dynamic libc_Lchown lchown "libc.so"
//go:cgo_import_dynamic libc_Link link "libc.so"
//go:cgo_import_dynamic libc___xnet_listen __xnet_listen "libsocket.so"
//go:cgo_import_dynamic libc_Lstat lstat "libc.so"
//go:cgo_import_dynamic libc_Mkdir mkdir "libc.so"
//go:cgo_import_dynamic libc_Mknod mknod "libc.so"
//go:cgo_import_dynamic libc_Nanosleep nanosleep "libc.so"
//go:cgo_import_dynamic libc_Open open "libc.so"
//go:cgo_import_dynamic libc_Pathconf pathconf "libc.so"
//go:cgo_import_dynamic libc_pread pread "libc.so"
//go:cgo_import_dynamic libc_pwrite pwrite "libc.so"
//go:cgo_import_dynamic libc_read read "libc.so"
//go:cgo_import_dynamic libc_Readlink readlink "libc.so"
//go:cgo_import_dynamic libc_Rename rename "libc.so"
//go:cgo_import_dynamic libc_Rmdir rmdir "libc.so"
//go:cgo_import_dynamic libc_lseek lseek "libc.so"
//go:cgo_import_dynamic libc_sendfile sendfile "libsendfile.so"
//go:cgo_import_dynamic libc_Setegid setegid "libc.so"
//go:cgo_import_dynamic libc_Seteuid seteuid "libc.so"
//go:cgo_import_dynamic libc_Setgid setgid "libc.so"
//go:cgo_import_dynamic libc_Setpgid setpgid "libc.so"
//go:cgo_import_dynamic libc_Setpriority setpriority "libc.so"
//go:cgo_import_dynamic libc_Setregid setregid "libc.so"
//go:cgo_import_dynamic libc_Setreuid setreuid "libc.so"
//go:cgo_import_dynamic libc_setrlimit setrlimit "libc.so"
//go:cgo_import_dynamic libc_Setsid setsid "libc.so"
//go:cgo_import_dynamic libc_Setuid setuid "libc.so"
//go:cgo_import_dynamic libc_shutdown shutdown "libsocket.so"
//go:cgo_import_dynamic libc_Stat stat "libc.so"
//go:cgo_import_dynamic libc_Symlink symlink "libc.so"
//go:cgo_import_dynamic libc_Sync sync "libc.so"
//go:cgo_import_dynamic libc_Truncate truncate "libc.so"
//go:cgo_import_dynamic libc_Fsync fsync "libc.so"
//go:cgo_import_dynamic libc_Ftruncate ftruncate "libc.so"
//go:cgo_import_dynamic libc_Umask umask "libc.so"
//go:cgo_import_dynamic libc_Unlink unlink "libc.so"
//go:cgo_import_dynamic libc_utimes utimes "libc.so"
//go:cgo_import_dynamic libc___xnet_bind __xnet_bind "libsocket.so"
//go:cgo_import_dynamic libc___xnet_connect __xnet_connect "libsocket.so"
//go:cgo_import_dynamic libc_mmap mmap "libc.so"
//go:cgo_import_dynamic libc_munmap munmap "libc.so"
//go:cgo_import_dynamic libc___xnet_sendto __xnet_sendto "libsocket.so"
//go:cgo_import_dynamic libc___xnet_socket __xnet_socket "libsocket.so"
//go:cgo_import_dynamic libc___xnet_socketpair __xnet_socketpair "libsocket.so"
//go:cgo_import_dynamic libc_write write "libc.so"
//go:cgo_import_dynamic libc_writev writev "libc.so"
//go:cgo_import_dynamic libc___xnet_getsockopt __xnet_getsockopt "libsocket.so"
//go:cgo_import_dynamic libc_getpeername getpeername "libsocket.so"
//go:cgo_import_dynamic libc_getsockname getsockname "libsocket.so"
//go:cgo_import_dynamic libc_setsockopt setsockopt "libsocket.so"
//go:cgo_import_dynamic libc_recvfrom recvfrom "libsocket.so"
//go:cgo_import_dynamic libc___xnet_recvmsg __xnet_recvmsg "libsocket.so"
//go:cgo_import_dynamic libc_getexecname getexecname "libc.so"
//go:cgo_import_dynamic libc_utimensat utimensat "libc.so"

//go:linkname libc_pipe2 libc_pipe2
//go:linkname libc_accept4 libc_accept4
//go:linkname libc_Getcwd libc_Getcwd
//go:linkname libc_getgroups libc_getgroups
//go:linkname libc_setgroups libc_setgroups
//go:linkname libc_fcntl libc_fcntl
//go:linkname libc_accept libc_accept
//go:linkname libc___xnet_sendmsg libc___xnet_sendmsg
//go:linkname libc_Access libc_Access
//go:linkname libc_Adjtime libc_Adjtime
//go:linkname libc_Chdir libc_Chdir
//go:linkname libc_Chmod libc_Chmod
//go:linkname libc_Chown libc_Chown
//go:linkname libc_Chroot libc_Chroot
//go:linkname libc_Close libc_Close
//go:linkname libc_Dup libc_Dup
//go:linkname libc_Fchdir libc_Fchdir
//go:linkname libc_Fchmod libc_Fchmod
//go:linkname libc_Fchown libc_Fchown
//go:linkname libc_Fpathconf libc_Fpathconf
//go:linkname libc_Fstat libc_Fstat
//go:linkname libc_Getdents libc_Getdents
//go:linkname libc_Getgid libc_Getgid
//go:linkname libc_Getpid libc_Getpid
//go:linkname libc_Geteuid libc_Geteuid
//go:linkname libc_Getegid libc_Getegid
//go:linkname libc_Getppid libc_Getppid
//go:linkname libc_Getpriority libc_Getpriority
//go:linkname libc_Getrlimit libc_Getrlimit
//go:linkname libc_Getrusage libc_Getrusage
//go:linkname libc_Gettimeofday libc_Gettimeofday
//go:linkname libc_Getuid libc_Getuid
//go:linkname libc_Kill libc_Kill
//go:linkname libc_Lchown libc_Lchown
//go:linkname libc_Link libc_Link
//go:linkname libc___xnet_listen libc___xnet_listen
//go:linkname libc_Lstat libc_Lstat
//go:linkname libc_Mkdir libc_Mkdir
//go:linkname libc_Mknod libc_Mknod
//go:linkname libc_Nanosleep libc_Nanosleep
//go:linkname libc_Open libc_Open
//go:linkname libc_Pathconf libc_Pathconf
//go:linkname libc_pread libc_pread
//go:linkname libc_pwrite libc_pwrite
//go:linkname libc_read libc_read
//go:linkname libc_Readlink libc_Readlink
//go:linkname libc_Rename libc_Rename
//go:linkname libc_Rmdir libc_Rmdir
//go:linkname libc_lseek libc_lseek
//go:linkname libc_sendfile libc_sendfile
//go:linkname libc_Setegid libc_Setegid
//go:linkname libc_Seteuid libc_Seteuid
//go:linkname libc_Setgid libc_Setgid
//go:linkname libc_Setpgid libc_Setpgid
//go:linkname libc_Setpriority libc_Setpriority
//go:linkname libc_Setregid libc_Setregid
//go:linkname libc_Setreuid libc_Setreuid
//go:linkname libc_setrlimit libc_setrlimit
//go:linkname libc_Setsid libc_Setsid
//go:linkname libc_Setuid libc_Setuid
//go:linkname libc_shutdown libc_shutdown
//go:linkname libc_Stat libc_Stat
//go:linkname libc_Symlink libc_Symlink
//go:linkname libc_Sync libc_Sync
//go:linkname libc_Truncate libc_Truncate
//go:linkname libc_Fsync libc_Fsync
//go:linkname libc_Ftruncate libc_Ftruncate
//go:linkname libc_Umask libc_Umask
//go:linkname libc_Unlink libc_Unlink
//go:linkname libc_utimes libc_utimes
//go:linkname libc___xnet_bind libc___xnet_bind
//go:linkname libc___xnet_connect libc___xnet_connect
//go:linkname libc_mmap libc_mmap
//go:linkname libc_munmap libc_munmap
//go:linkname libc___xnet_sendto libc___xnet_sendto
//go:linkname libc___xnet_socket libc___xnet_socket
//go:linkname libc___xnet_socketpair libc___xnet_socketpair
//go:linkname libc_write libc_write
//go:linkname libc_writev libc_writev
//go:linkname libc___xnet_getsockopt libc___xnet_getsockopt
//go:linkname libc_getpeername libc_getpeername
//go:linkname libc_getsockname libc_getsockname
//go:linkname libc_setsockopt libc_setsockopt
//go:linkname libc_recvfrom libc_recvfrom
//go:linkname libc___xnet_recvmsg libc___xnet_recvmsg
//go:linkname libc_getexecname libc_getexecname
//go:linkname libc_utimensat libc_utimensat

type libcFunc uintptr

var (
	libc_pipe2,
	libc_accept4,
	libc_Getcwd,
	libc_getgroups,
	libc_setgroups,
	libc_fcntl,
	libc_accept,
	libc___xnet_sendmsg,
	libc_Access,
	libc_Adjtime,
	libc_Chdir,
	libc_Chmod,
	libc_Chown,
	libc_Chroot,
	libc_Close,
	libc_Dup,
	libc_Fchdir,
	libc_Fchmod,
	libc_Fchown,
	libc_Fpathconf,
	libc_Fstat,
	libc_Getdents,
	libc_Getgid,
	libc_Getpid,
	libc_Geteuid,
	libc_Getegid,
	libc_Getppid,
	libc_Getpriority,
	libc_Getrlimit,
	libc_Getrusage,
	libc_Gettimeofday,
	libc_Getuid,
	libc_Kill,
	libc_Lchown,
	libc_Link,
	libc___xnet_listen,
	libc_Lstat,
	libc_Mkdir,
	libc_Mknod,
	libc_Nanosleep,
	libc_Open,
	libc_Pathconf,
	libc_pread,
	libc_pwrite,
	libc_read,
	libc_Readlink,
	libc_Rename,
	libc_Rmdir,
	libc_lseek,
	libc_sendfile,
	libc_Setegid,
	libc_Seteuid,
	libc_Setgid,
	libc_Setpgid,
	libc_Setpriority,
	libc_Setregid,
	libc_Setreuid,
	libc_setrlimit,
	libc_Setsid,
	libc_Setuid,
	libc_shutdown,
	libc_Stat,
	libc_Symlink,
	libc_Sync,
	libc_Truncate,
	libc_Fsync,
	libc_Ftruncate,
	libc_Umask,
	libc_Unlink,
	libc_utimes,
	libc___xnet_bind,
	libc___xnet_connect,
	libc_mmap,
	libc_munmap,
	libc___xnet_sendto,
	libc___xnet_socket,
	libc___xnet_socketpair,
	libc_write,
	libc_writev,
	libc___xnet_getsockopt,
	libc_getpeername,
	libc_getsockname,
	libc_setsockopt,
	libc_recvfrom,
	libc___xnet_recvmsg,
	libc_getexecname,
	libc_utimensat libcFunc
)

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pipe2(p *[2]_C_int, flags int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_pipe2)), 2, uintptr(unsafe.Pointer(p)), uintptr(flags), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept4(s int, rsa *RawSockaddrAny, addrlen *_Socklen, flags int) (fd int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_accept4)), 4, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), uintptr(flags), 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getcwd(buf []byte) (n int, err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Getcwd)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), 0, 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func getgroups(ngid int, gid *_Gid_t) (n int, err error) {
	r0, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_getgroups)), 2, uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0, 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setgroups(ngid int, gid *_Gid_t) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_setgroups)), 2, uintptr(ngid), uintptr(unsafe.Pointer(gid)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_fcntl)), 3, uintptr(fd), uintptr(cmd), uintptr(arg), 0, 0, 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func accept(s int, rsa *RawSockaddrAny, addrlen *_Socklen) (fd int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_accept)), 3, uintptr(s), uintptr(unsafe.Pointer(rsa)), uintptr(unsafe.Pointer(addrlen)), 0, 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendmsg(s int, msg *Msghdr, flags int) (n int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc___xnet_sendmsg)), 3, uintptr(s), uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Access(path string, mode uint32) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Access)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Adjtime(delta *Timeval, olddelta *Timeval) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Adjtime)), 2, uintptr(unsafe.Pointer(delta)), uintptr(unsafe.Pointer(olddelta)), 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Chdir)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Chmod)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Chown)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid), 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Chroot)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Close(fd int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Close)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Dup(fd int) (nfd int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Dup)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	nfd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchdir(fd int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Fchdir)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchmod(fd int, mode uint32) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Fchmod)), 2, uintptr(fd), uintptr(mode), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fchown(fd int, uid int, gid int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Fchown)), 3, uintptr(fd), uintptr(uid), uintptr(gid), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fpathconf(fd int, name int) (val int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Fpathconf)), 2, uintptr(fd), uintptr(name), 0, 0, 0, 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fstat(fd int, stat *Stat_t) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Fstat)), 2, uintptr(fd), uintptr(unsafe.Pointer(stat)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getdents(fd int, buf []byte, basep *uintptr) (n int, err error) {
	var _p0 *byte
	if len(buf) > 0 {
		_p0 = &buf[0]
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Getdents)), 4, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(buf)), uintptr(unsafe.Pointer(basep)), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getgid() (gid int) {
	r0, _, _ := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Getgid)), 0, 0, 0, 0, 0, 0, 0)
	gid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpid() (pid int) {
	r0, _, _ := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Getpid)), 0, 0, 0, 0, 0, 0, 0)
	pid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Geteuid() (euid int) {
	r0, _, _ := sysvicall6(uintptr(unsafe.Pointer(&libc_Geteuid)), 0, 0, 0, 0, 0, 0, 0)
	euid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getegid() (egid int) {
	r0, _, _ := sysvicall6(uintptr(unsafe.Pointer(&libc_Getegid)), 0, 0, 0, 0, 0, 0, 0)
	egid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getppid() (ppid int) {
	r0, _, _ := sysvicall6(uintptr(unsafe.Pointer(&libc_Getppid)), 0, 0, 0, 0, 0, 0, 0)
	ppid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getpriority(which int, who int) (n int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Getpriority)), 2, uintptr(which), uintptr(who), 0, 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Getrlimit)), 2, uintptr(which), uintptr(unsafe.Pointer(lim)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getrusage(who int, rusage *Rusage) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Getrusage)), 2, uintptr(who), uintptr(unsafe.Pointer(rusage)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Gettimeofday(tv *Timeval) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Gettimeofday)), 1, uintptr(unsafe.Pointer(tv)), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Getuid() (uid int) {
	r0, _, _ := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Getuid)), 0, 0, 0, 0, 0, 0, 0)
	uid = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Kill(pid int, signum Signal) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Kill)), 2, uintptr(pid), uintptr(signum), 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Lchown)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(uid), uintptr(gid), 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Link)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Listen(s int, backlog int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc___xnet_listen)), 2, uintptr(s), uintptr(backlog), 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Lstat)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Mkdir)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(mode), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Mknod(path string, mode uint32, dev int) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Mknod)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(dev), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Nanosleep(time *Timespec, leftover *Timespec) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Nanosleep)), 2, uintptr(unsafe.Pointer(time)), uintptr(unsafe.Pointer(leftover)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Open(path string, mode int, perm uint32) (fd int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Open)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(mode), uintptr(perm), 0, 0, 0)
	fd = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Pathconf(path string, name int) (val int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Pathconf)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(name), 0, 0, 0, 0)
	val = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pread(fd int, p []byte, offset int64) (n int, err error) {
	var _p0 *byte
	if len(p) > 0 {
		_p0 = &p[0]
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_pread)), 4, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(p)), uintptr(offset), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func pwrite(fd int, p []byte, offset int64) (n int, err error) {
	var _p0 *byte
	if len(p) > 0 {
		_p0 = &p[0]
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_pwrite)), 4, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(p)), uintptr(offset), 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func read(fd int, p []byte) (n int, err error) {
	var _p0 *byte
	if len(p) > 0 {
		_p0 = &p[0]
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_read)), 3, uintptr(fd), uintptr(unsafe.Pointer(_p0)), uintptr(len(p)), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Readlink(path string, buf []byte) (n int, err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	var _p1 *byte
	if len(buf) > 0 {
		_p1 = &buf[0]
	}
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Readlink)), 3, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), uintptr(len(buf)), 0, 0, 0)
	n = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Rename)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Rmdir(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Rmdir)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Seek(fd int, offset int64, whence int) (newoffset int64, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_lseek)), 3, uintptr(fd), uintptr(offset), uintptr(whence), 0, 0, 0)
	newoffset = int64(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func sendfile(outfd int, infd int, offset *int64, count int) (written int, err error) {
	r0, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_sendfile)), 4, uintptr(outfd), uintptr(infd), uintptr(unsafe.Pointer(offset)), uintptr(count), 0, 0)
	written = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setegid(egid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setegid)), 1, uintptr(egid), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Seteuid(euid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Seteuid)), 1, uintptr(euid), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setgid(gid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setgid)), 1, uintptr(gid), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setpgid(pid int, pgid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setpgid)), 2, uintptr(pid), uintptr(pgid), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setpriority(which int, who int, prio int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Setpriority)), 3, uintptr(which), uintptr(who), uintptr(prio), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setregid(rgid int, egid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setregid)), 2, uintptr(rgid), uintptr(egid), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setreuid(ruid int, euid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setreuid)), 2, uintptr(ruid), uintptr(euid), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func setrlimit(which int, lim *Rlimit) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_setrlimit)), 2, uintptr(which), uintptr(unsafe.Pointer(lim)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setsid() (pid int, err error) {
	r0, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setsid)), 0, 0, 0, 0, 0, 0, 0)
	pid = int(r0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Setuid(uid int) (err error) {
	_, _, e1 := rawSysvicall6(uintptr(unsafe.Pointer(&libc_Setuid)), 1, uintptr(uid), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Shutdown(s int, how int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_shutdown)), 2, uintptr(s), uintptr(how), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Stat(path string, stat *Stat_t) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Stat)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(stat)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Symlink)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(_p1)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Sync() (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Sync)), 0, 0, 0, 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Truncate)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(length), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Fsync(fd int) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Fsync)), 1, uintptr(fd), 0, 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Ftruncate(fd int, length int64) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Ftruncate)), 2, uintptr(fd), uintptr(length), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Umask(newmask int) (oldmask int) {
	r0, _, _ := sysvicall6(uintptr(unsafe.Pointer(&libc_Umask)), 1, uintptr(newmask), 0, 0, 0, 0, 0)
	oldmask = int(r0)
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func Unlink(path string) (err error) {
	var _p0 *byte
	_p0, err = BytePtrFromString(path)
	if err != nil {
		return
	}
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_Unlink)), 1, uintptr(unsafe.Pointer(_p0)), 0, 0, 0, 0, 0)
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
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc_utimes)), 2, uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(times)), 0, 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func bind(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := sysvicall6(uintptr(unsafe.Pointer(&libc___xnet_bind)), 3, uintptr(s), uintptr(addr), uintptr(addrlen), 0, 0, 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

// THIS FILE IS GENERATED BY THE COMMAND AT THE TOP; DO NOT EDIT

func connect(s int, addr unsafe.Pointer, addrlen _Socklen) (err error) {
	_, _, e1 := sysvicall6(uintptr(
"""




```