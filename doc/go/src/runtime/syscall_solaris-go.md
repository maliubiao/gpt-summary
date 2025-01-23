Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Goal:**

The core request is to understand the functionality of a specific Go file (`syscall_solaris.go`) within the `runtime` package. This immediately tells us we're dealing with low-level operating system interactions on Solaris.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the code for recurring patterns and keywords. I see:

* `// Copyright`, `// Use of this source code`: Standard Go license boilerplate - ignore for functionality.
* `package runtime`:  Confirms the location within the Go runtime.
* `import "unsafe"`: This is a strong indicator of low-level memory manipulation and system calls.
* `var libc_... libcFunc`: This suggests the code is interacting with the C standard library on Solaris. The `libc_` prefix and the `libcFunc` type strongly imply this is about making system calls.
* Function names prefixed with `syscall_`:  This is a huge clue. These are likely Go wrappers around the C library functions.
* `//go:nosplit`:  This directive indicates that these functions must not have stack splits, critical for low-level operations and interacting with the C world.
* `//go:linkname`:  This is crucial. It tells us that the Go functions are being linked to corresponding functions in the `syscall` package (often implemented in assembly or C). This means this file *implements* the Solaris-specific part of the `syscall` package's interface.
* `//go:cgo_unsafe_args`: Indicates that these functions pass pointers to C code, which requires careful handling.
* The structure of most `syscall_` functions:  They create a `libcall` struct, populate it with the C function pointer and arguments, and then call `asmcgocall`. This pattern clearly points to a mechanism for invoking C functions.
* Functions like `syscall_rawsyscall` and `syscall_rawsyscall6` that `panic`: This is an important observation, indicating that these specific raw system call mechanisms aren't supported directly on Solaris.
* Comments like "This is syscall.RawSyscall..." further solidify the connection to the `syscall` package.

**3. Categorizing the Functionality:**

Based on the identified patterns, I can start categorizing the functions:

* **Process Management:** `forkx`, `execve`, `exit`, `wait4`, `getpid`, `setpgid`, `setsid`.
* **File System:** `chdir`, `chroot`, `close`, `dup2`, `fcntl`.
* **System Information:** `gethostname`.
* **Security/Permissions:** `setgid`, `setgroups`, `setuid`, `issetugid` (though the code for `issetugid` isn't provided, its presence in the `var` section is a hint).
* **Resource Limits:** `setrlimit`.
* **Low-Level System Calls:** `syscall_syscall`, `syscall_sysvicall6`, `syscall_rawsysvicall6`. The "raw" variants seem to have subtle differences.
* **Input/Output:** `write`, `ioctl`.

**4. Understanding `libcall` and the Calling Mechanism:**

The `libcall` struct is central. It appears to be a way to package the necessary information to call a C function: the function pointer (`fn`), the number of arguments (`n`), and a pointer to the arguments (`args`). The `asmcgocall` function likely handles the transition from Go to C, setting up the stack and registers appropriately. The `entersyscallblock()` and `exitsyscall()` functions probably manage Go's scheduler during system calls.

**5. Identifying Key Go Features:**

The primary Go feature being implemented here is the `syscall` package. This package provides a platform-independent interface to operating system calls. This file provides the Solaris-specific implementation details for that interface.

**6. Constructing Example Go Code:**

Now that I understand the purpose, I can create examples. I pick a few representative functions from different categories:

* **File system:** `os.Chdir` using `syscall.Chdir`.
* **Process management:** `os.StartProcess` which internally uses `syscall.ForkExec` (which leverages `forkx` and `execve`).
* **System information:** `os.Hostname` using `syscall.Gethostname`.
* **Process waiting:** `os/exec` and `syscall.Wait4`.

For each example, I consider the necessary imports and how the high-level Go functions relate to the low-level `syscall_` functions.

**7. Inferring Input/Output and Command Line Arguments (if applicable):**

For the given code, there aren't direct command-line argument parsing functions. The input and output are primarily related to the arguments passed to the system calls themselves (e.g., file paths for `chdir`, process IDs for `wait4`).

**8. Identifying Potential Pitfalls:**

This is where understanding the `unsafe` package and C interoperation is crucial. Common mistakes would involve:

* **Incorrectly sized or typed arguments:**  Passing the wrong kind of pointer or a buffer that's too small.
* **Memory management issues:**  Forgetting to allocate or free memory correctly when interacting with C.
* **Understanding error handling:**  System calls return error codes, and Go needs to translate those into `error` values.
* **Concurrency issues:** System calls can block, so careful synchronization is needed in concurrent programs. The `//go:nosplit` annotation highlights the sensitivity of these low-level functions.

**9. Structuring the Answer:**

Finally, I organize the information into the requested categories:

* **Functionality Listing:** Enumerate the purpose of each `syscall_` function.
* **Go Feature Implementation:** Explain that this code implements the `syscall` package for Solaris and provide illustrative Go code examples.
* **Code Inference with Examples:** Show the Go code examples, linking them back to the `syscall_` functions and describing the assumed inputs and outputs (which are generally the arguments and return values of the underlying system calls).
* **Command Line Arguments:** State that the code doesn't directly handle command-line arguments.
* **Common Mistakes:** Explain the potential pitfalls related to `unsafe` and C interop, providing concrete examples.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the individual `syscall_` functions without seeing the bigger picture of them being part of the `syscall` package implementation. Recognizing the `//go:linkname` directives helps connect the pieces.
* I might have initially overlooked the implications of `//go:nosplit` and `//go:cgo_unsafe_args`. Realizing their significance is important for understanding the constraints and potential dangers of this code.
* While explaining the Go code examples, I need to ensure the imports are correct and the examples demonstrate the usage of the relevant `syscall` package functions, even if the provided file doesn't directly call those package functions. It's about showing *how* this low-level code is used.
这个文件 `go/src/runtime/syscall_solaris.go` 是 Go 语言运行时环境的一部分，专门针对 Solaris 操作系统。它主要负责提供 Go 语言程序与 Solaris 系统底层交互的桥梁，实现 Go 的 `syscall` 标准库在 Solaris 上的具体操作。

以下是该文件主要功能的详细列表：

**核心功能：系统调用接口**

该文件定义了一系列 Go 函数，这些函数是对 Solaris 系统调用的封装。这些函数以 `syscall_` 开头，并通过 `//go:linkname` 指令与 `syscall` 包中定义的（通常是汇编实现的）通用系统调用接口进行链接。这意味着，当 Go 程序调用 `syscall` 包中的函数时，最终会调用到这里定义的 Solaris 特定实现。

具体来说，它实现了以下系统调用相关的操作：

* **进程管理:**
    * `syscall_forkx`:  执行 `forkx` 系统调用，用于创建子进程。
    * `syscall_execve`: 执行 `execve` 系统调用，用于加载并执行新的程序。
    * `syscall_exit`:  执行 `exit` 系统调用，终止当前进程。
    * `syscall_wait4`: 执行 `wait4` 系统调用，等待子进程结束并获取其状态信息。
    * `syscall_getpid`: 执行 `getpid` 系统调用，获取当前进程的 ID。
    * `syscall_setpgid`: 执行 `setpgid` 系统调用，设置进程组 ID。
    * `syscall_setsid`: 执行 `setsid` 系统调用，创建一个新的会话并成为会话领导者。
* **文件系统操作:**
    * `syscall_chdir`: 执行 `chdir` 系统调用，改变当前工作目录。
    * `syscall_chroot`: 执行 `chroot` 系统调用，改变进程的根目录。
    * `syscall_close`: 执行 `close` 系统调用，关闭文件描述符。
    * `syscall_dup2`:  通过 `fcntl` 实现 `dup2` 功能，复制文件描述符。
    * `syscall_fcntl`: 执行 `fcntl` 系统调用，用于控制文件描述符的行为。
* **系统信息:**
    * `syscall_gethostname`: 执行 `gethostname` 系统调用，获取主机名。
* **安全与权限:**
    * `syscall_setgid`: 执行 `setgid` 系统调用，设置进程的组 ID。
    * `syscall_setgroups`: 执行 `setgroups` 系统调用，设置进程的附属组 ID 列表。
    * `syscall_setuid`: 执行 `setuid` 系统调用，设置进程的用户 ID。
* **资源限制:**
    * `syscall_setrlimit`: 执行 `setrlimit` 系统调用，设置进程的资源限制。
* **底层系统调用:**
    * `syscall_syscall`:  提供一个通用的 `syscall` 接口，允许直接调用 Solaris 系统调用。
    * `syscall_sysvicall6`, `syscall_rawsysvicall6`:  看起来是用于调用 C 库函数的机制，特别是 `sysvicall` 系列函数（Solaris 特有的系统调用接口），可能与 CGO 互操作有关。
* **其他:**
    * `syscall_ioctl`: 执行 `ioctl` 系统调用，用于设备特定的输入输出控制。
    * `syscall_write`: 执行 `write` 系统调用，向文件描述符写入数据。

**推断的 Go 语言功能实现：`syscall` 包在 Solaris 上的实现**

这个文件是 Go 语言 `syscall` 包在 Solaris 操作系统上的具体实现。`syscall` 包提供了一个与操作系统底层交互的接口，允许 Go 程序执行诸如文件操作、进程管理、网络通信等任务。由于不同操作系统底层的系统调用接口不同，因此 Go 需要为每个支持的操作系统提供特定的实现。 `syscall_solaris.go` 就是为 Solaris 提供的这部分实现。

**Go 代码示例：**

假设我们想在 Solaris 上获取当前进程的 ID，并改变当前工作目录。以下是如何使用 `syscall` 包实现：

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 获取进程 ID
	pid, _, err := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	if err != 0 {
		fmt.Printf("获取进程 ID 失败: %v\n", err)
	} else {
		fmt.Printf("当前进程 ID: %d\n", pid)
	}

	// 改变当前工作目录到 /tmp
	pathPtr := uintptr(unsafe.Pointer(syscall.StringBytePtr("/tmp")))
	_, _, err = syscall.Syscall(syscall.SYS_CHDIR, pathPtr, 0, 0)
	if err != 0 {
		fmt.Printf("改变工作目录失败: %v\n", err)
	} else {
		fmt.Println("成功改变工作目录到 /tmp")
	}
}
```

**假设的输入与输出：**

* **输入：**  程序执行在 Solaris 操作系统上。
* **输出：**
    * 如果成功获取进程 ID，则会打印类似 "当前进程 ID: 12345" 的信息。
    * 如果成功改变工作目录，则会打印 "成功改变工作目录到 /tmp"。
    * 如果任何系统调用失败，会打印相应的错误信息。

**代码推理：**

1. **`syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)`:**  这里使用了通用的 `syscall.Syscall` 函数来执行系统调用。`syscall.SYS_GETPID` 是 `syscall` 包中定义的 `getpid` 系统调用的常量。由于 `getpid` 不需要参数，所以后三个参数都为 0。在 `syscall_solaris.go` 中，`syscall_syscall` 函数会接收这些参数，并将 `syscall.SYS_GETPID` 转换为 Solaris 对应的系统调用号，然后调用 Solaris 的 `getpid` 函数。
2. **`syscall.StringBytePtr("/tmp")`:**  这个函数将 Go 字符串转换为指向以 null 结尾的 C 字符串的指针，这是 Solaris 系统调用 `chdir` 所需要的参数类型。
3. **`syscall.Syscall(syscall.SYS_CHDIR, pathPtr, 0, 0)`:**  类似地，这里调用 `syscall.Syscall` 执行 `chdir` 系统调用。`pathPtr` 是指向目标目录路径的指针。

**命令行参数的具体处理：**

这个文件本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 函数中，并通过 `os.Args` 切片访问。`syscall` 包提供的功能是程序与操作系统交互的基础，而命令行参数解析是更上层的应用逻辑。

**使用者易犯错的点：**

1. **不安全的指针操作 (`unsafe` 包):**  该文件大量使用了 `unsafe` 包进行指针操作，这非常强大但也容易出错。例如，不正确地计算指针偏移、将 Go 对象转换为不兼容的 C 类型、或者生命周期管理不当都可能导致程序崩溃或出现未定义行为。
    * **错误示例：**  假设在 `syscall_chdir` 中，错误地将 `path` 参数的类型声明为 `int` 而不是 `uintptr`，会导致传递给底层系统调用的数据错误。

2. **系统调用号的硬编码：** 虽然 Go 的 `syscall` 包提供了常量 (例如 `syscall.SYS_GETPID`)，但在某些情况下，直接使用或误用 Solaris 特有的系统调用号可能会导致代码在其他平台上无法移植或行为不一致。
    * **错误示例：**  直接在代码中使用 Solaris 的 `SYS_forkx` 系统调用号，而不是使用更通用的 `syscall.ForkExec` 函数，会导致代码在其他操作系统上无法编译或运行。

3. **错误处理：**  系统调用可能会失败，并且会返回错误码。使用者必须检查 `syscall.Syscall` 等函数的返回值中的 `err`，并妥善处理错误。忽略错误可能导致程序在遇到问题时继续执行，产生不可预测的结果。
    * **错误示例：**  在上面的示例代码中，如果没有检查 `syscall.Syscall` 的 `err` 返回值，那么即使获取进程 ID 或改变工作目录失败，程序也可能继续执行，而用户不会得到任何提示。

4. **CGO 的使用 (`//go:cgo_unsafe_args`):**  带有 `//go:cgo_unsafe_args` 注解的函数涉及到 Go 和 C 代码的交互。错误地传递参数、不理解内存管理规则或者数据类型的差异都可能导致问题。

总而言之，`go/src/runtime/syscall_solaris.go` 是 Go 语言运行时环境的重要组成部分，它实现了 `syscall` 包在 Solaris 上的底层操作，使得 Go 程序能够与 Solaris 操作系统进行交互。理解这个文件的功能有助于深入理解 Go 语言的系统编程能力以及跨平台特性的实现原理。

### 提示词
```
这是路径为go/src/runtime/syscall_solaris.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "unsafe"

var (
	libc_chdir,
	libc_chroot,
	libc_close,
	libc_execve,
	libc_fcntl,
	libc_forkx,
	libc_gethostname,
	libc_getpid,
	libc_ioctl,
	libc_setgid,
	libc_setgroups,
	libc_setrlimit,
	libc_setsid,
	libc_setuid,
	libc_setpgid,
	libc_syscall,
	libc_issetugid,
	libc_wait4 libcFunc
)

// Many of these are exported via linkname to assembly in the syscall
// package.

//go:nosplit
//go:linkname syscall_sysvicall6
//go:cgo_unsafe_args
func syscall_sysvicall6(fn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	call := libcall{
		fn:   fn,
		n:    nargs,
		args: uintptr(unsafe.Pointer(&a1)),
	}
	entersyscallblock()
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	exitsyscall()
	return call.r1, call.r2, call.err
}

//go:nosplit
//go:linkname syscall_rawsysvicall6
//go:cgo_unsafe_args
func syscall_rawsysvicall6(fn, nargs, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	call := libcall{
		fn:   fn,
		n:    nargs,
		args: uintptr(unsafe.Pointer(&a1)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.r1, call.r2, call.err
}

// TODO(aram): Once we remove all instances of C calling sysvicallN, make
// sysvicallN return errors and replace the body of the following functions
// with calls to sysvicallN.

//go:nosplit
//go:linkname syscall_chdir
func syscall_chdir(path uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_chdir)),
		n:    1,
		args: uintptr(unsafe.Pointer(&path)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

//go:nosplit
//go:linkname syscall_chroot
func syscall_chroot(path uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_chroot)),
		n:    1,
		args: uintptr(unsafe.Pointer(&path)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

// like close, but must not split stack, for forkx.
//
//go:nosplit
//go:linkname syscall_close
func syscall_close(fd int32) int32 {
	return int32(sysvicall1(&libc_close, uintptr(fd)))
}

const _F_DUP2FD = 0x9

//go:nosplit
//go:linkname syscall_dup2
func syscall_dup2(oldfd, newfd uintptr) (val, err uintptr) {
	return syscall_fcntl(oldfd, _F_DUP2FD, newfd)
}

//go:nosplit
//go:linkname syscall_execve
//go:cgo_unsafe_args
func syscall_execve(path, argv, envp uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_execve)),
		n:    3,
		args: uintptr(unsafe.Pointer(&path)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

// like exit, but must not split stack, for forkx.
//
//go:nosplit
//go:linkname syscall_exit
func syscall_exit(code uintptr) {
	sysvicall1(&libc_exit, code)
}

//go:nosplit
//go:linkname syscall_fcntl
//go:cgo_unsafe_args
func syscall_fcntl(fd, cmd, arg uintptr) (val, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_fcntl)),
		n:    3,
		args: uintptr(unsafe.Pointer(&fd)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.r1, call.err
}

//go:nosplit
//go:linkname syscall_forkx
func syscall_forkx(flags uintptr) (pid uintptr, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_forkx)),
		n:    1,
		args: uintptr(unsafe.Pointer(&flags)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	if int(call.r1) != -1 {
		call.err = 0
	}
	return call.r1, call.err
}

//go:linkname syscall_gethostname
func syscall_gethostname() (name string, err uintptr) {
	cname := new([_MAXHOSTNAMELEN]byte)
	var args = [2]uintptr{uintptr(unsafe.Pointer(&cname[0])), _MAXHOSTNAMELEN}
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_gethostname)),
		n:    2,
		args: uintptr(unsafe.Pointer(&args[0])),
	}
	entersyscallblock()
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	exitsyscall()
	if call.r1 != 0 {
		return "", call.err
	}
	cname[_MAXHOSTNAMELEN-1] = 0
	return gostringnocopy(&cname[0]), 0
}

//go:nosplit
//go:linkname syscall_getpid
func syscall_getpid() (pid, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_getpid)),
		n:    0,
		args: uintptr(unsafe.Pointer(&libc_getpid)), // it's unused but must be non-nil, otherwise crashes
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.r1, call.err
}

//go:nosplit
//go:linkname syscall_ioctl
//go:cgo_unsafe_args
func syscall_ioctl(fd, req, arg uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_ioctl)),
		n:    3,
		args: uintptr(unsafe.Pointer(&fd)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

// This is syscall.RawSyscall, it exists to satisfy some build dependency,
// but it doesn't work.
//
//go:linkname syscall_rawsyscall
func syscall_rawsyscall(trap, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	panic("RawSyscall not available on Solaris")
}

// This is syscall.RawSyscall6, it exists to avoid a linker error because
// syscall.RawSyscall6 is already declared. See golang.org/issue/24357
//
//go:linkname syscall_rawsyscall6
func syscall_rawsyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	panic("RawSyscall6 not available on Solaris")
}

//go:nosplit
//go:linkname syscall_setgid
func syscall_setgid(gid uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_setgid)),
		n:    1,
		args: uintptr(unsafe.Pointer(&gid)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

//go:nosplit
//go:linkname syscall_setgroups
//go:cgo_unsafe_args
func syscall_setgroups(ngid, gid uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_setgroups)),
		n:    2,
		args: uintptr(unsafe.Pointer(&ngid)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

//go:nosplit
//go:linkname syscall_setrlimit
//go:cgo_unsafe_args
func syscall_setrlimit(which uintptr, lim unsafe.Pointer) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_setrlimit)),
		n:    2,
		args: uintptr(unsafe.Pointer(&which)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

//go:nosplit
//go:linkname syscall_setsid
func syscall_setsid() (pid, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_setsid)),
		n:    0,
		args: uintptr(unsafe.Pointer(&libc_setsid)), // it's unused but must be non-nil, otherwise crashes
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.r1, call.err
}

//go:nosplit
//go:linkname syscall_setuid
func syscall_setuid(uid uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_setuid)),
		n:    1,
		args: uintptr(unsafe.Pointer(&uid)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

//go:nosplit
//go:linkname syscall_setpgid
//go:cgo_unsafe_args
func syscall_setpgid(pid, pgid uintptr) (err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_setpgid)),
		n:    2,
		args: uintptr(unsafe.Pointer(&pid)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.err
}

//go:linkname syscall_syscall
//go:cgo_unsafe_args
func syscall_syscall(trap, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_syscall)),
		n:    4,
		args: uintptr(unsafe.Pointer(&trap)),
	}
	entersyscallblock()
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	exitsyscall()
	return call.r1, call.r2, call.err
}

//go:linkname syscall_wait4
//go:cgo_unsafe_args
func syscall_wait4(pid uintptr, wstatus *uint32, options uintptr, rusage unsafe.Pointer) (wpid int, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_wait4)),
		n:    4,
		args: uintptr(unsafe.Pointer(&pid)),
	}
	entersyscallblock()
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	exitsyscall()
	KeepAlive(wstatus)
	KeepAlive(rusage)
	return int(call.r1), call.err
}

//go:nosplit
//go:linkname syscall_write
//go:cgo_unsafe_args
func syscall_write(fd, buf, nbyte uintptr) (n, err uintptr) {
	call := libcall{
		fn:   uintptr(unsafe.Pointer(&libc_write)),
		n:    3,
		args: uintptr(unsafe.Pointer(&fd)),
	}
	asmcgocall(unsafe.Pointer(&asmsysvicall6x), unsafe.Pointer(&call))
	return call.r1, call.err
}
```