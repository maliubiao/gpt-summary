Response:
Let's break down the thought process to answer the request about `go/src/runtime/sys_darwin.go`.

**1. Understanding the Core Request:**

The request asks for the functionality of the provided Go code snippet. It specifically targets `go/src/runtime/sys_darwin.go`, implying this file is specific to the Darwin (macOS and iOS) operating system. Key elements of the request are:

* **List functionalities:**  Identify what the code does.
* **Infer Go feature implementation:** Connect the code to higher-level Go language features.
* **Provide Go code examples:** Illustrate the inferred features in action.
* **Include input/output for code examples:**  Demonstrate the behavior.
* **Explain command-line parameter handling (if any):**  Look for code related to argument parsing.
* **Highlight common user mistakes:**  Identify potential pitfalls.
* **Answer in Chinese.**

**2. Initial Code Scan and Keyword Identification:**

A quick scan reveals several recurring patterns and keywords:

* `// Copyright ...` and `package runtime`:  Standard Go file header. Confirms this is part of the Go runtime.
* `import (...)`: Imports internal Go packages, suggesting low-level operations.
* `//go:linkname ...`: This is a crucial directive. It signifies that the Go function is actually implemented by a function in another package (usually `syscall` or `crypto/x509/internal/macos`), or even a C library function. This immediately tells us the code is mostly about *interfacing* with the operating system or other libraries.
* `//go:nosplit`: Indicates that these functions should not have stack splits, meaning they are performance-critical or used in low-level contexts where stack management needs careful control.
* `//go:cgo_unsafe_args`: Suggests interaction with C code and potential memory safety considerations.
* `func syscall_...`, `func syscallX_...`, `func syscall6_...`, etc.:  These patterns point to different system call wrappers, likely handling varying numbers of arguments or different return value expectations.
* `func ..._trampoline()`: The "trampoline" suffix strongly suggests these functions act as bridges between Go and C calling conventions. The code preceding them (e.g., `pthread_attr_init`) calls these trampoline functions.
* `libcCall(...)`: This function is central. It's the mechanism for actually calling C library functions.
* Function names like `pthread_attr_init`, `pthread_create`, `mmap`, `munmap`, `read`, `write`, `open`, `close`, `sigaction`, `sysctl`, etc.: These are standard POSIX system calls or thread-related functions, confirming the OS interaction.
* `osinit_hack()`:  The comment clearly explains this is a workaround for macOS bugs related to `fork+exec`.
* Mentions of `crypto/x509/internal/macos` and `runtime/pprof`: Indicates the code is used by these standard Go libraries.
* `//go:cgo_import_dynamic ...`: This confirms the use of Cgo and dynamically linked libraries.

**3. Categorizing Functionalities:**

Based on the keywords and function names, we can categorize the functionalities:

* **System Calls:**  The `syscall_*` functions are wrappers for making raw system calls.
* **Thread Management:** The `pthread_*` functions (init, getstacksize, setdetachstate, create, self, kill) relate to POSIX threads.
* **Memory Management:** `mmap`, `munmap`, `madvise`, `mlock` are standard memory mapping functions.
* **File I/O:** `read`, `write`, `open`, `close`, `pipe` are for file and pipe operations.
* **Time:** `nanotime1`, `walltime`, `usleep` deal with time-related operations.
* **Signal Handling:** `sigaction`, `sigprocmask`, `sigaltstack`, `raise`, `raiseproc` are for signal management.
* **System Information:** `sysctl`, `sysctlbyname` allow querying system information.
* **Process Control:** `exit`, and the `osinit_hack` which affects process creation.
* **Random Number Generation:** `arc4random_buf`.
* **Profiling Support:** `mach_vm_region`, `proc_regionfilename`.
* **Synchronization Primitives:** `pthread_mutex_*`, `pthread_cond_*`.
* **Other:** `fcntl`, `kqueue`, `kevent`, `issetugid`.

**4. Inferring Go Feature Implementations:**

Now, let's connect these low-level functions to higher-level Go features:

* **`syscall` package:** The `syscall_syscall`, `syscall_syscallX`, etc., functions directly implement the functionality of the `syscall` package, allowing Go programs to make raw system calls.
* **`os` package (file I/O, process control):** Functions like `open`, `close`, `read`, `write`, `pipe`, `exit` are used by the `os` package to implement file I/O operations and process control.
* **`time` package:** `nanotime1`, `walltime`, `usleep` are building blocks for the `time` package's time-keeping functionality.
* **`os/signal` package:** The `sigaction`, `sigprocmask`, etc., functions are the underlying mechanism for Go's signal handling.
* **`sync` package (threading and synchronization):** The `pthread_*` functions are used internally by the `runtime` and potentially the `sync` package to manage goroutines (which are often implemented using OS threads on Darwin) and provide synchronization primitives like mutexes and condition variables.
* **`crypto/rand` package:** `arc4random_buf` is used to generate cryptographically secure random numbers.
* **`runtime/pprof` package:** `mach_vm_region` and `proc_regionfilename` are specifically used for memory profiling.

**5. Providing Go Code Examples:**

For each inferred feature, we can write simple Go code examples:

* **`syscall`:** Use `syscall.Syscall`.
* **`os` (file I/O):** Use `os.Open`, `os.Read`, `os.Write`, `os.Close`.
* **`time`:** Use `time.Now`, `time.Sleep`.
* **`os/signal`:** Use `signal.Notify`.
* **`sync` (mutex):** Use `sync.Mutex`.

**6. Adding Input/Output and Explanations:**

For each code example, provide sample input and the expected output or behavior. Explain what the code is doing and how it relates to the underlying system calls.

**7. Command-line Parameters:**

Carefully review the code for any direct handling of command-line arguments. In this specific snippet, there's no explicit command-line parsing. Mention this fact.

**8. Common User Mistakes:**

Think about common pitfalls when working with system calls or low-level operations:

* **Incorrect error handling:**  System calls return error codes. Go wraps these in the `error` type, but understanding the underlying error numbers can be important.
* **Memory management:**  Passing pointers to C requires careful attention to memory lifetimes. The `KeepAlive` calls in the code hint at this.
* **Signal handling complexities:** Signal interactions can be tricky, especially in multi-threaded programs.
* **Assumptions about system behavior:** Relying on specific system call behavior that might differ across operating systems.

**9. Structuring the Answer in Chinese:**

Finally, translate the entire explanation into clear and concise Chinese. Use appropriate terminology and sentence structure. Pay attention to accurately conveying technical details.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus too much on the `//go:linkname` aspect without explaining *why* it's there. Refine to explain that it's for interoperability with C code and other Go packages.
* **Code example complexity:** Start with simpler examples and avoid introducing unnecessary complexity.
* **Clarity of explanations:** Ensure the connection between the low-level functions and the high-level Go features is explicit and easy to understand.
* **Accuracy of technical terms:** Double-check the Chinese translations of technical terms.

By following these steps, systematically analyzing the code, and focusing on the key aspects of the request, we can arrive at a comprehensive and accurate answer.
这段代码是 Go 语言运行时（runtime）包中针对 Darwin（macOS 和 iOS）操作系统的一部分实现。它的主要功能是提供 Go 语言程序与 Darwin 系统底层交互的桥梁。更具体地说，它实现了以下功能：

**1. 系统调用（Syscall）:**

* **`syscall_syscall`, `syscall_syscallX`, `syscall_syscall6`, `syscall_syscall9`, `syscall_syscall6X`, `syscall_syscallPtr`:**  这些函数是 Go 语言 `syscall` 标准库中 `Syscall`、`SyscallX`、`Syscall6` 等函数的底层实现。它们负责将 Go 的调用转换为对 Darwin 系统调用的实际调用。
    * `syscall` 和 `syscall6` 返回 32 位的结果。
    * `syscallX` 和 `syscall6X` 返回 64 位的结果。
    * `syscall9` 接受 9 个参数。
    * `syscallPtr` 类似于 `syscall`，但可能在参数传递方式上有所不同（具体取决于架构和系统调用）。
* **`syscall_rawSyscall`, `syscall_rawSyscall6`:**  这些是 `syscall` 包中 `RawSyscall` 和 `RawSyscall6` 的底层实现，它们提供更底层的系统调用接口，不涉及 `entersyscall` 和 `exitsyscall` 的处理，这通常用于一些性能敏感的场景。
* **`crypto_x509_syscall`:**  这个函数是 `crypto/x509/internal/macos` 包用来调用 Darwin 系统中 Security.framework 和 CoreFoundation (CF) 框架的系统调用。它允许传递浮点数参数。

**2. 线程操作 (pthread):**

* **`pthread_attr_init`, `pthread_attr_getstacksize`, `pthread_attr_setdetachstate`, `pthread_create`:**  这些函数是对 Darwin 系统中 `pthread` 系列函数的封装，用于线程属性的初始化、获取栈大小、设置分离状态以及创建新的线程。
* **`pthread_self`:** 获取当前线程的 ID。
* **`pthread_kill`:** 向指定的线程发送信号。

**3. 进程操作:**

* **`raise`:** 向当前进程发送信号。
* **`exit`:** 终止当前进程。
* **`raiseproc`:**  （与 `raise` 类似，可能在某些特定情况下使用，具体取决于 Go 运行时实现）。
* **`osinit_hack`:**  这是一个针对 macOS libc 库中可能导致 `fork+exec` 挂起的 bug 的临时性解决方案。它通过提前调用某些 libc 函数来初始化相关的全局状态，以避免在子进程中出现死锁。

**4. 内存管理:**

* **`mmap`:** 调用 Darwin 的 `mmap` 系统调用，用于创建内存映射。Go 运行时使用它来进行低级别的内存分配。
* **`munmap`:** 调用 Darwin 的 `munmap` 系统调用，用于释放内存映射。
* **`madvise`:**  调用 Darwin 的 `madvise` 系统调用，用于向内核提供关于内存使用模式的建议。
* **`mlock`:** 调用 Darwin 的 `mlock` 系统调用，用于将内存页锁定在 RAM 中，防止被交换到磁盘。

**5. 文件 I/O:**

* **`read`:** 调用 Darwin 的 `read` 系统调用，从文件描述符读取数据。
* **`write1`:** 调用 Darwin 的 `write` 系统调用，向文件描述符写入数据。
* **`open`:** 调用 Darwin 的 `open` 系统调用，打开或创建文件。
* **`closefd`:** 调用 Darwin 的 `close` 系统调用，关闭文件描述符。
* **`pipe`:** 调用 Darwin 的 `pipe` 系统调用，创建一个管道，用于进程间通信。

**6. 时间相关:**

* **`nanotime1`:** 获取高精度的时间戳（纳秒级别）。
* **`walltime`:** 获取当前的系统时间（秒和纳秒）。
* **`usleep`:** 使当前线程休眠指定的微秒数。
* **`usleep_no_g`:** 类似 `usleep`，但在没有 Go 调度器 `g` 的情况下调用，这在某些非常底层的操作中可能会用到。

**7. 信号处理:**

* **`sigaction`:** 设置进程对特定信号的处理方式。
* **`sigprocmask`:**  检查和修改进程的信号屏蔽字。
* **`sigaltstack`:** 设置和获取信号处理程序使用的备用栈。

**8. 系统信息:**

* **`sysctl`:**  允许获取和设置内核参数。
* **`sysctlbyname`:**  通过名称获取内核参数。

**9. 文件控制:**

* **`fcntl`:** 提供对文件描述符的各种控制操作，例如获取和设置文件状态标志。

**10. I/O 事件通知:**

* **`kqueue`:** 创建一个新的内核事件队列。
* **`kevent`:**  注册、修改或删除内核事件队列上的事件，并等待事件发生。

**11. 同步原语 (pthread):**

* **`pthread_mutex_init`, `pthread_mutex_lock`, `pthread_mutex_unlock`:**  封装了 POSIX 互斥锁的相关操作。
* **`pthread_cond_init`, `pthread_cond_wait`, `pthread_cond_timedwait_relative_np`, `pthread_cond_signal`:** 封装了 POSIX 条件变量的相关操作。

**12. 安全随机数:**

* **`arc4random_buf`:**  使用 Darwin 提供的 `arc4random_buf` 函数生成安全随机数。

**13. 其他:**

* **`setNonblock`:**  设置文件描述符为非阻塞模式。
* **`issetugid`:** 检查进程的实际用户 ID 和有效用户 ID 是否不同，或者实际组 ID 和有效组 ID 是否不同。这通常用于判断程序是否以特权用户身份运行。
* **`mach_vm_region`, `proc_regionfilename`:**  这两个函数被 `runtime/pprof` 包使用，用于获取进程的内存区域信息，以便进行性能分析。

**推理 Go 语言功能的实现并举例：**

这段代码主要涉及 Go 语言标准库中 `syscall`、`os`、`time`、`os/signal`、`sync` 和 `crypto/rand` 等包的底层实现。

**例子 1：`syscall` 包的 `Syscall` 函数**

假设我们要调用 Darwin 系统的 `getpid()` 系统调用来获取当前进程的 ID。

```go
package main

import (
	"fmt"
	"syscall"
)

func main() {
	pid, _, err := syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	if err != 0 {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Process ID:", pid)
}
```

**假设的输入与输出：**

* **输入：** 运行上述 Go 程序。
* **输出：**  `Process ID: <当前进程的PID>`  （例如：`Process ID: 12345`）

**代码推理：**

1. `syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)`  调用了 `syscall` 包的 `Syscall` 函数。
2. `syscall.SYS_GETPID` 是 `getpid()` 系统调用在 Go 中的常量表示。
3. `Syscall` 函数内部会调用 `runtime` 包中与操作系统相关的实现，对于 Darwin 来说，会调用 `syscall_syscall` 函数（因为 `getpid` 通常返回 32 位结果）。
4. `syscall_syscall` 函数会将参数 `syscall.SYS_GETPID` (对应 `fn`) 和三个 0 传递给底层的 `libcCall` 函数。
5. `libcCall` 函数最终会调用 Darwin 系统的 `getpid()` 函数。
6. `getpid()` 返回当前进程的 ID，`syscall_syscall` 会将结果返回给 Go 的 `syscall.Syscall` 函数。

**例子 2：`os` 包的 `Open` 函数**

假设我们要打开一个名为 `test.txt` 的文件。

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	file, err := os.Open("test.txt")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	fmt.Println("File opened successfully.")
}
```

**假设的输入与输出：**

* **输入：**  假设当前目录下存在名为 `test.txt` 的文件。
* **输出：** `File opened successfully.`

**代码推理：**

1. `os.Open("test.txt")` 调用了 `os` 包的 `Open` 函数。
2. `os.Open` 函数内部会调用 `runtime` 包中与操作系统相关的实现。
3. 对于 Darwin 系统，这会涉及到调用 `open` 函数（在 `sys_darwin.go` 中被定义）。
4. `open` 函数（对应 `sys_darwin.go` 中的 `open`）会调用 Darwin 系统的 `open()` 系统调用。
5. Darwin 的 `open()` 系统调用会尝试打开 `test.txt` 文件。
6. 如果打开成功，`open` 函数会返回一个文件描述符，`os.Open` 会将其封装成 `os.File` 对象。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `os` 包或者使用 `flag` 等标准库的包中。这段代码提供的底层系统调用接口会被这些更高级别的包所使用。

**使用者易犯错的点：**

* **不正确的系统调用号：**  如果直接使用 `syscall` 包调用系统调用，错误地使用了系统调用号会导致程序崩溃或产生未定义的行为。例如，使用了 Linux 的系统调用号在 macOS 上运行。
* **不正确的参数类型和大小：**  传递给系统调用的参数必须符合系统调用期望的类型和大小。例如，传递了错误的指针类型或长度，可能导致内存错误。
* **忽略错误返回值：**  系统调用通常会返回错误码。如果不检查错误返回值，可能会导致程序在遇到问题时继续执行，从而产生更严重的问题。

**例子说明错误点：**

```go
package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	// 错误地使用了 Linux 的 open 系统调用号 (在 macOS 上 SYS_OPEN 实际上是 open_nocancel)
	fd, _, err := syscall.Syscall(2, uintptr(unsafe.Pointer(syscall.StringBytePtr("nonexistent.txt"))), uintptr(syscall.O_RDONLY), 0)
	if err != 0 {
		fmt.Println("Error opening file (incorrect syscall):", err)
	} else {
		fmt.Println("File descriptor:", fd) // 这段代码很可能不会执行到
		syscall.Close(int(fd))
	}
}
```

在这个例子中，使用了 Linux 中 `open` 系统调用的调用号 `2`，这在 macOS 上可能对应不同的系统调用，或者根本不对应。这会导致程序行为异常，错误地尝试执行其他操作，或者返回意想不到的错误。正确的做法是使用 `syscall.SYS_OPEN` (或者更推荐使用 `os.Open` 等更高级的封装)。

总结来说，`go/src/runtime/sys_darwin.go` 是 Go 语言在 Darwin 操作系统上的基石，它通过封装底层的系统调用和线程操作，为 Go 程序提供了与操作系统交互的能力。理解这部分代码的功能有助于深入理解 Go 语言的运行机制。

Prompt: 
```
这是路径为go/src/runtime/sys_darwin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"unsafe"
)

// The X versions of syscall expect the libc call to return a 64-bit result.
// Otherwise (the non-X version) expects a 32-bit result.
// This distinction is required because an error is indicated by returning -1,
// and we need to know whether to check 32 or 64 bits of the result.
// (Some libc functions that return 32 bits put junk in the upper 32 bits of AX.)

// golang.org/x/sys linknames syscall_syscall
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_syscall syscall.syscall
//go:nosplit
func syscall_syscall(fn, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, r1, r2, err uintptr }{fn, a1, a2, a3, r1, r2, err}
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall)), unsafe.Pointer(&args))
	exitsyscall()
	return args.r1, args.r2, args.err
}
func syscall()

//go:linkname syscall_syscallX syscall.syscallX
//go:nosplit
func syscall_syscallX(fn, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, r1, r2, err uintptr }{fn, a1, a2, a3, r1, r2, err}
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscallX)), unsafe.Pointer(&args))
	exitsyscall()
	return args.r1, args.r2, args.err
}
func syscallX()

// golang.org/x/sys linknames syscall.syscall6
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
// syscall.syscall6 is meant for package syscall (and x/sys),
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/tetratelabs/wazero
//
// See go.dev/issue/67401.
//
//go:linkname syscall_syscall6 syscall.syscall6
//go:nosplit
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, a4, a5, a6, r1, r2, err uintptr }{fn, a1, a2, a3, a4, a5, a6, r1, r2, err}
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall6)), unsafe.Pointer(&args))
	exitsyscall()
	return args.r1, args.r2, args.err
}
func syscall6()

// golang.org/x/sys linknames syscall.syscall9
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_syscall9 syscall.syscall9
//go:nosplit
//go:cgo_unsafe_args
func syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2, err uintptr) {
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall9)), unsafe.Pointer(&fn))
	exitsyscall()
	return
}
func syscall9()

//go:linkname syscall_syscall6X syscall.syscall6X
//go:nosplit
func syscall_syscall6X(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, a4, a5, a6, r1, r2, err uintptr }{fn, a1, a2, a3, a4, a5, a6, r1, r2, err}
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall6X)), unsafe.Pointer(&args))
	exitsyscall()
	return args.r1, args.r2, args.err
}
func syscall6X()

// golang.org/x/sys linknames syscall.syscallPtr
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_syscallPtr syscall.syscallPtr
//go:nosplit
func syscall_syscallPtr(fn, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, r1, r2, err uintptr }{fn, a1, a2, a3, r1, r2, err}
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscallPtr)), unsafe.Pointer(&args))
	exitsyscall()
	return args.r1, args.r2, args.err
}
func syscallPtr()

// golang.org/x/sys linknames syscall_rawSyscall
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_rawSyscall syscall.rawSyscall
//go:nosplit
func syscall_rawSyscall(fn, a1, a2, a3 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, r1, r2, err uintptr }{fn, a1, a2, a3, r1, r2, err}
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall)), unsafe.Pointer(&args))
	return args.r1, args.r2, args.err
}

// golang.org/x/sys linknames syscall_rawSyscall6
// (in addition to standard package syscall).
// Do not remove or change the type signature.
//
//go:linkname syscall_rawSyscall6 syscall.rawSyscall6
//go:nosplit
func syscall_rawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2, err uintptr) {
	args := struct{ fn, a1, a2, a3, a4, a5, a6, r1, r2, err uintptr }{fn, a1, a2, a3, a4, a5, a6, r1, r2, err}
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall6)), unsafe.Pointer(&args))
	return args.r1, args.r2, args.err
}

// crypto_x509_syscall is used in crypto/x509/internal/macos to call into Security.framework and CF.

//go:linkname crypto_x509_syscall crypto/x509/internal/macos.syscall
//go:nosplit
func crypto_x509_syscall(fn, a1, a2, a3, a4, a5 uintptr, f1 float64) (r1 uintptr) {
	args := struct {
		fn, a1, a2, a3, a4, a5 uintptr
		f1                     float64
		r1                     uintptr
	}{fn, a1, a2, a3, a4, a5, f1, r1}
	entersyscall()
	libcCall(unsafe.Pointer(abi.FuncPCABI0(syscall_x509)), unsafe.Pointer(&args))
	exitsyscall()
	return args.r1
}
func syscall_x509()

// The *_trampoline functions convert from the Go calling convention to the C calling convention
// and then call the underlying libc function.  They are defined in sys_darwin_$ARCH.s.

//go:nosplit
//go:cgo_unsafe_args
func pthread_attr_init(attr *pthreadattr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_attr_init_trampoline)), unsafe.Pointer(&attr))
	KeepAlive(attr)
	return ret
}
func pthread_attr_init_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_attr_getstacksize(attr *pthreadattr, size *uintptr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_attr_getstacksize_trampoline)), unsafe.Pointer(&attr))
	KeepAlive(attr)
	KeepAlive(size)
	return ret
}
func pthread_attr_getstacksize_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_attr_setdetachstate(attr *pthreadattr, state int) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_attr_setdetachstate_trampoline)), unsafe.Pointer(&attr))
	KeepAlive(attr)
	return ret
}
func pthread_attr_setdetachstate_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_create(attr *pthreadattr, start uintptr, arg unsafe.Pointer) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_create_trampoline)), unsafe.Pointer(&attr))
	KeepAlive(attr)
	KeepAlive(arg) // Just for consistency. Arg of course needs to be kept alive for the start function.
	return ret
}
func pthread_create_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func raise(sig uint32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(raise_trampoline)), unsafe.Pointer(&sig))
}
func raise_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_self() (t pthread) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_self_trampoline)), unsafe.Pointer(&t))
	return
}
func pthread_self_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_kill(t pthread, sig uint32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_kill_trampoline)), unsafe.Pointer(&t))
	return
}
func pthread_kill_trampoline()

// osinit_hack is a clumsy hack to work around Apple libc bugs
// causing fork+exec to hang in the child process intermittently.
// See go.dev/issue/33565 and go.dev/issue/56784 for a few reports.
//
// The stacks obtained from the hung child processes are in
// libSystem_atfork_child, which is supposed to reinitialize various
// parts of the C library in the new process.
//
// One common stack dies in _notify_fork_child calling _notify_globals
// (inlined) calling _os_alloc_once, because _os_alloc_once detects that
// the once lock is held by the parent process and then calls
// _os_once_gate_corruption_abort. The allocation is setting up the
// globals for the notification subsystem. See the source code at [1].
// To work around this, we can allocate the globals earlier in the Go
// program's lifetime, before any execs are involved, by calling any
// notify routine that is exported, calls _notify_globals, and doesn't do
// anything too expensive otherwise. notify_is_valid_token(0) fits the bill.
//
// The other common stack dies in xpc_atfork_child calling
// _objc_msgSend_uncached which ends up in
// WAITING_FOR_ANOTHER_THREAD_TO_FINISH_CALLING_+initialize. Of course,
// whatever thread the child is waiting for is in the parent process and
// is not going to finish anything in the child process. There is no
// public source code for these routines, so it is unclear exactly what
// the problem is. An Apple engineer suggests using xpc_date_create_from_current,
// which empirically does fix the problem.
//
// So osinit_hack_trampoline (in sys_darwin_$GOARCH.s) calls
// notify_is_valid_token(0) and xpc_date_create_from_current(), which makes the
// fork+exec hangs stop happening. If Apple fixes the libc bug in
// some future version of macOS, then we can remove this awful code.
//
//go:nosplit
func osinit_hack() {
	if GOOS == "darwin" { // not ios
		libcCall(unsafe.Pointer(abi.FuncPCABI0(osinit_hack_trampoline)), nil)
	}
	return
}
func osinit_hack_trampoline()

// mmap is used to do low-level memory allocation via mmap. Don't allow stack
// splits, since this function (used by sysAlloc) is called in a lot of low-level
// parts of the runtime and callers often assume it won't acquire any locks.
//
//go:nosplit
func mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) (unsafe.Pointer, int) {
	args := struct {
		addr            unsafe.Pointer
		n               uintptr
		prot, flags, fd int32
		off             uint32
		ret1            unsafe.Pointer
		ret2            int
	}{addr, n, prot, flags, fd, off, nil, 0}
	libcCall(unsafe.Pointer(abi.FuncPCABI0(mmap_trampoline)), unsafe.Pointer(&args))
	return args.ret1, args.ret2
}
func mmap_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func munmap(addr unsafe.Pointer, n uintptr) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(munmap_trampoline)), unsafe.Pointer(&addr))
	KeepAlive(addr) // Just for consistency. Hopefully addr is not a Go address.
}
func munmap_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func madvise(addr unsafe.Pointer, n uintptr, flags int32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(madvise_trampoline)), unsafe.Pointer(&addr))
	KeepAlive(addr) // Just for consistency. Hopefully addr is not a Go address.
}
func madvise_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func mlock(addr unsafe.Pointer, n uintptr) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(mlock_trampoline)), unsafe.Pointer(&addr))
	KeepAlive(addr) // Just for consistency. Hopefully addr is not a Go address.
}
func mlock_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func read(fd int32, p unsafe.Pointer, n int32) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(read_trampoline)), unsafe.Pointer(&fd))
	KeepAlive(p)
	return ret
}
func read_trampoline()

func pipe() (r, w int32, errno int32) {
	var p [2]int32
	errno = libcCall(unsafe.Pointer(abi.FuncPCABI0(pipe_trampoline)), noescape(unsafe.Pointer(&p)))
	return p[0], p[1], errno
}
func pipe_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func closefd(fd int32) int32 {
	return libcCall(unsafe.Pointer(abi.FuncPCABI0(close_trampoline)), unsafe.Pointer(&fd))
}
func close_trampoline()

// This is exported via linkname to assembly in runtime/cgo.
//
//go:nosplit
//go:cgo_unsafe_args
//go:linkname exit
func exit(code int32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(exit_trampoline)), unsafe.Pointer(&code))
}
func exit_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func usleep(usec uint32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(usleep_trampoline)), unsafe.Pointer(&usec))
}
func usleep_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func usleep_no_g(usec uint32) {
	asmcgocall_no_g(unsafe.Pointer(abi.FuncPCABI0(usleep_trampoline)), unsafe.Pointer(&usec))
}

//go:nosplit
//go:cgo_unsafe_args
func write1(fd uintptr, p unsafe.Pointer, n int32) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(write_trampoline)), unsafe.Pointer(&fd))
	KeepAlive(p)
	return ret
}
func write_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func open(name *byte, mode, perm int32) (ret int32) {
	ret = libcCall(unsafe.Pointer(abi.FuncPCABI0(open_trampoline)), unsafe.Pointer(&name))
	KeepAlive(name)
	return
}
func open_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func nanotime1() int64 {
	var r struct {
		t            int64  // raw timer
		numer, denom uint32 // conversion factors. nanoseconds = t * numer / denom.
	}
	libcCall(unsafe.Pointer(abi.FuncPCABI0(nanotime_trampoline)), unsafe.Pointer(&r))
	// Note: Apple seems unconcerned about overflow here. See
	// https://developer.apple.com/library/content/qa/qa1398/_index.html
	// Note also, numer == denom == 1 is common.
	t := r.t
	if r.numer != 1 {
		t *= int64(r.numer)
	}
	if r.denom != 1 {
		t /= int64(r.denom)
	}
	return t
}
func nanotime_trampoline()

// walltime should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname walltime
//go:nosplit
//go:cgo_unsafe_args
func walltime() (int64, int32) {
	var t timespec
	libcCall(unsafe.Pointer(abi.FuncPCABI0(walltime_trampoline)), unsafe.Pointer(&t))
	return t.tv_sec, int32(t.tv_nsec)
}
func walltime_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sigaction(sig uint32, new *usigactiont, old *usigactiont) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(sigaction_trampoline)), unsafe.Pointer(&sig))
	KeepAlive(new)
	KeepAlive(old)
}
func sigaction_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sigprocmask(how uint32, new *sigset, old *sigset) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(sigprocmask_trampoline)), unsafe.Pointer(&how))
	KeepAlive(new)
	KeepAlive(old)
}
func sigprocmask_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sigaltstack(new *stackt, old *stackt) {
	if new != nil && new.ss_flags&_SS_DISABLE != 0 && new.ss_size == 0 {
		// Despite the fact that Darwin's sigaltstack man page says it ignores the size
		// when SS_DISABLE is set, it doesn't. sigaltstack returns ENOMEM
		// if we don't give it a reasonable size.
		// ref: http://lists.llvm.org/pipermail/llvm-commits/Week-of-Mon-20140421/214296.html
		new.ss_size = 32768
	}
	libcCall(unsafe.Pointer(abi.FuncPCABI0(sigaltstack_trampoline)), unsafe.Pointer(&new))
	KeepAlive(new)
	KeepAlive(old)
}
func sigaltstack_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func raiseproc(sig uint32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(raiseproc_trampoline)), unsafe.Pointer(&sig))
}
func raiseproc_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func setitimer(mode int32, new, old *itimerval) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(setitimer_trampoline)), unsafe.Pointer(&mode))
	KeepAlive(new)
	KeepAlive(old)
}
func setitimer_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sysctl(mib *uint32, miblen uint32, oldp *byte, oldlenp *uintptr, newp *byte, newlen uintptr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(sysctl_trampoline)), unsafe.Pointer(&mib))
	KeepAlive(mib)
	KeepAlive(oldp)
	KeepAlive(oldlenp)
	KeepAlive(newp)
	return ret
}
func sysctl_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sysctlbyname(name *byte, oldp *byte, oldlenp *uintptr, newp *byte, newlen uintptr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(sysctlbyname_trampoline)), unsafe.Pointer(&name))
	KeepAlive(name)
	KeepAlive(oldp)
	KeepAlive(oldlenp)
	KeepAlive(newp)
	return ret
}
func sysctlbyname_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func fcntl(fd, cmd, arg int32) (ret int32, errno int32) {
	args := struct {
		fd, cmd, arg int32
		ret, errno   int32
	}{fd, cmd, arg, 0, 0}
	libcCall(unsafe.Pointer(abi.FuncPCABI0(fcntl_trampoline)), unsafe.Pointer(&args))
	return args.ret, args.errno
}
func fcntl_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func kqueue() int32 {
	v := libcCall(unsafe.Pointer(abi.FuncPCABI0(kqueue_trampoline)), nil)
	return v
}
func kqueue_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func kevent(kq int32, ch *keventt, nch int32, ev *keventt, nev int32, ts *timespec) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(kevent_trampoline)), unsafe.Pointer(&kq))
	KeepAlive(ch)
	KeepAlive(ev)
	KeepAlive(ts)
	return ret
}
func kevent_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_mutex_init(m *pthreadmutex, attr *pthreadmutexattr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_mutex_init_trampoline)), unsafe.Pointer(&m))
	KeepAlive(m)
	KeepAlive(attr)
	return ret
}
func pthread_mutex_init_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_mutex_lock(m *pthreadmutex) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_mutex_lock_trampoline)), unsafe.Pointer(&m))
	KeepAlive(m)
	return ret
}
func pthread_mutex_lock_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_mutex_unlock(m *pthreadmutex) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_mutex_unlock_trampoline)), unsafe.Pointer(&m))
	KeepAlive(m)
	return ret
}
func pthread_mutex_unlock_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_cond_init(c *pthreadcond, attr *pthreadcondattr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_cond_init_trampoline)), unsafe.Pointer(&c))
	KeepAlive(c)
	KeepAlive(attr)
	return ret
}
func pthread_cond_init_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_cond_wait(c *pthreadcond, m *pthreadmutex) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_cond_wait_trampoline)), unsafe.Pointer(&c))
	KeepAlive(c)
	KeepAlive(m)
	return ret
}
func pthread_cond_wait_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_cond_timedwait_relative_np(c *pthreadcond, m *pthreadmutex, t *timespec) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_cond_timedwait_relative_np_trampoline)), unsafe.Pointer(&c))
	KeepAlive(c)
	KeepAlive(m)
	KeepAlive(t)
	return ret
}
func pthread_cond_timedwait_relative_np_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func pthread_cond_signal(c *pthreadcond) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(pthread_cond_signal_trampoline)), unsafe.Pointer(&c))
	KeepAlive(c)
	return ret
}
func pthread_cond_signal_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func arc4random_buf(p unsafe.Pointer, n int32) {
	// arc4random_buf() never fails, per its man page, so it's safe to ignore the return value.
	libcCall(unsafe.Pointer(abi.FuncPCABI0(arc4random_buf_trampoline)), unsafe.Pointer(&p))
	KeepAlive(p)
}
func arc4random_buf_trampoline()

// Not used on Darwin, but must be defined.
func exitThread(wait *atomic.Uint32) {
	throw("exitThread")
}

//go:nosplit
func setNonblock(fd int32) {
	flags, _ := fcntl(fd, _F_GETFL, 0)
	if flags != -1 {
		fcntl(fd, _F_SETFL, flags|_O_NONBLOCK)
	}
}

func issetugid() int32 {
	return libcCall(unsafe.Pointer(abi.FuncPCABI0(issetugid_trampoline)), nil)
}
func issetugid_trampoline()

// mach_vm_region is used to obtain virtual memory mappings for use by the
// profiling system and is only exported to runtime/pprof. It is restricted
// to obtaining mappings for the current process.
//
//go:linkname mach_vm_region runtime/pprof.mach_vm_region
func mach_vm_region(address, region_size *uint64, info unsafe.Pointer) int32 {
	// kern_return_t mach_vm_region(
	// 	vm_map_read_t target_task,
	// 	mach_vm_address_t *address,
	// 	mach_vm_size_t *size,
	// 	vm_region_flavor_t flavor,
	// 	vm_region_info_t info,
	// 	mach_msg_type_number_t *infoCnt,
	// 	mach_port_t *object_name);
	var count machMsgTypeNumber = _VM_REGION_BASIC_INFO_COUNT_64
	var object_name machPort
	args := struct {
		address     *uint64
		size        *uint64
		flavor      machVMRegionFlavour
		info        unsafe.Pointer
		count       *machMsgTypeNumber
		object_name *machPort
	}{
		address:     address,
		size:        region_size,
		flavor:      _VM_REGION_BASIC_INFO_64,
		info:        info,
		count:       &count,
		object_name: &object_name,
	}
	return libcCall(unsafe.Pointer(abi.FuncPCABI0(mach_vm_region_trampoline)), unsafe.Pointer(&args))
}
func mach_vm_region_trampoline()

//go:linkname proc_regionfilename runtime/pprof.proc_regionfilename
func proc_regionfilename(pid int, address uint64, buf *byte, buflen int64) int32 {
	args := struct {
		pid     int
		address uint64
		buf     *byte
		bufSize int64
	}{
		pid:     pid,
		address: address,
		buf:     buf,
		bufSize: buflen,
	}
	return libcCall(unsafe.Pointer(abi.FuncPCABI0(proc_regionfilename_trampoline)), unsafe.Pointer(&args))
}
func proc_regionfilename_trampoline()

// Tell the linker that the libc_* functions are to be found
// in a system library, with the libc_ prefix missing.

//go:cgo_import_dynamic libc_pthread_attr_init pthread_attr_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_attr_getstacksize pthread_attr_getstacksize "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_attr_setdetachstate pthread_attr_setdetachstate "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_create pthread_create "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_self pthread_self "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_kill pthread_kill "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_exit _exit "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_raise raise "/usr/lib/libSystem.B.dylib"

//go:cgo_import_dynamic libc_open open "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_close close "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_read read "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_write write "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pipe pipe "/usr/lib/libSystem.B.dylib"

//go:cgo_import_dynamic libc_mmap mmap "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_munmap munmap "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_madvise madvise "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mlock mlock "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_error __error "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_usleep usleep "/usr/lib/libSystem.B.dylib"

//go:cgo_import_dynamic libc_proc_regionfilename proc_regionfilename "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_task_self_ mach_task_self_ "/usr/lib/libSystem.B.dylib""
//go:cgo_import_dynamic libc_mach_vm_region mach_vm_region "/usr/lib/libSystem.B.dylib""
//go:cgo_import_dynamic libc_mach_timebase_info mach_timebase_info "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_absolute_time mach_absolute_time "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_clock_gettime clock_gettime "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sigaction sigaction "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_sigmask pthread_sigmask "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sigaltstack sigaltstack "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_getpid getpid "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_kill kill "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_setitimer setitimer "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sysctl sysctl "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sysctlbyname sysctlbyname "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_fcntl fcntl "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_kqueue kqueue "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_kevent kevent "/usr/lib/libSystem.B.dylib"

//go:cgo_import_dynamic libc_pthread_mutex_init pthread_mutex_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_mutex_lock pthread_mutex_lock "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_mutex_unlock pthread_mutex_unlock "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_cond_init pthread_cond_init "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_cond_wait pthread_cond_wait "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_cond_timedwait_relative_np pthread_cond_timedwait_relative_np "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_pthread_cond_signal pthread_cond_signal "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_arc4random_buf arc4random_buf "/usr/lib/libSystem.B.dylib"

//go:cgo_import_dynamic libc_notify_is_valid_token notify_is_valid_token "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_xpc_date_create_from_current xpc_date_create_from_current "/usr/lib/libSystem.B.dylib"

//go:cgo_import_dynamic libc_issetugid issetugid "/usr/lib/libSystem.B.dylib"

"""



```