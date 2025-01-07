Response:
Let's break down the thought process for answering the user's request about the `sys_openbsd2.go` file.

**1. Understanding the Request:**

The user has provided a snippet of Go code and wants to understand its functionality within the Go runtime. The specific requests are:

* **List the functions' functionalities.**  This requires examining each function and explaining what it does.
* **Infer the Go feature implemented.** This is a higher-level task, requiring knowledge of the Go runtime and how it interacts with the operating system.
* **Provide Go code examples.**  Illustrate how these low-level functions are used indirectly by higher-level Go constructs.
* **Explain code reasoning (with input/output).** For complex functions, clarify the flow and data manipulation.
* **Describe command-line argument handling.** Determine if any functions directly deal with command-line arguments (in this case, unlikely).
* **Identify common mistakes.** Point out potential pitfalls for developers using (or misusing) related concepts.
* **Use Chinese as the output language.**  This is a presentation requirement.

**2. Initial Code Analysis and Key Observations:**

* **`//go:build openbsd && !mips64`:**  This build tag immediately tells us the code is specific to the OpenBSD operating system and excludes the `mips64` architecture.
* **`package runtime`:** This is a core Go package, indicating low-level operating system interactions.
* **`import (...)`:** The imports of `internal/abi` and `internal/runtime/atomic` confirm that this code interacts with the internal workings of the Go runtime and potentially with assembly language.
* **`//go:linkname`, `//go:nosplit`, `//go:cgo_unsafe_args`:** These compiler directives provide important clues.
    * `linkname`:  Indicates that the Go function is linked to a function with a different name in another package (likely C code via cgo).
    * `nosplit`: Prevents the Go stack from being split during the execution of these functions. This is crucial for low-level runtime code that must avoid acquiring locks or performing operations that could lead to deadlocks.
    * `cgo_unsafe_args`: Signifies that the function interacts with C code via cgo and might pass pointers directly, requiring careful handling to avoid memory safety issues.
* **`libcCall`:** This function (not shown in the provided snippet but implied) is a key piece. It's the mechanism by which Go calls functions in the C standard library (libc).
* **`_trampoline` suffixes:** The `_trampoline` functions are likely assembly stubs that perform the actual system call.
* **Function signatures:**  The function signatures often mirror common POSIX system calls (e.g., `exit`, `getthrid`, `mmap`, `open`, `read`, `write`, etc.).

**3. Detailed Function Analysis (Iterative Process):**

For each function, I would perform the following steps:

* **Identify the corresponding POSIX system call:**  The function name and arguments often provide a strong hint. For example, `exit(code int32)` clearly corresponds to the `exit()` system call.
* **Explain the function's purpose:** Describe what the system call does.
* **Note the use of `libcCall` and trampolines:** Explain that this is how Go interfaces with the C library.
* **Consider the `//go:nosplit` directive:** Explain why it's used (low-level, avoiding locks).
* **Look for `KeepAlive`:** This function prevents the Go garbage collector from prematurely collecting the memory pointed to by the arguments passed to the C function. This is vital for safety when dealing with C pointers.
* **Infer the Go feature:**  How is this system call used by Go?  For example, `mmap` is clearly related to memory management, `open`, `read`, `write` to file I/O, and `exit` to program termination.

**4. Inferring the Go Feature:**

After analyzing the individual functions, the overall picture becomes clearer. This file provides the low-level operating system primitives necessary for the Go runtime to function on OpenBSD. Key features implemented include:

* **Process and Thread Management:** `exit`, `getthrid`, `raiseproc`, `thrkill`.
* **Memory Management:** `mmap`, `munmap`, `madvise`.
* **File I/O:** `open`, `closefd`, `read`, `write1`, `pipe2`.
* **Timers and Sleep:** `setitimer`, `usleep`.
* **System Information:** `sysctl`.
* **File Control:** `fcntl`.
* **Time Retrieval:** `nanotime1`, `walltime`.
* **Event Notification:** `kqueue`, `kevent`.
* **Signal Handling:** `sigaction`, `sigprocmask`, `sigaltstack`.

**5. Creating Go Code Examples:**

The goal here is to show *indirect* usage. Since these functions are part of the runtime, regular Go code doesn't call them directly. The examples should illustrate higher-level Go constructs that rely on these underlying system calls. For instance:

* `os.Exit()` uses the `exit` system call.
* Creating a goroutine involves thread creation (indirectly using something like `getthrid`).
* `make([]byte, size)` or `new()` might use `mmap` for memory allocation.
* `os.Open()`, `f.Read()`, `f.Write()` use `open`, `read`, and `write`.
* `time.Sleep()` uses `usleep`.
* `syscall.Sysctl()` uses `sysctl`.
* `os/signal` package uses `sigaction` and `sigprocmask`.

**6. Code Reasoning (Example for `mmap`):**

For a more complex function like `mmap`, it's helpful to explain the purpose of the arguments and return values, even though the code itself is relatively straightforward. Highlighting the parameters passed to the system call is key.

**7. Command-Line Argument Handling:**

A quick scan reveals no direct handling of command-line arguments in this file. This functionality would typically reside in the `os` package or the `main` function of a Go program.

**8. Identifying Common Mistakes:**

This requires thinking about how developers interact with the *concepts* these functions represent, even if they don't call the runtime functions directly. Examples include:

* **Forgetting to close files (`closefd`).**
* **Incorrect signal handling.**
* **Potential issues with memory management (though Go mostly handles this).**

**9. Structuring the Answer and Using Chinese:**

Finally, organize the information logically, using clear and concise language. Ensure the entire response is translated into Chinese as requested. Pay attention to correct terminology and grammar. Use formatting (like headings and code blocks) to improve readability.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps provide very low-level examples using `syscall` package.
* **Correction:**  It's better to show how these functions are used *implicitly* through higher-level Go constructs, as this reflects typical usage.
* **Initial thought:** Focus heavily on the `libcCall` mechanism.
* **Correction:** While important, the *functionality* of each system call is more crucial for the user's understanding. Explain `libcCall` briefly but prioritize what each function *does*.
* **Ensure consistency in terminology and Chinese translation.**

By following these steps, the detailed and comprehensive answer to the user's request can be constructed.
这段代码是 Go 运行时（runtime）包中针对 OpenBSD 操作系统（且非 mips64 架构）实现的一部分，它定义了一系列与操作系统底层交互的函数。这些函数通常是对 OpenBSD 系统调用的 Go 封装。

以下是这些函数的功能列表：

* **`exit(code int32)` / `exit_trampoline()`:**  用于终止当前进程，并返回给操作系统一个退出码。`exit_trampoline` 是一个汇编层面的跳转点，用于实际调用 C 库中的 `exit` 函数。
* **`getthrid() (tid int32)` / `getthrid_trampoline()`:** 获取当前线程的 ID。它调用 OpenBSD 的 `getthrid` 系统调用。
* **`raiseproc(sig uint32)` / `raiseproc_trampoline()`:** 向当前进程发送一个信号。它调用 OpenBSD 相关的信号发送机制。
* **`thrkill(tid int32, sig int)` / `thrkill_trampoline()`:** 向指定线程发送一个信号。它调用 OpenBSD 的 `thrkill` 系统调用。
* **`mmap(addr unsafe.Pointer, n uintptr, prot, flags, fd int32, off uint32) (unsafe.Pointer, int)` / `mmap_trampoline()`:**  用于进行底层内存映射。它调用 OpenBSD 的 `mmap` 系统调用，允许将文件或设备映射到内存中，或分配一块新的内存区域。
* **`munmap(addr unsafe.Pointer, n uintptr)` / `munmap_trampoline()`:**  取消之前通过 `mmap` 映射的内存区域。它调用 OpenBSD 的 `munmap` 系统调用。
* **`madvise(addr unsafe.Pointer, n uintptr, flags int32)` / `madvise_trampoline()`:**  向内核提供关于内存使用模式的建议，可以帮助内核优化内存管理。它调用 OpenBSD 的 `madvise` 系统调用。
* **`open(name *byte, mode, perm int32) (ret int32)` / `open_trampoline()`:**  打开一个文件或设备。它调用 OpenBSD 的 `open` 系统调用。
* **`closefd(fd int32) int32` / `close_trampoline()`:** 关闭一个文件描述符。它调用 OpenBSD 的 `close` 系统调用。
* **`read(fd int32, p unsafe.Pointer, n int32) int32` / `read_trampoline()`:**  从一个文件描述符读取数据。它调用 OpenBSD 的 `read` 系统调用。
* **`write1(fd uintptr, p unsafe.Pointer, n int32) int32` / `write_trampoline()`:** 向一个文件描述符写入数据。它调用 OpenBSD 的 `write` 系统调用。 请注意，函数名是 `write1`，但实际上绑定的是 `write_trampoline`。
* **`pipe2(flags int32) (r, w int32, errno int32)` / `pipe2_trampoline()`:**  创建一个管道，可以用于进程间通信。`flags` 参数可以指定管道的属性（例如，`O_CLOEXEC`）。它调用 OpenBSD 的 `pipe2` 系统调用。
* **`setitimer(mode int32, new, old *itimerval)` / `setitimer_trampoline()`:** 设置间隔定时器，用于周期性地发送信号。它调用 OpenBSD 的 `setitimer` 系统调用。
* **`usleep(usec uint32)` / `usleep_trampoline()`:**  使当前线程休眠指定的微秒数。它调用 OpenBSD 的 `usleep` 系统调用。
* **`usleep_no_g(usec uint32)`:**  与 `usleep` 类似，但在没有 Go 协程（G）上下文的情况下调用。这通常用于非常底层的操作。
* **`sysctl(mib *uint32, miblen uint32, out *byte, size *uintptr, dst *byte, ndst uintptr) int32` / `sysctl_trampoline()`:**  获取或设置内核参数。它调用 OpenBSD 的 `sysctl` 系统调用。
* **`fcntl(fd, cmd, arg int32) (ret int32, errno int32)` / `fcntl_trampoline()`:**  对已打开的文件描述符执行各种控制操作，如修改文件状态标志。它调用 OpenBSD 的 `fcntl` 系统调用。
* **`nanotime1() int64` / `clock_gettime_trampoline()`:** 获取高精度的时间戳（纳秒级别），通常使用单调时钟。它调用 OpenBSD 的 `clock_gettime` 系统调用，使用 `_CLOCK_MONOTONIC`。
* **`walltime() (int64, int32)` / `clock_gettime_trampoline()`:** 获取当前时间（秒和纳秒）。它调用 OpenBSD 的 `clock_gettime` 系统调用，使用 `_CLOCK_REALTIME`。
* **`kqueue() int32` / `kqueue_trampoline()`:** 创建一个 kqueue 文件描述符，用于事件通知。它是 OpenBSD 特有的事件通知机制。
* **`kevent(kq int32, ch *keventt, nch int32, ev *keventt, nev int32, ts *timespec) int32` / `kevent_trampoline()`:**  在 kqueue 上注册、修改或删除事件，并等待事件发生。
* **`sigaction(sig uint32, new *sigactiont, old *sigactiont)` / `sigaction_trampoline()`:**  设置进程对特定信号的处理方式。
* **`sigprocmask(how uint32, new *sigset, old *sigset)` / `sigprocmask_trampoline()`:**  检查或更改阻塞的信号集。 `sigprocmask_trampoline` 在没有 Go 协程上下文的情况下调用。
* **`sigaltstack(new *stackt, old *stackt)` / `sigaltstack_trampoline()`:** 设置或查询信号处理函数使用的备用堆栈。
* **`exitThread(wait *atomic.Uint32)`:**  在 OpenBSD 上未使用，但必须定义。它会抛出一个 panic。
* **`issetugid() (ret int32)` / `issetugid_trampoline()`:**  检查进程的有效用户 ID 是否与实际用户 ID 或保存的设置用户 ID 不同。这通常用于检测程序是否以特权模式运行。

**Go 语言功能的实现:**

这段代码是 Go 运行时与操作系统交互的基础，它实现了 Go 语言在 OpenBSD 上的核心功能，例如：

* **协程 (Goroutine) 的调度和管理:**  涉及到线程的创建、终止和信号处理。 `getthrid`, `thrkill`, `sigaction`, `sigprocmask`, `sigaltstack` 等函数都与此相关。
* **内存管理:** `mmap`, `munmap`, `madvise` 用于实现 Go 的堆内存分配和管理。
* **文件 I/O:** `open`, `closefd`, `read`, `write1`, `pipe2` 是 Go 标准库中 `os` 包进行文件操作的基础。
* **时间相关功能:** `nanotime1`, `walltime`, `usleep`, `setitimer` 用于实现 Go 的 `time` 包中的时间获取和休眠等功能。
* **系统调用访问:**  `sysctl`, `fcntl` 允许 Go 程序进行更底层的系统调用操作。
* **事件通知:** `kqueue`, `kevent` 是 Go 在 OpenBSD 上实现 `select` 和 `epoll` 类似功能的基础。
* **进程控制:** `exit` 用于程序的正常退出。

**Go 代码举例说明:**

虽然开发者通常不会直接调用这些 `runtime` 包中的函数，但 Go 的标准库会使用它们。以下是一些例子，说明了这些底层函数在更高层次 Go 代码中的作用：

```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// 使用 os.Exit 会间接调用 runtime.exit
	// os.Exit(0)

	// 使用 os.OpenFile 会间接调用 runtime.open 和 runtime.closefd
	file, err := os.OpenFile("test.txt", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	// 使用 file.Write 会间接调用 runtime.write1
	_, err = file.WriteString("Hello, OpenBSD!\n")
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}

	// 使用 time.Sleep 会间接调用 runtime.usleep
	time.Sleep(1 * time.Second)
	fmt.Println("Woke up!")

	// 使用 syscall.Sysctl 会间接调用 runtime.sysctl
	mib := []int32{syscall.CTL_KERN, syscall.KERN_OSTYPE}
	buf := make([]byte, 64)
	n, err := syscall.SysctlRaw(mib)
	if err != nil {
		fmt.Println("Error getting kernel ostype:", err)
	} else {
		fmt.Printf("Kernel OSType: %s\n", string(n))
	}

	// 使用 signal.Notify 会间接调用 runtime.sigaction 和 runtime.sigprocmask
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Println("\nReceived signal:", sig)
		// os.Exit(0)
	}()
	fmt.Println("Waiting for signal...")
	time.Sleep(5 * time.Second)
}
```

**假设的输入与输出 (针对 `open` 函数):**

**假设输入:**

```go
package main

import "syscall"

func main() {
	name := "/tmp/test_openbsd.txt"
	mode := syscall.O_RDWR | syscall.O_CREATE
	perm := int32(0644)
	fd, err := syscall.Open(name, mode, uint32(perm))
	if err != nil {
		println("Error opening file:", err.Error())
		return
	}
	println("File opened with fd:", fd)
	syscall.Close(fd)
}
```

**预期输出:**

如果在 `/tmp` 目录下不存在 `test_openbsd.txt` 文件，则会创建该文件，并且输出类似：

```
File opened with fd: 3
```

文件描述符的具体数值可能会有所不同。如果文件已存在，且 `mode` 中没有 `O_TRUNC`，则会打开现有文件。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `os` 包的更上层，例如 `os.Args` 变量。 `runtime` 包的这些底层函数并不直接感知命令行参数。

**使用者易犯错的点:**

* **文件描述符泄露:**  如果 `open` 调用成功后，返回的文件描述符没有被 `closefd` 正确关闭，会导致资源泄露。在 Go 中，通常使用 `defer file.Close()` 来确保文件关闭。
* **不安全地使用 `unsafe` 包:** 这些 `runtime` 函数大量使用了 `unsafe.Pointer`，直接操作内存。如果用户在自己的代码中不恰当地使用 `unsafe` 包，可能会导致程序崩溃或安全问题。但这通常不是直接调用这些 `runtime` 函数的错误，而是使用 `unsafe` 包的风险。
* **信号处理的复杂性:**  错误地设置或处理信号可能导致程序行为异常。例如，忘记恢复默认的信号处理程序，或者在信号处理函数中执行不安全的操作。
* **不理解系统调用的语义:**  例如，错误地使用 `mmap` 的参数可能导致程序崩溃或数据损坏。虽然 Go 封装了这些系统调用，但在某些需要直接使用 `syscall` 包的场景下，开发者需要理解这些底层调用的含义。

总结来说，这段 `sys_openbsd2.go` 文件是 Go 运行时在 OpenBSD 操作系统上的基石，它通过 cgo 技术与底层的 C 库进行交互，提供了 Go 程序运行所需的各种操作系统服务。开发者通常不需要直接接触这些函数，而是通过 Go 标准库提供的更高级的抽象来使用它们。

Prompt: 
```
这是路径为go/src/runtime/sys_openbsd2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build openbsd && !mips64

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"unsafe"
)

// This is exported via linkname to assembly in runtime/cgo.
//
//go:linkname exit
//go:nosplit
//go:cgo_unsafe_args
func exit(code int32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(exit_trampoline)), unsafe.Pointer(&code))
}
func exit_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func getthrid() (tid int32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(getthrid_trampoline)), unsafe.Pointer(&tid))
	return
}
func getthrid_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func raiseproc(sig uint32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(raiseproc_trampoline)), unsafe.Pointer(&sig))
}
func raiseproc_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func thrkill(tid int32, sig int) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(thrkill_trampoline)), unsafe.Pointer(&tid))
}
func thrkill_trampoline()

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
	KeepAlive(addr) // Just for consistency. Hopefully addr is not a Go address.
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
func open(name *byte, mode, perm int32) (ret int32) {
	ret = libcCall(unsafe.Pointer(abi.FuncPCABI0(open_trampoline)), unsafe.Pointer(&name))
	KeepAlive(name)
	return
}
func open_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func closefd(fd int32) int32 {
	return libcCall(unsafe.Pointer(abi.FuncPCABI0(close_trampoline)), unsafe.Pointer(&fd))
}
func close_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func read(fd int32, p unsafe.Pointer, n int32) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(read_trampoline)), unsafe.Pointer(&fd))
	KeepAlive(p)
	return ret
}
func read_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func write1(fd uintptr, p unsafe.Pointer, n int32) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(write_trampoline)), unsafe.Pointer(&fd))
	KeepAlive(p)
	return ret
}
func write_trampoline()

func pipe2(flags int32) (r, w int32, errno int32) {
	var p [2]int32
	args := struct {
		p     unsafe.Pointer
		flags int32
	}{noescape(unsafe.Pointer(&p)), flags}
	errno = libcCall(unsafe.Pointer(abi.FuncPCABI0(pipe2_trampoline)), unsafe.Pointer(&args))
	return p[0], p[1], errno
}
func pipe2_trampoline()

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
func sysctl(mib *uint32, miblen uint32, out *byte, size *uintptr, dst *byte, ndst uintptr) int32 {
	ret := libcCall(unsafe.Pointer(abi.FuncPCABI0(sysctl_trampoline)), unsafe.Pointer(&mib))
	KeepAlive(mib)
	KeepAlive(out)
	KeepAlive(size)
	KeepAlive(dst)
	return ret
}
func sysctl_trampoline()

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
func nanotime1() int64 {
	var ts timespec
	args := struct {
		clock_id int32
		tp       unsafe.Pointer
	}{_CLOCK_MONOTONIC, unsafe.Pointer(&ts)}
	if errno := libcCall(unsafe.Pointer(abi.FuncPCABI0(clock_gettime_trampoline)), unsafe.Pointer(&args)); errno < 0 {
		// Avoid growing the nosplit stack.
		systemstack(func() {
			println("runtime: errno", -errno)
			throw("clock_gettime failed")
		})
	}
	return ts.tv_sec*1e9 + int64(ts.tv_nsec)
}
func clock_gettime_trampoline()

//go:nosplit
func walltime() (int64, int32) {
	var ts timespec
	args := struct {
		clock_id int32
		tp       unsafe.Pointer
	}{_CLOCK_REALTIME, unsafe.Pointer(&ts)}
	if errno := libcCall(unsafe.Pointer(abi.FuncPCABI0(clock_gettime_trampoline)), unsafe.Pointer(&args)); errno < 0 {
		// Avoid growing the nosplit stack.
		systemstack(func() {
			println("runtime: errno", -errno)
			throw("clock_gettime failed")
		})
	}
	return ts.tv_sec, int32(ts.tv_nsec)
}

//go:nosplit
//go:cgo_unsafe_args
func kqueue() int32 {
	return libcCall(unsafe.Pointer(abi.FuncPCABI0(kqueue_trampoline)), nil)
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
func sigaction(sig uint32, new *sigactiont, old *sigactiont) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(sigaction_trampoline)), unsafe.Pointer(&sig))
	KeepAlive(new)
	KeepAlive(old)
}
func sigaction_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sigprocmask(how uint32, new *sigset, old *sigset) {
	// sigprocmask is called from sigsave, which is called from needm.
	// As such, we have to be able to run with no g here.
	asmcgocall_no_g(unsafe.Pointer(abi.FuncPCABI0(sigprocmask_trampoline)), unsafe.Pointer(&how))
	KeepAlive(new)
	KeepAlive(old)
}
func sigprocmask_trampoline()

//go:nosplit
//go:cgo_unsafe_args
func sigaltstack(new *stackt, old *stackt) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(sigaltstack_trampoline)), unsafe.Pointer(&new))
	KeepAlive(new)
	KeepAlive(old)
}
func sigaltstack_trampoline()

// Not used on OpenBSD, but must be defined.
func exitThread(wait *atomic.Uint32) {
	throw("exitThread")
}

//go:nosplit
//go:cgo_unsafe_args
func issetugid() (ret int32) {
	libcCall(unsafe.Pointer(abi.FuncPCABI0(issetugid_trampoline)), unsafe.Pointer(&ret))
	return
}
func issetugid_trampoline()

// Tell the linker that the libc_* functions are to be found
// in a system library, with the libc_ prefix missing.

//go:cgo_import_dynamic libc_errno __errno "libc.so"
//go:cgo_import_dynamic libc_exit exit "libc.so"
//go:cgo_import_dynamic libc_getthrid getthrid "libc.so"
//go:cgo_import_dynamic libc_sched_yield sched_yield "libc.so"
//go:cgo_import_dynamic libc_thrkill thrkill "libc.so"

//go:cgo_import_dynamic libc_mmap mmap "libc.so"
//go:cgo_import_dynamic libc_munmap munmap "libc.so"
//go:cgo_import_dynamic libc_madvise madvise "libc.so"

//go:cgo_import_dynamic libc_open open "libc.so"
//go:cgo_import_dynamic libc_close close "libc.so"
//go:cgo_import_dynamic libc_read read "libc.so"
//go:cgo_import_dynamic libc_write write "libc.so"
//go:cgo_import_dynamic libc_pipe2 pipe2 "libc.so"

//go:cgo_import_dynamic libc_clock_gettime clock_gettime "libc.so"
//go:cgo_import_dynamic libc_setitimer setitimer "libc.so"
//go:cgo_import_dynamic libc_usleep usleep "libc.so"
//go:cgo_import_dynamic libc_sysctl sysctl "libc.so"
//go:cgo_import_dynamic libc_fcntl fcntl "libc.so"
//go:cgo_import_dynamic libc_getpid getpid "libc.so"
//go:cgo_import_dynamic libc_kill kill "libc.so"
//go:cgo_import_dynamic libc_kqueue kqueue "libc.so"
//go:cgo_import_dynamic libc_kevent kevent "libc.so"

//go:cgo_import_dynamic libc_sigaction sigaction "libc.so"
//go:cgo_import_dynamic libc_sigaltstack sigaltstack "libc.so"

//go:cgo_import_dynamic libc_issetugid issetugid "libc.so"

//go:cgo_import_dynamic _ _ "libc.so"

"""



```