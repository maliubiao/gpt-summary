Response:
Let's break down the thought process for analyzing this Go runtime file for FreeBSD.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly read through the code, looking for keywords and patterns that give clues about the file's purpose. Keywords like `// Copyright`, `package runtime`, `import`, `type`, `func`, `//go:`, `const`, `var` immediately stand out. I also look for function names that resemble system calls or OS-level operations (e.g., `thr_new`, `sigaltstack`, `sysctl`, `kqueue`, `pipe2`, `fcntl`).

**2. Understanding the `package runtime` Context:**

Knowing this file is in the `runtime` package is crucial. This package is the heart of the Go runtime environment, handling low-level tasks like memory management, goroutine scheduling, and interaction with the operating system. Therefore, the functions here likely bridge the gap between Go's abstract execution model and the specifics of FreeBSD.

**3. Categorizing Functionality:**

I start grouping the functions based on their apparent purpose:

* **Thread Management:** Functions like `thr_new`, `thr_self`, `thr_kill`, `newosproc`, `newosproc0` clearly deal with creating, identifying, and managing operating system threads. The `mOS` struct likely holds OS-specific thread data.
* **Signal Handling:**  `sigaltstack`, `sigprocmask`, `sigaction`, `sigtramp`, `setsigstack`, `getsig`, `sigaddset`, `sigdelset`, `raise`, `signalM` are all related to signal management. This is a core OS interaction needed for handling interrupts, errors, and other asynchronous events.
* **System Calls:**  `sysctl`, `kqueue`, `kevent`, `pipe2`, `fcntl`, `sys_umtx_op` are direct interfaces to FreeBSD system calls, offering access to various kernel functionalities.
* **Time and Scheduling:**  `setitimer`, `osyield`, `osyield_no_g`, `futexsleep`, `futexwakeup`, `setProcessCPUProfiler`, `setThreadCPUProfiler` relate to timing, yielding execution, and potentially profiling.
* **CPU Affinity:** `cpuset_getaffinity`, `getncpu` are involved in managing which CPU cores a process or thread can run on.
* **Memory Management (Indirect):** `getPageSize`, `sysAlloc` (mentioned in comments) are related to memory allocation and page size retrieval, although `sysAlloc` isn't directly in this file.
* **Initialization:** `osinit`, `mpreinit`, `minit`, `unminit`, `mdestroy`, `libpreinit`, `sysargs`, `sysauxv`, `goenvs` are for setting up and tearing down the runtime environment.
* **Randomness:** `readRandom` is for obtaining random numbers.

**4. Inferring Go Features:**

Now, I connect the identified functions to higher-level Go features:

* **Goroutines and OS Threads:** The functions related to thread management (`thr_new`, `newosproc`) are the underlying mechanism for implementing goroutines. Go multiplexes goroutines onto a smaller number of OS threads.
* **`sync` Package Primitives (Mutexes, WaitGroups, etc.):**  `sys_umtx_op`, `futexsleep`, `futexwakeup` strongly suggest the implementation of low-level synchronization primitives used by the `sync` package (e.g., mutexes, condition variables). The comment mentioning "Linux's futex" reinforces this.
* **Signal Handling (e.g., `os/signal`):** The various `sig*` functions are the OS-specific implementation for Go's `os/signal` package, which allows Go programs to handle system signals.
* **Process Management (e.g., `os` package):** Functions like `pipe2`, `fcntl`, and the ability to get the process ID relate to Go's `os` package and its functions for interacting with the operating system (e.g., creating pipes, manipulating file descriptors).
* **CPU Profiling (`runtime/pprof`):** `setProcessCPUProfiler`, `setThreadCPUProfiler` directly link to the CPU profiling capabilities exposed by the `runtime/pprof` package.
* **Getting System Information:** `sysctl`, `getncpu`, `getPageSize` are used to retrieve system information like the number of CPUs and page size, often needed for runtime initialization and resource management.

**5. Code Examples and Assumptions:**

For each inferred Go feature, I try to construct a simple Go code example. This often requires making reasonable assumptions about how the underlying functions are used.

* **Example for Goroutines:** I use the simplest `go func() {}()` example, assuming `newosproc` is called when a new OS thread is needed to run goroutines.
* **Example for Mutexes:** I show a basic mutex lock/unlock pattern, assuming `futexsleep` and `futexwakeup` are involved in the underlying implementation when a goroutine needs to wait for a mutex.
* **Example for Signals:** I use `signal.Notify` to illustrate how Go programs can register signal handlers, linking it to the `sigaction` and related functions.
* **Example for Pipes:** I demonstrate the basic creation and use of a pipe, connecting it to the `pipe2` function.
* **Example for CPU Profiling:**  I show the standard way to start and stop CPU profiling using `pprof`.

**6. Command-Line Arguments:**

I consider if any of the functions relate to handling command-line arguments. `sysargs` is a strong indicator of this. I explain how it retrieves the arguments and auxiliary vector, which can contain system information passed from the kernel.

**7. Common Mistakes:**

I think about potential pitfalls for users based on the low-level nature of this code. Incorrect signal handling (blocking important signals) and misunderstanding CPU affinity settings are common issues when dealing with these kinds of OS-level functionalities.

**8. Structuring the Answer:**

Finally, I organize the information into a clear and structured format, using headings, bullet points, and code blocks to make it easy to read and understand. I use Chinese as requested in the prompt. I also ensure to address all parts of the original request.

This iterative process of scanning, categorizing, inferring, and exemplifying allows me to effectively analyze the given Go runtime code and explain its functionality in the context of higher-level Go features.
这段代码是 Go 语言运行时（runtime）的一部分，专门用于 FreeBSD 操作系统。它包含了与操作系统底层交互的函数，用于支持 Go 程序的运行。以下是其主要功能：

**1. 线程管理:**

* **`thr_new`**:  创建一个新的内核线程。这是 Go 创建新的操作系统线程（用于运行 Goroutine）的基础。
* **`thr_self`**: 获取当前线程的 ID。
* **`thr_kill`**: 向指定的线程发送信号。
* **`newosproc`**: Go 运行时用来创建新的操作系统线程的函数，它会调用 `thr_new`。
* **`newosproc0`**: 一个不需要有效 G（Goroutine 结构）的 `newosproc` 版本，主要用于早期的初始化阶段。

**2. 信号处理:**

* **`sigaltstack`**:  设置或获取信号处理程序的备用堆栈。这对于防止信号处理程序栈溢出非常重要。
* **`sigprocmask`**:  检查或更改线程的信号屏蔽字（哪些信号被阻塞）。
* **`sigaction`**:  检查或修改与特定信号关联的操作（例如，信号处理程序）。
* **`sigtramp`**:  信号处理程序的入口点（汇编实现，未在此文件中）。
* **`setsigstack`**: 设置信号处理程序使用备用堆栈。
* **`getsig`**: 获取指定信号的当前处理程序。
* **`sigaddset`**: 向信号集中添加一个信号。
* **`sigdelset`**: 从信号集中删除一个信号。
* **`raise`**: 向当前线程发送一个信号。
* **`signalM`**: 向指定的 M（Machine，代表一个操作系统线程）发送信号。

**3. 系统调用封装:**

* **`sysctl`**:  允许获取和设置内核参数。Go 使用它来获取诸如页大小、CPU 数量等信息。
* **`kqueue`**: 创建一个新的内核事件队列，用于高效地监视文件描述符和其他内核事件。
* **`kevent`**:  修改或等待内核事件队列中的事件。
* **`pipe2`**: 创建一个管道。
* **`fcntl`**:  对打开的文件描述符执行各种操作（例如，设置非阻塞模式）。
* **`sys_umtx_op`**: FreeBSD 的用户模式互斥操作，类似于 Linux 的 `futex`。用于实现低级别的同步原语。

**4. 同步原语（基于 `sys_umtx_op`）:**

* **`futexsleep`**:  使 Goroutine 进入睡眠状态，等待在指定地址上的互斥锁被释放。
* **`futexsleep1`**:  `futexsleep` 的实际实现。
* **`futexwakeup`**: 唤醒等待在指定地址上的互斥锁的 Goroutine。

**5. CPU 亲和性:**

* **`cpuset_getaffinity`**: 获取指定进程或线程的 CPU 亲和性掩码（允许其运行的 CPU 核心）。
* **`getncpu`**: 获取系统中的 CPU 核心数量。

**6. 其他系统交互:**

* **`setitimer`**: 设置一个间隔计时器，用于周期性地发送信号。可能用于实现 Go 的定时器功能或 CPU profiling。
* **`osyield`**:  主动让出当前线程的 CPU 时间片。
* **`issetugid`**: 检查进程是否以设置用户 ID 或设置组 ID 的权限运行。
* **`readRandom`**: 从 `/dev/urandom` 读取随机数。

**7. 运行时初始化:**

* **`osinit`**: 操作系统相关的初始化，例如获取 CPU 数量和页大小。
* **`mpreinit`**: 初始化一个新的 M 结构（代表一个操作系统线程），在父线程中调用。
* **`minit`**: 初始化一个新的 M 结构，在新线程中调用。
* **`unminit`**: 撤销 `minit` 的影响。
* **`mdestroy`**: 释放与 M 关联的资源。
* **`libpreinit`**: 在以 `c-archive` 或 `c-shared` 模式构建的 Go 代码中进行同步初始化。
* **`goenvs`**: 获取并处理 Go 环境变量。
* **`sysargs`**:  解析命令行参数和辅助向量。
* **`sysauxv`**: 处理辅助向量，从中提取系统信息。

**8. CPU Profiling:**

* **`setProcessCPUProfiler`**: 设置进程级别的 CPU profiler。
* **`setThreadCPUProfiler`**: 设置线程级别的 CPU profiler。
* **`validSIGPROF`**: 检查 `SIGPROF` 信号是否有效（用于 CPU profiling）。

**推理 Go 语言功能实现并举例:**

这段代码是 Go 运行时与 FreeBSD 操作系统交互的桥梁，它支撑着许多核心的 Go 语言功能。

**示例 1: Goroutine 的创建和调度**

* **推理:** `newosproc` 函数调用了底层的 `thr_new`，这表明 Go 的 Goroutine 是通过操作系统的线程来实现的。当 Go 需要创建一个新的并发执行单元时，它可能会调用 `newosproc` 来创建一个新的 OS 线程。

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	fmt.Println("当前 Goroutine 数量:", runtime.NumGoroutine())

	go func() {
		fmt.Println("新的 Goroutine 正在运行")
		time.Sleep(time.Second)
		fmt.Println("新的 Goroutine 运行结束")
	}()

	time.Sleep(500 * time.Millisecond) // 让新的 Goroutine 有机会运行
	fmt.Println("当前 Goroutine 数量:", runtime.NumGoroutine())

	time.Sleep(time.Second * 2) // 等待新的 Goroutine 结束
	fmt.Println("当前 Goroutine 数量:", runtime.NumGoroutine())
}

// 假设输入：无
// 预期输出（大致）：
// 当前 Goroutine 数量: 1
// 新的 Goroutine 正在运行
// 当前 Goroutine 数量: 2
// 新的 Goroutine 运行结束
// 当前 Goroutine 数量: 1
```

**示例 2: `sync.Mutex` 的实现**

* **推理:** `futexsleep` 和 `futexwakeup` 函数与 Linux 的 `futex` 功能类似，通常用于实现用户态的锁机制。Go 的 `sync.Mutex` 很可能在底层使用了这些系统调用来实现高效的互斥。

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

var counter int
var mu sync.Mutex

func increment() {
	mu.Lock()
	defer mu.Unlock()
	counter++
}

func main() {
	runtime.GOMAXPROCS(2) // 确保至少有两个 Goroutine 可以并行运行

	for i := 0; i < 1000; i++ {
		go increment()
	}

	time.Sleep(time.Second) // 等待所有 Goroutine 完成
	fmt.Println("Counter:", counter)
}

// 假设输入：无
// 预期输出：Counter: 1000 (由于互斥锁的保护，最终计数结果应该是准确的)
```

**示例 3: 信号处理 (`os/signal`)**

* **推理:** 代码中大量的 `sig*` 函数表明 Go 运行时需要处理操作系统信号。`os/signal` 包允许 Go 程序注册信号处理函数。

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
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Println("\n接收到信号:", sig)
		os.Exit(0)
	}()

	fmt.Println("等待信号...")
	time.Sleep(time.Hour)
}

// 假设输入：运行程序后，在终端按下 Ctrl+C (发送 SIGINT 信号)
// 预期输出：
// 等待信号...
//
// 接收到信号: interrupt
```

**命令行参数处理:**

`sysargs` 函数负责处理传递给 Go 程序的命令行参数。它会解析 `argc` (参数数量) 和 `argv` (参数字符串数组)。此外，它还会读取 `auxv` (辅助向量)，这是一个内核传递给程序的环境信息数组，包含诸如页大小等信息。

当启动一个 Go 程序时，操作系统会将命令行参数和辅助向量传递给程序。`sysargs` 会将这些信息存储起来，供 Go 运行时使用。例如，`os.Args` 就是通过这种方式获取命令行参数的。

**使用者易犯错的点:**

对于一般的 Go 开发者来说，直接与 `runtime/os_freebsd.go` 中的函数交互的情况非常少见。这些都是 Go 运行时的内部实现细节。但是，理解这些底层机制可以帮助理解一些潜在的问题：

* **信号处理不当:**  错误地屏蔽或处理信号可能导致程序行为异常甚至崩溃。例如，如果程序阻塞了 `SIGKILL` 信号，那么 `kill -9` 命令将无法正常终止程序。
* **CPU 亲和性设置不当:**  错误地设置 CPU 亲和性可能会限制程序的性能，尤其是在多核系统上。例如，将一个计算密集型的 Goroutine 限制在一个核心上运行，就无法充分利用多核的优势。

总而言之，`go/src/runtime/os_freebsd.go` 是 Go 运行时在 FreeBSD 操作系统上的基石，它提供了与操作系统交互的各种底层功能，使得 Go 程序能够在这个平台上正常运行。理解这些功能有助于深入理解 Go 运行时的机制。

Prompt: 
```
这是路径为go/src/runtime/os_freebsd.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

type mOS struct {
	waitsema uint32 // semaphore for parking on locks
}

//go:noescape
func thr_new(param *thrparam, size int32) int32

//go:noescape
func sigaltstack(new, old *stackt)

//go:noescape
func sigprocmask(how int32, new, old *sigset)

//go:noescape
func setitimer(mode int32, new, old *itimerval)

//go:noescape
func sysctl(mib *uint32, miblen uint32, out *byte, size *uintptr, dst *byte, ndst uintptr) int32

func raiseproc(sig uint32)

func thr_self() thread
func thr_kill(tid thread, sig int)

//go:noescape
func sys_umtx_op(addr *uint32, mode int32, val uint32, uaddr1 uintptr, ut *umtx_time) int32

func osyield()

//go:nosplit
func osyield_no_g() {
	osyield()
}

func kqueue() int32

//go:noescape
func kevent(kq int32, ch *keventt, nch int32, ev *keventt, nev int32, ts *timespec) int32

func pipe2(flags int32) (r, w int32, errno int32)
func fcntl(fd, cmd, arg int32) (ret int32, errno int32)

func issetugid() int32

// From FreeBSD's <sys/sysctl.h>
const (
	_CTL_HW      = 6
	_HW_PAGESIZE = 7
)

var sigset_all = sigset{[4]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}}

// Undocumented numbers from FreeBSD's lib/libc/gen/sysctlnametomib.c.
const (
	_CTL_QUERY     = 0
	_CTL_QUERY_MIB = 3
)

// sysctlnametomib fill mib with dynamically assigned sysctl entries of name,
// return count of effected mib slots, return 0 on error.
func sysctlnametomib(name []byte, mib *[_CTL_MAXNAME]uint32) uint32 {
	oid := [2]uint32{_CTL_QUERY, _CTL_QUERY_MIB}
	miblen := uintptr(_CTL_MAXNAME)
	if sysctl(&oid[0], 2, (*byte)(unsafe.Pointer(mib)), &miblen, (*byte)(unsafe.Pointer(&name[0])), (uintptr)(len(name))) < 0 {
		return 0
	}
	miblen /= unsafe.Sizeof(uint32(0))
	if miblen <= 0 {
		return 0
	}
	return uint32(miblen)
}

const (
	_CPU_CURRENT_PID = -1 // Current process ID.
)

//go:noescape
func cpuset_getaffinity(level int, which int, id int64, size int, mask *byte) int32

//go:systemstack
func getncpu() int32 {
	// Use a large buffer for the CPU mask. We're on the system
	// stack, so this is fine, and we can't allocate memory for a
	// dynamically-sized buffer at this point.
	const maxCPUs = 64 * 1024
	var mask [maxCPUs / 8]byte
	var mib [_CTL_MAXNAME]uint32

	// According to FreeBSD's /usr/src/sys/kern/kern_cpuset.c,
	// cpuset_getaffinity return ERANGE when provided buffer size exceed the limits in kernel.
	// Querying kern.smp.maxcpus to calculate maximum buffer size.
	// See https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=200802

	// Variable kern.smp.maxcpus introduced at Dec 23 2003, revision 123766,
	// with dynamically assigned sysctl entries.
	miblen := sysctlnametomib([]byte("kern.smp.maxcpus"), &mib)
	if miblen == 0 {
		return 1
	}

	// Query kern.smp.maxcpus.
	dstsize := uintptr(4)
	maxcpus := uint32(0)
	if sysctl(&mib[0], miblen, (*byte)(unsafe.Pointer(&maxcpus)), &dstsize, nil, 0) != 0 {
		return 1
	}

	maskSize := int(maxcpus+7) / 8
	if maskSize < goarch.PtrSize {
		maskSize = goarch.PtrSize
	}
	if maskSize > len(mask) {
		maskSize = len(mask)
	}

	if cpuset_getaffinity(_CPU_LEVEL_WHICH, _CPU_WHICH_PID, _CPU_CURRENT_PID,
		maskSize, (*byte)(unsafe.Pointer(&mask[0]))) != 0 {
		return 1
	}
	n := int32(0)
	for _, v := range mask[:maskSize] {
		for v != 0 {
			n += int32(v & 1)
			v >>= 1
		}
	}
	if n == 0 {
		return 1
	}
	return n
}

func getPageSize() uintptr {
	mib := [2]uint32{_CTL_HW, _HW_PAGESIZE}
	out := uint32(0)
	nout := unsafe.Sizeof(out)
	ret := sysctl(&mib[0], 2, (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	if ret >= 0 {
		return uintptr(out)
	}
	return 0
}

// FreeBSD's umtx_op syscall is effectively the same as Linux's futex, and
// thus the code is largely similar. See Linux implementation
// and lock_futex.go for comments.

//go:nosplit
func futexsleep(addr *uint32, val uint32, ns int64) {
	systemstack(func() {
		futexsleep1(addr, val, ns)
	})
}

func futexsleep1(addr *uint32, val uint32, ns int64) {
	var utp *umtx_time
	if ns >= 0 {
		var ut umtx_time
		ut._clockid = _CLOCK_MONOTONIC
		ut._timeout.setNsec(ns)
		utp = &ut
	}
	ret := sys_umtx_op(addr, _UMTX_OP_WAIT_UINT_PRIVATE, val, unsafe.Sizeof(*utp), utp)
	if ret >= 0 || ret == -_EINTR || ret == -_ETIMEDOUT {
		return
	}
	print("umtx_wait addr=", addr, " val=", val, " ret=", ret, "\n")
	*(*int32)(unsafe.Pointer(uintptr(0x1005))) = 0x1005
}

//go:nosplit
func futexwakeup(addr *uint32, cnt uint32) {
	ret := sys_umtx_op(addr, _UMTX_OP_WAKE_PRIVATE, cnt, 0, nil)
	if ret >= 0 {
		return
	}

	systemstack(func() {
		print("umtx_wake_addr=", addr, " ret=", ret, "\n")
	})
}

func thr_start()

// May run with m.p==nil, so write barriers are not allowed.
//
//go:nowritebarrier
func newosproc(mp *m) {
	stk := unsafe.Pointer(mp.g0.stack.hi)
	if false {
		print("newosproc stk=", stk, " m=", mp, " g=", mp.g0, " thr_start=", abi.FuncPCABI0(thr_start), " id=", mp.id, " ostk=", &mp, "\n")
	}

	param := thrparam{
		start_func: abi.FuncPCABI0(thr_start),
		arg:        unsafe.Pointer(mp),
		stack_base: mp.g0.stack.lo,
		stack_size: uintptr(stk) - mp.g0.stack.lo,
		child_tid:  nil, // minit will record tid
		parent_tid: nil,
		tls_base:   unsafe.Pointer(&mp.tls[0]),
		tls_size:   unsafe.Sizeof(mp.tls),
	}

	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	ret := retryOnEAGAIN(func() int32 {
		errno := thr_new(&param, int32(unsafe.Sizeof(param)))
		// thr_new returns negative errno
		return -errno
	})
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret != 0 {
		print("runtime: failed to create new OS thread (have ", mcount(), " already; errno=", ret, ")\n")
		throw("newosproc")
	}
}

// Version of newosproc that doesn't require a valid G.
//
//go:nosplit
func newosproc0(stacksize uintptr, fn unsafe.Pointer) {
	stack := sysAlloc(stacksize, &memstats.stacks_sys)
	if stack == nil {
		writeErrStr(failallocatestack)
		exit(1)
	}
	// This code "knows" it's being called once from the library
	// initialization code, and so it's using the static m0 for the
	// tls and procid (thread) pointers. thr_new() requires the tls
	// pointers, though the tid pointers can be nil.
	// However, newosproc0 is currently unreachable because builds
	// utilizing c-shared/c-archive force external linking.
	param := thrparam{
		start_func: uintptr(fn),
		arg:        nil,
		stack_base: uintptr(stack), //+stacksize?
		stack_size: stacksize,
		child_tid:  nil, // minit will record tid
		parent_tid: nil,
		tls_base:   unsafe.Pointer(&m0.tls[0]),
		tls_size:   unsafe.Sizeof(m0.tls),
	}

	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	ret := thr_new(&param, int32(unsafe.Sizeof(param)))
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret < 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}
}

// Called to do synchronous initialization of Go code built with
// -buildmode=c-archive or -buildmode=c-shared.
// None of the Go runtime is initialized.
//
//go:nosplit
//go:nowritebarrierrec
func libpreinit() {
	initsig(true)
}

func osinit() {
	ncpu = getncpu()
	if physPageSize == 0 {
		physPageSize = getPageSize()
	}
}

var urandom_dev = []byte("/dev/urandom\x00")

//go:nosplit
func readRandom(r []byte) int {
	fd := open(&urandom_dev[0], 0 /* O_RDONLY */, 0)
	n := read(fd, unsafe.Pointer(&r[0]), int32(len(r)))
	closefd(fd)
	return int(n)
}

func goenvs() {
	goenvs_unix()
}

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
	mp.gsignal = malg(32 * 1024)
	mp.gsignal.m = mp
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate memory.
func minit() {
	getg().m.procid = uint64(thr_self())

	// On FreeBSD before about April 2017 there was a bug such
	// that calling execve from a thread other than the main
	// thread did not reset the signal stack. That would confuse
	// minitSignals, which calls minitSignalStack, which checks
	// whether there is currently a signal stack and uses it if
	// present. To avoid this confusion, explicitly disable the
	// signal stack on the main thread when not running in a
	// library. This can be removed when we are confident that all
	// FreeBSD users are running a patched kernel. See issue #15658.
	if gp := getg(); !isarchive && !islibrary && gp.m == &m0 && gp == gp.m.g0 {
		st := stackt{ss_flags: _SS_DISABLE}
		sigaltstack(&st, nil)
	}

	minitSignals()
}

// Called from dropm to undo the effect of an minit.
//
//go:nosplit
func unminit() {
	unminitSignals()
	getg().m.procid = 0
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

func sigtramp()

type sigactiont struct {
	sa_handler uintptr
	sa_flags   int32
	sa_mask    sigset
}

// See os_freebsd2.go, os_freebsd_amd64.go for setsig function

//go:nosplit
//go:nowritebarrierrec
func setsigstack(i uint32) {
	var sa sigactiont
	sigaction(i, nil, &sa)
	if sa.sa_flags&_SA_ONSTACK != 0 {
		return
	}
	sa.sa_flags |= _SA_ONSTACK
	sigaction(i, &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func getsig(i uint32) uintptr {
	var sa sigactiont
	sigaction(i, nil, &sa)
	return sa.sa_handler
}

// setSignalstackSP sets the ss_sp field of a stackt.
//
//go:nosplit
func setSignalstackSP(s *stackt, sp uintptr) {
	s.ss_sp = sp
}

//go:nosplit
//go:nowritebarrierrec
func sigaddset(mask *sigset, i int) {
	mask.__bits[(i-1)/32] |= 1 << ((uint32(i) - 1) & 31)
}

func sigdelset(mask *sigset, i int) {
	mask.__bits[(i-1)/32] &^= 1 << ((uint32(i) - 1) & 31)
}

//go:nosplit
func (c *sigctxt) fixsigcode(sig uint32) {
}

func setProcessCPUProfiler(hz int32) {
	setProcessCPUProfilerTimer(hz)
}

func setThreadCPUProfiler(hz int32) {
	setThreadCPUProfilerHz(hz)
}

//go:nosplit
func validSIGPROF(mp *m, c *sigctxt) bool {
	return true
}

func sysargs(argc int32, argv **byte) {
	n := argc + 1

	// skip over argv, envp to get to auxv
	for argv_index(argv, n) != nil {
		n++
	}

	// skip NULL separator
	n++

	// now argv+n is auxv
	auxvp := (*[1 << 28]uintptr)(add(unsafe.Pointer(argv), uintptr(n)*goarch.PtrSize))
	pairs := sysauxv(auxvp[:])
	auxv = auxvp[: pairs*2 : pairs*2]
}

const (
	_AT_NULL     = 0  // Terminates the vector
	_AT_PAGESZ   = 6  // Page size in bytes
	_AT_PLATFORM = 15 // string identifying platform
	_AT_TIMEKEEP = 22 // Pointer to timehands.
	_AT_HWCAP    = 25 // CPU feature flags
	_AT_HWCAP2   = 26 // CPU feature flags 2
)

func sysauxv(auxv []uintptr) (pairs int) {
	var i int
	for i = 0; auxv[i] != _AT_NULL; i += 2 {
		tag, val := auxv[i], auxv[i+1]
		switch tag {
		// _AT_NCPUS from auxv shouldn't be used due to golang.org/issue/15206
		case _AT_PAGESZ:
			physPageSize = val
		case _AT_TIMEKEEP:
			timekeepSharedPage = (*vdsoTimekeep)(unsafe.Pointer(val))
		}

		archauxv(tag, val)
	}
	return i / 2
}

// sysSigaction calls the sigaction system call.
//
//go:nosplit
func sysSigaction(sig uint32, new, old *sigactiont) {
	// Use system stack to avoid split stack overflow on amd64
	if asmSigaction(uintptr(sig), new, old) != 0 {
		systemstack(func() {
			throw("sigaction failed")
		})
	}
}

// asmSigaction is implemented in assembly.
//
//go:noescape
func asmSigaction(sig uintptr, new, old *sigactiont) int32

// raise sends a signal to the calling thread.
//
// It must be nosplit because it is used by the signal handler before
// it definitely has a Go stack.
//
//go:nosplit
func raise(sig uint32) {
	thr_kill(thr_self(), int(sig))
}

func signalM(mp *m, sig int) {
	thr_kill(thread(mp.procid), sig)
}

// sigPerThreadSyscall is only used on linux, so we assign a bogus signal
// number.
const sigPerThreadSyscall = 1 << 31

//go:nosplit
func runPerThreadSyscall() {
	throw("runPerThreadSyscall only valid on linux")
}

"""



```