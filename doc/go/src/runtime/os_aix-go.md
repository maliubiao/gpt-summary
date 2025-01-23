Response:
Let's break down the thought process for analyzing this Go runtime code snippet for AIX.

**1. Initial Reading and Identification of Key Areas:**

First, I'd read through the code to get a general sense of what's going on. I'd look for keywords and structures that give clues about its purpose. Keywords like `runtime`, `os_aix.go`, `pthread`, `sem`, `sig`, `syscall` immediately suggest operating system interactions, threading, synchronization, and signal handling on the AIX platform. The `//go:build aix` comment confirms this is platform-specific code.

**2. Section-by-Section Analysis:**

Next, I'd go through the code in logical blocks:

* **Constants:** `threadStackSize` is clearly defining the default stack size for new OS threads.

* **Data Structures:** `funcDescriptor`, `mOS` are custom structures. `funcDescriptor` seems related to function calls, especially in assembly (`toc` often hints at table of contents for function pointers). `mOS` appears to hold OS-specific data for a Go `m` (machine/OS thread). The `waitsema` field strongly suggests a semaphore for thread synchronization.

* **Semaphore Functions:** `semacreate`, `semasleep`, `semawakeup` are clearly wrappers around AIX semaphore system calls (`sem_init`, `sem_timedwait`, `sem_wait`, `sem_post`). The error handling (`throw("...")`) is a standard Go runtime pattern for fatal errors.

* **Initialization:** `osinit` performs early OS-level initialization. The calls to `sysconf` suggest retrieving system configuration values (number of CPUs, page size).

* **Thread Creation:** `newosproc0` and `newosproc` are critical. They both use `pthread_create` to create new OS threads. The differences likely lie in the initialization state of the runtime. The comments in `newosproc0` specifically mention being called *before* the runtime is fully initialized. The use of `tstart` (a function descriptor) in `newosproc` and the passing of `mp` as an argument are important details.

* **Library Pre-initialization:** `libpreinit` is related to `-buildmode=c-archive` or `-buildmode=c-shared`, indicating interactions with C code.

* **M (Machine/OS Thread) Related Functions:** `mpreinit`, `miniterrno`, `minit`, `unminit`, `mdestroy` are all functions that operate on the `m` structure. `miniterrno` and `minitSignals` point to early setup of error handling and signal handling.

* **Signal Handling:** The `SIGNAL` section is extensive. `sigtramp`, `setsig`, `setsigstack`, `getsig`, `fixsigcode`, `sigaddset`, `sigdelset` all point to the implementation of Go's signal handling on AIX, likely bridging between OS signals and Go's internal signal handling.

* **Profiling:** `setProcessCPUProfiler`, `setThreadCPUProfiler`, `validSIGPROF` are related to CPU profiling.

* **Time Functions:** `nanotime1`, `walltime` are for getting time with nanosecond precision. They use `clock_gettime`.

* **File Control:** `fcntl`, `setNonblock` are wrappers around the `fcntl` system call, used for file descriptor manipulation.

* **Per-Thread Syscall (Linux Specific Note):** The comments about `sigPerThreadSyscall` and `runPerThreadSyscall` explicitly stating they are "only used on Linux" is crucial. This highlights platform-specific code and the need for conditional compilation (which is handled by the `//go:build aix` tag).

* **User/Group IDs:** `getuid`, `geteuid`, `getgid`, `getegid` are standard functions for retrieving user and group IDs.

**3. Inferring Functionality and Providing Examples:**

Based on the analysis above, I could start to infer the purpose of different code sections. For example:

* **Semaphores:**  The presence of `semacreate`, `semasleep`, `semawakeup` strongly suggests this code is implementing some form of synchronization primitive using OS semaphores. I can create a simple Go example showcasing the use of `sync.Mutex`, which internally might use these primitives.

* **Thread Creation:** The `newosproc` function is clearly responsible for creating new OS threads for Go goroutines. I can provide an example of using `go func() {}` to demonstrate implicit thread creation.

* **Signal Handling:** The `setsig` and related functions indicate customization of how OS signals are handled. I can show an example of using `signal.Notify` to intercept signals.

**4. Considering Assumptions and Edge Cases:**

When writing examples, it's important to state any assumptions made (e.g., "This assumes the existence of...") and consider potential edge cases or simplifications in the examples.

**5. Addressing Specific Questions:**

Finally, I'd specifically address the user's questions:

* **Functionality Listing:**  Provide a clear, concise list of the identified functionalities.
* **Functionality Inference and Examples:**  Explain the inferred purpose and provide corresponding Go code examples.
* **Code Reasoning with Assumptions:**  If code reasoning is involved, explicitly state the assumptions made.
* **Command-Line Arguments:** Review the code for any direct handling of command-line arguments (in this snippet, there isn't any).
* **Common Mistakes:** Think about common pitfalls when dealing with concurrency, signal handling, or low-level OS interactions. For instance, forgetting to release a mutex or not handling signals correctly.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  I might initially misinterpret a function's purpose, but by looking at the system calls being made and the context, I can refine my understanding.
* **Missing Information:** If I'm unsure about a specific detail, I'd acknowledge it and avoid making definitive statements. I might say something like, "It's likely that..." or "This *might* be used for..."
* **Clarity and Conciseness:** I would strive to explain complex concepts clearly and avoid jargon where possible. The goal is to make the information accessible.

By following this structured approach, I can systematically analyze the code snippet and provide a comprehensive and accurate answer to the user's request.这段代码是 Go 语言运行时（runtime）的一部分，专门用于 **AIX 操作系统**。它包含了在 AIX 上支持 Go 语言运行所需要的底层操作系统接口实现。

下面列举一下它的主要功能：

1. **线程栈大小定义:** 定义了线程栈的默认大小 `threadStackSize` 为 1MB (0x100000 字节)。

2. **函数描述符:** 定义了 `funcDescriptor` 结构体，用于表示函数描述符，其中包含函数指针 (`fn`) 和 TOC 指针 (`toc`)。`envPointer` 在 Go 中未使用。这主要是为了与 AIX 的 ABI 兼容。

3. **操作系统相关的线程本地存储 (TLS):** `mOS` 结构体用于存储与操作系统线程相关的特定数据，例如用于锁的等待信号量 (`waitsema`) 和指向线程本地 `errno` 的指针 (`perrno`)。

4. **信号量操作:** 提供了用于创建、睡眠和唤醒信号量的函数 (`semacreate`, `semasleep`, `semawakeup`)。这些函数是对 AIX 系统调用 `sem_init`, `sem_timedwait`, `sem_wait`, `sem_post` 的封装，用于实现 Go 内部的同步机制。

5. **操作系统初始化:** `osinit` 函数用于执行操作系统相关的初始化，例如获取 CPU 核心数 (`ncpu`) 和物理页大小 (`physPageSize`)。

6. **创建新的操作系统线程:**
   - `newosproc0`: 在运行时初始化之前创建新操作系统线程。
   - `newosproc`: 创建新的操作系统线程来运行 Go 代码。这两个函数都使用 AIX 的 `pthread_create` 系统调用。在线程创建时会禁用信号，并在线程内部初始化时启用。

7. **C 库预初始化:** `libpreinit` 函数用于在以 `c-archive` 或 `c-shared` 模式构建 Go 代码时进行同步初始化，此时 Go 运行时尚未完全初始化。

8. **M（Machine/OS 线程）相关操作:**
   - `mpreinit`: 初始化 `m` 结构体中的 `gsignal` 字段，用于处理信号。
   - `miniterrno`: 获取指向线程本地 `errno` 的指针。
   - `minit`: 执行每个新操作系统线程的初始化操作，包括初始化信号处理。
   - `unminit`: 执行线程的清理操作，例如取消信号处理的初始化。
   - `mdestroy`: 清理线程拥有的资源。

9. **线程启动函数:** `tstart` 是一个指向汇编语言定义的 `_tstart` 函数的描述符，该函数是新创建的操作系统线程的入口点。

10. **线程退出:** `exitThread` 函数在 AIX 上永远不会被调用，因为 AIX 让 libc 来清理线程。

11. **读取随机数:** `readRandom` 函数通过读取 `/dev/urandom` 设备来获取随机数。

12. **环境变量:** `goenvs` 函数调用 `goenvs_unix` 来处理环境变量。

13. **信号处理:**
    - 定义了信号量 `_NSIG`。
    - `sigtramp` 是一个指向汇编语言定义的 `_sigtramp` 函数的描述符，用于处理信号。
    - `setsig`: 设置信号处理函数。如果设置的函数是 Go 的 `sighandler`，则实际使用汇编代码的 `sigtramp` 作为处理函数。
    - `setsigstack`: 确保信号处理使用独立的栈。
    - `getsig`: 获取当前信号的处理函数。
    - `setSignalstackSP`: 设置信号处理栈的栈指针。
    - `fixsigcode`: 修正特定信号的信号代码。
    - `sigaddset`, `sigdelset`: 用于操作信号掩码。

14. **CPU Profiler:** 提供了设置进程和线程 CPU Profiler 的函数 (`setProcessCPUProfiler`, `setThreadCPUProfiler`)。

15. **时间相关函数:**
    - `nanotime1`: 获取纳秒级别的时间（单调时钟）。
    - `walltime`: 获取当前时间（实时时钟）。

16. **文件控制:**
    - `fcntl`:  是对 `fcntl` 系统调用的封装。
    - `setNonblock`: 设置文件描述符为非阻塞模式。

17. **用户和组 ID:** 提供了获取用户和组 ID 的函数 (`getuid`, `geteuid`, `getgid`, `getegid`)。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 Go 语言运行时在 AIX 操作系统上的**底层支撑**，包括：

* **Goroutine 的创建和调度:** 通过 `newosproc` 创建操作系统线程来运行 Goroutine。
* **同步原语:**  使用信号量 (`semacreate`, `semasleep`, `semawakeup`) 实现 Go 内部的锁和其他同步机制。
* **信号处理:**  提供了在 AIX 上处理操作系统信号的机制，使得 Go 程序能够响应中断、错误等信号。
* **时间和时钟:**  提供了获取高精度时间的能力。
* **系统调用接口:** 虽然这段代码中直接的系统调用封装不多，但它是构建更高层系统调用抽象的基础。
* **线程本地存储:**  使用 `mOS` 结构体管理线程特定的数据。

**Go 代码示例：**

虽然这段代码是 Go 运行时的底层实现，但我们可以通过一些 Go 代码示例来间接展示它所支撑的功能。

**示例 1: Goroutine 的创建**

```go
package main

import "runtime"

func main() {
	runtime.GOMAXPROCS(1) // 限制使用一个 CPU 核心，方便观察

	go func() {
		println("Hello from a goroutine!")
	}()

	// 让主 Goroutine 休眠一段时间，确保子 Goroutine 有机会执行
	// 在实际应用中，通常会使用同步机制来等待 Goroutine 完成
	ch := make(chan bool)
	<-ch
}
```

**推理:** 当你运行这个程序时，Go 运行时会调用 `newosproc` (或 `newosproc0` 在早期阶段) 来创建一个新的操作系统线程来执行 `go func() {}` 中的代码。`pthread_create` 会被调用，并传入 `tstart` 作为线程入口点。`tstart` 最终会引导执行我们定义的匿名函数。

**假设输入与输出:** 没有直接的输入，但 Go 运行时会根据 `GOMAXPROCS` 和系统负载来决定何时创建新的操作系统线程。输出是 "Hello from a goroutine!"。

**示例 2: 使用 Mutex (内部可能使用信号量)**

```go
package main

import (
	"fmt"
	"sync"
	"time"
)

var counter int
var mu sync.Mutex

func increment() {
	mu.Lock()
	counter++
	mu.Unlock()
}

func main() {
	for i := 0; i < 1000; i++ {
		go increment()
	}

	time.Sleep(time.Second) // 等待所有 Goroutine 完成
	fmt.Println("Counter:", counter)
}
```

**推理:** `sync.Mutex` 在底层很可能使用了类似 `semacreate`, `semasleep`, `semawakeup` 提供的信号量机制来实现互斥。当一个 Goroutine 调用 `mu.Lock()` 时，如果锁未被占用，它将成功获取锁。如果锁已被占用，它会调用 `semasleep` 进入睡眠状态，直到持有锁的 Goroutine 调用 `mu.Unlock()`，后者会调用 `semawakeup` 唤醒等待的 Goroutine。

**假设输入与输出:** 没有直接的输入。输出的 `Counter` 值应该接近 1000，因为互斥锁保证了对 `counter` 变量的原子访问。

**命令行参数的具体处理：**

这段代码本身**没有直接处理命令行参数**。命令行参数的处理通常发生在 `os` 包或 `flag` 包中，而不是在 `runtime` 包的特定操作系统实现中。 `runtime` 包更多关注底层的操作系统交互。

**使用者易犯错的点：**

由于这段代码是 Go 运行时的底层实现，**普通 Go 开发者通常不会直接与这段代码交互**。因此，不容易犯错。 然而，理解其背后的原理对于理解 Go 的并发模型和在 AIX 上可能遇到的特定行为是有帮助的。

如果需要考虑到使用 Cgo 与 AIX 系统调用交互的场景，那么一些常见的错误点可能包括：

* **不正确的信号处理:** 在 C 代码中注册的信号处理函数可能与 Go 的信号处理机制冲突。
* **线程安全问题:** 在 C 代码中操作 Go 的数据结构时，需要格外注意线程安全，因为 Go 的 Goroutine 可能会在不同的操作系统线程上运行。
* **资源管理:** 如果 C 代码分配了内存或其他资源，需要确保在不再需要时正确释放，避免内存泄漏。

总而言之，这段 `os_aix.go` 文件是 Go 语言在 AIX 平台上能够运行的关键组成部分，它实现了 Go 运行时与 AIX 操作系统之间的桥梁。 开发者通常无需直接操作它，但理解其功能有助于更深入地理解 Go 的底层机制。

### 提示词
```
这是路径为go/src/runtime/os_aix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"unsafe"
)

const (
	threadStackSize = 0x100000 // size of a thread stack allocated by OS
)

// funcDescriptor is a structure representing a function descriptor
// A variable with this type is always created in assembler
type funcDescriptor struct {
	fn         uintptr
	toc        uintptr
	envPointer uintptr // unused in Golang
}

type mOS struct {
	waitsema uintptr // semaphore for parking on locks
	perrno   uintptr // pointer to tls errno
}

//go:nosplit
func semacreate(mp *m) {
	if mp.waitsema != 0 {
		return
	}

	var sem *semt

	// Call libc's malloc rather than malloc. This will
	// allocate space on the C heap. We can't call mallocgc
	// here because it could cause a deadlock.
	sem = (*semt)(malloc(unsafe.Sizeof(*sem)))
	if sem_init(sem, 0, 0) != 0 {
		throw("sem_init")
	}
	mp.waitsema = uintptr(unsafe.Pointer(sem))
}

//go:nosplit
func semasleep(ns int64) int32 {
	mp := getg().m
	if ns >= 0 {
		var ts timespec

		if clock_gettime(_CLOCK_REALTIME, &ts) != 0 {
			throw("clock_gettime")
		}
		ts.tv_sec += ns / 1e9
		ts.tv_nsec += ns % 1e9
		if ts.tv_nsec >= 1e9 {
			ts.tv_sec++
			ts.tv_nsec -= 1e9
		}

		if r, err := sem_timedwait((*semt)(unsafe.Pointer(mp.waitsema)), &ts); r != 0 {
			if err == _ETIMEDOUT || err == _EAGAIN || err == _EINTR {
				return -1
			}
			println("sem_timedwait err ", err, " ts.tv_sec ", ts.tv_sec, " ts.tv_nsec ", ts.tv_nsec, " ns ", ns, " id ", mp.id)
			throw("sem_timedwait")
		}
		return 0
	}
	for {
		r1, err := sem_wait((*semt)(unsafe.Pointer(mp.waitsema)))
		if r1 == 0 {
			break
		}
		if err == _EINTR {
			continue
		}
		throw("sem_wait")
	}
	return 0
}

//go:nosplit
func semawakeup(mp *m) {
	if sem_post((*semt)(unsafe.Pointer(mp.waitsema))) != 0 {
		throw("sem_post")
	}
}

func osinit() {
	// Call miniterrno so that we can safely make system calls
	// before calling minit on m0.
	miniterrno()

	ncpu = int32(sysconf(__SC_NPROCESSORS_ONLN))
	physPageSize = sysconf(__SC_PAGE_SIZE)
}

// newosproc0 is a version of newosproc that can be called before the runtime
// is initialized.
//
// This function is not safe to use after initialization as it does not pass an M as fnarg.
//
//go:nosplit
func newosproc0(stacksize uintptr, fn *funcDescriptor) {
	var (
		attr pthread_attr
		oset sigset
		tid  pthread
	)

	if pthread_attr_init(&attr) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	if pthread_attr_setstacksize(&attr, threadStackSize) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	if pthread_attr_setdetachstate(&attr, _PTHREAD_CREATE_DETACHED) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	// Disable signals during create, so that the new thread starts
	// with signals disabled. It will enable them in minit.
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	var ret int32
	for tries := 0; tries < 20; tries++ {
		// pthread_create can fail with EAGAIN for no reasons
		// but it will be ok if it retries.
		ret = pthread_create(&tid, &attr, fn, nil)
		if ret != _EAGAIN {
			break
		}
		usleep(uint32(tries+1) * 1000) // Milliseconds.
	}
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret != 0 {
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

// Ms related functions
func mpreinit(mp *m) {
	mp.gsignal = malg(32 * 1024) // AIX wants >= 8K
	mp.gsignal.m = mp
}

// errno address must be retrieved by calling _Errno libc function.
// This will return a pointer to errno.
func miniterrno() {
	mp := getg().m
	r, _ := syscall0(&libc__Errno)
	mp.perrno = r

}

func minit() {
	miniterrno()
	minitSignals()
	getg().m.procid = uint64(pthread_self())
}

func unminit() {
	unminitSignals()
	getg().m.procid = 0
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

// tstart is a function descriptor to _tstart defined in assembly.
var tstart funcDescriptor

func newosproc(mp *m) {
	var (
		attr pthread_attr
		oset sigset
		tid  pthread
	)

	if pthread_attr_init(&attr) != 0 {
		throw("pthread_attr_init")
	}

	if pthread_attr_setstacksize(&attr, threadStackSize) != 0 {
		throw("pthread_attr_getstacksize")
	}

	if pthread_attr_setdetachstate(&attr, _PTHREAD_CREATE_DETACHED) != 0 {
		throw("pthread_attr_setdetachstate")
	}

	// Disable signals during create, so that the new thread starts
	// with signals disabled. It will enable them in minit.
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	ret := retryOnEAGAIN(func() int32 {
		return pthread_create(&tid, &attr, &tstart, unsafe.Pointer(mp))
	})
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret != 0 {
		print("runtime: failed to create new OS thread (have ", mcount(), " already; errno=", ret, ")\n")
		if ret == _EAGAIN {
			println("runtime: may need to increase max user processes (ulimit -u)")
		}
		throw("newosproc")
	}

}

func exitThread(wait *atomic.Uint32) {
	// We should never reach exitThread on AIX because we let
	// libc clean up threads.
	throw("exitThread")
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

/* SIGNAL */

const (
	_NSIG = 256
)

// sigtramp is a function descriptor to _sigtramp defined in assembly
var sigtramp funcDescriptor

//go:nosplit
//go:nowritebarrierrec
func setsig(i uint32, fn uintptr) {
	var sa sigactiont
	sa.sa_flags = _SA_SIGINFO | _SA_ONSTACK | _SA_RESTART
	sa.sa_mask = sigset_all
	if fn == abi.FuncPCABIInternal(sighandler) { // abi.FuncPCABIInternal(sighandler) matches the callers in signal_unix.go
		fn = uintptr(unsafe.Pointer(&sigtramp))
	}
	sa.sa_handler = fn
	sigaction(uintptr(i), &sa, nil)

}

//go:nosplit
//go:nowritebarrierrec
func setsigstack(i uint32) {
	var sa sigactiont
	sigaction(uintptr(i), nil, &sa)
	if sa.sa_flags&_SA_ONSTACK != 0 {
		return
	}
	sa.sa_flags |= _SA_ONSTACK
	sigaction(uintptr(i), &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func getsig(i uint32) uintptr {
	var sa sigactiont
	sigaction(uintptr(i), nil, &sa)
	return sa.sa_handler
}

// setSignalstackSP sets the ss_sp field of a stackt.
//
//go:nosplit
func setSignalstackSP(s *stackt, sp uintptr) {
	*(*uintptr)(unsafe.Pointer(&s.ss_sp)) = sp
}

//go:nosplit
func (c *sigctxt) fixsigcode(sig uint32) {
	switch sig {
	case _SIGPIPE:
		// For SIGPIPE, c.sigcode() isn't set to _SI_USER as on Linux.
		// Therefore, raisebadsignal won't raise SIGPIPE again if
		// it was deliver in a non-Go thread.
		c.set_sigcode(_SI_USER)
	}
}

//go:nosplit
//go:nowritebarrierrec
func sigaddset(mask *sigset, i int) {
	(*mask)[(i-1)/64] |= 1 << ((uint32(i) - 1) & 63)
}

func sigdelset(mask *sigset, i int) {
	(*mask)[(i-1)/64] &^= 1 << ((uint32(i) - 1) & 63)
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

const (
	_CLOCK_REALTIME  = 9
	_CLOCK_MONOTONIC = 10
)

//go:nosplit
func nanotime1() int64 {
	tp := &timespec{}
	if clock_gettime(_CLOCK_REALTIME, tp) != 0 {
		throw("syscall clock_gettime failed")
	}
	return tp.tv_sec*1000000000 + tp.tv_nsec
}

func walltime() (sec int64, nsec int32) {
	ts := &timespec{}
	if clock_gettime(_CLOCK_REALTIME, ts) != 0 {
		throw("syscall clock_gettime failed")
	}
	return ts.tv_sec, int32(ts.tv_nsec)
}

//go:nosplit
func fcntl(fd, cmd, arg int32) (int32, int32) {
	r, errno := syscall3(&libc_fcntl, uintptr(fd), uintptr(cmd), uintptr(arg))
	return int32(r), int32(errno)
}

//go:nosplit
func setNonblock(fd int32) {
	flags, _ := fcntl(fd, _F_GETFL, 0)
	if flags != -1 {
		fcntl(fd, _F_SETFL, flags|_O_NONBLOCK)
	}
}

// sigPerThreadSyscall is only used on linux, so we assign a bogus signal
// number.
const sigPerThreadSyscall = 1 << 31

//go:nosplit
func runPerThreadSyscall() {
	throw("runPerThreadSyscall only valid on linux")
}

//go:nosplit
func getuid() int32 {
	r, errno := syscall0(&libc_getuid)
	if errno != 0 {
		print("getuid failed ", errno)
		throw("getuid")
	}
	return int32(r)
}

//go:nosplit
func geteuid() int32 {
	r, errno := syscall0(&libc_geteuid)
	if errno != 0 {
		print("geteuid failed ", errno)
		throw("geteuid")
	}
	return int32(r)
}

//go:nosplit
func getgid() int32 {
	r, errno := syscall0(&libc_getgid)
	if errno != 0 {
		print("getgid failed ", errno)
		throw("getgid")
	}
	return int32(r)
}

//go:nosplit
func getegid() int32 {
	r, errno := syscall0(&libc_getegid)
	if errno != 0 {
		print("getegid failed ", errno)
		throw("getegid")
	}
	return int32(r)
}
```