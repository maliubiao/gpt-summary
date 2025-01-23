Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request is to understand the functionality of `go/src/runtime/os_netbsd.go`. This file's location immediately tells us it's part of the Go runtime and deals with operating system-specific implementations for NetBSD.

2. **Initial Scan - Identify Key Components:**  Quickly skim the code, looking for:
    * **Package Declaration:** `package runtime` - confirms it's runtime code.
    * **Imports:** `internal/abi`, `internal/goarch`, `internal/runtime/atomic`, `unsafe` -  These suggest low-level operations, dealing with memory layout, architecture specifics, and concurrency primitives.
    * **Constants:**  Lots of constants starting with `_`. These are likely system call numbers, flags, and other OS-related magic numbers. Pay attention to where they are sourced from (e.g., "From NetBSD's `<sys/ucontext.h>`").
    * **Types:** `mOS` -  This probably holds OS-specific data for the `m` (machine/OS thread) structure.
    * **`//go:noescape` and `//go:nosplit` directives:** These are crucial for understanding the context of the functions. `noescape` means the function's arguments don't escape to the heap, often used for performance or when interacting with C code. `nosplit` means the function must not grow the stack, essential for low-level operations like signal handling.
    * **External Functions:**  Declarations like `func setitimer(mode int32, new, old *itimerval)` without a function body indicate calls to the operating system's C API. The function names are very telling (e.g., `sigaction`, `sysctl`, `lwp_create`).
    * **Variables:** `sigset_all`, `urandom_dev`. These are likely global state or constants within the runtime.
    * **Functions with meaningful names:**  `getncpu`, `getPageSize`, `semacreate`, `semawakeup`, `newosproc`, `readRandom`, `setsig`, etc. These give strong hints about the functionalities implemented.

3. **Categorize Functionality:** Group the identified components into logical categories. This makes the analysis more structured.

    * **System Calls/OS Interaction:** Functions like `setitimer`, `sigaction`, `sigprocmask`, `sysctl`, `lwp_create`, `lwp_park`, `lwp_unpark`, `kqueue`, `kevent`, `pipe2`, `fcntl`, `open`, `read`, `closefd`. Constants related to these calls.
    * **Thread Management:** Functions related to creating and managing OS threads: `newosproc`, `netbsdMstart`, `lwp_create`, `lwp_self`.
    * **Synchronization Primitives:** `semacreate`, `semasleep`, `semawakeup`. These are likely Go's internal implementation of semaphores using NetBSD's primitives.
    * **Signal Handling:** `sigaction`, `sigaltstack`, `sigprocmask`, `sigtramp`, `setsig`, `getsig`. Constants related to signals.
    * **Memory Management:** `getPageSize`.
    * **CPU Information:** `getncpu`.
    * **Random Number Generation:** `readRandom`.
    * **Time/Timers:** `setitimer`, constants related to `CLOCK_*` and `TIMER_*`.
    * **Auxiliary Vector Handling:** `sysargs`, `sysauxv`, constants related to `AT_*`.

4. **Infer Go Feature Implementations:** Based on the categorized functionality, try to connect the low-level OS interactions with higher-level Go concepts.

    * **Goroutine Scheduling:** The functions related to thread creation (`newosproc`, `netbsdMstart`) and synchronization (`semacreate`, `semasleep`, `semawakeup`) are key parts of Go's goroutine scheduler implementation on NetBSD. The use of lightweight processes (`lwp_`) is a strong indicator.
    * **Signal Handling:** The `sigaction`, `sigaltstack`, etc., functions clearly implement Go's signal handling mechanism. The `sigtramp` function suggests a trampoline for executing Go signal handlers.
    * **`runtime.NumCPU()`:**  The `getncpu` function is likely used to implement `runtime.NumCPU()`.
    * **`os.Getpagesize()`:** The `getPageSize` function implements `os.Getpagesize()`.
    * **`math/rand.Read()`:** The `readRandom` function is used to seed the random number generator.
    * **`os/exec` and Pipes:** The `pipe2` function is likely used by `os/exec` to create pipes for inter-process communication.

5. **Provide Code Examples:** For the inferred Go features, provide concise code snippets that demonstrate their usage. This solidifies the understanding of how these low-level functions are used in practice.

6. **Address Specific Questions:** Go through the remaining parts of the prompt:

    * **Code Reasoning with Input/Output:**  This often applies to functions with more complex logic. For the given code, the individual low-level functions are quite direct in their purpose (wrapping system calls). Focus on demonstrating how the higher-level Go features use these primitives.
    * **Command-Line Arguments:** This file doesn't directly handle command-line arguments. The `sysargs` function parses the auxiliary vector, which *can* contain information related to program execution, but it's not the primary mechanism for argument parsing in Go. Clarify this distinction.
    * **Common Mistakes:**  Think about potential pitfalls for developers using the *related* Go features, even if the low-level code itself isn't directly interacted with. For example, incorrect signal handling is a common source of errors. Also consider potential issues with assumptions about thread creation or synchronization.

7. **Structure and Language:** Organize the answer clearly with headings and bullet points. Use precise and understandable Chinese. Explain technical terms when necessary.

8. **Review and Refine:** Before submitting the answer, reread it to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas where further explanation might be helpful. For instance, double-check that the code examples accurately reflect the functionality being described. Make sure the explanation of command-line arguments is nuanced and doesn't mislead the reader.
这段代码是 Go 语言运行时环境（runtime）中专门为 NetBSD 操作系统提供的实现。它包含了 Go 语言在 NetBSD 上进行底层操作所需的各种功能。下面列举其主要功能：

**核心功能：**

1. **线程管理 (Thread Management):**
   - `newosproc(mp *m)`: 创建新的操作系统线程（M，machine）。Go 的 goroutine 需要运行在操作系统线程之上。此函数使用 NetBSD 的 `lwp_create` 系统调用来创建新的轻量级进程 (LWP)，这在 NetBSD 中是实现用户级线程的方式。
   - `netbsdMstart()` 和 `netbsdMstart0()`:  新创建的操作系统线程的入口点。它们负责初始化 Go 运行时环境在该线程上的状态，例如设置信号栈，并最终调用 `mstart0()` 来开始执行 goroutine。
   - `lwp_self()`: 获取当前线程的 ID。

2. **Goroutine 同步 (Goroutine Synchronization):**
   - `semacreate(mp *m)`, `semasleep(ns int64)`, `semawakeup(mp *m)`:  实现了基于 NetBSD 轻量级进程的信号量机制。这些函数被 Go 运行时内部用于 goroutine 的阻塞和唤醒。`lwp_park` 用于将线程置于休眠状态，`lwp_unpark` 用于唤醒线程。

3. **信号处理 (Signal Handling):**
   - `sigaction(sig uint32, new, old *sigactiont)`:  NetBSD 的系统调用，用于设置对特定信号的处理方式。
   - `sigaltstack(new, old *stackt)`:  NetBSD 的系统调用，用于设置备用信号栈。在处理信号时，如果当前栈溢出，系统会切换到备用栈。
   - `sigprocmask(how int32, new, old *sigset)`: NetBSD 的系统调用，用于屏蔽或解除屏蔽某些信号，控制哪些信号可以传递给当前线程。
   - `sigtramp()`:  信号处理函数的跳转入口点（trampoline）。当收到信号时，系统会跳转到这个函数，然后由它来调用实际的 Go 信号处理函数。
   - `setsig(i uint32, fn uintptr)` 和 `getsig(i uint32)`:  用于设置和获取特定信号的处理函数。
   - `sigset_all`:  一个包含了所有信号的信号集，通常用于屏蔽所有信号。

4. **系统调用封装 (System Call Wrappers):**
   - 代码中定义了许多与 NetBSD 系统调用对应的 Go 函数，例如 `setitimer`, `sysctl`, `kqueue`, `kevent`, `pipe2`, `fcntl` 等。这些函数通常是 `//go:noescape` 的，表示它们的参数不会逃逸到堆上，并且直接调用了底层的系统调用。

5. **系统信息获取 (System Information Retrieval):**
   - `sysctl(mib *uint32, miblen uint32, out *byte, size *uintptr, dst *byte, ndst uintptr)`: NetBSD 的系统调用，用于获取系统信息。
   - `getncpu()`:  通过 `sysctl` 获取系统的 CPU 核心数。
   - `getPageSize()`: 通过 `sysctl` 获取系统的页面大小。
   - `getOSRev()`: 通过 `sysctl` 获取操作系统的版本号。

6. **随机数生成 (Random Number Generation):**
   - `readRandom(r []byte) int`: 从 `/dev/urandom` 读取随机数。

7. **其他辅助功能:**
   - `osyield()`: 让出当前线程的 CPU 时间片，允许其他线程运行。
   - `issetugid()`: 检查进程是否以设置用户 ID 或设置组 ID 的方式运行。
   - `sysargs(argc int32, argv **byte)` 和 `sysauxv(auxv []uintptr)`: 用于处理程序启动时的命令行参数和辅助向量（auxiliary vector），从中获取一些系统信息，例如页面大小。
   - `raise(sig uint32)` 和 `lwp_kill(tid int32, sig int)`:  发送信号给当前线程或其他线程。

**推理 Go 语言功能实现并举例：**

**1. Goroutine 的创建和调度:**

这段代码中的 `newosproc` 和相关的 `lwp_create` 调用是 Go 语言创建新的 goroutine 所需的底层操作系统线程的关键部分。当创建一个新的 goroutine 时，Go 运行时可能会决定创建一个新的操作系统线程来运行它（特别是在并行执行的场景下）。

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
)

func myGoroutine(id int) {
	fmt.Println("Goroutine", id, "running on OS thread", getOSThreadID())
}

func getOSThreadID() int32 {
	// 由于 Go 没有直接暴露获取 OS 线程 ID 的公共 API，
	// 这里我们假设可以通过某种方式调用 runtime 包的内部函数或者
	// 使用平台特定的方法。
	// 在实际的 Go 代码中，你不会直接调用 runtime 包的这些函数。
	// 这只是一个概念性的演示。
	// 在 NetBSD 上，它会对应 runtime.lwp_self() 的返回值。
	return int32(0) // 实际应该调用 runtime.lwp_self()，这里只是占位
}

func main() {
	runtime.GOMAXPROCS(2) // 设置使用 2 个 CPU 核心

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			myGoroutine(id)
		}(i)
	}
	wg.Wait()
}
```

**假设的输入与输出：**

上述代码的输出会显示多个 Goroutine 运行，并且（在 NetBSD 上）可能会运行在不同的操作系统线程上（尽管 Go 的调度器会进行管理，不保证每个 Goroutine 都分配到独立的 OS 线程）。`getOSThreadID()` 函数在这里只是一个占位符，实际在 Go 中获取 OS 线程 ID 比较复杂，通常不需要直接获取。

**2. `runtime.NumCPU()` 的实现:**

`getncpu()` 函数通过 `sysctl` 系统调用获取 `_HW_NCPUONLINE` 或 `_HW_NCPU`，这直接实现了 Go 语言的 `runtime.NumCPU()` 函数。

```go
package main

import (
	"fmt"
	"runtime"
)

func main() {
	n := runtime.NumCPU()
	fmt.Println("Number of CPUs:", n)
}
```

**输出：**

输出会显示 NetBSD 系统上的 CPU 核心数。

**3. `os.Getpagesize()` 的实现:**

`getPageSize()` 函数通过 `sysctl` 系统调用获取 `_HW_PAGESIZE`，实现了 Go 语言的 `os.Getpagesize()` 函数。

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	pageSize := os.Getpagesize()
	fmt.Println("Page size:", pageSize, "bytes")
}
```

**输出：**

输出会显示 NetBSD 系统上的页面大小（通常是 4096 字节）。

**命令行参数的具体处理：**

`sysargs` 函数在 Go 程序启动时被调用，它接收原始的命令行参数 `argc` 和 `argv`。它还负责跳过环境变量，找到辅助向量（auxiliary vector）。辅助向量包含了关于进程执行环境的额外信息，例如页面大小 (`_AT_PAGESZ`)。`sysauxv` 函数解析辅助向量，并将其中有用的信息（例如页面大小）存储到 Go 运行时的全局变量中。

**使用者易犯错的点：**

通常开发者不会直接与 `go/src/runtime/os_netbsd.go` 中的代码交互。这个文件是 Go 运行时的一部分，对用户来说是透明的。但是，理解其背后的原理可以帮助理解 Go 程序在 NetBSD 上的行为。

**一个潜在的误解点是关于 Goroutine 和操作系统线程的关系。**  初学者可能会认为每个 Goroutine 对应一个操作系统线程。实际上，Go 使用 M:N 的模型，即多个 Goroutine 可以复用少量操作系统线程。这段代码揭示了在 NetBSD 上，Go 运行时使用轻量级进程 (LWP) 来实现其 M（machine/OS thread）。开发者不需要直接管理这些 LWP，Go 运行时会负责调度 Goroutine 到可用的 M 上执行。

总结来说，`go/src/runtime/os_netbsd.go` 是 Go 语言在 NetBSD 操作系统上的底层实现，它提供了线程管理、goroutine 同步、信号处理、系统调用封装以及系统信息获取等核心功能，使得 Go 程序能够在 NetBSD 上正确运行。 开发者通常不需要直接关心这些底层的实现细节，Go 运行时会抽象这些复杂性，提供简洁易用的上层 API。

### 提示词
```
这是路径为go/src/runtime/os_netbsd.go的go语言实现的一部分， 请列举一下它的功能, 　
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

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"unsafe"
)

const (
	_SS_DISABLE  = 4
	_SIG_BLOCK   = 1
	_SIG_UNBLOCK = 2
	_SIG_SETMASK = 3
	_NSIG        = 33
	_SI_USER     = 0

	// From NetBSD's <sys/ucontext.h>
	_UC_SIGMASK = 0x01
	_UC_CPU     = 0x04

	// From <sys/lwp.h>
	_LWP_DETACHED = 0x00000040
)

type mOS struct {
	waitsemacount uint32
}

//go:noescape
func setitimer(mode int32, new, old *itimerval)

//go:noescape
func sigaction(sig uint32, new, old *sigactiont)

//go:noescape
func sigaltstack(new, old *stackt)

//go:noescape
func sigprocmask(how int32, new, old *sigset)

//go:noescape
func sysctl(mib *uint32, miblen uint32, out *byte, size *uintptr, dst *byte, ndst uintptr) int32

func lwp_tramp()

func raiseproc(sig uint32)

func lwp_kill(tid int32, sig int)

//go:noescape
func getcontext(ctxt unsafe.Pointer)

//go:noescape
func lwp_create(ctxt unsafe.Pointer, flags uintptr, lwpid unsafe.Pointer) int32

//go:noescape
func lwp_park(clockid, flags int32, ts *timespec, unpark int32, hint, unparkhint unsafe.Pointer) int32

//go:noescape
func lwp_unpark(lwp int32, hint unsafe.Pointer) int32

func lwp_self() int32

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

const (
	_ESRCH     = 3
	_ETIMEDOUT = 60

	// From NetBSD's <sys/time.h>
	_CLOCK_REALTIME  = 0
	_CLOCK_VIRTUAL   = 1
	_CLOCK_PROF      = 2
	_CLOCK_MONOTONIC = 3

	_TIMER_RELTIME = 0
	_TIMER_ABSTIME = 1
)

var sigset_all = sigset{[4]uint32{^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0)}}

// From NetBSD's <sys/sysctl.h>
const (
	_CTL_KERN   = 1
	_KERN_OSREV = 3

	_CTL_HW        = 6
	_HW_NCPU       = 3
	_HW_PAGESIZE   = 7
	_HW_NCPUONLINE = 16
)

func sysctlInt(mib []uint32) (int32, bool) {
	var out int32
	nout := unsafe.Sizeof(out)
	ret := sysctl(&mib[0], uint32(len(mib)), (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	if ret < 0 {
		return 0, false
	}
	return out, true
}

func getncpu() int32 {
	if n, ok := sysctlInt([]uint32{_CTL_HW, _HW_NCPUONLINE}); ok {
		return int32(n)
	}
	if n, ok := sysctlInt([]uint32{_CTL_HW, _HW_NCPU}); ok {
		return int32(n)
	}
	return 1
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

func getOSRev() int {
	if osrev, ok := sysctlInt([]uint32{_CTL_KERN, _KERN_OSREV}); ok {
		return int(osrev)
	}
	return 0
}

//go:nosplit
func semacreate(mp *m) {
}

//go:nosplit
func semasleep(ns int64) int32 {
	gp := getg()
	var deadline int64
	if ns >= 0 {
		deadline = nanotime() + ns
	}

	for {
		v := atomic.Load(&gp.m.waitsemacount)
		if v > 0 {
			if atomic.Cas(&gp.m.waitsemacount, v, v-1) {
				return 0 // semaphore acquired
			}
			continue
		}

		// Sleep until unparked by semawakeup or timeout.
		var tsp *timespec
		var ts timespec
		if ns >= 0 {
			wait := deadline - nanotime()
			if wait <= 0 {
				return -1
			}
			ts.setNsec(wait)
			tsp = &ts
		}
		ret := lwp_park(_CLOCK_MONOTONIC, _TIMER_RELTIME, tsp, 0, unsafe.Pointer(&gp.m.waitsemacount), nil)
		if ret == _ETIMEDOUT {
			return -1
		}
	}
}

//go:nosplit
func semawakeup(mp *m) {
	atomic.Xadd(&mp.waitsemacount, 1)
	// From NetBSD's _lwp_unpark(2) manual:
	// "If the target LWP is not currently waiting, it will return
	// immediately upon the next call to _lwp_park()."
	ret := lwp_unpark(int32(mp.procid), unsafe.Pointer(&mp.waitsemacount))
	if ret != 0 && ret != _ESRCH {
		// semawakeup can be called on signal stack.
		systemstack(func() {
			print("thrwakeup addr=", &mp.waitsemacount, " sem=", mp.waitsemacount, " ret=", ret, "\n")
		})
	}
}

// May run with m.p==nil, so write barriers are not allowed.
//
//go:nowritebarrier
func newosproc(mp *m) {
	stk := unsafe.Pointer(mp.g0.stack.hi)
	if false {
		print("newosproc stk=", stk, " m=", mp, " g=", mp.g0, " id=", mp.id, " ostk=", &mp, "\n")
	}

	var uc ucontextt
	getcontext(unsafe.Pointer(&uc))

	// _UC_SIGMASK does not seem to work here.
	// It would be nice if _UC_SIGMASK and _UC_STACK
	// worked so that we could do all the work setting
	// the sigmask and the stack here, instead of setting
	// the mask here and the stack in netbsdMstart.
	// For now do the blocking manually.
	uc.uc_flags = _UC_SIGMASK | _UC_CPU
	uc.uc_link = nil
	uc.uc_sigmask = sigset_all

	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)

	lwp_mcontext_init(&uc.uc_mcontext, stk, mp, mp.g0, abi.FuncPCABI0(netbsdMstart))

	ret := retryOnEAGAIN(func() int32 {
		errno := lwp_create(unsafe.Pointer(&uc), _LWP_DETACHED, unsafe.Pointer(&mp.procid))
		// lwp_create returns negative errno
		return -errno
	})
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if ret != 0 {
		print("runtime: failed to create new OS thread (have ", mcount()-1, " already; errno=", ret, ")\n")
		if ret == _EAGAIN {
			println("runtime: may need to increase max user processes (ulimit -p)")
		}
		throw("runtime.newosproc")
	}
}

// mstart is the entry-point for new Ms.
// It is written in assembly, uses ABI0, is marked TOPFRAME, and calls netbsdMstart0.
func netbsdMstart()

// netbsdMstart0 is the function call that starts executing a newly
// created thread. On NetBSD, a new thread inherits the signal stack
// of the creating thread. That confuses minit, so we remove that
// signal stack here before calling the regular mstart. It's a bit
// baroque to remove a signal stack here only to add one in minit, but
// it's a simple change that keeps NetBSD working like other OS's.
// At this point all signals are blocked, so there is no race.
//
//go:nosplit
func netbsdMstart0() {
	st := stackt{ss_flags: _SS_DISABLE}
	sigaltstack(&st, nil)
	mstart0()
}

func osinit() {
	ncpu = getncpu()
	if physPageSize == 0 {
		physPageSize = getPageSize()
	}
	needSysmonWorkaround = getOSRev() < 902000000 // NetBSD 9.2
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
	gp := getg()
	gp.m.procid = uint64(lwp_self())

	// On NetBSD a thread created by pthread_create inherits the
	// signal stack of the creating thread. We always create a
	// new signal stack here, to avoid having two Go threads using
	// the same signal stack. This breaks the case of a thread
	// created in C that calls sigaltstack and then calls a Go
	// function, because we will lose track of the C code's
	// sigaltstack, but it's the best we can do.
	signalstack(&gp.m.gsignal.stack)
	gp.m.newSigstack = true

	minitSignalMask()
}

// Called from dropm to undo the effect of an minit.
//
//go:nosplit
func unminit() {
	unminitSignals()
	// Don't clear procid, it is used by locking (semawake), and locking
	// must continue working after unminit.
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

func sigtramp()

type sigactiont struct {
	sa_sigaction uintptr
	sa_mask      sigset
	sa_flags     int32
}

//go:nosplit
//go:nowritebarrierrec
func setsig(i uint32, fn uintptr) {
	var sa sigactiont
	sa.sa_flags = _SA_SIGINFO | _SA_ONSTACK | _SA_RESTART
	sa.sa_mask = sigset_all
	if fn == abi.FuncPCABIInternal(sighandler) { // abi.FuncPCABIInternal(sighandler) matches the callers in signal_unix.go
		fn = abi.FuncPCABI0(sigtramp)
	}
	sa.sa_sigaction = fn
	sigaction(i, &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func setsigstack(i uint32) {
	throw("setsigstack")
}

//go:nosplit
//go:nowritebarrierrec
func getsig(i uint32) uintptr {
	var sa sigactiont
	sigaction(i, nil, &sa)
	return sa.sa_sigaction
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
	_AT_NULL   = 0 // Terminates the vector
	_AT_PAGESZ = 6 // Page size in bytes
)

func sysauxv(auxv []uintptr) (pairs int) {
	var i int
	for i = 0; auxv[i] != _AT_NULL; i += 2 {
		tag, val := auxv[i], auxv[i+1]
		switch tag {
		case _AT_PAGESZ:
			physPageSize = val
		}
	}
	return i / 2
}

// raise sends signal to the calling thread.
//
// It must be nosplit because it is used by the signal handler before
// it definitely has a Go stack.
//
//go:nosplit
func raise(sig uint32) {
	lwp_kill(lwp_self(), int(sig))
}

func signalM(mp *m, sig int) {
	lwp_kill(int32(mp.procid), sig)
}

// sigPerThreadSyscall is only used on linux, so we assign a bogus signal
// number.
const sigPerThreadSyscall = 1 << 31

//go:nosplit
func runPerThreadSyscall() {
	throw("runPerThreadSyscall only valid on linux")
}
```