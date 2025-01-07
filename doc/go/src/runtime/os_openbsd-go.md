Response:
Let's break down the thought process for analyzing this Go runtime code snippet.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable keywords and structures. Things that immediately jump out are:

* `package runtime`:  This tells us it's part of the core Go runtime.
* `import`:  Indicates dependencies on other internal packages.
* `type mOS struct`: Defines a platform-specific structure related to the "m" (machine/OS thread) type.
* `const`: Defines various operating system level constants (starting with `_`). These are often syscall numbers or flags.
* `func`:  A series of functions, many with descriptive names like `sysctlInt`, `getncpu`, `getPageSize`, `semacreate`, `semasleep`, `semawakeup`, `osinit`, `readRandom`, `setsig`, `signalM`, etc.
* `//go:linkname`, `//go:nosplit`, `//go:nowritebarrierrec`: These are compiler directives hinting at specific behaviors or constraints.
* `sigset`, `sigactiont`, `stackt`:  Types related to signal handling.
* Comments: Providing context and explanation.

**2. Grouping by Functionality:**

As I scan, I start mentally grouping the functions based on their names and the constants they use. This helps organize the information.

* **System Information:**  `sysctlInt`, `sysctlUint64`, `getncpu`, `getPageSize`. These clearly deal with retrieving system-level information.
* **Synchronization Primitives:** `semacreate`, `semasleep`, `semawakeup`. The "sema" prefix strongly suggests semaphore-related operations.
* **Initialization:** `osinit`, `mpreinit`, `minit`, `unminit`, `mdestroy`. These likely handle the setup and teardown of the runtime environment on OpenBSD.
* **Random Number Generation:** `readRandom`.
* **Environment Variables:** `goenvs`, `goenvs_unix`.
* **Signal Handling:** `sigtramp`, `sigactiont`, `setsig`, `getsig`, `setSignalstackSP`, `sigaddset`, `sigdelset`, `validSIGPROF`, `raise`, `signalM`. This is a substantial block related to signal management.
* **Stack Management:** `osStackAlloc`, `osStackFree`, `osStackRemap`.
* **Profiling:** `setProcessCPUProfiler`, `setThreadCPUProfiler`.

**3. Inferring Purpose and Functionality of Groups:**

Now I start to deduce the *why* behind these groups.

* **System Information:** The Go runtime needs to know things like the number of CPUs and the page size to optimize its scheduling and memory management. `sysctl` is a common Unix system call for this.
* **Synchronization:** Go's concurrency model relies on primitives like semaphores for coordinating goroutines. These functions are the low-level implementation for OpenBSD.
* **Initialization:**  Every program needs initialization. The runtime needs to set up its internal structures, signal handlers, and other OS-specific configurations.
* **Random Numbers:**  Essential for security and various other tasks. `/dev/urandom` is the standard Unix way to get cryptographically secure random numbers.
* **Environment Variables:** The runtime needs to access and potentially manipulate environment variables.
* **Signal Handling:**  Crucial for handling asynchronous events, including interrupts, errors, and signals sent by other processes. Go has its own signal handling mechanism that interacts with the OS.
* **Stack Management:** Goroutines have their own stacks. The runtime needs to allocate and manage this memory.
* **Profiling:**  Allows developers to analyze the performance of their Go programs.

**4. Focusing on Specific Functions and Inferring Go Features:**

Let's take a deeper dive into some specific functions to connect them to higher-level Go features.

* **`getncpu()` and `getPageSize()`:** These are clearly used to determine the system's CPU count and memory page size. This information is likely used internally by the Go scheduler and memory allocator.

* **`semacreate()`, `semasleep()`, `semawakeup()`:** These are the core of a semaphore implementation. In Go, this directly relates to the use of `sync.WaitGroup`, `sync.Mutex`, `sync.Cond`, and channel operations. When a goroutine blocks on a channel or mutex, these low-level semaphore functions are likely involved behind the scenes.

* **Signal Handling functions (`setsig`, `getsig`, `signalM`):** This is about how Go's `os/signal` package interacts with the operating system's signal mechanism. When you use `signal.Notify` in Go, it eventually translates to setting up signal handlers using functions like `sigaction`. The `sigtramp` function is likely an assembly trampoline to handle the transition from the OS signal handler to Go's signal handling logic.

* **`readRandom()`:** This directly implements the functionality of `crypto/rand`. When you call functions like `rand.Read` or `rand.Int`, this low-level function is used on OpenBSD to get the random bytes.

**5. Considering Compiler Directives and Internal Packages:**

The `//go:linkname`, `//go:nosplit`, and `//go:nowritebarrierrec` directives provide valuable clues.

* `//go:linkname`:  Indicates that a Go function is being linked to a function in an internal package (like `internal/cpu`). This is a way for the runtime to access low-level functionalities without exposing them as part of the public API.
* `//go:nosplit`:  Means the function cannot be preempted. This is important for low-level runtime functions that need to execute without interruption to maintain consistency.
* `//go:nowritebarrierrec`: Indicates that the function should not contain write barriers. Write barriers are used by the garbage collector, and these annotations are used to optimize performance in critical sections.

**6. Thinking about Error-Prone Areas:**

Based on the code, potential pitfalls for users might include:

* **Incorrect assumptions about CPU count:** The code explicitly mentions an issue with hyperthreading reporting. Users might need to be aware that the number of CPUs reported by Go might differ from the raw hardware count in some edge cases. However, this is handled internally by the runtime, so it's less of a *user* error and more of an implementation detail.
* **Signal handling complexities:**  While Go simplifies signal handling, understanding the underlying OS signals and their interactions can still be tricky. Incorrectly handling signals in C code that interacts with Go could lead to issues.

**7. Structuring the Answer:**

Finally, I organize the gathered information into a clear and structured answer, addressing each point in the prompt:

* Listing the functions and their direct functionalities.
* Inferring the higher-level Go features they enable, providing code examples where possible.
* Explaining any command-line parameter handling (though this snippet doesn't have any directly).
* Identifying potential user errors.

This systematic approach, starting with a broad overview and then drilling down into specifics, allows for a comprehensive understanding of the provided Go runtime code.
这段代码是 Go 语言运行时（runtime）库中针对 OpenBSD 操作系统的一部分实现，主要负责提供操作系统相关的底层功能，供 Go 运行时环境使用。下面列举其主要功能：

**1. 操作系统相关常量定义:**

* 定义了一些 OpenBSD 特有的错误码，如 `_ESRCH`（无此进程）、`_EWOULDBLOCK`（资源暂时不可用，相当于 `_EAGAIN`）、`_ENOTSUP`（不支持）。
* 定义了 OpenBSD 中 `sys/time.h` 中定义的时钟类型，如 `_CLOCK_REALTIME`（系统实时时钟）、`_CLOCK_VIRTUAL`（进程 CPU 时间）、`_CLOCK_PROF`（进程 CPU 和系统调用时间）、`_CLOCK_MONOTONIC`（单调递增时钟）。
* 定义了 `sys/sysctl.h` 中用于获取系统信息的 `mib` (Management Information Base) 的常量，如 `_CTL_HW`（硬件信息）、`_HW_NCPU`（CPU 核心数）、`_HW_PAGESIZE`（内存页大小）、`_HW_NCPUONLINE`（在线 CPU 核心数）。

**2. 系统调用辅助函数:**

* `sysctlInt(mib []uint32) (int32, bool)`:  封装了 `sysctl` 系统调用，用于获取整型类型的系统信息。输入参数 `mib` 是一个表示要查询的系统信息的数组。返回值为查询到的整数值和一个布尔值，指示查询是否成功。
* `sysctlUint64(mib []uint32) (uint64, bool)`:  与 `sysctlInt` 类似，但用于获取 64 位无符号整型类型的系统信息。
* `internal_cpu_sysctlUint64(mib []uint32) (uint64, bool)`: 通过 `//go:linkname` 指令，将内部包 `internal/cpu` 中的同名函数链接到这里的 `sysctlUint64`，用于获取 CPU 相关信息。

**3. 获取系统信息函数:**

* `getncpu() int32`:  获取系统 CPU 核心数。它会优先尝试使用 `hw.ncpuonline` 获取在线 CPU 核心数，如果失败则尝试使用 `hw.ncpu` 获取总核心数。这是为了解决 OpenBSD 6.4 上禁用超线程时 `hw.ncpu` 报告错误的问题。
* `getPageSize() uintptr`: 获取系统的内存页大小。

**4. 信号量相关函数:**

* `semacreate(mp *m)`:  一个空函数，在 OpenBSD 上似乎不需要显式的信号量创建操作。
* `semasleep(ns int64) int32`:  实现睡眠等待。当 `gp.m.waitsemacount` 大于 0 时，原子地减 1 并返回，表示获取了信号量。否则，它会调用 `thrsleep` 进入睡眠状态，直到被 `semawakeup` 唤醒或超时。如果超时，返回 -1。
    * **代码推理:** 这段代码实现了一种基于原子计数器的自旋锁和操作系统睡眠的混合信号量机制。goroutine 通过增加 `waitsemacount` 进入等待状态，其他 goroutine 通过减少 `waitsemacount` 来释放信号量。
    * **假设输入与输出:** 假设一个 goroutine 调用 `semasleep(1000000)`（等待 1 毫秒）。
        * 如果在 1 毫秒内，另一个 goroutine 调用了 `semawakeup` 并且成功减少了 `gp.m.waitsemacount`，那么 `semasleep` 会返回 0。
        * 如果 1 毫秒超时，`semasleep` 会返回 -1。
* `semawakeup(mp *m)`:  唤醒等待在指定 `m` (machine，代表一个 OS 线程) 上的信号量。它原子地增加 `mp.waitsemacount` 并调用 `thrwakeup` 唤醒一个等待的线程。

**5. 运行时初始化函数:**

* `osinit()`:  在 Go 运行时启动时调用，用于执行与操作系统相关的初始化操作，这里主要是获取 CPU 核心数和内存页大小。

**6. 读取随机数:**

* `urandom_dev`: 定义了 `/dev/urandom` 设备的路径。
* `readRandom(r []byte) int`: 从 `/dev/urandom` 读取随机数据填充到字节切片 `r` 中。

**7. 环境变量处理:**

* `goenvs()`:  调用通用的 Unix 环境变量处理函数 `goenvs_unix()`。

**8. 线程 (m) 初始化和清理函数:**

* `mpreinit(mp *m)`:  在创建新的 `m` 时调用（在父线程中），用于分配信号处理所需的 gsignal 栈。
* `minit()`: 在新线程中调用，设置线程的 `procid` 为操作系统线程 ID，并初始化信号处理。
* `unminit()`:  在 `dropm` 时调用，用于撤销 `minit` 的影响，包括清理信号处理相关的设置。
* `mdestroy(mp *m)`:  在 `exitm` 时调用，用于清理线程拥有的资源。

**9. 信号处理相关函数:**

* `sigtramp()`:  一个占位符，实际上是汇编代码实现的信号处理跳转函数。
* `sigactiont`: 定义了 `sigaction` 系统调用使用的结构体。
* `setsig(i uint32, fn uintptr)`: 设置信号处理函数。如果 `fn` 是默认的信号处理函数 `sighandler`，则会将其替换为 `sigtramp`，以便在信号发生时跳转到 Go 的信号处理逻辑。
* `setsigstack(i uint32)`:  在 OpenBSD 上会抛出 panic，表示不支持。
* `getsig(i uint32) uintptr`: 获取当前信号的处理函数。
* `setSignalstackSP(s *stackt, sp uintptr)`: 设置信号栈的栈顶指针。
* `sigaddset(mask *sigset, i int)`: 向信号掩码中添加指定的信号。
* `sigdelset(mask *sigset, i int)`: 从信号掩码中移除指定的信号。
* `(c *sigctxt).fixsigcode(sig uint32)`:  一个空函数，在 OpenBSD 上不需要修复信号代码。
* `validSIGPROF(mp *m, c *sigctxt) bool`:  始终返回 `true`，表示 `SIGPROF` 信号是有效的。

**10. CPU Profiling:**

* `setProcessCPUProfiler(hz int32)`: 设置进程级别的 CPU Profiler 的频率。
* `setThreadCPUProfiler(hz int32)`: 设置线程级别的 CPU Profiler 的频率。

**11. 栈内存管理:**

* `osStackAlloc(s *mspan)`:  分配栈内存，并使用 `mmap` 进行映射，并标记为栈内存 (`_MAP_STACK`).
* `osStackFree(s *mspan)`: 释放栈内存，通过 `mmap` 重新映射，去除 `_MAP_STACK` 标记。
* `osStackRemap(s *mspan, flags int32)`: 重新映射栈内存，可以添加或移除 `_MAP_STACK` 标记。

**12. 发送信号:**

* `raise(sig uint32)`: 向当前线程发送指定的信号。
* `signalM(mp *m, sig int)`: 向指定的 `m` 对应的线程发送信号。

**13. 线程级别系统调用 (Linux 特有):**

* `sigPerThreadSyscall`: 定义了一个在 Linux 上用于线程级别系统调用的信号，在 OpenBSD 上被赋予一个无效的值。
* `runPerThreadSyscall()`:  在 OpenBSD 上会抛出 panic，因为这个功能仅在 Linux 上有效。

**推理 Go 语言功能实现:**

**1. Goroutine 的同步与等待 (基于信号量):**

`semasleep` 和 `semawakeup` 提供了基本的同步原语，这可以用于实现 Go 语言中的 `sync.Mutex`、`sync.RWMutex`、`sync.WaitGroup` 和 channel 的底层阻塞和唤醒机制。

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func main() {
	var wg sync.WaitGroup
	var count int

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// 模拟需要同步的操作
			runtime.LockOSThread() // 通常不需要手动 LockOSThread，这里只是为了演示
			time.Sleep(time.Millisecond * 10)
			count++
			runtime.UnlockOSThread()
		}()
	}

	wg.Wait()
	fmt.Println("Count:", count)
}
```

在这个例子中，虽然没有直接调用 `semasleep` 或 `semawakeup`，但 `sync.WaitGroup` 的 `Wait()` 方法内部可能会使用类似的底层机制（在 OpenBSD 上可能是基于这段代码提供的信号量实现）来阻塞主 goroutine，直到所有的子 goroutine 都执行完毕。

**2. `os/signal` 包的实现:**

`setsig`、`getsig` 和 `signalM` 等函数是 `os/signal` 包实现的基础。当你使用 `signal.Notify` 监听特定信号时，Go 运行时会调用 `setsig` 来注册信号处理函数。当操作系统发送信号给进程时，OpenBSD 内核会调用 `sigtramp`，然后跳转到 Go 的信号处理逻辑。

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
		fmt.Println("\nReceived signal:", sig)
		os.Exit(0)
	}()

	fmt.Println("Press Ctrl+C to exit.")
	time.Sleep(time.Hour)
}
```

当你在终端按下 Ctrl+C 时，操作系统会发送 `SIGINT` 信号。Go 运行时通过 `setsig` 设置的信号处理函数会捕获这个信号，并通过 channel `sigs` 通知你的 Go 代码。

**3. 获取 CPU 核心数和内存页大小:**

`getncpu` 和 `getPageSize` 的返回值会被 Go 运行时用于调度 goroutine 和管理内存。例如，`runtime.GOMAXPROCS(n)` 默认会使用 `getncpu` 的返回值来设置可以并行执行的 goroutine 的最大数量。内存页大小信息则被内存分配器（如 mcache, mcentral 等）使用。

```go
package main

import (
	"fmt"
	"runtime"
)

func main() {
	n := runtime.NumCPU()
	fmt.Println("Number of CPUs:", n)

	pageSize := runtime.MemProfileRate // 这是一个和内存分配相关的配置，与 getPageSize 有间接联系
	fmt.Println("Memory Profile Rate:", pageSize)
}
```

虽然 `runtime.NumCPU()` 内部实现可能更复杂，但其最终目的是获取可用的 CPU 核心数，这与 `getncpu` 的功能一致。

**命令行参数处理:**

这段代码本身不涉及直接的命令行参数处理。Go 程序的命令行参数处理通常由 `os` 包完成，例如 `os.Args` 可以获取命令行参数。

**使用者易犯错的点:**

由于这段代码是 Go 运行时的底层实现，普通 Go 开发者不会直接调用其中的函数。因此，不容易犯直接调用上的错误。

然而，理解这些底层机制有助于理解 Go 程序的行为。例如，错误地设置 `GOMAXPROCS` 可能会导致 CPU 利用率不高，这与 `getncpu` 返回的 CPU 核心数有关。另外，对信号处理不当可能会导致程序行为异常，这与 `setsig` 等函数的行为相关。

总而言之，这段代码是 Go 语言在 OpenBSD 操作系统上运行的基础，它提供了诸如线程管理、同步、信号处理、内存管理等关键的底层功能，使得 Go 程序能够在 OpenBSD 上正确且高效地运行。

Prompt: 
```
这是路径为go/src/runtime/os_openbsd.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"internal/runtime/atomic"
	"unsafe"
)

type mOS struct {
	waitsemacount uint32
}

const (
	_ESRCH       = 3
	_EWOULDBLOCK = _EAGAIN
	_ENOTSUP     = 91

	// From OpenBSD's sys/time.h
	_CLOCK_REALTIME  = 0
	_CLOCK_VIRTUAL   = 1
	_CLOCK_PROF      = 2
	_CLOCK_MONOTONIC = 3
)

type sigset uint32

var sigset_all = ^sigset(0)

// From OpenBSD's <sys/sysctl.h>
const (
	_CTL_HW        = 6
	_HW_NCPU       = 3
	_HW_PAGESIZE   = 7
	_HW_NCPUONLINE = 25
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

func sysctlUint64(mib []uint32) (uint64, bool) {
	var out uint64
	nout := unsafe.Sizeof(out)
	ret := sysctl(&mib[0], uint32(len(mib)), (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	if ret < 0 {
		return 0, false
	}
	return out, true
}

//go:linkname internal_cpu_sysctlUint64 internal/cpu.sysctlUint64
func internal_cpu_sysctlUint64(mib []uint32) (uint64, bool) {
	return sysctlUint64(mib)
}

func getncpu() int32 {
	// Try hw.ncpuonline first because hw.ncpu would report a number twice as
	// high as the actual CPUs running on OpenBSD 6.4 with hyperthreading
	// disabled (hw.smt=0). See https://golang.org/issue/30127
	if n, ok := sysctlInt([]uint32{_CTL_HW, _HW_NCPUONLINE}); ok {
		return int32(n)
	}
	if n, ok := sysctlInt([]uint32{_CTL_HW, _HW_NCPU}); ok {
		return int32(n)
	}
	return 1
}

func getPageSize() uintptr {
	if ps, ok := sysctlInt([]uint32{_CTL_HW, _HW_PAGESIZE}); ok {
		return uintptr(ps)
	}
	return 0
}

//go:nosplit
func semacreate(mp *m) {
}

//go:nosplit
func semasleep(ns int64) int32 {
	gp := getg()

	// Compute sleep deadline.
	var tsp *timespec
	if ns >= 0 {
		var ts timespec
		ts.setNsec(ns + nanotime())
		tsp = &ts
	}

	for {
		v := atomic.Load(&gp.m.waitsemacount)
		if v > 0 {
			if atomic.Cas(&gp.m.waitsemacount, v, v-1) {
				return 0 // semaphore acquired
			}
			continue
		}

		// Sleep until woken by semawakeup or timeout; or abort if waitsemacount != 0.
		//
		// From OpenBSD's __thrsleep(2) manual:
		// "The abort argument, if not NULL, points to an int that will
		// be examined [...] immediately before blocking. If that int
		// is non-zero then __thrsleep() will immediately return EINTR
		// without blocking."
		ret := thrsleep(uintptr(unsafe.Pointer(&gp.m.waitsemacount)), _CLOCK_MONOTONIC, tsp, 0, &gp.m.waitsemacount)
		if ret == _EWOULDBLOCK {
			return -1
		}
	}
}

//go:nosplit
func semawakeup(mp *m) {
	atomic.Xadd(&mp.waitsemacount, 1)
	ret := thrwakeup(uintptr(unsafe.Pointer(&mp.waitsemacount)), 1)
	if ret != 0 && ret != _ESRCH {
		// semawakeup can be called on signal stack.
		systemstack(func() {
			print("thrwakeup addr=", &mp.waitsemacount, " sem=", mp.waitsemacount, " ret=", ret, "\n")
		})
	}
}

func osinit() {
	ncpu = getncpu()
	physPageSize = getPageSize()
}

// TODO(#69781): set startupRand using the .openbsd.randomdata ELF section.
// See SPECS.randomdata.

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
	gsignalSize := int32(32 * 1024)
	if GOARCH == "mips64" {
		gsignalSize = int32(64 * 1024)
	}
	mp.gsignal = malg(gsignalSize)
	mp.gsignal.m = mp
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, can not allocate memory.
func minit() {
	getg().m.procid = uint64(getthrid())
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
	sa_sigaction uintptr
	sa_mask      uint32
	sa_flags     int32
}

//go:nosplit
//go:nowritebarrierrec
func setsig(i uint32, fn uintptr) {
	var sa sigactiont
	sa.sa_flags = _SA_SIGINFO | _SA_ONSTACK | _SA_RESTART
	sa.sa_mask = uint32(sigset_all)
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
	*mask |= 1 << (uint32(i) - 1)
}

func sigdelset(mask *sigset, i int) {
	*mask &^= 1 << (uint32(i) - 1)
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

func osStackAlloc(s *mspan) {
	osStackRemap(s, _MAP_STACK)
}

func osStackFree(s *mspan) {
	// Undo MAP_STACK.
	osStackRemap(s, 0)
}

func osStackRemap(s *mspan, flags int32) {
	a, err := mmap(unsafe.Pointer(s.base()), s.npages*pageSize, _PROT_READ|_PROT_WRITE, _MAP_PRIVATE|_MAP_ANON|_MAP_FIXED|flags, -1, 0)
	if err != 0 || uintptr(a) != s.base() {
		print("runtime: remapping stack memory ", hex(s.base()), " ", s.npages*pageSize, " a=", a, " err=", err, "\n")
		throw("remapping stack memory failed")
	}
}

//go:nosplit
func raise(sig uint32) {
	thrkill(getthrid(), int(sig))
}

func signalM(mp *m, sig int) {
	thrkill(int32(mp.procid), sig)
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