Response:
Let's break down the thought process for analyzing this Go runtime code snippet.

**1. Initial Scan and Understanding the Context:**

* **File Path:**  `go/src/runtime/os_darwin.go` immediately tells us this is platform-specific code for macOS (Darwin). The `runtime` package is core to Go's execution.
* **Copyright and License:** Standard Go boilerplate, indicating open-source.
* **Package Declaration:** `package runtime` confirms the location.
* **Imports:** `internal/abi`, `internal/stringslite`, `unsafe`. These give hints about the code's purpose. `abi` likely deals with calling conventions, `stringslite` with string manipulation, and `unsafe` signifies low-level memory operations.

**2. Identifying Key Data Structures:**

* **`mOS` struct:**  This is clearly a struct associated with the `m` (machine/OS thread) structure in the Go runtime. The fields `initialized`, `mutex`, `cond`, and `count` strongly suggest this is related to thread synchronization.

**3. Analyzing Individual Functions (Top-Down or Based on Obvious Functionality):**

* **`unimplemented(name string)`:** Straightforward. Indicates a feature is not yet implemented and will cause a crash if called.
* **`semacreate(mp *m)`:**  "sema" likely refers to semaphore. The use of `pthread_mutex_init` and `pthread_cond_init` confirms this is about initializing synchronization primitives for a given `m`.
* **`semasleep(ns int64)`:**  This function manages a thread going to sleep, likely on a semaphore. The logic involves checking a count, waiting on a condition variable, and handling timeouts. The check for `g == mp.gsignal` is interesting and suggests a special handling for signal handlers.
* **`semawakeup(mp *m)`:**  This wakes up a thread sleeping on the semaphore associated with `mp`. It increments the count and signals the condition variable. The signal stack check is present here too.
* **`sigNoteRead`, `sigNoteWrite`:** These are global variables for file descriptors, specifically for a pipe. The naming suggests they are related to signals or notifications.
* **`sigNoteSetup(*note)`:**  This function initializes the pipe for signal notifications. The comment about "async-signal-safe" is crucial. The error handling for `duplicate sigNoteSetup` and `pipe failed` is standard. The non-blocking write end and blocking read end are important design choices.
* **`sigNoteWakeup(*note)`:**  Writes a byte to the write end of the pipe, thus signaling any thread waiting on the read end.
* **`sigNoteSleep(*note)`:**  Reads from the read end of the pipe, blocking until data is available. The `entersyscallblock`/`exitsyscall` calls are standard Go runtime practices for informing the scheduler about syscalls.
* **`osinit()`:**  General OS initialization. The comment about `pthread_create` being delayed and the calls to `getncpu` and `getPageSize` are important.
* **`sysctlbynameInt32(name []byte)` and `internal_cpu_getsysctlbyname`:**  These functions use the `sysctl` system call, a common macOS/BSD mechanism for getting kernel information. The `internal_cpu_` prefix suggests it's for internal use within the Go runtime.
* **`getncpu()` and `getPageSize()`:**  Specifically fetch the number of CPUs and the page size using `sysctl`. The hardcoded `_CTL_HW`, `_HW_NCPU`, and `_HW_PAGESIZE` are macOS constants.
* **`readRandom(r []byte)`:**  Uses `arc4random_buf` for generating random data.
* **`goenvs()`:**  Calls `goenvs_unix()`, indicating platform-independent environment variable handling.
* **`newosproc(mp *m)`:** This is critical for creating new OS threads for Go goroutines. The use of `pthread_create` and setting attributes like detached state are key. The signal masking around the `pthread_create` call is significant for thread safety.
* **`mstart_stub()`:** The comment indicates this is assembly glue code called by `pthread_create` to then invoke `mstart`.
* **`newosproc0(stacksize uintptr, fn uintptr)`:** Similar to `newosproc` but for pre-runtime initialization, without an `m`.
* **`libpreinit()`:** Initialization for `-buildmode=c-archive` or `-buildmode=c-shared`. `initsig(true)` hints at signal handling setup.
* **`mpreinit(mp *m)`:** Per-`m` initialization on the parent thread. The allocation of `gsignal` and the `mlock` on ARM64 are important platform-specific details.
* **`minit()`:** Per-`m` initialization on the new thread. Setting up signal stacks and masks.
* **`unminit()`:** Undoing the effects of `minit`.
* **`mdestroy(mp *m)`:**  Cleanup when an `m` is destroyed. The comment about not taking locks is crucial.
* **`osyield_no_g()` and `osyield()`:**  Yield the current thread. The `_no_g` version likely doesn't require a `g` (goroutine).
* **Signal Handling (`_NSIG`, `_SI_USER`, `_SIG_BLOCK`, etc., `sigset`, `sigset_all`, `setsig`, `sigtramp`, `cgoSigtramp`, `setsigstack`, `getsig`, `setSignalstackSP`, `sigaddset`, `sigdelset`):**  This large block of code deals with low-level signal management, including setting up signal handlers, signal masks, and the signal stack. The differentiation between `sigtramp` and `cgoSigtramp` is relevant for interoperability with C code.
* **Profiling (`setProcessCPUProfiler`, `setThreadCPUProfiler`, `validSIGPROF`):**  Functions related to CPU profiling, using timers and signals (`SIGPROF`).
* **`executablePath` and `sysargs`:**  Retrieving the executable path from the command-line arguments. The stripping of the "executable_path=" prefix is a macOS-specific detail.
* **`signalM(mp *m, sig int)`:**  Sends a signal to a specific thread.
* **`sigPerThreadSyscall` and `runPerThreadSyscall()`:** Indicate a Linux-specific feature (per-thread syscalls) that's not implemented on Darwin.

**4. Identifying Functionality and Examples:**

After analyzing each function, I start grouping them by functionality and thinking about how to illustrate them with Go code. For instance:

* **Thread Synchronization:** `mOS`, `semacreate`, `semasleep`, `semawakeup`. A simple example with goroutines using a mutex and condition variable comes to mind.
* **Signal Handling:**  `setsig`, `sigtramp`, etc. An example of registering a signal handler using `signal.Notify` and a custom handler function.
* **Process Information:** `getncpu`, `getPageSize`, `sysargs`. Showing how to use `runtime.NumCPU()` and `os.Args`.
* **Randomness:** `readRandom`. Illustrating the use of `rand.Read`.

**5. Considering Potential Pitfalls:**

This comes from experience with concurrency and system programming. The "semaphores on the signal stack" error stands out as a potential problem. The single `sigNote` instance is also a limitation.

**6. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, covering:

* **Core Functionalities:** Grouping related functions together.
* **Go Language Features:** Connecting the code to higher-level Go concepts.
* **Code Examples:** Providing concrete demonstrations.
* **Assumptions and I/O (where applicable):**  Being explicit about test cases.
* **Command-Line Arguments:**  Explaining how the code relates to them.
* **Common Mistakes:**  Highlighting potential errors for developers.

This iterative process of scanning, analyzing, grouping, exemplifying, and considering edge cases is crucial for understanding and explaining complex code like this snippet from the Go runtime.
这段代码是 Go 语言运行时（runtime）在 Darwin（macOS）操作系统上的特定实现部分。它主要负责以下几个核心功能：

**1. 操作系统线程管理 (OS Thread Management):**

* **`mOS` 结构体:**  存储与操作系统线程 (`m` 在 Go 运行时中代表一个 OS 线程) 相关的 Darwin 特有信息，例如互斥锁 (`mutex`) 和条件变量 (`cond`)，用于线程间的同步。
* **`semacreate(mp *m)`:** 初始化与特定 `m` 关联的信号量相关的互斥锁和条件变量。这似乎是 Go 运行时内部实现的一种轻量级同步机制，可能用于 Goroutine 的调度或管理。
* **`semasleep(ns int64)`:** 使当前 `m` 进入睡眠状态，等待信号。可以设置超时时间。它使用底层的 POSIX 线程同步原语 `pthread_mutex_lock`， `pthread_cond_wait` 和 `pthread_cond_timedwait_relative_np` 实现。
* **`semawakeup(mp *m)`:** 唤醒在与特定 `m` 关联的信号量上等待的线程。它使用 `pthread_mutex_lock` 和 `pthread_cond_signal` 实现。
* **`newosproc(mp *m)`:** 创建一个新的操作系统线程。这是 Go 运行时创建新 Goroutine 并将其绑定到 OS 线程的关键步骤。它使用了 POSIX 线程创建函数 `pthread_create`。
* **`newosproc0(stacksize uintptr, fn uintptr)`:**  一个在 Go 运行时初始化早期阶段创建 OS 线程的版本，可能用于引导启动过程。
* **`mpreinit(mp *m)`:** 在父线程中初始化新的 `m`，例如分配信号处理的栈空间 (`gsignal`)。
* **`minit()`:** 在新创建的线程中进行初始化，例如设置信号处理栈和信号掩码。
* **`unminit()`:**  撤销 `minit` 的操作，在 `m` 被移除时调用。
* **`mdestroy(mp *m)`:**  清理与 `m` 相关的资源。

**2. 信号处理 (Signal Handling):**

* **`sigNoteRead`, `sigNoteWrite`:**  全局变量，用于实现一个异步信号安全的通知机制。这是一个基于管道的实现，用于在信号处理程序中安全地唤醒等待的线程。
* **`sigNoteSetup(*note)`:** 初始化用于异步信号处理的通知机制。它创建一个管道，并设置写端为非阻塞。
* **`sigNoteWakeup(*note)`:**  向 `sigNoteWrite` 写入一个字节，唤醒在 `sigNoteSleep` 中等待的线程。
* **`sigNoteSleep(*note)`:** 从 `sigNoteRead` 读取数据，阻塞当前线程直到有数据可读。
* **`setsig(i uint32, fn uintptr)`:** 设置信号 `i` 的处理函数为 `fn`。它使用底层的 `sigaction` 系统调用。
* **`sigtramp()` 和 `cgoSigtramp()`:**  汇编实现的信号处理入口点。`sigtramp` 用于纯 Go 代码，`cgoSigtramp` 用于涉及 CGO 的情况。
* **`setsigstack(i uint32)`:**  确保信号处理程序在独立的栈上运行，避免栈溢出。
* **`getsig(i uint32)`:** 获取信号 `i` 的当前处理函数。
* **`sigaddset(mask *sigset, i int)` 和 `sigdelset(mask *sigset, i int)`:**  用于操作信号掩码。
* **`signalM(mp *m, sig int)`:** 向指定的 `m` (线程) 发送信号。

**3. 系统信息获取 (System Information Retrieval):**

* **`osinit()`:**  在运行时初始化阶段被调用，用于获取系统信息，如 CPU 数量和页大小。
* **`getncpu()`:** 使用 `sysctl` 系统调用获取 CPU 核心数。
* **`getPageSize()`:** 使用 `sysctl` 系统调用获取系统页大小。
* **`sysctlbynameInt32(name []byte)` 和 `internal_cpu_getsysctlbyname(name []byte)`:**  封装了使用 `sysctlbyname` 系统调用获取特定系统信息的功能。

**4. 随机数生成 (Random Number Generation):**

* **`readRandom(r []byte)`:** 使用 `arc4random_buf` 函数填充字节切片 `r`，提供安全的随机数。

**5. 环境变量处理 (Environment Variable Handling):**

* **`goenvs()`:** 调用平台无关的 `goenvs_unix()` 函数来处理环境变量。

**6. CPU 性能分析 (CPU Profiling):**

* **`setProcessCPUProfiler(hz int32)` 和 `setThreadCPUProfiler(hz int32)`:** 设置进程或线程级别的 CPU 性能分析器，指定采样频率。
* **`validSIGPROF(mp *m, c *sigctxt)`:** 校验 `SIGPROF` 信号的上下文是否有效。

**7. 进程参数处理 (Process Argument Handling):**

* **`executablePath`:** 全局变量，存储可执行文件的路径。
* **`sysargs(argc int32, argv **byte)`:**  在程序启动时被调用，用于解析命令行参数，并设置 `executablePath`。

**8. 其他:**

* **`unimplemented(name string)`:**  一个占位函数，用于标记尚未实现的功能。
* **`osyield()` 和 `osyield_no_g()`:**  让出当前 CPU 时间片，允许其他 Goroutine 运行。

**推理出的 Go 语言功能实现并举例：**

根据代码中的 `semacreate`, `semasleep`, `semawakeup`，可以推断这是 Go 语言中实现 **channel** 或类似同步机制的基础。Channel 允许 Goroutine 之间进行同步和通信。

**代码示例 (Channel 的一种可能的底层实现方式):**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func main() {
	// 假设我们有一个底层的 "semaphore" 结构体，类似于 mOS
	type semaphore struct {
		mu    sync.Mutex
		cond  *sync.Cond
		count int
	}

	newSemaphore := func() *semaphore {
		s := &semaphore{}
		s.cond = sync.NewCond(&s.mu)
		return s
	}

	semaCreate := func(s *semaphore) {
		// 在 runtime/os_darwin.go 中对应 semacreate
		// 这里使用 sync.Mutex 和 sync.Cond 模拟
	}

	semaSleep := func(s *semaphore, ns time.Duration) bool {
		// 在 runtime/os_darwin.go 中对应 semasleep
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.count > 0 {
			s.count--
			return true
		}
		if ns > 0 {
			timeout := time.Now().Add(ns)
			for s.count == 0 && time.Now().Before(timeout) {
				s.cond.Wait()
			}
			if s.count > 0 {
				s.count--
				return true
			}
			return false // 超时
		} else {
			for s.count == 0 {
				s.cond.Wait()
			}
			s.count--
			return true
		}
	}

	semaWakeup := func(s *semaphore) {
		// 在 runtime/os_darwin.go 中对应 semawakeup
		s.mu.Lock()
		defer s.mu.Unlock()
		s.count++
		s.cond.Signal()
	}

	// 使用 "semaphore" 模拟一个简单的 channel
	ch := newSemaphore()
	semaCreate(ch)

	go func() {
		fmt.Println("发送数据...")
		time.Sleep(1 * time.Second)
		semaWakeup(ch) // 模拟向 channel 发送数据
		fmt.Println("数据已发送")
	}()

	fmt.Println("等待数据...")
	semaSleep(ch, 0) // 模拟从 channel 接收数据，无限等待
	fmt.Println("接收到数据")

	runtime.Gosched()
}
```

**假设的输入与输出：**

在上面的 channel 模拟示例中：

* **输入：**  无显式输入，依赖于 Goroutine 的执行和时间延迟。
* **输出：**
  ```
  等待数据...
  发送数据...
  数据已发送
  接收到数据
  ```

**命令行参数的具体处理：**

`sysargs(argc int32, argv **byte)` 函数负责处理命令行参数。

* `argc`:  表示命令行参数的数量，包括程序本身。
* `argv`:  指向一个 C 风格的字符串数组的指针，每个字符串表示一个命令行参数。

`sysargs` 的主要功能是从 `argv` 中提取可执行文件的路径，并将其存储在全局变量 `executablePath` 中。  它还会跳过环境变量等信息，找到真正的可执行文件路径。

**使用者易犯错的点：**

虽然这段代码是 Go 运行时的内部实现，普通 Go 开发者不会直接接触，但理解其背后的概念有助于避免一些常见的并发编程错误：

* **在信号处理程序中使用非异步信号安全的函数:** `sigNoteSetup`, `sigNoteWakeup`, `sigNoteSleep` 的设计就是为了提供一个异步信号安全的方式进行通信。直接在信号处理程序中使用互斥锁或条件变量等非异步信号安全的函数可能会导致死锁或其他不可预测的行为。  Go 运行时通过特殊的机制（如 `sigNote`）来解决这个问题。
* **对底层线程同步机制理解不足:**  虽然 Go 提供了高级的并发原语（如 channel 和 `sync` 包），但理解底层的线程同步机制（如互斥锁和条件变量）有助于理解 Go 并发模型的实现原理，避免滥用或错误使用并发特性。

总而言之，这段 `os_darwin.go` 代码是 Go 语言在 macOS 平台上的基石，它负责底层的线程管理、信号处理、系统信息获取等关键功能，为 Go 程序的运行提供了必要的支撑。 开发者通常不需要直接操作这些底层细节，但了解其功能可以帮助更好地理解 Go 运行时的行为和并发模型的实现。

### 提示词
```
这是路径为go/src/runtime/os_darwin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/stringslite"
	"unsafe"
)

type mOS struct {
	initialized bool
	mutex       pthreadmutex
	cond        pthreadcond
	count       int
}

func unimplemented(name string) {
	println(name, "not implemented")
	*(*int)(unsafe.Pointer(uintptr(1231))) = 1231
}

//go:nosplit
func semacreate(mp *m) {
	if mp.initialized {
		return
	}
	mp.initialized = true
	if err := pthread_mutex_init(&mp.mutex, nil); err != 0 {
		throw("pthread_mutex_init")
	}
	if err := pthread_cond_init(&mp.cond, nil); err != 0 {
		throw("pthread_cond_init")
	}
}

//go:nosplit
func semasleep(ns int64) int32 {
	var start int64
	if ns >= 0 {
		start = nanotime()
	}
	g := getg()
	mp := g.m
	if g == mp.gsignal {
		// sema sleep/wakeup are implemented with pthreads, which are not async-signal-safe on Darwin.
		throw("semasleep on Darwin signal stack")
	}
	pthread_mutex_lock(&mp.mutex)
	for {
		if mp.count > 0 {
			mp.count--
			pthread_mutex_unlock(&mp.mutex)
			return 0
		}
		if ns >= 0 {
			spent := nanotime() - start
			if spent >= ns {
				pthread_mutex_unlock(&mp.mutex)
				return -1
			}
			var t timespec
			t.setNsec(ns - spent)
			err := pthread_cond_timedwait_relative_np(&mp.cond, &mp.mutex, &t)
			if err == _ETIMEDOUT {
				pthread_mutex_unlock(&mp.mutex)
				return -1
			}
		} else {
			pthread_cond_wait(&mp.cond, &mp.mutex)
		}
	}
}

//go:nosplit
func semawakeup(mp *m) {
	if g := getg(); g == g.m.gsignal {
		throw("semawakeup on Darwin signal stack")
	}
	pthread_mutex_lock(&mp.mutex)
	mp.count++
	if mp.count > 0 {
		pthread_cond_signal(&mp.cond)
	}
	pthread_mutex_unlock(&mp.mutex)
}

// The read and write file descriptors used by the sigNote functions.
var sigNoteRead, sigNoteWrite int32

// sigNoteSetup initializes a single, there-can-only-be-one, async-signal-safe note.
//
// The current implementation of notes on Darwin is not async-signal-safe,
// because the functions pthread_mutex_lock, pthread_cond_signal, and
// pthread_mutex_unlock, called by semawakeup, are not async-signal-safe.
// There is only one case where we need to wake up a note from a signal
// handler: the sigsend function. The signal handler code does not require
// all the features of notes: it does not need to do a timed wait.
// This is a separate implementation of notes, based on a pipe, that does
// not support timed waits but is async-signal-safe.
func sigNoteSetup(*note) {
	if sigNoteRead != 0 || sigNoteWrite != 0 {
		// Generalizing this would require avoiding the pipe-fork-closeonexec race, which entangles syscall.
		throw("duplicate sigNoteSetup")
	}
	var errno int32
	sigNoteRead, sigNoteWrite, errno = pipe()
	if errno != 0 {
		throw("pipe failed")
	}
	closeonexec(sigNoteRead)
	closeonexec(sigNoteWrite)

	// Make the write end of the pipe non-blocking, so that if the pipe
	// buffer is somehow full we will not block in the signal handler.
	// Leave the read end of the pipe blocking so that we will block
	// in sigNoteSleep.
	setNonblock(sigNoteWrite)
}

// sigNoteWakeup wakes up a thread sleeping on a note created by sigNoteSetup.
func sigNoteWakeup(*note) {
	var b byte
	write(uintptr(sigNoteWrite), unsafe.Pointer(&b), 1)
}

// sigNoteSleep waits for a note created by sigNoteSetup to be woken.
func sigNoteSleep(*note) {
	for {
		var b byte
		entersyscallblock()
		n := read(sigNoteRead, unsafe.Pointer(&b), 1)
		exitsyscall()
		if n != -_EINTR {
			return
		}
	}
}

// BSD interface for threading.
func osinit() {
	// pthread_create delayed until end of goenvs so that we
	// can look at the environment first.

	ncpu = getncpu()
	physPageSize = getPageSize()

	osinit_hack()
}

func sysctlbynameInt32(name []byte) (int32, int32) {
	out := int32(0)
	nout := unsafe.Sizeof(out)
	ret := sysctlbyname(&name[0], (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	return ret, out
}

//go:linkname internal_cpu_getsysctlbyname internal/cpu.getsysctlbyname
func internal_cpu_getsysctlbyname(name []byte) (int32, int32) {
	return sysctlbynameInt32(name)
}

const (
	_CTL_HW      = 6
	_HW_NCPU     = 3
	_HW_PAGESIZE = 7
)

func getncpu() int32 {
	// Use sysctl to fetch hw.ncpu.
	mib := [2]uint32{_CTL_HW, _HW_NCPU}
	out := uint32(0)
	nout := unsafe.Sizeof(out)
	ret := sysctl(&mib[0], 2, (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	if ret >= 0 && int32(out) > 0 {
		return int32(out)
	}
	return 1
}

func getPageSize() uintptr {
	// Use sysctl to fetch hw.pagesize.
	mib := [2]uint32{_CTL_HW, _HW_PAGESIZE}
	out := uint32(0)
	nout := unsafe.Sizeof(out)
	ret := sysctl(&mib[0], 2, (*byte)(unsafe.Pointer(&out)), &nout, nil, 0)
	if ret >= 0 && int32(out) > 0 {
		return uintptr(out)
	}
	return 0
}

//go:nosplit
func readRandom(r []byte) int {
	arc4random_buf(unsafe.Pointer(&r[0]), int32(len(r)))
	return len(r)
}

func goenvs() {
	goenvs_unix()
}

// May run with m.p==nil, so write barriers are not allowed.
//
//go:nowritebarrierrec
func newosproc(mp *m) {
	stk := unsafe.Pointer(mp.g0.stack.hi)
	if false {
		print("newosproc stk=", stk, " m=", mp, " g=", mp.g0, " id=", mp.id, " ostk=", &mp, "\n")
	}

	// Initialize an attribute object.
	var attr pthreadattr
	var err int32
	err = pthread_attr_init(&attr)
	if err != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	// Find out OS stack size for our own stack guard.
	var stacksize uintptr
	if pthread_attr_getstacksize(&attr, &stacksize) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}
	mp.g0.stack.hi = stacksize // for mstart

	// Tell the pthread library we won't join with this thread.
	if pthread_attr_setdetachstate(&attr, _PTHREAD_CREATE_DETACHED) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	// Finally, create the thread. It starts at mstart_stub, which does some low-level
	// setup and then calls mstart.
	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	err = retryOnEAGAIN(func() int32 {
		return pthread_create(&attr, abi.FuncPCABI0(mstart_stub), unsafe.Pointer(mp))
	})
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if err != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}
}

// glue code to call mstart from pthread_create.
func mstart_stub()

// newosproc0 is a version of newosproc that can be called before the runtime
// is initialized.
//
// This function is not safe to use after initialization as it does not pass an M as fnarg.
//
//go:nosplit
func newosproc0(stacksize uintptr, fn uintptr) {
	// Initialize an attribute object.
	var attr pthreadattr
	var err int32
	err = pthread_attr_init(&attr)
	if err != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	// The caller passes in a suggested stack size,
	// from when we allocated the stack and thread ourselves,
	// without libpthread. Now that we're using libpthread,
	// we use the OS default stack size instead of the suggestion.
	// Find out that stack size for our own stack guard.
	if pthread_attr_getstacksize(&attr, &stacksize) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}
	g0.stack.hi = stacksize // for mstart
	memstats.stacks_sys.add(int64(stacksize))

	// Tell the pthread library we won't join with this thread.
	if pthread_attr_setdetachstate(&attr, _PTHREAD_CREATE_DETACHED) != 0 {
		writeErrStr(failthreadcreate)
		exit(1)
	}

	// Finally, create the thread. It starts at mstart_stub, which does some low-level
	// setup and then calls mstart.
	var oset sigset
	sigprocmask(_SIG_SETMASK, &sigset_all, &oset)
	err = pthread_create(&attr, fn, nil)
	sigprocmask(_SIG_SETMASK, &oset, nil)
	if err != 0 {
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

// Called to initialize a new m (including the bootstrap m).
// Called on the parent thread (main thread in case of bootstrap), can allocate memory.
func mpreinit(mp *m) {
	mp.gsignal = malg(32 * 1024) // OS X wants >= 8K
	mp.gsignal.m = mp
	if GOOS == "darwin" && GOARCH == "arm64" {
		// mlock the signal stack to work around a kernel bug where it may
		// SIGILL when the signal stack is not faulted in while a signal
		// arrives. See issue 42774.
		mlock(unsafe.Pointer(mp.gsignal.stack.hi-physPageSize), physPageSize)
	}
}

// Called to initialize a new m (including the bootstrap m).
// Called on the new thread, cannot allocate memory.
func minit() {
	// iOS does not support alternate signal stack.
	// The signal handler handles it directly.
	if !(GOOS == "ios" && GOARCH == "arm64") {
		minitSignalStack()
	}
	minitSignalMask()
	getg().m.procid = uint64(pthread_self())
}

// Called from dropm to undo the effect of an minit.
//
//go:nosplit
func unminit() {
	// iOS does not support alternate signal stack.
	// See minit.
	if !(GOOS == "ios" && GOARCH == "arm64") {
		unminitSignals()
	}
	getg().m.procid = 0
}

// Called from exitm, but not from drop, to undo the effect of thread-owned
// resources in minit, semacreate, or elsewhere. Do not take locks after calling this.
func mdestroy(mp *m) {
}

//go:nosplit
func osyield_no_g() {
	usleep_no_g(1)
}

//go:nosplit
func osyield() {
	usleep(1)
}

const (
	_NSIG        = 32
	_SI_USER     = 0 /* empirically true, but not what headers say */
	_SIG_BLOCK   = 1
	_SIG_UNBLOCK = 2
	_SIG_SETMASK = 3
	_SS_DISABLE  = 4
)

//extern SigTabTT runtime·sigtab[];

type sigset uint32

var sigset_all = ^sigset(0)

//go:nosplit
//go:nowritebarrierrec
func setsig(i uint32, fn uintptr) {
	var sa usigactiont
	sa.sa_flags = _SA_SIGINFO | _SA_ONSTACK | _SA_RESTART
	sa.sa_mask = ^uint32(0)
	if fn == abi.FuncPCABIInternal(sighandler) { // abi.FuncPCABIInternal(sighandler) matches the callers in signal_unix.go
		if iscgo {
			fn = abi.FuncPCABI0(cgoSigtramp)
		} else {
			fn = abi.FuncPCABI0(sigtramp)
		}
	}
	*(*uintptr)(unsafe.Pointer(&sa.__sigaction_u)) = fn
	sigaction(i, &sa, nil)
}

// sigtramp is the callback from libc when a signal is received.
// It is called with the C calling convention.
func sigtramp()
func cgoSigtramp()

//go:nosplit
//go:nowritebarrierrec
func setsigstack(i uint32) {
	var osa usigactiont
	sigaction(i, nil, &osa)
	handler := *(*uintptr)(unsafe.Pointer(&osa.__sigaction_u))
	if osa.sa_flags&_SA_ONSTACK != 0 {
		return
	}
	var sa usigactiont
	*(*uintptr)(unsafe.Pointer(&sa.__sigaction_u)) = handler
	sa.sa_mask = osa.sa_mask
	sa.sa_flags = osa.sa_flags | _SA_ONSTACK
	sigaction(i, &sa, nil)
}

//go:nosplit
//go:nowritebarrierrec
func getsig(i uint32) uintptr {
	var sa usigactiont
	sigaction(i, nil, &sa)
	return *(*uintptr)(unsafe.Pointer(&sa.__sigaction_u))
}

// setSignalstackSP sets the ss_sp field of a stackt.
//
//go:nosplit
func setSignalstackSP(s *stackt, sp uintptr) {
	*(*uintptr)(unsafe.Pointer(&s.ss_sp)) = sp
}

//go:nosplit
//go:nowritebarrierrec
func sigaddset(mask *sigset, i int) {
	*mask |= 1 << (uint32(i) - 1)
}

func sigdelset(mask *sigset, i int) {
	*mask &^= 1 << (uint32(i) - 1)
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

//go:linkname executablePath os.executablePath
var executablePath string

func sysargs(argc int32, argv **byte) {
	// skip over argv, envv and the first string will be the path
	n := argc + 1
	for argv_index(argv, n) != nil {
		n++
	}
	executablePath = gostringnocopy(argv_index(argv, n+1))

	// strip "executable_path=" prefix if available, it's added after OS X 10.11.
	executablePath = stringslite.TrimPrefix(executablePath, "executable_path=")
}

func signalM(mp *m, sig int) {
	pthread_kill(pthread(mp.procid), uint32(sig))
}

// sigPerThreadSyscall is only used on linux, so we assign a bogus signal
// number.
const sigPerThreadSyscall = 1 << 31

//go:nosplit
func runPerThreadSyscall() {
	throw("runPerThreadSyscall only valid on linux")
}
```