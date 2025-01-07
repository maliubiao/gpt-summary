Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Recognition:**

The first thing I do is a quick scan looking for recognizable Go runtime related terms and Windows API calls. I see:

* `runtime`: This immediately tells me it's part of the core Go runtime, dealing with low-level operations.
* `os_windows.go`:  Confirms it's platform-specific, interacting with the Windows operating system.
* `stdcall`, `stdcall0`, `stdcallN`: These strongly suggest interactions with Windows DLLs using the `stdcall` calling convention.
* Windows API names like `_SwitchToThread`, `_WaitForSingleObject`, `_SetWaitableTimer`, `_GetThreadContext`, `_SuspendThread`, `_ResumeThread`, `_DuplicateHandle`, `_CloseHandle`, `_SetThreadPriority`, `_CreateWaitableTimerA`.
* Go runtime structures like `m` (machine/OS thread), `g` (goroutine), `context`, `mutex`.
* Concepts like profiling, preemption, signals (`_SIGINT`, `_SIGTERM`).

**2. Function Grouping and Purpose Identification (High-Level):**

Based on the keywords and API calls, I start grouping functions and inferring their general purpose:

* **`stdcall*` functions:** These are clearly wrappers for calling Windows API functions. The suffixes (0, 1, 2, ..., 8) likely indicate the number of arguments. The `//go:nosplit` and `//go:cgo_unsafe_args` hints at low-level, potentially stack-sensitive operations.
* **`osyield*` functions:** These relate to yielding the current OS thread. The `_no_g` variant suggests it can be called without a running goroutine. It probably calls `_SwitchToThread`.
* **`usleep*` functions:** These seem to implement pausing or sleeping for a specified duration. They use `_WaitForSingleObject` and potentially high-resolution timers (`_SetWaitableTimer`).
* **`ctrlHandler`:** This looks like a signal handler for Windows events like Ctrl+C, close, etc. It maps these to Go signals (`_SIGINT`, `_SIGTERM`) and uses `sigsend`.
* **`profilem`, `gFromSP`, `profileLoop`, `setProcessCPUProfiler`, `setThreadCPUProfiler`:** This whole block is clearly related to CPU profiling. It involves getting thread contexts, potentially suspending/resuming threads, and using timers.
* **`preemptM`, `osPreemptExtEnter`, `osPreemptExtExit`:** These functions appear to be about forcing a goroutine to stop its current execution (preemption). The `Ext` variants likely handle situations where Go code is calling out to external (non-Go) code.

**3. Deeper Dive into Function Groups (More Detail):**

Now, I examine the implementation details within each group:

* **`stdcall*`:** Notice the manipulation of `mp.libcall`. This suggests a mechanism for managing arguments and calling the API. The `unsafe.Pointer` usage highlights the low-level nature.
* **`osyield*`:**  The `systemstack` call in `osyield` is important; it ensures the function runs on a dedicated system stack, avoiding potential stack overflows in user goroutines.
* **`usleep*`:** The logic for using high-resolution timers or falling back to lower-resolution ones is interesting. The conversion of microseconds to milliseconds is key.
* **`ctrlHandler`:** The `block()` call after receiving a `_SIGTERM` is crucial for allowing signal handlers to clean up before the process exits.
* **Profiling:** The use of `_GetThreadContext` to get register values (IP, SP, LR) is standard for profilers. The loop in `profileLoop` iterates through all running OS threads managed by Go (`allm`). The synchronization using `mutex` (`threadLock`, `suspendLock`) is critical to avoid race conditions. The `_DuplicateHandle` call shows the need to obtain a valid handle to other threads.
* **Preemption:** The `preemptM` function is complex. The use of `_SuspendThread` and `_ResumeThread` is expected. The logic around `preemptExtLock` and checking for safe points (`isAsyncSafePoint`) shows careful handling of concurrency and ensuring that preemption happens at a safe moment. The code that modifies the thread's context (stack pointer, instruction pointer, link register) to inject the `asyncPreempt` function is the core of how the preemption is achieved. The different code paths for different architectures (386, amd64, arm, arm64) highlight the platform-specific nature of this operation.

**4. Inferring Go Features:**

Based on the function analysis, I can infer the Go features being implemented:

* **System Calls:** The `stdcall*` functions directly implement the ability for Go programs to make system calls to the Windows API.
* **Goroutine Scheduling:** The `osyield` and `usleep` functions are fundamental to the Go scheduler, allowing goroutines to voluntarily give up CPU time or wait for a period.
* **Signal Handling:** The `ctrlHandler` implements Go's signal handling mechanism on Windows, allowing Go programs to respond to events like Ctrl+C.
* **CPU Profiling:** The profiling functions enable the `go tool pprof` to collect CPU usage data, helping developers identify performance bottlenecks.
* **Goroutine Preemption:** The `preemptM` functions implement the ability for the Go runtime to forcibly interrupt a running goroutine, ensuring fairness and responsiveness. This is essential for preventing a single long-running goroutine from starving others.

**5. Code Examples and Reasoning (If applicable):**

For functions like `usleep`, it's straightforward to provide an example of `time.Sleep`. For preemption, it's harder to directly demonstrate the low-level mechanisms in user code, but one can illustrate the *effect* of preemption (e.g., a long-running loop not blocking other goroutines).

**6. Command-Line Arguments and Error Handling (If applicable):**

I didn't see specific command-line argument handling in this snippet. Error handling is mostly done via `print` and `throw`, which are runtime-level error reporting mechanisms.

**7. Common Mistakes (If applicable):**

The analysis of locking mechanisms in `preemptM` suggests potential pitfalls if developers were to try implementing similar low-level thread manipulation without careful synchronization. However, this code is internal to the Go runtime, so direct user errors are less likely. Perhaps misunderstandings about the precision of `time.Sleep` due to the underlying Windows timer resolution could be a point.

**8. Structure and Refine the Answer:**

Finally, I organize the information logically, starting with a general overview, then detailing each functional area, providing code examples, and addressing potential issues. I use clear, concise language and avoid overly technical jargon where possible, aiming for understanding by someone familiar with Go but perhaps not deeply familiar with its runtime internals. The "归纳一下它的功能" (summarize its functionality) is addressed in the final concluding paragraph.
这段代码是 `go/src/runtime/os_windows.go` 的一部分，主要负责 **Go 语言在 Windows 平台上的操作系统接口实现**。它是 Go 语言运行时环境与 Windows 系统内核进行交互的关键部分。

以下是这段代码功能的详细列举和推理：

**1. `stdcall` 系列函数 ( `stdcall`, `stdcall0` - `stdcall8` )**:

* **功能:**  封装了 Windows API 的标准调用约定 (`stdcall`)。它们负责将 Go 的参数转换为 Windows API 调用所需的格式，并执行实际的 API 调用。
* **推理:** Windows API 函数通常使用 `stdcall` 调用约定，这意味着参数从右向左压入栈，并且被调用者负责清理栈。这些函数提供了一个类型安全的方式来调用这些 API，避免了直接使用 `syscall` 包的潜在风险。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "syscall"
       "unsafe"
   )

   //go:linkname procexit os.procexit
   func procexit(code int)

   func main() {
       // 假设 _ExitProcess 是 Windows API 中的 ExitProcess 函数的地址
       // 实际上 Go 运行时会处理这些地址
       var _ExitProcess uintptr = 0x7FFE0390 // 这只是一个占位符，实际地址会变

       // 使用 stdcall0 封装的 ExitProcess (Go 运行时内部可能会有类似的封装)
       // 假设 stdcall0 的定义与代码片段中的类似
       type stdFunction uintptr
       // func stdcall0(fn stdFunction) uintptr // 假设的 stdcall0 定义

       exitCode := 123
       // 模拟调用 stdcall0(_ExitProcess, uintptr(exitCode))
       // 在实际的 Go 运行时中，会使用更安全的方式调用
       fmt.Println("Attempting to exit with code:", exitCode)
       procexit(exitCode) // 实际上 Go 会使用内部机制调用 ExitProcess
       fmt.Println("This should not be printed")
   }
   ```
   **假设的输入与输出:**  如果程序成功调用了 `ExitProcess`，那么输出将会是 "Attempting to exit with code: 123"，并且程序会立即终止，不会打印 "This should not be printed"。

**2. `osyield_no_g` 和 `osyield`**:

* **功能:**  使当前操作系统线程放弃 CPU 时间片，让其他线程有机会运行。
* **推理:**  `_SwitchToThread` 是 Windows API 中用于线程切换的函数。`osyield_no_g` 是在没有关联的 Go 协程 (`g`) 的情况下调用的，例如在运行时环境的某些低级操作中。 `osyield` 则会在系统栈上调用 `_SwitchToThread`，确保在 Go 协程的上下文中安全执行。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "runtime"
       "time"
   )

   func task1() {
       for i := 0; i < 5; i++ {
           fmt.Println("Task 1:", i)
           runtime.Gosched() // 让出 CPU，允许其他 Goroutine 运行
       }
   }

   func task2() {
       for i := 0; i < 5; i++ {
           fmt.Println("Task 2:", i)
           time.Sleep(time.Millisecond * 10) // 模拟耗时操作，可能导致线程切换
       }
   }

   func main() {
       go task1()
       go task2()

       time.Sleep(time.Second)
   }
   ```
   **假设的输入与输出:**  程序会交替输出 "Task 1: ..." 和 "Task 2: ..."，尽管 `task2` 中有 `time.Sleep`，`runtime.Gosched()` 也允许 `task2` 获取运行机会。这展示了 Go 调度器如何利用底层的线程切换机制。

**3. `usleep_no_g` 和 `usleep`**:

* **功能:**  使当前操作系统线程休眠指定的微秒数。
* **推理:** `_WaitForSingleObject` 是一个等待内核对象的函数。在这里，它被用来等待一个无效的句柄 (`_INVALID_HANDLE_VALUE`) 达到超时时间，从而实现休眠。`usleep` 考虑了高精度定时器 (`_SetWaitableTimer`) 的使用，如果可用，可以提供更精确的休眠。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "runtime"
       "time"
   )

   func main() {
       start := time.Now()
       runtime.Gosched() // 先让出 CPU
       time.Sleep(time.Millisecond * 100) // 使用 Go 的 sleep
       elapsed := time.Since(start)
       fmt.Println("Slept for:", elapsed)
   }
   ```
   **假设的输入与输出:** 程序会输出 "Slept for: 100.xxxxxxms" 左右，展示了 Go 的 `time.Sleep` 如何调用底层的休眠机制。

**4. `ctrlHandler`**:

* **功能:**  处理 Windows 控制台事件，例如 Ctrl+C、Ctrl+Break、窗口关闭等，并将它们转换为 Go 的信号。
* **推理:**  当用户在控制台中按下 Ctrl+C 等组合键时，Windows 会触发相应的事件。`ctrlHandler` 函数会被调用，根据事件类型发送相应的 Go 信号 (例如 `_SIGINT` 对应 Ctrl+C，`_SIGTERM` 对应关闭事件)。对于 `_SIGTERM`，它会调用 `block()`，阻止进程退出，以便信号处理程序有时间清理。
* **Go 代码示例:**
   ```go
   package main

   import (
       "fmt"
       "os"
       "os/signal"
       "syscall"
   )

   func main() {
       sigs := make(chan os.Signal, 1)
       signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

       done := make(chan bool, 1)

       go func() {
           sig := <-sigs
           fmt.Println("Received signal:", sig)
           // 执行清理操作
           fmt.Println("Cleaning up...")
           done <- true
       }()

       fmt.Println("Press Ctrl+C to trigger signal.")
       <-done // 等待信号处理完成
       fmt.Println("Exiting.")
   }
   ```
   **假设的输入与输出:** 当在控制台中运行此程序并按下 Ctrl+C 时，会输出 "Received signal: interrupt"，然后输出 "Cleaning up..." 和 "Exiting."。

**5. `profilem`, `gFromSP`, `profileLoop`, `setProcessCPUProfiler`, `setThreadCPUProfiler`**:

* **功能:**  实现 Go 程序的 CPU 性能分析功能 (profiling)。
* **推理:** 这部分代码使用 Windows API 来获取线程的上下文信息 (`_GetThreadContext`)，包括指令指针 (IP)、栈指针 (SP) 和链接寄存器 (LR)。`profilem` 函数根据这些信息调用 `sigprof`，将采样数据传递给 Go 的 profiling 机制。 `profileLoop` 是一个后台循环，定期采样所有 Go 管理的线程。 `setProcessCPUProfiler` 和 `setThreadCPUProfiler` 用于设置 profiling 的频率。
* **Go 代码示例:**  Go 的 profiling 通常通过命令行工具 `go tool pprof` 来使用，需要在运行的程序中引入 `net/http/pprof` 或使用 `-blockprofile`, `-cpuprofile`, `-memprofile` 等标志运行程序。
   ```bash
   go run main.go
   # 在另一个终端
   go tool pprof http://localhost:<port>/debug/pprof/profile
   ```
   **命令行参数:**  虽然代码本身没有处理命令行参数，但 Go 的 profiling 功能依赖于一些环境变量或 `go test` 的标志，例如 `GOTRACE`, `GODEBUG` 等可能影响 profiling 的行为。

**6. `preemptM`, `osPreemptExtEnter`, `osPreemptExtExit`**:

* **功能:**  实现 Go 协程的抢占式调度。
* **推理:** `preemptM` 函数尝试中断 (抢占) 正在运行在指定操作系统线程 (`m`) 上的 Go 协程。它使用 `_SuspendThread` 暂停线程，获取线程上下文，判断是否可以安全地进行抢占，并在安全点注入一个调用 `asyncPreempt` 的指令。 `osPreemptExtEnter` 和 `osPreemptExtExit` 用于在 Go 代码调用外部 (非 Go) 代码时同步抢占操作，避免潜在的死锁。
* **Go 代码示例:**  抢占式调度是 Go 运行时自动管理的，用户代码通常不需要显式调用这些函数。其效果体现在即使有长时间运行的 Goroutine，其他 Goroutine 也能获得执行机会，保持程序的响应性。
   ```go
   package main

   import (
       "fmt"
       "runtime"
       "time"
   )

   func longRunningTask() {
       for {
           // 模拟长时间运行
       }
   }

   func main() {
       runtime.GOMAXPROCS(1) // 为了更容易观察抢占效果
       go longRunningTask()

       for i := 0; i < 10; i++ {
           fmt.Println("Main goroutine:", i)
           time.Sleep(time.Millisecond * 100)
       }
   }
   ```
   **假设的输入与输出:**  即使 `longRunningTask` 进入无限循环，主 Goroutine 仍然能够执行并打印 "Main goroutine: ..."，这归功于 Go 的抢占式调度。

**使用者易犯错的点:**

* **直接调用 `stdcall` 系列函数:**  普通 Go 开发者不应该直接调用这些底层函数，因为它们是运行时内部使用的，并且需要对 Windows API 有深入的了解。不当使用可能导致程序崩溃或出现未定义的行为。
* **对 `usleep` 的精度期望过高:**  虽然代码尝试使用高精度定时器，但 Windows 的定时器精度受到多种因素的影响，实际的休眠时间可能与期望值略有偏差。
* **不理解抢占式调度的原理:**  虽然 Go 自动处理抢占，但理解其原理有助于理解 Go 程序的并发行为。

**总结这段代码的功能:**

这段代码是 Go 语言在 Windows 平台上实现操作系统接口的关键组成部分。它提供了以下核心功能：

* **调用 Windows API:** 通过 `stdcall` 系列函数，使得 Go 运行时可以安全地调用 Windows 系统调用。
* **线程控制:** 提供了线程让步 (`osyield`) 和休眠 (`usleep`) 的能力。
* **信号处理:**  能够捕获和处理 Windows 控制台事件，并将其转换为 Go 的信号。
* **CPU 性能分析:**  实现了 Go 程序的 CPU profiling 功能，用于性能诊断。
* **抢占式调度:**  支持 Go 协程的抢占式调度，保证程序的并发性和响应性。

总而言之，这段代码是 Go 运行时在 Windows 平台上运行的基础，它连接了 Go 的抽象并发模型和 Windows 的底层操作系统机制。

Prompt: 
```
这是路径为go/src/runtime/os_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
n = 7
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

//go:nosplit
//go:cgo_unsafe_args
func stdcall8(fn stdFunction, a0, a1, a2, a3, a4, a5, a6, a7 uintptr) uintptr {
	mp := getg().m
	mp.libcall.n = 8
	mp.libcall.args = uintptr(noescape(unsafe.Pointer(&a0)))
	return stdcall(fn)
}

// These must run on the system stack only.

//go:nosplit
func osyield_no_g() {
	stdcall_no_g(_SwitchToThread, 0, 0)
}

//go:nosplit
func osyield() {
	systemstack(func() {
		stdcall0(_SwitchToThread)
	})
}

//go:nosplit
func usleep_no_g(us uint32) {
	timeout := uintptr(us) / 1000 // ms units
	args := [...]uintptr{_INVALID_HANDLE_VALUE, timeout}
	stdcall_no_g(_WaitForSingleObject, len(args), uintptr(noescape(unsafe.Pointer(&args[0]))))
}

//go:nosplit
func usleep(us uint32) {
	systemstack(func() {
		var h, timeout uintptr
		// If the high-res timer is available and its handle has been allocated for this m, use it.
		// Otherwise fall back to the low-res one, which doesn't need a handle.
		if haveHighResTimer && getg().m.highResTimer != 0 {
			h = getg().m.highResTimer
			dt := -10 * int64(us) // relative sleep (negative), 100ns units
			stdcall6(_SetWaitableTimer, h, uintptr(unsafe.Pointer(&dt)), 0, 0, 0, 0)
			timeout = _INFINITE
		} else {
			h = _INVALID_HANDLE_VALUE
			timeout = uintptr(us) / 1000 // ms units
		}
		stdcall2(_WaitForSingleObject, h, timeout)
	})
}

func ctrlHandler(_type uint32) uintptr {
	var s uint32

	switch _type {
	case _CTRL_C_EVENT, _CTRL_BREAK_EVENT:
		s = _SIGINT
	case _CTRL_CLOSE_EVENT, _CTRL_LOGOFF_EVENT, _CTRL_SHUTDOWN_EVENT:
		s = _SIGTERM
	default:
		return 0
	}

	if sigsend(s) {
		if s == _SIGTERM {
			// Windows terminates the process after this handler returns.
			// Block indefinitely to give signal handlers a chance to clean up,
			// but make sure to be properly parked first, so the rest of the
			// program can continue executing.
			block()
		}
		return 1
	}
	return 0
}

// called from zcallback_windows_*.s to sys_windows_*.s
func callbackasm1()

var profiletimer uintptr

func profilem(mp *m, thread uintptr) {
	// Align Context to 16 bytes.
	var c *context
	var cbuf [unsafe.Sizeof(*c) + 15]byte
	c = (*context)(unsafe.Pointer((uintptr(unsafe.Pointer(&cbuf[15]))) &^ 15))

	c.contextflags = _CONTEXT_CONTROL
	stdcall2(_GetThreadContext, thread, uintptr(unsafe.Pointer(c)))

	gp := gFromSP(mp, c.sp())

	sigprof(c.ip(), c.sp(), c.lr(), gp, mp)
}

func gFromSP(mp *m, sp uintptr) *g {
	if gp := mp.g0; gp != nil && gp.stack.lo < sp && sp < gp.stack.hi {
		return gp
	}
	if gp := mp.gsignal; gp != nil && gp.stack.lo < sp && sp < gp.stack.hi {
		return gp
	}
	if gp := mp.curg; gp != nil && gp.stack.lo < sp && sp < gp.stack.hi {
		return gp
	}
	return nil
}

func profileLoop() {
	stdcall2(_SetThreadPriority, currentThread, _THREAD_PRIORITY_HIGHEST)

	for {
		stdcall2(_WaitForSingleObject, profiletimer, _INFINITE)
		first := (*m)(atomic.Loadp(unsafe.Pointer(&allm)))
		for mp := first; mp != nil; mp = mp.alllink {
			if mp == getg().m {
				// Don't profile ourselves.
				continue
			}

			lock(&mp.threadLock)
			// Do not profile threads blocked on Notes,
			// this includes idle worker threads,
			// idle timer thread, idle heap scavenger, etc.
			if mp.thread == 0 || mp.profilehz == 0 || mp.blocked {
				unlock(&mp.threadLock)
				continue
			}
			// Acquire our own handle to the thread.
			var thread uintptr
			if stdcall7(_DuplicateHandle, currentProcess, mp.thread, currentProcess, uintptr(unsafe.Pointer(&thread)), 0, 0, _DUPLICATE_SAME_ACCESS) == 0 {
				print("runtime: duplicatehandle failed; errno=", getlasterror(), "\n")
				throw("duplicatehandle failed")
			}
			unlock(&mp.threadLock)

			// mp may exit between the DuplicateHandle
			// above and the SuspendThread. The handle
			// will remain valid, but SuspendThread may
			// fail.
			if int32(stdcall1(_SuspendThread, thread)) == -1 {
				// The thread no longer exists.
				stdcall1(_CloseHandle, thread)
				continue
			}
			if mp.profilehz != 0 && !mp.blocked {
				// Pass the thread handle in case mp
				// was in the process of shutting down.
				profilem(mp, thread)
			}
			stdcall1(_ResumeThread, thread)
			stdcall1(_CloseHandle, thread)
		}
	}
}

func setProcessCPUProfiler(hz int32) {
	if profiletimer == 0 {
		var timer uintptr
		if haveHighResTimer {
			timer = createHighResTimer()
		} else {
			timer = stdcall3(_CreateWaitableTimerA, 0, 0, 0)
		}
		atomic.Storeuintptr(&profiletimer, timer)
		newm(profileLoop, nil, -1)
	}
}

func setThreadCPUProfiler(hz int32) {
	ms := int32(0)
	due := ^int64(^uint64(1 << 63))
	if hz > 0 {
		ms = 1000 / hz
		if ms == 0 {
			ms = 1
		}
		due = int64(ms) * -10000
	}
	stdcall6(_SetWaitableTimer, profiletimer, uintptr(unsafe.Pointer(&due)), uintptr(ms), 0, 0, 0)
	atomic.Store((*uint32)(unsafe.Pointer(&getg().m.profilehz)), uint32(hz))
}

const preemptMSupported = true

// suspendLock protects simultaneous SuspendThread operations from
// suspending each other.
var suspendLock mutex

func preemptM(mp *m) {
	if mp == getg().m {
		throw("self-preempt")
	}

	// Synchronize with external code that may try to ExitProcess.
	if !atomic.Cas(&mp.preemptExtLock, 0, 1) {
		// External code is running. Fail the preemption
		// attempt.
		mp.preemptGen.Add(1)
		return
	}

	// Acquire our own handle to mp's thread.
	lock(&mp.threadLock)
	if mp.thread == 0 {
		// The M hasn't been minit'd yet (or was just unminit'd).
		unlock(&mp.threadLock)
		atomic.Store(&mp.preemptExtLock, 0)
		mp.preemptGen.Add(1)
		return
	}
	var thread uintptr
	if stdcall7(_DuplicateHandle, currentProcess, mp.thread, currentProcess, uintptr(unsafe.Pointer(&thread)), 0, 0, _DUPLICATE_SAME_ACCESS) == 0 {
		print("runtime.preemptM: duplicatehandle failed; errno=", getlasterror(), "\n")
		throw("runtime.preemptM: duplicatehandle failed")
	}
	unlock(&mp.threadLock)

	// Prepare thread context buffer. This must be aligned to 16 bytes.
	var c *context
	var cbuf [unsafe.Sizeof(*c) + 15]byte
	c = (*context)(unsafe.Pointer((uintptr(unsafe.Pointer(&cbuf[15]))) &^ 15))
	c.contextflags = _CONTEXT_CONTROL

	// Serialize thread suspension. SuspendThread is asynchronous,
	// so it's otherwise possible for two threads to suspend each
	// other and deadlock. We must hold this lock until after
	// GetThreadContext, since that blocks until the thread is
	// actually suspended.
	lock(&suspendLock)

	// Suspend the thread.
	if int32(stdcall1(_SuspendThread, thread)) == -1 {
		unlock(&suspendLock)
		stdcall1(_CloseHandle, thread)
		atomic.Store(&mp.preemptExtLock, 0)
		// The thread no longer exists. This shouldn't be
		// possible, but just acknowledge the request.
		mp.preemptGen.Add(1)
		return
	}

	// We have to be very careful between this point and once
	// we've shown mp is at an async safe-point. This is like a
	// signal handler in the sense that mp could have been doing
	// anything when we stopped it, including holding arbitrary
	// locks.

	// We have to get the thread context before inspecting the M
	// because SuspendThread only requests a suspend.
	// GetThreadContext actually blocks until it's suspended.
	stdcall2(_GetThreadContext, thread, uintptr(unsafe.Pointer(c)))

	unlock(&suspendLock)

	// Does it want a preemption and is it safe to preempt?
	gp := gFromSP(mp, c.sp())
	if gp != nil && wantAsyncPreempt(gp) {
		if ok, newpc := isAsyncSafePoint(gp, c.ip(), c.sp(), c.lr()); ok {
			// Inject call to asyncPreempt
			targetPC := abi.FuncPCABI0(asyncPreempt)
			switch GOARCH {
			default:
				throw("unsupported architecture")
			case "386", "amd64":
				// Make it look like the thread called targetPC.
				sp := c.sp()
				sp -= goarch.PtrSize
				*(*uintptr)(unsafe.Pointer(sp)) = newpc
				c.set_sp(sp)
				c.set_ip(targetPC)

			case "arm":
				// Push LR. The injected call is responsible
				// for restoring LR. gentraceback is aware of
				// this extra slot. See sigctxt.pushCall in
				// signal_arm.go, which is similar except we
				// subtract 1 from IP here.
				sp := c.sp()
				sp -= goarch.PtrSize
				c.set_sp(sp)
				*(*uint32)(unsafe.Pointer(sp)) = uint32(c.lr())
				c.set_lr(newpc - 1)
				c.set_ip(targetPC)

			case "arm64":
				// Push LR. The injected call is responsible
				// for restoring LR. gentraceback is aware of
				// this extra slot. See sigctxt.pushCall in
				// signal_arm64.go.
				sp := c.sp() - 16 // SP needs 16-byte alignment
				c.set_sp(sp)
				*(*uint64)(unsafe.Pointer(sp)) = uint64(c.lr())
				c.set_lr(newpc)
				c.set_ip(targetPC)
			}
			stdcall2(_SetThreadContext, thread, uintptr(unsafe.Pointer(c)))
		}
	}

	atomic.Store(&mp.preemptExtLock, 0)

	// Acknowledge the preemption.
	mp.preemptGen.Add(1)

	stdcall1(_ResumeThread, thread)
	stdcall1(_CloseHandle, thread)
}

// osPreemptExtEnter is called before entering external code that may
// call ExitProcess.
//
// This must be nosplit because it may be called from a syscall with
// untyped stack slots, so the stack must not be grown or scanned.
//
//go:nosplit
func osPreemptExtEnter(mp *m) {
	for !atomic.Cas(&mp.preemptExtLock, 0, 1) {
		// An asynchronous preemption is in progress. It's not
		// safe to enter external code because it may call
		// ExitProcess and deadlock with SuspendThread.
		// Ideally we would do the preemption ourselves, but
		// can't since there may be untyped syscall arguments
		// on the stack. Instead, just wait and encourage the
		// SuspendThread APC to run. The preemption should be
		// done shortly.
		osyield()
	}
	// Asynchronous preemption is now blocked.
}

// osPreemptExtExit is called after returning from external code that
// may call ExitProcess.
//
// See osPreemptExtEnter for why this is nosplit.
//
//go:nosplit
func osPreemptExtExit(mp *m) {
	atomic.Store(&mp.preemptExtLock, 0)
}

"""




```