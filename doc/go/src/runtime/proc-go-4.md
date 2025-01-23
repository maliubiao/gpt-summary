Response:
My thought process for summarizing the provided Go code snippet went something like this:

1. **Identify the Core Functionality:** I first scanned the code for recurring keywords and function names. Terms like `syscall`, `entersyscall`, `exitsyscall`, `LockOSThread`, `UnlockOSThread`, `newproc`, `gfree`, and `sigprof` jumped out. This immediately suggested the code deals with system calls, thread locking, goroutine creation/management, and profiling.

2. **Group Related Functions:**  I then started grouping functions based on their prefixes and apparent purpose:
    * `entersyscall...` and `exitsyscall...`: Clearly related to entering and exiting system calls.
    * `LockOSThread`, `UnlockOSThread`, `lockOSThread`, `unlockOSThread`, `dolockOSThread`, `dounlockOSThread`:  Obviously related to managing OS thread locking for goroutines.
    * `newproc`, `newproc1`, `malg`, `gfget`, `gfput`, `gfpurge`: Related to goroutine creation and management of a free list of goroutines (`g`).
    * `syscall_runtime_BeforeFork`, `syscall_runtime_AfterFork`, `syscall_runtime_AfterForkInChild`, `syscall_runtime_BeforeExec`, `syscall_runtime_AfterExec`: Handlers for specific points during the `fork` and `exec` system calls.
    * `save`:  A utility for saving goroutine context.
    * `sigprof`: A signal handler related to profiling.

3. **Analyze Individual Function Groups:**  I then delved deeper into each group:

    * **System Calls:** The `entersyscall` functions handle the transition of a goroutine into a system call, saving its state and potentially handling preemption or GC coordination. The `exitsyscall` functions handle the return from a system call, trying to reacquire a processor, and potentially putting the goroutine back on the run queue. I noted the distinction between fast and slow paths for exiting system calls.

    * **OS Thread Locking:**  The `LockOSThread` and `UnlockOSThread` family manages the binding of a Go goroutine to a specific OS thread. This is important for interacting with external code that relies on thread-local state. I recognized the need for matching lock/unlock calls.

    * **Goroutine Creation/Management:**  `newproc` and `newproc1` are responsible for creating new goroutines. The `gfget` and `gfput` functions manage a free list of `g` structures to reduce allocation overhead. I saw the logic for stack management and reuse.

    * **Fork/Exec Handlers:**  These functions are crucial for ensuring the integrity of the Go runtime when the `fork` and `exec` system calls are used. They handle signal blocking and stack guard manipulation in the parent and child processes.

    * **`save`:** This is a low-level utility for capturing the program counter, stack pointer, and base pointer of a goroutine, essential for context switching and debugging. The `go:nosplit` and `go:nowritebarrierrec` directives indicated its critical nature.

    * **`sigprof`:** This is the signal handler for profiling, noting its limitations during certain atomic operations.

4. **Identify Key Concepts and Data Structures:**  As I analyzed, I identified key concepts like:
    * **`g`:** Represents a goroutine.
    * **`m`:** Represents an OS thread.
    * **`p`:** Represents a processor, a context for executing goroutines.
    * **`sched`:** The scheduler.
    * **`stack`:**  The goroutine's stack.
    * **System calls:** Interactions with the operating system kernel.
    * **Preemption:**  Interrupting a running goroutine.
    * **Garbage collection (GC):**  Automatic memory management.
    * **Tracing:**  Mechanism for observing the execution of the runtime.
    * **Profiling:**  Collecting performance data.

5. **Synthesize a Summary:** Finally, I combined my understanding into a concise summary, focusing on the major responsibilities of the code: managing goroutine lifecycle (creation, scheduling, system calls), OS thread management, and support for `fork`/`exec` and profiling. I made sure to emphasize the core theme of interaction between the Go runtime and the underlying operating system.

Essentially, I approached it like reverse-engineering a well-documented system. I looked for the components, understood their individual functions, and then described how they fit together to achieve the overall purpose. The "part 5 of 7" instruction in the prompt also reinforced that this was a piece of a larger system, so I focused on the specific functionalities present in this part without trying to explain the entire runtime.
这段代码是 Go 运行时环境 `runtime` 包中 `proc.go` 文件的一部分，主要负责 **goroutine 的生命周期管理、与操作系统交互（特别是系统调用）、以及与性能分析相关的操作**。作为第七部分中的第五部分，它主要关注以下功能：

**核心功能归纳:**

1. **处理 Goroutine 进入和退出系统调用:**  这段代码包含了 `entersyscall` 和 `exitsyscall` 系列函数，负责在 Goroutine 即将执行系统调用时保存其状态，并在系统调用完成后恢复其状态，使其能够继续执行。

2. **管理 Goroutine 与操作系统线程的绑定 (LockOSThread/UnlockOSThread):** 提供了将 Goroutine 绑定到特定操作系统线程的机制，以及解除绑定的功能。这对于需要与依赖线程本地状态的 C 代码或操作系统服务交互的 Goroutine 非常重要。

3. **Goroutine 的创建和回收:**  实现了 `newproc` 和 `newproc1` 函数，用于创建新的 Goroutine 并将其加入到调度器的运行队列中。同时，也包含 `gfput` 和 `gfget` 函数，用于维护一个空闲 Goroutine 的池子，以提高 Goroutine 创建的效率。

4. **处理 `fork` 和 `exec` 系统调用:**  定义了 `syscall_runtime_BeforeFork`、`syscall_runtime_AfterFork` 和 `syscall_runtime_AfterForkInChild` 等函数，用于在 `fork` 系统调用前后进行必要的运行时状态调整，以保证在父子进程中的正确运行。同样地，也包含了 `syscall_runtime_BeforeExec` 和 `syscall_runtime_AfterExec` 来处理 `exec` 系统调用。

5. **性能分析 (Profiling):**  包含了 `sigprof` 函数，这是一个信号处理函数，用于接收性能分析信号 (SIGPROF)，并记录 Goroutine 的执行状态，以便进行 CPU 性能分析。

**更详细的功能描述:**

* **`entersyscall` 和 `reentersyscall`:** 当 Goroutine 调用系统调用时，这些函数会被调用。它们的主要任务是：
    * 保存当前 Goroutine 的状态（程序计数器 PC、栈指针 SP、基址指针 BP）。
    * 将 Goroutine 的状态标记为 `_Gsyscall`，表示它正在执行系统调用。
    * 将当前 Goroutine 从其关联的处理器 `P` 上解绑。
    * 触发 tracing 事件，记录系统调用的开始。

* **`exitsyscall` 和 `exitsyscall0`:** 当系统调用返回时，这些函数会被调用。它们的主要任务是：
    * 尝试快速重新获取之前使用的处理器 `P`，如果成功，Goroutine 可以立即继续执行。
    * 如果无法快速获取处理器，则将 Goroutine 标记为 `_Grunnable`，并将其放入全局运行队列中，等待调度器分配处理器。
    * 触发 tracing 事件，记录系统调用的结束。

* **`entersyscallblock` 和 `entersyscallblock_handoff`:**  类似于 `entersyscall`，但用于已知会阻塞的系统调用。它会尝试将当前处理器 `P` 交还给调度器，以便其他 Goroutine 可以运行。

* **`save(pc, sp, bp uintptr)`:**  这是一个低级函数，用于保存 Goroutine 的程序计数器、栈指针和基址指针到 Goroutine 的 `sched` 结构体中。这在 Goroutine 切换或进入/退出系统调用时非常重要。

* **`LockOSThread()` 和相关函数:**  允许 Goroutine 绑定到一个操作系统线程。这意味着该 Goroutine 将始终在该线程上执行，直到显式地调用 `UnlockOSThread()`。这对于与 C 代码交互或者需要线程本地存储的情况很有用。

* **`UnlockOSThread()` 和相关函数:**  解除 Goroutine 与操作系统线程的绑定。

* **`newproc(fn *funcval)` 和 `newproc1(...)`:**  创建新的 Goroutine。`newproc` 是 `go` 关键字的底层实现，它会调用 `newproc1` 来分配和初始化新的 Goroutine 结构体，设置其执行的函数，并将其放入运行队列。

* **`malg(stacksize int32)`:**  分配一个新的 Goroutine 结构体，并为其分配指定大小的栈空间。

* **`gfput(pp *p, gp *g)` 和 `gfget(pp *p)`:**  实现了一个 Goroutine 的空闲列表。当 Goroutine 执行完成后，其结构体可以被放入空闲列表以供后续重用，避免频繁的内存分配和释放。

* **`syscall_runtime_BeforeFork()``, `syscall_runtime_AfterFork()``, `syscall_runtime_AfterForkInChild()`:**  在 `fork` 系统调用前后执行，用于处理信号屏蔽和栈保护等问题，以确保父子进程的正确行为。

* **`syscall_runtime_BeforeExec()` 和 `syscall_runtime_AfterExec()`:**  在 `exec` 系统调用前后执行，用于阻止在 `exec` 期间创建新线程。

* **`sigprof(pc, sp, lr uintptr, gp *g, mp *m)`:**  当接收到 `SIGPROF` 信号时被调用，用于记录当前 Goroutine 的状态，以便进行 CPU 性能分析。

**功能示例 (Go 代码):**

```go
package main

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
)

func worker() {
	fmt.Println("Worker goroutine started")
	time.Sleep(time.Second) // 模拟一些工作
	fmt.Println("Worker goroutine finished")
}

func systemCallExample() {
	fmt.Println("Calling a system call...")
	_, _, err := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
	if err != 0 {
		fmt.Println("System call failed:", err)
	} else {
		fmt.Println("System call succeeded")
	}
}

func lockOSThreadExample() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fmt.Println("Goroutine locked to OS thread")
	// 在这里可以安全地调用依赖线程本地状态的 C 代码或操作系统 API
}

func main() {
	go worker() // 创建一个新的 Goroutine

	systemCallExample() // 调用系统调用

	lockOSThreadExample()

	time.Sleep(2 * time.Second)
	fmt.Println("Main goroutine finished")
}
```

**假设的输入与输出 (代码推理):**

* **`entersyscall` 输入:**  当 `systemCallExample` 函数中的 `syscall.RawSyscall` 被调用时，`entersyscall` 会被触发。假设此时 Goroutine 的 PC 指向 `syscall.RawSyscall` 的调用地址，SP 指向当前的栈顶。
* **`entersyscall` 输出:**  `entersyscall` 会将当前的 PC 和 SP 保存到 Goroutine 的 `sched` 结构体中，并将 Goroutine 的状态设置为 `_Gsyscall`.
* **`exitsyscall` 输入:**  当 `syscall.RawSyscall` 完成执行并返回时，`exitsyscall` 会被触发。
* **`exitsyscall` 输出:** `exitsyscall` 会尝试重新获取处理器，如果成功，Goroutine 将继续执行。否则，Goroutine 将被放入运行队列等待调度。

**使用者易犯错的点 (举例):**

1. **`LockOSThread` 和 `UnlockOSThread` 不匹配:**  如果调用了 `LockOSThread` 但没有相应地调用 `UnlockOSThread`，会导致该操作系统线程被永久占用，无法执行其他 Goroutine，可能导致程序性能下降甚至死锁。

   ```go
   func badLocking() {
       runtime.LockOSThread()
       // 忘记调用 runtime.UnlockOSThread()
       fmt.Println("Locked to OS thread, but will never unlock")
       select {} // 阻塞，导致线程无法被释放
   }
   ```

2. **在不必要的时候使用 `LockOSThread`:** 过度使用 `LockOSThread` 会限制 Go 调度器的灵活性，降低并发性能。只有在确实需要与线程本地状态的外部代码交互时才应该使用。

**总结:**

这段 `proc.go` 的代码是 Go 运行时系统中至关重要的组成部分，它负责管理 Goroutine 的生命周期，处理与操作系统的交互，并提供了必要的机制来支持性能分析和与外部代码的集成。它确保了 Go 程序能够高效地利用操作系统资源，并提供了一种安全可靠的方式来执行并发任务。

### 提示词
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
The goroutine may have locked this thread because
		// it put it in an unusual kernel state. Kill it
		// rather than returning it to the thread pool.

		// Return to mstart, which will release the P and exit
		// the thread.
		if GOOS != "plan9" { // See golang.org/issue/22227.
			gogo(&mp.g0.sched)
		} else {
			// Clear lockedExt on plan9 since we may end up re-using
			// this thread.
			mp.lockedExt = 0
		}
	}
}

// save updates getg().sched to refer to pc and sp so that a following
// gogo will restore pc and sp.
//
// save must not have write barriers because invoking a write barrier
// can clobber getg().sched.
//
//go:nosplit
//go:nowritebarrierrec
func save(pc, sp, bp uintptr) {
	gp := getg()

	if gp == gp.m.g0 || gp == gp.m.gsignal {
		// m.g0.sched is special and must describe the context
		// for exiting the thread. mstart1 writes to it directly.
		// m.gsignal.sched should not be used at all.
		// This check makes sure save calls do not accidentally
		// run in contexts where they'd write to system g's.
		throw("save on system g not allowed")
	}

	gp.sched.pc = pc
	gp.sched.sp = sp
	gp.sched.lr = 0
	gp.sched.ret = 0
	gp.sched.bp = bp
	// We need to ensure ctxt is zero, but can't have a write
	// barrier here. However, it should always already be zero.
	// Assert that.
	if gp.sched.ctxt != nil {
		badctxt()
	}
}

// The goroutine g is about to enter a system call.
// Record that it's not using the cpu anymore.
// This is called only from the go syscall library and cgocall,
// not from the low-level system calls used by the runtime.
//
// Entersyscall cannot split the stack: the save must
// make g->sched refer to the caller's stack segment, because
// entersyscall is going to return immediately after.
//
// Nothing entersyscall calls can split the stack either.
// We cannot safely move the stack during an active call to syscall,
// because we do not know which of the uintptr arguments are
// really pointers (back into the stack).
// In practice, this means that we make the fast path run through
// entersyscall doing no-split things, and the slow path has to use systemstack
// to run bigger things on the system stack.
//
// reentersyscall is the entry point used by cgo callbacks, where explicitly
// saved SP and PC are restored. This is needed when exitsyscall will be called
// from a function further up in the call stack than the parent, as g->syscallsp
// must always point to a valid stack frame. entersyscall below is the normal
// entry point for syscalls, which obtains the SP and PC from the caller.
//
//go:nosplit
func reentersyscall(pc, sp, bp uintptr) {
	trace := traceAcquire()
	gp := getg()

	// Disable preemption because during this function g is in Gsyscall status,
	// but can have inconsistent g->sched, do not let GC observe it.
	gp.m.locks++

	// Entersyscall must not call any function that might split/grow the stack.
	// (See details in comment above.)
	// Catch calls that might, by replacing the stack guard with something that
	// will trip any stack check and leaving a flag to tell newstack to die.
	gp.stackguard0 = stackPreempt
	gp.throwsplit = true

	// Leave SP around for GC and traceback.
	save(pc, sp, bp)
	gp.syscallsp = sp
	gp.syscallpc = pc
	gp.syscallbp = bp
	casgstatus(gp, _Grunning, _Gsyscall)
	if staticLockRanking {
		// When doing static lock ranking casgstatus can call
		// systemstack which clobbers g.sched.
		save(pc, sp, bp)
	}
	if gp.syscallsp < gp.stack.lo || gp.stack.hi < gp.syscallsp {
		systemstack(func() {
			print("entersyscall inconsistent sp ", hex(gp.syscallsp), " [", hex(gp.stack.lo), ",", hex(gp.stack.hi), "]\n")
			throw("entersyscall")
		})
	}
	if gp.syscallbp != 0 && gp.syscallbp < gp.stack.lo || gp.stack.hi < gp.syscallbp {
		systemstack(func() {
			print("entersyscall inconsistent bp ", hex(gp.syscallbp), " [", hex(gp.stack.lo), ",", hex(gp.stack.hi), "]\n")
			throw("entersyscall")
		})
	}

	if trace.ok() {
		systemstack(func() {
			trace.GoSysCall()
			traceRelease(trace)
		})
		// systemstack itself clobbers g.sched.{pc,sp} and we might
		// need them later when the G is genuinely blocked in a
		// syscall
		save(pc, sp, bp)
	}

	if sched.sysmonwait.Load() {
		systemstack(entersyscall_sysmon)
		save(pc, sp, bp)
	}

	if gp.m.p.ptr().runSafePointFn != 0 {
		// runSafePointFn may stack split if run on this stack
		systemstack(runSafePointFn)
		save(pc, sp, bp)
	}

	gp.m.syscalltick = gp.m.p.ptr().syscalltick
	pp := gp.m.p.ptr()
	pp.m = 0
	gp.m.oldp.set(pp)
	gp.m.p = 0
	atomic.Store(&pp.status, _Psyscall)
	if sched.gcwaiting.Load() {
		systemstack(entersyscall_gcwait)
		save(pc, sp, bp)
	}

	gp.m.locks--
}

// Standard syscall entry used by the go syscall library and normal cgo calls.
//
// This is exported via linkname to assembly in the syscall package and x/sys.
//
// Other packages should not be accessing entersyscall directly,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:nosplit
//go:linkname entersyscall
func entersyscall() {
	// N.B. getcallerfp cannot be written directly as argument in the call
	// to reentersyscall because it forces spilling the other arguments to
	// the stack. This results in exceeding the nosplit stack requirements
	// on some platforms.
	fp := getcallerfp()
	reentersyscall(sys.GetCallerPC(), sys.GetCallerSP(), fp)
}

func entersyscall_sysmon() {
	lock(&sched.lock)
	if sched.sysmonwait.Load() {
		sched.sysmonwait.Store(false)
		notewakeup(&sched.sysmonnote)
	}
	unlock(&sched.lock)
}

func entersyscall_gcwait() {
	gp := getg()
	pp := gp.m.oldp.ptr()

	lock(&sched.lock)
	trace := traceAcquire()
	if sched.stopwait > 0 && atomic.Cas(&pp.status, _Psyscall, _Pgcstop) {
		if trace.ok() {
			// This is a steal in the new tracer. While it's very likely
			// that we were the ones to put this P into _Psyscall, between
			// then and now it's totally possible it had been stolen and
			// then put back into _Psyscall for us to acquire here. In such
			// case ProcStop would be incorrect.
			//
			// TODO(mknyszek): Consider emitting a ProcStop instead when
			// gp.m.syscalltick == pp.syscalltick, since then we know we never
			// lost the P.
			trace.ProcSteal(pp, true)
			traceRelease(trace)
		}
		pp.gcStopTime = nanotime()
		pp.syscalltick++
		if sched.stopwait--; sched.stopwait == 0 {
			notewakeup(&sched.stopnote)
		}
	} else if trace.ok() {
		traceRelease(trace)
	}
	unlock(&sched.lock)
}

// The same as entersyscall(), but with a hint that the syscall is blocking.

// entersyscallblock should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname entersyscallblock
//go:nosplit
func entersyscallblock() {
	gp := getg()

	gp.m.locks++ // see comment in entersyscall
	gp.throwsplit = true
	gp.stackguard0 = stackPreempt // see comment in entersyscall
	gp.m.syscalltick = gp.m.p.ptr().syscalltick
	gp.m.p.ptr().syscalltick++

	// Leave SP around for GC and traceback.
	pc := sys.GetCallerPC()
	sp := sys.GetCallerSP()
	bp := getcallerfp()
	save(pc, sp, bp)
	gp.syscallsp = gp.sched.sp
	gp.syscallpc = gp.sched.pc
	gp.syscallbp = gp.sched.bp
	if gp.syscallsp < gp.stack.lo || gp.stack.hi < gp.syscallsp {
		sp1 := sp
		sp2 := gp.sched.sp
		sp3 := gp.syscallsp
		systemstack(func() {
			print("entersyscallblock inconsistent sp ", hex(sp1), " ", hex(sp2), " ", hex(sp3), " [", hex(gp.stack.lo), ",", hex(gp.stack.hi), "]\n")
			throw("entersyscallblock")
		})
	}
	casgstatus(gp, _Grunning, _Gsyscall)
	if gp.syscallsp < gp.stack.lo || gp.stack.hi < gp.syscallsp {
		systemstack(func() {
			print("entersyscallblock inconsistent sp ", hex(sp), " ", hex(gp.sched.sp), " ", hex(gp.syscallsp), " [", hex(gp.stack.lo), ",", hex(gp.stack.hi), "]\n")
			throw("entersyscallblock")
		})
	}
	if gp.syscallbp != 0 && gp.syscallbp < gp.stack.lo || gp.stack.hi < gp.syscallbp {
		systemstack(func() {
			print("entersyscallblock inconsistent bp ", hex(bp), " ", hex(gp.sched.bp), " ", hex(gp.syscallbp), " [", hex(gp.stack.lo), ",", hex(gp.stack.hi), "]\n")
			throw("entersyscallblock")
		})
	}

	systemstack(entersyscallblock_handoff)

	// Resave for traceback during blocked call.
	save(sys.GetCallerPC(), sys.GetCallerSP(), getcallerfp())

	gp.m.locks--
}

func entersyscallblock_handoff() {
	trace := traceAcquire()
	if trace.ok() {
		trace.GoSysCall()
		traceRelease(trace)
	}
	handoffp(releasep())
}

// The goroutine g exited its system call.
// Arrange for it to run on a cpu again.
// This is called only from the go syscall library, not
// from the low-level system calls used by the runtime.
//
// Write barriers are not allowed because our P may have been stolen.
//
// This is exported via linkname to assembly in the syscall package.
//
// exitsyscall should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:nosplit
//go:nowritebarrierrec
//go:linkname exitsyscall
func exitsyscall() {
	gp := getg()

	gp.m.locks++ // see comment in entersyscall
	if sys.GetCallerSP() > gp.syscallsp {
		throw("exitsyscall: syscall frame is no longer valid")
	}

	gp.waitsince = 0
	oldp := gp.m.oldp.ptr()
	gp.m.oldp = 0
	if exitsyscallfast(oldp) {
		// When exitsyscallfast returns success, we have a P so can now use
		// write barriers
		if goroutineProfile.active {
			// Make sure that gp has had its stack written out to the goroutine
			// profile, exactly as it was when the goroutine profiler first
			// stopped the world.
			systemstack(func() {
				tryRecordGoroutineProfileWB(gp)
			})
		}
		trace := traceAcquire()
		if trace.ok() {
			lostP := oldp != gp.m.p.ptr() || gp.m.syscalltick != gp.m.p.ptr().syscalltick
			systemstack(func() {
				// Write out syscall exit eagerly.
				//
				// It's important that we write this *after* we know whether we
				// lost our P or not (determined by exitsyscallfast).
				trace.GoSysExit(lostP)
				if lostP {
					// We lost the P at some point, even though we got it back here.
					// Trace that we're starting again, because there was a traceGoSysBlock
					// call somewhere in exitsyscallfast (indicating that this goroutine
					// had blocked) and we're about to start running again.
					trace.GoStart()
				}
			})
		}
		// There's a cpu for us, so we can run.
		gp.m.p.ptr().syscalltick++
		// We need to cas the status and scan before resuming...
		casgstatus(gp, _Gsyscall, _Grunning)
		if trace.ok() {
			traceRelease(trace)
		}

		// Garbage collector isn't running (since we are),
		// so okay to clear syscallsp.
		gp.syscallsp = 0
		gp.m.locks--
		if gp.preempt {
			// restore the preemption request in case we've cleared it in newstack
			gp.stackguard0 = stackPreempt
		} else {
			// otherwise restore the real stackGuard, we've spoiled it in entersyscall/entersyscallblock
			gp.stackguard0 = gp.stack.lo + stackGuard
		}
		gp.throwsplit = false

		if sched.disable.user && !schedEnabled(gp) {
			// Scheduling of this goroutine is disabled.
			Gosched()
		}

		return
	}

	gp.m.locks--

	// Call the scheduler.
	mcall(exitsyscall0)

	// Scheduler returned, so we're allowed to run now.
	// Delete the syscallsp information that we left for
	// the garbage collector during the system call.
	// Must wait until now because until gosched returns
	// we don't know for sure that the garbage collector
	// is not running.
	gp.syscallsp = 0
	gp.m.p.ptr().syscalltick++
	gp.throwsplit = false
}

//go:nosplit
func exitsyscallfast(oldp *p) bool {
	// Freezetheworld sets stopwait but does not retake P's.
	if sched.stopwait == freezeStopWait {
		return false
	}

	// Try to re-acquire the last P.
	trace := traceAcquire()
	if oldp != nil && oldp.status == _Psyscall && atomic.Cas(&oldp.status, _Psyscall, _Pidle) {
		// There's a cpu for us, so we can run.
		wirep(oldp)
		exitsyscallfast_reacquired(trace)
		if trace.ok() {
			traceRelease(trace)
		}
		return true
	}
	if trace.ok() {
		traceRelease(trace)
	}

	// Try to get any other idle P.
	if sched.pidle != 0 {
		var ok bool
		systemstack(func() {
			ok = exitsyscallfast_pidle()
		})
		if ok {
			return true
		}
	}
	return false
}

// exitsyscallfast_reacquired is the exitsyscall path on which this G
// has successfully reacquired the P it was running on before the
// syscall.
//
//go:nosplit
func exitsyscallfast_reacquired(trace traceLocker) {
	gp := getg()
	if gp.m.syscalltick != gp.m.p.ptr().syscalltick {
		if trace.ok() {
			// The p was retaken and then enter into syscall again (since gp.m.syscalltick has changed).
			// traceGoSysBlock for this syscall was already emitted,
			// but here we effectively retake the p from the new syscall running on the same p.
			systemstack(func() {
				// We're stealing the P. It's treated
				// as if it temporarily stopped running. Then, start running.
				trace.ProcSteal(gp.m.p.ptr(), true)
				trace.ProcStart()
			})
		}
		gp.m.p.ptr().syscalltick++
	}
}

func exitsyscallfast_pidle() bool {
	lock(&sched.lock)
	pp, _ := pidleget(0)
	if pp != nil && sched.sysmonwait.Load() {
		sched.sysmonwait.Store(false)
		notewakeup(&sched.sysmonnote)
	}
	unlock(&sched.lock)
	if pp != nil {
		acquirep(pp)
		return true
	}
	return false
}

// exitsyscall slow path on g0.
// Failed to acquire P, enqueue gp as runnable.
//
// Called via mcall, so gp is the calling g from this M.
//
//go:nowritebarrierrec
func exitsyscall0(gp *g) {
	var trace traceLocker
	traceExitingSyscall()
	trace = traceAcquire()
	casgstatus(gp, _Gsyscall, _Grunnable)
	traceExitedSyscall()
	if trace.ok() {
		// Write out syscall exit eagerly.
		//
		// It's important that we write this *after* we know whether we
		// lost our P or not (determined by exitsyscallfast).
		trace.GoSysExit(true)
		traceRelease(trace)
	}
	dropg()
	lock(&sched.lock)
	var pp *p
	if schedEnabled(gp) {
		pp, _ = pidleget(0)
	}
	var locked bool
	if pp == nil {
		globrunqput(gp)

		// Below, we stoplockedm if gp is locked. globrunqput releases
		// ownership of gp, so we must check if gp is locked prior to
		// committing the release by unlocking sched.lock, otherwise we
		// could race with another M transitioning gp from unlocked to
		// locked.
		locked = gp.lockedm != 0
	} else if sched.sysmonwait.Load() {
		sched.sysmonwait.Store(false)
		notewakeup(&sched.sysmonnote)
	}
	unlock(&sched.lock)
	if pp != nil {
		acquirep(pp)
		execute(gp, false) // Never returns.
	}
	if locked {
		// Wait until another thread schedules gp and so m again.
		//
		// N.B. lockedm must be this M, as this g was running on this M
		// before entersyscall.
		stoplockedm()
		execute(gp, false) // Never returns.
	}
	stopm()
	schedule() // Never returns.
}

// Called from syscall package before fork.
//
// syscall_runtime_BeforeFork is for package syscall,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname syscall_runtime_BeforeFork syscall.runtime_BeforeFork
//go:nosplit
func syscall_runtime_BeforeFork() {
	gp := getg().m.curg

	// Block signals during a fork, so that the child does not run
	// a signal handler before exec if a signal is sent to the process
	// group. See issue #18600.
	gp.m.locks++
	sigsave(&gp.m.sigmask)
	sigblock(false)

	// This function is called before fork in syscall package.
	// Code between fork and exec must not allocate memory nor even try to grow stack.
	// Here we spoil g.stackguard0 to reliably detect any attempts to grow stack.
	// runtime_AfterFork will undo this in parent process, but not in child.
	gp.stackguard0 = stackFork
}

// Called from syscall package after fork in parent.
//
// syscall_runtime_AfterFork is for package syscall,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname syscall_runtime_AfterFork syscall.runtime_AfterFork
//go:nosplit
func syscall_runtime_AfterFork() {
	gp := getg().m.curg

	// See the comments in beforefork.
	gp.stackguard0 = gp.stack.lo + stackGuard

	msigrestore(gp.m.sigmask)

	gp.m.locks--
}

// inForkedChild is true while manipulating signals in the child process.
// This is used to avoid calling libc functions in case we are using vfork.
var inForkedChild bool

// Called from syscall package after fork in child.
// It resets non-sigignored signals to the default handler, and
// restores the signal mask in preparation for the exec.
//
// Because this might be called during a vfork, and therefore may be
// temporarily sharing address space with the parent process, this must
// not change any global variables or calling into C code that may do so.
//
// syscall_runtime_AfterForkInChild is for package syscall,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname syscall_runtime_AfterForkInChild syscall.runtime_AfterForkInChild
//go:nosplit
//go:nowritebarrierrec
func syscall_runtime_AfterForkInChild() {
	// It's OK to change the global variable inForkedChild here
	// because we are going to change it back. There is no race here,
	// because if we are sharing address space with the parent process,
	// then the parent process can not be running concurrently.
	inForkedChild = true

	clearSignalHandlers()

	// When we are the child we are the only thread running,
	// so we know that nothing else has changed gp.m.sigmask.
	msigrestore(getg().m.sigmask)

	inForkedChild = false
}

// pendingPreemptSignals is the number of preemption signals
// that have been sent but not received. This is only used on Darwin.
// For #41702.
var pendingPreemptSignals atomic.Int32

// Called from syscall package before Exec.
//
//go:linkname syscall_runtime_BeforeExec syscall.runtime_BeforeExec
func syscall_runtime_BeforeExec() {
	// Prevent thread creation during exec.
	execLock.lock()

	// On Darwin, wait for all pending preemption signals to
	// be received. See issue #41702.
	if GOOS == "darwin" || GOOS == "ios" {
		for pendingPreemptSignals.Load() > 0 {
			osyield()
		}
	}
}

// Called from syscall package after Exec.
//
//go:linkname syscall_runtime_AfterExec syscall.runtime_AfterExec
func syscall_runtime_AfterExec() {
	execLock.unlock()
}

// Allocate a new g, with a stack big enough for stacksize bytes.
func malg(stacksize int32) *g {
	newg := new(g)
	if stacksize >= 0 {
		stacksize = round2(stackSystem + stacksize)
		systemstack(func() {
			newg.stack = stackalloc(uint32(stacksize))
		})
		newg.stackguard0 = newg.stack.lo + stackGuard
		newg.stackguard1 = ^uintptr(0)
		// Clear the bottom word of the stack. We record g
		// there on gsignal stack during VDSO on ARM and ARM64.
		*(*uintptr)(unsafe.Pointer(newg.stack.lo)) = 0
	}
	return newg
}

// Create a new g running fn.
// Put it on the queue of g's waiting to run.
// The compiler turns a go statement into a call to this.
func newproc(fn *funcval) {
	gp := getg()
	pc := sys.GetCallerPC()
	systemstack(func() {
		newg := newproc1(fn, gp, pc, false, waitReasonZero)

		pp := getg().m.p.ptr()
		runqput(pp, newg, true)

		if mainStarted {
			wakep()
		}
	})
}

// Create a new g in state _Grunnable (or _Gwaiting if parked is true), starting at fn.
// callerpc is the address of the go statement that created this. The caller is responsible
// for adding the new g to the scheduler. If parked is true, waitreason must be non-zero.
func newproc1(fn *funcval, callergp *g, callerpc uintptr, parked bool, waitreason waitReason) *g {
	if fn == nil {
		fatal("go of nil func value")
	}

	mp := acquirem() // disable preemption because we hold M and P in local vars.
	pp := mp.p.ptr()
	newg := gfget(pp)
	if newg == nil {
		newg = malg(stackMin)
		casgstatus(newg, _Gidle, _Gdead)
		allgadd(newg) // publishes with a g->status of Gdead so GC scanner doesn't look at uninitialized stack.
	}
	if newg.stack.hi == 0 {
		throw("newproc1: newg missing stack")
	}

	if readgstatus(newg) != _Gdead {
		throw("newproc1: new g is not Gdead")
	}

	totalSize := uintptr(4*goarch.PtrSize + sys.MinFrameSize) // extra space in case of reads slightly beyond frame
	totalSize = alignUp(totalSize, sys.StackAlign)
	sp := newg.stack.hi - totalSize
	if usesLR {
		// caller's LR
		*(*uintptr)(unsafe.Pointer(sp)) = 0
		prepGoExitFrame(sp)
	}
	if GOARCH == "arm64" {
		// caller's FP
		*(*uintptr)(unsafe.Pointer(sp - goarch.PtrSize)) = 0
	}

	memclrNoHeapPointers(unsafe.Pointer(&newg.sched), unsafe.Sizeof(newg.sched))
	newg.sched.sp = sp
	newg.stktopsp = sp
	newg.sched.pc = abi.FuncPCABI0(goexit) + sys.PCQuantum // +PCQuantum so that previous instruction is in same function
	newg.sched.g = guintptr(unsafe.Pointer(newg))
	gostartcallfn(&newg.sched, fn)
	newg.parentGoid = callergp.goid
	newg.gopc = callerpc
	newg.ancestors = saveAncestors(callergp)
	newg.startpc = fn.fn
	if isSystemGoroutine(newg, false) {
		sched.ngsys.Add(1)
	} else {
		// Only user goroutines inherit synctest groups and pprof labels.
		newg.syncGroup = callergp.syncGroup
		if mp.curg != nil {
			newg.labels = mp.curg.labels
		}
		if goroutineProfile.active {
			// A concurrent goroutine profile is running. It should include
			// exactly the set of goroutines that were alive when the goroutine
			// profiler first stopped the world. That does not include newg, so
			// mark it as not needing a profile before transitioning it from
			// _Gdead.
			newg.goroutineProfiled.Store(goroutineProfileSatisfied)
		}
	}
	// Track initial transition?
	newg.trackingSeq = uint8(cheaprand())
	if newg.trackingSeq%gTrackingPeriod == 0 {
		newg.tracking = true
	}
	gcController.addScannableStack(pp, int64(newg.stack.hi-newg.stack.lo))

	// Get a goid and switch to runnable. Make all this atomic to the tracer.
	trace := traceAcquire()
	var status uint32 = _Grunnable
	if parked {
		status = _Gwaiting
		newg.waitreason = waitreason
	}
	if pp.goidcache == pp.goidcacheend {
		// Sched.goidgen is the last allocated id,
		// this batch must be [sched.goidgen+1, sched.goidgen+GoidCacheBatch].
		// At startup sched.goidgen=0, so main goroutine receives goid=1.
		pp.goidcache = sched.goidgen.Add(_GoidCacheBatch)
		pp.goidcache -= _GoidCacheBatch - 1
		pp.goidcacheend = pp.goidcache + _GoidCacheBatch
	}
	newg.goid = pp.goidcache
	casgstatus(newg, _Gdead, status)
	pp.goidcache++
	newg.trace.reset()
	if trace.ok() {
		trace.GoCreate(newg, newg.startpc, parked)
		traceRelease(trace)
	}

	// Set up race context.
	if raceenabled {
		newg.racectx = racegostart(callerpc)
		newg.raceignore = 0
		if newg.labels != nil {
			// See note in proflabel.go on labelSync's role in synchronizing
			// with the reads in the signal handler.
			racereleasemergeg(newg, unsafe.Pointer(&labelSync))
		}
	}
	releasem(mp)

	return newg
}

// saveAncestors copies previous ancestors of the given caller g and
// includes info for the current caller into a new set of tracebacks for
// a g being created.
func saveAncestors(callergp *g) *[]ancestorInfo {
	// Copy all prior info, except for the root goroutine (goid 0).
	if debug.tracebackancestors <= 0 || callergp.goid == 0 {
		return nil
	}
	var callerAncestors []ancestorInfo
	if callergp.ancestors != nil {
		callerAncestors = *callergp.ancestors
	}
	n := int32(len(callerAncestors)) + 1
	if n > debug.tracebackancestors {
		n = debug.tracebackancestors
	}
	ancestors := make([]ancestorInfo, n)
	copy(ancestors[1:], callerAncestors)

	var pcs [tracebackInnerFrames]uintptr
	npcs := gcallers(callergp, 0, pcs[:])
	ipcs := make([]uintptr, npcs)
	copy(ipcs, pcs[:])
	ancestors[0] = ancestorInfo{
		pcs:  ipcs,
		goid: callergp.goid,
		gopc: callergp.gopc,
	}

	ancestorsp := new([]ancestorInfo)
	*ancestorsp = ancestors
	return ancestorsp
}

// Put on gfree list.
// If local list is too long, transfer a batch to the global list.
func gfput(pp *p, gp *g) {
	if readgstatus(gp) != _Gdead {
		throw("gfput: bad status (not Gdead)")
	}

	stksize := gp.stack.hi - gp.stack.lo

	if stksize != uintptr(startingStackSize) {
		// non-standard stack size - free it.
		stackfree(gp.stack)
		gp.stack.lo = 0
		gp.stack.hi = 0
		gp.stackguard0 = 0
	}

	pp.gFree.push(gp)
	pp.gFree.n++
	if pp.gFree.n >= 64 {
		var (
			inc      int32
			stackQ   gQueue
			noStackQ gQueue
		)
		for pp.gFree.n >= 32 {
			gp := pp.gFree.pop()
			pp.gFree.n--
			if gp.stack.lo == 0 {
				noStackQ.push(gp)
			} else {
				stackQ.push(gp)
			}
			inc++
		}
		lock(&sched.gFree.lock)
		sched.gFree.noStack.pushAll(noStackQ)
		sched.gFree.stack.pushAll(stackQ)
		sched.gFree.n += inc
		unlock(&sched.gFree.lock)
	}
}

// Get from gfree list.
// If local list is empty, grab a batch from global list.
func gfget(pp *p) *g {
retry:
	if pp.gFree.empty() && (!sched.gFree.stack.empty() || !sched.gFree.noStack.empty()) {
		lock(&sched.gFree.lock)
		// Move a batch of free Gs to the P.
		for pp.gFree.n < 32 {
			// Prefer Gs with stacks.
			gp := sched.gFree.stack.pop()
			if gp == nil {
				gp = sched.gFree.noStack.pop()
				if gp == nil {
					break
				}
			}
			sched.gFree.n--
			pp.gFree.push(gp)
			pp.gFree.n++
		}
		unlock(&sched.gFree.lock)
		goto retry
	}
	gp := pp.gFree.pop()
	if gp == nil {
		return nil
	}
	pp.gFree.n--
	if gp.stack.lo != 0 && gp.stack.hi-gp.stack.lo != uintptr(startingStackSize) {
		// Deallocate old stack. We kept it in gfput because it was the
		// right size when the goroutine was put on the free list, but
		// the right size has changed since then.
		systemstack(func() {
			stackfree(gp.stack)
			gp.stack.lo = 0
			gp.stack.hi = 0
			gp.stackguard0 = 0
		})
	}
	if gp.stack.lo == 0 {
		// Stack was deallocated in gfput or just above. Allocate a new one.
		systemstack(func() {
			gp.stack = stackalloc(startingStackSize)
		})
		gp.stackguard0 = gp.stack.lo + stackGuard
	} else {
		if raceenabled {
			racemalloc(unsafe.Pointer(gp.stack.lo), gp.stack.hi-gp.stack.lo)
		}
		if msanenabled {
			msanmalloc(unsafe.Pointer(gp.stack.lo), gp.stack.hi-gp.stack.lo)
		}
		if asanenabled {
			asanunpoison(unsafe.Pointer(gp.stack.lo), gp.stack.hi-gp.stack.lo)
		}
	}
	return gp
}

// Purge all cached G's from gfree list to the global list.
func gfpurge(pp *p) {
	var (
		inc      int32
		stackQ   gQueue
		noStackQ gQueue
	)
	for !pp.gFree.empty() {
		gp := pp.gFree.pop()
		pp.gFree.n--
		if gp.stack.lo == 0 {
			noStackQ.push(gp)
		} else {
			stackQ.push(gp)
		}
		inc++
	}
	lock(&sched.gFree.lock)
	sched.gFree.noStack.pushAll(noStackQ)
	sched.gFree.stack.pushAll(stackQ)
	sched.gFree.n += inc
	unlock(&sched.gFree.lock)
}

// Breakpoint executes a breakpoint trap.
func Breakpoint() {
	breakpoint()
}

// dolockOSThread is called by LockOSThread and lockOSThread below
// after they modify m.locked. Do not allow preemption during this call,
// or else the m might be different in this function than in the caller.
//
//go:nosplit
func dolockOSThread() {
	if GOARCH == "wasm" {
		return // no threads on wasm yet
	}
	gp := getg()
	gp.m.lockedg.set(gp)
	gp.lockedm.set(gp.m)
}

// LockOSThread wires the calling goroutine to its current operating system thread.
// The calling goroutine will always execute in that thread,
// and no other goroutine will execute in it,
// until the calling goroutine has made as many calls to
// [UnlockOSThread] as to LockOSThread.
// If the calling goroutine exits without unlocking the thread,
// the thread will be terminated.
//
// All init functions are run on the startup thread. Calling LockOSThread
// from an init function will cause the main function to be invoked on
// that thread.
//
// A goroutine should call LockOSThread before calling OS services or
// non-Go library functions that depend on per-thread state.
//
//go:nosplit
func LockOSThread() {
	if atomic.Load(&newmHandoff.haveTemplateThread) == 0 && GOOS != "plan9" {
		// If we need to start a new thread from the locked
		// thread, we need the template thread. Start it now
		// while we're in a known-good state.
		startTemplateThread()
	}
	gp := getg()
	gp.m.lockedExt++
	if gp.m.lockedExt == 0 {
		gp.m.lockedExt--
		panic("LockOSThread nesting overflow")
	}
	dolockOSThread()
}

//go:nosplit
func lockOSThread() {
	getg().m.lockedInt++
	dolockOSThread()
}

// dounlockOSThread is called by UnlockOSThread and unlockOSThread below
// after they update m->locked. Do not allow preemption during this call,
// or else the m might be in different in this function than in the caller.
//
//go:nosplit
func dounlockOSThread() {
	if GOARCH == "wasm" {
		return // no threads on wasm yet
	}
	gp := getg()
	if gp.m.lockedInt != 0 || gp.m.lockedExt != 0 {
		return
	}
	gp.m.lockedg = 0
	gp.lockedm = 0
}

// UnlockOSThread undoes an earlier call to LockOSThread.
// If this drops the number of active LockOSThread calls on the
// calling goroutine to zero, it unwires the calling goroutine from
// its fixed operating system thread.
// If there are no active LockOSThread calls, this is a no-op.
//
// Before calling UnlockOSThread, the caller must ensure that the OS
// thread is suitable for running other goroutines. If the caller made
// any permanent changes to the state of the thread that would affect
// other goroutines, it should not call this function and thus leave
// the goroutine locked to the OS thread until the goroutine (and
// hence the thread) exits.
//
//go:nosplit
func UnlockOSThread() {
	gp := getg()
	if gp.m.lockedExt == 0 {
		return
	}
	gp.m.lockedExt--
	dounlockOSThread()
}

//go:nosplit
func unlockOSThread() {
	gp := getg()
	if gp.m.lockedInt == 0 {
		systemstack(badunlockosthread)
	}
	gp.m.lockedInt--
	dounlockOSThread()
}

func badunlockosthread() {
	throw("runtime: internal error: misuse of lockOSThread/unlockOSThread")
}

func gcount() int32 {
	n := int32(atomic.Loaduintptr(&allglen)) - sched.gFree.n - sched.ngsys.Load()
	for _, pp := range allp {
		n -= pp.gFree.n
	}

	// All these variables can be changed concurrently, so the result can be inconsistent.
	// But at least the current goroutine is running.
	if n < 1 {
		n = 1
	}
	return n
}

func mcount() int32 {
	return int32(sched.mnext - sched.nmfreed)
}

var prof struct {
	signalLock atomic.Uint32

	// Must hold signalLock to write. Reads may be lock-free, but
	// signalLock should be taken to synchronize with changes.
	hz atomic.Int32
}

func _System()                    { _System() }
func _ExternalCode()              { _ExternalCode() }
func _LostExternalCode()          { _LostExternalCode() }
func _GC()                        { _GC() }
func _LostSIGPROFDuringAtomic64() { _LostSIGPROFDuringAtomic64() }
func _LostContendedRuntimeLock()  { _LostContendedRuntimeLock() }
func _VDSO()                      { _VDSO() }

// Called if we receive a SIGPROF signal.
// Called by the signal handler, may run during STW.
//
//go:nowritebarrierrec
func sigprof(pc, sp, lr uintptr, gp *g, mp *m) {
	if prof.hz.Load() == 0 {
		return
	}

	// If mp.profilehz is 0, then profiling is not enabled for this thread.
	// We must check this to avoid a deadlock between setcpuprofilerate
	// and the call to cpuprof.add, below.
	if mp != nil && mp.profilehz == 0 {
		return
	}

	// On mips{,le}/arm, 64bit atomics are emulated with spinlocks, in
	// internal/runtime/atomic. If SIGPROF arrives while the program is inside
	// the critical section, it creates a deadlock (when writing the sample).
	// As a workaround, create a counter of SIGPROFs while in critical section
	// to store the count, and pass it to sigprof.add() later when SIGPROF is
	// received from somewhere else (with _LostSIGPROFDuringAtomic64 as pc).
	if GOARCH == "mips" || GOARCH == "mipsle" || GOARCH == "arm" {
		if f := findfunc(pc); f.valid() {
			if stringslite.HasPrefix(funcname(f), "internal/runtime/atomic") {
				cpuprof.lostAtomic++
				return
			}
		}
		if GOARCH == "arm" && goarm < 7 && GOOS == "linux" && pc&0xffff0000 == 0xffff0000 {
			// internal/runtime/atomic functions call into kernel
			// helpers on arm < 7. See
			// internal/runtime/atomic/sys_linux_arm.s.
			cpuprof.lostAtomic++
			return
		}
	}

	// Profiling runs concurrently with GC, so it must not allocate.
	// Set a trap in case the code does allocate.
	// Note that on windows, one thread takes profiles of all the
	// other threads, so mp is usually not getg().m.
	// In fact mp
```