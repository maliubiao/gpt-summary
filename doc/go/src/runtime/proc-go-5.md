Response:
My thought process for analyzing the provided Go code snippet and answering the request goes through these stages:

1. **Understand the Core Request:** The user wants to understand the functionality of the provided Go code snippet, which is a part of `runtime/proc.go`. Specifically, they are asking for a summary of its functions in the context of Go's overall behavior. They also want examples, handling of command-line arguments (if any), common mistakes, and a final summary since this is part 6 of 7.

2. **Identify Key Functions and Their Purposes:**  I start by scanning the code for function definitions and their names. The prominent functions in this snippet are:

    * `profilem`:  Clearly related to CPU profiling.
    * `setcpuprofilerate`:  Configuring the CPU profiling rate.
    * `(*p).init`: Initializing a `p` (processor) struct.
    * `(*p).destroy`: Cleaning up a `p` struct.
    * `procresize`:  Changing the number of available processors (GOMAXPROCS).
    * `acquirep`: Associating an `m` (machine/OS thread) with a `p`.
    * `wirep`:  A sub-step of `acquirep`, specifically the part without write barriers.
    * `releasep`, `releasepNoTrace`: Disassociating an `m` from a `p`.
    * `incidlelocked`: Incrementing a counter related to idle, locked `m`s.
    * `checkdead`: Detecting deadlock conditions.
    * `sysmon`: The system monitor goroutine.
    * `retake`:  Retaking `p`s that are blocked in syscalls or have been running for too long.
    * `preemptall`, `preemptone`: Requesting preemption of goroutines.
    * `schedtrace`:  Printing scheduling-related information.
    * `schedEnableUser`: Enabling/disabling scheduling of user goroutines.
    * `schedEnabled`: Checking if a goroutine should be scheduled.
    * `mput`, `mget`: Managing the list of idle `m`s.
    * `globrunqput`, `globrunqputhead`, `globrunqputbatch`, `globrunqget`: Managing the global run queue of goroutines.
    * `(*pMask).read`, `(*pMask).set`, `(*pMask).clear`: Operations on a bitmask for `p`s.
    * `pidleput`, `pidleget`, `pidlegetSpinning`: Managing the list of idle `p`s.

3. **Infer Go Feature Implementations:** Based on the function names and their internal logic, I can deduce the Go features being implemented:

    * **CPU Profiling:** `profilem` and `setcpuprofilerate` directly point to this. The code collects stack traces when profiling is enabled.
    * **Goroutine Scheduling:** The functions related to `p` and `m` management, run queues, and preemption are central to Go's scheduler.
    * **Dynamic GOMAXPROCS:** `procresize` handles changes to the number of OS threads Go can use.
    * **System Monitoring:** `sysmon` is a background goroutine responsible for tasks like network polling, retaking `p`s, and triggering garbage collection.
    * **Deadlock Detection:** `checkdead` analyzes the state of `m`s and `g`s to identify potential deadlocks.

4. **Provide Code Examples:** For the major features, I create simple Go code examples to illustrate how these features are used in practice. For CPU profiling, I show how to enable it and examine the output. For GOMAXPROCS, I demonstrate how to set it.

5. **Address Command-Line Arguments:** I review the functions for any direct interaction with command-line arguments. In this snippet, `setcpuprofilerate` takes a rate, but it's not directly tied to a command-line flag within this code. However, I know the `go test` and `go run` commands can control profiling, so I mention that. Similarly, GOMAXPROCS can be set via an environment variable.

6. **Identify Common Mistakes:** I think about common errors developers might make related to these features. For CPU profiling, forgetting to stop profiling is a classic one. For GOMAXPROCS, setting it too high or too low without understanding the implications is a potential issue.

7. **Address the "Part 6 of 7" Constraint:**  Since this is a specific part, I need to synthesize a higher-level understanding of the role of this code within the broader `runtime/proc.go` file and the Go runtime in general. This part primarily focuses on the core scheduling and processor management aspects.

8. **Structure the Answer:** I organize the information logically, starting with the function list, then delving into the inferred features with examples, argument handling, common mistakes, and finally the summary for Part 6. I use clear, concise language and format the code examples for readability.

9. **Refine and Review:** I reread my answer to ensure accuracy, completeness, and clarity. I check if I've addressed all aspects of the user's request and if the explanations are easy to understand for someone familiar with Go. For instance, I ensure the examples compile and illustrate the point effectively.

This iterative process of code analysis, feature inference, example creation, and contextualization allows me to provide a comprehensive and helpful answer to the user's request. The "Part 6 of 7" constraint pushes me to think about the broader context and how this specific section contributes to the overall functionality.
这是 `go/src/runtime/proc.go` 文件的一部分，主要负责 Go 运行时系统中 **处理器 (P) 和机器线程 (M) 的管理，以及与 Goroutine 调度相关的核心功能**。

这是第 6 部分，让我们归纳一下它的主要功能：

**核心功能归纳:**

1. **CPU 性能剖析 (Profiling):**
   - `profilem`:  核心的 CPU 性能剖析函数，当发生性能剖析信号时被调用，用于收集当前线程的堆栈信息，以便分析 CPU 使用情况。它处理 CGO 调用、libcall (Windows 系统调用) 和 VDSO 调用等不同情况下的堆栈收集。
   - `setcpuprofilerate`: 设置 CPU 性能剖析的采样频率。

2. **处理器 (P) 的生命周期管理:**
   - `(*p).init`: 初始化一个新的 P，将其状态设置为 `_Pgcstop`，并分配必要的资源，如 `mcache` (内存缓存)。
   - `(*p).destroy`: 销毁一个 P，将其状态设置为 `_Pdead`，并将 P 上运行队列中的 Goroutine 移到全局队列中，释放 P 占用的资源。
   - `procresize`: 动态调整 Go 程序可以使用的操作系统线程数量 (`GOMAXPROCS`)。它负责创建或销毁 P，并将可运行的 Goroutine 分发到不同的 P 上。

3. **P 和 M 的关联与分离:**
   - `acquirep`: 将一个 M 与一个 P 关联起来，使 M 可以执行该 P 上的 Goroutine。
   - `wirep`: `acquirep` 的第一步，执行实际的 M 和 P 关联，这个步骤不允许有写屏障。
   - `releasep`, `releasepNoTrace`: 将一个 M 与其关联的 P 分离。

4. **死锁检测:**
   - `checkdead`: 检测程序是否处于死锁状态。它通过检查运行中的 M 的数量来判断是否存在死锁。

5. **系统监控 (Sysmon):**
   - `sysmon`:  一个后台 Goroutine，负责执行一些周期性的系统监控任务，例如：
     - 网络轮询：检查是否有就绪的网络连接。
     - 从系统调用中回收 P：如果一个 P 在系统调用中阻塞太久，`sysmon` 会将其回收，以便其他 Goroutine 可以使用。
     - 抢占长时间运行的 Goroutine：强制长时间占用 CPU 的 Goroutine 让出 CPU。
     - 触发垃圾回收：如果距离上次垃圾回收的时间过长，`sysmon` 会触发一次垃圾回收。

6. **Goroutine 抢占:**
   - `retake`: `sysmon` 调用，用于回收在系统调用中阻塞的 P，并抢占长时间运行的 Goroutine。
   - `preemptall`:  通知所有正在运行的 Goroutine 应该停止（通常用于安全点操作）。
   - `preemptone`:  通知在指定 P 上运行的 Goroutine 停止。

7. **调度追踪:**
   - `schedtrace`:  打印当前的调度器状态信息，用于调试和性能分析。

8. **用户 Goroutine 调度控制:**
   - `schedEnableUser`: 启用或禁用用户 Goroutine 的调度。
   - `schedEnabled`:  检查一个 Goroutine 是否应该被调度。

9. **M 的管理:**
   - `mput`: 将一个 M 放到空闲 M 列表 (`midle`) 中。
   - `mget`: 从空闲 M 列表中获取一个 M。

10. **全局运行队列管理:**
    - `globrunqput`: 将一个 Goroutine 放到全局运行队列的尾部。
    - `globrunqputhead`: 将一个 Goroutine 放到全局运行队列的头部。
    - `globrunqputbatch`: 将一批 Goroutine 放到全局运行队列中。
    - `globrunqget`: 从全局运行队列中获取一批 Goroutine。

11. **空闲 P 的管理:**
    - `pidleput`: 将一个 P 放到空闲 P 列表 (`pidle`) 中。
    - `pidleget`: 从空闲 P 列表中获取一个 P。
    - `pidlegetSpinning`:  由自旋的 M 调用，尝试从空闲 P 列表中获取一个 P。

**可以推理出它是什么 Go 语言功能的实现：**

这部分代码是 **Go 运行时调度器 (Scheduler)** 的核心实现。它负责 Goroutine 的创建、执行和管理，以及 Go 程序与操作系统线程的交互。  通过这些函数，Go 运行时能够高效地将大量的 Goroutine 复用到少量的操作系统线程上，实现并发执行。

**Go 代码举例说明 (CPU 性能剖析):**

```go
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func worker() {
	for i := 0; i < 1000000; i++ {
		// 模拟一些计算密集型的工作
		_ = i * i
	}
}

func main() {
	// 创建 CPU 性能剖析文件
	f, err := os.Create("cpu.prof")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// 启动 CPU 性能剖析
	if err := pprof.StartCPUProfile(f); err != nil {
		panic(err)
	}
	defer pprof.StopCPUProfile()

	// 运行一些 Goroutine
	for i := 0; i < 4; i++ {
		go worker()
	}

	// 等待一段时间
	time.Sleep(5 * time.Second)

	fmt.Println("CPU profiling data written to cpu.prof")
}
```

**假设的输入与输出 (CPU 性能剖析):**

* **输入:** 运行上述 Go 代码。
* **输出:** 将会在当前目录下生成一个名为 `cpu.prof` 的文件，其中包含了 CPU 性能剖析的数据。可以使用 `go tool pprof cpu.prof` 命令来分析该文件，查看各个函数的 CPU 占用情况。

**命令行参数的具体处理:**

在提供的代码片段中，`setcpuprofilerate` 函数接受一个 `hz` 参数，表示每秒采样的次数。虽然这段代码本身不直接处理命令行参数，但 Go 语言提供了多种方式来控制 CPU 性能剖析，例如：

* **`go test -cpuprofile=cpu.prof`:** 在运行测试时启用 CPU 性能剖析。
* **`go run` 时使用 `runtime/pprof` 包:**  如上面的代码示例所示，程序可以通过 `runtime/pprof` 包中的函数来启动和停止 CPU 性能剖析。

**使用者易犯错的点 (CPU 性能剖析):**

* **忘记停止性能剖析:** 如果程序中启动了 CPU 性能剖析，但忘记调用 `pprof.StopCPUProfile()`，会导致性能剖析一直进行，可能会影响程序性能，并且生成非常大的性能剖析文件。

**总结：**

这段代码是 Go 运行时调度器的核心组成部分，负责管理处理器、线程以及 Goroutine 的调度和生命周期。它实现了 CPU 性能剖析、动态调整 `GOMAXPROCS`、死锁检测、系统监控以及 Goroutine 抢占等关键功能，是理解 Go 并发模型的基础。

Prompt: 
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第6部分，共7部分，请归纳一下它的功能

"""
may not even be stopped.
	// See golang.org/issue/17165.
	getg().m.mallocing++

	var u unwinder
	var stk [maxCPUProfStack]uintptr
	n := 0
	if mp.ncgo > 0 && mp.curg != nil && mp.curg.syscallpc != 0 && mp.curg.syscallsp != 0 {
		cgoOff := 0
		// Check cgoCallersUse to make sure that we are not
		// interrupting other code that is fiddling with
		// cgoCallers.  We are running in a signal handler
		// with all signals blocked, so we don't have to worry
		// about any other code interrupting us.
		if mp.cgoCallersUse.Load() == 0 && mp.cgoCallers != nil && mp.cgoCallers[0] != 0 {
			for cgoOff < len(mp.cgoCallers) && mp.cgoCallers[cgoOff] != 0 {
				cgoOff++
			}
			n += copy(stk[:], mp.cgoCallers[:cgoOff])
			mp.cgoCallers[0] = 0
		}

		// Collect Go stack that leads to the cgo call.
		u.initAt(mp.curg.syscallpc, mp.curg.syscallsp, 0, mp.curg, unwindSilentErrors)
	} else if usesLibcall() && mp.libcallg != 0 && mp.libcallpc != 0 && mp.libcallsp != 0 {
		// Libcall, i.e. runtime syscall on windows.
		// Collect Go stack that leads to the call.
		u.initAt(mp.libcallpc, mp.libcallsp, 0, mp.libcallg.ptr(), unwindSilentErrors)
	} else if mp != nil && mp.vdsoSP != 0 {
		// VDSO call, e.g. nanotime1 on Linux.
		// Collect Go stack that leads to the call.
		u.initAt(mp.vdsoPC, mp.vdsoSP, 0, gp, unwindSilentErrors|unwindJumpStack)
	} else {
		u.initAt(pc, sp, lr, gp, unwindSilentErrors|unwindTrap|unwindJumpStack)
	}
	n += tracebackPCs(&u, 0, stk[n:])

	if n <= 0 {
		// Normal traceback is impossible or has failed.
		// Account it against abstract "System" or "GC".
		n = 2
		if inVDSOPage(pc) {
			pc = abi.FuncPCABIInternal(_VDSO) + sys.PCQuantum
		} else if pc > firstmoduledata.etext {
			// "ExternalCode" is better than "etext".
			pc = abi.FuncPCABIInternal(_ExternalCode) + sys.PCQuantum
		}
		stk[0] = pc
		if mp.preemptoff != "" {
			stk[1] = abi.FuncPCABIInternal(_GC) + sys.PCQuantum
		} else {
			stk[1] = abi.FuncPCABIInternal(_System) + sys.PCQuantum
		}
	}

	if prof.hz.Load() != 0 {
		// Note: it can happen on Windows that we interrupted a system thread
		// with no g, so gp could nil. The other nil checks are done out of
		// caution, but not expected to be nil in practice.
		var tagPtr *unsafe.Pointer
		if gp != nil && gp.m != nil && gp.m.curg != nil {
			tagPtr = &gp.m.curg.labels
		}
		cpuprof.add(tagPtr, stk[:n])

		gprof := gp
		var mp *m
		var pp *p
		if gp != nil && gp.m != nil {
			if gp.m.curg != nil {
				gprof = gp.m.curg
			}
			mp = gp.m
			pp = gp.m.p.ptr()
		}
		traceCPUSample(gprof, mp, pp, stk[:n])
	}
	getg().m.mallocing--
}

// setcpuprofilerate sets the CPU profiling rate to hz times per second.
// If hz <= 0, setcpuprofilerate turns off CPU profiling.
func setcpuprofilerate(hz int32) {
	// Force sane arguments.
	if hz < 0 {
		hz = 0
	}

	// Disable preemption, otherwise we can be rescheduled to another thread
	// that has profiling enabled.
	gp := getg()
	gp.m.locks++

	// Stop profiler on this thread so that it is safe to lock prof.
	// if a profiling signal came in while we had prof locked,
	// it would deadlock.
	setThreadCPUProfiler(0)

	for !prof.signalLock.CompareAndSwap(0, 1) {
		osyield()
	}
	if prof.hz.Load() != hz {
		setProcessCPUProfiler(hz)
		prof.hz.Store(hz)
	}
	prof.signalLock.Store(0)

	lock(&sched.lock)
	sched.profilehz = hz
	unlock(&sched.lock)

	if hz != 0 {
		setThreadCPUProfiler(hz)
	}

	gp.m.locks--
}

// init initializes pp, which may be a freshly allocated p or a
// previously destroyed p, and transitions it to status _Pgcstop.
func (pp *p) init(id int32) {
	pp.id = id
	pp.status = _Pgcstop
	pp.sudogcache = pp.sudogbuf[:0]
	pp.deferpool = pp.deferpoolbuf[:0]
	pp.wbBuf.reset()
	if pp.mcache == nil {
		if id == 0 {
			if mcache0 == nil {
				throw("missing mcache?")
			}
			// Use the bootstrap mcache0. Only one P will get
			// mcache0: the one with ID 0.
			pp.mcache = mcache0
		} else {
			pp.mcache = allocmcache()
		}
	}
	if raceenabled && pp.raceprocctx == 0 {
		if id == 0 {
			pp.raceprocctx = raceprocctx0
			raceprocctx0 = 0 // bootstrap
		} else {
			pp.raceprocctx = raceproccreate()
		}
	}
	lockInit(&pp.timers.mu, lockRankTimers)

	// This P may get timers when it starts running. Set the mask here
	// since the P may not go through pidleget (notably P 0 on startup).
	timerpMask.set(id)
	// Similarly, we may not go through pidleget before this P starts
	// running if it is P 0 on startup.
	idlepMask.clear(id)
}

// destroy releases all of the resources associated with pp and
// transitions it to status _Pdead.
//
// sched.lock must be held and the world must be stopped.
func (pp *p) destroy() {
	assertLockHeld(&sched.lock)
	assertWorldStopped()

	// Move all runnable goroutines to the global queue
	for pp.runqhead != pp.runqtail {
		// Pop from tail of local queue
		pp.runqtail--
		gp := pp.runq[pp.runqtail%uint32(len(pp.runq))].ptr()
		// Push onto head of global queue
		globrunqputhead(gp)
	}
	if pp.runnext != 0 {
		globrunqputhead(pp.runnext.ptr())
		pp.runnext = 0
	}

	// Move all timers to the local P.
	getg().m.p.ptr().timers.take(&pp.timers)

	// Flush p's write barrier buffer.
	if gcphase != _GCoff {
		wbBufFlush1(pp)
		pp.gcw.dispose()
	}
	for i := range pp.sudogbuf {
		pp.sudogbuf[i] = nil
	}
	pp.sudogcache = pp.sudogbuf[:0]
	pp.pinnerCache = nil
	for j := range pp.deferpoolbuf {
		pp.deferpoolbuf[j] = nil
	}
	pp.deferpool = pp.deferpoolbuf[:0]
	systemstack(func() {
		for i := 0; i < pp.mspancache.len; i++ {
			// Safe to call since the world is stopped.
			mheap_.spanalloc.free(unsafe.Pointer(pp.mspancache.buf[i]))
		}
		pp.mspancache.len = 0
		lock(&mheap_.lock)
		pp.pcache.flush(&mheap_.pages)
		unlock(&mheap_.lock)
	})
	freemcache(pp.mcache)
	pp.mcache = nil
	gfpurge(pp)
	if raceenabled {
		if pp.timers.raceCtx != 0 {
			// The race detector code uses a callback to fetch
			// the proc context, so arrange for that callback
			// to see the right thing.
			// This hack only works because we are the only
			// thread running.
			mp := getg().m
			phold := mp.p.ptr()
			mp.p.set(pp)

			racectxend(pp.timers.raceCtx)
			pp.timers.raceCtx = 0

			mp.p.set(phold)
		}
		raceprocdestroy(pp.raceprocctx)
		pp.raceprocctx = 0
	}
	pp.gcAssistTime = 0
	pp.status = _Pdead
}

// Change number of processors.
//
// sched.lock must be held, and the world must be stopped.
//
// gcworkbufs must not be being modified by either the GC or the write barrier
// code, so the GC must not be running if the number of Ps actually changes.
//
// Returns list of Ps with local work, they need to be scheduled by the caller.
func procresize(nprocs int32) *p {
	assertLockHeld(&sched.lock)
	assertWorldStopped()

	old := gomaxprocs
	if old < 0 || nprocs <= 0 {
		throw("procresize: invalid arg")
	}
	trace := traceAcquire()
	if trace.ok() {
		trace.Gomaxprocs(nprocs)
		traceRelease(trace)
	}

	// update statistics
	now := nanotime()
	if sched.procresizetime != 0 {
		sched.totaltime += int64(old) * (now - sched.procresizetime)
	}
	sched.procresizetime = now

	maskWords := (nprocs + 31) / 32

	// Grow allp if necessary.
	if nprocs > int32(len(allp)) {
		// Synchronize with retake, which could be running
		// concurrently since it doesn't run on a P.
		lock(&allpLock)
		if nprocs <= int32(cap(allp)) {
			allp = allp[:nprocs]
		} else {
			nallp := make([]*p, nprocs)
			// Copy everything up to allp's cap so we
			// never lose old allocated Ps.
			copy(nallp, allp[:cap(allp)])
			allp = nallp
		}

		if maskWords <= int32(cap(idlepMask)) {
			idlepMask = idlepMask[:maskWords]
			timerpMask = timerpMask[:maskWords]
		} else {
			nidlepMask := make([]uint32, maskWords)
			// No need to copy beyond len, old Ps are irrelevant.
			copy(nidlepMask, idlepMask)
			idlepMask = nidlepMask

			ntimerpMask := make([]uint32, maskWords)
			copy(ntimerpMask, timerpMask)
			timerpMask = ntimerpMask
		}
		unlock(&allpLock)
	}

	// initialize new P's
	for i := old; i < nprocs; i++ {
		pp := allp[i]
		if pp == nil {
			pp = new(p)
		}
		pp.init(i)
		atomicstorep(unsafe.Pointer(&allp[i]), unsafe.Pointer(pp))
	}

	gp := getg()
	if gp.m.p != 0 && gp.m.p.ptr().id < nprocs {
		// continue to use the current P
		gp.m.p.ptr().status = _Prunning
		gp.m.p.ptr().mcache.prepareForSweep()
	} else {
		// release the current P and acquire allp[0].
		//
		// We must do this before destroying our current P
		// because p.destroy itself has write barriers, so we
		// need to do that from a valid P.
		if gp.m.p != 0 {
			trace := traceAcquire()
			if trace.ok() {
				// Pretend that we were descheduled
				// and then scheduled again to keep
				// the trace consistent.
				trace.GoSched()
				trace.ProcStop(gp.m.p.ptr())
				traceRelease(trace)
			}
			gp.m.p.ptr().m = 0
		}
		gp.m.p = 0
		pp := allp[0]
		pp.m = 0
		pp.status = _Pidle
		acquirep(pp)
		trace := traceAcquire()
		if trace.ok() {
			trace.GoStart()
			traceRelease(trace)
		}
	}

	// g.m.p is now set, so we no longer need mcache0 for bootstrapping.
	mcache0 = nil

	// release resources from unused P's
	for i := nprocs; i < old; i++ {
		pp := allp[i]
		pp.destroy()
		// can't free P itself because it can be referenced by an M in syscall
	}

	// Trim allp.
	if int32(len(allp)) != nprocs {
		lock(&allpLock)
		allp = allp[:nprocs]
		idlepMask = idlepMask[:maskWords]
		timerpMask = timerpMask[:maskWords]
		unlock(&allpLock)
	}

	var runnablePs *p
	for i := nprocs - 1; i >= 0; i-- {
		pp := allp[i]
		if gp.m.p.ptr() == pp {
			continue
		}
		pp.status = _Pidle
		if runqempty(pp) {
			pidleput(pp, now)
		} else {
			pp.m.set(mget())
			pp.link.set(runnablePs)
			runnablePs = pp
		}
	}
	stealOrder.reset(uint32(nprocs))
	var int32p *int32 = &gomaxprocs // make compiler check that gomaxprocs is an int32
	atomic.Store((*uint32)(unsafe.Pointer(int32p)), uint32(nprocs))
	if old != nprocs {
		// Notify the limiter that the amount of procs has changed.
		gcCPULimiter.resetCapacity(now, nprocs)
	}
	return runnablePs
}

// Associate p and the current m.
//
// This function is allowed to have write barriers even if the caller
// isn't because it immediately acquires pp.
//
//go:yeswritebarrierrec
func acquirep(pp *p) {
	// Do the part that isn't allowed to have write barriers.
	wirep(pp)

	// Have p; write barriers now allowed.

	// Perform deferred mcache flush before this P can allocate
	// from a potentially stale mcache.
	pp.mcache.prepareForSweep()

	trace := traceAcquire()
	if trace.ok() {
		trace.ProcStart()
		traceRelease(trace)
	}
}

// wirep is the first step of acquirep, which actually associates the
// current M to pp. This is broken out so we can disallow write
// barriers for this part, since we don't yet have a P.
//
//go:nowritebarrierrec
//go:nosplit
func wirep(pp *p) {
	gp := getg()

	if gp.m.p != 0 {
		// Call on the systemstack to avoid a nosplit overflow build failure
		// on some platforms when built with -N -l. See #64113.
		systemstack(func() {
			throw("wirep: already in go")
		})
	}
	if pp.m != 0 || pp.status != _Pidle {
		// Call on the systemstack to avoid a nosplit overflow build failure
		// on some platforms when built with -N -l. See #64113.
		systemstack(func() {
			id := int64(0)
			if pp.m != 0 {
				id = pp.m.ptr().id
			}
			print("wirep: p->m=", pp.m, "(", id, ") p->status=", pp.status, "\n")
			throw("wirep: invalid p state")
		})
	}
	gp.m.p.set(pp)
	pp.m.set(gp.m)
	pp.status = _Prunning
}

// Disassociate p and the current m.
func releasep() *p {
	trace := traceAcquire()
	if trace.ok() {
		trace.ProcStop(getg().m.p.ptr())
		traceRelease(trace)
	}
	return releasepNoTrace()
}

// Disassociate p and the current m without tracing an event.
func releasepNoTrace() *p {
	gp := getg()

	if gp.m.p == 0 {
		throw("releasep: invalid arg")
	}
	pp := gp.m.p.ptr()
	if pp.m.ptr() != gp.m || pp.status != _Prunning {
		print("releasep: m=", gp.m, " m->p=", gp.m.p.ptr(), " p->m=", hex(pp.m), " p->status=", pp.status, "\n")
		throw("releasep: invalid p state")
	}
	gp.m.p = 0
	pp.m = 0
	pp.status = _Pidle
	return pp
}

func incidlelocked(v int32) {
	lock(&sched.lock)
	sched.nmidlelocked += v
	if v > 0 {
		checkdead()
	}
	unlock(&sched.lock)
}

// Check for deadlock situation.
// The check is based on number of running M's, if 0 -> deadlock.
// sched.lock must be held.
func checkdead() {
	assertLockHeld(&sched.lock)

	// For -buildmode=c-shared or -buildmode=c-archive it's OK if
	// there are no running goroutines. The calling program is
	// assumed to be running.
	// One exception is Wasm, which is single-threaded. If we are
	// in Go and all goroutines are blocked, it deadlocks.
	if (islibrary || isarchive) && GOARCH != "wasm" {
		return
	}

	// If we are dying because of a signal caught on an already idle thread,
	// freezetheworld will cause all running threads to block.
	// And runtime will essentially enter into deadlock state,
	// except that there is a thread that will call exit soon.
	if panicking.Load() > 0 {
		return
	}

	// If we are not running under cgo, but we have an extra M then account
	// for it. (It is possible to have an extra M on Windows without cgo to
	// accommodate callbacks created by syscall.NewCallback. See issue #6751
	// for details.)
	var run0 int32
	if !iscgo && cgoHasExtraM && extraMLength.Load() > 0 {
		run0 = 1
	}

	run := mcount() - sched.nmidle - sched.nmidlelocked - sched.nmsys
	if run > run0 {
		return
	}
	if run < 0 {
		print("runtime: checkdead: nmidle=", sched.nmidle, " nmidlelocked=", sched.nmidlelocked, " mcount=", mcount(), " nmsys=", sched.nmsys, "\n")
		unlock(&sched.lock)
		throw("checkdead: inconsistent counts")
	}

	grunning := 0
	forEachG(func(gp *g) {
		if isSystemGoroutine(gp, false) {
			return
		}
		s := readgstatus(gp)
		switch s &^ _Gscan {
		case _Gwaiting,
			_Gpreempted:
			grunning++
		case _Grunnable,
			_Grunning,
			_Gsyscall:
			print("runtime: checkdead: find g ", gp.goid, " in status ", s, "\n")
			unlock(&sched.lock)
			throw("checkdead: runnable g")
		}
	})
	if grunning == 0 { // possible if main goroutine calls runtime·Goexit()
		unlock(&sched.lock) // unlock so that GODEBUG=scheddetail=1 doesn't hang
		fatal("no goroutines (main called runtime.Goexit) - deadlock!")
	}

	// Maybe jump time forward for playground.
	if faketime != 0 {
		if when := timeSleepUntil(); when < maxWhen {
			faketime = when

			// Start an M to steal the timer.
			pp, _ := pidleget(faketime)
			if pp == nil {
				// There should always be a free P since
				// nothing is running.
				unlock(&sched.lock)
				throw("checkdead: no p for timer")
			}
			mp := mget()
			if mp == nil {
				// There should always be a free M since
				// nothing is running.
				unlock(&sched.lock)
				throw("checkdead: no m for timer")
			}
			// M must be spinning to steal. We set this to be
			// explicit, but since this is the only M it would
			// become spinning on its own anyways.
			sched.nmspinning.Add(1)
			mp.spinning = true
			mp.nextp.set(pp)
			notewakeup(&mp.park)
			return
		}
	}

	// There are no goroutines running, so we can look at the P's.
	for _, pp := range allp {
		if len(pp.timers.heap) > 0 {
			return
		}
	}

	unlock(&sched.lock) // unlock so that GODEBUG=scheddetail=1 doesn't hang
	fatal("all goroutines are asleep - deadlock!")
}

// forcegcperiod is the maximum time in nanoseconds between garbage
// collections. If we go this long without a garbage collection, one
// is forced to run.
//
// This is a variable for testing purposes. It normally doesn't change.
var forcegcperiod int64 = 2 * 60 * 1e9

// needSysmonWorkaround is true if the workaround for
// golang.org/issue/42515 is needed on NetBSD.
var needSysmonWorkaround bool = false

// haveSysmon indicates whether there is sysmon thread support.
//
// No threads on wasm yet, so no sysmon.
const haveSysmon = GOARCH != "wasm"

// Always runs without a P, so write barriers are not allowed.
//
//go:nowritebarrierrec
func sysmon() {
	lock(&sched.lock)
	sched.nmsys++
	checkdead()
	unlock(&sched.lock)

	lasttrace := int64(0)
	idle := 0 // how many cycles in succession we had not wokeup somebody
	delay := uint32(0)

	for {
		if idle == 0 { // start with 20us sleep...
			delay = 20
		} else if idle > 50 { // start doubling the sleep after 1ms...
			delay *= 2
		}
		if delay > 10*1000 { // up to 10ms
			delay = 10 * 1000
		}
		usleep(delay)

		// sysmon should not enter deep sleep if schedtrace is enabled so that
		// it can print that information at the right time.
		//
		// It should also not enter deep sleep if there are any active P's so
		// that it can retake P's from syscalls, preempt long running G's, and
		// poll the network if all P's are busy for long stretches.
		//
		// It should wakeup from deep sleep if any P's become active either due
		// to exiting a syscall or waking up due to a timer expiring so that it
		// can resume performing those duties. If it wakes from a syscall it
		// resets idle and delay as a bet that since it had retaken a P from a
		// syscall before, it may need to do it again shortly after the
		// application starts work again. It does not reset idle when waking
		// from a timer to avoid adding system load to applications that spend
		// most of their time sleeping.
		now := nanotime()
		if debug.schedtrace <= 0 && (sched.gcwaiting.Load() || sched.npidle.Load() == gomaxprocs) {
			lock(&sched.lock)
			if sched.gcwaiting.Load() || sched.npidle.Load() == gomaxprocs {
				syscallWake := false
				next := timeSleepUntil()
				if next > now {
					sched.sysmonwait.Store(true)
					unlock(&sched.lock)
					// Make wake-up period small enough
					// for the sampling to be correct.
					sleep := forcegcperiod / 2
					if next-now < sleep {
						sleep = next - now
					}
					shouldRelax := sleep >= osRelaxMinNS
					if shouldRelax {
						osRelax(true)
					}
					syscallWake = notetsleep(&sched.sysmonnote, sleep)
					if shouldRelax {
						osRelax(false)
					}
					lock(&sched.lock)
					sched.sysmonwait.Store(false)
					noteclear(&sched.sysmonnote)
				}
				if syscallWake {
					idle = 0
					delay = 20
				}
			}
			unlock(&sched.lock)
		}

		lock(&sched.sysmonlock)
		// Update now in case we blocked on sysmonnote or spent a long time
		// blocked on schedlock or sysmonlock above.
		now = nanotime()

		// trigger libc interceptors if needed
		if *cgo_yield != nil {
			asmcgocall(*cgo_yield, nil)
		}
		// poll network if not polled for more than 10ms
		lastpoll := sched.lastpoll.Load()
		if netpollinited() && lastpoll != 0 && lastpoll+10*1000*1000 < now {
			sched.lastpoll.CompareAndSwap(lastpoll, now)
			list, delta := netpoll(0) // non-blocking - returns list of goroutines
			if !list.empty() {
				// Need to decrement number of idle locked M's
				// (pretending that one more is running) before injectglist.
				// Otherwise it can lead to the following situation:
				// injectglist grabs all P's but before it starts M's to run the P's,
				// another M returns from syscall, finishes running its G,
				// observes that there is no work to do and no other running M's
				// and reports deadlock.
				incidlelocked(-1)
				injectglist(&list)
				incidlelocked(1)
				netpollAdjustWaiters(delta)
			}
		}
		if GOOS == "netbsd" && needSysmonWorkaround {
			// netpoll is responsible for waiting for timer
			// expiration, so we typically don't have to worry
			// about starting an M to service timers. (Note that
			// sleep for timeSleepUntil above simply ensures sysmon
			// starts running again when that timer expiration may
			// cause Go code to run again).
			//
			// However, netbsd has a kernel bug that sometimes
			// misses netpollBreak wake-ups, which can lead to
			// unbounded delays servicing timers. If we detect this
			// overrun, then startm to get something to handle the
			// timer.
			//
			// See issue 42515 and
			// https://gnats.netbsd.org/cgi-bin/query-pr-single.pl?number=50094.
			if next := timeSleepUntil(); next < now {
				startm(nil, false, false)
			}
		}
		if scavenger.sysmonWake.Load() != 0 {
			// Kick the scavenger awake if someone requested it.
			scavenger.wake()
		}
		// retake P's blocked in syscalls
		// and preempt long running G's
		if retake(now) != 0 {
			idle = 0
		} else {
			idle++
		}
		// check if we need to force a GC
		if t := (gcTrigger{kind: gcTriggerTime, now: now}); t.test() && forcegc.idle.Load() {
			lock(&forcegc.lock)
			forcegc.idle.Store(false)
			var list gList
			list.push(forcegc.g)
			injectglist(&list)
			unlock(&forcegc.lock)
		}
		if debug.schedtrace > 0 && lasttrace+int64(debug.schedtrace)*1000000 <= now {
			lasttrace = now
			schedtrace(debug.scheddetail > 0)
		}
		unlock(&sched.sysmonlock)
	}
}

type sysmontick struct {
	schedtick   uint32
	syscalltick uint32
	schedwhen   int64
	syscallwhen int64
}

// forcePreemptNS is the time slice given to a G before it is
// preempted.
const forcePreemptNS = 10 * 1000 * 1000 // 10ms

func retake(now int64) uint32 {
	n := 0
	// Prevent allp slice changes. This lock will be completely
	// uncontended unless we're already stopping the world.
	lock(&allpLock)
	// We can't use a range loop over allp because we may
	// temporarily drop the allpLock. Hence, we need to re-fetch
	// allp each time around the loop.
	for i := 0; i < len(allp); i++ {
		pp := allp[i]
		if pp == nil {
			// This can happen if procresize has grown
			// allp but not yet created new Ps.
			continue
		}
		pd := &pp.sysmontick
		s := pp.status
		sysretake := false
		if s == _Prunning || s == _Psyscall {
			// Preempt G if it's running on the same schedtick for
			// too long. This could be from a single long-running
			// goroutine or a sequence of goroutines run via
			// runnext, which share a single schedtick time slice.
			t := int64(pp.schedtick)
			if int64(pd.schedtick) != t {
				pd.schedtick = uint32(t)
				pd.schedwhen = now
			} else if pd.schedwhen+forcePreemptNS <= now {
				preemptone(pp)
				// In case of syscall, preemptone() doesn't
				// work, because there is no M wired to P.
				sysretake = true
			}
		}
		if s == _Psyscall {
			// Retake P from syscall if it's there for more than 1 sysmon tick (at least 20us).
			t := int64(pp.syscalltick)
			if !sysretake && int64(pd.syscalltick) != t {
				pd.syscalltick = uint32(t)
				pd.syscallwhen = now
				continue
			}
			// On the one hand we don't want to retake Ps if there is no other work to do,
			// but on the other hand we want to retake them eventually
			// because they can prevent the sysmon thread from deep sleep.
			if runqempty(pp) && sched.nmspinning.Load()+sched.npidle.Load() > 0 && pd.syscallwhen+10*1000*1000 > now {
				continue
			}
			// Drop allpLock so we can take sched.lock.
			unlock(&allpLock)
			// Need to decrement number of idle locked M's
			// (pretending that one more is running) before the CAS.
			// Otherwise the M from which we retake can exit the syscall,
			// increment nmidle and report deadlock.
			incidlelocked(-1)
			trace := traceAcquire()
			if atomic.Cas(&pp.status, s, _Pidle) {
				if trace.ok() {
					trace.ProcSteal(pp, false)
					traceRelease(trace)
				}
				n++
				pp.syscalltick++
				handoffp(pp)
			} else if trace.ok() {
				traceRelease(trace)
			}
			incidlelocked(1)
			lock(&allpLock)
		}
	}
	unlock(&allpLock)
	return uint32(n)
}

// Tell all goroutines that they have been preempted and they should stop.
// This function is purely best-effort. It can fail to inform a goroutine if a
// processor just started running it.
// No locks need to be held.
// Returns true if preemption request was issued to at least one goroutine.
func preemptall() bool {
	res := false
	for _, pp := range allp {
		if pp.status != _Prunning {
			continue
		}
		if preemptone(pp) {
			res = true
		}
	}
	return res
}

// Tell the goroutine running on processor P to stop.
// This function is purely best-effort. It can incorrectly fail to inform the
// goroutine. It can inform the wrong goroutine. Even if it informs the
// correct goroutine, that goroutine might ignore the request if it is
// simultaneously executing newstack.
// No lock needs to be held.
// Returns true if preemption request was issued.
// The actual preemption will happen at some point in the future
// and will be indicated by the gp->status no longer being
// Grunning
func preemptone(pp *p) bool {
	mp := pp.m.ptr()
	if mp == nil || mp == getg().m {
		return false
	}
	gp := mp.curg
	if gp == nil || gp == mp.g0 {
		return false
	}

	gp.preempt = true

	// Every call in a goroutine checks for stack overflow by
	// comparing the current stack pointer to gp->stackguard0.
	// Setting gp->stackguard0 to StackPreempt folds
	// preemption into the normal stack overflow check.
	gp.stackguard0 = stackPreempt

	// Request an async preemption of this P.
	if preemptMSupported && debug.asyncpreemptoff == 0 {
		pp.preempt = true
		preemptM(mp)
	}

	return true
}

var starttime int64

func schedtrace(detailed bool) {
	now := nanotime()
	if starttime == 0 {
		starttime = now
	}

	lock(&sched.lock)
	print("SCHED ", (now-starttime)/1e6, "ms: gomaxprocs=", gomaxprocs, " idleprocs=", sched.npidle.Load(), " threads=", mcount(), " spinningthreads=", sched.nmspinning.Load(), " needspinning=", sched.needspinning.Load(), " idlethreads=", sched.nmidle, " runqueue=", sched.runqsize)
	if detailed {
		print(" gcwaiting=", sched.gcwaiting.Load(), " nmidlelocked=", sched.nmidlelocked, " stopwait=", sched.stopwait, " sysmonwait=", sched.sysmonwait.Load(), "\n")
	}
	// We must be careful while reading data from P's, M's and G's.
	// Even if we hold schedlock, most data can be changed concurrently.
	// E.g. (p->m ? p->m->id : -1) can crash if p->m changes from non-nil to nil.
	for i, pp := range allp {
		mp := pp.m.ptr()
		h := atomic.Load(&pp.runqhead)
		t := atomic.Load(&pp.runqtail)
		if detailed {
			print("  P", i, ": status=", pp.status, " schedtick=", pp.schedtick, " syscalltick=", pp.syscalltick, " m=")
			if mp != nil {
				print(mp.id)
			} else {
				print("nil")
			}
			print(" runqsize=", t-h, " gfreecnt=", pp.gFree.n, " timerslen=", len(pp.timers.heap), "\n")
		} else {
			// In non-detailed mode format lengths of per-P run queues as:
			// [len1 len2 len3 len4]
			print(" ")
			if i == 0 {
				print("[")
			}
			print(t - h)
			if i == len(allp)-1 {
				print("]\n")
			}
		}
	}

	if !detailed {
		unlock(&sched.lock)
		return
	}

	for mp := allm; mp != nil; mp = mp.alllink {
		pp := mp.p.ptr()
		print("  M", mp.id, ": p=")
		if pp != nil {
			print(pp.id)
		} else {
			print("nil")
		}
		print(" curg=")
		if mp.curg != nil {
			print(mp.curg.goid)
		} else {
			print("nil")
		}
		print(" mallocing=", mp.mallocing, " throwing=", mp.throwing, " preemptoff=", mp.preemptoff, " locks=", mp.locks, " dying=", mp.dying, " spinning=", mp.spinning, " blocked=", mp.blocked, " lockedg=")
		if lockedg := mp.lockedg.ptr(); lockedg != nil {
			print(lockedg.goid)
		} else {
			print("nil")
		}
		print("\n")
	}

	forEachG(func(gp *g) {
		print("  G", gp.goid, ": status=", readgstatus(gp), "(", gp.waitreason.String(), ") m=")
		if gp.m != nil {
			print(gp.m.id)
		} else {
			print("nil")
		}
		print(" lockedm=")
		if lockedm := gp.lockedm.ptr(); lockedm != nil {
			print(lockedm.id)
		} else {
			print("nil")
		}
		print("\n")
	})
	unlock(&sched.lock)
}

// schedEnableUser enables or disables the scheduling of user
// goroutines.
//
// This does not stop already running user goroutines, so the caller
// should first stop the world when disabling user goroutines.
func schedEnableUser(enable bool) {
	lock(&sched.lock)
	if sched.disable.user == !enable {
		unlock(&sched.lock)
		return
	}
	sched.disable.user = !enable
	if enable {
		n := sched.disable.n
		sched.disable.n = 0
		globrunqputbatch(&sched.disable.runnable, n)
		unlock(&sched.lock)
		for ; n != 0 && sched.npidle.Load() != 0; n-- {
			startm(nil, false, false)
		}
	} else {
		unlock(&sched.lock)
	}
}

// schedEnabled reports whether gp should be scheduled. It returns
// false is scheduling of gp is disabled.
//
// sched.lock must be held.
func schedEnabled(gp *g) bool {
	assertLockHeld(&sched.lock)

	if sched.disable.user {
		return isSystemGoroutine(gp, true)
	}
	return true
}

// Put mp on midle list.
// sched.lock must be held.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func mput(mp *m) {
	assertLockHeld(&sched.lock)

	mp.schedlink = sched.midle
	sched.midle.set(mp)
	sched.nmidle++
	checkdead()
}

// Try to get an m from midle list.
// sched.lock must be held.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func mget() *m {
	assertLockHeld(&sched.lock)

	mp := sched.midle.ptr()
	if mp != nil {
		sched.midle = mp.schedlink
		sched.nmidle--
	}
	return mp
}

// Put gp on the global runnable queue.
// sched.lock must be held.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func globrunqput(gp *g) {
	assertLockHeld(&sched.lock)

	sched.runq.pushBack(gp)
	sched.runqsize++
}

// Put gp at the head of the global runnable queue.
// sched.lock must be held.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func globrunqputhead(gp *g) {
	assertLockHeld(&sched.lock)

	sched.runq.push(gp)
	sched.runqsize++
}

// Put a batch of runnable goroutines on the global runnable queue.
// This clears *batch.
// sched.lock must be held.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func globrunqputbatch(batch *gQueue, n int32) {
	assertLockHeld(&sched.lock)

	sched.runq.pushBackAll(*batch)
	sched.runqsize += n
	*batch = gQueue{}
}

// Try get a batch of G's from the global runnable queue.
// sched.lock must be held.
func globrunqget(pp *p, max int32) *g {
	assertLockHeld(&sched.lock)

	if sched.runqsize == 0 {
		return nil
	}

	n := sched.runqsize/gomaxprocs + 1
	if n > sched.runqsize {
		n = sched.runqsize
	}
	if max > 0 && n > max {
		n = max
	}
	if n > int32(len(pp.runq))/2 {
		n = int32(len(pp.runq)) / 2
	}

	sched.runqsize -= n

	gp := sched.runq.pop()
	n--
	for ; n > 0; n-- {
		gp1 := sched.runq.pop()
		runqput(pp, gp1, false)
	}
	return gp
}

// pMask is an atomic bitstring with one bit per P.
type pMask []uint32

// read returns true if P id's bit is set.
func (p pMask) read(id uint32) bool {
	word := id / 32
	mask := uint32(1) << (id % 32)
	return (atomic.Load(&p[word]) & mask) != 0
}

// set sets P id's bit.
func (p pMask) set(id int32) {
	word := id / 32
	mask := uint32(1) << (id % 32)
	atomic.Or(&p[word], mask)
}

// clear clears P id's bit.
func (p pMask) clear(id int32) {
	word := id / 32
	mask := uint32(1) << (id % 32)
	atomic.And(&p[word], ^mask)
}

// pidleput puts p on the _Pidle list. now must be a relatively recent call
// to nanotime or zero. Returns now or the current time if now was zero.
//
// This releases ownership of p. Once sched.lock is released it is no longer
// safe to use p.
//
// sched.lock must be held.
//
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func pidleput(pp *p, now int64) int64 {
	assertLockHeld(&sched.lock)

	if !runqempty(pp) {
		throw("pidleput: P has non-empty run queue")
	}
	if now == 0 {
		now = nanotime()
	}
	if pp.timers.len.Load() == 0 {
		timerpMask.clear(pp.id)
	}
	idlepMask.set(pp.id)
	pp.link = sched.pidle
	sched.pidle.set(pp)
	sched.npidle.Add(1)
	if !pp.limiterEvent.start(limiterEventIdle, now) {
		throw("must be able to track idle limiter event")
	}
	return now
}

// pidleget tries to get a p from the _Pidle list, acquiring ownership.
//
// sched.lock must be held.
//
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func pidleget(now int64) (*p, int64) {
	assertLockHeld(&sched.lock)

	pp := sched.pidle.ptr()
	if pp != nil {
		// Timer may get added at any time now.
		if now == 0 {
			now = nanotime()
		}
		timerpMask.set(pp.id)
		idlepMask.clear(pp.id)
		sched.pidle = pp.link
		sched.npidle.Add(-1)
		pp.limiterEvent.stop(limiterEventIdle, now)
	}
	return pp, now
}

// pidlegetSpinning tries to get a p from the _Pidle list, acquiring ownership.
// This is called by spinning Ms (or callers than need a spinning M) that have
// found work. If no P is available, this must synchronized with non-spinning
// Ms that may be preparing to drop their P without discovering this work.
//
// sched.lock must be held.
//
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func pidlegetSpinning(now int64) (*p, int64) {
	assertLockHeld(&sched.lock)

	pp, now := pidleget(now)
	if pp == nil {
		// See "Delicate dance" comment in findrunnable. We found work
		// that we cannot take, we must synchronize with non-spinning
		// Ms that may be preparing to drop their P.
		sched.needspinning.Store(1)
		return nil, now
	}

"""




```