Response:
Let's break down the thought process for analyzing this Go code snippet from `runtime/proc.go`.

1. **Understanding the Request:** The core request is to analyze a specific part of `runtime/proc.go` and explain its functionality, infer broader Go features, provide examples, and point out potential pitfalls. It's also specified that this is part 4 of 7, suggesting there's a larger context, but we need to focus on the provided snippet.

2. **Initial Scan and Keyword Identification:**  Read through the code, looking for prominent keywords and function names. Key terms that jump out include: `stopm`, `gcstopm`, `execute`, `findRunnable`, `stealWork`, `schedule`, `dropg`, `park_m`, `gosched_m`, `goyield_m`, `goexit1`, `goexit0`, `preemptPark`. These immediately suggest the code is related to goroutine and thread management, scheduling, garbage collection interactions, and stopping/starting the world.

3. **Function-by-Function Analysis:**  Go through each function, trying to understand its local purpose.

    * **`stopm()`:**  This looks like it's about pausing the current M (OS thread). The comments confirm this. The `notewakeup` hints at a synchronization mechanism.

    * **`gcstopm()`:** Similar to `stopm`, but specifically for garbage collection. The checks for `sched.gcwaiting` confirm this. The interaction with `sched.lock` and `sched.stopnote` is important.

    * **`execute(gp *g, inheritTime bool)`:** This function clearly puts a goroutine `gp` onto the current M to run. The setting of `gp.m`, `casgstatus`, and `gogo` (likely a low-level context switch) are crucial.

    * **`findRunnable()`:**  This is the heart of the scheduler. It searches for a goroutine to run, checking various sources like local/global run queues, network polling, and stealing from other Ps. The numerous `if` conditions and calls to other functions (like `gcstopm`, `traceReader`, `stealWork`, `netpoll`) indicate its complexity.

    * **`stealWork()`:**  As the name suggests, this is about a P trying to take work from another P's run queue or timers. The nested loops and calls to `runqsteal` are key.

    * **`checkRunqsNoP()` and `checkTimersNoP()`:**  These seem like specialized helper functions for `findRunnable` when a P isn't currently held. They iterate through Ps to find runnable goroutines or expiring timers.

    * **`checkIdleGCNoP()`:**  Specifically handles finding idle GC work when no P is held.

    * **`wakeNetPoller()`:**  Deals with waking up the network poller thread for handling I/O events.

    * **`resetspinning()`:**  Manages the state of "spinning" Ms, which are actively looking for work.

    * **`injectglist()`:**  Takes a list of runnable goroutines and adds them to appropriate run queues, potentially waking up idle Ps.

    * **`schedule()`:** The main scheduling loop. It calls `findRunnable` and then executes the chosen goroutine. It also handles locked goroutines and checks for spinning Ms.

    * **`dropg()`:**  Detaches the current goroutine from the current M.

    * **`park_m()`:**  The core of the `park` operation, putting a goroutine to sleep, often waiting for a specific condition. The `waitunlockf` mechanism is important for synchronization primitives.

    * **`goschedImpl()` (and `gosched_m`, `goschedguarded_m`):** Implement `runtime.Gosched()`, voluntarily yielding the CPU. The tracing and putting the goroutine on the global run queue are key aspects.

    * **`gopreempt_m()` and `preemptPark()`:** Handle goroutine preemption, forcibly pausing a running goroutine.

    * **`goyield()` and `goyield_m()`:** Similar to `Gosched` but puts the goroutine on the local run queue.

    * **`goexit1()` and `goexit0()`:**  Handle goroutine termination.

    * **`gdestroy()`:** Cleans up the resources associated with a terminated goroutine.

4. **Inferring Go Features:** Based on the function analysis, several Go concurrency and runtime features become apparent:

    * **Goroutines:** The core concept being managed.
    * **M (OS Threads):**  The execution units for goroutines.
    * **P (Processor):**  The abstraction that ties goroutines to Ms. The code shows Ps have run queues.
    * **Scheduler:** The logic for deciding which goroutine runs on which M. `findRunnable` is a central part.
    * **Run Queues (Local and Global):**  Mechanisms for storing runnable goroutines.
    * **Preemption:** The ability to interrupt a running goroutine.
    * **`runtime.Gosched()`:**  Voluntarily yielding the CPU.
    * **`sync.Mutex` (implied):** The use of `lock` and `unlock` suggests mutexes are used for synchronization.
    * **Network Poller:** Handling asynchronous I/O.
    * **Timers:**  Managing delayed execution.
    * **Garbage Collection Integration:** Functions like `gcstopm` and the checks for GC state show tight integration.
    * **Tracing:**  The `traceAcquire` and `traceRelease` calls indicate support for runtime tracing.
    * **Spinning Threads:** The concept of Ms actively looking for work.
    * **`park`/`unpark`:** Low-level primitives for blocking and waking goroutines.

5. **Code Examples:**  For each inferred feature, create simple Go code examples that demonstrate the feature and would likely involve the functions in the analyzed snippet. Focus on clear, concise examples. Think about how the different functions would be involved in the execution of these examples.

6. **Reasoning with Input/Output:**  For more complex functions (like `findRunnable`), consider hypothetical scenarios and trace the flow. What happens if the local run queue is empty? What if the global run queue has items? What if network events are pending? This helps in understanding the decision-making process within the code.

7. **Command-Line Arguments (If Applicable):**  Scan the code for any direct usage of command-line flags or environment variables. In this snippet, there isn't much direct handling, but broader knowledge of the Go runtime might lead to mentioning things like `GOMAXPROCS`.

8. **Common Pitfalls:**  Think about how developers might misuse or misunderstand the concepts illustrated by the code. For example, blocking the main goroutine, excessive use of `runtime.Gosched` without understanding its implications, or misunderstanding the interaction between goroutines and OS threads.

9. **Summarization:**  Finally, synthesize the information gathered into a concise summary of the code snippet's functionality. Focus on the main responsibilities and the key concepts involved. Since this is part 4 of 7, consider how this part contributes to the overall picture of Go's concurrency model.

10. **Review and Refine:**  Read through the entire analysis to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. Ensure the examples are correct and illustrative.

This systematic approach, starting from a broad overview and then diving into specifics, allows for a comprehensive understanding of the code snippet and its place within the larger Go runtime. The process involves code reading, keyword identification, inferring functionality, generating examples, considering edge cases, and summarizing the findings.
这段 `go/src/runtime/proc.go` 代码是 Go 运行时系统中关于 **goroutine 调度** 的核心部分。它定义了如何停止、启动和查找可运行的 goroutine，以及如何进行上下文切换和处理各种调度事件。

以下是这段代码的具体功能归纳：

**核心 Goroutine 调度功能:**

* **停止 M (OS 线程):**
    * `stopm()`:  将当前 M 停止运行，通常是因为没有可运行的 goroutine 或者需要等待某些事件。
    * `gcstopm()`:  专门用于垃圾回收的停止 M。当垃圾回收需要停止整个世界 (stop-the-world) 时，此函数会被调用来暂停工作线程。

* **执行 Goroutine:**
    * `execute(gp *g, inheritTime bool)`: 将指定的 goroutine `gp` 调度到当前的 M 上运行。它可以选择是否继承当前时间片剩余的时间。这是将 goroutine 真正投入运行的关键步骤。

* **查找可运行的 Goroutine:**
    * `findRunnable() (gp *g, inheritTime, tryWakeP bool)`:  这是调度器的核心函数。它负责从各种来源（本地运行队列、全局运行队列、网络轮询、偷取其他 P 的 goroutine 等）查找一个可以运行的 goroutine。它会返回找到的 goroutine 以及一些标志位，例如是否继承时间片以及是否需要唤醒一个 P。

* **工作窃取:**
    * `stealWork(now int64) (gp *g, inheritTime bool, rnow, pollUntil int64, newWork bool)`: 当一个 M 没有自己的可运行 goroutine 时，它会尝试从其他 P 的运行队列中“偷取” goroutine 来执行，以提高 CPU 利用率。

* **检查运行队列和定时器（无 P 的情况）:**
    * `checkRunqsNoP(allpSnapshot []*p, idlepMaskSnapshot pMask) *p`:  当没有 P 与当前 M 关联时，检查所有 P 是否有可运行的 goroutine 可以偷取。
    * `checkTimersNoP(allpSnapshot []*p, timerpMaskSnapshot pMask, pollUntil int64) int64`:  当没有 P 时，检查所有 P 的定时器，看是否有即将到期的定时器，并更新等待时间。

* **检查空闲 GC 工作（无 P 的情况）:**
    * `checkIdleGCNoP() (*p, *g)`:  当没有 P 时，检查是否有空闲的 GC 标记工作可以执行，并尝试获取一个 P 和一个 GC 工作 goroutine。

* **唤醒网络轮询器:**
    * `wakeNetPoller(when int64)`:  唤醒睡眠中的网络轮询线程，以便处理网络事件或定时器。

* **重置自旋状态:**
    * `resetspinning()`:  当一个自旋的 M 找到工作后，会调用此函数来停止自旋状态，并可能唤醒其他 P。

* **注入 Goroutine 列表:**
    * `injectglist(glist *gList)`: 将一个可运行的 goroutine 列表添加到相应的运行队列中。如果没有当前 P，则添加到全局队列，并可能启动新的 M 来运行这些 goroutine。

* **调度循环:**
    * `schedule()`: 这是调度器的主要循环。它调用 `findRunnable` 找到一个可运行的 goroutine，然后调用 `execute` 来执行它。

* **放弃 Goroutine:**
    * `dropg()`:  解除当前 M 和当前正在运行的 goroutine 的关联。通常在 goroutine 需要等待某些事件或主动让出 CPU 时调用。

* **Goroutine 进入休眠:**
    * `park_m(gp *g)`: 将一个 goroutine 置于休眠状态，等待被唤醒。可以指定一个解锁函数 `waitunlockf` 在休眠前执行。

* **主动让出 CPU:**
    * `goschedImpl(gp *g, preempted bool)` / `gosched_m(gp *g)` / `goschedguarded_m(gp *g)`:  当前 goroutine 主动让出 CPU，将自己放入全局运行队列，并触发调度。
    * `goyield()` / `goyield_m(gp *g)`:  类似于 `Gosched`，但将当前 goroutine 放入当前 P 的本地运行队列。

* **抢占 Goroutine:**
    * `preemptPark(gp *g)`:  强制将一个正在运行的 goroutine 暂停，将其状态设置为可抢占。

* **Goroutine 退出:**
    * `goexit1()` / `goexit0(gp *g)`:  结束当前 goroutine 的执行。
    * `gdestroy(gp *g)`:  清理已退出 goroutine 的相关资源。

**推断的 Go 语言功能实现:**

这段代码主要涉及 Go 语言的 **并发模型** 和 **运行时调度器** 的实现。它展示了 Go 如何高效地管理和调度大量的 goroutine，以及如何与底层操作系统线程进行交互。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func worker(id int) {
	fmt.Printf("Worker %d starting\n", id)
	time.Sleep(time.Second) // 模拟工作
	fmt.Printf("Worker %d finishing\n", id)
}

func main() {
	runtime.GOMAXPROCS(2) // 设置使用的 CPU 核心数

	var wg sync.WaitGroup
	numWorkers := 5

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			worker(id)
		}(i)
	}

	wg.Wait()
	fmt.Println("All workers done")
}
```

**假设的输入与输出:**

在这个例子中，假设 `runtime.GOMAXPROCS(2)` 设置了使用 2 个 CPU 核心。当程序运行时，会创建 5 个 goroutine 来执行 `worker` 函数。

* **输入:**  启动 Go 程序。
* **输出:**  程序会并发地执行 5 个 `worker` 函数，输出类似于：
```
Worker 0 starting
Worker 1 starting
Worker 2 starting
Worker 3 starting
Worker 4 starting
(等待 1 秒)
Worker 1 finishing
Worker 0 finishing
Worker 3 finishing
Worker 2 finishing
Worker 4 finishing
All workers done
```

**代码推理:**

当 `go func(...)` 创建新的 goroutine 时，这些 goroutine 会被放入全局运行队列中。  运行时调度器（由这段 `proc.go` 中的代码驱动）负责将这些 goroutine 分配到可用的 M (与 OS 线程关联) 上执行。

* `findRunnable()` 会被调用来查找可运行的 goroutine。
* 如果当前的 M 没有工作，`stealWork()` 可能会尝试从其他 P 的运行队列中偷取 goroutine。
* `execute()` 会将选定的 goroutine 调度到 M 上运行。
* `time.Sleep()` 会导致 goroutine 进入等待状态，这时可能会调用 `dropg()` 让出 CPU，并可能唤醒其他 goroutine。
* 当 `time.Sleep()` 结束时，goroutine 会被标记为可运行，并重新加入运行队列。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `os` 和 `flag` 等标准库中。但是，`runtime.GOMAXPROCS()` 可以通过环境变量 `GOMAXPROCS` 来设置，这间接地影响了这段代码的行为，因为它控制了可以同时运行的操作系统线程的最大数量，从而影响了 goroutine 的调度。

**使用者易犯错的点:**

这段代码是 Go 运行时的内部实现，普通 Go 开发者通常不需要直接与之交互。但是，理解其背后的原理可以帮助避免一些常见的并发编程错误：

* **过度依赖 `runtime.Gosched()`:**  不恰当地使用 `runtime.Gosched()` 可能会导致性能下降，因为它强制 goroutine 让出 CPU，即使它还有工作要做。开发者应该让调度器根据需要自动进行调度。
* **误解 Goroutine 的并发性与并行性:**  即使在多核处理器上，过多的 I/O 密集型 goroutine 也可能导致上下文切换开销过大，降低效率。理解 CPU 绑定 (CPU-bound) 和 I/O 绑定 (I/O-bound) 的任务，并合理设置 `GOMAXPROCS` 非常重要。
* **死锁 (Deadlock) 和活锁 (Livelock):**  不正确的同步原语使用（例如互斥锁、通道）可能导致死锁或活锁。理解调度器如何处理阻塞的 goroutine 可以帮助调试这些问题。

**这段代码的功能归纳:**

这段 `go/src/runtime/proc.go` 代码的核心功能是实现 Go 语言的 **goroutine 调度器**。它负责：

1. **管理 M (OS 线程) 的生命周期:**  包括停止和启动 M。
2. **寻找和执行可运行的 goroutine:** 从不同的运行队列中选择 goroutine 并调度到 M 上执行。
3. **处理 goroutine 的状态转换:**  包括运行、休眠、等待、退出等状态的切换。
4. **支持工作窃取:**  在 M 空闲时尝试从其他 P 偷取工作。
5. **与垃圾回收器协同工作:**  在垃圾回收期间暂停工作线程。
6. **支持主动让出和强制抢占:**  允许 goroutine 主动让出 CPU 或被强制暂停。

总而言之，这段代码是 Go 运行时并发模型的核心引擎，确保 goroutine 能够高效、公平地在操作系统线程上运行。

Prompt: 
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共7部分，请归纳一下它的功能

"""
urrent P to the locked m
	incidlelocked(-1)
	pp := releasep()
	mp.nextp.set(pp)
	notewakeup(&mp.park)
	stopm()
}

// Stops the current m for stopTheWorld.
// Returns when the world is restarted.
func gcstopm() {
	gp := getg()

	if !sched.gcwaiting.Load() {
		throw("gcstopm: not waiting for gc")
	}
	if gp.m.spinning {
		gp.m.spinning = false
		// OK to just drop nmspinning here,
		// startTheWorld will unpark threads as necessary.
		if sched.nmspinning.Add(-1) < 0 {
			throw("gcstopm: negative nmspinning")
		}
	}
	pp := releasep()
	lock(&sched.lock)
	pp.status = _Pgcstop
	pp.gcStopTime = nanotime()
	sched.stopwait--
	if sched.stopwait == 0 {
		notewakeup(&sched.stopnote)
	}
	unlock(&sched.lock)
	stopm()
}

// Schedules gp to run on the current M.
// If inheritTime is true, gp inherits the remaining time in the
// current time slice. Otherwise, it starts a new time slice.
// Never returns.
//
// Write barriers are allowed because this is called immediately after
// acquiring a P in several places.
//
//go:yeswritebarrierrec
func execute(gp *g, inheritTime bool) {
	mp := getg().m

	if goroutineProfile.active {
		// Make sure that gp has had its stack written out to the goroutine
		// profile, exactly as it was when the goroutine profiler first stopped
		// the world.
		tryRecordGoroutineProfile(gp, nil, osyield)
	}

	// Assign gp.m before entering _Grunning so running Gs have an
	// M.
	mp.curg = gp
	gp.m = mp
	casgstatus(gp, _Grunnable, _Grunning)
	gp.waitsince = 0
	gp.preempt = false
	gp.stackguard0 = gp.stack.lo + stackGuard
	if !inheritTime {
		mp.p.ptr().schedtick++
	}

	// Check whether the profiler needs to be turned on or off.
	hz := sched.profilehz
	if mp.profilehz != hz {
		setThreadCPUProfiler(hz)
	}

	trace := traceAcquire()
	if trace.ok() {
		trace.GoStart()
		traceRelease(trace)
	}

	gogo(&gp.sched)
}

// Finds a runnable goroutine to execute.
// Tries to steal from other P's, get g from local or global queue, poll network.
// tryWakeP indicates that the returned goroutine is not normal (GC worker, trace
// reader) so the caller should try to wake a P.
func findRunnable() (gp *g, inheritTime, tryWakeP bool) {
	mp := getg().m

	// The conditions here and in handoffp must agree: if
	// findrunnable would return a G to run, handoffp must start
	// an M.

top:
	pp := mp.p.ptr()
	if sched.gcwaiting.Load() {
		gcstopm()
		goto top
	}
	if pp.runSafePointFn != 0 {
		runSafePointFn()
	}

	// now and pollUntil are saved for work stealing later,
	// which may steal timers. It's important that between now
	// and then, nothing blocks, so these numbers remain mostly
	// relevant.
	now, pollUntil, _ := pp.timers.check(0)

	// Try to schedule the trace reader.
	if traceEnabled() || traceShuttingDown() {
		gp := traceReader()
		if gp != nil {
			trace := traceAcquire()
			casgstatus(gp, _Gwaiting, _Grunnable)
			if trace.ok() {
				trace.GoUnpark(gp, 0)
				traceRelease(trace)
			}
			return gp, false, true
		}
	}

	// Try to schedule a GC worker.
	if gcBlackenEnabled != 0 {
		gp, tnow := gcController.findRunnableGCWorker(pp, now)
		if gp != nil {
			return gp, false, true
		}
		now = tnow
	}

	// Check the global runnable queue once in a while to ensure fairness.
	// Otherwise two goroutines can completely occupy the local runqueue
	// by constantly respawning each other.
	if pp.schedtick%61 == 0 && sched.runqsize > 0 {
		lock(&sched.lock)
		gp := globrunqget(pp, 1)
		unlock(&sched.lock)
		if gp != nil {
			return gp, false, false
		}
	}

	// Wake up the finalizer G.
	if fingStatus.Load()&(fingWait|fingWake) == fingWait|fingWake {
		if gp := wakefing(); gp != nil {
			ready(gp, 0, true)
		}
	}
	if *cgo_yield != nil {
		asmcgocall(*cgo_yield, nil)
	}

	// local runq
	if gp, inheritTime := runqget(pp); gp != nil {
		return gp, inheritTime, false
	}

	// global runq
	if sched.runqsize != 0 {
		lock(&sched.lock)
		gp := globrunqget(pp, 0)
		unlock(&sched.lock)
		if gp != nil {
			return gp, false, false
		}
	}

	// Poll network.
	// This netpoll is only an optimization before we resort to stealing.
	// We can safely skip it if there are no waiters or a thread is blocked
	// in netpoll already. If there is any kind of logical race with that
	// blocked thread (e.g. it has already returned from netpoll, but does
	// not set lastpoll yet), this thread will do blocking netpoll below
	// anyway.
	if netpollinited() && netpollAnyWaiters() && sched.lastpoll.Load() != 0 {
		if list, delta := netpoll(0); !list.empty() { // non-blocking
			gp := list.pop()
			injectglist(&list)
			netpollAdjustWaiters(delta)
			trace := traceAcquire()
			casgstatus(gp, _Gwaiting, _Grunnable)
			if trace.ok() {
				trace.GoUnpark(gp, 0)
				traceRelease(trace)
			}
			return gp, false, false
		}
	}

	// Spinning Ms: steal work from other Ps.
	//
	// Limit the number of spinning Ms to half the number of busy Ps.
	// This is necessary to prevent excessive CPU consumption when
	// GOMAXPROCS>>1 but the program parallelism is low.
	if mp.spinning || 2*sched.nmspinning.Load() < gomaxprocs-sched.npidle.Load() {
		if !mp.spinning {
			mp.becomeSpinning()
		}

		gp, inheritTime, tnow, w, newWork := stealWork(now)
		if gp != nil {
			// Successfully stole.
			return gp, inheritTime, false
		}
		if newWork {
			// There may be new timer or GC work; restart to
			// discover.
			goto top
		}

		now = tnow
		if w != 0 && (pollUntil == 0 || w < pollUntil) {
			// Earlier timer to wait for.
			pollUntil = w
		}
	}

	// We have nothing to do.
	//
	// If we're in the GC mark phase, can safely scan and blacken objects,
	// and have work to do, run idle-time marking rather than give up the P.
	if gcBlackenEnabled != 0 && gcMarkWorkAvailable(pp) && gcController.addIdleMarkWorker() {
		node := (*gcBgMarkWorkerNode)(gcBgMarkWorkerPool.pop())
		if node != nil {
			pp.gcMarkWorkerMode = gcMarkWorkerIdleMode
			gp := node.gp.ptr()

			trace := traceAcquire()
			casgstatus(gp, _Gwaiting, _Grunnable)
			if trace.ok() {
				trace.GoUnpark(gp, 0)
				traceRelease(trace)
			}
			return gp, false, false
		}
		gcController.removeIdleMarkWorker()
	}

	// wasm only:
	// If a callback returned and no other goroutine is awake,
	// then wake event handler goroutine which pauses execution
	// until a callback was triggered.
	gp, otherReady := beforeIdle(now, pollUntil)
	if gp != nil {
		trace := traceAcquire()
		casgstatus(gp, _Gwaiting, _Grunnable)
		if trace.ok() {
			trace.GoUnpark(gp, 0)
			traceRelease(trace)
		}
		return gp, false, false
	}
	if otherReady {
		goto top
	}

	// Before we drop our P, make a snapshot of the allp slice,
	// which can change underfoot once we no longer block
	// safe-points. We don't need to snapshot the contents because
	// everything up to cap(allp) is immutable.
	allpSnapshot := allp
	// Also snapshot masks. Value changes are OK, but we can't allow
	// len to change out from under us.
	idlepMaskSnapshot := idlepMask
	timerpMaskSnapshot := timerpMask

	// return P and block
	lock(&sched.lock)
	if sched.gcwaiting.Load() || pp.runSafePointFn != 0 {
		unlock(&sched.lock)
		goto top
	}
	if sched.runqsize != 0 {
		gp := globrunqget(pp, 0)
		unlock(&sched.lock)
		return gp, false, false
	}
	if !mp.spinning && sched.needspinning.Load() == 1 {
		// See "Delicate dance" comment below.
		mp.becomeSpinning()
		unlock(&sched.lock)
		goto top
	}
	if releasep() != pp {
		throw("findrunnable: wrong p")
	}
	now = pidleput(pp, now)
	unlock(&sched.lock)

	// Delicate dance: thread transitions from spinning to non-spinning
	// state, potentially concurrently with submission of new work. We must
	// drop nmspinning first and then check all sources again (with
	// #StoreLoad memory barrier in between). If we do it the other way
	// around, another thread can submit work after we've checked all
	// sources but before we drop nmspinning; as a result nobody will
	// unpark a thread to run the work.
	//
	// This applies to the following sources of work:
	//
	// * Goroutines added to the global or a per-P run queue.
	// * New/modified-earlier timers on a per-P timer heap.
	// * Idle-priority GC work (barring golang.org/issue/19112).
	//
	// If we discover new work below, we need to restore m.spinning as a
	// signal for resetspinning to unpark a new worker thread (because
	// there can be more than one starving goroutine).
	//
	// However, if after discovering new work we also observe no idle Ps
	// (either here or in resetspinning), we have a problem. We may be
	// racing with a non-spinning M in the block above, having found no
	// work and preparing to release its P and park. Allowing that P to go
	// idle will result in loss of work conservation (idle P while there is
	// runnable work). This could result in complete deadlock in the
	// unlikely event that we discover new work (from netpoll) right as we
	// are racing with _all_ other Ps going idle.
	//
	// We use sched.needspinning to synchronize with non-spinning Ms going
	// idle. If needspinning is set when they are about to drop their P,
	// they abort the drop and instead become a new spinning M on our
	// behalf. If we are not racing and the system is truly fully loaded
	// then no spinning threads are required, and the next thread to
	// naturally become spinning will clear the flag.
	//
	// Also see "Worker thread parking/unparking" comment at the top of the
	// file.
	wasSpinning := mp.spinning
	if mp.spinning {
		mp.spinning = false
		if sched.nmspinning.Add(-1) < 0 {
			throw("findrunnable: negative nmspinning")
		}

		// Note the for correctness, only the last M transitioning from
		// spinning to non-spinning must perform these rechecks to
		// ensure no missed work. However, the runtime has some cases
		// of transient increments of nmspinning that are decremented
		// without going through this path, so we must be conservative
		// and perform the check on all spinning Ms.
		//
		// See https://go.dev/issue/43997.

		// Check global and P runqueues again.

		lock(&sched.lock)
		if sched.runqsize != 0 {
			pp, _ := pidlegetSpinning(0)
			if pp != nil {
				gp := globrunqget(pp, 0)
				if gp == nil {
					throw("global runq empty with non-zero runqsize")
				}
				unlock(&sched.lock)
				acquirep(pp)
				mp.becomeSpinning()
				return gp, false, false
			}
		}
		unlock(&sched.lock)

		pp := checkRunqsNoP(allpSnapshot, idlepMaskSnapshot)
		if pp != nil {
			acquirep(pp)
			mp.becomeSpinning()
			goto top
		}

		// Check for idle-priority GC work again.
		pp, gp := checkIdleGCNoP()
		if pp != nil {
			acquirep(pp)
			mp.becomeSpinning()

			// Run the idle worker.
			pp.gcMarkWorkerMode = gcMarkWorkerIdleMode
			trace := traceAcquire()
			casgstatus(gp, _Gwaiting, _Grunnable)
			if trace.ok() {
				trace.GoUnpark(gp, 0)
				traceRelease(trace)
			}
			return gp, false, false
		}

		// Finally, check for timer creation or expiry concurrently with
		// transitioning from spinning to non-spinning.
		//
		// Note that we cannot use checkTimers here because it calls
		// adjusttimers which may need to allocate memory, and that isn't
		// allowed when we don't have an active P.
		pollUntil = checkTimersNoP(allpSnapshot, timerpMaskSnapshot, pollUntil)
	}

	// Poll network until next timer.
	if netpollinited() && (netpollAnyWaiters() || pollUntil != 0) && sched.lastpoll.Swap(0) != 0 {
		sched.pollUntil.Store(pollUntil)
		if mp.p != 0 {
			throw("findrunnable: netpoll with p")
		}
		if mp.spinning {
			throw("findrunnable: netpoll with spinning")
		}
		delay := int64(-1)
		if pollUntil != 0 {
			if now == 0 {
				now = nanotime()
			}
			delay = pollUntil - now
			if delay < 0 {
				delay = 0
			}
		}
		if faketime != 0 {
			// When using fake time, just poll.
			delay = 0
		}
		list, delta := netpoll(delay) // block until new work is available
		// Refresh now again, after potentially blocking.
		now = nanotime()
		sched.pollUntil.Store(0)
		sched.lastpoll.Store(now)
		if faketime != 0 && list.empty() {
			// Using fake time and nothing is ready; stop M.
			// When all M's stop, checkdead will call timejump.
			stopm()
			goto top
		}
		lock(&sched.lock)
		pp, _ := pidleget(now)
		unlock(&sched.lock)
		if pp == nil {
			injectglist(&list)
			netpollAdjustWaiters(delta)
		} else {
			acquirep(pp)
			if !list.empty() {
				gp := list.pop()
				injectglist(&list)
				netpollAdjustWaiters(delta)
				trace := traceAcquire()
				casgstatus(gp, _Gwaiting, _Grunnable)
				if trace.ok() {
					trace.GoUnpark(gp, 0)
					traceRelease(trace)
				}
				return gp, false, false
			}
			if wasSpinning {
				mp.becomeSpinning()
			}
			goto top
		}
	} else if pollUntil != 0 && netpollinited() {
		pollerPollUntil := sched.pollUntil.Load()
		if pollerPollUntil == 0 || pollerPollUntil > pollUntil {
			netpollBreak()
		}
	}
	stopm()
	goto top
}

// pollWork reports whether there is non-background work this P could
// be doing. This is a fairly lightweight check to be used for
// background work loops, like idle GC. It checks a subset of the
// conditions checked by the actual scheduler.
func pollWork() bool {
	if sched.runqsize != 0 {
		return true
	}
	p := getg().m.p.ptr()
	if !runqempty(p) {
		return true
	}
	if netpollinited() && netpollAnyWaiters() && sched.lastpoll.Load() != 0 {
		if list, delta := netpoll(0); !list.empty() {
			injectglist(&list)
			netpollAdjustWaiters(delta)
			return true
		}
	}
	return false
}

// stealWork attempts to steal a runnable goroutine or timer from any P.
//
// If newWork is true, new work may have been readied.
//
// If now is not 0 it is the current time. stealWork returns the passed time or
// the current time if now was passed as 0.
func stealWork(now int64) (gp *g, inheritTime bool, rnow, pollUntil int64, newWork bool) {
	pp := getg().m.p.ptr()

	ranTimer := false

	const stealTries = 4
	for i := 0; i < stealTries; i++ {
		stealTimersOrRunNextG := i == stealTries-1

		for enum := stealOrder.start(cheaprand()); !enum.done(); enum.next() {
			if sched.gcwaiting.Load() {
				// GC work may be available.
				return nil, false, now, pollUntil, true
			}
			p2 := allp[enum.position()]
			if pp == p2 {
				continue
			}

			// Steal timers from p2. This call to checkTimers is the only place
			// where we might hold a lock on a different P's timers. We do this
			// once on the last pass before checking runnext because stealing
			// from the other P's runnext should be the last resort, so if there
			// are timers to steal do that first.
			//
			// We only check timers on one of the stealing iterations because
			// the time stored in now doesn't change in this loop and checking
			// the timers for each P more than once with the same value of now
			// is probably a waste of time.
			//
			// timerpMask tells us whether the P may have timers at all. If it
			// can't, no need to check at all.
			if stealTimersOrRunNextG && timerpMask.read(enum.position()) {
				tnow, w, ran := p2.timers.check(now)
				now = tnow
				if w != 0 && (pollUntil == 0 || w < pollUntil) {
					pollUntil = w
				}
				if ran {
					// Running the timers may have
					// made an arbitrary number of G's
					// ready and added them to this P's
					// local run queue. That invalidates
					// the assumption of runqsteal
					// that it always has room to add
					// stolen G's. So check now if there
					// is a local G to run.
					if gp, inheritTime := runqget(pp); gp != nil {
						return gp, inheritTime, now, pollUntil, ranTimer
					}
					ranTimer = true
				}
			}

			// Don't bother to attempt to steal if p2 is idle.
			if !idlepMask.read(enum.position()) {
				if gp := runqsteal(pp, p2, stealTimersOrRunNextG); gp != nil {
					return gp, false, now, pollUntil, ranTimer
				}
			}
		}
	}

	// No goroutines found to steal. Regardless, running a timer may have
	// made some goroutine ready that we missed. Indicate the next timer to
	// wait for.
	return nil, false, now, pollUntil, ranTimer
}

// Check all Ps for a runnable G to steal.
//
// On entry we have no P. If a G is available to steal and a P is available,
// the P is returned which the caller should acquire and attempt to steal the
// work to.
func checkRunqsNoP(allpSnapshot []*p, idlepMaskSnapshot pMask) *p {
	for id, p2 := range allpSnapshot {
		if !idlepMaskSnapshot.read(uint32(id)) && !runqempty(p2) {
			lock(&sched.lock)
			pp, _ := pidlegetSpinning(0)
			if pp == nil {
				// Can't get a P, don't bother checking remaining Ps.
				unlock(&sched.lock)
				return nil
			}
			unlock(&sched.lock)
			return pp
		}
	}

	// No work available.
	return nil
}

// Check all Ps for a timer expiring sooner than pollUntil.
//
// Returns updated pollUntil value.
func checkTimersNoP(allpSnapshot []*p, timerpMaskSnapshot pMask, pollUntil int64) int64 {
	for id, p2 := range allpSnapshot {
		if timerpMaskSnapshot.read(uint32(id)) {
			w := p2.timers.wakeTime()
			if w != 0 && (pollUntil == 0 || w < pollUntil) {
				pollUntil = w
			}
		}
	}

	return pollUntil
}

// Check for idle-priority GC, without a P on entry.
//
// If some GC work, a P, and a worker G are all available, the P and G will be
// returned. The returned P has not been wired yet.
func checkIdleGCNoP() (*p, *g) {
	// N.B. Since we have no P, gcBlackenEnabled may change at any time; we
	// must check again after acquiring a P. As an optimization, we also check
	// if an idle mark worker is needed at all. This is OK here, because if we
	// observe that one isn't needed, at least one is currently running. Even if
	// it stops running, its own journey into the scheduler should schedule it
	// again, if need be (at which point, this check will pass, if relevant).
	if atomic.Load(&gcBlackenEnabled) == 0 || !gcController.needIdleMarkWorker() {
		return nil, nil
	}
	if !gcMarkWorkAvailable(nil) {
		return nil, nil
	}

	// Work is available; we can start an idle GC worker only if there is
	// an available P and available worker G.
	//
	// We can attempt to acquire these in either order, though both have
	// synchronization concerns (see below). Workers are almost always
	// available (see comment in findRunnableGCWorker for the one case
	// there may be none). Since we're slightly less likely to find a P,
	// check for that first.
	//
	// Synchronization: note that we must hold sched.lock until we are
	// committed to keeping it. Otherwise we cannot put the unnecessary P
	// back in sched.pidle without performing the full set of idle
	// transition checks.
	//
	// If we were to check gcBgMarkWorkerPool first, we must somehow handle
	// the assumption in gcControllerState.findRunnableGCWorker that an
	// empty gcBgMarkWorkerPool is only possible if gcMarkDone is running.
	lock(&sched.lock)
	pp, now := pidlegetSpinning(0)
	if pp == nil {
		unlock(&sched.lock)
		return nil, nil
	}

	// Now that we own a P, gcBlackenEnabled can't change (as it requires STW).
	if gcBlackenEnabled == 0 || !gcController.addIdleMarkWorker() {
		pidleput(pp, now)
		unlock(&sched.lock)
		return nil, nil
	}

	node := (*gcBgMarkWorkerNode)(gcBgMarkWorkerPool.pop())
	if node == nil {
		pidleput(pp, now)
		unlock(&sched.lock)
		gcController.removeIdleMarkWorker()
		return nil, nil
	}

	unlock(&sched.lock)

	return pp, node.gp.ptr()
}

// wakeNetPoller wakes up the thread sleeping in the network poller if it isn't
// going to wake up before the when argument; or it wakes an idle P to service
// timers and the network poller if there isn't one already.
func wakeNetPoller(when int64) {
	if sched.lastpoll.Load() == 0 {
		// In findrunnable we ensure that when polling the pollUntil
		// field is either zero or the time to which the current
		// poll is expected to run. This can have a spurious wakeup
		// but should never miss a wakeup.
		pollerPollUntil := sched.pollUntil.Load()
		if pollerPollUntil == 0 || pollerPollUntil > when {
			netpollBreak()
		}
	} else {
		// There are no threads in the network poller, try to get
		// one there so it can handle new timers.
		if GOOS != "plan9" { // Temporary workaround - see issue #42303.
			wakep()
		}
	}
}

func resetspinning() {
	gp := getg()
	if !gp.m.spinning {
		throw("resetspinning: not a spinning m")
	}
	gp.m.spinning = false
	nmspinning := sched.nmspinning.Add(-1)
	if nmspinning < 0 {
		throw("findrunnable: negative nmspinning")
	}
	// M wakeup policy is deliberately somewhat conservative, so check if we
	// need to wakeup another P here. See "Worker thread parking/unparking"
	// comment at the top of the file for details.
	wakep()
}

// injectglist adds each runnable G on the list to some run queue,
// and clears glist. If there is no current P, they are added to the
// global queue, and up to npidle M's are started to run them.
// Otherwise, for each idle P, this adds a G to the global queue
// and starts an M. Any remaining G's are added to the current P's
// local run queue.
// This may temporarily acquire sched.lock.
// Can run concurrently with GC.
func injectglist(glist *gList) {
	if glist.empty() {
		return
	}
	trace := traceAcquire()
	if trace.ok() {
		for gp := glist.head.ptr(); gp != nil; gp = gp.schedlink.ptr() {
			trace.GoUnpark(gp, 0)
		}
		traceRelease(trace)
	}

	// Mark all the goroutines as runnable before we put them
	// on the run queues.
	head := glist.head.ptr()
	var tail *g
	qsize := 0
	for gp := head; gp != nil; gp = gp.schedlink.ptr() {
		tail = gp
		qsize++
		casgstatus(gp, _Gwaiting, _Grunnable)
	}

	// Turn the gList into a gQueue.
	var q gQueue
	q.head.set(head)
	q.tail.set(tail)
	*glist = gList{}

	startIdle := func(n int) {
		for i := 0; i < n; i++ {
			mp := acquirem() // See comment in startm.
			lock(&sched.lock)

			pp, _ := pidlegetSpinning(0)
			if pp == nil {
				unlock(&sched.lock)
				releasem(mp)
				break
			}

			startm(pp, false, true)
			unlock(&sched.lock)
			releasem(mp)
		}
	}

	pp := getg().m.p.ptr()
	if pp == nil {
		lock(&sched.lock)
		globrunqputbatch(&q, int32(qsize))
		unlock(&sched.lock)
		startIdle(qsize)
		return
	}

	npidle := int(sched.npidle.Load())
	var (
		globq gQueue
		n     int
	)
	for n = 0; n < npidle && !q.empty(); n++ {
		g := q.pop()
		globq.pushBack(g)
	}
	if n > 0 {
		lock(&sched.lock)
		globrunqputbatch(&globq, int32(n))
		unlock(&sched.lock)
		startIdle(n)
		qsize -= n
	}

	if !q.empty() {
		runqputbatch(pp, &q, qsize)
	}

	// Some P's might have become idle after we loaded `sched.npidle`
	// but before any goroutines were added to the queue, which could
	// lead to idle P's when there is work available in the global queue.
	// That could potentially last until other goroutines become ready
	// to run. That said, we need to find a way to hedge
	//
	// Calling wakep() here is the best bet, it will do nothing in the
	// common case (no racing on `sched.npidle`), while it could wake one
	// more P to execute G's, which might end up with >1 P's: the first one
	// wakes another P and so forth until there is no more work, but this
	// ought to be an extremely rare case.
	//
	// Also see "Worker thread parking/unparking" comment at the top of the file for details.
	wakep()
}

// One round of scheduler: find a runnable goroutine and execute it.
// Never returns.
func schedule() {
	mp := getg().m

	if mp.locks != 0 {
		throw("schedule: holding locks")
	}

	if mp.lockedg != 0 {
		stoplockedm()
		execute(mp.lockedg.ptr(), false) // Never returns.
	}

	// We should not schedule away from a g that is executing a cgo call,
	// since the cgo call is using the m's g0 stack.
	if mp.incgo {
		throw("schedule: in cgo")
	}

top:
	pp := mp.p.ptr()
	pp.preempt = false

	// Safety check: if we are spinning, the run queue should be empty.
	// Check this before calling checkTimers, as that might call
	// goready to put a ready goroutine on the local run queue.
	if mp.spinning && (pp.runnext != 0 || pp.runqhead != pp.runqtail) {
		throw("schedule: spinning with local work")
	}

	gp, inheritTime, tryWakeP := findRunnable() // blocks until work is available

	if debug.dontfreezetheworld > 0 && freezing.Load() {
		// See comment in freezetheworld. We don't want to perturb
		// scheduler state, so we didn't gcstopm in findRunnable, but
		// also don't want to allow new goroutines to run.
		//
		// Deadlock here rather than in the findRunnable loop so if
		// findRunnable is stuck in a loop we don't perturb that
		// either.
		lock(&deadlock)
		lock(&deadlock)
	}

	// This thread is going to run a goroutine and is not spinning anymore,
	// so if it was marked as spinning we need to reset it now and potentially
	// start a new spinning M.
	if mp.spinning {
		resetspinning()
	}

	if sched.disable.user && !schedEnabled(gp) {
		// Scheduling of this goroutine is disabled. Put it on
		// the list of pending runnable goroutines for when we
		// re-enable user scheduling and look again.
		lock(&sched.lock)
		if schedEnabled(gp) {
			// Something re-enabled scheduling while we
			// were acquiring the lock.
			unlock(&sched.lock)
		} else {
			sched.disable.runnable.pushBack(gp)
			sched.disable.n++
			unlock(&sched.lock)
			goto top
		}
	}

	// If about to schedule a not-normal goroutine (a GCworker or tracereader),
	// wake a P if there is one.
	if tryWakeP {
		wakep()
	}
	if gp.lockedm != 0 {
		// Hands off own p to the locked m,
		// then blocks waiting for a new p.
		startlockedm(gp)
		goto top
	}

	execute(gp, inheritTime)
}

// dropg removes the association between m and the current goroutine m->curg (gp for short).
// Typically a caller sets gp's status away from Grunning and then
// immediately calls dropg to finish the job. The caller is also responsible
// for arranging that gp will be restarted using ready at an
// appropriate time. After calling dropg and arranging for gp to be
// readied later, the caller can do other work but eventually should
// call schedule to restart the scheduling of goroutines on this m.
func dropg() {
	gp := getg()

	setMNoWB(&gp.m.curg.m, nil)
	setGNoWB(&gp.m.curg, nil)
}

func parkunlock_c(gp *g, lock unsafe.Pointer) bool {
	unlock((*mutex)(lock))
	return true
}

// park continuation on g0.
func park_m(gp *g) {
	mp := getg().m

	trace := traceAcquire()

	// If g is in a synctest group, we don't want to let the group
	// become idle until after the waitunlockf (if any) has confirmed
	// that the park is happening.
	// We need to record gp.syncGroup here, since waitunlockf can change it.
	sg := gp.syncGroup
	if sg != nil {
		sg.incActive()
	}

	if trace.ok() {
		// Trace the event before the transition. It may take a
		// stack trace, but we won't own the stack after the
		// transition anymore.
		trace.GoPark(mp.waitTraceBlockReason, mp.waitTraceSkip)
	}
	// N.B. Not using casGToWaiting here because the waitreason is
	// set by park_m's caller.
	casgstatus(gp, _Grunning, _Gwaiting)
	if trace.ok() {
		traceRelease(trace)
	}

	dropg()

	if fn := mp.waitunlockf; fn != nil {
		ok := fn(gp, mp.waitlock)
		mp.waitunlockf = nil
		mp.waitlock = nil
		if !ok {
			trace := traceAcquire()
			casgstatus(gp, _Gwaiting, _Grunnable)
			if sg != nil {
				sg.decActive()
			}
			if trace.ok() {
				trace.GoUnpark(gp, 2)
				traceRelease(trace)
			}
			execute(gp, true) // Schedule it back, never returns.
		}
	}

	if sg != nil {
		sg.decActive()
	}

	schedule()
}

func goschedImpl(gp *g, preempted bool) {
	trace := traceAcquire()
	status := readgstatus(gp)
	if status&^_Gscan != _Grunning {
		dumpgstatus(gp)
		throw("bad g status")
	}
	if trace.ok() {
		// Trace the event before the transition. It may take a
		// stack trace, but we won't own the stack after the
		// transition anymore.
		if preempted {
			trace.GoPreempt()
		} else {
			trace.GoSched()
		}
	}
	casgstatus(gp, _Grunning, _Grunnable)
	if trace.ok() {
		traceRelease(trace)
	}

	dropg()
	lock(&sched.lock)
	globrunqput(gp)
	unlock(&sched.lock)

	if mainStarted {
		wakep()
	}

	schedule()
}

// Gosched continuation on g0.
func gosched_m(gp *g) {
	goschedImpl(gp, false)
}

// goschedguarded is a forbidden-states-avoided version of gosched_m.
func goschedguarded_m(gp *g) {
	if !canPreemptM(gp.m) {
		gogo(&gp.sched) // never return
	}
	goschedImpl(gp, false)
}

func gopreempt_m(gp *g) {
	goschedImpl(gp, true)
}

// preemptPark parks gp and puts it in _Gpreempted.
//
//go:systemstack
func preemptPark(gp *g) {
	status := readgstatus(gp)
	if status&^_Gscan != _Grunning {
		dumpgstatus(gp)
		throw("bad g status")
	}

	if gp.asyncSafePoint {
		// Double-check that async preemption does not
		// happen in SPWRITE assembly functions.
		// isAsyncSafePoint must exclude this case.
		f := findfunc(gp.sched.pc)
		if !f.valid() {
			throw("preempt at unknown pc")
		}
		if f.flag&abi.FuncFlagSPWrite != 0 {
			println("runtime: unexpected SPWRITE function", funcname(f), "in async preempt")
			throw("preempt SPWRITE")
		}
	}

	// Transition from _Grunning to _Gscan|_Gpreempted. We can't
	// be in _Grunning when we dropg because then we'd be running
	// without an M, but the moment we're in _Gpreempted,
	// something could claim this G before we've fully cleaned it
	// up. Hence, we set the scan bit to lock down further
	// transitions until we can dropg.
	casGToPreemptScan(gp, _Grunning, _Gscan|_Gpreempted)
	dropg()

	// Be careful about how we trace this next event. The ordering
	// is subtle.
	//
	// The moment we CAS into _Gpreempted, suspendG could CAS to
	// _Gwaiting, do its work, and ready the goroutine. All of
	// this could happen before we even get the chance to emit
	// an event. The end result is that the events could appear
	// out of order, and the tracer generally assumes the scheduler
	// takes care of the ordering between GoPark and GoUnpark.
	//
	// The answer here is simple: emit the event while we still hold
	// the _Gscan bit on the goroutine. We still need to traceAcquire
	// and traceRelease across the CAS because the tracer could be
	// what's calling suspendG in the first place, and we want the
	// CAS and event emission to appear atomic to the tracer.
	trace := traceAcquire()
	if trace.ok() {
		trace.GoPark(traceBlockPreempted, 0)
	}
	casfrom_Gscanstatus(gp, _Gscan|_Gpreempted, _Gpreempted)
	if trace.ok() {
		traceRelease(trace)
	}
	schedule()
}

// goyield is like Gosched, but it:
// - emits a GoPreempt trace event instead of a GoSched trace event
// - puts the current G on the runq of the current P instead of the globrunq
//
// goyield should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//   - github.com/sagernet/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname goyield
func goyield() {
	checkTimeouts()
	mcall(goyield_m)
}

func goyield_m(gp *g) {
	trace := traceAcquire()
	pp := gp.m.p.ptr()
	if trace.ok() {
		// Trace the event before the transition. It may take a
		// stack trace, but we won't own the stack after the
		// transition anymore.
		trace.GoPreempt()
	}
	casgstatus(gp, _Grunning, _Grunnable)
	if trace.ok() {
		traceRelease(trace)
	}
	dropg()
	runqput(pp, gp, false)
	schedule()
}

// Finishes execution of the current goroutine.
func goexit1() {
	if raceenabled {
		if gp := getg(); gp.syncGroup != nil {
			racereleasemergeg(gp, gp.syncGroup.raceaddr())
		}
		racegoend()
	}
	trace := traceAcquire()
	if trace.ok() {
		trace.GoEnd()
		traceRelease(trace)
	}
	mcall(goexit0)
}

// goexit continuation on g0.
func goexit0(gp *g) {
	gdestroy(gp)
	schedule()
}

func gdestroy(gp *g) {
	mp := getg().m
	pp := mp.p.ptr()

	casgstatus(gp, _Grunning, _Gdead)
	gcController.addScannableStack(pp, -int64(gp.stack.hi-gp.stack.lo))
	if isSystemGoroutine(gp, false) {
		sched.ngsys.Add(-1)
	}
	gp.m = nil
	locked := gp.lockedm != 0
	gp.lockedm = 0
	mp.lockedg = 0
	gp.preemptStop = false
	gp.paniconfault = false
	gp._defer = nil // should be true already but just in case.
	gp._panic = nil // non-nil for Goexit during panic. points at stack-allocated data.
	gp.writebuf = nil
	gp.waitreason = waitReasonZero
	gp.param = nil
	gp.labels = nil
	gp.timer = nil
	gp.syncGroup = nil

	if gcBlackenEnabled != 0 && gp.gcAssistBytes > 0 {
		// Flush assist credit to the global pool. This gives
		// better information to pacing if the application is
		// rapidly creating an exiting goroutines.
		assistWorkPerByte := gcController.assistWorkPerByte.Load()
		scanCredit := int64(assistWorkPerByte * float64(gp.gcAssistBytes))
		gcController.bgScanCredit.Add(scanCredit)
		gp.gcAssistBytes = 0
	}

	dropg()

	if GOARCH == "wasm" { // no threads yet on wasm
		gfput(pp, gp)
		return
	}

	if locked && mp.lockedInt != 0 {
		print("runtime: mp.lockedInt = ", mp.lockedInt, "\n")
		if mp.isextra {
			throw("runtime.Goexit called in a thread that was not created by the Go runtime")
		}
		throw("exited a goroutine internally locked to the OS thread")
	}
	gfput(pp, gp)
	if locked {
		//
"""




```