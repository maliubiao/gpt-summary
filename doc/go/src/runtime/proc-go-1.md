Response:
My thinking process to analyze the provided Go code snippet and answer the request went through these stages:

1. **Understanding the Request:** I first broke down the request into its key components:
    * Identify the functionality of the provided Go code.
    * If possible, infer the high-level Go feature being implemented.
    * Provide Go code examples to illustrate the feature.
    * Include assumed inputs and outputs for code examples.
    * Detail handling of command-line arguments (if any).
    * Point out common mistakes users might make (if any).
    * Summarize the functionality of this specific part (Part 2 of 7).

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code looking for prominent keywords and function names that hint at the functionality. Key terms I noted were:
    * `freezetheworld`:  Suggests pausing or stopping the execution of goroutines.
    * `readgstatus`, `casgstatus`, `castogscanstatus`, `casfrom_Gscanstatus`:  Clearly related to the status of goroutines (`g`). The `cas` prefix suggests Compare-and-Swap operations, indicating concurrency control. The `_Gscan` part hints at interaction with the garbage collector.
    * `stopTheWorld`, `startTheWorld`, `stopTheWorldGC`, `startTheWorldGC`:  Strong indicators of mechanisms to pause and resume all or most goroutines. The "GC" variants suggest a relationship with garbage collection.
    * `stwReason`:  An enumeration for "stop-the-world" reasons.
    * `mstart`, `mstart0`, `mstart1`: Entry points for new "Ms" (machine threads or OS threads in Go).
    * `mexit`:  Exiting a machine thread.
    * `forEachP`:  Iterating over all "Ps" (processor local storage in Go's scheduler).

3. **Function-Level Analysis:**  I then examined individual functions and their interactions:
    * **`freezetheworld()`:** This function appears to be a less forceful version of `stopTheWorld`, used during crashes. It attempts to stop goroutines and prevent new ones from starting, but with a "best-effort" approach. The `debug.dontfreezetheworld` condition suggests a debugging or testing hook.
    * **`readgstatus()` and `cas...status()` functions:** These are the core of managing goroutine state transitions, specifically ensuring atomic updates and potentially synchronizing with the garbage collector (due to the `_Gscan` statuses). The `lockRankGscan` suggests a specific locking mechanism related to scanning goroutines.
    * **`stopTheWorld()` and `startTheWorld()`:** These functions are crucial for pausing and resuming the entire Go runtime. They involve acquiring a semaphore (`worldsema`), setting the `preemptoff` flag, and coordinating the stopping and restarting of "Ps". The `stwReason` parameter is important for understanding why the world is being stopped.
    * **`stopTheWorldGC()` and `startTheWorldGC()`:** These are variations of the above, specifically tied to garbage collection, using an additional semaphore (`gcsema`).
    * **`mstart...()` functions:** These define the initialization sequence for new machine threads. They set up the `g0` goroutine, initialize the scheduler, and potentially handle CGo.
    * **`mexit()`:**  This function handles the cleanup and termination of a machine thread, including releasing its "P" and freeing resources.
    * **`forEachP()`:** This function enables executing a given function on every "P" at a GC safe point. It's used for global memory barriers and coordinating actions across all processors.

4. **Inferring the High-Level Feature:** Based on the function names and their interactions, it became clear that this code snippet is heavily involved in **Go's concurrency and runtime management**. Specifically, it deals with:
    * **Goroutine State Management:** Tracking and atomically updating the state of goroutines.
    * **Scheduler Control:** Stopping and starting the execution of goroutines on available processors.
    * **Garbage Collection Coordination:**  Ensuring safe points for garbage collection by pausing and resuming goroutines.
    * **Machine Thread Lifecycle:**  Managing the creation and termination of OS threads used by the Go runtime.

5. **Crafting Examples and Explanations:**
    * **`freezetheworld()`:** I provided a scenario where a fatal error occurs, triggering `freezetheworld`. I highlighted the purpose of `debug.dontfreezetheworld`.
    * **`casgstatus()`:** I demonstrated a simple goroutine state transition and emphasized the atomic nature and the role of `_Gscan`. I added hypothetical input and output for clarity.
    * **`stopTheWorld()` and `startTheWorld()`:** I illustrated a common use case during memory statistics collection, showing the necessity of pausing the world for consistent data.
    * **Command-line arguments:** I specifically looked for mentions of command-line flags (like `debug.dontfreezetheworld`) and explained their purpose and potential impact.
    * **Common mistakes:**  I considered scenarios where users might misuse these low-level functions, focusing on the dangers of directly manipulating goroutine states or calling `stopTheWorld` without proper understanding.

6. **Summarizing Part 2's Functionality:** Finally, I synthesized the individual function analyses to create a concise summary of the provided code segment's overall purpose. I highlighted the core functionalities related to goroutine status, world stopping/starting (especially related to GC), and the management of machine threads.

7. **Iteration and Refinement:**  Throughout this process, I mentally reviewed my understanding and the generated explanations. I checked for consistency, accuracy, and clarity. I tried to anticipate potential questions a reader might have and address them proactively. For example, explaining the purpose of `worldsema` and `gcsema` helps clarify the synchronization mechanisms.

By following these steps, I was able to produce a comprehensive and informative answer that addressed all aspects of the original request. The key was to start with a broad understanding, then progressively drill down into the details of individual functions and finally synthesize the information back into a coherent overview.
这是 `go/src/runtime/proc.go` 文件的一部分，主要涉及 Go 运行时系统中 **goroutine 的状态管理** 和 **停止/启动整个程序世界 (Stop-The-World, STW)** 的机制。

**功能归纳 (针对提供的代码片段):**

这部分代码主要负责以下功能：

1. **安全地冻结整个程序世界 (freezetheworld):**
   - 提供一种在发生严重错误或崩溃时，尝试暂停所有 Goroutine 执行的机制。
   - 它是一个尽力而为的操作，不保证立即停止所有 Goroutine。
   - 主要用于崩溃时的诊断和调试，例如生成堆栈跟踪。

2. **原子地管理 Goroutine 的状态 (readgstatus, casgstatus, castogscanstatus, casfrom_Gscanstatus):**
   - 定义了读取和修改 Goroutine (`g`) 状态的原子操作。
   - 状态的转换需要经过严格的控制，以避免并发问题。
   - 特别地，引入了 `_Gscan` 状态，用于在垃圾回收扫描 Goroutine 时进行标记，确保 GC 的正确性。

3. **停止和启动整个程序世界 (stopTheWorld, startTheWorld, stopTheWorldGC, startTheWorldGC):**
   - 提供了暂停所有 Goroutine 执行的机制，通常用于垃圾回收的标记和清理阶段，以及获取一致的程序状态（例如，生成堆栈快照）。
   - `stopTheWorld` 会阻止所有 P (processor) 执行 Goroutine，并等待它们到达安全点。
   - `startTheWorld` 则会恢复所有 P 的执行。
   - `stopTheWorldGC` 和 `startTheWorldGC` 是针对垃圾回收的特殊版本，会额外阻塞 GC 的启动。

4. **管理 M (machine thread) 的生命周期 (mstart, mstart0, mstart1, mexit, mPark):**
   - `mstart` 系列函数是新 M 的入口点，负责初始化 M 的状态，包括设置栈、关联 G0 Goroutine 等。
   - `mexit` 函数负责清理并退出当前的 M 线程。
   - `mPark` 函数使 M 线程进入休眠状态，等待被唤醒。

5. **在所有 P 上执行特定函数 (forEachP):**
   - 提供了一种在所有 P 上执行特定函数的方法，通常用于需要全局同步的操作，例如 GC 的屏障操作。
   - 它确保函数会在所有 P 都到达安全点后执行。

**核心功能推理与 Go 代码示例:**

这部分代码的核心功能是实现 **Go 语言的并发模型**，特别是 **Goroutine 的调度** 和 **垃圾回收的协同**。

**示例 1: Goroutine 状态转换**

```go
package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// 假设的 _G 类型定义 (实际在 runtime 内部)
type g struct {
	atomicstatus atomic.Uint32
	// ... 其他字段
}

const (
	_Gidle      uint32 = 0 // g has just been created and not yet initialized
	_Grunnable  uint32 = 1 // g is on a run queue
	_Grunning   uint32 = 2 // g is executing Go code
	_Gsyscall   uint32 = 3 // g is executing a system call
	_Gwaiting   uint32 = 4 // g is blocked in runtime
	_Gdead      uint32 = 6 // g is no longer being used
	_Gcopystack uint32 = 8 // g is in the process of stack copying

	// 省略其他状态
)

func main() {
	gp := &g{}

	// 假设我们想将一个新建的 Goroutine 从 _Gidle 状态变为 _Grunnable 状态
	oldStatus := _Gidle
	newStatus := _Grunnable

	// 模拟 runtime 中的 casgstatus 操作
	success := atomic.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&gp.atomicstatus)), oldStatus, newStatus)

	if success {
		fmt.Printf("Goroutine 状态从 %d 成功转换为 %d\n", oldStatus, newStatus)
	} else {
		currentStatus := atomic.LoadUint32(&gp.atomicstatus)
		fmt.Printf("Goroutine 状态转换失败，当前状态为 %d\n", currentStatus)
	}
}
```

**假设的输入与输出:**

* **输入:** 创建一个新的 `g` 结构体，初始状态为 `_Gidle`。
* **输出:** `Goroutine 状态从 0 成功转换为 1`

**示例 2: 停止和启动程序世界**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func worker(id int, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < 5; i++ {
		fmt.Printf("Worker %d: %d\n", id, i)
		time.Sleep(time.Millisecond * 100)
	}
}

func main() {
	var wg sync.WaitGroup
	numWorkers := 3

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(i, &wg)
	}

	fmt.Println("等待所有 Worker 启动...")
	time.Sleep(time.Second) // 模拟等待所有 Goroutine 运行一段时间

	fmt.Println("尝试停止程序世界...")
	// 实际中不应该直接调用 runtime 的私有函数，这里仅为演示
	// runtime.stopTheWorld(runtime.StwReason("演示目的"))
	// 这里我们无法直接模拟 stopTheWorld，因为它需要 runtime 的上下文

	fmt.Println("模拟程序世界已停止，暂停所有 Goroutine 的执行")
	time.Sleep(time.Second * 2) // 模拟程序世界停止的时间

	fmt.Println("尝试启动程序世界...")
	// runtime.startTheWorld()
	fmt.Println("模拟程序世界已启动，恢复所有 Goroutine 的执行")

	wg.Wait()
	fmt.Println("所有 Worker 完成")
}
```

**解释:**  由于 `stopTheWorld` 和 `startTheWorld` 是 runtime 内部函数，我们无法在用户代码中直接调用。上面的代码只是一个概念性的演示，说明了 STW 的大致流程：先停止所有 Goroutine 的执行，执行一些操作（例如 GC），然后再恢复它们的执行。

**命令行参数:**

提供的代码片段中，`freezetheworld` 函数提到了 `debug.dontfreezetheworld`。这实际上不是一个命令行参数，而是一个 **构建标签 (build tag)** 或 **内部调试变量**。

* **`debug.dontfreezetheworld`:**  如果在编译 Go 程序时设置了这个构建标签（例如，使用 `go build -tags="debug"` 并修改 runtime 代码），则在调用 `freezetheworld` 时，Go 运行时会避免真正地停止所有 P，而是允许 Goroutine 继续执行，但这会带来调试上的风险。这通常用于在调试崩溃问题时，允许更精细地观察 Goroutine 的状态。

**使用者易犯错的点:**

由于这部分代码是 Go 运行时的核心部分，普通 Go 开发者通常不会直接使用或接触这些函数。然而，理解这些概念对于理解 Go 的并发模型和性能特征至关重要。

一个可能的误解是 **过度依赖或尝试手动控制 Goroutine 的状态**。Go 的调度器会自动管理 Goroutine 的状态转换，开发者不应该尝试自己去修改或猜测这些状态。错误地操作 Goroutine 状态可能会导致程序崩溃或其他不可预测的行为。

**Part 2 功能总结:**

总而言之，这部分 `go/src/runtime/proc.go` 代码的核心功能是 **提供管理 Goroutine 状态的原子操作** 和 **实现安全地停止和启动整个 Go 程序世界的机制**。这些机制是 Go 运行时系统实现并发、垃圾回收和程序诊断的基础。 `freezetheworld` 提供了在崩溃场景下的特殊处理，而 `mstart` 和 `mexit` 则负责 M 线程的生命周期管理，`forEachP` 用于跨 P 的同步操作。理解这些机制有助于更深入地理解 Go 语言的底层运作原理。

Prompt: 
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共7部分，请归纳一下它的功能

"""
(mp)
}

// freezeStopWait is a large value that freezetheworld sets
// sched.stopwait to in order to request that all Gs permanently stop.
const freezeStopWait = 0x7fffffff

// freezing is set to non-zero if the runtime is trying to freeze the
// world.
var freezing atomic.Bool

// Similar to stopTheWorld but best-effort and can be called several times.
// There is no reverse operation, used during crashing.
// This function must not lock any mutexes.
func freezetheworld() {
	freezing.Store(true)
	if debug.dontfreezetheworld > 0 {
		// Don't prempt Ps to stop goroutines. That will perturb
		// scheduler state, making debugging more difficult. Instead,
		// allow goroutines to continue execution.
		//
		// fatalpanic will tracebackothers to trace all goroutines. It
		// is unsafe to trace a running goroutine, so tracebackothers
		// will skip running goroutines. That is OK and expected, we
		// expect users of dontfreezetheworld to use core files anyway.
		//
		// However, allowing the scheduler to continue running free
		// introduces a race: a goroutine may be stopped when
		// tracebackothers checks its status, and then start running
		// later when we are in the middle of traceback, potentially
		// causing a crash.
		//
		// To mitigate this, when an M naturally enters the scheduler,
		// schedule checks if freezing is set and if so stops
		// execution. This guarantees that while Gs can transition from
		// running to stopped, they can never transition from stopped
		// to running.
		//
		// The sleep here allows racing Ms that missed freezing and are
		// about to run a G to complete the transition to running
		// before we start traceback.
		usleep(1000)
		return
	}

	// stopwait and preemption requests can be lost
	// due to races with concurrently executing threads,
	// so try several times
	for i := 0; i < 5; i++ {
		// this should tell the scheduler to not start any new goroutines
		sched.stopwait = freezeStopWait
		sched.gcwaiting.Store(true)
		// this should stop running goroutines
		if !preemptall() {
			break // no running goroutines
		}
		usleep(1000)
	}
	// to be sure
	usleep(1000)
	preemptall()
	usleep(1000)
}

// All reads and writes of g's status go through readgstatus, casgstatus
// castogscanstatus, casfrom_Gscanstatus.
//
//go:nosplit
func readgstatus(gp *g) uint32 {
	return gp.atomicstatus.Load()
}

// The Gscanstatuses are acting like locks and this releases them.
// If it proves to be a performance hit we should be able to make these
// simple atomic stores but for now we are going to throw if
// we see an inconsistent state.
func casfrom_Gscanstatus(gp *g, oldval, newval uint32) {
	success := false

	// Check that transition is valid.
	switch oldval {
	default:
		print("runtime: casfrom_Gscanstatus bad oldval gp=", gp, ", oldval=", hex(oldval), ", newval=", hex(newval), "\n")
		dumpgstatus(gp)
		throw("casfrom_Gscanstatus:top gp->status is not in scan state")
	case _Gscanrunnable,
		_Gscanwaiting,
		_Gscanrunning,
		_Gscansyscall,
		_Gscanpreempted:
		if newval == oldval&^_Gscan {
			success = gp.atomicstatus.CompareAndSwap(oldval, newval)
		}
	}
	if !success {
		print("runtime: casfrom_Gscanstatus failed gp=", gp, ", oldval=", hex(oldval), ", newval=", hex(newval), "\n")
		dumpgstatus(gp)
		throw("casfrom_Gscanstatus: gp->status is not in scan state")
	}
	releaseLockRankAndM(lockRankGscan)
}

// This will return false if the gp is not in the expected status and the cas fails.
// This acts like a lock acquire while the casfromgstatus acts like a lock release.
func castogscanstatus(gp *g, oldval, newval uint32) bool {
	switch oldval {
	case _Grunnable,
		_Grunning,
		_Gwaiting,
		_Gsyscall:
		if newval == oldval|_Gscan {
			r := gp.atomicstatus.CompareAndSwap(oldval, newval)
			if r {
				acquireLockRankAndM(lockRankGscan)
			}
			return r

		}
	}
	print("runtime: castogscanstatus oldval=", hex(oldval), " newval=", hex(newval), "\n")
	throw("castogscanstatus")
	panic("not reached")
}

// casgstatusAlwaysTrack is a debug flag that causes casgstatus to always track
// various latencies on every transition instead of sampling them.
var casgstatusAlwaysTrack = false

// If asked to move to or from a Gscanstatus this will throw. Use the castogscanstatus
// and casfrom_Gscanstatus instead.
// casgstatus will loop if the g->atomicstatus is in a Gscan status until the routine that
// put it in the Gscan state is finished.
//
//go:nosplit
func casgstatus(gp *g, oldval, newval uint32) {
	if (oldval&_Gscan != 0) || (newval&_Gscan != 0) || oldval == newval {
		systemstack(func() {
			// Call on the systemstack to prevent print and throw from counting
			// against the nosplit stack reservation.
			print("runtime: casgstatus: oldval=", hex(oldval), " newval=", hex(newval), "\n")
			throw("casgstatus: bad incoming values")
		})
	}

	lockWithRankMayAcquire(nil, lockRankGscan)

	// See https://golang.org/cl/21503 for justification of the yield delay.
	const yieldDelay = 5 * 1000
	var nextYield int64

	// loop if gp->atomicstatus is in a scan state giving
	// GC time to finish and change the state to oldval.
	for i := 0; !gp.atomicstatus.CompareAndSwap(oldval, newval); i++ {
		if oldval == _Gwaiting && gp.atomicstatus.Load() == _Grunnable {
			systemstack(func() {
				// Call on the systemstack to prevent throw from counting
				// against the nosplit stack reservation.
				throw("casgstatus: waiting for Gwaiting but is Grunnable")
			})
		}
		if i == 0 {
			nextYield = nanotime() + yieldDelay
		}
		if nanotime() < nextYield {
			for x := 0; x < 10 && gp.atomicstatus.Load() != oldval; x++ {
				procyield(1)
			}
		} else {
			osyield()
			nextYield = nanotime() + yieldDelay/2
		}
	}

	if gp.syncGroup != nil {
		systemstack(func() {
			gp.syncGroup.changegstatus(gp, oldval, newval)
		})
	}

	if oldval == _Grunning {
		// Track every gTrackingPeriod time a goroutine transitions out of running.
		if casgstatusAlwaysTrack || gp.trackingSeq%gTrackingPeriod == 0 {
			gp.tracking = true
		}
		gp.trackingSeq++
	}
	if !gp.tracking {
		return
	}

	// Handle various kinds of tracking.
	//
	// Currently:
	// - Time spent in runnable.
	// - Time spent blocked on a sync.Mutex or sync.RWMutex.
	switch oldval {
	case _Grunnable:
		// We transitioned out of runnable, so measure how much
		// time we spent in this state and add it to
		// runnableTime.
		now := nanotime()
		gp.runnableTime += now - gp.trackingStamp
		gp.trackingStamp = 0
	case _Gwaiting:
		if !gp.waitreason.isMutexWait() {
			// Not blocking on a lock.
			break
		}
		// Blocking on a lock, measure it. Note that because we're
		// sampling, we have to multiply by our sampling period to get
		// a more representative estimate of the absolute value.
		// gTrackingPeriod also represents an accurate sampling period
		// because we can only enter this state from _Grunning.
		now := nanotime()
		sched.totalMutexWaitTime.Add((now - gp.trackingStamp) * gTrackingPeriod)
		gp.trackingStamp = 0
	}
	switch newval {
	case _Gwaiting:
		if !gp.waitreason.isMutexWait() {
			// Not blocking on a lock.
			break
		}
		// Blocking on a lock. Write down the timestamp.
		now := nanotime()
		gp.trackingStamp = now
	case _Grunnable:
		// We just transitioned into runnable, so record what
		// time that happened.
		now := nanotime()
		gp.trackingStamp = now
	case _Grunning:
		// We're transitioning into running, so turn off
		// tracking and record how much time we spent in
		// runnable.
		gp.tracking = false
		sched.timeToRun.record(gp.runnableTime)
		gp.runnableTime = 0
	}
}

// casGToWaiting transitions gp from old to _Gwaiting, and sets the wait reason.
//
// Use this over casgstatus when possible to ensure that a waitreason is set.
func casGToWaiting(gp *g, old uint32, reason waitReason) {
	// Set the wait reason before calling casgstatus, because casgstatus will use it.
	gp.waitreason = reason
	casgstatus(gp, old, _Gwaiting)
}

// casGToWaitingForGC transitions gp from old to _Gwaiting, and sets the wait reason.
// The wait reason must be a valid isWaitingForGC wait reason.
//
// Use this over casgstatus when possible to ensure that a waitreason is set.
func casGToWaitingForGC(gp *g, old uint32, reason waitReason) {
	if !reason.isWaitingForGC() {
		throw("casGToWaitingForGC with non-isWaitingForGC wait reason")
	}
	casGToWaiting(gp, old, reason)
}

// casGToPreemptScan transitions gp from _Grunning to _Gscan|_Gpreempted.
//
// TODO(austin): This is the only status operation that both changes
// the status and locks the _Gscan bit. Rethink this.
func casGToPreemptScan(gp *g, old, new uint32) {
	if old != _Grunning || new != _Gscan|_Gpreempted {
		throw("bad g transition")
	}
	acquireLockRankAndM(lockRankGscan)
	for !gp.atomicstatus.CompareAndSwap(_Grunning, _Gscan|_Gpreempted) {
	}
	// We never notify gp.syncGroup that the goroutine state has moved
	// from _Grunning to _Gpreempted. We call syncGroup.changegstatus
	// after status changes happen, but doing so here would violate the
	// ordering between the gscan and synctest locks. syncGroup doesn't
	// distinguish between _Grunning and _Gpreempted anyway, so not
	// notifying it is fine.
}

// casGFromPreempted attempts to transition gp from _Gpreempted to
// _Gwaiting. If successful, the caller is responsible for
// re-scheduling gp.
func casGFromPreempted(gp *g, old, new uint32) bool {
	if old != _Gpreempted || new != _Gwaiting {
		throw("bad g transition")
	}
	gp.waitreason = waitReasonPreempted
	if !gp.atomicstatus.CompareAndSwap(_Gpreempted, _Gwaiting) {
		return false
	}
	if sg := gp.syncGroup; sg != nil {
		sg.changegstatus(gp, _Gpreempted, _Gwaiting)
	}
	return true
}

// stwReason is an enumeration of reasons the world is stopping.
type stwReason uint8

// Reasons to stop-the-world.
//
// Avoid reusing reasons and add new ones instead.
const (
	stwUnknown                     stwReason = iota // "unknown"
	stwGCMarkTerm                                   // "GC mark termination"
	stwGCSweepTerm                                  // "GC sweep termination"
	stwWriteHeapDump                                // "write heap dump"
	stwGoroutineProfile                             // "goroutine profile"
	stwGoroutineProfileCleanup                      // "goroutine profile cleanup"
	stwAllGoroutinesStack                           // "all goroutines stack trace"
	stwReadMemStats                                 // "read mem stats"
	stwAllThreadsSyscall                            // "AllThreadsSyscall"
	stwGOMAXPROCS                                   // "GOMAXPROCS"
	stwStartTrace                                   // "start trace"
	stwStopTrace                                    // "stop trace"
	stwForTestCountPagesInUse                       // "CountPagesInUse (test)"
	stwForTestReadMetricsSlow                       // "ReadMetricsSlow (test)"
	stwForTestReadMemStatsSlow                      // "ReadMemStatsSlow (test)"
	stwForTestPageCachePagesLeaked                  // "PageCachePagesLeaked (test)"
	stwForTestResetDebugLog                         // "ResetDebugLog (test)"
)

func (r stwReason) String() string {
	return stwReasonStrings[r]
}

func (r stwReason) isGC() bool {
	return r == stwGCMarkTerm || r == stwGCSweepTerm
}

// If you add to this list, also add it to src/internal/trace/parser.go.
// If you change the values of any of the stw* constants, bump the trace
// version number and make a copy of this.
var stwReasonStrings = [...]string{
	stwUnknown:                     "unknown",
	stwGCMarkTerm:                  "GC mark termination",
	stwGCSweepTerm:                 "GC sweep termination",
	stwWriteHeapDump:               "write heap dump",
	stwGoroutineProfile:            "goroutine profile",
	stwGoroutineProfileCleanup:     "goroutine profile cleanup",
	stwAllGoroutinesStack:          "all goroutines stack trace",
	stwReadMemStats:                "read mem stats",
	stwAllThreadsSyscall:           "AllThreadsSyscall",
	stwGOMAXPROCS:                  "GOMAXPROCS",
	stwStartTrace:                  "start trace",
	stwStopTrace:                   "stop trace",
	stwForTestCountPagesInUse:      "CountPagesInUse (test)",
	stwForTestReadMetricsSlow:      "ReadMetricsSlow (test)",
	stwForTestReadMemStatsSlow:     "ReadMemStatsSlow (test)",
	stwForTestPageCachePagesLeaked: "PageCachePagesLeaked (test)",
	stwForTestResetDebugLog:        "ResetDebugLog (test)",
}

// worldStop provides context from the stop-the-world required by the
// start-the-world.
type worldStop struct {
	reason           stwReason
	startedStopping  int64
	finishedStopping int64
	stoppingCPUTime  int64
}

// Temporary variable for stopTheWorld, when it can't write to the stack.
//
// Protected by worldsema.
var stopTheWorldContext worldStop

// stopTheWorld stops all P's from executing goroutines, interrupting
// all goroutines at GC safe points and records reason as the reason
// for the stop. On return, only the current goroutine's P is running.
// stopTheWorld must not be called from a system stack and the caller
// must not hold worldsema. The caller must call startTheWorld when
// other P's should resume execution.
//
// stopTheWorld is safe for multiple goroutines to call at the
// same time. Each will execute its own stop, and the stops will
// be serialized.
//
// This is also used by routines that do stack dumps. If the system is
// in panic or being exited, this may not reliably stop all
// goroutines.
//
// Returns the STW context. When starting the world, this context must be
// passed to startTheWorld.
func stopTheWorld(reason stwReason) worldStop {
	semacquire(&worldsema)
	gp := getg()
	gp.m.preemptoff = reason.String()
	systemstack(func() {
		// Mark the goroutine which called stopTheWorld preemptible so its
		// stack may be scanned.
		// This lets a mark worker scan us while we try to stop the world
		// since otherwise we could get in a mutual preemption deadlock.
		// We must not modify anything on the G stack because a stack shrink
		// may occur. A stack shrink is otherwise OK though because in order
		// to return from this function (and to leave the system stack) we
		// must have preempted all goroutines, including any attempting
		// to scan our stack, in which case, any stack shrinking will
		// have already completed by the time we exit.
		//
		// N.B. The execution tracer is not aware of this status
		// transition and handles it specially based on the
		// wait reason.
		casGToWaitingForGC(gp, _Grunning, waitReasonStoppingTheWorld)
		stopTheWorldContext = stopTheWorldWithSema(reason) // avoid write to stack
		casgstatus(gp, _Gwaiting, _Grunning)
	})
	return stopTheWorldContext
}

// startTheWorld undoes the effects of stopTheWorld.
//
// w must be the worldStop returned by stopTheWorld.
func startTheWorld(w worldStop) {
	systemstack(func() { startTheWorldWithSema(0, w) })

	// worldsema must be held over startTheWorldWithSema to ensure
	// gomaxprocs cannot change while worldsema is held.
	//
	// Release worldsema with direct handoff to the next waiter, but
	// acquirem so that semrelease1 doesn't try to yield our time.
	//
	// Otherwise if e.g. ReadMemStats is being called in a loop,
	// it might stomp on other attempts to stop the world, such as
	// for starting or ending GC. The operation this blocks is
	// so heavy-weight that we should just try to be as fair as
	// possible here.
	//
	// We don't want to just allow us to get preempted between now
	// and releasing the semaphore because then we keep everyone
	// (including, for example, GCs) waiting longer.
	mp := acquirem()
	mp.preemptoff = ""
	semrelease1(&worldsema, true, 0)
	releasem(mp)
}

// stopTheWorldGC has the same effect as stopTheWorld, but blocks
// until the GC is not running. It also blocks a GC from starting
// until startTheWorldGC is called.
func stopTheWorldGC(reason stwReason) worldStop {
	semacquire(&gcsema)
	return stopTheWorld(reason)
}

// startTheWorldGC undoes the effects of stopTheWorldGC.
//
// w must be the worldStop returned by stopTheWorld.
func startTheWorldGC(w worldStop) {
	startTheWorld(w)
	semrelease(&gcsema)
}

// Holding worldsema grants an M the right to try to stop the world.
var worldsema uint32 = 1

// Holding gcsema grants the M the right to block a GC, and blocks
// until the current GC is done. In particular, it prevents gomaxprocs
// from changing concurrently.
//
// TODO(mknyszek): Once gomaxprocs and the execution tracer can handle
// being changed/enabled during a GC, remove this.
var gcsema uint32 = 1

// stopTheWorldWithSema is the core implementation of stopTheWorld.
// The caller is responsible for acquiring worldsema and disabling
// preemption first and then should stopTheWorldWithSema on the system
// stack:
//
//	semacquire(&worldsema, 0)
//	m.preemptoff = "reason"
//	var stw worldStop
//	systemstack(func() {
//		stw = stopTheWorldWithSema(reason)
//	})
//
// When finished, the caller must either call startTheWorld or undo
// these three operations separately:
//
//	m.preemptoff = ""
//	systemstack(func() {
//		now = startTheWorldWithSema(stw)
//	})
//	semrelease(&worldsema)
//
// It is allowed to acquire worldsema once and then execute multiple
// startTheWorldWithSema/stopTheWorldWithSema pairs.
// Other P's are able to execute between successive calls to
// startTheWorldWithSema and stopTheWorldWithSema.
// Holding worldsema causes any other goroutines invoking
// stopTheWorld to block.
//
// Returns the STW context. When starting the world, this context must be
// passed to startTheWorldWithSema.
func stopTheWorldWithSema(reason stwReason) worldStop {
	trace := traceAcquire()
	if trace.ok() {
		trace.STWStart(reason)
		traceRelease(trace)
	}
	gp := getg()

	// If we hold a lock, then we won't be able to stop another M
	// that is blocked trying to acquire the lock.
	if gp.m.locks > 0 {
		throw("stopTheWorld: holding locks")
	}

	lock(&sched.lock)
	start := nanotime() // exclude time waiting for sched.lock from start and total time metrics.
	sched.stopwait = gomaxprocs
	sched.gcwaiting.Store(true)
	preemptall()
	// stop current P
	gp.m.p.ptr().status = _Pgcstop // Pgcstop is only diagnostic.
	gp.m.p.ptr().gcStopTime = start
	sched.stopwait--
	// try to retake all P's in Psyscall status
	trace = traceAcquire()
	for _, pp := range allp {
		s := pp.status
		if s == _Psyscall && atomic.Cas(&pp.status, s, _Pgcstop) {
			if trace.ok() {
				trace.ProcSteal(pp, false)
			}
			pp.syscalltick++
			pp.gcStopTime = nanotime()
			sched.stopwait--
		}
	}
	if trace.ok() {
		traceRelease(trace)
	}

	// stop idle P's
	now := nanotime()
	for {
		pp, _ := pidleget(now)
		if pp == nil {
			break
		}
		pp.status = _Pgcstop
		pp.gcStopTime = nanotime()
		sched.stopwait--
	}
	wait := sched.stopwait > 0
	unlock(&sched.lock)

	// wait for remaining P's to stop voluntarily
	if wait {
		for {
			// wait for 100us, then try to re-preempt in case of any races
			if notetsleep(&sched.stopnote, 100*1000) {
				noteclear(&sched.stopnote)
				break
			}
			preemptall()
		}
	}

	finish := nanotime()
	startTime := finish - start
	if reason.isGC() {
		sched.stwStoppingTimeGC.record(startTime)
	} else {
		sched.stwStoppingTimeOther.record(startTime)
	}

	// Double-check we actually stopped everything, and all the invariants hold.
	// Also accumulate all the time spent by each P in _Pgcstop up to the point
	// where everything was stopped. This will be accumulated into the total pause
	// CPU time by the caller.
	stoppingCPUTime := int64(0)
	bad := ""
	if sched.stopwait != 0 {
		bad = "stopTheWorld: not stopped (stopwait != 0)"
	} else {
		for _, pp := range allp {
			if pp.status != _Pgcstop {
				bad = "stopTheWorld: not stopped (status != _Pgcstop)"
			}
			if pp.gcStopTime == 0 && bad == "" {
				bad = "stopTheWorld: broken CPU time accounting"
			}
			stoppingCPUTime += finish - pp.gcStopTime
			pp.gcStopTime = 0
		}
	}
	if freezing.Load() {
		// Some other thread is panicking. This can cause the
		// sanity checks above to fail if the panic happens in
		// the signal handler on a stopped thread. Either way,
		// we should halt this thread.
		lock(&deadlock)
		lock(&deadlock)
	}
	if bad != "" {
		throw(bad)
	}

	worldStopped()

	return worldStop{
		reason:           reason,
		startedStopping:  start,
		finishedStopping: finish,
		stoppingCPUTime:  stoppingCPUTime,
	}
}

// reason is the same STW reason passed to stopTheWorld. start is the start
// time returned by stopTheWorld.
//
// now is the current time; prefer to pass 0 to capture a fresh timestamp.
//
// stattTheWorldWithSema returns now.
func startTheWorldWithSema(now int64, w worldStop) int64 {
	assertWorldStopped()

	mp := acquirem() // disable preemption because it can be holding p in a local var
	if netpollinited() {
		list, delta := netpoll(0) // non-blocking
		injectglist(&list)
		netpollAdjustWaiters(delta)
	}
	lock(&sched.lock)

	procs := gomaxprocs
	if newprocs != 0 {
		procs = newprocs
		newprocs = 0
	}
	p1 := procresize(procs)
	sched.gcwaiting.Store(false)
	if sched.sysmonwait.Load() {
		sched.sysmonwait.Store(false)
		notewakeup(&sched.sysmonnote)
	}
	unlock(&sched.lock)

	worldStarted()

	for p1 != nil {
		p := p1
		p1 = p1.link.ptr()
		if p.m != 0 {
			mp := p.m.ptr()
			p.m = 0
			if mp.nextp != 0 {
				throw("startTheWorld: inconsistent mp->nextp")
			}
			mp.nextp.set(p)
			notewakeup(&mp.park)
		} else {
			// Start M to run P.  Do not start another M below.
			newm(nil, p, -1)
		}
	}

	// Capture start-the-world time before doing clean-up tasks.
	if now == 0 {
		now = nanotime()
	}
	totalTime := now - w.startedStopping
	if w.reason.isGC() {
		sched.stwTotalTimeGC.record(totalTime)
	} else {
		sched.stwTotalTimeOther.record(totalTime)
	}
	trace := traceAcquire()
	if trace.ok() {
		trace.STWDone()
		traceRelease(trace)
	}

	// Wakeup an additional proc in case we have excessive runnable goroutines
	// in local queues or in the global queue. If we don't, the proc will park itself.
	// If we have lots of excessive work, resetspinning will unpark additional procs as necessary.
	wakep()

	releasem(mp)

	return now
}

// usesLibcall indicates whether this runtime performs system calls
// via libcall.
func usesLibcall() bool {
	switch GOOS {
	case "aix", "darwin", "illumos", "ios", "solaris", "windows":
		return true
	case "openbsd":
		return GOARCH != "mips64"
	}
	return false
}

// mStackIsSystemAllocated indicates whether this runtime starts on a
// system-allocated stack.
func mStackIsSystemAllocated() bool {
	switch GOOS {
	case "aix", "darwin", "plan9", "illumos", "ios", "solaris", "windows":
		return true
	case "openbsd":
		return GOARCH != "mips64"
	}
	return false
}

// mstart is the entry-point for new Ms.
// It is written in assembly, uses ABI0, is marked TOPFRAME, and calls mstart0.
func mstart()

// mstart0 is the Go entry-point for new Ms.
// This must not split the stack because we may not even have stack
// bounds set up yet.
//
// May run during STW (because it doesn't have a P yet), so write
// barriers are not allowed.
//
//go:nosplit
//go:nowritebarrierrec
func mstart0() {
	gp := getg()

	osStack := gp.stack.lo == 0
	if osStack {
		// Initialize stack bounds from system stack.
		// Cgo may have left stack size in stack.hi.
		// minit may update the stack bounds.
		//
		// Note: these bounds may not be very accurate.
		// We set hi to &size, but there are things above
		// it. The 1024 is supposed to compensate this,
		// but is somewhat arbitrary.
		size := gp.stack.hi
		if size == 0 {
			size = 16384 * sys.StackGuardMultiplier
		}
		gp.stack.hi = uintptr(noescape(unsafe.Pointer(&size)))
		gp.stack.lo = gp.stack.hi - size + 1024
	}
	// Initialize stack guard so that we can start calling regular
	// Go code.
	gp.stackguard0 = gp.stack.lo + stackGuard
	// This is the g0, so we can also call go:systemstack
	// functions, which check stackguard1.
	gp.stackguard1 = gp.stackguard0
	mstart1()

	// Exit this thread.
	if mStackIsSystemAllocated() {
		// Windows, Solaris, illumos, Darwin, AIX and Plan 9 always system-allocate
		// the stack, but put it in gp.stack before mstart,
		// so the logic above hasn't set osStack yet.
		osStack = true
	}
	mexit(osStack)
}

// The go:noinline is to guarantee the sys.GetCallerPC/sys.GetCallerSP below are safe,
// so that we can set up g0.sched to return to the call of mstart1 above.
//
//go:noinline
func mstart1() {
	gp := getg()

	if gp != gp.m.g0 {
		throw("bad runtime·mstart")
	}

	// Set up m.g0.sched as a label returning to just
	// after the mstart1 call in mstart0 above, for use by goexit0 and mcall.
	// We're never coming back to mstart1 after we call schedule,
	// so other calls can reuse the current frame.
	// And goexit0 does a gogo that needs to return from mstart1
	// and let mstart0 exit the thread.
	gp.sched.g = guintptr(unsafe.Pointer(gp))
	gp.sched.pc = sys.GetCallerPC()
	gp.sched.sp = sys.GetCallerSP()

	asminit()
	minit()

	// Install signal handlers; after minit so that minit can
	// prepare the thread to be able to handle the signals.
	if gp.m == &m0 {
		mstartm0()
	}

	if debug.dataindependenttiming == 1 {
		sys.EnableDIT()
	}

	if fn := gp.m.mstartfn; fn != nil {
		fn()
	}

	if gp.m != &m0 {
		acquirep(gp.m.nextp.ptr())
		gp.m.nextp = 0
	}
	schedule()
}

// mstartm0 implements part of mstart1 that only runs on the m0.
//
// Write barriers are allowed here because we know the GC can't be
// running yet, so they'll be no-ops.
//
//go:yeswritebarrierrec
func mstartm0() {
	// Create an extra M for callbacks on threads not created by Go.
	// An extra M is also needed on Windows for callbacks created by
	// syscall.NewCallback. See issue #6751 for details.
	if (iscgo || GOOS == "windows") && !cgoHasExtraM {
		cgoHasExtraM = true
		newextram()
	}
	initsig(false)
}

// mPark causes a thread to park itself, returning once woken.
//
//go:nosplit
func mPark() {
	gp := getg()
	notesleep(&gp.m.park)
	noteclear(&gp.m.park)
}

// mexit tears down and exits the current thread.
//
// Don't call this directly to exit the thread, since it must run at
// the top of the thread stack. Instead, use gogo(&gp.m.g0.sched) to
// unwind the stack to the point that exits the thread.
//
// It is entered with m.p != nil, so write barriers are allowed. It
// will release the P before exiting.
//
//go:yeswritebarrierrec
func mexit(osStack bool) {
	mp := getg().m

	if mp == &m0 {
		// This is the main thread. Just wedge it.
		//
		// On Linux, exiting the main thread puts the process
		// into a non-waitable zombie state. On Plan 9,
		// exiting the main thread unblocks wait even though
		// other threads are still running. On Solaris we can
		// neither exitThread nor return from mstart. Other
		// bad things probably happen on other platforms.
		//
		// We could try to clean up this M more before wedging
		// it, but that complicates signal handling.
		handoffp(releasep())
		lock(&sched.lock)
		sched.nmfreed++
		checkdead()
		unlock(&sched.lock)
		mPark()
		throw("locked m0 woke up")
	}

	sigblock(true)
	unminit()

	// Free the gsignal stack.
	if mp.gsignal != nil {
		stackfree(mp.gsignal.stack)
		// On some platforms, when calling into VDSO (e.g. nanotime)
		// we store our g on the gsignal stack, if there is one.
		// Now the stack is freed, unlink it from the m, so we
		// won't write to it when calling VDSO code.
		mp.gsignal = nil
	}

	// Remove m from allm.
	lock(&sched.lock)
	for pprev := &allm; *pprev != nil; pprev = &(*pprev).alllink {
		if *pprev == mp {
			*pprev = mp.alllink
			goto found
		}
	}
	throw("m not found in allm")
found:
	// Events must not be traced after this point.

	// Delay reaping m until it's done with the stack.
	//
	// Put mp on the free list, though it will not be reaped while freeWait
	// is freeMWait. mp is no longer reachable via allm, so even if it is
	// on an OS stack, we must keep a reference to mp alive so that the GC
	// doesn't free mp while we are still using it.
	//
	// Note that the free list must not be linked through alllink because
	// some functions walk allm without locking, so may be using alllink.
	//
	// N.B. It's important that the M appears on the free list simultaneously
	// with it being removed so that the tracer can find it.
	mp.freeWait.Store(freeMWait)
	mp.freelink = sched.freem
	sched.freem = mp
	unlock(&sched.lock)

	atomic.Xadd64(&ncgocall, int64(mp.ncgocall))
	sched.totalRuntimeLockWaitTime.Add(mp.mLockProfile.waitTime.Load())

	// Release the P.
	handoffp(releasep())
	// After this point we must not have write barriers.

	// Invoke the deadlock detector. This must happen after
	// handoffp because it may have started a new M to take our
	// P's work.
	lock(&sched.lock)
	sched.nmfreed++
	checkdead()
	unlock(&sched.lock)

	if GOOS == "darwin" || GOOS == "ios" {
		// Make sure pendingPreemptSignals is correct when an M exits.
		// For #41702.
		if mp.signalPending.Load() != 0 {
			pendingPreemptSignals.Add(-1)
		}
	}

	// Destroy all allocated resources. After this is called, we may no
	// longer take any locks.
	mdestroy(mp)

	if osStack {
		// No more uses of mp, so it is safe to drop the reference.
		mp.freeWait.Store(freeMRef)

		// Return from mstart and let the system thread
		// library free the g0 stack and terminate the thread.
		return
	}

	// mstart is the thread's entry point, so there's nothing to
	// return to. Exit the thread directly. exitThread will clear
	// m.freeWait when it's done with the stack and the m can be
	// reaped.
	exitThread(&mp.freeWait)
}

// forEachP calls fn(p) for every P p when p reaches a GC safe point.
// If a P is currently executing code, this will bring the P to a GC
// safe point and execute fn on that P. If the P is not executing code
// (it is idle or in a syscall), this will call fn(p) directly while
// preventing the P from exiting its state. This does not ensure that
// fn will run on every CPU executing Go code, but it acts as a global
// memory barrier. GC uses this as a "ragged barrier."
//
// The caller must hold worldsema. fn must not refer to any
// part of the current goroutine's stack, since the GC may move it.
func forEachP(reason waitReason, fn func(*p)) {
	systemstack(func() {
		gp := getg().m.curg
		// Mark the user stack as preemptible so that it may be scanned.
		// Otherwise, our attempt to force all P's to a safepoint could
		// result in a deadlock as we attempt to preempt a worker that's
		// trying to preempt us (e.g. for a stack scan).
		//
		// N.B. The execution tracer is not aware of this status
		// transition and handles it specially based on the
		// wait reason.
		casGToWaitingForGC(gp, _Grunning, reason)
		forEachPInternal(fn)
		casgstatus(gp, _Gwaiting, _Grunning)
	})
}

// forEachPInternal calls fn(p) for every P p when p reaches a GC safe point.
// It is the internal implementation of forEachP.
//
// The caller must hold worldsema and either must ensure that a GC is not
// running (otherwise this may deadlock with the GC trying to preempt this P)
// or it must leave its goroutine in a preemptible state before it switches
// to the systemstack. Due to these restrictions, prefer forEachP when possible.
//
//go:systemstack
func forEachPInternal(fn func(*p)) {
	mp := acquirem()
	pp := getg().m.p.ptr()

	lock(&sched.lock)
	if sched.safePointWait != 0 {
		throw("forEachP: sched.safePointWait != 0")
	}
	sched.safePointWait = gomaxprocs - 1
	sched.safePointFn = fn

	// Ask all Ps to run the safe point function.
	for _, p2 := range allp {
		if p2 != pp {
			atomic.Store(&p2.runSafePointFn, 1)
		}
	}
	preemptall()

	// Any P entering _Pidle or _Psyscall from now on will observe
	// p.runSafePointFn == 1 and will call runSafePointFn when
	// changing its status to _Pidle/_Psyscall.

	// Run safe point function for all idle Ps. sched.pidle will
	// not change because we hold sched.lock.
	for p := sched.pidle.ptr(); p != nil; p = p.link.ptr() {
		if atomic.Cas(&p.runSafePointFn, 1, 0) {
			fn(p)
			sched.safePointWait--
		}
	}

	wait := sched.safePointWait > 0
	unlock(&sched.lock)

	// Run fn for the current P.
	fn(pp)

	// Force Ps currently in _Psyscall into _Pidle and hand them
	// off to induce safe point function execution.
	for _, p2 := range allp {
		s := p2.status

		// We need to be fine-grained about tracing here, since handoffp
		// might call into the tracer, and the tracer is non-reentrant.
		trace := traceAcquire()
		if s == _Psyscall && p2.runSafePointFn == 1 && atomic.Cas(&p2.status, s, _Pidle) {
			if trace.ok() {
				// It's important that we traceRelease before we call handoffp, which may also traceAcquire.
				trace.ProcSteal(p2, false)
				traceRelease(trace)
			}
			p2.syscalltick++
			handoffp(p2)
		} else if trace.ok() {
			traceRelease(trace)
		}
	}

	// Wait for remaining Ps to run fn.
	if wait {
		fo
"""




```