Response:
Let's break down the thought process for analyzing this Go GC code snippet and answering the user's request.

**1. Understanding the Request:**

The core request is to understand the *functionality* of the provided Go code snippet, which is part of the garbage collector (`mgc.go`). The user also asks for specific ways to illustrate this functionality (Go code examples, command-line parameters, common mistakes) and wants a summary of the code's purpose. The "Part 2 of 3" indicates context and that there are likely related code sections.

**2. Initial Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for prominent keywords and function names. Words like `gcMarkDone`, `gcMarkTermination`, `gcMark`, `gcSweep`, `stopTheWorld`, `startTheWorld`, `write barrier`, `mark bits`, `background marking`, `assists`, `CPU limiter`, `heap`, `stack`, and variables like `work`, `gcphase`, `memstats` jump out. These are strong indicators of the code's purpose.

**3. Identifying Key Functions and Their Roles:**

Based on the keywords, I can start to identify the major functions and their likely roles:

* **`gcMarkDone()`:**  This function seems to be a central point where the concurrent marking phase *completes* (or is thought to be complete). The logic around checking for remaining work, stopping the world, and transitioning to `gcMarkTermination` is evident.
* **`gcMarkTermination()`:** This function clearly handles the *finalization* of the marking phase. It includes actions like turning off the write barrier, performing a final mark (potentially), and initiating sweeping.
* **`gcMark()`:** Called within `gcMarkTermination`, this function seems to be the actual implementation of the (final) marking process when the world is stopped.
* **`gcSweep()`:**  This function is responsible for *sweeping* the heap, reclaiming unmarked memory. It handles both concurrent and stop-the-world sweeping.
* **`gcBgMarkStartWorkers()` and `gcBgMarkWorker()`:**  These functions are clearly related to *concurrent* marking, as suggested by "background." They manage worker goroutines that assist in the marking process.

**4. Tracing the Control Flow:**

Understanding how these functions interact is crucial. I can see a sequence:

* Concurrent marking is ongoing (not shown in this snippet).
* `gcMarkDone()` is called when the GC *thinks* marking is finished.
* `gcMarkDone()` checks for remaining work and potentially restarts marking.
* If no restart is needed, `gcMarkDone()` transitions to `gcMarkTermination()`.
* `gcMarkTermination()` stops the world, calls `gcMark()`, and then `gcSweep()`.

**5. Inferring the Purpose of Code Blocks:**

With the overall flow in mind, I can examine specific code blocks:

* **Stopping and Starting the World (`stopTheWorldWithSema`, `startTheWorldWithSema`):**  These clearly manage the stop-the-world pauses essential for certain GC phases.
* **Write Barrier Handling (`wbBufFlush1`):**  The presence of this function indicates the code deals with write barriers, which are crucial for concurrent GC to track object modifications.
* **CPU Limiter (`gcCPULimiter`):**  The code explicitly interacts with a CPU limiter, suggesting mechanisms to control the GC's CPU usage.
* **Assists (`gcWakeAllAssists`):**  The mention of "assists" points to a mechanism where regular goroutines can contribute to the GC effort.
* **Memory Statistics (`memstats`):**  Updates to `memstats` are present, indicating the code tracks and records GC-related metrics.

**6. Addressing Specific User Questions:**

* **Functionality Listing:**  This is a direct result of the above analysis. I can list the identified functions and their roles.
* **Go Language Feature:**  The code clearly implements the *garbage collection* mechanism in Go, specifically the mark and sweep phases, including concurrent aspects.
* **Go Code Example:**  To illustrate GC, a simple program that allocates memory and triggers GC (either explicitly or implicitly) is appropriate. Demonstrating the impact of GC on memory usage is key.
* **Input/Output:** For the code example, the input is the program's execution, and the output is the memory usage before and after GC.
* **Command-Line Parameters:** The `GODEBUG` environment variable is the standard way to influence Go's runtime behavior, including GC. `gctrace` is a relevant example.
* **Common Mistakes:**  Understanding how GC works helps identify potential pitfalls, like relying on immediate finalization or creating excessive garbage.
* **Functionality Summary:**  This is a concise restatement of the overall purpose of the code, focusing on mark and sweep, concurrency, and world stopping.

**7. Structuring the Answer:**

Finally, I need to organize the information logically, using clear and concise language. Headings and bullet points improve readability. Providing code examples and explanations directly addresses the user's request.

**Self-Correction/Refinement During the Process:**

* **Initial Over-Simplification:**  I might initially think `gcMarkDone` simply finishes marking, but the code reveals the check for remaining work and potential restarts.
* **Focusing on Keywords:**  Relying solely on keywords might miss nuanced behavior. Careful reading of the code within functions is crucial.
* **Assuming Linearity:** The concurrent nature of the GC requires understanding that operations might not happen strictly sequentially.
* **Clarity of Examples:**  Ensuring the Go code example is simple yet effectively demonstrates the GC's impact is important. Adding explanations to the code is necessary.

By following these steps, combining code analysis with knowledge of Go's GC principles, and refining my understanding through careful reading, I can generate a comprehensive and accurate answer to the user's request.
这是 Go 语言运行时（runtime）中垃圾回收（Garbage Collection，GC）机制的一部分，具体来说是并发标记阶段的收尾工作。

**功能归纳:**

这段代码主要负责并发标记阶段的结束处理和向下一个 GC 周期过渡：

1. **等待并发标记完成:** `semacquire(&work.markDoneSema)` 确保所有的并发标记工作都已完成。
2. **检测并处理遗留工作:** 检查是否存在由于写屏障在完成屏障之后执行而产生的遗留的待标记对象。如果存在，会重启并发标记。这是一个异常情况，通常是为了解决特定问题（如 issue #27993）。
3. **禁用辅助和后台工作者:**  `atomic.Store(&gcBlackenEnabled, 0)` 禁用 GC 辅助和后台标记工作者。
4. **唤醒阻塞的辅助 Goroutine 和弱引用转换:** 释放相关的信号量，允许被阻塞的 GC 辅助 Goroutine 和等待弱引用转强的 Goroutine 继续执行。这些 Goroutine 会在世界重新启动后运行。
5. **切换到 STW (Stop-The-World) 模式并执行最终标记和清理:**
    * `stopTheWorldWithSema(stwGCMarkTerm)` 停止所有用户 Goroutine。
    * `gcMarkTermination(stw)` 执行最终的标记终止阶段。
    * `gcMark(startTime)` 在 STW 模式下进行最后的标记扫描，确保没有遗漏的对象。
    * `gcSweep(work.mode)` 执行垃圾清理，回收未标记的内存。
6. **更新 GC 控制器和统计信息:** 更新 GC 的触发阈值、步调，以及相关的内存统计信息。
7. **重置 GC 状态:**  为下一个 GC 周期做准备，例如重置标记状态。
8. **启动或唤醒后台清理 Goroutine:** 如果是并发清理，则唤醒清理 Goroutine。
9. **释放世界和 GC 信号量:**  `semrelease(&worldsema)` 和 `semrelease(&gcsema)` 允许用户 Goroutine 继续运行，并允许下一个 GC 周期开始。

**更详细的功能拆解:**

* **`semacquire(&work.markDoneSema)`:** 这是一个阻塞操作，当前 Goroutine 会一直等待，直到 `work.markDoneSema` 信号量的值大于 0。这个信号量在并发标记工作者完成任务时会被释放，因此这里起到了同步的作用，确保在进行后续操作前，并发标记阶段已完成。

* **检查遗留工作并重启标记 (处理 issue #27993):**  由于写屏障是在并发执行的，有可能在并发标记的完成屏障之后，又有新的指针写入操作发生，导致新的灰色对象产生。这段代码会检查每个 P 的写屏障缓冲区 (`wbBufFlush1(p)`) 和 GC 工作队列 (`!p.gcw.empty()`)，如果发现有遗留的未处理对象，则会重启并发标记。这是一个相对罕见的情况，主要是为了保证 GC 的正确性。

* **`stopTheWorldWithSema(stwGCMarkTerm)` 和 `startTheWorldWithSema(...)`:**  这两个函数是 Go 语言 GC 中重要的组成部分，用于暂停和恢复所有用户 Goroutine 的执行。`stopTheWorldWithSema` 会阻塞直到所有 Goroutine 进入安全点，然后暂停它们。`startTheWorldWithSema` 则会唤醒并允许这些 Goroutine 继续执行。`stwGCMarkTerm` 是一个特定的停止世界的原因，表明是为了标记终止阶段。

* **`gcMarkTermination(stw)`:**  这个函数负责执行标记终止的逻辑。它会设置 GC 的状态为 `_GCmarktermination`，记录堆信息，并在系统栈上调用 `gcMark` 执行最后的标记工作。

* **`gcMark(startTime)`:**  在世界停止的情况下执行最后的标记操作。由于并发标记阶段可能存在遗漏，这里需要进行最终的扫描，确保所有可达对象都被标记。

* **`gcSweep(work.mode)`:**  负责执行垃圾清理阶段，回收所有未被标记的对象所占用的内存。`work.mode` 参数决定了清理的模式（例如，强制阻塞清理或并发清理）。

* **禁用辅助和后台工作者，唤醒阻塞的 Goroutine:**  在标记阶段完成后，不再需要辅助 Goroutine 和后台标记工作者参与，因此需要禁用它们。同时，之前因为等待标记完成而被阻塞的辅助 Goroutine 和弱引用转换操作可以被唤醒，以便在世界重启后继续执行。

* **更新 GC 控制器和统计信息:** `gcController.endCycle(...)` 会根据当前的 GC 结果更新 GC 控制器的状态，例如调整下一次 GC 的触发时机。同时，代码还会更新各种内存统计信息，例如暂停时间、GC 周期等，这些信息可以通过 `runtime.MemStats` 获取。

**Go 代码示例 (说明 GC 的触发和基本流程):**

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc before GC: %v bytes\n", m.Alloc)

	// 分配大量内存，触发 GC
	for i := 0; i < 1000000; i++ {
		_ = make([]byte, 1024)
	}

	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc after allocation but before explicit GC: %v bytes\n", m.Alloc)

	// 手动触发 GC
	runtime.GC()

	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc after explicit GC: %v bytes\n", m.Alloc)

	// 等待一段时间，可能触发后台 GC
	time.Sleep(time.Second * 2)
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc after waiting (potential background GC): %v bytes\n", m.Alloc)
}
```

**假设的输入与输出:**

* **输入:** 程序执行，分配大量内存。
* **输出:**
  ```
  Alloc before GC: 295408 bytes
  Alloc after allocation but before explicit GC: 104888448 bytes
  Alloc after explicit GC: 332968 bytes
  Alloc after waiting (potential background GC): 332968 bytes
  ```

**解释:**

* `Alloc before GC`:  程序开始时已分配的内存。
* `Alloc after allocation but before explicit GC`:  分配大量内存后，`Alloc` 显著增加。此时，GC 可能尚未运行。
* `Alloc after explicit GC`: 调用 `runtime.GC()` 后，触发了垃圾回收，未使用的内存被回收，`Alloc` 降低。
* `Alloc after waiting (potential background GC)`:  等待一段时间后，后台 GC 可能运行，但在这个简单的例子中，由于之前的显式 GC 已经清理了大部分垃圾，所以 `Alloc` 可能没有明显变化。

**涉及代码推理:**

* **`semrelease(&worldsema)`:**  这个操作会释放 `worldsema` 信号量，该信号量控制着用户 Goroutine 的运行。释放后，之前被 `stopTheWorldWithSema` 暂停的 Goroutine 就可以继续执行了。这标志着 STW 阶段的结束，程序恢复正常运行。

* **`semrelease(&gcsema)`:**  这个操作会释放 `gcsema` 信号量，该信号量用于控制 GC 的并发执行。释放后，如果有其他 Goroutine 正在等待开始新的 GC 周期，它们就可以继续执行。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。Go 语言的 GC 行为可以通过环境变量 `GODEBUG` 进行配置。一些相关的 `GODEBUG` 参数包括：

* **`gctrace=1`:**  启用 GC 跟踪，会在每次 GC 发生时打印详细的统计信息，包括各个阶段的耗时、堆内存使用情况等。这对于分析 GC 行为非常有用。
* **`gc=off`:**  完全禁用垃圾回收。这通常只在非常特殊的场景下使用，因为没有 GC 会导致内存泄漏。
* **`hardgcbudget=value` 和 `softgcbudget=value`:**  控制并发 GC 的步调。
* **` Scavenge=disable`**: 禁用内存回收（scavenger）。

这些参数会在 Go 程序启动时被读取并影响 GC 的运行方式。例如，如果设置了 `GODEBUG=gctrace=1`，每次 GC 完成后，控制台会输出类似以下的信息：

```
gc 1 @0.004s 0%: 0.002+0.068 ms clock, 0.004+0.045/0.038/0+0.004 ms cpu, 4->4->4 MB, 5 MB goal, 16 P
```

这个输出包含了 GC 发生的次数、时间、各阶段耗时、内存使用情况等详细信息，可以帮助开发者理解 GC 的行为和性能。

**使用者易犯错的点 (与 GC 相关，不一定直接对应这段代码):**

1. **过度依赖 `runtime.GC()`:**  显式调用 `runtime.GC()` 可能会导致性能问题。Go 的 GC 设计为自动运行，通常不需要手动触发。过度调用反而可能干扰 GC 的正常工作，造成不必要的 STW 延迟。

   ```go
   // 不推荐的做法
   for i := 0; i < 1000; i++ {
       allocateMemory()
       runtime.GC() // 频繁手动触发 GC
   }
   ```

2. **误解 Finalizer 的执行时机:**  Finalizer（通过 `runtime.SetFinalizer` 设置）的执行时机是不确定的，不应该依赖 Finalizer 来释放重要的资源（例如文件句柄）。Finalizer 在 GC 认为对象不可达时会被调用，但这可能在很久之后。

   ```go
   // 错误的做法：依赖 Finalizer 关闭文件
   type MyResource struct {
       f *os.File
   }

   func NewMyResource(filename string) *MyResource {
       f, _ := os.Open(filename)
       res := &MyResource{f: f}
       runtime.SetFinalizer(res, func(r *MyResource) {
           r.f.Close() // Finalizer 的执行时机不确定
           fmt.Println("File closed in finalizer")
       })
       return res
   }

   func main() {
       res := NewMyResource("test.txt")
       // ... 使用 res ...
       // 忘记显式关闭文件，期望 Finalizer 处理
   }
   ```
   **正确的做法是使用 `defer` 显式关闭资源。**

3. **创建过多临时对象:**  在循环或其他性能敏感的代码中创建过多的临时对象会给 GC 带来压力，导致更频繁的 GC 和更高的 CPU 占用。应该尽量重用对象或使用 `sync.Pool` 来减少对象分配。

   ```go
   // 可能导致频繁 GC 的代码
   for i := 0; i < 10000; i++ {
       data := make([]byte, 1024) // 每次循环都分配新的切片
       processData(data)
   }

   // 优化后的代码，重用切片
   var data []byte = make([]byte, 1024)
   for i := 0; i < 10000; i++ {
       processData(data)
   }
   ```

这段代码是 Go 语言 GC 并发标记阶段结束的关键部分，它协调了各个组件，确保标记工作的完成，并安全地过渡到清理阶段，最终恢复程序的正常运行。理解这段代码有助于深入理解 Go 语言的内存管理机制。

### 提示词
```
这是路径为go/src/runtime/mgc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
ier.Load() {
	}

	// There was no global work, no local work, and no Ps
	// communicated work since we took markDoneSema. Therefore
	// there are no grey objects and no more objects can be
	// shaded. Transition to mark termination.
	now := nanotime()
	work.tMarkTerm = now
	getg().m.preemptoff = "gcing"
	var stw worldStop
	systemstack(func() {
		stw = stopTheWorldWithSema(stwGCMarkTerm)
	})
	// The gcphase is _GCmark, it will transition to _GCmarktermination
	// below. The important thing is that the wb remains active until
	// all marking is complete. This includes writes made by the GC.

	// Accumulate fine-grained stopping time.
	work.cpuStats.accumulateGCPauseTime(stw.stoppingCPUTime, 1)

	// There is sometimes work left over when we enter mark termination due
	// to write barriers performed after the completion barrier above.
	// Detect this and resume concurrent mark. This is obviously
	// unfortunate.
	//
	// See issue #27993 for details.
	//
	// Switch to the system stack to call wbBufFlush1, though in this case
	// it doesn't matter because we're non-preemptible anyway.
	restart := false
	systemstack(func() {
		for _, p := range allp {
			wbBufFlush1(p)
			if !p.gcw.empty() {
				restart = true
				break
			}
		}
	})
	if restart {
		gcDebugMarkDone.restartedDueTo27993 = true

		getg().m.preemptoff = ""
		systemstack(func() {
			// Accumulate the time we were stopped before we had to start again.
			work.cpuStats.accumulateGCPauseTime(nanotime()-stw.finishedStopping, work.maxprocs)

			// Start the world again.
			now := startTheWorldWithSema(0, stw)
			work.pauseNS += now - stw.startedStopping
		})
		semrelease(&worldsema)
		goto top
	}

	gcComputeStartingStackSize()

	// Disable assists and background workers. We must do
	// this before waking blocked assists.
	atomic.Store(&gcBlackenEnabled, 0)

	// Notify the CPU limiter that GC assists will now cease.
	gcCPULimiter.startGCTransition(false, now)

	// Wake all blocked assists. These will run when we
	// start the world again.
	gcWakeAllAssists()

	// Wake all blocked weak->strong conversions. These will run
	// when we start the world again.
	work.strongFromWeak.block = false
	gcWakeAllStrongFromWeak()

	// Likewise, release the transition lock. Blocked
	// workers and assists will run when we start the
	// world again.
	semrelease(&work.markDoneSema)

	// In STW mode, re-enable user goroutines. These will be
	// queued to run after we start the world.
	schedEnableUser(true)

	// endCycle depends on all gcWork cache stats being flushed.
	// The termination algorithm above ensured that up to
	// allocations since the ragged barrier.
	gcController.endCycle(now, int(gomaxprocs), work.userForced)

	// Perform mark termination. This will restart the world.
	gcMarkTermination(stw)
}

// World must be stopped and mark assists and background workers must be
// disabled.
func gcMarkTermination(stw worldStop) {
	// Start marktermination (write barrier remains enabled for now).
	setGCPhase(_GCmarktermination)

	work.heap1 = gcController.heapLive.Load()
	startTime := nanotime()

	mp := acquirem()
	mp.preemptoff = "gcing"
	mp.traceback = 2
	curgp := mp.curg
	// N.B. The execution tracer is not aware of this status
	// transition and handles it specially based on the
	// wait reason.
	casGToWaitingForGC(curgp, _Grunning, waitReasonGarbageCollection)

	// Run gc on the g0 stack. We do this so that the g stack
	// we're currently running on will no longer change. Cuts
	// the root set down a bit (g0 stacks are not scanned, and
	// we don't need to scan gc's internal state).  We also
	// need to switch to g0 so we can shrink the stack.
	systemstack(func() {
		gcMark(startTime)
		// Must return immediately.
		// The outer function's stack may have moved
		// during gcMark (it shrinks stacks, including the
		// outer function's stack), so we must not refer
		// to any of its variables. Return back to the
		// non-system stack to pick up the new addresses
		// before continuing.
	})

	var stwSwept bool
	systemstack(func() {
		work.heap2 = work.bytesMarked
		if debug.gccheckmark > 0 {
			// Run a full non-parallel, stop-the-world
			// mark using checkmark bits, to check that we
			// didn't forget to mark anything during the
			// concurrent mark process.
			startCheckmarks()
			gcResetMarkState()
			gcw := &getg().m.p.ptr().gcw
			gcDrain(gcw, 0)
			wbBufFlush1(getg().m.p.ptr())
			gcw.dispose()
			endCheckmarks()
		}

		// marking is complete so we can turn the write barrier off
		setGCPhase(_GCoff)
		stwSwept = gcSweep(work.mode)
	})

	mp.traceback = 0
	casgstatus(curgp, _Gwaiting, _Grunning)

	trace := traceAcquire()
	if trace.ok() {
		trace.GCDone()
		traceRelease(trace)
	}

	// all done
	mp.preemptoff = ""

	if gcphase != _GCoff {
		throw("gc done but gcphase != _GCoff")
	}

	// Record heapInUse for scavenger.
	memstats.lastHeapInUse = gcController.heapInUse.load()

	// Update GC trigger and pacing, as well as downstream consumers
	// of this pacing information, for the next cycle.
	systemstack(gcControllerCommit)

	// Update timing memstats
	now := nanotime()
	sec, nsec, _ := time_now()
	unixNow := sec*1e9 + int64(nsec)
	work.pauseNS += now - stw.startedStopping
	work.tEnd = now
	atomic.Store64(&memstats.last_gc_unix, uint64(unixNow)) // must be Unix time to make sense to user
	atomic.Store64(&memstats.last_gc_nanotime, uint64(now)) // monotonic time for us
	memstats.pause_ns[memstats.numgc%uint32(len(memstats.pause_ns))] = uint64(work.pauseNS)
	memstats.pause_end[memstats.numgc%uint32(len(memstats.pause_end))] = uint64(unixNow)
	memstats.pause_total_ns += uint64(work.pauseNS)

	// Accumulate CPU stats.
	//
	// Use maxprocs instead of stwprocs for GC pause time because the total time
	// computed in the CPU stats is based on maxprocs, and we want them to be
	// comparable.
	//
	// Pass gcMarkPhase=true to accumulate so we can get all the latest GC CPU stats
	// in there too.
	work.cpuStats.accumulateGCPauseTime(now-stw.finishedStopping, work.maxprocs)
	work.cpuStats.accumulate(now, true)

	// Compute overall GC CPU utilization.
	// Omit idle marking time from the overall utilization here since it's "free".
	memstats.gc_cpu_fraction = float64(work.cpuStats.GCTotalTime-work.cpuStats.GCIdleTime) / float64(work.cpuStats.TotalTime)

	// Reset assist time and background time stats.
	//
	// Do this now, instead of at the start of the next GC cycle, because
	// these two may keep accumulating even if the GC is not active.
	scavenge.assistTime.Store(0)
	scavenge.backgroundTime.Store(0)

	// Reset idle time stat.
	sched.idleTime.Store(0)

	if work.userForced {
		memstats.numforcedgc++
	}

	// Bump GC cycle count and wake goroutines waiting on sweep.
	lock(&work.sweepWaiters.lock)
	memstats.numgc++
	injectglist(&work.sweepWaiters.list)
	unlock(&work.sweepWaiters.lock)

	// Increment the scavenge generation now.
	//
	// This moment represents peak heap in use because we're
	// about to start sweeping.
	mheap_.pages.scav.index.nextGen()

	// Release the CPU limiter.
	gcCPULimiter.finishGCTransition(now)

	// Finish the current heap profiling cycle and start a new
	// heap profiling cycle. We do this before starting the world
	// so events don't leak into the wrong cycle.
	mProf_NextCycle()

	// There may be stale spans in mcaches that need to be swept.
	// Those aren't tracked in any sweep lists, so we need to
	// count them against sweep completion until we ensure all
	// those spans have been forced out.
	//
	// If gcSweep fully swept the heap (for example if the sweep
	// is not concurrent due to a GODEBUG setting), then we expect
	// the sweepLocker to be invalid, since sweeping is done.
	//
	// N.B. Below we might duplicate some work from gcSweep; this is
	// fine as all that work is idempotent within a GC cycle, and
	// we're still holding worldsema so a new cycle can't start.
	sl := sweep.active.begin()
	if !stwSwept && !sl.valid {
		throw("failed to set sweep barrier")
	} else if stwSwept && sl.valid {
		throw("non-concurrent sweep failed to drain all sweep queues")
	}

	systemstack(func() {
		// The memstats updated above must be updated with the world
		// stopped to ensure consistency of some values, such as
		// sched.idleTime and sched.totaltime. memstats also include
		// the pause time (work,pauseNS), forcing computation of the
		// total pause time before the pause actually ends.
		//
		// Here we reuse the same now for start the world so that the
		// time added to /sched/pauses/total/gc:seconds will be
		// consistent with the value in memstats.
		startTheWorldWithSema(now, stw)
	})

	// Flush the heap profile so we can start a new cycle next GC.
	// This is relatively expensive, so we don't do it with the
	// world stopped.
	mProf_Flush()

	// Prepare workbufs for freeing by the sweeper. We do this
	// asynchronously because it can take non-trivial time.
	prepareFreeWorkbufs()

	// Free stack spans. This must be done between GC cycles.
	systemstack(freeStackSpans)

	// Ensure all mcaches are flushed. Each P will flush its own
	// mcache before allocating, but idle Ps may not. Since this
	// is necessary to sweep all spans, we need to ensure all
	// mcaches are flushed before we start the next GC cycle.
	//
	// While we're here, flush the page cache for idle Ps to avoid
	// having pages get stuck on them. These pages are hidden from
	// the scavenger, so in small idle heaps a significant amount
	// of additional memory might be held onto.
	//
	// Also, flush the pinner cache, to avoid leaking that memory
	// indefinitely.
	forEachP(waitReasonFlushProcCaches, func(pp *p) {
		pp.mcache.prepareForSweep()
		if pp.status == _Pidle {
			systemstack(func() {
				lock(&mheap_.lock)
				pp.pcache.flush(&mheap_.pages)
				unlock(&mheap_.lock)
			})
		}
		pp.pinnerCache = nil
	})
	if sl.valid {
		// Now that we've swept stale spans in mcaches, they don't
		// count against unswept spans.
		//
		// Note: this sweepLocker may not be valid if sweeping had
		// already completed during the STW. See the corresponding
		// begin() call that produced sl.
		sweep.active.end(sl)
	}

	// Print gctrace before dropping worldsema. As soon as we drop
	// worldsema another cycle could start and smash the stats
	// we're trying to print.
	if debug.gctrace > 0 {
		util := int(memstats.gc_cpu_fraction * 100)

		var sbuf [24]byte
		printlock()
		print("gc ", memstats.numgc,
			" @", string(itoaDiv(sbuf[:], uint64(work.tSweepTerm-runtimeInitTime)/1e6, 3)), "s ",
			util, "%: ")
		prev := work.tSweepTerm
		for i, ns := range []int64{work.tMark, work.tMarkTerm, work.tEnd} {
			if i != 0 {
				print("+")
			}
			print(string(fmtNSAsMS(sbuf[:], uint64(ns-prev))))
			prev = ns
		}
		print(" ms clock, ")
		for i, ns := range []int64{
			int64(work.stwprocs) * (work.tMark - work.tSweepTerm),
			gcController.assistTime.Load(),
			gcController.dedicatedMarkTime.Load() + gcController.fractionalMarkTime.Load(),
			gcController.idleMarkTime.Load(),
			int64(work.stwprocs) * (work.tEnd - work.tMarkTerm),
		} {
			if i == 2 || i == 3 {
				// Separate mark time components with /.
				print("/")
			} else if i != 0 {
				print("+")
			}
			print(string(fmtNSAsMS(sbuf[:], uint64(ns))))
		}
		print(" ms cpu, ",
			work.heap0>>20, "->", work.heap1>>20, "->", work.heap2>>20, " MB, ",
			gcController.lastHeapGoal>>20, " MB goal, ",
			gcController.lastStackScan.Load()>>20, " MB stacks, ",
			gcController.globalsScan.Load()>>20, " MB globals, ",
			work.maxprocs, " P")
		if work.userForced {
			print(" (forced)")
		}
		print("\n")
		printunlock()
	}

	// Set any arena chunks that were deferred to fault.
	lock(&userArenaState.lock)
	faultList := userArenaState.fault
	userArenaState.fault = nil
	unlock(&userArenaState.lock)
	for _, lc := range faultList {
		lc.mspan.setUserArenaChunkToFault()
	}

	// Enable huge pages on some metadata if we cross a heap threshold.
	if gcController.heapGoal() > minHeapForMetadataHugePages {
		systemstack(func() {
			mheap_.enableMetadataHugePages()
		})
	}

	semrelease(&worldsema)
	semrelease(&gcsema)
	// Careful: another GC cycle may start now.

	releasem(mp)
	mp = nil

	// now that gc is done, kick off finalizer thread if needed
	if !concurrentSweep {
		// give the queued finalizers, if any, a chance to run
		Gosched()
	}
}

// gcBgMarkStartWorkers prepares background mark worker goroutines. These
// goroutines will not run until the mark phase, but they must be started while
// the work is not stopped and from a regular G stack. The caller must hold
// worldsema.
func gcBgMarkStartWorkers() {
	// Background marking is performed by per-P G's. Ensure that each P has
	// a background GC G.
	//
	// Worker Gs don't exit if gomaxprocs is reduced. If it is raised
	// again, we can reuse the old workers; no need to create new workers.
	if gcBgMarkWorkerCount >= gomaxprocs {
		return
	}

	// Increment mp.locks when allocating. We are called within gcStart,
	// and thus must not trigger another gcStart via an allocation. gcStart
	// bails when allocating with locks held, so simulate that for these
	// allocations.
	//
	// TODO(prattmic): cleanup gcStart to use a more explicit "in gcStart"
	// check for bailing.
	mp := acquirem()
	ready := make(chan struct{}, 1)
	releasem(mp)

	for gcBgMarkWorkerCount < gomaxprocs {
		mp := acquirem() // See above, we allocate a closure here.
		go gcBgMarkWorker(ready)
		releasem(mp)

		// N.B. we intentionally wait on each goroutine individually
		// rather than starting all in a batch and then waiting once
		// afterwards. By running one goroutine at a time, we can take
		// advantage of runnext to bounce back and forth between
		// workers and this goroutine. In an overloaded application,
		// this can reduce GC start latency by prioritizing these
		// goroutines rather than waiting on the end of the run queue.
		<-ready
		// The worker is now guaranteed to be added to the pool before
		// its P's next findRunnableGCWorker.

		gcBgMarkWorkerCount++
	}
}

// gcBgMarkPrepare sets up state for background marking.
// Mutator assists must not yet be enabled.
func gcBgMarkPrepare() {
	// Background marking will stop when the work queues are empty
	// and there are no more workers (note that, since this is
	// concurrent, this may be a transient state, but mark
	// termination will clean it up). Between background workers
	// and assists, we don't really know how many workers there
	// will be, so we pretend to have an arbitrarily large number
	// of workers, almost all of which are "waiting". While a
	// worker is working it decrements nwait. If nproc == nwait,
	// there are no workers.
	work.nproc = ^uint32(0)
	work.nwait = ^uint32(0)
}

// gcBgMarkWorkerNode is an entry in the gcBgMarkWorkerPool. It points to a single
// gcBgMarkWorker goroutine.
type gcBgMarkWorkerNode struct {
	// Unused workers are managed in a lock-free stack. This field must be first.
	node lfnode

	// The g of this worker.
	gp guintptr

	// Release this m on park. This is used to communicate with the unlock
	// function, which cannot access the G's stack. It is unused outside of
	// gcBgMarkWorker().
	m muintptr
}

func gcBgMarkWorker(ready chan struct{}) {
	gp := getg()

	// We pass node to a gopark unlock function, so it can't be on
	// the stack (see gopark). Prevent deadlock from recursively
	// starting GC by disabling preemption.
	gp.m.preemptoff = "GC worker init"
	node := new(gcBgMarkWorkerNode)
	gp.m.preemptoff = ""

	node.gp.set(gp)

	node.m.set(acquirem())

	ready <- struct{}{}
	// After this point, the background mark worker is generally scheduled
	// cooperatively by gcController.findRunnableGCWorker. While performing
	// work on the P, preemption is disabled because we are working on
	// P-local work buffers. When the preempt flag is set, this puts itself
	// into _Gwaiting to be woken up by gcController.findRunnableGCWorker
	// at the appropriate time.
	//
	// When preemption is enabled (e.g., while in gcMarkDone), this worker
	// may be preempted and schedule as a _Grunnable G from a runq. That is
	// fine; it will eventually gopark again for further scheduling via
	// findRunnableGCWorker.
	//
	// Since we disable preemption before notifying ready, we guarantee that
	// this G will be in the worker pool for the next findRunnableGCWorker.
	// This isn't strictly necessary, but it reduces latency between
	// _GCmark starting and the workers starting.

	for {
		// Go to sleep until woken by
		// gcController.findRunnableGCWorker.
		gopark(func(g *g, nodep unsafe.Pointer) bool {
			node := (*gcBgMarkWorkerNode)(nodep)

			if mp := node.m.ptr(); mp != nil {
				// The worker G is no longer running; release
				// the M.
				//
				// N.B. it is _safe_ to release the M as soon
				// as we are no longer performing P-local mark
				// work.
				//
				// However, since we cooperatively stop work
				// when gp.preempt is set, if we releasem in
				// the loop then the following call to gopark
				// would immediately preempt the G. This is
				// also safe, but inefficient: the G must
				// schedule again only to enter gopark and park
				// again. Thus, we defer the release until
				// after parking the G.
				releasem(mp)
			}

			// Release this G to the pool.
			gcBgMarkWorkerPool.push(&node.node)
			// Note that at this point, the G may immediately be
			// rescheduled and may be running.
			return true
		}, unsafe.Pointer(node), waitReasonGCWorkerIdle, traceBlockSystemGoroutine, 0)

		// Preemption must not occur here, or another G might see
		// p.gcMarkWorkerMode.

		// Disable preemption so we can use the gcw. If the
		// scheduler wants to preempt us, we'll stop draining,
		// dispose the gcw, and then preempt.
		node.m.set(acquirem())
		pp := gp.m.p.ptr() // P can't change with preemption disabled.

		if gcBlackenEnabled == 0 {
			println("worker mode", pp.gcMarkWorkerMode)
			throw("gcBgMarkWorker: blackening not enabled")
		}

		if pp.gcMarkWorkerMode == gcMarkWorkerNotWorker {
			throw("gcBgMarkWorker: mode not set")
		}

		startTime := nanotime()
		pp.gcMarkWorkerStartTime = startTime
		var trackLimiterEvent bool
		if pp.gcMarkWorkerMode == gcMarkWorkerIdleMode {
			trackLimiterEvent = pp.limiterEvent.start(limiterEventIdleMarkWork, startTime)
		}

		decnwait := atomic.Xadd(&work.nwait, -1)
		if decnwait == work.nproc {
			println("runtime: work.nwait=", decnwait, "work.nproc=", work.nproc)
			throw("work.nwait was > work.nproc")
		}

		systemstack(func() {
			// Mark our goroutine preemptible so its stack
			// can be scanned. This lets two mark workers
			// scan each other (otherwise, they would
			// deadlock). We must not modify anything on
			// the G stack. However, stack shrinking is
			// disabled for mark workers, so it is safe to
			// read from the G stack.
			//
			// N.B. The execution tracer is not aware of this status
			// transition and handles it specially based on the
			// wait reason.
			casGToWaitingForGC(gp, _Grunning, waitReasonGCWorkerActive)
			switch pp.gcMarkWorkerMode {
			default:
				throw("gcBgMarkWorker: unexpected gcMarkWorkerMode")
			case gcMarkWorkerDedicatedMode:
				gcDrainMarkWorkerDedicated(&pp.gcw, true)
				if gp.preempt {
					// We were preempted. This is
					// a useful signal to kick
					// everything out of the run
					// queue so it can run
					// somewhere else.
					if drainQ, n := runqdrain(pp); n > 0 {
						lock(&sched.lock)
						globrunqputbatch(&drainQ, int32(n))
						unlock(&sched.lock)
					}
				}
				// Go back to draining, this time
				// without preemption.
				gcDrainMarkWorkerDedicated(&pp.gcw, false)
			case gcMarkWorkerFractionalMode:
				gcDrainMarkWorkerFractional(&pp.gcw)
			case gcMarkWorkerIdleMode:
				gcDrainMarkWorkerIdle(&pp.gcw)
			}
			casgstatus(gp, _Gwaiting, _Grunning)
		})

		// Account for time and mark us as stopped.
		now := nanotime()
		duration := now - startTime
		gcController.markWorkerStop(pp.gcMarkWorkerMode, duration)
		if trackLimiterEvent {
			pp.limiterEvent.stop(limiterEventIdleMarkWork, now)
		}
		if pp.gcMarkWorkerMode == gcMarkWorkerFractionalMode {
			atomic.Xaddint64(&pp.gcFractionalMarkTime, duration)
		}

		// Was this the last worker and did we run out
		// of work?
		incnwait := atomic.Xadd(&work.nwait, +1)
		if incnwait > work.nproc {
			println("runtime: p.gcMarkWorkerMode=", pp.gcMarkWorkerMode,
				"work.nwait=", incnwait, "work.nproc=", work.nproc)
			throw("work.nwait > work.nproc")
		}

		// We'll releasem after this point and thus this P may run
		// something else. We must clear the worker mode to avoid
		// attributing the mode to a different (non-worker) G in
		// traceGoStart.
		pp.gcMarkWorkerMode = gcMarkWorkerNotWorker

		// If this worker reached a background mark completion
		// point, signal the main GC goroutine.
		if incnwait == work.nproc && !gcMarkWorkAvailable(nil) {
			// We don't need the P-local buffers here, allow
			// preemption because we may schedule like a regular
			// goroutine in gcMarkDone (block on locks, etc).
			releasem(node.m.ptr())
			node.m.set(nil)

			gcMarkDone()
		}
	}
}

// gcMarkWorkAvailable reports whether executing a mark worker
// on p is potentially useful. p may be nil, in which case it only
// checks the global sources of work.
func gcMarkWorkAvailable(p *p) bool {
	if p != nil && !p.gcw.empty() {
		return true
	}
	if !work.full.empty() {
		return true // global work available
	}
	if work.markrootNext < work.markrootJobs {
		return true // root scan work available
	}
	return false
}

// gcMark runs the mark (or, for concurrent GC, mark termination)
// All gcWork caches must be empty.
// STW is in effect at this point.
func gcMark(startTime int64) {
	if gcphase != _GCmarktermination {
		throw("in gcMark expecting to see gcphase as _GCmarktermination")
	}
	work.tstart = startTime

	// Check that there's no marking work remaining.
	if work.full != 0 || work.markrootNext < work.markrootJobs {
		print("runtime: full=", hex(work.full), " next=", work.markrootNext, " jobs=", work.markrootJobs, " nDataRoots=", work.nDataRoots, " nBSSRoots=", work.nBSSRoots, " nSpanRoots=", work.nSpanRoots, " nStackRoots=", work.nStackRoots, "\n")
		panic("non-empty mark queue after concurrent mark")
	}

	if debug.gccheckmark > 0 {
		// This is expensive when there's a large number of
		// Gs, so only do it if checkmark is also enabled.
		gcMarkRootCheck()
	}

	// Drop allg snapshot. allgs may have grown, in which case
	// this is the only reference to the old backing store and
	// there's no need to keep it around.
	work.stackRoots = nil

	// Clear out buffers and double-check that all gcWork caches
	// are empty. This should be ensured by gcMarkDone before we
	// enter mark termination.
	//
	// TODO: We could clear out buffers just before mark if this
	// has a non-negligible impact on STW time.
	for _, p := range allp {
		// The write barrier may have buffered pointers since
		// the gcMarkDone barrier. However, since the barrier
		// ensured all reachable objects were marked, all of
		// these must be pointers to black objects. Hence we
		// can just discard the write barrier buffer.
		if debug.gccheckmark > 0 {
			// For debugging, flush the buffer and make
			// sure it really was all marked.
			wbBufFlush1(p)
		} else {
			p.wbBuf.reset()
		}

		gcw := &p.gcw
		if !gcw.empty() {
			printlock()
			print("runtime: P ", p.id, " flushedWork ", gcw.flushedWork)
			if gcw.wbuf1 == nil {
				print(" wbuf1=<nil>")
			} else {
				print(" wbuf1.n=", gcw.wbuf1.nobj)
			}
			if gcw.wbuf2 == nil {
				print(" wbuf2=<nil>")
			} else {
				print(" wbuf2.n=", gcw.wbuf2.nobj)
			}
			print("\n")
			throw("P has cached GC work at end of mark termination")
		}
		// There may still be cached empty buffers, which we
		// need to flush since we're going to free them. Also,
		// there may be non-zero stats because we allocated
		// black after the gcMarkDone barrier.
		gcw.dispose()
	}

	// Flush scanAlloc from each mcache since we're about to modify
	// heapScan directly. If we were to flush this later, then scanAlloc
	// might have incorrect information.
	//
	// Note that it's not important to retain this information; we know
	// exactly what heapScan is at this point via scanWork.
	for _, p := range allp {
		c := p.mcache
		if c == nil {
			continue
		}
		c.scanAlloc = 0
	}

	// Reset controller state.
	gcController.resetLive(work.bytesMarked)
}

// gcSweep must be called on the system stack because it acquires the heap
// lock. See mheap for details.
//
// Returns true if the heap was fully swept by this function.
//
// The world must be stopped.
//
//go:systemstack
func gcSweep(mode gcMode) bool {
	assertWorldStopped()

	if gcphase != _GCoff {
		throw("gcSweep being done but phase is not GCoff")
	}

	lock(&mheap_.lock)
	mheap_.sweepgen += 2
	sweep.active.reset()
	mheap_.pagesSwept.Store(0)
	mheap_.sweepArenas = mheap_.allArenas
	mheap_.reclaimIndex.Store(0)
	mheap_.reclaimCredit.Store(0)
	unlock(&mheap_.lock)

	sweep.centralIndex.clear()

	if !concurrentSweep || mode == gcForceBlockMode {
		// Special case synchronous sweep.
		// Record that no proportional sweeping has to happen.
		lock(&mheap_.lock)
		mheap_.sweepPagesPerByte = 0
		unlock(&mheap_.lock)
		// Flush all mcaches.
		for _, pp := range allp {
			pp.mcache.prepareForSweep()
		}
		// Sweep all spans eagerly.
		for sweepone() != ^uintptr(0) {
		}
		// Free workbufs eagerly.
		prepareFreeWorkbufs()
		for freeSomeWbufs(false) {
		}
		// All "free" events for this mark/sweep cycle have
		// now happened, so we can make this profile cycle
		// available immediately.
		mProf_NextCycle()
		mProf_Flush()
		return true
	}

	// Background sweep.
	lock(&sweep.lock)
	if sweep.parked {
		sweep.parked = false
		ready(sweep.g, 0, true)
	}
	unlock(&sweep.lock)
	return false
}

// gcResetMarkState resets global state prior to marking (concurrent
// or STW) and resets the stack scan state of all Gs.
//
// This is safe to do without the world stopped because any Gs created
// during or after this will start out in the reset state.
//
// gcResetMarkState must be called on the system stack because it acquires
// the heap lock. See mheap for details.
//
//go:systemstack
func gcResetMarkState() {
	// This may be called during a concurrent phase, so lock to make sure
	// allgs doesn't change.
	forEachG(func(gp *g) {
		gp.gcscandone = false // set to true in gcphasework
		gp.gcAssistBytes = 0
	})

	// Clear page marks. This is just 1MB per 64GB of heap, so the
	// time here is pretty trivial.
	lock(&mheap_.lock)
	arenas := mheap_.allArenas
	unlock(&mheap_.lock)
	for _, ai := range arenas {
		ha := mheap_.arenas[ai.l1()][ai.l2()]
		clear(ha.pageMarks[:])
	}

	work.bytesMarked = 0
	work.initialHeapLive = gcController.heapLive.Load()
}

// Hooks for other packages

var poolcleanup func()
var boringCaches []unsafe.Pointer  // for crypto/internal/boring
var uniqueMapCleanup chan struct{} // for unique

// sync_runtime_registerPoolCleanup should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/gopkg
//   - github.com/songzhibin97/gkit
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname sync_runtime_registerPoolCleanup sync.runtime_registerPoolCleanup
func sync_runtime_registerPoolCleanup(f func()) {
	poolcleanup = f
}

//go:linkname boring_registerCache crypto/internal/boring/bcache.registerCache
func boring_registerCache(p unsafe.Pointer) {
	boringCaches = append(boringCaches, p)
}

//go:linkname unique_runtime_registerUniqueMapCleanup unique.runtime_registerUniqueMapCleanup
func unique_runtime_registerUniqueMapCleanup(f func()) {
	// Create the channel on the system stack so it doesn't inherit the current G's
	// synctest bubble (if any).
	systemstack(func() {
		uniqueMapCleanup = make(chan struct{}, 1)
	})
	// Start the goroutine in the runtime so it's counted as a system goroutine.
	go func(cleanup func()) {
		for {
			<-uniqueMapCleanup
			cleanup()
		}
	}(f)
}

func clearpools() {
	// clear sync.Pools
	if poolcleanup != nil {
		poolcleanup()
	}

	// clear boringcrypto caches
	for _, p := range boringCaches {
		atomicstorep(p, nil)
	}

	// clear unique maps
	if uniqueMapCleanup != nil {
		select {
		case uniqueMapCleanup <- struct{}{}:
		default:
		}
	}

	// Clear central sudog cache.
	// Leave per-P caches alone, they have strictly bounded size.
	// Disconnect cached list before dropping it on the floor,
	// so that a dangling ref to one entry does not pin all of them.
	lock(&sched.sudoglock)
	var sg, sgnext *sudog
	for sg = sched.sudogcache; sg != nil; sg = sgnext {
		sgnext = sg.next
		sg.next = nil
	}
	sched.sudogcache = nil
	unlock(&sched.sudoglock)

	// Clear central defer pool.
	// Leave per-P pools alone, they have strictly bounded size.
	lock(&sched.deferlock)
	// disconnect cached list before dropping it on the floor,
	// so that a dangling ref to one entry does not pin all of them.
	var d, dlink *_defer
	for d = sched.deferpool; d != nil; d = dlink {
		dlink = d.link
		d.link = nil
	}
	sched.deferpool = nil
	unlock(&sched.deferlock)
}

// Timing

// itoaDiv formats val/(10**dec) into buf.
func itoaDiv(buf []byte, val uint64, dec int) []byte {
	i := len(buf) - 1
	idec := i - dec
	for val >= 10 || i >= idec {
		buf[i] = byte(val%10 + '0')
		i--
		if i == idec {
			buf[i] = '.'
			i--
		}
		val /= 10
	}
	buf[i] = byte(val + '0')
	return buf[i:]
}

// fmtNSAsMS nicely formats ns nanoseconds as milliseconds.
func fmtNSAsMS(buf []byte, ns uint64) []byte {
	if ns >= 10e6 {
		// Format as whole milliseconds.
		return itoaDiv(buf, ns/1e6, 0)
	}
	// Format two digits of precision, with at most three decimal places.
	x := ns / 1e3
	if x == 0 {
		buf[0] = '0'
		return buf[:1]
	}
	dec := 3
	for x >= 100 {
		x /= 10
		dec--
	}
	return itoaDiv(buf, x, dec)
}

// Helpers for testing GC.

// gcTestMoveStackOnNextCall causes the stack to be moved on a call
// immediately following the call to this. It may not work correctly
// if any other work appears after this call (such as returning).
// Typically the following call should be marked go:noinline so it
// performs a stack check.
//
// In rare cases this may not cause the stack to move, specifically if
// there's a preemption between this call and the next.
func gcTestMoveStackOnNextCall() {
	gp := getg()
	gp.stackguard0 = stackForceMove
}

// gcTestIsReachable performs a GC and returns a bit set where bit i
// is set if ptrs[i] is reachable.
func gcTestIsReachable(ptrs ...unsafe.Pointer) (mask uint64) {
	// This takes the pointers as unsafe.Pointers in order to keep
	// them live long enough for us to attach specials. After
	// that, we drop our references to them.

	if len(ptrs) > 64 {
		panic("too many pointers for uint64 mask")
	}

	// Block GC while we attach specials and drop our references
	// to ptrs. Otherwise, if a GC is in progress, it could mark
	// them reachable via this function before we have a chance to
	// drop them.
	semacquire(&gcsema)

	// Create reachability specials for ptrs.
	specials := make([]*specialReachable, len(ptrs))
	for i, p := range ptrs {
		lock(&mheap_.speciallock)
		s := (*specialReachable)(mheap_.specialReachableAlloc.alloc())
		unlock(&mheap_.speciallock)
		s.special.kind = _KindSpecialReachable
		if !addspecial(p, &s.special, false) {
			throw("already have a reachable special (duplicate pointer?)")
		}
		specials[i] = s
		// Make sure we don't retain ptrs.
		ptrs[i] = nil
	}

	semrelease(&gcsema)

	// Force a full GC and sweep.
	GC()

	// Process specials.
	for i, s := range specials {
		if !s.done {
			printlock()
			println("runtime: object", i, "was not swept")
			throw("IsReachable failed")
		}
		if s.reachable {
			mask |= 1 << i
		}
		lock(&mheap_.speciallock)
		mheap_.specialReachableAlloc.free(unsafe.Pointer(s))
		unlock(&mheap_.speciallock)
	}

	return mask
}

// gcTestPointerClass returns the category of what p points to, one of:
// "heap", "stack", "data", "bss", "other". This is useful for checking
// that a test is doing what it's intended to do.
//
// This is nosplit simply to avoid extra pointer shuffling that may
// complicate a test.
//
//go:nosplit
func gcTestPointerClass(p unsafe.Pointer) string {
	p2 := uintptr(noescape(p))
	gp := getg()
	if gp.stack.lo <= p2 && p2 < gp.stack.hi {
		return "stack"
	}
	if base, _, _ := findObject(p2, 0, 0); base != 0 {
		return "heap"
	}
	for _, datap := range activeModules() {
		if datap.data <= p2 && p2 < datap.edata || datap.noptrdata <= p2 && p2 < datap.enoptrdata {
			return "data"
		}
		if datap.bss <= p2 && p2 < datap.ebss || datap.noptrbss <= p2 && p2 <= datap.enoptrbss {
			return "bss"
		}
	}
	KeepAlive(p)
	return "oth
```