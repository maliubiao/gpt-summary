Response:
Let's break down the request and the provided Go code to formulate a comprehensive answer.

**1. Understanding the Core Request:**

The user has provided a snippet of Go code from `runtime/mgcpacer.go` and wants to understand its functionality. The key is to identify the central purpose of this code within the Go runtime. The filename itself, "mgcpacer," strongly suggests this code is related to pacing the garbage collector.

**2. Initial Code Analysis - Keywords and Concepts:**

Scanning the code reveals several recurring themes and data structures:

* **`gcControllerState`:** This struct seems to hold the core state and configuration for GC pacing.
* **`heapGoal`:**  Multiple functions deal with calculating and adjusting the heap goal. This is a central concept in Go's GC – the target heap size at which a GC cycle should end.
* **`trigger`:**  Functions like `trigger()` calculate the point (heap size) at which a new GC cycle should begin.
* **`commit`:**  This function seems to be a key step in updating and recalculating pacing parameters after various events.
* **`markWorker`:**  The code mentions different modes for mark workers (dedicated, fractional, idle), suggesting it's involved in managing the concurrent mark phase of the GC.
* **`memoryLimit`:** This is a relatively recent addition to Go, and its presence here indicates the code is involved in memory limit management for the GC.
* **`gcPercent`:**  The traditional GOGC environment variable is referenced, further confirming the GC pacing focus.
* **Atomic operations:** The use of `atomic.Int64` suggests concurrency and the need for thread-safe updates of shared state.
* **`trace`:** The use of `traceAcquire` and `traceRelease` indicates integration with Go's tracing facility, likely for debugging and performance analysis.

**3. Forming Hypotheses about Functionality:**

Based on the keywords and code structure, a reasonable hypothesis is that this code is responsible for:

* **Dynamically adjusting the heap goal:**  Taking into account `gcPercent`, `memoryLimit`, and various runtime conditions.
* **Determining the GC trigger:**  Calculating when a new GC cycle should start based on the current heap size and the heap goal.
* **Managing concurrent mark workers:** Allocating and managing workers during the concurrent mark phase.
* **Responding to changes in memory pressure:** Adapting the GC behavior based on the configured memory limit.
* **Integrating with the Go runtime's GC lifecycle:**  Interacting with other parts of the GC like the sweeper and scavenger.

**4. Deeper Dive into Specific Functions:**

* **`tryGet`:** This function seems to be about acquiring a mark worker, potentially in different modes (dedicated, fractional). The logic involving `dedicatedMarkWorkersNeeded` and `fractionalUtilizationGoal` is key here.
* **`resetLive`:** This looks like initialization logic at the start of a GC cycle.
* **`markWorkerStop`:**  This function handles the cleanup and accounting when a mark worker finishes.
* **`update`:**  This function seems to update the controller state based on changes in live and scannable heap.
* **`heapGoalInternal` and `heapGoal`:**  These functions implement the logic for calculating the heap goal, considering both `gcPercent` and `memoryLimit`. The comments within `memoryLimitHeapGoal` are crucial for understanding its complexity.
* **`trigger`:** This function calculates the precise point at which a GC should be triggered. The constants like `triggerRatioDen`, `minTriggerRatioNum`, and `maxTriggerRatioNum` are significant here.
* **`commit`:** This is a central function that recalculates pacing parameters after events like sweep completion. It ties together `gcPercent`, `memoryLimit`, and estimations of GC workload.
* **`setGCPercent` and `setMemoryLimit`:** These are the entry points for external configuration via environment variables or runtime/debug functions.
* **`addIdleMarkWorker`, `needIdleMarkWorker`, `removeIdleMarkWorker`, `setMaxIdleMarkWorkers`:** These functions manage a pool of idle mark workers.

**5. Constructing the Explanation (Following the Prompt's Structure):**

* **List of Functions:**  Simply enumerate the functions and briefly state their purpose.
* **Reasoning about Go Feature Implementation:**  Focus on the core hypothesis: this code implements the dynamic pacing of the garbage collector. Highlight how functions like `heapGoal`, `trigger`, and `commit` contribute to this.
* **Go Code Example:**  Choose a representative scenario, like setting `GOGC`. Show how `setGCPercent` and `gcControllerCommit` are involved. Include the assumed input (setting the environment variable) and the expected output (change in heap goal or trigger point). *Initially, I might have thought of a more complex example, but simpler is better for demonstration.*
* **Code Reasoning (with Assumptions):**  Focus on a function with interesting logic, such as `tryGet`. Explain the assumptions about the state of the GC and the meaning of the inputs/outputs.
* **Command-Line Argument Handling:** Explain how `readGOGC` and `readGOMEMLIMIT` process environment variables. Describe the possible values and their effects.
* **Common Mistakes:**  Think about potential errors users might make when interacting with GC settings (e.g., setting extreme values for `GOGC` or `GOMEMLIMIT` without understanding the implications). *Initially, I considered a more technical error, but focusing on user-level mistakes is more helpful.*
* **Summary of Functionality (Part 2):** Condense the main purpose of the code into a concise summary.

**6. Refinement and Iteration:**

* **Clarity and Language:** Ensure the explanation is in clear, concise Chinese. Avoid overly technical jargon where possible.
* **Accuracy:** Double-check the understanding of the code's logic.
* **Completeness:**  Address all aspects of the prompt.
* **Structure:** Organize the answer logically, following the prompt's structure.

By following this thought process, systematically analyzing the code, and structuring the answer according to the prompt's requirements, we arrive at the comprehensive and informative response provided previously.
这是 `go/src/runtime/mgcpacer.go` 文件中 `gcControllerState` 结构体及其相关方法的第二部分。 结合第一部分，我们可以归纳一下它的功能：

**核心功能：动态控制 Go 垃圾回收器的行为，目标是高效地管理内存使用和避免过度的 GC 开销。**

更具体地说，这部分代码主要负责以下几个方面：

1. **管理后台标记工作者 (Background Mark Workers):**
   - `tryGet`:  尝试获取一个后台标记工作者来协助并发标记阶段。它可以分配专用 (dedicated) 或部分 (fractional) 的工作者，或者在没有需求时将工作者放回池中。
   - `markWorkerStop`:  当一个标记工作者停止执行时，更新相关的统计信息，例如专用标记时间、部分标记时间和空闲标记时间，并根据工作模式调整 `dedicatedMarkWorkersNeeded` 计数器。
   - `addIdleMarkWorker`, `needIdleMarkWorker`, `removeIdleMarkWorker`, `setMaxIdleMarkWorkers`: 管理空闲标记工作者的数量，允许在 CPU 空闲时进行额外的标记工作。

2. **在 GC 周期之间重置和更新控制器状态:**
   - `resetLive`: 在上一个 GC 周期结束后、提交 (commit) 之前调用，用于初始化下一个标记阶段的状态，包括更新 `heapMarked`、`heapLive`、`heapScan` 等关键指标。

3. **动态调整堆内存目标 (Heap Goal) 和触发点 (Trigger):**
   - `heapGoalInternal`, `heapGoal`: 计算当前的堆内存目标。这个目标受 `GOGC` 环境变量、内存限制 (通过 `GOMEMLIMIT`) 以及一些启发式规则影响。`heapGoalInternal` 返回更详细的信息，包括最小触发点。
   - `memoryLimitHeapGoal`:  专门根据内存限制计算堆内存目标。它考虑了非堆内存的使用、超出内存限制的情况，并设置一定的 headroom 来应对 pacing 的不准确性。
   - `trigger`: 基于当前的堆内存目标和一些动态调整的参数，计算出应该触发下一次 GC 的堆内存大小。它确保触发点在目标以下，并考虑了一些边界情况和优化策略。
   - `commit`: 这是一个核心函数，用于重新计算所有用于推导触发点和堆内存目标的 pacing 参数。它会根据是否完成了清理 (sweep) 工作、`gcPercent` 的设置以及当前的堆内存使用情况来调整。它还会更新 `runway`，表示我们希望为本次 GC 预留的内存增长空间。
   - `revise`:  (虽然这部分代码片段中没有直接展示 `revise` 的实现，但上下文提到 `commit` 后会调用它)  `revise` 函数会根据 `commit` 更新后的状态，调整并发标记的 pacing。

4. **处理全局变量和栈的扫描工作量:**
   - `addGlobals`: 增加全局变量的扫描工作量。
   - `addScannableStack`: 增加可扫描栈的大小，可以针对特定的 P (processor) 进行调整。

5. **配置 GC 行为:**
   - `setGCPercent`: 更新 `GOGC` 环境变量对应的值，并重新计算最小堆大小。
   - `setMemoryLimit`: 更新内存限制，影响堆内存目标的计算。
   - `readGOGC`, `readGOMEMLIMIT`: 读取环境变量 `GOGC` 和 `GOMEMLIMIT` 的值。

6. **集成到 Go 运行时:**
   - `gcControllerCommit`:  封装了 `gcController.commit` 的调用，并更新了 sweep 和 scavenger 的 pacing。它需要在系统栈上执行，因为它会持有堆锁。

**总结来说，这部分代码是 Go 运行时 GC 动态调整机制的核心，它通过监控内存使用情况、工作负载和配置参数，来智能地决定何时以及如何进行垃圾回收，以达到性能和资源利用率的最佳平衡。它实现了基于 `GOGC` 和 `GOMEMLIMIT` 的内存管理策略，并动态地调整 GC 的触发时机和目标，同时管理并发标记工作者以提高 GC 的效率。**

**可能的易犯错的点 (基于两部分代码)：**

* **错误地理解 `GOGC` 的含义:**  `GOGC=100` 意味着在上次 GC 完成后，当堆内存增长到上次标记后存活对象大小的 100% 时，触发新的 GC。 设置过小的值会导致频繁的 GC，影响程序性能；设置过大的值可能导致内存使用过高。
* **错误地理解 `GOMEMLIMIT` 的含义:** `GOMEMLIMIT` 是一个硬性的内存使用上限，包含 Go 运行时使用的所有内存，包括堆、栈、元数据等。设置过低的值可能会导致频繁的 GC 和程序崩溃 (OOM)。
* **在程序运行过程中频繁地修改 `GOGC` 或 `GOMEMLIMIT`:**  虽然 Go 提供了在运行时修改这些参数的功能，但频繁的修改可能会导致 GC 行为不稳定，难以预测程序的内存使用情况和性能。建议在程序启动时根据预期负载设置好这些参数。

这部分代码专注于 GC 的动态控制和管理，与第一部分共同构建了 Go 运行时中复杂的垃圾回收 pacing 机制。

Prompt: 
```
这是路径为go/src/runtime/mgcpacer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
rker G it was
		// just using, ensuring work can complete.
		return nil, now
	}

	decIfPositive := func(val *atomic.Int64) bool {
		for {
			v := val.Load()
			if v <= 0 {
				return false
			}

			if val.CompareAndSwap(v, v-1) {
				return true
			}
		}
	}

	if decIfPositive(&c.dedicatedMarkWorkersNeeded) {
		// This P is now dedicated to marking until the end of
		// the concurrent mark phase.
		pp.gcMarkWorkerMode = gcMarkWorkerDedicatedMode
	} else if c.fractionalUtilizationGoal == 0 {
		// No need for fractional workers.
		gcBgMarkWorkerPool.push(&node.node)
		return nil, now
	} else {
		// Is this P behind on the fractional utilization
		// goal?
		//
		// This should be kept in sync with pollFractionalWorkerExit.
		delta := now - c.markStartTime
		if delta > 0 && float64(pp.gcFractionalMarkTime)/float64(delta) > c.fractionalUtilizationGoal {
			// Nope. No need to run a fractional worker.
			gcBgMarkWorkerPool.push(&node.node)
			return nil, now
		}
		// Run a fractional worker.
		pp.gcMarkWorkerMode = gcMarkWorkerFractionalMode
	}

	// Run the background mark worker.
	gp := node.gp.ptr()
	trace := traceAcquire()
	casgstatus(gp, _Gwaiting, _Grunnable)
	if trace.ok() {
		trace.GoUnpark(gp, 0)
		traceRelease(trace)
	}
	return gp, now
}

// resetLive sets up the controller state for the next mark phase after the end
// of the previous one. Must be called after endCycle and before commit, before
// the world is started.
//
// The world must be stopped.
func (c *gcControllerState) resetLive(bytesMarked uint64) {
	c.heapMarked = bytesMarked
	c.heapLive.Store(bytesMarked)
	c.heapScan.Store(uint64(c.heapScanWork.Load()))
	c.lastHeapScan = uint64(c.heapScanWork.Load())
	c.lastStackScan.Store(uint64(c.stackScanWork.Load()))
	c.triggered = ^uint64(0) // Reset triggered.

	// heapLive was updated, so emit a trace event.
	trace := traceAcquire()
	if trace.ok() {
		trace.HeapAlloc(bytesMarked)
		traceRelease(trace)
	}
}

// markWorkerStop must be called whenever a mark worker stops executing.
//
// It updates mark work accounting in the controller by a duration of
// work in nanoseconds and other bookkeeping.
//
// Safe to execute at any time.
func (c *gcControllerState) markWorkerStop(mode gcMarkWorkerMode, duration int64) {
	switch mode {
	case gcMarkWorkerDedicatedMode:
		c.dedicatedMarkTime.Add(duration)
		c.dedicatedMarkWorkersNeeded.Add(1)
	case gcMarkWorkerFractionalMode:
		c.fractionalMarkTime.Add(duration)
	case gcMarkWorkerIdleMode:
		c.idleMarkTime.Add(duration)
		c.removeIdleMarkWorker()
	default:
		throw("markWorkerStop: unknown mark worker mode")
	}
}

func (c *gcControllerState) update(dHeapLive, dHeapScan int64) {
	if dHeapLive != 0 {
		trace := traceAcquire()
		live := gcController.heapLive.Add(dHeapLive)
		if trace.ok() {
			// gcController.heapLive changed.
			trace.HeapAlloc(live)
			traceRelease(trace)
		}
	}
	if gcBlackenEnabled == 0 {
		// Update heapScan when we're not in a current GC. It is fixed
		// at the beginning of a cycle.
		if dHeapScan != 0 {
			gcController.heapScan.Add(dHeapScan)
		}
	} else {
		// gcController.heapLive changed.
		c.revise()
	}
}

func (c *gcControllerState) addScannableStack(pp *p, amount int64) {
	if pp == nil {
		c.maxStackScan.Add(amount)
		return
	}
	pp.maxStackScanDelta += amount
	if pp.maxStackScanDelta >= maxStackScanSlack || pp.maxStackScanDelta <= -maxStackScanSlack {
		c.maxStackScan.Add(pp.maxStackScanDelta)
		pp.maxStackScanDelta = 0
	}
}

func (c *gcControllerState) addGlobals(amount int64) {
	c.globalsScan.Add(amount)
}

// heapGoal returns the current heap goal.
func (c *gcControllerState) heapGoal() uint64 {
	goal, _ := c.heapGoalInternal()
	return goal
}

// heapGoalInternal is the implementation of heapGoal which returns additional
// information that is necessary for computing the trigger.
//
// The returned minTrigger is always <= goal.
func (c *gcControllerState) heapGoalInternal() (goal, minTrigger uint64) {
	// Start with the goal calculated for gcPercent.
	goal = c.gcPercentHeapGoal.Load()

	// Check if the memory-limit-based goal is smaller, and if so, pick that.
	if newGoal := c.memoryLimitHeapGoal(); newGoal < goal {
		goal = newGoal
	} else {
		// We're not limited by the memory limit goal, so perform a series of
		// adjustments that might move the goal forward in a variety of circumstances.

		sweepDistTrigger := c.sweepDistMinTrigger.Load()
		if sweepDistTrigger > goal {
			// Set the goal to maintain a minimum sweep distance since
			// the last call to commit. Note that we never want to do this
			// if we're in the memory limit regime, because it could push
			// the goal up.
			goal = sweepDistTrigger
		}
		// Since we ignore the sweep distance trigger in the memory
		// limit regime, we need to ensure we don't propagate it to
		// the trigger, because it could cause a violation of the
		// invariant that the trigger < goal.
		minTrigger = sweepDistTrigger

		// Ensure that the heap goal is at least a little larger than
		// the point at which we triggered. This may not be the case if GC
		// start is delayed or if the allocation that pushed gcController.heapLive
		// over trigger is large or if the trigger is really close to
		// GOGC. Assist is proportional to this distance, so enforce a
		// minimum distance, even if it means going over the GOGC goal
		// by a tiny bit.
		//
		// Ignore this if we're in the memory limit regime: we'd prefer to
		// have the GC respond hard about how close we are to the goal than to
		// push the goal back in such a manner that it could cause us to exceed
		// the memory limit.
		const minRunway = 64 << 10
		if c.triggered != ^uint64(0) && goal < c.triggered+minRunway {
			goal = c.triggered + minRunway
		}
	}
	return
}

// memoryLimitHeapGoal returns a heap goal derived from memoryLimit.
func (c *gcControllerState) memoryLimitHeapGoal() uint64 {
	// Start by pulling out some values we'll need. Be careful about overflow.
	var heapFree, heapAlloc, mappedReady uint64
	for {
		heapFree = c.heapFree.load()                         // Free and unscavenged memory.
		heapAlloc = c.totalAlloc.Load() - c.totalFree.Load() // Heap object bytes in use.
		mappedReady = c.mappedReady.Load()                   // Total unreleased mapped memory.
		if heapFree+heapAlloc <= mappedReady {
			break
		}
		// It is impossible for total unreleased mapped memory to exceed heap memory, but
		// because these stats are updated independently, we may observe a partial update
		// including only some values. Thus, we appear to break the invariant. However,
		// this condition is necessarily transient, so just try again. In the case of a
		// persistent accounting error, we'll deadlock here.
	}

	// Below we compute a goal from memoryLimit. There are a few things to be aware of.
	// Firstly, the memoryLimit does not easily compare to the heap goal: the former
	// is total mapped memory by the runtime that hasn't been released, while the latter is
	// only heap object memory. Intuitively, the way we convert from one to the other is to
	// subtract everything from memoryLimit that both contributes to the memory limit (so,
	// ignore scavenged memory) and doesn't contain heap objects. This isn't quite what
	// lines up with reality, but it's a good starting point.
	//
	// In practice this computation looks like the following:
	//
	//    goal := memoryLimit - ((mappedReady - heapFree - heapAlloc) + max(mappedReady - memoryLimit, 0))
	//                    ^1                                    ^2
	//    goal -= goal / 100 * memoryLimitHeapGoalHeadroomPercent
	//    ^3
	//
	// Let's break this down.
	//
	// The first term (marker 1) is everything that contributes to the memory limit and isn't
	// or couldn't become heap objects. It represents, broadly speaking, non-heap overheads.
	// One oddity you may have noticed is that we also subtract out heapFree, i.e. unscavenged
	// memory that may contain heap objects in the future.
	//
	// Let's take a step back. In an ideal world, this term would look something like just
	// the heap goal. That is, we "reserve" enough space for the heap to grow to the heap
	// goal, and subtract out everything else. This is of course impossible; the definition
	// is circular! However, this impossible definition contains a key insight: the amount
	// we're *going* to use matters just as much as whatever we're currently using.
	//
	// Consider if the heap shrinks to 1/10th its size, leaving behind lots of free and
	// unscavenged memory. mappedReady - heapAlloc will be quite large, because of that free
	// and unscavenged memory, pushing the goal down significantly.
	//
	// heapFree is also safe to exclude from the memory limit because in the steady-state, it's
	// just a pool of memory for future heap allocations, and making new allocations from heapFree
	// memory doesn't increase overall memory use. In transient states, the scavenger and the
	// allocator actively manage the pool of heapFree memory to maintain the memory limit.
	//
	// The second term (marker 2) is the amount of memory we've exceeded the limit by, and is
	// intended to help recover from such a situation. By pushing the heap goal down, we also
	// push the trigger down, triggering and finishing a GC sooner in order to make room for
	// other memory sources. Note that since we're effectively reducing the heap goal by X bytes,
	// we're actually giving more than X bytes of headroom back, because the heap goal is in
	// terms of heap objects, but it takes more than X bytes (e.g. due to fragmentation) to store
	// X bytes worth of objects.
	//
	// The final adjustment (marker 3) reduces the maximum possible memory limit heap goal by
	// memoryLimitHeapGoalPercent. As the name implies, this is to provide additional headroom in
	// the face of pacing inaccuracies, and also to leave a buffer of unscavenged memory so the
	// allocator isn't constantly scavenging. The reduction amount also has a fixed minimum
	// (memoryLimitMinHeapGoalHeadroom, not pictured) because the aforementioned pacing inaccuracies
	// disproportionately affect small heaps: as heaps get smaller, the pacer's inputs get fuzzier.
	// Shorter GC cycles and less GC work means noisy external factors like the OS scheduler have a
	// greater impact.

	memoryLimit := uint64(c.memoryLimit.Load())

	// Compute term 1.
	nonHeapMemory := mappedReady - heapFree - heapAlloc

	// Compute term 2.
	var overage uint64
	if mappedReady > memoryLimit {
		overage = mappedReady - memoryLimit
	}

	if nonHeapMemory+overage >= memoryLimit {
		// We're at a point where non-heap memory exceeds the memory limit on its own.
		// There's honestly not much we can do here but just trigger GCs continuously
		// and let the CPU limiter reign that in. Something has to give at this point.
		// Set it to heapMarked, the lowest possible goal.
		return c.heapMarked
	}

	// Compute the goal.
	goal := memoryLimit - (nonHeapMemory + overage)

	// Apply some headroom to the goal to account for pacing inaccuracies and to reduce
	// the impact of scavenging at allocation time in response to a high allocation rate
	// when GOGC=off. See issue #57069. Also, be careful about small limits.
	headroom := goal / 100 * memoryLimitHeapGoalHeadroomPercent
	if headroom < memoryLimitMinHeapGoalHeadroom {
		// Set a fixed minimum to deal with the particularly large effect pacing inaccuracies
		// have for smaller heaps.
		headroom = memoryLimitMinHeapGoalHeadroom
	}
	if goal < headroom || goal-headroom < headroom {
		goal = headroom
	} else {
		goal = goal - headroom
	}
	// Don't let us go below the live heap. A heap goal below the live heap doesn't make sense.
	if goal < c.heapMarked {
		goal = c.heapMarked
	}
	return goal
}

const (
	// These constants determine the bounds on the GC trigger as a fraction
	// of heap bytes allocated between the start of a GC (heapLive == heapMarked)
	// and the end of a GC (heapLive == heapGoal).
	//
	// The constants are obscured in this way for efficiency. The denominator
	// of the fraction is always a power-of-two for a quick division, so that
	// the numerator is a single constant integer multiplication.
	triggerRatioDen = 64

	// The minimum trigger constant was chosen empirically: given a sufficiently
	// fast/scalable allocator with 48 Ps that could drive the trigger ratio
	// to <0.05, this constant causes applications to retain the same peak
	// RSS compared to not having this allocator.
	minTriggerRatioNum = 45 // ~0.7

	// The maximum trigger constant is chosen somewhat arbitrarily, but the
	// current constant has served us well over the years.
	maxTriggerRatioNum = 61 // ~0.95
)

// trigger returns the current point at which a GC should trigger along with
// the heap goal.
//
// The returned value may be compared against heapLive to determine whether
// the GC should trigger. Thus, the GC trigger condition should be (but may
// not be, in the case of small movements for efficiency) checked whenever
// the heap goal may change.
func (c *gcControllerState) trigger() (uint64, uint64) {
	goal, minTrigger := c.heapGoalInternal()

	// Invariant: the trigger must always be less than the heap goal.
	//
	// Note that the memory limit sets a hard maximum on our heap goal,
	// but the live heap may grow beyond it.

	if c.heapMarked >= goal {
		// The goal should never be smaller than heapMarked, but let's be
		// defensive about it. The only reasonable trigger here is one that
		// causes a continuous GC cycle at heapMarked, but respect the goal
		// if it came out as smaller than that.
		return goal, goal
	}

	// Below this point, c.heapMarked < goal.

	// heapMarked is our absolute minimum, and it's possible the trigger
	// bound we get from heapGoalinternal is less than that.
	if minTrigger < c.heapMarked {
		minTrigger = c.heapMarked
	}

	// If we let the trigger go too low, then if the application
	// is allocating very rapidly we might end up in a situation
	// where we're allocating black during a nearly always-on GC.
	// The result of this is a growing heap and ultimately an
	// increase in RSS. By capping us at a point >0, we're essentially
	// saying that we're OK using more CPU during the GC to prevent
	// this growth in RSS.
	triggerLowerBound := ((goal-c.heapMarked)/triggerRatioDen)*minTriggerRatioNum + c.heapMarked
	if minTrigger < triggerLowerBound {
		minTrigger = triggerLowerBound
	}

	// For small heaps, set the max trigger point at maxTriggerRatio of the way
	// from the live heap to the heap goal. This ensures we always have *some*
	// headroom when the GC actually starts. For larger heaps, set the max trigger
	// point at the goal, minus the minimum heap size.
	//
	// This choice follows from the fact that the minimum heap size is chosen
	// to reflect the costs of a GC with no work to do. With a large heap but
	// very little scan work to perform, this gives us exactly as much runway
	// as we would need, in the worst case.
	maxTrigger := ((goal-c.heapMarked)/triggerRatioDen)*maxTriggerRatioNum + c.heapMarked
	if goal > defaultHeapMinimum && goal-defaultHeapMinimum > maxTrigger {
		maxTrigger = goal - defaultHeapMinimum
	}
	maxTrigger = max(maxTrigger, minTrigger)

	// Compute the trigger from our bounds and the runway stored by commit.
	var trigger uint64
	runway := c.runway.Load()
	if runway > goal {
		trigger = minTrigger
	} else {
		trigger = goal - runway
	}
	trigger = max(trigger, minTrigger)
	trigger = min(trigger, maxTrigger)
	if trigger > goal {
		print("trigger=", trigger, " heapGoal=", goal, "\n")
		print("minTrigger=", minTrigger, " maxTrigger=", maxTrigger, "\n")
		throw("produced a trigger greater than the heap goal")
	}
	return trigger, goal
}

// commit recomputes all pacing parameters needed to derive the
// trigger and the heap goal. Namely, the gcPercent-based heap goal,
// and the amount of runway we want to give the GC this cycle.
//
// This can be called any time. If GC is the in the middle of a
// concurrent phase, it will adjust the pacing of that phase.
//
// isSweepDone should be the result of calling isSweepDone(),
// unless we're testing or we know we're executing during a GC cycle.
//
// This depends on gcPercent, gcController.heapMarked, and
// gcController.heapLive. These must be up to date.
//
// Callers must call gcControllerState.revise after calling this
// function if the GC is enabled.
//
// mheap_.lock must be held or the world must be stopped.
func (c *gcControllerState) commit(isSweepDone bool) {
	if !c.test {
		assertWorldStoppedOrLockHeld(&mheap_.lock)
	}

	if isSweepDone {
		// The sweep is done, so there aren't any restrictions on the trigger
		// we need to think about.
		c.sweepDistMinTrigger.Store(0)
	} else {
		// Concurrent sweep happens in the heap growth
		// from gcController.heapLive to trigger. Make sure we
		// give the sweeper some runway if it doesn't have enough.
		c.sweepDistMinTrigger.Store(c.heapLive.Load() + sweepMinHeapDistance)
	}

	// Compute the next GC goal, which is when the allocated heap
	// has grown by GOGC/100 over where it started the last cycle,
	// plus additional runway for non-heap sources of GC work.
	gcPercentHeapGoal := ^uint64(0)
	if gcPercent := c.gcPercent.Load(); gcPercent >= 0 {
		gcPercentHeapGoal = c.heapMarked + (c.heapMarked+c.lastStackScan.Load()+c.globalsScan.Load())*uint64(gcPercent)/100
	}
	// Apply the minimum heap size here. It's defined in terms of gcPercent
	// and is only updated by functions that call commit.
	if gcPercentHeapGoal < c.heapMinimum {
		gcPercentHeapGoal = c.heapMinimum
	}
	c.gcPercentHeapGoal.Store(gcPercentHeapGoal)

	// Compute the amount of runway we want the GC to have by using our
	// estimate of the cons/mark ratio.
	//
	// The idea is to take our expected scan work, and multiply it by
	// the cons/mark ratio to determine how long it'll take to complete
	// that scan work in terms of bytes allocated. This gives us our GC's
	// runway.
	//
	// However, the cons/mark ratio is a ratio of rates per CPU-second, but
	// here we care about the relative rates for some division of CPU
	// resources among the mutator and the GC.
	//
	// To summarize, we have B / cpu-ns, and we want B / ns. We get that
	// by multiplying by our desired division of CPU resources. We choose
	// to express CPU resources as GOMAPROCS*fraction. Note that because
	// we're working with a ratio here, we can omit the number of CPU cores,
	// because they'll appear in the numerator and denominator and cancel out.
	// As a result, this is basically just "weighing" the cons/mark ratio by
	// our desired division of resources.
	//
	// Furthermore, by setting the runway so that CPU resources are divided
	// this way, assuming that the cons/mark ratio is correct, we make that
	// division a reality.
	c.runway.Store(uint64((c.consMark * (1 - gcGoalUtilization) / (gcGoalUtilization)) * float64(c.lastHeapScan+c.lastStackScan.Load()+c.globalsScan.Load())))
}

// setGCPercent updates gcPercent. commit must be called after.
// Returns the old value of gcPercent.
//
// The world must be stopped, or mheap_.lock must be held.
func (c *gcControllerState) setGCPercent(in int32) int32 {
	if !c.test {
		assertWorldStoppedOrLockHeld(&mheap_.lock)
	}

	out := c.gcPercent.Load()
	if in < 0 {
		in = -1
	}
	c.heapMinimum = defaultHeapMinimum * uint64(in) / 100
	c.gcPercent.Store(in)

	return out
}

//go:linkname setGCPercent runtime/debug.setGCPercent
func setGCPercent(in int32) (out int32) {
	// Run on the system stack since we grab the heap lock.
	systemstack(func() {
		lock(&mheap_.lock)
		out = gcController.setGCPercent(in)
		gcControllerCommit()
		unlock(&mheap_.lock)
	})

	// If we just disabled GC, wait for any concurrent GC mark to
	// finish so we always return with no GC running.
	if in < 0 {
		gcWaitOnMark(work.cycles.Load())
	}

	return out
}

func readGOGC() int32 {
	p := gogetenv("GOGC")
	if p == "off" {
		return -1
	}
	if n, ok := atoi32(p); ok {
		return n
	}
	return 100
}

// setMemoryLimit updates memoryLimit. commit must be called after
// Returns the old value of memoryLimit.
//
// The world must be stopped, or mheap_.lock must be held.
func (c *gcControllerState) setMemoryLimit(in int64) int64 {
	if !c.test {
		assertWorldStoppedOrLockHeld(&mheap_.lock)
	}

	out := c.memoryLimit.Load()
	if in >= 0 {
		c.memoryLimit.Store(in)
	}

	return out
}

//go:linkname setMemoryLimit runtime/debug.setMemoryLimit
func setMemoryLimit(in int64) (out int64) {
	// Run on the system stack since we grab the heap lock.
	systemstack(func() {
		lock(&mheap_.lock)
		out = gcController.setMemoryLimit(in)
		if in < 0 || out == in {
			// If we're just checking the value or not changing
			// it, there's no point in doing the rest.
			unlock(&mheap_.lock)
			return
		}
		gcControllerCommit()
		unlock(&mheap_.lock)
	})
	return out
}

func readGOMEMLIMIT() int64 {
	p := gogetenv("GOMEMLIMIT")
	if p == "" || p == "off" {
		return maxInt64
	}
	n, ok := parseByteCount(p)
	if !ok {
		print("GOMEMLIMIT=", p, "\n")
		throw("malformed GOMEMLIMIT; see `go doc runtime/debug.SetMemoryLimit`")
	}
	return n
}

// addIdleMarkWorker attempts to add a new idle mark worker.
//
// If this returns true, the caller must become an idle mark worker unless
// there's no background mark worker goroutines in the pool. This case is
// harmless because there are already background mark workers running.
// If this returns false, the caller must NOT become an idle mark worker.
//
// nosplit because it may be called without a P.
//
//go:nosplit
func (c *gcControllerState) addIdleMarkWorker() bool {
	for {
		old := c.idleMarkWorkers.Load()
		n, max := int32(old&uint64(^uint32(0))), int32(old>>32)
		if n >= max {
			// See the comment on idleMarkWorkers for why
			// n > max is tolerated.
			return false
		}
		if n < 0 {
			print("n=", n, " max=", max, "\n")
			throw("negative idle mark workers")
		}
		new := uint64(uint32(n+1)) | (uint64(max) << 32)
		if c.idleMarkWorkers.CompareAndSwap(old, new) {
			return true
		}
	}
}

// needIdleMarkWorker is a hint as to whether another idle mark worker is needed.
//
// The caller must still call addIdleMarkWorker to become one. This is mainly
// useful for a quick check before an expensive operation.
//
// nosplit because it may be called without a P.
//
//go:nosplit
func (c *gcControllerState) needIdleMarkWorker() bool {
	p := c.idleMarkWorkers.Load()
	n, max := int32(p&uint64(^uint32(0))), int32(p>>32)
	return n < max
}

// removeIdleMarkWorker must be called when a new idle mark worker stops executing.
func (c *gcControllerState) removeIdleMarkWorker() {
	for {
		old := c.idleMarkWorkers.Load()
		n, max := int32(old&uint64(^uint32(0))), int32(old>>32)
		if n-1 < 0 {
			print("n=", n, " max=", max, "\n")
			throw("negative idle mark workers")
		}
		new := uint64(uint32(n-1)) | (uint64(max) << 32)
		if c.idleMarkWorkers.CompareAndSwap(old, new) {
			return
		}
	}
}

// setMaxIdleMarkWorkers sets the maximum number of idle mark workers allowed.
//
// This method is optimistic in that it does not wait for the number of
// idle mark workers to reduce to max before returning; it assumes the workers
// will deschedule themselves.
func (c *gcControllerState) setMaxIdleMarkWorkers(max int32) {
	for {
		old := c.idleMarkWorkers.Load()
		n := int32(old & uint64(^uint32(0)))
		if n < 0 {
			print("n=", n, " max=", max, "\n")
			throw("negative idle mark workers")
		}
		new := uint64(uint32(n)) | (uint64(max) << 32)
		if c.idleMarkWorkers.CompareAndSwap(old, new) {
			return
		}
	}
}

// gcControllerCommit is gcController.commit, but passes arguments from live
// (non-test) data. It also updates any consumers of the GC pacing, such as
// sweep pacing and the background scavenger.
//
// Calls gcController.commit.
//
// The heap lock must be held, so this must be executed on the system stack.
//
//go:systemstack
func gcControllerCommit() {
	assertWorldStoppedOrLockHeld(&mheap_.lock)

	gcController.commit(isSweepDone())

	// Update mark pacing.
	if gcphase != _GCoff {
		gcController.revise()
	}

	// TODO(mknyszek): This isn't really accurate any longer because the heap
	// goal is computed dynamically. Still useful to snapshot, but not as useful.
	trace := traceAcquire()
	if trace.ok() {
		trace.HeapGoal()
		traceRelease(trace)
	}

	trigger, heapGoal := gcController.trigger()
	gcPaceSweeper(trigger)
	gcPaceScavenger(gcController.memoryLimit.Load(), heapGoal, gcController.lastHeapGoal)
}

"""




```