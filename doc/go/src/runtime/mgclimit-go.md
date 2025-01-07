Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The primary request is to understand the functionality of the `mgclimit.go` file, which deals with limiting GC CPU usage. The request also asks for a Go code example, reasoning with assumptions, command-line argument analysis (if applicable), and common pitfalls.

2. **Identify Key Data Structures:** The first step is to identify the central data structure. In this case, it's `gcCPULimiterState`. Analyzing its fields gives a high-level understanding of the mechanism:
    * `lock`:  Indicates a need for synchronization, suggesting concurrent access.
    * `enabled`:  A boolean flag, likely indicating if the limiter is active.
    * `bucket`:  A nested struct with `fill` and `capacity`, strongly suggesting a "leaky bucket" algorithm.
    * `overflow`: Hints at tracking when the GC tried to exceed its limit.
    * Time-related fields (`assistTimePool`, `idleTimePool`, `lastUpdate`): These indicate the limiter tracks time spent on various activities.
    * `lastEnabledCycle`:  Suggests tracking when the limiter was last active.
    * `nprocs`: Indicates awareness of the number of available processors.

3. **Analyze Key Functions:** Next, look at the methods associated with `gcCPULimiterState`:
    * `limiting()`:  Simple check for the `enabled` state.
    * `startGCTransition()` and `finishGCTransition()`: These clearly manage transitions related to the GC, likely STW (Stop-The-World) phases. The mention of locking and flushing hints at critical operations.
    * `needUpdate()`:  A periodic update mechanism is in place.
    * `addAssistTime()` and `addIdleTime()`:  External methods for contributing time information.
    * `update()` and `updateLocked()`:  The core logic for updating the bucket based on time information. The locking behavior is important here.
    * `accumulate()`:  The heart of the leaky bucket logic, adjusting the `fill` and potentially enabling/disabling the limiter.
    * `tryLock()` and `unlock()`: Standard locking primitives.
    * `resetCapacity()`:  Handles changes in `GOMAXPROCS`.

4. **Focus on the Leaky Bucket Analogy:** The comments and the structure of the `bucket` field strongly suggest a leaky bucket. Visualize how it works:
    * GC activity "fills" the bucket.
    * Mutator (application) activity "drains" the bucket.
    * The `capacity` represents the limit.
    * If the bucket is full, the limiter is enabled.

5. **Infer the Purpose and Functionality:** Based on the above analysis, we can deduce the following:
    * The code implements a CPU usage limiter for the Go garbage collector.
    * It uses a leaky bucket algorithm to allow bursts of GC activity without immediately throttling.
    * The limit is roughly 50% of CPU time.
    * It tracks various time components: GC assist time, idle time, and total CPU time.
    * It adjusts the limit based on `GOMAXPROCS`.

6. **Construct a Go Code Example:** To illustrate the functionality, think about how the limiter would behave in a simple scenario. A program that allocates a lot of memory will trigger the GC frequently. The example should demonstrate the limiter kicking in when GC usage becomes excessive. Key elements of the example:
    * A loop that causes allocations.
    * Accessing `runtime.GC()` to force garbage collection (for demonstration purposes).
    * Using `runtime.ReadMemStats` to observe GC-related metrics.
    * Checking the `gcCPULimiter.limiting()` state.
    * *Initial Thought:*  Directly manipulating `gcCPULimiter` fields. *Correction:* Realized this is internal and the example should focus on *observing* the *effects* of the limiter.

7. **Reasoning with Assumptions (Input/Output):**  Think about specific scenarios and how the limiter would react. For instance:
    * *High Allocation Rate:* Input: Program allocating rapidly. Output: `gcCPULimiter.limiting()` becomes true, potentially impacting application performance.
    * *Idle Application:* Input: Program mostly idle. Output:  Bucket drains, `gcCPULimiter.limiting()` remains false.

8. **Command-Line Arguments:** Scan the code for any interaction with `os.Args` or the `flag` package. In this case, there are no explicit command-line parameters being parsed within the snippet. Therefore, the conclusion is that this specific code doesn't directly handle command-line arguments, though the GC behavior itself might be influenced by environment variables like `GOGC`.

9. **Common Pitfalls:**  Consider how developers might misunderstand or misuse this feature. Since it's an internal mechanism, direct misuse is unlikely. The focus should be on *misunderstanding the behavior* or expecting it to solve problems it's not designed for:
    * Assuming it's a precise hard limit.
    * Expecting it to solve all performance issues related to GC.
    * Not understanding the leaky bucket analogy.

10. **Structure the Answer:** Organize the findings logically:
    * Start with a summary of the functionality.
    * Explain the leaky bucket mechanism.
    * Provide the Go code example with clear explanations.
    * Detail the reasoning with input/output assumptions.
    * Address command-line arguments (or the lack thereof).
    * Discuss potential pitfalls.

11. **Refine and Review:** Read through the generated answer, ensuring clarity, accuracy, and completeness. Double-check the code example and the explanations. Make sure the language is accessible and avoids overly technical jargon where possible. For example, initially, I might have used more internal Go terms, but I would refine it to be more understandable to a wider audience.
这段Go语言代码实现了**Go垃圾回收器（Garbage Collector, GC）的CPU使用限制功能**。

**功能详解：**

这段代码的核心目标是在某些情况下限制Go GC的CPU使用率，防止GC过度占用CPU资源，影响应用程序的正常运行（例如，进入所谓的“死亡螺旋”状态，即GC消耗大量CPU但无法回收足够的内存）。

它使用了一种**漏桶（Leaky Bucket）**机制来实现这个限制：

1. **填充 (Fill)：** 漏桶以GC消耗的CPU时间来填充。
2. **泄露 (Drain)：** 漏桶以应用程序（mutator）消耗的CPU时间来泄露。
3. **容量 (Capacity)：** 漏桶有一个最大容量。

**核心原理：**

* **限制触发：** 当漏桶中的“水”（代表GC CPU时间）超过容量时，限制器被激活，指示GC应该采取行动来限制CPU使用率。
* **保守的限制：** 由于填充和泄露直接使用时间，没有加权，因此默认情况下设置了一个非常保守的50%的CPU使用率上限。
* **容忍峰值：** 漏桶机制允许GC CPU使用率出现短暂的峰值，而不会立即触发限制，从而避免影响吞吐量。
* **不积累“信用”：**  漏桶的“水”不会变为负值。这意味着即使应用程序长时间空闲，GC也不会因此获得“信用”，从而防止在之后出现突发的GC CPU占用过高的情况。
* **窗口期：** 漏桶的容量也定义了限制器考虑的时间窗口。例如，如果容量是1 CPU秒，那么只有在最近的2 CPU秒窗口内，GC CPU时间至少达到1秒时，限制器才会启动。

**Go语言功能实现推断与代码示例：**

这个功能是Go运行时系统内部的实现，开发者通常不需要直接操作它。它的目标是自动管理GC的行为，以平衡内存回收和应用程序性能。

可以推断，Go运行时系统会在GC的各个阶段调用`gcCPULimiterState`的方法来更新漏桶的状态和检查是否需要限制GC的CPU使用。

以下是一个**假设性**的Go代码示例，展示了在GC过程中如何可能与这个限制器交互（**请注意，这只是一个概念性的例子，实际的交互发生在Go运行时内部，开发者无法直接访问和控制**）：

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	// 假设我们有一个不断分配内存的场景
	for i := 0; i < 10000; i++ {
		_ = make([]byte, 1024*1024) // 分配 1MB 内存

		// 假设我们可以某种方式获取当前的GC CPU限制器状态 (实际无法直接获取)
		// limiterState := runtime.GetGCCPULimiterState() // 假设有这样的函数

		// 模拟检查是否达到了限制
		// if limiterState.limiting() {
		// 	fmt.Println("GC CPU 限制器已激活，可能需要放缓分配")
		// 	time.Sleep(100 * time.Millisecond) // 模拟放缓操作
		// }
	}

	fmt.Println("内存分配完成")
	runtime.GC() // 手动触发一次 GC
}
```

**假设的输入与输出：**

假设上面的程序在运行过程中，由于不断分配内存，导致GC频繁触发，并且GC的CPU占用率很高。

* **输入：**  持续的内存分配，导致GC不断运行。
* **输出：**  在`gcCPULimiterState`内部，漏桶的填充速度会超过泄露速度，当`fill`达到`capacity`时，`limiting()`方法会返回`true`。虽然上面的示例代码无法直接观察到这个状态变化，但在实际的Go运行时中，这会触发GC采取措施来降低其CPU使用率，例如减少并发GC worker的数量或者降低GC的频率。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。Go的GC行为可以通过一些环境变量来配置，例如：

* **`GOGC`**: 设置垃圾回收的目标百分比。`GOGC=off` 可以完全禁用 GC。
* **`GOMAXPROCS`**:  设置可同时执行用户代码的最大 CPU 核心数。这会影响到 `resetCapacity` 方法中计算的漏桶容量。

`resetCapacity` 方法会根据 `GOMAXPROCS` 的值来调整漏桶的容量。例如，如果 `GOMAXPROCS` 从 4 变为 8，`resetCapacity` 会被调用，并将漏桶的容量调整为原来的两倍。

**使用者易犯错的点：**

由于 `gcCPULimiter` 是Go运行时内部的机制，普通开发者无法直接控制或修改其行为。因此，这里不存在使用者易犯错的点。

**总结：**

`go/src/runtime/mgclimit.go` 实现了一个精巧的机制，用于动态地限制Go垃圾回收器的CPU使用率，以防止GC过度占用资源，影响应用程序的性能。它通过漏桶模型来平滑GC的CPU使用，允许短暂的峰值，并在GC CPU使用率过高时进行干预，从而保持系统的整体稳定性和响应性。 开发者无需直接操作此代码，Go运行时会自动管理其行为。

Prompt: 
```
这是路径为go/src/runtime/mgclimit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import "internal/runtime/atomic"

// gcCPULimiter is a mechanism to limit GC CPU utilization in situations
// where it might become excessive and inhibit application progress (e.g.
// a death spiral).
//
// The core of the limiter is a leaky bucket mechanism that fills with GC
// CPU time and drains with mutator time. Because the bucket fills and
// drains with time directly (i.e. without any weighting), this effectively
// sets a very conservative limit of 50%. This limit could be enforced directly,
// however, but the purpose of the bucket is to accommodate spikes in GC CPU
// utilization without hurting throughput.
//
// Note that the bucket in the leaky bucket mechanism can never go negative,
// so the GC never gets credit for a lot of CPU time spent without the GC
// running. This is intentional, as an application that stays idle for, say,
// an entire day, could build up enough credit to fail to prevent a death
// spiral the following day. The bucket's capacity is the GC's only leeway.
//
// The capacity thus also sets the window the limiter considers. For example,
// if the capacity of the bucket is 1 cpu-second, then the limiter will not
// kick in until at least 1 full cpu-second in the last 2 cpu-second window
// is spent on GC CPU time.
var gcCPULimiter gcCPULimiterState

type gcCPULimiterState struct {
	lock atomic.Uint32

	enabled atomic.Bool

	// gcEnabled is an internal copy of gcBlackenEnabled that determines
	// whether the limiter tracks total assist time.
	//
	// gcBlackenEnabled isn't used directly so as to keep this structure
	// unit-testable.
	gcEnabled bool

	// transitioning is true when the GC is in a STW and transitioning between
	// the mark and sweep phases.
	transitioning bool

	// test indicates whether this instance of the struct was made for testing purposes.
	test bool

	bucket struct {
		// Invariants:
		// - fill >= 0
		// - capacity >= 0
		// - fill <= capacity
		fill, capacity uint64
	}
	// overflow is the cumulative amount of GC CPU time that we tried to fill the
	// bucket with but exceeded its capacity.
	overflow uint64

	// assistTimePool is the accumulated assist time since the last update.
	assistTimePool atomic.Int64

	// idleMarkTimePool is the accumulated idle mark time since the last update.
	idleMarkTimePool atomic.Int64

	// idleTimePool is the accumulated time Ps spent on the idle list since the last update.
	idleTimePool atomic.Int64

	// lastUpdate is the nanotime timestamp of the last time update was called.
	//
	// Updated under lock, but may be read concurrently.
	lastUpdate atomic.Int64

	// lastEnabledCycle is the GC cycle that last had the limiter enabled.
	lastEnabledCycle atomic.Uint32

	// nprocs is an internal copy of gomaxprocs, used to determine total available
	// CPU time.
	//
	// gomaxprocs isn't used directly so as to keep this structure unit-testable.
	nprocs int32
}

// limiting returns true if the CPU limiter is currently enabled, meaning the Go GC
// should take action to limit CPU utilization.
//
// It is safe to call concurrently with other operations.
func (l *gcCPULimiterState) limiting() bool {
	return l.enabled.Load()
}

// startGCTransition notifies the limiter of a GC transition.
//
// This call takes ownership of the limiter and disables all other means of
// updating the limiter. Release ownership by calling finishGCTransition.
//
// It is safe to call concurrently with other operations.
func (l *gcCPULimiterState) startGCTransition(enableGC bool, now int64) {
	if !l.tryLock() {
		// This must happen during a STW, so we can't fail to acquire the lock.
		// If we did, something went wrong. Throw.
		throw("failed to acquire lock to start a GC transition")
	}
	if l.gcEnabled == enableGC {
		throw("transitioning GC to the same state as before?")
	}
	// Flush whatever was left between the last update and now.
	l.updateLocked(now)
	l.gcEnabled = enableGC
	l.transitioning = true
	// N.B. finishGCTransition releases the lock.
	//
	// We don't release here to increase the chance that if there's a failure
	// to finish the transition, that we throw on failing to acquire the lock.
}

// finishGCTransition notifies the limiter that the GC transition is complete
// and releases ownership of it. It also accumulates STW time in the bucket.
// now must be the timestamp from the end of the STW pause.
func (l *gcCPULimiterState) finishGCTransition(now int64) {
	if !l.transitioning {
		throw("finishGCTransition called without starting one?")
	}
	// Count the full nprocs set of CPU time because the world is stopped
	// between startGCTransition and finishGCTransition. Even though the GC
	// isn't running on all CPUs, it is preventing user code from doing so,
	// so it might as well be.
	if lastUpdate := l.lastUpdate.Load(); now >= lastUpdate {
		l.accumulate(0, (now-lastUpdate)*int64(l.nprocs))
	}
	l.lastUpdate.Store(now)
	l.transitioning = false
	l.unlock()
}

// gcCPULimiterUpdatePeriod dictates the maximum amount of wall-clock time
// we can go before updating the limiter.
const gcCPULimiterUpdatePeriod = 10e6 // 10ms

// needUpdate returns true if the limiter's maximum update period has been
// exceeded, and so would benefit from an update.
func (l *gcCPULimiterState) needUpdate(now int64) bool {
	return now-l.lastUpdate.Load() > gcCPULimiterUpdatePeriod
}

// addAssistTime notifies the limiter of additional assist time. It will be
// included in the next update.
func (l *gcCPULimiterState) addAssistTime(t int64) {
	l.assistTimePool.Add(t)
}

// addIdleTime notifies the limiter of additional time a P spent on the idle list. It will be
// subtracted from the total CPU time in the next update.
func (l *gcCPULimiterState) addIdleTime(t int64) {
	l.idleTimePool.Add(t)
}

// update updates the bucket given runtime-specific information. now is the
// current monotonic time in nanoseconds.
//
// This is safe to call concurrently with other operations, except *GCTransition.
func (l *gcCPULimiterState) update(now int64) {
	if !l.tryLock() {
		// We failed to acquire the lock, which means something else is currently
		// updating. Just drop our update, the next one to update will include
		// our total assist time.
		return
	}
	if l.transitioning {
		throw("update during transition")
	}
	l.updateLocked(now)
	l.unlock()
}

// updateLocked is the implementation of update. l.lock must be held.
func (l *gcCPULimiterState) updateLocked(now int64) {
	lastUpdate := l.lastUpdate.Load()
	if now < lastUpdate {
		// Defensively avoid overflow. This isn't even the latest update anyway.
		return
	}
	windowTotalTime := (now - lastUpdate) * int64(l.nprocs)
	l.lastUpdate.Store(now)

	// Drain the pool of assist time.
	assistTime := l.assistTimePool.Load()
	if assistTime != 0 {
		l.assistTimePool.Add(-assistTime)
	}

	// Drain the pool of idle time.
	idleTime := l.idleTimePool.Load()
	if idleTime != 0 {
		l.idleTimePool.Add(-idleTime)
	}

	if !l.test {
		// Consume time from in-flight events. Make sure we're not preemptible so allp can't change.
		//
		// The reason we do this instead of just waiting for those events to finish and push updates
		// is to ensure that all the time we're accounting for happened sometime between lastUpdate
		// and now. This dramatically simplifies reasoning about the limiter because we're not at
		// risk of extra time being accounted for in this window than actually happened in this window,
		// leading to all sorts of weird transient behavior.
		mp := acquirem()
		for _, pp := range allp {
			typ, duration := pp.limiterEvent.consume(now)
			switch typ {
			case limiterEventIdleMarkWork:
				fallthrough
			case limiterEventIdle:
				idleTime += duration
				sched.idleTime.Add(duration)
			case limiterEventMarkAssist:
				fallthrough
			case limiterEventScavengeAssist:
				assistTime += duration
			case limiterEventNone:
				break
			default:
				throw("invalid limiter event type found")
			}
		}
		releasem(mp)
	}

	// Compute total GC time.
	windowGCTime := assistTime
	if l.gcEnabled {
		windowGCTime += int64(float64(windowTotalTime) * gcBackgroundUtilization)
	}

	// Subtract out all idle time from the total time. Do this after computing
	// GC time, because the background utilization is dependent on the *real*
	// total time, not the total time after idle time is subtracted.
	//
	// Idle time is counted as any time that a P is on the P idle list plus idle mark
	// time. Idle mark workers soak up time that the application spends idle.
	//
	// On a heavily undersubscribed system, any additional idle time can skew GC CPU
	// utilization, because the GC might be executing continuously and thrashing,
	// yet the CPU utilization with respect to GOMAXPROCS will be quite low, so
	// the limiter fails to turn on. By subtracting idle time, we're removing time that
	// we know the application was idle giving a more accurate picture of whether
	// the GC is thrashing.
	//
	// Note that this can cause the limiter to turn on even if it's not needed. For
	// instance, on a system with 32 Ps but only 1 running goroutine, each GC will have
	// 8 dedicated GC workers. Assuming the GC cycle is half mark phase and half sweep
	// phase, then the GC CPU utilization over that cycle, with idle time removed, will
	// be 8/(8+2) = 80%. Even though the limiter turns on, though, assist should be
	// unnecessary, as the GC has way more CPU time to outpace the 1 goroutine that's
	// running.
	windowTotalTime -= idleTime

	l.accumulate(windowTotalTime-windowGCTime, windowGCTime)
}

// accumulate adds time to the bucket and signals whether the limiter is enabled.
//
// This is an internal function that deals just with the bucket. Prefer update.
// l.lock must be held.
func (l *gcCPULimiterState) accumulate(mutatorTime, gcTime int64) {
	headroom := l.bucket.capacity - l.bucket.fill
	enabled := headroom == 0

	// Let's be careful about three things here:
	// 1. The addition and subtraction, for the invariants.
	// 2. Overflow.
	// 3. Excessive mutation of l.enabled, which is accessed
	//    by all assists, potentially more than once.
	change := gcTime - mutatorTime

	// Handle limiting case.
	if change > 0 && headroom <= uint64(change) {
		l.overflow += uint64(change) - headroom
		l.bucket.fill = l.bucket.capacity
		if !enabled {
			l.enabled.Store(true)
			l.lastEnabledCycle.Store(memstats.numgc + 1)
		}
		return
	}

	// Handle non-limiting cases.
	if change < 0 && l.bucket.fill <= uint64(-change) {
		// Bucket emptied.
		l.bucket.fill = 0
	} else {
		// All other cases.
		l.bucket.fill -= uint64(-change)
	}
	if change != 0 && enabled {
		l.enabled.Store(false)
	}
}

// tryLock attempts to lock l. Returns true on success.
func (l *gcCPULimiterState) tryLock() bool {
	return l.lock.CompareAndSwap(0, 1)
}

// unlock releases the lock on l. Must be called if tryLock returns true.
func (l *gcCPULimiterState) unlock() {
	old := l.lock.Swap(0)
	if old != 1 {
		throw("double unlock")
	}
}

// capacityPerProc is the limiter's bucket capacity for each P in GOMAXPROCS.
const capacityPerProc = 1e9 // 1 second in nanoseconds

// resetCapacity updates the capacity based on GOMAXPROCS. Must not be called
// while the GC is enabled.
//
// It is safe to call concurrently with other operations.
func (l *gcCPULimiterState) resetCapacity(now int64, nprocs int32) {
	if !l.tryLock() {
		// This must happen during a STW, so we can't fail to acquire the lock.
		// If we did, something went wrong. Throw.
		throw("failed to acquire lock to reset capacity")
	}
	// Flush the rest of the time for this period.
	l.updateLocked(now)
	l.nprocs = nprocs

	l.bucket.capacity = uint64(nprocs) * capacityPerProc
	if l.bucket.fill > l.bucket.capacity {
		l.bucket.fill = l.bucket.capacity
		l.enabled.Store(true)
		l.lastEnabledCycle.Store(memstats.numgc + 1)
	} else if l.bucket.fill < l.bucket.capacity {
		l.enabled.Store(false)
	}
	l.unlock()
}

// limiterEventType indicates the type of an event occurring on some P.
//
// These events represent the full set of events that the GC CPU limiter tracks
// to execute its function.
//
// This type may use no more than limiterEventBits bits of information.
type limiterEventType uint8

const (
	limiterEventNone           limiterEventType = iota // None of the following events.
	limiterEventIdleMarkWork                           // Refers to an idle mark worker (see gcMarkWorkerMode).
	limiterEventMarkAssist                             // Refers to mark assist (see gcAssistAlloc).
	limiterEventScavengeAssist                         // Refers to a scavenge assist (see allocSpan).
	limiterEventIdle                                   // Refers to time a P spent on the idle list.

	limiterEventBits = 3
)

// limiterEventTypeMask is a mask for the bits in p.limiterEventStart that represent
// the event type. The rest of the bits of that field represent a timestamp.
const (
	limiterEventTypeMask  = uint64((1<<limiterEventBits)-1) << (64 - limiterEventBits)
	limiterEventStampNone = limiterEventStamp(0)
)

// limiterEventStamp is a nanotime timestamp packed with a limiterEventType.
type limiterEventStamp uint64

// makeLimiterEventStamp creates a new stamp from the event type and the current timestamp.
func makeLimiterEventStamp(typ limiterEventType, now int64) limiterEventStamp {
	return limiterEventStamp(uint64(typ)<<(64-limiterEventBits) | (uint64(now) &^ limiterEventTypeMask))
}

// duration computes the difference between now and the start time stored in the stamp.
//
// Returns 0 if the difference is negative, which may happen if now is stale or if the
// before and after timestamps cross a 2^(64-limiterEventBits) boundary.
func (s limiterEventStamp) duration(now int64) int64 {
	// The top limiterEventBits bits of the timestamp are derived from the current time
	// when computing a duration.
	start := int64((uint64(now) & limiterEventTypeMask) | (uint64(s) &^ limiterEventTypeMask))
	if now < start {
		return 0
	}
	return now - start
}

// type extracts the event type from the stamp.
func (s limiterEventStamp) typ() limiterEventType {
	return limiterEventType(s >> (64 - limiterEventBits))
}

// limiterEvent represents tracking state for an event tracked by the GC CPU limiter.
type limiterEvent struct {
	stamp atomic.Uint64 // Stores a limiterEventStamp.
}

// start begins tracking a new limiter event of the current type. If an event
// is already in flight, then a new event cannot begin because the current time is
// already being attributed to that event. In this case, this function returns false.
// Otherwise, it returns true.
//
// The caller must be non-preemptible until at least stop is called or this function
// returns false. Because this is trying to measure "on-CPU" time of some event, getting
// scheduled away during it can mean that whatever we're measuring isn't a reflection
// of "on-CPU" time. The OS could deschedule us at any time, but we want to maintain as
// close of an approximation as we can.
func (e *limiterEvent) start(typ limiterEventType, now int64) bool {
	if limiterEventStamp(e.stamp.Load()).typ() != limiterEventNone {
		return false
	}
	e.stamp.Store(uint64(makeLimiterEventStamp(typ, now)))
	return true
}

// consume acquires the partial event CPU time from any in-flight event.
// It achieves this by storing the current time as the new event time.
//
// Returns the type of the in-flight event, as well as how long it's currently been
// executing for. Returns limiterEventNone if no event is active.
func (e *limiterEvent) consume(now int64) (typ limiterEventType, duration int64) {
	// Read the limiter event timestamp and update it to now.
	for {
		old := limiterEventStamp(e.stamp.Load())
		typ = old.typ()
		if typ == limiterEventNone {
			// There's no in-flight event, so just push that up.
			return
		}
		duration = old.duration(now)
		if duration == 0 {
			// We might have a stale now value, or this crossed the
			// 2^(64-limiterEventBits) boundary in the clock readings.
			// Just ignore it.
			return limiterEventNone, 0
		}
		new := makeLimiterEventStamp(typ, now)
		if e.stamp.CompareAndSwap(uint64(old), uint64(new)) {
			break
		}
	}
	return
}

// stop stops the active limiter event. Throws if the
//
// The caller must be non-preemptible across the event. See start as to why.
func (e *limiterEvent) stop(typ limiterEventType, now int64) {
	var stamp limiterEventStamp
	for {
		stamp = limiterEventStamp(e.stamp.Load())
		if stamp.typ() != typ {
			print("runtime: want=", typ, " got=", stamp.typ(), "\n")
			throw("limiterEvent.stop: found wrong event in p's limiter event slot")
		}
		if e.stamp.CompareAndSwap(uint64(stamp), uint64(limiterEventStampNone)) {
			break
		}
	}
	duration := stamp.duration(now)
	if duration == 0 {
		// It's possible that we're missing time because we crossed a
		// 2^(64-limiterEventBits) boundary between the start and end.
		// In this case, we're dropping that information. This is OK because
		// at worst it'll cause a transient hiccup that will quickly resolve
		// itself as all new timestamps begin on the other side of the boundary.
		// Such a hiccup should be incredibly rare.
		return
	}
	// Account for the event.
	switch typ {
	case limiterEventIdleMarkWork:
		gcCPULimiter.addIdleTime(duration)
	case limiterEventIdle:
		gcCPULimiter.addIdleTime(duration)
		sched.idleTime.Add(duration)
	case limiterEventMarkAssist:
		fallthrough
	case limiterEventScavengeAssist:
		gcCPULimiter.addAssistTime(duration)
	default:
		throw("limiterEvent.stop: invalid limiter event type found")
	}
}

"""



```