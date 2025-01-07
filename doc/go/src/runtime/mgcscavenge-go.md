Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The first step is to recognize the high-level purpose. The comments clearly state: "Scavenging free pages."  This immediately tells us we're dealing with memory management, specifically reclaiming unused memory.

2. **Identify Key Components:**  Scan the code for important terms and data structures. Keywords like "scavenge," "heap," "RSS," "goal," "memory limit," "background," "synchronous," and names like `scavenge`, `gcController`, `mheap_`, and `pageAlloc` jump out. These are the building blocks of the functionality.

3. **Analyze Top-Level Comments:** The initial block of comments provides a fantastic overview. Read it carefully and note the two types of scavenging (background and allocation-time), the concepts of RSS goals, the distinction between having a memory limit and not, and the idea of "dense" allocation and its implications.

4. **Examine Data Structures:** Look at the `scavenge` struct and `scavengerState` struct. What information do they hold?
    * `scavenge`: Goals related to `gcPercent` and `memoryLimit`, and timing information (`assistTime`, `backgroundTime`). This seems to track the overall scavenging status and targets.
    * `scavengerState`: Contains the actual state of the background scavenger goroutine: its goroutine (`g`), timer, lock, sleep-related variables (`sleepRatio`, `sleepController`), and importantly, function pointers for `scavenge` and `shouldStop`. This structure manages the execution and pacing of the background scavenger.

5. **Follow the Logic (Function by Function):** Go through the main functions and understand their individual roles.
    * `heapRetained()`:  A simple helper to estimate RSS.
    * `gcPaceScavenger()`: This is crucial. It calculates the scavenging goals based on whether a memory limit is set. Pay close attention to the formulas and the conditions for setting the goals. The comments are very helpful here.
    * `bgscavenge()`: This is the entry point for the background scavenger goroutine. It initializes the state, parks, and then enters the main loop of running and sleeping.
    * `scavenge()` (on `pageAlloc`): This function orchestrates the actual scavenging process, calling `scavengeOne` in a loop.
    * `scavengeOne()`: This is where the low-level memory manipulation happens. It finds candidates, marks them as allocated temporarily, calls `sysUnused` to release the memory to the OS, and then frees the pages back to the allocator.
    * `printScavTrace()`: A debugging/monitoring function.

6. **Identify Key Concepts and Algorithms:**
    * **Targeted RSS Reduction:** The core idea is to bring the application's memory footprint down to a desired level.
    * **Dual Goals:**  Scavenging is driven by either the `gcPercent` (heap goal) or the `memoryLimit`.
    * **Background vs. Synchronous:** Two distinct ways scavenging occurs, with different triggers and strategies.
    * **Pacing:** The background scavenger is paced to avoid consuming too much CPU time. The `scavengerState` and its `sleepController` are key here.
    * **Density Heuristics:**  The concept of avoiding scavenging "dense" chunks, particularly for the background scavenger, is important for performance.
    * **`sysUnused`:** The fundamental system call for releasing memory.

7. **Synthesize and Summarize:**  Now that you have a good understanding of the individual pieces, start putting them together in a coherent summary. Focus on the "what" and "why" of the code. Use the comments as a guide.

8. **Address Specific Questions:**  Go back to the original prompt and answer each part.
    * **Functionality:**  List the key functions you identified.
    * **Go Feature:**  Clearly, this is part of the Go runtime's garbage collection system, specifically focused on memory reclamation.
    * **Code Example:**  Think about how to trigger this. Setting `GOMEMLIMIT` is a direct way to engage the memory limit-based scavenging. A simpler example involves observing heap growth triggering synchronous scavenging.
    * **Assumptions and I/O:**  Focus on the memory limit example and what you'd expect to see in memory usage.
    * **Command-Line Arguments:** `GOMEMLIMIT` is the primary one.
    * **Common Mistakes:**  Consider scenarios where assumptions might break down or where manual intervention might conflict with the automatic process.

9. **Refine and Organize:**  Ensure your answer is well-structured, uses clear language, and accurately reflects the code's behavior. Use headings and bullet points for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this just about freeing memory?"  **Correction:** Realize it's more sophisticated than that, involving goals, pacing, and different strategies.
* **Focus on individual lines:** **Correction:**  Shift to understanding the purpose of entire functions and how they interact.
* **Overlook the pacing mechanism:** **Correction:** Pay closer attention to `scavengerState` and how the `sleepController` works.
* **Not connecting the code to a Go feature:** **Correction:** Recognize that this is a key part of the garbage collection implementation, specifically memory pressure management.
* **Struggling with a code example:** **Correction:** Think about the most direct ways to trigger the described behavior (e.g., `GOMEMLIMIT`).

By following these steps, you can systematically analyze and understand complex code like this Go runtime snippet. The key is to start with the big picture, break it down into smaller pieces, understand the purpose of each piece, and then synthesize your understanding back into a coherent whole.

这段Go语言代码是Go运行时环境（runtime）中负责**内存回收（Scavenging）** 的一部分。它的主要功能是释放堆内存中空闲且未使用的页，从而减少Go应用程序的内存占用（RSS, Resident Set Size），并应对页级别的内存碎片问题。

以下是代码的具体功能归纳：

**核心功能： 释放未使用的堆内存页**

* **目标：** 降低应用程序的内存占用（RSS）并应对内存碎片。
* **机制：** 通过将空闲的内存页返还给操作系统来实现。

**两种Scavenging方式：**

1. **后台（异步）Scavenger：**
   * **运行方式：** 在一个独立的goroutine中运行，类似于后台的垃圾回收扫描器（sweeper）。
   * **资源限制：**  其资源使用受到限制，最多使用mutator（应用程序）运行时间的`scavengePercent` (默认为1%)。
   * **触发条件：** 当预估的堆内存RSS高于目标值时触发。
   * **目标计算：**
      * **无内存限制时：** 目标RSS是基于当前的堆目标（heapGoal），并考虑了一定的额外保留空间 (`retainExtraPercent`) 和上一次GC后的堆使用量 (`lastHeapInUse`)，以适应堆的增长和碎片。
      * **有内存限制时：** 目标RSS是基于设定的内存限制 (`memoryLimit`)，并向下调整了一定的比例 (`reduceExtraPercent`)，以确保即使接近限制也能积极回收内存。
   * **更新频率：**  目标值在每次GC后更新。
   * **释放条件：**  只释放那些至少在一个完整的GC周期内没有被密集分配的内存块，以提高内存重用的可能性并避免破坏巨页。

2. **分配时（同步）Scavenger：**
   * **运行方式：** 在分配内存页时同步执行。
   * **触发条件：**
      * 当分配内存会导致超出内存限制时。
      * 当堆大小增长时（意味着现有碎片不足以满足分配）。
   * **释放条件：**  对于因堆增长触发的同步回收，也会考虑内存块的“密度”，避免回收正在被密集使用的内存。但对于因内存限制或`debug.FreeOSMemory`触发的回收，会强制回收，忽略密度限制。

**关键组件和概念：**

* **`scavengePercent`:**  后台回收器允许使用的mutator时间的百分比上限。
* **`retainExtraPercent`:**  在没有内存限制时，Scavenger目标值高于堆目标的额外百分比，作为分配器的缓冲。
* **`reduceExtraPercent`:** 在有内存限制时，Scavenger目标值低于内存限制的百分比，确保积极回收。
* **`heapRetained()`:**  估计当前堆内存的RSS。
* **`gcPaceScavenger()`:**  更新Scavenger的步调，包括速率和RSS目标。
* **`scavenge` 结构体:** 存储了后台Scavenger的目标值 (`gcPercentGoal`, `memoryLimitGoal`) 和时间统计 (`assistTime`, `backgroundTime`)。
* **`scavengerState` 结构体:**  管理后台Scavenger goroutine的状态，包括锁、goroutine、定时器、睡眠控制 (`sleepController`) 以及实际执行回收的函数 (`scavenge`)。
* **`sysUnused()`:**  底层系统调用，用于将内存页返还给操作系统。
* **内存块“密度”：**  指在一个GC周期内，内存块中被分配的页面的比例。Scavenger会避免回收高密度使用的内存块，除非被强制。

**可以推理出的Go语言功能实现：**

这段代码是Go语言运行时垃圾回收器中，**内存压力管理** 或 **内存释放优化** 功能的具体实现。它旨在在应用程序不使用某些内存时，将其释放回操作系统，从而降低内存占用。

**Go代码示例：**

以下代码演示了如何通过设置 `GOMEMLIMIT` 环境变量来触发基于内存限制的Scavenging：

```go
// main.go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	// 模拟分配大量内存
	largeData := make([]byte, 1024*1024*500) // 500MB
	_ = largeData

	fmt.Println("分配了大量内存")
	printMemStats()

	// 等待一段时间，让后台 Scavenger 有机会运行
	time.Sleep(10 * time.Second)

	fmt.Println("等待后内存状态:")
	printMemStats()

	// 手动触发一次 GC，可能加速 Scavenging
	runtime.GC()

	fmt.Println("GC 后内存状态:")
	printMemStats()

	// 继续运行，观察内存变化
	time.Sleep(10 * time.Second)
	fmt.Println("再次等待后内存状态:")
	printMemStats()
}

func printMemStats() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tHeapAlloc = %v MiB", bToMb(m.HeapAlloc))
	fmt.Printf("\tHeapSys = %v MiB", bToMb(m.HeapSys))
	fmt.Printf("\tHeapIdle = %v MiB", bToMb(m.HeapIdle))
	fmt.Printf("\tHeapReleased = %v MiB", bToMb(m.HeapReleased))
	fmt.Printf("\tMallocs = %v\n", m.Mallocs)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
```

**假设的输入与输出：**

假设我们编译并运行上述代码，并在运行前设置了 `GOMEMLIMIT=300m` 环境变量。

**输入：**

* 运行 `go run main.go` 前设置环境变量 `GOMEMLIMIT=300m`

**预期输出（可能因系统环境略有不同）：**

```
分配了大量内存
Alloc = XXX MiB	TotalAlloc = YYY MiB	Sys = ZZZ MiB	HeapAlloc = AAA MiB	HeapSys = BBB MiB	HeapIdle = CCC MiB	HeapReleased = DDD MiB	Mallocs = EEE
等待后内存状态:
Alloc = FFF MiB	TotalAlloc = YYY MiB	Sys = GGG MiB	HeapAlloc = HHH MiB	HeapSys = III MiB	HeapIdle = JJJ MiB	HeapReleased = KKK MiB	Mallocs = EEE
GC 后内存状态:
Alloc = LLL MiB	TotalAlloc = YYY MiB	Sys = MMM MiB	HeapAlloc = NNN MiB	HeapSys = OOO MiB	HeapIdle = PPP MiB	HeapReleased = QQQ MiB	Mallocs = EEE
再次等待后内存状态:
Alloc = RRR MiB	TotalAlloc = YYY MiB	Sys = SSS MiB	HeapAlloc = TTT MiB	HeapSys = UUU MiB	HeapIdle = VVV MiB	HeapReleased = WWW MiB	Mallocs = EEE
```

**推理：**

* 初始分配后，`Sys` 和 `HeapSys` 会比较高。
* 在等待期间，由于设置了 `GOMEMLIMIT`，后台 Scavenger 会尝试将 `Sys` 和 `HeapSys` 降低到接近 300MB 的目标。你会观察到 `HeapReleased` 的值增加。
* 手动触发 GC 可能会加速 Scavenging 的过程，更明显地看到内存释放。

**涉及的命令行参数的具体处理：**

* **`GOMEMLIMIT`：**  这个环境变量用于设置Go程序的内存使用硬限制。当设置了这个值后，`gcPaceScavenger` 函数会使用基于内存限制的目标计算方式。后台 Scavenger 和分配时的 Scavenger 都会积极工作以维持内存使用在限制之下。代码中会读取这个环境变量的值，并将其转换为内部使用的字节数。

**使用者易犯错的点：**

* **过度依赖或不理解 Scavenging 的工作方式：** 开发者可能会误以为设置了 `GOMEMLIMIT` 后，内存会立即且总是被回收。Scavenging 是一个后台过程，受到步调控制，并且会考虑内存重用的可能性。因此，即使设置了内存限制，内存的释放也可能不是立即发生的。
* **与 `debug.FreeOSMemory()` 的混淆：**  `debug.FreeOSMemory()` 会强制进行内存回收，不考虑“密度”等优化策略，可能导致性能下降。开发者应该理解这两种机制的区别，并在合适的场景下使用。

**总结：**

这段代码实现了Go语言运行时环境中用于回收空闲堆内存页的 Scavenging 机制，包括后台异步和分配时同步两种方式。其目标是降低内存占用，应对内存碎片，并受到 `GOMEMLIMIT` 环境变量的影响。理解 Scavenging 的工作方式对于优化Go应用程序的内存使用至关重要。

Prompt: 
```
这是路径为go/src/runtime/mgcscavenge.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Scavenging free pages.
//
// This file implements scavenging (the release of physical pages backing mapped
// memory) of free and unused pages in the heap as a way to deal with page-level
// fragmentation and reduce the RSS of Go applications.
//
// Scavenging in Go happens on two fronts: there's the background
// (asynchronous) scavenger and the allocation-time (synchronous) scavenger.
//
// The former happens on a goroutine much like the background sweeper which is
// soft-capped at using scavengePercent of the mutator's time, based on
// order-of-magnitude estimates of the costs of scavenging. The latter happens
// when allocating pages from the heap.
//
// The scavenger's primary goal is to bring the estimated heap RSS of the
// application down to a goal.
//
// Before we consider what this looks like, we need to split the world into two
// halves. One in which a memory limit is not set, and one in which it is.
//
// For the former, the goal is defined as:
//   (retainExtraPercent+100) / 100 * (heapGoal / lastHeapGoal) * lastHeapInUse
//
// Essentially, we wish to have the application's RSS track the heap goal, but
// the heap goal is defined in terms of bytes of objects, rather than pages like
// RSS. As a result, we need to take into account for fragmentation internal to
// spans. heapGoal / lastHeapGoal defines the ratio between the current heap goal
// and the last heap goal, which tells us by how much the heap is growing and
// shrinking. We estimate what the heap will grow to in terms of pages by taking
// this ratio and multiplying it by heapInUse at the end of the last GC, which
// allows us to account for this additional fragmentation. Note that this
// procedure makes the assumption that the degree of fragmentation won't change
// dramatically over the next GC cycle. Overestimating the amount of
// fragmentation simply results in higher memory use, which will be accounted
// for by the next pacing up date. Underestimating the fragmentation however
// could lead to performance degradation. Handling this case is not within the
// scope of the scavenger. Situations where the amount of fragmentation balloons
// over the course of a single GC cycle should be considered pathologies,
// flagged as bugs, and fixed appropriately.
//
// An additional factor of retainExtraPercent is added as a buffer to help ensure
// that there's more unscavenged memory to allocate out of, since each allocation
// out of scavenged memory incurs a potentially expensive page fault.
//
// If a memory limit is set, then we wish to pick a scavenge goal that maintains
// that memory limit. For that, we look at total memory that has been committed
// (memstats.mappedReady) and try to bring that down below the limit. In this case,
// we want to give buffer space in the *opposite* direction. When the application
// is close to the limit, we want to make sure we push harder to keep it under, so
// if we target below the memory limit, we ensure that the background scavenger is
// giving the situation the urgency it deserves.
//
// In this case, the goal is defined as:
//    (100-reduceExtraPercent) / 100 * memoryLimit
//
// We compute both of these goals, and check whether either of them have been met.
// The background scavenger continues operating as long as either one of the goals
// has not been met.
//
// The goals are updated after each GC.
//
// Synchronous scavenging happens for one of two reasons: if an allocation would
// exceed the memory limit or whenever the heap grows in size, for some
// definition of heap-growth. The intuition behind this second reason is that the
// application had to grow the heap because existing fragments were not sufficiently
// large to satisfy a page-level memory allocation, so we scavenge those fragments
// eagerly to offset the growth in RSS that results.
//
// Lastly, not all pages are available for scavenging at all times and in all cases.
// The background scavenger and heap-growth scavenger only release memory in chunks
// that have not been densely-allocated for at least 1 full GC cycle. The reason
// behind this is likelihood of reuse: the Go heap is allocated in a first-fit order
// and by the end of the GC mark phase, the heap tends to be densely packed. Releasing
// memory in these densely packed chunks while they're being packed is counter-productive,
// and worse, it breaks up huge pages on systems that support them. The scavenger (invoked
// during memory allocation) further ensures that chunks it identifies as "dense" are
// immediately eligible for being backed by huge pages. Note that for the most part these
// density heuristics are best-effort heuristics. It's totally possible (but unlikely)
// that a chunk that just became dense is scavenged in the case of a race between memory
// allocation and scavenging.
//
// When synchronously scavenging for the memory limit or for debug.FreeOSMemory, these
// "dense" packing heuristics are ignored (in other words, scavenging is "forced") because
// in these scenarios returning memory to the OS is more important than keeping CPU
// overheads low.

package runtime

import (
	"internal/goos"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

const (
	// The background scavenger is paced according to these parameters.
	//
	// scavengePercent represents the portion of mutator time we're willing
	// to spend on scavenging in percent.
	scavengePercent = 1 // 1%

	// retainExtraPercent represents the amount of memory over the heap goal
	// that the scavenger should keep as a buffer space for the allocator.
	// This constant is used when we do not have a memory limit set.
	//
	// The purpose of maintaining this overhead is to have a greater pool of
	// unscavenged memory available for allocation (since using scavenged memory
	// incurs an additional cost), to account for heap fragmentation and
	// the ever-changing layout of the heap.
	retainExtraPercent = 10

	// reduceExtraPercent represents the amount of memory under the limit
	// that the scavenger should target. For example, 5 means we target 95%
	// of the limit.
	//
	// The purpose of shooting lower than the limit is to ensure that, once
	// close to the limit, the scavenger is working hard to maintain it. If
	// we have a memory limit set but are far away from it, there's no harm
	// in leaving up to 100-retainExtraPercent live, and it's more efficient
	// anyway, for the same reasons that retainExtraPercent exists.
	reduceExtraPercent = 5

	// maxPagesPerPhysPage is the maximum number of supported runtime pages per
	// physical page, based on maxPhysPageSize.
	maxPagesPerPhysPage = maxPhysPageSize / pageSize

	// scavengeCostRatio is the approximate ratio between the costs of using previously
	// scavenged memory and scavenging memory.
	//
	// For most systems the cost of scavenging greatly outweighs the costs
	// associated with using scavenged memory, making this constant 0. On other systems
	// (especially ones where "sysUsed" is not just a no-op) this cost is non-trivial.
	//
	// This ratio is used as part of multiplicative factor to help the scavenger account
	// for the additional costs of using scavenged memory in its pacing.
	scavengeCostRatio = 0.7 * (goos.IsDarwin + goos.IsIos)

	// scavChunkHiOcFrac indicates the fraction of pages that need to be allocated
	// in the chunk in a single GC cycle for it to be considered high density.
	scavChunkHiOccFrac  = 0.96875
	scavChunkHiOccPages = uint16(scavChunkHiOccFrac * pallocChunkPages)
)

// heapRetained returns an estimate of the current heap RSS.
func heapRetained() uint64 {
	return gcController.heapInUse.load() + gcController.heapFree.load()
}

// gcPaceScavenger updates the scavenger's pacing, particularly
// its rate and RSS goal. For this, it requires the current heapGoal,
// and the heapGoal for the previous GC cycle.
//
// The RSS goal is based on the current heap goal with a small overhead
// to accommodate non-determinism in the allocator.
//
// The pacing is based on scavengePageRate, which applies to both regular and
// huge pages. See that constant for more information.
//
// Must be called whenever GC pacing is updated.
//
// mheap_.lock must be held or the world must be stopped.
func gcPaceScavenger(memoryLimit int64, heapGoal, lastHeapGoal uint64) {
	assertWorldStoppedOrLockHeld(&mheap_.lock)

	// As described at the top of this file, there are two scavenge goals here: one
	// for gcPercent and one for memoryLimit. Let's handle the latter first because
	// it's simpler.

	// We want to target retaining (100-reduceExtraPercent)% of the heap.
	memoryLimitGoal := uint64(float64(memoryLimit) * (1 - reduceExtraPercent/100.0))

	// mappedReady is comparable to memoryLimit, and represents how much total memory
	// the Go runtime has committed now (estimated).
	mappedReady := gcController.mappedReady.Load()

	// If we're below the goal already indicate that we don't need the background
	// scavenger for the memory limit. This may seems worrisome at first, but note
	// that the allocator will assist the background scavenger in the face of a memory
	// limit, so we'll be safe even if we stop the scavenger when we shouldn't have.
	if mappedReady <= memoryLimitGoal {
		scavenge.memoryLimitGoal.Store(^uint64(0))
	} else {
		scavenge.memoryLimitGoal.Store(memoryLimitGoal)
	}

	// Now handle the gcPercent goal.

	// If we're called before the first GC completed, disable scavenging.
	// We never scavenge before the 2nd GC cycle anyway (we don't have enough
	// information about the heap yet) so this is fine, and avoids a fault
	// or garbage data later.
	if lastHeapGoal == 0 {
		scavenge.gcPercentGoal.Store(^uint64(0))
		return
	}
	// Compute our scavenging goal.
	goalRatio := float64(heapGoal) / float64(lastHeapGoal)
	gcPercentGoal := uint64(float64(memstats.lastHeapInUse) * goalRatio)
	// Add retainExtraPercent overhead to retainedGoal. This calculation
	// looks strange but the purpose is to arrive at an integer division
	// (e.g. if retainExtraPercent = 12.5, then we get a divisor of 8)
	// that also avoids the overflow from a multiplication.
	gcPercentGoal += gcPercentGoal / (1.0 / (retainExtraPercent / 100.0))
	// Align it to a physical page boundary to make the following calculations
	// a bit more exact.
	gcPercentGoal = (gcPercentGoal + uint64(physPageSize) - 1) &^ (uint64(physPageSize) - 1)

	// Represents where we are now in the heap's contribution to RSS in bytes.
	//
	// Guaranteed to always be a multiple of physPageSize on systems where
	// physPageSize <= pageSize since we map new heap memory at a size larger than
	// any physPageSize and released memory in multiples of the physPageSize.
	//
	// However, certain functions recategorize heap memory as other stats (e.g.
	// stacks) and this happens in multiples of pageSize, so on systems
	// where physPageSize > pageSize the calculations below will not be exact.
	// Generally this is OK since we'll be off by at most one regular
	// physical page.
	heapRetainedNow := heapRetained()

	// If we're already below our goal, or within one page of our goal, then indicate
	// that we don't need the background scavenger for maintaining a memory overhead
	// proportional to the heap goal.
	if heapRetainedNow <= gcPercentGoal || heapRetainedNow-gcPercentGoal < uint64(physPageSize) {
		scavenge.gcPercentGoal.Store(^uint64(0))
	} else {
		scavenge.gcPercentGoal.Store(gcPercentGoal)
	}
}

var scavenge struct {
	// gcPercentGoal is the amount of retained heap memory (measured by
	// heapRetained) that the runtime will try to maintain by returning
	// memory to the OS. This goal is derived from gcController.gcPercent
	// by choosing to retain enough memory to allocate heap memory up to
	// the heap goal.
	gcPercentGoal atomic.Uint64

	// memoryLimitGoal is the amount of memory retained by the runtime (
	// measured by gcController.mappedReady) that the runtime will try to
	// maintain by returning memory to the OS. This goal is derived from
	// gcController.memoryLimit by choosing to target the memory limit or
	// some lower target to keep the scavenger working.
	memoryLimitGoal atomic.Uint64

	// assistTime is the time spent by the allocator scavenging in the last GC cycle.
	//
	// This is reset once a GC cycle ends.
	assistTime atomic.Int64

	// backgroundTime is the time spent by the background scavenger in the last GC cycle.
	//
	// This is reset once a GC cycle ends.
	backgroundTime atomic.Int64
}

const (
	// It doesn't really matter what value we start at, but we can't be zero, because
	// that'll cause divide-by-zero issues. Pick something conservative which we'll
	// also use as a fallback.
	startingScavSleepRatio = 0.001

	// Spend at least 1 ms scavenging, otherwise the corresponding
	// sleep time to maintain our desired utilization is too low to
	// be reliable.
	minScavWorkTime = 1e6
)

// Sleep/wait state of the background scavenger.
var scavenger scavengerState

type scavengerState struct {
	// lock protects all fields below.
	lock mutex

	// g is the goroutine the scavenger is bound to.
	g *g

	// timer is the timer used for the scavenger to sleep.
	timer *timer

	// sysmonWake signals to sysmon that it should wake the scavenger.
	sysmonWake atomic.Uint32

	// parked is whether or not the scavenger is parked.
	parked bool

	// printControllerReset instructs printScavTrace to signal that
	// the controller was reset.
	printControllerReset bool

	// targetCPUFraction is the target CPU overhead for the scavenger.
	targetCPUFraction float64

	// sleepRatio is the ratio of time spent doing scavenging work to
	// time spent sleeping. This is used to decide how long the scavenger
	// should sleep for in between batches of work. It is set by
	// critSleepController in order to maintain a CPU overhead of
	// targetCPUFraction.
	//
	// Lower means more sleep, higher means more aggressive scavenging.
	sleepRatio float64

	// sleepController controls sleepRatio.
	//
	// See sleepRatio for more details.
	sleepController piController

	// controllerCooldown is the time left in nanoseconds during which we avoid
	// using the controller and we hold sleepRatio at a conservative
	// value. Used if the controller's assumptions fail to hold.
	controllerCooldown int64

	// sleepStub is a stub used for testing to avoid actually having
	// the scavenger sleep.
	//
	// Unlike the other stubs, this is not populated if left nil
	// Instead, it is called when non-nil because any valid implementation
	// of this function basically requires closing over this scavenger
	// state, and allocating a closure is not allowed in the runtime as
	// a matter of policy.
	sleepStub func(n int64) int64

	// scavenge is a function that scavenges n bytes of memory.
	// Returns how many bytes of memory it actually scavenged, as
	// well as the time it took in nanoseconds. Usually mheap.pages.scavenge
	// with nanotime called around it, but stubbed out for testing.
	// Like mheap.pages.scavenge, if it scavenges less than n bytes of
	// memory, the caller may assume the heap is exhausted of scavengable
	// memory for now.
	//
	// If this is nil, it is populated with the real thing in init.
	scavenge func(n uintptr) (uintptr, int64)

	// shouldStop is a callback called in the work loop and provides a
	// point that can force the scavenger to stop early, for example because
	// the scavenge policy dictates too much has been scavenged already.
	//
	// If this is nil, it is populated with the real thing in init.
	shouldStop func() bool

	// gomaxprocs returns the current value of gomaxprocs. Stub for testing.
	//
	// If this is nil, it is populated with the real thing in init.
	gomaxprocs func() int32
}

// init initializes a scavenger state and wires to the current G.
//
// Must be called from a regular goroutine that can allocate.
func (s *scavengerState) init() {
	if s.g != nil {
		throw("scavenger state is already wired")
	}
	lockInit(&s.lock, lockRankScavenge)
	s.g = getg()

	s.timer = new(timer)
	f := func(s any, _ uintptr, _ int64) {
		s.(*scavengerState).wake()
	}
	s.timer.init(f, s)

	// input: fraction of CPU time actually used.
	// setpoint: ideal CPU fraction.
	// output: ratio of time worked to time slept (determines sleep time).
	//
	// The output of this controller is somewhat indirect to what we actually
	// want to achieve: how much time to sleep for. The reason for this definition
	// is to ensure that the controller's outputs have a direct relationship with
	// its inputs (as opposed to an inverse relationship), making it somewhat
	// easier to reason about for tuning purposes.
	s.sleepController = piController{
		// Tuned loosely via Ziegler-Nichols process.
		kp: 0.3375,
		ti: 3.2e6,
		tt: 1e9, // 1 second reset time.

		// These ranges seem wide, but we want to give the controller plenty of
		// room to hunt for the optimal value.
		min: 0.001,  // 1:1000
		max: 1000.0, // 1000:1
	}
	s.sleepRatio = startingScavSleepRatio

	// Install real functions if stubs aren't present.
	if s.scavenge == nil {
		s.scavenge = func(n uintptr) (uintptr, int64) {
			start := nanotime()
			r := mheap_.pages.scavenge(n, nil, false)
			end := nanotime()
			if start >= end {
				return r, 0
			}
			scavenge.backgroundTime.Add(end - start)
			return r, end - start
		}
	}
	if s.shouldStop == nil {
		s.shouldStop = func() bool {
			// If background scavenging is disabled or if there's no work to do just stop.
			return heapRetained() <= scavenge.gcPercentGoal.Load() &&
				gcController.mappedReady.Load() <= scavenge.memoryLimitGoal.Load()
		}
	}
	if s.gomaxprocs == nil {
		s.gomaxprocs = func() int32 {
			return gomaxprocs
		}
	}
}

// park parks the scavenger goroutine.
func (s *scavengerState) park() {
	lock(&s.lock)
	if getg() != s.g {
		throw("tried to park scavenger from another goroutine")
	}
	s.parked = true
	goparkunlock(&s.lock, waitReasonGCScavengeWait, traceBlockSystemGoroutine, 2)
}

// ready signals to sysmon that the scavenger should be awoken.
func (s *scavengerState) ready() {
	s.sysmonWake.Store(1)
}

// wake immediately unparks the scavenger if necessary.
//
// Safe to run without a P.
func (s *scavengerState) wake() {
	lock(&s.lock)
	if s.parked {
		// Unset sysmonWake, since the scavenger is now being awoken.
		s.sysmonWake.Store(0)

		// s.parked is unset to prevent a double wake-up.
		s.parked = false

		// Ready the goroutine by injecting it. We use injectglist instead
		// of ready or goready in order to allow us to run this function
		// without a P. injectglist also avoids placing the goroutine in
		// the current P's runnext slot, which is desirable to prevent
		// the scavenger from interfering with user goroutine scheduling
		// too much.
		var list gList
		list.push(s.g)
		injectglist(&list)
	}
	unlock(&s.lock)
}

// sleep puts the scavenger to sleep based on the amount of time that it worked
// in nanoseconds.
//
// Note that this function should only be called by the scavenger.
//
// The scavenger may be woken up earlier by a pacing change, and it may not go
// to sleep at all if there's a pending pacing change.
func (s *scavengerState) sleep(worked float64) {
	lock(&s.lock)
	if getg() != s.g {
		throw("tried to sleep scavenger from another goroutine")
	}

	if worked < minScavWorkTime {
		// This means there wasn't enough work to actually fill up minScavWorkTime.
		// That's fine; we shouldn't try to do anything with this information
		// because it's going result in a short enough sleep request that things
		// will get messy. Just assume we did at least this much work.
		// All this means is that we'll sleep longer than we otherwise would have.
		worked = minScavWorkTime
	}

	// Multiply the critical time by 1 + the ratio of the costs of using
	// scavenged memory vs. scavenging memory. This forces us to pay down
	// the cost of reusing this memory eagerly by sleeping for a longer period
	// of time and scavenging less frequently. More concretely, we avoid situations
	// where we end up scavenging so often that we hurt allocation performance
	// because of the additional overheads of using scavenged memory.
	worked *= 1 + scavengeCostRatio

	// sleepTime is the amount of time we're going to sleep, based on the amount
	// of time we worked, and the sleepRatio.
	sleepTime := int64(worked / s.sleepRatio)

	var slept int64
	if s.sleepStub == nil {
		// Set the timer.
		//
		// This must happen here instead of inside gopark
		// because we can't close over any variables without
		// failing escape analysis.
		start := nanotime()
		s.timer.reset(start+sleepTime, 0)

		// Mark ourselves as asleep and go to sleep.
		s.parked = true
		goparkunlock(&s.lock, waitReasonSleep, traceBlockSleep, 2)

		// How long we actually slept for.
		slept = nanotime() - start

		lock(&s.lock)
		// Stop the timer here because s.wake is unable to do it for us.
		// We don't really care if we succeed in stopping the timer. One
		// reason we might fail is that we've already woken up, but the timer
		// might be in the process of firing on some other P; essentially we're
		// racing with it. That's totally OK. Double wake-ups are perfectly safe.
		s.timer.stop()
		unlock(&s.lock)
	} else {
		unlock(&s.lock)
		slept = s.sleepStub(sleepTime)
	}

	// Stop here if we're cooling down from the controller.
	if s.controllerCooldown > 0 {
		// worked and slept aren't exact measures of time, but it's OK to be a bit
		// sloppy here. We're just hoping we're avoiding some transient bad behavior.
		t := slept + int64(worked)
		if t > s.controllerCooldown {
			s.controllerCooldown = 0
		} else {
			s.controllerCooldown -= t
		}
		return
	}

	// idealFraction is the ideal % of overall application CPU time that we
	// spend scavenging.
	idealFraction := float64(scavengePercent) / 100.0

	// Calculate the CPU time spent.
	//
	// This may be slightly inaccurate with respect to GOMAXPROCS, but we're
	// recomputing this often enough relative to GOMAXPROCS changes in general
	// (it only changes when the world is stopped, and not during a GC) that
	// that small inaccuracy is in the noise.
	cpuFraction := worked / ((float64(slept) + worked) * float64(s.gomaxprocs()))

	// Update the critSleepRatio, adjusting until we reach our ideal fraction.
	var ok bool
	s.sleepRatio, ok = s.sleepController.next(cpuFraction, idealFraction, float64(slept)+worked)
	if !ok {
		// The core assumption of the controller, that we can get a proportional
		// response, broke down. This may be transient, so temporarily switch to
		// sleeping a fixed, conservative amount.
		s.sleepRatio = startingScavSleepRatio
		s.controllerCooldown = 5e9 // 5 seconds.

		// Signal the scav trace printer to output this.
		s.controllerFailed()
	}
}

// controllerFailed indicates that the scavenger's scheduling
// controller failed.
func (s *scavengerState) controllerFailed() {
	lock(&s.lock)
	s.printControllerReset = true
	unlock(&s.lock)
}

// run is the body of the main scavenging loop.
//
// Returns the number of bytes released and the estimated time spent
// releasing those bytes.
//
// Must be run on the scavenger goroutine.
func (s *scavengerState) run() (released uintptr, worked float64) {
	lock(&s.lock)
	if getg() != s.g {
		throw("tried to run scavenger from another goroutine")
	}
	unlock(&s.lock)

	for worked < minScavWorkTime {
		// If something from outside tells us to stop early, stop.
		if s.shouldStop() {
			break
		}

		// scavengeQuantum is the amount of memory we try to scavenge
		// in one go. A smaller value means the scavenger is more responsive
		// to the scheduler in case of e.g. preemption. A larger value means
		// that the overheads of scavenging are better amortized, so better
		// scavenging throughput.
		//
		// The current value is chosen assuming a cost of ~10µs/physical page
		// (this is somewhat pessimistic), which implies a worst-case latency of
		// about 160µs for 4 KiB physical pages. The current value is biased
		// toward latency over throughput.
		const scavengeQuantum = 64 << 10

		// Accumulate the amount of time spent scavenging.
		r, duration := s.scavenge(scavengeQuantum)

		// On some platforms we may see end >= start if the time it takes to scavenge
		// memory is less than the minimum granularity of its clock (e.g. Windows) or
		// due to clock bugs.
		//
		// In this case, just assume scavenging takes 10 µs per regular physical page
		// (determined empirically), and conservatively ignore the impact of huge pages
		// on timing.
		const approxWorkedNSPerPhysicalPage = 10e3
		if duration == 0 {
			worked += approxWorkedNSPerPhysicalPage * float64(r/physPageSize)
		} else {
			// TODO(mknyszek): If duration is small compared to worked, it could be
			// rounded down to zero. Probably not a problem in practice because the
			// values are all within a few orders of magnitude of each other but maybe
			// worth worrying about.
			worked += float64(duration)
		}
		released += r

		// scavenge does not return until it either finds the requisite amount of
		// memory to scavenge, or exhausts the heap. If we haven't found enough
		// to scavenge, then the heap must be exhausted.
		if r < scavengeQuantum {
			break
		}
		// When using fake time just do one loop.
		if faketime != 0 {
			break
		}
	}
	if released > 0 && released < physPageSize {
		// If this happens, it means that we may have attempted to release part
		// of a physical page, but the likely effect of that is that it released
		// the whole physical page, some of which may have still been in-use.
		// This could lead to memory corruption. Throw.
		throw("released less than one physical page of memory")
	}
	return
}

// Background scavenger.
//
// The background scavenger maintains the RSS of the application below
// the line described by the proportional scavenging statistics in
// the mheap struct.
func bgscavenge(c chan int) {
	scavenger.init()

	c <- 1
	scavenger.park()

	for {
		released, workTime := scavenger.run()
		if released == 0 {
			scavenger.park()
			continue
		}
		mheap_.pages.scav.releasedBg.Add(released)
		scavenger.sleep(workTime)
	}
}

// scavenge scavenges nbytes worth of free pages, starting with the
// highest address first. Successive calls continue from where it left
// off until the heap is exhausted. force makes all memory available to
// scavenge, ignoring huge page heuristics.
//
// Returns the amount of memory scavenged in bytes.
//
// scavenge always tries to scavenge nbytes worth of memory, and will
// only fail to do so if the heap is exhausted for now.
func (p *pageAlloc) scavenge(nbytes uintptr, shouldStop func() bool, force bool) uintptr {
	released := uintptr(0)
	for released < nbytes {
		ci, pageIdx := p.scav.index.find(force)
		if ci == 0 {
			break
		}
		systemstack(func() {
			released += p.scavengeOne(ci, pageIdx, nbytes-released)
		})
		if shouldStop != nil && shouldStop() {
			break
		}
	}
	return released
}

// printScavTrace prints a scavenge trace line to standard error.
//
// released should be the amount of memory released since the last time this
// was called, and forced indicates whether the scavenge was forced by the
// application.
//
// scavenger.lock must be held.
func printScavTrace(releasedBg, releasedEager uintptr, forced bool) {
	assertLockHeld(&scavenger.lock)

	printlock()
	print("scav ",
		releasedBg>>10, " KiB work (bg), ",
		releasedEager>>10, " KiB work (eager), ",
		gcController.heapReleased.load()>>10, " KiB now, ",
		(gcController.heapInUse.load()*100)/heapRetained(), "% util",
	)
	if forced {
		print(" (forced)")
	} else if scavenger.printControllerReset {
		print(" [controller reset]")
		scavenger.printControllerReset = false
	}
	println()
	printunlock()
}

// scavengeOne walks over the chunk at chunk index ci and searches for
// a contiguous run of pages to scavenge. It will try to scavenge
// at most max bytes at once, but may scavenge more to avoid
// breaking huge pages. Once it scavenges some memory it returns
// how much it scavenged in bytes.
//
// searchIdx is the page index to start searching from in ci.
//
// Returns the number of bytes scavenged.
//
// Must run on the systemstack because it acquires p.mheapLock.
//
//go:systemstack
func (p *pageAlloc) scavengeOne(ci chunkIdx, searchIdx uint, max uintptr) uintptr {
	// Calculate the maximum number of pages to scavenge.
	//
	// This should be alignUp(max, pageSize) / pageSize but max can and will
	// be ^uintptr(0), so we need to be very careful not to overflow here.
	// Rather than use alignUp, calculate the number of pages rounded down
	// first, then add back one if necessary.
	maxPages := max / pageSize
	if max%pageSize != 0 {
		maxPages++
	}

	// Calculate the minimum number of pages we can scavenge.
	//
	// Because we can only scavenge whole physical pages, we must
	// ensure that we scavenge at least minPages each time, aligned
	// to minPages*pageSize.
	minPages := physPageSize / pageSize
	if minPages < 1 {
		minPages = 1
	}

	lock(p.mheapLock)
	if p.summary[len(p.summary)-1][ci].max() >= uint(minPages) {
		// We only bother looking for a candidate if there at least
		// minPages free pages at all.
		base, npages := p.chunkOf(ci).findScavengeCandidate(searchIdx, minPages, maxPages)

		// If we found something, scavenge it and return!
		if npages != 0 {
			// Compute the full address for the start of the range.
			addr := chunkBase(ci) + uintptr(base)*pageSize

			// Mark the range we're about to scavenge as allocated, because
			// we don't want any allocating goroutines to grab it while
			// the scavenging is in progress. Be careful here -- just do the
			// bare minimum to avoid stepping on our own scavenging stats.
			p.chunkOf(ci).allocRange(base, npages)
			p.update(addr, uintptr(npages), true, true)

			// With that done, it's safe to unlock.
			unlock(p.mheapLock)

			if !p.test {
				// Only perform sys* operations if we're not in a test.
				// It's dangerous to do so otherwise.
				sysUnused(unsafe.Pointer(addr), uintptr(npages)*pageSize)

				// Update global accounting only when not in test, otherwise
				// the runtime's accounting will be wrong.
				nbytes := int64(npages * pageSize)
				gcController.heapReleased.add(nbytes)
				gcController.heapFree.add(-nbytes)

				stats := memstats.heapStats.acquire()
				atomic.Xaddint64(&stats.committed, -nbytes)
				atomic.Xaddint64(&stats.released, nbytes)
				memstats.heapStats.release()
			}

			// Relock the heap, because now we need to make these pages
			// available allocation. Free them back to the page allocator.
			lock(p.mheapLock)
			if b := (offAddr{addr}); b.lessThan(p.searchAddr) {
				p.searchAddr = b
			}
			p.chunkOf(ci).free(base, npages)
			p.update(addr, uintptr(npages), true, false)

			// Mark the range as scavenged.
			p.chunkOf(ci).scavenged.setRange(base, npages)
			unlock(p.mheapLock)

			return uintptr(npages) * pageSize
		}
	}
	// Mark this chunk as having no free pages.
	p.scav.index.setEmpty(ci)
	unlock(p.mheapLock)

	return 0
}

// fillAligned returns x but with all zeroes in m-aligned
// groups of m bits set to 1 if any bit in the group is non-zero.
//
// For example, fillAligned(0x0100a3, 8) == 0xff00ff.
//
// Note that if m == 1, this is a no-op.
//
// m must be a power of 2 <= maxPagesPerPhysPage.
func fillAligned(x uint64, m uint) uint64 {
	apply := func(x uint64, c uint64) uint64 {
		// The technique used it here is derived from
		// https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
		// and extended for more than just bytes (like nibbles
		// and uint16s) by using an appropriate constant.
		//
		// To summarize the technique, quoting from that page:
		// "[It] works by first zeroing the high bits of the [8]
		// bytes in the word. Subsequently, it adds a number that
		// will result in an overflow to the high bit of a byte if
		// any of the low bits were initially set. Next the high
		// bits of the original word are ORed with these values;
		// thus, the high bit of a byte is set iff any bit in the
		// byte was set. Finally, we determine if any of these high
		// bits are zero by ORing with ones everywhere except the
		// high bits and inverting the result."
		return ^((((x & c) + c) | x) | c)
	}
	// Transform x to contain a 1 bit at the top of each m-aligned
	// group of m zero bits.
	switch m {
	case 1:
		return x
	case 2:
		x = apply(x, 0x5555555555555555)
	case 4:
		x = apply(x, 0x7777777777777777)
	case 8:
		x = apply(x, 0x7f7f7f7f7f7f7f7f)
	case 16:
		x = apply(x, 0x7fff7fff7fff7fff)
	case 32:
		x = apply(x, 0x7fffffff7fffffff)
	case 64: // == maxPagesPerPhysPage
		x = appl
"""




```