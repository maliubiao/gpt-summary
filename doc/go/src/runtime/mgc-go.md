Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to analyze the provided Go code snippet (a portion of `mgc.go`) and identify its functionalities. The prompt also requests examples, explanations of specific features like command-line arguments, and potential pitfalls for users. It's crucial to remember this is just *part* of the file.

2. **Initial Skim and Keyword Spotting:** I'd quickly read through the comments and code, looking for keywords and phrases that indicate the purpose of different sections. Terms like "Garbage collector," "mark," "sweep," "write barrier," "allocation," "STW," "concurrent," etc., immediately jump out and provide a high-level understanding.

3. **Break Down by Section:** The comments are very helpful in structuring the code's functionality. I'd mentally (or literally) divide the code based on these comment sections:
    * Overall GC description
    * Mark phase details
    * Mark termination
    * Sweep phase details
    * GC rate
    * Oblets (large object handling)
    * Package declaration and imports
    * Constants and global variables
    * `gcinit`, `gcenable` functions
    * `writeBarrier` and `gcphase`
    * `gcMarkWorkerMode`
    * `workType` structure
    * `GC()` function
    * `gcWaitOnMark`
    * `gcMode` and `gcTrigger`
    * `gcStart`
    * `gcMarkDone`

4. **Focus on Key Concepts:** Within each section, I'd identify the core concepts and mechanisms being implemented. For example:
    * **Mark Phase:** Root marking, work queue, grey objects, blackening.
    * **Sweep Phase:** Concurrent, lazy, background sweeper.
    * **Write Barrier:**  Its purpose (maintaining the no-white-to-black invariant) and when it's enabled/disabled.
    * **STW (Stop-The-World):** When and why it happens.
    * **Concurrency:** How the GC runs concurrently with the mutator.
    * **`workType`:** The structure that manages GC work.

5. **Infer Functionality from Code:** Even though the comments are detailed, I'd still look at the code itself to confirm and understand the implementation details. For example:
    * `atomic.Store` and `atomic.Load`: Indicate concurrent access and updates to shared variables.
    * `lock` and `unlock`: Signal the use of mutexes for protecting critical sections.
    * Function names like `gcinit`, `gcenable`, `gcStart`, `gcMarkDone`: Clearly suggest their roles.

6. **Address Specific Prompt Points:**  As I go through the code, I'd specifically look for information related to:
    * **Go Language Features:** The GC itself is a fundamental Go language feature.
    * **Code Examples:**  I'd think about how to illustrate the concepts (like calling `runtime.GC()`). Since this is an internal runtime file, direct manipulation isn't typically done by users.
    * **Assumed Input/Output:** For the examples, I'd define a simple scenario that triggers the GC.
    * **Command-Line Arguments:** The prompt mentions this. I see references to `readGOGC()` and `readGOMEMLIMIT()`, indicating environment variable usage, which is a form of command-line configuration.
    * **User Errors:** Based on my understanding of the GC process, I'd identify potential misunderstandings or misuses (like incorrectly assuming immediate memory release after `runtime.GC()`).

7. **Synthesize and Organize:** Finally, I'd organize my findings into a clear and structured answer, addressing each part of the prompt:
    * List the functionalities concisely.
    * Provide a well-explained code example.
    * Detail the command-line parameter handling.
    * Highlight potential user errors.
    * Provide a summary.

8. **Refine and Review:** I'd reread my answer to ensure accuracy, clarity, and completeness, comparing it against the original code and the prompt's requirements. I'd check for any ambiguity or missing information.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Focus heavily on low-level details of the algorithms.
* **Correction:**  Shift focus to the *functionality* as requested, while still explaining the underlying mechanisms. The prompt asks "what it *does*," not just "how it does it."
* **Initial Thought:** Provide very complex code examples involving direct memory manipulation.
* **Correction:**  Recognize that this is a runtime file, and user interaction is primarily through `runtime.GC()`. Keep the example simple and relevant to a user's perspective.
* **Initial Thought:** Overlook the command-line parameter aspect.
* **Correction:** Notice the `readGOGC` and `readGOMEMLIMIT` functions and connect them to the prompt's requirement.
* **Initial Thought:** Assume users directly interact with the internal GC structures.
* **Correction:** Focus on common user-level misunderstandings about GC behavior.

By following these steps, including the self-correction aspect, I arrive at a comprehensive and accurate answer that addresses all parts of the user's request. The emphasis is on understanding the code's purpose and presenting it in a way that is informative and helpful to someone trying to understand the Go garbage collector.
这段代码是Go语言运行时（runtime）中负责垃圾回收（Garbage Collection，GC）的核心部分，文件路径是 `go/src/runtime/mgc.go`。 它是整个GC实现中至关重要的一部分，涵盖了GC的多个关键阶段和机制。

**这段代码的主要功能归纳如下：**

1. **定义了Go语言的垃圾回收器（GC）的主要结构和算法。**  它描述了并发标记清除算法的各个步骤，包括停止世界（STW）、标记、标记终止和清除阶段。
2. **实现了垃圾回收的各个阶段的控制逻辑。** 代码中包含了控制GC状态转换、启动和停止GC、协调不同goroutine参与GC工作的机制。
3. **管理了GC的工作队列和辅助机制。**  例如，`workType` 结构体用于管理标记阶段的工作缓冲区和任务。
4. **定义了与GC相关的配置和参数。**  例如，`GOGC` 环境变量的读取和使用，以及触发GC的条件。
5. **实现了并发扫描和清除的机制。**  描述了如何在后台并发地回收未使用的内存空间。
6. **处理了与写屏障（Write Barrier）相关的逻辑。**  控制写屏障的启用和禁用，确保在并发标记阶段的对象状态一致性。
7. **提供了用户触发GC的接口。**  `GC()` 函数允许用户显式地调用垃圾回收。

**如果你能推理出它是什么go语言功能的实现，请用go代码举例说明:**

这段代码实现了 Go 语言的 **垃圾回收 (Garbage Collection)** 功能。Go 语言的 GC 负责自动回收程序中不再使用的内存，避免内存泄漏，让开发者可以专注于业务逻辑。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	fmt.Println("开始分配大量内存...")
	var data []*int
	for i := 0; i < 1000000; i++ {
		// 分配一个整数并将其指针添加到切片中
		num := new(int)
		*num = i
		data = append(data, num)
	}
	fmt.Println("内存分配完成，切片长度:", len(data))

	// 显式触发垃圾回收
	fmt.Println("显式触发垃圾回收...")
	runtime.GC()
	fmt.Println("垃圾回收完成")

	// 模拟一段时间后，某些对象不再被引用
	fmt.Println("等待一段时间...")
	time.Sleep(5 * time.Second)

	// 再次触发垃圾回收，回收不再使用的内存
	fmt.Println("再次显式触发垃圾回收...")
	runtime.GC()
	fmt.Println("垃圾回收完成")

	// 可以通过 runtime.MemStats 查看内存使用情况
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("堆上已分配内存: %v MiB\n", m.HeapAlloc/1024/1024)
	fmt.Printf("系统已分配内存: %v MiB\n", m.Sys/1024/1024)
}
```

**假设的输入与输出:**

在这个例子中，没有直接的用户输入。

**输出 (大致):**

```
开始分配大量内存...
内存分配完成，切片长度: 1000000
显式触发垃圾回收...
垃圾回收完成
等待一段时间...
再次显式触发垃圾回收...
垃圾回收完成
堆上已分配内存: 若干 MiB (第二次GC后可能会降低)
系统已分配内存: 若干 MiB
```

**代码推理:**

1. **内存分配:**  `for` 循环分配了大量的整数，并将它们的指针存储在 `data` 切片中。 这会增加程序的内存使用量，从而为 GC 创造了工作的机会。
2. **显式触发 GC:**  `runtime.GC()` 函数会强制 Go 运行时执行一次垃圾回收。
3. **等待:**  `time.Sleep()` 模拟了一段时间，在这段时间内，之前分配的一些 `int` 可能不再被程序引用 (尽管在这个例子中，`data` 切片仍然持有所有指针，所以不会立即回收)。
4. **再次触发 GC:** 再次调用 `runtime.GC()`，Go 的 GC 会回收那些不再被引用的内存。
5. **查看内存统计:** `runtime.ReadMemStats()` 可以获取当前的内存使用情况，可以观察到垃圾回收前后堆内存的变化。

**如果涉及命令行参数的具体处理，请详细介绍一下:**

这段代码本身并没有直接处理命令行参数。 然而，它提到了 `GOGC` 环境变量。

**`GOGC` 环境变量:**

* **作用:** `GOGC` 是一个环境变量，用于设置垃圾回收的目标百分比。它控制着 GC 的触发频率。
* **默认值:** 默认值为 100。
* **含义:** 当 `GOGC=100` 时，表示当堆内存使用量达到上一次 GC 后存活对象大小的两倍时，会触发下一次 GC。例如，如果上次 GC 后存活对象大小为 4MB，则当堆内存使用量达到 8MB 时会触发 GC。
* **负值:** 如果将 `GOGC` 设置为负值，则会禁用垃圾回收（通常不建议这样做）。
* **如何使用:**  在运行 Go 程序之前设置环境变量。例如：
    * **Linux/macOS:** `GOGC=50 go run your_program.go`
    * **Windows:** `set GOGC=50 & go run your_program.go`

**这段代码中 `gcController.init(readGOGC(), readGOMEMLIMIT())`  部分负责读取 `GOGC` 和 `GOMEMLIMIT` 环境变量的值，并初始化 GC 控制器的状态。** `readGOGC()` 和 `readGOMEMLIMIT()` 函数（未在此代码段中显示）会读取这些环境变量。

**`GOMEMLIMIT` 环境变量:**

* **作用:** `GOMEMLIMIT` 是一个环境变量，用于设置 Go 程序可以使用的最大内存量。这是一种限制内存使用的机制，可以防止程序无限增长的内存占用。
* **单位:**  可以指定字节数，或者使用单位后缀 (例如 "2GiB", "100MiB")。
* **与 GC 的关系:**  `GOMEMLIMIT` 会影响 GC 的触发时机。 当内存使用接近 `GOMEMLIMIT` 时，GC 会更加积极地运行以避免超出限制。

**如果有哪些使用者易犯错的点，请举例说明，没有则不必说明:**

1. **误以为 `runtime.GC()` 会立即释放所有不再使用的内存。** Go 的 GC 是并发的，调用 `runtime.GC()` 只是触发一次 GC 周期，实际的内存回收可能发生在稍后的时间。  依赖 `runtime.GC()` 进行精确的内存管理通常是错误的。
2. **过度依赖 `runtime.GC()` 进行性能优化。**  频繁地手动调用 `runtime.GC()` 可能会导致程序暂停，影响性能。Go 的 GC 设计为自动运行，大多数情况下不需要手动干预。
3. **不理解 `GOGC` 的作用，随意修改其值。**  不合理的 `GOGC` 值可能会导致 GC 过于频繁（影响性能）或过于稀疏（导致内存占用过高）。
4. **忽略 `GOMEMLIMIT` 的作用，导致程序占用过多资源。**  在高并发或者资源受限的环境中，设置合适的 `GOMEMLIMIT` 可以防止程序占用过多内存导致系统崩溃或其他问题。
5. **混淆 `runtime.GC()` 和 `debug.FreeOSMemory()`。**  `runtime.GC()` 触发垃圾回收，回收 Go 堆上的内存。 `debug.FreeOSMemory()` 尝试将 Go 运行时持有的、但当前未使用的内存归还给操作系统。 两者功能不同，不要混淆使用。

**总结一下它的功能 (针对提供的代码片段):**

这段 `mgc.go` 的代码片段是 Go 语言运行时垃圾回收实现的核心组成部分。 它定义了 GC 的基本结构、状态、关键阶段（标记和清除），以及相关的控制逻辑和数据结构（如 `workType`）。 它还处理了与写屏障、GC 触发条件（包括对 `GOGC` 环境变量的读取）以及用户显式触发 GC 的接口 (`GC()` 函数) 相关的逻辑。  总而言之，它是 Go 语言自动内存管理机制的基石。

### 提示词
```
这是路径为go/src/runtime/mgc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Garbage collector (GC).
//
// The GC runs concurrently with mutator threads, is type accurate (aka precise), allows multiple
// GC thread to run in parallel. It is a concurrent mark and sweep that uses a write barrier. It is
// non-generational and non-compacting. Allocation is done using size segregated per P allocation
// areas to minimize fragmentation while eliminating locks in the common case.
//
// The algorithm decomposes into several steps.
// This is a high level description of the algorithm being used. For an overview of GC a good
// place to start is Richard Jones' gchandbook.org.
//
// The algorithm's intellectual heritage includes Dijkstra's on-the-fly algorithm, see
// Edsger W. Dijkstra, Leslie Lamport, A. J. Martin, C. S. Scholten, and E. F. M. Steffens. 1978.
// On-the-fly garbage collection: an exercise in cooperation. Commun. ACM 21, 11 (November 1978),
// 966-975.
// For journal quality proofs that these steps are complete, correct, and terminate see
// Hudson, R., and Moss, J.E.B. Copying Garbage Collection without stopping the world.
// Concurrency and Computation: Practice and Experience 15(3-5), 2003.
//
// 1. GC performs sweep termination.
//
//    a. Stop the world. This causes all Ps to reach a GC safe-point.
//
//    b. Sweep any unswept spans. There will only be unswept spans if
//    this GC cycle was forced before the expected time.
//
// 2. GC performs the mark phase.
//
//    a. Prepare for the mark phase by setting gcphase to _GCmark
//    (from _GCoff), enabling the write barrier, enabling mutator
//    assists, and enqueueing root mark jobs. No objects may be
//    scanned until all Ps have enabled the write barrier, which is
//    accomplished using STW.
//
//    b. Start the world. From this point, GC work is done by mark
//    workers started by the scheduler and by assists performed as
//    part of allocation. The write barrier shades both the
//    overwritten pointer and the new pointer value for any pointer
//    writes (see mbarrier.go for details). Newly allocated objects
//    are immediately marked black.
//
//    c. GC performs root marking jobs. This includes scanning all
//    stacks, shading all globals, and shading any heap pointers in
//    off-heap runtime data structures. Scanning a stack stops a
//    goroutine, shades any pointers found on its stack, and then
//    resumes the goroutine.
//
//    d. GC drains the work queue of grey objects, scanning each grey
//    object to black and shading all pointers found in the object
//    (which in turn may add those pointers to the work queue).
//
//    e. Because GC work is spread across local caches, GC uses a
//    distributed termination algorithm to detect when there are no
//    more root marking jobs or grey objects (see gcMarkDone). At this
//    point, GC transitions to mark termination.
//
// 3. GC performs mark termination.
//
//    a. Stop the world.
//
//    b. Set gcphase to _GCmarktermination, and disable workers and
//    assists.
//
//    c. Perform housekeeping like flushing mcaches.
//
// 4. GC performs the sweep phase.
//
//    a. Prepare for the sweep phase by setting gcphase to _GCoff,
//    setting up sweep state and disabling the write barrier.
//
//    b. Start the world. From this point on, newly allocated objects
//    are white, and allocating sweeps spans before use if necessary.
//
//    c. GC does concurrent sweeping in the background and in response
//    to allocation. See description below.
//
// 5. When sufficient allocation has taken place, replay the sequence
// starting with 1 above. See discussion of GC rate below.

// Concurrent sweep.
//
// The sweep phase proceeds concurrently with normal program execution.
// The heap is swept span-by-span both lazily (when a goroutine needs another span)
// and concurrently in a background goroutine (this helps programs that are not CPU bound).
// At the end of STW mark termination all spans are marked as "needs sweeping".
//
// The background sweeper goroutine simply sweeps spans one-by-one.
//
// To avoid requesting more OS memory while there are unswept spans, when a
// goroutine needs another span, it first attempts to reclaim that much memory
// by sweeping. When a goroutine needs to allocate a new small-object span, it
// sweeps small-object spans for the same object size until it frees at least
// one object. When a goroutine needs to allocate large-object span from heap,
// it sweeps spans until it frees at least that many pages into heap. There is
// one case where this may not suffice: if a goroutine sweeps and frees two
// nonadjacent one-page spans to the heap, it will allocate a new two-page
// span, but there can still be other one-page unswept spans which could be
// combined into a two-page span.
//
// It's critical to ensure that no operations proceed on unswept spans (that would corrupt
// mark bits in GC bitmap). During GC all mcaches are flushed into the central cache,
// so they are empty. When a goroutine grabs a new span into mcache, it sweeps it.
// When a goroutine explicitly frees an object or sets a finalizer, it ensures that
// the span is swept (either by sweeping it, or by waiting for the concurrent sweep to finish).
// The finalizer goroutine is kicked off only when all spans are swept.
// When the next GC starts, it sweeps all not-yet-swept spans (if any).

// GC rate.
// Next GC is after we've allocated an extra amount of memory proportional to
// the amount already in use. The proportion is controlled by GOGC environment variable
// (100 by default). If GOGC=100 and we're using 4M, we'll GC again when we get to 8M
// (this mark is computed by the gcController.heapGoal method). This keeps the GC cost in
// linear proportion to the allocation cost. Adjusting GOGC just changes the linear constant
// (and also the amount of extra memory used).

// Oblets
//
// In order to prevent long pauses while scanning large objects and to
// improve parallelism, the garbage collector breaks up scan jobs for
// objects larger than maxObletBytes into "oblets" of at most
// maxObletBytes. When scanning encounters the beginning of a large
// object, it scans only the first oblet and enqueues the remaining
// oblets as new scan jobs.

package runtime

import (
	"internal/cpu"
	"internal/runtime/atomic"
	"unsafe"
)

const (
	_DebugGC      = 0
	_FinBlockSize = 4 * 1024

	// concurrentSweep is a debug flag. Disabling this flag
	// ensures all spans are swept while the world is stopped.
	concurrentSweep = true

	// debugScanConservative enables debug logging for stack
	// frames that are scanned conservatively.
	debugScanConservative = false

	// sweepMinHeapDistance is a lower bound on the heap distance
	// (in bytes) reserved for concurrent sweeping between GC
	// cycles.
	sweepMinHeapDistance = 1024 * 1024
)

// heapObjectsCanMove always returns false in the current garbage collector.
// It exists for go4.org/unsafe/assume-no-moving-gc, which is an
// unfortunate idea that had an even more unfortunate implementation.
// Every time a new Go release happened, the package stopped building,
// and the authors had to add a new file with a new //go:build line, and
// then the entire ecosystem of packages with that as a dependency had to
// explicitly update to the new version. Many packages depend on
// assume-no-moving-gc transitively, through paths like
// inet.af/netaddr -> go4.org/intern -> assume-no-moving-gc.
// This was causing a significant amount of friction around each new
// release, so we added this bool for the package to //go:linkname
// instead. The bool is still unfortunate, but it's not as bad as
// breaking the ecosystem on every new release.
//
// If the Go garbage collector ever does move heap objects, we can set
// this to true to break all the programs using assume-no-moving-gc.
//
//go:linkname heapObjectsCanMove
func heapObjectsCanMove() bool {
	return false
}

func gcinit() {
	if unsafe.Sizeof(workbuf{}) != _WorkbufSize {
		throw("size of Workbuf is suboptimal")
	}
	// No sweep on the first cycle.
	sweep.active.state.Store(sweepDrainedMask)

	// Initialize GC pacer state.
	// Use the environment variable GOGC for the initial gcPercent value.
	// Use the environment variable GOMEMLIMIT for the initial memoryLimit value.
	gcController.init(readGOGC(), readGOMEMLIMIT())

	work.startSema = 1
	work.markDoneSema = 1
	lockInit(&work.sweepWaiters.lock, lockRankSweepWaiters)
	lockInit(&work.assistQueue.lock, lockRankAssistQueue)
	lockInit(&work.strongFromWeak.lock, lockRankStrongFromWeakQueue)
	lockInit(&work.wbufSpans.lock, lockRankWbufSpans)
}

// gcenable is called after the bulk of the runtime initialization,
// just before we're about to start letting user code run.
// It kicks off the background sweeper goroutine, the background
// scavenger goroutine, and enables GC.
func gcenable() {
	// Kick off sweeping and scavenging.
	c := make(chan int, 2)
	go bgsweep(c)
	go bgscavenge(c)
	<-c
	<-c
	memstats.enablegc = true // now that runtime is initialized, GC is okay
}

// Garbage collector phase.
// Indicates to write barrier and synchronization task to perform.
var gcphase uint32

// The compiler knows about this variable.
// If you change it, you must change builtin/runtime.go, too.
// If you change the first four bytes, you must also change the write
// barrier insertion code.
//
// writeBarrier should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname writeBarrier
var writeBarrier struct {
	enabled bool    // compiler emits a check of this before calling write barrier
	pad     [3]byte // compiler uses 32-bit load for "enabled" field
	alignme uint64  // guarantee alignment so that compiler can use a 32 or 64-bit load
}

// gcBlackenEnabled is 1 if mutator assists and background mark
// workers are allowed to blacken objects. This must only be set when
// gcphase == _GCmark.
var gcBlackenEnabled uint32

const (
	_GCoff             = iota // GC not running; sweeping in background, write barrier disabled
	_GCmark                   // GC marking roots and workbufs: allocate black, write barrier ENABLED
	_GCmarktermination        // GC mark termination: allocate black, P's help GC, write barrier ENABLED
)

//go:nosplit
func setGCPhase(x uint32) {
	atomic.Store(&gcphase, x)
	writeBarrier.enabled = gcphase == _GCmark || gcphase == _GCmarktermination
}

// gcMarkWorkerMode represents the mode that a concurrent mark worker
// should operate in.
//
// Concurrent marking happens through four different mechanisms. One
// is mutator assists, which happen in response to allocations and are
// not scheduled. The other three are variations in the per-P mark
// workers and are distinguished by gcMarkWorkerMode.
type gcMarkWorkerMode int

const (
	// gcMarkWorkerNotWorker indicates that the next scheduled G is not
	// starting work and the mode should be ignored.
	gcMarkWorkerNotWorker gcMarkWorkerMode = iota

	// gcMarkWorkerDedicatedMode indicates that the P of a mark
	// worker is dedicated to running that mark worker. The mark
	// worker should run without preemption.
	gcMarkWorkerDedicatedMode

	// gcMarkWorkerFractionalMode indicates that a P is currently
	// running the "fractional" mark worker. The fractional worker
	// is necessary when GOMAXPROCS*gcBackgroundUtilization is not
	// an integer and using only dedicated workers would result in
	// utilization too far from the target of gcBackgroundUtilization.
	// The fractional worker should run until it is preempted and
	// will be scheduled to pick up the fractional part of
	// GOMAXPROCS*gcBackgroundUtilization.
	gcMarkWorkerFractionalMode

	// gcMarkWorkerIdleMode indicates that a P is running the mark
	// worker because it has nothing else to do. The idle worker
	// should run until it is preempted and account its time
	// against gcController.idleMarkTime.
	gcMarkWorkerIdleMode
)

// gcMarkWorkerModeStrings are the strings labels of gcMarkWorkerModes
// to use in execution traces.
var gcMarkWorkerModeStrings = [...]string{
	"Not worker",
	"GC (dedicated)",
	"GC (fractional)",
	"GC (idle)",
}

// pollFractionalWorkerExit reports whether a fractional mark worker
// should self-preempt. It assumes it is called from the fractional
// worker.
func pollFractionalWorkerExit() bool {
	// This should be kept in sync with the fractional worker
	// scheduler logic in findRunnableGCWorker.
	now := nanotime()
	delta := now - gcController.markStartTime
	if delta <= 0 {
		return true
	}
	p := getg().m.p.ptr()
	selfTime := p.gcFractionalMarkTime + (now - p.gcMarkWorkerStartTime)
	// Add some slack to the utilization goal so that the
	// fractional worker isn't behind again the instant it exits.
	return float64(selfTime)/float64(delta) > 1.2*gcController.fractionalUtilizationGoal
}

var work workType

type workType struct {
	full  lfstack          // lock-free list of full blocks workbuf
	_     cpu.CacheLinePad // prevents false-sharing between full and empty
	empty lfstack          // lock-free list of empty blocks workbuf
	_     cpu.CacheLinePad // prevents false-sharing between empty and nproc/nwait

	wbufSpans struct {
		lock mutex
		// free is a list of spans dedicated to workbufs, but
		// that don't currently contain any workbufs.
		free mSpanList
		// busy is a list of all spans containing workbufs on
		// one of the workbuf lists.
		busy mSpanList
	}

	// Restore 64-bit alignment on 32-bit.
	_ uint32

	// bytesMarked is the number of bytes marked this cycle. This
	// includes bytes blackened in scanned objects, noscan objects
	// that go straight to black, objects allocated as black during
	// the cycle, and permagrey objects scanned by markroot during
	// the concurrent scan phase.
	//
	// This is updated atomically during the cycle. Updates may be batched
	// arbitrarily, since the value is only read at the end of the cycle.
	//
	// Because of benign races during marking, this number may not
	// be the exact number of marked bytes, but it should be very
	// close.
	//
	// Put this field here because it needs 64-bit atomic access
	// (and thus 8-byte alignment even on 32-bit architectures).
	bytesMarked uint64

	markrootNext uint32 // next markroot job
	markrootJobs uint32 // number of markroot jobs

	nproc  uint32
	tstart int64
	nwait  uint32

	// Number of roots of various root types. Set by gcMarkRootPrepare.
	//
	// nStackRoots == len(stackRoots), but we have nStackRoots for
	// consistency.
	nDataRoots, nBSSRoots, nSpanRoots, nStackRoots int

	// Base indexes of each root type. Set by gcMarkRootPrepare.
	baseData, baseBSS, baseSpans, baseStacks, baseEnd uint32

	// stackRoots is a snapshot of all of the Gs that existed
	// before the beginning of concurrent marking. The backing
	// store of this must not be modified because it might be
	// shared with allgs.
	stackRoots []*g

	// Each type of GC state transition is protected by a lock.
	// Since multiple threads can simultaneously detect the state
	// transition condition, any thread that detects a transition
	// condition must acquire the appropriate transition lock,
	// re-check the transition condition and return if it no
	// longer holds or perform the transition if it does.
	// Likewise, any transition must invalidate the transition
	// condition before releasing the lock. This ensures that each
	// transition is performed by exactly one thread and threads
	// that need the transition to happen block until it has
	// happened.
	//
	// startSema protects the transition from "off" to mark or
	// mark termination.
	startSema uint32
	// markDoneSema protects transitions from mark to mark termination.
	markDoneSema uint32

	bgMarkDone uint32 // cas to 1 when at a background mark completion point
	// Background mark completion signaling

	// mode is the concurrency mode of the current GC cycle.
	mode gcMode

	// userForced indicates the current GC cycle was forced by an
	// explicit user call.
	userForced bool

	// initialHeapLive is the value of gcController.heapLive at the
	// beginning of this GC cycle.
	initialHeapLive uint64

	// assistQueue is a queue of assists that are blocked because
	// there was neither enough credit to steal or enough work to
	// do.
	assistQueue struct {
		lock mutex
		q    gQueue
	}

	// sweepWaiters is a list of blocked goroutines to wake when
	// we transition from mark termination to sweep.
	sweepWaiters struct {
		lock mutex
		list gList
	}

	// strongFromWeak controls how the GC interacts with weak->strong
	// pointer conversions.
	strongFromWeak struct {
		// block is a flag set during mark termination that prevents
		// new weak->strong conversions from executing by blocking the
		// goroutine and enqueuing it onto q.
		//
		// Mutated only by one goroutine at a time in gcMarkDone,
		// with globally-synchronizing events like forEachP and
		// stopTheWorld.
		block bool

		// q is a queue of goroutines that attempted to perform a
		// weak->strong conversion during mark termination.
		//
		// Protected by lock.
		lock mutex
		q    gQueue
	}

	// cycles is the number of completed GC cycles, where a GC
	// cycle is sweep termination, mark, mark termination, and
	// sweep. This differs from memstats.numgc, which is
	// incremented at mark termination.
	cycles atomic.Uint32

	// Timing/utilization stats for this cycle.
	stwprocs, maxprocs                 int32
	tSweepTerm, tMark, tMarkTerm, tEnd int64 // nanotime() of phase start

	// pauseNS is the total STW time this cycle, measured as the time between
	// when stopping began (just before trying to stop Ps) and just after the
	// world started again.
	pauseNS int64

	// debug.gctrace heap sizes for this cycle.
	heap0, heap1, heap2 uint64

	// Cumulative estimated CPU usage.
	cpuStats
}

// GC runs a garbage collection and blocks the caller until the
// garbage collection is complete. It may also block the entire
// program.
func GC() {
	// We consider a cycle to be: sweep termination, mark, mark
	// termination, and sweep. This function shouldn't return
	// until a full cycle has been completed, from beginning to
	// end. Hence, we always want to finish up the current cycle
	// and start a new one. That means:
	//
	// 1. In sweep termination, mark, or mark termination of cycle
	// N, wait until mark termination N completes and transitions
	// to sweep N.
	//
	// 2. In sweep N, help with sweep N.
	//
	// At this point we can begin a full cycle N+1.
	//
	// 3. Trigger cycle N+1 by starting sweep termination N+1.
	//
	// 4. Wait for mark termination N+1 to complete.
	//
	// 5. Help with sweep N+1 until it's done.
	//
	// This all has to be written to deal with the fact that the
	// GC may move ahead on its own. For example, when we block
	// until mark termination N, we may wake up in cycle N+2.

	// Wait until the current sweep termination, mark, and mark
	// termination complete.
	n := work.cycles.Load()
	gcWaitOnMark(n)

	// We're now in sweep N or later. Trigger GC cycle N+1, which
	// will first finish sweep N if necessary and then enter sweep
	// termination N+1.
	gcStart(gcTrigger{kind: gcTriggerCycle, n: n + 1})

	// Wait for mark termination N+1 to complete.
	gcWaitOnMark(n + 1)

	// Finish sweep N+1 before returning. We do this both to
	// complete the cycle and because runtime.GC() is often used
	// as part of tests and benchmarks to get the system into a
	// relatively stable and isolated state.
	for work.cycles.Load() == n+1 && sweepone() != ^uintptr(0) {
		Gosched()
	}

	// Callers may assume that the heap profile reflects the
	// just-completed cycle when this returns (historically this
	// happened because this was a STW GC), but right now the
	// profile still reflects mark termination N, not N+1.
	//
	// As soon as all of the sweep frees from cycle N+1 are done,
	// we can go ahead and publish the heap profile.
	//
	// First, wait for sweeping to finish. (We know there are no
	// more spans on the sweep queue, but we may be concurrently
	// sweeping spans, so we have to wait.)
	for work.cycles.Load() == n+1 && !isSweepDone() {
		Gosched()
	}

	// Now we're really done with sweeping, so we can publish the
	// stable heap profile. Only do this if we haven't already hit
	// another mark termination.
	mp := acquirem()
	cycle := work.cycles.Load()
	if cycle == n+1 || (gcphase == _GCmark && cycle == n+2) {
		mProf_PostSweep()
	}
	releasem(mp)
}

// gcWaitOnMark blocks until GC finishes the Nth mark phase. If GC has
// already completed this mark phase, it returns immediately.
func gcWaitOnMark(n uint32) {
	for {
		// Disable phase transitions.
		lock(&work.sweepWaiters.lock)
		nMarks := work.cycles.Load()
		if gcphase != _GCmark {
			// We've already completed this cycle's mark.
			nMarks++
		}
		if nMarks > n {
			// We're done.
			unlock(&work.sweepWaiters.lock)
			return
		}

		// Wait until sweep termination, mark, and mark
		// termination of cycle N complete.
		work.sweepWaiters.list.push(getg())
		goparkunlock(&work.sweepWaiters.lock, waitReasonWaitForGCCycle, traceBlockUntilGCEnds, 1)
	}
}

// gcMode indicates how concurrent a GC cycle should be.
type gcMode int

const (
	gcBackgroundMode gcMode = iota // concurrent GC and sweep
	gcForceMode                    // stop-the-world GC now, concurrent sweep
	gcForceBlockMode               // stop-the-world GC now and STW sweep (forced by user)
)

// A gcTrigger is a predicate for starting a GC cycle. Specifically,
// it is an exit condition for the _GCoff phase.
type gcTrigger struct {
	kind gcTriggerKind
	now  int64  // gcTriggerTime: current time
	n    uint32 // gcTriggerCycle: cycle number to start
}

type gcTriggerKind int

const (
	// gcTriggerHeap indicates that a cycle should be started when
	// the heap size reaches the trigger heap size computed by the
	// controller.
	gcTriggerHeap gcTriggerKind = iota

	// gcTriggerTime indicates that a cycle should be started when
	// it's been more than forcegcperiod nanoseconds since the
	// previous GC cycle.
	gcTriggerTime

	// gcTriggerCycle indicates that a cycle should be started if
	// we have not yet started cycle number gcTrigger.n (relative
	// to work.cycles).
	gcTriggerCycle
)

// test reports whether the trigger condition is satisfied, meaning
// that the exit condition for the _GCoff phase has been met. The exit
// condition should be tested when allocating.
func (t gcTrigger) test() bool {
	if !memstats.enablegc || panicking.Load() != 0 || gcphase != _GCoff {
		return false
	}
	switch t.kind {
	case gcTriggerHeap:
		trigger, _ := gcController.trigger()
		return gcController.heapLive.Load() >= trigger
	case gcTriggerTime:
		if gcController.gcPercent.Load() < 0 {
			return false
		}
		lastgc := int64(atomic.Load64(&memstats.last_gc_nanotime))
		return lastgc != 0 && t.now-lastgc > forcegcperiod
	case gcTriggerCycle:
		// t.n > work.cycles, but accounting for wraparound.
		return int32(t.n-work.cycles.Load()) > 0
	}
	return true
}

// gcStart starts the GC. It transitions from _GCoff to _GCmark (if
// debug.gcstoptheworld == 0) or performs all of GC (if
// debug.gcstoptheworld != 0).
//
// This may return without performing this transition in some cases,
// such as when called on a system stack or with locks held.
func gcStart(trigger gcTrigger) {
	// Since this is called from malloc and malloc is called in
	// the guts of a number of libraries that might be holding
	// locks, don't attempt to start GC in non-preemptible or
	// potentially unstable situations.
	mp := acquirem()
	if gp := getg(); gp == mp.g0 || mp.locks > 1 || mp.preemptoff != "" {
		releasem(mp)
		return
	}
	releasem(mp)
	mp = nil

	if gp := getg(); gp.syncGroup != nil {
		// Disassociate the G from its synctest bubble while allocating.
		// This is less elegant than incrementing the group's active count,
		// but avoids any contamination between GC and synctest.
		sg := gp.syncGroup
		gp.syncGroup = nil
		defer func() {
			gp.syncGroup = sg
		}()
	}

	// Pick up the remaining unswept/not being swept spans concurrently
	//
	// This shouldn't happen if we're being invoked in background
	// mode since proportional sweep should have just finished
	// sweeping everything, but rounding errors, etc, may leave a
	// few spans unswept. In forced mode, this is necessary since
	// GC can be forced at any point in the sweeping cycle.
	//
	// We check the transition condition continuously here in case
	// this G gets delayed in to the next GC cycle.
	for trigger.test() && sweepone() != ^uintptr(0) {
	}

	// Perform GC initialization and the sweep termination
	// transition.
	semacquire(&work.startSema)
	// Re-check transition condition under transition lock.
	if !trigger.test() {
		semrelease(&work.startSema)
		return
	}

	// In gcstoptheworld debug mode, upgrade the mode accordingly.
	// We do this after re-checking the transition condition so
	// that multiple goroutines that detect the heap trigger don't
	// start multiple STW GCs.
	mode := gcBackgroundMode
	if debug.gcstoptheworld == 1 {
		mode = gcForceMode
	} else if debug.gcstoptheworld == 2 {
		mode = gcForceBlockMode
	}

	// Ok, we're doing it! Stop everybody else
	semacquire(&gcsema)
	semacquire(&worldsema)

	// For stats, check if this GC was forced by the user.
	// Update it under gcsema to avoid gctrace getting wrong values.
	work.userForced = trigger.kind == gcTriggerCycle

	trace := traceAcquire()
	if trace.ok() {
		trace.GCStart()
		traceRelease(trace)
	}

	// Check that all Ps have finished deferred mcache flushes.
	for _, p := range allp {
		if fg := p.mcache.flushGen.Load(); fg != mheap_.sweepgen {
			println("runtime: p", p.id, "flushGen", fg, "!= sweepgen", mheap_.sweepgen)
			throw("p mcache not flushed")
		}
	}

	gcBgMarkStartWorkers()

	systemstack(gcResetMarkState)

	work.stwprocs, work.maxprocs = gomaxprocs, gomaxprocs
	if work.stwprocs > ncpu {
		// This is used to compute CPU time of the STW phases,
		// so it can't be more than ncpu, even if GOMAXPROCS is.
		work.stwprocs = ncpu
	}
	work.heap0 = gcController.heapLive.Load()
	work.pauseNS = 0
	work.mode = mode

	now := nanotime()
	work.tSweepTerm = now
	var stw worldStop
	systemstack(func() {
		stw = stopTheWorldWithSema(stwGCSweepTerm)
	})

	// Accumulate fine-grained stopping time.
	work.cpuStats.accumulateGCPauseTime(stw.stoppingCPUTime, 1)

	// Finish sweep before we start concurrent scan.
	systemstack(func() {
		finishsweep_m()
	})

	// clearpools before we start the GC. If we wait the memory will not be
	// reclaimed until the next GC cycle.
	clearpools()

	work.cycles.Add(1)

	// Assists and workers can start the moment we start
	// the world.
	gcController.startCycle(now, int(gomaxprocs), trigger)

	// Notify the CPU limiter that assists may begin.
	gcCPULimiter.startGCTransition(true, now)

	// In STW mode, disable scheduling of user Gs. This may also
	// disable scheduling of this goroutine, so it may block as
	// soon as we start the world again.
	if mode != gcBackgroundMode {
		schedEnableUser(false)
	}

	// Enter concurrent mark phase and enable
	// write barriers.
	//
	// Because the world is stopped, all Ps will
	// observe that write barriers are enabled by
	// the time we start the world and begin
	// scanning.
	//
	// Write barriers must be enabled before assists are
	// enabled because they must be enabled before
	// any non-leaf heap objects are marked. Since
	// allocations are blocked until assists can
	// happen, we want to enable assists as early as
	// possible.
	setGCPhase(_GCmark)

	gcBgMarkPrepare() // Must happen before assists are enabled.
	gcMarkRootPrepare()

	// Mark all active tinyalloc blocks. Since we're
	// allocating from these, they need to be black like
	// other allocations. The alternative is to blacken
	// the tiny block on every allocation from it, which
	// would slow down the tiny allocator.
	gcMarkTinyAllocs()

	// At this point all Ps have enabled the write
	// barrier, thus maintaining the no white to
	// black invariant. Enable mutator assists to
	// put back-pressure on fast allocating
	// mutators.
	atomic.Store(&gcBlackenEnabled, 1)

	// In STW mode, we could block the instant systemstack
	// returns, so make sure we're not preemptible.
	mp = acquirem()

	// Update the CPU stats pause time.
	//
	// Use maxprocs instead of stwprocs here because the total time
	// computed in the CPU stats is based on maxprocs, and we want them
	// to be comparable.
	work.cpuStats.accumulateGCPauseTime(nanotime()-stw.finishedStopping, work.maxprocs)

	// Concurrent mark.
	systemstack(func() {
		now = startTheWorldWithSema(0, stw)
		work.pauseNS += now - stw.startedStopping
		work.tMark = now

		// Release the CPU limiter.
		gcCPULimiter.finishGCTransition(now)
	})

	// Release the world sema before Gosched() in STW mode
	// because we will need to reacquire it later but before
	// this goroutine becomes runnable again, and we could
	// self-deadlock otherwise.
	semrelease(&worldsema)
	releasem(mp)

	// Make sure we block instead of returning to user code
	// in STW mode.
	if mode != gcBackgroundMode {
		Gosched()
	}

	semrelease(&work.startSema)
}

// gcMarkDoneFlushed counts the number of P's with flushed work.
//
// Ideally this would be a captured local in gcMarkDone, but forEachP
// escapes its callback closure, so it can't capture anything.
//
// This is protected by markDoneSema.
var gcMarkDoneFlushed uint32

// gcDebugMarkDone contains fields used to debug/test mark termination.
var gcDebugMarkDone struct {
	// spinAfterRaggedBarrier forces gcMarkDone to spin after it executes
	// the ragged barrier.
	spinAfterRaggedBarrier atomic.Bool

	// restartedDueTo27993 indicates that we restarted mark termination
	// due to the bug described in issue #27993.
	//
	// Protected by worldsema.
	restartedDueTo27993 bool
}

// gcMarkDone transitions the GC from mark to mark termination if all
// reachable objects have been marked (that is, there are no grey
// objects and can be no more in the future). Otherwise, it flushes
// all local work to the global queues where it can be discovered by
// other workers.
//
// This should be called when all local mark work has been drained and
// there are no remaining workers. Specifically, when
//
//	work.nwait == work.nproc && !gcMarkWorkAvailable(p)
//
// The calling context must be preemptible.
//
// Flushing local work is important because idle Ps may have local
// work queued. This is the only way to make that work visible and
// drive GC to completion.
//
// It is explicitly okay to have write barriers in this function. If
// it does transition to mark termination, then all reachable objects
// have been marked, so the write barrier cannot shade any more
// objects.
func gcMarkDone() {
	// Ensure only one thread is running the ragged barrier at a
	// time.
	semacquire(&work.markDoneSema)

top:
	// Re-check transition condition under transition lock.
	//
	// It's critical that this checks the global work queues are
	// empty before performing the ragged barrier. Otherwise,
	// there could be global work that a P could take after the P
	// has passed the ragged barrier.
	if !(gcphase == _GCmark && work.nwait == work.nproc && !gcMarkWorkAvailable(nil)) {
		semrelease(&work.markDoneSema)
		return
	}

	// forEachP needs worldsema to execute, and we'll need it to
	// stop the world later, so acquire worldsema now.
	semacquire(&worldsema)

	// Prevent weak->strong conversions from generating additional
	// GC work. forEachP will guarantee that it is observed globally.
	work.strongFromWeak.block = true

	// Flush all local buffers and collect flushedWork flags.
	gcMarkDoneFlushed = 0
	forEachP(waitReasonGCMarkTermination, func(pp *p) {
		// Flush the write barrier buffer, since this may add
		// work to the gcWork.
		wbBufFlush1(pp)

		// Flush the gcWork, since this may create global work
		// and set the flushedWork flag.
		//
		// TODO(austin): Break up these workbufs to
		// better distribute work.
		pp.gcw.dispose()
		// Collect the flushedWork flag.
		if pp.gcw.flushedWork {
			atomic.Xadd(&gcMarkDoneFlushed, 1)
			pp.gcw.flushedWork = false
		}
	})

	if gcMarkDoneFlushed != 0 {
		// More grey objects were discovered since the
		// previous termination check, so there may be more
		// work to do. Keep going. It's possible the
		// transition condition became true again during the
		// ragged barrier, so re-check it.
		semrelease(&worldsema)
		goto top
	}

	// For debugging/testing.
	for gcDebugMarkDone.spinAfterRaggedBarr
```