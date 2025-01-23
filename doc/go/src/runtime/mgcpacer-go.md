Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/runtime/mgcpacer.go`.

To address this, I will:
1. **Identify the main purpose of the code:** Based on the package name (`runtime`) and the constants and types defined, it seems to be related to garbage collection pacing.
2. **List the key functionalities:**  I will go through the constants, variables, and the `gcControllerState` struct to enumerate the features it controls or monitors.
3. **Infer the Go language feature:**  The code clearly deals with the garbage collector.
4. **Provide a Go code example:**  I will demonstrate a simple Go program that triggers garbage collection to illustrate the functionality.
5. **Address code reasoning with assumptions:** Since the provided snippet is declarative (constants and struct definition), there isn't much direct code reasoning to do. I will focus on explaining the purpose of different fields in the struct.
6. **Explain command-line parameters:** I will discuss how environment variables like `GOGC` and `GOMEMLIMIT` influence the behavior described in the code.
7. **Highlight potential user errors:** I will point out common mistakes users might make when trying to configure or understand GC pacing.
8. **Summarize the functionalities:** Finally, I will provide a concise overview of the code's purpose.
这段Go代码是 `go/src/runtime/mgcpacer.go` 文件的一部分，它主要定义了 **垃圾回收 (Garbage Collection, GC) 的步调控制器 (Pacer)**。其核心功能是 **动态地调整 GC 的触发时机和标记工作量**，以达到预期的 CPU 利用率和内存使用目标。

**具体功能列举:**

1. **定义了与 GC 步调控制相关的常量:**
   - `gcGoalUtilization`:  GC 标记的期望 CPU 利用率。
   - `gcBackgroundUtilization`: 后台标记的固定 CPU 利用率。
   - `gcCreditSlack`: 本地累积扫描工作信用额度的阈值。
   - `gcAssistTimeSlack`: 每个 P 可以累积的互斥器辅助时间的阈值。
   - `gcOverAssistWork`:  每次 GC 辅助操作额外进行的扫描工作量。
   - `defaultHeapMinimum`: `GOGC=100` 时的默认最小堆大小。
   - `maxStackScanSlack`: 每个 P 可以累积的栈空间分配或释放量的阈值。
   - `memoryLimitMinHeapGoalHeadroom`: 内存受限模式下，pacer 给予堆目标的最小额外空间。
   - `memoryLimitHeapGoalHeadroomPercent`: 内存受限模式下，基于内存限制的堆目标应有的额外空间百分比。

2. **定义了 `gcControllerState` 结构体:** 这个结构体存储了 GC 步调控制器的所有状态信息，包括：
   - `gcPercent`: 从 `GOGC` 环境变量初始化的 GC 百分比。
   - `memoryLimit`: 从 `GOMEMLIMIT` 环境变量初始化的软内存限制。
   - `heapMinimum`:  触发 GC 的最小堆大小。
   - `runway`:  应用程序分配的堆字节数，作为 GC 启动后的“跑道”。
   - `consMark`:  应用程序的每 CPU cons/mark 比率的估计值。
   - `lastConsMark`:  过去 4 个 GC 周期的 cons/mark 值。
   - `gcPercentHeapGoal`: 基于 `gcPercent` 计算的下一次 GC 结束时的目标 `heapLive` 大小。
   - `sweepDistMinTrigger`: 确保最小清除距离的最小触发点。
   - `triggered`: 当前 GC 周期实际触发时的 `heapLive` 值。
   - `lastHeapGoal`: 上一次 GC 结束时的 `heapGoal` 值。
   - `heapLive`: GC 认为的存活字节数。
   - `heapScan`:  可扫描堆的字节数。
   - `lastHeapScan`: 上一个 GC 周期扫描的堆字节数。
   - `lastStackScan`: 上一个 GC 周期扫描的栈字节数。
   - `maxStackScan`:  goroutine 已分配的栈空间总量。
   - `globalsScan`: 可扫描的全局变量空间总量。
   - `heapMarked`: 上一个 GC 周期标记的字节数。
   - `heapScanWork`, `stackScanWork`, `globalsScanWork`: 本周期执行的堆、栈和全局变量扫描工作量。
   - `bgScanCredit`: 后台并发扫描累积的扫描工作信用。
   - `assistTime`: 本周期互斥器辅助所花费的时间。
   - `dedicatedMarkTime`: 本周期专用标记 worker 所花费的时间。
   - `fractionalMarkTime`: 本周期分数标记 worker 所花费的时间。
   - `idleMarkTime`: 本周期空闲标记所花费的时间。
   - `markStartTime`: 辅助和后台标记 worker 启动的绝对开始时间。
   - `dedicatedMarkWorkersNeeded`: 需要启动的专用标记 worker 的数量。
   - `idleMarkWorkers`: 当前正在执行和允许执行的最大空闲标记 worker 数量。
   - `assistWorkPerByte`: 每次分配的字节数应该由互斥器辅助执行的扫描工作比率。
   - `assistBytesPerWork`:  `assistWorkPerByte` 的倒数。
   - `fractionalUtilizationGoal`:  在没有运行专用 worker 的每个 P 上，分数标记 worker 应该花费的挂钟时间比例。
   - 一些原子更新的内存统计信息，如 `heapInUse`, `heapReleased`, `heapFree`, `totalAlloc`, `totalFree`, `mappedReady`。

**推断的 Go 语言功能实现:**

这段代码是 Go 运行时 (runtime) 系统中 **垃圾回收 (Garbage Collection)** 功能的核心组成部分，具体来说，是 **控制 GC 触发时机和工作量的动态步调算法的实现**。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	// 获取当前的 GOGC 设置
	gcPercent := runtime.ReadMemStats(&runtime.MemStats{}).GCCPUFraction * 100
	fmt.Printf("当前 GOGC 设置（近似）: %.0f%%\n", gcPercent)

	// 分配大量内存
	s := make([]byte, 100*1024*1024) // 分配 100MB
	_ = s

	// 触发一次显式 GC
	runtime.GC()
	fmt.Println("显式触发 GC 后")

	// 再次分配一些内存
	s2 := make([]byte, 50*1024*1024) // 分配 50MB
	_ = s2

	// Go 的 GC 会根据 pacer 的策略自动触发，无需显式调用 runtime.GC()

	// 等待一段时间，让自动 GC 有机会发生
	time.Sleep(2 * time.Second)
	fmt.Println("等待一段时间后")
}
```

**假设的输入与输出:**

假设我们运行上面的代码，并且环境变量 `GOGC` 没有被显式设置，那么 Go 会使用默认值 (通常是 100)。

* **输入:**  运行上述 Go 代码。
* **输出:**
   ```
   当前 GOGC 设置（近似）: 100%
   显式触发 GC 后
   等待一段时间后
   ```

   在这个例子中，`runtime.GC()` 会显式触发一次垃圾回收。而等待一段时间后，Go 的 GC pacer 会根据内存分配情况和其内部算法（由 `mgcpacer.go` 中的代码控制）来决定是否需要自动触发垃圾回收。  我们无法直接从这个简单的例子中观察到 `mgcpacer.go` 的具体运行细节，但可以理解 `mgcpacer.go` 负责决定何时以及如何进行自动 GC。

**命令行参数的具体处理:**

`mgcpacer.go` 代码本身并不直接处理命令行参数。它的行为受到 **环境变量** 的影响，特别是：

* **`GOGC`**:  设置垃圾回收的目标。它表示在一次 GC 完成之后，允许新分配的内存占上次 GC 后存活对象大小的百分比。
    - `GOGC=off`: 禁用垃圾回收。
    - `GOGC=0`: 频繁进行垃圾回收。
    - `GOGC=100` (默认值):  在堆大小达到上次 GC 后存活对象大小的两倍时触发新的 GC。
    - 更高的值会减少 GC 的频率，但也可能导致更高的内存使用。

   `gcControllerState` 结构体中的 `gcPercent` 字段会从 `GOGC` 的值进行初始化。

* **`GOMEMLIMIT`**: 设置 Go 程序可以使用的最大内存量（包括堆和所有其他运行时分配的内存）。
    - 例如：`GOMEMLIMIT=1GiB` 将内存限制设置为 1GB。
    - `GOMEMLIMIT=off` 或不设置：禁用内存限制。

   `gcControllerState` 结构体中的 `memoryLimit` 字段会从 `GOMEMLIMIT` 的值进行初始化。

`mgcpacer.go` 中的代码会读取并使用这些环境变量的值来计算 GC 的触发点和控制标记过程。例如，`heapMinimum` 的计算就与 `GOGC` 的值有关。

**使用者易犯错的点:**

1. **误解 `GOGC` 的含义:**  新手可能会认为 `GOGC` 直接控制了 GC 的频率，但实际上它更多的是定义了 GC 的目标，即允许堆增长到多大后再触发 GC。过低地设置 `GOGC` 可能导致频繁的 GC，降低程序性能。过高地设置 `GOGC` 可能导致内存使用过高。

   **例子:**  如果用户设置 `GOGC=20`，他们可能会惊讶地发现 GC 非常频繁，即使内存使用量并不高，因为 pacer 会努力保持堆大小在上次 GC 后存活对象大小的 1.2 倍左右。

2. **忽略 `GOMEMLIMIT` 的影响:**  不理解 `GOMEMLIMIT` 的作用，或者设置不当，可能会导致程序在内存受限的环境中表现不佳，例如被操作系统强制终止 (OOM)。

   **例子:**  在一个容器化的环境中，如果没有设置 `GOMEMLIMIT`，Go 程序可能会尝试使用宿主机的所有内存，超出容器的限制，导致容器被 kill。

3. **过度依赖显式 GC 调用:**  虽然可以使用 `runtime.GC()` 显式触发 GC，但过度依赖它通常不是一个好主意。Go 的 GC pacer 旨在自动地、高效地管理内存。频繁的显式调用可能会干扰 pacer 的工作，甚至降低性能。

   **例子:**  在循环中每次分配大量内存后都调用 `runtime.GC()`，这会强制进行 STW (Stop-The-World) GC，显著降低程序的吞吐量。

**功能归纳 (第1部分):**

`go/src/runtime/mgcpacer.go` 代码的这一部分主要定义了 **垃圾回收步调控制器** 的数据结构和相关的配置常量。它描述了 GC pacer 的 **状态 (通过 `gcControllerState` 结构体)** 和一些 **基本的配置参数 (通过常量)**。 这些定义为后续的 GC 步调算法的实现奠定了基础，这些算法会利用这些状态和参数来动态地决定何时触发 GC 以及分配多少资源用于标记工作。 核心目标是 **在保证程序性能的前提下，有效地管理内存使用**。

### 提示词
```
这是路径为go/src/runtime/mgcpacer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/cpu"
	"internal/goexperiment"
	"internal/runtime/atomic"
	_ "unsafe" // for go:linkname
)

const (
	// gcGoalUtilization is the goal CPU utilization for
	// marking as a fraction of GOMAXPROCS.
	//
	// Increasing the goal utilization will shorten GC cycles as the GC
	// has more resources behind it, lessening costs from the write barrier,
	// but comes at the cost of increasing mutator latency.
	gcGoalUtilization = gcBackgroundUtilization

	// gcBackgroundUtilization is the fixed CPU utilization for background
	// marking. It must be <= gcGoalUtilization. The difference between
	// gcGoalUtilization and gcBackgroundUtilization will be made up by
	// mark assists. The scheduler will aim to use within 50% of this
	// goal.
	//
	// As a general rule, there's little reason to set gcBackgroundUtilization
	// < gcGoalUtilization. One reason might be in mostly idle applications,
	// where goroutines are unlikely to assist at all, so the actual
	// utilization will be lower than the goal. But this is moot point
	// because the idle mark workers already soak up idle CPU resources.
	// These two values are still kept separate however because they are
	// distinct conceptually, and in previous iterations of the pacer the
	// distinction was more important.
	gcBackgroundUtilization = 0.25

	// gcCreditSlack is the amount of scan work credit that can
	// accumulate locally before updating gcController.heapScanWork and,
	// optionally, gcController.bgScanCredit. Lower values give a more
	// accurate assist ratio and make it more likely that assists will
	// successfully steal background credit. Higher values reduce memory
	// contention.
	gcCreditSlack = 2000

	// gcAssistTimeSlack is the nanoseconds of mutator assist time that
	// can accumulate on a P before updating gcController.assistTime.
	gcAssistTimeSlack = 5000

	// gcOverAssistWork determines how many extra units of scan work a GC
	// assist does when an assist happens. This amortizes the cost of an
	// assist by pre-paying for this many bytes of future allocations.
	gcOverAssistWork = 64 << 10

	// defaultHeapMinimum is the value of heapMinimum for GOGC==100.
	defaultHeapMinimum = (goexperiment.HeapMinimum512KiBInt)*(512<<10) +
		(1-goexperiment.HeapMinimum512KiBInt)*(4<<20)

	// maxStackScanSlack is the bytes of stack space allocated or freed
	// that can accumulate on a P before updating gcController.stackSize.
	maxStackScanSlack = 8 << 10

	// memoryLimitMinHeapGoalHeadroom is the minimum amount of headroom the
	// pacer gives to the heap goal when operating in the memory-limited regime.
	// That is, it'll reduce the heap goal by this many extra bytes off of the
	// base calculation, at minimum.
	memoryLimitMinHeapGoalHeadroom = 1 << 20

	// memoryLimitHeapGoalHeadroomPercent is how headroom the memory-limit-based
	// heap goal should have as a percent of the maximum possible heap goal allowed
	// to maintain the memory limit.
	memoryLimitHeapGoalHeadroomPercent = 3
)

// gcController implements the GC pacing controller that determines
// when to trigger concurrent garbage collection and how much marking
// work to do in mutator assists and background marking.
//
// It calculates the ratio between the allocation rate (in terms of CPU
// time) and the GC scan throughput to determine the heap size at which to
// trigger a GC cycle such that no GC assists are required to finish on time.
// This algorithm thus optimizes GC CPU utilization to the dedicated background
// mark utilization of 25% of GOMAXPROCS by minimizing GC assists.
// GOMAXPROCS. The high-level design of this algorithm is documented
// at https://github.com/golang/proposal/blob/master/design/44167-gc-pacer-redesign.md.
// See https://golang.org/s/go15gcpacing for additional historical context.
var gcController gcControllerState

type gcControllerState struct {
	// Initialized from GOGC. GOGC=off means no GC.
	gcPercent atomic.Int32

	// memoryLimit is the soft memory limit in bytes.
	//
	// Initialized from GOMEMLIMIT. GOMEMLIMIT=off is equivalent to MaxInt64
	// which means no soft memory limit in practice.
	//
	// This is an int64 instead of a uint64 to more easily maintain parity with
	// the SetMemoryLimit API, which sets a maximum at MaxInt64. This value
	// should never be negative.
	memoryLimit atomic.Int64

	// heapMinimum is the minimum heap size at which to trigger GC.
	// For small heaps, this overrides the usual GOGC*live set rule.
	//
	// When there is a very small live set but a lot of allocation, simply
	// collecting when the heap reaches GOGC*live results in many GC
	// cycles and high total per-GC overhead. This minimum amortizes this
	// per-GC overhead while keeping the heap reasonably small.
	//
	// During initialization this is set to 4MB*GOGC/100. In the case of
	// GOGC==0, this will set heapMinimum to 0, resulting in constant
	// collection even when the heap size is small, which is useful for
	// debugging.
	heapMinimum uint64

	// runway is the amount of runway in heap bytes allocated by the
	// application that we want to give the GC once it starts.
	//
	// This is computed from consMark during mark termination.
	runway atomic.Uint64

	// consMark is the estimated per-CPU consMark ratio for the application.
	//
	// It represents the ratio between the application's allocation
	// rate, as bytes allocated per CPU-time, and the GC's scan rate,
	// as bytes scanned per CPU-time.
	// The units of this ratio are (B / cpu-ns) / (B / cpu-ns).
	//
	// At a high level, this value is computed as the bytes of memory
	// allocated (cons) per unit of scan work completed (mark) in a GC
	// cycle, divided by the CPU time spent on each activity.
	//
	// Updated at the end of each GC cycle, in endCycle.
	consMark float64

	// lastConsMark is the computed cons/mark value for the previous 4 GC
	// cycles. Note that this is *not* the last value of consMark, but the
	// measured cons/mark value in endCycle.
	lastConsMark [4]float64

	// gcPercentHeapGoal is the goal heapLive for when next GC ends derived
	// from gcPercent.
	//
	// Set to ^uint64(0) if gcPercent is disabled.
	gcPercentHeapGoal atomic.Uint64

	// sweepDistMinTrigger is the minimum trigger to ensure a minimum
	// sweep distance.
	//
	// This bound is also special because it applies to both the trigger
	// *and* the goal (all other trigger bounds must be based *on* the goal).
	//
	// It is computed ahead of time, at commit time. The theory is that,
	// absent a sudden change to a parameter like gcPercent, the trigger
	// will be chosen to always give the sweeper enough headroom. However,
	// such a change might dramatically and suddenly move up the trigger,
	// in which case we need to ensure the sweeper still has enough headroom.
	sweepDistMinTrigger atomic.Uint64

	// triggered is the point at which the current GC cycle actually triggered.
	// Only valid during the mark phase of a GC cycle, otherwise set to ^uint64(0).
	//
	// Updated while the world is stopped.
	triggered uint64

	// lastHeapGoal is the value of heapGoal at the moment the last GC
	// ended. Note that this is distinct from the last value heapGoal had,
	// because it could change if e.g. gcPercent changes.
	//
	// Read and written with the world stopped or with mheap_.lock held.
	lastHeapGoal uint64

	// heapLive is the number of bytes considered live by the GC.
	// That is: retained by the most recent GC plus allocated
	// since then. heapLive ≤ memstats.totalAlloc-memstats.totalFree, since
	// heapAlloc includes unmarked objects that have not yet been swept (and
	// hence goes up as we allocate and down as we sweep) while heapLive
	// excludes these objects (and hence only goes up between GCs).
	//
	// To reduce contention, this is updated only when obtaining a span
	// from an mcentral and at this point it counts all of the unallocated
	// slots in that span (which will be allocated before that mcache
	// obtains another span from that mcentral). Hence, it slightly
	// overestimates the "true" live heap size. It's better to overestimate
	// than to underestimate because 1) this triggers the GC earlier than
	// necessary rather than potentially too late and 2) this leads to a
	// conservative GC rate rather than a GC rate that is potentially too
	// low.
	//
	// Whenever this is updated, call traceHeapAlloc() and
	// this gcControllerState's revise() method.
	heapLive atomic.Uint64

	// heapScan is the number of bytes of "scannable" heap. This is the
	// live heap (as counted by heapLive), but omitting no-scan objects and
	// no-scan tails of objects.
	//
	// This value is fixed at the start of a GC cycle. It represents the
	// maximum scannable heap.
	heapScan atomic.Uint64

	// lastHeapScan is the number of bytes of heap that were scanned
	// last GC cycle. It is the same as heapMarked, but only
	// includes the "scannable" parts of objects.
	//
	// Updated when the world is stopped.
	lastHeapScan uint64

	// lastStackScan is the number of bytes of stack that were scanned
	// last GC cycle.
	lastStackScan atomic.Uint64

	// maxStackScan is the amount of allocated goroutine stack space in
	// use by goroutines.
	//
	// This number tracks allocated goroutine stack space rather than used
	// goroutine stack space (i.e. what is actually scanned) because used
	// goroutine stack space is much harder to measure cheaply. By using
	// allocated space, we make an overestimate; this is OK, it's better
	// to conservatively overcount than undercount.
	maxStackScan atomic.Uint64

	// globalsScan is the total amount of global variable space
	// that is scannable.
	globalsScan atomic.Uint64

	// heapMarked is the number of bytes marked by the previous
	// GC. After mark termination, heapLive == heapMarked, but
	// unlike heapLive, heapMarked does not change until the
	// next mark termination.
	heapMarked uint64

	// heapScanWork is the total heap scan work performed this cycle.
	// stackScanWork is the total stack scan work performed this cycle.
	// globalsScanWork is the total globals scan work performed this cycle.
	//
	// These are updated atomically during the cycle. Updates occur in
	// bounded batches, since they are both written and read
	// throughout the cycle. At the end of the cycle, heapScanWork is how
	// much of the retained heap is scannable.
	//
	// Currently these are measured in bytes. For most uses, this is an
	// opaque unit of work, but for estimation the definition is important.
	//
	// Note that stackScanWork includes only stack space scanned, not all
	// of the allocated stack.
	heapScanWork    atomic.Int64
	stackScanWork   atomic.Int64
	globalsScanWork atomic.Int64

	// bgScanCredit is the scan work credit accumulated by the concurrent
	// background scan. This credit is accumulated by the background scan
	// and stolen by mutator assists.  Updates occur in bounded batches,
	// since it is both written and read throughout the cycle.
	bgScanCredit atomic.Int64

	// assistTime is the nanoseconds spent in mutator assists
	// during this cycle. This is updated atomically, and must also
	// be updated atomically even during a STW, because it is read
	// by sysmon. Updates occur in bounded batches, since it is both
	// written and read throughout the cycle.
	assistTime atomic.Int64

	// dedicatedMarkTime is the nanoseconds spent in dedicated mark workers
	// during this cycle. This is updated at the end of the concurrent mark
	// phase.
	dedicatedMarkTime atomic.Int64

	// fractionalMarkTime is the nanoseconds spent in the fractional mark
	// worker during this cycle. This is updated throughout the cycle and
	// will be up-to-date if the fractional mark worker is not currently
	// running.
	fractionalMarkTime atomic.Int64

	// idleMarkTime is the nanoseconds spent in idle marking during this
	// cycle. This is updated throughout the cycle.
	idleMarkTime atomic.Int64

	// markStartTime is the absolute start time in nanoseconds
	// that assists and background mark workers started.
	markStartTime int64

	// dedicatedMarkWorkersNeeded is the number of dedicated mark workers
	// that need to be started. This is computed at the beginning of each
	// cycle and decremented as dedicated mark workers get started.
	dedicatedMarkWorkersNeeded atomic.Int64

	// idleMarkWorkers is two packed int32 values in a single uint64.
	// These two values are always updated simultaneously.
	//
	// The bottom int32 is the current number of idle mark workers executing.
	//
	// The top int32 is the maximum number of idle mark workers allowed to
	// execute concurrently. Normally, this number is just gomaxprocs. However,
	// during periodic GC cycles it is set to 0 because the system is idle
	// anyway; there's no need to go full blast on all of GOMAXPROCS.
	//
	// The maximum number of idle mark workers is used to prevent new workers
	// from starting, but it is not a hard maximum. It is possible (but
	// exceedingly rare) for the current number of idle mark workers to
	// transiently exceed the maximum. This could happen if the maximum changes
	// just after a GC ends, and an M with no P.
	//
	// Note that if we have no dedicated mark workers, we set this value to
	// 1 in this case we only have fractional GC workers which aren't scheduled
	// strictly enough to ensure GC progress. As a result, idle-priority mark
	// workers are vital to GC progress in these situations.
	//
	// For example, consider a situation in which goroutines block on the GC
	// (such as via runtime.GOMAXPROCS) and only fractional mark workers are
	// scheduled (e.g. GOMAXPROCS=1). Without idle-priority mark workers, the
	// last running M might skip scheduling a fractional mark worker if its
	// utilization goal is met, such that once it goes to sleep (because there's
	// nothing to do), there will be nothing else to spin up a new M for the
	// fractional worker in the future, stalling GC progress and causing a
	// deadlock. However, idle-priority workers will *always* run when there is
	// nothing left to do, ensuring the GC makes progress.
	//
	// See github.com/golang/go/issues/44163 for more details.
	idleMarkWorkers atomic.Uint64

	// assistWorkPerByte is the ratio of scan work to allocated
	// bytes that should be performed by mutator assists. This is
	// computed at the beginning of each cycle and updated every
	// time heapScan is updated.
	assistWorkPerByte atomic.Float64

	// assistBytesPerWork is 1/assistWorkPerByte.
	//
	// Note that because this is read and written independently
	// from assistWorkPerByte users may notice a skew between
	// the two values, and such a state should be safe.
	assistBytesPerWork atomic.Float64

	// fractionalUtilizationGoal is the fraction of wall clock
	// time that should be spent in the fractional mark worker on
	// each P that isn't running a dedicated worker.
	//
	// For example, if the utilization goal is 25% and there are
	// no dedicated workers, this will be 0.25. If the goal is
	// 25%, there is one dedicated worker, and GOMAXPROCS is 5,
	// this will be 0.05 to make up the missing 5%.
	//
	// If this is zero, no fractional workers are needed.
	fractionalUtilizationGoal float64

	// These memory stats are effectively duplicates of fields from
	// memstats.heapStats but are updated atomically or with the world
	// stopped and don't provide the same consistency guarantees.
	//
	// Because the runtime is responsible for managing a memory limit, it's
	// useful to couple these stats more tightly to the gcController, which
	// is intimately connected to how that memory limit is maintained.
	heapInUse    sysMemStat    // bytes in mSpanInUse spans
	heapReleased sysMemStat    // bytes released to the OS
	heapFree     sysMemStat    // bytes not in any span, but not released to the OS
	totalAlloc   atomic.Uint64 // total bytes allocated
	totalFree    atomic.Uint64 // total bytes freed
	mappedReady  atomic.Uint64 // total virtual memory in the Ready state (see mem.go).

	// test indicates that this is a test-only copy of gcControllerState.
	test bool

	_ cpu.CacheLinePad
}

func (c *gcControllerState) init(gcPercent int32, memoryLimit int64) {
	c.heapMinimum = defaultHeapMinimum
	c.triggered = ^uint64(0)
	c.setGCPercent(gcPercent)
	c.setMemoryLimit(memoryLimit)
	c.commit(true) // No sweep phase in the first GC cycle.
	// N.B. Don't bother calling traceHeapGoal. Tracing is never enabled at
	// initialization time.
	// N.B. No need to call revise; there's no GC enabled during
	// initialization.
}

// startCycle resets the GC controller's state and computes estimates
// for a new GC cycle. The caller must hold worldsema and the world
// must be stopped.
func (c *gcControllerState) startCycle(markStartTime int64, procs int, trigger gcTrigger) {
	c.heapScanWork.Store(0)
	c.stackScanWork.Store(0)
	c.globalsScanWork.Store(0)
	c.bgScanCredit.Store(0)
	c.assistTime.Store(0)
	c.dedicatedMarkTime.Store(0)
	c.fractionalMarkTime.Store(0)
	c.idleMarkTime.Store(0)
	c.markStartTime = markStartTime
	c.triggered = c.heapLive.Load()

	// Compute the background mark utilization goal. In general,
	// this may not come out exactly. We round the number of
	// dedicated workers so that the utilization is closest to
	// 25%. For small GOMAXPROCS, this would introduce too much
	// error, so we add fractional workers in that case.
	totalUtilizationGoal := float64(procs) * gcBackgroundUtilization
	dedicatedMarkWorkersNeeded := int64(totalUtilizationGoal + 0.5)
	utilError := float64(dedicatedMarkWorkersNeeded)/totalUtilizationGoal - 1
	const maxUtilError = 0.3
	if utilError < -maxUtilError || utilError > maxUtilError {
		// Rounding put us more than 30% off our goal. With
		// gcBackgroundUtilization of 25%, this happens for
		// GOMAXPROCS<=3 or GOMAXPROCS=6. Enable fractional
		// workers to compensate.
		if float64(dedicatedMarkWorkersNeeded) > totalUtilizationGoal {
			// Too many dedicated workers.
			dedicatedMarkWorkersNeeded--
		}
		c.fractionalUtilizationGoal = (totalUtilizationGoal - float64(dedicatedMarkWorkersNeeded)) / float64(procs)
	} else {
		c.fractionalUtilizationGoal = 0
	}

	// In STW mode, we just want dedicated workers.
	if debug.gcstoptheworld > 0 {
		dedicatedMarkWorkersNeeded = int64(procs)
		c.fractionalUtilizationGoal = 0
	}

	// Clear per-P state
	for _, p := range allp {
		p.gcAssistTime = 0
		p.gcFractionalMarkTime = 0
	}

	if trigger.kind == gcTriggerTime {
		// During a periodic GC cycle, reduce the number of idle mark workers
		// required. However, we need at least one dedicated mark worker or
		// idle GC worker to ensure GC progress in some scenarios (see comment
		// on maxIdleMarkWorkers).
		if dedicatedMarkWorkersNeeded > 0 {
			c.setMaxIdleMarkWorkers(0)
		} else {
			// TODO(mknyszek): The fundamental reason why we need this is because
			// we can't count on the fractional mark worker to get scheduled.
			// Fix that by ensuring it gets scheduled according to its quota even
			// if the rest of the application is idle.
			c.setMaxIdleMarkWorkers(1)
		}
	} else {
		// N.B. gomaxprocs and dedicatedMarkWorkersNeeded are guaranteed not to
		// change during a GC cycle.
		c.setMaxIdleMarkWorkers(int32(procs) - int32(dedicatedMarkWorkersNeeded))
	}

	// Compute initial values for controls that are updated
	// throughout the cycle.
	c.dedicatedMarkWorkersNeeded.Store(dedicatedMarkWorkersNeeded)
	c.revise()

	if debug.gcpacertrace > 0 {
		heapGoal := c.heapGoal()
		assistRatio := c.assistWorkPerByte.Load()
		print("pacer: assist ratio=", assistRatio,
			" (scan ", gcController.heapScan.Load()>>20, " MB in ",
			work.initialHeapLive>>20, "->",
			heapGoal>>20, " MB)",
			" workers=", dedicatedMarkWorkersNeeded,
			"+", c.fractionalUtilizationGoal, "\n")
	}
}

// revise updates the assist ratio during the GC cycle to account for
// improved estimates. This should be called whenever gcController.heapScan,
// gcController.heapLive, or if any inputs to gcController.heapGoal are
// updated. It is safe to call concurrently, but it may race with other
// calls to revise.
//
// The result of this race is that the two assist ratio values may not line
// up or may be stale. In practice this is OK because the assist ratio
// moves slowly throughout a GC cycle, and the assist ratio is a best-effort
// heuristic anyway. Furthermore, no part of the heuristic depends on
// the two assist ratio values being exact reciprocals of one another, since
// the two values are used to convert values from different sources.
//
// The worst case result of this raciness is that we may miss a larger shift
// in the ratio (say, if we decide to pace more aggressively against the
// hard heap goal) but even this "hard goal" is best-effort (see #40460).
// The dedicated GC should ensure we don't exceed the hard goal by too much
// in the rare case we do exceed it.
//
// It should only be called when gcBlackenEnabled != 0 (because this
// is when assists are enabled and the necessary statistics are
// available).
func (c *gcControllerState) revise() {
	gcPercent := c.gcPercent.Load()
	if gcPercent < 0 {
		// If GC is disabled but we're running a forced GC,
		// act like GOGC is huge for the below calculations.
		gcPercent = 100000
	}
	live := c.heapLive.Load()
	scan := c.heapScan.Load()
	work := c.heapScanWork.Load() + c.stackScanWork.Load() + c.globalsScanWork.Load()

	// Assume we're under the soft goal. Pace GC to complete at
	// heapGoal assuming the heap is in steady-state.
	heapGoal := int64(c.heapGoal())

	// The expected scan work is computed as the amount of bytes scanned last
	// GC cycle (both heap and stack), plus our estimate of globals work for this cycle.
	scanWorkExpected := int64(c.lastHeapScan + c.lastStackScan.Load() + c.globalsScan.Load())

	// maxScanWork is a worst-case estimate of the amount of scan work that
	// needs to be performed in this GC cycle. Specifically, it represents
	// the case where *all* scannable memory turns out to be live, and
	// *all* allocated stack space is scannable.
	maxStackScan := c.maxStackScan.Load()
	maxScanWork := int64(scan + maxStackScan + c.globalsScan.Load())
	if work > scanWorkExpected {
		// We've already done more scan work than expected. Because our expectation
		// is based on a steady-state scannable heap size, we assume this means our
		// heap is growing. Compute a new heap goal that takes our existing runway
		// computed for scanWorkExpected and extrapolates it to maxScanWork, the worst-case
		// scan work. This keeps our assist ratio stable if the heap continues to grow.
		//
		// The effect of this mechanism is that assists stay flat in the face of heap
		// growths. It's OK to use more memory this cycle to scan all the live heap,
		// because the next GC cycle is inevitably going to use *at least* that much
		// memory anyway.
		extHeapGoal := int64(float64(heapGoal-int64(c.triggered))/float64(scanWorkExpected)*float64(maxScanWork)) + int64(c.triggered)
		scanWorkExpected = maxScanWork

		// hardGoal is a hard limit on the amount that we're willing to push back the
		// heap goal, and that's twice the heap goal (i.e. if GOGC=100 and the heap and/or
		// stacks and/or globals grow to twice their size, this limits the current GC cycle's
		// growth to 4x the original live heap's size).
		//
		// This maintains the invariant that we use no more memory than the next GC cycle
		// will anyway.
		hardGoal := int64((1.0 + float64(gcPercent)/100.0) * float64(heapGoal))
		if extHeapGoal > hardGoal {
			extHeapGoal = hardGoal
		}
		heapGoal = extHeapGoal
	}
	if int64(live) > heapGoal {
		// We're already past our heap goal, even the extrapolated one.
		// Leave ourselves some extra runway, so in the worst case we
		// finish by that point.
		const maxOvershoot = 1.1
		heapGoal = int64(float64(heapGoal) * maxOvershoot)

		// Compute the upper bound on the scan work remaining.
		scanWorkExpected = maxScanWork
	}

	// Compute the remaining scan work estimate.
	//
	// Note that we currently count allocations during GC as both
	// scannable heap (heapScan) and scan work completed
	// (scanWork), so allocation will change this difference
	// slowly in the soft regime and not at all in the hard
	// regime.
	scanWorkRemaining := scanWorkExpected - work
	if scanWorkRemaining < 1000 {
		// We set a somewhat arbitrary lower bound on
		// remaining scan work since if we aim a little high,
		// we can miss by a little.
		//
		// We *do* need to enforce that this is at least 1,
		// since marking is racy and double-scanning objects
		// may legitimately make the remaining scan work
		// negative, even in the hard goal regime.
		scanWorkRemaining = 1000
	}

	// Compute the heap distance remaining.
	heapRemaining := heapGoal - int64(live)
	if heapRemaining <= 0 {
		// This shouldn't happen, but if it does, avoid
		// dividing by zero or setting the assist negative.
		heapRemaining = 1
	}

	// Compute the mutator assist ratio so by the time the mutator
	// allocates the remaining heap bytes up to heapGoal, it will
	// have done (or stolen) the remaining amount of scan work.
	// Note that the assist ratio values are updated atomically
	// but not together. This means there may be some degree of
	// skew between the two values. This is generally OK as the
	// values shift relatively slowly over the course of a GC
	// cycle.
	assistWorkPerByte := float64(scanWorkRemaining) / float64(heapRemaining)
	assistBytesPerWork := float64(heapRemaining) / float64(scanWorkRemaining)
	c.assistWorkPerByte.Store(assistWorkPerByte)
	c.assistBytesPerWork.Store(assistBytesPerWork)
}

// endCycle computes the consMark estimate for the next cycle.
// userForced indicates whether the current GC cycle was forced
// by the application.
func (c *gcControllerState) endCycle(now int64, procs int, userForced bool) {
	// Record last heap goal for the scavenger.
	// We'll be updating the heap goal soon.
	gcController.lastHeapGoal = c.heapGoal()

	// Compute the duration of time for which assists were turned on.
	assistDuration := now - c.markStartTime

	// Assume background mark hit its utilization goal.
	utilization := gcBackgroundUtilization
	// Add assist utilization; avoid divide by zero.
	if assistDuration > 0 {
		utilization += float64(c.assistTime.Load()) / float64(assistDuration*int64(procs))
	}

	if c.heapLive.Load() <= c.triggered {
		// Shouldn't happen, but let's be very safe about this in case the
		// GC is somehow extremely short.
		//
		// In this case though, the only reasonable value for c.heapLive-c.triggered
		// would be 0, which isn't really all that useful, i.e. the GC was so short
		// that it didn't matter.
		//
		// Ignore this case and don't update anything.
		return
	}
	idleUtilization := 0.0
	if assistDuration > 0 {
		idleUtilization = float64(c.idleMarkTime.Load()) / float64(assistDuration*int64(procs))
	}
	// Determine the cons/mark ratio.
	//
	// The units we want for the numerator and denominator are both B / cpu-ns.
	// We get this by taking the bytes allocated or scanned, and divide by the amount of
	// CPU time it took for those operations. For allocations, that CPU time is
	//
	//    assistDuration * procs * (1 - utilization)
	//
	// Where utilization includes just background GC workers and assists. It does *not*
	// include idle GC work time, because in theory the mutator is free to take that at
	// any point.
	//
	// For scanning, that CPU time is
	//
	//    assistDuration * procs * (utilization + idleUtilization)
	//
	// In this case, we *include* idle utilization, because that is additional CPU time that
	// the GC had available to it.
	//
	// In effect, idle GC time is sort of double-counted here, but it's very weird compared
	// to other kinds of GC work, because of how fluid it is. Namely, because the mutator is
	// *always* free to take it.
	//
	// So this calculation is really:
	//     (heapLive-trigger) / (assistDuration * procs * (1-utilization)) /
	//         (scanWork) / (assistDuration * procs * (utilization+idleUtilization))
	//
	// Note that because we only care about the ratio, assistDuration and procs cancel out.
	scanWork := c.heapScanWork.Load() + c.stackScanWork.Load() + c.globalsScanWork.Load()
	currentConsMark := (float64(c.heapLive.Load()-c.triggered) * (utilization + idleUtilization)) /
		(float64(scanWork) * (1 - utilization))

	// Update our cons/mark estimate. This is the maximum of the value we just computed and the last
	// 4 cons/mark values we measured. The reason we take the maximum here is to bias a noisy
	// cons/mark measurement toward fewer assists at the expense of additional GC cycles (starting
	// earlier).
	oldConsMark := c.consMark
	c.consMark = currentConsMark
	for i := range c.lastConsMark {
		if c.lastConsMark[i] > c.consMark {
			c.consMark = c.lastConsMark[i]
		}
	}
	copy(c.lastConsMark[:], c.lastConsMark[1:])
	c.lastConsMark[len(c.lastConsMark)-1] = currentConsMark

	if debug.gcpacertrace > 0 {
		printlock()
		goal := gcGoalUtilization * 100
		print("pacer: ", int(utilization*100), "% CPU (", int(goal), " exp.) for ")
		print(c.heapScanWork.Load(), "+", c.stackScanWork.Load(), "+", c.globalsScanWork.Load(), " B work (", c.lastHeapScan+c.lastStackScan.Load()+c.globalsScan.Load(), " B exp.) ")
		live := c.heapLive.Load()
		print("in ", c.triggered, " B -> ", live, " B (∆goal ", int64(live)-int64(c.lastHeapGoal), ", cons/mark ", oldConsMark, ")")
		println()
		printunlock()
	}
}

// enlistWorker encourages another dedicated mark worker to start on
// another P if there are spare worker slots. It is used by putfull
// when more work is made available.
//
//go:nowritebarrier
func (c *gcControllerState) enlistWorker() {
	// If there are idle Ps, wake one so it will run an idle worker.
	// NOTE: This is suspected of causing deadlocks. See golang.org/issue/19112.
	//
	//	if sched.npidle.Load() != 0 && sched.nmspinning.Load() == 0 {
	//		wakep()
	//		return
	//	}

	// There are no idle Ps. If we need more dedicated workers,
	// try to preempt a running P so it will switch to a worker.
	if c.dedicatedMarkWorkersNeeded.Load() <= 0 {
		return
	}
	// Pick a random other P to preempt.
	if gomaxprocs <= 1 {
		return
	}
	gp := getg()
	if gp == nil || gp.m == nil || gp.m.p == 0 {
		return
	}
	myID := gp.m.p.ptr().id
	for tries := 0; tries < 5; tries++ {
		id := int32(cheaprandn(uint32(gomaxprocs - 1)))
		if id >= myID {
			id++
		}
		p := allp[id]
		if p.status != _Prunning {
			continue
		}
		if preemptone(p) {
			return
		}
	}
}

// findRunnableGCWorker returns a background mark worker for pp if it
// should be run. This must only be called when gcBlackenEnabled != 0.
func (c *gcControllerState) findRunnableGCWorker(pp *p, now int64) (*g, int64) {
	if gcBlackenEnabled == 0 {
		throw("gcControllerState.findRunnable: blackening not enabled")
	}

	// Since we have the current time, check if the GC CPU limiter
	// hasn't had an update in a while. This check is necessary in
	// case the limiter is on but hasn't been checked in a while and
	// so may have left sufficient headroom to turn off again.
	if now == 0 {
		now = nanotime()
	}
	if gcCPULimiter.needUpdate(now) {
		gcCPULimiter.update(now)
	}

	if !gcMarkWorkAvailable(pp) {
		// No work to be done right now. This can happen at
		// the end of the mark phase when there are still
		// assists tapering off. Don't bother running a worker
		// now because it'll just return immediately.
		return nil, now
	}

	if c.dedicatedMarkWorkersNeeded.Load() <= 0 && c.fractionalUtilizationGoal == 0 {
		// No current need for dedicated workers, and no need at all for
		// fractional workers. Check before trying to acquire a worker; when
		// GOMAXPROCS is large, that can be expensive and is often unnecessary.
		//
		// When a dedicated worker stops running, the gcBgMarkWorker loop notes
		// the need for the worker before returning it to the pool. If we don't
		// see the need now, we wouldn't have found it in the pool anyway.
		return nil, now
	}

	// Grab a worker before we commit to running below.
	node := (*gcBgMarkWorkerNode)(gcBgMarkWorkerPool.pop())
	if node == nil {
		// There is at least one worker per P, so normally there are
		// enough workers to run on all Ps, if necessary. However, once
		// a worker enters gcMarkDone it may park without rejoining the
		// pool, thus freeing a P with no corresponding worker.
		// gcMarkDone never depends on another worker doing work, so it
		// is safe to simply do nothing here.
		//
		// If gcMarkDone bails out without completing the mark phase,
		// it will always do so with queued global work. Thus, that P
		// will be immediately eligible to re-run the wo
```