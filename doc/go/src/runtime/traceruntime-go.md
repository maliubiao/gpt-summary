Response:
我的目标是深入理解给定的 Go 源代码文件 `traceruntime.go`，并用中文清晰地解释其功能、实现方式，并提供代码示例和潜在的易错点。

**我的思考过程如下：**

1. **整体浏览与结构分析:**  首先，我快速阅读了整个代码，注意到了 `package runtime` 和  `// Runtime -> tracer API.` 的注释，这明确了代码是 Go 运行时环境的一部分，并且是用于跟踪 (tracing) 功能的 API。我注意到代码中定义了几个核心的结构体：`gTraceState`, `mTraceState`, `pTraceState`，这暗示了 tracing 功能是基于 Goroutine (G)、Machine (M) 和 Processor (P) 的状态来进行的。

2. **功能模块识别:**  我开始识别代码中的关键函数和常量，并尝试将它们归类到不同的功能模块：
    * **初始化:** `traceLockInit()` 看起来是用来初始化锁的，这些锁很可能用于保护 tracing 数据结构。
    * **使能/禁用:** `traceEnabled()`, `traceAllocFreeEnabled()`, `traceShuttingDown()` 似乎是用来查询 tracing 功能的当前状态。
    * **事件记录的核心:**  `traceLocker` 结构体和 `traceAcquire()`, `traceRelease()` 函数是关键，它们控制着对 tracing 数据的访问。`eventWriter` 和各种以 `Go...`, `Proc...`, `GC...`, `STW...`, `Heap...` 开头的函数显然是用于记录不同类型的 tracing 事件。
    * **阻塞/停止原因:** `traceBlockReason` 和 `traceGoStopReason` 定义了 Goroutine 阻塞和停止的不同原因，这对于分析程序行为至关重要。
    * **用户态 tracing API:**  以 `trace_user...` 开头的函数看起来是提供给用户程序使用的 tracing API。
    * **线程销毁处理:** `traceThreadDestroy()`  处理线程销毁时的 tracing 相关清理工作。

3. **关键概念理解:** 我仔细阅读了 `traceLocker` 的注释，理解了它代表着一个正在写入 trace 事件的 M，并且在 `traceLocker` 生效期间，对 G/M/P 的操作以及 trace 事件的写入被认为是原子性的。这对于理解 tracing 的一致性和正确性非常重要。

4. **代码推理与示例构建:**  对于关键的功能模块，我尝试推理其实现方式，并思考如何用 Go 代码来触发这些 tracing 事件。例如：
    * **`traceAcquire()` 和 `traceRelease()`:**  这是所有 tracing 事件记录的入口和出口，就像一个临界区。
    * **`GoCreate()`:**  显然在 `go` 关键字创建新的 Goroutine 时会被调用。
    * **`GoSched()`:**  当调用 `runtime.Gosched()` 时会被调用。
    * **`GoPark()`:**  在 Goroutine 进入阻塞状态时被调用，例如等待 channel 或互斥锁。
    * **`GoSysCall()` 和 `GoSysExit()`:**  在 Goroutine 进入和退出系统调用时被调用。
    * **用户态 tracing API (`trace_user...`)**:  需要通过 `//go:linkname` 链接到 `runtime/trace` 包中的函数。

    我开始构思简单的 Go 代码示例，来验证我的理解。例如，对于 `GoCreate`:

    ```go
    package main

    import "runtime"

    func main() {
        go func() {
            // Some work
        }()
    }
    ```

    当我运行程序并启用 tracing 后，我期望在 trace 数据中看到 `traceEvGoCreate` 事件。

5. **命令行参数处理:** 我查阅了 Go 官方文档和相关资料，了解了如何通过命令行参数来启用和配置 tracing，例如 `-trace` 标志。

6. **易错点分析:**  我思考了用户在使用 tracing 功能时可能犯的错误。例如，用户可能会忘记在用户态 tracing API 中调用 `traceAcquire()` 和 `traceRelease()`，或者在性能敏感的代码中过度使用用户态 tracing API。

7. **组织答案:**  我将我的理解组织成结构化的中文答案，包括功能概述、具体功能解析、代码示例、命令行参数说明和易错点。  我特别注意使用清晰的语言和代码注释来解释复杂的概念。

8. **迭代和完善:**  我多次审阅我的答案，确保其准确性、完整性和易读性。  我可能会重新阅读代码，查阅相关文档，以填补理解上的空白或修正错误。

通过以上思考过程，我逐步构建了对 `traceruntime.go` 的深入理解，并能够用中文清晰地解释其功能和实现方式。
这段代码是 Go 运行时环境 `runtime` 包中 `traceruntime.go` 文件的一部分，它实现了 **Go 程序的运行时跟踪 (tracing) 功能**。

**主要功能概览:**

这段代码定义了用于收集和记录 Go 程序运行时事件的机制。这些事件可以用于分析程序的性能、理解 Goroutine 的行为、以及进行故障排查。

**具体功能列举:**

1. **定义跟踪状态结构体:**
   - `gTraceState`:  存储每个 Goroutine 的跟踪状态信息，例如事件序列号。
   - `mTraceState`: 存储每个 Machine (OS 线程) 的跟踪状态信息，例如用于写入跟踪数据的缓冲区、锁信息等。
   - `pTraceState`: 存储每个 Processor (逻辑处理器) 的跟踪状态信息，例如绑定的 M 的 ID、是否可以进行垃圾回收扫描等。

2. **初始化跟踪锁:** `traceLockInit()` 函数用于初始化全局的跟踪锁，用于保护跟踪相关的数据结构，防止并发访问冲突。

3. **定义跟踪事件类型和原因:**
   - `traceBlockReason`: 枚举 Goroutine 阻塞的原因，例如等待网络、channel、锁等。
   - `traceGoStopReason`: 枚举 Goroutine 停止运行的原因，例如调用 `runtime.Gosched()` 或被抢占。

4. **提供查询跟踪状态的函数:**
   - `traceEnabled()`: 返回当前跟踪是否启用。
   - `traceAllocFreeEnabled()`: 返回当前跟踪是否启用了内存分配/释放事件的记录。
   - `traceShuttingDown()`: 返回当前跟踪是否正在关闭。

5. **核心的跟踪事件记录机制：`traceLocker` 和 `traceAcquire`/`traceRelease`:**
   - `traceLocker`:  表示一个 M 正在写入跟踪事件。在 `traceLocker` 有效期间，对 G/M/P 的操作以及写入跟踪事件被认为是原子性的。
   - `traceAcquire()`:  获取一个 `traceLocker`，准备开始记录跟踪事件。它会检查跟踪是否启用，并获取必要的锁。
   - `traceRelease()`:  释放 `traceLocker`，表示完成跟踪事件的记录。

6. **提供记录各种运行时事件的函数 (通过 `traceLocker`):**
   - **Goroutine 相关:** `GoCreate`, `GoStart`, `GoEnd`, `GoSched`, `GoPreempt`, `GoStop`, `GoPark`, `GoUnpark`, `GoSwitch`, `GoSysCall`, `GoSysExit`, `GoCreateSyscall`, `GoDestroySyscall`.
   - **Processor 相关:** `ProcStart`, `ProcStop`, `ProcSteal`.
   - **垃圾回收相关:** `GCActive`, `GCStart`, `GCDone`, `GCSweepStart`, `GCSweepSpan`, `GCSweepDone`, `GCMarkAssistStart`, `GCMarkAssistDone`.
   - **Stop-The-World (STW) 相关:** `STWStart`, `STWDone`.
   - **内存分配相关:** `HeapAlloc`, `HeapGoal`.
   - **用户自定义事件:** 通过 `trace_userTaskCreate`, `trace_userTaskEnd`, `trace_userRegion`, `trace_userLog` 提供用户态的跟踪 API。
   - **其他:** `Gomaxprocs`.

7. **处理线程销毁时的跟踪数据:** `traceThreadDestroy()` 函数在线程被销毁时，负责刷新该线程可能还未写入的跟踪数据。

**推理 Go 语言功能实现：运行时跟踪 (Runtime Tracing)**

这段代码是 Go 运行时跟踪功能的核心实现。Go 的运行时跟踪允许开发者在程序运行时收集各种事件，并将这些事件记录到文件中，然后可以使用 `go tool trace` 命令来分析这些跟踪数据。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"os"
	"runtime/trace"
)

func main() {
	// 创建一个跟踪文件
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// 启动跟踪
	err = trace.Start(f)
	if err != nil {
		panic(err)
	}
	defer trace.Stop()

	fmt.Println("开始执行...")

	go func() {
		fmt.Println("Goroutine 1 执行")
		// 模拟一些工作
		for i := 0; i < 100000; i++ {
		}
	}()

	go func() {
		fmt.Println("Goroutine 2 执行")
		// 模拟一些工作
		for i := 0; i < 50000; i++ {
		}
	}()

	// 主 Goroutine 也做一些工作
	for i := 0; i < 200000; i++ {
	}

	fmt.Println("执行结束")
}
```

**假设的输入与输出:**

* **输入:** 运行上述代码。
* **输出:** 会生成一个名为 `trace.out` 的文件，其中包含了程序运行期间的各种跟踪事件，例如 Goroutine 的创建、启动、停止，GC 事件，系统调用等。可以使用 `go tool trace trace.out` 命令来查看和分析这些数据。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。Go 的运行时跟踪功能通常通过以下方式启用：

1. **在代码中使用 `runtime/trace` 包：**  如上面的代码示例所示，使用 `trace.Start()` 和 `trace.Stop()` 函数来控制跟踪的开始和结束，并指定跟踪数据输出的文件。

2. **使用 `-trace` 命令行标志：**  在运行 Go 程序时，可以使用 `-trace=<filename>` 标志来启用跟踪，并将跟踪数据输出到指定的文件中。例如：

   ```bash
   go run -trace=mytrace.out main.go
   ```

   运行时环境会解析这个标志，并在程序启动时自动开始跟踪，并在程序结束时停止跟踪并将数据写入 `mytrace.out` 文件。  具体的参数解析和处理逻辑在 Go 的 `os` 和 `flag` 等包中实现，而不是在 `traceruntime.go` 中。

**使用者易犯错的点:**

1. **忘记停止跟踪:**  如果在代码中使用了 `trace.Start()`，务必确保在适当的时候调用 `trace.Stop()`，否则可能会导致资源泄漏或跟踪文件不完整。通常使用 `defer trace.Stop()` 来确保即使发生 panic 也能停止跟踪。

   ```go
   func main() {
       f, _ := os.Create("trace.out")
       trace.Start(f)
       defer trace.Stop() // 容易忘记添加这一行
       // ...
   }
   ```

2. **在性能敏感的代码中过度使用用户态跟踪 API:**  `trace_userTaskCreate`, `trace_userRegion`, `trace_userLog` 等用户态跟踪 API 会引入一定的性能开销。在高频调用的代码路径中使用这些 API 可能会对程序的性能产生显著影响。应该谨慎使用，仅在需要深入了解特定代码段行为时使用。

3. **并发访问跟踪数据结构 (理论上，使用者一般不会直接操作这些):**  虽然 `traceruntime.go` 内部使用了锁来保护跟踪数据结构，但如果用户尝试在运行时修改与跟踪相关的全局变量或数据结构（虽然这通常是不推荐且危险的），可能会导致数据不一致或其他问题。但这更多是针对 Go 运行时开发的注意事项，普通使用者不会直接触及这些内部结构。

总而言之，`traceruntime.go` 是 Go 运行时跟踪功能的基石，它定义了跟踪事件的结构、记录机制以及与 Goroutine、M 和 P 相关的跟踪状态。通过它，Go 提供了强大的工具来帮助开发者理解和优化程序的运行时行为。

Prompt: 
```
这是路径为go/src/runtime/traceruntime.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Runtime -> tracer API.

package runtime

import (
	"internal/runtime/atomic"
	_ "unsafe" // for go:linkname
)

// gTraceState is per-G state for the tracer.
type gTraceState struct {
	traceSchedResourceState
}

// reset resets the gTraceState for a new goroutine.
func (s *gTraceState) reset() {
	s.seq = [2]uint64{}
	// N.B. s.statusTraced is managed and cleared separately.
}

// mTraceState is per-M state for the tracer.
type mTraceState struct {
	seqlock       atomic.Uintptr                    // seqlock indicating that this M is writing to a trace buffer.
	buf           [2][traceNumExperiments]*traceBuf // Per-M traceBuf for writing. Indexed by trace.gen%2.
	link          *m                                // Snapshot of alllink or freelink.
	reentered     uint32                            // Whether we've reentered tracing from within tracing.
	oldthrowsplit bool                              // gp.throwsplit upon calling traceLocker.writer. For debugging.
}

// pTraceState is per-P state for the tracer.
type pTraceState struct {
	traceSchedResourceState

	// mSyscallID is the ID of the M this was bound to before entering a syscall.
	mSyscallID int64

	// maySweep indicates the sweep events should be traced.
	// This is used to defer the sweep start event until a span
	// has actually been swept.
	maySweep bool

	// inSweep indicates that at least one sweep event has been traced.
	inSweep bool

	// swept and reclaimed track the number of bytes swept and reclaimed
	// by sweeping in the current sweep loop (while maySweep was true).
	swept, reclaimed uintptr
}

// traceLockInit initializes global trace locks.
func traceLockInit() {
	// Sharing a lock rank here is fine because they should never be accessed
	// together. If they are, we want to find out immediately.
	lockInit(&trace.stringTab[0].lock, lockRankTraceStrings)
	lockInit(&trace.stringTab[0].tab.mem.lock, lockRankTraceStrings)
	lockInit(&trace.stringTab[1].lock, lockRankTraceStrings)
	lockInit(&trace.stringTab[1].tab.mem.lock, lockRankTraceStrings)
	lockInit(&trace.stackTab[0].tab.mem.lock, lockRankTraceStackTab)
	lockInit(&trace.stackTab[1].tab.mem.lock, lockRankTraceStackTab)
	lockInit(&trace.typeTab[0].tab.mem.lock, lockRankTraceTypeTab)
	lockInit(&trace.typeTab[1].tab.mem.lock, lockRankTraceTypeTab)
	lockInit(&trace.lock, lockRankTrace)
}

// lockRankMayTraceFlush records the lock ranking effects of a
// potential call to traceFlush.
//
// nosplit because traceAcquire is nosplit.
//
//go:nosplit
func lockRankMayTraceFlush() {
	lockWithRankMayAcquire(&trace.lock, getLockRank(&trace.lock))
}

// traceBlockReason is an enumeration of reasons a goroutine might block.
// This is the interface the rest of the runtime uses to tell the
// tracer why a goroutine blocked. The tracer then propagates this information
// into the trace however it sees fit.
//
// Note that traceBlockReasons should not be compared, since reasons that are
// distinct by name may *not* be distinct by value.
type traceBlockReason uint8

const (
	traceBlockGeneric traceBlockReason = iota
	traceBlockForever
	traceBlockNet
	traceBlockSelect
	traceBlockCondWait
	traceBlockSync
	traceBlockChanSend
	traceBlockChanRecv
	traceBlockGCMarkAssist
	traceBlockGCSweep
	traceBlockSystemGoroutine
	traceBlockPreempted
	traceBlockDebugCall
	traceBlockUntilGCEnds
	traceBlockSleep
	traceBlockGCWeakToStrongWait
	traceBlockSynctest
)

var traceBlockReasonStrings = [...]string{
	traceBlockGeneric:            "unspecified",
	traceBlockForever:            "forever",
	traceBlockNet:                "network",
	traceBlockSelect:             "select",
	traceBlockCondWait:           "sync.(*Cond).Wait",
	traceBlockSync:               "sync",
	traceBlockChanSend:           "chan send",
	traceBlockChanRecv:           "chan receive",
	traceBlockGCMarkAssist:       "GC mark assist wait for work",
	traceBlockGCSweep:            "GC background sweeper wait",
	traceBlockSystemGoroutine:    "system goroutine wait",
	traceBlockPreempted:          "preempted",
	traceBlockDebugCall:          "wait for debug call",
	traceBlockUntilGCEnds:        "wait until GC ends",
	traceBlockSleep:              "sleep",
	traceBlockGCWeakToStrongWait: "GC weak to strong wait",
	traceBlockSynctest:           "synctest",
}

// traceGoStopReason is an enumeration of reasons a goroutine might yield.
//
// Note that traceGoStopReasons should not be compared, since reasons that are
// distinct by name may *not* be distinct by value.
type traceGoStopReason uint8

const (
	traceGoStopGeneric traceGoStopReason = iota
	traceGoStopGoSched
	traceGoStopPreempted
)

var traceGoStopReasonStrings = [...]string{
	traceGoStopGeneric:   "unspecified",
	traceGoStopGoSched:   "runtime.Gosched",
	traceGoStopPreempted: "preempted",
}

// traceEnabled returns true if the trace is currently enabled.
//
//go:nosplit
func traceEnabled() bool {
	return trace.enabled
}

// traceAllocFreeEnabled returns true if the trace is currently enabled
// and alloc/free events are also enabled.
//
//go:nosplit
func traceAllocFreeEnabled() bool {
	return trace.enabledWithAllocFree
}

// traceShuttingDown returns true if the trace is currently shutting down.
func traceShuttingDown() bool {
	return trace.shutdown.Load()
}

// traceLocker represents an M writing trace events. While a traceLocker value
// is valid, the tracer observes all operations on the G/M/P or trace events being
// written as happening atomically.
type traceLocker struct {
	mp  *m
	gen uintptr
}

// debugTraceReentrancy checks if the trace is reentrant.
//
// This is optional because throwing in a function makes it instantly
// not inlineable, and we want traceAcquire to be inlineable for
// low overhead when the trace is disabled.
const debugTraceReentrancy = false

// traceAcquire prepares this M for writing one or more trace events.
//
// nosplit because it's called on the syscall path when stack movement is forbidden.
//
//go:nosplit
func traceAcquire() traceLocker {
	if !traceEnabled() {
		return traceLocker{}
	}
	return traceAcquireEnabled()
}

// traceAcquireEnabled is the traceEnabled path for traceAcquire. It's explicitly
// broken out to make traceAcquire inlineable to keep the overhead of the tracer
// when it's disabled low.
//
// nosplit because it's called by traceAcquire, which is nosplit.
//
//go:nosplit
func traceAcquireEnabled() traceLocker {
	// Any time we acquire a traceLocker, we may flush a trace buffer. But
	// buffer flushes are rare. Record the lock edge even if it doesn't happen
	// this time.
	lockRankMayTraceFlush()

	// Prevent preemption.
	mp := acquirem()

	// Check if we're already tracing. It's safe to be reentrant in general,
	// because this function (and the invariants of traceLocker.writer) ensure
	// that it is.
	if mp.trace.seqlock.Load()%2 == 1 {
		mp.trace.reentered++
		return traceLocker{mp, trace.gen.Load()}
	}

	// Acquire the trace seqlock. This prevents traceAdvance from moving forward
	// until all Ms are observed to be outside of their seqlock critical section.
	//
	// Note: The seqlock is mutated here and also in traceCPUSample. If you update
	// usage of the seqlock here, make sure to also look at what traceCPUSample is
	// doing.
	seq := mp.trace.seqlock.Add(1)
	if debugTraceReentrancy && seq%2 != 1 {
		throw("bad use of trace.seqlock")
	}

	// N.B. This load of gen appears redundant with the one in traceEnabled.
	// However, it's very important that the gen we use for writing to the trace
	// is acquired under a traceLocker so traceAdvance can make sure no stale
	// gen values are being used.
	//
	// Because we're doing this load again, it also means that the trace
	// might end up being disabled when we load it. In that case we need to undo
	// what we did and bail.
	gen := trace.gen.Load()
	if gen == 0 {
		mp.trace.seqlock.Add(1)
		releasem(mp)
		return traceLocker{}
	}
	return traceLocker{mp, gen}
}

// ok returns true if the traceLocker is valid (i.e. tracing is enabled).
//
// nosplit because it's called on the syscall path when stack movement is forbidden.
//
//go:nosplit
func (tl traceLocker) ok() bool {
	return tl.gen != 0
}

// traceRelease indicates that this M is done writing trace events.
//
// nosplit because it's called on the syscall path when stack movement is forbidden.
//
//go:nosplit
func traceRelease(tl traceLocker) {
	if tl.mp.trace.reentered > 0 {
		tl.mp.trace.reentered--
	} else {
		seq := tl.mp.trace.seqlock.Add(1)
		if debugTraceReentrancy && seq%2 != 0 {
			print("runtime: seq=", seq, "\n")
			throw("bad use of trace.seqlock")
		}
	}
	releasem(tl.mp)
}

// traceExitingSyscall marks a goroutine as exiting the syscall slow path.
//
// Must be paired with a traceExitedSyscall call.
func traceExitingSyscall() {
	trace.exitingSyscall.Add(1)
}

// traceExitedSyscall marks a goroutine as having exited the syscall slow path.
func traceExitedSyscall() {
	trace.exitingSyscall.Add(-1)
}

// Gomaxprocs emits a ProcsChange event.
func (tl traceLocker) Gomaxprocs(procs int32) {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvProcsChange, traceArg(procs), tl.stack(1))
}

// ProcStart traces a ProcStart event.
//
// Must be called with a valid P.
func (tl traceLocker) ProcStart() {
	pp := tl.mp.p.ptr()
	// Procs are typically started within the scheduler when there is no user goroutine. If there is a user goroutine,
	// it must be in _Gsyscall because the only time a goroutine is allowed to have its Proc moved around from under it
	// is during a syscall.
	tl.eventWriter(traceGoSyscall, traceProcIdle).event(traceEvProcStart, traceArg(pp.id), pp.trace.nextSeq(tl.gen))
}

// ProcStop traces a ProcStop event.
func (tl traceLocker) ProcStop(pp *p) {
	// The only time a goroutine is allowed to have its Proc moved around
	// from under it is during a syscall.
	tl.eventWriter(traceGoSyscall, traceProcRunning).event(traceEvProcStop)
}

// GCActive traces a GCActive event.
//
// Must be emitted by an actively running goroutine on an active P. This restriction can be changed
// easily and only depends on where it's currently called.
func (tl traceLocker) GCActive() {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCActive, traceArg(trace.seqGC))
	// N.B. Only one GC can be running at a time, so this is naturally
	// serialized by the caller.
	trace.seqGC++
}

// GCStart traces a GCBegin event.
//
// Must be emitted by an actively running goroutine on an active P. This restriction can be changed
// easily and only depends on where it's currently called.
func (tl traceLocker) GCStart() {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCBegin, traceArg(trace.seqGC), tl.stack(3))
	// N.B. Only one GC can be running at a time, so this is naturally
	// serialized by the caller.
	trace.seqGC++
}

// GCDone traces a GCEnd event.
//
// Must be emitted by an actively running goroutine on an active P. This restriction can be changed
// easily and only depends on where it's currently called.
func (tl traceLocker) GCDone() {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCEnd, traceArg(trace.seqGC))
	// N.B. Only one GC can be running at a time, so this is naturally
	// serialized by the caller.
	trace.seqGC++
}

// STWStart traces a STWBegin event.
func (tl traceLocker) STWStart(reason stwReason) {
	// Although the current P may be in _Pgcstop here, we model the P as running during the STW. This deviates from the
	// runtime's state tracking, but it's more accurate and doesn't result in any loss of information.
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvSTWBegin, tl.string(reason.String()), tl.stack(2))
}

// STWDone traces a STWEnd event.
func (tl traceLocker) STWDone() {
	// Although the current P may be in _Pgcstop here, we model the P as running during the STW. This deviates from the
	// runtime's state tracking, but it's more accurate and doesn't result in any loss of information.
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvSTWEnd)
}

// GCSweepStart prepares to trace a sweep loop. This does not
// emit any events until traceGCSweepSpan is called.
//
// GCSweepStart must be paired with traceGCSweepDone and there
// must be no preemption points between these two calls.
//
// Must be called with a valid P.
func (tl traceLocker) GCSweepStart() {
	// Delay the actual GCSweepBegin event until the first span
	// sweep. If we don't sweep anything, don't emit any events.
	pp := tl.mp.p.ptr()
	if pp.trace.maySweep {
		throw("double traceGCSweepStart")
	}
	pp.trace.maySweep, pp.trace.swept, pp.trace.reclaimed = true, 0, 0
}

// GCSweepSpan traces the sweep of a single span. If this is
// the first span swept since traceGCSweepStart was called, this
// will emit a GCSweepBegin event.
//
// This may be called outside a traceGCSweepStart/traceGCSweepDone
// pair; however, it will not emit any trace events in this case.
//
// Must be called with a valid P.
func (tl traceLocker) GCSweepSpan(bytesSwept uintptr) {
	pp := tl.mp.p.ptr()
	if pp.trace.maySweep {
		if pp.trace.swept == 0 {
			tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCSweepBegin, tl.stack(1))
			pp.trace.inSweep = true
		}
		pp.trace.swept += bytesSwept
	}
}

// GCSweepDone finishes tracing a sweep loop. If any memory was
// swept (i.e. traceGCSweepSpan emitted an event) then this will emit
// a GCSweepEnd event.
//
// Must be called with a valid P.
func (tl traceLocker) GCSweepDone() {
	pp := tl.mp.p.ptr()
	if !pp.trace.maySweep {
		throw("missing traceGCSweepStart")
	}
	if pp.trace.inSweep {
		tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCSweepEnd, traceArg(pp.trace.swept), traceArg(pp.trace.reclaimed))
		pp.trace.inSweep = false
	}
	pp.trace.maySweep = false
}

// GCMarkAssistStart emits a MarkAssistBegin event.
func (tl traceLocker) GCMarkAssistStart() {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCMarkAssistBegin, tl.stack(1))
}

// GCMarkAssistDone emits a MarkAssistEnd event.
func (tl traceLocker) GCMarkAssistDone() {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGCMarkAssistEnd)
}

// GoCreate emits a GoCreate event.
func (tl traceLocker) GoCreate(newg *g, pc uintptr, blocked bool) {
	newg.trace.setStatusTraced(tl.gen)
	ev := traceEvGoCreate
	if blocked {
		ev = traceEvGoCreateBlocked
	}
	tl.eventWriter(traceGoRunning, traceProcRunning).event(ev, traceArg(newg.goid), tl.startPC(pc), tl.stack(2))
}

// GoStart emits a GoStart event.
//
// Must be called with a valid P.
func (tl traceLocker) GoStart() {
	gp := getg().m.curg
	pp := gp.m.p
	w := tl.eventWriter(traceGoRunnable, traceProcRunning)
	w.event(traceEvGoStart, traceArg(gp.goid), gp.trace.nextSeq(tl.gen))
	if pp.ptr().gcMarkWorkerMode != gcMarkWorkerNotWorker {
		w.event(traceEvGoLabel, trace.markWorkerLabels[tl.gen%2][pp.ptr().gcMarkWorkerMode])
	}
}

// GoEnd emits a GoDestroy event.
//
// TODO(mknyszek): Rename this to GoDestroy.
func (tl traceLocker) GoEnd() {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGoDestroy)
}

// GoSched emits a GoStop event with a GoSched reason.
func (tl traceLocker) GoSched() {
	tl.GoStop(traceGoStopGoSched)
}

// GoPreempt emits a GoStop event with a GoPreempted reason.
func (tl traceLocker) GoPreempt() {
	tl.GoStop(traceGoStopPreempted)
}

// GoStop emits a GoStop event with the provided reason.
func (tl traceLocker) GoStop(reason traceGoStopReason) {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGoStop, traceArg(trace.goStopReasons[tl.gen%2][reason]), tl.stack(1))
}

// GoPark emits a GoBlock event with the provided reason.
//
// TODO(mknyszek): Replace traceBlockReason with waitReason. It's silly
// that we have both, and waitReason is way more descriptive.
func (tl traceLocker) GoPark(reason traceBlockReason, skip int) {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGoBlock, traceArg(trace.goBlockReasons[tl.gen%2][reason]), tl.stack(skip))
}

// GoUnpark emits a GoUnblock event.
func (tl traceLocker) GoUnpark(gp *g, skip int) {
	// Emit a GoWaiting status if necessary for the unblocked goroutine.
	tl.emitUnblockStatus(gp, tl.gen)
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGoUnblock, traceArg(gp.goid), gp.trace.nextSeq(tl.gen), tl.stack(skip))
}

// GoSwitch emits a GoSwitch event. If destroy is true, the calling goroutine
// is simultaneously being destroyed.
func (tl traceLocker) GoSwitch(nextg *g, destroy bool) {
	// Emit a GoWaiting status if necessary for the unblocked goroutine.
	tl.emitUnblockStatus(nextg, tl.gen)
	w := tl.eventWriter(traceGoRunning, traceProcRunning)
	ev := traceEvGoSwitch
	if destroy {
		ev = traceEvGoSwitchDestroy
	}
	w.event(ev, traceArg(nextg.goid), nextg.trace.nextSeq(tl.gen))
}

// emitUnblockStatus emits a GoStatus GoWaiting event for a goroutine about to be
// unblocked to the trace writer.
func (tl traceLocker) emitUnblockStatus(gp *g, gen uintptr) {
	if !gp.trace.statusWasTraced(gen) && gp.trace.acquireStatus(gen) {
		// TODO(go.dev/issue/65634): Although it would be nice to add a stack trace here of gp,
		// we cannot safely do so. gp is in _Gwaiting and so we don't have ownership of its stack.
		// We can fix this by acquiring the goroutine's scan bit.
		tl.writer().writeGoStatus(gp.goid, -1, traceGoWaiting, gp.inMarkAssist, 0).end()
	}
}

// GoSysCall emits a GoSyscallBegin event.
//
// Must be called with a valid P.
func (tl traceLocker) GoSysCall() {
	// Scribble down the M that the P is currently attached to.
	pp := tl.mp.p.ptr()
	pp.trace.mSyscallID = int64(tl.mp.procid)
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvGoSyscallBegin, pp.trace.nextSeq(tl.gen), tl.stack(1))
}

// GoSysExit emits a GoSyscallEnd event, possibly along with a GoSyscallBlocked event
// if lostP is true.
//
// lostP must be true in all cases that a goroutine loses its P during a syscall.
// This means it's not sufficient to check if it has no P. In particular, it needs to be
// true in the following cases:
// - The goroutine lost its P, it ran some other code, and then got it back. It's now running with that P.
// - The goroutine lost its P and was unable to reacquire it, and is now running without a P.
// - The goroutine lost its P and acquired a different one, and is now running with that P.
func (tl traceLocker) GoSysExit(lostP bool) {
	ev := traceEvGoSyscallEnd
	procStatus := traceProcSyscall // Procs implicitly enter traceProcSyscall on GoSyscallBegin.
	if lostP {
		ev = traceEvGoSyscallEndBlocked
		procStatus = traceProcRunning // If a G has a P when emitting this event, it reacquired a P and is indeed running.
	} else {
		tl.mp.p.ptr().trace.mSyscallID = -1
	}
	tl.eventWriter(traceGoSyscall, procStatus).event(ev)
}

// ProcSteal indicates that our current M stole a P from another M.
//
// inSyscall indicates that we're stealing the P from a syscall context.
//
// The caller must have ownership of pp.
func (tl traceLocker) ProcSteal(pp *p, inSyscall bool) {
	// Grab the M ID we stole from.
	mStolenFrom := pp.trace.mSyscallID
	pp.trace.mSyscallID = -1

	// Emit the status of the P we're stealing. We may be just about to do this when creating the event
	// writer but it's not guaranteed, even if inSyscall is true. Although it might seem like from a
	// syscall context we're always stealing a P for ourselves, we may have not wired it up yet (so
	// it wouldn't be visible to eventWriter) or we may not even intend to wire it up to ourselves
	// at all (e.g. entersyscall_gcwait).
	if !pp.trace.statusWasTraced(tl.gen) && pp.trace.acquireStatus(tl.gen) {
		// Careful: don't use the event writer. We never want status or in-progress events
		// to trigger more in-progress events.
		tl.writer().writeProcStatus(uint64(pp.id), traceProcSyscallAbandoned, pp.trace.inSweep).end()
	}

	// The status of the proc and goroutine, if we need to emit one here, is not evident from the
	// context of just emitting this event alone. There are two cases. Either we're trying to steal
	// the P just to get its attention (e.g. STW or sysmon retake) or we're trying to steal a P for
	// ourselves specifically to keep running. The two contexts look different, but can be summarized
	// fairly succinctly. In the former, we're a regular running goroutine and proc, if we have either.
	// In the latter, we're a goroutine in a syscall.
	goStatus := traceGoRunning
	procStatus := traceProcRunning
	if inSyscall {
		goStatus = traceGoSyscall
		procStatus = traceProcSyscallAbandoned
	}
	tl.eventWriter(goStatus, procStatus).event(traceEvProcSteal, traceArg(pp.id), pp.trace.nextSeq(tl.gen), traceArg(mStolenFrom))
}

// HeapAlloc emits a HeapAlloc event.
func (tl traceLocker) HeapAlloc(live uint64) {
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvHeapAlloc, traceArg(live))
}

// HeapGoal reads the current heap goal and emits a HeapGoal event.
func (tl traceLocker) HeapGoal() {
	heapGoal := gcController.heapGoal()
	if heapGoal == ^uint64(0) {
		// Heap-based triggering is disabled.
		heapGoal = 0
	}
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvHeapGoal, traceArg(heapGoal))
}

// GoCreateSyscall indicates that a goroutine has transitioned from dead to GoSyscall.
//
// Unlike GoCreate, the caller must be running on gp.
//
// This occurs when C code calls into Go. On pthread platforms it occurs only when
// a C thread calls into Go code for the first time.
func (tl traceLocker) GoCreateSyscall(gp *g) {
	// N.B. We should never trace a status for this goroutine (which we're currently running on),
	// since we want this to appear like goroutine creation.
	gp.trace.setStatusTraced(tl.gen)
	tl.eventWriter(traceGoBad, traceProcBad).event(traceEvGoCreateSyscall, traceArg(gp.goid))
}

// GoDestroySyscall indicates that a goroutine has transitioned from GoSyscall to dead.
//
// Must not have a P.
//
// This occurs when Go code returns back to C. On pthread platforms it occurs only when
// the C thread is destroyed.
func (tl traceLocker) GoDestroySyscall() {
	// N.B. If we trace a status here, we must never have a P, and we must be on a goroutine
	// that is in the syscall state.
	tl.eventWriter(traceGoSyscall, traceProcBad).event(traceEvGoDestroySyscall)
}

// To access runtime functions from runtime/trace.
// See runtime/trace/annotation.go

// trace_userTaskCreate emits a UserTaskCreate event.
//
//go:linkname trace_userTaskCreate runtime/trace.userTaskCreate
func trace_userTaskCreate(id, parentID uint64, taskType string) {
	tl := traceAcquire()
	if !tl.ok() {
		// Need to do this check because the caller won't have it.
		return
	}
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvUserTaskBegin, traceArg(id), traceArg(parentID), tl.string(taskType), tl.stack(3))
	traceRelease(tl)
}

// trace_userTaskEnd emits a UserTaskEnd event.
//
//go:linkname trace_userTaskEnd runtime/trace.userTaskEnd
func trace_userTaskEnd(id uint64) {
	tl := traceAcquire()
	if !tl.ok() {
		// Need to do this check because the caller won't have it.
		return
	}
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvUserTaskEnd, traceArg(id), tl.stack(2))
	traceRelease(tl)
}

// trace_userRegion emits a UserRegionBegin or UserRegionEnd event,
// depending on mode (0 == Begin, 1 == End).
//
// TODO(mknyszek): Just make this two functions.
//
//go:linkname trace_userRegion runtime/trace.userRegion
func trace_userRegion(id, mode uint64, name string) {
	tl := traceAcquire()
	if !tl.ok() {
		// Need to do this check because the caller won't have it.
		return
	}
	var ev traceEv
	switch mode {
	case 0:
		ev = traceEvUserRegionBegin
	case 1:
		ev = traceEvUserRegionEnd
	default:
		return
	}
	tl.eventWriter(traceGoRunning, traceProcRunning).event(ev, traceArg(id), tl.string(name), tl.stack(3))
	traceRelease(tl)
}

// trace_userLog emits a UserRegionBegin or UserRegionEnd event.
//
//go:linkname trace_userLog runtime/trace.userLog
func trace_userLog(id uint64, category, message string) {
	tl := traceAcquire()
	if !tl.ok() {
		// Need to do this check because the caller won't have it.
		return
	}
	tl.eventWriter(traceGoRunning, traceProcRunning).event(traceEvUserLog, traceArg(id), tl.string(category), tl.uniqueString(message), tl.stack(3))
	traceRelease(tl)
}

// traceThreadDestroy is called when a thread is removed from
// sched.freem.
//
// mp must not be able to emit trace events anymore.
//
// sched.lock must be held to synchronize with traceAdvance.
func traceThreadDestroy(mp *m) {
	assertLockHeld(&sched.lock)

	// Flush all outstanding buffers to maintain the invariant
	// that an M only has active buffers while on sched.freem
	// or allm.
	//
	// Perform a traceAcquire/traceRelease on behalf of mp to
	// synchronize with the tracer trying to flush our buffer
	// as well.
	seq := mp.trace.seqlock.Add(1)
	if debugTraceReentrancy && seq%2 != 1 {
		throw("bad use of trace.seqlock")
	}
	systemstack(func() {
		lock(&trace.lock)
		for i := range mp.trace.buf {
			for exp, buf := range mp.trace.buf[i] {
				if buf != nil {
					// N.B. traceBufFlush accepts a generation, but it
					// really just cares about gen%2.
					traceBufFlush(buf, uintptr(i))
					mp.trace.buf[i][exp] = nil
				}
			}
		}
		unlock(&trace.lock)
	})
	seq1 := mp.trace.seqlock.Add(1)
	if seq1 != seq+1 {
		print("runtime: seq1=", seq1, "\n")
		throw("bad use of trace.seqlock")
	}
}

"""



```