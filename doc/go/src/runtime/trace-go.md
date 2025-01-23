Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Understanding the Request:**

The request asks for a functional summary of the provided Go code, specifically focusing on the `go/src/runtime/trace.go` file. It also requests:

* **Core Functionality:**  What does this code *do*?
* **Go Feature Implementation:** What larger Go feature does this code contribute to?  Provide an example.
* **Code Inference/Reasoning:**  Explain any logic that isn't immediately obvious, including assumptions about inputs and outputs.
* **Command-Line Arguments:**  Describe any relevant command-line flags.
* **Common Mistakes:** Identify potential pitfalls for users.
* **Summarization:** Conclude with a concise summary of the functionality.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for keywords and patterns that suggest functionality. Some initial observations:

* **Package `runtime`:**  This immediately tells us we're dealing with low-level Go runtime functionality.
* **Comments:** The initial comments clearly state "Go execution tracer." This is a huge clue. Further comments mention capturing various events like goroutine creation, blocking, syscalls, GC, etc.
* **Data Structures:**  The `trace` struct contains fields like `reading`, `empty`, `full`, `stackTab`, `stringTab`, `cpuLogRead`, `enabled`, `gen`, `shutdown`. These suggest management of trace buffers, data storage, and control flow.
* **Functions:**  `StartTrace`, `StopTrace`, `traceAdvance`, `ReadTrace` stand out as core functions for starting, stopping, advancing, and reading traces.
* **Synchronization Primitives:**  `mutex`, `atomic.Bool`, `atomic.Uintptr`, `atomic.Int32`, `uint32` (used as semaphores), `semacquire`, `semrelease` indicate the code is dealing with concurrency and shared state.
* **`go:linkname` and `//go:systemstack`:** These are hints about internal runtime details and special function attributes.

**3. Focusing on Key Functions:**

Next, delve deeper into the most prominent functions:

* **`StartTrace()`:**  The code checks if tracing is already enabled. It initializes CPU profiling, determines the first generation, registers labels, *stops the world* (a significant action indicating synchronization), and sets the `enabled` and `gen` flags. The comments about the "problem window" and the need for `stopTheWorld` are crucial for understanding the challenges of enabling tracing safely.
* **`StopTrace()`:** This seems like a simple call to `traceAdvance(true)`.
* **`traceAdvance()`:** This is a complex function. It advances the trace to the next generation or stops it entirely. It handles flushing buffers, collects untraced goroutines, and interacts with semaphores. The detailed steps for flushing buffers and dealing with potentially stuck Ms are noteworthy.
* **`ReadTrace()`:** This function retrieves trace data. It uses a loop and a `gopark` call, suggesting it might block waiting for data. The interaction with `trace.reader` is important for ensuring only one reader.

**4. Connecting the Dots and Inferring Functionality:**

Based on the keywords, data structures, and function behavior, we can start to piece together the purpose of the code:

* **Tracing Mechanism:** This code implements a mechanism for capturing detailed execution events in a running Go program.
* **Buffer Management:**  The `traceBuf` structure and the `empty`, `full`, and `reading` lists suggest a system for allocating, filling, and consuming trace buffers.
* **Data Deduplication:** The `stackTab`, `stringTab`, and `typeTab` hint at optimizing trace data by storing unique stacks, strings, and types only once and referencing them by IDs.
* **Concurrency Control:** The use of mutexes, atomics, and semaphores is essential for managing shared state and preventing race conditions during trace operations. The concept of "generations" (`gen`) seems key for managing different phases of tracing.
* **CPU Profiling Integration:**  The `cpuLogRead` and related fields indicate integration with CPU profiling data.

**5. Relating to a Go Feature (and Providing an Example):**

The most obvious Go feature this code enables is the **execution tracer**. The `runtime/trace` package in the standard library provides the user-facing API for controlling this tracer.

A simple example demonstrates how a developer would use this:

```go
import (
	"os"
	"runtime/trace"
)

func main() {
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	trace.Start(f)
	defer trace.Stop()

	// Your Go code here
	println("Hello, tracing!")
}
```

**6. Addressing Specific Request Points:**

* **Code Inference:**  The logic around generations is a key inference point. The code handles wrapping around generations (`traceNextGen`) and uses modulo operations (`gen%2`) to manage double-buffered data structures. The flushing mechanism and the handling of potentially blocked Ms are also areas requiring careful reasoning. The assumption is that the trace reader (`ReadTrace`) consumes the buffers sequentially.
* **Command-Line Arguments:** The `-trace` flag for the `go test` command is the primary way developers interact with this functionality.
* **Common Mistakes:** Forgetting to `defer trace.Stop()` after `trace.Start()` is a likely mistake, leading to incomplete or corrupted traces. Trying to call `ReadTrace` from multiple goroutines is explicitly warned against in the code.

**7. Structuring the Answer:**

Finally, organize the gathered information into a clear and structured answer, using headings and bullet points to enhance readability. Start with the main functionality and then address the other points in the request.

**Self-Correction/Refinement:**

During the process, I might revisit earlier assumptions or interpretations. For example, initially, I might not have fully grasped the significance of the "stop the world" operation. Reading the comments carefully and understanding the potential race conditions helps to clarify this. Similarly, the role of generations and the double-buffering scheme might require further thought to understand its purpose in managing concurrent access. The error handling within `ReadTrace` (avoiding crashes despite misuse) is also a subtle but important detail.
这段代码是 Go 语言运行时（runtime）包中负责**执行跟踪（execution tracing）**功能的一部分。它的主要功能是捕获 Go 程序运行时的各种事件，并将这些事件记录下来，供后续分析和诊断使用。

更具体地说，这段代码负责：

**1. 跟踪状态管理:**

* 定义了全局的跟踪上下文 `trace` 结构体，用于存储跟踪相关的各种状态信息，例如：
    * 跟踪锁 (`lock`)，用于保护共享的跟踪数据。
    * 跟踪缓冲区管理 (`reading`, `empty`, `full`)，负责分配、使用和回收用于存储跟踪事件的缓冲区。
    * 跟踪读取器状态 (`readerGen`, `flushedGen`, `headerWritten`)，用于协调跟踪数据的写入和读取。
    * 同步信号量 (`doneSema`)，用于同步跟踪数据生成和读取的进度。
    * 数据表 (`stackTab`, `stringTab`, `typeTab`)，用于去重存储堆栈信息、字符串和类型信息，以减少跟踪数据的大小。
    * CPU  профилирование 相关的数据结构 (`cpuLogRead`, `cpuLogWrite`, `cpuSleep`, `cpuLogDone`, `cpuBuf`)，用于收集 CPU 使用率信息。
    * 跟踪读取器 goroutine 的指针 (`reader`)。
    * 预先填充的字符串 ID 映射 (`markWorkerLabels`, `goStopReasons`, `goBlockReasons`)。
    * 跟踪是否启用和是否启用内存分配释放跟踪的标志 (`enabled`, `enabledWithAllocFree`)。
    * 跟踪代数计数器 (`gen`, `lastNonZeroGen`)。
    * 跟踪是否正在关闭的标志 (`shutdown`)。
    * 正在退出系统调用的 goroutine 数量 (`exitingSyscall`)。
    * GC 序列号 (`seqGC`)。
    * 启动跟踪时的最小堆地址 (`minPageHeapAddr`)。
    * 启动跟踪前的 `debug.malloc` 的值 (`debugMalloc`)。

**2. 启动和停止跟踪:**

* `StartTrace()` 函数用于启用当前进程的跟踪功能。
    * 它会先检查是否已经启用了跟踪。
    * 它会初始化 CPU профилирование 相关的数据结构。
    * 它会计算第一个跟踪代数 (`firstGen`)。
    * 它会重置 GC 序列号和跟踪读取器状态。
    * 它会在字符串表中注册一些基本的字符串。
    * **关键步骤：它会停止整个世界 (stop-the-world, STW)**，以确保在开始跟踪时，所有 goroutine 都处于安全状态，避免在读取 goroutine 状态时发生数据不一致。这是为了解决在启用跟踪的瞬间可能发生的竞态条件。
    * 它会获取最小堆地址，重置所有 P 的系统调用 ID。
    * 它会设置 `trace.enabled` 和 `trace.gen` 来正式启动跟踪。
    * 它会等待正在退出系统调用的 goroutine 完成。
    * 它会记录一些初始信息，例如 `Gomaxprocs` 和 STW 开始事件。
    * 如果启用了内存分配释放跟踪，它会进行内存快照。
    * 它会记录堆目标值。
    * 它会为每个 P 发送 `ProcStatus` 事件。
    * 最后，它会启动世界 (start-the-world) 并启动 `traceAdvancer` goroutine。

* `StopTrace()` 函数用于停止跟踪。它实际上调用了 `traceAdvance(true)`。

* `traceAdvance(stopTrace bool)` 函数负责将跟踪推进到下一个代数，并清理当前代数的数据。如果 `stopTrace` 为 `true`，则会完全禁用跟踪。
    * 它会先获取 `traceAdvanceSema` 信号量。
    * 它会记录当前代数的频率事件 (`EvFrequency`)。
    * 它会收集所有尚未被跟踪的 goroutine 的信息，并准备发送其状态事件。
    * 如果 `stopTrace` 为 `false`，它会为下一个代数重新注册运行时 goroutine 的标签和停止/阻塞原因。
    * **关键步骤：它会再次停止整个世界**，以确保 STW 事件的一致性。
    * 它会更新跟踪代数或禁用跟踪。
    * 它会发送 `ProcsChange` 事件。
    * 如果需要，它会发送 `GCActive` 事件。
    * 它会遍历所有 m，并刷新其跟踪缓冲区。
    * 它会发送尚未被跟踪的 goroutine 的状态事件。
    * 它会读取并刷新 CPU профилирование 数据。
    * 它会刷新堆栈、类型和字符串表。
    * 它会更新 `trace.flushedGen`。
    * 如果 `stopTrace` 为 `true`，它会执行一些清理工作，例如释放缓冲区，重置标志等。
    * 它会阻塞直到跟踪读取器处理完上一代的数据。
    * 最后，它会释放 `traceAdvanceSema` 信号量，并在 `stopTrace` 为 `true` 时释放 `traceShutdownSema` 信号量并停止 `traceAdvancer`。

**3. 读取跟踪数据:**

* `ReadTrace()` 函数用于从缓冲区中读取跟踪数据。
    * 它会循环尝试从缓冲区中获取数据。
    * 如果没有数据，它会让当前的 goroutine 进入睡眠状态，等待数据到达。
    * 它使用 `trace.reader` 来确保只有一个 goroutine 可以同时读取跟踪数据。
    * 它会在首次调用时写入跟踪头信息。
    * 它会从 `trace.full` 队列中获取已满的跟踪缓冲区。
    * 如果所有数据都已读取完毕，并且跟踪已经关闭，则返回 `nil`。

**它可以推理出这是 Go 语言的** **执行跟踪 (Execution Tracing)** **功能的实现。**

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"os"
	"runtime/trace"
)

func main() {
	// 创建一个用于写入跟踪数据的文件
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

	// 一些需要被跟踪的代码
	fmt.Println("Hello, tracing!")
	for i := 0; i < 5; i++ {
		fmt.Println("Iteration:", i)
	}
}
```

**假设的输入与输出:**

* **输入:** 上述 Go 代码。
* **输出:** 一个名为 `trace.out` 的文件，其中包含了程序的执行跟踪数据。这个文件是二进制格式，需要使用 `go tool trace` 命令进行解析和可视化。

**命令行参数:**

虽然这段代码本身不直接处理命令行参数，但 Go 的 `testing` 包提供了 `-test.trace` 标志，可以方便地在测试期间启用跟踪。

```bash
go test -test.trace=trace.out
```

这将会在运行测试时生成一个名为 `trace.out` 的跟踪文件。

**使用者易犯错的点:**

* **忘记调用 `trace.Stop()`:** 如果在 `trace.Start()` 之后忘记调用 `trace.Stop()`，可能会导致跟踪数据不完整或损坏。通常应该使用 `defer` 语句来确保 `trace.Stop()` 总是被调用。
* **在多个 goroutine 中同时调用 `ReadTrace()`:**  代码中明确指出 `ReadTrace` 必须由一个 goroutine 调用。如果在多个 goroutine 中同时调用，会导致程序行为不可预测，甚至崩溃。

**功能归纳:**

这段代码是 Go 语言运行时执行跟踪功能的核心实现，它负责捕获程序运行时的各种事件，管理跟踪数据的缓冲区，并提供启动、停止和读取跟踪数据的功能。它通过精细的同步机制，包括停止世界 (stop-the-world)，来保证跟踪数据的一致性和准确性。它为开发者提供了一种强大的工具来分析和理解 Go 程序的运行行为，例如性能瓶颈、并发问题等。

### 提示词
```
这是路径为go/src/runtime/trace.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Go execution tracer.
// The tracer captures a wide range of execution events like goroutine
// creation/blocking/unblocking, syscall enter/exit/block, GC-related events,
// changes of heap size, processor start/stop, etc and writes them to a buffer
// in a compact form. A precise nanosecond-precision timestamp and a stack
// trace is captured for most events.
//
// Tracer invariants (to keep the synchronization making sense):
// - An m that has a trace buffer must be on either the allm or sched.freem lists.
// - Any trace buffer mutation must either be happening in traceAdvance or between
//   a traceAcquire and a subsequent traceRelease.
// - traceAdvance cannot return until the previous generation's buffers are all flushed.
//
// See https://go.dev/issue/60773 for a link to the full design.

package runtime

import (
	"internal/runtime/atomic"
	"unsafe"
)

// Trace state.

// trace is global tracing context.
var trace struct {
	// trace.lock must only be acquired on the system stack where
	// stack splits cannot happen while it is held.
	lock mutex

	// Trace buffer management.
	//
	// First we check the empty list for any free buffers. If not, buffers
	// are allocated directly from the OS. Once they're filled up and/or
	// flushed, they end up on the full queue for trace.gen%2.
	//
	// The trace reader takes buffers off the full list one-by-one and
	// places them into reading until they're finished being read from.
	// Then they're placed onto the empty list.
	//
	// Protected by trace.lock.
	reading       *traceBuf // buffer currently handed off to user
	empty         *traceBuf // stack of empty buffers
	full          [2]traceBufQueue
	workAvailable atomic.Bool

	// State for the trace reader goroutine.
	//
	// Protected by trace.lock.
	readerGen     atomic.Uintptr // the generation the reader is currently reading for
	flushedGen    atomic.Uintptr // the last completed generation
	headerWritten bool           // whether ReadTrace has emitted trace header

	// doneSema is used to synchronize the reader and traceAdvance. Specifically,
	// it notifies traceAdvance that the reader is done with a generation.
	// Both semaphores are 0 by default (so, acquires block). traceAdvance
	// attempts to acquire for gen%2 after flushing the last buffers for gen.
	// Meanwhile the reader releases the sema for gen%2 when it has finished
	// processing gen.
	doneSema [2]uint32

	// Trace data tables for deduplicating data going into the trace.
	// There are 2 of each: one for gen%2, one for 1-gen%2.
	stackTab  [2]traceStackTable  // maps stack traces to unique ids
	stringTab [2]traceStringTable // maps strings to unique ids
	typeTab   [2]traceTypeTable   // maps type pointers to unique ids

	// cpuLogRead accepts CPU profile samples from the signal handler where
	// they're generated. There are two profBufs here: one for gen%2, one for
	// 1-gen%2. These profBufs use a three-word header to hold the IDs of the P, G,
	// and M (respectively) that were active at the time of the sample. Because
	// profBuf uses a record with all zeros in its header to indicate overflow,
	// we make sure to make the P field always non-zero: The ID of a real P will
	// start at bit 1, and bit 0 will be set. Samples that arrive while no P is
	// running (such as near syscalls) will set the first header field to 0b10.
	// This careful handling of the first header field allows us to store ID of
	// the active G directly in the second field, even though that will be 0
	// when sampling g0.
	//
	// Initialization and teardown of these fields is protected by traceAdvanceSema.
	cpuLogRead  [2]*profBuf
	signalLock  atomic.Uint32              // protects use of the following member, only usable in signal handlers
	cpuLogWrite [2]atomic.Pointer[profBuf] // copy of cpuLogRead for use in signal handlers, set without signalLock
	cpuSleep    *wakeableSleep
	cpuLogDone  <-chan struct{}
	cpuBuf      [2]*traceBuf

	reader atomic.Pointer[g] // goroutine that called ReadTrace, or nil

	// Fast mappings from enumerations to string IDs that are prepopulated
	// in the trace.
	markWorkerLabels [2][len(gcMarkWorkerModeStrings)]traceArg
	goStopReasons    [2][len(traceGoStopReasonStrings)]traceArg
	goBlockReasons   [2][len(traceBlockReasonStrings)]traceArg

	// enabled indicates whether tracing is enabled, but it is only an optimization,
	// NOT the source of truth on whether tracing is enabled. Tracing is only truly
	// enabled if gen != 0. This is used as an optimistic fast path check.
	//
	// Transitioning this value from true -> false is easy (once gen is 0)
	// because it's OK for enabled to have a stale "true" value. traceAcquire will
	// always double-check gen.
	//
	// Transitioning this value from false -> true is harder. We need to make sure
	// this is observable as true strictly before gen != 0. To maintain this invariant
	// we only make this transition with the world stopped and use the store to gen
	// as a publication barrier.
	enabled bool

	// enabledWithAllocFree is set if debug.traceallocfree is != 0 when tracing begins.
	// It follows the same synchronization protocol as enabled.
	enabledWithAllocFree bool

	// Trace generation counter.
	gen            atomic.Uintptr
	lastNonZeroGen uintptr // last non-zero value of gen

	// shutdown is set when we are waiting for trace reader to finish after setting gen to 0
	//
	// Writes protected by trace.lock.
	shutdown atomic.Bool

	// Number of goroutines in syscall exiting slow path.
	exitingSyscall atomic.Int32

	// seqGC is the sequence counter for GC begin/end.
	//
	// Mutated only during stop-the-world.
	seqGC uint64

	// minPageHeapAddr is the minimum address of the page heap when tracing started.
	minPageHeapAddr uint64

	// debugMalloc is the value of debug.malloc before tracing began.
	debugMalloc bool
}

// Trace public API.

var (
	traceAdvanceSema  uint32 = 1
	traceShutdownSema uint32 = 1
)

// StartTrace enables tracing for the current process.
// While tracing, the data will be buffered and available via [ReadTrace].
// StartTrace returns an error if tracing is already enabled.
// Most clients should use the [runtime/trace] package or the [testing] package's
// -test.trace flag instead of calling StartTrace directly.
func StartTrace() error {
	if traceEnabled() || traceShuttingDown() {
		return errorString("tracing is already enabled")
	}
	// Block until cleanup of the last trace is done.
	semacquire(&traceShutdownSema)
	semrelease(&traceShutdownSema)

	// Hold traceAdvanceSema across trace start, since we'll want it on
	// the other side of tracing being enabled globally.
	semacquire(&traceAdvanceSema)

	// Initialize CPU profile -> trace ingestion.
	traceInitReadCPU()

	// Compute the first generation for this StartTrace.
	//
	// Note: we start from the last non-zero generation rather than 1 so we
	// can avoid resetting all the arrays indexed by gen%2 or gen%3. There's
	// more than one of each per m, p, and goroutine.
	firstGen := traceNextGen(trace.lastNonZeroGen)

	// Reset GC sequencer.
	trace.seqGC = 1

	// Reset trace reader state.
	trace.headerWritten = false
	trace.readerGen.Store(firstGen)
	trace.flushedGen.Store(0)

	// Register some basic strings in the string tables.
	traceRegisterLabelsAndReasons(firstGen)

	// Stop the world.
	//
	// The purpose of stopping the world is to make sure that no goroutine is in a
	// context where it could emit an event by bringing all goroutines to a safe point
	// with no opportunity to transition.
	//
	// The exception to this rule are goroutines that are concurrently exiting a syscall.
	// Those will all be forced into the syscalling slow path, and we'll just make sure
	// that we don't observe any goroutines in that critical section before starting
	// the world again.
	//
	// A good follow-up question to this is why stopping the world is necessary at all
	// given that we have traceAcquire and traceRelease. Unfortunately, those only help
	// us when tracing is already active (for performance, so when tracing is off the
	// tracing seqlock is left untouched). The main issue here is subtle: we're going to
	// want to obtain a correct starting status for each goroutine, but there are windows
	// of time in which we could read and emit an incorrect status. Specifically:
	//
	//	trace := traceAcquire()
	//  // <----> problem window
	//	casgstatus(gp, _Gwaiting, _Grunnable)
	//	if trace.ok() {
	//		trace.GoUnpark(gp, 2)
	//		traceRelease(trace)
	//	}
	//
	// More precisely, if we readgstatus for a gp while another goroutine is in the problem
	// window and that goroutine didn't observe that tracing had begun, then we might write
	// a GoStatus(GoWaiting) event for that goroutine, but it won't trace an event marking
	// the transition from GoWaiting to GoRunnable. The trace will then be broken, because
	// future events will be emitted assuming the tracer sees GoRunnable.
	//
	// In short, what we really need here is to make sure that the next time *any goroutine*
	// hits a traceAcquire, it sees that the trace is enabled.
	//
	// Note also that stopping the world is necessary to make sure sweep-related events are
	// coherent. Since the world is stopped and sweeps are non-preemptible, we can never start
	// the world and see an unpaired sweep 'end' event. Other parts of the tracer rely on this.
	stw := stopTheWorld(stwStartTrace)

	// Prevent sysmon from running any code that could generate events.
	lock(&sched.sysmonlock)

	// Grab the minimum page heap address. All Ps are stopped, so it's safe to read this since
	// nothing can allocate heap memory.
	trace.minPageHeapAddr = uint64(mheap_.pages.inUse.ranges[0].base.addr())

	// Reset mSyscallID on all Ps while we have them stationary and the trace is disabled.
	for _, pp := range allp {
		pp.trace.mSyscallID = -1
	}

	// Start tracing.
	//
	// Set trace.enabled. This is *very* subtle. We need to maintain the invariant that if
	// trace.gen != 0, then trace.enabled is always observed as true. Simultaneously, for
	// performance, we need trace.enabled to be read without any synchronization.
	//
	// We ensure this is safe by stopping the world, which acts a global barrier on almost
	// every M, and explicitly synchronize with any other Ms that could be running concurrently
	// with us. Today, there are only two such cases:
	// - sysmon, which we synchronized with by acquiring sysmonlock.
	// - goroutines exiting syscalls, which we synchronize with via trace.exitingSyscall.
	//
	// After trace.gen is updated, other Ms may start creating trace buffers and emitting
	// data into them.
	trace.enabled = true
	if debug.traceallocfree.Load() != 0 {
		// Enable memory events since the GODEBUG is set.
		trace.debugMalloc = debug.malloc
		trace.enabledWithAllocFree = true
		debug.malloc = true
	}
	trace.gen.Store(firstGen)

	// Wait for exitingSyscall to drain.
	//
	// It may not monotonically decrease to zero, but in the limit it will always become
	// zero because the world is stopped and there are no available Ps for syscall-exited
	// goroutines to run on.
	//
	// Because we set gen before checking this, and because exitingSyscall is always incremented
	// *before* traceAcquire (which checks gen), we can be certain that when exitingSyscall is zero
	// that any goroutine that goes to exit a syscall from then on *must* observe the new gen as
	// well as trace.enabled being set to true.
	//
	// The critical section on each goroutine here is going to be quite short, so the likelihood
	// that we observe a zero value is high.
	for trace.exitingSyscall.Load() != 0 {
		osyield()
	}

	// Record some initial pieces of information.
	//
	// N.B. This will also emit a status event for this goroutine.
	tl := traceAcquire()
	tl.Gomaxprocs(gomaxprocs)  // Get this as early in the trace as possible. See comment in traceAdvance.
	tl.STWStart(stwStartTrace) // We didn't trace this above, so trace it now.

	// Record the fact that a GC is active, if applicable.
	if gcphase == _GCmark || gcphase == _GCmarktermination {
		tl.GCActive()
	}

	// Dump a snapshot of memory, if enabled.
	if trace.enabledWithAllocFree {
		traceSnapshotMemory(firstGen)
	}

	// Record the heap goal so we have it at the very beginning of the trace.
	tl.HeapGoal()

	// Make sure a ProcStatus is emitted for every P, while we're here.
	for _, pp := range allp {
		tl.writer().writeProcStatusForP(pp, pp == tl.mp.p.ptr()).end()
	}
	traceRelease(tl)

	unlock(&sched.sysmonlock)
	startTheWorld(stw)

	traceStartReadCPU()
	traceAdvancer.start()

	semrelease(&traceAdvanceSema)
	return nil
}

// StopTrace stops tracing, if it was previously enabled.
// StopTrace only returns after all the reads for the trace have completed.
func StopTrace() {
	traceAdvance(true)
}

// traceAdvance moves tracing to the next generation, and cleans up the current generation,
// ensuring that it's flushed out before returning. If stopTrace is true, it disables tracing
// altogether instead of advancing to the next generation.
//
// traceAdvanceSema must not be held.
//
// traceAdvance is called by golang.org/x/exp/trace using linkname.
//
//go:linkname traceAdvance
func traceAdvance(stopTrace bool) {
	semacquire(&traceAdvanceSema)

	// Get the gen that we're advancing from. In this function we don't really care much
	// about the generation we're advancing _into_ since we'll do all the cleanup in this
	// generation for the next advancement.
	gen := trace.gen.Load()
	if gen == 0 {
		// We may end up here traceAdvance is called concurrently with StopTrace.
		semrelease(&traceAdvanceSema)
		return
	}

	// Write an EvFrequency event for this generation.
	//
	// N.B. This may block for quite a while to get a good frequency estimate, so make sure we do
	// this here and not e.g. on the trace reader.
	traceFrequency(gen)

	// Collect all the untraced Gs.
	type untracedG struct {
		gp           *g
		goid         uint64
		mid          int64
		stackID      uint64
		status       uint32
		waitreason   waitReason
		inMarkAssist bool
	}
	var untracedGs []untracedG
	forEachGRace(func(gp *g) {
		// Make absolutely sure all Gs are ready for the next
		// generation. We need to do this even for dead Gs because
		// they may come alive with a new identity, and its status
		// traced bookkeeping might end up being stale.
		// We may miss totally new goroutines, but they'll always
		// have clean bookkeeping.
		gp.trace.readyNextGen(gen)
		// If the status was traced, nothing else to do.
		if gp.trace.statusWasTraced(gen) {
			return
		}
		// Scribble down information about this goroutine.
		ug := untracedG{gp: gp, mid: -1}
		systemstack(func() {
			me := getg().m.curg
			// We don't have to handle this G status transition because we
			// already eliminated ourselves from consideration above.
			casGToWaitingForGC(me, _Grunning, waitReasonTraceGoroutineStatus)
			// We need to suspend and take ownership of the G to safely read its
			// goid. Note that we can't actually emit the event at this point
			// because we might stop the G in a window where it's unsafe to write
			// events based on the G's status. We need the global trace buffer flush
			// coming up to make sure we're not racing with the G.
			//
			// It should be very unlikely that we try to preempt a running G here.
			// The only situation that we might is that we're racing with a G
			// that's running for the first time in this generation. Therefore,
			// this should be relatively fast.
			s := suspendG(gp)
			if !s.dead {
				ug.goid = s.g.goid
				if s.g.m != nil {
					ug.mid = int64(s.g.m.procid)
				}
				ug.status = readgstatus(s.g) &^ _Gscan
				ug.waitreason = s.g.waitreason
				ug.inMarkAssist = s.g.inMarkAssist
				ug.stackID = traceStack(0, gp, gen)
			}
			resumeG(s)
			casgstatus(me, _Gwaiting, _Grunning)
		})
		if ug.goid != 0 {
			untracedGs = append(untracedGs, ug)
		}
	})

	if !stopTrace {
		// Re-register runtime goroutine labels and stop/block reasons.
		traceRegisterLabelsAndReasons(traceNextGen(gen))
	}

	// Now that we've done some of the heavy stuff, prevent the world from stopping.
	// This is necessary to ensure the consistency of the STW events. If we're feeling
	// adventurous we could lift this restriction and add a STWActive event, but the
	// cost of maintaining this consistency is low. We're not going to hold this semaphore
	// for very long and most STW periods are very short.
	// Once we hold worldsema, prevent preemption as well so we're not interrupted partway
	// through this. We want to get this done as soon as possible.
	semacquire(&worldsema)
	mp := acquirem()

	// Advance the generation or stop the trace.
	trace.lastNonZeroGen = gen
	if stopTrace {
		systemstack(func() {
			// Ordering is important here. Set shutdown first, then disable tracing,
			// so that conditions like (traceEnabled() || traceShuttingDown()) have
			// no opportunity to be false. Hold the trace lock so this update appears
			// atomic to the trace reader.
			lock(&trace.lock)
			trace.shutdown.Store(true)
			trace.gen.Store(0)
			unlock(&trace.lock)

			// Clear trace.enabled. It is totally OK for this value to be stale,
			// because traceAcquire will always double-check gen.
			trace.enabled = false
		})
	} else {
		trace.gen.Store(traceNextGen(gen))
	}

	// Emit a ProcsChange event so we have one on record for each generation.
	// Let's emit it as soon as possible so that downstream tools can rely on the value
	// being there fairly soon in a generation.
	//
	// It's important that we do this before allowing stop-the-worlds again,
	// because the procs count could change.
	if !stopTrace {
		tl := traceAcquire()
		tl.Gomaxprocs(gomaxprocs)
		traceRelease(tl)
	}

	// Emit a GCActive event in the new generation if necessary.
	//
	// It's important that we do this before allowing stop-the-worlds again,
	// because that could emit global GC-related events.
	if !stopTrace && (gcphase == _GCmark || gcphase == _GCmarktermination) {
		tl := traceAcquire()
		tl.GCActive()
		traceRelease(tl)
	}

	// Preemption is OK again after this. If the world stops or whatever it's fine.
	// We're just cleaning up the last generation after this point.
	//
	// We also don't care if the GC starts again after this for the same reasons.
	releasem(mp)
	semrelease(&worldsema)

	// Snapshot allm and freem.
	//
	// Snapshotting after the generation counter update is sufficient.
	// Because an m must be on either allm or sched.freem if it has an active trace
	// buffer, new threads added to allm after this point must necessarily observe
	// the new generation number (sched.lock acts as a barrier).
	//
	// Threads that exit before this point and are on neither list explicitly
	// flush their own buffers in traceThreadDestroy.
	//
	// Snapshotting freem is necessary because Ms can continue to emit events
	// while they're still on that list. Removal from sched.freem is serialized with
	// this snapshot, so either we'll capture an m on sched.freem and race with
	// the removal to flush its buffers (resolved by traceThreadDestroy acquiring
	// the thread's seqlock, which one of us must win, so at least its old gen buffer
	// will be flushed in time for the new generation) or it will have flushed its
	// buffers before we snapshotted it to begin with.
	lock(&sched.lock)
	mToFlush := allm
	for mp := mToFlush; mp != nil; mp = mp.alllink {
		mp.trace.link = mp.alllink
	}
	for mp := sched.freem; mp != nil; mp = mp.freelink {
		mp.trace.link = mToFlush
		mToFlush = mp
	}
	unlock(&sched.lock)

	// Iterate over our snapshot, flushing every buffer until we're done.
	//
	// Because trace writers read the generation while the seqlock is
	// held, we can be certain that when there are no writers there are
	// also no stale generation values left. Therefore, it's safe to flush
	// any buffers that remain in that generation's slot.
	const debugDeadlock = false
	systemstack(func() {
		// Track iterations for some rudimentary deadlock detection.
		i := 0
		detectedDeadlock := false

		for mToFlush != nil {
			prev := &mToFlush
			for mp := *prev; mp != nil; {
				if mp.trace.seqlock.Load()%2 != 0 {
					// The M is writing. Come back to it later.
					prev = &mp.trace.link
					mp = mp.trace.link
					continue
				}
				// Flush the trace buffer.
				//
				// trace.lock needed for traceBufFlush, but also to synchronize
				// with traceThreadDestroy, which flushes both buffers unconditionally.
				lock(&trace.lock)
				for exp, buf := range mp.trace.buf[gen%2] {
					if buf != nil {
						traceBufFlush(buf, gen)
						mp.trace.buf[gen%2][exp] = nil
					}
				}
				unlock(&trace.lock)

				// Remove the m from the flush list.
				*prev = mp.trace.link
				mp.trace.link = nil
				mp = *prev
			}
			// Yield only if we're going to be going around the loop again.
			if mToFlush != nil {
				osyield()
			}

			if debugDeadlock {
				// Try to detect a deadlock. We probably shouldn't loop here
				// this many times.
				if i > 100000 && !detectedDeadlock {
					detectedDeadlock = true
					println("runtime: failing to flush")
					for mp := mToFlush; mp != nil; mp = mp.trace.link {
						print("runtime: m=", mp.id, "\n")
					}
				}
				i++
			}
		}
	})

	// At this point, the old generation is fully flushed minus stack and string
	// tables, CPU samples, and goroutines that haven't run at all during the last
	// generation.

	// Check to see if any Gs still haven't had events written out for them.
	statusWriter := unsafeTraceWriter(gen, nil)
	for _, ug := range untracedGs {
		if ug.gp.trace.statusWasTraced(gen) {
			// It was traced, we don't need to do anything.
			continue
		}
		// It still wasn't traced. Because we ensured all Ms stopped writing trace
		// events to the last generation, that must mean the G never had its status
		// traced in gen between when we recorded it and now. If that's true, the goid
		// and status we recorded then is exactly what we want right now.
		status := goStatusToTraceGoStatus(ug.status, ug.waitreason)
		statusWriter = statusWriter.writeGoStatus(ug.goid, ug.mid, status, ug.inMarkAssist, ug.stackID)
	}
	statusWriter.flush().end()

	// Read everything out of the last gen's CPU profile buffer.
	traceReadCPU(gen)

	// Flush CPU samples, stacks, and strings for the last generation. This is safe,
	// because we're now certain no M is writing to the last generation.
	//
	// Ordering is important here. traceCPUFlush may generate new stacks and dumping
	// stacks may generate new strings.
	traceCPUFlush(gen)
	trace.stackTab[gen%2].dump(gen)
	trace.typeTab[gen%2].dump(gen)
	trace.stringTab[gen%2].reset(gen)

	// That's it. This generation is done producing buffers.
	systemstack(func() {
		lock(&trace.lock)
		trace.flushedGen.Store(gen)
		unlock(&trace.lock)
	})

	// Perform status reset on dead Ps because they just appear as idle.
	//
	// Preventing preemption is sufficient to access allp safely. allp is only
	// mutated by GOMAXPROCS calls, which require a STW.
	//
	// TODO(mknyszek): Consider explicitly emitting ProcCreate and ProcDestroy
	// events to indicate whether a P exists, rather than just making its
	// existence implicit.
	mp = acquirem()
	for _, pp := range allp[len(allp):cap(allp)] {
		pp.trace.readyNextGen(traceNextGen(gen))
	}
	releasem(mp)

	if stopTrace {
		// Acquire the shutdown sema to begin the shutdown process.
		semacquire(&traceShutdownSema)

		// Finish off CPU profile reading.
		traceStopReadCPU()

		// Reset debug.malloc if necessary. Note that this is set in a racy
		// way; that's OK. Some mallocs may still enter into the debug.malloc
		// block, but they won't generate events because tracing is disabled.
		// That is, it's OK if mallocs read a stale debug.malloc or
		// trace.enabledWithAllocFree value.
		if trace.enabledWithAllocFree {
			trace.enabledWithAllocFree = false
			debug.malloc = trace.debugMalloc
		}
	} else {
		// Go over each P and emit a status event for it if necessary.
		//
		// We do this at the beginning of the new generation instead of the
		// end like we do for goroutines because forEachP doesn't give us a
		// hook to skip Ps that have already been traced. Since we have to
		// preempt all Ps anyway, might as well stay consistent with StartTrace
		// which does this during the STW.
		semacquire(&worldsema)
		forEachP(waitReasonTraceProcStatus, func(pp *p) {
			tl := traceAcquire()
			if !pp.trace.statusWasTraced(tl.gen) {
				tl.writer().writeProcStatusForP(pp, false).end()
			}
			traceRelease(tl)
		})
		semrelease(&worldsema)
	}

	// Block until the trace reader has finished processing the last generation.
	semacquire(&trace.doneSema[gen%2])
	if raceenabled {
		raceacquire(unsafe.Pointer(&trace.doneSema[gen%2]))
	}

	// Double-check that things look as we expect after advancing and perform some
	// final cleanup if the trace has fully stopped.
	systemstack(func() {
		lock(&trace.lock)
		if !trace.full[gen%2].empty() {
			throw("trace: non-empty full trace buffer for done generation")
		}
		if stopTrace {
			if !trace.full[1-(gen%2)].empty() {
				throw("trace: non-empty full trace buffer for next generation")
			}
			if trace.reading != nil || trace.reader.Load() != nil {
				throw("trace: reading after shutdown")
			}
			// Free all the empty buffers.
			for trace.empty != nil {
				buf := trace.empty
				trace.empty = buf.link
				sysFree(unsafe.Pointer(buf), unsafe.Sizeof(*buf), &memstats.other_sys)
			}
			// Clear trace.shutdown and other flags.
			trace.headerWritten = false
			trace.shutdown.Store(false)
		}
		unlock(&trace.lock)
	})

	if stopTrace {
		// Clear the sweep state on every P for the next time tracing is enabled.
		//
		// It may be stale in the next trace because we may have ended tracing in
		// the middle of a sweep on a P.
		//
		// It's fine not to call forEachP here because tracing is disabled and we
		// know at this point that nothing is calling into the tracer, but we do
		// need to look at dead Ps too just because GOMAXPROCS could have been called
		// at any point since we stopped tracing, and we have to ensure there's no
		// bad state on dead Ps too. Prevent a STW and a concurrent GOMAXPROCS that
		// might mutate allp by making ourselves briefly non-preemptible.
		mp := acquirem()
		for _, pp := range allp[:cap(allp)] {
			pp.trace.inSweep = false
			pp.trace.maySweep = false
			pp.trace.swept = 0
			pp.trace.reclaimed = 0
		}
		releasem(mp)
	}

	// Release the advance semaphore. If stopTrace is true we're still holding onto
	// traceShutdownSema.
	//
	// Do a direct handoff. Don't let one caller of traceAdvance starve
	// other calls to traceAdvance.
	semrelease1(&traceAdvanceSema, true, 0)

	if stopTrace {
		// Stop the traceAdvancer. We can't be holding traceAdvanceSema here because
		// we'll deadlock (we're blocked on the advancer goroutine exiting, but it
		// may be currently trying to acquire traceAdvanceSema).
		traceAdvancer.stop()
		semrelease(&traceShutdownSema)
	}
}

func traceNextGen(gen uintptr) uintptr {
	if gen == ^uintptr(0) {
		// gen is used both %2 and %3 and we want both patterns to continue when we loop around.
		// ^uint32(0) and ^uint64(0) are both odd and multiples of 3. Therefore the next generation
		// we want is even and one more than a multiple of 3. The smallest such number is 4.
		return 4
	}
	return gen + 1
}

// traceRegisterLabelsAndReasons re-registers mark worker labels and
// goroutine stop/block reasons in the string table for the provided
// generation. Note: the provided generation must not have started yet.
func traceRegisterLabelsAndReasons(gen uintptr) {
	for i, label := range gcMarkWorkerModeStrings[:] {
		trace.markWorkerLabels[gen%2][i] = traceArg(trace.stringTab[gen%2].put(gen, label))
	}
	for i, str := range traceBlockReasonStrings[:] {
		trace.goBlockReasons[gen%2][i] = traceArg(trace.stringTab[gen%2].put(gen, str))
	}
	for i, str := range traceGoStopReasonStrings[:] {
		trace.goStopReasons[gen%2][i] = traceArg(trace.stringTab[gen%2].put(gen, str))
	}
}

// ReadTrace returns the next chunk of binary tracing data, blocking until data
// is available. If tracing is turned off and all the data accumulated while it
// was on has been returned, ReadTrace returns nil. The caller must copy the
// returned data before calling ReadTrace again.
// ReadTrace must be called from one goroutine at a time.
func ReadTrace() []byte {
top:
	var buf []byte
	var park bool
	systemstack(func() {
		buf, park = readTrace0()
	})
	if park {
		gopark(func(gp *g, _ unsafe.Pointer) bool {
			if !trace.reader.CompareAndSwapNoWB(nil, gp) {
				// We're racing with another reader.
				// Wake up and handle this case.
				return false
			}

			if g2 := traceReader(); gp == g2 {
				// New data arrived between unlocking
				// and the CAS and we won the wake-up
				// race, so wake up directly.
				return false
			} else if g2 != nil {
				printlock()
				println("runtime: got trace reader", g2, g2.goid)
				throw("unexpected trace reader")
			}

			return true
		}, nil, waitReasonTraceReaderBlocked, traceBlockSystemGoroutine, 2)
		goto top
	}

	return buf
}

// readTrace0 is ReadTrace's continuation on g0. This must run on the
// system stack because it acquires trace.lock.
//
//go:systemstack
func readTrace0() (buf []byte, park bool) {
	if raceenabled {
		// g0 doesn't have a race context. Borrow the user G's.
		if getg().racectx != 0 {
			throw("expected racectx == 0")
		}
		getg().racectx = getg().m.curg.racectx
		// (This defer should get open-coded, which is safe on
		// the system stack.)
		defer func() { getg().racectx = 0 }()
	}

	// This function must not allocate while holding trace.lock:
	// allocation can call heap allocate, which will try to emit a trace
	// event while holding heap lock.
	lock(&trace.lock)

	if trace.reader.Load() != nil {
		// More than one goroutine reads trace. This is bad.
		// But we rather do not crash the program because of tracing,
		// because tracing can be enabled at runtime on prod servers.
		unlock(&trace.lock)
		println("runtime: ReadTrace called from multiple goroutines simultaneously")
		return nil, false
	}
	// Recycle the old buffer.
	if buf := trace.reading; buf != nil {
		buf.link = trace.empty
		trace.empty = buf
		trace.reading = nil
	}
	// Write trace header.
	if !trace.headerWritten {
		trace.headerWritten = true
		unlock(&trace.lock)
		return []byte("go 1.23 trace\x00\x00\x00"), false
	}

	// Read the next buffer.

	if trace.readerGen.Load() == 0 {
		trace.readerGen.Store(1)
	}
	var gen uintptr
	for {
		assertLockHeld(&trace.lock)
		gen = trace.readerGen.Load()

		// Check to see if we need to block for more data in this generation
		// or if we need to move our generation forward.
		if !trace.full[gen%2].empty() {
			break
		}
		// Most of the time readerGen is one generation ahead of flushedGen, as the
		// current generation is being read from. Then, once the last buffer is flushed
		// into readerGen, flushedGen will rise to meet it. At this point, the tracer
		// is waiting on the reader to finish flushing the last generation so that it
		// can continue to advance.
		if trace.flushedGen.Load() == gen {
			if trace.shutdown.Load() {
				unlock(&trace.lock)

				// Wake up anyone waiting for us to be done with this generation.
				//
				// Do this after reading trace.shutdown, because the thread we're
				// waking up is going to clear trace.shutdown.
				if raceenabled {
					// Model synchronization on trace.doneSema, which te race
					// detector does not see. This is required to avoid false
					// race reports on writer passed to trace.Start.
					racerelease(unsafe.Pointer(&trace.doneSema[gen%2]))
				}
				semrelease(&trace.doneSema[gen%2])

				// We're shutting down, and the last generation is fully
				// read. We're done.
				return nil, false
			}
			// The previous gen has had all of its buffers flushed, and
			// there's nothing else for us to read. Advance the generation
			// we're reading from and try again.
			trace.readerGen.Store(trace.gen.Load())
			unlock(&trace.lock)

			// Wake up anyone waiting for us to be done with this generation.
			//
			// Do this after reading gen to make sure we can't have the trace
			// advance until we've read it.
			if raceenabled {
				// See comment above in the shutdown case.
				racerelease(unsafe.Pointer(&trace.doneSema[gen%2]))
			}
			semrelease(&trace.doneSema[gen%2])

			// Reacquire the lock and go back to the top of the loop.
			lock(&trace.lock)
			continue
		}
		// Wait for new data.
		//
		// We don't simply use a note because the scheduler
		// executes this goroutine directl
```