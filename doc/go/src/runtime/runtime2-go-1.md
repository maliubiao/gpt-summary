Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is part of `runtime2.go`. It's the *second part* of a larger file, so the summary should focus on the specific structures and constants defined here.

2. **Identify Key Data Structures:** I start by scanning the code for type definitions (`type ... struct { ... }`). These are the fundamental building blocks of the code. I identify the following key structures:

    * `lfnode`:  A lock-free stack node.
    * `forcegcstate`:  State related to forced garbage collection.
    * `_defer`: Represents a deferred function call.
    * `_panic`: Represents an active panic.
    * `savedOpenDeferState`:  Saves state for open-coded defers during panics.
    * `ancestorInfo`:  Information about a goroutine's creation history.
    * `waitReason`:  Enumerates reasons why a goroutine might be stopped.
    * `_func`:  Metadata about a function.
    * `funcinl`: Metadata for inlined functions.
    * `itab`: Interface table (defined in `abi` package).

3. **Identify Key Constants:**  Next, I look for constant declarations (`const ...`). These often define specific states, flags, or numerical values used within the data structures or the runtime. I note:

    * Signal constants (`_SigNotify`, `_SigKill`, etc.): These relate to signal handling.
    * `waitReason` constants: Enumerating the different reasons a goroutine might be waiting.

4. **Identify Global Variables:** I look for variable declarations (`var ...`). These are the shared state of the runtime. I note:

    * `allm`:  Pointer to the "all machine" structure (presumably from the first part of the file).
    * `gomaxprocs`, `ncpu`, `forcegc`, `sched`, `newprocs`: Variables related to scheduling and the number of processors.
    * `allp`, `allpLock`, `idlepMask`, `timerpMask`:  Variables related to the management of P (processor) structures.
    * `gcBgMarkWorkerPool`, `gcBgMarkWorkerCount`:  Variables related to background GC workers.
    * CPU feature variables (`processorVersionInfo`, `isIntel`).
    * `goarm`, `goarmsoftfp`: ARM architecture related flags.
    * `islibrary`, `isarchive`: Build mode flags.
    * `waitReasonStrings`:  An array mapping `waitReason` values to their string representations.
    * `isWaitingForGC`, `isIdleInSynctest`: Boolean arrays indicating specific states for `waitReason`.

5. **Identify Functions:** I look for function definitions (`func ...`). These represent the actions that can be performed. I identify:

    * `getcallerfp()`:  A function to retrieve the frame pointer of the caller's caller.
    * Methods on `waitReason` (`String()`, `isMutexWait()`, `isWaitingForGC()`, `isIdleInSynctest()`): Functions providing information about wait reasons.

6. **Group and Categorize:**  Now, I start grouping the identified elements by their purpose. I see these broad categories emerging:

    * **Goroutine State and Management:**  `_defer`, `_panic`, `ancestorInfo`, `waitReason`. These structures and constants directly relate to the lifecycle and current status of goroutines.
    * **Scheduling and Processor Management:** `allm`, `gomaxprocs`, `ncpu`, `allp`, `allpLock`, `idlepMask`, `timerpMask`. These are about how goroutines are assigned to and run on processors.
    * **Garbage Collection:** `forcegcstate`, `gcBgMarkWorkerPool`, `gcBgMarkWorkerCount`, `isWaitingForGC`.
    * **Function Metadata:** `_func`, `funcinl`. Information about functions needed for debugging, stack traces, etc.
    * **Signal Handling:** The `_Sig...` constants.
    * **Architecture and Build Details:** `processorVersionInfo`, `isIntel`, `goarm`, `goarmsoftfp`, `islibrary`, `isarchive`.
    * **Low-Level Utilities:** `lfnode`, `getcallerfp()`.

7. **Synthesize the Summary:** Based on the categorization, I formulate a concise summary of the code's functionality. I focus on the *roles* of the defined structures and variables within the Go runtime. I use terms like "defines data structures," "manages," "tracks," and "provides information about" to describe their purpose. I avoid getting too deep into the specific implementation details unless they are crucial to understanding the overall function.

8. **Review and Refine:**  I read the summary to ensure it accurately reflects the content of the code snippet. I check for clarity and conciseness. I make sure I've addressed the "second part" aspect of the prompt. I also double-check if I've missed any major functional areas.

This systematic approach allows me to break down the relatively complex code snippet into manageable parts and build a comprehensive understanding of its purpose within the larger Go runtime environment. It also helps me organize my thoughts and generate a well-structured and informative summary.
这是 `go/src/runtime/runtime2.go` 文件的一部分，主要定义了 Go 运行时系统中的核心数据结构和常量，用于管理 Goroutine、调度、内存管理、Panic 处理、信号处理等关键功能。

由于这是第二部分，我们可以推断第一部分可能定义了更基础的结构，例如 `g`（Goroutine）、`m`（Machine/OS Thread）、`p`（Processor），而这部分则在此基础上定义了更高级别的抽象和状态信息。

**归纳一下它的功能:**

这部分代码主要定义了以下方面的功能和数据结构：

1. **已退出 M 的统计信息:**  `mstats` 结构体用于跟踪已退出的操作系统线程 (M) 的相关统计信息，例如锁等待时间。

2. **信号处理相关的常量:**  定义了一系列常量 (`_SigNotify`, `_SigKill`, `_SigThrow` 等) 用于配置和控制信号的处理方式，例如是否通知 `signal.Notify`、是否直接退出或抛出 Panic 等。

3. **函数元数据:**  定义了 `_func` 和 `funcinl` 结构体，用于存储关于函数的元数据信息，例如入口地址、函数名、参数大小、源代码位置等。这些信息对于调试、profiling 和 stack trace 非常重要。 `funcinl` 用于表示内联函数的元数据。

4. **无锁栈节点:**  `lfnode` 结构体定义了一个用于构建无锁栈的数据结构，可能用于某些高并发场景下的数据管理。

5. **强制 GC 状态:**  `forcegcstate` 结构体用于控制和跟踪强制垃圾回收的状态。

6. **defer 机制:**  `_defer` 结构体定义了 `defer` 语句所调用的函数的元数据信息，包括调用的 SP 和 PC、函数指针以及链表指针，用于实现 `defer` 的后进先出执行顺序。

7. **Panic 处理:**  `_panic` 结构体用于存储 Panic 发生时的相关信息，例如 Panic 的参数、调用链信息、是否被 recover 等。`savedOpenDeferState` 用于在 open-coded defer 中保存 Panic 的状态。

8. **Goroutine 启动信息:**  `ancestorInfo` 结构体用于记录 Goroutine 的启动信息，例如启动它的 Goroutine 的调用栈和 ID，用于追踪 Goroutine 的来源。

9. **Goroutine 等待原因:**  `waitReason` 类型和相关的常量及字符串数组定义了 Goroutine 进入等待状态的各种原因，例如 IO 等待、Channel 操作、GC 等待、锁等待等。

10. **全局调度器状态:**  定义了一些全局变量，如 `allm`（所有 M 的链表头）、`gomaxprocs`（GOMAXPROCS 的值）、`ncpu`（CPU 核心数）、`forcegc`（强制 GC 状态）、`sched`（调度器状态）、`newprocs`（新的 P 的数量）等，用于维护全局的调度器状态。

11. **Processor 管理:**  定义了与 Processor (P) 管理相关的全局变量，如 `allp`（所有 P 的数组）、`allpLock`（保护 `allp` 等的互斥锁）、`idlepMask`（空闲 P 的位掩码）、`timerpMask`（可能包含定时器的 P 的位掩码）。

12. **后台 GC Worker:** 定义了与后台 GC Mark Worker 相关的变量，如 `gcBgMarkWorkerPool`（后台 GC Worker 的池）、`gcBgMarkWorkerCount`（后台 GC Worker 的数量）。

13. **CPU 特性信息:**  定义了用于存储 CPU 特性信息的变量，例如 `processorVersionInfo` 和 `isIntel`。

14. **ARM 架构相关:**  定义了 `goarm` 和 `goarmsoftfp` 变量，用于指示 ARM 架构的特性。

15. **构建模式信息:**  定义了 `islibrary` 和 `isarchive` 变量，用于指示 Go 程序的构建模式。

16. **获取调用者帧指针:**  定义了 `getcallerfp()` 函数，用于获取调用者的调用者的帧指针，这在某些底层操作中很有用。

**功能举例说明 (涉及代码推理):**

**1. defer 机制:**

假设有以下 Go 代码：

```go
package main

import "fmt"

func cleanup() {
	fmt.Println("清理资源")
}

func main() {
	defer cleanup()
	fmt.Println("主函数执行")
}
```

**推理:**

当 `main` 函数执行到 `defer cleanup()` 时，运行时系统会创建一个 `_defer` 结构体，并将 `cleanup` 函数的相关信息（例如函数指针、当前的 SP 和 PC）存储在该结构体中。然后，这个 `_defer` 结构体会被添加到当前 Goroutine 的 `_defer` 链表中。当 `main` 函数即将返回时，运行时系统会遍历该链表，并依次执行其中的 `cleanup` 函数。

**假设的 `_defer` 结构体内容 (简化):**

```
_defer {
    heap: false,
    rangefunc: false,
    sp:  // main 函数执行 defer 时的栈指针
    pc:  // defer 语句的下一条指令的地址
    fn:  cleanup, // 指向 cleanup 函数的指针
    link: nil,  // 当前是链表尾部
    // ... 其他字段
}
```

**输出:**

```
主函数执行
清理资源
```

**2. Panic 处理:**

假设有以下 Go 代码：

```go
package main

import "fmt"

func recoverFunc() {
	if r := recover(); r != nil {
		fmt.Println("捕获到 Panic:", r)
	}
}

func main() {
	defer recoverFunc()
	panic("Something went wrong!")
	fmt.Println("这行代码不会执行")
}
```

**推理:**

当 `main` 函数执行到 `panic("Something went wrong!")` 时，运行时系统会创建一个 `_panic` 结构体，并将 Panic 的参数 "Something went wrong!" 存储在该结构体中。然后，运行时系统会沿着当前的调用栈查找是否有 `defer` 注册了 `recover` 函数。在本例中，`recoverFunc` 被注册。运行时系统会执行 `recoverFunc`，`recover()` 函数会捕获到当前的 Panic 对象，并返回 Panic 的参数。

**假设的 `_panic` 结构体内容 (简化):**

```
_panic {
    argp:  // 指向 Panic 参数的指针
    arg:  "Something went wrong!",
    link: nil,
    // ... 其他字段
}
```

**输出:**

```
捕获到 Panic: Something went wrong!
```

**使用者易犯错的点 (与这部分代码直接相关的可能较少，但可以考虑 `defer` 和 `panic` 的常见误用):**

例如，在循环中使用 `defer` 可能会导致资源延迟释放，因为 `defer` 的函数调用是在函数返回时才执行的。

```go
package main

import "os"

func main() {
	for i := 0; i < 10; i++ {
		f, err := os.CreateTemp("", "example")
		if err != nil {
			panic(err)
		}
		defer f.Close() // 错误：会在循环结束后才关闭所有文件
		// ... 使用文件 f
	}
}
```

正确的做法应该是在循环内部显式地关闭文件，或者将 `defer` 放在一个内部函数中。

**总结:**

这部分 `runtime2.go` 代码是 Go 运行时系统的核心组成部分，它定义了用于管理 Goroutine 生命周期、调度、错误处理、内存管理等关键操作的数据结构和常量。理解这些结构有助于深入理解 Go 语言的运行机制。

### 提示词
```
这是路径为go/src/runtime/runtime2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
for Ms that have exited.
	totalRuntimeLockWaitTime atomic.Int64
}

// Values for the flags field of a sigTabT.
const (
	_SigNotify   = 1 << iota // let signal.Notify have signal, even if from kernel
	_SigKill                 // if signal.Notify doesn't take it, exit quietly
	_SigThrow                // if signal.Notify doesn't take it, exit loudly
	_SigPanic                // if the signal is from the kernel, panic
	_SigDefault              // if the signal isn't explicitly requested, don't monitor it
	_SigGoExit               // cause all runtime procs to exit (only used on Plan 9).
	_SigSetStack             // Don't explicitly install handler, but add SA_ONSTACK to existing libc handler
	_SigUnblock              // always unblock; see blockableSig
	_SigIgn                  // _SIG_DFL action is to ignore the signal
)

// Layout of in-memory per-function information prepared by linker
// See https://golang.org/s/go12symtab.
// Keep in sync with linker (../cmd/link/internal/ld/pcln.go:/pclntab)
// and with package debug/gosym and with symtab.go in package runtime.
type _func struct {
	sys.NotInHeap // Only in static data

	entryOff uint32 // start pc, as offset from moduledata.text/pcHeader.textStart
	nameOff  int32  // function name, as index into moduledata.funcnametab.

	args        int32  // in/out args size
	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	npcdata   uint32
	cuOffset  uint32     // runtime.cutab offset of this function's CU
	startLine int32      // line number of start of function (func keyword/TEXT directive)
	funcID    abi.FuncID // set for certain special runtime functions
	flag      abi.FuncFlag
	_         [1]byte // pad
	nfuncdata uint8   // must be last, must end on a uint32-aligned boundary

	// The end of the struct is followed immediately by two variable-length
	// arrays that reference the pcdata and funcdata locations for this
	// function.

	// pcdata contains the offset into moduledata.pctab for the start of
	// that index's table. e.g.,
	// &moduledata.pctab[_func.pcdata[_PCDATA_UnsafePoint]] is the start of
	// the unsafe point table.
	//
	// An offset of 0 indicates that there is no table.
	//
	// pcdata [npcdata]uint32

	// funcdata contains the offset past moduledata.gofunc which contains a
	// pointer to that index's funcdata. e.g.,
	// *(moduledata.gofunc +  _func.funcdata[_FUNCDATA_ArgsPointerMaps]) is
	// the argument pointer map.
	//
	// An offset of ^uint32(0) indicates that there is no entry.
	//
	// funcdata [nfuncdata]uint32
}

// Pseudo-Func that is returned for PCs that occur in inlined code.
// A *Func can be either a *_func or a *funcinl, and they are distinguished
// by the first uintptr.
//
// TODO(austin): Can we merge this with inlinedCall?
type funcinl struct {
	ones      uint32  // set to ^0 to distinguish from _func
	entry     uintptr // entry of the real (the "outermost") frame
	name      string
	file      string
	line      int32
	startLine int32
}

type itab = abi.ITab

// Lock-free stack node.
// Also known to export_test.go.
type lfnode struct {
	next    uint64
	pushcnt uintptr
}

type forcegcstate struct {
	lock mutex
	g    *g
	idle atomic.Bool
}

// A _defer holds an entry on the list of deferred calls.
// If you add a field here, add code to clear it in deferProcStack.
// This struct must match the code in cmd/compile/internal/ssagen/ssa.go:deferstruct
// and cmd/compile/internal/ssagen/ssa.go:(*state).call.
// Some defers will be allocated on the stack and some on the heap.
// All defers are logically part of the stack, so write barriers to
// initialize them are not required. All defers must be manually scanned,
// and for heap defers, marked.
type _defer struct {
	heap      bool
	rangefunc bool    // true for rangefunc list
	sp        uintptr // sp at time of defer
	pc        uintptr // pc at time of defer
	fn        func()  // can be nil for open-coded defers
	link      *_defer // next defer on G; can point to either heap or stack!

	// If rangefunc is true, *head is the head of the atomic linked list
	// during a range-over-func execution.
	head *atomic.Pointer[_defer]
}

// A _panic holds information about an active panic.
//
// A _panic value must only ever live on the stack.
//
// The argp and link fields are stack pointers, but don't need special
// handling during stack growth: because they are pointer-typed and
// _panic values only live on the stack, regular stack pointer
// adjustment takes care of them.
type _panic struct {
	argp unsafe.Pointer // pointer to arguments of deferred call run during panic; cannot move - known to liblink
	arg  any            // argument to panic
	link *_panic        // link to earlier panic

	// startPC and startSP track where _panic.start was called.
	startPC uintptr
	startSP unsafe.Pointer

	// The current stack frame that we're running deferred calls for.
	sp unsafe.Pointer
	lr uintptr
	fp unsafe.Pointer

	// retpc stores the PC where the panic should jump back to, if the
	// function last returned by _panic.next() recovers the panic.
	retpc uintptr

	// Extra state for handling open-coded defers.
	deferBitsPtr *uint8
	slotsPtr     unsafe.Pointer

	recovered   bool // whether this panic has been recovered
	goexit      bool
	deferreturn bool
}

// savedOpenDeferState tracks the extra state from _panic that's
// necessary for deferreturn to pick up where gopanic left off,
// without needing to unwind the stack.
type savedOpenDeferState struct {
	retpc           uintptr
	deferBitsOffset uintptr
	slotsOffset     uintptr
}

// ancestorInfo records details of where a goroutine was started.
type ancestorInfo struct {
	pcs  []uintptr // pcs from the stack of this goroutine
	goid uint64    // goroutine id of this goroutine; original goroutine possibly dead
	gopc uintptr   // pc of go statement that created this goroutine
}

// A waitReason explains why a goroutine has been stopped.
// See gopark. Do not re-use waitReasons, add new ones.
type waitReason uint8

const (
	waitReasonZero                  waitReason = iota // ""
	waitReasonGCAssistMarking                         // "GC assist marking"
	waitReasonIOWait                                  // "IO wait"
	waitReasonChanReceiveNilChan                      // "chan receive (nil chan)"
	waitReasonChanSendNilChan                         // "chan send (nil chan)"
	waitReasonDumpingHeap                             // "dumping heap"
	waitReasonGarbageCollection                       // "garbage collection"
	waitReasonGarbageCollectionScan                   // "garbage collection scan"
	waitReasonPanicWait                               // "panicwait"
	waitReasonSelect                                  // "select"
	waitReasonSelectNoCases                           // "select (no cases)"
	waitReasonGCAssistWait                            // "GC assist wait"
	waitReasonGCSweepWait                             // "GC sweep wait"
	waitReasonGCScavengeWait                          // "GC scavenge wait"
	waitReasonChanReceive                             // "chan receive"
	waitReasonChanSend                                // "chan send"
	waitReasonFinalizerWait                           // "finalizer wait"
	waitReasonForceGCIdle                             // "force gc (idle)"
	waitReasonSemacquire                              // "semacquire"
	waitReasonSleep                                   // "sleep"
	waitReasonSyncCondWait                            // "sync.Cond.Wait"
	waitReasonSyncMutexLock                           // "sync.Mutex.Lock"
	waitReasonSyncRWMutexRLock                        // "sync.RWMutex.RLock"
	waitReasonSyncRWMutexLock                         // "sync.RWMutex.Lock"
	waitReasonSyncWaitGroupWait                       // "sync.WaitGroup.Wait"
	waitReasonTraceReaderBlocked                      // "trace reader (blocked)"
	waitReasonWaitForGCCycle                          // "wait for GC cycle"
	waitReasonGCWorkerIdle                            // "GC worker (idle)"
	waitReasonGCWorkerActive                          // "GC worker (active)"
	waitReasonPreempted                               // "preempted"
	waitReasonDebugCall                               // "debug call"
	waitReasonGCMarkTermination                       // "GC mark termination"
	waitReasonStoppingTheWorld                        // "stopping the world"
	waitReasonFlushProcCaches                         // "flushing proc caches"
	waitReasonTraceGoroutineStatus                    // "trace goroutine status"
	waitReasonTraceProcStatus                         // "trace proc status"
	waitReasonPageTraceFlush                          // "page trace flush"
	waitReasonCoroutine                               // "coroutine"
	waitReasonGCWeakToStrongWait                      // "GC weak to strong wait"
	waitReasonSynctestRun                             // "synctest.Run"
	waitReasonSynctestWait                            // "synctest.Wait"
	waitReasonSynctestChanReceive                     // "chan receive (synctest)"
	waitReasonSynctestChanSend                        // "chan send (synctest)"
	waitReasonSynctestSelect                          // "select (synctest)"
)

var waitReasonStrings = [...]string{
	waitReasonZero:                  "",
	waitReasonGCAssistMarking:       "GC assist marking",
	waitReasonIOWait:                "IO wait",
	waitReasonChanReceiveNilChan:    "chan receive (nil chan)",
	waitReasonChanSendNilChan:       "chan send (nil chan)",
	waitReasonDumpingHeap:           "dumping heap",
	waitReasonGarbageCollection:     "garbage collection",
	waitReasonGarbageCollectionScan: "garbage collection scan",
	waitReasonPanicWait:             "panicwait",
	waitReasonSelect:                "select",
	waitReasonSelectNoCases:         "select (no cases)",
	waitReasonGCAssistWait:          "GC assist wait",
	waitReasonGCSweepWait:           "GC sweep wait",
	waitReasonGCScavengeWait:        "GC scavenge wait",
	waitReasonChanReceive:           "chan receive",
	waitReasonChanSend:              "chan send",
	waitReasonFinalizerWait:         "finalizer wait",
	waitReasonForceGCIdle:           "force gc (idle)",
	waitReasonSemacquire:            "semacquire",
	waitReasonSleep:                 "sleep",
	waitReasonSyncCondWait:          "sync.Cond.Wait",
	waitReasonSyncMutexLock:         "sync.Mutex.Lock",
	waitReasonSyncRWMutexRLock:      "sync.RWMutex.RLock",
	waitReasonSyncRWMutexLock:       "sync.RWMutex.Lock",
	waitReasonSyncWaitGroupWait:     "sync.WaitGroup.Wait",
	waitReasonTraceReaderBlocked:    "trace reader (blocked)",
	waitReasonWaitForGCCycle:        "wait for GC cycle",
	waitReasonGCWorkerIdle:          "GC worker (idle)",
	waitReasonGCWorkerActive:        "GC worker (active)",
	waitReasonPreempted:             "preempted",
	waitReasonDebugCall:             "debug call",
	waitReasonGCMarkTermination:     "GC mark termination",
	waitReasonStoppingTheWorld:      "stopping the world",
	waitReasonFlushProcCaches:       "flushing proc caches",
	waitReasonTraceGoroutineStatus:  "trace goroutine status",
	waitReasonTraceProcStatus:       "trace proc status",
	waitReasonPageTraceFlush:        "page trace flush",
	waitReasonCoroutine:             "coroutine",
	waitReasonGCWeakToStrongWait:    "GC weak to strong wait",
	waitReasonSynctestRun:           "synctest.Run",
	waitReasonSynctestWait:          "synctest.Wait",
	waitReasonSynctestChanReceive:   "chan receive (synctest)",
	waitReasonSynctestChanSend:      "chan send (synctest)",
	waitReasonSynctestSelect:        "select (synctest)",
}

func (w waitReason) String() string {
	if w < 0 || w >= waitReason(len(waitReasonStrings)) {
		return "unknown wait reason"
	}
	return waitReasonStrings[w]
}

func (w waitReason) isMutexWait() bool {
	return w == waitReasonSyncMutexLock ||
		w == waitReasonSyncRWMutexRLock ||
		w == waitReasonSyncRWMutexLock
}

func (w waitReason) isWaitingForGC() bool {
	return isWaitingForGC[w]
}

// isWaitingForGC indicates that a goroutine is only entering _Gwaiting and
// setting a waitReason because it needs to be able to let the GC take ownership
// of its stack. The G is always actually executing on the system stack, in
// these cases.
//
// TODO(mknyszek): Consider replacing this with a new dedicated G status.
var isWaitingForGC = [len(waitReasonStrings)]bool{
	waitReasonStoppingTheWorld:      true,
	waitReasonGCMarkTermination:     true,
	waitReasonGarbageCollection:     true,
	waitReasonGarbageCollectionScan: true,
	waitReasonTraceGoroutineStatus:  true,
	waitReasonTraceProcStatus:       true,
	waitReasonPageTraceFlush:        true,
	waitReasonGCAssistMarking:       true,
	waitReasonGCWorkerActive:        true,
	waitReasonFlushProcCaches:       true,
}

func (w waitReason) isIdleInSynctest() bool {
	return isIdleInSynctest[w]
}

// isIdleInSynctest indicates that a goroutine is considered idle by synctest.Wait.
var isIdleInSynctest = [len(waitReasonStrings)]bool{
	waitReasonChanReceiveNilChan:  true,
	waitReasonChanSendNilChan:     true,
	waitReasonSelectNoCases:       true,
	waitReasonSleep:               true,
	waitReasonSyncCondWait:        true,
	waitReasonSyncWaitGroupWait:   true,
	waitReasonCoroutine:           true,
	waitReasonSynctestRun:         true,
	waitReasonSynctestWait:        true,
	waitReasonSynctestChanReceive: true,
	waitReasonSynctestChanSend:    true,
	waitReasonSynctestSelect:      true,
}

var (
	allm       *m
	gomaxprocs int32
	ncpu       int32
	forcegc    forcegcstate
	sched      schedt
	newprocs   int32
)

var (
	// allpLock protects P-less reads and size changes of allp, idlepMask,
	// and timerpMask, and all writes to allp.
	allpLock mutex

	// len(allp) == gomaxprocs; may change at safe points, otherwise
	// immutable.
	allp []*p

	// Bitmask of Ps in _Pidle list, one bit per P. Reads and writes must
	// be atomic. Length may change at safe points.
	//
	// Each P must update only its own bit. In order to maintain
	// consistency, a P going idle must the idle mask simultaneously with
	// updates to the idle P list under the sched.lock, otherwise a racing
	// pidleget may clear the mask before pidleput sets the mask,
	// corrupting the bitmap.
	//
	// N.B., procresize takes ownership of all Ps in stopTheWorldWithSema.
	idlepMask pMask

	// Bitmask of Ps that may have a timer, one bit per P. Reads and writes
	// must be atomic. Length may change at safe points.
	//
	// Ideally, the timer mask would be kept immediately consistent on any timer
	// operations. Unfortunately, updating a shared global data structure in the
	// timer hot path adds too much overhead in applications frequently switching
	// between no timers and some timers.
	//
	// As a compromise, the timer mask is updated only on pidleget / pidleput. A
	// running P (returned by pidleget) may add a timer at any time, so its mask
	// must be set. An idle P (passed to pidleput) cannot add new timers while
	// idle, so if it has no timers at that time, its mask may be cleared.
	//
	// Thus, we get the following effects on timer-stealing in findrunnable:
	//
	//   - Idle Ps with no timers when they go idle are never checked in findrunnable
	//     (for work- or timer-stealing; this is the ideal case).
	//   - Running Ps must always be checked.
	//   - Idle Ps whose timers are stolen must continue to be checked until they run
	//     again, even after timer expiration.
	//
	// When the P starts running again, the mask should be set, as a timer may be
	// added at any time.
	//
	// TODO(prattmic): Additional targeted updates may improve the above cases.
	// e.g., updating the mask when stealing a timer.
	timerpMask pMask
)

// goarmsoftfp is used by runtime/cgo assembly.
//
//go:linkname goarmsoftfp

var (
	// Pool of GC parked background workers. Entries are type
	// *gcBgMarkWorkerNode.
	gcBgMarkWorkerPool lfstack

	// Total number of gcBgMarkWorker goroutines. Protected by worldsema.
	gcBgMarkWorkerCount int32

	// Information about what cpu features are available.
	// Packages outside the runtime should not use these
	// as they are not an external api.
	// Set on startup in asm_{386,amd64}.s
	processorVersionInfo uint32
	isIntel              bool
)

// set by cmd/link on arm systems
// accessed using linkname by internal/runtime/atomic.
//
// goarm should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/creativeprojects/go-selfupdate
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname goarm
var (
	goarm       uint8
	goarmsoftfp uint8
)

// Set by the linker so the runtime can determine the buildmode.
var (
	islibrary bool // -buildmode=c-shared
	isarchive bool // -buildmode=c-archive
)

// Must agree with internal/buildcfg.FramePointerEnabled.
const framepointer_enabled = GOARCH == "amd64" || GOARCH == "arm64"

// getcallerfp returns the frame pointer of the caller of the caller
// of this function.
//
//go:nosplit
//go:noinline
func getcallerfp() uintptr {
	fp := getfp() // This frame's FP.
	if fp != 0 {
		fp = *(*uintptr)(unsafe.Pointer(fp)) // The caller's FP.
		fp = *(*uintptr)(unsafe.Pointer(fp)) // The caller's caller's FP.
	}
	return fp
}
```