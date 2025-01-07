Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionalities of the provided Go code snippet, which is specifically from `go/src/runtime/export_test.go`. The key here is "export_test.go", indicating it's for *internal testing* of the `runtime` package.

2. **Initial Scan for Clues:** I'll quickly scan the code for keywords and patterns that suggest its purpose:
    * Variable declarations with uppercase names (e.g., `Fadd64`, `Entersyscall`). This strongly suggests these are exporting internal functions/variables for testing.
    * Function definitions that seem to wrap or directly call internal `runtime` functions (e.g., `LFStackPush` calling `(*lfstack)(head).push(...)`).
    * Constants with names implying testing or internal details (e.g., `CrashStackImplemented`, `TracebackInnerFrames`).
    * Type definitions that shadow internal `runtime` types (e.g., `TimeTimer`, `LockRank`).
    * Function names ending in "Test" (e.g., `RunSchedLocalQueueTest`). This clearly indicates testing functionality.

3. **Categorize Functionalities:** Based on the scan, I can start grouping the exposed elements into categories:

    * **Exposing Internal Functions:**  Many variables are assigned to internal `runtime` functions. This allows test code outside the `runtime` package to call these internal functions. Examples: Floating-point operations (`Fadd64`, etc.), syscall handling (`Entersyscall`, `Exitsyscall`), atomic operations (`Xadduintptr`).

    * **Exposing Internal Variables:**  Some variables are pointers to internal `runtime` variables. This allows test code to inspect or modify (carefully!) the internal state. Example: `ReadRandomFailed`.

    * **Exposing Internal Constants:**  Constants are directly exported, providing access to internal configuration or flags. Examples: `CrashStackImplemented`, `TracebackInnerFrames`.

    * **Exposing Internal Types:**  Type aliases or new types based on internal `runtime` types are defined. This allows test code to work with these internal structures. Examples: `TimeTimer`, `LockRank`.

    * **Helper Functions for Internal Structures:** Functions that operate on internal data structures (like lock-free stacks or run queues) are exposed. Examples: `LFStackPush`, `LFStackPop`, `RunSchedLocalQueueTest`, `RunSchedLocalQueueStealTest`.

    * **Low-Level System Interaction:**  Functions related to interacting with the OS or hardware are exposed. Examples: `Nanotime`, `Usleep`, `PhysPageSize`.

    * **Memory Management Details:**  Functions and types related to memory management (allocation, deallocation, garbage collection) are exposed. Examples: `Memmove`, `MemclrNoHeapPointers`, `CountPagesInUse`, `ReadMemStatsSlow`, `PageAlloc`, `PallocData`.

    * **Hashing Functions:**  Internal hash functions are exposed. Examples: `StringHash`, `BytesHash`.

    * **String Conversion:** Functions for converting to/from Go strings. Example: `GostringW`.

    * **Environment Variables:** Access to environment variables. Examples: `Envs`, `SetEnvs`.

    * **Goroutine and Scheduler Internals:** Functions to inspect or manipulate goroutine state and the scheduler. Examples: `Getg`, `Goid`, `GIsWaitingOnMutex`.

    * **Panic and Stack Handling:** Functions related to panic handling and stack manipulation. Examples: `PanicForTesting`, `ShrinkStackAndVerifyFramePointers`.

    * **Synchronization Primitives:** Access to internal implementations of mutexes and semaphores. Examples: `RWMutex`, `Lock`, `Unlock`, `Semacquire`, `Semrelease1`.

    * **Profiling and Metrics:** Functions for accessing internal profiling buffers and runtime metrics. Examples: `NewProfBuf`, `ReadCPUStats`, `ReadMetricsSlow`.

4. **Synthesize the Core Functionality:** Based on the categorized functionalities, I can now formulate a concise summary. The primary purpose of `export_test.go` is to **expose internal components of the `runtime` package for testing**. This allows for fine-grained testing of low-level functionality that wouldn't be accessible through the standard Go API.

5. **Address Specific Requests:**  The prompt also asks about:

    * **Go Language Feature:**  The main feature being tested is the **Go runtime** itself. The examples provided in the code illustrate testing various aspects of the runtime.

    * **Code Examples:**  The code *itself* contains examples of how these exposed functionalities are used *within the test file*. I would pick a few representative examples (like the `LFStackPush`/`LFStackPop` or the run queue tests) to illustrate this.

    * **Assumptions, Inputs, and Outputs:** For the code examples, I'd make reasonable assumptions about the initial state and show the expected outcome.

    * **Command-Line Arguments:**  This file itself doesn't process command-line arguments. The tests that *use* these exposed functionalities might, but that's outside the scope of this file. So, the answer is that it doesn't directly handle command-line arguments.

    * **Common Mistakes:**  The primary risk with using these exposed functions is breaking internal runtime invariants or causing unexpected side effects. I'd give an example of incorrect usage, like directly manipulating internal data structures without understanding the consequences.

6. **Structure the Answer:** I'd organize the answer logically, starting with the main purpose, then elaborating on the different categories of exposed functionality, providing code examples where appropriate, and finally addressing the specific points in the prompt. Using clear headings and bullet points helps with readability.

7. **Refine and Review:**  Finally, I'd review the answer for clarity, accuracy, and completeness, ensuring it addresses all parts of the request.

By following these steps, I can dissect the code, understand its purpose, and generate a comprehensive and informative answer like the example you provided. The key is to recognize the "export_test" convention and then analyze the code through that lens.
这是一个 Go 语言运行时（runtime）包中的测试辅助文件 `export_test.go` 的一部分。它的主要功能是：

**功能归纳：**

这个文件的主要目的是**将 `runtime` 包内部的私有函数、变量、常量和类型暴露出来，以便在外部的测试代码中进行访问和测试。**  它充当了一个桥梁，允许测试代码深入到 `runtime` 包的实现细节中进行验证，而这些细节在正常的包使用中是不可见的。

**更详细的功能列表：**

1. **暴露内部函数:**  将一些内部使用的函数（通常是小写字母开头）赋值给外部可访问的变量（通常是大写字母开头）。例如：
   - `var Fadd64 = fadd64`  允许测试代码调用内部的 `fadd64` 函数。
   - `var Entersyscall = entersyscall` 允许测试代码调用内部的 `entersyscall` 函数。

2. **暴露内部变量:**  将内部的变量暴露出来，允许测试代码读取或修改（需要谨慎）这些变量的状态。例如：
   - `var ReadRandomFailed = &readRandomFailed` 允许测试代码检查 `readRandomFailed` 变量的值。
   - `var ForceGCPeriod = &forcegcperiod` 允许测试代码修改 `forcegcperiod` 变量的值。

3. **暴露内部常量:**  将内部的常量暴露出来，供测试代码使用。例如：
   - `const CrashStackImplemented = crashStackImplemented`

4. **暴露内部类型:**  定义与内部类型结构相同的外部类型别名，使得测试代码可以声明和使用这些类型。例如：
   - `type TimeTimer = timeTimer`
   - `type LockRank lockRank`

5. **提供测试辅助函数:**  提供一些专门用于测试的函数，这些函数可能封装了对内部状态的访问或操作。例如：
   - `func LFStackPush(head *uint64, node *LFNode)` 允许测试代码操作内部的无锁栈。
   - `func RunSchedLocalQueueTest()`  提供了一个测试本地运行队列的函数。
   - `func CountPagesInUse() (pagesInUse, counted uintptr)`  提供了一个获取已使用页数的函数。

**它是什么 Go 语言功能的实现？**

这个 `export_test.go` 文件本身并不是一个具体 Go 语言功能的实现，而是用于**测试和验证 Go 语言运行时系统的各种核心功能**。  通过暴露内部细节，可以对以下方面进行更深入的测试：

- **调度器 (Scheduler):** 例如 `RunSchedLocalQueueTest`, `RunSchedLocalQueueStealTest`, `RunSchedLocalQueueEmptyTest` 等函数用于测试调度器的本地运行队列和窃取机制。
- **内存管理 (Memory Management):** 例如 `CountPagesInUse`, `ReadMemStatsSlow`, `NewPageAlloc`, `FreePageAlloc` 等函数和类型用于测试堆内存的管理、分配和回收。
- **垃圾回收 (Garbage Collection):** 虽然这段代码没有直接体现，但通过操作内存状态和检查相关指标，可以辅助测试垃圾回收器的行为。
- **系统调用 (System Calls):** 例如 `Entersyscall`, `Exitsyscall` 允许测试代码观察系统调用的入口和出口。
- **原子操作 (Atomic Operations):** 例如暴露 `atomic.Xadduintptr` 允许测试代码验证原子操作的正确性。
- **锁机制 (Locking):** 例如暴露 `Lock`, `Unlock`, `RWMutex` 以及相关的内部结构 `rwmutex`，允许测试代码更细致地测试锁的行为。
- **无锁数据结构 (Lock-Free Data Structures):** 例如 `LFStackPush`, `LFStackPop` 用于测试无锁栈的实现。
- **哈希表 (Hash Maps):** 例如暴露 `StringHash`, `BytesHash` 等哈希函数用于测试哈希算法。
- **栈管理 (Stack Management):** 例如 `ShrinkStackAndVerifyFramePointers` 用于测试栈的收缩和帧指针的正确性。
- **性能分析 (Profiling):** 例如 `NewProfBuf`, `ReadCPUStats` 用于测试性能分析相关的组件。

**Go 代码举例说明：**

假设我们要测试 `runtime` 包内部的无锁栈 `lfstack` 的 `push` 和 `pop` 操作。我们可以在一个测试文件中这样使用 `export_test.go` 中暴露的函数：

```go
// go/src/runtime/lfstack_test.go

package runtime_test // 注意这里是 runtime_test，因为我们要测试 runtime 内部

import (
	"runtime"
	"testing"
	"unsafe"
)

func TestLFStackPushPop(t *testing.T) {
	var head uint64
	node1 := runtime.LFNode{Next: 0, Pushcnt: 1}
	node2 := runtime.LFNode{Next: 0, Pushcnt: 2}

	runtime.LFStackPush(&head, &node1)
	runtime.LFStackPush(&head, &node2)

	popped1 := runtime.LFStackPop(&head)
	popped2 := runtime.LFStackPop(&head)

	if popped1 != &node2 {
		t.Errorf("Expected popped node to be node2, got %+v", popped1)
	}
	if popped2 != &node1 {
		t.Errorf("Expected popped node to be node1, got %+v", popped2)
	}
}
```

**假设的输入与输出：**

在这个例子中，输入是 `head` 变量的初始状态（通常为 0），以及要压入栈的 `LFNode` 结构体。输出是调用 `LFStackPop` 函数返回的 `LFNode` 指针。  测试会断言弹出的节点的顺序和内容是否符合预期（后进先出）。

**命令行参数的具体处理：**

`export_test.go` 本身不涉及命令行参数的处理。命令行参数通常在测试程序的主函数中处理，然后传递给测试函数。  `export_test.go` 只是提供测试的工具。

**使用者易犯错的点：**

使用 `export_test.go` 中的暴露的功能需要非常小心，因为：

1. **破坏内部状态:**  直接修改内部变量可能会破坏 `runtime` 的内部状态，导致程序崩溃或行为异常。例如，错误地修改 `forcegcperiod` 可能会影响垃圾回收的行为。

2. **依赖内部实现:**  测试代码依赖于 `runtime` 的内部实现细节，这意味着当 `runtime` 的实现发生变化时，测试代码可能需要同步更新。

3. **并发问题:**  在并发环境下测试 `runtime` 内部的机制（例如锁、无锁数据结构）需要非常谨慎地处理并发和同步问题，否则测试结果可能不可靠。

**总结 `export_test.go` 的功能：**

总而言之，`go/src/runtime/export_test.go` 是 `runtime` 包为了方便内部测试而设计的一个特殊文件，它通过暴露内部的实现细节，允许测试代码能够更深入、更细致地验证 `runtime` 系统的各种核心功能和机制的正确性。它本身不是一个功能实现，而是测试的基础设施。

Prompt: 
```
这是路径为go/src/runtime/export_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Export guts for testing.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/goos"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

var Fadd64 = fadd64
var Fsub64 = fsub64
var Fmul64 = fmul64
var Fdiv64 = fdiv64
var F64to32 = f64to32
var F32to64 = f32to64
var Fcmp64 = fcmp64
var Fintto64 = fintto64
var F64toint = f64toint

var Entersyscall = entersyscall
var Exitsyscall = exitsyscall
var LockedOSThread = lockedOSThread
var Xadduintptr = atomic.Xadduintptr

var ReadRandomFailed = &readRandomFailed

var Fastlog2 = fastlog2

var Atoi = atoi
var Atoi32 = atoi32
var ParseByteCount = parseByteCount

var Nanotime = nanotime
var NetpollBreak = netpollBreak
var Usleep = usleep

var PhysPageSize = physPageSize
var PhysHugePageSize = physHugePageSize

var NetpollGenericInit = netpollGenericInit

var Memmove = memmove
var MemclrNoHeapPointers = memclrNoHeapPointers

var CgoCheckPointer = cgoCheckPointer

const CrashStackImplemented = crashStackImplemented

const TracebackInnerFrames = tracebackInnerFrames
const TracebackOuterFrames = tracebackOuterFrames

var MapKeys = keys
var MapValues = values

var LockPartialOrder = lockPartialOrder

type TimeTimer = timeTimer

type LockRank lockRank

func (l LockRank) String() string {
	return lockRank(l).String()
}

const PreemptMSupported = preemptMSupported

type LFNode struct {
	Next    uint64
	Pushcnt uintptr
}

func LFStackPush(head *uint64, node *LFNode) {
	(*lfstack)(head).push((*lfnode)(unsafe.Pointer(node)))
}

func LFStackPop(head *uint64) *LFNode {
	return (*LFNode)((*lfstack)(head).pop())
}
func LFNodeValidate(node *LFNode) {
	lfnodeValidate((*lfnode)(unsafe.Pointer(node)))
}

func Netpoll(delta int64) {
	systemstack(func() {
		netpoll(delta)
	})
}

func PointerMask(x any) (ret []byte) {
	systemstack(func() {
		ret = pointerMask(x)
	})
	return
}

func RunSchedLocalQueueTest() {
	pp := new(p)
	gs := make([]g, len(pp.runq))
	Escape(gs) // Ensure gs doesn't move, since we use guintptrs
	for i := 0; i < len(pp.runq); i++ {
		if g, _ := runqget(pp); g != nil {
			throw("runq is not empty initially")
		}
		for j := 0; j < i; j++ {
			runqput(pp, &gs[i], false)
		}
		for j := 0; j < i; j++ {
			if g, _ := runqget(pp); g != &gs[i] {
				print("bad element at iter ", i, "/", j, "\n")
				throw("bad element")
			}
		}
		if g, _ := runqget(pp); g != nil {
			throw("runq is not empty afterwards")
		}
	}
}

func RunSchedLocalQueueStealTest() {
	p1 := new(p)
	p2 := new(p)
	gs := make([]g, len(p1.runq))
	Escape(gs) // Ensure gs doesn't move, since we use guintptrs
	for i := 0; i < len(p1.runq); i++ {
		for j := 0; j < i; j++ {
			gs[j].sig = 0
			runqput(p1, &gs[j], false)
		}
		gp := runqsteal(p2, p1, true)
		s := 0
		if gp != nil {
			s++
			gp.sig++
		}
		for {
			gp, _ = runqget(p2)
			if gp == nil {
				break
			}
			s++
			gp.sig++
		}
		for {
			gp, _ = runqget(p1)
			if gp == nil {
				break
			}
			gp.sig++
		}
		for j := 0; j < i; j++ {
			if gs[j].sig != 1 {
				print("bad element ", j, "(", gs[j].sig, ") at iter ", i, "\n")
				throw("bad element")
			}
		}
		if s != i/2 && s != i/2+1 {
			print("bad steal ", s, ", want ", i/2, " or ", i/2+1, ", iter ", i, "\n")
			throw("bad steal")
		}
	}
}

func RunSchedLocalQueueEmptyTest(iters int) {
	// Test that runq is not spuriously reported as empty.
	// Runq emptiness affects scheduling decisions and spurious emptiness
	// can lead to underutilization (both runnable Gs and idle Ps coexist
	// for arbitrary long time).
	done := make(chan bool, 1)
	p := new(p)
	gs := make([]g, 2)
	Escape(gs) // Ensure gs doesn't move, since we use guintptrs
	ready := new(uint32)
	for i := 0; i < iters; i++ {
		*ready = 0
		next0 := (i & 1) == 0
		next1 := (i & 2) == 0
		runqput(p, &gs[0], next0)
		go func() {
			for atomic.Xadd(ready, 1); atomic.Load(ready) != 2; {
			}
			if runqempty(p) {
				println("next:", next0, next1)
				throw("queue is empty")
			}
			done <- true
		}()
		for atomic.Xadd(ready, 1); atomic.Load(ready) != 2; {
		}
		runqput(p, &gs[1], next1)
		runqget(p)
		<-done
		runqget(p)
	}
}

var (
	StringHash = stringHash
	BytesHash  = bytesHash
	Int32Hash  = int32Hash
	Int64Hash  = int64Hash
	MemHash    = memhash
	MemHash32  = memhash32
	MemHash64  = memhash64
	EfaceHash  = efaceHash
	IfaceHash  = ifaceHash
)

var UseAeshash = &useAeshash

func MemclrBytes(b []byte) {
	s := (*slice)(unsafe.Pointer(&b))
	memclrNoHeapPointers(s.array, uintptr(s.len))
}

const HashLoad = hashLoad

// entry point for testing
func GostringW(w []uint16) (s string) {
	systemstack(func() {
		s = gostringw(&w[0])
	})
	return
}

var Open = open
var Close = closefd
var Read = read
var Write = write

func Envs() []string     { return envs }
func SetEnvs(e []string) { envs = e }

const PtrSize = goarch.PtrSize

var ForceGCPeriod = &forcegcperiod

// SetTracebackEnv is like runtime/debug.SetTraceback, but it raises
// the "environment" traceback level, so later calls to
// debug.SetTraceback (e.g., from testing timeouts) can't lower it.
func SetTracebackEnv(level string) {
	setTraceback(level)
	traceback_env = traceback_cache
}

var ReadUnaligned32 = readUnaligned32
var ReadUnaligned64 = readUnaligned64

func CountPagesInUse() (pagesInUse, counted uintptr) {
	stw := stopTheWorld(stwForTestCountPagesInUse)

	pagesInUse = mheap_.pagesInUse.Load()

	for _, s := range mheap_.allspans {
		if s.state.get() == mSpanInUse {
			counted += s.npages
		}
	}

	startTheWorld(stw)

	return
}

func Fastrand() uint32          { return uint32(rand()) }
func Fastrand64() uint64        { return rand() }
func Fastrandn(n uint32) uint32 { return randn(n) }

type ProfBuf profBuf

func NewProfBuf(hdrsize, bufwords, tags int) *ProfBuf {
	return (*ProfBuf)(newProfBuf(hdrsize, bufwords, tags))
}

func (p *ProfBuf) Write(tag *unsafe.Pointer, now int64, hdr []uint64, stk []uintptr) {
	(*profBuf)(p).write(tag, now, hdr, stk)
}

const (
	ProfBufBlocking    = profBufBlocking
	ProfBufNonBlocking = profBufNonBlocking
)

func (p *ProfBuf) Read(mode profBufReadMode) ([]uint64, []unsafe.Pointer, bool) {
	return (*profBuf)(p).read(mode)
}

func (p *ProfBuf) Close() {
	(*profBuf)(p).close()
}

type CPUStats = cpuStats

func ReadCPUStats() CPUStats {
	return work.cpuStats
}

func ReadMetricsSlow(memStats *MemStats, samplesp unsafe.Pointer, len, cap int) {
	stw := stopTheWorld(stwForTestReadMetricsSlow)

	// Initialize the metrics beforehand because this could
	// allocate and skew the stats.
	metricsLock()
	initMetrics()

	systemstack(func() {
		// Donate the racectx to g0. readMetricsLocked calls into the race detector
		// via map access.
		getg().racectx = getg().m.curg.racectx

		// Read the metrics once before in case it allocates and skews the metrics.
		// readMetricsLocked is designed to only allocate the first time it is called
		// with a given slice of samples. In effect, this extra read tests that this
		// remains true, since otherwise the second readMetricsLocked below could
		// allocate before it returns.
		readMetricsLocked(samplesp, len, cap)

		// Read memstats first. It's going to flush
		// the mcaches which readMetrics does not do, so
		// going the other way around may result in
		// inconsistent statistics.
		readmemstats_m(memStats)

		// Read metrics again. We need to be sure we're on the
		// system stack with readmemstats_m so that we don't call into
		// the stack allocator and adjust metrics between there and here.
		readMetricsLocked(samplesp, len, cap)

		// Undo the donation.
		getg().racectx = 0
	})
	metricsUnlock()

	startTheWorld(stw)
}

var DoubleCheckReadMemStats = &doubleCheckReadMemStats

// ReadMemStatsSlow returns both the runtime-computed MemStats and
// MemStats accumulated by scanning the heap.
func ReadMemStatsSlow() (base, slow MemStats) {
	stw := stopTheWorld(stwForTestReadMemStatsSlow)

	// Run on the system stack to avoid stack growth allocation.
	systemstack(func() {
		// Make sure stats don't change.
		getg().m.mallocing++

		readmemstats_m(&base)

		// Initialize slow from base and zero the fields we're
		// recomputing.
		slow = base
		slow.Alloc = 0
		slow.TotalAlloc = 0
		slow.Mallocs = 0
		slow.Frees = 0
		slow.HeapReleased = 0
		var bySize [_NumSizeClasses]struct {
			Mallocs, Frees uint64
		}

		// Add up current allocations in spans.
		for _, s := range mheap_.allspans {
			if s.state.get() != mSpanInUse {
				continue
			}
			if s.isUnusedUserArenaChunk() {
				continue
			}
			if sizeclass := s.spanclass.sizeclass(); sizeclass == 0 {
				slow.Mallocs++
				slow.Alloc += uint64(s.elemsize)
			} else {
				slow.Mallocs += uint64(s.allocCount)
				slow.Alloc += uint64(s.allocCount) * uint64(s.elemsize)
				bySize[sizeclass].Mallocs += uint64(s.allocCount)
			}
		}

		// Add in frees by just reading the stats for those directly.
		var m heapStatsDelta
		memstats.heapStats.unsafeRead(&m)

		// Collect per-sizeclass free stats.
		var smallFree uint64
		for i := 0; i < _NumSizeClasses; i++ {
			slow.Frees += m.smallFreeCount[i]
			bySize[i].Frees += m.smallFreeCount[i]
			bySize[i].Mallocs += m.smallFreeCount[i]
			smallFree += m.smallFreeCount[i] * uint64(class_to_size[i])
		}
		slow.Frees += m.tinyAllocCount + m.largeFreeCount
		slow.Mallocs += slow.Frees

		slow.TotalAlloc = slow.Alloc + m.largeFree + smallFree

		for i := range slow.BySize {
			slow.BySize[i].Mallocs = bySize[i].Mallocs
			slow.BySize[i].Frees = bySize[i].Frees
		}

		for i := mheap_.pages.start; i < mheap_.pages.end; i++ {
			chunk := mheap_.pages.tryChunkOf(i)
			if chunk == nil {
				continue
			}
			pg := chunk.scavenged.popcntRange(0, pallocChunkPages)
			slow.HeapReleased += uint64(pg) * pageSize
		}
		for _, p := range allp {
			pg := sys.OnesCount64(p.pcache.scav)
			slow.HeapReleased += uint64(pg) * pageSize
		}

		getg().m.mallocing--
	})

	startTheWorld(stw)
	return
}

// ShrinkStackAndVerifyFramePointers attempts to shrink the stack of the current goroutine
// and verifies that unwinding the new stack doesn't crash, even if the old
// stack has been freed or reused (simulated via poisoning).
func ShrinkStackAndVerifyFramePointers() {
	before := stackPoisonCopy
	defer func() { stackPoisonCopy = before }()
	stackPoisonCopy = 1

	gp := getg()
	systemstack(func() {
		shrinkstack(gp)
	})
	// If our new stack contains frame pointers into the old stack, this will
	// crash because the old stack has been poisoned.
	FPCallers(make([]uintptr, 1024))
}

// BlockOnSystemStack switches to the system stack, prints "x\n" to
// stderr, and blocks in a stack containing
// "runtime.blockOnSystemStackInternal".
func BlockOnSystemStack() {
	systemstack(blockOnSystemStackInternal)
}

func blockOnSystemStackInternal() {
	print("x\n")
	lock(&deadlock)
	lock(&deadlock)
}

type RWMutex struct {
	rw rwmutex
}

func (rw *RWMutex) Init() {
	rw.rw.init(lockRankTestR, lockRankTestRInternal, lockRankTestW)
}

func (rw *RWMutex) RLock() {
	rw.rw.rlock()
}

func (rw *RWMutex) RUnlock() {
	rw.rw.runlock()
}

func (rw *RWMutex) Lock() {
	rw.rw.lock()
}

func (rw *RWMutex) Unlock() {
	rw.rw.unlock()
}

func LockOSCounts() (external, internal uint32) {
	gp := getg()
	if gp.m.lockedExt+gp.m.lockedInt == 0 {
		if gp.lockedm != 0 {
			panic("lockedm on non-locked goroutine")
		}
	} else {
		if gp.lockedm == 0 {
			panic("nil lockedm on locked goroutine")
		}
	}
	return gp.m.lockedExt, gp.m.lockedInt
}

//go:noinline
func TracebackSystemstack(stk []uintptr, i int) int {
	if i == 0 {
		pc, sp := sys.GetCallerPC(), sys.GetCallerSP()
		var u unwinder
		u.initAt(pc, sp, 0, getg(), unwindJumpStack) // Don't ignore errors, for testing
		return tracebackPCs(&u, 0, stk)
	}
	n := 0
	systemstack(func() {
		n = TracebackSystemstack(stk, i-1)
	})
	return n
}

func KeepNArenaHints(n int) {
	hint := mheap_.arenaHints
	for i := 1; i < n; i++ {
		hint = hint.next
		if hint == nil {
			return
		}
	}
	hint.next = nil
}

// MapNextArenaHint reserves a page at the next arena growth hint,
// preventing the arena from growing there, and returns the range of
// addresses that are no longer viable.
//
// This may fail to reserve memory. If it fails, it still returns the
// address range it attempted to reserve.
func MapNextArenaHint() (start, end uintptr, ok bool) {
	hint := mheap_.arenaHints
	addr := hint.addr
	if hint.down {
		start, end = addr-heapArenaBytes, addr
		addr -= physPageSize
	} else {
		start, end = addr, addr+heapArenaBytes
	}
	got := sysReserve(unsafe.Pointer(addr), physPageSize)
	ok = (addr == uintptr(got))
	if !ok {
		// We were unable to get the requested reservation.
		// Release what we did get and fail.
		sysFreeOS(got, physPageSize)
	}
	return
}

func GetNextArenaHint() uintptr {
	return mheap_.arenaHints.addr
}

type G = g

type Sudog = sudog

func Getg() *G {
	return getg()
}

func Goid() uint64 {
	return getg().goid
}

func GIsWaitingOnMutex(gp *G) bool {
	return readgstatus(gp) == _Gwaiting && gp.waitreason.isMutexWait()
}

var CasGStatusAlwaysTrack = &casgstatusAlwaysTrack

//go:noinline
func PanicForTesting(b []byte, i int) byte {
	return unexportedPanicForTesting(b, i)
}

//go:noinline
func unexportedPanicForTesting(b []byte, i int) byte {
	return b[i]
}

func G0StackOverflow() {
	systemstack(func() {
		g0 := getg()
		sp := sys.GetCallerSP()
		// The stack bounds for g0 stack is not always precise.
		// Use an artificially small stack, to trigger a stack overflow
		// without actually run out of the system stack (which may seg fault).
		g0.stack.lo = sp - 4096 - stackSystem
		g0.stackguard0 = g0.stack.lo + stackGuard
		g0.stackguard1 = g0.stackguard0

		stackOverflow(nil)
	})
}

func stackOverflow(x *byte) {
	var buf [256]byte
	stackOverflow(&buf[0])
}

func RunGetgThreadSwitchTest() {
	// Test that getg works correctly with thread switch.
	// With gccgo, if we generate getg inlined, the backend
	// may cache the address of the TLS variable, which
	// will become invalid after a thread switch. This test
	// checks that the bad caching doesn't happen.

	ch := make(chan int)
	go func(ch chan int) {
		ch <- 5
		LockOSThread()
	}(ch)

	g1 := getg()

	// Block on a receive. This is likely to get us a thread
	// switch. If we yield to the sender goroutine, it will
	// lock the thread, forcing us to resume on a different
	// thread.
	<-ch

	g2 := getg()
	if g1 != g2 {
		panic("g1 != g2")
	}

	// Also test getg after some control flow, as the
	// backend is sensitive to control flow.
	g3 := getg()
	if g1 != g3 {
		panic("g1 != g3")
	}
}

const (
	PageSize         = pageSize
	PallocChunkPages = pallocChunkPages
	PageAlloc64Bit   = pageAlloc64Bit
	PallocSumBytes   = pallocSumBytes
)

// Expose pallocSum for testing.
type PallocSum pallocSum

func PackPallocSum(start, max, end uint) PallocSum { return PallocSum(packPallocSum(start, max, end)) }
func (m PallocSum) Start() uint                    { return pallocSum(m).start() }
func (m PallocSum) Max() uint                      { return pallocSum(m).max() }
func (m PallocSum) End() uint                      { return pallocSum(m).end() }

// Expose pallocBits for testing.
type PallocBits pallocBits

func (b *PallocBits) Find(npages uintptr, searchIdx uint) (uint, uint) {
	return (*pallocBits)(b).find(npages, searchIdx)
}
func (b *PallocBits) AllocRange(i, n uint)       { (*pallocBits)(b).allocRange(i, n) }
func (b *PallocBits) Free(i, n uint)             { (*pallocBits)(b).free(i, n) }
func (b *PallocBits) Summarize() PallocSum       { return PallocSum((*pallocBits)(b).summarize()) }
func (b *PallocBits) PopcntRange(i, n uint) uint { return (*pageBits)(b).popcntRange(i, n) }

// SummarizeSlow is a slow but more obviously correct implementation
// of (*pallocBits).summarize. Used for testing.
func SummarizeSlow(b *PallocBits) PallocSum {
	var start, most, end uint

	const N = uint(len(b)) * 64
	for start < N && (*pageBits)(b).get(start) == 0 {
		start++
	}
	for end < N && (*pageBits)(b).get(N-end-1) == 0 {
		end++
	}
	run := uint(0)
	for i := uint(0); i < N; i++ {
		if (*pageBits)(b).get(i) == 0 {
			run++
		} else {
			run = 0
		}
		most = max(most, run)
	}
	return PackPallocSum(start, most, end)
}

// Expose non-trivial helpers for testing.
func FindBitRange64(c uint64, n uint) uint { return findBitRange64(c, n) }

// Given two PallocBits, returns a set of bit ranges where
// they differ.
func DiffPallocBits(a, b *PallocBits) []BitRange {
	ba := (*pageBits)(a)
	bb := (*pageBits)(b)

	var d []BitRange
	base, size := uint(0), uint(0)
	for i := uint(0); i < uint(len(ba))*64; i++ {
		if ba.get(i) != bb.get(i) {
			if size == 0 {
				base = i
			}
			size++
		} else {
			if size != 0 {
				d = append(d, BitRange{base, size})
			}
			size = 0
		}
	}
	if size != 0 {
		d = append(d, BitRange{base, size})
	}
	return d
}

// StringifyPallocBits gets the bits in the bit range r from b,
// and returns a string containing the bits as ASCII 0 and 1
// characters.
func StringifyPallocBits(b *PallocBits, r BitRange) string {
	str := ""
	for j := r.I; j < r.I+r.N; j++ {
		if (*pageBits)(b).get(j) != 0 {
			str += "1"
		} else {
			str += "0"
		}
	}
	return str
}

// Expose pallocData for testing.
type PallocData pallocData

func (d *PallocData) FindScavengeCandidate(searchIdx uint, min, max uintptr) (uint, uint) {
	return (*pallocData)(d).findScavengeCandidate(searchIdx, min, max)
}
func (d *PallocData) AllocRange(i, n uint) { (*pallocData)(d).allocRange(i, n) }
func (d *PallocData) ScavengedSetRange(i, n uint) {
	(*pallocData)(d).scavenged.setRange(i, n)
}
func (d *PallocData) PallocBits() *PallocBits {
	return (*PallocBits)(&(*pallocData)(d).pallocBits)
}
func (d *PallocData) Scavenged() *PallocBits {
	return (*PallocBits)(&(*pallocData)(d).scavenged)
}

// Expose fillAligned for testing.
func FillAligned(x uint64, m uint) uint64 { return fillAligned(x, m) }

// Expose pageCache for testing.
type PageCache pageCache

const PageCachePages = pageCachePages

func NewPageCache(base uintptr, cache, scav uint64) PageCache {
	return PageCache(pageCache{base: base, cache: cache, scav: scav})
}
func (c *PageCache) Empty() bool   { return (*pageCache)(c).empty() }
func (c *PageCache) Base() uintptr { return (*pageCache)(c).base }
func (c *PageCache) Cache() uint64 { return (*pageCache)(c).cache }
func (c *PageCache) Scav() uint64  { return (*pageCache)(c).scav }
func (c *PageCache) Alloc(npages uintptr) (uintptr, uintptr) {
	return (*pageCache)(c).alloc(npages)
}
func (c *PageCache) Flush(s *PageAlloc) {
	cp := (*pageCache)(c)
	sp := (*pageAlloc)(s)

	systemstack(func() {
		// None of the tests need any higher-level locking, so we just
		// take the lock internally.
		lock(sp.mheapLock)
		cp.flush(sp)
		unlock(sp.mheapLock)
	})
}

// Expose chunk index type.
type ChunkIdx chunkIdx

// Expose pageAlloc for testing. Note that because pageAlloc is
// not in the heap, so is PageAlloc.
type PageAlloc pageAlloc

func (p *PageAlloc) Alloc(npages uintptr) (uintptr, uintptr) {
	pp := (*pageAlloc)(p)

	var addr, scav uintptr
	systemstack(func() {
		// None of the tests need any higher-level locking, so we just
		// take the lock internally.
		lock(pp.mheapLock)
		addr, scav = pp.alloc(npages)
		unlock(pp.mheapLock)
	})
	return addr, scav
}
func (p *PageAlloc) AllocToCache() PageCache {
	pp := (*pageAlloc)(p)

	var c PageCache
	systemstack(func() {
		// None of the tests need any higher-level locking, so we just
		// take the lock internally.
		lock(pp.mheapLock)
		c = PageCache(pp.allocToCache())
		unlock(pp.mheapLock)
	})
	return c
}
func (p *PageAlloc) Free(base, npages uintptr) {
	pp := (*pageAlloc)(p)

	systemstack(func() {
		// None of the tests need any higher-level locking, so we just
		// take the lock internally.
		lock(pp.mheapLock)
		pp.free(base, npages)
		unlock(pp.mheapLock)
	})
}
func (p *PageAlloc) Bounds() (ChunkIdx, ChunkIdx) {
	return ChunkIdx((*pageAlloc)(p).start), ChunkIdx((*pageAlloc)(p).end)
}
func (p *PageAlloc) Scavenge(nbytes uintptr) (r uintptr) {
	pp := (*pageAlloc)(p)
	systemstack(func() {
		r = pp.scavenge(nbytes, nil, true)
	})
	return
}
func (p *PageAlloc) InUse() []AddrRange {
	ranges := make([]AddrRange, 0, len(p.inUse.ranges))
	for _, r := range p.inUse.ranges {
		ranges = append(ranges, AddrRange{r})
	}
	return ranges
}

// Returns nil if the PallocData's L2 is missing.
func (p *PageAlloc) PallocData(i ChunkIdx) *PallocData {
	ci := chunkIdx(i)
	return (*PallocData)((*pageAlloc)(p).tryChunkOf(ci))
}

// AddrRange is a wrapper around addrRange for testing.
type AddrRange struct {
	addrRange
}

// MakeAddrRange creates a new address range.
func MakeAddrRange(base, limit uintptr) AddrRange {
	return AddrRange{makeAddrRange(base, limit)}
}

// Base returns the virtual base address of the address range.
func (a AddrRange) Base() uintptr {
	return a.addrRange.base.addr()
}

// Base returns the virtual address of the limit of the address range.
func (a AddrRange) Limit() uintptr {
	return a.addrRange.limit.addr()
}

// Equals returns true if the two address ranges are exactly equal.
func (a AddrRange) Equals(b AddrRange) bool {
	return a == b
}

// Size returns the size in bytes of the address range.
func (a AddrRange) Size() uintptr {
	return a.addrRange.size()
}

// testSysStat is the sysStat passed to test versions of various
// runtime structures. We do actually have to keep track of this
// because otherwise memstats.mappedReady won't actually line up
// with other stats in the runtime during tests.
var testSysStat = &memstats.other_sys

// AddrRanges is a wrapper around addrRanges for testing.
type AddrRanges struct {
	addrRanges
	mutable bool
}

// NewAddrRanges creates a new empty addrRanges.
//
// Note that this initializes addrRanges just like in the
// runtime, so its memory is persistentalloc'd. Call this
// function sparingly since the memory it allocates is
// leaked.
//
// This AddrRanges is mutable, so we can test methods like
// Add.
func NewAddrRanges() AddrRanges {
	r := addrRanges{}
	r.init(testSysStat)
	return AddrRanges{r, true}
}

// MakeAddrRanges creates a new addrRanges populated with
// the ranges in a.
//
// The returned AddrRanges is immutable, so methods like
// Add will fail.
func MakeAddrRanges(a ...AddrRange) AddrRanges {
	// Methods that manipulate the backing store of addrRanges.ranges should
	// not be used on the result from this function (e.g. add) since they may
	// trigger reallocation. That would normally be fine, except the new
	// backing store won't come from the heap, but from persistentalloc, so
	// we'll leak some memory implicitly.
	ranges := make([]addrRange, 0, len(a))
	total := uintptr(0)
	for _, r := range a {
		ranges = append(ranges, r.addrRange)
		total += r.Size()
	}
	return AddrRanges{addrRanges{
		ranges:     ranges,
		totalBytes: total,
		sysStat:    testSysStat,
	}, false}
}

// Ranges returns a copy of the ranges described by the
// addrRanges.
func (a *AddrRanges) Ranges() []AddrRange {
	result := make([]AddrRange, 0, len(a.addrRanges.ranges))
	for _, r := range a.addrRanges.ranges {
		result = append(result, AddrRange{r})
	}
	return result
}

// FindSucc returns the successor to base. See addrRanges.findSucc
// for more details.
func (a *AddrRanges) FindSucc(base uintptr) int {
	return a.findSucc(base)
}

// Add adds a new AddrRange to the AddrRanges.
//
// The AddrRange must be mutable (i.e. created by NewAddrRanges),
// otherwise this method will throw.
func (a *AddrRanges) Add(r AddrRange) {
	if !a.mutable {
		throw("attempt to mutate immutable AddrRanges")
	}
	a.add(r.addrRange)
}

// TotalBytes returns the totalBytes field of the addrRanges.
func (a *AddrRanges) TotalBytes() uintptr {
	return a.addrRanges.totalBytes
}

// BitRange represents a range over a bitmap.
type BitRange struct {
	I, N uint // bit index and length in bits
}

// NewPageAlloc creates a new page allocator for testing and
// initializes it with the scav and chunks maps. Each key in these maps
// represents a chunk index and each value is a series of bit ranges to
// set within each bitmap's chunk.
//
// The initialization of the pageAlloc preserves the invariant that if a
// scavenged bit is set the alloc bit is necessarily unset, so some
// of the bits described by scav may be cleared in the final bitmap if
// ranges in chunks overlap with them.
//
// scav is optional, and if nil, the scavenged bitmap will be cleared
// (as opposed to all 1s, which it usually is). Furthermore, every
// chunk index in scav must appear in chunks; ones that do not are
// ignored.
func NewPageAlloc(chunks, scav map[ChunkIdx][]BitRange) *PageAlloc {
	p := new(pageAlloc)

	// We've got an entry, so initialize the pageAlloc.
	p.init(new(mutex), testSysStat, true)
	lockInit(p.mheapLock, lockRankMheap)
	for i, init := range chunks {
		addr := chunkBase(chunkIdx(i))

		// Mark the chunk's existence in the pageAlloc.
		systemstack(func() {
			lock(p.mheapLock)
			p.grow(addr, pallocChunkBytes)
			unlock(p.mheapLock)
		})

		// Initialize the bitmap and update pageAlloc metadata.
		ci := chunkIndex(addr)
		chunk := p.chunkOf(ci)

		// Clear all the scavenged bits which grow set.
		chunk.scavenged.clearRange(0, pallocChunkPages)

		// Simulate the allocation and subsequent free of all pages in
		// the chunk for the scavenge index. This sets the state equivalent
		// with all pages within the index being free.
		p.scav.index.alloc(ci, pallocChunkPages)
		p.scav.index.free(ci, 0, pallocChunkPages)

		// Apply scavenge state if applicable.
		if scav != nil {
			if scvg, ok := scav[i]; ok {
				for _, s := range scvg {
					// Ignore the case of s.N == 0. setRange doesn't handle
					// it and it's a no-op anyway.
					if s.N != 0 {
						chunk.scavenged.setRange(s.I, s.N)
					}
				}
			}
		}

		// Apply alloc state.
		for _, s := range init {
			// Ignore the case of s.N == 0. allocRange doesn't handle
			// it and it's a no-op anyway.
			if s.N != 0 {
				chunk.allocRange(s.I, s.N)

				// Make sure the scavenge index is updated.
				p.scav.index.alloc(ci, s.N)
			}
		}

		// Update heap metadata for the allocRange calls above.
		systemstack(func() {
			lock(p.mheapLock)
			p.update(addr, pallocChunkPages, false, false)
			unlock(p.mheapLock)
		})
	}

	return (*PageAlloc)(p)
}

// FreePageAlloc releases hard OS resources owned by the pageAlloc. Once this
// is called the pageAlloc may no longer be used. The object itself will be
// collected by the garbage collector once it is no longer live.
func FreePageAlloc(pp *PageAlloc) {
	p := (*pageAlloc)(pp)

	// Free all the mapped space for the summary levels.
	if pageAlloc64Bit != 0 {
		for l := 0; l < summaryLevels; l++ {
			sysFreeOS(unsafe.Pointer(&p.summary[l][0]), uintptr(cap(p.summary[l]))*pallocSumBytes)
		}
	} else {
		resSize := uintptr(0)
		for _, s := range p.summary {
			resSize += uintptr(cap(s)) * pallocSumBytes
		}
		sysFreeOS(unsafe.Pointer(&p.summary[0][0]), alignUp(resSize, physPageSize))
	}

	// Free extra data structures.
	sysFreeOS(unsafe.Pointer(&p.scav.index.chunks[0]), uintptr(cap(p.scav.index.chunks))*unsafe.Sizeof(atomicScavChunkData{}))

	// Subtract back out whatever we mapped for the summaries.
	// sysUsed adds to p.sysStat and memstats.mappedReady no matter what
	// (and in anger should actually be accounted for), and there's no other
	// way to figure out how much we actually mapped.
	gcController.mappedReady.Add(-int64(p.summaryMappedReady))
	testSysStat.add(-int64(p.summaryMappedReady))

	// Free the mapped space for chunks.
	for i := range p.chunks {
		if x := p.chunks[i]; x != nil {
			p.chunks[i] = nil
			// This memory comes from sysAlloc and will always be page-aligned.
			sysFree(unsafe.Pointer(x), unsafe.Sizeof(*p.chunks[0]), testSysStat)
		}
	}
}

// BaseChunkIdx is a convenient chunkIdx value which works on both
// 64 bit and 32 bit platforms, allowing the tests to share code
// between the two.
//
// This should not be higher than 0x100*pallocChunkBytes to support
// mips and mipsle, which only have 31-bit address spaces.
var BaseChunkIdx = func() ChunkIdx {
	var prefix uintptr
	if pageAlloc64Bit != 0 {
		prefix = 0xc000
	} else {
		prefix = 0x100
	}
	baseAddr := prefix * pallocChunkBytes
	if goos.IsAix != 0 {
		baseAddr += arenaBaseOffset
	}
	return ChunkIdx(chunkIndex(baseAddr))
}()

// PageBase returns an address given a chunk index and a page index
// relative to that chunk.
func PageBase(c ChunkIdx, pageIdx uint) uintptr {
	return chunkBase(chunkIdx(c)) + uintptr(pageIdx)*pageSize
}

type BitsMismatch struct {
	Base      uintptr
	Got, Want uint64
}

func CheckScavengedBitsCleared(mismatches []BitsMismatch) (n int, ok bool) {
	ok = true

	// Run on the system stack to avoid stack growth allocation.
	systemstack(func() {
		getg().m.mallocing++

		// Lock so that we can safely access the bitmap.
		lock(&mheap_.lock)
	chunkLoop:
		for i := mheap_.pages.start; i < mheap_.pages.end; i++ {
			chunk := mheap_.pages.tryChunkOf(i)
			if chunk == nil {
				continue
			}
			for j := 0; j < pallocChunkPages/64; j++ {
				// Run over each 64-bit bitmap section and ensure
				// scavenged is being cleared properly on allocation.
				// If a used bit and scavenged bit are both set, that's
				// an error, and could indicate a larger problem, or
				// an accounting problem.
				want := chunk.scavenged[j] &^ chunk.pallocBits[j]
				got := chunk.scavenged[j]
				if want != got {
					ok = false
					if n >= len(mismatches) {
						break chunkLoop
					}
					mismatches[n] = BitsMismatch{
						Base: chunkBase(i) + uintptr(j)*64*pageSize,
						Got:  got,
						Want: want,
					}
					n++
				}
			}
		}
		unlock(&mheap_.lock)

		getg().m.mallocing--
	})
	return
}

func PageCachePagesLeaked() (leaked uintptr) {
	stw := stopTheWorld(stwForTestPageCachePagesLeaked)

	// Walk over destroyed Ps and look for unflushed caches.
	deadp := allp[len(allp):cap(allp)]
	for _, p := range deadp {
		// Since we're going past len(allp) we may see nil Ps.
		// Just ignore them.
		if p != nil {
			leaked += uintptr(sys.OnesCount64(p.pcache.cache))
		}
	}

	startTheWorld(stw)
	return
}

var ProcYield = procyield
var OSYield = osyield

type Mutex = mutex

var Lock = lock
var Unlock = unlock

var MutexContended = mutexContended

func SemRootLock(addr *uint32) *mutex {
	root := semtable.rootFor(addr)
	return &root.lock
}

var Semacquire = semacquire
var Semrelease1 = semrelease1

func SemNwait(addr *uint32) uint32 {
	root := semtable.rootFor(addr)
	return root.nwait.Load()
}

const SemTableSize = semTabSize

// SemTable is a wrapper around semTable exported for testing.
type SemTable struct {
	semTable
}

// Enqueue simulates enqueuing a waiter for a semaphore (or lock) at addr.
func (t *SemTable) Enqueue(addr *uint32) {
	s := acquireSudog()
	s.releasetime = 0
	s.acquiretime = 0
	s.ticket = 0
	t.semTable.rootFor(addr).queue(addr, s, false)
}

// Dequeue simulates dequeuing a waiter for a semaphore (or lock) at addr.
//
// Returns true if there actually was a waiter to be dequeued.
func (t *SemTable) Dequeue(addr *uint32) bool {
	s, _, _ := t.semTable.rootFor(addr).dequeue(addr)
	if s != nil {
		releaseSudog(s)
		return true
	}
	return false
}

// mspan wrapper for testing.
type MSpan mspan

// Allocate an mspan for testing.
func AllocMSpan() *MSpan {
	var s *mspan
	systemstack(func() {
		lock(&mheap_.lock)
		s = (*mspan)(mheap_.spanalloc.alloc())
		unlock(&mheap_.lock)
	})
	return (*MSpan)(s)
}

// Free an allocated mspan.
func FreeMSpan(s *MSpan) {
	systemstack(func() {
		lock(&mheap_.lock)
		mheap_.spanalloc.free(unsafe.Pointer(s))
		unlock(&mheap_.lock)
	})
}

func MSpanCountAlloc(ms *MSpan, bits []byte) int {
	s := (*mspan)(ms)
	s.nelems = uint16(len(bits) * 8)
	s.gcmarkBits = (*gcBits)(unsafe.Pointer(&bits[0]))
	result := s.countAlloc()
	s.gcmarkBits = nil
	return result
}

const (
	TimeHistSubBucketBits = timeHistSubBucketBits
	TimeHistNumSubBuckets = timeHistNumSubBuckets
	TimeHistNumBuckets    = timeHistNumBuckets
	TimeHistMinBucketBits = timeHistMinBucketBits
	TimeHistMaxBucketBits = timeHistMaxBucketBits
)

type TimeHistogram timeHistogram

// Count returns the counts for the given bucket, subBucket indices.
// Returns true if the bucket was valid, otherwise returns the counts
// for the overflow bucket if bucket > 0 or the underflow bucket if
// bucket < 0, and false.
func (th *TimeHistogram) Count(bucket, subBucket int) (uint64, bool) {
	t := (*timeHistogram)(th)
	if bucket < 0 {
		return t.underflow.Load(), false
	}
	i := bucket*TimeHistNumSubBuckets + subBucket
	if i >= len(t.counts) {
		return t.overflow.Load(), false
	}
	return t.counts[i].Load(), true
}

func (th *TimeHistogram) Record(duration int64) {
	(*timeHistog
"""




```