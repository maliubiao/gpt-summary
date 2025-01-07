Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

The first step is a quick scan looking for obvious keywords and patterns:

* **Copyright/License:**  Standard Go header. Indicates open-source nature.
* **`package runtime`:** This is crucial. It tells us this code is part of the core Go runtime, meaning it deals with low-level operations.
* **Comments starting with `//`:**  These are essential for understanding the purpose of different sections. Pay close attention to "Malloc profiling," "Patterned after tcmalloc," and descriptions of data structures.
* **Variable declarations:** `profInsertLock`, `profBlockLock`, `profMemActiveLock`, `profMemFutureLock`. The `mutex` type suggests these are used for synchronization, likely around shared profiling data.
* **Constants:** `memProfile`, `blockProfile`, `mutexProfile`, `buckHashSize`, `maxSkip`, `maxProfStackDepth`. These define specific types of profiles and configuration parameters.
* **Struct definitions:** `bucket`, `memRecord`, `memRecordCycle`, `blockRecord`, `mProfCycleHolder`. These are the core data structures used to store profiling information. The comments within these structs are particularly important.
* **Function names:** `newBucket`, `stkbucket`, `mProf_NextCycle`, `mProf_Flush`, `mProf_Malloc`, `mProf_Free`, `SetBlockProfileRate`, `blockevent`, `saveblockevent`, `SetMutexProfileFraction`, `mutexevent`, `MemProfile`, etc. These names give strong hints about the functionality of the code.

**2. Identifying Core Functionality - Profiling:**

The comments and variable/constant names strongly suggest this code is about *profiling*. Specifically, the terms "Malloc profiling," "blockProfile," and "mutexProfile" indicate it's tracking memory allocations, blocking events (like waiting on channels or mutexes), and mutex contention.

**3. Understanding Data Structures - The `bucket`:**

The `bucket` struct seems central. The comments state it "holds per-call-stack profiling information."  The fields `next`, `allnext`, `typ`, `hash`, `size`, and `nstk` suggest it's part of a hash table or linked list, and stores information about the type of profile, a hash of the call stack, the size of the allocation, and the number of stack frames. The comment about memory layout is a bit unusual but important for understanding how the stack trace and record data are stored together.

**4. Delving into Specific Profile Types:**

* **`memRecord`:** The detailed comments about the "3-stage scheme of stats accumulation" are key here. It reveals the complexity of tracking memory allocations and frees consistently across GC cycles. The `active` and `future` fields with their cycle-based logic are fundamental.
* **`blockRecord`:**  Simpler, storing `count` and `cycles`. Likely related to the duration and frequency of blocking events.
* **`mutexProfile`:**  Shares the `blockRecord` structure, indicating it tracks similar information about mutex contention.

**5. Tracing the Flow of Information (High-Level):**

Based on the function names, we can start to piece together how profiling data is collected:

* **Allocation:** `mProf_Malloc` is called during allocation. It gets the call stack, finds or creates a `bucket`, and updates the `memRecord`.
* **Freeing:** `mProf_Free` is called during deallocation and updates the `memRecord`.
* **Blocking:** `blockevent` and `saveblockevent` are called when goroutines block. They capture the stack and update the `blockRecord`.
* **Mutex Contention:** `mutexevent` and related functions in `mLockProfile` track mutex contention. The `mLockProfile` struct and its methods (`recordLock`, `recordUnlock`, `captureStack`, `store`) are dedicated to this.
* **Publishing Profiles:** `mProf_NextCycle` and `mProf_Flush` control when profiling data is moved from the `future` to the `active` state in `memRecord`, making it available to users.

**6. Command-Line Parameters and User Errors (Anticipation):**

While this snippet doesn't *directly* handle command-line arguments, the presence of `MemProfileRate`, `SetBlockProfileRate`, and `SetMutexProfileFraction` strongly implies that there are mechanisms (likely environment variables or programmatic settings) to control the profiling behavior. Potential user errors could involve setting these rates incorrectly or misunderstanding their impact on performance and data accuracy.

**7. Go Code Examples (Hypothetical - Since it's runtime code):**

Since this is runtime code, directly demonstrating its use in user-level Go code is tricky. However, we can infer how user code *interacts* with these mechanisms through the `runtime` package's profiling interfaces (like `runtime.MemProfile`).

**8. Refining the Summary:**

Finally, after the detailed analysis, the initial summary can be refined to be more precise and include the key aspects identified.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe this is just about memory allocation."  **Correction:** The presence of `blockProfile` and `mutexProfile` clearly expands the scope.
* **Initial thought:** "The locks are just for basic thread safety." **Correction:** The comments specifically mentioning the multi-stage accumulation in `memRecord` reveal the need for careful synchronization to ensure data consistency during concurrent allocation and garbage collection.
* **Realization:**  The code is heavily intertwined with the Go garbage collector's lifecycle (mark and sweep). This is essential for the consistent memory profiling.

By following this systematic approach, combining code reading with comment analysis and logical deduction, we can arrive at a comprehensive understanding of the provided Go runtime code snippet.
这段代码是 Go 语言运行时环境（runtime）中 `mprof.go` 文件的一部分，主要负责实现 **内存分配（Malloc）的性能分析（Profiling）** 功能，并包含了 **阻塞（Blocking）分析** 和 **互斥锁（Mutex）分析** 的基础设施。

以下是它的功能归纳：

**核心功能：内存分配性能分析 (Memory Profiling)**

1. **跟踪内存分配和释放：**  当程序进行内存分配 (`malloc`) 和释放 (`free`) 时，这段代码会记录这些事件，包括分配和释放的字节数以及对象数量。
2. **基于调用栈聚合信息：**  它会将内存分配和释放事件关联到发生这些事件的函数调用栈。这意味着你可以看到哪些代码路径导致了最多的内存分配。
3. **采样机制：**  为了避免记录所有内存分配事件带来的性能开销，它使用了采样机制。`MemProfileRate` 变量控制了采样的频率，即每分配多少字节的内存才会记录一次分配事件。
4. **时间点的快照：**  为了提供内存使用情况在特定时间点的准确快照，它使用了一个复杂的三阶段累积方案（`active` 和 `future` 数组）。这主要是为了解决 `malloc` 和 `free` 事件发生时间不同步的问题，尤其是在垃圾回收期间。
5. **与垃圾回收集成：**  内存分析与 Go 的垃圾回收器紧密集成。`mProf_NextCycle`、`mProf_Flush` 和 `mProf_PostSweep` 等函数在垃圾回收的不同阶段被调用，以确保内存分析数据的准确性和一致性。

**次要功能：阻塞分析和互斥锁分析 (Blocking and Mutex Profiling)**

1. **阻塞事件记录：**  当 Goroutine 因为某些原因阻塞时（例如，等待 channel 或 mutex），`blockevent` 函数会被调用，并根据 `blockprofilerate` 变量控制的采样率来记录阻塞事件。
2. **互斥锁竞争记录：**  当 Goroutine 尝试获取互斥锁但发生竞争时，`mutexevent` 函数会被调用，并根据 `mutexprofilerate` 变量控制的采样率来记录互斥锁竞争事件。
3. **共享数据结构：**  阻塞分析和互斥锁分析使用相似的数据结构 (`blockRecord`) 和逻辑来存储和聚合信息。

**数据结构：**

* **`bucket`：** 核心数据结构，存储特定调用栈的分析信息。通过哈希表查找，包含指向下一个 `bucket` 的指针、类型、哈希值、大小和堆栈信息。
* **`memRecord`：**  存储内存分配分析的详细信息，包括 `active` 状态和 `future` 周期的数据，用于跟踪不同时间点的分配和释放情况。
* **`memRecordCycle`：**  表示一个内存分析周期的分配和释放统计数据。
* **`blockRecord`：**  存储阻塞分析或互斥锁分析的计数和周期信息。
* **`mProfCycleHolder`：**  管理全局堆分析周期计数器。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 `runtime` 包中 **性能分析 (Profiling)** 功能的核心组成部分，特别是以下几个方面：

* **`runtime.MemProfile`:**  用于获取内存分配的性能分析数据。
* **`runtime.SetBlockProfileRate`:** 用于控制阻塞事件的采样率。
* **`runtime.SetMutexProfileFraction`:** 用于控制互斥锁竞争事件的采样率。

**Go 代码举例说明：**

虽然这段代码本身属于 `runtime` 包，用户代码不能直接调用其中的大部分函数，但用户可以通过 `runtime` 包提供的接口来触发和获取这些分析数据。

```go
package main

import (
	"fmt"
	"runtime"
	"runtime/pprof"
	"time"
)

func allocateMemory() {
	_ = make([]byte, 1024*1024) // 分配 1MB 内存
}

func blockOperation(ch chan int) {
	<-ch // 阻塞等待 channel 接收数据
}

func main() {
	// 设置内存分析采样率 (每分配 1MB 内存记录一次)
	runtime.MemProfileRate = 1024 * 1024

	// 设置阻塞分析采样率 (每阻塞 1 纳秒记录一次，相当于记录所有阻塞事件)
	runtime.SetBlockProfileRate(1)

	// 设置互斥锁分析采样率 (每次竞争都记录)
	runtime.SetMutexProfileFraction(1)

	// 模拟内存分配
	for i := 0; i < 10; i++ {
		allocateMemory()
	}

	// 模拟阻塞操作
	ch := make(chan int)
	go blockOperation(ch)
	time.Sleep(time.Second) // 让 Goroutine 阻塞一段时间
	close(ch)

	// 获取内存分析数据
	memprof := pprof.Lookup("heap")
	if memprof != nil {
		fmt.Println("Memory Profile Available")
		// 可以将 memprof 写入文件等进行分析
	}

	// 获取阻塞分析数据
	blockprof := pprof.Lookup("block")
	if blockprof != nil {
		fmt.Println("Block Profile Available")
		// 可以将 blockprof 写入文件等进行分析
	}

	// 获取互斥锁分析数据
	mutexprof := pprof.Lookup("mutex")
	if mutexprof != nil {
		fmt.Println("Mutex Profile Available")
		// 可以将 mutexprof 写入文件等进行分析
	}
}
```

**假设的输入与输出（代码推理）：**

假设在 `mProf_Malloc` 函数被调用时，`mp.profStack` 包含以下调用栈信息：

```
[
  0x10a0b00, // 函数 A 的返回地址
  0x10a1200, // 函数 B 的返回地址
  0x10a1900, // 函数 C 的返回地址 (调用 malloc 的函数)
  0x0,       // 栈结束标记
  ...
]
```

并且要分配的内存大小 `size` 是 `1024` 字节。`typ` 是 `memProfile`。

**`stkbucket` 函数的假设输入：**

* `typ`: `memProfile`
* `size`: `1024`
* `stk`: `[0x10a0b00, 0x10a1200, 0x10a1900]`
* `alloc`: `true` (因为是 `mProf_Malloc` 调用)

**可能的输出：**

`stkbucket` 函数会根据调用栈计算哈希值，并在哈希表中查找是否存在匹配的 `bucket`。

* **情况 1：已存在匹配的 `bucket`**
   - 如果哈希表中已存在一个 `typ` 为 `memProfile`，`hash` 值与计算出的哈希值相同，`size` 为 `1024`，且 `stk` 内容相同的 `bucket`，则该函数会返回指向该 `bucket` 的指针。

* **情况 2：不存在匹配的 `bucket`**
   - 如果找不到匹配的 `bucket`，并且 `alloc` 为 `true`，则 `stkbucket` 函数会：
     1. 获取 `profInsertLock`。
     2. 再次检查是否已存在匹配的 `bucket`（以防止并发创建）。
     3. 如果仍然不存在，则调用 `newBucket` 创建一个新的 `bucket`，并将调用栈信息、大小、哈希值等信息存储到新的 `bucket` 中。
     4. 将新的 `bucket` 插入到哈希表中对应的链表中，并更新全局的 `mbuckets` 链表。
     5. 释放 `profInsertLock`。
     6. 返回指向新创建的 `bucket` 的指针。

**`mProf_Malloc` 函数的假设输出：**

1. `callers` 函数会提取 `mp.profStack` 中的有效返回地址，假设 `nstk` 为 3。
2. `stkbucket` 函数会被调用，根据输入查找或创建一个 `bucket`。
3. 获取到或创建的 `bucket` 的 `memRecord` 会被更新，对应 `future` 数组中当前周期的 `allocs` 计数器会加 1，`alloc_bytes` 计数器会加 1024。
4. `setprofilebucket` 函数会被调用，将分配的内存块 `p` 与找到或创建的 `bucket` 关联起来。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。与性能分析相关的配置通常通过以下方式进行：

* **环境变量：** 例如，`GODEBUG` 环境变量可以用于启用或禁用某些调试选项，其中可能包括与性能分析相关的选项（尽管此代码片段中未直接体现）。
* **`runtime` 包的函数：**  如 `runtime.MemProfileRate`、`runtime.SetBlockProfileRate` 和 `runtime.SetMutexProfileFraction`，允许程序在运行时动态调整性能分析的设置。
* **`go test` 命令的标志：** 在运行测试时，可以使用 `-memprofile`、`-blockprofile` 和 `-mutexprofile` 标志来生成性能分析文件。
* **`net/http/pprof` 包：**  对于 Web 应用，可以使用 `net/http/pprof` 包提供的 HTTP 接口来动态获取性能分析数据。

**使用者易犯错的点：**

* **误解采样率的影响：**  如果 `MemProfileRate` 设置过高，会导致错过一些内存分配事件，影响分析的准确性。如果设置过低，会导致性能开销过大。需要根据实际情况权衡。
* **不理解内存分析的时间点快照：**  由于 `malloc` 和 `free` 事件的异步性，以及垃圾回收的影响，内存分析的结果反映的是特定时间点的状态，而不是实时的分配情况。
* **忘记设置采样率：**  默认情况下，某些性能分析功能可能处于关闭状态（例如，`blockprofilerate` 初始值为 0）。使用者需要显式地设置采样率才能启用这些功能。
* **在性能敏感的代码中使用过低的采样率：**  虽然低采样率可以提供更详细的信息，但也可能对程序的性能产生显著影响，尤其是在高并发的场景下。
* **不了解不同 profile 类型的含义：**  内存、阻塞和互斥锁分析分别关注不同的性能瓶颈，需要根据具体的性能问题选择合适的 profile 类型进行分析。

总而言之，这段 `mprof.go` 的代码是 Go 语言运行时环境中实现核心性能分析功能的基础设施，为开发者提供了观察程序内存分配、阻塞和互斥锁竞争情况的手段，从而帮助识别和解决性能瓶颈。理解其工作原理有助于更好地利用 Go 语言提供的性能分析工具。

Prompt: 
```
这是路径为go/src/runtime/mprof.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Malloc profiling.
// Patterned after tcmalloc's algorithms; shorter code.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/profilerecord"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

// NOTE(rsc): Everything here could use cas if contention became an issue.
var (
	// profInsertLock protects changes to the start of all *bucket linked lists
	profInsertLock mutex
	// profBlockLock protects the contents of every blockRecord struct
	profBlockLock mutex
	// profMemActiveLock protects the active field of every memRecord struct
	profMemActiveLock mutex
	// profMemFutureLock is a set of locks that protect the respective elements
	// of the future array of every memRecord struct
	profMemFutureLock [len(memRecord{}.future)]mutex
)

// All memory allocations are local and do not escape outside of the profiler.
// The profiler is forbidden from referring to garbage-collected memory.

const (
	// profile types
	memProfile bucketType = 1 + iota
	blockProfile
	mutexProfile

	// size of bucket hash table
	buckHashSize = 179999

	// maxSkip is to account for deferred inline expansion
	// when using frame pointer unwinding. We record the stack
	// with "physical" frame pointers but handle skipping "logical"
	// frames at some point after collecting the stack. So
	// we need extra space in order to avoid getting fewer than the
	// desired maximum number of frames after expansion.
	// This should be at least as large as the largest skip value
	// used for profiling; otherwise stacks may be truncated inconsistently
	maxSkip = 6

	// maxProfStackDepth is the highest valid value for debug.profstackdepth.
	// It's used for the bucket.stk func.
	// TODO(fg): can we get rid of this?
	maxProfStackDepth = 1024
)

type bucketType int

// A bucket holds per-call-stack profiling information.
// The representation is a bit sleazy, inherited from C.
// This struct defines the bucket header. It is followed in
// memory by the stack words and then the actual record
// data, either a memRecord or a blockRecord.
//
// Per-call-stack profiling information.
// Lookup by hashing call stack into a linked-list hash table.
//
// None of the fields in this bucket header are modified after
// creation, including its next and allnext links.
//
// No heap pointers.
type bucket struct {
	_       sys.NotInHeap
	next    *bucket
	allnext *bucket
	typ     bucketType // memBucket or blockBucket (includes mutexProfile)
	hash    uintptr
	size    uintptr
	nstk    uintptr
}

// A memRecord is the bucket data for a bucket of type memProfile,
// part of the memory profile.
type memRecord struct {
	// The following complex 3-stage scheme of stats accumulation
	// is required to obtain a consistent picture of mallocs and frees
	// for some point in time.
	// The problem is that mallocs come in real time, while frees
	// come only after a GC during concurrent sweeping. So if we would
	// naively count them, we would get a skew toward mallocs.
	//
	// Hence, we delay information to get consistent snapshots as
	// of mark termination. Allocations count toward the next mark
	// termination's snapshot, while sweep frees count toward the
	// previous mark termination's snapshot:
	//
	//              MT          MT          MT          MT
	//             .·|         .·|         .·|         .·|
	//          .·˙  |      .·˙  |      .·˙  |      .·˙  |
	//       .·˙     |   .·˙     |   .·˙     |   .·˙     |
	//    .·˙        |.·˙        |.·˙        |.·˙        |
	//
	//       alloc → ▲ ← free
	//               ┠┅┅┅┅┅┅┅┅┅┅┅P
	//       C+2     →    C+1    →  C
	//
	//                   alloc → ▲ ← free
	//                           ┠┅┅┅┅┅┅┅┅┅┅┅P
	//                   C+2     →    C+1    →  C
	//
	// Since we can't publish a consistent snapshot until all of
	// the sweep frees are accounted for, we wait until the next
	// mark termination ("MT" above) to publish the previous mark
	// termination's snapshot ("P" above). To do this, allocation
	// and free events are accounted to *future* heap profile
	// cycles ("C+n" above) and we only publish a cycle once all
	// of the events from that cycle must be done. Specifically:
	//
	// Mallocs are accounted to cycle C+2.
	// Explicit frees are accounted to cycle C+2.
	// GC frees (done during sweeping) are accounted to cycle C+1.
	//
	// After mark termination, we increment the global heap
	// profile cycle counter and accumulate the stats from cycle C
	// into the active profile.

	// active is the currently published profile. A profiling
	// cycle can be accumulated into active once its complete.
	active memRecordCycle

	// future records the profile events we're counting for cycles
	// that have not yet been published. This is ring buffer
	// indexed by the global heap profile cycle C and stores
	// cycles C, C+1, and C+2. Unlike active, these counts are
	// only for a single cycle; they are not cumulative across
	// cycles.
	//
	// We store cycle C here because there's a window between when
	// C becomes the active cycle and when we've flushed it to
	// active.
	future [3]memRecordCycle
}

// memRecordCycle
type memRecordCycle struct {
	allocs, frees           uintptr
	alloc_bytes, free_bytes uintptr
}

// add accumulates b into a. It does not zero b.
func (a *memRecordCycle) add(b *memRecordCycle) {
	a.allocs += b.allocs
	a.frees += b.frees
	a.alloc_bytes += b.alloc_bytes
	a.free_bytes += b.free_bytes
}

// A blockRecord is the bucket data for a bucket of type blockProfile,
// which is used in blocking and mutex profiles.
type blockRecord struct {
	count  float64
	cycles int64
}

var (
	mbuckets atomic.UnsafePointer // *bucket, memory profile buckets
	bbuckets atomic.UnsafePointer // *bucket, blocking profile buckets
	xbuckets atomic.UnsafePointer // *bucket, mutex profile buckets
	buckhash atomic.UnsafePointer // *buckhashArray

	mProfCycle mProfCycleHolder
)

type buckhashArray [buckHashSize]atomic.UnsafePointer // *bucket

const mProfCycleWrap = uint32(len(memRecord{}.future)) * (2 << 24)

// mProfCycleHolder holds the global heap profile cycle number (wrapped at
// mProfCycleWrap, stored starting at bit 1), and a flag (stored at bit 0) to
// indicate whether future[cycle] in all buckets has been queued to flush into
// the active profile.
type mProfCycleHolder struct {
	value atomic.Uint32
}

// read returns the current cycle count.
func (c *mProfCycleHolder) read() (cycle uint32) {
	v := c.value.Load()
	cycle = v >> 1
	return cycle
}

// setFlushed sets the flushed flag. It returns the current cycle count and the
// previous value of the flushed flag.
func (c *mProfCycleHolder) setFlushed() (cycle uint32, alreadyFlushed bool) {
	for {
		prev := c.value.Load()
		cycle = prev >> 1
		alreadyFlushed = (prev & 0x1) != 0
		next := prev | 0x1
		if c.value.CompareAndSwap(prev, next) {
			return cycle, alreadyFlushed
		}
	}
}

// increment increases the cycle count by one, wrapping the value at
// mProfCycleWrap. It clears the flushed flag.
func (c *mProfCycleHolder) increment() {
	// We explicitly wrap mProfCycle rather than depending on
	// uint wraparound because the memRecord.future ring does not
	// itself wrap at a power of two.
	for {
		prev := c.value.Load()
		cycle := prev >> 1
		cycle = (cycle + 1) % mProfCycleWrap
		next := cycle << 1
		if c.value.CompareAndSwap(prev, next) {
			break
		}
	}
}

// newBucket allocates a bucket with the given type and number of stack entries.
func newBucket(typ bucketType, nstk int) *bucket {
	size := unsafe.Sizeof(bucket{}) + uintptr(nstk)*unsafe.Sizeof(uintptr(0))
	switch typ {
	default:
		throw("invalid profile bucket type")
	case memProfile:
		size += unsafe.Sizeof(memRecord{})
	case blockProfile, mutexProfile:
		size += unsafe.Sizeof(blockRecord{})
	}

	b := (*bucket)(persistentalloc(size, 0, &memstats.buckhash_sys))
	b.typ = typ
	b.nstk = uintptr(nstk)
	return b
}

// stk returns the slice in b holding the stack. The caller can assume that the
// backing array is immutable.
func (b *bucket) stk() []uintptr {
	stk := (*[maxProfStackDepth]uintptr)(add(unsafe.Pointer(b), unsafe.Sizeof(*b)))
	if b.nstk > maxProfStackDepth {
		// prove that slicing works; otherwise a failure requires a P
		throw("bad profile stack count")
	}
	return stk[:b.nstk:b.nstk]
}

// mp returns the memRecord associated with the memProfile bucket b.
func (b *bucket) mp() *memRecord {
	if b.typ != memProfile {
		throw("bad use of bucket.mp")
	}
	data := add(unsafe.Pointer(b), unsafe.Sizeof(*b)+b.nstk*unsafe.Sizeof(uintptr(0)))
	return (*memRecord)(data)
}

// bp returns the blockRecord associated with the blockProfile bucket b.
func (b *bucket) bp() *blockRecord {
	if b.typ != blockProfile && b.typ != mutexProfile {
		throw("bad use of bucket.bp")
	}
	data := add(unsafe.Pointer(b), unsafe.Sizeof(*b)+b.nstk*unsafe.Sizeof(uintptr(0)))
	return (*blockRecord)(data)
}

// Return the bucket for stk[0:nstk], allocating new bucket if needed.
func stkbucket(typ bucketType, size uintptr, stk []uintptr, alloc bool) *bucket {
	bh := (*buckhashArray)(buckhash.Load())
	if bh == nil {
		lock(&profInsertLock)
		// check again under the lock
		bh = (*buckhashArray)(buckhash.Load())
		if bh == nil {
			bh = (*buckhashArray)(sysAlloc(unsafe.Sizeof(buckhashArray{}), &memstats.buckhash_sys))
			if bh == nil {
				throw("runtime: cannot allocate memory")
			}
			buckhash.StoreNoWB(unsafe.Pointer(bh))
		}
		unlock(&profInsertLock)
	}

	// Hash stack.
	var h uintptr
	for _, pc := range stk {
		h += pc
		h += h << 10
		h ^= h >> 6
	}
	// hash in size
	h += size
	h += h << 10
	h ^= h >> 6
	// finalize
	h += h << 3
	h ^= h >> 11

	i := int(h % buckHashSize)
	// first check optimistically, without the lock
	for b := (*bucket)(bh[i].Load()); b != nil; b = b.next {
		if b.typ == typ && b.hash == h && b.size == size && eqslice(b.stk(), stk) {
			return b
		}
	}

	if !alloc {
		return nil
	}

	lock(&profInsertLock)
	// check again under the insertion lock
	for b := (*bucket)(bh[i].Load()); b != nil; b = b.next {
		if b.typ == typ && b.hash == h && b.size == size && eqslice(b.stk(), stk) {
			unlock(&profInsertLock)
			return b
		}
	}

	// Create new bucket.
	b := newBucket(typ, len(stk))
	copy(b.stk(), stk)
	b.hash = h
	b.size = size

	var allnext *atomic.UnsafePointer
	if typ == memProfile {
		allnext = &mbuckets
	} else if typ == mutexProfile {
		allnext = &xbuckets
	} else {
		allnext = &bbuckets
	}

	b.next = (*bucket)(bh[i].Load())
	b.allnext = (*bucket)(allnext.Load())

	bh[i].StoreNoWB(unsafe.Pointer(b))
	allnext.StoreNoWB(unsafe.Pointer(b))

	unlock(&profInsertLock)
	return b
}

func eqslice(x, y []uintptr) bool {
	if len(x) != len(y) {
		return false
	}
	for i, xi := range x {
		if xi != y[i] {
			return false
		}
	}
	return true
}

// mProf_NextCycle publishes the next heap profile cycle and creates a
// fresh heap profile cycle. This operation is fast and can be done
// during STW. The caller must call mProf_Flush before calling
// mProf_NextCycle again.
//
// This is called by mark termination during STW so allocations and
// frees after the world is started again count towards a new heap
// profiling cycle.
func mProf_NextCycle() {
	mProfCycle.increment()
}

// mProf_Flush flushes the events from the current heap profiling
// cycle into the active profile. After this it is safe to start a new
// heap profiling cycle with mProf_NextCycle.
//
// This is called by GC after mark termination starts the world. In
// contrast with mProf_NextCycle, this is somewhat expensive, but safe
// to do concurrently.
func mProf_Flush() {
	cycle, alreadyFlushed := mProfCycle.setFlushed()
	if alreadyFlushed {
		return
	}

	index := cycle % uint32(len(memRecord{}.future))
	lock(&profMemActiveLock)
	lock(&profMemFutureLock[index])
	mProf_FlushLocked(index)
	unlock(&profMemFutureLock[index])
	unlock(&profMemActiveLock)
}

// mProf_FlushLocked flushes the events from the heap profiling cycle at index
// into the active profile. The caller must hold the lock for the active profile
// (profMemActiveLock) and for the profiling cycle at index
// (profMemFutureLock[index]).
func mProf_FlushLocked(index uint32) {
	assertLockHeld(&profMemActiveLock)
	assertLockHeld(&profMemFutureLock[index])
	head := (*bucket)(mbuckets.Load())
	for b := head; b != nil; b = b.allnext {
		mp := b.mp()

		// Flush cycle C into the published profile and clear
		// it for reuse.
		mpc := &mp.future[index]
		mp.active.add(mpc)
		*mpc = memRecordCycle{}
	}
}

// mProf_PostSweep records that all sweep frees for this GC cycle have
// completed. This has the effect of publishing the heap profile
// snapshot as of the last mark termination without advancing the heap
// profile cycle.
func mProf_PostSweep() {
	// Flush cycle C+1 to the active profile so everything as of
	// the last mark termination becomes visible. *Don't* advance
	// the cycle, since we're still accumulating allocs in cycle
	// C+2, which have to become C+1 in the next mark termination
	// and so on.
	cycle := mProfCycle.read() + 1

	index := cycle % uint32(len(memRecord{}.future))
	lock(&profMemActiveLock)
	lock(&profMemFutureLock[index])
	mProf_FlushLocked(index)
	unlock(&profMemFutureLock[index])
	unlock(&profMemActiveLock)
}

// Called by malloc to record a profiled block.
func mProf_Malloc(mp *m, p unsafe.Pointer, size uintptr) {
	if mp.profStack == nil {
		// mp.profStack is nil if we happen to sample an allocation during the
		// initialization of mp. This case is rare, so we just ignore such
		// allocations. Change MemProfileRate to 1 if you need to reproduce such
		// cases for testing purposes.
		return
	}
	// Only use the part of mp.profStack we need and ignore the extra space
	// reserved for delayed inline expansion with frame pointer unwinding.
	nstk := callers(5, mp.profStack[:debug.profstackdepth])
	index := (mProfCycle.read() + 2) % uint32(len(memRecord{}.future))

	b := stkbucket(memProfile, size, mp.profStack[:nstk], true)
	mr := b.mp()
	mpc := &mr.future[index]

	lock(&profMemFutureLock[index])
	mpc.allocs++
	mpc.alloc_bytes += size
	unlock(&profMemFutureLock[index])

	// Setprofilebucket locks a bunch of other mutexes, so we call it outside of
	// the profiler locks. This reduces potential contention and chances of
	// deadlocks. Since the object must be alive during the call to
	// mProf_Malloc, it's fine to do this non-atomically.
	systemstack(func() {
		setprofilebucket(p, b)
	})
}

// Called when freeing a profiled block.
func mProf_Free(b *bucket, size uintptr) {
	index := (mProfCycle.read() + 1) % uint32(len(memRecord{}.future))

	mp := b.mp()
	mpc := &mp.future[index]

	lock(&profMemFutureLock[index])
	mpc.frees++
	mpc.free_bytes += size
	unlock(&profMemFutureLock[index])
}

var blockprofilerate uint64 // in CPU ticks

// SetBlockProfileRate controls the fraction of goroutine blocking events
// that are reported in the blocking profile. The profiler aims to sample
// an average of one blocking event per rate nanoseconds spent blocked.
//
// To include every blocking event in the profile, pass rate = 1.
// To turn off profiling entirely, pass rate <= 0.
func SetBlockProfileRate(rate int) {
	var r int64
	if rate <= 0 {
		r = 0 // disable profiling
	} else if rate == 1 {
		r = 1 // profile everything
	} else {
		// convert ns to cycles, use float64 to prevent overflow during multiplication
		r = int64(float64(rate) * float64(ticksPerSecond()) / (1000 * 1000 * 1000))
		if r == 0 {
			r = 1
		}
	}

	atomic.Store64(&blockprofilerate, uint64(r))
}

func blockevent(cycles int64, skip int) {
	if cycles <= 0 {
		cycles = 1
	}

	rate := int64(atomic.Load64(&blockprofilerate))
	if blocksampled(cycles, rate) {
		saveblockevent(cycles, rate, skip+1, blockProfile)
	}
}

// blocksampled returns true for all events where cycles >= rate. Shorter
// events have a cycles/rate random chance of returning true.
func blocksampled(cycles, rate int64) bool {
	if rate <= 0 || (rate > cycles && cheaprand64()%rate > cycles) {
		return false
	}
	return true
}

// saveblockevent records a profile event of the type specified by which.
// cycles is the quantity associated with this event and rate is the sampling rate,
// used to adjust the cycles value in the manner determined by the profile type.
// skip is the number of frames to omit from the traceback associated with the event.
// The traceback will be recorded from the stack of the goroutine associated with the current m.
// skip should be positive if this event is recorded from the current stack
// (e.g. when this is not called from a system stack)
func saveblockevent(cycles, rate int64, skip int, which bucketType) {
	if debug.profstackdepth == 0 {
		// profstackdepth is set to 0 by the user, so mp.profStack is nil and we
		// can't record a stack trace.
		return
	}
	if skip > maxSkip {
		print("requested skip=", skip)
		throw("invalid skip value")
	}
	gp := getg()
	mp := acquirem() // we must not be preempted while accessing profstack

	var nstk int
	if tracefpunwindoff() || gp.m.hasCgoOnStack() {
		if gp.m.curg == nil || gp.m.curg == gp {
			nstk = callers(skip, mp.profStack)
		} else {
			nstk = gcallers(gp.m.curg, skip, mp.profStack)
		}
	} else {
		if gp.m.curg == nil || gp.m.curg == gp {
			if skip > 0 {
				// We skip one fewer frame than the provided value for frame
				// pointer unwinding because the skip value includes the current
				// frame, whereas the saved frame pointer will give us the
				// caller's return address first (so, not including
				// saveblockevent)
				skip -= 1
			}
			nstk = fpTracebackPartialExpand(skip, unsafe.Pointer(getfp()), mp.profStack)
		} else {
			mp.profStack[0] = gp.m.curg.sched.pc
			nstk = 1 + fpTracebackPartialExpand(skip, unsafe.Pointer(gp.m.curg.sched.bp), mp.profStack[1:])
		}
	}

	saveBlockEventStack(cycles, rate, mp.profStack[:nstk], which)
	releasem(mp)
}

// fpTracebackPartialExpand records a call stack obtained starting from fp.
// This function will skip the given number of frames, properly accounting for
// inlining, and save remaining frames as "physical" return addresses. The
// consumer should later use CallersFrames or similar to expand inline frames.
func fpTracebackPartialExpand(skip int, fp unsafe.Pointer, pcBuf []uintptr) int {
	var n int
	lastFuncID := abi.FuncIDNormal
	skipOrAdd := func(retPC uintptr) bool {
		if skip > 0 {
			skip--
		} else if n < len(pcBuf) {
			pcBuf[n] = retPC
			n++
		}
		return n < len(pcBuf)
	}
	for n < len(pcBuf) && fp != nil {
		// return addr sits one word above the frame pointer
		pc := *(*uintptr)(unsafe.Pointer(uintptr(fp) + goarch.PtrSize))

		if skip > 0 {
			callPC := pc - 1
			fi := findfunc(callPC)
			u, uf := newInlineUnwinder(fi, callPC)
			for ; uf.valid(); uf = u.next(uf) {
				sf := u.srcFunc(uf)
				if sf.funcID == abi.FuncIDWrapper && elideWrapperCalling(lastFuncID) {
					// ignore wrappers
				} else if more := skipOrAdd(uf.pc + 1); !more {
					return n
				}
				lastFuncID = sf.funcID
			}
		} else {
			// We've skipped the desired number of frames, so no need
			// to perform further inline expansion now.
			pcBuf[n] = pc
			n++
		}

		// follow the frame pointer to the next one
		fp = unsafe.Pointer(*(*uintptr)(fp))
	}
	return n
}

// lockTimer assists with profiling contention on runtime-internal locks.
//
// There are several steps between the time that an M experiences contention and
// when that contention may be added to the profile. This comes from our
// constraints: We need to keep the critical section of each lock small,
// especially when those locks are contended. The reporting code cannot acquire
// new locks until the M has released all other locks, which means no memory
// allocations and encourages use of (temporary) M-local storage.
//
// The M will have space for storing one call stack that caused contention, and
// for the magnitude of that contention. It will also have space to store the
// magnitude of additional contention the M caused, since it only has space to
// remember one call stack and might encounter several contention events before
// it releases all of its locks and is thus able to transfer the local buffer
// into the profile.
//
// The M will collect the call stack when it unlocks the contended lock. That
// minimizes the impact on the critical section of the contended lock, and
// matches the mutex profile's behavior for contention in sync.Mutex: measured
// at the Unlock method.
//
// The profile for contention on sync.Mutex blames the caller of Unlock for the
// amount of contention experienced by the callers of Lock which had to wait.
// When there are several critical sections, this allows identifying which of
// them is responsible.
//
// Matching that behavior for runtime-internal locks will require identifying
// which Ms are blocked on the mutex. The semaphore-based implementation is
// ready to allow that, but the futex-based implementation will require a bit
// more work. Until then, we report contention on runtime-internal locks with a
// call stack taken from the unlock call (like the rest of the user-space
// "mutex" profile), but assign it a duration value based on how long the
// previous lock call took (like the user-space "block" profile).
//
// Thus, reporting the call stacks of runtime-internal lock contention is
// guarded by GODEBUG for now. Set GODEBUG=runtimecontentionstacks=1 to enable.
//
// TODO(rhysh): plumb through the delay duration, remove GODEBUG, update comment
//
// The M will track this by storing a pointer to the lock; lock/unlock pairs for
// runtime-internal locks are always on the same M.
//
// Together, that demands several steps for recording contention. First, when
// finally acquiring a contended lock, the M decides whether it should plan to
// profile that event by storing a pointer to the lock in its "to be profiled
// upon unlock" field. If that field is already set, it uses the relative
// magnitudes to weight a random choice between itself and the other lock, with
// the loser's time being added to the "additional contention" field. Otherwise
// if the M's call stack buffer is occupied, it does the comparison against that
// sample's magnitude.
//
// Second, having unlocked a mutex the M checks to see if it should capture the
// call stack into its local buffer. Finally, when the M unlocks its last mutex,
// it transfers the local buffer into the profile. As part of that step, it also
// transfers any "additional contention" time to the profile. Any lock
// contention that it experiences while adding samples to the profile will be
// recorded later as "additional contention" and not include a call stack, to
// avoid an echo.
type lockTimer struct {
	lock      *mutex
	timeRate  int64
	timeStart int64
	tickStart int64
}

func (lt *lockTimer) begin() {
	rate := int64(atomic.Load64(&mutexprofilerate))

	lt.timeRate = gTrackingPeriod
	if rate != 0 && rate < lt.timeRate {
		lt.timeRate = rate
	}
	if int64(cheaprand())%lt.timeRate == 0 {
		lt.timeStart = nanotime()
	}

	if rate > 0 && int64(cheaprand())%rate == 0 {
		lt.tickStart = cputicks()
	}
}

func (lt *lockTimer) end() {
	gp := getg()

	if lt.timeStart != 0 {
		nowTime := nanotime()
		gp.m.mLockProfile.waitTime.Add((nowTime - lt.timeStart) * lt.timeRate)
	}

	if lt.tickStart != 0 {
		nowTick := cputicks()
		gp.m.mLockProfile.recordLock(nowTick-lt.tickStart, lt.lock)
	}
}

type mLockProfile struct {
	waitTime   atomic.Int64 // total nanoseconds spent waiting in runtime.lockWithRank
	stack      []uintptr    // stack that experienced contention in runtime.lockWithRank
	pending    uintptr      // *mutex that experienced contention (to be traceback-ed)
	cycles     int64        // cycles attributable to "pending" (if set), otherwise to "stack"
	cyclesLost int64        // contention for which we weren't able to record a call stack
	haveStack  bool         // stack and cycles are to be added to the mutex profile
	disabled   bool         // attribute all time to "lost"
}

func (prof *mLockProfile) recordLock(cycles int64, l *mutex) {
	if cycles < 0 {
		cycles = 0
	}

	if prof.disabled {
		// We're experiencing contention while attempting to report contention.
		// Make a note of its magnitude, but don't allow it to be the sole cause
		// of another contention report.
		prof.cyclesLost += cycles
		return
	}

	if uintptr(unsafe.Pointer(l)) == prof.pending {
		// Optimization: we'd already planned to profile this same lock (though
		// possibly from a different unlock site).
		prof.cycles += cycles
		return
	}

	if prev := prof.cycles; prev > 0 {
		// We can only store one call stack for runtime-internal lock contention
		// on this M, and we've already got one. Decide which should stay, and
		// add the other to the report for runtime._LostContendedRuntimeLock.
		if cycles == 0 {
			return
		}
		prevScore := uint64(cheaprand64()) % uint64(prev)
		thisScore := uint64(cheaprand64()) % uint64(cycles)
		if prevScore > thisScore {
			prof.cyclesLost += cycles
			return
		} else {
			prof.cyclesLost += prev
		}
	}
	// Saving the *mutex as a uintptr is safe because:
	//  - lockrank_on.go does this too, which gives it regular exercise
	//  - the lock would only move if it's stack allocated, which means it
	//      cannot experience multi-M contention
	prof.pending = uintptr(unsafe.Pointer(l))
	prof.cycles = cycles
}

// From unlock2, we might not be holding a p in this code.
//
//go:nowritebarrierrec
func (prof *mLockProfile) recordUnlock(l *mutex) {
	if uintptr(unsafe.Pointer(l)) == prof.pending {
		prof.captureStack()
	}
	if gp := getg(); gp.m.locks == 1 && gp.m.mLockProfile.haveStack {
		prof.store()
	}
}

func (prof *mLockProfile) captureStack() {
	if debug.profstackdepth == 0 {
		// profstackdepth is set to 0 by the user, so mp.profStack is nil and we
		// can't record a stack trace.
		return
	}

	skip := 3 // runtime.(*mLockProfile).recordUnlock runtime.unlock2 runtime.unlockWithRank
	if staticLockRanking {
		// When static lock ranking is enabled, we'll always be on the system
		// stack at this point. There will be a runtime.unlockWithRank.func1
		// frame, and if the call to runtime.unlock took place on a user stack
		// then there'll also be a runtime.systemstack frame. To keep stack
		// traces somewhat consistent whether or not static lock ranking is
		// enabled, we'd like to skip those. But it's hard to tell how long
		// we've been on the system stack so accept an extra frame in that case,
		// with a leaf of "runtime.unlockWithRank runtime.unlock" instead of
		// "runtime.unlock".
		skip += 1 // runtime.unlockWithRank.func1
	}
	prof.pending = 0
	prof.haveStack = true

	prof.stack[0] = logicalStackSentinel
	if debug.runtimeContentionStacks.Load() == 0 {
		prof.stack[1] = abi.FuncPCABIInternal(_LostContendedRuntimeLock) + sys.PCQuantum
		prof.stack[2] = 0
		return
	}

	var nstk int
	gp := getg()
	sp := sys.GetCallerSP()
	pc := sys.GetCallerPC()
	systemstack(func() {
		var u unwinder
		u.initAt(pc, sp, 0, gp, unwindSilentErrors|unwindJumpStack)
		nstk = 1 + tracebackPCs(&u, skip, prof.stack[1:])
	})
	if nstk < len(prof.stack) {
		prof.stack[nstk] = 0
	}
}

func (prof *mLockProfile) store() {
	// Report any contention we experience within this function as "lost"; it's
	// important that the act of reporting a contention event not lead to a
	// reportable contention event. This also means we can use prof.stack
	// without copying, since it won't change during this function.
	mp := acquirem()
	prof.disabled = true

	nstk := int(debug.profstackdepth)
	for i := 0; i < nstk; i++ {
		if pc := prof.stack[i]; pc == 0 {
			nstk = i
			break
		}
	}

	cycles, lost := prof.cycles, prof.cyclesLost
	prof.cycles, prof.cyclesLost = 0, 0
	prof.haveStack = false

	rate := int64(atomic.Load64(&mutexprofilerate))
	saveBlockEventStack(cycles, rate, prof.stack[:nstk], mutexProfile)
	if lost > 0 {
		lostStk := [...]uintptr{
			logicalStackSentinel,
			abi.FuncPCABIInternal(_LostContendedRuntimeLock) + sys.PCQuantum,
		}
		saveBlockEventStack(lost, rate, lostStk[:], mutexProfile)
	}

	prof.disabled = false
	releasem(mp)
}

func saveBlockEventStack(cycles, rate int64, stk []uintptr, which bucketType) {
	b := stkbucket(which, 0, stk, true)
	bp := b.bp()

	lock(&profBlockLock)
	// We want to up-scale the count and cycles according to the
	// probability that the event was sampled. For block profile events,
	// the sample probability is 1 if cycles >= rate, and cycles / rate
	// otherwise. For mutex profile events, the sample probability is 1 / rate.
	// We scale the events by 1 / (probability the event was sampled).
	if which == blockProfile && cycles < rate {
		// Remove sampling bias, see discussion on http://golang.org/cl/299991.
		bp.count += float64(rate) / float64(cycles)
		bp.cycles += rate
	} else if which == mutexProfile {
		bp.count += float64(rate)
		bp.cycles += rate * cycles
	} else {
		bp.count++
		bp.cycles += cycles
	}
	unlock(&profBlockLock)
}

var mutexprofilerate uint64 // fraction sampled

// SetMutexProfileFraction controls the fraction of mutex contention events
// that are reported in the mutex profile. On average 1/rate events are
// reported. The previous rate is returned.
//
// To turn off profiling entirely, pass rate 0.
// To just read the current rate, pass rate < 0.
// (For n>1 the details of sampling may change.)
func SetMutexProfileFraction(rate int) int {
	if rate < 0 {
		return int(mutexprofilerate)
	}
	old := mutexprofilerate
	atomic.Store64(&mutexprofilerate, uint64(rate))
	return int(old)
}

//go:linkname mutexevent sync.event
func mutexevent(cycles int64, skip int) {
	if cycles < 0 {
		cycles = 0
	}
	rate := int64(atomic.Load64(&mutexprofilerate))
	if rate > 0 && cheaprand64()%rate == 0 {
		saveblockevent(cycles, rate, skip+1, mutexProfile)
	}
}

// Go interface to profile data.

// A StackRecord describes a single execution stack.
type StackRecord struct {
	Stack0 [32]uintptr // stack trace for this record; ends at first 0 entry
}

// Stack returns the stack trace associated with the record,
// a prefix of r.Stack0.
func (r *StackRecord) Stack() []uintptr {
	for i, v := range r.Stack0 {
		if v == 0 {
			return r.Stack0[0:i]
		}
	}
	return r.Stack0[0:]
}

// MemProfileRate controls the fraction of memory allocations
// that are recorded and reported in the memory profile.
// The profiler aims to sample an average of
// one allocation per MemProfileRate bytes allocated.
//
// To include every allocated block in the profile, set MemProfileRate to 1.
// To turn off profiling entirely, set MemProfileRate to 0.
//
// The tools that process the memory profiles assume that the
// profile rate is constant across the lifetime of the program
// and equal to the current value. Programs that change the
// memory profiling rate should do so just once, as early as
// possible in the execution of the program (for example,
// at the beginning of main).
var MemProfileRate int = 512 * 1024

// disableMemoryProfiling is set by the linker if memory profiling
// is not used and the link type guarantees nobody else could use it
// elsewhere.
// We check if the runtime.memProfileInternal symbol is present.
var disableMemoryProfiling bool

// A MemProfileRecord describes the live objects allocated
// by a particular call sequence (stack trace).
type MemProfileRecord struct {
	AllocBytes, FreeBytes     int64       // number of bytes allocated, freed
	AllocObjects, FreeObjects int64       // number of objects allocated, freed
	Stack0                    [32]uintptr // stack trace for this record; ends at first 0 entry
}

// InUseBytes returns the number of bytes in use (AllocBytes - FreeBytes).
func (r *MemProfileRecord) InUseBytes() int64 { return r.AllocBytes - r.FreeBytes }

// InUseObjects returns the number of objects in use (AllocObjects - FreeObjects).
func (r *MemProfileRecord) InUseObjects() int64 {
	return r.AllocObjects - r.FreeObjects
}

// Stack returns the stack trace associated with the record,
// a prefix of r.Stack0.
func (r *MemProfileRecord) Stack() []uintptr {
	for i, v := range r.Stack0 {
		if v == 0 {
			return r.Stack0[0:i]
		}
	}
	return r.Stack0[0:]
}

// MemProfile returns a profile of memory allocated and freed per allocation
// site.
//
// MemProfile returns n, the number of records in the current memory profile.
// If len(p) >= n, MemProfile copies the profile into p and returns n, true.
// If len(p) < n, MemProfile does not change p and returns n, false.
//
// If inuseZero is true, the profile includes allocation records
// where r.AllocBytes > 0 but r.AllocBytes == r.FreeBytes.
// These are sites where memory was allocated, but it has all
// been
"""




```