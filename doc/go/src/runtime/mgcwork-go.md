Response:
Let's break down the thought process for analyzing the `mgcwork.go` code snippet and generating the response.

**1. Understanding the Core Purpose:**

The initial comments and the structure of the `gcWork` struct immediately suggest this code is about managing work for the garbage collector. The terms "grey objects," "black objects," "work queue," "produce," and "consume" are strong indicators. The mention of "write barriers," "root discovery," and "stack scanning" reinforces this. The fundamental goal seems to be distributing and processing objects that need to be scanned during the GC cycle.

**2. Deconstructing the `gcWork` Struct:**

* **`wbuf1`, `wbuf2 *workbuf`:**  These are clearly the core data structures. The comments about primary/secondary buffers and the "stack" analogy are crucial for understanding the local work buffering strategy. The hysteresis concept is interesting and hints at performance optimization.
* **`bytesMarked uint64`:**  This is a counter, likely tracking the amount of work done by this specific `gcWork` instance.
* **`heapScanWork int64`:** Another counter, focusing on a specific type of work related to heap scanning.
* **`flushedWork bool`:** A flag to track if work has been moved to the global queue, important for inter-worker communication.

**3. Analyzing Key Functions of `gcWork`:**

* **`init()`:**  Simple initialization, acquiring empty work buffers.
* **`put(obj uintptr)`:**  The producer function. The logic around `wbuf1`, `wbuf2`, and the `putfull()` call points to how local buffers are filled and then moved to a global queue. The `enlistWorker()` call hints at triggering more GC worker activity.
* **`putFast(obj uintptr)`:**  An optimization for fast path enqueuing, avoiding the overhead of buffer swapping.
* **`putBatch(obj []uintptr)`:**  Handles enqueuing multiple objects efficiently.
* **`tryGet() uintptr`:** The consumer function. The logic mirrors `put`, retrieving work from local buffers and then the global queue (`trygetfull()`).
* **`tryGetFast() uintptr`:**  Fast path retrieval.
* **`dispose()`:**  Crucial for cleaning up. Moving local buffers to the global queue and aggregating the counters are the key actions. This is likely called when a worker finishes its current task.
* **`balance()`:**  A mechanism to proactively move work to the global queue, potentially to improve work distribution.
* **`empty()`:** Checks if there's any local work remaining.

**4. Examining `workbuf` and its Factories:**

* **`workbuf` struct:**  The internal structure for storing pointers. The fixed-size array `obj` is the actual work queue.
* **`getempty()`:** Allocates new work buffers, potentially involving acquiring memory from the heap. The logic for managing `work.empty` and `work.wbufSpans` is apparent.
* **`putempty()`:** Returns an empty buffer to the `work.empty` list.
* **`putfull()`:** Moves a full (or partially full) buffer to the global `work.full` list.
* **`trygetfull()`:** Attempts to retrieve a buffer from the global `work.full` list.
* **`handoff()`:**  Splits a work buffer to distribute work.

**5. Inferring the Go Feature:**

Based on the terminology and functionality, it's clear this code implements the **concurrent garbage collector's work stealing mechanism**. The `gcWork` acts as a local work queue for each worker (likely a P in the Go scheduler), and the global queues (`work.empty`, `work.full`) facilitate sharing work between workers.

**6. Crafting the Go Code Example:**

The example should demonstrate how a typical GC worker would use `gcWork`. This involves getting a `gcWork` instance, putting objects onto it, and then getting objects back for processing. Disabling preemption is essential because, as the comments state, manipulating `gcWork` during the mark phase requires preventing state transitions.

**7. Identifying Potential Pitfalls:**

The "preemption must be disabled" comment is a major red flag for potential errors. Forgetting this could lead to race conditions and data corruption during the GC mark phase.

**8. Structuring the Answer:**

Organizing the answer into logical sections (Functionality, Go Feature, Code Example, Potential Pitfalls) makes it easier to understand. Using clear and concise language is important. For the code example, providing assumed inputs and outputs clarifies the behavior.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this is just about managing memory buffers for GC.
* **Correction:** The terms "grey objects," "black objects," and the put/get operations strongly indicate it's about managing *work*, not just raw memory.
* **Refinement of the Go example:** Initially, I considered a more complex scenario. However, a simple put/get sequence clearly illustrates the core functionality. Adding the preemption disabling detail is crucial.
* **Clarifying potential pitfalls:** Focusing on the preemption issue is the most significant and easily understood potential error for users interacting with GC internals (even indirectly).

By following these steps of understanding the core purpose, dissecting the data structures and functions, inferring the higher-level functionality, creating a relevant example, and identifying common errors, we can effectively analyze and explain the given Go code snippet.
这段代码是 Go 语言运行时（runtime）中垃圾回收器（Garbage Collector，GC）工作窃取（Work Stealing）机制的一部分实现。它定义了用于生产和消费待扫描对象的 `gcWork` 结构体以及相关的操作函数。

**主要功能:**

1. **管理垃圾回收的待扫描对象（grey objects）队列:**  `gcWork` 结构体充当一个本地的工作队列，用于缓存待垃圾回收扫描的对象指针。这些对象被称为“灰色对象”，表示它们已经被标记但尚未被扫描。

2. **生产者/消费者模型:**  GC 的各个阶段（如写屏障、根对象发现、栈扫描、对象扫描）会产生指向灰色对象的指针，并将它们放入 `gcWork` 的队列中（生产者）。扫描器线程则从 `gcWork` 的队列中取出这些指针，扫描对象，并可能产生新的灰色对象（消费者）。

3. **本地缓存以减少竞争:**  每个 `gcWork` 实例都拥有两个工作缓冲区 (`wbuf1` 和 `wbuf2`)，作为本地缓存。这减少了多个 GC 工作线程直接竞争全局工作队列的频率，提高了效率。

4. **工作窃取的支持:** 当一个 GC 工作线程的本地队列为空时，它可以从全局工作队列或其他工作线程的本地队列中“窃取”工作。虽然这段代码本身没有直接体现“窃取”的逻辑，但它为工作窃取提供了基础的数据结构和操作。 `putfull` 和 `trygetfull` 等函数用于与全局工作队列交互。

5. **延迟刷新到全局队列:**  `gcWork` 会先将工作对象缓存在本地缓冲区中，当缓冲区满或需要平衡工作负载时，再将缓冲区刷新到全局工作队列。这通过 `putfull` 函数实现。

6. **从全局队列获取工作:** 当本地缓冲区为空时，`gcWork` 可以尝试从全局工作队列中获取工作，通过 `trygetfull` 函数实现。

**它是什么 Go 语言功能的实现？**

这段代码是 **Go 语言并发垃圾回收器**中 **并发标记阶段的工作窃取机制** 的核心组件之一。 具体来说，它实现了每个 P (Processor，Go 运行时中的逻辑处理器) 关联的本地工作队列。

**Go 代码举例说明:**

以下代码示例展示了一个简化的场景，说明了 `gcWork` 的基本使用方式。 请注意，这只是为了演示 `gcWork` 的 `put` 和 `tryGet` 操作，实际的 GC 过程远比这复杂。

```go
package main

import (
	"fmt"
	"runtime"
	"unsafe"
)

// 假设这是 runtime 包中的 gcWork 结构体 (简化版)
type gcWork struct {
	wbuf1 *workbuf
	wbuf2 *workbuf
}

// 假设这是 runtime 包中的 workbuf 结构体 (简化版)
type workbuf struct {
	obj  [10]uintptr // 存储对象指针
	nobj int        // 当前缓冲区中的对象数量
}

// 假设这是 runtime 包中的 getempty 函数 (简化版)
func getempty() *workbuf {
	return &workbuf{}
}

// 假设这是 runtime 包中的 putfull 函数 (简化版)
func putfull(wb *workbuf) {
	fmt.Printf("将缓冲区放入全局队列，内容: %v\n", wb.obj[:wb.nobj])
}

// 假设这是 runtime 包中的 trygetfull 函数 (简化版)
func trygetfull() *workbuf {
	// 模拟从全局队列获取缓冲区
	return &workbuf{obj: [10]uintptr{uintptr(300), uintptr(400)}, nobj: 2}
}

// 假设这是 runtime 包中 gcController 的 enlistWorker 方法 (简化版)
func enlistWorker() {
	fmt.Println("通知 GC 控制器有新的工作")
}

// 假设这是 runtime 包中的 _GCmark 常量
const _GCmark = 2

// 假设这是 runtime 包中的 gcphase 变量
var gcphase = _GCmark

func main() {
	// 模拟获取当前 P 的 gcWork
	gcw := &gcWork{}

	// 模拟 put 操作
	obj1 := uintptr(100)
	obj2 := uintptr(200)
	gcw.put(obj1)
	gcw.put(obj2)

	// 模拟本地缓冲区满的情况
	for i := 0; i < 8; i++ {
		gcw.put(uintptr(200 + i*10))
	}
	gcw.put(uintptr(280)) // 触发 wbuf1 满，切换到 wbuf2

	// 模拟 tryGet 操作
	for i := 0; i < 12; i++ {
		obj := gcw.tryGet()
		if obj != 0 {
			fmt.Printf("获取到对象: %v\n", obj)
		} else {
			fmt.Println("本地和全局队列都为空")
			break
		}
	}
}

// 简化版的 gcWork.put 方法
func (w *gcWork) put(obj uintptr) {
	flushed := false
	wbuf := w.wbuf1
	if wbuf == nil {
		w.init()
		wbuf = w.wbuf1
	} else if wbuf.nobj == len(wbuf.obj) {
		w.wbuf1, w.wbuf2 = w.wbuf2, w.wbuf1
		wbuf = w.wbuf1
		if wbuf.nobj == len(wbuf.obj) {
			putfull(wbuf)
			flushed = true
			wbuf = getempty()
			w.wbuf1 = wbuf
		}
	}
	wbuf.obj[wbuf.nobj] = obj
	wbuf.nobj++

	if flushed && gcphase == _GCmark {
		enlistWorker()
	}
}

// 简化版的 gcWork.tryGet 方法
func (w *gcWork) tryGet() uintptr {
	wbuf := w.wbuf1
	if wbuf == nil {
		w.init()
		wbuf = w.wbuf1
	}
	if wbuf.nobj == 0 {
		w.wbuf1, w.wbuf2 = w.wbuf2, w.wbuf1
		wbuf = w.wbuf1
		if wbuf.nobj == 0 {
			owbuf := wbuf
			wbuf = trygetfull()
			if wbuf == nil {
				return 0
			}
			// 假设 putempty 在这里被调用来处理 owbuf
			w.wbuf1 = wbuf
		}
	}

	if wbuf != nil && wbuf.nobj > 0 {
		wbuf.nobj--
		return wbuf.obj[wbuf.nobj]
	}
	return 0
}

// 简化版的 gcWork.init 方法
func (w *gcWork) init() {
	w.wbuf1 = getempty()
	wbuf2 := trygetfull()
	if wbuf2 == nil {
		wbuf2 = getempty()
	}
	w.wbuf2 = wbuf2
}
```

**假设的输入与输出:**

在上面的例子中，我们假设要垃圾回收的对象的地址是 `100`, `200`, `200` 到 `270`。

**可能的输出:**

```
获取到对象: 100
获取到对象: 200
获取到对象: 200
获取到对象: 210
获取到对象: 220
获取到对象: 230
获取到对象: 240
获取到对象: 250
获取到对象: 260
获取到对象: 270
将缓冲区放入全局队列，内容: [100 200 200 210 220 230 240 250 260 270]
通知 GC 控制器有新的工作
获取到对象: 400
获取到对象: 300
本地和全局队列都为空
```

**代码推理:**

1. **`gcWork` 的初始化 (`init`):**  当第一次使用 `gcWork` 时，`init` 函数会被调用。它会尝试从全局队列获取一个满的缓冲区 (`trygetfull`) 作为 `wbuf2`，如果失败则创建一个新的空缓冲区。`wbuf1` 始终初始化为空缓冲区。

2. **`put(obj uintptr)`:**  当需要将一个待扫描的对象指针放入队列时，`put` 函数被调用。
   - 它首先尝试将对象放入当前的 `wbuf1`。
   - 如果 `wbuf1` 已满，它会将 `wbuf1` 和 `wbuf2` 交换，并将之前满的 `wbuf1`（现在的 `wbuf2`）放入全局的满缓冲区队列 (`putfull`)。
   - 然后，它会尝试将对象放入新的 `wbuf1`（之前是 `wbuf2`）。如果新的 `wbuf1` 也满了，则会创建一个新的空缓冲区。
   - 如果成功将缓冲区放入全局队列，并且当前处于标记阶段 (`gcphase == _GCmark`)，则会通知 GC 控制器有新的工作需要处理 (`enlistWorker`)。

3. **`tryGet() uintptr`:** 当 GC 工作线程需要获取待扫描的对象时，`tryGet` 被调用。
   - 它首先尝试从 `wbuf1` 中获取对象。
   - 如果 `wbuf1` 为空，它会将 `wbuf1` 和 `wbuf2` 交换。
   - 如果交换后新的 `wbuf1` 仍然为空，它会尝试从全局满缓冲区队列中获取一个缓冲区 (`trygetfull`)。
   - 如果从全局队列获取到缓冲区，则将其设置为 `wbuf1`。
   - 最后，如果 `wbuf1` 不为空，则从中取出一个对象并返回。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。与 GC 相关的命令行参数（如 `GOGC`, `GODEBUG` 等）的处理逻辑通常在 `runtime` 包的其他文件中，例如 `proc.go` 或 `os_*.go` 中。这些参数会影响 GC 的行为，例如触发 GC 的频率、并发度等，但不会直接修改 `mgcwork.go` 中定义的数据结构或函数。

**使用者易犯错的点:**

由于 `gcWork` 是 Go 运行时内部使用的结构，普通 Go 开发者通常不会直接操作它。然而，理解其背后的原理有助于理解 GC 的行为。

对于涉及到 **runtime hacking** 或者 **编写底层的 GC 工具** 的开发者，一个潜在的错误是：

- **在不正确的时机访问或修改 `gcWork`:**  `gcWork` 的状态在 GC 运行过程中会发生变化，直接操作可能会导致数据竞争或程序崩溃。例如，在没有禁用抢占的情况下访问 `gcWork` 可能会导致问题，正如代码注释中提到的 "preemption must be disabled"。

**示例说明易犯错的点 (假设可以访问 `gcWork`):**

假设一个错误的场景，在 GC 标记阶段，一个外部程序尝试访问并修改一个 P 的 `gcWork`，而没有禁用抢占：

```go
// 这是一个不应该出现的场景，仅用于演示错误
// 假设可以获取到某个 P 的 gcw
// gcw := getSpecificP().gcw

// 错误地尝试直接修改 gcw，可能导致数据竞争
// gcw.wbuf1.nobj = 0
```

在并发的 GC 过程中，如果 GC 线程也在同时操作同一个 `gcWork`，上述代码可能会导致 `wbuf1.nobj` 的值被错误地修改，从而破坏 GC 的正常工作。

总而言之，`go/src/runtime/mgcwork.go` 中的代码是 Go 并发垃圾回收器中用于管理待扫描对象的核心组件，它通过本地缓存和与全局队列的交互，实现了高效的工作分配和处理。理解这段代码有助于深入了解 Go 语言的内存管理机制。

Prompt: 
```
这是路径为go/src/runtime/mgcwork.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

const (
	_WorkbufSize = 2048 // in bytes; larger values result in less contention

	// workbufAlloc is the number of bytes to allocate at a time
	// for new workbufs. This must be a multiple of pageSize and
	// should be a multiple of _WorkbufSize.
	//
	// Larger values reduce workbuf allocation overhead. Smaller
	// values reduce heap fragmentation.
	workbufAlloc = 32 << 10
)

func init() {
	if workbufAlloc%pageSize != 0 || workbufAlloc%_WorkbufSize != 0 {
		throw("bad workbufAlloc")
	}
}

// Garbage collector work pool abstraction.
//
// This implements a producer/consumer model for pointers to grey
// objects. A grey object is one that is marked and on a work
// queue. A black object is marked and not on a work queue.
//
// Write barriers, root discovery, stack scanning, and object scanning
// produce pointers to grey objects. Scanning consumes pointers to
// grey objects, thus blackening them, and then scans them,
// potentially producing new pointers to grey objects.

// A gcWork provides the interface to produce and consume work for the
// garbage collector.
//
// A gcWork can be used on the stack as follows:
//
//	(preemption must be disabled)
//	gcw := &getg().m.p.ptr().gcw
//	.. call gcw.put() to produce and gcw.tryGet() to consume ..
//
// It's important that any use of gcWork during the mark phase prevent
// the garbage collector from transitioning to mark termination since
// gcWork may locally hold GC work buffers. This can be done by
// disabling preemption (systemstack or acquirem).
type gcWork struct {
	// wbuf1 and wbuf2 are the primary and secondary work buffers.
	//
	// This can be thought of as a stack of both work buffers'
	// pointers concatenated. When we pop the last pointer, we
	// shift the stack up by one work buffer by bringing in a new
	// full buffer and discarding an empty one. When we fill both
	// buffers, we shift the stack down by one work buffer by
	// bringing in a new empty buffer and discarding a full one.
	// This way we have one buffer's worth of hysteresis, which
	// amortizes the cost of getting or putting a work buffer over
	// at least one buffer of work and reduces contention on the
	// global work lists.
	//
	// wbuf1 is always the buffer we're currently pushing to and
	// popping from and wbuf2 is the buffer that will be discarded
	// next.
	//
	// Invariant: Both wbuf1 and wbuf2 are nil or neither are.
	wbuf1, wbuf2 *workbuf

	// Bytes marked (blackened) on this gcWork. This is aggregated
	// into work.bytesMarked by dispose.
	bytesMarked uint64

	// Heap scan work performed on this gcWork. This is aggregated into
	// gcController by dispose and may also be flushed by callers.
	// Other types of scan work are flushed immediately.
	heapScanWork int64

	// flushedWork indicates that a non-empty work buffer was
	// flushed to the global work list since the last gcMarkDone
	// termination check. Specifically, this indicates that this
	// gcWork may have communicated work to another gcWork.
	flushedWork bool
}

// Most of the methods of gcWork are go:nowritebarrierrec because the
// write barrier itself can invoke gcWork methods but the methods are
// not generally re-entrant. Hence, if a gcWork method invoked the
// write barrier while the gcWork was in an inconsistent state, and
// the write barrier in turn invoked a gcWork method, it could
// permanently corrupt the gcWork.

func (w *gcWork) init() {
	w.wbuf1 = getempty()
	wbuf2 := trygetfull()
	if wbuf2 == nil {
		wbuf2 = getempty()
	}
	w.wbuf2 = wbuf2
}

// put enqueues a pointer for the garbage collector to trace.
// obj must point to the beginning of a heap object or an oblet.
//
//go:nowritebarrierrec
func (w *gcWork) put(obj uintptr) {
	flushed := false
	wbuf := w.wbuf1
	// Record that this may acquire the wbufSpans or heap lock to
	// allocate a workbuf.
	lockWithRankMayAcquire(&work.wbufSpans.lock, lockRankWbufSpans)
	lockWithRankMayAcquire(&mheap_.lock, lockRankMheap)
	if wbuf == nil {
		w.init()
		wbuf = w.wbuf1
		// wbuf is empty at this point.
	} else if wbuf.nobj == len(wbuf.obj) {
		w.wbuf1, w.wbuf2 = w.wbuf2, w.wbuf1
		wbuf = w.wbuf1
		if wbuf.nobj == len(wbuf.obj) {
			putfull(wbuf)
			w.flushedWork = true
			wbuf = getempty()
			w.wbuf1 = wbuf
			flushed = true
		}
	}

	wbuf.obj[wbuf.nobj] = obj
	wbuf.nobj++

	// If we put a buffer on full, let the GC controller know so
	// it can encourage more workers to run. We delay this until
	// the end of put so that w is in a consistent state, since
	// enlistWorker may itself manipulate w.
	if flushed && gcphase == _GCmark {
		gcController.enlistWorker()
	}
}

// putFast does a put and reports whether it can be done quickly
// otherwise it returns false and the caller needs to call put.
//
//go:nowritebarrierrec
func (w *gcWork) putFast(obj uintptr) bool {
	wbuf := w.wbuf1
	if wbuf == nil || wbuf.nobj == len(wbuf.obj) {
		return false
	}

	wbuf.obj[wbuf.nobj] = obj
	wbuf.nobj++
	return true
}

// putBatch performs a put on every pointer in obj. See put for
// constraints on these pointers.
//
//go:nowritebarrierrec
func (w *gcWork) putBatch(obj []uintptr) {
	if len(obj) == 0 {
		return
	}

	flushed := false
	wbuf := w.wbuf1
	if wbuf == nil {
		w.init()
		wbuf = w.wbuf1
	}

	for len(obj) > 0 {
		for wbuf.nobj == len(wbuf.obj) {
			putfull(wbuf)
			w.flushedWork = true
			w.wbuf1, w.wbuf2 = w.wbuf2, getempty()
			wbuf = w.wbuf1
			flushed = true
		}
		n := copy(wbuf.obj[wbuf.nobj:], obj)
		wbuf.nobj += n
		obj = obj[n:]
	}

	if flushed && gcphase == _GCmark {
		gcController.enlistWorker()
	}
}

// tryGet dequeues a pointer for the garbage collector to trace.
//
// If there are no pointers remaining in this gcWork or in the global
// queue, tryGet returns 0.  Note that there may still be pointers in
// other gcWork instances or other caches.
//
//go:nowritebarrierrec
func (w *gcWork) tryGet() uintptr {
	wbuf := w.wbuf1
	if wbuf == nil {
		w.init()
		wbuf = w.wbuf1
		// wbuf is empty at this point.
	}
	if wbuf.nobj == 0 {
		w.wbuf1, w.wbuf2 = w.wbuf2, w.wbuf1
		wbuf = w.wbuf1
		if wbuf.nobj == 0 {
			owbuf := wbuf
			wbuf = trygetfull()
			if wbuf == nil {
				return 0
			}
			putempty(owbuf)
			w.wbuf1 = wbuf
		}
	}

	wbuf.nobj--
	return wbuf.obj[wbuf.nobj]
}

// tryGetFast dequeues a pointer for the garbage collector to trace
// if one is readily available. Otherwise it returns 0 and
// the caller is expected to call tryGet().
//
//go:nowritebarrierrec
func (w *gcWork) tryGetFast() uintptr {
	wbuf := w.wbuf1
	if wbuf == nil || wbuf.nobj == 0 {
		return 0
	}

	wbuf.nobj--
	return wbuf.obj[wbuf.nobj]
}

// dispose returns any cached pointers to the global queue.
// The buffers are being put on the full queue so that the
// write barriers will not simply reacquire them before the
// GC can inspect them. This helps reduce the mutator's
// ability to hide pointers during the concurrent mark phase.
//
//go:nowritebarrierrec
func (w *gcWork) dispose() {
	if wbuf := w.wbuf1; wbuf != nil {
		if wbuf.nobj == 0 {
			putempty(wbuf)
		} else {
			putfull(wbuf)
			w.flushedWork = true
		}
		w.wbuf1 = nil

		wbuf = w.wbuf2
		if wbuf.nobj == 0 {
			putempty(wbuf)
		} else {
			putfull(wbuf)
			w.flushedWork = true
		}
		w.wbuf2 = nil
	}
	if w.bytesMarked != 0 {
		// dispose happens relatively infrequently. If this
		// atomic becomes a problem, we should first try to
		// dispose less and if necessary aggregate in a per-P
		// counter.
		atomic.Xadd64(&work.bytesMarked, int64(w.bytesMarked))
		w.bytesMarked = 0
	}
	if w.heapScanWork != 0 {
		gcController.heapScanWork.Add(w.heapScanWork)
		w.heapScanWork = 0
	}
}

// balance moves some work that's cached in this gcWork back on the
// global queue.
//
//go:nowritebarrierrec
func (w *gcWork) balance() {
	if w.wbuf1 == nil {
		return
	}
	if wbuf := w.wbuf2; wbuf.nobj != 0 {
		putfull(wbuf)
		w.flushedWork = true
		w.wbuf2 = getempty()
	} else if wbuf := w.wbuf1; wbuf.nobj > 4 {
		w.wbuf1 = handoff(wbuf)
		w.flushedWork = true // handoff did putfull
	} else {
		return
	}
	// We flushed a buffer to the full list, so wake a worker.
	if gcphase == _GCmark {
		gcController.enlistWorker()
	}
}

// empty reports whether w has no mark work available.
//
//go:nowritebarrierrec
func (w *gcWork) empty() bool {
	return w.wbuf1 == nil || (w.wbuf1.nobj == 0 && w.wbuf2.nobj == 0)
}

// Internally, the GC work pool is kept in arrays in work buffers.
// The gcWork interface caches a work buffer until full (or empty) to
// avoid contending on the global work buffer lists.

type workbufhdr struct {
	node lfnode // must be first
	nobj int
}

type workbuf struct {
	_ sys.NotInHeap
	workbufhdr
	// account for the above fields
	obj [(_WorkbufSize - unsafe.Sizeof(workbufhdr{})) / goarch.PtrSize]uintptr
}

// workbuf factory routines. These funcs are used to manage the
// workbufs.
// If the GC asks for some work these are the only routines that
// make wbufs available to the GC.

func (b *workbuf) checknonempty() {
	if b.nobj == 0 {
		throw("workbuf is empty")
	}
}

func (b *workbuf) checkempty() {
	if b.nobj != 0 {
		throw("workbuf is not empty")
	}
}

// getempty pops an empty work buffer off the work.empty list,
// allocating new buffers if none are available.
//
//go:nowritebarrier
func getempty() *workbuf {
	var b *workbuf
	if work.empty != 0 {
		b = (*workbuf)(work.empty.pop())
		if b != nil {
			b.checkempty()
		}
	}
	// Record that this may acquire the wbufSpans or heap lock to
	// allocate a workbuf.
	lockWithRankMayAcquire(&work.wbufSpans.lock, lockRankWbufSpans)
	lockWithRankMayAcquire(&mheap_.lock, lockRankMheap)
	if b == nil {
		// Allocate more workbufs.
		var s *mspan
		if work.wbufSpans.free.first != nil {
			lock(&work.wbufSpans.lock)
			s = work.wbufSpans.free.first
			if s != nil {
				work.wbufSpans.free.remove(s)
				work.wbufSpans.busy.insert(s)
			}
			unlock(&work.wbufSpans.lock)
		}
		if s == nil {
			systemstack(func() {
				s = mheap_.allocManual(workbufAlloc/pageSize, spanAllocWorkBuf)
			})
			if s == nil {
				throw("out of memory")
			}
			// Record the new span in the busy list.
			lock(&work.wbufSpans.lock)
			work.wbufSpans.busy.insert(s)
			unlock(&work.wbufSpans.lock)
		}
		// Slice up the span into new workbufs. Return one and
		// put the rest on the empty list.
		for i := uintptr(0); i+_WorkbufSize <= workbufAlloc; i += _WorkbufSize {
			newb := (*workbuf)(unsafe.Pointer(s.base() + i))
			newb.nobj = 0
			lfnodeValidate(&newb.node)
			if i == 0 {
				b = newb
			} else {
				putempty(newb)
			}
		}
	}
	return b
}

// putempty puts a workbuf onto the work.empty list.
// Upon entry this goroutine owns b. The lfstack.push relinquishes ownership.
//
//go:nowritebarrier
func putempty(b *workbuf) {
	b.checkempty()
	work.empty.push(&b.node)
}

// putfull puts the workbuf on the work.full list for the GC.
// putfull accepts partially full buffers so the GC can avoid competing
// with the mutators for ownership of partially full buffers.
//
//go:nowritebarrier
func putfull(b *workbuf) {
	b.checknonempty()
	work.full.push(&b.node)
}

// trygetfull tries to get a full or partially empty workbuffer.
// If one is not immediately available return nil.
//
//go:nowritebarrier
func trygetfull() *workbuf {
	b := (*workbuf)(work.full.pop())
	if b != nil {
		b.checknonempty()
		return b
	}
	return b
}

//go:nowritebarrier
func handoff(b *workbuf) *workbuf {
	// Make new buffer with half of b's pointers.
	b1 := getempty()
	n := b.nobj / 2
	b.nobj -= n
	b1.nobj = n
	memmove(unsafe.Pointer(&b1.obj[0]), unsafe.Pointer(&b.obj[b.nobj]), uintptr(n)*unsafe.Sizeof(b1.obj[0]))

	// Put b on full list - let first half of b get stolen.
	putfull(b)
	return b1
}

// prepareFreeWorkbufs moves busy workbuf spans to free list so they
// can be freed to the heap. This must only be called when all
// workbufs are on the empty list.
func prepareFreeWorkbufs() {
	lock(&work.wbufSpans.lock)
	if work.full != 0 {
		throw("cannot free workbufs when work.full != 0")
	}
	// Since all workbufs are on the empty list, we don't care
	// which ones are in which spans. We can wipe the entire empty
	// list and move all workbuf spans to the free list.
	work.empty = 0
	work.wbufSpans.free.takeAll(&work.wbufSpans.busy)
	unlock(&work.wbufSpans.lock)
}

// freeSomeWbufs frees some workbufs back to the heap and returns
// true if it should be called again to free more.
func freeSomeWbufs(preemptible bool) bool {
	const batchSize = 64 // ~1–2 µs per span.
	lock(&work.wbufSpans.lock)
	if gcphase != _GCoff || work.wbufSpans.free.isEmpty() {
		unlock(&work.wbufSpans.lock)
		return false
	}
	systemstack(func() {
		gp := getg().m.curg
		for i := 0; i < batchSize && !(preemptible && gp.preempt); i++ {
			span := work.wbufSpans.free.first
			if span == nil {
				break
			}
			work.wbufSpans.free.remove(span)
			mheap_.freeManual(span, spanAllocWorkBuf)
		}
	})
	more := !work.wbufSpans.free.isEmpty()
	unlock(&work.wbufSpans.lock)
	return more
}

"""



```