Response:
My thinking process to answer the request about `mgcmark.go` went something like this:

1. **Understand the Goal:** The primary goal is to explain the functionality of the provided Go code snippet, which is a part of the garbage collector's marking phase. The request also asks for examples, command-line arguments (if applicable), potential errors, and a summary.

2. **Initial Code Scan and Keyword Identification:** I quickly scanned the code for key terms and functions. I noticed:
    * `gcMarkRootPrepare`, `gcMarkRootCheck`, `markroot`:  These clearly indicate root marking.
    * `fixedRootFinalizers`, `fixedRootFreeGStacks`:  These are special root types.
    * `work.nDataRoots`, `work.nBSSRoots`, `work.nStackRoots`, `work.nSpanRoots`: These track different types of roots.
    * Loops iterating over `activeModules()`, `mheap_.markArenas`, and `allGsSnapshot()`:  These suggest scanning different memory regions.
    * `scanblock`, `scanstack`, `scanobject`, `scanConservative`: These are the core scanning functions.
    * `gcAssistAlloc`, `gcAssistAlloc1`, `gcParkAssist`, `gcFlushBgCredit`: These relate to GC assist for allocations.

3. **Categorize Functionality:** Based on the keywords and structure, I started grouping the functions by their apparent purpose:
    * **Root Marking:**  `gcMarkRootPrepare`, `gcMarkRootCheck`, `markroot`, `markrootBlock`, `markrootFreeGStacks`, `markrootSpans`.
    * **Stack Scanning:** `scanstack`, `scanframeworker`.
    * **GC Assist:** `gcAssistAlloc`, `gcAssistAlloc1`, `gcWakeAllAssists`, `gcParkAssist`, `gcFlushBgCredit`.

4. **Analyze Each Category/Function:** I then delved deeper into each function and category:

    * **Root Marking:**
        * **`gcMarkRootPrepare`:**  This function seems to be the initialization step. It calculates the number of different types of roots (globals, BSS, spans, stacks) and prepares for their scanning. The `activeModules()`, `mheap_.markArenas`, and `allGsSnapshot()` calls are crucial for identifying these root sets.
        * **`gcMarkRootCheck`:**  This is a debug function to ensure all roots have been processed.
        * **`markroot`:** This is the main function for scanning individual roots. It uses a `switch` statement to handle different root types.
        * **`markrootBlock`:**  Handles scanning chunks of global data and BSS segments.
        * **`markrootFreeGStacks`:**  Releases the stacks of dead goroutines.
        * **`markrootSpans`:** Scans special objects associated with spans, like finalizers and weak handles.

    * **Stack Scanning:**
        * **`scanstack`:**  Scans the stack of a given goroutine, identifying pointers to heap objects. It handles stack shrinking. The use of `unwinder` and `scanframeworker` suggests a detailed examination of stack frames.
        * **`scanframeworker`:**  Examines a single stack frame for pointers.

    * **GC Assist:**
        * **`gcAssistAlloc`:**  The main entry point for allocation-time GC assistance. It checks if assistance is needed and either steals background credit or performs scan work.
        * **`gcAssistAlloc1`:**  The system stack part of `gcAssistAlloc` that does the actual scanning.
        * **`gcWakeAllAssists`:** Wakes up goroutines blocked on GC assist.
        * **`gcParkAssist`:**  Parks a goroutine that needs GC assist.
        * **`gcFlushBgCredit`:**  Distributes background GC credit, prioritizing blocked assists.

5. **Identify Key Go Features:** Based on the functionality, I recognized the following key Go features being implemented:
    * **Garbage Collection:**  The core purpose of the code.
    * **Root Scanning:** A fundamental step in mark-and-sweep GC.
    * **Stack Scanning:**  Essential for identifying live objects.
    * **Finalizers:**  The `fixedRootFinalizers` and `markrootSpans` sections handle finalizers.
    * **Weak Handles:** `markrootSpans` also deals with weak handles.
    * **Goroutine Management:**  Scanning goroutine stacks.
    * **GC Pacing/Assisting:**  `gcAssistAlloc` implements a mechanism for mutators to contribute to the GC effort.

6. **Formulate Examples (Conceptual):** Since the request asked for examples, I thought about simple Go code snippets that would demonstrate the *effects* of the code, even though directly calling these internal functions isn't possible:
    * An object with a finalizer.
    * Using `runtime.SetFinalizer`.
    * A basic allocation that might trigger GC assist.

7. **Consider Command-Line Arguments:** I knew that Go's GC behavior can be influenced by environment variables like `GOGC` and `GOMEMLIMIT`. These are the closest equivalent to command-line parameters for GC.

8. **Identify Potential Pitfalls:**  I thought about common mistakes developers might make that relate to GC and the concepts in the code:
    * Relying on finalizers for resource release (finalizers aren't guaranteed to run promptly).
    * Creating circular dependencies that might delay garbage collection.

9. **Structure the Answer:** I organized the answer according to the request's prompts:
    * Function list.
    * Inference of Go features.
    * Code examples.
    * Command-line arguments.
    * Potential mistakes.
    * Summary of functionality.

10. **Refine and Elaborate:** I reviewed my drafted answer, adding more detail and explanations where necessary. For instance, I explained *why* certain things were done in the code (e.g., why stacks are scanned, the purpose of finalizers). I also made sure the language was clear and concise.

This iterative process of scanning, categorizing, analyzing, connecting to Go features, and formulating examples allowed me to produce a comprehensive answer that addressed all aspects of the request.
这是 `go/src/runtime/mgcmark.go` 文件的一部分，主要负责 Go 语言垃圾回收器（Garbage Collector, GC）**标记（marking）阶段** 的核心功能。

以下是其功能的详细列表：

**核心功能：标记活跃对象**

* **根对象扫描 (Root Scanning):**  识别并扫描所有作为垃圾回收起点的根对象，包括：
    * **固定根对象 (Fixed Roots):**
        * **终结器队列 (Finalizers):**  扫描待执行终结器的对象。
        * **空闲 G 栈 (Free G Stacks):** 扫描已死亡 Goroutine 的栈，以便释放其占用的内存。
    * **数据段根对象 (Data Roots):**  扫描 Go 程序的数据段（全局变量）。
    * **BSS 段根对象 (BSS Roots):** 扫描 Go 程序的 BSS 段（未初始化全局变量）。
    * **Span 根对象 (Span Roots):** 扫描堆内存中的 Span 结构，查找包含特殊对象的 Span，例如带有终结器的对象和弱引用对象。
    * **栈根对象 (Stack Roots):** 扫描所有活跃 Goroutine 的栈。
* **对象扫描 (Object Scanning):** 从根对象出发，递归地遍历并标记所有可达（live）的对象。
* **辅助标记 (Mark Assist):**  允许应用程序的 Goroutine 在分配内存时协助 GC 的标记工作，以分摊 GC 的开销并降低 GC 造成的程序暂停时间。

**具体功能分解：**

1. **`gcMarkRootPrepare()`:**
   - 在标记阶段开始时被调用，用于**准备根对象扫描**。
   - 计算各种根对象的数量（数据段、BSS 段、Span、栈）。
   - 创建根对象扫描任务队列。
   - 拍摄当前堆 Arena 的快照 (`mheap_.markArenas`)，用于后续的 Span 根对象扫描。
   - 获取所有活跃 Goroutine 的快照 (`allGsSnapshot()`)，用于后续的栈扫描。

2. **`gcMarkRootCheck()`:**
   - 用于**调试**目的，在根对象扫描完成后检查是否所有根对象都被扫描过。

3. **`markroot()`:**
   - **执行单个根对象的扫描任务**。
   - 根据传入的索引 `i` 判断要扫描的根对象类型。
   - 调用相应的扫描函数（例如 `markrootBlock`，`scanstack`，`markrootSpans`）。
   - 计算并返回本次扫描操作完成的工作量。

4. **`markrootBlock()`:**
   - **扫描数据段或 BSS 段的一部分内存块**，查找其中的指针。
   - 根据给定的指针掩码 `ptrmask0` 判断哪些位置可能包含指针。

5. **`markrootFreeGStacks()`:**
   - **释放已死亡 Goroutine 的栈内存**。
   - 从全局空闲 Goroutine 列表中获取带有栈的 Goroutine。
   - 调用 `stackfree()` 释放这些栈。

6. **`markrootSpans()`:**
   - **扫描堆内存中的 Span 结构，查找特殊对象**。
   - 特别关注带有终结器的对象和弱引用对象。
   - 对于带有终结器的对象，会扫描对象可达的所有内容（但不包括对象本身，以便可以被回收），并扫描终结器函数指针。
   - 对于弱引用对象，会扫描弱引用句柄本身。

7. **`gcAssistAlloc()`:**
   - 当 Goroutine 需要分配内存时，如果 GC 需要协助，则会调用此函数。
   - **协调 Goroutine 参与 GC 标记工作**，使其承担一部分扫描任务，以减少 GC 的压力。
   - 可以从后台 GC 的扫描信用中“窃取”一部分。
   - 如果 Goroutine 无法完成所需的协助工作，则会被放入辅助队列并等待被唤醒。

8. **`gcAssistAlloc1()`:**
   - `gcAssistAlloc` 的一部分，在系统栈上执行，避免访问用户栈可能导致的问题。
   - **实际执行 GC 辅助标记工作**，调用 `gcDrainN` 进行扫描。

9. **`gcWakeAllAssists()`:**
   - 在 GC 标记阶段结束后，**唤醒所有因 GC 辅助而阻塞的 Goroutine**。

10. **`gcParkAssist()`:**
    - 当 Goroutine 需要进行 GC 辅助但无法立即完成时，将其**放入辅助队列并阻塞**。

11. **`gcFlushBgCredit()`:**
    - **将后台 GC 的扫描工作信用分配出去**。
    - 优先满足辅助队列中等待的 Goroutine 的需求，然后将剩余的信用添加到全局后台扫描信用中。

12. **`scanstack()`:**
    - **扫描指定 Goroutine 的栈**，查找指向堆内存的指针。
    - 调用 `scanframeworker` 扫描栈帧。
    - 处理 defer 和 panic 结构中的指针。
    - 可以根据栈的使用情况尝试缩小栈的大小。

13. **`scanframeworker()`:**
    - **扫描单个栈帧**，查找局部变量和函数参数/返回值中的指针。

**推理 Go 语言功能实现:**

从这段代码可以看出，它直接参与实现了 Go 语言的 **垃圾回收机制**，特别是其中的 **并发标记阶段**。  Go 使用的是一种 **基于三色标记的并发垃圾回收算法**，这段代码主要负责将活跃对象标记为黑色。

**Go 代码示例 (演示终结器的扫描):**

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

type MyObject struct {
	data string
}

func finalizer(obj *MyObject) {
	fmt.Println("Finalizer called for:", obj.data)
}

func main() {
	obj := &MyObject{"Hello, Finalizer!"}
	runtime.SetFinalizer(obj, finalizer)

	// 让对象变得不可达
	obj = nil

	// 触发 GC (不保证立即执行)
	runtime.GC()

	// 等待一段时间，以便终结器有机会运行
	time.Sleep(time.Second)

	fmt.Println("Program finished")
}
```

**假设输入与输出:**

在上面的代码示例中，当 `runtime.GC()` 被调用时，如果垃圾回收器开始执行标记阶段，`mgcmark.go` 中的相关代码（特别是涉及到 `fixedRootFinalizers` 和 `markrootSpans` 的部分）会被执行。

* **输入 (假设):**  堆中存在一个 `MyObject` 实例，并且通过 `runtime.SetFinalizer` 为其设置了终结器 `finalizer`。 该对象变得不可达。
* **输出 (预期):**  在 GC 标记阶段，垃圾回收器会扫描终结器队列，找到 `MyObject` 实例对应的终结器信息。 `markrootSpans` 会扫描该 Span，识别出 `MyObject` 拥有终结器。最终，当 GC 执行到终结阶段时，`finalizer` 函数会被调用，输出 "Finalizer called for: Hello, Finalizer!"。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。Go 语言的垃圾回收行为主要受到 **环境变量** 的影响，例如：

* **`GOGC`:**  设置垃圾回收的目标百分比。默认值为 100，表示在上次回收后，堆内存增长达到上次回收后存活对象大小的 100% 时触发新的回收。
* **`GOMEMLIMIT`:** 设置 Go 程序可以使用的最大内存量。
* **`GOTRACE`:** 用于生成 GC 跟踪信息，可以帮助分析 GC 的行为。

这些环境变量会在 Go 程序的启动过程中被读取，并影响垃圾回收器的策略和参数。`mgcmark.go` 中定义的常量和逻辑会根据这些全局配置进行工作。

**使用者易犯错的点:**

这里描述的是 Go 运行时库的内部实现，普通 Go 开发者不会直接与这些代码交互。但是，理解其功能可以帮助避免与垃圾回收相关的常见误解：

* **过度依赖终结器 (Finalizers) 进行资源释放:**  终结器不能保证及时执行，并且在程序异常退出时可能不会执行。因此，不应该将终结器作为释放关键资源（如文件句柄、网络连接）的唯一手段。应该使用 `defer` 语句配合 `Close()` 等方法进行显式资源管理。

**功能归纳 (第 1 部分):**

这部分 `mgcmark.go` 的主要功能是 **实现 Go 语言垃圾回收器标记阶段的核心逻辑，负责识别和标记所有在程序执行过程中仍然活跃的对象。** 它通过扫描各种类型的根对象（全局变量、Goroutine 栈、特殊 Span 等）并递归地遍历对象图来实现这一目标。此外，它还包含了 GC 辅助机制，允许 Goroutine 在分配内存时分担一部分标记工作。

Prompt: 
```
这是路径为go/src/runtime/mgcmark.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Garbage collector: marking and scanning

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

const (
	fixedRootFinalizers = iota
	fixedRootFreeGStacks
	fixedRootCount

	// rootBlockBytes is the number of bytes to scan per data or
	// BSS root.
	rootBlockBytes = 256 << 10

	// maxObletBytes is the maximum bytes of an object to scan at
	// once. Larger objects will be split up into "oblets" of at
	// most this size. Since we can scan 1–2 MB/ms, 128 KB bounds
	// scan preemption at ~100 µs.
	//
	// This must be > _MaxSmallSize so that the object base is the
	// span base.
	maxObletBytes = 128 << 10

	// drainCheckThreshold specifies how many units of work to do
	// between self-preemption checks in gcDrain. Assuming a scan
	// rate of 1 MB/ms, this is ~100 µs. Lower values have higher
	// overhead in the scan loop (the scheduler check may perform
	// a syscall, so its overhead is nontrivial). Higher values
	// make the system less responsive to incoming work.
	drainCheckThreshold = 100000

	// pagesPerSpanRoot indicates how many pages to scan from a span root
	// at a time. Used by special root marking.
	//
	// Higher values improve throughput by increasing locality, but
	// increase the minimum latency of a marking operation.
	//
	// Must be a multiple of the pageInUse bitmap element size and
	// must also evenly divide pagesPerArena.
	pagesPerSpanRoot = 512
)

// gcMarkRootPrepare queues root scanning jobs (stacks, globals, and
// some miscellany) and initializes scanning-related state.
//
// The world must be stopped.
func gcMarkRootPrepare() {
	assertWorldStopped()

	// Compute how many data and BSS root blocks there are.
	nBlocks := func(bytes uintptr) int {
		return int(divRoundUp(bytes, rootBlockBytes))
	}

	work.nDataRoots = 0
	work.nBSSRoots = 0

	// Scan globals.
	for _, datap := range activeModules() {
		nDataRoots := nBlocks(datap.edata - datap.data)
		if nDataRoots > work.nDataRoots {
			work.nDataRoots = nDataRoots
		}

		nBSSRoots := nBlocks(datap.ebss - datap.bss)
		if nBSSRoots > work.nBSSRoots {
			work.nBSSRoots = nBSSRoots
		}
	}

	// Scan span roots for finalizer specials.
	//
	// We depend on addfinalizer to mark objects that get
	// finalizers after root marking.
	//
	// We're going to scan the whole heap (that was available at the time the
	// mark phase started, i.e. markArenas) for in-use spans which have specials.
	//
	// Break up the work into arenas, and further into chunks.
	//
	// Snapshot allArenas as markArenas. This snapshot is safe because allArenas
	// is append-only.
	mheap_.markArenas = mheap_.allArenas[:len(mheap_.allArenas):len(mheap_.allArenas)]
	work.nSpanRoots = len(mheap_.markArenas) * (pagesPerArena / pagesPerSpanRoot)

	// Scan stacks.
	//
	// Gs may be created after this point, but it's okay that we
	// ignore them because they begin life without any roots, so
	// there's nothing to scan, and any roots they create during
	// the concurrent phase will be caught by the write barrier.
	work.stackRoots = allGsSnapshot()
	work.nStackRoots = len(work.stackRoots)

	work.markrootNext = 0
	work.markrootJobs = uint32(fixedRootCount + work.nDataRoots + work.nBSSRoots + work.nSpanRoots + work.nStackRoots)

	// Calculate base indexes of each root type
	work.baseData = uint32(fixedRootCount)
	work.baseBSS = work.baseData + uint32(work.nDataRoots)
	work.baseSpans = work.baseBSS + uint32(work.nBSSRoots)
	work.baseStacks = work.baseSpans + uint32(work.nSpanRoots)
	work.baseEnd = work.baseStacks + uint32(work.nStackRoots)
}

// gcMarkRootCheck checks that all roots have been scanned. It is
// purely for debugging.
func gcMarkRootCheck() {
	if work.markrootNext < work.markrootJobs {
		print(work.markrootNext, " of ", work.markrootJobs, " markroot jobs done\n")
		throw("left over markroot jobs")
	}

	// Check that stacks have been scanned.
	//
	// We only check the first nStackRoots Gs that we should have scanned.
	// Since we don't care about newer Gs (see comment in
	// gcMarkRootPrepare), no locking is required.
	i := 0
	forEachGRace(func(gp *g) {
		if i >= work.nStackRoots {
			return
		}

		if !gp.gcscandone {
			println("gp", gp, "goid", gp.goid,
				"status", readgstatus(gp),
				"gcscandone", gp.gcscandone)
			throw("scan missed a g")
		}

		i++
	})
}

// ptrmask for an allocation containing a single pointer.
var oneptrmask = [...]uint8{1}

// markroot scans the i'th root.
//
// Preemption must be disabled (because this uses a gcWork).
//
// Returns the amount of GC work credit produced by the operation.
// If flushBgCredit is true, then that credit is also flushed
// to the background credit pool.
//
// nowritebarrier is only advisory here.
//
//go:nowritebarrier
func markroot(gcw *gcWork, i uint32, flushBgCredit bool) int64 {
	// Note: if you add a case here, please also update heapdump.go:dumproots.
	var workDone int64
	var workCounter *atomic.Int64
	switch {
	case work.baseData <= i && i < work.baseBSS:
		workCounter = &gcController.globalsScanWork
		for _, datap := range activeModules() {
			workDone += markrootBlock(datap.data, datap.edata-datap.data, datap.gcdatamask.bytedata, gcw, int(i-work.baseData))
		}

	case work.baseBSS <= i && i < work.baseSpans:
		workCounter = &gcController.globalsScanWork
		for _, datap := range activeModules() {
			workDone += markrootBlock(datap.bss, datap.ebss-datap.bss, datap.gcbssmask.bytedata, gcw, int(i-work.baseBSS))
		}

	case i == fixedRootFinalizers:
		for fb := allfin; fb != nil; fb = fb.alllink {
			cnt := uintptr(atomic.Load(&fb.cnt))
			// Finalizers that contain cleanups only have fn set. None of the other
			// fields are necessary.
			scanblock(uintptr(unsafe.Pointer(&fb.fin[0])), cnt*unsafe.Sizeof(fb.fin[0]), &finptrmask[0], gcw, nil)
		}

	case i == fixedRootFreeGStacks:
		// Switch to the system stack so we can call
		// stackfree.
		systemstack(markrootFreeGStacks)

	case work.baseSpans <= i && i < work.baseStacks:
		// mark mspan.specials
		markrootSpans(gcw, int(i-work.baseSpans))

	default:
		// the rest is scanning goroutine stacks
		workCounter = &gcController.stackScanWork
		if i < work.baseStacks || work.baseEnd <= i {
			printlock()
			print("runtime: markroot index ", i, " not in stack roots range [", work.baseStacks, ", ", work.baseEnd, ")\n")
			throw("markroot: bad index")
		}
		gp := work.stackRoots[i-work.baseStacks]

		// remember when we've first observed the G blocked
		// needed only to output in traceback
		status := readgstatus(gp) // We are not in a scan state
		if (status == _Gwaiting || status == _Gsyscall) && gp.waitsince == 0 {
			gp.waitsince = work.tstart
		}

		// scanstack must be done on the system stack in case
		// we're trying to scan our own stack.
		systemstack(func() {
			// If this is a self-scan, put the user G in
			// _Gwaiting to prevent self-deadlock. It may
			// already be in _Gwaiting if this is a mark
			// worker or we're in mark termination.
			userG := getg().m.curg
			selfScan := gp == userG && readgstatus(userG) == _Grunning
			if selfScan {
				casGToWaitingForGC(userG, _Grunning, waitReasonGarbageCollectionScan)
			}

			// TODO: suspendG blocks (and spins) until gp
			// stops, which may take a while for
			// running goroutines. Consider doing this in
			// two phases where the first is non-blocking:
			// we scan the stacks we can and ask running
			// goroutines to scan themselves; and the
			// second blocks.
			stopped := suspendG(gp)
			if stopped.dead {
				gp.gcscandone = true
				return
			}
			if gp.gcscandone {
				throw("g already scanned")
			}
			workDone += scanstack(gp, gcw)
			gp.gcscandone = true
			resumeG(stopped)

			if selfScan {
				casgstatus(userG, _Gwaiting, _Grunning)
			}
		})
	}
	if workCounter != nil && workDone != 0 {
		workCounter.Add(workDone)
		if flushBgCredit {
			gcFlushBgCredit(workDone)
		}
	}
	return workDone
}

// markrootBlock scans the shard'th shard of the block of memory [b0,
// b0+n0), with the given pointer mask.
//
// Returns the amount of work done.
//
//go:nowritebarrier
func markrootBlock(b0, n0 uintptr, ptrmask0 *uint8, gcw *gcWork, shard int) int64 {
	if rootBlockBytes%(8*goarch.PtrSize) != 0 {
		// This is necessary to pick byte offsets in ptrmask0.
		throw("rootBlockBytes must be a multiple of 8*ptrSize")
	}

	// Note that if b0 is toward the end of the address space,
	// then b0 + rootBlockBytes might wrap around.
	// These tests are written to avoid any possible overflow.
	off := uintptr(shard) * rootBlockBytes
	if off >= n0 {
		return 0
	}
	b := b0 + off
	ptrmask := (*uint8)(add(unsafe.Pointer(ptrmask0), uintptr(shard)*(rootBlockBytes/(8*goarch.PtrSize))))
	n := uintptr(rootBlockBytes)
	if off+n > n0 {
		n = n0 - off
	}

	// Scan this shard.
	scanblock(b, n, ptrmask, gcw, nil)
	return int64(n)
}

// markrootFreeGStacks frees stacks of dead Gs.
//
// This does not free stacks of dead Gs cached on Ps, but having a few
// cached stacks around isn't a problem.
func markrootFreeGStacks() {
	// Take list of dead Gs with stacks.
	lock(&sched.gFree.lock)
	list := sched.gFree.stack
	sched.gFree.stack = gList{}
	unlock(&sched.gFree.lock)
	if list.empty() {
		return
	}

	// Free stacks.
	q := gQueue{list.head, list.head}
	for gp := list.head.ptr(); gp != nil; gp = gp.schedlink.ptr() {
		stackfree(gp.stack)
		gp.stack.lo = 0
		gp.stack.hi = 0
		// Manipulate the queue directly since the Gs are
		// already all linked the right way.
		q.tail.set(gp)
	}

	// Put Gs back on the free list.
	lock(&sched.gFree.lock)
	sched.gFree.noStack.pushAll(q)
	unlock(&sched.gFree.lock)
}

// markrootSpans marks roots for one shard of markArenas.
//
//go:nowritebarrier
func markrootSpans(gcw *gcWork, shard int) {
	// Objects with finalizers have two GC-related invariants:
	//
	// 1) Everything reachable from the object must be marked.
	// This ensures that when we pass the object to its finalizer,
	// everything the finalizer can reach will be retained.
	//
	// 2) Finalizer specials (which are not in the garbage
	// collected heap) are roots. In practice, this means the fn
	// field must be scanned.
	//
	// Objects with weak handles have only one invariant related
	// to this function: weak handle specials (which are not in the
	// garbage collected heap) are roots. In practice, this means
	// the handle field must be scanned. Note that the value the
	// handle pointer referenced does *not* need to be scanned. See
	// the definition of specialWeakHandle for details.
	sg := mheap_.sweepgen

	// Find the arena and page index into that arena for this shard.
	ai := mheap_.markArenas[shard/(pagesPerArena/pagesPerSpanRoot)]
	ha := mheap_.arenas[ai.l1()][ai.l2()]
	arenaPage := uint(uintptr(shard) * pagesPerSpanRoot % pagesPerArena)

	// Construct slice of bitmap which we'll iterate over.
	specialsbits := ha.pageSpecials[arenaPage/8:]
	specialsbits = specialsbits[:pagesPerSpanRoot/8]
	for i := range specialsbits {
		// Find set bits, which correspond to spans with specials.
		specials := atomic.Load8(&specialsbits[i])
		if specials == 0 {
			continue
		}
		for j := uint(0); j < 8; j++ {
			if specials&(1<<j) == 0 {
				continue
			}
			// Find the span for this bit.
			//
			// This value is guaranteed to be non-nil because having
			// specials implies that the span is in-use, and since we're
			// currently marking we can be sure that we don't have to worry
			// about the span being freed and re-used.
			s := ha.spans[arenaPage+uint(i)*8+j]

			// The state must be mSpanInUse if the specials bit is set, so
			// sanity check that.
			if state := s.state.get(); state != mSpanInUse {
				print("s.state = ", state, "\n")
				throw("non in-use span found with specials bit set")
			}
			// Check that this span was swept (it may be cached or uncached).
			if !useCheckmark && !(s.sweepgen == sg || s.sweepgen == sg+3) {
				// sweepgen was updated (+2) during non-checkmark GC pass
				print("sweep ", s.sweepgen, " ", sg, "\n")
				throw("gc: unswept span")
			}

			// Lock the specials to prevent a special from being
			// removed from the list while we're traversing it.
			lock(&s.speciallock)
			for sp := s.specials; sp != nil; sp = sp.next {
				switch sp.kind {
				case _KindSpecialFinalizer:
					// don't mark finalized object, but scan it so we
					// retain everything it points to.
					spf := (*specialfinalizer)(unsafe.Pointer(sp))
					// A finalizer can be set for an inner byte of an object, find object beginning.
					p := s.base() + uintptr(spf.special.offset)/s.elemsize*s.elemsize

					// Mark everything that can be reached from
					// the object (but *not* the object itself or
					// we'll never collect it).
					if !s.spanclass.noscan() {
						scanobject(p, gcw)
					}

					// The special itself is a root.
					scanblock(uintptr(unsafe.Pointer(&spf.fn)), goarch.PtrSize, &oneptrmask[0], gcw, nil)
				case _KindSpecialWeakHandle:
					// The special itself is a root.
					spw := (*specialWeakHandle)(unsafe.Pointer(sp))
					scanblock(uintptr(unsafe.Pointer(&spw.handle)), goarch.PtrSize, &oneptrmask[0], gcw, nil)
				case _KindSpecialCleanup:
					spc := (*specialCleanup)(unsafe.Pointer(sp))
					// The special itself is a root.
					scanblock(uintptr(unsafe.Pointer(&spc.fn)), goarch.PtrSize, &oneptrmask[0], gcw, nil)
				}
			}
			unlock(&s.speciallock)
		}
	}
}

// gcAssistAlloc performs GC work to make gp's assist debt positive.
// gp must be the calling user goroutine.
//
// This must be called with preemption enabled.
func gcAssistAlloc(gp *g) {
	// Don't assist in non-preemptible contexts. These are
	// generally fragile and won't allow the assist to block.
	if getg() == gp.m.g0 {
		return
	}
	if mp := getg().m; mp.locks > 0 || mp.preemptoff != "" {
		return
	}

	if gp := getg(); gp.syncGroup != nil {
		// Disassociate the G from its synctest bubble while allocating.
		// This is less elegant than incrementing the group's active count,
		// but avoids any contamination between GC assist and synctest.
		sg := gp.syncGroup
		gp.syncGroup = nil
		defer func() {
			gp.syncGroup = sg
		}()
	}

	// This extremely verbose boolean indicates whether we've
	// entered mark assist from the perspective of the tracer.
	//
	// In the tracer, this is just before we call gcAssistAlloc1
	// *regardless* of whether tracing is enabled. This is because
	// the tracer allows for tracing to begin (and advance
	// generations) in the middle of a GC mark phase, so we need to
	// record some state so that the tracer can pick it up to ensure
	// a consistent trace result.
	//
	// TODO(mknyszek): Hide the details of inMarkAssist in tracer
	// functions and simplify all the state tracking. This is a lot.
	enteredMarkAssistForTracing := false
retry:
	if gcCPULimiter.limiting() {
		// If the CPU limiter is enabled, intentionally don't
		// assist to reduce the amount of CPU time spent in the GC.
		if enteredMarkAssistForTracing {
			trace := traceAcquire()
			if trace.ok() {
				trace.GCMarkAssistDone()
				// Set this *after* we trace the end to make sure
				// that we emit an in-progress event if this is
				// the first event for the goroutine in the trace
				// or trace generation. Also, do this between
				// acquire/release because this is part of the
				// goroutine's trace state, and it must be atomic
				// with respect to the tracer.
				gp.inMarkAssist = false
				traceRelease(trace)
			} else {
				// This state is tracked even if tracing isn't enabled.
				// It's only used by the new tracer.
				// See the comment on enteredMarkAssistForTracing.
				gp.inMarkAssist = false
			}
		}
		return
	}
	// Compute the amount of scan work we need to do to make the
	// balance positive. When the required amount of work is low,
	// we over-assist to build up credit for future allocations
	// and amortize the cost of assisting.
	assistWorkPerByte := gcController.assistWorkPerByte.Load()
	assistBytesPerWork := gcController.assistBytesPerWork.Load()
	debtBytes := -gp.gcAssistBytes
	scanWork := int64(assistWorkPerByte * float64(debtBytes))
	if scanWork < gcOverAssistWork {
		scanWork = gcOverAssistWork
		debtBytes = int64(assistBytesPerWork * float64(scanWork))
	}

	// Steal as much credit as we can from the background GC's
	// scan credit. This is racy and may drop the background
	// credit below 0 if two mutators steal at the same time. This
	// will just cause steals to fail until credit is accumulated
	// again, so in the long run it doesn't really matter, but we
	// do have to handle the negative credit case.
	bgScanCredit := gcController.bgScanCredit.Load()
	stolen := int64(0)
	if bgScanCredit > 0 {
		if bgScanCredit < scanWork {
			stolen = bgScanCredit
			gp.gcAssistBytes += 1 + int64(assistBytesPerWork*float64(stolen))
		} else {
			stolen = scanWork
			gp.gcAssistBytes += debtBytes
		}
		gcController.bgScanCredit.Add(-stolen)

		scanWork -= stolen

		if scanWork == 0 {
			// We were able to steal all of the credit we
			// needed.
			if enteredMarkAssistForTracing {
				trace := traceAcquire()
				if trace.ok() {
					trace.GCMarkAssistDone()
					// Set this *after* we trace the end to make sure
					// that we emit an in-progress event if this is
					// the first event for the goroutine in the trace
					// or trace generation. Also, do this between
					// acquire/release because this is part of the
					// goroutine's trace state, and it must be atomic
					// with respect to the tracer.
					gp.inMarkAssist = false
					traceRelease(trace)
				} else {
					// This state is tracked even if tracing isn't enabled.
					// It's only used by the new tracer.
					// See the comment on enteredMarkAssistForTracing.
					gp.inMarkAssist = false
				}
			}
			return
		}
	}
	if !enteredMarkAssistForTracing {
		trace := traceAcquire()
		if trace.ok() {
			trace.GCMarkAssistStart()
			// Set this *after* we trace the start, otherwise we may
			// emit an in-progress event for an assist we're about to start.
			gp.inMarkAssist = true
			traceRelease(trace)
		} else {
			gp.inMarkAssist = true
		}
		// In the new tracer, set enter mark assist tracing if we
		// ever pass this point, because we must manage inMarkAssist
		// correctly.
		//
		// See the comment on enteredMarkAssistForTracing.
		enteredMarkAssistForTracing = true
	}

	// Perform assist work
	systemstack(func() {
		gcAssistAlloc1(gp, scanWork)
		// The user stack may have moved, so this can't touch
		// anything on it until it returns from systemstack.
	})

	completed := gp.param != nil
	gp.param = nil
	if completed {
		gcMarkDone()
	}

	if gp.gcAssistBytes < 0 {
		// We were unable steal enough credit or perform
		// enough work to pay off the assist debt. We need to
		// do one of these before letting the mutator allocate
		// more to prevent over-allocation.
		//
		// If this is because we were preempted, reschedule
		// and try some more.
		if gp.preempt {
			Gosched()
			goto retry
		}

		// Add this G to an assist queue and park. When the GC
		// has more background credit, it will satisfy queued
		// assists before flushing to the global credit pool.
		//
		// Note that this does *not* get woken up when more
		// work is added to the work list. The theory is that
		// there wasn't enough work to do anyway, so we might
		// as well let background marking take care of the
		// work that is available.
		if !gcParkAssist() {
			goto retry
		}

		// At this point either background GC has satisfied
		// this G's assist debt, or the GC cycle is over.
	}
	if enteredMarkAssistForTracing {
		trace := traceAcquire()
		if trace.ok() {
			trace.GCMarkAssistDone()
			// Set this *after* we trace the end to make sure
			// that we emit an in-progress event if this is
			// the first event for the goroutine in the trace
			// or trace generation. Also, do this between
			// acquire/release because this is part of the
			// goroutine's trace state, and it must be atomic
			// with respect to the tracer.
			gp.inMarkAssist = false
			traceRelease(trace)
		} else {
			// This state is tracked even if tracing isn't enabled.
			// It's only used by the new tracer.
			// See the comment on enteredMarkAssistForTracing.
			gp.inMarkAssist = false
		}
	}
}

// gcAssistAlloc1 is the part of gcAssistAlloc that runs on the system
// stack. This is a separate function to make it easier to see that
// we're not capturing anything from the user stack, since the user
// stack may move while we're in this function.
//
// gcAssistAlloc1 indicates whether this assist completed the mark
// phase by setting gp.param to non-nil. This can't be communicated on
// the stack since it may move.
//
//go:systemstack
func gcAssistAlloc1(gp *g, scanWork int64) {
	// Clear the flag indicating that this assist completed the
	// mark phase.
	gp.param = nil

	if atomic.Load(&gcBlackenEnabled) == 0 {
		// The gcBlackenEnabled check in malloc races with the
		// store that clears it but an atomic check in every malloc
		// would be a performance hit.
		// Instead we recheck it here on the non-preemptible system
		// stack to determine if we should perform an assist.

		// GC is done, so ignore any remaining debt.
		gp.gcAssistBytes = 0
		return
	}
	// Track time spent in this assist. Since we're on the
	// system stack, this is non-preemptible, so we can
	// just measure start and end time.
	//
	// Limiter event tracking might be disabled if we end up here
	// while on a mark worker.
	startTime := nanotime()
	trackLimiterEvent := gp.m.p.ptr().limiterEvent.start(limiterEventMarkAssist, startTime)

	decnwait := atomic.Xadd(&work.nwait, -1)
	if decnwait == work.nproc {
		println("runtime: work.nwait =", decnwait, "work.nproc=", work.nproc)
		throw("nwait > work.nprocs")
	}

	// gcDrainN requires the caller to be preemptible.
	casGToWaitingForGC(gp, _Grunning, waitReasonGCAssistMarking)

	// drain own cached work first in the hopes that it
	// will be more cache friendly.
	gcw := &getg().m.p.ptr().gcw
	workDone := gcDrainN(gcw, scanWork)

	casgstatus(gp, _Gwaiting, _Grunning)

	// Record that we did this much scan work.
	//
	// Back out the number of bytes of assist credit that
	// this scan work counts for. The "1+" is a poor man's
	// round-up, to ensure this adds credit even if
	// assistBytesPerWork is very low.
	assistBytesPerWork := gcController.assistBytesPerWork.Load()
	gp.gcAssistBytes += 1 + int64(assistBytesPerWork*float64(workDone))

	// If this is the last worker and we ran out of work,
	// signal a completion point.
	incnwait := atomic.Xadd(&work.nwait, +1)
	if incnwait > work.nproc {
		println("runtime: work.nwait=", incnwait,
			"work.nproc=", work.nproc)
		throw("work.nwait > work.nproc")
	}

	if incnwait == work.nproc && !gcMarkWorkAvailable(nil) {
		// This has reached a background completion point. Set
		// gp.param to a non-nil value to indicate this. It
		// doesn't matter what we set it to (it just has to be
		// a valid pointer).
		gp.param = unsafe.Pointer(gp)
	}
	now := nanotime()
	duration := now - startTime
	pp := gp.m.p.ptr()
	pp.gcAssistTime += duration
	if trackLimiterEvent {
		pp.limiterEvent.stop(limiterEventMarkAssist, now)
	}
	if pp.gcAssistTime > gcAssistTimeSlack {
		gcController.assistTime.Add(pp.gcAssistTime)
		gcCPULimiter.update(now)
		pp.gcAssistTime = 0
	}
}

// gcWakeAllAssists wakes all currently blocked assists. This is used
// at the end of a GC cycle. gcBlackenEnabled must be false to prevent
// new assists from going to sleep after this point.
func gcWakeAllAssists() {
	lock(&work.assistQueue.lock)
	list := work.assistQueue.q.popList()
	injectglist(&list)
	unlock(&work.assistQueue.lock)
}

// gcParkAssist puts the current goroutine on the assist queue and parks.
//
// gcParkAssist reports whether the assist is now satisfied. If it
// returns false, the caller must retry the assist.
func gcParkAssist() bool {
	lock(&work.assistQueue.lock)
	// If the GC cycle finished while we were getting the lock,
	// exit the assist. The cycle can't finish while we hold the
	// lock.
	if atomic.Load(&gcBlackenEnabled) == 0 {
		unlock(&work.assistQueue.lock)
		return true
	}

	gp := getg()
	oldList := work.assistQueue.q
	work.assistQueue.q.pushBack(gp)

	// Recheck for background credit now that this G is in
	// the queue, but can still back out. This avoids a
	// race in case background marking has flushed more
	// credit since we checked above.
	if gcController.bgScanCredit.Load() > 0 {
		work.assistQueue.q = oldList
		if oldList.tail != 0 {
			oldList.tail.ptr().schedlink.set(nil)
		}
		unlock(&work.assistQueue.lock)
		return false
	}
	// Park.
	goparkunlock(&work.assistQueue.lock, waitReasonGCAssistWait, traceBlockGCMarkAssist, 2)
	return true
}

// gcFlushBgCredit flushes scanWork units of background scan work
// credit. This first satisfies blocked assists on the
// work.assistQueue and then flushes any remaining credit to
// gcController.bgScanCredit.
//
// Write barriers are disallowed because this is used by gcDrain after
// it has ensured that all work is drained and this must preserve that
// condition.
//
//go:nowritebarrierrec
func gcFlushBgCredit(scanWork int64) {
	if work.assistQueue.q.empty() {
		// Fast path; there are no blocked assists. There's a
		// small window here where an assist may add itself to
		// the blocked queue and park. If that happens, we'll
		// just get it on the next flush.
		gcController.bgScanCredit.Add(scanWork)
		return
	}

	assistBytesPerWork := gcController.assistBytesPerWork.Load()
	scanBytes := int64(float64(scanWork) * assistBytesPerWork)

	lock(&work.assistQueue.lock)
	for !work.assistQueue.q.empty() && scanBytes > 0 {
		gp := work.assistQueue.q.pop()
		// Note that gp.gcAssistBytes is negative because gp
		// is in debt. Think carefully about the signs below.
		if scanBytes+gp.gcAssistBytes >= 0 {
			// Satisfy this entire assist debt.
			scanBytes += gp.gcAssistBytes
			gp.gcAssistBytes = 0
			// It's important that we *not* put gp in
			// runnext. Otherwise, it's possible for user
			// code to exploit the GC worker's high
			// scheduler priority to get itself always run
			// before other goroutines and always in the
			// fresh quantum started by GC.
			ready(gp, 0, false)
		} else {
			// Partially satisfy this assist.
			gp.gcAssistBytes += scanBytes
			scanBytes = 0
			// As a heuristic, we move this assist to the
			// back of the queue so that large assists
			// can't clog up the assist queue and
			// substantially delay small assists.
			work.assistQueue.q.pushBack(gp)
			break
		}
	}

	if scanBytes > 0 {
		// Convert from scan bytes back to work.
		assistWorkPerByte := gcController.assistWorkPerByte.Load()
		scanWork = int64(float64(scanBytes) * assistWorkPerByte)
		gcController.bgScanCredit.Add(scanWork)
	}
	unlock(&work.assistQueue.lock)
}

// scanstack scans gp's stack, greying all pointers found on the stack.
//
// Returns the amount of scan work performed, but doesn't update
// gcController.stackScanWork or flush any credit. Any background credit produced
// by this function should be flushed by its caller. scanstack itself can't
// safely flush because it may result in trying to wake up a goroutine that
// was just scanned, resulting in a self-deadlock.
//
// scanstack will also shrink the stack if it is safe to do so. If it
// is not, it schedules a stack shrink for the next synchronous safe
// point.
//
// scanstack is marked go:systemstack because it must not be preempted
// while using a workbuf.
//
//go:nowritebarrier
//go:systemstack
func scanstack(gp *g, gcw *gcWork) int64 {
	if readgstatus(gp)&_Gscan == 0 {
		print("runtime:scanstack: gp=", gp, ", goid=", gp.goid, ", gp->atomicstatus=", hex(readgstatus(gp)), "\n")
		throw("scanstack - bad status")
	}

	switch readgstatus(gp) &^ _Gscan {
	default:
		print("runtime: gp=", gp, ", goid=", gp.goid, ", gp->atomicstatus=", readgstatus(gp), "\n")
		throw("mark - bad status")
	case _Gdead:
		return 0
	case _Grunning:
		print("runtime: gp=", gp, ", goid=", gp.goid, ", gp->atomicstatus=", readgstatus(gp), "\n")
		throw("scanstack: goroutine not stopped")
	case _Grunnable, _Gsyscall, _Gwaiting:
		// ok
	}

	if gp == getg() {
		throw("can't scan our own stack")
	}

	// scannedSize is the amount of work we'll be reporting.
	//
	// It is less than the allocated size (which is hi-lo).
	var sp uintptr
	if gp.syscallsp != 0 {
		sp = gp.syscallsp // If in a system call this is the stack pointer (gp.sched.sp can be 0 in this case on Windows).
	} else {
		sp = gp.sched.sp
	}
	scannedSize := gp.stack.hi - sp

	// Keep statistics for initial stack size calculation.
	// Note that this accumulates the scanned size, not the allocated size.
	p := getg().m.p.ptr()
	p.scannedStackSize += uint64(scannedSize)
	p.scannedStacks++

	if isShrinkStackSafe(gp) {
		// Shrink the stack if not much of it is being used.
		shrinkstack(gp)
	} else {
		// Otherwise, shrink the stack at the next sync safe point.
		gp.preemptShrink = true
	}

	var state stackScanState
	state.stack = gp.stack

	if stackTraceDebug {
		println("stack trace goroutine", gp.goid)
	}

	if debugScanConservative && gp.asyncSafePoint {
		print("scanning async preempted goroutine ", gp.goid, " stack [", hex(gp.stack.lo), ",", hex(gp.stack.hi), ")\n")
	}

	// Scan the saved context register. This is effectively a live
	// register that gets moved back and forth between the
	// register and sched.ctxt without a write barrier.
	if gp.sched.ctxt != nil {
		scanblock(uintptr(unsafe.Pointer(&gp.sched.ctxt)), goarch.PtrSize, &oneptrmask[0], gcw, &state)
	}

	// Scan the stack. Accumulate a list of stack objects.
	var u unwinder
	for u.init(gp, 0); u.valid(); u.next() {
		scanframeworker(&u.frame, &state, gcw)
	}

	// Find additional pointers that point into the stack from the heap.
	// Currently this includes defers and panics. See also function copystack.

	// Find and trace other pointers in defer records.
	for d := gp._defer; d != nil; d = d.link {
		if d.fn != nil {
			// Scan the func value, which could be a stack allocated closure.
			// See issue 30453.
			scanblock(uintptr(unsafe.Pointer(&d.fn)), goarch.PtrSize, &oneptrmask[0], gcw, &state)
		}
		if d.link != nil {
			// The link field of a stack-allocated defer record might point
			// to a heap-allocated defer record. Keep that heap record live.
			scanblock(uintptr(unsafe.Pointer(&d.link)), goarch.PtrSize, &oneptrmask[0], gcw, &state)
		}
		// Retain defers records themselves.
		// Defer records might not be reachable from the G through regular heap
		// tracing because the defer linked list might weave between the stack and the heap.
		if d.heap {
			scanblock(uintptr(unsafe.Pointer(&d)), goarch.PtrSize, &oneptrmask[0], gcw, &state)
		}
	}
	if gp._panic != nil {
		// Panics are always stack allocated.
		state.putPtr(uintptr(unsafe.Pointer(gp._panic)), false)
	}

	// Find and scan all reachable stack objects.
	//
	// The state's pointer queue prioritizes precise pointers over
	// conservative pointers so that we'll prefer scanning stack
	// objects precisely.
	state.buildIndex()
	for {
		p, conservative := state.getPtr()
		if p == 0 {
			break
		}
		obj := state.findObject(p)
		if obj == nil {
			continue
		}
		r := obj.r
		if r == nil {
			// We've already scanned this object.
			continue
		}
		obj.setRecord(nil) // Don't scan it again.
		if stackTraceDebug {
			printlock()
			print("  live stkobj at", hex(state.stack.lo+uintptr(obj.off)), "of size", obj.size)
			if conservative {
				print(" (conservative)")
			}
			println()
			printunlock()
		}
		ptrBytes, gcData := r.gcdata()
		b := state.stack.lo + uintptr(obj.off)
		if conservative {
			scanConservative(b, ptrBytes, gcData, gcw, &state)
		} else {
			scanblock(b, ptrBytes, gcData, gcw, &state)
		}
	}

	// Deallocate object buffers.
	// (Pointer buffers were all deallocated in the loop above.)
	for state.head != nil {
		x := state.head
		state.head = x.next
		if stackTraceDebug {
			for i := 0; i < x.nobj; i++ {
				obj := &x.obj[i]
				if obj.r == nil { // reachable
					continue
				}
				println("  dead stkobj at", hex(gp.stack.lo+uintptr(obj.off)), "of size", obj.r.size)
				// Note: not necessarily really dead - only reachable-from-ptr dead.
			}
		}
		x.nobj = 0
		putempty((*workbuf)(unsafe.Pointer(x)))
	}
	if state.buf != nil || state.cbuf != nil || state.freeBuf != nil {
		throw("remaining pointer buffers")
	}
	return int64(scannedSize)
}

// Scan a stack frame: local variables and function arguments/results.
//
//go:nowritebarrier
func scanframeworker(frame *stkframe, state *stackScanState, gcw *gcWork) {
	if _DebugGC > 1 && frame
"""




```