Response:
Let's break down the thought process for analyzing this Go code snippet related to garbage collection marking.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided Go code, which is a part of `runtime/mgcmark.go`. The request also asks for examples, potential errors, and a summary. The fact it's "part 2 of 2" suggests the previous part likely dealt with related aspects of GC marking, providing context.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for important keywords and function names that provide clues about its purpose. Keywords like `scan`, `mark`, `grey`, `black`, `object`, `frame`, `stack`, `conservative`, `drain`, `work`, `preempt`, `STW` (Stop-The-World), and data structures like `gcWork` and `mspan` jump out. These strongly suggest the code is involved in the mark phase of the garbage collector.

**3. Deeper Dive into Key Functions:**

Next, I'd focus on the main functions:

* **`scanframe`:**  The name clearly indicates it's about scanning stack frames. The logic for conservative scanning (`state.conservative`) and precise scanning (using `getStackMap`) stands out. The handling of `asyncPreempt` and `debugCallV2` suggests special cases during debugging or asynchronous preemption.

* **`gcDrain` and its wrappers (`gcDrainMarkWorkerIdle`, `gcDrainMarkWorkerDedicated`, `gcDrainMarkWorkerFractional`):** The "drain" suggests emptying or processing some kind of work queue. The flags passed to `gcDrain` provide insights into its different modes of operation (until preempt, idle, fractional, flush credit). The interaction with `gcWork`, `work.markrootNext`, and `gcw.tryGetFast`/`tryGet` points to processing root marking jobs and heap marking jobs. The mentions of `writeBarrier` are important too.

* **`scanblock`:** The name implies scanning a block of memory, and the presence of `ptrmask` suggests it can selectively scan based on a pointer bitmap. The interaction with `stackScanState` further confirms its role in stack scanning.

* **`scanobject`:** This seems to be the core function for scanning a heap object, using span information and type pointers (`typePointers`). The handling of large objects and "oblets" is an interesting detail.

* **`scanConservative`:**  This function explicitly performs conservative scanning, treating anything that looks like a pointer as one. The comments highlight its use when precise information is unavailable.

* **`greyobject`:** This function is responsible for marking an object as "grey," the intermediate state in mark-sweep GC. It interacts with `mbit` and enqueues the object for further processing.

* **`gcmarknewobject`:**  This function handles the marking of newly allocated objects. The fact it marks them "black" directly implies they don't need further scanning.

* **`gcMarkTinyAllocs`:** This function specifically deals with marking objects allocated in "tiny" allocation blocks.

**4. Inferring the Overall Functionality:**

Based on the individual function analysis, I can infer the overall functionality:

* **Stack Scanning:** The code scans stack frames to find pointers to heap objects. It supports both precise scanning (using compiler-generated stack maps) and conservative scanning (when precise information is unavailable).
* **Heap Scanning:**  It scans heap objects (and "oblets" for large objects) to find pointers to other heap objects. This involves traversing the object's memory based on type information.
* **Root Scanning:**  The `gcDrain` function also processes root marking jobs, which involve scanning global variables and other roots for pointers.
* **Work Management:**  The `gcWork` structure and the `gcDrain` function manage the work of marking objects. It seems to involve work stealing and balancing.
* **Conservative vs. Precise Scanning:**  The code distinguishes between these two approaches, highlighting the situations where each is used.
* **Grey Marking:** The `greyobject` function implements the "grey" marking step in a tri-color marking algorithm.
* **Handling New Objects and Tiny Allocations:**  Specific functions handle the efficient marking of newly allocated objects and objects in tiny allocation blocks.
* **Preemption Handling:** The code interacts with the Go scheduler and considers preemption, especially in the `gcDrain` function.

**5. Constructing Examples and Explanations:**

With a good understanding of the functionality, I can now construct examples and explanations. For the `scanframe` example, showing a normal function and a function where conservative scanning is triggered (like an async preemption handler) is useful. For `gcDrain`, illustrating the different flags and their effects is important.

**6. Identifying Potential Errors:**

Looking at the code and comments, I can identify potential error scenarios:

* **Incorrect GC Phase:**  The checks in `gcDrain` and `gcDrainN` related to `writeBarrier.enabled` highlight the importance of calling these functions during the correct GC phase.
* **Marking Free Objects:** The checks in `greyobject` for marking free objects indicate a potential logic error.
* **Misaligned Objects:** The check in `greyobject` for pointer alignment suggests this could lead to crashes or unexpected behavior.

**7. Summarizing and Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, addressing each part of the original request: listing functions, explaining functionality, providing examples, discussing command-line parameters (though none were present in this snippet), highlighting potential errors, and summarizing the overall functionality. The "part 2 of 2" instruction reminds me to focus on the specific functionality presented in this snippet while acknowledging that it's part of a larger GC process.

**Self-Correction/Refinement During the Process:**

* **Initially, I might have overemphasized the details of specific data structures like `gcWork` and `mspan`.**  However, the request asks for functionality, so I would shift the focus to *what* the code does rather than *how* it does it at a low level.
* **I might have initially overlooked the significance of the different `gcDrain` wrappers.**  Recognizing that these are for profiling helps understand their purpose.
* **The "conservative scanning" concept is crucial.** I'd make sure to clearly explain why and when it's necessary.

By following this structured approach, combining code analysis with knowledge of garbage collection principles, I can effectively understand and explain the provided Go code snippet.
这段代码是 Go 语言运行时（runtime）中垃圾回收（Garbage Collection，GC）标记（mark）阶段的核心部分。它主要负责遍历 Goroutine 的栈和堆上的对象，标记出所有可达的对象，为后续的清理（sweep）阶段做准备。

**功能归纳：**

这段代码主要实现了以下功能：

1. **栈扫描 (Stack Scanning):**
   - 遍历 Goroutine 的栈帧 (stack frame)。
   - 区分精确扫描和保守扫描两种模式。
   - **精确扫描:** 利用编译器生成的栈地图 (stack map) 精确地识别栈上的指针，并标记这些指针指向的堆对象。
   - **保守扫描:** 当无法获取精确的栈地图时（例如，在异步抢占或 `debugCallV2` 调用的上下文中），保守地将栈上的所有看起来像指针的值都当作指针处理，并尝试标记它们指向的堆对象。
   - 特殊处理异步抢占 (`asyncPreempt`) 和 `debugCallV2` 调用导致的栈扫描。

2. **堆扫描 (Heap Scanning):**
   - 从工作队列 (`gcWork`) 中获取待扫描的对象。
   - 利用 Span 信息和类型信息 (`typePointers`) 遍历对象内部的字段。
   - 识别对象内部的指针，并标记这些指针指向的堆对象。
   - 将新发现的需要扫描的对象添加到工作队列中。
   - 支持扫描大的对象，并将其分割成更小的 "oblet" 进行并行处理。

3. **根对象扫描 (Root Scanning):**
   - `gcDrain` 函数负责处理根对象扫描的任务。
   - 从全局的 `work` 结构体中获取根对象扫描的任务。
   - 调用 `markroot` 函数来扫描各种类型的根对象（例如，全局变量、寄存器等）。

4. **工作窃取和平衡 (Work Stealing and Balancing):**
   - `gcDrain` 函数中，如果本地工作队列为空，会尝试从全局工作队列 (`work.full == 0`) 或其他 P 的工作队列中窃取工作 (`gcw.balance()`)，以提高并行性。

5. **后台扫描信用管理 (Background Scan Credit Management):**
   - `gcDrain` 函数可以配置为定期将扫描工作量反馈给 `gcController.bgScanCredit`，用于控制后台扫描的速率。

6. **新分配对象和 Tiny 对象处理:**
   - `gcmarknewobject` 函数用于直接将新分配的对象标记为黑色，前提是该对象不包含任何非 nil 指针。
   - `gcMarkTinyAllocs` 函数用于标记所有活动的 tiny 对象分配块。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言垃圾回收器中**并发标记 (Concurrent Marking)** 阶段的核心实现。并发标记是 Go GC 的关键特性，它允许 GC 和用户 Goroutine 并发执行，从而减少 STW（Stop-The-World）时间，提高程序的响应性。

**Go 代码举例说明：**

```go
package main

import "runtime"

type MyStruct struct {
	Data *int
	Next *MyStruct
}

func main() {
	runtime.GC() // 手动触发一次 GC

	// 创建一些对象，形成对象图
	var a int = 10
	b := &MyStruct{Data: &a}
	c := &MyStruct{Next: b}

	// 在 GC 标记阶段，GC 会遍历 c, b, a 这些可达的对象并进行标记
	runtime.KeepAlive(c) // 确保 c 不会被过早回收

	runtime.GC() // 再次触发 GC，清理未标记的对象
}
```

**假设的输入与输出：**

假设在上面的例子中，GC 开始标记时：

* **输入 (栈扫描):**
    - 当前 Goroutine 的栈信息，包括栈指针、变量地址等。
    - 栈地图信息（如果可用），指示哪些栈上的位置可能包含指针。
* **输入 (堆扫描):**
    - 工作队列中包含 `c` 对象的地址。
* **处理:**
    1. **栈扫描:** GC 会扫描 `main` 函数的栈帧，找到指向 `c` 的指针。
    2. **堆扫描:**
       - 从工作队列取出 `c` 的地址。
       - 扫描 `c` 对象的内存布局，找到 `Next` 字段是指向 `b` 的指针。
       - 将 `b` 的地址添加到工作队列。
       - 扫描 `b` 对象的内存布局，找到 `Data` 字段是指向 `a` 的指针。
       - 由于 `a` 不是堆对象（很可能在栈上或静态区），标记过程可能会略有不同，但其可达性会被追踪。
* **输出:**
    - `c`、`b` 以及 `a` (如果被认为是需要标记的) 都会被标记为可达对象。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。Go 运行时的 GC 行为可以通过环境变量和 `runtime/debug` 包中的函数进行配置，例如：

* **`GOGC` 环境变量:** 设置 GC 的目标百分比。
* **`GODEBUG=gctrace=1` 环境变量:** 启用 GC 跟踪信息输出。
* **`runtime/debug.SetGCPercent()` 函数:** 在程序运行时动态设置 GC 的目标百分比。

**使用者易犯错的点：**

虽然使用者不直接操作这段代码，但理解其背后的原理可以避免一些常见的与 GC 相关的错误：

1. **误解 `runtime.GC()` 的作用:** `runtime.GC()` 只是建议运行时执行一次 GC，并不能保证立即执行。过度依赖手动 GC 可能反而会影响性能。
2. **忘记使用 `runtime.KeepAlive()`:** 在某些情况下，如果一个对象不再被 Go 代码直接引用，但在 C 代码中可能还在使用，GC 可能会过早回收它。`runtime.KeepAlive()` 可以防止这种情况发生。
3. **性能分析不足导致不必要的 GC 优化:**  过早或不当的 GC 优化往往是徒劳的，甚至可能降低性能。应该基于实际的性能分析结果进行优化。

**总结这段代码的功能：**

这段 `mgcmark.go` 的代码是 Go 语言并发垃圾回收器中**标记阶段**的关键组成部分。它负责：

- **遍历 Goroutine 的栈**，识别并标记栈上指向堆对象的指针。
- **遍历堆上的对象**，识别并标记对象内部指向其他堆对象的指针。
- **处理根对象**，确保所有从根可达的对象都能被标记。
- **管理标记工作队列**，实现高效的并发标记。
- **支持保守扫描**，处理无法精确获取栈信息的场景。
- **处理新分配的对象和 tiny 对象**，优化标记效率。

总而言之，这段代码确保了在 GC 过程中，所有仍在使用的（可达的）对象都被正确标记，为后续的清理阶段安全地回收不再使用的内存奠定了基础。

Prompt: 
```
这是路径为go/src/runtime/mgcmark.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
.continpc != 0 {
		print("scanframe ", funcname(frame.fn), "\n")
	}

	isAsyncPreempt := frame.fn.valid() && frame.fn.funcID == abi.FuncID_asyncPreempt
	isDebugCall := frame.fn.valid() && frame.fn.funcID == abi.FuncID_debugCallV2
	if state.conservative || isAsyncPreempt || isDebugCall {
		if debugScanConservative {
			println("conservatively scanning function", funcname(frame.fn), "at PC", hex(frame.continpc))
		}

		// Conservatively scan the frame. Unlike the precise
		// case, this includes the outgoing argument space
		// since we may have stopped while this function was
		// setting up a call.
		//
		// TODO: We could narrow this down if the compiler
		// produced a single map per function of stack slots
		// and registers that ever contain a pointer.
		if frame.varp != 0 {
			size := frame.varp - frame.sp
			if size > 0 {
				scanConservative(frame.sp, size, nil, gcw, state)
			}
		}

		// Scan arguments to this frame.
		if n := frame.argBytes(); n != 0 {
			// TODO: We could pass the entry argument map
			// to narrow this down further.
			scanConservative(frame.argp, n, nil, gcw, state)
		}

		if isAsyncPreempt || isDebugCall {
			// This function's frame contained the
			// registers for the asynchronously stopped
			// parent frame. Scan the parent
			// conservatively.
			state.conservative = true
		} else {
			// We only wanted to scan those two frames
			// conservatively. Clear the flag for future
			// frames.
			state.conservative = false
		}
		return
	}

	locals, args, objs := frame.getStackMap(false)

	// Scan local variables if stack frame has been allocated.
	if locals.n > 0 {
		size := uintptr(locals.n) * goarch.PtrSize
		scanblock(frame.varp-size, size, locals.bytedata, gcw, state)
	}

	// Scan arguments.
	if args.n > 0 {
		scanblock(frame.argp, uintptr(args.n)*goarch.PtrSize, args.bytedata, gcw, state)
	}

	// Add all stack objects to the stack object list.
	if frame.varp != 0 {
		// varp is 0 for defers, where there are no locals.
		// In that case, there can't be a pointer to its args, either.
		// (And all args would be scanned above anyway.)
		for i := range objs {
			obj := &objs[i]
			off := obj.off
			base := frame.varp // locals base pointer
			if off >= 0 {
				base = frame.argp // arguments and return values base pointer
			}
			ptr := base + uintptr(off)
			if ptr < frame.sp {
				// object hasn't been allocated in the frame yet.
				continue
			}
			if stackTraceDebug {
				println("stkobj at", hex(ptr), "of size", obj.size)
			}
			state.addObject(ptr, obj)
		}
	}
}

type gcDrainFlags int

const (
	gcDrainUntilPreempt gcDrainFlags = 1 << iota
	gcDrainFlushBgCredit
	gcDrainIdle
	gcDrainFractional
)

// gcDrainMarkWorkerIdle is a wrapper for gcDrain that exists to better account
// mark time in profiles.
func gcDrainMarkWorkerIdle(gcw *gcWork) {
	gcDrain(gcw, gcDrainIdle|gcDrainUntilPreempt|gcDrainFlushBgCredit)
}

// gcDrainMarkWorkerDedicated is a wrapper for gcDrain that exists to better account
// mark time in profiles.
func gcDrainMarkWorkerDedicated(gcw *gcWork, untilPreempt bool) {
	flags := gcDrainFlushBgCredit
	if untilPreempt {
		flags |= gcDrainUntilPreempt
	}
	gcDrain(gcw, flags)
}

// gcDrainMarkWorkerFractional is a wrapper for gcDrain that exists to better account
// mark time in profiles.
func gcDrainMarkWorkerFractional(gcw *gcWork) {
	gcDrain(gcw, gcDrainFractional|gcDrainUntilPreempt|gcDrainFlushBgCredit)
}

// gcDrain scans roots and objects in work buffers, blackening grey
// objects until it is unable to get more work. It may return before
// GC is done; it's the caller's responsibility to balance work from
// other Ps.
//
// If flags&gcDrainUntilPreempt != 0, gcDrain returns when g.preempt
// is set.
//
// If flags&gcDrainIdle != 0, gcDrain returns when there is other work
// to do.
//
// If flags&gcDrainFractional != 0, gcDrain self-preempts when
// pollFractionalWorkerExit() returns true. This implies
// gcDrainNoBlock.
//
// If flags&gcDrainFlushBgCredit != 0, gcDrain flushes scan work
// credit to gcController.bgScanCredit every gcCreditSlack units of
// scan work.
//
// gcDrain will always return if there is a pending STW or forEachP.
//
// Disabling write barriers is necessary to ensure that after we've
// confirmed that we've drained gcw, that we don't accidentally end
// up flipping that condition by immediately adding work in the form
// of a write barrier buffer flush.
//
// Don't set nowritebarrierrec because it's safe for some callees to
// have write barriers enabled.
//
//go:nowritebarrier
func gcDrain(gcw *gcWork, flags gcDrainFlags) {
	if !writeBarrier.enabled {
		throw("gcDrain phase incorrect")
	}

	// N.B. We must be running in a non-preemptible context, so it's
	// safe to hold a reference to our P here.
	gp := getg().m.curg
	pp := gp.m.p.ptr()
	preemptible := flags&gcDrainUntilPreempt != 0
	flushBgCredit := flags&gcDrainFlushBgCredit != 0
	idle := flags&gcDrainIdle != 0

	initScanWork := gcw.heapScanWork

	// checkWork is the scan work before performing the next
	// self-preempt check.
	checkWork := int64(1<<63 - 1)
	var check func() bool
	if flags&(gcDrainIdle|gcDrainFractional) != 0 {
		checkWork = initScanWork + drainCheckThreshold
		if idle {
			check = pollWork
		} else if flags&gcDrainFractional != 0 {
			check = pollFractionalWorkerExit
		}
	}

	// Drain root marking jobs.
	if work.markrootNext < work.markrootJobs {
		// Stop if we're preemptible, if someone wants to STW, or if
		// someone is calling forEachP.
		for !(gp.preempt && (preemptible || sched.gcwaiting.Load() || pp.runSafePointFn != 0)) {
			job := atomic.Xadd(&work.markrootNext, +1) - 1
			if job >= work.markrootJobs {
				break
			}
			markroot(gcw, job, flushBgCredit)
			if check != nil && check() {
				goto done
			}
		}
	}

	// Drain heap marking jobs.
	//
	// Stop if we're preemptible, if someone wants to STW, or if
	// someone is calling forEachP.
	//
	// TODO(mknyszek): Consider always checking gp.preempt instead
	// of having the preempt flag, and making an exception for certain
	// mark workers in retake. That might be simpler than trying to
	// enumerate all the reasons why we might want to preempt, even
	// if we're supposed to be mostly non-preemptible.
	for !(gp.preempt && (preemptible || sched.gcwaiting.Load() || pp.runSafePointFn != 0)) {
		// Try to keep work available on the global queue. We used to
		// check if there were waiting workers, but it's better to
		// just keep work available than to make workers wait. In the
		// worst case, we'll do O(log(_WorkbufSize)) unnecessary
		// balances.
		if work.full == 0 {
			gcw.balance()
		}

		b := gcw.tryGetFast()
		if b == 0 {
			b = gcw.tryGet()
			if b == 0 {
				// Flush the write barrier
				// buffer; this may create
				// more work.
				wbBufFlush()
				b = gcw.tryGet()
			}
		}
		if b == 0 {
			// Unable to get work.
			break
		}
		scanobject(b, gcw)

		// Flush background scan work credit to the global
		// account if we've accumulated enough locally so
		// mutator assists can draw on it.
		if gcw.heapScanWork >= gcCreditSlack {
			gcController.heapScanWork.Add(gcw.heapScanWork)
			if flushBgCredit {
				gcFlushBgCredit(gcw.heapScanWork - initScanWork)
				initScanWork = 0
			}
			checkWork -= gcw.heapScanWork
			gcw.heapScanWork = 0

			if checkWork <= 0 {
				checkWork += drainCheckThreshold
				if check != nil && check() {
					break
				}
			}
		}
	}

done:
	// Flush remaining scan work credit.
	if gcw.heapScanWork > 0 {
		gcController.heapScanWork.Add(gcw.heapScanWork)
		if flushBgCredit {
			gcFlushBgCredit(gcw.heapScanWork - initScanWork)
		}
		gcw.heapScanWork = 0
	}
}

// gcDrainN blackens grey objects until it has performed roughly
// scanWork units of scan work or the G is preempted. This is
// best-effort, so it may perform less work if it fails to get a work
// buffer. Otherwise, it will perform at least n units of work, but
// may perform more because scanning is always done in whole object
// increments. It returns the amount of scan work performed.
//
// The caller goroutine must be in a preemptible state (e.g.,
// _Gwaiting) to prevent deadlocks during stack scanning. As a
// consequence, this must be called on the system stack.
//
//go:nowritebarrier
//go:systemstack
func gcDrainN(gcw *gcWork, scanWork int64) int64 {
	if !writeBarrier.enabled {
		throw("gcDrainN phase incorrect")
	}

	// There may already be scan work on the gcw, which we don't
	// want to claim was done by this call.
	workFlushed := -gcw.heapScanWork

	// In addition to backing out because of a preemption, back out
	// if the GC CPU limiter is enabled.
	gp := getg().m.curg
	for !gp.preempt && !gcCPULimiter.limiting() && workFlushed+gcw.heapScanWork < scanWork {
		// See gcDrain comment.
		if work.full == 0 {
			gcw.balance()
		}

		b := gcw.tryGetFast()
		if b == 0 {
			b = gcw.tryGet()
			if b == 0 {
				// Flush the write barrier buffer;
				// this may create more work.
				wbBufFlush()
				b = gcw.tryGet()
			}
		}

		if b == 0 {
			// Try to do a root job.
			if work.markrootNext < work.markrootJobs {
				job := atomic.Xadd(&work.markrootNext, +1) - 1
				if job < work.markrootJobs {
					workFlushed += markroot(gcw, job, false)
					continue
				}
			}
			// No heap or root jobs.
			break
		}

		scanobject(b, gcw)

		// Flush background scan work credit.
		if gcw.heapScanWork >= gcCreditSlack {
			gcController.heapScanWork.Add(gcw.heapScanWork)
			workFlushed += gcw.heapScanWork
			gcw.heapScanWork = 0
		}
	}

	// Unlike gcDrain, there's no need to flush remaining work
	// here because this never flushes to bgScanCredit and
	// gcw.dispose will flush any remaining work to scanWork.

	return workFlushed + gcw.heapScanWork
}

// scanblock scans b as scanobject would, but using an explicit
// pointer bitmap instead of the heap bitmap.
//
// This is used to scan non-heap roots, so it does not update
// gcw.bytesMarked or gcw.heapScanWork.
//
// If stk != nil, possible stack pointers are also reported to stk.putPtr.
//
//go:nowritebarrier
func scanblock(b0, n0 uintptr, ptrmask *uint8, gcw *gcWork, stk *stackScanState) {
	// Use local copies of original parameters, so that a stack trace
	// due to one of the throws below shows the original block
	// base and extent.
	b := b0
	n := n0

	for i := uintptr(0); i < n; {
		// Find bits for the next word.
		bits := uint32(*addb(ptrmask, i/(goarch.PtrSize*8)))
		if bits == 0 {
			i += goarch.PtrSize * 8
			continue
		}
		for j := 0; j < 8 && i < n; j++ {
			if bits&1 != 0 {
				// Same work as in scanobject; see comments there.
				p := *(*uintptr)(unsafe.Pointer(b + i))
				if p != 0 {
					if obj, span, objIndex := findObject(p, b, i); obj != 0 {
						greyobject(obj, b, i, span, gcw, objIndex)
					} else if stk != nil && p >= stk.stack.lo && p < stk.stack.hi {
						stk.putPtr(p, false)
					}
				}
			}
			bits >>= 1
			i += goarch.PtrSize
		}
	}
}

// scanobject scans the object starting at b, adding pointers to gcw.
// b must point to the beginning of a heap object or an oblet.
// scanobject consults the GC bitmap for the pointer mask and the
// spans for the size of the object.
//
//go:nowritebarrier
func scanobject(b uintptr, gcw *gcWork) {
	// Prefetch object before we scan it.
	//
	// This will overlap fetching the beginning of the object with initial
	// setup before we start scanning the object.
	sys.Prefetch(b)

	// Find the bits for b and the size of the object at b.
	//
	// b is either the beginning of an object, in which case this
	// is the size of the object to scan, or it points to an
	// oblet, in which case we compute the size to scan below.
	s := spanOfUnchecked(b)
	n := s.elemsize
	if n == 0 {
		throw("scanobject n == 0")
	}
	if s.spanclass.noscan() {
		// Correctness-wise this is ok, but it's inefficient
		// if noscan objects reach here.
		throw("scanobject of a noscan object")
	}

	var tp typePointers
	if n > maxObletBytes {
		// Large object. Break into oblets for better
		// parallelism and lower latency.
		if b == s.base() {
			// Enqueue the other oblets to scan later.
			// Some oblets may be in b's scalar tail, but
			// these will be marked as "no more pointers",
			// so we'll drop out immediately when we go to
			// scan those.
			for oblet := b + maxObletBytes; oblet < s.base()+s.elemsize; oblet += maxObletBytes {
				if !gcw.putFast(oblet) {
					gcw.put(oblet)
				}
			}
		}

		// Compute the size of the oblet. Since this object
		// must be a large object, s.base() is the beginning
		// of the object.
		n = s.base() + s.elemsize - b
		n = min(n, maxObletBytes)
		tp = s.typePointersOfUnchecked(s.base())
		tp = tp.fastForward(b-tp.addr, b+n)
	} else {
		tp = s.typePointersOfUnchecked(b)
	}

	var scanSize uintptr
	for {
		var addr uintptr
		if tp, addr = tp.nextFast(); addr == 0 {
			if tp, addr = tp.next(b + n); addr == 0 {
				break
			}
		}

		// Keep track of farthest pointer we found, so we can
		// update heapScanWork. TODO: is there a better metric,
		// now that we can skip scalar portions pretty efficiently?
		scanSize = addr - b + goarch.PtrSize

		// Work here is duplicated in scanblock and above.
		// If you make changes here, make changes there too.
		obj := *(*uintptr)(unsafe.Pointer(addr))

		// At this point we have extracted the next potential pointer.
		// Quickly filter out nil and pointers back to the current object.
		if obj != 0 && obj-b >= n {
			// Test if obj points into the Go heap and, if so,
			// mark the object.
			//
			// Note that it's possible for findObject to
			// fail if obj points to a just-allocated heap
			// object because of a race with growing the
			// heap. In this case, we know the object was
			// just allocated and hence will be marked by
			// allocation itself.
			if obj, span, objIndex := findObject(obj, b, addr-b); obj != 0 {
				greyobject(obj, b, addr-b, span, gcw, objIndex)
			}
		}
	}
	gcw.bytesMarked += uint64(n)
	gcw.heapScanWork += int64(scanSize)
}

// scanConservative scans block [b, b+n) conservatively, treating any
// pointer-like value in the block as a pointer.
//
// If ptrmask != nil, only words that are marked in ptrmask are
// considered as potential pointers.
//
// If state != nil, it's assumed that [b, b+n) is a block in the stack
// and may contain pointers to stack objects.
func scanConservative(b, n uintptr, ptrmask *uint8, gcw *gcWork, state *stackScanState) {
	if debugScanConservative {
		printlock()
		print("conservatively scanning [", hex(b), ",", hex(b+n), ")\n")
		hexdumpWords(b, b+n, func(p uintptr) byte {
			if ptrmask != nil {
				word := (p - b) / goarch.PtrSize
				bits := *addb(ptrmask, word/8)
				if (bits>>(word%8))&1 == 0 {
					return '$'
				}
			}

			val := *(*uintptr)(unsafe.Pointer(p))
			if state != nil && state.stack.lo <= val && val < state.stack.hi {
				return '@'
			}

			span := spanOfHeap(val)
			if span == nil {
				return ' '
			}
			idx := span.objIndex(val)
			if span.isFree(idx) {
				return ' '
			}
			return '*'
		})
		printunlock()
	}

	for i := uintptr(0); i < n; i += goarch.PtrSize {
		if ptrmask != nil {
			word := i / goarch.PtrSize
			bits := *addb(ptrmask, word/8)
			if bits == 0 {
				// Skip 8 words (the loop increment will do the 8th)
				//
				// This must be the first time we've
				// seen this word of ptrmask, so i
				// must be 8-word-aligned, but check
				// our reasoning just in case.
				if i%(goarch.PtrSize*8) != 0 {
					throw("misaligned mask")
				}
				i += goarch.PtrSize*8 - goarch.PtrSize
				continue
			}
			if (bits>>(word%8))&1 == 0 {
				continue
			}
		}

		val := *(*uintptr)(unsafe.Pointer(b + i))

		// Check if val points into the stack.
		if state != nil && state.stack.lo <= val && val < state.stack.hi {
			// val may point to a stack object. This
			// object may be dead from last cycle and
			// hence may contain pointers to unallocated
			// objects, but unlike heap objects we can't
			// tell if it's already dead. Hence, if all
			// pointers to this object are from
			// conservative scanning, we have to scan it
			// defensively, too.
			state.putPtr(val, true)
			continue
		}

		// Check if val points to a heap span.
		span := spanOfHeap(val)
		if span == nil {
			continue
		}

		// Check if val points to an allocated object.
		idx := span.objIndex(val)
		if span.isFree(idx) {
			continue
		}

		// val points to an allocated object. Mark it.
		obj := span.base() + idx*span.elemsize
		greyobject(obj, b, i, span, gcw, idx)
	}
}

// Shade the object if it isn't already.
// The object is not nil and known to be in the heap.
// Preemption must be disabled.
//
//go:nowritebarrier
func shade(b uintptr) {
	if obj, span, objIndex := findObject(b, 0, 0); obj != 0 {
		gcw := &getg().m.p.ptr().gcw
		greyobject(obj, 0, 0, span, gcw, objIndex)
	}
}

// obj is the start of an object with mark mbits.
// If it isn't already marked, mark it and enqueue into gcw.
// base and off are for debugging only and could be removed.
//
// See also wbBufFlush1, which partially duplicates this logic.
//
//go:nowritebarrierrec
func greyobject(obj, base, off uintptr, span *mspan, gcw *gcWork, objIndex uintptr) {
	// obj should be start of allocation, and so must be at least pointer-aligned.
	if obj&(goarch.PtrSize-1) != 0 {
		throw("greyobject: obj not pointer-aligned")
	}
	mbits := span.markBitsForIndex(objIndex)

	if useCheckmark {
		if setCheckmark(obj, base, off, mbits) {
			// Already marked.
			return
		}
	} else {
		if debug.gccheckmark > 0 && span.isFree(objIndex) {
			print("runtime: marking free object ", hex(obj), " found at *(", hex(base), "+", hex(off), ")\n")
			gcDumpObject("base", base, off)
			gcDumpObject("obj", obj, ^uintptr(0))
			getg().m.traceback = 2
			throw("marking free object")
		}

		// If marked we have nothing to do.
		if mbits.isMarked() {
			return
		}
		mbits.setMarked()

		// Mark span.
		arena, pageIdx, pageMask := pageIndexOf(span.base())
		if arena.pageMarks[pageIdx]&pageMask == 0 {
			atomic.Or8(&arena.pageMarks[pageIdx], pageMask)
		}

		// If this is a noscan object, fast-track it to black
		// instead of greying it.
		if span.spanclass.noscan() {
			gcw.bytesMarked += uint64(span.elemsize)
			return
		}
	}

	// We're adding obj to P's local workbuf, so it's likely
	// this object will be processed soon by the same P.
	// Even if the workbuf gets flushed, there will likely still be
	// some benefit on platforms with inclusive shared caches.
	sys.Prefetch(obj)
	// Queue the obj for scanning.
	if !gcw.putFast(obj) {
		gcw.put(obj)
	}
}

// gcDumpObject dumps the contents of obj for debugging and marks the
// field at byte offset off in obj.
func gcDumpObject(label string, obj, off uintptr) {
	s := spanOf(obj)
	print(label, "=", hex(obj))
	if s == nil {
		print(" s=nil\n")
		return
	}
	print(" s.base()=", hex(s.base()), " s.limit=", hex(s.limit), " s.spanclass=", s.spanclass, " s.elemsize=", s.elemsize, " s.state=")
	if state := s.state.get(); 0 <= state && int(state) < len(mSpanStateNames) {
		print(mSpanStateNames[state], "\n")
	} else {
		print("unknown(", state, ")\n")
	}

	skipped := false
	size := s.elemsize
	if s.state.get() == mSpanManual && size == 0 {
		// We're printing something from a stack frame. We
		// don't know how big it is, so just show up to an
		// including off.
		size = off + goarch.PtrSize
	}
	for i := uintptr(0); i < size; i += goarch.PtrSize {
		// For big objects, just print the beginning (because
		// that usually hints at the object's type) and the
		// fields around off.
		if !(i < 128*goarch.PtrSize || off-16*goarch.PtrSize < i && i < off+16*goarch.PtrSize) {
			skipped = true
			continue
		}
		if skipped {
			print(" ...\n")
			skipped = false
		}
		print(" *(", label, "+", i, ") = ", hex(*(*uintptr)(unsafe.Pointer(obj + i))))
		if i == off {
			print(" <==")
		}
		print("\n")
	}
	if skipped {
		print(" ...\n")
	}
}

// gcmarknewobject marks a newly allocated object black. obj must
// not contain any non-nil pointers.
//
// This is nosplit so it can manipulate a gcWork without preemption.
//
//go:nowritebarrier
//go:nosplit
func gcmarknewobject(span *mspan, obj uintptr) {
	if useCheckmark { // The world should be stopped so this should not happen.
		throw("gcmarknewobject called while doing checkmark")
	}
	if gcphase == _GCmarktermination {
		// Check this here instead of on the hot path.
		throw("mallocgc called with gcphase == _GCmarktermination")
	}

	// Mark object.
	objIndex := span.objIndex(obj)
	span.markBitsForIndex(objIndex).setMarked()

	// Mark span.
	arena, pageIdx, pageMask := pageIndexOf(span.base())
	if arena.pageMarks[pageIdx]&pageMask == 0 {
		atomic.Or8(&arena.pageMarks[pageIdx], pageMask)
	}

	gcw := &getg().m.p.ptr().gcw
	gcw.bytesMarked += uint64(span.elemsize)
}

// gcMarkTinyAllocs greys all active tiny alloc blocks.
//
// The world must be stopped.
func gcMarkTinyAllocs() {
	assertWorldStopped()

	for _, p := range allp {
		c := p.mcache
		if c == nil || c.tiny == 0 {
			continue
		}
		_, span, objIndex := findObject(c.tiny, 0, 0)
		gcw := &p.gcw
		greyobject(c.tiny, 0, 0, span, gcw, objIndex)
	}
}

"""




```