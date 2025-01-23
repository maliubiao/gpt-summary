Response:
Let's break down the thought process for analyzing this Go code snippet from `runtime/stack.go`.

**1. Initial Scan and Understanding the Context:**

* **File Path:**  The path `go/src/runtime/stack.go` immediately tells us this code is part of the core Go runtime, specifically dealing with stack management. This means performance and correctness are paramount.
* **Copyright and License:** Standard Go boilerplate, indicating open-source and licensing.
* **Package `runtime`:** Confirms the core runtime nature of the code.
* **Imports:**  `internal/abi`, `internal/cpu`, etc., signal interactions with low-level aspects of the Go environment, like architecture, OS, and CPU features. The presence of `unsafe` highlights direct memory manipulation.

**2. Identifying Key Sections and Their Purposes (Top-Down Approach):**

* **Stack Layout Parameters (Comments):** The extensive comments at the beginning are crucial. They describe the fundamental concepts of stack management in Go: `StackGuard`, `StackSmall`, `StackBig`, and how the runtime checks for stack overflow. The detailed explanation of the assembly-level checks is a strong indicator of this file's core function. The mention of `deferproc` and `morestack` hints at their close relationship with stack management.
* **Constants:**  The `const` block defines important values related to stack sizes, guards, and debugging options. These values are likely used throughout the stack management logic. Pay attention to how some constants are conditional based on the OS (`goos`) and architecture (`goarch`).
* **Variables:**  The `var` block declares global variables. `stackpool` and `stackLarge` immediately stand out as central data structures for managing stack memory. The naming suggests different strategies for handling small and large stacks. `stackDebug` points to debugging features.
* **Functions:** The function declarations provide a roadmap of the operations this code performs: `stackinit`, `stacklog2`, `stackpoolalloc`, `stackpoolfree`, `stackcacherefill`, `stackcacherelease`, `stackcache_clear`, `stackalloc`, `stackfree`, `copystack`, `newstack`, etc. The names are generally descriptive, making it easier to infer their roles.

**3. Deep Dive into Key Functionalities (Focusing on the Request):**

* **Stack Allocation and Deallocation:** The presence of `stackalloc` and `stackfree` is a clear indication of the code's responsibility for managing stack memory. The comments within these functions, particularly the checks for powers of 2 and the handling of `stackFromSystem` and `debug.efence`, reveal different allocation strategies. The use of `mcache` and `stackpool` within these functions points to a caching mechanism for efficiency.
* **Stack Overflow Handling:** The initial comments and the `stackGuard` constant strongly suggest this code is involved in preventing stack overflows. The mention of `morestack` implies a function called when the stack needs to grow.
* **Stack Copying/Resizing (`copystack`):** This function explicitly deals with moving a goroutine's stack to a new location, likely when the stack needs to grow or shrink. The function's logic involves careful adjustment of pointers within the stack frame.
* **Stack Growth (`newstack`):** This function seems to be the entry point when a stack overflow is detected and the stack needs to be expanded. It interacts with `copystack`.
* **Stack Caching (`stackcacherefill`, `stackcacherelease`, `stackcache_clear`):** These functions indicate a caching mechanism to optimize stack allocation and deallocation, likely using per-processor (`mcache`) caches.

**4. Inferring Go Language Features:**

* **Goroutines:** The entire concept of stack management in this code is intrinsically linked to goroutines. Each goroutine needs its own stack.
* **Stack Growth:** The `newstack` and `copystack` functions clearly implement Go's automatic stack growth mechanism.
* **`defer`:** The comments mentioning `deferproc` hint at how `defer` statements interact with stack management (needing to be adjacent to the caller's frame).
* **Channels:** The mentions of `SudoG` and the synchronization with channel operations in `syncadjustsudogs` indicate the code's awareness of how channel operations might interact with stack manipulation.

**5. Structuring the Answer (Following the Prompt's Requirements):**

* **List Functionalities:**  Start by summarizing the key tasks the code performs, drawing directly from the observations made in steps 2 and 3.
* **Infer Go Language Features with Examples:** Connect the identified functionalities to specific Go language features. For example, the stack allocation/deallocation directly relates to how goroutines get their stacks. Provide simple Go code snippets to illustrate these features.
* **Code Reasoning with Hypotheses:** For functions like `stackalloc` and `stackfree`, walk through the logic, making assumptions about inputs and outputs to demonstrate understanding.
* **Command-Line Arguments (if applicable):**  In this snippet, there aren't obvious command-line argument processing sections. Note this explicitly as requested.
* **Common Mistakes:** Identify potential pitfalls for users, if apparent. For instance, misunderstanding the automatic stack growth and creating excessively deep recursion could lead to stack overflows, though the runtime handles this.
* **Summary of Functionalities (Part 1):** Conclude by briefly reiterating the main roles of the code as requested for the first part of the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about allocating memory for stacks."
* **Correction:**  Realized it's more than just raw allocation. The comments about stack guards, overflow checks, and copying indicate more sophisticated management.
* **Initial thought:** "The `stackpool` is just a simple list of free stacks."
* **Correction:** Recognized the tiered approach with `stackpool` for small stacks and `stackLarge` for larger ones, as well as the caching mechanism (`mcache`).
* **Focus on the "Why":**  Instead of just listing function names, focus on *why* these functions exist and how they contribute to the overall goal of managing goroutine stacks efficiently and safely.

By following these steps, combining top-down analysis with a deeper dive into specific functionalities, and constantly connecting the code to the broader context of the Go runtime, it's possible to arrive at a comprehensive and accurate understanding of the provided code snippet.
```
这是路径为go/src/runtime/stack.go的go语言实现的一部分， 请列举一下它的功能,
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明,
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

这段 `go/src/runtime/stack.go` 代码片段主要负责 **goroutine 栈的分配、管理和释放**。  更具体地说，它实现了以下功能：

1. **定义了栈的布局参数和常量:** 包括栈的最小大小 (`stackMin`)，分配的最小栈大小 (`fixedStack`)，栈保护区域的大小 (`stackGuard`)，以及用于系统特定目的的额外栈空间 (`stackSystem`)。这些常量指导着栈内存的分配和管理策略。
2. **实现了栈溢出检测机制:** 代码中注释详细解释了如何通过比较栈指针 (`SP`) 和栈保护边界 (`g->stackguard`) 来检测栈溢出。根据栈帧大小的不同，采用了不同的检测策略，小的栈帧可以直接比较，大的栈帧会先计算一个偏移量再比较，超大的栈帧则直接调用 `morestack` 函数。
3. **维护了小栈的全局对象池 (`stackpool`):**  为了高效地分配和回收小尺寸的栈，代码维护了一个全局的自由栈片段池。根据栈的大小，将栈片段分为不同的“阶”（order），每个阶都有一个独立的自由列表。
4. **维护了大栈的全局对象池 (`stackLarge`):** 对于较大的栈，代码维护了另一个全局对象池，也按照页的数量进行组织。
5. **提供了栈的分配 (`stackalloc`) 和释放 (`stackfree`) 函数:**
    * `stackalloc` 负责为 goroutine 分配新的栈空间。它会根据请求的大小，优先从 `stackpool` 或 `stackLarge` 中获取，如果池中没有可用空间，则会向堆申请新的内存。
    * `stackfree` 负责释放不再使用的栈空间，将其返回到相应的对象池中。
6. **实现了基于 per-P 的小栈缓存 (`mcache.stackcache`):** 为了进一步提高小栈的分配效率，每个 P (processor) 都有一个自己的小栈缓存。`stackcacherefill` 和 `stackcacherelease` 函数负责在全局对象池和 P 的缓存之间移动栈片段。`stackcache_clear` 用于清理 P 的栈缓存。
7. **实现了栈的拷贝 (`copystack`) 和扩容 (`newstack`) 机制:**
    * 当 goroutine 的栈空间不足时，会调用 `newstack` 函数。
    * `copystack` 函数负责将 goroutine 的旧栈内容拷贝到一块新的、更大的栈空间中，并更新相关的指针信息，从而实现栈的动态扩容。
8. **提供了调整栈指针的函数 (`adjustpointer`, `adjustpointers`, `adjustframe`):** 在栈拷贝过程中，需要调整栈上的指针，使其指向新的栈地址。这些函数负责遍历栈帧，根据编译器的元数据信息，识别并调整栈上的指针。
9. **支持栈相关的调试功能:**  通过 `stackDebug` 常量控制不同级别的栈操作日志输出，方便调试。

**推理出的 Go 语言功能实现:**

这段代码是 **Go 语言 goroutine 的栈管理** 的核心实现。  Go 语言的 goroutine 拥有动态可增长的栈，这是其轻量级并发特性的重要支撑。这段代码就负责了 goroutine 栈的创建、扩容、收缩和销毁。

**Go 代码举例说明:**

```go
package main

import "runtime"
import "sync"

func recursiveFunc(n int) {
	if n <= 0 {
		return
	}
	// 每次递归调用都会增加栈的使用
	recursiveFunc(n - 1)
}

func main() {
	runtime.GOMAXPROCS(1) // 为了简化，设置只使用一个 P
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recursiveFunc(10000) // 可能会触发栈的扩容
		}()
	}
	wg.Wait()
}
```

**假设的输入与输出（针对 `stackalloc` 和 `stackfree`）:**

**`stackalloc` 假设：**

* **输入:** `n = 4096` (请求分配 4096 字节的栈)
* **假设条件:**  此时 `stackpool` 中有大小为 4096 字节的空闲栈片段。
* **输出:** 返回一个 `stack` 结构体，例如 `{lo: 0xc000010000, hi: 0xc000011000}`，表示分配的栈的起始地址和结束地址。

**`stackfree` 假设：**

* **输入:** `stk = {lo: 0xc000010000, hi: 0xc000011000}` (需要释放的栈)
* **假设条件:**  该栈是通过 `stackalloc` 分配的，并且大小为 4096 字节。当前的 GC 状态是 `_GCoff` (GC 未运行)。
* **输出:** 该栈会被添加到 `stackpool` 中对应大小的自由列表中，以便后续的分配可以复用。

**命令行参数的具体处理:**

在这段代码片段中，没有直接处理命令行参数的逻辑。与栈相关的命令行参数（例如 `-stack`，用于设置栈大小限制）的处理通常在 `runtime` 包的其他文件中，例如 `runtime/proc.go` 中完成。

**使用者易犯错的点:**

虽然 Go 语言的栈管理是自动的，用户通常不需要直接干预，但以下情况可能导致与栈相关的错误：

1. **无限递归:**  如果函数无限递归调用自身，会导致栈空间不断增长，最终超出系统限制，抛出 “stack overflow” 错误。虽然 Go 会动态扩容栈，但仍然存在理论上限。

   ```go
   package main

   func infiniteRecursion() {
       infiniteRecursion()
   }

   func main() {
       infiniteRecursion() // 运行一段时间后会 panic: runtime: stack overflow
   }
   ```

2. **创建大量的 goroutine 而不进行控制:**  如果程序创建了大量的 goroutine，每个 goroutine 都有自己的栈，这可能会消耗大量的内存。

   ```go
   package main

   import "time"

   func worker() {
       for {
           // 执行一些任务
           time.Sleep(time.Second)
       }
   }

   func main() {
       for i := 0; i < 100000; i++ { // 创建大量 goroutine
           go worker()
       }
       time.Sleep(time.Hour) // 让程序运行一段时间
   }
   ```
   虽然每个 goroutine 的初始栈很小，但大量的 goroutine 累积起来仍然会占用不少内存。

**总结一下它的功能 (第 1 部分):**

这段 `go/src/runtime/stack.go` 代码片段是 Go 语言运行时系统中负责 **goroutine 栈内存管理** 的核心部分。它定义了栈的结构和分配策略，实现了栈溢出检测、高效的栈分配和回收机制（包括全局对象池和 per-P 缓存），以及动态栈扩容的功能。  它的主要目标是确保 goroutine 能够拥有足够的栈空间来执行代码，同时尽可能地减少内存开销和提高性能。

### 提示词
```
这是路径为go/src/runtime/stack.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/cpu"
	"internal/goarch"
	"internal/goos"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

/*
Stack layout parameters.
Included both by runtime (compiled via 6c) and linkers (compiled via gcc).

The per-goroutine g->stackguard is set to point StackGuard bytes
above the bottom of the stack.  Each function compares its stack
pointer against g->stackguard to check for overflow.  To cut one
instruction from the check sequence for functions with tiny frames,
the stack is allowed to protrude StackSmall bytes below the stack
guard.  Functions with large frames don't bother with the check and
always call morestack.  The sequences are (for amd64, others are
similar):

	guard = g->stackguard
	frame = function's stack frame size
	argsize = size of function arguments (call + return)

	stack frame size <= StackSmall:
		CMPQ guard, SP
		JHI 3(PC)
		MOVQ m->morearg, $(argsize << 32)
		CALL morestack(SB)

	stack frame size > StackSmall but < StackBig
		LEAQ (frame-StackSmall)(SP), R0
		CMPQ guard, R0
		JHI 3(PC)
		MOVQ m->morearg, $(argsize << 32)
		CALL morestack(SB)

	stack frame size >= StackBig:
		MOVQ m->morearg, $((argsize << 32) | frame)
		CALL morestack(SB)

The bottom StackGuard - StackSmall bytes are important: there has
to be enough room to execute functions that refuse to check for
stack overflow, either because they need to be adjacent to the
actual caller's frame (deferproc) or because they handle the imminent
stack overflow (morestack).

For example, deferproc might call malloc, which does one of the
above checks (without allocating a full frame), which might trigger
a call to morestack.  This sequence needs to fit in the bottom
section of the stack.  On amd64, morestack's frame is 40 bytes, and
deferproc's frame is 56 bytes.  That fits well within the
StackGuard - StackSmall bytes at the bottom.
The linkers explore all possible call traces involving non-splitting
functions to make sure that this limit cannot be violated.
*/

const (
	// stackSystem is a number of additional bytes to add
	// to each stack below the usual guard area for OS-specific
	// purposes like signal handling. Used on Windows, Plan 9,
	// and iOS because they do not use a separate stack.
	stackSystem = goos.IsWindows*4096 + goos.IsPlan9*512 + goos.IsIos*goarch.IsArm64*1024

	// The minimum size of stack used by Go code
	stackMin = 2048

	// The minimum stack size to allocate.
	// The hackery here rounds fixedStack0 up to a power of 2.
	fixedStack0 = stackMin + stackSystem
	fixedStack1 = fixedStack0 - 1
	fixedStack2 = fixedStack1 | (fixedStack1 >> 1)
	fixedStack3 = fixedStack2 | (fixedStack2 >> 2)
	fixedStack4 = fixedStack3 | (fixedStack3 >> 4)
	fixedStack5 = fixedStack4 | (fixedStack4 >> 8)
	fixedStack6 = fixedStack5 | (fixedStack5 >> 16)
	fixedStack  = fixedStack6 + 1

	// stackNosplit is the maximum number of bytes that a chain of NOSPLIT
	// functions can use.
	// This arithmetic must match that in cmd/internal/objabi/stack.go:StackNosplit.
	stackNosplit = abi.StackNosplitBase * sys.StackGuardMultiplier

	// The stack guard is a pointer this many bytes above the
	// bottom of the stack.
	//
	// The guard leaves enough room for a stackNosplit chain of NOSPLIT calls
	// plus one stackSmall frame plus stackSystem bytes for the OS.
	// This arithmetic must match that in cmd/internal/objabi/stack.go:StackLimit.
	stackGuard = stackNosplit + stackSystem + abi.StackSmall
)

const (
	// stackDebug == 0: no logging
	//            == 1: logging of per-stack operations
	//            == 2: logging of per-frame operations
	//            == 3: logging of per-word updates
	//            == 4: logging of per-word reads
	stackDebug       = 0
	stackFromSystem  = 0 // allocate stacks from system memory instead of the heap
	stackFaultOnFree = 0 // old stacks are mapped noaccess to detect use after free
	stackNoCache     = 0 // disable per-P small stack caches

	// check the BP links during traceback.
	debugCheckBP = false
)

var (
	stackPoisonCopy = 0 // fill stack that should not be accessed with garbage, to detect bad dereferences during copy
)

const (
	uintptrMask = 1<<(8*goarch.PtrSize) - 1

	// The values below can be stored to g.stackguard0 to force
	// the next stack check to fail.
	// These are all larger than any real SP.

	// Goroutine preemption request.
	// 0xfffffade in hex.
	stackPreempt = uintptrMask & -1314

	// Thread is forking. Causes a split stack check failure.
	// 0xfffffb2e in hex.
	stackFork = uintptrMask & -1234

	// Force a stack movement. Used for debugging.
	// 0xfffffeed in hex.
	stackForceMove = uintptrMask & -275

	// stackPoisonMin is the lowest allowed stack poison value.
	stackPoisonMin = uintptrMask & -4096
)

// Global pool of spans that have free stacks.
// Stacks are assigned an order according to size.
//
//	order = log_2(size/FixedStack)
//
// There is a free list for each order.
var stackpool [_NumStackOrders]struct {
	item stackpoolItem
	_    [(cpu.CacheLinePadSize - unsafe.Sizeof(stackpoolItem{})%cpu.CacheLinePadSize) % cpu.CacheLinePadSize]byte
}

type stackpoolItem struct {
	_    sys.NotInHeap
	mu   mutex
	span mSpanList
}

// Global pool of large stack spans.
var stackLarge struct {
	lock mutex
	free [heapAddrBits - pageShift]mSpanList // free lists by log_2(s.npages)
}

func stackinit() {
	if _StackCacheSize&_PageMask != 0 {
		throw("cache size must be a multiple of page size")
	}
	for i := range stackpool {
		stackpool[i].item.span.init()
		lockInit(&stackpool[i].item.mu, lockRankStackpool)
	}
	for i := range stackLarge.free {
		stackLarge.free[i].init()
		lockInit(&stackLarge.lock, lockRankStackLarge)
	}
}

// stacklog2 returns ⌊log_2(n)⌋.
func stacklog2(n uintptr) int {
	log2 := 0
	for n > 1 {
		n >>= 1
		log2++
	}
	return log2
}

// Allocates a stack from the free pool. Must be called with
// stackpool[order].item.mu held.
func stackpoolalloc(order uint8) gclinkptr {
	list := &stackpool[order].item.span
	s := list.first
	lockWithRankMayAcquire(&mheap_.lock, lockRankMheap)
	if s == nil {
		// no free stacks. Allocate another span worth.
		s = mheap_.allocManual(_StackCacheSize>>_PageShift, spanAllocStack)
		if s == nil {
			throw("out of memory")
		}
		if s.allocCount != 0 {
			throw("bad allocCount")
		}
		if s.manualFreeList.ptr() != nil {
			throw("bad manualFreeList")
		}
		osStackAlloc(s)
		s.elemsize = fixedStack << order
		for i := uintptr(0); i < _StackCacheSize; i += s.elemsize {
			x := gclinkptr(s.base() + i)
			x.ptr().next = s.manualFreeList
			s.manualFreeList = x
		}
		list.insert(s)
	}
	x := s.manualFreeList
	if x.ptr() == nil {
		throw("span has no free stacks")
	}
	s.manualFreeList = x.ptr().next
	s.allocCount++
	if s.manualFreeList.ptr() == nil {
		// all stacks in s are allocated.
		list.remove(s)
	}
	return x
}

// Adds stack x to the free pool. Must be called with stackpool[order].item.mu held.
func stackpoolfree(x gclinkptr, order uint8) {
	s := spanOfUnchecked(uintptr(x))
	if s.state.get() != mSpanManual {
		throw("freeing stack not in a stack span")
	}
	if s.manualFreeList.ptr() == nil {
		// s will now have a free stack
		stackpool[order].item.span.insert(s)
	}
	x.ptr().next = s.manualFreeList
	s.manualFreeList = x
	s.allocCount--
	if gcphase == _GCoff && s.allocCount == 0 {
		// Span is completely free. Return it to the heap
		// immediately if we're sweeping.
		//
		// If GC is active, we delay the free until the end of
		// GC to avoid the following type of situation:
		//
		// 1) GC starts, scans a SudoG but does not yet mark the SudoG.elem pointer
		// 2) The stack that pointer points to is copied
		// 3) The old stack is freed
		// 4) The containing span is marked free
		// 5) GC attempts to mark the SudoG.elem pointer. The
		//    marking fails because the pointer looks like a
		//    pointer into a free span.
		//
		// By not freeing, we prevent step #4 until GC is done.
		stackpool[order].item.span.remove(s)
		s.manualFreeList = 0
		osStackFree(s)
		mheap_.freeManual(s, spanAllocStack)
	}
}

// stackcacherefill/stackcacherelease implement a global pool of stack segments.
// The pool is required to prevent unlimited growth of per-thread caches.
//
//go:systemstack
func stackcacherefill(c *mcache, order uint8) {
	if stackDebug >= 1 {
		print("stackcacherefill order=", order, "\n")
	}

	// Grab some stacks from the global cache.
	// Grab half of the allowed capacity (to prevent thrashing).
	var list gclinkptr
	var size uintptr
	lock(&stackpool[order].item.mu)
	for size < _StackCacheSize/2 {
		x := stackpoolalloc(order)
		x.ptr().next = list
		list = x
		size += fixedStack << order
	}
	unlock(&stackpool[order].item.mu)
	c.stackcache[order].list = list
	c.stackcache[order].size = size
}

//go:systemstack
func stackcacherelease(c *mcache, order uint8) {
	if stackDebug >= 1 {
		print("stackcacherelease order=", order, "\n")
	}
	x := c.stackcache[order].list
	size := c.stackcache[order].size
	lock(&stackpool[order].item.mu)
	for size > _StackCacheSize/2 {
		y := x.ptr().next
		stackpoolfree(x, order)
		x = y
		size -= fixedStack << order
	}
	unlock(&stackpool[order].item.mu)
	c.stackcache[order].list = x
	c.stackcache[order].size = size
}

//go:systemstack
func stackcache_clear(c *mcache) {
	if stackDebug >= 1 {
		print("stackcache clear\n")
	}
	for order := uint8(0); order < _NumStackOrders; order++ {
		lock(&stackpool[order].item.mu)
		x := c.stackcache[order].list
		for x.ptr() != nil {
			y := x.ptr().next
			stackpoolfree(x, order)
			x = y
		}
		c.stackcache[order].list = 0
		c.stackcache[order].size = 0
		unlock(&stackpool[order].item.mu)
	}
}

// stackalloc allocates an n byte stack.
//
// stackalloc must run on the system stack because it uses per-P
// resources and must not split the stack.
//
//go:systemstack
func stackalloc(n uint32) stack {
	// Stackalloc must be called on scheduler stack, so that we
	// never try to grow the stack during the code that stackalloc runs.
	// Doing so would cause a deadlock (issue 1547).
	thisg := getg()
	if thisg != thisg.m.g0 {
		throw("stackalloc not on scheduler stack")
	}
	if n&(n-1) != 0 {
		throw("stack size not a power of 2")
	}
	if stackDebug >= 1 {
		print("stackalloc ", n, "\n")
	}

	if debug.efence != 0 || stackFromSystem != 0 {
		n = uint32(alignUp(uintptr(n), physPageSize))
		v := sysAlloc(uintptr(n), &memstats.stacks_sys)
		if v == nil {
			throw("out of memory (stackalloc)")
		}
		return stack{uintptr(v), uintptr(v) + uintptr(n)}
	}

	// Small stacks are allocated with a fixed-size free-list allocator.
	// If we need a stack of a bigger size, we fall back on allocating
	// a dedicated span.
	var v unsafe.Pointer
	if n < fixedStack<<_NumStackOrders && n < _StackCacheSize {
		order := uint8(0)
		n2 := n
		for n2 > fixedStack {
			order++
			n2 >>= 1
		}
		var x gclinkptr
		if stackNoCache != 0 || thisg.m.p == 0 || thisg.m.preemptoff != "" {
			// thisg.m.p == 0 can happen in the guts of exitsyscall
			// or procresize. Just get a stack from the global pool.
			// Also don't touch stackcache during gc
			// as it's flushed concurrently.
			lock(&stackpool[order].item.mu)
			x = stackpoolalloc(order)
			unlock(&stackpool[order].item.mu)
		} else {
			c := thisg.m.p.ptr().mcache
			x = c.stackcache[order].list
			if x.ptr() == nil {
				stackcacherefill(c, order)
				x = c.stackcache[order].list
			}
			c.stackcache[order].list = x.ptr().next
			c.stackcache[order].size -= uintptr(n)
		}
		v = unsafe.Pointer(x)
	} else {
		var s *mspan
		npage := uintptr(n) >> _PageShift
		log2npage := stacklog2(npage)

		// Try to get a stack from the large stack cache.
		lock(&stackLarge.lock)
		if !stackLarge.free[log2npage].isEmpty() {
			s = stackLarge.free[log2npage].first
			stackLarge.free[log2npage].remove(s)
		}
		unlock(&stackLarge.lock)

		lockWithRankMayAcquire(&mheap_.lock, lockRankMheap)

		if s == nil {
			// Allocate a new stack from the heap.
			s = mheap_.allocManual(npage, spanAllocStack)
			if s == nil {
				throw("out of memory")
			}
			osStackAlloc(s)
			s.elemsize = uintptr(n)
		}
		v = unsafe.Pointer(s.base())
	}

	if traceAllocFreeEnabled() {
		trace := traceAcquire()
		if trace.ok() {
			trace.GoroutineStackAlloc(uintptr(v), uintptr(n))
			traceRelease(trace)
		}
	}
	if raceenabled {
		racemalloc(v, uintptr(n))
	}
	if msanenabled {
		msanmalloc(v, uintptr(n))
	}
	if asanenabled {
		asanunpoison(v, uintptr(n))
	}
	if stackDebug >= 1 {
		print("  allocated ", v, "\n")
	}
	return stack{uintptr(v), uintptr(v) + uintptr(n)}
}

// stackfree frees an n byte stack allocation at stk.
//
// stackfree must run on the system stack because it uses per-P
// resources and must not split the stack.
//
//go:systemstack
func stackfree(stk stack) {
	gp := getg()
	v := unsafe.Pointer(stk.lo)
	n := stk.hi - stk.lo
	if n&(n-1) != 0 {
		throw("stack not a power of 2")
	}
	if stk.lo+n < stk.hi {
		throw("bad stack size")
	}
	if stackDebug >= 1 {
		println("stackfree", v, n)
		memclrNoHeapPointers(v, n) // for testing, clobber stack data
	}
	if debug.efence != 0 || stackFromSystem != 0 {
		if debug.efence != 0 || stackFaultOnFree != 0 {
			sysFault(v, n)
		} else {
			sysFree(v, n, &memstats.stacks_sys)
		}
		return
	}
	if traceAllocFreeEnabled() {
		trace := traceAcquire()
		if trace.ok() {
			trace.GoroutineStackFree(uintptr(v))
			traceRelease(trace)
		}
	}
	if msanenabled {
		msanfree(v, n)
	}
	if asanenabled {
		asanpoison(v, n)
	}
	if n < fixedStack<<_NumStackOrders && n < _StackCacheSize {
		order := uint8(0)
		n2 := n
		for n2 > fixedStack {
			order++
			n2 >>= 1
		}
		x := gclinkptr(v)
		if stackNoCache != 0 || gp.m.p == 0 || gp.m.preemptoff != "" {
			lock(&stackpool[order].item.mu)
			stackpoolfree(x, order)
			unlock(&stackpool[order].item.mu)
		} else {
			c := gp.m.p.ptr().mcache
			if c.stackcache[order].size >= _StackCacheSize {
				stackcacherelease(c, order)
			}
			x.ptr().next = c.stackcache[order].list
			c.stackcache[order].list = x
			c.stackcache[order].size += n
		}
	} else {
		s := spanOfUnchecked(uintptr(v))
		if s.state.get() != mSpanManual {
			println(hex(s.base()), v)
			throw("bad span state")
		}
		if gcphase == _GCoff {
			// Free the stack immediately if we're
			// sweeping.
			osStackFree(s)
			mheap_.freeManual(s, spanAllocStack)
		} else {
			// If the GC is running, we can't return a
			// stack span to the heap because it could be
			// reused as a heap span, and this state
			// change would race with GC. Add it to the
			// large stack cache instead.
			log2npage := stacklog2(s.npages)
			lock(&stackLarge.lock)
			stackLarge.free[log2npage].insert(s)
			unlock(&stackLarge.lock)
		}
	}
}

var maxstacksize uintptr = 1 << 20 // enough until runtime.main sets it for real

var maxstackceiling = maxstacksize

var ptrnames = []string{
	0: "scalar",
	1: "ptr",
}

// Stack frame layout
//
// (x86)
// +------------------+
// | args from caller |
// +------------------+ <- frame->argp
// |  return address  |
// +------------------+
// |  caller's BP (*) | (*) if framepointer_enabled && varp > sp
// +------------------+ <- frame->varp
// |     locals       |
// +------------------+
// |  args to callee  |
// +------------------+ <- frame->sp
//
// (arm)
// +------------------+
// | args from caller |
// +------------------+ <- frame->argp
// | caller's retaddr |
// +------------------+
// |  caller's FP (*) | (*) on ARM64, if framepointer_enabled && varp > sp
// +------------------+ <- frame->varp
// |     locals       |
// +------------------+
// |  args to callee  |
// +------------------+
// |  return address  |
// +------------------+ <- frame->sp
//
// varp > sp means that the function has a frame;
// varp == sp means frameless function.

type adjustinfo struct {
	old   stack
	delta uintptr // ptr distance from old to new stack (newbase - oldbase)

	// sghi is the highest sudog.elem on the stack.
	sghi uintptr
}

// adjustpointer checks whether *vpp is in the old stack described by adjinfo.
// If so, it rewrites *vpp to point into the new stack.
func adjustpointer(adjinfo *adjustinfo, vpp unsafe.Pointer) {
	pp := (*uintptr)(vpp)
	p := *pp
	if stackDebug >= 4 {
		print("        ", pp, ":", hex(p), "\n")
	}
	if adjinfo.old.lo <= p && p < adjinfo.old.hi {
		*pp = p + adjinfo.delta
		if stackDebug >= 3 {
			print("        adjust ptr ", pp, ":", hex(p), " -> ", hex(*pp), "\n")
		}
	}
}

// Information from the compiler about the layout of stack frames.
// Note: this type must agree with reflect.bitVector.
type bitvector struct {
	n        int32 // # of bits
	bytedata *uint8
}

// ptrbit returns the i'th bit in bv.
// ptrbit is less efficient than iterating directly over bitvector bits,
// and should only be used in non-performance-critical code.
// See adjustpointers for an example of a high-efficiency walk of a bitvector.
func (bv *bitvector) ptrbit(i uintptr) uint8 {
	b := *(addb(bv.bytedata, i/8))
	return (b >> (i % 8)) & 1
}

// bv describes the memory starting at address scanp.
// Adjust any pointers contained therein.
func adjustpointers(scanp unsafe.Pointer, bv *bitvector, adjinfo *adjustinfo, f funcInfo) {
	minp := adjinfo.old.lo
	maxp := adjinfo.old.hi
	delta := adjinfo.delta
	num := uintptr(bv.n)
	// If this frame might contain channel receive slots, use CAS
	// to adjust pointers. If the slot hasn't been received into
	// yet, it may contain stack pointers and a concurrent send
	// could race with adjusting those pointers. (The sent value
	// itself can never contain stack pointers.)
	useCAS := uintptr(scanp) < adjinfo.sghi
	for i := uintptr(0); i < num; i += 8 {
		if stackDebug >= 4 {
			for j := uintptr(0); j < 8; j++ {
				print("        ", add(scanp, (i+j)*goarch.PtrSize), ":", ptrnames[bv.ptrbit(i+j)], ":", hex(*(*uintptr)(add(scanp, (i+j)*goarch.PtrSize))), " # ", i, " ", *addb(bv.bytedata, i/8), "\n")
			}
		}
		b := *(addb(bv.bytedata, i/8))
		for b != 0 {
			j := uintptr(sys.TrailingZeros8(b))
			b &= b - 1
			pp := (*uintptr)(add(scanp, (i+j)*goarch.PtrSize))
		retry:
			p := *pp
			if f.valid() && 0 < p && p < minLegalPointer && debug.invalidptr != 0 {
				// Looks like a junk value in a pointer slot.
				// Live analysis wrong?
				getg().m.traceback = 2
				print("runtime: bad pointer in frame ", funcname(f), " at ", pp, ": ", hex(p), "\n")
				throw("invalid pointer found on stack")
			}
			if minp <= p && p < maxp {
				if stackDebug >= 3 {
					print("adjust ptr ", hex(p), " ", funcname(f), "\n")
				}
				if useCAS {
					ppu := (*unsafe.Pointer)(unsafe.Pointer(pp))
					if !atomic.Casp1(ppu, unsafe.Pointer(p), unsafe.Pointer(p+delta)) {
						goto retry
					}
				} else {
					*pp = p + delta
				}
			}
		}
	}
}

// Note: the argument/return area is adjusted by the callee.
func adjustframe(frame *stkframe, adjinfo *adjustinfo) {
	if frame.continpc == 0 {
		// Frame is dead.
		return
	}
	f := frame.fn
	if stackDebug >= 2 {
		print("    adjusting ", funcname(f), " frame=[", hex(frame.sp), ",", hex(frame.fp), "] pc=", hex(frame.pc), " continpc=", hex(frame.continpc), "\n")
	}

	// Adjust saved frame pointer if there is one.
	if (goarch.ArchFamily == goarch.AMD64 || goarch.ArchFamily == goarch.ARM64) && frame.argp-frame.varp == 2*goarch.PtrSize {
		if stackDebug >= 3 {
			print("      saved bp\n")
		}
		if debugCheckBP {
			// Frame pointers should always point to the next higher frame on
			// the Go stack (or be nil, for the top frame on the stack).
			bp := *(*uintptr)(unsafe.Pointer(frame.varp))
			if bp != 0 && (bp < adjinfo.old.lo || bp >= adjinfo.old.hi) {
				println("runtime: found invalid frame pointer")
				print("bp=", hex(bp), " min=", hex(adjinfo.old.lo), " max=", hex(adjinfo.old.hi), "\n")
				throw("bad frame pointer")
			}
		}
		// On AMD64, this is the caller's frame pointer saved in the current
		// frame.
		// On ARM64, this is the frame pointer of the caller's caller saved
		// by the caller in its frame (one word below its SP).
		adjustpointer(adjinfo, unsafe.Pointer(frame.varp))
	}

	locals, args, objs := frame.getStackMap(true)

	// Adjust local variables if stack frame has been allocated.
	if locals.n > 0 {
		size := uintptr(locals.n) * goarch.PtrSize
		adjustpointers(unsafe.Pointer(frame.varp-size), &locals, adjinfo, f)
	}

	// Adjust arguments.
	if args.n > 0 {
		if stackDebug >= 3 {
			print("      args\n")
		}
		adjustpointers(unsafe.Pointer(frame.argp), &args, adjinfo, funcInfo{})
	}

	// Adjust pointers in all stack objects (whether they are live or not).
	// See comments in mgcmark.go:scanframeworker.
	if frame.varp != 0 {
		for i := range objs {
			obj := &objs[i]
			off := obj.off
			base := frame.varp // locals base pointer
			if off >= 0 {
				base = frame.argp // arguments and return values base pointer
			}
			p := base + uintptr(off)
			if p < frame.sp {
				// Object hasn't been allocated in the frame yet.
				// (Happens when the stack bounds check fails and
				// we call into morestack.)
				continue
			}
			ptrBytes, gcData := obj.gcdata()
			for i := uintptr(0); i < ptrBytes; i += goarch.PtrSize {
				if *addb(gcData, i/(8*goarch.PtrSize))>>(i/goarch.PtrSize&7)&1 != 0 {
					adjustpointer(adjinfo, unsafe.Pointer(p+i))
				}
			}
		}
	}
}

func adjustctxt(gp *g, adjinfo *adjustinfo) {
	adjustpointer(adjinfo, unsafe.Pointer(&gp.sched.ctxt))
	if !framepointer_enabled {
		return
	}
	if debugCheckBP {
		bp := gp.sched.bp
		if bp != 0 && (bp < adjinfo.old.lo || bp >= adjinfo.old.hi) {
			println("runtime: found invalid top frame pointer")
			print("bp=", hex(bp), " min=", hex(adjinfo.old.lo), " max=", hex(adjinfo.old.hi), "\n")
			throw("bad top frame pointer")
		}
	}
	oldfp := gp.sched.bp
	adjustpointer(adjinfo, unsafe.Pointer(&gp.sched.bp))
	if GOARCH == "arm64" {
		// On ARM64, the frame pointer is saved one word *below* the SP,
		// which is not copied or adjusted in any frame. Do it explicitly
		// here.
		if oldfp == gp.sched.sp-goarch.PtrSize {
			memmove(unsafe.Pointer(gp.sched.bp), unsafe.Pointer(oldfp), goarch.PtrSize)
			adjustpointer(adjinfo, unsafe.Pointer(gp.sched.bp))
		}
	}
}

func adjustdefers(gp *g, adjinfo *adjustinfo) {
	// Adjust pointers in the Defer structs.
	// We need to do this first because we need to adjust the
	// defer.link fields so we always work on the new stack.
	adjustpointer(adjinfo, unsafe.Pointer(&gp._defer))
	for d := gp._defer; d != nil; d = d.link {
		adjustpointer(adjinfo, unsafe.Pointer(&d.fn))
		adjustpointer(adjinfo, unsafe.Pointer(&d.sp))
		adjustpointer(adjinfo, unsafe.Pointer(&d.link))
	}
}

func adjustpanics(gp *g, adjinfo *adjustinfo) {
	// Panics are on stack and already adjusted.
	// Update pointer to head of list in G.
	adjustpointer(adjinfo, unsafe.Pointer(&gp._panic))
}

func adjustsudogs(gp *g, adjinfo *adjustinfo) {
	// the data elements pointed to by a SudoG structure
	// might be in the stack.
	for s := gp.waiting; s != nil; s = s.waitlink {
		adjustpointer(adjinfo, unsafe.Pointer(&s.elem))
	}
}

func fillstack(stk stack, b byte) {
	for p := stk.lo; p < stk.hi; p++ {
		*(*byte)(unsafe.Pointer(p)) = b
	}
}

func findsghi(gp *g, stk stack) uintptr {
	var sghi uintptr
	for sg := gp.waiting; sg != nil; sg = sg.waitlink {
		p := uintptr(sg.elem) + uintptr(sg.c.elemsize)
		if stk.lo <= p && p < stk.hi && p > sghi {
			sghi = p
		}
	}
	return sghi
}

// syncadjustsudogs adjusts gp's sudogs and copies the part of gp's
// stack they refer to while synchronizing with concurrent channel
// operations. It returns the number of bytes of stack copied.
func syncadjustsudogs(gp *g, used uintptr, adjinfo *adjustinfo) uintptr {
	if gp.waiting == nil {
		return 0
	}

	// Lock channels to prevent concurrent send/receive.
	var lastc *hchan
	for sg := gp.waiting; sg != nil; sg = sg.waitlink {
		if sg.c != lastc {
			// There is a ranking cycle here between gscan bit and
			// hchan locks. Normally, we only allow acquiring hchan
			// locks and then getting a gscan bit. In this case, we
			// already have the gscan bit. We allow acquiring hchan
			// locks here as a special case, since a deadlock can't
			// happen because the G involved must already be
			// suspended. So, we get a special hchan lock rank here
			// that is lower than gscan, but doesn't allow acquiring
			// any other locks other than hchan.
			lockWithRank(&sg.c.lock, lockRankHchanLeaf)
		}
		lastc = sg.c
	}

	// Adjust sudogs.
	adjustsudogs(gp, adjinfo)

	// Copy the part of the stack the sudogs point in to
	// while holding the lock to prevent races on
	// send/receive slots.
	var sgsize uintptr
	if adjinfo.sghi != 0 {
		oldBot := adjinfo.old.hi - used
		newBot := oldBot + adjinfo.delta
		sgsize = adjinfo.sghi - oldBot
		memmove(unsafe.Pointer(newBot), unsafe.Pointer(oldBot), sgsize)
	}

	// Unlock channels.
	lastc = nil
	for sg := gp.waiting; sg != nil; sg = sg.waitlink {
		if sg.c != lastc {
			unlock(&sg.c.lock)
		}
		lastc = sg.c
	}

	return sgsize
}

// Copies gp's stack to a new stack of a different size.
// Caller must have changed gp status to Gcopystack.
func copystack(gp *g, newsize uintptr) {
	if gp.syscallsp != 0 {
		throw("stack growth not allowed in system call")
	}
	old := gp.stack
	if old.lo == 0 {
		throw("nil stackbase")
	}
	used := old.hi - gp.sched.sp
	// Add just the difference to gcController.addScannableStack.
	// g0 stacks never move, so this will never account for them.
	// It's also fine if we have no P, addScannableStack can deal with
	// that case.
	gcController.addScannableStack(getg().m.p.ptr(), int64(newsize)-int64(old.hi-old.lo))

	// allocate new stack
	new := stackalloc(uint32(newsize))
	if stackPoisonCopy != 0 {
		fillstack(new, 0xfd)
	}
	if stackDebug >= 1 {
		print("copystack gp=", gp, " [", hex(old.lo), " ", hex(old.hi-used), " ", hex(old.hi), "]", " -> [", hex(new.lo), " ", hex(new.hi-used), " ", hex(new.hi), "]/", newsize, "\n")
	}

	// Compute adjustment.
	var adjinfo adjustinfo
	adjinfo.old = old
	adjinfo.delta = new.hi - old.hi

	// Adjust sudogs, synchronizing with channel ops if necessary.
	ncopy := used
	if !gp.activeStackChans {
		if newsize < old.hi-old.lo && gp.parkingOnChan.Load() {
			// It's not safe for someone to shrink this stack while we're actively
			// parking on a channel, but it is safe to grow since we do that
			// ourselves and explicitly don't want to synchronize with channels
			// since we could self-deadlock.
			throw("racy sudog adjustment due to parking on channel")
		}
		adjustsudogs(gp, &adjinfo)
	} else {
		// sudogs may be pointing in to the stack and gp has
		// released channel locks, so other goroutines could
		// be writing to gp's stack. Find the highest such
		// pointer so we can handle everything there and below
		// carefully. (This shouldn't be far from the bottom
		// of the stack, so there's little cost in handling
		// everything below it carefully.)
		adjinfo.sghi = findsghi(gp, old)

		// Synchronize with channel ops and copy the part of
		// the stack they may interact with.
		ncopy -= syncadjustsudogs(gp, used, &adjinfo)
	}

	// Copy the stack (or the rest of it) to the new location
	memmove(unsafe.Pointer(new.hi-ncopy), unsafe.Pointer(old.hi-ncopy), ncopy)

	// Adjust remaining structures that have pointers into stacks.
	// We have to do most of these before we traceback the new
	// stack because gentraceback uses them.
	adjustctxt(gp, &adjinfo)
	adjustdefers(gp, &adjinfo)
	adjustpanics(gp, &adjinfo)
	if adjinfo.sghi != 0 {
		adjinfo.sghi += adjinfo.delta
	}

	// Swap out old stack for new one
	gp.stack = new
	gp.stackguard0 = new.lo + stackGuard // NOTE: might clobber a preempt request
	gp.sched.sp = new.hi - used
	gp.stktopsp += adjinfo.delta

	// Adjust pointers in the new stack.
	var u unwinder
	for u.init(gp, 0); u.valid(); u.next() {
		adjustframe(&u.frame, &adjinfo)
	}

	// free old stack
	if stackPoisonCopy != 0 {
		fillstack(old, 0xfc)
	}
	stackfree(old)
}

// round x up to a power of 2.
func round2(x int32) int32 {
	s := uint(0)
	for 1<<s < x {
		s++
	}
	return 1 << s
}

// Called from runtime·morestack when more stack is needed.
// Allocate larger stack and relocate to new stack.
// Stack growth is multiplicative, for constant amortized cost.
//
// g->atomicstatus will be Grunning or Gscanrunning upon entry.
// If the scheduler is trying to stop this g, then it will set preemptStop.
//
// This must be nowritebarrierrec because it can be called as part of
// stack growth from other nowritebarrierrec functions, but the
// compiler doesn't check this.
//
//go:nowritebarrierrec
func newstack() {
	thisg := getg()
	// TODO: double check all gp. shouldn't be getg().
	if thisg.m.morebuf.g.ptr().stackguard0 == stackFork {
		throw("stack growth after fork")
	}
	if thisg.m.morebuf.g.ptr() != thisg.m.curg {
		print("runtime: newstack called from g=", hex(thisg.m.morebuf.g), "\n"+"\tm=", thisg.m, " m->curg=", thisg.m.curg, " m->g0=", thisg.m.g0, " m->gsignal=", thisg.m.gsignal, "\n")
		morebuf := thisg.m.morebuf
		traceback(morebuf.pc, morebuf.sp, morebuf.lr, morebuf.g.ptr())
		throw("runtime: wrong goroutine in newstack")
	}

	gp := thisg.m.curg

	if thisg.m.curg.throwsplit {
		// Update syscallsp, syscallpc in case traceback uses them.
		morebuf := thisg.m.morebuf
		gp.syscallsp = morebuf.sp
		gp.syscallpc = morebuf.pc
		pcname, pcoff := "(unknown)", uintptr(0)
		f := findfunc(gp.sched.pc)
		if f.valid() {
			pcname = funcname(f)
			pcoff = gp.sched.pc - f.entry()
		}
		print("runtime: newstack at ", pcname, "+", hex(pcoff),
			" sp=", hex(gp.sched.sp), " stack=[", hex(gp.stack.lo), ", ", hex(gp.stack.hi), "]\n",
			"\tmorebuf={pc:", hex(morebuf.pc), " sp:", hex(morebuf.sp), " lr:", hex(morebuf.lr), "}\n",
			"\tsched={pc:", hex(gp.sched.pc), " sp:", hex(gp.sched.sp), " lr:", hex(gp.sched.lr), " ctxt:", gp.sched.ctxt, "}\n")

		thisg.m.traceback = 2 // Include runtime frames
		traceback(morebuf.pc, morebuf.sp, morebuf.lr, gp)
		throw("runtime: stack split at bad time")
	}

	morebuf := thisg.m.morebuf
	thisg.m.morebuf.pc = 0
	thisg.m.morebuf.lr = 0
	thisg.m.morebuf.sp = 0
	thisg.m.morebuf.g = 0

	// NOTE: stackguard0 may change underfoot, if another thread
	// is about to try to preempt gp. Read it just once and use that same
	// value now and below.
	stackguard0 := atomic.Loaduintptr(&gp.stackguard0)

	// Be conservative about where we preempt.
	// We are interested in preempting user Go code, not runtime code.
	// If we're holding locks, mallocing, or preemption is disabled, don't
	// preempt.
	// This check is very early in newstack so that even the status change
	// from Grunning to Gwaiting and back doesn't happen in this case.
	// That status change by itself can be viewed as a small preemption,
	// because the GC might change Gwaiting to Gscanwaiting, and then
	// this goroutine has to wait for the GC to finish before continuing.
	// If the GC is in some way dependent on this goroutine (for example,
	// it needs a lock held by the goroutine), that small preemption turns
	// into a real deadlock.
	preempt := stackguard0 == stackPreempt
	if preempt {
		if !canPreemptM(thisg.m) {
			// Let the goroutine keep running for now.
			// gp->preempt is set, so it will be preempted next time.
			gp.stackguard0 = gp.stack.lo + stackGuard
			gogo(&gp.sched) // never return
		}
	}

	if gp.stack.lo == 0 {
		throw("missing stack in newstack")
	}
	sp := gp.sched.sp
	if goarch.ArchFamily == goarch.AMD64 || goarch.ArchFamily == goarch.I386 || goarch.ArchFamily == goarch.WASM {
		// The call to morestack cost a word.
		sp -= goarch.PtrSize
	}
	if stackDebug >= 1 || sp < gp.stack.lo {
		print("runtime: newstack sp=", hex(sp), " stack=[", hex(gp.stack.lo), ", ", hex(gp.stack.hi), "]\n",
			"\tmorebuf={pc:", hex(morebuf.pc), " sp:", hex(morebuf.sp), " lr:", hex(morebuf.lr), "}\n",
			"\tsched={pc:", hex(gp.sched.pc), " sp:", hex(gp.sched.sp), " lr:", hex(gp.sched.lr), " ctxt:", gp.sched.ctxt, "}\n")
	}
	if sp < gp.stack.lo {
		print("runtime: gp=", gp, ", goid=", gp.goid, ", gp->status=", hex(readgstatus(gp)), "\n ")
		print("runtime: split stack overflow: ", hex(sp), " < ", hex(gp.stack.lo), "\n")
		throw("runtime: split stack overflow")
	}

	if preempt {
		if gp == thisg.m.g0 {
			throw("runtime: preempt g0")
		}
		if thisg.m.p == 0 && thisg.m.locks == 0 {
			throw("runtime: g is running but p is not")
		}

		if gp.preemptShrink {
			// We're at a synchronous safe point now, so
			// do the pending stack shrink.
			gp.preemptShrink = false
			shrinkstack(gp)
		}

		if gp.preemptStop {
			preemptPark(gp) // never returns
		}

		// Act like goroutine called runtime.Gosched.
		gopreempt_m(gp) // never return
	}

	// Allocate a bigger segment and move the stack.
	o
```