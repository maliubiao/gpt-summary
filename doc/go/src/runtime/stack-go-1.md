Response:
The user wants a summary of the Go runtime code snippet provided, focusing on its functionality within the larger context of Go's stack management. I need to identify the core operations performed by these functions and explain their roles.

Here's a breakdown of the functions and their purposes:

- **`newstack`**:  This function handles the growth of a goroutine's stack when it overflows.
- **`nilfunc`**: A placeholder function that causes a nil pointer dereference, used in `gostartcallfn`.
- **`gostartcallfn`**:  Sets up a `gobuf` structure to simulate a function call, primarily used for starting new goroutines.
- **`isShrinkStackSafe`**: Determines if it's safe to shrink a goroutine's stack based on various conditions like syscalls or GC activity.
- **`shrinkstack`**:  Reduces the size of a goroutine's stack when it's underutilized.
- **`freeStackSpans`**:  Releases unused stack memory back to the system during garbage collection.
- **`stackObjectRecord.gcdata`**:  Provides information about objects on the stack for garbage collection purposes.
- **`morestackc`**: A placeholder function that throws an error if the system stack code is executed on the user stack.
- **`gcComputeStartingStackSize`**:  Calculates the optimal initial stack size for new goroutines based on recent stack usage.

Therefore, the main functionalities revolve around dynamic stack management (growing and shrinking), setting up goroutine execution, and providing information needed for garbage collection.
这段代码是 Go 运行时（runtime）中 `stack.go` 文件的一部分，它主要负责 **goroutine 栈的动态管理**。具体来说，它实现了 goroutine 栈的自动增长和收缩机制，以及与垃圾回收器交互以管理栈内存的功能。

以下是代码片段中各个函数的主要功能归纳：

1. **`newstack(gp *g)`**:
   - **功能：**  当 goroutine 的栈空间不足以容纳新的函数调用时，此函数会被调用来分配更大的栈空间。
   - **详细过程：**
     - 计算新的栈大小，通常是当前栈大小的两倍。
     - 考虑当前函数可能需要的额外栈空间 (`funcMaxSPDelta`)。
     - 检查是否超过最大栈大小限制 (`maxstacksize` 或 `maxstackceiling`)。
     - 将 goroutine 的状态设置为 `_Gcopystack`，防止并发的垃圾回收扫描栈。
     - 调用 `copystack` 函数将旧栈的内容复制到新的更大的栈中。
     - 将 goroutine 的状态恢复为 `_Grunning`。
     - 通过 `gogo` 函数恢复 goroutine 的执行。

2. **`nilfunc()`**:
   - **功能：**  一个简单的空函数，其作用是故意引发一个 nil 指针解引用的错误。
   - **用途：**  在 `gostartcallfn` 中作为一种默认或回退的函数指针使用。

3. **`gostartcallfn(gobuf *gobuf, fv *funcval)`**:
   - **功能：**  调整 `gobuf` 结构体，使其看起来像是执行了一个对函数 `fn` 的调用，并在 `fn` 的第一条指令前停止。
   - **用途：**  主要用于启动新的 goroutine，模拟函数调用的上下文。它接收一个 `gobuf` 结构体（用于保存 goroutine 的执行状态）和一个 `funcval` 结构体（包含函数指针和接收者）。如果 `fv` 为 `nil`，则使用 `nilfunc` 的地址作为函数指针。
   - **关联概念：**  `gobuf` 结构体是 goroutine 的上下文信息，包括程序计数器 (PC) 和栈指针 (SP)。

4. **`isShrinkStackSafe(gp *g) bool`**:
   - **功能：**  检查收缩 goroutine 的栈是否安全。
   - **判断条件：**  在以下情况下收缩栈是不安全的：
     - goroutine 正在执行系统调用 (`gp.syscallsp != 0`)。
     - goroutine 处于异步安全点 (`gp.asyncSafePoint`)。
     - goroutine 正在等待 channel (`gp.parkingOnChan.Load()`).
     - 跟踪（tracing）已启用，并且 goroutine 处于等待 GC 的状态。

5. **`shrinkstack(gp *g)`**:
   - **功能：**  尝试收缩 goroutine 的栈。
   - **前提条件：**  goroutine 必须处于停止状态，并且当前拥有其栈的所有权。
   - **执行过程：**
     - 检查收缩栈的安全性 (`isShrinkStackSafe`)。
     - 计算新的栈大小，通常是当前栈大小的一半。
     - 确保新的栈大小不小于最小栈大小 (`fixedStack`)。
     - 只有当 goroutine 使用的栈空间少于当前栈空间的四分之一时才进行收缩。
     - 调用 `copystack` 函数将栈内容复制到新的更小的栈中。
   - **排除情况：**  某些情况下禁止收缩栈，例如：
     - 启用了 `debug.gcshrinkstackoff`。
     - 当前 goroutine 正在执行垃圾回收的后台标记 worker (`gcBgMarkWorker`)。

6. **`freeStackSpans()`**:
   - **功能：**  在垃圾回收结束后，释放不再使用的栈内存块。
   - **过程：**
     - 遍历不同大小的栈内存池 (`stackpool`)，释放 `allocCount` 为 0 的空闲栈段。
     - 遍历大栈内存池 (`stackLarge`)，释放其中的空闲栈段。
     - 使用 `osStackFree` 将内存归还给操作系统。

7. **`stackObjectRecord` 结构体和 `gcdata()` 方法**:
   - **功能：**  `stackObjectRecord` 结构体用于描述栈帧中的一个对象，记录其在栈帧中的偏移量、大小以及指向 GC 元数据的偏移量。
   - **`gcdata()` 方法：** 返回对象中包含指针的字节数以及指向这些指针的位掩码，供垃圾回收器使用。

8. **`morestackc()`**:
   - **功能：**  一个占位函数，如果尝试在用户栈上执行系统栈代码，则会抛出 panic。
   - **用途：**  用于防止错误地在不正确的栈上执行代码。

9. **`startingStackSize` 变量和 `gcComputeStartingStackSize()` 函数**:
   - **`startingStackSize`：**  指定新创建的 goroutine 的初始栈大小。
   - **`gcComputeStartingStackSize()`：**  在每次垃圾回收时计算一个更合适的初始栈大小，基于之前扫描过的栈的平均大小。这是一种优化策略，旨在避免过早或过度的栈增长。

**总结归纳代码片段的功能：**

这段代码片段的核心功能是 **实现 goroutine 栈的动态管理，以提高内存利用率和程序性能。** 它包括：

- **栈增长（`newstack`）：**  在栈溢出时自动扩展栈空间。
- **栈收缩（`shrinkstack`）：**  在栈空间利用率较低时自动回收多余的栈空间。
- **栈内存管理（`freeStackSpans`）：**  在垃圾回收期间释放不再使用的栈内存。
- **goroutine 启动上下文设置（`gostartcallfn`）：**  为新 goroutine 的执行做好准备。
- **垃圾回收支持（`stackObjectRecord` 和 `gcdata`）：**  提供栈上对象的信息，帮助垃圾回收器追踪指针。
- **初始栈大小优化（`gcComputeStartingStackSize`）：**  动态调整新 goroutine 的初始栈大小，以减少内存浪费。

这段代码是 Go 运行时系统中非常核心和底层的部分，它保证了 goroutine 能够根据需要动态地调整其栈大小，既避免了栈溢出的风险，又尽可能地减少了内存占用。

Prompt: 
```
这是路径为go/src/runtime/stack.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
ldsize := gp.stack.hi - gp.stack.lo
	newsize := oldsize * 2

	// Make sure we grow at least as much as needed to fit the new frame.
	// (This is just an optimization - the caller of morestack will
	// recheck the bounds on return.)
	if f := findfunc(gp.sched.pc); f.valid() {
		max := uintptr(funcMaxSPDelta(f))
		needed := max + stackGuard
		used := gp.stack.hi - gp.sched.sp
		for newsize-used < needed {
			newsize *= 2
		}
	}

	if stackguard0 == stackForceMove {
		// Forced stack movement used for debugging.
		// Don't double the stack (or we may quickly run out
		// if this is done repeatedly).
		newsize = oldsize
	}

	if newsize > maxstacksize || newsize > maxstackceiling {
		if maxstacksize < maxstackceiling {
			print("runtime: goroutine stack exceeds ", maxstacksize, "-byte limit\n")
		} else {
			print("runtime: goroutine stack exceeds ", maxstackceiling, "-byte limit\n")
		}
		print("runtime: sp=", hex(sp), " stack=[", hex(gp.stack.lo), ", ", hex(gp.stack.hi), "]\n")
		throw("stack overflow")
	}

	// The goroutine must be executing in order to call newstack,
	// so it must be Grunning (or Gscanrunning).
	casgstatus(gp, _Grunning, _Gcopystack)

	// The concurrent GC will not scan the stack while we are doing the copy since
	// the gp is in a Gcopystack status.
	copystack(gp, newsize)
	if stackDebug >= 1 {
		print("stack grow done\n")
	}
	casgstatus(gp, _Gcopystack, _Grunning)
	gogo(&gp.sched)
}

//go:nosplit
func nilfunc() {
	*(*uint8)(nil) = 0
}

// adjust Gobuf as if it executed a call to fn
// and then stopped before the first instruction in fn.
func gostartcallfn(gobuf *gobuf, fv *funcval) {
	var fn unsafe.Pointer
	if fv != nil {
		fn = unsafe.Pointer(fv.fn)
	} else {
		fn = unsafe.Pointer(abi.FuncPCABIInternal(nilfunc))
	}
	gostartcall(gobuf, fn, unsafe.Pointer(fv))
}

// isShrinkStackSafe returns whether it's safe to attempt to shrink
// gp's stack. Shrinking the stack is only safe when we have precise
// pointer maps for all frames on the stack. The caller must hold the
// _Gscan bit for gp or must be running gp itself.
func isShrinkStackSafe(gp *g) bool {
	// We can't copy the stack if we're in a syscall.
	// The syscall might have pointers into the stack and
	// often we don't have precise pointer maps for the innermost
	// frames.
	if gp.syscallsp != 0 {
		return false
	}
	// We also can't copy the stack if we're at an asynchronous
	// safe-point because we don't have precise pointer maps for
	// all frames.
	if gp.asyncSafePoint {
		return false
	}
	// We also can't *shrink* the stack in the window between the
	// goroutine calling gopark to park on a channel and
	// gp.activeStackChans being set.
	if gp.parkingOnChan.Load() {
		return false
	}
	// We also can't copy the stack while tracing is enabled, and
	// gp is in _Gwaiting solely to make itself available to the GC.
	// In these cases, the G is actually executing on the system
	// stack, and the execution tracer may want to take a stack trace
	// of the G's stack. Note: it's safe to access gp.waitreason here.
	// We're only checking if this is true if we took ownership of the
	// G with the _Gscan bit. This prevents the goroutine from transitioning,
	// which prevents gp.waitreason from changing.
	if traceEnabled() && readgstatus(gp)&^_Gscan == _Gwaiting && gp.waitreason.isWaitingForGC() {
		return false
	}
	return true
}

// Maybe shrink the stack being used by gp.
//
// gp must be stopped and we must own its stack. It may be in
// _Grunning, but only if this is our own user G.
func shrinkstack(gp *g) {
	if gp.stack.lo == 0 {
		throw("missing stack in shrinkstack")
	}
	if s := readgstatus(gp); s&_Gscan == 0 {
		// We don't own the stack via _Gscan. We could still
		// own it if this is our own user G and we're on the
		// system stack.
		if !(gp == getg().m.curg && getg() != getg().m.curg && s == _Grunning) {
			// We don't own the stack.
			throw("bad status in shrinkstack")
		}
	}
	if !isShrinkStackSafe(gp) {
		throw("shrinkstack at bad time")
	}
	// Check for self-shrinks while in a libcall. These may have
	// pointers into the stack disguised as uintptrs, but these
	// code paths should all be nosplit.
	if gp == getg().m.curg && gp.m.libcallsp != 0 {
		throw("shrinking stack in libcall")
	}

	if debug.gcshrinkstackoff > 0 {
		return
	}
	f := findfunc(gp.startpc)
	if f.valid() && f.funcID == abi.FuncID_gcBgMarkWorker {
		// We're not allowed to shrink the gcBgMarkWorker
		// stack (see gcBgMarkWorker for explanation).
		return
	}

	oldsize := gp.stack.hi - gp.stack.lo
	newsize := oldsize / 2
	// Don't shrink the allocation below the minimum-sized stack
	// allocation.
	if newsize < fixedStack {
		return
	}
	// Compute how much of the stack is currently in use and only
	// shrink the stack if gp is using less than a quarter of its
	// current stack. The currently used stack includes everything
	// down to the SP plus the stack guard space that ensures
	// there's room for nosplit functions.
	avail := gp.stack.hi - gp.stack.lo
	if used := gp.stack.hi - gp.sched.sp + stackNosplit; used >= avail/4 {
		return
	}

	if stackDebug > 0 {
		print("shrinking stack ", oldsize, "->", newsize, "\n")
	}

	copystack(gp, newsize)
}

// freeStackSpans frees unused stack spans at the end of GC.
func freeStackSpans() {
	// Scan stack pools for empty stack spans.
	for order := range stackpool {
		lock(&stackpool[order].item.mu)
		list := &stackpool[order].item.span
		for s := list.first; s != nil; {
			next := s.next
			if s.allocCount == 0 {
				list.remove(s)
				s.manualFreeList = 0
				osStackFree(s)
				mheap_.freeManual(s, spanAllocStack)
			}
			s = next
		}
		unlock(&stackpool[order].item.mu)
	}

	// Free large stack spans.
	lock(&stackLarge.lock)
	for i := range stackLarge.free {
		for s := stackLarge.free[i].first; s != nil; {
			next := s.next
			stackLarge.free[i].remove(s)
			osStackFree(s)
			mheap_.freeManual(s, spanAllocStack)
			s = next
		}
	}
	unlock(&stackLarge.lock)
}

// A stackObjectRecord is generated by the compiler for each stack object in a stack frame.
// This record must match the generator code in cmd/compile/internal/liveness/plive.go:emitStackObjects.
type stackObjectRecord struct {
	// offset in frame
	// if negative, offset from varp
	// if non-negative, offset from argp
	off       int32
	size      int32
	ptrBytes  int32
	gcdataoff uint32 // offset to gcdata from moduledata.rodata
}

// gcdata returns the number of bytes that contain pointers, and
// a ptr/nonptr bitmask covering those bytes.
// Note that this bitmask might be larger than internal/abi.MaxPtrmaskBytes.
func (r *stackObjectRecord) gcdata() (uintptr, *byte) {
	ptr := uintptr(unsafe.Pointer(r))
	var mod *moduledata
	for datap := &firstmoduledata; datap != nil; datap = datap.next {
		if datap.gofunc <= ptr && ptr < datap.end {
			mod = datap
			break
		}
	}
	// If you get a panic here due to a nil mod,
	// you may have made a copy of a stackObjectRecord.
	// You must use the original pointer.
	res := mod.rodata + uintptr(r.gcdataoff)
	return uintptr(r.ptrBytes), (*byte)(unsafe.Pointer(res))
}

// This is exported as ABI0 via linkname so obj can call it.
//
//go:nosplit
//go:linkname morestackc
func morestackc() {
	throw("attempt to execute system stack code on user stack")
}

// startingStackSize is the amount of stack that new goroutines start with.
// It is a power of 2, and between fixedStack and maxstacksize, inclusive.
// startingStackSize is updated every GC by tracking the average size of
// stacks scanned during the GC.
var startingStackSize uint32 = fixedStack

func gcComputeStartingStackSize() {
	if debug.adaptivestackstart == 0 {
		return
	}
	// For details, see the design doc at
	// https://docs.google.com/document/d/1YDlGIdVTPnmUiTAavlZxBI1d9pwGQgZT7IKFKlIXohQ/edit?usp=sharing
	// The basic algorithm is to track the average size of stacks
	// and start goroutines with stack equal to that average size.
	// Starting at the average size uses at most 2x the space that
	// an ideal algorithm would have used.
	// This is just a heuristic to avoid excessive stack growth work
	// early in a goroutine's lifetime. See issue 18138. Stacks that
	// are allocated too small can still grow, and stacks allocated
	// too large can still shrink.
	var scannedStackSize uint64
	var scannedStacks uint64
	for _, p := range allp {
		scannedStackSize += p.scannedStackSize
		scannedStacks += p.scannedStacks
		// Reset for next time
		p.scannedStackSize = 0
		p.scannedStacks = 0
	}
	if scannedStacks == 0 {
		startingStackSize = fixedStack
		return
	}
	avg := scannedStackSize/scannedStacks + stackGuard
	// Note: we add stackGuard to ensure that a goroutine that
	// uses the average space will not trigger a growth.
	if avg > uint64(maxstacksize) {
		avg = uint64(maxstacksize)
	}
	if avg < fixedStack {
		avg = fixedStack
	}
	// Note: maxstacksize fits in 30 bits, so avg also does.
	startingStackSize = uint32(round2(int32(avg)))
}

"""




```