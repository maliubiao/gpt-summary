Response:
My thinking process to answer the request about `go/src/runtime/traceback.go` went something like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of a Go source code snippet, specifically `go/src/runtime/traceback.go`. It also probes for the Go feature it implements, illustrative code examples, command-line parameter handling (if any), and common pitfalls. The request is explicitly for "part 1" of the file.

2. **Initial Code Scan (Focus on Top-Level Structures):**  I first scanned the provided code, paying attention to:
    * `package runtime`:  This immediately tells me this code is part of the Go runtime, dealing with core language features.
    * `import` statements:  Libraries like `internal/abi`, `internal/bytealg`, etc., hint at low-level operations related to calling conventions, memory manipulation, and architecture specifics.
    * Constants (`const`): `usesLR`, `tracebackInnerFrames`, `tracebackOuterFrames`, and `unwindFlags` suggest the code deals with stack frames, return addresses (link registers), and controlling the unwinding process.
    * Types (`type`): The `unwindFlags` and especially the `unwinder` struct are key. The fields within `unwinder` (`frame`, `g`, `cgoCtxt`, `calleeFuncID`, `flags`) provide direct clues to its purpose. `stkframe` (referenced but not fully defined here) is also significant.
    * Functions (`func`):  The names of the functions, like `init`, `initAt`, `valid`, `next`, `resolveInternal`, `finishInternal`, `symPC`, `cgoCallers`, `tracebackPCs`, `printArgs`, `funcNamePiecesForPrint`, `printFuncName`, `printcreatedby`, `traceback`, `tracebacktrap`, and `traceback1`, strongly indicate the code's role in traversing and presenting stack information.

3. **Formulate a Core Hypothesis:** Based on the names and the structure of the `unwinder`, the core functionality seems to be **walking and interpreting the call stack**. The presence of "traceback" in many function names reinforces this. The `unwindFlags` suggest controlling *how* this walking occurs, especially in error or signal handling scenarios.

4. **Identify Key Concepts and Mechanisms:**
    * **Stack Frames:** The `stkframe` within `unwinder` points to the concept of individual call stack frames. The code manipulates PCs, SPs, and LRs, which are fundamental to understanding stack frames.
    * **Link Register (LR):** The `usesLR` constant and the handling of `lr` in the code indicate architecture-specific logic related to how return addresses are stored.
    * **Unwinding:** The term "unwinder" and functions like `next` and `resolveInternal` clearly relate to the process of stepping through the stack frames.
    * **CGO:** The presence of `cgoCtxt` and `cgoCallers` suggests handling of calls between Go and C code.
    * **Error Handling:** The `unwindFlags` like `unwindPrintErrors` and `unwindSilentErrors` highlight the code's role in dealing with potential issues during stack walking, especially in potentially unstable environments like signal handlers.

5. **Infer the Go Feature:**  Given the core hypothesis, the most likely Go feature implemented is **stack traces (or stack backtraces)**. This makes sense given the `runtime` package location and the function names. Stack traces are crucial for debugging, profiling, and error reporting.

6. **Illustrative Go Code (Conceptual):**  While the provided snippet *is* the implementation, the request asks for how this functionality is used. I thought about scenarios where stack traces are generated:
    * **Panics:**  When a Go program panics, it prints a stack trace.
    * **`runtime.Stack()`:** This function explicitly retrieves the current goroutine's stack.
    * **Profiling:** Profiling tools often need to sample stack traces.

    Based on this, I could construct a simple example demonstrating a panic to show a stack trace. I also considered showing `runtime.Stack()`, but a panic example is more directly tied to the likely purpose of the code.

7. **Command-Line Parameters:**  I reviewed the code for any direct interaction with command-line flags or environment variables. I found none in this snippet. Therefore, the answer is that it doesn't directly handle command-line parameters.

8. **Common Pitfalls:** I considered what could go wrong when working with stack traces or low-level stack manipulation. A key issue is attempting to trace the *current* goroutine from within that same goroutine, as the stack might be growing or changing. The code itself explicitly checks for this and throws an error.

9. **Summarize Functionality (Part 1):**  Finally, I synthesized all the information gathered into a concise summary of the functionality covered in the provided code snippet. This included:
    * Core purpose: Traversing the call stack.
    * Key data structure: `unwinder`.
    * Architecture awareness: Handling link registers.
    * Error handling: Graceful degradation in error scenarios.
    * CGO integration.
    * Initialization and iteration mechanisms.

10. **Review and Refine:** I reread my answers to ensure they were clear, accurate, and directly addressed the questions in the request. I double-checked the code for any details I might have missed. For instance, the `tracebackInnerFrames` and `tracebackOuterFrames` constants are important for understanding how much of the stack trace is typically printed.

This iterative process of scanning, hypothesizing, identifying key concepts, and then refining the understanding led to the comprehensive answer provided. The code itself contains many clues, and understanding the broader context of the Go runtime is essential for interpreting its function.
这部分代码是 Go 语言运行时环境 `runtime` 包中负责实现**堆栈回溯 (stack traceback)** 功能的核心组件。

**功能归纳:**

1. **堆栈帧遍历 (Stack Frame Iteration):**  代码定义了一个 `unwinder` 结构体，以及与其关联的方法，用于迭代遍历 Go 程序的调用堆栈中的每一个物理栈帧 (physical stack frame)。

2. **架构感知 (Architecture Awareness):**  代码考虑了不同 CPU 架构的差异，特别是是否使用链接寄存器 (link register, LR) 来保存返回地址。它使用 `usesLR` 常量来区分这些架构，并根据不同的架构采用不同的策略来找到返回地址。

3. **处理错误 (Error Handling):**  代码中定义了 `unwindFlags`，用于控制堆栈回溯过程中的错误处理行为。它可以选择打印错误信息并停止，或者静默忽略错误。这对于在可能发生错误的场景（例如信号处理或崩溃时）获取尽可能多的堆栈信息非常重要。

4. **CGO 集成 (CGO Integration):**  代码中包含了处理 CGO (C 语言互操作) 调用的逻辑。它可以与 CGO 的堆栈回溯机制协同工作，以便在 Go 代码调用 C 代码时也能提供完整的堆栈信息。

5. **延迟调用和异常处理 (Defer and Panic Handling):**  代码可以识别出由于 `panic` 导致的堆栈帧，并能够处理 `defer` 语句的影响，以提供更准确的回溯信息。

6. **内联函数处理 (Inlined Function Handling):**  虽然这部分代码没有直接展示内联函数的处理逻辑，但它通过调用 `newInlineUnwinder` 以及后续的迭代，暗示了对内联函数的支持，能够在回溯中展示内联的逻辑调用栈帧。

**它是什么 Go 语言功能的实现：**

这部分代码是 Go 语言**堆栈追踪 (stack trace)** 功能的核心实现。当程序发生 panic、或者使用 `runtime.Stack()` 函数时，就会使用这部分代码来生成堆栈信息。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"runtime"
)

func innerFunc() {
	panic("something went wrong")
}

func outerFunc() {
	innerFunc()
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			stackBuf := make([]byte, 1024)
			n := runtime.Stack(stackBuf, false) // 获取当前 goroutine 的堆栈信息
			fmt.Printf("Recovered from panic: %v\nStack trace:\n%s", r, stackBuf[:n])
		}
	}()
	outerFunc()
}
```

**假设的输入与输出：**

在上面的例子中，当 `innerFunc` 发生 `panic` 时，`recover()` 函数会捕获这个 `panic`。然后 `runtime.Stack()` 函数会被调用。

**假设输入：**  当前 goroutine 的状态，包括当前的程序计数器 (PC)、栈指针 (SP) 等信息。

**可能的输出 (输出会因 Go 版本和架构而异，这里只是一个示意):**

```
Recovered from panic: something went wrong
Stack trace:
goroutine 1 [running]:
main.innerFunc(...)
        /path/to/your/file.go:9
main.outerFunc(...)
        /path/to/your/file.go:13
main.main()
        /path/to/your/file.go:20
runtime.main()
        /usr/local/go/src/runtime/proc.go:267 +0xeb
exit status 2
```

**命令行参数的具体处理：**

在这部分代码中，没有看到直接处理命令行参数的逻辑。堆栈回溯通常是由运行时环境根据程序执行的状态自动触发，或者由程序显式调用 `runtime.Stack()` 等函数来触发。

**使用者易犯错的点：**

一个常见的错误是尝试在**当前正在运行的 goroutine** 中进行堆栈回溯，尤其是在可能会导致栈增长的场景下。  代码中的 `initAt` 函数就对此进行了检查并抛出 `throw("cannot trace user goroutine on its own stack")` 的错误。这是因为在栈增长过程中，之前获取的栈指针等信息可能会失效。

**总结：**

这部分 `go/src/runtime/traceback.go` 代码实现了 Go 语言运行时环境中的核心堆栈回溯机制。它能够遍历程序的调用栈，并考虑到不同架构、CGO 调用以及错误处理等情况，为开发者提供程序执行过程中的关键信息，主要用于错误诊断和调试。

Prompt: 
```
这是路径为go/src/runtime/traceback.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package runtime

import (
	"internal/abi"
	"internal/bytealg"
	"internal/goarch"
	"internal/runtime/sys"
	"internal/stringslite"
	"unsafe"
)

// The code in this file implements stack trace walking for all architectures.
// The most important fact about a given architecture is whether it uses a link register.
// On systems with link registers, the prologue for a non-leaf function stores the
// incoming value of LR at the bottom of the newly allocated stack frame.
// On systems without link registers (x86), the architecture pushes a return PC during
// the call instruction, so the return PC ends up above the stack frame.
// In this file, the return PC is always called LR, no matter how it was found.

const usesLR = sys.MinFrameSize > 0

const (
	// tracebackInnerFrames is the number of innermost frames to print in a
	// stack trace. The total maximum frames is tracebackInnerFrames +
	// tracebackOuterFrames.
	tracebackInnerFrames = 50

	// tracebackOuterFrames is the number of outermost frames to print in a
	// stack trace.
	tracebackOuterFrames = 50
)

// unwindFlags control the behavior of various unwinders.
type unwindFlags uint8

const (
	// unwindPrintErrors indicates that if unwinding encounters an error, it
	// should print a message and stop without throwing. This is used for things
	// like stack printing, where it's better to get incomplete information than
	// to crash. This is also used in situations where everything may not be
	// stopped nicely and the stack walk may not be able to complete, such as
	// during profiling signals or during a crash.
	//
	// If neither unwindPrintErrors or unwindSilentErrors are set, unwinding
	// performs extra consistency checks and throws on any error.
	//
	// Note that there are a small number of fatal situations that will throw
	// regardless of unwindPrintErrors or unwindSilentErrors.
	unwindPrintErrors unwindFlags = 1 << iota

	// unwindSilentErrors silently ignores errors during unwinding.
	unwindSilentErrors

	// unwindTrap indicates that the initial PC and SP are from a trap, not a
	// return PC from a call.
	//
	// The unwindTrap flag is updated during unwinding. If set, frame.pc is the
	// address of a faulting instruction instead of the return address of a
	// call. It also means the liveness at pc may not be known.
	//
	// TODO: Distinguish frame.continpc, which is really the stack map PC, from
	// the actual continuation PC, which is computed differently depending on
	// this flag and a few other things.
	unwindTrap

	// unwindJumpStack indicates that, if the traceback is on a system stack, it
	// should resume tracing at the user stack when the system stack is
	// exhausted.
	unwindJumpStack
)

// An unwinder iterates the physical stack frames of a Go sack.
//
// Typical use of an unwinder looks like:
//
//	var u unwinder
//	for u.init(gp, 0); u.valid(); u.next() {
//		// ... use frame info in u ...
//	}
//
// Implementation note: This is carefully structured to be pointer-free because
// tracebacks happen in places that disallow write barriers (e.g., signals).
// Even if this is stack-allocated, its pointer-receiver methods don't know that
// their receiver is on the stack, so they still emit write barriers. Here we
// address that by carefully avoiding any pointers in this type. Another
// approach would be to split this into a mutable part that's passed by pointer
// but contains no pointers itself and an immutable part that's passed and
// returned by value and can contain pointers. We could potentially hide that
// we're doing that in trivial methods that are inlined into the caller that has
// the stack allocation, but that's fragile.
type unwinder struct {
	// frame is the current physical stack frame, or all 0s if
	// there is no frame.
	frame stkframe

	// g is the G who's stack is being unwound. If the
	// unwindJumpStack flag is set and the unwinder jumps stacks,
	// this will be different from the initial G.
	g guintptr

	// cgoCtxt is the index into g.cgoCtxt of the next frame on the cgo stack.
	// The cgo stack is unwound in tandem with the Go stack as we find marker frames.
	cgoCtxt int

	// calleeFuncID is the function ID of the caller of the current
	// frame.
	calleeFuncID abi.FuncID

	// flags are the flags to this unwind. Some of these are updated as we
	// unwind (see the flags documentation).
	flags unwindFlags
}

// init initializes u to start unwinding gp's stack and positions the
// iterator on gp's innermost frame. gp must not be the current G.
//
// A single unwinder can be reused for multiple unwinds.
func (u *unwinder) init(gp *g, flags unwindFlags) {
	// Implementation note: This starts the iterator on the first frame and we
	// provide a "valid" method. Alternatively, this could start in a "before
	// the first frame" state and "next" could return whether it was able to
	// move to the next frame, but that's both more awkward to use in a "for"
	// loop and is harder to implement because we have to do things differently
	// for the first frame.
	u.initAt(^uintptr(0), ^uintptr(0), ^uintptr(0), gp, flags)
}

func (u *unwinder) initAt(pc0, sp0, lr0 uintptr, gp *g, flags unwindFlags) {
	// Don't call this "g"; it's too easy get "g" and "gp" confused.
	if ourg := getg(); ourg == gp && ourg == ourg.m.curg {
		// The starting sp has been passed in as a uintptr, and the caller may
		// have other uintptr-typed stack references as well.
		// If during one of the calls that got us here or during one of the
		// callbacks below the stack must be grown, all these uintptr references
		// to the stack will not be updated, and traceback will continue
		// to inspect the old stack memory, which may no longer be valid.
		// Even if all the variables were updated correctly, it is not clear that
		// we want to expose a traceback that begins on one stack and ends
		// on another stack. That could confuse callers quite a bit.
		// Instead, we require that initAt and any other function that
		// accepts an sp for the current goroutine (typically obtained by
		// calling GetCallerSP) must not run on that goroutine's stack but
		// instead on the g0 stack.
		throw("cannot trace user goroutine on its own stack")
	}

	if pc0 == ^uintptr(0) && sp0 == ^uintptr(0) { // Signal to fetch saved values from gp.
		if gp.syscallsp != 0 {
			pc0 = gp.syscallpc
			sp0 = gp.syscallsp
			if usesLR {
				lr0 = 0
			}
		} else {
			pc0 = gp.sched.pc
			sp0 = gp.sched.sp
			if usesLR {
				lr0 = gp.sched.lr
			}
		}
	}

	var frame stkframe
	frame.pc = pc0
	frame.sp = sp0
	if usesLR {
		frame.lr = lr0
	}

	// If the PC is zero, it's likely a nil function call.
	// Start in the caller's frame.
	if frame.pc == 0 {
		if usesLR {
			frame.pc = *(*uintptr)(unsafe.Pointer(frame.sp))
			frame.lr = 0
		} else {
			frame.pc = *(*uintptr)(unsafe.Pointer(frame.sp))
			frame.sp += goarch.PtrSize
		}
	}

	// internal/runtime/atomic functions call into kernel helpers on
	// arm < 7. See internal/runtime/atomic/sys_linux_arm.s.
	//
	// Start in the caller's frame.
	if GOARCH == "arm" && goarm < 7 && GOOS == "linux" && frame.pc&0xffff0000 == 0xffff0000 {
		// Note that the calls are simple BL without pushing the return
		// address, so we use LR directly.
		//
		// The kernel helpers are frameless leaf functions, so SP and
		// LR are not touched.
		frame.pc = frame.lr
		frame.lr = 0
	}

	f := findfunc(frame.pc)
	if !f.valid() {
		if flags&unwindSilentErrors == 0 {
			print("runtime: g ", gp.goid, " gp=", gp, ": unknown pc ", hex(frame.pc), "\n")
			tracebackHexdump(gp.stack, &frame, 0)
		}
		if flags&(unwindPrintErrors|unwindSilentErrors) == 0 {
			throw("unknown pc")
		}
		*u = unwinder{}
		return
	}
	frame.fn = f

	// Populate the unwinder.
	*u = unwinder{
		frame:        frame,
		g:            gp.guintptr(),
		cgoCtxt:      len(gp.cgoCtxt) - 1,
		calleeFuncID: abi.FuncIDNormal,
		flags:        flags,
	}

	isSyscall := frame.pc == pc0 && frame.sp == sp0 && pc0 == gp.syscallpc && sp0 == gp.syscallsp
	u.resolveInternal(true, isSyscall)
}

func (u *unwinder) valid() bool {
	return u.frame.pc != 0
}

// resolveInternal fills in u.frame based on u.frame.fn, pc, and sp.
//
// innermost indicates that this is the first resolve on this stack. If
// innermost is set, isSyscall indicates that the PC/SP was retrieved from
// gp.syscall*; this is otherwise ignored.
//
// On entry, u.frame contains:
//   - fn is the running function.
//   - pc is the PC in the running function.
//   - sp is the stack pointer at that program counter.
//   - For the innermost frame on LR machines, lr is the program counter that called fn.
//
// On return, u.frame contains:
//   - fp is the stack pointer of the caller.
//   - lr is the program counter that called fn.
//   - varp, argp, and continpc are populated for the current frame.
//
// If fn is a stack-jumping function, resolveInternal can change the entire
// frame state to follow that stack jump.
//
// This is internal to unwinder.
func (u *unwinder) resolveInternal(innermost, isSyscall bool) {
	frame := &u.frame
	gp := u.g.ptr()

	f := frame.fn
	if f.pcsp == 0 {
		// No frame information, must be external function, like race support.
		// See golang.org/issue/13568.
		u.finishInternal()
		return
	}

	// Compute function info flags.
	flag := f.flag
	if f.funcID == abi.FuncID_cgocallback {
		// cgocallback does write SP to switch from the g0 to the curg stack,
		// but it carefully arranges that during the transition BOTH stacks
		// have cgocallback frame valid for unwinding through.
		// So we don't need to exclude it with the other SP-writing functions.
		flag &^= abi.FuncFlagSPWrite
	}
	if isSyscall {
		// Some Syscall functions write to SP, but they do so only after
		// saving the entry PC/SP using entersyscall.
		// Since we are using the entry PC/SP, the later SP write doesn't matter.
		flag &^= abi.FuncFlagSPWrite
	}

	// Found an actual function.
	// Derive frame pointer.
	if frame.fp == 0 {
		// Jump over system stack transitions. If we're on g0 and there's a user
		// goroutine, try to jump. Otherwise this is a regular call.
		// We also defensively check that this won't switch M's on us,
		// which could happen at critical points in the scheduler.
		// This ensures gp.m doesn't change from a stack jump.
		if u.flags&unwindJumpStack != 0 && gp == gp.m.g0 && gp.m.curg != nil && gp.m.curg.m == gp.m {
			switch f.funcID {
			case abi.FuncID_morestack:
				// morestack does not return normally -- newstack()
				// gogo's to curg.sched. Match that.
				// This keeps morestack() from showing up in the backtrace,
				// but that makes some sense since it'll never be returned
				// to.
				gp = gp.m.curg
				u.g.set(gp)
				frame.pc = gp.sched.pc
				frame.fn = findfunc(frame.pc)
				f = frame.fn
				flag = f.flag
				frame.lr = gp.sched.lr
				frame.sp = gp.sched.sp
				u.cgoCtxt = len(gp.cgoCtxt) - 1
			case abi.FuncID_systemstack:
				// systemstack returns normally, so just follow the
				// stack transition.
				if usesLR && funcspdelta(f, frame.pc) == 0 {
					// We're at the function prologue and the stack
					// switch hasn't happened, or epilogue where we're
					// about to return. Just unwind normally.
					// Do this only on LR machines because on x86
					// systemstack doesn't have an SP delta (the CALL
					// instruction opens the frame), therefore no way
					// to check.
					flag &^= abi.FuncFlagSPWrite
					break
				}
				gp = gp.m.curg
				u.g.set(gp)
				frame.sp = gp.sched.sp
				u.cgoCtxt = len(gp.cgoCtxt) - 1
				flag &^= abi.FuncFlagSPWrite
			}
		}
		frame.fp = frame.sp + uintptr(funcspdelta(f, frame.pc))
		if !usesLR {
			// On x86, call instruction pushes return PC before entering new function.
			frame.fp += goarch.PtrSize
		}
	}

	// Derive link register.
	if flag&abi.FuncFlagTopFrame != 0 {
		// This function marks the top of the stack. Stop the traceback.
		frame.lr = 0
	} else if flag&abi.FuncFlagSPWrite != 0 && (!innermost || u.flags&(unwindPrintErrors|unwindSilentErrors) != 0) {
		// The function we are in does a write to SP that we don't know
		// how to encode in the spdelta table. Examples include context
		// switch routines like runtime.gogo but also any code that switches
		// to the g0 stack to run host C code.
		// We can't reliably unwind the SP (we might not even be on
		// the stack we think we are), so stop the traceback here.
		//
		// The one exception (encoded in the complex condition above) is that
		// we assume if we're doing a precise traceback, and this is the
		// innermost frame, that the SPWRITE function voluntarily preempted itself on entry
		// during the stack growth check. In that case, the function has
		// not yet had a chance to do any writes to SP and is safe to unwind.
		// isAsyncSafePoint does not allow assembly functions to be async preempted,
		// and preemptPark double-checks that SPWRITE functions are not async preempted.
		// So for GC stack traversal, we can safely ignore SPWRITE for the innermost frame,
		// but farther up the stack we'd better not find any.
		// This is somewhat imprecise because we're just guessing that we're in the stack
		// growth check. It would be better if SPWRITE were encoded in the spdelta
		// table so we would know for sure that we were still in safe code.
		//
		// uSE uPE inn | action
		//  T   _   _  | frame.lr = 0
		//  F   T   _  | frame.lr = 0
		//  F   F   F  | print; panic
		//  F   F   T  | ignore SPWrite
		if u.flags&(unwindPrintErrors|unwindSilentErrors) == 0 && !innermost {
			println("traceback: unexpected SPWRITE function", funcname(f))
			throw("traceback")
		}
		frame.lr = 0
	} else {
		var lrPtr uintptr
		if usesLR {
			if innermost && frame.sp < frame.fp || frame.lr == 0 {
				lrPtr = frame.sp
				frame.lr = *(*uintptr)(unsafe.Pointer(lrPtr))
			}
		} else {
			if frame.lr == 0 {
				lrPtr = frame.fp - goarch.PtrSize
				frame.lr = *(*uintptr)(unsafe.Pointer(lrPtr))
			}
		}
	}

	frame.varp = frame.fp
	if !usesLR {
		// On x86, call instruction pushes return PC before entering new function.
		frame.varp -= goarch.PtrSize
	}

	// For architectures with frame pointers, if there's
	// a frame, then there's a saved frame pointer here.
	//
	// NOTE: This code is not as general as it looks.
	// On x86, the ABI is to save the frame pointer word at the
	// top of the stack frame, so we have to back down over it.
	// On arm64, the frame pointer should be at the bottom of
	// the stack (with R29 (aka FP) = RSP), in which case we would
	// not want to do the subtraction here. But we started out without
	// any frame pointer, and when we wanted to add it, we didn't
	// want to break all the assembly doing direct writes to 8(RSP)
	// to set the first parameter to a called function.
	// So we decided to write the FP link *below* the stack pointer
	// (with R29 = RSP - 8 in Go functions).
	// This is technically ABI-compatible but not standard.
	// And it happens to end up mimicking the x86 layout.
	// Other architectures may make different decisions.
	if frame.varp > frame.sp && framepointer_enabled {
		frame.varp -= goarch.PtrSize
	}

	frame.argp = frame.fp + sys.MinFrameSize

	// Determine frame's 'continuation PC', where it can continue.
	// Normally this is the return address on the stack, but if sigpanic
	// is immediately below this function on the stack, then the frame
	// stopped executing due to a trap, and frame.pc is probably not
	// a safe point for looking up liveness information. In this panicking case,
	// the function either doesn't return at all (if it has no defers or if the
	// defers do not recover) or it returns from one of the calls to
	// deferproc a second time (if the corresponding deferred func recovers).
	// In the latter case, use a deferreturn call site as the continuation pc.
	frame.continpc = frame.pc
	if u.calleeFuncID == abi.FuncID_sigpanic {
		if frame.fn.deferreturn != 0 {
			frame.continpc = frame.fn.entry() + uintptr(frame.fn.deferreturn) + 1
			// Note: this may perhaps keep return variables alive longer than
			// strictly necessary, as we are using "function has a defer statement"
			// as a proxy for "function actually deferred something". It seems
			// to be a minor drawback. (We used to actually look through the
			// gp._defer for a defer corresponding to this function, but that
			// is hard to do with defer records on the stack during a stack copy.)
			// Note: the +1 is to offset the -1 that
			// stack.go:getStackMap does to back up a return
			// address make sure the pc is in the CALL instruction.
		} else {
			frame.continpc = 0
		}
	}
}

func (u *unwinder) next() {
	frame := &u.frame
	f := frame.fn
	gp := u.g.ptr()

	// Do not unwind past the bottom of the stack.
	if frame.lr == 0 {
		u.finishInternal()
		return
	}
	flr := findfunc(frame.lr)
	if !flr.valid() {
		// This happens if you get a profiling interrupt at just the wrong time.
		// In that context it is okay to stop early.
		// But if no error flags are set, we're doing a garbage collection and must
		// get everything, so crash loudly.
		fail := u.flags&(unwindPrintErrors|unwindSilentErrors) == 0
		doPrint := u.flags&unwindSilentErrors == 0
		if doPrint && gp.m.incgo && f.funcID == abi.FuncID_sigpanic {
			// We can inject sigpanic
			// calls directly into C code,
			// in which case we'll see a C
			// return PC. Don't complain.
			doPrint = false
		}
		if fail || doPrint {
			print("runtime: g ", gp.goid, ": unexpected return pc for ", funcname(f), " called from ", hex(frame.lr), "\n")
			tracebackHexdump(gp.stack, frame, 0)
		}
		if fail {
			throw("unknown caller pc")
		}
		frame.lr = 0
		u.finishInternal()
		return
	}

	if frame.pc == frame.lr && frame.sp == frame.fp {
		// If the next frame is identical to the current frame, we cannot make progress.
		print("runtime: traceback stuck. pc=", hex(frame.pc), " sp=", hex(frame.sp), "\n")
		tracebackHexdump(gp.stack, frame, frame.sp)
		throw("traceback stuck")
	}

	injectedCall := f.funcID == abi.FuncID_sigpanic || f.funcID == abi.FuncID_asyncPreempt || f.funcID == abi.FuncID_debugCallV2
	if injectedCall {
		u.flags |= unwindTrap
	} else {
		u.flags &^= unwindTrap
	}

	// Unwind to next frame.
	u.calleeFuncID = f.funcID
	frame.fn = flr
	frame.pc = frame.lr
	frame.lr = 0
	frame.sp = frame.fp
	frame.fp = 0

	// On link register architectures, sighandler saves the LR on stack
	// before faking a call.
	if usesLR && injectedCall {
		x := *(*uintptr)(unsafe.Pointer(frame.sp))
		frame.sp += alignUp(sys.MinFrameSize, sys.StackAlign)
		f = findfunc(frame.pc)
		frame.fn = f
		if !f.valid() {
			frame.pc = x
		} else if funcspdelta(f, frame.pc) == 0 {
			frame.lr = x
		}
	}

	u.resolveInternal(false, false)
}

// finishInternal is an unwinder-internal helper called after the stack has been
// exhausted. It sets the unwinder to an invalid state and checks that it
// successfully unwound the entire stack.
func (u *unwinder) finishInternal() {
	u.frame.pc = 0

	// Note that panic != nil is okay here: there can be leftover panics,
	// because the defers on the panic stack do not nest in frame order as
	// they do on the defer stack. If you have:
	//
	//	frame 1 defers d1
	//	frame 2 defers d2
	//	frame 3 defers d3
	//	frame 4 panics
	//	frame 4's panic starts running defers
	//	frame 5, running d3, defers d4
	//	frame 5 panics
	//	frame 5's panic starts running defers
	//	frame 6, running d4, garbage collects
	//	frame 6, running d2, garbage collects
	//
	// During the execution of d4, the panic stack is d4 -> d3, which
	// is nested properly, and we'll treat frame 3 as resumable, because we
	// can find d3. (And in fact frame 3 is resumable. If d4 recovers
	// and frame 5 continues running, d3, d3 can recover and we'll
	// resume execution in (returning from) frame 3.)
	//
	// During the execution of d2, however, the panic stack is d2 -> d3,
	// which is inverted. The scan will match d2 to frame 2 but having
	// d2 on the stack until then means it will not match d3 to frame 3.
	// This is okay: if we're running d2, then all the defers after d2 have
	// completed and their corresponding frames are dead. Not finding d3
	// for frame 3 means we'll set frame 3's continpc == 0, which is correct
	// (frame 3 is dead). At the end of the walk the panic stack can thus
	// contain defers (d3 in this case) for dead frames. The inversion here
	// always indicates a dead frame, and the effect of the inversion on the
	// scan is to hide those dead frames, so the scan is still okay:
	// what's left on the panic stack are exactly (and only) the dead frames.
	//
	// We require callback != nil here because only when callback != nil
	// do we know that gentraceback is being called in a "must be correct"
	// context as opposed to a "best effort" context. The tracebacks with
	// callbacks only happen when everything is stopped nicely.
	// At other times, such as when gathering a stack for a profiling signal
	// or when printing a traceback during a crash, everything may not be
	// stopped nicely, and the stack walk may not be able to complete.
	gp := u.g.ptr()
	if u.flags&(unwindPrintErrors|unwindSilentErrors) == 0 && u.frame.sp != gp.stktopsp {
		print("runtime: g", gp.goid, ": frame.sp=", hex(u.frame.sp), " top=", hex(gp.stktopsp), "\n")
		print("\tstack=[", hex(gp.stack.lo), "-", hex(gp.stack.hi), "\n")
		throw("traceback did not unwind completely")
	}
}

// symPC returns the PC that should be used for symbolizing the current frame.
// Specifically, this is the PC of the last instruction executed in this frame.
//
// If this frame did a normal call, then frame.pc is a return PC, so this will
// return frame.pc-1, which points into the CALL instruction. If the frame was
// interrupted by a signal (e.g., profiler, segv, etc) then frame.pc is for the
// trapped instruction, so this returns frame.pc. See issue #34123. Finally,
// frame.pc can be at function entry when the frame is initialized without
// actually running code, like in runtime.mstart, in which case this returns
// frame.pc because that's the best we can do.
func (u *unwinder) symPC() uintptr {
	if u.flags&unwindTrap == 0 && u.frame.pc > u.frame.fn.entry() {
		// Regular call.
		return u.frame.pc - 1
	}
	// Trapping instruction or we're at the function entry point.
	return u.frame.pc
}

// cgoCallers populates pcBuf with the cgo callers of the current frame using
// the registered cgo unwinder. It returns the number of PCs written to pcBuf.
// If the current frame is not a cgo frame or if there's no registered cgo
// unwinder, it returns 0.
func (u *unwinder) cgoCallers(pcBuf []uintptr) int {
	if cgoTraceback == nil || u.frame.fn.funcID != abi.FuncID_cgocallback || u.cgoCtxt < 0 {
		// We don't have a cgo unwinder (typical case), or we do but we're not
		// in a cgo frame or we're out of cgo context.
		return 0
	}

	ctxt := u.g.ptr().cgoCtxt[u.cgoCtxt]
	u.cgoCtxt--
	cgoContextPCs(ctxt, pcBuf)
	for i, pc := range pcBuf {
		if pc == 0 {
			return i
		}
	}
	return len(pcBuf)
}

// tracebackPCs populates pcBuf with the return addresses for each frame from u
// and returns the number of PCs written to pcBuf. The returned PCs correspond
// to "logical frames" rather than "physical frames"; that is if A is inlined
// into B, this will still return a PCs for both A and B. This also includes PCs
// generated by the cgo unwinder, if one is registered.
//
// If skip != 0, this skips this many logical frames.
//
// Callers should set the unwindSilentErrors flag on u.
func tracebackPCs(u *unwinder, skip int, pcBuf []uintptr) int {
	var cgoBuf [32]uintptr
	n := 0
	for ; n < len(pcBuf) && u.valid(); u.next() {
		f := u.frame.fn
		cgoN := u.cgoCallers(cgoBuf[:])

		// TODO: Why does &u.cache cause u to escape? (Same in traceback2)
		for iu, uf := newInlineUnwinder(f, u.symPC()); n < len(pcBuf) && uf.valid(); uf = iu.next(uf) {
			sf := iu.srcFunc(uf)
			if sf.funcID == abi.FuncIDWrapper && elideWrapperCalling(u.calleeFuncID) {
				// ignore wrappers
			} else if skip > 0 {
				skip--
			} else {
				// Callers expect the pc buffer to contain return addresses
				// and do the -1 themselves, so we add 1 to the call pc to
				// create a "return pc". Since there is no actual call, here
				// "return pc" just means a pc you subtract 1 from to get
				// the pc of the "call". The actual no-op we insert may or
				// may not be 1 byte.
				pcBuf[n] = uf.pc + 1
				n++
			}
			u.calleeFuncID = sf.funcID
		}
		// Add cgo frames (if we're done skipping over the requested number of
		// Go frames).
		if skip == 0 {
			n += copy(pcBuf[n:], cgoBuf[:cgoN])
		}
	}
	return n
}

// printArgs prints function arguments in traceback.
func printArgs(f funcInfo, argp unsafe.Pointer, pc uintptr) {
	p := (*[abi.TraceArgsMaxLen]uint8)(funcdata(f, abi.FUNCDATA_ArgInfo))
	if p == nil {
		return
	}

	liveInfo := funcdata(f, abi.FUNCDATA_ArgLiveInfo)
	liveIdx := pcdatavalue(f, abi.PCDATA_ArgLiveIndex, pc)
	startOffset := uint8(0xff) // smallest offset that needs liveness info (slots with a lower offset is always live)
	if liveInfo != nil {
		startOffset = *(*uint8)(liveInfo)
	}

	isLive := func(off, slotIdx uint8) bool {
		if liveInfo == nil || liveIdx <= 0 {
			return true // no liveness info, always live
		}
		if off < startOffset {
			return true
		}
		bits := *(*uint8)(add(liveInfo, uintptr(liveIdx)+uintptr(slotIdx/8)))
		return bits&(1<<(slotIdx%8)) != 0
	}

	print1 := func(off, sz, slotIdx uint8) {
		x := readUnaligned64(add(argp, uintptr(off)))
		// mask out irrelevant bits
		if sz < 8 {
			shift := 64 - sz*8
			if goarch.BigEndian {
				x = x >> shift
			} else {
				x = x << shift >> shift
			}
		}
		print(hex(x))
		if !isLive(off, slotIdx) {
			print("?")
		}
	}

	start := true
	printcomma := func() {
		if !start {
			print(", ")
		}
	}
	pi := 0
	slotIdx := uint8(0) // register arg spill slot index
printloop:
	for {
		o := p[pi]
		pi++
		switch o {
		case abi.TraceArgsEndSeq:
			break printloop
		case abi.TraceArgsStartAgg:
			printcomma()
			print("{")
			start = true
			continue
		case abi.TraceArgsEndAgg:
			print("}")
		case abi.TraceArgsDotdotdot:
			printcomma()
			print("...")
		case abi.TraceArgsOffsetTooLarge:
			printcomma()
			print("_")
		default:
			printcomma()
			sz := p[pi]
			pi++
			print1(o, sz, slotIdx)
			if o >= startOffset {
				slotIdx++
			}
		}
		start = false
	}
}

// funcNamePiecesForPrint returns the function name for printing to the user.
// It returns three pieces so it doesn't need an allocation for string
// concatenation.
func funcNamePiecesForPrint(name string) (string, string, string) {
	// Replace the shape name in generic function with "...".
	i := bytealg.IndexByteString(name, '[')
	if i < 0 {
		return name, "", ""
	}
	j := len(name) - 1
	for name[j] != ']' {
		j--
	}
	if j <= i {
		return name, "", ""
	}
	return name[:i], "[...]", name[j+1:]
}

// funcNameForPrint returns the function name for printing to the user.
func funcNameForPrint(name string) string {
	a, b, c := funcNamePiecesForPrint(name)
	return a + b + c
}

// printFuncName prints a function name. name is the function name in
// the binary's func data table.
func printFuncName(name string) {
	if name == "runtime.gopanic" {
		print("panic")
		return
	}
	a, b, c := funcNamePiecesForPrint(name)
	print(a, b, c)
}

func printcreatedby(gp *g) {
	// Show what created goroutine, except main goroutine (goid 1).
	pc := gp.gopc
	f := findfunc(pc)
	if f.valid() && showframe(f.srcFunc(), gp, false, abi.FuncIDNormal) && gp.goid != 1 {
		printcreatedby1(f, pc, gp.parentGoid)
	}
}

func printcreatedby1(f funcInfo, pc uintptr, goid uint64) {
	print("created by ")
	printFuncName(funcname(f))
	if goid != 0 {
		print(" in goroutine ", goid)
	}
	print("\n")
	tracepc := pc // back up to CALL instruction for funcline.
	if pc > f.entry() {
		tracepc -= sys.PCQuantum
	}
	file, line := funcline(f, tracepc)
	print("\t", file, ":", line)
	if pc > f.entry() {
		print(" +", hex(pc-f.entry()))
	}
	print("\n")
}

func traceback(pc, sp, lr uintptr, gp *g) {
	traceback1(pc, sp, lr, gp, 0)
}

// tracebacktrap is like traceback but expects that the PC and SP were obtained
// from a trap, not from gp->sched or gp->syscallpc/gp->syscallsp or GetCallerPC/GetCallerSP.
// Because they are from a trap instead of from a saved pair,
// the initial PC must not be rewound to the previous instruction.
// (All the saved pairs record a PC that is a return address, so we
// rewind it into the CALL instruction.)
// If gp.m.libcall{g,pc,sp} information is available, it uses that information in preference to
// the pc/sp/lr passed in.
func tracebacktrap(pc, sp, lr uintptr, gp *g) {
	if gp.m.libcallsp != 0 {
		// We're in C code somewhere, traceback from the saved position.
		traceback1(gp.m.libcallpc, gp.m.libcallsp, 0, gp.m.libcallg.ptr(), 0)
		return
	}
	traceback1(pc, sp, lr, gp, unwindTrap)
}

func traceback1(pc, sp, lr uintptr, gp *g, flags unwindFlags) {
	// If the goroutine is in cgo, and we have a cgo traceback, print that.
	if iscgo && gp.m != nil && gp.m.ncgo > 0 && gp.syscallsp != 0 && gp.m.cgoCallers != nil && gp.m.cgoCallers[0] != 0 {
		// Lock cgoCallers so that a signal handler won't
		// change it, copy the array, reset it, unlock it.
		// We are locked to the thread and are not running
		// concurrently with a signal handler.
		// We just have to stop a signal handler from interrupting
		// in the middle of our copy.
		gp.m.cgoCallersUse.Store(1)
		cgoCallers := *gp.m.cgoCallers
		gp.m.cgoCallers[0] = 0
		gp.m.cgoCallersUse.Store(0)

		printCgoTraceback(&cgoCallers)
	}

	if readgstatus(gp)&^_Gscan == _Gsyscall {
		// Override registers if blocked in system call.
		pc = gp.syscallpc
		sp = gp.syscallsp
		flags &^= unwindTrap
	}
	if gp.m != nil && gp.m.vdsoSP != 0 {
		// Override registers if running in VDSO. This comes after the
		// _Gsyscall check to cover VDSO calls after entersyscall.
		pc = gp.m.vdsoPC
		sp = gp.m.vdsoSP
		flags &^= unwindTrap
	}

	// Print traceback.
	//
	// We print the first tracebackInnerFrames frames, and the last
	// tracebackOuterFrames frames. There are many possible approaches to this.
	// There are various complications to this:
	//
	// - We'd prefer to walk the stack once because in really bad situations
	//   traceback may crash (and we want as much output as possible) or the stack
	//   may be changing.
	//
	// - Each physical frame can represent several logical frames, so we might
	//   have to pause in the middle of a physical frame and pick up in the middle
	//   of a physical frame.
	//
	// - The cgo symbolizer can expand a cgo PC to more than one logical frame,
	//   and involves juggling state on the C side that we don't manage. Since its
	//   expansion state is managed on the C side, we can't capture the expansion
	//   state part way through, and because the output strings are managed on the
	//   C side, we can't capture the output. Thus, our only choice is to replay a
	//   whole expansion, potentially discarding some of it.
	//
	// Rejected approaches:
	//
	// - Do two passes where the first pass just counts and the second pass does
	//   all the printing. This is undesirable if the stack is corrupted or changing
	//   because we won't see a partial stack if we panic.
	//
	// - Keep a ring buffer of the last N logical frames and use this to print
	//   the bottom frames once we reach the end of the stack. This works, but
	//   requires keeping a surprising amount of state on the stack, and we have
	//   to run the cgo symbolizer twice—once to count frames, and a second to
	//   print them—since we can't retain the strings it returns.
	//
	// Instead, we print the outer frames, and if we reach that limit, we clone
	// the unwinder, count the remaining frames, and then skip forward and
	// finish printing from the clone. This makes two passes over the outer part
	// of the stack, but the single pass over the inner part ensures that's
	// printed immediately and not revisited. It keeps minimal state on the
	// stack. And through a combination of skip counts and limits, we can do all
	// of the steps we need with a single traceback printer implementation.
	//
	// We could be more lax about exactly how many frames we print, for example
	// always stopping and resuming on physical frame boundaries, or at least
	// cgo expansion boundaries. It's not clear that's much simpler.
	flags |= unwindPrintErrors
	var u unwinder
	tracebackWithRuntime := func(showRuntime bool) int {
		const maxInt int = 0x7fffffff
		u.initAt(pc, sp, lr, gp, flags)
		n, lastN := traceback2(&u, showRuntime, 0, tracebackInnerFrames)
		if n < tracebackInnerFrames {
			// 
"""




```