Response:
Let's break down the thought process for analyzing this Go code snippet related to stack tracebacks.

**1. Initial Reading and Keyword Spotting:**

The first step is to read through the code, identifying key function names, variables, and comments. Terms like `traceback`, `unwinder`, `frame`, `pc`, `sp`, `fp`, `goroutine`, `cgo`, `symbolizer`, `print`, and `skip` immediately stand out. These words provide strong hints about the code's purpose.

**2. Function-Level Analysis:**

Next, examine individual functions and their roles.

* **`traceback(..)` and `traceback2(..)`:** These are clearly the core functions for generating stack traces. Notice `traceback` seems to call `traceback2` and handles some edge cases. `traceback2` appears to be the workhorse.
* **`printcreatedby(..)` and `printAncestorTraceback(..)`:** These deal with tracing the creation history of goroutines, which is a crucial part of understanding concurrent execution.
* **`callers(..)` and `gcallers(..)`:** These functions provide a way to get the call stack programmatically, used by other parts of the Go runtime and potentially user code. The `go:linkname` comment is a red flag indicating special usage.
* **`showframe(..)` and `showfuncinfo(..)`:** These functions control which frames are included in the output, filtering out runtime details by default.
* **`isSystemGoroutine(..)`:**  This identifies internal runtime goroutines, often excluded from user-level stack traces for clarity.
* **`SetCgoTraceback(..)` and related functions (e.g., `printCgoTraceback`, `callCgoSymbolizer`):** These handle the interaction with C code through cgo, allowing stack traces to span across Go and C code.
* **Helper functions like `goroutineheader(..)` and `tracebackHexdump(..)`:** These provide formatting and debugging utilities for stack traces.

**3. Identifying Core Functionality (Instruction Following):**

Now, start tracing the execution flow within the key functions, especially `traceback` and `traceback2`.

* **`traceback`:**
    * Takes a `gp` (goroutine pointer) as input.
    * Handles the case where `gp` is nil (use the current goroutine).
    * Calls `tracebackWithRuntime` twice – first without runtime frames, then with if the first call produced nothing. This indicates a default behavior and a fallback.
    * Calls `printcreatedby` to show how the goroutine was created.
    * Iterates through ancestor goroutines (if any) and calls `printAncestorTraceback`.
* **`traceback2`:**
    * Uses an `unwinder` to iterate through stack frames.
    * Has a `commitFrame` closure to decide whether to print a frame based on `skip` and `max` parameters.
    * Uses an `inlineUnwinder` to handle inlined function calls.
    * Filters frames based on `showRuntime` and `showframe`.
    * Prints function names, arguments (for non-inlined frames), file/line information, and potentially register values.
    * Handles CGO calls using `u.cgoCallers` and `printOneCgoTraceback`.

**4. Inferring Go Language Features:**

Based on the observed functionality, we can infer:

* **Panic and Recover:** The ability to print stack traces is crucial for debugging panics.
* **Goroutines and Concurrency:** The functions for tracing ancestor goroutines and handling different goroutine states directly relate to Go's concurrency model.
* **Cgo Integration:** The `SetCgoTraceback` family of functions clearly indicates support for interoperability with C code, where stack traces need to encompass both Go and C frames.
* **Inlining:** The `inlineUnwinder` and related logic show that Go's compiler performs function inlining, and the traceback mechanism can handle this.
* **Runtime Introspection:**  The code accesses internal goroutine states and function metadata, indicating deep integration with the Go runtime.

**5. Code Example Creation (Illustrative):**

To illustrate the functionality, create simple Go programs that demonstrate:

* **Basic Stack Trace:** A simple function call chain leading to a panic.
* **Goroutine Creation Trace:** Using `go func()` to create a new goroutine and observe the "created by" information.
* **Cgo Stack Trace (Conceptual):** Describe a scenario where Go calls C code, and the stack trace shows both sides. A full working example requires setting up C code and cgo, which might be too complex for a quick illustration, so a conceptual explanation is sufficient.

**6. Input/Output Reasoning:**

Think about the inputs to these functions and the expected outputs:

* **`traceback(gp)`:** Input is a goroutine pointer. Output is a formatted stack trace printed to standard error.
* **`callers(skip, pcbuf)`:** Input is a number of frames to skip and a buffer. Output is the number of PC values written to the buffer.

**7. Command-Line Arguments:**

Consider how command-line arguments might influence stack trace behavior. The `-debug` flag is a key example for enabling more verbose output.

**8. Identifying Common Mistakes:**

Think about potential pitfalls for users:

* **Misinterpreting "created by":**  Users might confuse the goroutine that *started* another goroutine with a direct function call.
* **Assuming `callers` always returns the full stack:** The `skip` argument and buffer size limitations need to be understood.

**9. Summarization (Based on Part 1 and Part 2):**

Combine the observations from both parts of the code to provide a concise summary of the functionality. Emphasize the key aspects: generating stack traces, handling goroutines, supporting cgo, and providing programmatic access to the call stack.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps focus too much on low-level details of the unwinder.
* **Correction:**  Shift focus to the higher-level purpose and how these details contribute to the overall goal of generating user-friendly stack traces.
* **Initial thought:**  Overlook the importance of `showframe` and `showfuncinfo`.
* **Correction:** Realize that these functions are crucial for controlling the level of detail in the stack trace, which is important for usability.
* **Initial thought:**  Focus too heavily on the data structures used.
* **Correction:** Emphasize the *actions* and *information provided* by the code rather than just the data structures themselves.

By following these steps, combining code reading with reasoning about the purpose and context, one can effectively analyze and explain the functionality of this Go code snippet.
这是 `go/src/runtime/traceback.go` 代码的第二部分，主要功能是**在程序运行时生成和打印 goroutine 的堆栈跟踪信息**。它延续了第一部分的功能，并在此基础上提供了更精细的控制和对 CGO 调用的支持。

以下是对其功能的归纳：

**核心功能：打印堆栈跟踪**

* **精细控制的堆栈打印 (`traceback2`)**:  这是打印堆栈跟踪的核心函数。它接收一个 `unwinder` 对象，以及控制显示运行时帧、跳过帧数和最大打印帧数的参数。这允许更灵活地定制要显示的堆栈信息。
* **处理堆栈帧**:  `traceback2` 遍历堆栈帧，并根据 `showRuntime` 和 `showframe` 的判断来决定是否打印当前帧的信息，包括函数名、文件名、行号以及可能的内存地址信息。
* **处理内联函数**: 通过 `newInlineUnwinder` 和相关的逻辑，能够正确地展示内联函数的堆栈信息。
* **省略中间帧**: 当堆栈帧数过多时，会省略中间部分，并用 "..." 提示，以提高可读性。

**处理 Goroutine 的创建信息**

* **打印祖先 Goroutine 的堆栈 (`printAncestorTraceback`)**:  用于展示 Goroutine 的创建路径，这对于理解并发程序的执行流程非常重要。它会打印创建当前 Goroutine 的父 Goroutine 的堆栈信息。
* **简化祖先堆栈信息**: 由于只能访问到创建 Goroutine 时的 PC 值，祖先 Goroutine 的堆栈信息精度会降低。

**提供程序化访问堆栈信息的能力**

* **`callers` 和 `gcallers` 函数**:  这两个函数允许在 Go 代码中获取当前 Goroutine 或指定 Goroutine 的调用栈 PC 值。这为开发调试工具或性能分析工具提供了基础。

**处理 CGO 调用**

* **支持 CGO 堆栈跟踪 (`printCgoTraceback`, `printOneCgoTraceback`)**:  当 Go 代码调用 C 代码时，该部分代码负责获取和打印 C 代码的堆栈信息，使得堆栈跟踪能够跨越 Go 和 C 的边界。
* **`SetCgoTraceback` 函数**:  允许用户自定义 CGO 堆栈跟踪、上下文和符号化的回调函数，以适应不同的 C 库和调试需求。
* **`cgoContextPCs` 函数**:  用于获取 CGO 上下文的 PC 值。

**其他辅助功能**

* **`showframe` 和 `showfuncinfo`**:  用于判断是否显示某个堆栈帧的信息，通常用于过滤掉运行时内部的函数调用，使堆栈跟踪更简洁。
* **`isSystemGoroutine`**:  判断一个 Goroutine 是否是运行时内部的 Goroutine，这在某些场景下可以用于过滤。
* **`tracebackHexdump`**:  提供堆栈内存的十六进制转储功能，用于更底层的调试。
* **`goroutineheader`**:  打印 Goroutine 的基本信息，如 ID、状态、等待时间等。
* **`tracebackothers`**: 打印除了当前 Goroutine 之外的其他所有 Goroutine 的堆栈信息。

**总结:**

这部分代码是 Go 运行时系统中生成和管理堆栈跟踪的核心组件，它不仅用于在发生 panic 时打印错误信息，还提供了更细粒度的控制和扩展能力，例如支持 CGO 堆栈跟踪和程序化访问堆栈信息。这对于调试、性能分析以及理解 Go 程序的执行流程至关重要。它与第一部分共同构成了 Go 语言强大的堆栈跟踪机制。

Prompt: 
```
这是路径为go/src/runtime/traceback.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
We printed the whole stack.
			return n
		}
		// Clone the unwinder and figure out how many frames are left. This
		// count will include any logical frames already printed for u's current
		// physical frame.
		u2 := u
		remaining, _ := traceback2(&u, showRuntime, maxInt, 0)
		elide := remaining - lastN - tracebackOuterFrames
		if elide > 0 {
			print("...", elide, " frames elided...\n")
			traceback2(&u2, showRuntime, lastN+elide, tracebackOuterFrames)
		} else if elide <= 0 {
			// There are tracebackOuterFrames or fewer frames left to print.
			// Just print the rest of the stack.
			traceback2(&u2, showRuntime, lastN, tracebackOuterFrames)
		}
		return n
	}
	// By default, omits runtime frames. If that means we print nothing at all,
	// repeat forcing all frames printed.
	if tracebackWithRuntime(false) == 0 {
		tracebackWithRuntime(true)
	}
	printcreatedby(gp)

	if gp.ancestors == nil {
		return
	}
	for _, ancestor := range *gp.ancestors {
		printAncestorTraceback(ancestor)
	}
}

// traceback2 prints a stack trace starting at u. It skips the first "skip"
// logical frames, after which it prints at most "max" logical frames. It
// returns n, which is the number of logical frames skipped and printed, and
// lastN, which is the number of logical frames skipped or printed just in the
// physical frame that u references.
func traceback2(u *unwinder, showRuntime bool, skip, max int) (n, lastN int) {
	// commitFrame commits to a logical frame and returns whether this frame
	// should be printed and whether iteration should stop.
	commitFrame := func() (pr, stop bool) {
		if skip == 0 && max == 0 {
			// Stop
			return false, true
		}
		n++
		lastN++
		if skip > 0 {
			// Skip
			skip--
			return false, false
		}
		// Print
		max--
		return true, false
	}

	gp := u.g.ptr()
	level, _, _ := gotraceback()
	var cgoBuf [32]uintptr
	for ; u.valid(); u.next() {
		lastN = 0
		f := u.frame.fn
		for iu, uf := newInlineUnwinder(f, u.symPC()); uf.valid(); uf = iu.next(uf) {
			sf := iu.srcFunc(uf)
			callee := u.calleeFuncID
			u.calleeFuncID = sf.funcID
			if !(showRuntime || showframe(sf, gp, n == 0, callee)) {
				continue
			}

			if pr, stop := commitFrame(); stop {
				return
			} else if !pr {
				continue
			}

			name := sf.name()
			file, line := iu.fileLine(uf)
			// Print during crash.
			//	main(0x1, 0x2, 0x3)
			//		/home/rsc/go/src/runtime/x.go:23 +0xf
			//
			printFuncName(name)
			print("(")
			if iu.isInlined(uf) {
				print("...")
			} else {
				argp := unsafe.Pointer(u.frame.argp)
				printArgs(f, argp, u.symPC())
			}
			print(")\n")
			print("\t", file, ":", line)
			if !iu.isInlined(uf) {
				if u.frame.pc > f.entry() {
					print(" +", hex(u.frame.pc-f.entry()))
				}
				if gp.m != nil && gp.m.throwing >= throwTypeRuntime && gp == gp.m.curg || level >= 2 {
					print(" fp=", hex(u.frame.fp), " sp=", hex(u.frame.sp), " pc=", hex(u.frame.pc))
				}
			}
			print("\n")
		}

		// Print cgo frames.
		if cgoN := u.cgoCallers(cgoBuf[:]); cgoN > 0 {
			var arg cgoSymbolizerArg
			anySymbolized := false
			stop := false
			for _, pc := range cgoBuf[:cgoN] {
				if cgoSymbolizer == nil {
					if pr, stop := commitFrame(); stop {
						break
					} else if pr {
						print("non-Go function at pc=", hex(pc), "\n")
					}
				} else {
					stop = printOneCgoTraceback(pc, commitFrame, &arg)
					anySymbolized = true
					if stop {
						break
					}
				}
			}
			if anySymbolized {
				// Free symbolization state.
				arg.pc = 0
				callCgoSymbolizer(&arg)
			}
			if stop {
				return
			}
		}
	}
	return n, 0
}

// printAncestorTraceback prints the traceback of the given ancestor.
// TODO: Unify this with gentraceback and CallersFrames.
func printAncestorTraceback(ancestor ancestorInfo) {
	print("[originating from goroutine ", ancestor.goid, "]:\n")
	for fidx, pc := range ancestor.pcs {
		f := findfunc(pc) // f previously validated
		if showfuncinfo(f.srcFunc(), fidx == 0, abi.FuncIDNormal) {
			printAncestorTracebackFuncInfo(f, pc)
		}
	}
	if len(ancestor.pcs) == tracebackInnerFrames {
		print("...additional frames elided...\n")
	}
	// Show what created goroutine, except main goroutine (goid 1).
	f := findfunc(ancestor.gopc)
	if f.valid() && showfuncinfo(f.srcFunc(), false, abi.FuncIDNormal) && ancestor.goid != 1 {
		// In ancestor mode, we'll already print the goroutine ancestor.
		// Pass 0 for the goid parameter so we don't print it again.
		printcreatedby1(f, ancestor.gopc, 0)
	}
}

// printAncestorTracebackFuncInfo prints the given function info at a given pc
// within an ancestor traceback. The precision of this info is reduced
// due to only have access to the pcs at the time of the caller
// goroutine being created.
func printAncestorTracebackFuncInfo(f funcInfo, pc uintptr) {
	u, uf := newInlineUnwinder(f, pc)
	file, line := u.fileLine(uf)
	printFuncName(u.srcFunc(uf).name())
	print("(...)\n")
	print("\t", file, ":", line)
	if pc > f.entry() {
		print(" +", hex(pc-f.entry()))
	}
	print("\n")
}

// callers should be an internal detail,
// (and is almost identical to Callers),
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/phuslu/log
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname callers
func callers(skip int, pcbuf []uintptr) int {
	sp := sys.GetCallerSP()
	pc := sys.GetCallerPC()
	gp := getg()
	var n int
	systemstack(func() {
		var u unwinder
		u.initAt(pc, sp, 0, gp, unwindSilentErrors)
		n = tracebackPCs(&u, skip, pcbuf)
	})
	return n
}

func gcallers(gp *g, skip int, pcbuf []uintptr) int {
	var u unwinder
	u.init(gp, unwindSilentErrors)
	return tracebackPCs(&u, skip, pcbuf)
}

// showframe reports whether the frame with the given characteristics should
// be printed during a traceback.
func showframe(sf srcFunc, gp *g, firstFrame bool, calleeID abi.FuncID) bool {
	mp := getg().m
	if mp.throwing >= throwTypeRuntime && gp != nil && (gp == mp.curg || gp == mp.caughtsig.ptr()) {
		return true
	}
	return showfuncinfo(sf, firstFrame, calleeID)
}

// showfuncinfo reports whether a function with the given characteristics should
// be printed during a traceback.
func showfuncinfo(sf srcFunc, firstFrame bool, calleeID abi.FuncID) bool {
	level, _, _ := gotraceback()
	if level > 1 {
		// Show all frames.
		return true
	}

	if sf.funcID == abi.FuncIDWrapper && elideWrapperCalling(calleeID) {
		return false
	}

	name := sf.name()

	// Special case: always show runtime.gopanic frame
	// in the middle of a stack trace, so that we can
	// see the boundary between ordinary code and
	// panic-induced deferred code.
	// See golang.org/issue/5832.
	if name == "runtime.gopanic" && !firstFrame {
		return true
	}

	return bytealg.IndexByteString(name, '.') >= 0 && (!stringslite.HasPrefix(name, "runtime.") || isExportedRuntime(name))
}

// isExportedRuntime reports whether name is an exported runtime function.
// It is only for runtime functions, so ASCII A-Z is fine.
func isExportedRuntime(name string) bool {
	// Check and remove package qualifier.
	name, found := stringslite.CutPrefix(name, "runtime.")
	if !found {
		return false
	}
	rcvr := ""

	// Extract receiver type, if any.
	// For example, runtime.(*Func).Entry
	i := len(name) - 1
	for i >= 0 && name[i] != '.' {
		i--
	}
	if i >= 0 {
		rcvr = name[:i]
		name = name[i+1:]
		// Remove parentheses and star for pointer receivers.
		if len(rcvr) >= 3 && rcvr[0] == '(' && rcvr[1] == '*' && rcvr[len(rcvr)-1] == ')' {
			rcvr = rcvr[2 : len(rcvr)-1]
		}
	}

	// Exported functions and exported methods on exported types.
	return len(name) > 0 && 'A' <= name[0] && name[0] <= 'Z' && (len(rcvr) == 0 || 'A' <= rcvr[0] && rcvr[0] <= 'Z')
}

// elideWrapperCalling reports whether a wrapper function that called
// function id should be elided from stack traces.
func elideWrapperCalling(id abi.FuncID) bool {
	// If the wrapper called a panic function instead of the
	// wrapped function, we want to include it in stacks.
	return !(id == abi.FuncID_gopanic || id == abi.FuncID_sigpanic || id == abi.FuncID_panicwrap)
}

var gStatusStrings = [...]string{
	_Gidle:      "idle",
	_Grunnable:  "runnable",
	_Grunning:   "running",
	_Gsyscall:   "syscall",
	_Gwaiting:   "waiting",
	_Gdead:      "dead",
	_Gcopystack: "copystack",
	_Gpreempted: "preempted",
}

func goroutineheader(gp *g) {
	level, _, _ := gotraceback()

	gpstatus := readgstatus(gp)

	isScan := gpstatus&_Gscan != 0
	gpstatus &^= _Gscan // drop the scan bit

	// Basic string status
	var status string
	if 0 <= gpstatus && gpstatus < uint32(len(gStatusStrings)) {
		status = gStatusStrings[gpstatus]
	} else {
		status = "???"
	}

	// Override.
	if gpstatus == _Gwaiting && gp.waitreason != waitReasonZero {
		status = gp.waitreason.String()
	}

	// approx time the G is blocked, in minutes
	var waitfor int64
	if (gpstatus == _Gwaiting || gpstatus == _Gsyscall) && gp.waitsince != 0 {
		waitfor = (nanotime() - gp.waitsince) / 60e9
	}
	print("goroutine ", gp.goid)
	if gp.m != nil && gp.m.throwing >= throwTypeRuntime && gp == gp.m.curg || level >= 2 {
		print(" gp=", gp)
		if gp.m != nil {
			print(" m=", gp.m.id, " mp=", gp.m)
		} else {
			print(" m=nil")
		}
	}
	print(" [", status)
	if isScan {
		print(" (scan)")
	}
	if waitfor >= 1 {
		print(", ", waitfor, " minutes")
	}
	if gp.lockedm != 0 {
		print(", locked to thread")
	}
	if sg := gp.syncGroup; sg != nil {
		print(", synctest group ", sg.root.goid)
	}
	print("]:\n")
}

func tracebackothers(me *g) {
	level, _, _ := gotraceback()

	// Show the current goroutine first, if we haven't already.
	curgp := getg().m.curg
	if curgp != nil && curgp != me {
		print("\n")
		goroutineheader(curgp)
		traceback(^uintptr(0), ^uintptr(0), 0, curgp)
	}

	// We can't call locking forEachG here because this may be during fatal
	// throw/panic, where locking could be out-of-order or a direct
	// deadlock.
	//
	// Instead, use forEachGRace, which requires no locking. We don't lock
	// against concurrent creation of new Gs, but even with allglock we may
	// miss Gs created after this loop.
	forEachGRace(func(gp *g) {
		if gp == me || gp == curgp || readgstatus(gp) == _Gdead || isSystemGoroutine(gp, false) && level < 2 {
			return
		}
		print("\n")
		goroutineheader(gp)
		// Note: gp.m == getg().m occurs when tracebackothers is called
		// from a signal handler initiated during a systemstack call.
		// The original G is still in the running state, and we want to
		// print its stack.
		if gp.m != getg().m && readgstatus(gp)&^_Gscan == _Grunning {
			print("\tgoroutine running on other thread; stack unavailable\n")
			printcreatedby(gp)
		} else {
			traceback(^uintptr(0), ^uintptr(0), 0, gp)
		}
	})
}

// tracebackHexdump hexdumps part of stk around frame.sp and frame.fp
// for debugging purposes. If the address bad is included in the
// hexdumped range, it will mark it as well.
func tracebackHexdump(stk stack, frame *stkframe, bad uintptr) {
	const expand = 32 * goarch.PtrSize
	const maxExpand = 256 * goarch.PtrSize
	// Start around frame.sp.
	lo, hi := frame.sp, frame.sp
	// Expand to include frame.fp.
	if frame.fp != 0 && frame.fp < lo {
		lo = frame.fp
	}
	if frame.fp != 0 && frame.fp > hi {
		hi = frame.fp
	}
	// Expand a bit more.
	lo, hi = lo-expand, hi+expand
	// But don't go too far from frame.sp.
	if lo < frame.sp-maxExpand {
		lo = frame.sp - maxExpand
	}
	if hi > frame.sp+maxExpand {
		hi = frame.sp + maxExpand
	}
	// And don't go outside the stack bounds.
	if lo < stk.lo {
		lo = stk.lo
	}
	if hi > stk.hi {
		hi = stk.hi
	}

	// Print the hex dump.
	print("stack: frame={sp:", hex(frame.sp), ", fp:", hex(frame.fp), "} stack=[", hex(stk.lo), ",", hex(stk.hi), ")\n")
	hexdumpWords(lo, hi, func(p uintptr) byte {
		switch p {
		case frame.fp:
			return '>'
		case frame.sp:
			return '<'
		case bad:
			return '!'
		}
		return 0
	})
}

// isSystemGoroutine reports whether the goroutine g must be omitted
// in stack dumps and deadlock detector. This is any goroutine that
// starts at a runtime.* entry point, except for runtime.main,
// runtime.handleAsyncEvent (wasm only) and sometimes runtime.runfinq.
//
// If fixed is true, any goroutine that can vary between user and
// system (that is, the finalizer goroutine) is considered a user
// goroutine.
func isSystemGoroutine(gp *g, fixed bool) bool {
	// Keep this in sync with internal/trace.IsSystemGoroutine.
	f := findfunc(gp.startpc)
	if !f.valid() {
		return false
	}
	if f.funcID == abi.FuncID_runtime_main || f.funcID == abi.FuncID_corostart || f.funcID == abi.FuncID_handleAsyncEvent {
		return false
	}
	if f.funcID == abi.FuncID_runfinq {
		// We include the finalizer goroutine if it's calling
		// back into user code.
		if fixed {
			// This goroutine can vary. In fixed mode,
			// always consider it a user goroutine.
			return false
		}
		return fingStatus.Load()&fingRunningFinalizer == 0
	}
	return stringslite.HasPrefix(funcname(f), "runtime.")
}

// SetCgoTraceback records three C functions to use to gather
// traceback information from C code and to convert that traceback
// information into symbolic information. These are used when printing
// stack traces for a program that uses cgo.
//
// The traceback and context functions may be called from a signal
// handler, and must therefore use only async-signal safe functions.
// The symbolizer function may be called while the program is
// crashing, and so must be cautious about using memory.  None of the
// functions may call back into Go.
//
// The context function will be called with a single argument, a
// pointer to a struct:
//
//	struct {
//		Context uintptr
//	}
//
// In C syntax, this struct will be
//
//	struct {
//		uintptr_t Context;
//	};
//
// If the Context field is 0, the context function is being called to
// record the current traceback context. It should record in the
// Context field whatever information is needed about the current
// point of execution to later produce a stack trace, probably the
// stack pointer and PC. In this case the context function will be
// called from C code.
//
// If the Context field is not 0, then it is a value returned by a
// previous call to the context function. This case is called when the
// context is no longer needed; that is, when the Go code is returning
// to its C code caller. This permits the context function to release
// any associated resources.
//
// While it would be correct for the context function to record a
// complete a stack trace whenever it is called, and simply copy that
// out in the traceback function, in a typical program the context
// function will be called many times without ever recording a
// traceback for that context. Recording a complete stack trace in a
// call to the context function is likely to be inefficient.
//
// The traceback function will be called with a single argument, a
// pointer to a struct:
//
//	struct {
//		Context    uintptr
//		SigContext uintptr
//		Buf        *uintptr
//		Max        uintptr
//	}
//
// In C syntax, this struct will be
//
//	struct {
//		uintptr_t  Context;
//		uintptr_t  SigContext;
//		uintptr_t* Buf;
//		uintptr_t  Max;
//	};
//
// The Context field will be zero to gather a traceback from the
// current program execution point. In this case, the traceback
// function will be called from C code.
//
// Otherwise Context will be a value previously returned by a call to
// the context function. The traceback function should gather a stack
// trace from that saved point in the program execution. The traceback
// function may be called from an execution thread other than the one
// that recorded the context, but only when the context is known to be
// valid and unchanging. The traceback function may also be called
// deeper in the call stack on the same thread that recorded the
// context. The traceback function may be called multiple times with
// the same Context value; it will usually be appropriate to cache the
// result, if possible, the first time this is called for a specific
// context value.
//
// If the traceback function is called from a signal handler on a Unix
// system, SigContext will be the signal context argument passed to
// the signal handler (a C ucontext_t* cast to uintptr_t). This may be
// used to start tracing at the point where the signal occurred. If
// the traceback function is not called from a signal handler,
// SigContext will be zero.
//
// Buf is where the traceback information should be stored. It should
// be PC values, such that Buf[0] is the PC of the caller, Buf[1] is
// the PC of that function's caller, and so on.  Max is the maximum
// number of entries to store.  The function should store a zero to
// indicate the top of the stack, or that the caller is on a different
// stack, presumably a Go stack.
//
// Unlike runtime.Callers, the PC values returned should, when passed
// to the symbolizer function, return the file/line of the call
// instruction.  No additional subtraction is required or appropriate.
//
// On all platforms, the traceback function is invoked when a call from
// Go to C to Go requests a stack trace. On linux/amd64, linux/ppc64le,
// linux/arm64, and freebsd/amd64, the traceback function is also invoked
// when a signal is received by a thread that is executing a cgo call.
// The traceback function should not make assumptions about when it is
// called, as future versions of Go may make additional calls.
//
// The symbolizer function will be called with a single argument, a
// pointer to a struct:
//
//	struct {
//		PC      uintptr // program counter to fetch information for
//		File    *byte   // file name (NUL terminated)
//		Lineno  uintptr // line number
//		Func    *byte   // function name (NUL terminated)
//		Entry   uintptr // function entry point
//		More    uintptr // set non-zero if more info for this PC
//		Data    uintptr // unused by runtime, available for function
//	}
//
// In C syntax, this struct will be
//
//	struct {
//		uintptr_t PC;
//		char*     File;
//		uintptr_t Lineno;
//		char*     Func;
//		uintptr_t Entry;
//		uintptr_t More;
//		uintptr_t Data;
//	};
//
// The PC field will be a value returned by a call to the traceback
// function.
//
// The first time the function is called for a particular traceback,
// all the fields except PC will be 0. The function should fill in the
// other fields if possible, setting them to 0/nil if the information
// is not available. The Data field may be used to store any useful
// information across calls. The More field should be set to non-zero
// if there is more information for this PC, zero otherwise. If More
// is set non-zero, the function will be called again with the same
// PC, and may return different information (this is intended for use
// with inlined functions). If More is zero, the function will be
// called with the next PC value in the traceback. When the traceback
// is complete, the function will be called once more with PC set to
// zero; this may be used to free any information. Each call will
// leave the fields of the struct set to the same values they had upon
// return, except for the PC field when the More field is zero. The
// function must not keep a copy of the struct pointer between calls.
//
// When calling SetCgoTraceback, the version argument is the version
// number of the structs that the functions expect to receive.
// Currently this must be zero.
//
// The symbolizer function may be nil, in which case the results of
// the traceback function will be displayed as numbers. If the
// traceback function is nil, the symbolizer function will never be
// called. The context function may be nil, in which case the
// traceback function will only be called with the context field set
// to zero.  If the context function is nil, then calls from Go to C
// to Go will not show a traceback for the C portion of the call stack.
//
// SetCgoTraceback should be called only once, ideally from an init function.
func SetCgoTraceback(version int, traceback, context, symbolizer unsafe.Pointer) {
	if version != 0 {
		panic("unsupported version")
	}

	if cgoTraceback != nil && cgoTraceback != traceback ||
		cgoContext != nil && cgoContext != context ||
		cgoSymbolizer != nil && cgoSymbolizer != symbolizer {
		panic("call SetCgoTraceback only once")
	}

	cgoTraceback = traceback
	cgoContext = context
	cgoSymbolizer = symbolizer

	// The context function is called when a C function calls a Go
	// function. As such it is only called by C code in runtime/cgo.
	if _cgo_set_context_function != nil {
		cgocall(_cgo_set_context_function, context)
	}
}

var cgoTraceback unsafe.Pointer
var cgoContext unsafe.Pointer
var cgoSymbolizer unsafe.Pointer

// cgoTracebackArg is the type passed to cgoTraceback.
type cgoTracebackArg struct {
	context    uintptr
	sigContext uintptr
	buf        *uintptr
	max        uintptr
}

// cgoContextArg is the type passed to the context function.
type cgoContextArg struct {
	context uintptr
}

// cgoSymbolizerArg is the type passed to cgoSymbolizer.
type cgoSymbolizerArg struct {
	pc       uintptr
	file     *byte
	lineno   uintptr
	funcName *byte
	entry    uintptr
	more     uintptr
	data     uintptr
}

// printCgoTraceback prints a traceback of callers.
func printCgoTraceback(callers *cgoCallers) {
	if cgoSymbolizer == nil {
		for _, c := range callers {
			if c == 0 {
				break
			}
			print("non-Go function at pc=", hex(c), "\n")
		}
		return
	}

	commitFrame := func() (pr, stop bool) { return true, false }
	var arg cgoSymbolizerArg
	for _, c := range callers {
		if c == 0 {
			break
		}
		printOneCgoTraceback(c, commitFrame, &arg)
	}
	arg.pc = 0
	callCgoSymbolizer(&arg)
}

// printOneCgoTraceback prints the traceback of a single cgo caller.
// This can print more than one line because of inlining.
// It returns the "stop" result of commitFrame.
func printOneCgoTraceback(pc uintptr, commitFrame func() (pr, stop bool), arg *cgoSymbolizerArg) bool {
	arg.pc = pc
	for {
		if pr, stop := commitFrame(); stop {
			return true
		} else if !pr {
			continue
		}

		callCgoSymbolizer(arg)
		if arg.funcName != nil {
			// Note that we don't print any argument
			// information here, not even parentheses.
			// The symbolizer must add that if appropriate.
			println(gostringnocopy(arg.funcName))
		} else {
			println("non-Go function")
		}
		print("\t")
		if arg.file != nil {
			print(gostringnocopy(arg.file), ":", arg.lineno, " ")
		}
		print("pc=", hex(pc), "\n")
		if arg.more == 0 {
			return false
		}
	}
}

// callCgoSymbolizer calls the cgoSymbolizer function.
func callCgoSymbolizer(arg *cgoSymbolizerArg) {
	call := cgocall
	if panicking.Load() > 0 || getg().m.curg != getg() {
		// We do not want to call into the scheduler when panicking
		// or when on the system stack.
		call = asmcgocall
	}
	if msanenabled {
		msanwrite(unsafe.Pointer(arg), unsafe.Sizeof(cgoSymbolizerArg{}))
	}
	if asanenabled {
		asanwrite(unsafe.Pointer(arg), unsafe.Sizeof(cgoSymbolizerArg{}))
	}
	call(cgoSymbolizer, noescape(unsafe.Pointer(arg)))
}

// cgoContextPCs gets the PC values from a cgo traceback.
func cgoContextPCs(ctxt uintptr, buf []uintptr) {
	if cgoTraceback == nil {
		return
	}
	call := cgocall
	if panicking.Load() > 0 || getg().m.curg != getg() {
		// We do not want to call into the scheduler when panicking
		// or when on the system stack.
		call = asmcgocall
	}
	arg := cgoTracebackArg{
		context: ctxt,
		buf:     (*uintptr)(noescape(unsafe.Pointer(&buf[0]))),
		max:     uintptr(len(buf)),
	}
	if msanenabled {
		msanwrite(unsafe.Pointer(&arg), unsafe.Sizeof(arg))
	}
	if asanenabled {
		asanwrite(unsafe.Pointer(&arg), unsafe.Sizeof(arg))
	}
	call(cgoTraceback, noescape(unsafe.Pointer(&arg)))
}

"""




```