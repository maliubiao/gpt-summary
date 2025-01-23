Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable keywords and patterns. I'd look for:

* **Package Name:** `package runtime` - This immediately tells me it's core Go runtime code, likely dealing with low-level system interactions.
* **Imports:** `internal/abi`, `internal/runtime/sys`, `unsafe` - These confirm the low-level nature and hint at interaction with the operating system and memory manipulation.
* **Function Names:** `preventErrorDialogs`, `enableWER`, `initExceptionHandler`, `isAbort`, `isgoexception`, `sigtrampgo`, `exceptionhandler`, `sehhandler`, `firstcontinuehandler`, `lastcontinuehandler`, `winthrow`, `sigpanic`, `crash`, `dieFromException`. These names strongly suggest signal handling, exception management, and error reporting.
* **Constants:**  Names like `_SEM_FAILCRITICALERRORS`, `_WER_FAULT_REPORTING_NO_UI`, `_EXCEPTION_ACCESS_VIOLATION`, etc., point towards Windows-specific error codes and flags.
* **Assembly Directives:** Comments referencing `.s` files (`sys_windows_386.s`, etc.) and function names like `exceptiontramp` strongly indicate interaction with assembly code for low-level operations.
* **`stdcall` keyword:**  This is a very strong indicator of interaction with Windows API calls.
* **`go:nosplit` pragma:** This suggests functions where stack growth is undesirable or potentially dangerous, often related to critical error handling.
* **Struct Names:** `exceptionrecord`, `context`, `exceptionpointers` - These are standard Windows exception handling data structures.

**2. Grouping Functionality by Purpose:**

As I identify keywords and functions, I start grouping them based on their apparent purpose.

* **Error Reporting/Dialog Suppression:** `preventErrorDialogs`, `enableWER`. The constants used confirm this.
* **Exception Handling Setup:** `initExceptionHandler`, `exceptiontramp`, `firstcontinuetramp`, `lastcontinuetramp`, `sehtramp`, `sigresume`. The interaction with `_AddVectoredExceptionHandler`, `_SetUnhandledExceptionFilter`, and the assembly trampolines solidifies this.
* **Exception Classification:** `isAbort`, `isgoexception`. These help determine the nature and origin of an exception.
* **Signal Handling (Go Specific):** `sigtrampgo`, `exceptionhandler`, `sigpanic`. These functions seem to bridge the gap between Windows exceptions and Go's panic mechanism.
* **SEH Handling:** `sehhandler`. This suggests interaction with Windows Structured Exception Handling.
* **Continue Handlers:** `firstcontinuehandler`, `lastcontinuehandler`. These appear to be part of the exception handling chain.
* **Termination/Crash Handling:** `winthrow`, `crash`, `dieFromException`. These functions deal with the final stages of error handling, potentially terminating the program.

**3. Inferring Go Feature Implementation:**

Based on the grouped functionalities, I can start inferring which Go features this code implements.

* **Panic/Recover:** The presence of `sigpanic` and the handling of specific exception codes like `_EXCEPTION_ACCESS_VIOLATION` strongly suggest this code is involved in implementing Go's `panic` and potentially the underlying mechanisms for `recover`.
* **Error Handling on Windows:** The focus on Windows API calls and exception handling structures clearly indicates the code is responsible for handling runtime errors and signals within Go programs running on Windows.
* **Integration with Windows Exception Handling:** The interaction with VEH and SEH confirms the integration with Windows' native exception handling mechanisms.

**4. Code Reasoning and Flow:**

Now, I'd try to trace the flow of execution for different scenarios.

* **A Go program crashes with a segmentation fault:**  I'd follow the likely path: CPU generates an exception, Windows VEH catches it, `exceptiontramp` is called, which likely calls `sigtrampgo`, then `exceptionhandler`. `isgoexception` checks if it's a Go-related issue. If so, `sigpanic` is called to trigger the Go panic mechanism.
* **A Go program calls `runtime.abort()`:** `isAbort` checks for this, and the code likely bypasses the normal panic flow and calls `winthrow` directly for a more immediate crash.
* **Handling exceptions originating from non-Go code:** The `sehhandler` and checks in `lastcontinuehandler` suggest a mechanism to differentiate between Go and non-Go exceptions.

**5. Generating Examples and Scenarios:**

To illustrate the functionality, I'd think of simple Go code examples that would trigger the different parts of this code.

* **Segmentation fault:** A simple nil pointer dereference.
* **Division by zero:**  An integer division by zero.
* **Explicit `runtime.abort()`:**  A direct call to `runtime.abort()`.

**6. Identifying Potential Pitfalls:**

I'd consider what could go wrong or what developers might misunderstand.

* **Mixing Go and Windows exception handling:**  The complexity of the VEH/SEH interaction could be confusing. Developers might try to use Windows exception handling for Go panics directly, which isn't the intended way.
* **Understanding `go:nosplit`:** Developers might not fully grasp the implications of `go:nosplit` and why it's necessary in certain critical error-handling paths.

**7. Structuring the Answer:**

Finally, I'd organize my findings into a clear and structured answer, covering:

* **Overall Functionality:** A high-level summary of the code's purpose.
* **Specific Functions:** A breakdown of each key function and its role.
* **Go Feature Implementation:** Linking the code to specific Go language features.
* **Code Examples:**  Illustrative Go code snippets.
* **Assumptions and Input/Output (if applicable):**  Clarifying any assumptions made during the analysis.
* **Command-Line Arguments (if applicable):** Describing any relevant command-line flags.
* **Common Mistakes:**  Highlighting potential pitfalls for developers.

This iterative process of scanning, grouping, inferring, reasoning, and generating examples helps to comprehensively understand and explain the functionality of the given Go code snippet.
这段代码是 Go 语言 `runtime` 包中专门为 Windows 操作系统处理信号和异常的部分。它的核心功能是将 Windows 的异常处理机制（如 Structured Exception Handling, SEH 和 Vectored Exception Handling, VEH）与 Go 语言的 panic 机制连接起来，从而在发生错误时能够优雅地处理并报告。

以下是代码的主要功能点：

**1. 阻止错误对话框显示 (`preventErrorDialogs`)：**

   -  通过调用 Windows API `GetErrorMode` 和 `SetErrorMode`，禁用一些可能弹出的系统错误对话框，例如程序崩溃时的 "应用程序发生错误" 对话框。这可以防止用户在程序崩溃时看到系统弹窗，而是让 Go 运行时来处理错误并打印更友好的信息。
   -  同时，它也禁用 Windows 错误报告 (WER) 的用户界面，即使 WER 功能被启用，也不会弹出收集错误信息的窗口。

**2. 重新启用 Windows 错误报告 (`enableWER`)：**

   -  这个函数与 `preventErrorDialogs` 相对应，允许重新启用 Windows 的错误报告功能，但仍然会阻止错误报告的用户界面弹出。这通常在需要收集崩溃信息但又不希望打扰用户的情况下使用。

**3. 初始化异常处理器 (`initExceptionHandler`)：**

   -  通过调用 Windows API `AddVectoredExceptionHandler` 注册一个 VEH 处理函数 `exceptiontramp`。VEH 是一种先于 SEH 执行的异常处理机制，它允许在异常发生时先执行一些自定义的处理逻辑。
   -  对于 386 架构，它使用 `SetUnhandledExceptionFilter` 注册 `lastcontinuetramp` 作为未处理异常的过滤器。
   -  对于其他架构（如 AMD64），它使用 `AddVectoredContinueHandler` 注册 `firstcontinuetramp` 和 `lastcontinuetramp` 作为 Vectored Continue Handlers。这些处理程序在异常处理完成后或搜索合适的异常处理程序时被调用。

**4. 判断是否是 `runtime.abort()` 导致的异常 (`isAbort`)：**

   -  检查异常发生时的指令指针 (IP) 是否指向 `runtime.abort` 函数调用后的位置。Go 的 `runtime.abort()` 函数会故意触发一个断点异常来立即终止程序。

**5. 判断异常是否应该被转换为 Go 的 panic (`isgoexception`)：**

   -  检查异常发生时的指令指针是否在 Go 程序的代码段内（`firstmoduledata.text` 到 `firstmoduledata.etext`）。这确保了只处理由 Go 代码引起的异常。
   -  检查异常代码是否是 Go 运行时需要处理的特定 Windows 异常代码，例如访问违例 (`_EXCEPTION_ACCESS_VIOLATION`)、除零错误 (`_EXCEPTION_INT_DIVIDE_BY_ZERO`) 等。

**6. 获取当前 Goroutine (`sigFetchG`, `sigFetchGSafe`)：**

   -  这些函数用于在信号处理上下文中安全地获取当前的 Goroutine。由于信号处理函数可能在任何线程的任何时刻被调用，因此需要一种安全的方式来访问 Goroutine 的信息。`sigFetchGSafe` 是一个更安全的版本，在 TLS 没有设置的情况下不会 panic，这主要用于 386 架构。

**7. 异常处理入口点 (`sigtrampgo`)：**

   -  这是一个由汇编代码 `sigtramp` 调用的 Go 函数，作为 VEH 处理程序的入口点。
   -  它根据异常的类型调用不同的 Go 异常处理函数 (`exceptionhandler`, `firstcontinuehandler`, `lastcontinuehandler`)。
   -  它还处理在 g0 栈上运行的情况，以避免因栈溢出而导致的问题。

**8. 主要的异常处理逻辑 (`exceptionhandler`)：**

   -  这是处理 Windows 异常的核心函数。
   -  它首先调用 `isgoexception` 判断是否是需要 Go 处理的异常。
   -  如果异常是由 `runtime.abort()` 触发或者在不允许安全调用 `sigpanic` 的情况下（例如栈溢出），则调用 `winthrow` 直接终止程序。
   -  否则，它会将异常信息（异常代码、地址等）存储到当前 Goroutine 的上下文中，并将程序计数器 (IP) 设置为 `sigpanic0` 函数的地址，从而触发 Go 的 panic 机制。

**9. SEH 处理函数 (`sehhandler`)：**

   -  当 VEH 处理程序没有处理异常时，SEH 处理程序会被调用。
   -  这个函数的主要目的是在异常发生在非 g0 栈的 Goroutine 中时，手动展开栈帧，以便让 Windows 的 SEH 机制能够正确地找到合适的异常处理程序或最终调用未处理异常过滤器。

**10. Continue Handlers (`firstcontinuehandler`, `lastcontinuehandler`)：**

   -  这些处理程序在异常处理链中被调用。
   -  `firstcontinuehandler` 用于在 `exceptionhandler` 已经处理了异常后，阻止 Windows 继续搜索其他处理程序。
   -  `lastcontinuehandler` 作为最后的手段，当 Go 运行时无法处理异常时被调用。它会打印崩溃信息并退出程序。它还会区分 Go 程序本身引发的异常和作为 DLL/Archive 被加载时外部程序引发的异常。

**11. 抛出 Windows 异常 (`winthrow`)：**

   -  这个函数在确定无法通过 Go 的 panic 机制处理异常时被调用。
   -  它负责打印详细的异常信息，包括异常代码、地址、程序计数器等。
   -  如果 `gotraceback()` 返回需要打印栈跟踪，则会调用 `tracebacktrap` 和 `tracebackothers` 打印栈信息。
   -  最后，如果 `docrash` 为 true，则调用 `dieFromException` 触发一个无法被处理的异常来强制终止程序。

**12. 触发 Go 的 panic (`sigpanic`)：**

   -  这个函数根据 Goroutine 中存储的异常信息来触发相应的 Go panic。
   -  它会根据不同的异常代码调用不同的 panic 函数，例如 `panicmem` (内存访问错误), `panicdivide` (除零错误), `panicoverflow` (算术溢出), `panicfloat` (浮点数异常)。

**13. 强制程序崩溃 (`crash`, `dieFromException`)：**

   -  `crash` 函数会调用 `dieFromException`，后者会调用 Windows API `RaiseFailFastException` 抛出一个无法被处理的异常，从而确保程序以预期的退出状态终止。

**14. 未实现的信号处理相关函数 (`initsig`, `sigenable`, `sigdisable`, `sigignore`, `signame`)：**

   -  这些函数在 Windows 上没有实际的实现，因为 Windows 的信号处理机制与 Unix-like 系统有很大不同。Go 在 Windows 上主要依赖异常处理机制。

**总结来说，这段代码实现了 Go 语言在 Windows 上的异常处理和 panic 机制的底层支持。它拦截 Windows 的异常，判断是否是 Go 代码引起的，如果是，则将其转换为 Go 的 panic，否则采取相应的措施（例如打印错误信息或终止程序）。**

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"runtime"
)

func main() {
	// 示例 1: 除零错误
	a := 10
	b := 0
	// 当执行到下一行时，会触发一个 Windows 的 _EXCEPTION_INT_DIVIDE_BY_ZERO 异常
	// runtime/signal_windows.go 中的代码会将此异常转换为 Go 的 panic
	_ = a / b
	fmt.Println("这行代码不会被执行")
}
```

**假设的输入与输出：**

运行上述代码，在 Windows 系统上，你会看到类似以下的输出：

```
panic: integer divide by zero

goroutine 1 [running]:
main.main()
        /path/to/your/file.go:11 +0x29
exit status 2
```

**推理过程：**

1. 当执行 `a / b` 时，由于 `b` 为 0，CPU 会产生一个 `_EXCEPTION_INT_DIVIDE_BY_ZERO` 异常。
2. Windows 的 VEH 机制会捕获到这个异常，并执行在 `runtime/signal_windows.go` 中注册的 `exceptiontramp` (汇编代码)。
3. `exceptiontramp` 会调用 `sigtrampgo`。
4. `sigtrampgo` 会根据异常类型调用 `exceptionhandler`。
5. `exceptionhandler` 会调用 `isgoexception`，判断异常是否发生在 Go 代码中（是）。
6. `exceptionhandler` 会将异常信息存储到当前 Goroutine 的上下文中，并将程序计数器设置为 `sigpanic0`。
7. Go 的调度器会执行到 `sigpanic` 函数。
8. `sigpanic` 会根据异常代码 `_EXCEPTION_INT_DIVIDE_BY_ZERO` 调用 `panicdivide()`。
9. `panicdivide()` 会创建一个包含 "integer divide by zero" 信息的 panic。
10. Go 的 panic 处理机制会开始栈展开，最终打印出 panic 信息和栈跟踪。

**使用者易犯错的点：**

在一般 Go 语言开发中，开发者通常不需要直接与 `runtime/signal_windows.go` 交互。但是，理解其背后的机制有助于理解以下几点：

1. **不要尝试直接捕获 Windows 异常来处理 Go 的 panic。** Go 有自己的 panic 和 recover 机制，应该使用 Go 提供的方式来处理错误。直接使用 Windows 的异常处理机制可能会导致不可预测的行为。

2. **理解 Windows 和 Unix-like 系统在信号处理上的差异。**  在编写跨平台代码时，需要注意信号处理机制的不同。例如，在 Unix-like 系统上常用的 `signal` 包在 Windows 上的行为可能不同，或者根本不适用。Go 在 Windows 上更多地依赖异常处理来实现类似的功能。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `os` 和 `flag` 等包中。 然而，一些环境变量可能会影响这段代码的行为，例如：

*   **`GOTRACEBACK` 环境变量：**  这个环境变量会影响 `gotraceback()` 函数的返回值，从而控制在发生 panic 或异常时是否打印栈跟踪信息。

**总结：**

`runtime/signal_windows.go` 是 Go 运行时在 Windows 上进行底层错误处理的关键部分，它负责将 Windows 的异常转换为 Go 的 panic，并提供了阻止错误对话框和控制崩溃行为的功能。理解这段代码有助于更深入地理解 Go 在 Windows 上的运行机制。

### 提示词
```
这是路径为go/src/runtime/signal_windows.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/sys"
	"unsafe"
)

const (
	_SEM_FAILCRITICALERRORS = 0x0001
	_SEM_NOGPFAULTERRORBOX  = 0x0002
	_SEM_NOOPENFILEERRORBOX = 0x8000

	_WER_FAULT_REPORTING_NO_UI = 0x0020
)

func preventErrorDialogs() {
	errormode := stdcall0(_GetErrorMode)
	stdcall1(_SetErrorMode, errormode|_SEM_FAILCRITICALERRORS|_SEM_NOGPFAULTERRORBOX|_SEM_NOOPENFILEERRORBOX)

	// Disable WER fault reporting UI.
	// Do this even if WER is disabled as a whole,
	// as WER might be enabled later with setTraceback("wer")
	// and we still want the fault reporting UI to be disabled if this happens.
	var werflags uintptr
	stdcall2(_WerGetFlags, currentProcess, uintptr(unsafe.Pointer(&werflags)))
	stdcall1(_WerSetFlags, werflags|_WER_FAULT_REPORTING_NO_UI)
}

// enableWER re-enables Windows error reporting without fault reporting UI.
func enableWER() {
	// re-enable Windows Error Reporting
	errormode := stdcall0(_GetErrorMode)
	if errormode&_SEM_NOGPFAULTERRORBOX != 0 {
		stdcall1(_SetErrorMode, errormode^_SEM_NOGPFAULTERRORBOX)
	}
}

// in sys_windows_386.s, sys_windows_amd64.s, sys_windows_arm.s, and sys_windows_arm64.s
func exceptiontramp()
func firstcontinuetramp()
func lastcontinuetramp()
func sehtramp()
func sigresume()

func initExceptionHandler() {
	stdcall2(_AddVectoredExceptionHandler, 1, abi.FuncPCABI0(exceptiontramp))
	if GOARCH == "386" {
		// use SetUnhandledExceptionFilter for windows-386.
		// note: SetUnhandledExceptionFilter handler won't be called, if debugging.
		stdcall1(_SetUnhandledExceptionFilter, abi.FuncPCABI0(lastcontinuetramp))
	} else {
		stdcall2(_AddVectoredContinueHandler, 1, abi.FuncPCABI0(firstcontinuetramp))
		stdcall2(_AddVectoredContinueHandler, 0, abi.FuncPCABI0(lastcontinuetramp))
	}
}

// isAbort returns true, if context r describes exception raised
// by calling runtime.abort function.
//
//go:nosplit
func isAbort(r *context) bool {
	pc := r.ip()
	if GOARCH == "386" || GOARCH == "amd64" || GOARCH == "arm" {
		// In the case of an abort, the exception IP is one byte after
		// the INT3 (this differs from UNIX OSes). Note that on ARM,
		// this means that the exception IP is no longer aligned.
		pc--
	}
	return isAbortPC(pc)
}

// isgoexception reports whether this exception should be translated
// into a Go panic or throw.
//
// It is nosplit to avoid growing the stack in case we're aborting
// because of a stack overflow.
//
//go:nosplit
func isgoexception(info *exceptionrecord, r *context) bool {
	// Only handle exception if executing instructions in Go binary
	// (not Windows library code).
	// TODO(mwhudson): needs to loop to support shared libs
	if r.ip() < firstmoduledata.text || firstmoduledata.etext < r.ip() {
		return false
	}

	// Go will only handle some exceptions.
	switch info.exceptioncode {
	default:
		return false
	case _EXCEPTION_ACCESS_VIOLATION:
	case _EXCEPTION_IN_PAGE_ERROR:
	case _EXCEPTION_INT_DIVIDE_BY_ZERO:
	case _EXCEPTION_INT_OVERFLOW:
	case _EXCEPTION_FLT_DENORMAL_OPERAND:
	case _EXCEPTION_FLT_DIVIDE_BY_ZERO:
	case _EXCEPTION_FLT_INEXACT_RESULT:
	case _EXCEPTION_FLT_OVERFLOW:
	case _EXCEPTION_FLT_UNDERFLOW:
	case _EXCEPTION_BREAKPOINT:
	case _EXCEPTION_ILLEGAL_INSTRUCTION: // breakpoint arrives this way on arm64
	}
	return true
}

const (
	callbackVEH = iota
	callbackFirstVCH
	callbackLastVCH
)

// sigFetchGSafe is like getg() but without panicking
// when TLS is not set.
// Only implemented on windows/386, which is the only
// arch that loads TLS when calling getg(). Others
// use a dedicated register.
func sigFetchGSafe() *g

func sigFetchG() *g {
	if GOARCH == "386" {
		return sigFetchGSafe()
	}
	return getg()
}

// sigtrampgo is called from the exception handler function, sigtramp,
// written in assembly code.
// Return EXCEPTION_CONTINUE_EXECUTION if the exception is handled,
// else return EXCEPTION_CONTINUE_SEARCH.
//
// It is nosplit for the same reason as exceptionhandler.
//
//go:nosplit
func sigtrampgo(ep *exceptionpointers, kind int) int32 {
	gp := sigFetchG()
	if gp == nil {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	var fn func(info *exceptionrecord, r *context, gp *g) int32
	switch kind {
	case callbackVEH:
		fn = exceptionhandler
	case callbackFirstVCH:
		fn = firstcontinuehandler
	case callbackLastVCH:
		fn = lastcontinuehandler
	default:
		throw("unknown sigtramp callback")
	}

	// Check if we are running on g0 stack, and if we are,
	// call fn directly instead of creating the closure.
	// for the systemstack argument.
	//
	// A closure can't be marked as nosplit, so it might
	// call morestack if we are at the g0 stack limit.
	// If that happens, the runtime will call abort
	// and end up in sigtrampgo again.
	// TODO: revisit this workaround if/when closures
	// can be compiled as nosplit.
	//
	// Note that this scenario should only occur on
	// TestG0StackOverflow. Any other occurrence should
	// be treated as a bug.
	var ret int32
	if gp != gp.m.g0 {
		systemstack(func() {
			ret = fn(ep.record, ep.context, gp)
		})
	} else {
		ret = fn(ep.record, ep.context, gp)
	}
	if ret == _EXCEPTION_CONTINUE_SEARCH {
		return ret
	}

	// Check if we need to set up the control flow guard workaround.
	// On Windows, the stack pointer in the context must lie within
	// system stack limits when we resume from exception.
	// Store the resume SP and PC in alternate registers
	// and return to sigresume on the g0 stack.
	// sigresume makes no use of the stack at all,
	// loading SP from RX and jumping to RY, being RX and RY two scratch registers.
	// Note that blindly smashing RX and RY is only safe because we know sigpanic
	// will not actually return to the original frame, so the registers
	// are effectively dead. But this does mean we can't use the
	// same mechanism for async preemption.
	if ep.context.ip() == abi.FuncPCABI0(sigresume) {
		// sigresume has already been set up by a previous exception.
		return ret
	}
	prepareContextForSigResume(ep.context)
	ep.context.set_sp(gp.m.g0.sched.sp)
	ep.context.set_ip(abi.FuncPCABI0(sigresume))
	return ret
}

// Called by sigtramp from Windows VEH handler.
// Return value signals whether the exception has been handled (EXCEPTION_CONTINUE_EXECUTION)
// or should be made available to other handlers in the chain (EXCEPTION_CONTINUE_SEARCH).
//
// This is nosplit to avoid growing the stack until we've checked for
// _EXCEPTION_BREAKPOINT, which is raised by abort() if we overflow the g0 stack.
//
//go:nosplit
func exceptionhandler(info *exceptionrecord, r *context, gp *g) int32 {
	if !isgoexception(info, r) {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	if gp.throwsplit || isAbort(r) {
		// We can't safely sigpanic because it may grow the stack.
		// Or this is a call to abort.
		// Don't go through any more of the Windows handler chain.
		// Crash now.
		winthrow(info, r, gp)
	}

	// After this point, it is safe to grow the stack.

	// Make it look like a call to the signal func.
	// Have to pass arguments out of band since
	// augmenting the stack frame would break
	// the unwinding code.
	gp.sig = info.exceptioncode
	gp.sigcode0 = info.exceptioninformation[0]
	gp.sigcode1 = info.exceptioninformation[1]
	gp.sigpc = r.ip()

	// Only push runtime·sigpanic if r.ip() != 0.
	// If r.ip() == 0, probably panicked because of a
	// call to a nil func. Not pushing that onto sp will
	// make the trace look like a call to runtime·sigpanic instead.
	// (Otherwise the trace will end at runtime·sigpanic and we
	// won't get to see who faulted.)
	// Also don't push a sigpanic frame if the faulting PC
	// is the entry of asyncPreempt. In this case, we suspended
	// the thread right between the fault and the exception handler
	// starting to run, and we have pushed an asyncPreempt call.
	// The exception is not from asyncPreempt, so not to push a
	// sigpanic call to make it look like that. Instead, just
	// overwrite the PC. (See issue #35773)
	if r.ip() != 0 && r.ip() != abi.FuncPCABI0(asyncPreempt) {
		sp := unsafe.Pointer(r.sp())
		delta := uintptr(sys.StackAlign)
		sp = add(sp, -delta)
		r.set_sp(uintptr(sp))
		if usesLR {
			*((*uintptr)(sp)) = r.lr()
			r.set_lr(r.ip())
		} else {
			*((*uintptr)(sp)) = r.ip()
		}
	}
	r.set_ip(abi.FuncPCABI0(sigpanic0))
	return _EXCEPTION_CONTINUE_EXECUTION
}

// sehhandler is reached as part of the SEH chain.
//
// It is nosplit for the same reason as exceptionhandler.
//
//go:nosplit
func sehhandler(_ *exceptionrecord, _ uint64, _ *context, dctxt *_DISPATCHER_CONTEXT) int32 {
	g0 := getg()
	if g0 == nil || g0.m.curg == nil {
		// No g available, nothing to do here.
		return _EXCEPTION_CONTINUE_SEARCH_SEH
	}
	// The Windows SEH machinery will unwind the stack until it finds
	// a frame with a handler for the exception or until the frame is
	// outside the stack boundaries, in which case it will call the
	// UnhandledExceptionFilter. Unfortunately, it doesn't know about
	// the goroutine stack, so it will stop unwinding when it reaches the
	// first frame not running in g0. As a result, neither non-Go exceptions
	// handlers higher up the stack nor UnhandledExceptionFilter will be called.
	//
	// To work around this, manually unwind the stack until the top of the goroutine
	// stack is reached, and then pass the control back to Windows.
	gp := g0.m.curg
	ctxt := dctxt.ctx()
	var base, sp uintptr
	for {
		entry := stdcall3(_RtlLookupFunctionEntry, ctxt.ip(), uintptr(unsafe.Pointer(&base)), 0)
		if entry == 0 {
			break
		}
		stdcall8(_RtlVirtualUnwind, 0, base, ctxt.ip(), entry, uintptr(unsafe.Pointer(ctxt)), 0, uintptr(unsafe.Pointer(&sp)), 0)
		if sp < gp.stack.lo || gp.stack.hi <= sp {
			break
		}
	}
	return _EXCEPTION_CONTINUE_SEARCH_SEH
}

// It seems Windows searches ContinueHandler's list even
// if ExceptionHandler returns EXCEPTION_CONTINUE_EXECUTION.
// firstcontinuehandler will stop that search,
// if exceptionhandler did the same earlier.
//
// It is nosplit for the same reason as exceptionhandler.
//
//go:nosplit
func firstcontinuehandler(info *exceptionrecord, r *context, gp *g) int32 {
	if !isgoexception(info, r) {
		return _EXCEPTION_CONTINUE_SEARCH
	}
	return _EXCEPTION_CONTINUE_EXECUTION
}

// lastcontinuehandler is reached, because runtime cannot handle
// current exception. lastcontinuehandler will print crash info and exit.
//
// It is nosplit for the same reason as exceptionhandler.
//
//go:nosplit
func lastcontinuehandler(info *exceptionrecord, r *context, gp *g) int32 {
	if islibrary || isarchive {
		// Go DLL/archive has been loaded in a non-go program.
		// If the exception does not originate from go, the go runtime
		// should not take responsibility of crashing the process.
		return _EXCEPTION_CONTINUE_SEARCH
	}

	// VEH is called before SEH, but arm64 MSVC DLLs use SEH to trap
	// illegal instructions during runtime initialization to determine
	// CPU features, so if we make it to the last handler and we're
	// arm64 and it's an illegal instruction and this is coming from
	// non-Go code, then assume it's this runtime probing happen, and
	// pass that onward to SEH.
	if GOARCH == "arm64" && info.exceptioncode == _EXCEPTION_ILLEGAL_INSTRUCTION &&
		(r.ip() < firstmoduledata.text || firstmoduledata.etext < r.ip()) {
		return _EXCEPTION_CONTINUE_SEARCH
	}

	winthrow(info, r, gp)
	return 0 // not reached
}

// Always called on g0. gp is the G where the exception occurred.
//
//go:nosplit
func winthrow(info *exceptionrecord, r *context, gp *g) {
	g0 := getg()

	if panicking.Load() != 0 { // traceback already printed
		exit(2)
	}
	panicking.Store(1)

	// In case we're handling a g0 stack overflow, blow away the
	// g0 stack bounds so we have room to print the traceback. If
	// this somehow overflows the stack, the OS will trap it.
	g0.stack.lo = 0
	g0.stackguard0 = g0.stack.lo + stackGuard
	g0.stackguard1 = g0.stackguard0

	print("Exception ", hex(info.exceptioncode), " ", hex(info.exceptioninformation[0]), " ", hex(info.exceptioninformation[1]), " ", hex(r.ip()), "\n")

	print("PC=", hex(r.ip()), "\n")
	if g0.m.incgo && gp == g0.m.g0 && g0.m.curg != nil {
		if iscgo {
			print("signal arrived during external code execution\n")
		}
		gp = g0.m.curg
	}
	print("\n")

	g0.m.throwing = throwTypeRuntime
	g0.m.caughtsig.set(gp)

	level, _, docrash := gotraceback()
	if level > 0 {
		tracebacktrap(r.ip(), r.sp(), r.lr(), gp)
		tracebackothers(gp)
		dumpregs(r)
	}

	if docrash {
		dieFromException(info, r)
	}

	exit(2)
}

func sigpanic() {
	gp := getg()
	if !canpanic() {
		throw("unexpected signal during runtime execution")
	}

	switch gp.sig {
	case _EXCEPTION_ACCESS_VIOLATION, _EXCEPTION_IN_PAGE_ERROR:
		if gp.sigcode1 < 0x1000 {
			panicmem()
		}
		if gp.paniconfault {
			panicmemAddr(gp.sigcode1)
		}
		if inUserArenaChunk(gp.sigcode1) {
			// We could check that the arena chunk is explicitly set to fault,
			// but the fact that we faulted on accessing it is enough to prove
			// that it is.
			print("accessed data from freed user arena ", hex(gp.sigcode1), "\n")
		} else {
			print("unexpected fault address ", hex(gp.sigcode1), "\n")
		}
		throw("fault")
	case _EXCEPTION_INT_DIVIDE_BY_ZERO:
		panicdivide()
	case _EXCEPTION_INT_OVERFLOW:
		panicoverflow()
	case _EXCEPTION_FLT_DENORMAL_OPERAND,
		_EXCEPTION_FLT_DIVIDE_BY_ZERO,
		_EXCEPTION_FLT_INEXACT_RESULT,
		_EXCEPTION_FLT_OVERFLOW,
		_EXCEPTION_FLT_UNDERFLOW:
		panicfloat()
	}
	throw("fault")
}

// Following are not implemented.

func initsig(preinit bool) {
}

func sigenable(sig uint32) {
}

func sigdisable(sig uint32) {
}

func sigignore(sig uint32) {
}

func signame(sig uint32) string {
	return ""
}

//go:nosplit
func crash() {
	dieFromException(nil, nil)
}

// dieFromException raises an exception that bypasses all exception handlers.
// This provides the expected exit status for the shell.
//
//go:nosplit
func dieFromException(info *exceptionrecord, r *context) {
	if info == nil {
		gp := getg()
		if gp.sig != 0 {
			// Try to reconstruct an exception record from
			// the exception information stored in gp.
			info = &exceptionrecord{
				exceptionaddress: gp.sigpc,
				exceptioncode:    gp.sig,
				numberparameters: 2,
			}
			info.exceptioninformation[0] = gp.sigcode0
			info.exceptioninformation[1] = gp.sigcode1
		} else {
			// By default, a failing Go application exits with exit code 2.
			// Use this value when gp does not contain exception info.
			info = &exceptionrecord{
				exceptioncode: 2,
			}
		}
	}
	const FAIL_FAST_GENERATE_EXCEPTION_ADDRESS = 0x1
	stdcall3(_RaiseFailFastException, uintptr(unsafe.Pointer(info)), uintptr(unsafe.Pointer(r)), FAIL_FAST_GENERATE_EXCEPTION_ADDRESS)
}

// gsignalStack is unused on Windows.
type gsignalStack struct{}
```