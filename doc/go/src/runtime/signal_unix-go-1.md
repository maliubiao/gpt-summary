Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The initial prompt mentions the file path `go/src/runtime/signal_unix.go`. This immediately tells us we're dealing with low-level signal handling within the Go runtime, specifically for Unix-like operating systems. The "part 2 of 2" suggests this builds upon concepts introduced in the first part.

2. **Identify Key Functions and Data Structures:**  The first pass involves scanning the code for function names, type definitions (like `gsignalStack`), and global variables. This gives a high-level overview of the code's components. Some obvious candidates are:

    * `setsig`: Likely responsible for setting signal handlers.
    * `crash`:  Related to program termination due to a signal.
    * `ensureSigM`:  Something to do with ensuring a thread for signal handling.
    * `noSignalStack`, `sigNotOnStack`, `signalDuringFork`: Functions handling unexpected signal states.
    * `badsignal`:  Dealing with signals when there's no Go context.
    * `sigfwd`, `sigfwdgo`: Forwarding signals to other handlers.
    * `sigsave`, `msigrestore`, `sigblock`, `unblocksig`: Manipulating signal masks.
    * `minitSignals`, `minitSignalStack`, `minitSignalMask`, `unminitSignals`: Initialization and cleanup related to signal handling.
    * `blockableSig`: Determining if a signal can be blocked.
    * `gsignalStack`, `setGsignalStack`, `restoreGsignalStack`, `signalstack`: Managing alternate signal stacks.
    * `setsigsegv`:  Simulating a segmentation fault (platform-specific).

3. **Group Functions by Functionality:**  Based on the naming and comments, group related functions. This helps understand the overall flow and purpose of different sections:

    * **Signal Handling Setup/Modification:** `setsig`, `ensureSigM`, `minitSignals`, `minitSignalStack`, `minitSignalMask`, `unminitSignals`
    * **Handling Unexpected Signal States:** `noSignalStack`, `sigNotOnStack`, `signalDuringFork`
    * **Handling Signals in Non-Go Contexts:** `badsignal`, `sigsave`, `msigrestore`, `sigblock`, `unblocksig`
    * **Signal Forwarding:** `sigfwd`, `sigfwdgo`
    * **Signal Stack Management:** `gsignalStack`, `setGsignalStack`, `restoreGsignalStack`, `signalstack`
    * **Program Termination:** `crash`
    * **Signal Blocking Logic:** `blockableSig`
    * **Platform-Specific Functionality:** `setsigsegv`

4. **Analyze Individual Functions (Focus on Key Ones):** Dive deeper into the more complex or interesting functions, paying attention to comments and logic:

    * **`ensureSigM`:** The comment clearly states its purpose: ensuring a dedicated thread for handling `os/signal` notifications. The `select` statement with channels suggests a loop waiting for enable/disable requests. The `sigprocmask` calls are key for managing the thread's signal mask.
    * **`sigfwdgo`:**  This function is central to the decision-making process of whether Go handles a signal or forwards it. The checks for `handlingSig`, `signalsOK`, `fwdFn`, and the logic for synchronous signals and SIGPIPE are important.
    * **`minitSignals` and related:** The comments explain how Go manages signal stacks, especially when interacting with non-Go code or CGO. The `newSigstack` flag is a crucial detail.
    * **`blockableSig`:** The logic for determining which signals can be blocked and the exceptions for certain signals (`_SigUnblock`, preemption, `_SigKill`, `_SigThrow`) needs careful attention.

5. **Infer Go Features and Provide Examples:** Based on the function analysis, connect the code to higher-level Go features:

    * `os/signal`: The most obvious connection. `ensureSigM` and the enable/disable channels directly relate to how `os/signal.Notify` and `os/signal.Stop` work. Provide a simple example demonstrating this.
    * Panic and Recover: Signals like `SIGSEGV`, `SIGABRT` often lead to panics in Go. The `crash` function and the mentions of `_SigPanic` support this.
    * CGO Interaction:  Several comments and code sections (like `minitSignalStack`, `badsignal`) deal with the complexities of signal handling when Go interacts with C code.

6. **Consider Edge Cases and Potential Pitfalls:**  Think about situations where things might go wrong:

    * Incorrect Signal Handling in C/C++: The code has checks for situations where non-Go code misconfigures signal handlers (e.g., not using `SA_ONSTACK`). This is a key point for potential errors.

7. **Structure the Answer:** Organize the findings into logical sections: Functionality, Go Feature Implementation (with examples), Code Inference (if applicable), and Potential Pitfalls.

8. **Refine and Summarize:**  Review the analysis for clarity and accuracy. For "part 2," focus on summarizing the overall functionality of the code snippet, building upon the understanding gained from the detailed analysis. The key takeaway is Go's sophisticated and careful management of signals to ensure proper execution and integration with the underlying operating system and potentially with non-Go code.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe some functions are about performance optimization. **Correction:**  While efficiency is a concern, the primary focus is correctness and handling various signal scenarios, especially in the context of concurrent execution and C interoperation.
* **Overemphasis on individual functions:** **Correction:**  Shift focus to the interaction between functions and the overall purpose of each functional group (signal setup, handling, forwarding, etc.).
* **Insufficiently linking to Go features:** **Correction:**  Explicitly connect the low-level code to the observable behavior of Go's `os/signal` package and panic/recover mechanisms.

By following this structured approach, one can effectively analyze and understand complex low-level code like this Go runtime snippet.
这是 `go/src/runtime/signal_unix.go` 文件的第二部分，主要负责处理 Unix 系统上的信号。结合第一部分的内容，我们可以归纳出它的功能如下：

**核心功能：管理和处理 Go 程序中的 Unix 信号**

这部分代码延续了第一部分的功能，更深入地涉及了信号的接收、处理、转发以及与非 Go 代码的交互。其核心目标是确保 Go 程序能够正确且安全地响应各种 Unix 信号，同时考虑到与 C 代码的互操作性。

**具体功能归纳：**

1. **恢复默认信号处理 (针对被忽略的信号):**  如果一个信号被 Go 程序忽略，并且该信号导致程序没有退出，那么 `restoresig` 函数会将该信号的处理恢复为 Go 的默认处理方式 (sighandler)。这样做是为了防止在 Go 信号处理器恢复之前再次收到相同的信号导致问题。

2. **程序崩溃 (crash):** `crash` 函数会调用 `dieFromSignal(_SIGABRT)`，导致程序因为 `SIGABRT` 信号而终止。这通常用于指示程序内部出现了无法恢复的错误。

3. **确保信号处理 Goroutine (ensureSigM):**  `ensureSigM` 函数启动一个全局的、睡眠的 Goroutine，专门用于处理通过 `os/signal` 包启用的信号。这个 Goroutine 会绑定到一个操作系统线程 (使用 `LockOSThread`)，并维护一个信号屏蔽字。当 `os/signal.Notify()` 或 `os/signal.Stop()` 被调用时，会通过 channel (`enableSigChan`, `disableSigChan`) 通知这个 Goroutine 更新其信号屏蔽字。

4. **处理异常的信号状态:**
    * `noSignalStack`: 当接收到信号时，但当前线程没有设置备用信号栈时调用。这通常意味着非 Go 代码禁用了信号栈。
    * `sigNotOnStack`: 当接收到信号时，线程设置了备用信号栈，但信号处理程序没有在该栈上执行时调用。这通常意味着非 Go 代码在设置信号处理程序时没有设置 `SA_ONSTACK` 标志。
    * `signalDuringFork`: 当在 `fork` 系统调用期间接收到信号时调用。这是一种安全检查，因为在 `fork` 期间我们应该屏蔽信号。

5. **处理非 Go 上下文中的信号 (badsignal):** `badsignal` 函数在没有关联的 Goroutine (`g`) 或 Machine (`m`) 的情况下运行，例如在外部线程接收到信号时。它会尝试获取一个 `m` 来处理信号。如果 Go 代码不想处理该信号，则会调用 `raisebadsignal` 将信号转发出去。

6. **信号转发 (sigfwd, sigfwdgo):**
    * `sigfwd`:  是一个 `go:noescape` 函数，用于将信号转发到之前安装的信号处理程序。
    * `sigfwdgo`: 决定是否由 Go 处理信号，如果不是，则将信号转发给之前的处理程序。它会检查信号是否正在被 Go 处理、信号是否应该被忽略、是否存在需要转发的处理程序等。对于某些特定的信号 (例如 Darwin/iOS 上的 `SIGPIPE`)，即使 Go 正在处理，也可能选择忽略。它还会判断信号是否发生在 Go 代码内部，以决定是否转发。

7. **保存和恢复信号屏蔽字 (sigsave, msigrestore):**
    * `sigsave`: 将当前线程的信号屏蔽字保存到提供的 `sigset` 指针中。这用于当非 Go 线程调用 Go 函数时，保存非 Go 的信号屏蔽字。
    * `msigrestore`: 将当前线程的信号屏蔽字设置为提供的 `sigset` 值。这用于当非 Go 线程调用 Go 函数后返回时，恢复非 Go 的信号屏蔽字。

8. **屏蔽信号 (sigblock):**  `sigblock` 函数会屏蔽当前线程的信号。在非 Go 线程调用 Go 函数时，用于在设置和清理 Goroutine 状态时防止信号干扰。`sigblock(true)` 用于线程退出时，会使用 `sigsetAllExiting` 的屏蔽字，该屏蔽字会排除一些 libc 内部使用的信号，以避免死锁。

9. **取消屏蔽信号 (unblocksig):** `unblocksig` 函数从当前线程的信号屏蔽字中移除指定的信号。

10. **初始化信号处理 (minitSignals, minitSignalStack, minitSignalMask):**
    * `minitSignals`: 在初始化一个新的 `m` 时调用，用于设置线程的备用信号栈和信号屏蔽字。
    * `minitSignalStack`: 设置线程的备用信号栈。如果线程没有设置备用信号栈（通常情况），则将其设置为 `gsignal` 栈。如果线程已经设置了备用信号栈（非 Go 线程调用 Go 函数的情况），则将 `gsignal` 栈设置为备用信号栈。
    * `minitSignalMask`: 设置线程的信号屏蔽字。开始时使用 `m.sigmask`，然后从中移除所有必要的信号，确保这些信号不会被屏蔽。

11. **清理信号处理 (unminitSignals):** 在 `dropm` 中调用，用于撤销在非 Go 线程上调用 `minit` 的影响。主要负责恢复信号栈的状态。

12. **判断信号是否可以被屏蔽 (blockableSig):**  `blockableSig` 函数判断一个信号是否可以被信号屏蔽字屏蔽。某些信号 (例如 `_SigUnblock` 标记的信号，以及 preempt 信号) 永远不应该被屏蔽。在非 c-archive/c-shared 模式下，`_SigKill` 和 `_SigThrow` 标记的信号也不应该被屏蔽。

13. **管理 `gsignal` 栈 (gsignalStack, setGsignalStack, restoreGsignalStack, signalstack):**
    * `gsignalStack`:  结构体，用于保存 `gsignal` 栈的字段。
    * `setGsignalStack`: 将当前 `m` 的 `gsignal` 栈设置为从 `sigaltstack` 系统调用返回的备用信号栈。它会将旧的值保存在提供的 `gsignalStack` 结构体中。
    * `restoreGsignalStack`: 将 `gsignal` 栈恢复到进入信号处理程序之前的值。
    * `signalstack`: 将当前线程的备用信号栈设置为指定的 `stack`。

14. **模拟段错误 (setsigsegv):**  在 Darwin/arm64 平台上使用，用于模拟段错误。这个函数通过 `linkname` 导出到 `runtime/cgo` 中的汇编代码。

**总结：**

这部分代码是 Go runtime 信号处理机制的关键组成部分，它深入处理了信号的接收、判断、转发和屏蔽等底层操作。它不仅要保证 Go 程序自身信号处理的正确性，还要处理与非 Go 代码 (特别是 C/C++) 交互时的复杂情况，例如在非 Go 线程中调用 Go 函数时如何正确地保存和恢复信号上下文。代码中大量的 `//go:nosplit` 注释表明这些函数必须在栈空间受限的情况下运行，通常是在处理信号的关键路径上。整体来看，这部分代码致力于构建一个健壮且灵活的信号处理框架，以支持 Go 程序在各种 Unix 环境下的稳定运行。

### 提示词
```
这是路径为go/src/runtime/signal_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
al didn't cause the program to exit, restore the
	// Go signal handler and carry on.
	//
	// We may receive another instance of the signal before we
	// restore the Go handler, but that is not so bad: we know
	// that the Go program has been ignoring the signal.
	setsig(sig, abi.FuncPCABIInternal(sighandler))
}

//go:nosplit
func crash() {
	dieFromSignal(_SIGABRT)
}

// ensureSigM starts one global, sleeping thread to make sure at least one thread
// is available to catch signals enabled for os/signal.
func ensureSigM() {
	if maskUpdatedChan != nil {
		return
	}
	maskUpdatedChan = make(chan struct{})
	disableSigChan = make(chan uint32)
	enableSigChan = make(chan uint32)
	go func() {
		// Signal masks are per-thread, so make sure this goroutine stays on one
		// thread.
		LockOSThread()
		defer UnlockOSThread()
		// The sigBlocked mask contains the signals not active for os/signal,
		// initially all signals except the essential. When signal.Notify()/Stop is called,
		// sigenable/sigdisable in turn notify this thread to update its signal
		// mask accordingly.
		sigBlocked := sigset_all
		for i := range sigtable {
			if !blockableSig(uint32(i)) {
				sigdelset(&sigBlocked, i)
			}
		}
		sigprocmask(_SIG_SETMASK, &sigBlocked, nil)
		for {
			select {
			case sig := <-enableSigChan:
				if sig > 0 {
					sigdelset(&sigBlocked, int(sig))
				}
			case sig := <-disableSigChan:
				if sig > 0 && blockableSig(sig) {
					sigaddset(&sigBlocked, int(sig))
				}
			}
			sigprocmask(_SIG_SETMASK, &sigBlocked, nil)
			maskUpdatedChan <- struct{}{}
		}
	}()
}

// This is called when we receive a signal when there is no signal stack.
// This can only happen if non-Go code calls sigaltstack to disable the
// signal stack.
func noSignalStack(sig uint32) {
	println("signal", sig, "received on thread with no signal stack")
	throw("non-Go code disabled sigaltstack")
}

// This is called if we receive a signal when there is a signal stack
// but we are not on it. This can only happen if non-Go code called
// sigaction without setting the SS_ONSTACK flag.
func sigNotOnStack(sig uint32, sp uintptr, mp *m) {
	println("signal", sig, "received but handler not on signal stack")
	print("mp.gsignal stack [", hex(mp.gsignal.stack.lo), " ", hex(mp.gsignal.stack.hi), "], ")
	print("mp.g0 stack [", hex(mp.g0.stack.lo), " ", hex(mp.g0.stack.hi), "], sp=", hex(sp), "\n")
	throw("non-Go code set up signal handler without SA_ONSTACK flag")
}

// signalDuringFork is called if we receive a signal while doing a fork.
// We do not want signals at that time, as a signal sent to the process
// group may be delivered to the child process, causing confusion.
// This should never be called, because we block signals across the fork;
// this function is just a safety check. See issue 18600 for background.
func signalDuringFork(sig uint32) {
	println("signal", sig, "received during fork")
	throw("signal received during fork")
}

// This runs on a foreign stack, without an m or a g. No stack split.
//
//go:nosplit
//go:norace
//go:nowritebarrierrec
func badsignal(sig uintptr, c *sigctxt) {
	if !iscgo && !cgoHasExtraM {
		// There is no extra M. needm will not be able to grab
		// an M. Instead of hanging, just crash.
		// Cannot call split-stack function as there is no G.
		writeErrStr("fatal: bad g in signal handler\n")
		exit(2)
		*(*uintptr)(unsafe.Pointer(uintptr(123))) = 2
	}
	needm(true)
	if !sigsend(uint32(sig)) {
		// A foreign thread received the signal sig, and the
		// Go code does not want to handle it.
		raisebadsignal(uint32(sig), c)
	}
	dropm()
}

//go:noescape
func sigfwd(fn uintptr, sig uint32, info *siginfo, ctx unsafe.Pointer)

// Determines if the signal should be handled by Go and if not, forwards the
// signal to the handler that was installed before Go's. Returns whether the
// signal was forwarded.
// This is called by the signal handler, and the world may be stopped.
//
//go:nosplit
//go:nowritebarrierrec
func sigfwdgo(sig uint32, info *siginfo, ctx unsafe.Pointer) bool {
	if sig >= uint32(len(sigtable)) {
		return false
	}
	fwdFn := atomic.Loaduintptr(&fwdSig[sig])
	flags := sigtable[sig].flags

	// If we aren't handling the signal, forward it.
	if atomic.Load(&handlingSig[sig]) == 0 || !signalsOK {
		// If the signal is ignored, doing nothing is the same as forwarding.
		if fwdFn == _SIG_IGN || (fwdFn == _SIG_DFL && flags&_SigIgn != 0) {
			return true
		}
		// We are not handling the signal and there is no other handler to forward to.
		// Crash with the default behavior.
		if fwdFn == _SIG_DFL {
			setsig(sig, _SIG_DFL)
			dieFromSignal(sig)
			return false
		}

		sigfwd(fwdFn, sig, info, ctx)
		return true
	}

	// This function and its caller sigtrampgo assumes SIGPIPE is delivered on the
	// originating thread. This property does not hold on macOS (golang.org/issue/33384),
	// so we have no choice but to ignore SIGPIPE.
	if (GOOS == "darwin" || GOOS == "ios") && sig == _SIGPIPE {
		return true
	}

	// If there is no handler to forward to, no need to forward.
	if fwdFn == _SIG_DFL {
		return false
	}

	c := &sigctxt{info, ctx}
	// Only forward synchronous signals and SIGPIPE.
	// Unfortunately, user generated SIGPIPEs will also be forwarded, because si_code
	// is set to _SI_USER even for a SIGPIPE raised from a write to a closed socket
	// or pipe.
	if (c.sigFromUser() || flags&_SigPanic == 0) && sig != _SIGPIPE {
		return false
	}
	// Determine if the signal occurred inside Go code. We test that:
	//   (1) we weren't in VDSO page,
	//   (2) we were in a goroutine (i.e., m.curg != nil), and
	//   (3) we weren't in CGO.
	//   (4) we weren't in dropped extra m.
	gp := sigFetchG(c)
	if gp != nil && gp.m != nil && gp.m.curg != nil && !gp.m.isExtraInC && !gp.m.incgo {
		return false
	}

	// Signal not handled by Go, forward it.
	if fwdFn != _SIG_IGN {
		sigfwd(fwdFn, sig, info, ctx)
	}

	return true
}

// sigsave saves the current thread's signal mask into *p.
// This is used to preserve the non-Go signal mask when a non-Go
// thread calls a Go function.
// This is nosplit and nowritebarrierrec because it is called by needm
// which may be called on a non-Go thread with no g available.
//
//go:nosplit
//go:nowritebarrierrec
func sigsave(p *sigset) {
	sigprocmask(_SIG_SETMASK, nil, p)
}

// msigrestore sets the current thread's signal mask to sigmask.
// This is used to restore the non-Go signal mask when a non-Go thread
// calls a Go function.
// This is nosplit and nowritebarrierrec because it is called by dropm
// after g has been cleared.
//
//go:nosplit
//go:nowritebarrierrec
func msigrestore(sigmask sigset) {
	sigprocmask(_SIG_SETMASK, &sigmask, nil)
}

// sigsetAllExiting is used by sigblock(true) when a thread is
// exiting.
var sigsetAllExiting = func() sigset {
	res := sigset_all

	// Apply GOOS-specific overrides here, rather than in osinit,
	// because osinit may be called before sigsetAllExiting is
	// initialized (#51913).
	if GOOS == "linux" && iscgo {
		// #42494 glibc and musl reserve some signals for
		// internal use and require they not be blocked by
		// the rest of a normal C runtime. When the go runtime
		// blocks...unblocks signals, temporarily, the blocked
		// interval of time is generally very short. As such,
		// these expectations of *libc code are mostly met by
		// the combined go+cgo system of threads. However,
		// when go causes a thread to exit, via a return from
		// mstart(), the combined runtime can deadlock if
		// these signals are blocked. Thus, don't block these
		// signals when exiting threads.
		// - glibc: SIGCANCEL (32), SIGSETXID (33)
		// - musl: SIGTIMER (32), SIGCANCEL (33), SIGSYNCCALL (34)
		sigdelset(&res, 32)
		sigdelset(&res, 33)
		sigdelset(&res, 34)
	}

	return res
}()

// sigblock blocks signals in the current thread's signal mask.
// This is used to block signals while setting up and tearing down g
// when a non-Go thread calls a Go function. When a thread is exiting
// we use the sigsetAllExiting value, otherwise the OS specific
// definition of sigset_all is used.
// This is nosplit and nowritebarrierrec because it is called by needm
// which may be called on a non-Go thread with no g available.
//
//go:nosplit
//go:nowritebarrierrec
func sigblock(exiting bool) {
	if exiting {
		sigprocmask(_SIG_SETMASK, &sigsetAllExiting, nil)
		return
	}
	sigprocmask(_SIG_SETMASK, &sigset_all, nil)
}

// unblocksig removes sig from the current thread's signal mask.
// This is nosplit and nowritebarrierrec because it is called from
// dieFromSignal, which can be called by sigfwdgo while running in the
// signal handler, on the signal stack, with no g available.
//
//go:nosplit
//go:nowritebarrierrec
func unblocksig(sig uint32) {
	var set sigset
	sigaddset(&set, int(sig))
	sigprocmask(_SIG_UNBLOCK, &set, nil)
}

// minitSignals is called when initializing a new m to set the
// thread's alternate signal stack and signal mask.
func minitSignals() {
	minitSignalStack()
	minitSignalMask()
}

// minitSignalStack is called when initializing a new m to set the
// alternate signal stack. If the alternate signal stack is not set
// for the thread (the normal case) then set the alternate signal
// stack to the gsignal stack. If the alternate signal stack is set
// for the thread (the case when a non-Go thread sets the alternate
// signal stack and then calls a Go function) then set the gsignal
// stack to the alternate signal stack. We also set the alternate
// signal stack to the gsignal stack if cgo is not used (regardless
// of whether it is already set). Record which choice was made in
// newSigstack, so that it can be undone in unminit.
func minitSignalStack() {
	mp := getg().m
	var st stackt
	sigaltstack(nil, &st)
	if st.ss_flags&_SS_DISABLE != 0 || !iscgo {
		signalstack(&mp.gsignal.stack)
		mp.newSigstack = true
	} else {
		setGsignalStack(&st, &mp.goSigStack)
		mp.newSigstack = false
	}
}

// minitSignalMask is called when initializing a new m to set the
// thread's signal mask. When this is called all signals have been
// blocked for the thread.  This starts with m.sigmask, which was set
// either from initSigmask for a newly created thread or by calling
// sigsave if this is a non-Go thread calling a Go function. It
// removes all essential signals from the mask, thus causing those
// signals to not be blocked. Then it sets the thread's signal mask.
// After this is called the thread can receive signals.
func minitSignalMask() {
	nmask := getg().m.sigmask
	for i := range sigtable {
		if !blockableSig(uint32(i)) {
			sigdelset(&nmask, i)
		}
	}
	sigprocmask(_SIG_SETMASK, &nmask, nil)
}

// unminitSignals is called from dropm, via unminit, to undo the
// effect of calling minit on a non-Go thread.
//
//go:nosplit
func unminitSignals() {
	if getg().m.newSigstack {
		st := stackt{ss_flags: _SS_DISABLE}
		sigaltstack(&st, nil)
	} else {
		// We got the signal stack from someone else. Restore
		// the Go-allocated stack in case this M gets reused
		// for another thread (e.g., it's an extram). Also, on
		// Android, libc allocates a signal stack for all
		// threads, so it's important to restore the Go stack
		// even on Go-created threads so we can free it.
		restoreGsignalStack(&getg().m.goSigStack)
	}
}

// blockableSig reports whether sig may be blocked by the signal mask.
// We never want to block the signals marked _SigUnblock;
// these are the synchronous signals that turn into a Go panic.
// We never want to block the preemption signal if it is being used.
// In a Go program--not a c-archive/c-shared--we never want to block
// the signals marked _SigKill or _SigThrow, as otherwise it's possible
// for all running threads to block them and delay their delivery until
// we start a new thread. When linked into a C program we let the C code
// decide on the disposition of those signals.
func blockableSig(sig uint32) bool {
	flags := sigtable[sig].flags
	if flags&_SigUnblock != 0 {
		return false
	}
	if sig == sigPreempt && preemptMSupported && debug.asyncpreemptoff == 0 {
		return false
	}
	if isarchive || islibrary {
		return true
	}
	return flags&(_SigKill|_SigThrow) == 0
}

// gsignalStack saves the fields of the gsignal stack changed by
// setGsignalStack.
type gsignalStack struct {
	stack       stack
	stackguard0 uintptr
	stackguard1 uintptr
	stktopsp    uintptr
}

// setGsignalStack sets the gsignal stack of the current m to an
// alternate signal stack returned from the sigaltstack system call.
// It saves the old values in *old for use by restoreGsignalStack.
// This is used when handling a signal if non-Go code has set the
// alternate signal stack.
//
//go:nosplit
//go:nowritebarrierrec
func setGsignalStack(st *stackt, old *gsignalStack) {
	gp := getg()
	if old != nil {
		old.stack = gp.m.gsignal.stack
		old.stackguard0 = gp.m.gsignal.stackguard0
		old.stackguard1 = gp.m.gsignal.stackguard1
		old.stktopsp = gp.m.gsignal.stktopsp
	}
	stsp := uintptr(unsafe.Pointer(st.ss_sp))
	gp.m.gsignal.stack.lo = stsp
	gp.m.gsignal.stack.hi = stsp + st.ss_size
	gp.m.gsignal.stackguard0 = stsp + stackGuard
	gp.m.gsignal.stackguard1 = stsp + stackGuard
}

// restoreGsignalStack restores the gsignal stack to the value it had
// before entering the signal handler.
//
//go:nosplit
//go:nowritebarrierrec
func restoreGsignalStack(st *gsignalStack) {
	gp := getg().m.gsignal
	gp.stack = st.stack
	gp.stackguard0 = st.stackguard0
	gp.stackguard1 = st.stackguard1
	gp.stktopsp = st.stktopsp
}

// signalstack sets the current thread's alternate signal stack to s.
//
//go:nosplit
func signalstack(s *stack) {
	st := stackt{ss_size: s.hi - s.lo}
	setSignalstackSP(&st, s.lo)
	sigaltstack(&st, nil)
}

// setsigsegv is used on darwin/arm64 to fake a segmentation fault.
//
// This is exported via linkname to assembly in runtime/cgo.
//
//go:nosplit
//go:linkname setsigsegv
func setsigsegv(pc uintptr) {
	gp := getg()
	gp.sig = _SIGSEGV
	gp.sigpc = pc
	gp.sigcode0 = _SEGV_MAPERR
	gp.sigcode1 = 0 // TODO: emulate si_addr
}
```