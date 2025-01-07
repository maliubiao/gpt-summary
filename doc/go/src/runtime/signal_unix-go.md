Response:
The user wants a summary of the functionalities of the provided Go code snippet, which is part of the `runtime` package and deals with signal handling on Unix-like systems.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The code is located in `runtime/signal_unix.go`, clearly indicating it handles signals on Unix-based operating systems. Keywords like `sigTabT`, `sighandler`, `setsig`, `getsig`, and the various signal constants (e.g., `_SIGURG`, `_SIGPIPE`) strongly suggest signal management.

2. **Analyze key data structures:**
    * `sigTabT`: This structure holds information about each signal (flags and name). It acts as a lookup table.
    * `fwdSig`: This array stores the original signal handlers before Go took over. This is crucial for forwarding signals when Go isn't interested in handling them.
    * `handlingSig`:  This array tracks whether Go's signal handler is currently active for a given signal. This is important for enabling/disabling Go's handling.
    * `disableSigChan`, `enableSigChan`, `maskUpdatedChan`: These channels are for synchronizing signal mask updates, suggesting a dedicated mechanism for managing which signals are blocked or allowed.

3. **Analyze key functions:**
    * `initsig()`: This function initializes signal handling. It iterates through the signals, retrieves existing handlers, and installs Go's handler where appropriate. The `preinit` parameter suggests different initialization paths.
    * `sigInstallGoHandler()`:  This function determines if Go should install its own signal handler for a given signal, considering factors like `c-archive`/`c-shared` build modes and specific signals like `SIGPIPE` and the preemption signal.
    * `sigenable()`, `sigdisable()`, `sigignore()`: These functions control whether Go's handler is active for a specific signal. They interact with the signal mask management channels.
    * `sighandler()`: This is the core Go signal handler. It determines the appropriate action to take when a signal occurs, potentially involving panics, forwarding the signal, or triggering specific actions like preemption.
    * `sigpanic()`: This function converts a signal into a Go panic.
    * `dieFromSignal()`: This function terminates the program due to a signal.
    * `raisebadsignal()`:  This function handles signals received on non-Go threads when Go isn't managing them, forwarding the signal to the original handler.
    * `preemptM()` and `doSigPreempt()`: These functions implement non-cooperative goroutine preemption using signals.

4. **Identify key constants and variables:**
    * `sigPreempt`: The signal used for preemption.
    * `signalsOK`: A flag indicating if signal handlers are allowed to run.
    * `isarchive`, `islibrary`, `iscgo`: Build mode flags that affect signal handling.
    * `_NSIG`: The total number of signals on the system.

5. **Infer higher-level functionality:** By looking at the functions and data structures, it becomes clear that the code manages the interception and handling of operating system signals. It allows Go to respond to events like interrupts, errors, and user-defined signals. The preemption logic points to the implementation of Go's scheduler.

6. **Consider build modes and conditions:**  The code checks for `isarchive`, `islibrary`, and `iscgo`, showing that signal handling behavior can differ depending on how the Go code is being built and used.

7. **Synthesize the summary:** Combine the observations from the above steps to create a concise summary of the code's functionality. Emphasize the core responsibility of intercepting and handling signals, and mention key aspects like forwarding, different handling for Go and non-Go threads, and the preemption mechanism.
这段代码是 Go 运行时环境 (`runtime`) 中处理 Unix 信号的一部分。它的主要功能是：

**核心功能归纳：Go 运行时环境的 Unix 信号处理**

更具体地说，这段代码负责以下几个方面：

1. **定义信号表 (`sigtable`)**:  定义了一个全局的信号表，用于存储每个 Unix 信号的标志（`flags`）和名称（`name`）。这使得 Go 运行时可以知道如何处理不同的信号。

2. **获取信号名称 (`signame`)**:  提供了一个函数 `signame`，根据信号编号返回信号的名称。

3. **定义默认信号处理行为 (`_SIG_DFL`, `_SIG_IGN`)**: 定义了表示默认信号处理行为（`_SIG_DFL`）和忽略信号行为（`_SIG_IGN`）的常量。

4. **选择抢占信号 (`sigPreempt`)**:  定义了用于非协作抢占的信号 (`_SIGURG`)，并解释了选择该信号的原因（需要是调试器默认传递的信号，libc 内部不使用，可以自发产生而没有副作用，且在没有实时信号的平台上可用）。

5. **存储原始信号处理函数 (`fwdSig`)**:  维护一个数组 `fwdSig`，用于存储在 Go 安装自己的信号处理程序之前，系统注册的原始信号处理函数。这用于在 Go 不想处理特定信号时，将信号转发回原始处理程序。

6. **跟踪信号处理状态 (`handlingSig`)**:  使用一个数组 `handlingSig` 来跟踪当前是否正在使用 Go 的信号处理程序来处理某个信号。

7. **信号掩码同步通道 (`disableSigChan`, `enableSigChan`, `maskUpdatedChan`)**:  定义了用于与信号掩码线程同步更新信号掩码的通道。

8. **初始化信号处理 (`initsig`)**:  在运行时初始化阶段调用，用于安装 Go 的信号处理程序。它会遍历所有信号，获取原始的处理程序，并根据 `sigtable` 中的配置安装 Go 的处理程序 (`sighandler`)。对于不需要 Go 处理的信号，会记录原始的处理程序，并在必要时设置 `SA_ONSTACK` 标志。

9. **判断是否安装 Go 信号处理程序 (`sigInstallGoHandler`)**:  根据信号类型和构建模式（例如 `c-archive` 或 `c-shared`）判断是否应该为某个信号安装 Go 的信号处理程序。

10. **启用和禁用 Go 信号处理 (`sigenable`, `sigdisable`)**:  提供了 `sigenable` 和 `sigdisable` 函数，用于在运行时动态地启用或禁用 Go 对特定信号的处理。这些函数会与信号掩码同步通道交互。

11. **忽略信号 (`sigignore`)**:  提供 `sigignore` 函数，用于忽略指定的信号。

12. **清除信号处理程序 (`clearSignalHandlers`)**:  用于在 fork 后清除所有非忽略的信号处理程序，恢复到默认行为。

13. **设置进程 CPU 性能剖析定时器 (`setProcessCPUProfilerTimer`)**:  用于设置 CPU 性能剖析的定时器，涉及到 `SIGPROF` 信号的处理。

14. **设置线程 CPU 性能剖析频率 (`setThreadCPUProfilerHz`)**:  用于设置线程特定的 CPU 性能剖析频率。

15. **处理 SIGPIPE 信号 (`sigpipe`)**:  定义了 `SIGPIPE` 信号的处理函数，通常用于处理管道断开的情况。

16. **处理抢占信号 (`doSigPreempt`)**:  定义了处理抢占信号的函数，用于在安全点中断 goroutine 的执行。

17. **发送抢占请求 (`preemptM`)**:  用于向指定的 M (machine/内核线程) 发送抢占请求。

18. **安全地获取 G (`sigFetchG`)**:  在信号处理程序中安全地获取当前 Goroutine 的信息。

19. **信号处理入口点 (`sigtrampgo`)**:  这是汇编代码实现的信号处理跳转函数的 Go 语言入口点。它负责在信号发生时进行一些必要的设置，然后调用真正的信号处理函数 `sighandler`。

20. **处理非 Go 线程上的 SIGPROF 信号 (`sigprofNonGo`, `sigprofNonGoPC`)**:  专门处理在非 Go 线程上接收到的性能剖析信号。

21. **调整信号栈 (`adjustSignalStack`)**:  在信号处理程序中，如果检测到使用了非 Go 的信号栈 (`sigaltstack`)，则进行调整。

22. **致命信号处理 (`sighandler`)**:  这是主要的信号处理函数。它根据信号的类型和配置，执行相应的操作，例如抛出 panic、转发信号或者终止程序。

23. **将信号转化为 panic (`sigpanic`)**:  对于某些同步信号（例如 `SIGSEGV`，`SIGBUS`，`SIGFPE`），`sigpanic` 函数将其转化为 Go 的 panic 异常。

24. **因信号而终止程序 (`dieFromSignal`)**:  用于处理那些会导致程序终止的信号。

25. **处理非 Go 线程上未注册的信号 (`raisebadsignal`)**:  当在非 Go 线程上收到一个 Go 程序没有注册处理的信号时，`raisebadsignal` 会将该信号转发回原始的处理程序。

**总结:**

这段代码是 Go 运行时系统中至关重要的一部分，它负责**拦截、管理和响应 Unix 系统信号**。它允许 Go 程序优雅地处理各种系统事件，包括错误、用户交互和性能分析请求。  它还实现了 Go 调度器的非协作抢占机制。这段代码区分了 Go 线程和非 Go 线程上的信号处理，并提供了灵活的机制来决定如何处理不同的信号。

Prompt: 
```
这是路径为go/src/runtime/signal_unix.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

// sigTabT is the type of an entry in the global sigtable array.
// sigtable is inherently system dependent, and appears in OS-specific files,
// but sigTabT is the same for all Unixy systems.
// The sigtable array is indexed by a system signal number to get the flags
// and printable name of each signal.
type sigTabT struct {
	flags int32
	name  string
}

//go:linkname os_sigpipe os.sigpipe
func os_sigpipe() {
	systemstack(sigpipe)
}

func signame(sig uint32) string {
	if sig >= uint32(len(sigtable)) {
		return ""
	}
	return sigtable[sig].name
}

const (
	_SIG_DFL uintptr = 0
	_SIG_IGN uintptr = 1
)

// sigPreempt is the signal used for non-cooperative preemption.
//
// There's no good way to choose this signal, but there are some
// heuristics:
//
// 1. It should be a signal that's passed-through by debuggers by
// default. On Linux, this is SIGALRM, SIGURG, SIGCHLD, SIGIO,
// SIGVTALRM, SIGPROF, and SIGWINCH, plus some glibc-internal signals.
//
// 2. It shouldn't be used internally by libc in mixed Go/C binaries
// because libc may assume it's the only thing that can handle these
// signals. For example SIGCANCEL or SIGSETXID.
//
// 3. It should be a signal that can happen spuriously without
// consequences. For example, SIGALRM is a bad choice because the
// signal handler can't tell if it was caused by the real process
// alarm or not (arguably this means the signal is broken, but I
// digress). SIGUSR1 and SIGUSR2 are also bad because those are often
// used in meaningful ways by applications.
//
// 4. We need to deal with platforms without real-time signals (like
// macOS), so those are out.
//
// We use SIGURG because it meets all of these criteria, is extremely
// unlikely to be used by an application for its "real" meaning (both
// because out-of-band data is basically unused and because SIGURG
// doesn't report which socket has the condition, making it pretty
// useless), and even if it is, the application has to be ready for
// spurious SIGURG. SIGIO wouldn't be a bad choice either, but is more
// likely to be used for real.
const sigPreempt = _SIGURG

// Stores the signal handlers registered before Go installed its own.
// These signal handlers will be invoked in cases where Go doesn't want to
// handle a particular signal (e.g., signal occurred on a non-Go thread).
// See sigfwdgo for more information on when the signals are forwarded.
//
// This is read by the signal handler; accesses should use
// atomic.Loaduintptr and atomic.Storeuintptr.
var fwdSig [_NSIG]uintptr

// handlingSig is indexed by signal number and is non-zero if we are
// currently handling the signal. Or, to put it another way, whether
// the signal handler is currently set to the Go signal handler or not.
// This is uint32 rather than bool so that we can use atomic instructions.
var handlingSig [_NSIG]uint32

// channels for synchronizing signal mask updates with the signal mask
// thread
var (
	disableSigChan  chan uint32
	enableSigChan   chan uint32
	maskUpdatedChan chan struct{}
)

func init() {
	// _NSIG is the number of signals on this operating system.
	// sigtable should describe what to do for all the possible signals.
	if len(sigtable) != _NSIG {
		print("runtime: len(sigtable)=", len(sigtable), " _NSIG=", _NSIG, "\n")
		throw("bad sigtable len")
	}
}

var signalsOK bool

// Initialize signals.
// Called by libpreinit so runtime may not be initialized.
//
//go:nosplit
//go:nowritebarrierrec
func initsig(preinit bool) {
	if !preinit {
		// It's now OK for signal handlers to run.
		signalsOK = true
	}

	// For c-archive/c-shared this is called by libpreinit with
	// preinit == true.
	if (isarchive || islibrary) && !preinit {
		return
	}

	for i := uint32(0); i < _NSIG; i++ {
		t := &sigtable[i]
		if t.flags == 0 || t.flags&_SigDefault != 0 {
			continue
		}

		// We don't need to use atomic operations here because
		// there shouldn't be any other goroutines running yet.
		fwdSig[i] = getsig(i)

		if !sigInstallGoHandler(i) {
			// Even if we are not installing a signal handler,
			// set SA_ONSTACK if necessary.
			if fwdSig[i] != _SIG_DFL && fwdSig[i] != _SIG_IGN {
				setsigstack(i)
			} else if fwdSig[i] == _SIG_IGN {
				sigInitIgnored(i)
			}
			continue
		}

		handlingSig[i] = 1
		setsig(i, abi.FuncPCABIInternal(sighandler))
	}
}

//go:nosplit
//go:nowritebarrierrec
func sigInstallGoHandler(sig uint32) bool {
	// For some signals, we respect an inherited SIG_IGN handler
	// rather than insist on installing our own default handler.
	// Even these signals can be fetched using the os/signal package.
	switch sig {
	case _SIGHUP, _SIGINT:
		if atomic.Loaduintptr(&fwdSig[sig]) == _SIG_IGN {
			return false
		}
	}

	if (GOOS == "linux" || GOOS == "android") && !iscgo && sig == sigPerThreadSyscall {
		// sigPerThreadSyscall is the same signal used by glibc for
		// per-thread syscalls on Linux. We use it for the same purpose
		// in non-cgo binaries.
		return true
	}

	t := &sigtable[sig]
	if t.flags&_SigSetStack != 0 {
		return false
	}

	// When built using c-archive or c-shared, only install signal
	// handlers for synchronous signals and SIGPIPE and sigPreempt.
	if (isarchive || islibrary) && t.flags&_SigPanic == 0 && sig != _SIGPIPE && sig != sigPreempt {
		return false
	}

	return true
}

// sigenable enables the Go signal handler to catch the signal sig.
// It is only called while holding the os/signal.handlers lock,
// via os/signal.enableSignal and signal_enable.
func sigenable(sig uint32) {
	if sig >= uint32(len(sigtable)) {
		return
	}

	// SIGPROF is handled specially for profiling.
	if sig == _SIGPROF {
		return
	}

	t := &sigtable[sig]
	if t.flags&_SigNotify != 0 {
		ensureSigM()
		enableSigChan <- sig
		<-maskUpdatedChan
		if atomic.Cas(&handlingSig[sig], 0, 1) {
			atomic.Storeuintptr(&fwdSig[sig], getsig(sig))
			setsig(sig, abi.FuncPCABIInternal(sighandler))
		}
	}
}

// sigdisable disables the Go signal handler for the signal sig.
// It is only called while holding the os/signal.handlers lock,
// via os/signal.disableSignal and signal_disable.
func sigdisable(sig uint32) {
	if sig >= uint32(len(sigtable)) {
		return
	}

	// SIGPROF is handled specially for profiling.
	if sig == _SIGPROF {
		return
	}

	t := &sigtable[sig]
	if t.flags&_SigNotify != 0 {
		ensureSigM()
		disableSigChan <- sig
		<-maskUpdatedChan

		// If initsig does not install a signal handler for a
		// signal, then to go back to the state before Notify
		// we should remove the one we installed.
		if !sigInstallGoHandler(sig) {
			atomic.Store(&handlingSig[sig], 0)
			setsig(sig, atomic.Loaduintptr(&fwdSig[sig]))
		}
	}
}

// sigignore ignores the signal sig.
// It is only called while holding the os/signal.handlers lock,
// via os/signal.ignoreSignal and signal_ignore.
func sigignore(sig uint32) {
	if sig >= uint32(len(sigtable)) {
		return
	}

	// SIGPROF is handled specially for profiling.
	if sig == _SIGPROF {
		return
	}

	t := &sigtable[sig]
	if t.flags&_SigNotify != 0 {
		atomic.Store(&handlingSig[sig], 0)
		setsig(sig, _SIG_IGN)
	}
}

// clearSignalHandlers clears all signal handlers that are not ignored
// back to the default. This is called by the child after a fork, so that
// we can enable the signal mask for the exec without worrying about
// running a signal handler in the child.
//
//go:nosplit
//go:nowritebarrierrec
func clearSignalHandlers() {
	for i := uint32(0); i < _NSIG; i++ {
		if atomic.Load(&handlingSig[i]) != 0 {
			setsig(i, _SIG_DFL)
		}
	}
}

// setProcessCPUProfilerTimer is called when the profiling timer changes.
// It is called with prof.signalLock held. hz is the new timer, and is 0 if
// profiling is being disabled. Enable or disable the signal as
// required for -buildmode=c-archive.
func setProcessCPUProfilerTimer(hz int32) {
	if hz != 0 {
		// Enable the Go signal handler if not enabled.
		if atomic.Cas(&handlingSig[_SIGPROF], 0, 1) {
			h := getsig(_SIGPROF)
			// If no signal handler was installed before, then we record
			// _SIG_IGN here. When we turn off profiling (below) we'll start
			// ignoring SIGPROF signals. We do this, rather than change
			// to SIG_DFL, because there may be a pending SIGPROF
			// signal that has not yet been delivered to some other thread.
			// If we change to SIG_DFL when turning off profiling, the
			// program will crash when that SIGPROF is delivered. We assume
			// that programs that use profiling don't want to crash on a
			// stray SIGPROF. See issue 19320.
			// We do the change here instead of when turning off profiling,
			// because there we may race with a signal handler running
			// concurrently, in particular, sigfwdgo may observe _SIG_DFL and
			// die. See issue 43828.
			if h == _SIG_DFL {
				h = _SIG_IGN
			}
			atomic.Storeuintptr(&fwdSig[_SIGPROF], h)
			setsig(_SIGPROF, abi.FuncPCABIInternal(sighandler))
		}

		var it itimerval
		it.it_interval.tv_sec = 0
		it.it_interval.set_usec(1000000 / hz)
		it.it_value = it.it_interval
		setitimer(_ITIMER_PROF, &it, nil)
	} else {
		setitimer(_ITIMER_PROF, &itimerval{}, nil)

		// If the Go signal handler should be disabled by default,
		// switch back to the signal handler that was installed
		// when we enabled profiling. We don't try to handle the case
		// of a program that changes the SIGPROF handler while Go
		// profiling is enabled.
		if !sigInstallGoHandler(_SIGPROF) {
			if atomic.Cas(&handlingSig[_SIGPROF], 1, 0) {
				h := atomic.Loaduintptr(&fwdSig[_SIGPROF])
				setsig(_SIGPROF, h)
			}
		}
	}
}

// setThreadCPUProfilerHz makes any thread-specific changes required to
// implement profiling at a rate of hz.
// No changes required on Unix systems when using setitimer.
func setThreadCPUProfilerHz(hz int32) {
	getg().m.profilehz = hz
}

func sigpipe() {
	if signal_ignored(_SIGPIPE) || sigsend(_SIGPIPE) {
		return
	}
	dieFromSignal(_SIGPIPE)
}

// doSigPreempt handles a preemption signal on gp.
func doSigPreempt(gp *g, ctxt *sigctxt) {
	// Check if this G wants to be preempted and is safe to
	// preempt.
	if wantAsyncPreempt(gp) {
		if ok, newpc := isAsyncSafePoint(gp, ctxt.sigpc(), ctxt.sigsp(), ctxt.siglr()); ok {
			// Adjust the PC and inject a call to asyncPreempt.
			ctxt.pushCall(abi.FuncPCABI0(asyncPreempt), newpc)
		}
	}

	// Acknowledge the preemption.
	gp.m.preemptGen.Add(1)
	gp.m.signalPending.Store(0)

	if GOOS == "darwin" || GOOS == "ios" {
		pendingPreemptSignals.Add(-1)
	}
}

const preemptMSupported = true

// preemptM sends a preemption request to mp. This request may be
// handled asynchronously and may be coalesced with other requests to
// the M. When the request is received, if the running G or P are
// marked for preemption and the goroutine is at an asynchronous
// safe-point, it will preempt the goroutine. It always atomically
// increments mp.preemptGen after handling a preemption request.
func preemptM(mp *m) {
	// On Darwin, don't try to preempt threads during exec.
	// Issue #41702.
	if GOOS == "darwin" || GOOS == "ios" {
		execLock.rlock()
	}

	if mp.signalPending.CompareAndSwap(0, 1) {
		if GOOS == "darwin" || GOOS == "ios" {
			pendingPreemptSignals.Add(1)
		}

		// If multiple threads are preempting the same M, it may send many
		// signals to the same M such that it hardly make progress, causing
		// live-lock problem. Apparently this could happen on darwin. See
		// issue #37741.
		// Only send a signal if there isn't already one pending.
		signalM(mp, sigPreempt)
	}

	if GOOS == "darwin" || GOOS == "ios" {
		execLock.runlock()
	}
}

// sigFetchG fetches the value of G safely when running in a signal handler.
// On some architectures, the g value may be clobbered when running in a VDSO.
// See issue #32912.
//
//go:nosplit
func sigFetchG(c *sigctxt) *g {
	switch GOARCH {
	case "arm", "arm64", "loong64", "ppc64", "ppc64le", "riscv64", "s390x":
		if !iscgo && inVDSOPage(c.sigpc()) {
			// When using cgo, we save the g on TLS and load it from there
			// in sigtramp. Just use that.
			// Otherwise, before making a VDSO call we save the g to the
			// bottom of the signal stack. Fetch from there.
			// TODO: in efence mode, stack is sysAlloc'd, so this wouldn't
			// work.
			sp := sys.GetCallerSP()
			s := spanOf(sp)
			if s != nil && s.state.get() == mSpanManual && s.base() < sp && sp < s.limit {
				gp := *(**g)(unsafe.Pointer(s.base()))
				return gp
			}
			return nil
		}
	}
	return getg()
}

// sigtrampgo is called from the signal handler function, sigtramp,
// written in assembly code.
// This is called by the signal handler, and the world may be stopped.
//
// It must be nosplit because getg() is still the G that was running
// (if any) when the signal was delivered, but it's (usually) called
// on the gsignal stack. Until this switches the G to gsignal, the
// stack bounds check won't work.
//
//go:nosplit
//go:nowritebarrierrec
func sigtrampgo(sig uint32, info *siginfo, ctx unsafe.Pointer) {
	if sigfwdgo(sig, info, ctx) {
		return
	}
	c := &sigctxt{info, ctx}
	gp := sigFetchG(c)
	setg(gp)
	if gp == nil || (gp.m != nil && gp.m.isExtraInC) {
		if sig == _SIGPROF {
			// Some platforms (Linux) have per-thread timers, which we use in
			// combination with the process-wide timer. Avoid double-counting.
			if validSIGPROF(nil, c) {
				sigprofNonGoPC(c.sigpc())
			}
			return
		}
		if sig == sigPreempt && preemptMSupported && debug.asyncpreemptoff == 0 {
			// This is probably a signal from preemptM sent
			// while executing Go code but received while
			// executing non-Go code.
			// We got past sigfwdgo, so we know that there is
			// no non-Go signal handler for sigPreempt.
			// The default behavior for sigPreempt is to ignore
			// the signal, so badsignal will be a no-op anyway.
			if GOOS == "darwin" || GOOS == "ios" {
				pendingPreemptSignals.Add(-1)
			}
			return
		}
		c.fixsigcode(sig)
		// Set g to nil here and badsignal will use g0 by needm.
		// TODO: reuse the current m here by using the gsignal and adjustSignalStack,
		// since the current g maybe a normal goroutine and actually running on the signal stack,
		// it may hit stack split that is not expected here.
		if gp != nil {
			setg(nil)
		}
		badsignal(uintptr(sig), c)
		// Restore g
		if gp != nil {
			setg(gp)
		}
		return
	}

	setg(gp.m.gsignal)

	// If some non-Go code called sigaltstack, adjust.
	var gsignalStack gsignalStack
	setStack := adjustSignalStack(sig, gp.m, &gsignalStack)
	if setStack {
		gp.m.gsignal.stktopsp = sys.GetCallerSP()
	}

	if gp.stackguard0 == stackFork {
		signalDuringFork(sig)
	}

	c.fixsigcode(sig)
	sighandler(sig, info, ctx, gp)
	setg(gp)
	if setStack {
		restoreGsignalStack(&gsignalStack)
	}
}

// If the signal handler receives a SIGPROF signal on a non-Go thread,
// it tries to collect a traceback into sigprofCallers.
// sigprofCallersUse is set to non-zero while sigprofCallers holds a traceback.
var sigprofCallers cgoCallers
var sigprofCallersUse uint32

// sigprofNonGo is called if we receive a SIGPROF signal on a non-Go thread,
// and the signal handler collected a stack trace in sigprofCallers.
// When this is called, sigprofCallersUse will be non-zero.
// g is nil, and what we can do is very limited.
//
// It is called from the signal handling functions written in assembly code that
// are active for cgo programs, cgoSigtramp and sigprofNonGoWrapper, which have
// not verified that the SIGPROF delivery corresponds to the best available
// profiling source for this thread.
//
//go:nosplit
//go:nowritebarrierrec
func sigprofNonGo(sig uint32, info *siginfo, ctx unsafe.Pointer) {
	if prof.hz.Load() != 0 {
		c := &sigctxt{info, ctx}
		// Some platforms (Linux) have per-thread timers, which we use in
		// combination with the process-wide timer. Avoid double-counting.
		if validSIGPROF(nil, c) {
			n := 0
			for n < len(sigprofCallers) && sigprofCallers[n] != 0 {
				n++
			}
			cpuprof.addNonGo(sigprofCallers[:n])
		}
	}

	atomic.Store(&sigprofCallersUse, 0)
}

// sigprofNonGoPC is called when a profiling signal arrived on a
// non-Go thread and we have a single PC value, not a stack trace.
// g is nil, and what we can do is very limited.
//
//go:nosplit
//go:nowritebarrierrec
func sigprofNonGoPC(pc uintptr) {
	if prof.hz.Load() != 0 {
		stk := []uintptr{
			pc,
			abi.FuncPCABIInternal(_ExternalCode) + sys.PCQuantum,
		}
		cpuprof.addNonGo(stk)
	}
}

// adjustSignalStack adjusts the current stack guard based on the
// stack pointer that is actually in use while handling a signal.
// We do this in case some non-Go code called sigaltstack.
// This reports whether the stack was adjusted, and if so stores the old
// signal stack in *gsigstack.
//
//go:nosplit
func adjustSignalStack(sig uint32, mp *m, gsigStack *gsignalStack) bool {
	sp := uintptr(unsafe.Pointer(&sig))
	if sp >= mp.gsignal.stack.lo && sp < mp.gsignal.stack.hi {
		return false
	}

	var st stackt
	sigaltstack(nil, &st)
	stsp := uintptr(unsafe.Pointer(st.ss_sp))
	if st.ss_flags&_SS_DISABLE == 0 && sp >= stsp && sp < stsp+st.ss_size {
		setGsignalStack(&st, gsigStack)
		return true
	}

	if sp >= mp.g0.stack.lo && sp < mp.g0.stack.hi {
		// The signal was delivered on the g0 stack.
		// This can happen when linked with C code
		// using the thread sanitizer, which collects
		// signals then delivers them itself by calling
		// the signal handler directly when C code,
		// including C code called via cgo, calls a
		// TSAN-intercepted function such as malloc.
		//
		// We check this condition last as g0.stack.lo
		// may be not very accurate (see mstart).
		st := stackt{ss_size: mp.g0.stack.hi - mp.g0.stack.lo}
		setSignalstackSP(&st, mp.g0.stack.lo)
		setGsignalStack(&st, gsigStack)
		return true
	}

	// sp is not within gsignal stack, g0 stack, or sigaltstack. Bad.
	// Call indirectly to avoid nosplit stack overflow on OpenBSD.
	adjustSignalStack2Indirect(sig, sp, mp, st.ss_flags&_SS_DISABLE != 0)
	return false
}

var adjustSignalStack2Indirect = adjustSignalStack2

//go:nosplit
func adjustSignalStack2(sig uint32, sp uintptr, mp *m, ssDisable bool) {
	setg(nil)
	needm(true)
	if ssDisable {
		noSignalStack(sig)
	} else {
		sigNotOnStack(sig, sp, mp)
	}
	dropm()
}

// crashing is the number of m's we have waited for when implementing
// GOTRACEBACK=crash when a signal is received.
var crashing atomic.Int32

// testSigtrap and testSigusr1 are used by the runtime tests. If
// non-nil, it is called on SIGTRAP/SIGUSR1. If it returns true, the
// normal behavior on this signal is suppressed.
var testSigtrap func(info *siginfo, ctxt *sigctxt, gp *g) bool
var testSigusr1 func(gp *g) bool

// sigsysIgnored is non-zero if we are currently ignoring SIGSYS. See issue #69065.
var sigsysIgnored uint32

//go:linkname ignoreSIGSYS os.ignoreSIGSYS
func ignoreSIGSYS() {
	atomic.Store(&sigsysIgnored, 1)
}

//go:linkname restoreSIGSYS os.restoreSIGSYS
func restoreSIGSYS() {
	atomic.Store(&sigsysIgnored, 0)
}

// sighandler is invoked when a signal occurs. The global g will be
// set to a gsignal goroutine and we will be running on the alternate
// signal stack. The parameter gp will be the value of the global g
// when the signal occurred. The sig, info, and ctxt parameters are
// from the system signal handler: they are the parameters passed when
// the SA is passed to the sigaction system call.
//
// The garbage collector may have stopped the world, so write barriers
// are not allowed.
//
//go:nowritebarrierrec
func sighandler(sig uint32, info *siginfo, ctxt unsafe.Pointer, gp *g) {
	// The g executing the signal handler. This is almost always
	// mp.gsignal. See delayedSignal for an exception.
	gsignal := getg()
	mp := gsignal.m
	c := &sigctxt{info, ctxt}

	// Cgo TSAN (not the Go race detector) intercepts signals and calls the
	// signal handler at a later time. When the signal handler is called, the
	// memory may have changed, but the signal context remains old. The
	// unmatched signal context and memory makes it unsafe to unwind or inspect
	// the stack. So we ignore delayed non-fatal signals that will cause a stack
	// inspection (profiling signal and preemption signal).
	// cgo_yield is only non-nil for TSAN, and is specifically used to trigger
	// signal delivery. We use that as an indicator of delayed signals.
	// For delayed signals, the handler is called on the g0 stack (see
	// adjustSignalStack).
	delayedSignal := *cgo_yield != nil && mp != nil && gsignal.stack == mp.g0.stack

	if sig == _SIGPROF {
		// Some platforms (Linux) have per-thread timers, which we use in
		// combination with the process-wide timer. Avoid double-counting.
		if !delayedSignal && validSIGPROF(mp, c) {
			sigprof(c.sigpc(), c.sigsp(), c.siglr(), gp, mp)
		}
		return
	}

	if sig == _SIGTRAP && testSigtrap != nil && testSigtrap(info, (*sigctxt)(noescape(unsafe.Pointer(c))), gp) {
		return
	}

	if sig == _SIGUSR1 && testSigusr1 != nil && testSigusr1(gp) {
		return
	}

	if (GOOS == "linux" || GOOS == "android") && sig == sigPerThreadSyscall {
		// sigPerThreadSyscall is the same signal used by glibc for
		// per-thread syscalls on Linux. We use it for the same purpose
		// in non-cgo binaries. Since this signal is not _SigNotify,
		// there is nothing more to do once we run the syscall.
		runPerThreadSyscall()
		return
	}

	if sig == sigPreempt && debug.asyncpreemptoff == 0 && !delayedSignal {
		// Might be a preemption signal.
		doSigPreempt(gp, c)
		// Even if this was definitely a preemption signal, it
		// may have been coalesced with another signal, so we
		// still let it through to the application.
	}

	flags := int32(_SigThrow)
	if sig < uint32(len(sigtable)) {
		flags = sigtable[sig].flags
	}
	if !c.sigFromUser() && flags&_SigPanic != 0 && (gp.throwsplit || gp != mp.curg) {
		// We can't safely sigpanic because it may grow the
		// stack. Abort in the signal handler instead.
		//
		// Also don't inject a sigpanic if we are not on a
		// user G stack. Either we're in the runtime, or we're
		// running C code. Either way we cannot recover.
		flags = _SigThrow
	}
	if isAbortPC(c.sigpc()) {
		// On many architectures, the abort function just
		// causes a memory fault. Don't turn that into a panic.
		flags = _SigThrow
	}
	if !c.sigFromUser() && flags&_SigPanic != 0 {
		// The signal is going to cause a panic.
		// Arrange the stack so that it looks like the point
		// where the signal occurred made a call to the
		// function sigpanic. Then set the PC to sigpanic.

		// Have to pass arguments out of band since
		// augmenting the stack frame would break
		// the unwinding code.
		gp.sig = sig
		gp.sigcode0 = uintptr(c.sigcode())
		gp.sigcode1 = c.fault()
		gp.sigpc = c.sigpc()

		c.preparePanic(sig, gp)
		return
	}

	if c.sigFromUser() || flags&_SigNotify != 0 {
		if sigsend(sig) {
			return
		}
	}

	if c.sigFromUser() && signal_ignored(sig) {
		return
	}

	if sig == _SIGSYS && c.sigFromSeccomp() && atomic.Load(&sigsysIgnored) != 0 {
		return
	}

	if flags&_SigKill != 0 {
		dieFromSignal(sig)
	}

	// _SigThrow means that we should exit now.
	// If we get here with _SigPanic, it means that the signal
	// was sent to us by a program (c.sigFromUser() is true);
	// in that case, if we didn't handle it in sigsend, we exit now.
	if flags&(_SigThrow|_SigPanic) == 0 {
		return
	}

	mp.throwing = throwTypeRuntime
	mp.caughtsig.set(gp)

	if crashing.Load() == 0 {
		startpanic_m()
	}

	gp = fatalsignal(sig, c, gp, mp)

	level, _, docrash := gotraceback()
	if level > 0 {
		goroutineheader(gp)
		tracebacktrap(c.sigpc(), c.sigsp(), c.siglr(), gp)
		if crashing.Load() > 0 && gp != mp.curg && mp.curg != nil && readgstatus(mp.curg)&^_Gscan == _Grunning {
			// tracebackothers on original m skipped this one; trace it now.
			goroutineheader(mp.curg)
			traceback(^uintptr(0), ^uintptr(0), 0, mp.curg)
		} else if crashing.Load() == 0 {
			tracebackothers(gp)
			print("\n")
		}
		dumpregs(c)
	}

	if docrash {
		var crashSleepMicros uint32 = 5000
		var watchdogTimeoutMicros uint32 = 2000 * crashSleepMicros

		isCrashThread := false
		if crashing.CompareAndSwap(0, 1) {
			isCrashThread = true
		} else {
			crashing.Add(1)
		}
		if crashing.Load() < mcount()-int32(extraMLength.Load()) {
			// There are other m's that need to dump their stacks.
			// Relay SIGQUIT to the next m by sending it to the current process.
			// All m's that have already received SIGQUIT have signal masks blocking
			// receipt of any signals, so the SIGQUIT will go to an m that hasn't seen it yet.
			// The first m will wait until all ms received the SIGQUIT, then crash/exit.
			// Just in case the relaying gets botched, each m involved in
			// the relay sleeps for 5 seconds and then does the crash/exit itself.
			// The faulting m is crashing first so it is the faulting thread in the core dump (see issue #63277):
			// in expected operation, the first m will wait until the last m has received the SIGQUIT,
			// and then run crash/exit and the process is gone.
			// However, if it spends more than 10 seconds to send SIGQUIT to all ms,
			// any of ms may crash/exit the process after waiting for 10 seconds.
			print("\n-----\n\n")
			raiseproc(_SIGQUIT)
		}
		if isCrashThread {
			// Sleep for short intervals so that we can crash quickly after all ms have received SIGQUIT.
			// Reset the timer whenever we see more ms received SIGQUIT
			// to make it have enough time to crash (see issue #64752).
			timeout := watchdogTimeoutMicros
			maxCrashing := crashing.Load()
			for timeout > 0 && (crashing.Load() < mcount()-int32(extraMLength.Load())) {
				usleep(crashSleepMicros)
				timeout -= crashSleepMicros

				if c := crashing.Load(); c > maxCrashing {
					// We make progress, so reset the watchdog timeout
					maxCrashing = c
					timeout = watchdogTimeoutMicros
				}
			}
		} else {
			maxCrashing := int32(0)
			c := crashing.Load()
			for c > maxCrashing {
				maxCrashing = c
				usleep(watchdogTimeoutMicros)
				c = crashing.Load()
			}
		}
		printDebugLog()
		crash()
	}

	printDebugLog()

	exit(2)
}

func fatalsignal(sig uint32, c *sigctxt, gp *g, mp *m) *g {
	if sig < uint32(len(sigtable)) {
		print(sigtable[sig].name, "\n")
	} else {
		print("Signal ", sig, "\n")
	}

	if isSecureMode() {
		exit(2)
	}

	print("PC=", hex(c.sigpc()), " m=", mp.id, " sigcode=", c.sigcode())
	if sig == _SIGSEGV || sig == _SIGBUS {
		print(" addr=", hex(c.fault()))
	}
	print("\n")
	if mp.incgo && gp == mp.g0 && mp.curg != nil {
		print("signal arrived during cgo execution\n")
		// Switch to curg so that we get a traceback of the Go code
		// leading up to the cgocall, which switched from curg to g0.
		gp = mp.curg
	}
	if sig == _SIGILL || sig == _SIGFPE {
		// It would be nice to know how long the instruction is.
		// Unfortunately, that's complicated to do in general (mostly for x86
		// and s930x, but other archs have non-standard instruction lengths also).
		// Opt to print 16 bytes, which covers most instructions.
		const maxN = 16
		n := uintptr(maxN)
		// We have to be careful, though. If we're near the end of
		// a page and the following page isn't mapped, we could
		// segfault. So make sure we don't straddle a page (even though
		// that could lead to printing an incomplete instruction).
		// We're assuming here we can read at least the page containing the PC.
		// I suppose it is possible that the page is mapped executable but not readable?
		pc := c.sigpc()
		if n > physPageSize-pc%physPageSize {
			n = physPageSize - pc%physPageSize
		}
		print("instruction bytes:")
		b := (*[maxN]byte)(unsafe.Pointer(pc))
		for i := uintptr(0); i < n; i++ {
			print(" ", hex(b[i]))
		}
		println()
	}
	print("\n")
	return gp
}

// sigpanic turns a synchronous signal into a run-time panic.
// If the signal handler sees a synchronous panic, it arranges the
// stack to look like the function where the signal occurred called
// sigpanic, sets the signal's PC value to sigpanic, and returns from
// the signal handler. The effect is that the program will act as
// though the function that got the signal simply called sigpanic
// instead.
//
// This must NOT be nosplit because the linker doesn't know where
// sigpanic calls can be injected.
//
// The signal handler must not inject a call to sigpanic if
// getg().throwsplit, since sigpanic may need to grow the stack.
//
// This is exported via linkname to assembly in runtime/cgo.
//
//go:linkname sigpanic
func sigpanic() {
	gp := getg()
	if !canpanic() {
		throw("unexpected signal during runtime execution")
	}

	switch gp.sig {
	case _SIGBUS:
		if gp.sigcode0 == _BUS_ADRERR && gp.sigcode1 < 0x1000 {
			panicmem()
		}
		// Support runtime/debug.SetPanicOnFault.
		if gp.paniconfault {
			panicmemAddr(gp.sigcode1)
		}
		print("unexpected fault address ", hex(gp.sigcode1), "\n")
		throw("fault")
	case _SIGSEGV:
		if (gp.sigcode0 == 0 || gp.sigcode0 == _SEGV_MAPERR || gp.sigcode0 == _SEGV_ACCERR) && gp.sigcode1 < 0x1000 {
			panicmem()
		}
		// Support runtime/debug.SetPanicOnFault.
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
	case _SIGFPE:
		switch gp.sigcode0 {
		case _FPE_INTDIV:
			panicdivide()
		case _FPE_INTOVF:
			panicoverflow()
		}
		panicfloat()
	}

	if gp.sig >= uint32(len(sigtable)) {
		// can't happen: we looked up gp.sig in sigtable to decide to call sigpanic
		throw("unexpected signal value")
	}
	panic(errorString(sigtable[gp.sig].name))
}

// dieFromSignal kills the program with a signal.
// This provides the expected exit status for the shell.
// This is only called with fatal signals expected to kill the process.
//
//go:nosplit
//go:nowritebarrierrec
func dieFromSignal(sig uint32) {
	unblocksig(sig)
	// Mark the signal as unhandled to ensure it is forwarded.
	atomic.Store(&handlingSig[sig], 0)
	raise(sig)

	// That should have killed us. On some systems, though, raise
	// sends the signal to the whole process rather than to just
	// the current thread, which means that the signal may not yet
	// have been delivered. Give other threads a chance to run and
	// pick up the signal.
	osyield()
	osyield()
	osyield()

	// If that didn't work, try _SIG_DFL.
	setsig(sig, _SIG_DFL)
	raise(sig)

	osyield()
	osyield()
	osyield()

	// If we are still somehow running, just exit with the wrong status.
	exit(2)
}

// raisebadsignal is called when a signal is received on a non-Go
// thread, and the Go program does not want to handle it (that is, the
// program has not called os/signal.Notify for the signal).
func raisebadsignal(sig uint32, c *sigctxt) {
	if sig == _SIGPROF {
		// Ignore profiling signals that arrive on non-Go threads.
		return
	}

	var handler uintptr
	var flags int32
	if sig >= _NSIG {
		handler = _SIG_DFL
	} else {
		handler = atomic.Loaduintptr(&fwdSig[sig])
		flags = sigtable[sig].flags
	}

	// If the signal is ignored, raising the signal is no-op.
	if handler == _SIG_IGN || (handler == _SIG_DFL && flags&_SigIgn != 0) {
		return
	}

	// Reset the signal handler and raise the signal.
	// We are currently running inside a signal handler, so the
	// signal is blocked. We need to unblock it before raising the
	// signal, or the signal we raise will be ignored until we return
	// from the signal handler. We know that the signal was unblocked
	// before entering the handler, or else we would not have received
	// it. That means that we don't have to worry about blocking it
	// again.
	unblocksig(sig)
	setsig(sig, handler)

	// If we're linked into a non-Go program we want to try to
	// avoid modifying the original context in which the signal
	// was raised. If the handler is the default, we know it
	// is non-recoverable, so we don't have to worry about
	// re-installing sighandler. At this point we can just
	// return and the signal will be re-raised and caught by
	// the default handler with the correct context.
	//
	// On FreeBSD, the libthr sigaction code prevents
	// this from working so we fall through to raise.
	if GOOS != "freebsd" && (isarchive || islibrary) && handler == _SIG_DFL && !c.sigFromUser() {
		return
	}

	raise(sig)

	// Give the signal a chance to be delivered.
	// In almost all real cases the program is about to crash,
	// so sleeping here is not a waste of time.
	usleep(1000)

	// If the sign
"""




```