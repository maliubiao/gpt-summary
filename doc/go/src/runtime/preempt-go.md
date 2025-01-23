Response:
Let's break down the thought process for analyzing this Go code snippet and generating the answer.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of the provided Go code (specifically `preempt.go`), focusing on how it handles goroutine preemption. The request also asks for specific examples, code demonstrations, and potential pitfalls.

**2. Initial Reading and Keyword Identification:**

The first step is to read through the comments and code, looking for key terms and concepts related to preemption. Words like "preempt," "safe-point," "synchronous," "asynchronous," "signal," "stack bound," "suspend," "resume," and the different `_G` states immediately stand out. The copyright notice and package declaration are less important for understanding the *functionality* but help establish context.

**3. Deconstructing the Comments:**

The comments at the beginning are crucial. They explicitly describe the different types of safe-points (blocked, synchronous, asynchronous) and how each works. This provides the core conceptual framework. The comments also detail the implementation strategies for synchronous (stack bound poisoning) and asynchronous (OS signals) preemption. These comments are a treasure trove of information and should be carefully parsed.

**4. Analyzing the `suspendG` Function:**

This function appears to be the heart of the preemption mechanism. The loop and the `switch` statement within it are clearly responsible for driving a goroutine to a safe preemption point. Key aspects to analyze here include:

* **The `readgstatus` and `castogscanstatus` functions:**  These are likely used for atomically checking and changing the state of a goroutine.
* **The different `_G` states:** Understanding how the goroutine transitions between these states (`_Gdead`, `_Gcopystack`, `_Gpreempted`, `_Grunnable`, `_Gsyscall`, `_Gwaiting`, `_Grunning`, `_Gscan`, `_Gscanrunning`) during the suspension process is critical.
* **The handling of synchronous and asynchronous preemption requests:**  Notice how `gp.preemptStop`, `gp.preempt`, and `gp.stackguard0` are manipulated for synchronous preemption, and how `preemptM` is called for asynchronous preemption.
* **The `yield` and `osyield` calls:** These are used to avoid busy-waiting.
* **The return value `suspendGState`:** This structure holds information about the suspended goroutine.

**5. Analyzing the `resumeG` Function:**

This function is the counterpart to `suspendG`. It reverses the suspension process, changing the goroutine's state and potentially rescheduling it using `ready`.

**6. Analyzing Other Functions:**

* **`canPreemptM`:**  This function determines if a given M (OS thread bound to a P) is in a safe state for preemption. The conditions (`mp.locks == 0`, etc.) are important.
* **`asyncPreempt` and `asyncPreempt2`:** These seem to be the entry points for asynchronous preemption. The comment about saving registers and the assembly implementation is noteworthy.
* **`isAsyncSafePoint`:** This function checks if the current instruction pointer is at a location where asynchronous preemption is safe. The various checks (user G, M state, stack space, unsafe points, runtime packages) are important details.
* **`wantAsyncPreempt`:** A simple check to see if a preemption is pending.

**7. Inferring the High-Level Functionality:**

Based on the code and comments, the core functionality is clearly about allowing the Go runtime to interrupt the execution of goroutines for various reasons (e.g., time slicing, garbage collection). The distinction between synchronous and asynchronous preemption is key.

**8. Constructing Examples and Explanations:**

Now that the individual pieces and the overall functionality are understood, the next step is to synthesize this information into a coherent explanation.

* **Listing Functionality:** This is a direct extraction of the key tasks performed by the code.
* **Inferring Go Functionality:** The preemption mechanism is directly related to the Go scheduler and its ability to manage concurrency. The examples should illustrate scenarios where preemption would occur (e.g., long-running computations, blocking operations).
* **Code Examples:**  The examples need to be simple and illustrative. The `for` loop example for synchronous preemption and the signal-based example (even if conceptual) for asynchronous preemption work well. It's important to explicitly state the assumptions and the expected output.
* **Command-Line Arguments:**  The code itself doesn't directly handle command-line arguments. The explanation should clarify this and point out that the *scheduler* and *runtime* as a whole are influenced by command-line flags related to scheduling and debugging.
* **User Errors:** The potential for deadlocks if `suspendG` is called from a non-preemptible goroutine is a crucial point. A simple example demonstrating this helps illustrate the problem.

**9. Refining the Language:**

The final step is to polish the language, ensuring clarity, accuracy, and conciseness. Using clear headings, bullet points, and code formatting improves readability. Translating technical terms into plain language where possible also helps. For instance, explaining "poisoning the stack bound" as a technique to trigger the stack growth mechanism makes it more accessible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe the code directly interacts with OS-level thread management. **Correction:** The code uses signals for asynchronous preemption, but the runtime manages the mapping of goroutines to OS threads.
* **Initial thought:**  Focus heavily on the low-level details of assembly code. **Correction:** While mentioned, the focus should be on the higher-level logic and the *purpose* of `asyncPreempt`.
* **Initial thought:**  Overcomplicate the code examples. **Correction:** Keep the examples simple and focused on demonstrating the core concept.

By following this structured approach, combining careful reading, keyword analysis, understanding the flow of execution, and then synthesizing the information into clear explanations and examples, a comprehensive and accurate answer can be generated.
这段代码是 Go 语言运行时（runtime）中 `preempt.go` 文件的一部分，主要负责**实现 Goroutine 的抢占式调度**。

下面详细列举其功能，并进行推理和举例说明：

**1. 功能列举：**

* **定义了 Goroutine 挂起的状态 (`suspendGState`)**:  用于存储挂起 Goroutine 的相关信息。
* **实现了 Goroutine 的挂起 (`suspendG`)**:  该函数负责将一个正在运行的 Goroutine 暂停到一个安全点。
* **实现了 Goroutine 的恢复 (`resumeG`)**: 该函数负责恢复一个之前被挂起的 Goroutine 的执行。
* **判断 M (Machine, 代表一个操作系统线程) 是否可以被抢占 (`canPreemptM`)**:  用于检查一个 M 当前的状态是否允许其上的 Goroutine 被安全地抢占。
* **定义了异步抢占的入口函数 (`asyncPreempt`, `asyncPreempt2`)**:  `asyncPreempt` 是汇编实现，负责保存用户寄存器，然后调用 `asyncPreempt2`。
* **计算异步抢占所需的栈空间 (`asyncPreemptStack`)**:  用于确保 Goroutine 有足够的栈空间来注入异步抢占的调用。
* **判断是否需要对 Goroutine 进行异步抢占 (`wantAsyncPreempt`)**:  检查 Goroutine 和其所在的 P (Processor, 代表执行上下文) 是否有抢占请求。
* **判断给定指令指针是否为异步安全点 (`isAsyncSafePoint`)**:  确定在某个特定的代码位置暂停 Goroutine 是否安全，并返回可能的新的恢复执行地址。

**2. 推理 Go 语言功能：抢占式调度**

这段代码的核心目标是实现 Go 语言的**抢占式调度器**。  Go 语言的调度器负责在多个 Goroutine 之间分配 CPU 时间。  为了保证公平性和响应性，调度器需要能够中断长时间运行的 Goroutine，让其他 Goroutine 获得运行机会。  `preempt.go` 中的代码就是实现这种中断机制的关键部分。

**Go 代码举例说明：**

假设我们有一个长时间运行的 Goroutine，如果没有抢占机制，它可能会一直占用 CPU，导致其他 Goroutine 无法执行。

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func longRunningTask() {
	start := time.Now()
	for i := 0; i < 1000000000; i++ {
		// 模拟长时间计算
	}
	fmt.Println("Long running task finished in", time.Since(start))
}

func anotherTask() {
	fmt.Println("Another task is running.")
}

func main() {
	runtime.GOMAXPROCS(1) // 使用单核 CPU 方便观察抢占效果

	go longRunningTask()
	go anotherTask()

	time.Sleep(time.Second * 2) // 让 main Goroutine 等待一段时间
	fmt.Println("Main goroutine exiting.")
}
```

**假设的输入与输出：**

**输入：** 运行上述 Go 代码。

**输出 (可能，取决于调度器的具体行为):**

```
Another task is running.
Long running task finished in ...
Main goroutine exiting.
```

**代码推理：**

* 当 `longRunningTask` Goroutine 运行时，如果没有抢占机制，它会一直执行循环，直到结束。
* Go 语言的抢占机制会定期检查是否有其他 Goroutine 需要运行。
* `suspendG` 函数会被调度器调用，尝试挂起 `longRunningTask`。
* 挂起时，会检查当前是否处于安全点。
* 如果是同步安全点 (例如函数调用前，循环的开始等)，通过修改栈边界触发异常，进入抢占处理。
* 如果是异步安全点，可能会通过发送信号的方式暂停 Goroutine。
* `resumeG` 函数会在 `longRunningTask` 被挂起后，或者在下次调度到它的时候被调用，恢复其执行。
* 即使 `longRunningTask` 是一个无限循环，由于抢占机制，`anotherTask` 也有机会运行。

**3. 涉及命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。然而，Go 语言运行时的一些行为可以通过命令行参数进行控制，例如：

* **`GODEBUG=asyncpreemptoff=1`**:  这个环境变量可以禁用异步抢占。设置后，运行时将只依赖同步抢占。
* **`GOMAXPROCS`**:  虽然不直接影响 `preempt.go` 的逻辑，但它控制着可以同时运行的操作系统线程的数量，从而间接影响 Goroutine 的调度和抢占发生的频率。

**如果禁用了异步抢占 (`GODEBUG=asyncpreemptoff=1`)**:  调度器将主要依赖同步安全点进行抢占。这意味着抢占只会在 Goroutine 执行到特定的安全点时发生，例如函数调用、循环的开始等。如果一个 Goroutine 执行了一个非常长的、没有安全点的操作，它可能不会被及时抢占。

**4. 使用者易犯错的点：**

使用者通常不需要直接与 `preempt.go` 中的代码交互，因为这是 Go 运行时的内部实现。但是，理解抢占机制对于编写高性能和可靠的 Go 程序仍然很重要。

一个潜在的误解是认为 Goroutine 会立即响应抢占请求。实际上，抢占只有在 Goroutine 到达安全点时才能发生。  长时间运行的、没有安全点的计算密集型 Goroutine 可能会延迟其他 Goroutine 的执行。

**例子 (理解安全点的重要性):**

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func noSafePointTask() {
	start := time.Now()
	sum := 0
	for i := 0; i < 1000000000; i++ {
		sum += i // 没有任何函数调用或可能触发安全点的操作
	}
	fmt.Println("No safe point task finished in", time.Since(start), "sum:", sum)
}

func anotherTaskAgain() {
	fmt.Println("Another task is running again.")
}

func main() {
	runtime.GOMAXPROCS(1)

	go noSafePointTask()
	go anotherTaskAgain()

	time.Sleep(time.Second * 2)
	fmt.Println("Main goroutine exiting.")
}
```

**预期行为：**  在上面的例子中，由于 `noSafePointTask` 的循环中没有任何可能触发安全点的操作，即使启用了抢占，`anotherTaskAgain` 也可能需要等待 `noSafePointTask` 执行很长时间才能开始运行。

**总结:**

`go/src/runtime/preempt.go` 是 Go 语言抢占式调度的核心实现，它通过同步和异步两种方式将运行中的 Goroutine 暂停到安全点，以便调度器可以切换到其他 Goroutine，从而保证 Go 程序的并发性和响应性。理解这段代码的功能有助于理解 Go 语言的调度机制，虽然开发者通常不需要直接与其交互，但了解其原理对于编写高效的并发程序至关重要。

### 提示词
```
这是路径为go/src/runtime/preempt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Goroutine preemption
//
// A goroutine can be preempted at any safe-point. Currently, there
// are a few categories of safe-points:
//
// 1. A blocked safe-point occurs for the duration that a goroutine is
//    descheduled, blocked on synchronization, or in a system call.
//
// 2. Synchronous safe-points occur when a running goroutine checks
//    for a preemption request.
//
// 3. Asynchronous safe-points occur at any instruction in user code
//    where the goroutine can be safely paused and a conservative
//    stack and register scan can find stack roots. The runtime can
//    stop a goroutine at an async safe-point using a signal.
//
// At both blocked and synchronous safe-points, a goroutine's CPU
// state is minimal and the garbage collector has complete information
// about its entire stack. This makes it possible to deschedule a
// goroutine with minimal space, and to precisely scan a goroutine's
// stack.
//
// Synchronous safe-points are implemented by overloading the stack
// bound check in function prologues. To preempt a goroutine at the
// next synchronous safe-point, the runtime poisons the goroutine's
// stack bound to a value that will cause the next stack bound check
// to fail and enter the stack growth implementation, which will
// detect that it was actually a preemption and redirect to preemption
// handling.
//
// Preemption at asynchronous safe-points is implemented by suspending
// the thread using an OS mechanism (e.g., signals) and inspecting its
// state to determine if the goroutine was at an asynchronous
// safe-point. Since the thread suspension itself is generally
// asynchronous, it also checks if the running goroutine wants to be
// preempted, since this could have changed. If all conditions are
// satisfied, it adjusts the signal context to make it look like the
// signaled thread just called asyncPreempt and resumes the thread.
// asyncPreempt spills all registers and enters the scheduler.
//
// (An alternative would be to preempt in the signal handler itself.
// This would let the OS save and restore the register state and the
// runtime would only need to know how to extract potentially
// pointer-containing registers from the signal context. However, this
// would consume an M for every preempted G, and the scheduler itself
// is not designed to run from a signal handler, as it tends to
// allocate memory and start threads in the preemption path.)

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/stringslite"
)

type suspendGState struct {
	g *g

	// dead indicates the goroutine was not suspended because it
	// is dead. This goroutine could be reused after the dead
	// state was observed, so the caller must not assume that it
	// remains dead.
	dead bool

	// stopped indicates that this suspendG transitioned the G to
	// _Gwaiting via g.preemptStop and thus is responsible for
	// readying it when done.
	stopped bool
}

// suspendG suspends goroutine gp at a safe-point and returns the
// state of the suspended goroutine. The caller gets read access to
// the goroutine until it calls resumeG.
//
// It is safe for multiple callers to attempt to suspend the same
// goroutine at the same time. The goroutine may execute between
// subsequent successful suspend operations. The current
// implementation grants exclusive access to the goroutine, and hence
// multiple callers will serialize. However, the intent is to grant
// shared read access, so please don't depend on exclusive access.
//
// This must be called from the system stack and the user goroutine on
// the current M (if any) must be in a preemptible state. This
// prevents deadlocks where two goroutines attempt to suspend each
// other and both are in non-preemptible states. There are other ways
// to resolve this deadlock, but this seems simplest.
//
// TODO(austin): What if we instead required this to be called from a
// user goroutine? Then we could deschedule the goroutine while
// waiting instead of blocking the thread. If two goroutines tried to
// suspend each other, one of them would win and the other wouldn't
// complete the suspend until it was resumed. We would have to be
// careful that they couldn't actually queue up suspend for each other
// and then both be suspended. This would also avoid the need for a
// kernel context switch in the synchronous case because we could just
// directly schedule the waiter. The context switch is unavoidable in
// the signal case.
//
//go:systemstack
func suspendG(gp *g) suspendGState {
	if mp := getg().m; mp.curg != nil && readgstatus(mp.curg) == _Grunning {
		// Since we're on the system stack of this M, the user
		// G is stuck at an unsafe point. If another goroutine
		// were to try to preempt m.curg, it could deadlock.
		throw("suspendG from non-preemptible goroutine")
	}

	// See https://golang.org/cl/21503 for justification of the yield delay.
	const yieldDelay = 10 * 1000
	var nextYield int64

	// Drive the goroutine to a preemption point.
	stopped := false
	var asyncM *m
	var asyncGen uint32
	var nextPreemptM int64
	for i := 0; ; i++ {
		switch s := readgstatus(gp); s {
		default:
			if s&_Gscan != 0 {
				// Someone else is suspending it. Wait
				// for them to finish.
				//
				// TODO: It would be nicer if we could
				// coalesce suspends.
				break
			}

			dumpgstatus(gp)
			throw("invalid g status")

		case _Gdead:
			// Nothing to suspend.
			//
			// preemptStop may need to be cleared, but
			// doing that here could race with goroutine
			// reuse. Instead, goexit0 clears it.
			return suspendGState{dead: true}

		case _Gcopystack:
			// The stack is being copied. We need to wait
			// until this is done.

		case _Gpreempted:
			// We (or someone else) suspended the G. Claim
			// ownership of it by transitioning it to
			// _Gwaiting.
			if !casGFromPreempted(gp, _Gpreempted, _Gwaiting) {
				break
			}

			// We stopped the G, so we have to ready it later.
			stopped = true

			s = _Gwaiting
			fallthrough

		case _Grunnable, _Gsyscall, _Gwaiting:
			// Claim goroutine by setting scan bit.
			// This may race with execution or readying of gp.
			// The scan bit keeps it from transition state.
			if !castogscanstatus(gp, s, s|_Gscan) {
				break
			}

			// Clear the preemption request. It's safe to
			// reset the stack guard because we hold the
			// _Gscan bit and thus own the stack.
			gp.preemptStop = false
			gp.preempt = false
			gp.stackguard0 = gp.stack.lo + stackGuard

			// The goroutine was already at a safe-point
			// and we've now locked that in.
			//
			// TODO: It would be much better if we didn't
			// leave it in _Gscan, but instead gently
			// prevented its scheduling until resumption.
			// Maybe we only use this to bump a suspended
			// count and the scheduler skips suspended
			// goroutines? That wouldn't be enough for
			// {_Gsyscall,_Gwaiting} -> _Grunning. Maybe
			// for all those transitions we need to check
			// suspended and deschedule?
			return suspendGState{g: gp, stopped: stopped}

		case _Grunning:
			// Optimization: if there is already a pending preemption request
			// (from the previous loop iteration), don't bother with the atomics.
			if gp.preemptStop && gp.preempt && gp.stackguard0 == stackPreempt && asyncM == gp.m && asyncM.preemptGen.Load() == asyncGen {
				break
			}

			// Temporarily block state transitions.
			if !castogscanstatus(gp, _Grunning, _Gscanrunning) {
				break
			}

			// Request synchronous preemption.
			gp.preemptStop = true
			gp.preempt = true
			gp.stackguard0 = stackPreempt

			// Prepare for asynchronous preemption.
			asyncM2 := gp.m
			asyncGen2 := asyncM2.preemptGen.Load()
			needAsync := asyncM != asyncM2 || asyncGen != asyncGen2
			asyncM = asyncM2
			asyncGen = asyncGen2

			casfrom_Gscanstatus(gp, _Gscanrunning, _Grunning)

			// Send asynchronous preemption. We do this
			// after CASing the G back to _Grunning
			// because preemptM may be synchronous and we
			// don't want to catch the G just spinning on
			// its status.
			if preemptMSupported && debug.asyncpreemptoff == 0 && needAsync {
				// Rate limit preemptM calls. This is
				// particularly important on Windows
				// where preemptM is actually
				// synchronous and the spin loop here
				// can lead to live-lock.
				now := nanotime()
				if now >= nextPreemptM {
					nextPreemptM = now + yieldDelay/2
					preemptM(asyncM)
				}
			}
		}

		// TODO: Don't busy wait. This loop should really only
		// be a simple read/decide/CAS loop that only fails if
		// there's an active race. Once the CAS succeeds, we
		// should queue up the preemption (which will require
		// it to be reliable in the _Grunning case, not
		// best-effort) and then sleep until we're notified
		// that the goroutine is suspended.
		if i == 0 {
			nextYield = nanotime() + yieldDelay
		}
		if nanotime() < nextYield {
			procyield(10)
		} else {
			osyield()
			nextYield = nanotime() + yieldDelay/2
		}
	}
}

// resumeG undoes the effects of suspendG, allowing the suspended
// goroutine to continue from its current safe-point.
func resumeG(state suspendGState) {
	if state.dead {
		// We didn't actually stop anything.
		return
	}

	gp := state.g
	switch s := readgstatus(gp); s {
	default:
		dumpgstatus(gp)
		throw("unexpected g status")

	case _Grunnable | _Gscan,
		_Gwaiting | _Gscan,
		_Gsyscall | _Gscan:
		casfrom_Gscanstatus(gp, s, s&^_Gscan)
	}

	if state.stopped {
		// We stopped it, so we need to re-schedule it.
		ready(gp, 0, true)
	}
}

// canPreemptM reports whether mp is in a state that is safe to preempt.
//
// It is nosplit because it has nosplit callers.
//
//go:nosplit
func canPreemptM(mp *m) bool {
	return mp.locks == 0 && mp.mallocing == 0 && mp.preemptoff == "" && mp.p.ptr().status == _Prunning
}

//go:generate go run mkpreempt.go

// asyncPreempt saves all user registers and calls asyncPreempt2.
//
// When stack scanning encounters an asyncPreempt frame, it scans that
// frame and its parent frame conservatively.
//
// asyncPreempt is implemented in assembly.
func asyncPreempt()

//go:nosplit
func asyncPreempt2() {
	gp := getg()
	gp.asyncSafePoint = true
	if gp.preemptStop {
		mcall(preemptPark)
	} else {
		mcall(gopreempt_m)
	}
	gp.asyncSafePoint = false
}

// asyncPreemptStack is the bytes of stack space required to inject an
// asyncPreempt call.
var asyncPreemptStack = ^uintptr(0)

func init() {
	f := findfunc(abi.FuncPCABI0(asyncPreempt))
	total := funcMaxSPDelta(f)
	f = findfunc(abi.FuncPCABIInternal(asyncPreempt2))
	total += funcMaxSPDelta(f)
	// Add some overhead for return PCs, etc.
	asyncPreemptStack = uintptr(total) + 8*goarch.PtrSize
	if asyncPreemptStack > stackNosplit {
		// We need more than the nosplit limit. This isn't
		// unsafe, but it may limit asynchronous preemption.
		//
		// This may be a problem if we start using more
		// registers. In that case, we should store registers
		// in a context object. If we pre-allocate one per P,
		// asyncPreempt can spill just a few registers to the
		// stack, then grab its context object and spill into
		// it. When it enters the runtime, it would allocate a
		// new context for the P.
		print("runtime: asyncPreemptStack=", asyncPreemptStack, "\n")
		throw("async stack too large")
	}
}

// wantAsyncPreempt returns whether an asynchronous preemption is
// queued for gp.
func wantAsyncPreempt(gp *g) bool {
	// Check both the G and the P.
	return (gp.preempt || gp.m.p != 0 && gp.m.p.ptr().preempt) && readgstatus(gp)&^_Gscan == _Grunning
}

// isAsyncSafePoint reports whether gp at instruction PC is an
// asynchronous safe point. This indicates that:
//
// 1. It's safe to suspend gp and conservatively scan its stack and
// registers. There are no potentially hidden pointer values and it's
// not in the middle of an atomic sequence like a write barrier.
//
// 2. gp has enough stack space to inject the asyncPreempt call.
//
// 3. It's generally safe to interact with the runtime, even if we're
// in a signal handler stopped here. For example, there are no runtime
// locks held, so acquiring a runtime lock won't self-deadlock.
//
// In some cases the PC is safe for asynchronous preemption but it
// also needs to adjust the resumption PC. The new PC is returned in
// the second result.
func isAsyncSafePoint(gp *g, pc, sp, lr uintptr) (bool, uintptr) {
	mp := gp.m

	// Only user Gs can have safe-points. We check this first
	// because it's extremely common that we'll catch mp in the
	// scheduler processing this G preemption.
	if mp.curg != gp {
		return false, 0
	}

	// Check M state.
	if mp.p == 0 || !canPreemptM(mp) {
		return false, 0
	}

	// Check stack space.
	if sp < gp.stack.lo || sp-gp.stack.lo < asyncPreemptStack {
		return false, 0
	}

	// Check if PC is an unsafe-point.
	f := findfunc(pc)
	if !f.valid() {
		// Not Go code.
		return false, 0
	}
	if (GOARCH == "mips" || GOARCH == "mipsle" || GOARCH == "mips64" || GOARCH == "mips64le") && lr == pc+8 && funcspdelta(f, pc) == 0 {
		// We probably stopped at a half-executed CALL instruction,
		// where the LR is updated but the PC has not. If we preempt
		// here we'll see a seemingly self-recursive call, which is in
		// fact not.
		// This is normally ok, as we use the return address saved on
		// stack for unwinding, not the LR value. But if this is a
		// call to morestack, we haven't created the frame, and we'll
		// use the LR for unwinding, which will be bad.
		return false, 0
	}
	up, startpc := pcdatavalue2(f, abi.PCDATA_UnsafePoint, pc)
	if up == abi.UnsafePointUnsafe {
		// Unsafe-point marked by compiler. This includes
		// atomic sequences (e.g., write barrier) and nosplit
		// functions (except at calls).
		return false, 0
	}
	if fd := funcdata(f, abi.FUNCDATA_LocalsPointerMaps); fd == nil || f.flag&abi.FuncFlagAsm != 0 {
		// This is assembly code. Don't assume it's well-formed.
		// TODO: Empirically we still need the fd == nil check. Why?
		//
		// TODO: Are there cases that are safe but don't have a
		// locals pointer map, like empty frame functions?
		// It might be possible to preempt any assembly functions
		// except the ones that have funcFlag_SPWRITE set in f.flag.
		return false, 0
	}
	// Check the inner-most name
	u, uf := newInlineUnwinder(f, pc)
	name := u.srcFunc(uf).name()
	if stringslite.HasPrefix(name, "runtime.") ||
		stringslite.HasPrefix(name, "runtime/internal/") ||
		stringslite.HasPrefix(name, "reflect.") {
		// For now we never async preempt the runtime or
		// anything closely tied to the runtime. Known issues
		// include: various points in the scheduler ("don't
		// preempt between here and here"), much of the defer
		// implementation (untyped info on stack), bulk write
		// barriers (write barrier check),
		// reflect.{makeFuncStub,methodValueCall}.
		//
		// TODO(austin): We should improve this, or opt things
		// in incrementally.
		return false, 0
	}
	switch up {
	case abi.UnsafePointRestart1, abi.UnsafePointRestart2:
		// Restartable instruction sequence. Back off PC to
		// the start PC.
		if startpc == 0 || startpc > pc || pc-startpc > 20 {
			throw("bad restart PC")
		}
		return true, startpc
	case abi.UnsafePointRestartAtEntry:
		// Restart from the function entry at resumption.
		return true, f.entry()
	}
	return true, pc
}
```