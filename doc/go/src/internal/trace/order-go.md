Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The primary goal is to explain the functionality of the provided Go code snippet, which seems to be related to tracing and event ordering. The request specifically asks for a summary of its functions, identification of the Go feature it implements, illustrative code examples, details on command-line arguments (if applicable), common mistakes, and a final summary. The prompt also mentions it's the first part of a two-part piece.

2. **Initial Code Scan and Keyword Identification:** I'll quickly scan the code looking for key terms and structures. I see:
    * `package trace`:  Confirms it's part of a tracing mechanism.
    * `ordering struct`:  This is the central data structure. The fields (`gStates`, `pStates`, `mStates`, `activeTasks`, `gcSeq`, `gcState`, `initialGen`, `queue`) strongly suggest it's managing the state of goroutines, processors, machines (threads), tasks, and garbage collection.
    * `Advance` and `Next` methods: These suggest a producer-consumer pattern where `Advance` adds events and `Next` retrieves them in order.
    * `orderingDispatch`:  This looks like a dispatch table, mapping event types to handler functions. This is a common pattern for processing different types of trace events.
    * Event types like `EvProcsChange`, `EvGoCreate`, `EvGoStart`, `EvGCBegin`, etc.: These are clearly tracing events related to the Go runtime.
    * Comments mentioning "validation" and "putting events in the right order": This confirms the core purpose.
    * References to Go versions (e.g., `go122`):  Indicates version-specific event handling.

3. **Formulate a High-Level Description:** Based on the initial scan, I can deduce that this code is responsible for taking raw trace events and organizing them into a consistent and valid order, likely for analysis or visualization. It maintains internal state about the Go runtime's scheduler to ensure events are processed correctly.

4. **Identify the Core Functionality (`ordering` struct and its methods):** The `ordering` struct is the heart of the system. The `Advance` method attempts to process a new event, updating the internal state and adding completed events to the `queue`. The `Next` method (though not shown in this part) is implied to retrieve events from the `queue`.

5. **Analyze the `Advance` Method:**  I'll examine the `Advance` method more closely:
    * It takes an event (`ev`, `evt`), the thread ID (`m`), and a generation number (`gen`).
    * It manages state using maps: `gStates`, `pStates`, `mStates`.
    * It uses the `orderingDispatch` table to call specific handler functions based on the event type.
    * The handler functions (like `advanceProcStart`, `advanceGoCreate`) modify the internal state.
    * The method returns a boolean indicating if the event was successfully advanced and an error if something went wrong.
    * It updates `mState` to keep track of which goroutine and processor are running on a particular thread.

6. **Focus on the `orderingDispatch` Table:** This is crucial for understanding *what* the code does. I'll list the categories of events it handles:
    * Processor-related events (`EvProcStart`, `EvProcStop`, etc.)
    * Goroutine-related events (`EvGoCreate`, `EvGoStart`, `EvGoBlock`, etc.)
    * Stop-the-world (STW) events (`EvSTWBegin`, `EvSTWEnd`)
    * Garbage collection (GC) events (`EvGCBegin`, `EvGCEnd`, etc.)
    * Annotation events (`EvGoLabel`, `EvUserTaskBegin`, etc.)
    * Coroutine switch events (`EvGoSwitch`, `EvGoSwitchDestroy`)
    * Experimental events (span, heap object, goroutine stack)

7. **Infer the Go Feature:**  Given the focus on goroutines, processors, scheduling states, and tracing, it's highly likely this code is part of the implementation for **Go's execution tracing facility (often accessed via the `runtime/trace` package)**. This facility allows developers to record runtime events for performance analysis.

8. **Consider Code Examples (Though Limited by the Snippet):**  Since the request asks for code examples, and this snippet is internal, I need to think about *how* a user would interact with the *external* tracing API. This involves starting and stopping tracing, and then potentially analyzing the trace data. However, the *ordering* logic itself is hidden from the user. Therefore, the example will focus on how a user *generates* trace data, which this `order.go` file would then process internally.

9. **Address Command-Line Arguments (Likely None Directly):** The provided code is internal. It's unlikely to directly process command-line arguments. The tracing facility is typically controlled through Go program code (e.g., `runtime/trace.Start`, `runtime/trace.Stop`) or via environment variables. Therefore, I'll explain that the code itself doesn't handle command-line arguments directly, but the *tracing facility it supports* might be influenced by environment variables or programmatically set options.

10. **Think About Common Mistakes (Based on the Logic):**  Given the complexity of managing scheduler state and event ordering, potential mistakes would likely involve:
    * **Incorrectly interpreting the order of events:** This code aims to *prevent* this, but users analyzing raw traces without such ordering logic could easily misunderstand the timeline.
    * **Assuming events happen atomically:** The tracing mechanism captures points in time, and the ordering logic helps to reconstruct the relationships between these points.
    * **Misunderstanding the different states of goroutines and processors:**  The `gStates` and `pStates` are critical, and misunderstanding these states could lead to incorrect analysis.

11. **Draft the Summary:**  Finally, I'll synthesize the information gathered into a concise summary of the code's functionality. This summary should highlight the key responsibilities: event validation, state management, and ensuring correct ordering.

12. **Review and Refine:** I'll reread the request and my answer to make sure I've addressed all the points and that the explanation is clear and accurate. I'll ensure the language is appropriate and avoids overly technical jargon where possible. I'll also double-check that I've correctly identified the Go feature being implemented.

By following these steps, I can construct a comprehensive answer that addresses all aspects of the request, even with the limitation of only having a partial code snippet. The key is to infer the overall purpose and context based on the structure and content of the provided code.
这是 `go/src/internal/trace/order.go` 文件的一部分，它主要负责**对 Go 程序的执行跟踪事件进行排序和验证**。

**功能归纳:**

这段代码的核心功能是维护 Go 调度器的状态的模拟，并利用这个模拟来：

1. **验证跟踪事件的顺序和有效性**：`Advance` 方法接收一个事件，并根据当前模拟的调度器状态来判断这个事件是否应该发生在这个时间点。如果事件与预期的状态不符，`Advance` 方法会返回错误，表明跟踪数据可能存在问题或顺序错误。

2. **将事件放入正确的顺序**：虽然 `Advance` 方法主要负责验证，但它也通过 `queue` 将验证通过的事件存储起来。`Next` 方法（在这部分代码中未展示，但从注释可以推断出）会从 `queue` 中按正确的顺序取出事件。

3. **维护 Goroutine、Processor (P) 和 Machine/Thread (M) 的状态**：`ordering` 结构体中包含了 `gStates`、`pStates` 和 `mStates` 这几个 map，分别用于存储 Goroutine、P 和 M 的状态信息，例如 Goroutine 的运行状态（running, runnable, waiting 等），P 的状态（idle, running, syscall 等），以及 M 当前绑定的 G 和 P。

4. **处理不同类型的跟踪事件**：`orderingDispatch` 是一个函数指针数组，它将不同的事件类型映射到相应的处理函数 (`advance...`)。每个处理函数负责根据特定的事件类型更新调度器状态。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言**执行跟踪 (Execution Tracing)** 功能的内部实现的一部分。Go 的执行跟踪允许开发者记录程序运行时的各种事件，例如 Goroutine 的创建、启动、阻塞、系统调用，以及 GC 的过程等。这些跟踪数据可以用于性能分析和问题排查。

**Go 代码举例说明:**

虽然 `go/src/internal/trace/order.go` 是内部实现，用户一般不会直接调用其中的方法。用户通常通过 `runtime/trace` 包提供的 API 来启动和停止跟踪，以及分析跟踪数据。

以下是一个简单的 Go 代码示例，演示如何启动和停止跟踪：

```go
package main

import (
	"fmt"
	"os"
	"runtime/trace"
)

func main() {
	// 创建一个用于保存跟踪数据的文件
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// 启动跟踪
	if err := trace.Start(f); err != nil {
		panic(err)
	}
	defer trace.Stop()

	// 一些需要跟踪的代码
	fmt.Println("Hello, tracing!")
}
```

在这个例子中，`trace.Start(f)` 启动了跟踪，所有的运行时事件会被写入到 `trace.out` 文件中。`trace.Stop()` 停止跟踪。

`go/src/internal/trace/order.go` 中的代码会在 Go 运行时内部被调用，用于处理这些生成的跟踪事件，确保它们被正确地排序和验证。

**代码推理 (假设的输入与输出):**

假设我们有以下两个跟踪事件，发生在同一个线程 `m1` 上：

1. **事件 1:** `EvGoCreate` (创建 Goroutine), `gid=10`, `parent_gid=1`, `time=100`
2. **事件 2:** `EvGoStart` (启动 Goroutine), `gid=10`, `time=150`

假设当前 `ordering` 结构体的状态如下：

* `gStates`: 包含 Goroutine `1`，状态为 `GoRunning`
* `mStates`: 包含线程 `m1`，当前运行的 Goroutine 为 `1`

**调用 `Advance` 处理事件 1:**

* **输入:** `ev` 为 `EvGoCreate` 事件，`evt` 为对应的事件表，`m = m1`, `gen` 为当前 generation number。
* `ordering.Advance` 会调用 `(*ordering).advanceGoCreate` 函数。
* `advanceGoCreate` 函数会检查当前线程 `m1` 是否绑定了一个正在运行的 P (假设是) 以及当前 Goroutine (`1`) 是否正在运行。
* 由于是 `EvGoCreate` 事件，会创建一个新的 `gState` 并添加到 `o.gStates` 中，`gid=10`, 状态为 `GoRunnable` (默认创建状态)。
* **输出:** `Advance` 返回 `true`, `err` 为 `nil`。事件会被添加到 `o.queue` 中。

**调用 `Advance` 处理事件 2:**

* **输入:** `ev` 为 `EvGoStart` 事件，`evt` 为对应的事件表，`m = m1`, `gen` 为当前 generation number。
* `ordering.Advance` 会调用 `(*ordering).advanceGoStart` 函数。
* `advanceGoStart` 函数会检查 Goroutine `10` 是否存在并且状态为 `GoRunnable`。
* 它还会检查当前线程 `m1` 是否绑定了一个 P 并且没有正在运行的 Goroutine (因为 `GoStart` 表示开始在一个 P 上运行)。
* 如果所有检查都通过，`advanceGoStart` 会更新 Goroutine `10` 的状态为 `GoRunning`，并将线程 `m1` 的状态更新为运行 Goroutine `10`。
* **输出:** `Advance` 返回 `true`, `err` 为 `nil`。事件会被添加到 `o.queue` 中。

**命令行参数:**

这段代码本身不直接处理命令行参数。Go 程序的执行跟踪通常通过 `runtime/trace` 包的 API 函数来控制，或者通过设置特定的环境变量（例如 `GOTRACE`）来启用。

**易犯错的点:**

由于这段代码是内部实现，普通开发者不会直接使用。但是，如果开发者尝试自己解析和处理 Go 的跟踪数据，可能会犯以下错误：

* **假设事件总是按时间顺序到达:**  实际的跟踪事件可能会因为各种原因（例如网络延迟，操作系统调度）而乱序到达。`go/src/internal/trace/order.go` 的存在就是为了解决这个问题。
* **不理解 Goroutine 和 P/M 的状态转换:**  跟踪事件反映了 Goroutine 和 P/M 的状态变化。不理解这些状态的含义和转换规则可能会导致错误地解释跟踪数据。例如，一个 Goroutine 可能在不同的时间点处于 `GoRunnable`, `GoRunning`, `GoWaiting` 等不同的状态。
* **忽略事件之间的依赖关系:**  某些事件的发生依赖于其他事件。例如，一个 `EvGoStart` 事件必须在一个 `EvGoCreate` 事件之后发生。`go/src/internal/trace/order.go` 负责检查这些依赖关系。

**总结一下它的功能:**

总而言之，`go/src/internal/trace/order.go` 的这段代码是 Go 语言执行跟踪功能的核心组成部分，它通过模拟 Go 调度器的状态，来验证和排序接收到的跟踪事件。这确保了跟踪数据的准确性和一致性，为后续的分析和可视化提供了可靠的基础。

Prompt: 
```
这是路径为go/src/internal/trace/order.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"fmt"
	"strings"

	"internal/trace/event"
	"internal/trace/event/go122"
	"internal/trace/version"
)

// ordering emulates Go scheduler state for both validation and
// for putting events in the right order.
//
// The interface to ordering consists of two methods: Advance
// and Next. Advance is called to try and advance an event and
// add completed events to the ordering. Next is used to pick
// off events in the ordering.
type ordering struct {
	gStates     map[GoID]*gState
	pStates     map[ProcID]*pState // TODO: The keys are dense, so this can be a slice.
	mStates     map[ThreadID]*mState
	activeTasks map[TaskID]taskState
	gcSeq       uint64
	gcState     gcState
	initialGen  uint64
	queue       queue[Event]
}

// Advance checks if it's valid to proceed with ev which came from thread m.
//
// It assumes the gen value passed to it is monotonically increasing across calls.
//
// If any error is returned, then the trace is broken and trace parsing must cease.
// If it's not valid to advance with ev, but no error was encountered, the caller
// should attempt to advance with other candidate events from other threads. If the
// caller runs out of candidates, the trace is invalid.
//
// If this returns true, Next is guaranteed to return a complete event. However,
// multiple events may be added to the ordering, so the caller should (but is not
// required to) continue to call Next until it is exhausted.
func (o *ordering) Advance(ev *baseEvent, evt *evTable, m ThreadID, gen uint64) (bool, error) {
	if o.initialGen == 0 {
		// Set the initial gen if necessary.
		o.initialGen = gen
	}

	var curCtx, newCtx schedCtx
	curCtx.M = m
	newCtx.M = m

	var ms *mState
	if m == NoThread {
		curCtx.P = NoProc
		curCtx.G = NoGoroutine
		newCtx = curCtx
	} else {
		// Pull out or create the mState for this event.
		var ok bool
		ms, ok = o.mStates[m]
		if !ok {
			ms = &mState{
				g: NoGoroutine,
				p: NoProc,
			}
			o.mStates[m] = ms
		}
		curCtx.P = ms.p
		curCtx.G = ms.g
		newCtx = curCtx
	}

	f := orderingDispatch[ev.typ]
	if f == nil {
		return false, fmt.Errorf("bad event type found while ordering: %v", ev.typ)
	}
	newCtx, ok, err := f(o, ev, evt, m, gen, curCtx)
	if err == nil && ok && ms != nil {
		// Update the mState for this event.
		ms.p = newCtx.P
		ms.g = newCtx.G
	}
	return ok, err
}

type orderingHandleFunc func(o *ordering, ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error)

var orderingDispatch = [256]orderingHandleFunc{
	// Procs.
	go122.EvProcsChange: (*ordering).advanceAnnotation,
	go122.EvProcStart:   (*ordering).advanceProcStart,
	go122.EvProcStop:    (*ordering).advanceProcStop,
	go122.EvProcSteal:   (*ordering).advanceProcSteal,
	go122.EvProcStatus:  (*ordering).advanceProcStatus,

	// Goroutines.
	go122.EvGoCreate:            (*ordering).advanceGoCreate,
	go122.EvGoCreateSyscall:     (*ordering).advanceGoCreateSyscall,
	go122.EvGoStart:             (*ordering).advanceGoStart,
	go122.EvGoDestroy:           (*ordering).advanceGoStopExec,
	go122.EvGoDestroySyscall:    (*ordering).advanceGoDestroySyscall,
	go122.EvGoStop:              (*ordering).advanceGoStopExec,
	go122.EvGoBlock:             (*ordering).advanceGoStopExec,
	go122.EvGoUnblock:           (*ordering).advanceGoUnblock,
	go122.EvGoSyscallBegin:      (*ordering).advanceGoSyscallBegin,
	go122.EvGoSyscallEnd:        (*ordering).advanceGoSyscallEnd,
	go122.EvGoSyscallEndBlocked: (*ordering).advanceGoSyscallEndBlocked,
	go122.EvGoStatus:            (*ordering).advanceGoStatus,

	// STW.
	go122.EvSTWBegin: (*ordering).advanceGoRangeBegin,
	go122.EvSTWEnd:   (*ordering).advanceGoRangeEnd,

	// GC events.
	go122.EvGCActive:           (*ordering).advanceGCActive,
	go122.EvGCBegin:            (*ordering).advanceGCBegin,
	go122.EvGCEnd:              (*ordering).advanceGCEnd,
	go122.EvGCSweepActive:      (*ordering).advanceGCSweepActive,
	go122.EvGCSweepBegin:       (*ordering).advanceGCSweepBegin,
	go122.EvGCSweepEnd:         (*ordering).advanceGCSweepEnd,
	go122.EvGCMarkAssistActive: (*ordering).advanceGoRangeActive,
	go122.EvGCMarkAssistBegin:  (*ordering).advanceGoRangeBegin,
	go122.EvGCMarkAssistEnd:    (*ordering).advanceGoRangeEnd,
	go122.EvHeapAlloc:          (*ordering).advanceHeapMetric,
	go122.EvHeapGoal:           (*ordering).advanceHeapMetric,

	// Annotations.
	go122.EvGoLabel:         (*ordering).advanceAnnotation,
	go122.EvUserTaskBegin:   (*ordering).advanceUserTaskBegin,
	go122.EvUserTaskEnd:     (*ordering).advanceUserTaskEnd,
	go122.EvUserRegionBegin: (*ordering).advanceUserRegionBegin,
	go122.EvUserRegionEnd:   (*ordering).advanceUserRegionEnd,
	go122.EvUserLog:         (*ordering).advanceAnnotation,

	// Coroutines. Added in Go 1.23.
	go122.EvGoSwitch:        (*ordering).advanceGoSwitch,
	go122.EvGoSwitchDestroy: (*ordering).advanceGoSwitch,
	go122.EvGoCreateBlocked: (*ordering).advanceGoCreate,

	// GoStatus event with a stack. Added in Go 1.23.
	go122.EvGoStatusStack: (*ordering).advanceGoStatus,

	// Experimental events.

	// Experimental heap span events. Added in Go 1.23.
	go122.EvSpan:      (*ordering).advanceAllocFree,
	go122.EvSpanAlloc: (*ordering).advanceAllocFree,
	go122.EvSpanFree:  (*ordering).advanceAllocFree,

	// Experimental heap object events. Added in Go 1.23.
	go122.EvHeapObject:      (*ordering).advanceAllocFree,
	go122.EvHeapObjectAlloc: (*ordering).advanceAllocFree,
	go122.EvHeapObjectFree:  (*ordering).advanceAllocFree,

	// Experimental goroutine stack events. Added in Go 1.23.
	go122.EvGoroutineStack:      (*ordering).advanceAllocFree,
	go122.EvGoroutineStackAlloc: (*ordering).advanceAllocFree,
	go122.EvGoroutineStackFree:  (*ordering).advanceAllocFree,
}

func (o *ordering) advanceProcStatus(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	pid := ProcID(ev.args[0])
	status := go122.ProcStatus(ev.args[1])
	if int(status) >= len(go122ProcStatus2ProcState) {
		return curCtx, false, fmt.Errorf("invalid status for proc %d: %d", pid, status)
	}
	oldState := go122ProcStatus2ProcState[status]
	if s, ok := o.pStates[pid]; ok {
		if status == go122.ProcSyscallAbandoned && s.status == go122.ProcSyscall {
			// ProcSyscallAbandoned is a special case of ProcSyscall. It indicates a
			// potential loss of information, but if we're already in ProcSyscall,
			// we haven't lost the relevant information. Promote the status and advance.
			oldState = ProcRunning
			ev.args[1] = uint64(go122.ProcSyscall)
		} else if status == go122.ProcSyscallAbandoned && s.status == go122.ProcSyscallAbandoned {
			// If we're passing through ProcSyscallAbandoned, then there's no promotion
			// to do. We've lost the M that this P is associated with. However it got there,
			// it's going to appear as idle in the API, so pass through as idle.
			oldState = ProcIdle
			ev.args[1] = uint64(go122.ProcSyscallAbandoned)
		} else if s.status != status {
			return curCtx, false, fmt.Errorf("inconsistent status for proc %d: old %v vs. new %v", pid, s.status, status)
		}
		s.seq = makeSeq(gen, 0) // Reset seq.
	} else {
		o.pStates[pid] = &pState{id: pid, status: status, seq: makeSeq(gen, 0)}
		if gen == o.initialGen {
			oldState = ProcUndetermined
		} else {
			oldState = ProcNotExist
		}
	}
	ev.extra(version.Go122)[0] = uint64(oldState) // Smuggle in the old state for StateTransition.

	// Bind the proc to the new context, if it's running.
	newCtx := curCtx
	if status == go122.ProcRunning || status == go122.ProcSyscall {
		newCtx.P = pid
	}
	// If we're advancing through ProcSyscallAbandoned *but* oldState is running then we've
	// promoted it to ProcSyscall. However, because it's ProcSyscallAbandoned, we know this
	// P is about to get stolen and its status very likely isn't being emitted by the same
	// thread it was bound to. Since this status is Running -> Running and Running is binding,
	// we need to make sure we emit it in the right context: the context to which it is bound.
	// Find it, and set our current context to it.
	if status == go122.ProcSyscallAbandoned && oldState == ProcRunning {
		// N.B. This is slow but it should be fairly rare.
		found := false
		for mid, ms := range o.mStates {
			if ms.p == pid {
				curCtx.M = mid
				curCtx.P = pid
				curCtx.G = ms.g
				found = true
			}
		}
		if !found {
			return curCtx, false, fmt.Errorf("failed to find sched context for proc %d that's about to be stolen", pid)
		}
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceProcStart(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	pid := ProcID(ev.args[0])
	seq := makeSeq(gen, ev.args[1])

	// Try to advance. We might fail here due to sequencing, because the P hasn't
	// had a status emitted, or because we already have a P and we're in a syscall,
	// and we haven't observed that it was stolen from us yet.
	state, ok := o.pStates[pid]
	if !ok || state.status != go122.ProcIdle || !seq.succeeds(state.seq) || curCtx.P != NoProc {
		// We can't make an inference as to whether this is bad. We could just be seeing
		// a ProcStart on a different M before the proc's state was emitted, or before we
		// got to the right point in the trace.
		//
		// Note that we also don't advance here if we have a P and we're in a syscall.
		return curCtx, false, nil
	}
	// We can advance this P. Check some invariants.
	//
	// We might have a goroutine if a goroutine is exiting a syscall.
	reqs := event.SchedReqs{Thread: event.MustHave, Proc: event.MustNotHave, Goroutine: event.MayHave}
	if err := validateCtx(curCtx, reqs); err != nil {
		return curCtx, false, err
	}
	state.status = go122.ProcRunning
	state.seq = seq
	newCtx := curCtx
	newCtx.P = pid
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceProcStop(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// We must be able to advance this P.
	//
	// There are 2 ways a P can stop: ProcStop and ProcSteal. ProcStop is used when the P
	// is stopped by the same M that started it, while ProcSteal is used when another M
	// steals the P by stopping it from a distance.
	//
	// Since a P is bound to an M, and we're stopping on the same M we started, it must
	// always be possible to advance the current M's P from a ProcStop. This is also why
	// ProcStop doesn't need a sequence number.
	state, ok := o.pStates[curCtx.P]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for proc (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.P)
	}
	if state.status != go122.ProcRunning && state.status != go122.ProcSyscall {
		return curCtx, false, fmt.Errorf("%s event for proc that's not %s or %s", go122.EventString(ev.typ), go122.ProcRunning, go122.ProcSyscall)
	}
	reqs := event.SchedReqs{Thread: event.MustHave, Proc: event.MustHave, Goroutine: event.MayHave}
	if err := validateCtx(curCtx, reqs); err != nil {
		return curCtx, false, err
	}
	state.status = go122.ProcIdle
	newCtx := curCtx
	newCtx.P = NoProc
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceProcSteal(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	pid := ProcID(ev.args[0])
	seq := makeSeq(gen, ev.args[1])
	state, ok := o.pStates[pid]
	if !ok || (state.status != go122.ProcSyscall && state.status != go122.ProcSyscallAbandoned) || !seq.succeeds(state.seq) {
		// We can't make an inference as to whether this is bad. We could just be seeing
		// a ProcStart on a different M before the proc's state was emitted, or before we
		// got to the right point in the trace.
		return curCtx, false, nil
	}
	// We can advance this P. Check some invariants.
	reqs := event.SchedReqs{Thread: event.MustHave, Proc: event.MayHave, Goroutine: event.MayHave}
	if err := validateCtx(curCtx, reqs); err != nil {
		return curCtx, false, err
	}
	// Smuggle in the P state that let us advance so we can surface information to the event.
	// Specifically, we need to make sure that the event is interpreted not as a transition of
	// ProcRunning -> ProcIdle but ProcIdle -> ProcIdle instead.
	//
	// ProcRunning is binding, but we may be running with a P on the current M and we can't
	// bind another P. This P is about to go ProcIdle anyway.
	oldStatus := state.status
	ev.extra(version.Go122)[0] = uint64(oldStatus)

	// Update the P's status and sequence number.
	state.status = go122.ProcIdle
	state.seq = seq

	// If we've lost information then don't try to do anything with the M.
	// It may have moved on and we can't be sure.
	if oldStatus == go122.ProcSyscallAbandoned {
		o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
		return curCtx, true, nil
	}

	// Validate that the M we're stealing from is what we expect.
	mid := ThreadID(ev.args[2]) // The M we're stealing from.

	newCtx := curCtx
	if mid == curCtx.M {
		// We're stealing from ourselves. This behaves like a ProcStop.
		if curCtx.P != pid {
			return curCtx, false, fmt.Errorf("tried to self-steal proc %d (thread %d), but got proc %d instead", pid, mid, curCtx.P)
		}
		newCtx.P = NoProc
		o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
		return newCtx, true, nil
	}

	// We're stealing from some other M.
	mState, ok := o.mStates[mid]
	if !ok {
		return curCtx, false, fmt.Errorf("stole proc from non-existent thread %d", mid)
	}

	// Make sure we're actually stealing the right P.
	if mState.p != pid {
		return curCtx, false, fmt.Errorf("tried to steal proc %d from thread %d, but got proc %d instead", pid, mid, mState.p)
	}

	// Tell the M it has no P so it can proceed.
	//
	// This is safe because we know the P was in a syscall and
	// the other M must be trying to get out of the syscall.
	// GoSyscallEndBlocked cannot advance until the corresponding
	// M loses its P.
	mState.p = NoProc
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceGoStatus(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	gid := GoID(ev.args[0])
	mid := ThreadID(ev.args[1])
	status := go122.GoStatus(ev.args[2])

	if int(status) >= len(go122GoStatus2GoState) {
		return curCtx, false, fmt.Errorf("invalid status for goroutine %d: %d", gid, status)
	}
	oldState := go122GoStatus2GoState[status]
	if s, ok := o.gStates[gid]; ok {
		if s.status != status {
			return curCtx, false, fmt.Errorf("inconsistent status for goroutine %d: old %v vs. new %v", gid, s.status, status)
		}
		s.seq = makeSeq(gen, 0) // Reset seq.
	} else if gen == o.initialGen {
		// Set the state.
		o.gStates[gid] = &gState{id: gid, status: status, seq: makeSeq(gen, 0)}
		oldState = GoUndetermined
	} else {
		return curCtx, false, fmt.Errorf("found goroutine status for new goroutine after the first generation: id=%v status=%v", gid, status)
	}
	ev.args[2] = uint64(oldState)<<32 | uint64(status) // Smuggle in the old state for StateTransition.

	newCtx := curCtx
	switch status {
	case go122.GoRunning:
		// Bind the goroutine to the new context, since it's running.
		newCtx.G = gid
	case go122.GoSyscall:
		if mid == NoThread {
			return curCtx, false, fmt.Errorf("found goroutine %d in syscall without a thread", gid)
		}
		// Is the syscall on this thread? If so, bind it to the context.
		// Otherwise, we're talking about a G sitting in a syscall on an M.
		// Validate the named M.
		if mid == curCtx.M {
			if gen != o.initialGen && curCtx.G != gid {
				// If this isn't the first generation, we *must* have seen this
				// binding occur already. Even if the G was blocked in a syscall
				// for multiple generations since trace start, we would have seen
				// a previous GoStatus event that bound the goroutine to an M.
				return curCtx, false, fmt.Errorf("inconsistent thread for syscalling goroutine %d: thread has goroutine %d", gid, curCtx.G)
			}
			newCtx.G = gid
			break
		}
		// Now we're talking about a thread and goroutine that have been
		// blocked on a syscall for the entire generation. This case must
		// not have a P; the runtime makes sure that all Ps are traced at
		// the beginning of a generation, which involves taking a P back
		// from every thread.
		ms, ok := o.mStates[mid]
		if ok {
			// This M has been seen. That means we must have seen this
			// goroutine go into a syscall on this thread at some point.
			if ms.g != gid {
				// But the G on the M doesn't match. Something's wrong.
				return curCtx, false, fmt.Errorf("inconsistent thread for syscalling goroutine %d: thread has goroutine %d", gid, ms.g)
			}
			// This case is just a Syscall->Syscall event, which needs to
			// appear as having the G currently bound to this M.
			curCtx.G = ms.g
		} else if !ok {
			// The M hasn't been seen yet. That means this goroutine
			// has just been sitting in a syscall on this M. Create
			// a state for it.
			o.mStates[mid] = &mState{g: gid, p: NoProc}
			// Don't set curCtx.G in this case because this event is the
			// binding event (and curCtx represents the "before" state).
		}
		// Update the current context to the M we're talking about.
		curCtx.M = mid
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceGoCreate(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Goroutines must be created on a running P, but may or may not be created
	// by a running goroutine.
	reqs := event.SchedReqs{Thread: event.MustHave, Proc: event.MustHave, Goroutine: event.MayHave}
	if err := validateCtx(curCtx, reqs); err != nil {
		return curCtx, false, err
	}
	// If we have a goroutine, it must be running.
	if state, ok := o.gStates[curCtx.G]; ok && state.status != go122.GoRunning {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %s", go122.EventString(ev.typ), GoRunning)
	}
	// This goroutine created another. Add a state for it.
	newgid := GoID(ev.args[0])
	if _, ok := o.gStates[newgid]; ok {
		return curCtx, false, fmt.Errorf("tried to create goroutine (%v) that already exists", newgid)
	}
	status := go122.GoRunnable
	if ev.typ == go122.EvGoCreateBlocked {
		status = go122.GoWaiting
	}
	o.gStates[newgid] = &gState{id: newgid, status: status, seq: makeSeq(gen, 0)}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoStopExec(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// These are goroutine events that all require an active running
	// goroutine on some thread. They must *always* be advance-able,
	// since running goroutines are bound to their M.
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	state, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for goroutine (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.G)
	}
	if state.status != go122.GoRunning {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %s", go122.EventString(ev.typ), GoRunning)
	}
	// Handle each case slightly differently; we just group them together
	// because they have shared preconditions.
	newCtx := curCtx
	switch ev.typ {
	case go122.EvGoDestroy:
		// This goroutine is exiting itself.
		delete(o.gStates, curCtx.G)
		newCtx.G = NoGoroutine
	case go122.EvGoStop:
		// Goroutine stopped (yielded). It's runnable but not running on this M.
		state.status = go122.GoRunnable
		newCtx.G = NoGoroutine
	case go122.EvGoBlock:
		// Goroutine blocked. It's waiting now and not running on this M.
		state.status = go122.GoWaiting
		newCtx.G = NoGoroutine
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceGoStart(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	gid := GoID(ev.args[0])
	seq := makeSeq(gen, ev.args[1])
	state, ok := o.gStates[gid]
	if !ok || state.status != go122.GoRunnable || !seq.succeeds(state.seq) {
		// We can't make an inference as to whether this is bad. We could just be seeing
		// a GoStart on a different M before the goroutine was created, before it had its
		// state emitted, or before we got to the right point in the trace yet.
		return curCtx, false, nil
	}
	// We can advance this goroutine. Check some invariants.
	reqs := event.SchedReqs{Thread: event.MustHave, Proc: event.MustHave, Goroutine: event.MustNotHave}
	if err := validateCtx(curCtx, reqs); err != nil {
		return curCtx, false, err
	}
	state.status = go122.GoRunning
	state.seq = seq
	newCtx := curCtx
	newCtx.G = gid
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceGoUnblock(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// N.B. These both reference the goroutine to unblock, not the current goroutine.
	gid := GoID(ev.args[0])
	seq := makeSeq(gen, ev.args[1])
	state, ok := o.gStates[gid]
	if !ok || state.status != go122.GoWaiting || !seq.succeeds(state.seq) {
		// We can't make an inference as to whether this is bad. We could just be seeing
		// a GoUnblock on a different M before the goroutine was created and blocked itself,
		// before it had its state emitted, or before we got to the right point in the trace yet.
		return curCtx, false, nil
	}
	state.status = go122.GoRunnable
	state.seq = seq
	// N.B. No context to validate. Basically anything can unblock
	// a goroutine (e.g. sysmon).
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoSwitch(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// GoSwitch and GoSwitchDestroy represent a trio of events:
	// - Unblock of the goroutine to switch to.
	// - Block or destroy of the current goroutine.
	// - Start executing the next goroutine.
	//
	// Because it acts like a GoStart for the next goroutine, we can
	// only advance it if the sequence numbers line up.
	//
	// The current goroutine on the thread must be actively running.
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	curGState, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for goroutine (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.G)
	}
	if curGState.status != go122.GoRunning {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %s", go122.EventString(ev.typ), GoRunning)
	}
	nextg := GoID(ev.args[0])
	seq := makeSeq(gen, ev.args[1]) // seq is for nextg, not curCtx.G.
	nextGState, ok := o.gStates[nextg]
	if !ok || nextGState.status != go122.GoWaiting || !seq.succeeds(nextGState.seq) {
		// We can't make an inference as to whether this is bad. We could just be seeing
		// a GoSwitch on a different M before the goroutine was created, before it had its
		// state emitted, or before we got to the right point in the trace yet.
		return curCtx, false, nil
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})

	// Update the state of the executing goroutine and emit an event for it
	// (GoSwitch and GoSwitchDestroy will be interpreted as GoUnblock events
	// for nextg).
	switch ev.typ {
	case go122.EvGoSwitch:
		// Goroutine blocked. It's waiting now and not running on this M.
		curGState.status = go122.GoWaiting

		// Emit a GoBlock event.
		// TODO(mknyszek): Emit a reason.
		o.queue.push(makeEvent(evt, curCtx, go122.EvGoBlock, ev.time, 0 /* no reason */, 0 /* no stack */))
	case go122.EvGoSwitchDestroy:
		// This goroutine is exiting itself.
		delete(o.gStates, curCtx.G)

		// Emit a GoDestroy event.
		o.queue.push(makeEvent(evt, curCtx, go122.EvGoDestroy, ev.time))
	}
	// Update the state of the next goroutine.
	nextGState.status = go122.GoRunning
	nextGState.seq = seq
	newCtx := curCtx
	newCtx.G = nextg

	// Queue an event for the next goroutine starting to run.
	startCtx := curCtx
	startCtx.G = NoGoroutine
	o.queue.push(makeEvent(evt, startCtx, go122.EvGoStart, ev.time, uint64(nextg), ev.args[1]))
	return newCtx, true, nil
}

func (o *ordering) advanceGoSyscallBegin(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Entering a syscall requires an active running goroutine with a
	// proc on some thread. It is always advancable.
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	state, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for goroutine (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.G)
	}
	if state.status != go122.GoRunning {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %s", go122.EventString(ev.typ), GoRunning)
	}
	// Goroutine entered a syscall. It's still running on this P and M.
	state.status = go122.GoSyscall
	pState, ok := o.pStates[curCtx.P]
	if !ok {
		return curCtx, false, fmt.Errorf("uninitialized proc %d found during %s", curCtx.P, go122.EventString(ev.typ))
	}
	pState.status = go122.ProcSyscall
	// Validate the P sequence number on the event and advance it.
	//
	// We have a P sequence number for what is supposed to be a goroutine event
	// so that we can correctly model P stealing. Without this sequence number here,
	// the syscall from which a ProcSteal event is stealing can be ambiguous in the
	// face of broken timestamps. See the go122-syscall-steal-proc-ambiguous test for
	// more details.
	//
	// Note that because this sequence number only exists as a tool for disambiguation,
	// we can enforce that we have the right sequence number at this point; we don't need
	// to back off and see if any other events will advance. This is a running P.
	pSeq := makeSeq(gen, ev.args[0])
	if !pSeq.succeeds(pState.seq) {
		return curCtx, false, fmt.Errorf("failed to advance %s: can't make sequence: %s -> %s", go122.EventString(ev.typ), pState.seq, pSeq)
	}
	pState.seq = pSeq
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoSyscallEnd(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// This event is always advance-able because it happens on the same
	// thread that EvGoSyscallStart happened, and the goroutine can't leave
	// that thread until its done.
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	state, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for goroutine (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.G)
	}
	if state.status != go122.GoSyscall {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %s", go122.EventString(ev.typ), GoRunning)
	}
	state.status = go122.GoRunning

	// Transfer the P back to running from syscall.
	pState, ok := o.pStates[curCtx.P]
	if !ok {
		return curCtx, false, fmt.Errorf("uninitialized proc %d found during %s", curCtx.P, go122.EventString(ev.typ))
	}
	if pState.status != go122.ProcSyscall {
		return curCtx, false, fmt.Errorf("expected proc %d in state %v, but got %v instead", curCtx.P, go122.ProcSyscall, pState.status)
	}
	pState.status = go122.ProcRunning
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoSyscallEndBlocked(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// This event becomes advanceable when its P is not in a syscall state
	// (lack of a P altogether is also acceptable for advancing).
	// The transfer out of ProcSyscall can happen either voluntarily via
	// ProcStop or involuntarily via ProcSteal. We may also acquire a new P
	// before we get here (after the transfer out) but that's OK: that new
	// P won't be in the ProcSyscall state anymore.
	//
	// Basically: while we have a preemptible P, don't advance, because we
	// *know* from the event that we're going to lose it at some point during
	// the syscall. We shouldn't advance until that happens.
	if curCtx.P != NoProc {
		pState, ok := o.pStates[curCtx.P]
		if !ok {
			return curCtx, false, fmt.Errorf("uninitialized proc %d found during %s", curCtx.P, go122.EventString(ev.typ))
		}
		if pState.status == go122.ProcSyscall {
			return curCtx, false, nil
		}
	}
	// As mentioned above, we may have a P here if we ProcStart
	// before this event.
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MayHave, Goroutine: event.MustHave}); err != nil {
		return curCtx, false, err
	}
	state, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for goroutine (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.G)
	}
	if state.status != go122.GoSyscall {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %s", go122.EventString(ev.typ), GoRunning)
	}
	newCtx := curCtx
	newCtx.G = NoGoroutine
	state.status = go122.GoRunnable
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceGoCreateSyscall(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// This event indicates that a goroutine is effectively
	// being created out of a cgo callback. Such a goroutine
	// is 'created' in the syscall state.
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MayHave, Goroutine: event.MustNotHave}); err != nil {
		return curCtx, false, err
	}
	// This goroutine is effectively being created. Add a state for it.
	newgid := GoID(ev.args[0])
	if _, ok := o.gStates[newgid]; ok {
		return curCtx, false, fmt.Errorf("tried to create goroutine (%v) in syscall that already exists", newgid)
	}
	o.gStates[newgid] = &gState{id: newgid, status: go122.GoSyscall, seq: makeSeq(gen, 0)}
	// Goroutine is executing. Bind it to the context.
	newCtx := curCtx
	newCtx.G = newgid
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceGoDestroySyscall(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// This event indicates that a goroutine created for a
	// cgo callback is disappearing, either because the callback
	// ending or the C thread that called it is being destroyed.
	//
	// Also, treat this as if we lost our P too.
	// The thread ID may be reused by the platform and we'll get
	// really confused if we try to steal the P is this is running
	// with later. The new M with the same ID could even try to
	// steal back this P from itself!
	//
	// The runtime is careful to make sure that any GoCreateSyscall
	// event will enter the runtime emitting events for reacquiring a P.
	//
	// Note: we might have a P here. The P might not be released
	// eagerly by the runtime, and it might get stolen back later
	// (or never again, if the program is going to exit).
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MayHave, Goroutine: event.MustHave}); err != nil {
		return curCtx, false, err
	}
	// Check to make sure the goroutine exists in the right state.
	state, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("event %s for goroutine (%v) that doesn't exist", go122.EventString(ev.typ), curCtx.G)
	}
	if state.status != go122.GoSyscall {
		return curCtx, false, fmt.Errorf("%s event for goroutine that's not %v", go122.EventString(ev.typ), GoSyscall)
	}
	// This goroutine is exiting itself.
	delete(o.gStates, curCtx.G)
	newCtx := curCtx
	newCtx.G = NoGoroutine

	// If we have a proc, then we're dissociating from it now. See the comment at the top of the case.
	if curCtx.P != NoProc {
		pState, ok := o.pStates[curCtx.P]
		if !ok {
			return curCtx, false, fmt.Errorf("found invalid proc %d during %s", curCtx.P, go122.EventString(ev.typ))
		}
		if pState.status != go122.ProcSyscall {
			return curCtx, false, fmt.Errorf("proc %d in unexpected state %s during %s", curCtx.P, pState.status, go122.EventString(ev.typ))
		}
		// See the go122-create-syscall-reuse-thread-id test case for more details.
		pState.status = go122.ProcSyscallAbandoned
		newCtx.P = NoProc

		// Queue an extra self-ProcSteal event.
		extra := makeEvent(evt, curCtx, go122.EvProcSteal, ev.time, uint64(curCtx.P))
		extra.base.extra(version.Go122)[0] = uint64(go122.ProcSyscall)
		o.que
"""




```