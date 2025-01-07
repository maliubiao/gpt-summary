Response:
Let's break down the thought process for analyzing this Go code.

**1. Initial Understanding - What is the core purpose?**

The comment `// Validator is a type used for validating a stream of trace.Events.` immediately tells us the central goal: to check if a sequence of trace events is valid. This is the most important piece of information to start with.

**2. Deconstructing the `Validator` struct:**

Next, examine the fields of the `Validator` struct. These fields hold the state needed to perform the validation:

* `lastTs`:  Likely to track the timestamp of the previous event for ordering checks.
* `gs`, `ps`, `ms`: These maps store the state of Goroutines, Procs, and "Ms" (likely OS threads or scheduler threads). The `*goState`, `*procState`, and `*schedContext` types hint at what information is being tracked for each.
* `ranges`:  Keeps track of active "ranges" associated with resources. The `[]string` suggests that multiple named ranges can be active for a single resource.
* `tasks`: Stores information about active tasks.
* `seenSync`: A boolean flag, probably indicating whether a synchronization event has been encountered.
* `Go121`: Another boolean, hinting at version-specific behavior.

**3. Analyzing the `NewValidator` function:**

This is straightforward. It initializes a `Validator` with empty maps and the default `seenSync` and `Go121` values.

**4. Deep Dive into the `Event` method (the core logic):**

This is where the main validation happens. Process each `case` within the `switch ev.Kind()` block:

* **`trace.EventSync`**:  Simply sets `v.seenSync = true`. This suggests synchronization events are important for some validation rules.
* **`trace.EventMetric`**: Checks the format of metric names and the validity of metric values. The `strings.Contains(m.Name, ":")` is a key detail.
* **`trace.EventLabel`**: Validates that labels are associated with existing resources (Goroutines, Procs, or Threads).
* **`trace.EventStackSample`**:  Notes that there's not much to validate here, but it *does* mention that the stack was already checked. This suggests a separate check.
* **`trace.EventStateTransition`**:  This is the most complex case. Focus on understanding the logic for both Goroutine and Proc state transitions. Notice the duplicated logic (and the TODO comment about potential generalization). Key checks include:
    * Valid state transitions (no `Undetermined` after `Sync`).
    * Resource existence.
    * Consistency between old and new states.
    * Correct association of Goroutines and Procs with threads (`schedContext`).
* **`trace.EventRangeBegin`, `trace.EventRangeActive`, `trace.EventRangeEnd`**:  Manages the state of active ranges, ensuring proper start and end.
* **`trace.EventTaskBegin`, `trace.EventTaskEnd`**: Validates task lifecycle events.
* **`trace.EventLog`**:  Acknowledges that there isn't much to validate for log events.

**5. Analyzing Helper Functions:**

* **`hasRange`, `addRange`, `hasAnyRange`, `deleteRange`**: These functions manage the `v.ranges` map, providing utilities for checking and manipulating active ranges.
* **`getOrCreateThread`**:  Manages the `v.ms` map, creating `schedContext` entries as needed. The `lenient` function and the `v.Go121` check are important details here, indicating handling of older trace formats.
* **`checkStack`**:  Validates the structure of stack traces.

**6. Understanding `errAccumulator`:**

This is a utility for collecting multiple errors during validation. The `Errorf` and `Errors` methods are standard ways to accumulate and return errors in Go.

**7. Inferring Functionality and Providing Examples:**

Based on the analysis, deduce the overall functionality: validation of trace event streams. Then, create concrete examples demonstrating how different event types are validated and the potential errors that can occur. For example, show an out-of-order timestamp, an invalid metric name, a state transition error, etc.

**8. Identifying Potential User Errors:**

Think about the constraints enforced by the validator and how a user generating trace events might violate these constraints. Examples include incorrect timestamp ordering, invalid resource IDs, or mismatched range begin/end events.

**9. Structuring the Answer:**

Organize the findings logically:

* **功能列举**: Start with a concise summary of the validator's capabilities.
* **功能推断与代码示例**: Choose key functionalities (like state transitions or range management) and provide Go code snippets demonstrating valid and invalid scenarios. Include assumed inputs and outputs.
* **命令行参数**:  Since this code doesn't directly interact with command-line arguments, explicitly state that.
* **易犯错的点**: Based on the validation rules, identify common mistakes users might make when producing trace data.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the validator checks for *every* possible error.
* **Correction:**  The code focuses on consistency and basic structural integrity. It doesn't perform deep semantic analysis of the traced application's logic.
* **Initial thought:** The `Go121` flag is for future features.
* **Correction:** The comment in `getOrCreateThread` explains it's for handling *older* trace formats, making the validation more lenient.

By following this structured approach, dissecting the code piece by piece, and thinking about the purpose and implications of each component, we can arrive at a comprehensive and accurate understanding of the `validation.go` file.
这段代码是 Go 语言 `internal/trace` 包中用于测试目的的一部分，它实现了一个 `Validator` 类型，用于验证一系列 `trace.Event` 的流是否符合预期的格式和逻辑。简单来说，它的功能是**检查 trace 事件流的有效性**。

以下是它的主要功能点：

1. **验证时间戳顺序**: 确保事件的时间戳是递增的，不允许出现时间倒流的情况。
2. **验证事件栈信息**: 检查每个事件关联的堆栈帧信息是否完整有效，例如函数名、文件名、PC 地址和行号是否都存在。
3. **记录 `Sync` 事件**: 标记是否遇到了全局同步事件 `trace.EventSync`，这个信息可能会影响后续的状态转换验证。
4. **验证 `Metric` 事件**: 检查指标 (Metric) 事件的名称是否符合 `runtime/metrics` 的约定 (包含冒号 `:`), 并且指标的值的类型是有效的。
5. **验证 `Label` 事件**: 检查标签 (Label) 事件是否关联到有效的资源 (Goroutine, Proc, Thread)，确保标签指向的资源是存在的。
6. **跳过 `StackSample` 事件的深入验证**:  对于 `StackSample` 事件，代码注释说明不需要做太多检查，因为它主要包含调度上下文和堆栈信息，调度上下文不保证与其他事件对齐。
7. **验证 `StateTransition` 事件 (状态转换)**: 这是验证器最核心的功能之一，用于检查 Goroutine 和 Proc 的状态转换是否合法：
    * 确保状态不会转换为 `Undetermined` (未确定) 状态，除非是在第一次全局同步之前。
    * 确保 Goroutine 或 Proc 在有活跃的 Range 的情况下不会变为 `NotExist` (不存在) 状态。
    * 检查状态转换的旧状态是否与记录的当前状态一致。
    * 验证 Goroutine 和 Proc 的调度上下文 (与 Thread 的绑定) 是否正确。当 Goroutine 或 Proc 进入执行状态时，会检查是否已经有其他的 Goroutine 或 Proc 在同一个线程上执行。当退出执行状态时，会检查是否正确地解除了与线程的绑定。
8. **验证 `Range` 事件 (区间)**: 跟踪 Goroutine, Proc 或 Thread 上开始、激活和结束的命名区间。确保同一个资源上不会重复开始同一个名字的区间，并且结束的区间必须是之前开始或激活的。
9. **验证 `Task` 事件 (任务)**:
    * 检查任务开始事件的 ID 是否有效 (非 `NoTask` 或 `BackgroundTask`)。
    * 检查任务的父任务是否不是 `BackgroundTask`。
    * 验证任务结束事件的类型是否与开始事件的类型一致。
10. **验证 `Log` 事件**:  对于日志事件，基本上不做深入的检查，只确保可以生成 `Log` 结构体。

**功能推断与代码示例 (以 `StateTransition` 事件为例):**

这个 `Validator` 实现了对 Goroutine 和 Proc 状态转换的跟踪和验证。它维护了 Goroutine 和 Proc 的当前状态，并在遇到 `StateTransition` 事件时检查状态的改变是否符合逻辑。

**假设输入 (一系列 `trace.Event`):**

```go
package main

import (
	"fmt"
	"internal/trace"
	"internal/trace/testtrace"
	"time"
)

func main() {
	v := testtrace.NewValidator()

	// 假设的 Goroutine ID 和 Proc ID
	gid := trace.GoID(100)
	pid := trace.ProcID(1)
	tid := trace.ThreadID(1)
	now := time.Now()

	// Goroutine 创建事件
	err := v.Event(trace.NewEvent(now, trace.EventStateTransition, 0, 0).
		SetStateTransition(trace.ResourceGoroutine, uint64(gid), trace.GoUndetermined, trace.GoWaiting, trace.Stack{}))
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Goroutine 变为可运行状态
	now = now.Add(time.Millisecond)
	err = v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
		SetStateTransition(trace.ResourceGoroutine, uint64(gid), trace.GoWaiting, trace.GoRunnable, trace.Stack{}))
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Goroutine 在 Proc 上开始执行
	now = now.Add(time.Millisecond)
	err = v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
		SetStateTransition(trace.ResourceGoroutine, uint64(gid), trace.GoRunnable, trace.GoRunning, trace.Stack{}))
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Proc 进入执行状态
	now = now.Add(time.Microsecond)
	err = v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
		SetStateTransition(trace.ResourceProc, uint64(pid), trace.ProcIdle, trace.ProcRunning, trace.Stack{}))
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Goroutine 停止执行
	now = now.Add(time.Millisecond)
	err = v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
		SetStateTransition(trace.ResourceGoroutine, uint64(gid), trace.GoRunning, trace.GoWaiting, trace.Stack{}))
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Proc 退出执行状态
	now = now.Add(time.Microsecond)
	err = v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
		SetStateTransition(trace.ResourceProc, uint64(pid), trace.ProcRunning, trace.ProcIdle, trace.Stack{}))
	if err != nil {
		fmt.Println("Error:", err)
	}

	// ... 更多的事件
}
```

**假设输出 (如果没有错误):**

如果上述事件流是有效的，`v.Event()` 方法将返回 `nil`。如果存在任何验证错误，它将返回一个包含错误信息的 `error`。例如，如果我们在 Goroutine 变为 `GoRunnable` 之前，就发送它变为 `GoRunning` 的事件，`Validator` 将会检测到状态不一致并返回错误。

**代码推理:**

`Validator` 内部维护了 `gs` (Goroutine 状态), `ps` (Proc 状态) 和 `ms` (Thread 的调度上下文)。当接收到 `StateTransition` 事件时，它会根据事件中的资源类型 (Goroutine 或 Proc) 和新旧状态，更新或检查相应的状态信息。

例如，当一个 Goroutine 从 `GoRunnable` 状态转换为 `GoRunning` 状态时，`Validator` 会检查当前执行该 Goroutine 的线程 (`ev.Thread()`) 上是否已经有其他的 Goroutine 正在运行。如果存在，就会报错。同样，当 Proc 进入或退出 `ProcRunning` 状态时，也会检查其与线程的绑定关系。

**命令行参数的具体处理:**

这段代码本身是一个库，用于验证 trace 事件流，它**不直接处理命令行参数**。 它的使用者通常是一些工具或测试程序，这些工具或测试程序会生成或读取 trace 数据，并使用 `Validator` 来确保数据的正确性。

**使用者易犯错的点 (以 `StateTransition` 事件为例):**

1. **时间戳顺序错误**:  发送时间戳早于前一个事件的事件。`Validator` 会报错 "timestamp out-of-order"。
   ```go
   // 错误示例：时间倒流
   now1 := time.Now()
   v.Event(trace.NewEvent(now1, /* ... */))
   now2 := now1.Add(-time.Second) // now2 早于 now1
   err := v.Event(trace.NewEvent(now2, trace.EventStateTransition, /* ... */))
   fmt.Println(err) // 可能输出: timestamp out-of-order for ...
   ```

2. **状态转换不连贯**:  跳过中间状态，例如直接从 `GoWaiting` 转换到 `GoRunning`，而没有经过 `GoRunnable` 状态。`Validator` 会报错 "bad old state"。
   ```go
   // 错误示例：跳过 Runnable 状态
   gid := trace.GoID(100)
   now := time.Now()
   v.Event(trace.NewEvent(now, trace.EventStateTransition, 0, 0).
       SetStateTransition(trace.ResourceGoroutine, uint64(gid), trace.GoUndetermined, trace.GoWaiting, trace.Stack{}))
   now = now.Add(time.Millisecond)
   err := v.Event(trace.NewEvent(now, trace.EventStateTransition, 0, 0).
       SetStateTransition(trace.ResourceGoroutine, uint64(gid), trace.GoWaiting, trace.GoRunning, trace.Stack{})) // 错误：应该先转换为 GoRunnable
   fmt.Println(err) // 可能输出: bad old state for goroutine 100: got waiting, want runnable
   ```

3. **线程绑定错误**:  在同一个线程上尝试运行多个 Goroutine 或 Proc。`Validator` 会报错 "tried to run goroutine ... when one was already executing"。
   ```go
   // 错误示例：同一个线程运行多个 Goroutine
   gid1 := trace.GoID(100)
   gid2 := trace.GoID(101)
   tid := trace.ThreadID(1)
   now := time.Now()

   v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
       SetStateTransition(trace.ResourceGoroutine, uint64(gid1), trace.GoRunnable, trace.GoRunning, trace.Stack{}))

   now = now.Add(time.Millisecond)
   err := v.Event(trace.NewEvent(now, trace.EventStateTransition, uint64(tid), 0).
       SetStateTransition(trace.ResourceGoroutine, uint64(gid2), trace.GoRunnable, trace.GoRunning, trace.Stack{})) // 错误：线程 tid 已经在运行 gid1
   fmt.Println(err) // 可能输出: tried to run goroutine 101 when one was already executing (100) on thread 1
   ```

4. **Range 的开始和结束不匹配**:  尝试结束一个未开始的 Range，或者在同一个资源上重复开始同一个名字的 Range。

理解这些功能和潜在的错误点，可以帮助开发者生成有效的 Go trace 数据，并利用这个 `Validator` 进行验证。

Prompt: 
```
这是路径为go/src/internal/trace/testtrace/validation.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testtrace

import (
	"errors"
	"fmt"
	"internal/trace"
	"slices"
	"strings"
)

// Validator is a type used for validating a stream of trace.Events.
type Validator struct {
	lastTs   trace.Time
	gs       map[trace.GoID]*goState
	ps       map[trace.ProcID]*procState
	ms       map[trace.ThreadID]*schedContext
	ranges   map[trace.ResourceID][]string
	tasks    map[trace.TaskID]string
	seenSync bool
	Go121    bool
}

type schedContext struct {
	M trace.ThreadID
	P trace.ProcID
	G trace.GoID
}

type goState struct {
	state   trace.GoState
	binding *schedContext
}

type procState struct {
	state   trace.ProcState
	binding *schedContext
}

// NewValidator creates a new Validator.
func NewValidator() *Validator {
	return &Validator{
		gs:     make(map[trace.GoID]*goState),
		ps:     make(map[trace.ProcID]*procState),
		ms:     make(map[trace.ThreadID]*schedContext),
		ranges: make(map[trace.ResourceID][]string),
		tasks:  make(map[trace.TaskID]string),
	}
}

// Event validates ev as the next event in a stream of trace.Events.
//
// Returns an error if validation fails.
func (v *Validator) Event(ev trace.Event) error {
	e := new(errAccumulator)

	// Validate timestamp order.
	if v.lastTs != 0 {
		if ev.Time() <= v.lastTs {
			e.Errorf("timestamp out-of-order for %+v", ev)
		} else {
			v.lastTs = ev.Time()
		}
	} else {
		v.lastTs = ev.Time()
	}

	// Validate event stack.
	checkStack(e, ev.Stack())

	switch ev.Kind() {
	case trace.EventSync:
		// Just record that we've seen a Sync at some point.
		v.seenSync = true
	case trace.EventMetric:
		m := ev.Metric()
		if !strings.Contains(m.Name, ":") {
			// Should have a ":" as per runtime/metrics convention.
			e.Errorf("invalid metric name %q", m.Name)
		}
		// Make sure the value is OK.
		if m.Value.Kind() == trace.ValueBad {
			e.Errorf("invalid value")
		}
		switch m.Value.Kind() {
		case trace.ValueUint64:
			// Just make sure it doesn't panic.
			_ = m.Value.Uint64()
		}
	case trace.EventLabel:
		l := ev.Label()

		// Check label.
		if l.Label == "" {
			e.Errorf("invalid label %q", l.Label)
		}

		// Check label resource.
		if l.Resource.Kind == trace.ResourceNone {
			e.Errorf("label resource none")
		}
		switch l.Resource.Kind {
		case trace.ResourceGoroutine:
			id := l.Resource.Goroutine()
			if _, ok := v.gs[id]; !ok {
				e.Errorf("label for invalid goroutine %d", id)
			}
		case trace.ResourceProc:
			id := l.Resource.Proc()
			if _, ok := v.ps[id]; !ok {
				e.Errorf("label for invalid proc %d", id)
			}
		case trace.ResourceThread:
			id := l.Resource.Thread()
			if _, ok := v.ms[id]; !ok {
				e.Errorf("label for invalid thread %d", id)
			}
		}
	case trace.EventStackSample:
		// Not much to check here. It's basically a sched context and a stack.
		// The sched context is also not guaranteed to align with other events.
		// We already checked the stack above.
	case trace.EventStateTransition:
		// Validate state transitions.
		//
		// TODO(mknyszek): A lot of logic is duplicated between goroutines and procs.
		// The two are intentionally handled identically; from the perspective of the
		// API, resources all have the same general properties. Consider making this
		// code generic over resources and implementing validation just once.
		tr := ev.StateTransition()
		checkStack(e, tr.Stack)
		switch tr.Resource.Kind {
		case trace.ResourceGoroutine:
			// Basic state transition validation.
			id := tr.Resource.Goroutine()
			old, new := tr.Goroutine()
			if new == trace.GoUndetermined {
				e.Errorf("transition to undetermined state for goroutine %d", id)
			}
			if v.seenSync && old == trace.GoUndetermined {
				e.Errorf("undetermined goroutine %d after first global sync", id)
			}
			if new == trace.GoNotExist && v.hasAnyRange(trace.MakeResourceID(id)) {
				e.Errorf("goroutine %d died with active ranges", id)
			}
			state, ok := v.gs[id]
			if ok {
				if old != state.state {
					e.Errorf("bad old state for goroutine %d: got %s, want %s", id, old, state.state)
				}
				state.state = new
			} else {
				if old != trace.GoUndetermined && old != trace.GoNotExist {
					e.Errorf("bad old state for unregistered goroutine %d: %s", id, old)
				}
				state = &goState{state: new}
				v.gs[id] = state
			}
			// Validate sched context.
			if new.Executing() {
				ctx := v.getOrCreateThread(e, ev, ev.Thread())
				if ctx != nil {
					if ctx.G != trace.NoGoroutine && ctx.G != id {
						e.Errorf("tried to run goroutine %d when one was already executing (%d) on thread %d", id, ctx.G, ev.Thread())
					}
					ctx.G = id
					state.binding = ctx
				}
			} else if old.Executing() && !new.Executing() {
				if tr.Stack != ev.Stack() {
					// This is a case where the transition is happening to a goroutine that is also executing, so
					// these two stacks should always match.
					e.Errorf("StateTransition.Stack doesn't match Event.Stack")
				}
				ctx := state.binding
				if ctx != nil {
					if ctx.G != id {
						e.Errorf("tried to stop goroutine %d when it wasn't currently executing (currently executing %d) on thread %d", id, ctx.G, ev.Thread())
					}
					ctx.G = trace.NoGoroutine
					state.binding = nil
				} else {
					e.Errorf("stopping goroutine %d not bound to any active context", id)
				}
			}
		case trace.ResourceProc:
			// Basic state transition validation.
			id := tr.Resource.Proc()
			old, new := tr.Proc()
			if new == trace.ProcUndetermined {
				e.Errorf("transition to undetermined state for proc %d", id)
			}
			if v.seenSync && old == trace.ProcUndetermined {
				e.Errorf("undetermined proc %d after first global sync", id)
			}
			if new == trace.ProcNotExist && v.hasAnyRange(trace.MakeResourceID(id)) {
				e.Errorf("proc %d died with active ranges", id)
			}
			state, ok := v.ps[id]
			if ok {
				if old != state.state {
					e.Errorf("bad old state for proc %d: got %s, want %s", id, old, state.state)
				}
				state.state = new
			} else {
				if old != trace.ProcUndetermined && old != trace.ProcNotExist {
					e.Errorf("bad old state for unregistered proc %d: %s", id, old)
				}
				state = &procState{state: new}
				v.ps[id] = state
			}
			// Validate sched context.
			if new.Executing() {
				ctx := v.getOrCreateThread(e, ev, ev.Thread())
				if ctx != nil {
					if ctx.P != trace.NoProc && ctx.P != id {
						e.Errorf("tried to run proc %d when one was already executing (%d) on thread %d", id, ctx.P, ev.Thread())
					}
					ctx.P = id
					state.binding = ctx
				}
			} else if old.Executing() && !new.Executing() {
				ctx := state.binding
				if ctx != nil {
					if ctx.P != id {
						e.Errorf("tried to stop proc %d when it wasn't currently executing (currently executing %d) on thread %d", id, ctx.P, ctx.M)
					}
					ctx.P = trace.NoProc
					state.binding = nil
				} else {
					e.Errorf("stopping proc %d not bound to any active context", id)
				}
			}
		}
	case trace.EventRangeBegin, trace.EventRangeActive, trace.EventRangeEnd:
		// Validate ranges.
		r := ev.Range()
		switch ev.Kind() {
		case trace.EventRangeBegin:
			if v.hasRange(r.Scope, r.Name) {
				e.Errorf("already active range %q on %v begun again", r.Name, r.Scope)
			}
			v.addRange(r.Scope, r.Name)
		case trace.EventRangeActive:
			if !v.hasRange(r.Scope, r.Name) {
				v.addRange(r.Scope, r.Name)
			}
		case trace.EventRangeEnd:
			if !v.hasRange(r.Scope, r.Name) {
				e.Errorf("inactive range %q on %v ended", r.Name, r.Scope)
			}
			v.deleteRange(r.Scope, r.Name)
		}
	case trace.EventTaskBegin:
		// Validate task begin.
		t := ev.Task()
		if t.ID == trace.NoTask || t.ID == trace.BackgroundTask {
			// The background task should never have an event emitted for it.
			e.Errorf("found invalid task ID for task of type %s", t.Type)
		}
		if t.Parent == trace.BackgroundTask {
			// It's not possible for a task to be a subtask of the background task.
			e.Errorf("found background task as the parent for task of type %s", t.Type)
		}
		// N.B. Don't check the task type. Empty string is a valid task type.
		v.tasks[t.ID] = t.Type
	case trace.EventTaskEnd:
		// Validate task end.
		// We can see a task end without a begin, so ignore a task without information.
		// Instead, if we've seen the task begin, just make sure the task end lines up.
		t := ev.Task()
		if typ, ok := v.tasks[t.ID]; ok {
			if t.Type != typ {
				e.Errorf("task end type %q doesn't match task start type %q for task %d", t.Type, typ, t.ID)
			}
			delete(v.tasks, t.ID)
		}
	case trace.EventLog:
		// There's really not much here to check, except that we can
		// generate a Log. The category and message are entirely user-created,
		// so we can't make any assumptions as to what they are. We also
		// can't validate the task, because proving the task's existence is very
		// much best-effort.
		_ = ev.Log()
	}
	return e.Errors()
}

func (v *Validator) hasRange(r trace.ResourceID, name string) bool {
	ranges, ok := v.ranges[r]
	return ok && slices.Contains(ranges, name)
}

func (v *Validator) addRange(r trace.ResourceID, name string) {
	ranges, _ := v.ranges[r]
	ranges = append(ranges, name)
	v.ranges[r] = ranges
}

func (v *Validator) hasAnyRange(r trace.ResourceID) bool {
	ranges, ok := v.ranges[r]
	return ok && len(ranges) != 0
}

func (v *Validator) deleteRange(r trace.ResourceID, name string) {
	ranges, ok := v.ranges[r]
	if !ok {
		return
	}
	i := slices.Index(ranges, name)
	if i < 0 {
		return
	}
	v.ranges[r] = slices.Delete(ranges, i, i+1)
}

func (v *Validator) getOrCreateThread(e *errAccumulator, ev trace.Event, m trace.ThreadID) *schedContext {
	lenient := func() bool {
		// Be lenient about GoUndetermined -> GoSyscall transitions if they
		// originate from an old trace. These transitions lack thread
		// information in trace formats older than 1.22.
		if !v.Go121 {
			return false
		}
		if ev.Kind() != trace.EventStateTransition {
			return false
		}
		tr := ev.StateTransition()
		if tr.Resource.Kind != trace.ResourceGoroutine {
			return false
		}
		from, to := tr.Goroutine()
		return from == trace.GoUndetermined && to == trace.GoSyscall
	}
	if m == trace.NoThread && !lenient() {
		e.Errorf("must have thread, but thread ID is none")
		return nil
	}
	s, ok := v.ms[m]
	if !ok {
		s = &schedContext{M: m, P: trace.NoProc, G: trace.NoGoroutine}
		v.ms[m] = s
		return s
	}
	return s
}

func checkStack(e *errAccumulator, stk trace.Stack) {
	// Check for non-empty values, but we also check for crashes due to incorrect validation.
	for i, f := range slices.Collect(stk.Frames()) {
		if i == 0 {
			// Allow for one fully zero stack.
			//
			// TODO(mknyszek): Investigate why that happens.
			continue
		}
		if f.Func == "" || f.File == "" || f.PC == 0 || f.Line == 0 {
			e.Errorf("invalid stack frame %#v: missing information", f)
		}
	}
}

type errAccumulator struct {
	errs []error
}

func (e *errAccumulator) Errorf(f string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf(f, args...))
}

func (e *errAccumulator) Errors() error {
	return errors.Join(e.errs...)
}

"""



```