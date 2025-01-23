Response:
Let's break down the thought process for answering the request about `go/src/internal/trace/event.go`.

**1. Understanding the Goal:**

The primary goal is to explain the functionality of the provided Go code snippet. This involves identifying the data structures and their purposes, understanding the different event types, and figuring out how these events relate to the Go runtime tracing system. The request also specifically asks for examples, code demonstrations, and potential pitfalls.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for important keywords and structures:

* **`package trace`:**  Indicates this is part of the tracing functionality.
* **`EventKind`:**  This is clearly an enumeration defining different types of trace events. I'd note the various event types (Sync, Metric, Label, StackSample, RangeBegin/End/Active, TaskBegin/End, RegionBegin/End, Log, StateTransition, Experimental). This is a core piece of information.
* **`Event` struct:** This seems to be the main structure representing a trace event. It contains fields like `table`, `ctx`, and `base`.
* **`Metric`, `Label`, `Range`, `Task`, `Region`, `Log`, `Stack`, `StackFrame`, `ExperimentalEvent` structs:** These likely hold details specific to different event types.
* **Methods on `Event` (e.g., `Kind()`, `Time()`, `Goroutine()`, `Metric()`, `Label()`, etc.):** These are accessors to get information from an `Event`. The method names strongly hint at the type of information they provide.
* **`StateTransition`:** This struct and the associated methods suggest handling changes in the state of various runtime entities (goroutines, procs, threads).
* **`ExperimentalEvent`:**  Clearly for handling events that are not yet stable.
* **Constants like `NoTask`, `BackgroundTask`, `NoStack`:** These represent default or "null" values.
* **Comments:**  The comments are valuable for understanding the intended purpose of the different types and fields. I'd pay close attention to these.
* **Mappings like `go122Type2Kind`, `go122GoStatus2GoState`, `go122ProcStatus2ProcState`:** These suggest the code is dealing with specific Go versions (1.22 in this case) and mapping internal trace event types to higher-level concepts.

**3. Deduce the Core Functionality:**

Based on the keywords and structures, I'd deduce the core functionality:

* **Representation of Trace Events:** The code defines structures to represent different kinds of events that occur during the execution of a Go program.
* **Metadata about Events:**  Each event carries metadata like a timestamp, the goroutine/proc/thread it's associated with, and potentially a stack trace.
* **Specific Event Types:** The `EventKind` enum and the associated structs allow for structured access to information specific to each event type (e.g., a `Metric` event has a name and value).
* **State Tracking:**  The `StateTransition` events track changes in the state of goroutines, procs, and potentially threads.
* **User-Level Tracing:** The `Task`, `Region`, and `Log` events seem to provide mechanisms for application code to insert custom trace information.
* **Stack Sampling:** `EventStackSample` and the `Stack` struct deal with capturing stack traces.
* **Experimental Features:**  The `ExperimentalEvent` structure allows for the inclusion of non-stable trace data.

**4. Illustrative Examples (Mental Prototyping and Code Snippets):**

Now, I'd think about how to illustrate these concepts with Go code.

* **`EventKind`:**  A simple example demonstrating iterating through the `EventKind` enum and printing their string representations.
* **`Event` and Accessors:**  A snippet showing how to get the `Kind`, `Time`, `Goroutine`, etc., from an `Event` instance. I'd need to invent a hypothetical `Event` to demonstrate this.
* **Specific Event Types:**
    * **`Metric`:**  Show accessing the `Name` and `Value`.
    * **`Label`:** Show accessing the `Label` and `Resource`.
    * **`Range`:**  Illustrate the `Name` and `Scope`.
    * **`Task`:** Show `ID`, `Parent`, and `Type`.
    * **`Region`:** Show `Task` and `Type`.
    * **`Log`:** Show `Task`, `Category`, and `Message`.
    * **`StateTransition`:** This is a bit more complex. I'd focus on showing how to get the `Resource`, `Reason`, and the `old` and `new` states. An example of a goroutine blocking would be good here.
    * **`Stack`:**  Demonstrate iterating over `Frames`.
* **`ExperimentalEvent`:** Show accessing `Name`, `ArgNames`, and `Args`.

**5. Inferring Go Language Features:**

Based on the code, I'd infer the following Go features are being implemented:

* **Runtime Tracing:** The entire file is dedicated to representing trace events, strongly indicating this is part of Go's runtime tracing mechanism.
* **Performance Analysis:**  The data collected by these events is used for performance analysis and debugging.
* **Instrumentation:** The trace events act as instrumentation points in the Go runtime and user code.

**6. Command-Line Arguments (If Applicable):**

While the provided code doesn't directly handle command-line arguments, I know that the Go tracer is typically enabled via an environment variable or a command-line flag when running a Go program. I'd explain this generally.

**7. Potential Pitfalls:**

I'd consider common mistakes users might make:

* **Incorrectly Assuming Timestamps are Globally Comparable Across Different Traces (Pre-Go 1.22):** The comments highlight this issue, so it's important to emphasize.
* **Misinterpreting Event Context:**  Understanding that state transitions refer to the state *before* the transition is crucial.
* **Accessing the Wrong Event Data:**  Trying to access `Metric()` on a non-`Metric` event will panic, so it's important to check the `Kind()` first.

**8. Structuring the Answer:**

Finally, I'd organize the information logically:

* Start with a high-level overview of the file's purpose.
* Detail the different `EventKind` types.
* Explain the `Event` struct and its methods.
* Provide code examples for each important event type.
* Discuss the inferred Go language features.
* Explain how the tracing is typically enabled.
* Highlight potential pitfalls.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing only on the structures. **Correction:**  Realized the importance of the methods on `Event` for accessing the data.
* **Initial thought:** Providing very basic examples. **Correction:**  Made the examples more concrete and relevant to tracing scenarios (e.g., goroutine blocking).
* **Initial thought:**  Not explicitly mentioning the Go version dependency of timestamp comparison. **Correction:**  Emphasized the information in the comments about pre-Go 1.22 traces.

By following these steps, iterating through the code, and thinking about practical usage scenarios, I can arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言运行时追踪（runtime tracing）系统的一部分，它定义了用于表示和处理追踪事件的数据结构和相关方法。

**它的主要功能可以概括为:**

1. **定义了各种追踪事件的类型 (`EventKind`)**:  例如同步事件、指标事件、标签事件、栈采样事件、时间范围事件、任务事件、区域事件、日志事件和状态转换事件等。这些类型可以帮助追踪器区分不同类型的运行时行为。

2. **定义了通用的事件结构 (`Event`)**: 该结构体包含了所有事件的通用信息，例如事件发生的时间、相关的 Goroutine、Processor 和 Thread ID，以及指向底层事件数据表的指针。

3. **定义了特定事件类型的结构体**:  针对不同的 `EventKind`，代码定义了相应的结构体来存储该类型事件的详细信息，例如：
    * `Metric`: 存储指标的名称和值。
    * `Label`: 存储标签和它所关联的资源。
    * `Range`: 存储时间范围的名称和作用域。
    * `Task`: 存储任务的 ID、父任务 ID 和类型。
    * `Region`: 存储区域所属的任务 ID 和类型。
    * `Log`: 存储日志所属的任务 ID、类别和消息。
    * `Stack`:  表示一个栈，实际上是对栈数据的一个句柄。
    * `StackFrame`: 表示栈中的一个帧。
    * `ExperimentalEvent`: 表示实验性的事件，包含原始的参数名和参数值。

4. **提供了访问事件信息的便捷方法**:  `Event` 结构体上定义了各种方法（例如 `Kind()`, `Time()`, `Goroutine()`, `Metric()`, `Label()`, `Range()`, `Task()`, `Region()`, `Log()`, `StateTransition()`, `Experimental()`），用于安全且类型化地访问事件的特定信息。

5. **处理状态转换事件 (`EventStateTransition`)**:  定义了 `StateTransition` 结构体，用于描述 Goroutine 和 Processor 的状态变化，并提供了 `goStateTransition` 和 `procStateTransition` 等辅助函数来创建这些状态转换事件。

6. **处理实验性事件 (`EventExperimental`)**:  允许追踪器记录和处理一些非稳定、实验性的事件。

**它可以被推理为 Go 语言运行时追踪功能的实现基础。**  Go 的 `runtime/trace` 包提供了在程序运行时收集各种事件的能力，用于性能分析、死锁检测、行为理解等。`internal/trace/event.go` 则是这些事件在内部的表示形式。

**Go 代码举例说明:**

虽然 `internal` 包通常不直接在用户代码中使用，但我们可以模拟一下 `runtime/trace` 包如何使用这些事件结构：

```go
package main

import (
	"fmt"
	"runtime"
	"runtime/trace"
	"os"
)

func main() {
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err := trace.Start(f); err != nil {
		panic(err)
	}
	defer trace.Stop()

	// 一些业务逻辑
	fmt.Println("开始执行...")

	trace.Log("main", "info", "程序正在运行")

	task := trace.NewTask(nil, "MyTask")
	defer task.End()

	trace.WithRegion(task, "MyRegion", func() {
		fmt.Println("在区域内执行")
	})

	runtime.GC() // 触发一次 GC，这会产生一些 trace 事件

	fmt.Println("执行结束")
}
```

**假设的输入与输出 (基于上面的代码示例):**

运行上面的代码，会在 `trace.out` 文件中生成一个二进制的追踪文件。 使用 `go tool trace trace.out` 可以查看这个追踪文件。

**追踪文件 (`trace.out`) 内容的逻辑表示 (简化版):**

```
Event{Kind:Sync, Time: <timestamp>}
Event{Kind:Log, Time: <timestamp>, Task: 0, Category: "main", Message: "程序正在运行"}
Event{Kind:TaskBegin, Time: <timestamp>, ID: 1, Parent: 0, Type: "MyTask"}
Event{Kind:RegionBegin, Time: <timestamp>, Task: 1, Type: "MyRegion"}
Event{Kind:RegionEnd, Time: <timestamp>, Task: 1, Type: "MyRegion"}
Event{Kind:TaskEnd, Time: <timestamp>, ID: 1, Parent: 0, Type: "MyTask"}
Event{Kind:StateTransition, Time: <timestamp>, Resource: ProcID(0), Reason: "idle", ProcID: 0, OldState: ProcRunning, NewState: ProcIdle} // 可能的 Proc 状态转换
Event{Kind:RangeBegin, Time: <timestamp>, Name: "GC concurrent mark phase", Scope: ResourceNone} // GC 开始
// ... 更多与 GC 相关的事件
Event{Kind:RangeEnd, Time: <timestamp>, Name: "GC concurrent mark phase", Scope: ResourceNone}   // GC 结束
```

**需要注意的是，实际的 `trace.out` 文件是二进制格式，并且包含非常多的底层细节。上面的输出只是一个简化的、易于理解的逻辑表示。**

**命令行参数的具体处理:**

`internal/trace/event.go` 本身不直接处理命令行参数。 命令行参数的处理通常发生在 `runtime/trace` 包和 `go tool trace` 工具中。

* **`runtime/trace` 包:**  其 `trace.Start()` 函数接受一个 `io.Writer` 作为参数，通常是将追踪信息写入到一个文件中。用户可以通过编程方式控制何时启动和停止追踪。

* **`go tool trace` 工具:** 这是一个独立的命令行工具，用于分析 Go 程序生成的追踪文件。它接受追踪文件的路径作为参数，例如：
    ```bash
    go tool trace trace.out
    ```
    `go tool trace` 还会提供一些子命令和选项来进行更细致的分析和可视化，例如查看 Goroutine 状态、火焰图等。

**使用者易犯错的点 (虽然用户不直接使用 `internal/trace/event.go`):**

尽管用户不直接操作 `internal/trace/event.go` 中定义的结构体，但在使用 `runtime/trace` 包时，仍然可能犯一些错误，这些错误可能与理解这些事件的含义有关：

1. **误解时间戳的含义:**  代码注释中提到了在 Windows 平台和旧版本 Go 中，时间戳的比较可能存在问题。使用者可能会错误地认为所有追踪文件的时间戳都可以跨文件进行精确比较。

2. **不理解不同事件的上下文:**  例如，对于 `StateTransition` 事件，需要理解它描述的是状态 *之前* 的上下文。 `Event.Goroutine()` 返回的是状态变化前的 Goroutine ID。

3. **过度依赖实验性事件:**  使用者可能会依赖 `ExperimentalEvent` 中提供的非稳定信息，但这些信息的格式和存在性在未来的 Go 版本中可能会发生变化。

4. **没有正确配置追踪:**  忘记调用 `trace.Stop()` 或者在程序退出前追踪数据没有完全写入文件，会导致追踪数据不完整。

总而言之，`go/src/internal/trace/event.go` 是 Go 语言运行时追踪系统的核心数据结构定义，它为运行时事件提供了统一的表示，并为上层 `runtime/trace` 包和 `go tool trace` 提供了基础。理解这些事件类型和结构对于有效地分析 Go 程序的运行时行为至关重要。

### 提示词
```
这是路径为go/src/internal/trace/event.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"fmt"
	"iter"
	"math"
	"strings"
	"time"

	"internal/trace/event"
	"internal/trace/event/go122"
	"internal/trace/version"
)

// EventKind indicates the kind of event this is.
//
// Use this information to obtain a more specific event that
// allows access to more detailed information.
type EventKind uint16

const (
	EventBad EventKind = iota

	// EventKindSync is an event that indicates a global synchronization
	// point in the trace. At the point of a sync event, the
	// trace reader can be certain that all resources (e.g. threads,
	// goroutines) that have existed until that point have been enumerated.
	EventSync

	// EventMetric is an event that represents the value of a metric at
	// a particular point in time.
	EventMetric

	// EventLabel attaches a label to a resource.
	EventLabel

	// EventStackSample represents an execution sample, indicating what a
	// thread/proc/goroutine was doing at a particular point in time via
	// its backtrace.
	//
	// Note: Samples should be considered a close approximation of
	// what a thread/proc/goroutine was executing at a given point in time.
	// These events may slightly contradict the situation StateTransitions
	// describe, so they should only be treated as a best-effort annotation.
	EventStackSample

	// EventRangeBegin and EventRangeEnd are a pair of generic events representing
	// a special range of time. Ranges are named and scoped to some resource
	// (identified via ResourceKind). A range that has begun but has not ended
	// is considered active.
	//
	// EvRangeBegin and EvRangeEnd will share the same name, and an End will always
	// follow a Begin on the same instance of the resource. The associated
	// resource ID can be obtained from the Event. ResourceNone indicates the
	// range is globally scoped. That is, any goroutine/proc/thread can start or
	// stop, but only one such range may be active at any given time.
	//
	// EventRangeActive is like EventRangeBegin, but indicates that the range was
	// already active. In this case, the resource referenced may not be in the current
	// context.
	EventRangeBegin
	EventRangeActive
	EventRangeEnd

	// EvTaskBegin and EvTaskEnd are a pair of events representing a runtime/trace.Task.
	EventTaskBegin
	EventTaskEnd

	// EventRegionBegin and EventRegionEnd are a pair of events represent a runtime/trace.Region.
	EventRegionBegin
	EventRegionEnd

	// EventLog represents a runtime/trace.Log call.
	EventLog

	// EventStateTransition represents a state change for some resource.
	EventStateTransition

	// EventExperimental is an experimental event that is unvalidated and exposed in a raw form.
	// Users are expected to understand the format and perform their own validation. These events
	// may always be safely ignored.
	EventExperimental
)

// String returns a string form of the EventKind.
func (e EventKind) String() string {
	if int(e) >= len(eventKindStrings) {
		return eventKindStrings[0]
	}
	return eventKindStrings[e]
}

var eventKindStrings = [...]string{
	EventBad:             "Bad",
	EventSync:            "Sync",
	EventMetric:          "Metric",
	EventLabel:           "Label",
	EventStackSample:     "StackSample",
	EventRangeBegin:      "RangeBegin",
	EventRangeActive:     "RangeActive",
	EventRangeEnd:        "RangeEnd",
	EventTaskBegin:       "TaskBegin",
	EventTaskEnd:         "TaskEnd",
	EventRegionBegin:     "RegionBegin",
	EventRegionEnd:       "RegionEnd",
	EventLog:             "Log",
	EventStateTransition: "StateTransition",
	EventExperimental:    "Experimental",
}

const maxTime = Time(math.MaxInt64)

// Time is a timestamp in nanoseconds.
//
// It corresponds to the monotonic clock on the platform that the
// trace was taken, and so is possible to correlate with timestamps
// for other traces taken on the same machine using the same clock
// (i.e. no reboots in between).
//
// The actual absolute value of the timestamp is only meaningful in
// relation to other timestamps from the same clock.
//
// BUG: Timestamps coming from traces on Windows platforms are
// only comparable with timestamps from the same trace. Timestamps
// across traces cannot be compared, because the system clock is
// not used as of Go 1.22.
//
// BUG: Traces produced by Go versions 1.21 and earlier cannot be
// compared with timestamps from other traces taken on the same
// machine. This is because the system clock was not used at all
// to collect those timestamps.
type Time int64

// Sub subtracts t0 from t, returning the duration in nanoseconds.
func (t Time) Sub(t0 Time) time.Duration {
	return time.Duration(int64(t) - int64(t0))
}

// Metric provides details about a Metric event.
type Metric struct {
	// Name is the name of the sampled metric.
	//
	// Names follow the same convention as metric names in the
	// runtime/metrics package, meaning they include the unit.
	// Names that match with the runtime/metrics package represent
	// the same quantity. Note that this corresponds to the
	// runtime/metrics package for the Go version this trace was
	// collected for.
	Name string

	// Value is the sampled value of the metric.
	//
	// The Value's Kind is tied to the name of the metric, and so is
	// guaranteed to be the same for metric samples for the same metric.
	Value Value
}

// Label provides details about a Label event.
type Label struct {
	// Label is the label applied to some resource.
	Label string

	// Resource is the resource to which this label should be applied.
	Resource ResourceID
}

// Range provides details about a Range event.
type Range struct {
	// Name is a human-readable name for the range.
	//
	// This name can be used to identify the end of the range for the resource
	// its scoped to, because only one of each type of range may be active on
	// a particular resource. The relevant resource should be obtained from the
	// Event that produced these details. The corresponding RangeEnd will have
	// an identical name.
	Name string

	// Scope is the resource that the range is scoped to.
	//
	// For example, a ResourceGoroutine scope means that the same goroutine
	// must have a start and end for the range, and that goroutine can only
	// have one range of a particular name active at any given time. The
	// ID that this range is scoped to may be obtained via Event.Goroutine.
	//
	// The ResourceNone scope means that the range is globally scoped. As a
	// result, any goroutine/proc/thread may start or end the range, and only
	// one such named range may be active globally at any given time.
	//
	// For RangeBegin and RangeEnd events, this will always reference some
	// resource ID in the current execution context. For RangeActive events,
	// this may reference a resource not in the current context. Prefer Scope
	// over the current execution context.
	Scope ResourceID
}

// RangeAttributes provides attributes about a completed Range.
type RangeAttribute struct {
	// Name is the human-readable name for the range.
	Name string

	// Value is the value of the attribute.
	Value Value
}

// TaskID is the internal ID of a task used to disambiguate tasks (even if they
// are of the same type).
type TaskID uint64

const (
	// NoTask indicates the lack of a task.
	NoTask = TaskID(^uint64(0))

	// BackgroundTask is the global task that events are attached to if there was
	// no other task in the context at the point the event was emitted.
	BackgroundTask = TaskID(0)
)

// Task provides details about a Task event.
type Task struct {
	// ID is a unique identifier for the task.
	//
	// This can be used to associate the beginning of a task with its end.
	ID TaskID

	// ParentID is the ID of the parent task.
	Parent TaskID

	// Type is the taskType that was passed to runtime/trace.NewTask.
	//
	// May be "" if a task's TaskBegin event isn't present in the trace.
	Type string
}

// Region provides details about a Region event.
type Region struct {
	// Task is the ID of the task this region is associated with.
	Task TaskID

	// Type is the regionType that was passed to runtime/trace.StartRegion or runtime/trace.WithRegion.
	Type string
}

// Log provides details about a Log event.
type Log struct {
	// Task is the ID of the task this region is associated with.
	Task TaskID

	// Category is the category that was passed to runtime/trace.Log or runtime/trace.Logf.
	Category string

	// Message is the message that was passed to runtime/trace.Log or runtime/trace.Logf.
	Message string
}

// Stack represents a stack. It's really a handle to a stack and it's trivially comparable.
//
// If two Stacks are equal then their Frames are guaranteed to be identical. If they are not
// equal, however, their Frames may still be equal.
type Stack struct {
	table *evTable
	id    stackID
}

// Frames is an iterator over the frames in a Stack.
func (s Stack) Frames() iter.Seq[StackFrame] {
	return func(yield func(StackFrame) bool) {
		if s.id == 0 {
			return
		}
		stk := s.table.stacks.mustGet(s.id)
		for _, pc := range stk.pcs {
			f := s.table.pcs[pc]
			sf := StackFrame{
				PC:   f.pc,
				Func: s.table.strings.mustGet(f.funcID),
				File: s.table.strings.mustGet(f.fileID),
				Line: f.line,
			}
			if !yield(sf) {
				return
			}
		}
	}
}

// NoStack is a sentinel value that can be compared against any Stack value, indicating
// a lack of a stack trace.
var NoStack = Stack{}

// StackFrame represents a single frame of a stack.
type StackFrame struct {
	// PC is the program counter of the function call if this
	// is not a leaf frame. If it's a leaf frame, it's the point
	// at which the stack trace was taken.
	PC uint64

	// Func is the name of the function this frame maps to.
	Func string

	// File is the file which contains the source code of Func.
	File string

	// Line is the line number within File which maps to PC.
	Line uint64
}

// ExperimentalEvent presents a raw view of an experimental event's arguments and their names.
type ExperimentalEvent struct {
	// Name is the name of the event.
	Name string

	// ArgNames is the names of the event's arguments in order.
	// This may refer to a globally shared slice. Copy before mutating.
	ArgNames []string

	// Args contains the event's arguments.
	Args []uint64

	// Data is additional unparsed data that is associated with the experimental event.
	// Data is likely to be shared across many ExperimentalEvents, so callers that parse
	// Data are encouraged to cache the parse result and look it up by the value of Data.
	Data *ExperimentalData
}

// ExperimentalData represents some raw and unparsed sidecar data present in the trace that is
// associated with certain kinds of experimental events. For example, this data may contain
// tables needed to interpret ExperimentalEvent arguments, or the ExperimentEvent could just be
// a placeholder for a differently encoded event that's actually present in the experimental data.
type ExperimentalData struct {
	// Batches contain the actual experimental data, along with metadata about each batch.
	Batches []ExperimentalBatch
}

// ExperimentalBatch represents a packet of unparsed data along with metadata about that packet.
type ExperimentalBatch struct {
	// Thread is the ID of the thread that produced a packet of data.
	Thread ThreadID

	// Data is a packet of unparsed data all produced by one thread.
	Data []byte
}

// Event represents a single event in the trace.
type Event struct {
	table *evTable
	ctx   schedCtx
	base  baseEvent
}

// Kind returns the kind of event that this is.
func (e Event) Kind() EventKind {
	return go122Type2Kind[e.base.typ]
}

// Time returns the timestamp of the event.
func (e Event) Time() Time {
	return e.base.time
}

// Goroutine returns the ID of the goroutine that was executing when
// this event happened. It describes part of the execution context
// for this event.
//
// Note that for goroutine state transitions this always refers to the
// state before the transition. For example, if a goroutine is just
// starting to run on this thread and/or proc, then this will return
// NoGoroutine. In this case, the goroutine starting to run will be
// can be found at Event.StateTransition().Resource.
func (e Event) Goroutine() GoID {
	return e.ctx.G
}

// Proc returns the ID of the proc this event event pertains to.
//
// Note that for proc state transitions this always refers to the
// state before the transition. For example, if a proc is just
// starting to run on this thread, then this will return NoProc.
func (e Event) Proc() ProcID {
	return e.ctx.P
}

// Thread returns the ID of the thread this event pertains to.
//
// Note that for thread state transitions this always refers to the
// state before the transition. For example, if a thread is just
// starting to run, then this will return NoThread.
//
// Note: tracking thread state is not currently supported, so this
// will always return a valid thread ID. However thread state transitions
// may be tracked in the future, and callers must be robust to this
// possibility.
func (e Event) Thread() ThreadID {
	return e.ctx.M
}

// Stack returns a handle to a stack associated with the event.
//
// This represents a stack trace at the current moment in time for
// the current execution context.
func (e Event) Stack() Stack {
	if e.base.typ == evSync {
		return NoStack
	}
	if e.base.typ == go122.EvCPUSample {
		return Stack{table: e.table, id: stackID(e.base.args[0])}
	}
	spec := go122.Specs()[e.base.typ]
	if len(spec.StackIDs) == 0 {
		return NoStack
	}
	// The stack for the main execution context is always the
	// first stack listed in StackIDs. Subtract one from this
	// because we've peeled away the timestamp argument.
	id := stackID(e.base.args[spec.StackIDs[0]-1])
	if id == 0 {
		return NoStack
	}
	return Stack{table: e.table, id: id}
}

// Metric returns details about a Metric event.
//
// Panics if Kind != EventMetric.
func (e Event) Metric() Metric {
	if e.Kind() != EventMetric {
		panic("Metric called on non-Metric event")
	}
	var m Metric
	switch e.base.typ {
	case go122.EvProcsChange:
		m.Name = "/sched/gomaxprocs:threads"
		m.Value = Value{kind: ValueUint64, scalar: e.base.args[0]}
	case go122.EvHeapAlloc:
		m.Name = "/memory/classes/heap/objects:bytes"
		m.Value = Value{kind: ValueUint64, scalar: e.base.args[0]}
	case go122.EvHeapGoal:
		m.Name = "/gc/heap/goal:bytes"
		m.Value = Value{kind: ValueUint64, scalar: e.base.args[0]}
	default:
		panic(fmt.Sprintf("internal error: unexpected event type for Metric kind: %s", go122.EventString(e.base.typ)))
	}
	return m
}

// Label returns details about a Label event.
//
// Panics if Kind != EventLabel.
func (e Event) Label() Label {
	if e.Kind() != EventLabel {
		panic("Label called on non-Label event")
	}
	if e.base.typ != go122.EvGoLabel {
		panic(fmt.Sprintf("internal error: unexpected event type for Label kind: %s", go122.EventString(e.base.typ)))
	}
	return Label{
		Label:    e.table.strings.mustGet(stringID(e.base.args[0])),
		Resource: ResourceID{Kind: ResourceGoroutine, id: int64(e.ctx.G)},
	}
}

// Range returns details about an EventRangeBegin, EventRangeActive, or EventRangeEnd event.
//
// Panics if Kind != EventRangeBegin, Kind != EventRangeActive, and Kind != EventRangeEnd.
func (e Event) Range() Range {
	if kind := e.Kind(); kind != EventRangeBegin && kind != EventRangeActive && kind != EventRangeEnd {
		panic("Range called on non-Range event")
	}
	var r Range
	switch e.base.typ {
	case go122.EvSTWBegin, go122.EvSTWEnd:
		// N.B. ordering.advance smuggles in the STW reason as e.base.args[0]
		// for go122.EvSTWEnd (it's already there for Begin).
		r.Name = "stop-the-world (" + e.table.strings.mustGet(stringID(e.base.args[0])) + ")"
		r.Scope = ResourceID{Kind: ResourceGoroutine, id: int64(e.Goroutine())}
	case go122.EvGCBegin, go122.EvGCActive, go122.EvGCEnd:
		r.Name = "GC concurrent mark phase"
		r.Scope = ResourceID{Kind: ResourceNone}
	case go122.EvGCSweepBegin, go122.EvGCSweepActive, go122.EvGCSweepEnd:
		r.Name = "GC incremental sweep"
		r.Scope = ResourceID{Kind: ResourceProc}
		if e.base.typ == go122.EvGCSweepActive {
			r.Scope.id = int64(e.base.args[0])
		} else {
			r.Scope.id = int64(e.Proc())
		}
		r.Scope.id = int64(e.Proc())
	case go122.EvGCMarkAssistBegin, go122.EvGCMarkAssistActive, go122.EvGCMarkAssistEnd:
		r.Name = "GC mark assist"
		r.Scope = ResourceID{Kind: ResourceGoroutine}
		if e.base.typ == go122.EvGCMarkAssistActive {
			r.Scope.id = int64(e.base.args[0])
		} else {
			r.Scope.id = int64(e.Goroutine())
		}
	default:
		panic(fmt.Sprintf("internal error: unexpected event type for Range kind: %s", go122.EventString(e.base.typ)))
	}
	return r
}

// RangeAttributes returns attributes for a completed range.
//
// Panics if Kind != EventRangeEnd.
func (e Event) RangeAttributes() []RangeAttribute {
	if e.Kind() != EventRangeEnd {
		panic("Range called on non-Range event")
	}
	if e.base.typ != go122.EvGCSweepEnd {
		return nil
	}
	return []RangeAttribute{
		{
			Name:  "bytes swept",
			Value: Value{kind: ValueUint64, scalar: e.base.args[0]},
		},
		{
			Name:  "bytes reclaimed",
			Value: Value{kind: ValueUint64, scalar: e.base.args[1]},
		},
	}
}

// Task returns details about a TaskBegin or TaskEnd event.
//
// Panics if Kind != EventTaskBegin and Kind != EventTaskEnd.
func (e Event) Task() Task {
	if kind := e.Kind(); kind != EventTaskBegin && kind != EventTaskEnd {
		panic("Task called on non-Task event")
	}
	parentID := NoTask
	var typ string
	switch e.base.typ {
	case go122.EvUserTaskBegin:
		parentID = TaskID(e.base.args[1])
		typ = e.table.strings.mustGet(stringID(e.base.args[2]))
	case go122.EvUserTaskEnd:
		parentID = TaskID(e.base.extra(version.Go122)[0])
		typ = e.table.getExtraString(extraStringID(e.base.extra(version.Go122)[1]))
	default:
		panic(fmt.Sprintf("internal error: unexpected event type for Task kind: %s", go122.EventString(e.base.typ)))
	}
	return Task{
		ID:     TaskID(e.base.args[0]),
		Parent: parentID,
		Type:   typ,
	}
}

// Region returns details about a RegionBegin or RegionEnd event.
//
// Panics if Kind != EventRegionBegin and Kind != EventRegionEnd.
func (e Event) Region() Region {
	if kind := e.Kind(); kind != EventRegionBegin && kind != EventRegionEnd {
		panic("Region called on non-Region event")
	}
	if e.base.typ != go122.EvUserRegionBegin && e.base.typ != go122.EvUserRegionEnd {
		panic(fmt.Sprintf("internal error: unexpected event type for Region kind: %s", go122.EventString(e.base.typ)))
	}
	return Region{
		Task: TaskID(e.base.args[0]),
		Type: e.table.strings.mustGet(stringID(e.base.args[1])),
	}
}

// Log returns details about a Log event.
//
// Panics if Kind != EventLog.
func (e Event) Log() Log {
	if e.Kind() != EventLog {
		panic("Log called on non-Log event")
	}
	if e.base.typ != go122.EvUserLog {
		panic(fmt.Sprintf("internal error: unexpected event type for Log kind: %s", go122.EventString(e.base.typ)))
	}
	return Log{
		Task:     TaskID(e.base.args[0]),
		Category: e.table.strings.mustGet(stringID(e.base.args[1])),
		Message:  e.table.strings.mustGet(stringID(e.base.args[2])),
	}
}

// StateTransition returns details about a StateTransition event.
//
// Panics if Kind != EventStateTransition.
func (e Event) StateTransition() StateTransition {
	if e.Kind() != EventStateTransition {
		panic("StateTransition called on non-StateTransition event")
	}
	var s StateTransition
	switch e.base.typ {
	case go122.EvProcStart:
		s = procStateTransition(ProcID(e.base.args[0]), ProcIdle, ProcRunning)
	case go122.EvProcStop:
		s = procStateTransition(e.ctx.P, ProcRunning, ProcIdle)
	case go122.EvProcSteal:
		// N.B. ordering.advance populates e.base.extra.
		beforeState := ProcRunning
		if go122.ProcStatus(e.base.extra(version.Go122)[0]) == go122.ProcSyscallAbandoned {
			// We've lost information because this ProcSteal advanced on a
			// SyscallAbandoned state. Treat the P as idle because ProcStatus
			// treats SyscallAbandoned as Idle. Otherwise we'll have an invalid
			// transition.
			beforeState = ProcIdle
		}
		s = procStateTransition(ProcID(e.base.args[0]), beforeState, ProcIdle)
	case go122.EvProcStatus:
		// N.B. ordering.advance populates e.base.extra.
		s = procStateTransition(ProcID(e.base.args[0]), ProcState(e.base.extra(version.Go122)[0]), go122ProcStatus2ProcState[e.base.args[1]])
	case go122.EvGoCreate, go122.EvGoCreateBlocked:
		status := GoRunnable
		if e.base.typ == go122.EvGoCreateBlocked {
			status = GoWaiting
		}
		s = goStateTransition(GoID(e.base.args[0]), GoNotExist, status)
		s.Stack = Stack{table: e.table, id: stackID(e.base.args[1])}
	case go122.EvGoCreateSyscall:
		s = goStateTransition(GoID(e.base.args[0]), GoNotExist, GoSyscall)
	case go122.EvGoStart:
		s = goStateTransition(GoID(e.base.args[0]), GoRunnable, GoRunning)
	case go122.EvGoDestroy:
		s = goStateTransition(e.ctx.G, GoRunning, GoNotExist)
		s.Stack = e.Stack() // This event references the resource the event happened on.
	case go122.EvGoDestroySyscall:
		s = goStateTransition(e.ctx.G, GoSyscall, GoNotExist)
	case go122.EvGoStop:
		s = goStateTransition(e.ctx.G, GoRunning, GoRunnable)
		s.Reason = e.table.strings.mustGet(stringID(e.base.args[0]))
		s.Stack = e.Stack() // This event references the resource the event happened on.
	case go122.EvGoBlock:
		s = goStateTransition(e.ctx.G, GoRunning, GoWaiting)
		s.Reason = e.table.strings.mustGet(stringID(e.base.args[0]))
		s.Stack = e.Stack() // This event references the resource the event happened on.
	case go122.EvGoUnblock, go122.EvGoSwitch, go122.EvGoSwitchDestroy:
		// N.B. GoSwitch and GoSwitchDestroy both emit additional events, but
		// the first thing they both do is unblock the goroutine they name,
		// identically to an unblock event (even their arguments match).
		s = goStateTransition(GoID(e.base.args[0]), GoWaiting, GoRunnable)
	case go122.EvGoSyscallBegin:
		s = goStateTransition(e.ctx.G, GoRunning, GoSyscall)
		s.Stack = e.Stack() // This event references the resource the event happened on.
	case go122.EvGoSyscallEnd:
		s = goStateTransition(e.ctx.G, GoSyscall, GoRunning)
		s.Stack = e.Stack() // This event references the resource the event happened on.
	case go122.EvGoSyscallEndBlocked:
		s = goStateTransition(e.ctx.G, GoSyscall, GoRunnable)
		s.Stack = e.Stack() // This event references the resource the event happened on.
	case go122.EvGoStatus, go122.EvGoStatusStack:
		packedStatus := e.base.args[2]
		from, to := packedStatus>>32, packedStatus&((1<<32)-1)
		s = goStateTransition(GoID(e.base.args[0]), GoState(from), go122GoStatus2GoState[to])
	default:
		panic(fmt.Sprintf("internal error: unexpected event type for StateTransition kind: %s", go122.EventString(e.base.typ)))
	}
	return s
}

// Experimental returns a view of the raw event for an experimental event.
//
// Panics if Kind != EventExperimental.
func (e Event) Experimental() ExperimentalEvent {
	if e.Kind() != EventExperimental {
		panic("Experimental called on non-Experimental event")
	}
	spec := go122.Specs()[e.base.typ]
	argNames := spec.Args[1:] // Skip timestamp; already handled.
	return ExperimentalEvent{
		Name:     spec.Name,
		ArgNames: argNames,
		Args:     e.base.args[:len(argNames)],
		Data:     e.table.expData[spec.Experiment],
	}
}

const evSync = ^event.Type(0)

var go122Type2Kind = [...]EventKind{
	go122.EvCPUSample:           EventStackSample,
	go122.EvProcsChange:         EventMetric,
	go122.EvProcStart:           EventStateTransition,
	go122.EvProcStop:            EventStateTransition,
	go122.EvProcSteal:           EventStateTransition,
	go122.EvProcStatus:          EventStateTransition,
	go122.EvGoCreate:            EventStateTransition,
	go122.EvGoCreateSyscall:     EventStateTransition,
	go122.EvGoStart:             EventStateTransition,
	go122.EvGoDestroy:           EventStateTransition,
	go122.EvGoDestroySyscall:    EventStateTransition,
	go122.EvGoStop:              EventStateTransition,
	go122.EvGoBlock:             EventStateTransition,
	go122.EvGoUnblock:           EventStateTransition,
	go122.EvGoSyscallBegin:      EventStateTransition,
	go122.EvGoSyscallEnd:        EventStateTransition,
	go122.EvGoSyscallEndBlocked: EventStateTransition,
	go122.EvGoStatus:            EventStateTransition,
	go122.EvSTWBegin:            EventRangeBegin,
	go122.EvSTWEnd:              EventRangeEnd,
	go122.EvGCActive:            EventRangeActive,
	go122.EvGCBegin:             EventRangeBegin,
	go122.EvGCEnd:               EventRangeEnd,
	go122.EvGCSweepActive:       EventRangeActive,
	go122.EvGCSweepBegin:        EventRangeBegin,
	go122.EvGCSweepEnd:          EventRangeEnd,
	go122.EvGCMarkAssistActive:  EventRangeActive,
	go122.EvGCMarkAssistBegin:   EventRangeBegin,
	go122.EvGCMarkAssistEnd:     EventRangeEnd,
	go122.EvHeapAlloc:           EventMetric,
	go122.EvHeapGoal:            EventMetric,
	go122.EvGoLabel:             EventLabel,
	go122.EvUserTaskBegin:       EventTaskBegin,
	go122.EvUserTaskEnd:         EventTaskEnd,
	go122.EvUserRegionBegin:     EventRegionBegin,
	go122.EvUserRegionEnd:       EventRegionEnd,
	go122.EvUserLog:             EventLog,
	go122.EvGoSwitch:            EventStateTransition,
	go122.EvGoSwitchDestroy:     EventStateTransition,
	go122.EvGoCreateBlocked:     EventStateTransition,
	go122.EvGoStatusStack:       EventStateTransition,
	go122.EvSpan:                EventExperimental,
	go122.EvSpanAlloc:           EventExperimental,
	go122.EvSpanFree:            EventExperimental,
	go122.EvHeapObject:          EventExperimental,
	go122.EvHeapObjectAlloc:     EventExperimental,
	go122.EvHeapObjectFree:      EventExperimental,
	go122.EvGoroutineStack:      EventExperimental,
	go122.EvGoroutineStackAlloc: EventExperimental,
	go122.EvGoroutineStackFree:  EventExperimental,
	evSync:                      EventSync,
}

var go122GoStatus2GoState = [...]GoState{
	go122.GoRunnable: GoRunnable,
	go122.GoRunning:  GoRunning,
	go122.GoWaiting:  GoWaiting,
	go122.GoSyscall:  GoSyscall,
}

var go122ProcStatus2ProcState = [...]ProcState{
	go122.ProcRunning:          ProcRunning,
	go122.ProcIdle:             ProcIdle,
	go122.ProcSyscall:          ProcRunning,
	go122.ProcSyscallAbandoned: ProcIdle,
}

// String returns the event as a human-readable string.
//
// The format of the string is intended for debugging and is subject to change.
func (e Event) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "M=%d P=%d G=%d", e.Thread(), e.Proc(), e.Goroutine())
	fmt.Fprintf(&sb, " %s Time=%d", e.Kind(), e.Time())
	// Kind-specific fields.
	switch kind := e.Kind(); kind {
	case EventMetric:
		m := e.Metric()
		fmt.Fprintf(&sb, " Name=%q Value=%s", m.Name, valueAsString(m.Value))
	case EventLabel:
		l := e.Label()
		fmt.Fprintf(&sb, " Label=%q Resource=%s", l.Label, l.Resource)
	case EventRangeBegin, EventRangeActive, EventRangeEnd:
		r := e.Range()
		fmt.Fprintf(&sb, " Name=%q Scope=%s", r.Name, r.Scope)
		if kind == EventRangeEnd {
			fmt.Fprintf(&sb, " Attributes=[")
			for i, attr := range e.RangeAttributes() {
				if i != 0 {
					fmt.Fprintf(&sb, " ")
				}
				fmt.Fprintf(&sb, "%q=%s", attr.Name, valueAsString(attr.Value))
			}
			fmt.Fprintf(&sb, "]")
		}
	case EventTaskBegin, EventTaskEnd:
		t := e.Task()
		fmt.Fprintf(&sb, " ID=%d Parent=%d Type=%q", t.ID, t.Parent, t.Type)
	case EventRegionBegin, EventRegionEnd:
		r := e.Region()
		fmt.Fprintf(&sb, " Task=%d Type=%q", r.Task, r.Type)
	case EventLog:
		l := e.Log()
		fmt.Fprintf(&sb, " Task=%d Category=%q Message=%q", l.Task, l.Category, l.Message)
	case EventStateTransition:
		s := e.StateTransition()
		fmt.Fprintf(&sb, " Resource=%s Reason=%q", s.Resource, s.Reason)
		switch s.Resource.Kind {
		case ResourceGoroutine:
			id := s.Resource.Goroutine()
			old, new := s.Goroutine()
			fmt.Fprintf(&sb, " GoID=%d %s->%s", id, old, new)
		case ResourceProc:
			id := s.Resource.Proc()
			old, new := s.Proc()
			fmt.Fprintf(&sb, " ProcID=%d %s->%s", id, old, new)
		}
		if s.Stack != NoStack {
			fmt.Fprintln(&sb)
			fmt.Fprintln(&sb, "TransitionStack=")
			for f := range s.Stack.Frames() {
				fmt.Fprintf(&sb, "\t%s @ 0x%x\n", f.Func, f.PC)
				fmt.Fprintf(&sb, "\t\t%s:%d\n", f.File, f.Line)
			}
		}
	case EventExperimental:
		r := e.Experimental()
		fmt.Fprintf(&sb, " Name=%s ArgNames=%v Args=%v", r.Name, r.ArgNames, r.Args)
	}
	if stk := e.Stack(); stk != NoStack {
		fmt.Fprintln(&sb)
		fmt.Fprintln(&sb, "Stack=")
		for f := range stk.Frames() {
			fmt.Fprintf(&sb, "\t%s @ 0x%x\n", f.Func, f.PC)
			fmt.Fprintf(&sb, "\t\t%s:%d\n", f.File, f.Line)
		}
	}
	return sb.String()
}

// validateTableIDs checks to make sure lookups in e.table
// will work.
func (e Event) validateTableIDs() error {
	if e.base.typ == evSync {
		return nil
	}
	spec := go122.Specs()[e.base.typ]

	// Check stacks.
	for _, i := range spec.StackIDs {
		id := stackID(e.base.args[i-1])
		_, ok := e.table.stacks.get(id)
		if !ok {
			return fmt.Errorf("found invalid stack ID %d for event %s", id, spec.Name)
		}
	}
	// N.B. Strings referenced by stack frames are validated
	// early on, when reading the stacks in to begin with.

	// Check strings.
	for _, i := range spec.StringIDs {
		id := stringID(e.base.args[i-1])
		_, ok := e.table.strings.get(id)
		if !ok {
			return fmt.Errorf("found invalid string ID %d for event %s", id, spec.Name)
		}
	}
	return nil
}

func syncEvent(table *evTable, ts Time) Event {
	return Event{
		table: table,
		ctx: schedCtx{
			G: NoGoroutine,
			P: NoProc,
			M: NoThread,
		},
		base: baseEvent{
			typ:  evSync,
			time: ts,
		},
	}
}
```