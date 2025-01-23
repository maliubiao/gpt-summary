Response:
The user wants to understand the functionality of the provided Go code snippet. This is the second part of a two-part request, so I need to summarize the functionality based on the code.

The code defines a structure `ordering` which seems to be responsible for processing and ordering trace events. It maintains state related to goroutines, processors, threads, and garbage collection. The `advance...` functions handle different types of trace events, validating their context and updating the internal state before adding them to a queue.

Therefore, the main function of this code is to enforce a specific order on trace events and validate their consistency based on the current state of the application being traced.
这段代码是 `go/src/internal/trace/order.go` 文件的一部分，它定义了一个名为 `ordering` 的结构体和一系列以 `advance` 开头的方法，用于处理和排序追踪事件。

**归纳一下它的功能:**

这段代码的主要功能是 **对 Go 程序的追踪事件进行排序和验证，以确保事件的逻辑一致性**。 `ordering` 结构体维护了程序运行时的状态信息（例如，goroutine、processor、thread 的状态，以及 GC 的状态），并根据这些状态来决定如何处理和排序新的追踪事件。

具体来说，它做了以下几点：

1. **维护程序状态:** `ordering` 结构体内部包含了 `gStates` (goroutine 状态), `pStates` (processor 状态), `mStates` (thread 状态) 以及 `gcState` (垃圾回收状态)。这些状态用于跟踪程序执行过程中的各种实体的生命周期和状态变化。

2. **接收并处理追踪事件:**  每个以 `advance` 开头的方法都对应一种或一类追踪事件（例如 `advanceGoCreate`, `advanceGoSched`, `advanceUserTaskBegin`, `advanceGCActive` 等）。这些方法接收一个追踪事件，并根据事件类型和当前程序状态执行以下操作：
    * **验证事件的上下文:**  使用 `validateCtx` 函数检查事件发生的上下文（例如，是否在预期的 goroutine、processor 或 thread 上发生）。
    * **更新程序状态:** 根据事件的类型更新相应的状态信息（例如，创建新的 goroutine，标记 goroutine 进入运行状态，开始或结束用户任务等）。
    * **进行逻辑检查:**  检查事件的发生是否符合逻辑，例如，避免在同一个 task ID 上重复开始 task，确保 region 的开始和结束匹配。
    * **将事件添加到队列:** 如果事件验证通过，则将其添加到 `queue` 中等待进一步处理。

3. **对追踪事件进行排序:**  `ordering` 结构体内部维护一个 `queue`，新接收到的且验证通过的事件会被添加到这个队列中。`Next()` 方法用于从队列中取出下一个事件，从而实现对追踪事件的排序。这个排序过程基于事件的逻辑顺序和程序状态。

**推断出的 Go 语言功能实现：**

这段代码很可能是 Go 语言追踪功能的核心排序和验证模块的一部分。Go 的 `runtime/trace` 包提供了对程序执行过程进行追踪的能力，可以记录各种事件，例如 goroutine 的创建、调度、阻塞，系统调用的执行，以及用户自定义的事件。`ordering` 结构体的作用就是确保这些事件按照正确的逻辑顺序排列，并且事件的上下文是有效的。

**Go 代码举例说明:**

虽然这段代码本身不是可以直接运行的 Go 代码，但我们可以通过模拟一些追踪事件的产生来理解其功能。假设我们有以下追踪事件：

```
// 模拟的追踪事件结构，简化起见
type MockTraceEvent struct {
	EventType string
	Timestamp int64
	GoroutineID int
	// ... 其他相关参数
}

// 模拟的事件数据
var events = []MockTraceEvent{
	{"GoCreate", 100, 1}, // Goroutine 1 创建
	{"GoStart", 110, 1},  // Goroutine 1 开始运行
	{"UserTaskBegin", 120, 1}, // Goroutine 1 开始用户任务
	{"GoSched", 130, 1},  // Goroutine 1 让出 CPU
	{"GoStart", 140, 2},  // Goroutine 2 开始运行
	{"UserTaskEnd", 150, 1},   // Goroutine 1 结束用户任务
}

// 假设的 ordering 结构体和方法
// type ordering struct { /* ... */ }
// func (o *ordering) advanceGoCreate(ev MockTraceEvent) bool { /* ... */ return true }
// func (o *ordering) advanceGoStart(ev MockTraceEvent) bool { /* ... */ return true }
// func (o *ordering) advanceUserTaskBegin(ev MockTraceEvent) bool { /* ... */ return true }
// func (o *ordering) advanceGoSched(ev MockTraceEvent) bool { /* ... */ return true }
// func (o *ordering) advanceUserTaskEnd(ev MockTraceEvent) bool { /* ... */ return true }

func main() {
	// 初始化 ordering 结构体
	// order := &ordering{ /* ... */ }

	// 逐个处理模拟的事件
	// for _, event := range events {
	// 	switch event.EventType {
	// 	case "GoCreate":
	// 		order.advanceGoCreate(event)
	// 	case "GoStart":
	// 		order.advanceGoStart(event)
	// 	case "UserTaskBegin":
	// 		order.advanceUserTaskBegin(event)
	// 	// ... 其他事件类型
	// 	}
	// }

	// 从队列中取出排序后的事件
	// for {
	// 	event, ok := order.Next()
	// 	if !ok {
	// 		break
	// 	}
	// 	fmt.Println("Processed event:", event)
	// }
}
```

**假设的输入与输出:**

**输入:** 一系列无序的追踪事件，例如上述 `events` 变量中的数据。

**输出:**  经过 `ordering` 结构体处理后，按照逻辑顺序排列的事件队列。例如，对于上述模拟事件，输出的顺序可能是：

```
Processed event: {EventType:GoCreate Timestamp:100 GoroutineID:1}
Processed event: {EventType:GoStart Timestamp:110 GoroutineID:1}
Processed event: {EventType:UserTaskBegin Timestamp:120 GoroutineID:1}
Processed event: {EventType:GoSched Timestamp:130 GoroutineID:1}
Processed event: {EventType:GoStart Timestamp:140 GoroutineID:2}
Processed event: {EventType:UserTaskEnd Timestamp:150 GoroutineID:1}
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `go tool trace` 工具中，该工具会读取追踪文件并将事件传递给类似于 `ordering` 这样的结构进行处理和展示。

**使用者易犯错的点:**

这段代码是 Go 内部的实现细节，普通 Go 开发者通常不会直接使用它。但是，如果开发者尝试手动解析和处理追踪文件，可能会犯以下错误：

* **忽略事件的上下文:**  错误地假设事件的顺序与它们在追踪文件中出现的顺序一致，而没有考虑到事件发生的 goroutine、processor 或 thread 上下文。
* **状态管理错误:** 在尝试自己实现类似 `ordering` 功能时，可能会错误地更新或维护程序状态，导致对事件的逻辑判断出错。
* **对特定事件的特殊处理不足:** 不同的追踪事件可能需要特殊的处理逻辑（例如，`UserTaskBegin` 和 `UserTaskEnd` 需要维护 activeTasks 状态），如果处理不当会导致数据不一致。

总而言之，这段代码是 Go 追踪功能中负责事件排序和一致性验证的关键部分，它通过维护程序状态和执行各种检查来确保追踪数据的准确性和可靠性。

### 提示词
```
这是路径为go/src/internal/trace/order.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
ue.push(extra)
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return newCtx, true, nil
}

func (o *ordering) advanceUserTaskBegin(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Handle tasks. Tasks are interesting because:
	// - There's no Begin event required to reference a task.
	// - End for a particular task ID can appear multiple times.
	// As a result, there's very little to validate. The only
	// thing we have to be sure of is that a task didn't begin
	// after it had already begun. Task IDs are allowed to be
	// reused, so we don't care about a Begin after an End.
	id := TaskID(ev.args[0])
	if _, ok := o.activeTasks[id]; ok {
		return curCtx, false, fmt.Errorf("task ID conflict: %d", id)
	}
	// Get the parent ID, but don't validate it. There's no guarantee
	// we actually have information on whether it's active.
	parentID := TaskID(ev.args[1])
	if parentID == BackgroundTask {
		// Note: a value of 0 here actually means no parent, *not* the
		// background task. Automatic background task attachment only
		// applies to regions.
		parentID = NoTask
		ev.args[1] = uint64(NoTask)
	}

	// Validate the name and record it. We'll need to pass it through to
	// EvUserTaskEnd.
	nameID := stringID(ev.args[2])
	name, ok := evt.strings.get(nameID)
	if !ok {
		return curCtx, false, fmt.Errorf("invalid string ID %v for %v event", nameID, ev.typ)
	}
	o.activeTasks[id] = taskState{name: name, parentID: parentID}
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceUserTaskEnd(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	id := TaskID(ev.args[0])
	if ts, ok := o.activeTasks[id]; ok {
		// Smuggle the task info. This may happen in a different generation,
		// which may not have the name in its string table. Add it to the extra
		// strings table so we can look it up later.
		ev.extra(version.Go122)[0] = uint64(ts.parentID)
		ev.extra(version.Go122)[1] = uint64(evt.addExtraString(ts.name))
		delete(o.activeTasks, id)
	} else {
		// Explicitly clear the task info.
		ev.extra(version.Go122)[0] = uint64(NoTask)
		ev.extra(version.Go122)[1] = uint64(evt.addExtraString(""))
	}
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceUserRegionBegin(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	tid := TaskID(ev.args[0])
	nameID := stringID(ev.args[1])
	name, ok := evt.strings.get(nameID)
	if !ok {
		return curCtx, false, fmt.Errorf("invalid string ID %v for %v event", nameID, ev.typ)
	}
	gState, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("encountered EvUserRegionBegin without known state for current goroutine %d", curCtx.G)
	}
	if err := gState.beginRegion(userRegion{tid, name}); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceUserRegionEnd(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	tid := TaskID(ev.args[0])
	nameID := stringID(ev.args[1])
	name, ok := evt.strings.get(nameID)
	if !ok {
		return curCtx, false, fmt.Errorf("invalid string ID %v for %v event", nameID, ev.typ)
	}
	gState, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("encountered EvUserRegionEnd without known state for current goroutine %d", curCtx.G)
	}
	if err := gState.endRegion(userRegion{tid, name}); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

// Handle the GC mark phase.
//
// We have sequence numbers for both start and end because they
// can happen on completely different threads. We want an explicit
// partial order edge between start and end here, otherwise we're
// relying entirely on timestamps to make sure we don't advance a
// GCEnd for a _different_ GC cycle if timestamps are wildly broken.
func (o *ordering) advanceGCActive(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	seq := ev.args[0]
	if gen == o.initialGen {
		if o.gcState != gcUndetermined {
			return curCtx, false, fmt.Errorf("GCActive in the first generation isn't first GC event")
		}
		o.gcSeq = seq
		o.gcState = gcRunning
		o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
		return curCtx, true, nil
	}
	if seq != o.gcSeq+1 {
		// This is not the right GC cycle.
		return curCtx, false, nil
	}
	if o.gcState != gcRunning {
		return curCtx, false, fmt.Errorf("encountered GCActive while GC was not in progress")
	}
	o.gcSeq = seq
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGCBegin(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	seq := ev.args[0]
	if o.gcState == gcUndetermined {
		o.gcSeq = seq
		o.gcState = gcRunning
		o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
		return curCtx, true, nil
	}
	if seq != o.gcSeq+1 {
		// This is not the right GC cycle.
		return curCtx, false, nil
	}
	if o.gcState == gcRunning {
		return curCtx, false, fmt.Errorf("encountered GCBegin while GC was already in progress")
	}
	o.gcSeq = seq
	o.gcState = gcRunning
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGCEnd(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	seq := ev.args[0]
	if seq != o.gcSeq+1 {
		// This is not the right GC cycle.
		return curCtx, false, nil
	}
	if o.gcState == gcNotRunning {
		return curCtx, false, fmt.Errorf("encountered GCEnd when GC was not in progress")
	}
	if o.gcState == gcUndetermined {
		return curCtx, false, fmt.Errorf("encountered GCEnd when GC was in an undetermined state")
	}
	o.gcSeq = seq
	o.gcState = gcNotRunning
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceAnnotation(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Handle simple instantaneous events that require a G.
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceHeapMetric(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Handle allocation metrics, which don't require a G.
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MustHave, Goroutine: event.MayHave}); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGCSweepBegin(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Handle sweep, which is bound to a P and doesn't require a G.
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MustHave, Goroutine: event.MayHave}); err != nil {
		return curCtx, false, err
	}
	if err := o.pStates[curCtx.P].beginRange(makeRangeType(ev.typ, 0)); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGCSweepActive(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	pid := ProcID(ev.args[0])
	// N.B. In practice Ps can't block while they're sweeping, so this can only
	// ever reference curCtx.P. However, be lenient about this like we are with
	// GCMarkAssistActive; there's no reason the runtime couldn't change to block
	// in the middle of a sweep.
	pState, ok := o.pStates[pid]
	if !ok {
		return curCtx, false, fmt.Errorf("encountered GCSweepActive for unknown proc %d", pid)
	}
	if err := pState.activeRange(makeRangeType(ev.typ, 0), gen == o.initialGen); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGCSweepEnd(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MustHave, Goroutine: event.MayHave}); err != nil {
		return curCtx, false, err
	}
	_, err := o.pStates[curCtx.P].endRange(ev.typ)
	if err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoRangeBegin(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Handle special goroutine-bound event ranges.
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	desc := stringID(0)
	if ev.typ == go122.EvSTWBegin {
		desc = stringID(ev.args[0])
	}
	gState, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("encountered event of type %d without known state for current goroutine %d", ev.typ, curCtx.G)
	}
	if err := gState.beginRange(makeRangeType(ev.typ, desc)); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoRangeActive(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	gid := GoID(ev.args[0])
	// N.B. Like GoStatus, this can happen at any time, because it can
	// reference a non-running goroutine. Don't check anything about the
	// current scheduler context.
	gState, ok := o.gStates[gid]
	if !ok {
		return curCtx, false, fmt.Errorf("uninitialized goroutine %d found during %s", gid, go122.EventString(ev.typ))
	}
	if err := gState.activeRange(makeRangeType(ev.typ, 0), gen == o.initialGen); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceGoRangeEnd(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	if err := validateCtx(curCtx, event.UserGoReqs); err != nil {
		return curCtx, false, err
	}
	gState, ok := o.gStates[curCtx.G]
	if !ok {
		return curCtx, false, fmt.Errorf("encountered event of type %d without known state for current goroutine %d", ev.typ, curCtx.G)
	}
	desc, err := gState.endRange(ev.typ)
	if err != nil {
		return curCtx, false, err
	}
	if ev.typ == go122.EvSTWEnd {
		// Smuggle the kind into the event.
		// Don't use ev.extra here so we have symmetry with STWBegin.
		ev.args[0] = uint64(desc)
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

func (o *ordering) advanceAllocFree(ev *baseEvent, evt *evTable, m ThreadID, gen uint64, curCtx schedCtx) (schedCtx, bool, error) {
	// Handle simple instantaneous events that may or may not have a P.
	if err := validateCtx(curCtx, event.SchedReqs{Thread: event.MustHave, Proc: event.MayHave, Goroutine: event.MayHave}); err != nil {
		return curCtx, false, err
	}
	o.queue.push(Event{table: evt, ctx: curCtx, base: *ev})
	return curCtx, true, nil
}

// Next returns the next event in the ordering.
func (o *ordering) Next() (Event, bool) {
	return o.queue.pop()
}

// schedCtx represents the scheduling resources associated with an event.
type schedCtx struct {
	G GoID
	P ProcID
	M ThreadID
}

// validateCtx ensures that ctx conforms to some reqs, returning an error if
// it doesn't.
func validateCtx(ctx schedCtx, reqs event.SchedReqs) error {
	// Check thread requirements.
	if reqs.Thread == event.MustHave && ctx.M == NoThread {
		return fmt.Errorf("expected a thread but didn't have one")
	} else if reqs.Thread == event.MustNotHave && ctx.M != NoThread {
		return fmt.Errorf("expected no thread but had one")
	}

	// Check proc requirements.
	if reqs.Proc == event.MustHave && ctx.P == NoProc {
		return fmt.Errorf("expected a proc but didn't have one")
	} else if reqs.Proc == event.MustNotHave && ctx.P != NoProc {
		return fmt.Errorf("expected no proc but had one")
	}

	// Check goroutine requirements.
	if reqs.Goroutine == event.MustHave && ctx.G == NoGoroutine {
		return fmt.Errorf("expected a goroutine but didn't have one")
	} else if reqs.Goroutine == event.MustNotHave && ctx.G != NoGoroutine {
		return fmt.Errorf("expected no goroutine but had one")
	}
	return nil
}

// gcState is a trinary variable for the current state of the GC.
//
// The third state besides "enabled" and "disabled" is "undetermined."
type gcState uint8

const (
	gcUndetermined gcState = iota
	gcNotRunning
	gcRunning
)

// String returns a human-readable string for the GC state.
func (s gcState) String() string {
	switch s {
	case gcUndetermined:
		return "Undetermined"
	case gcNotRunning:
		return "NotRunning"
	case gcRunning:
		return "Running"
	}
	return "Bad"
}

// userRegion represents a unique user region when attached to some gState.
type userRegion struct {
	// name must be a resolved string because the string ID for the same
	// string may change across generations, but we care about checking
	// the value itself.
	taskID TaskID
	name   string
}

// rangeType is a way to classify special ranges of time.
//
// These typically correspond 1:1 with "Begin" events, but
// they may have an optional subtype that describes the range
// in more detail.
type rangeType struct {
	typ  event.Type // "Begin" event.
	desc stringID   // Optional subtype.
}

// makeRangeType constructs a new rangeType.
func makeRangeType(typ event.Type, desc stringID) rangeType {
	if styp := go122.Specs()[typ].StartEv; styp != go122.EvNone {
		typ = styp
	}
	return rangeType{typ, desc}
}

// gState is the state of a goroutine at a point in the trace.
type gState struct {
	id     GoID
	status go122.GoStatus
	seq    seqCounter

	// regions are the active user regions for this goroutine.
	regions []userRegion

	// rangeState is the state of special time ranges bound to this goroutine.
	rangeState
}

// beginRegion starts a user region on the goroutine.
func (s *gState) beginRegion(r userRegion) error {
	s.regions = append(s.regions, r)
	return nil
}

// endRegion ends a user region on the goroutine.
func (s *gState) endRegion(r userRegion) error {
	if len(s.regions) == 0 {
		// We do not know about regions that began before tracing started.
		return nil
	}
	if next := s.regions[len(s.regions)-1]; next != r {
		return fmt.Errorf("misuse of region in goroutine %v: region end %v when the inner-most active region start event is %v", s.id, r, next)
	}
	s.regions = s.regions[:len(s.regions)-1]
	return nil
}

// pState is the state of a proc at a point in the trace.
type pState struct {
	id     ProcID
	status go122.ProcStatus
	seq    seqCounter

	// rangeState is the state of special time ranges bound to this proc.
	rangeState
}

// mState is the state of a thread at a point in the trace.
type mState struct {
	g GoID   // Goroutine bound to this M. (The goroutine's state is Executing.)
	p ProcID // Proc bound to this M. (The proc's state is Executing.)
}

// rangeState represents the state of special time ranges.
type rangeState struct {
	// inFlight contains the rangeTypes of any ranges bound to a resource.
	inFlight []rangeType
}

// beginRange begins a special range in time on the goroutine.
//
// Returns an error if the range is already in progress.
func (s *rangeState) beginRange(typ rangeType) error {
	if s.hasRange(typ) {
		return fmt.Errorf("discovered event already in-flight for when starting event %v", go122.Specs()[typ.typ].Name)
	}
	s.inFlight = append(s.inFlight, typ)
	return nil
}

// activeRange marks special range in time on the goroutine as active in the
// initial generation, or confirms that it is indeed active in later generations.
func (s *rangeState) activeRange(typ rangeType, isInitialGen bool) error {
	if isInitialGen {
		if s.hasRange(typ) {
			return fmt.Errorf("found named active range already in first gen: %v", typ)
		}
		s.inFlight = append(s.inFlight, typ)
	} else if !s.hasRange(typ) {
		return fmt.Errorf("resource is missing active range: %v %v", go122.Specs()[typ.typ].Name, s.inFlight)
	}
	return nil
}

// hasRange returns true if a special time range on the goroutine as in progress.
func (s *rangeState) hasRange(typ rangeType) bool {
	for _, ftyp := range s.inFlight {
		if ftyp == typ {
			return true
		}
	}
	return false
}

// endRange ends a special range in time on the goroutine.
//
// This must line up with the start event type  of the range the goroutine is currently in.
func (s *rangeState) endRange(typ event.Type) (stringID, error) {
	st := go122.Specs()[typ].StartEv
	idx := -1
	for i, r := range s.inFlight {
		if r.typ == st {
			idx = i
			break
		}
	}
	if idx < 0 {
		return 0, fmt.Errorf("tried to end event %v, but not in-flight", go122.Specs()[st].Name)
	}
	// Swap remove.
	desc := s.inFlight[idx].desc
	s.inFlight[idx], s.inFlight[len(s.inFlight)-1] = s.inFlight[len(s.inFlight)-1], s.inFlight[idx]
	s.inFlight = s.inFlight[:len(s.inFlight)-1]
	return desc, nil
}

// seqCounter represents a global sequence counter for a resource.
type seqCounter struct {
	gen uint64 // The generation for the local sequence counter seq.
	seq uint64 // The sequence number local to the generation.
}

// makeSeq creates a new seqCounter.
func makeSeq(gen, seq uint64) seqCounter {
	return seqCounter{gen: gen, seq: seq}
}

// succeeds returns true if a is the immediate successor of b.
func (a seqCounter) succeeds(b seqCounter) bool {
	return a.gen == b.gen && a.seq == b.seq+1
}

// String returns a debug string representation of the seqCounter.
func (c seqCounter) String() string {
	return fmt.Sprintf("%d (gen=%d)", c.seq, c.gen)
}

func dumpOrdering(order *ordering) string {
	var sb strings.Builder
	for id, state := range order.gStates {
		fmt.Fprintf(&sb, "G %d [status=%s seq=%s]\n", id, state.status, state.seq)
	}
	fmt.Fprintln(&sb)
	for id, state := range order.pStates {
		fmt.Fprintf(&sb, "P %d [status=%s seq=%s]\n", id, state.status, state.seq)
	}
	fmt.Fprintln(&sb)
	for id, state := range order.mStates {
		fmt.Fprintf(&sb, "M %d [g=%d p=%d]\n", id, state.g, state.p)
	}
	fmt.Fprintln(&sb)
	fmt.Fprintf(&sb, "GC %d %s\n", order.gcSeq, order.gcState)
	return sb.String()
}

// taskState represents an active task.
type taskState struct {
	// name is the type of the active task.
	name string

	// parentID is the parent ID of the active task.
	parentID TaskID
}

// queue implements a growable ring buffer with a queue API.
type queue[T any] struct {
	start, end int
	buf        []T
}

// push adds a new event to the back of the queue.
func (q *queue[T]) push(value T) {
	if q.end-q.start == len(q.buf) {
		q.grow()
	}
	q.buf[q.end%len(q.buf)] = value
	q.end++
}

// grow increases the size of the queue.
func (q *queue[T]) grow() {
	if len(q.buf) == 0 {
		q.buf = make([]T, 2)
		return
	}

	// Create new buf and copy data over.
	newBuf := make([]T, len(q.buf)*2)
	pivot := q.start % len(q.buf)
	first, last := q.buf[pivot:], q.buf[:pivot]
	copy(newBuf[:len(first)], first)
	copy(newBuf[len(first):], last)

	// Update the queue state.
	q.start = 0
	q.end = len(q.buf)
	q.buf = newBuf
}

// pop removes an event from the front of the queue. If the
// queue is empty, it returns an EventBad event.
func (q *queue[T]) pop() (T, bool) {
	if q.end-q.start == 0 {
		return *new(T), false
	}
	elem := &q.buf[q.start%len(q.buf)]
	value := *elem
	*elem = *new(T) // Clear the entry before returning, so we don't hold onto old tables.
	q.start++
	return value, true
}

// makeEvent creates an Event from the provided information.
//
// It's just a convenience function; it's always OK to construct
// an Event manually if this isn't quite the right way to express
// the contents of the event.
func makeEvent(table *evTable, ctx schedCtx, typ event.Type, time Time, args ...uint64) Event {
	ev := Event{
		table: table,
		ctx:   ctx,
		base: baseEvent{
			typ:  typ,
			time: time,
		},
	}
	copy(ev.base.args[:], args)
	return ev
}
```