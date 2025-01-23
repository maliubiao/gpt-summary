Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `summary.go` file within the `internal/trace` package. This means figuring out what it *does*, how it *works*, and what Go features it utilizes. The request also specifically asks for examples, code reasoning, handling of command-line arguments (though this file doesn't seem to have direct CLI interaction), and common pitfalls.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for key terms and structures. This helps to get a high-level overview:

* **`package trace`**:  Indicates this is part of the Go tracing infrastructure.
* **`Summary`, `GoroutineSummary`, `UserTaskSummary`, `UserRegionSummary`**: These type definitions strongly suggest the code is about aggregating and structuring data related to goroutines, tasks, and regions within a trace. The "Summary" likely holds the final processed data.
* **`Event`**: This pops up frequently in the structs and the `Summarizer.Event` method. It's a good bet that the code processes trace events.
* **`Time`**:  Many fields are of type `Time`, suggesting the code deals with timestamps and durations.
* **`map`**:  Used extensively for storing goroutines, tasks, block reasons, and ranges.
* **`slice`**: Used for storing regions and children.
* **`Summarizer` struct**: This looks like the main processing unit. The `Event` method within it confirms this.
* **`NewSummarizer`, `Event`, `Finalize`**:  These methods suggest a lifecycle for processing trace data.
* **`RelatedGoroutinesV2`**: A separate function for identifying related goroutines.
* **`IsSystemGoroutine`**: A utility function for classifying goroutines.

**3. Focusing on the Core Functionality - The `Summarizer`:**

The `Summarizer` struct and its methods (`NewSummarizer`, `Event`, `Finalize`) seem central. I'd then dive into the `Event` method, which is where the core processing logic resides.

* **`Event` Method Breakdown:**  I'd analyze the `switch ev.Kind()` block. Each `case` handles a different type of trace event. This is where the state transitions, range tracking, and task/region management happen.
* **State Transitions (`EventStateTransition`):** This case is crucial for understanding how goroutine states are tracked (Running, Waiting, Runnable, Syscall). The code updates the `GoroutineSummary` based on these transitions, calculating execution time, wait time, block time, etc. The logic for handling `GoUndetermined` is interesting – it seems to handle the start of a goroutine's lifecycle.
* **Ranges (`EventRangeBegin`, `EventRangeActive`, `EventRangeEnd`):**  The code tracks both goroutine-scoped and processor-scoped ranges, attempting to attribute them to the appropriate goroutine. The `rangesP` map is a key detail here.
* **User-Defined Regions (`EventRegionBegin`, `EventRegionEnd`):**  This part handles the explicit regions defined in the user's code. The association with tasks and the stacking of regions are important.
* **Tasks and Logs (`EventTaskBegin`, `EventTaskEnd`, `EventLog`):** This manages the hierarchy of tasks and associates logs with them. The `getOrAddTask` function is a utility for ensuring tasks are created as needed.

**4. Understanding the Data Structures:**

With a better understanding of the `Event` processing, I'd revisit the data structures:

* **`Summary`:**  The top-level result, containing maps of goroutine and task summaries.
* **`GoroutineSummary`:**  Stores detailed information about a single goroutine, including its state, execution statistics, and related regions. The internal `goroutineSummary` is a clever way to hold temporary state during processing.
* **`UserTaskSummary`:**  Represents a user-defined task, its hierarchy, associated goroutines, regions, and logs.
* **`UserRegionSummary`:**  Describes a user-defined region within a goroutine or task, including its start and end times and execution statistics within that region.
* **`GoroutineExecStats`:** A struct specifically for holding various execution time statistics. The `NonOverlappingStats` and `UnknownTime` methods are useful for understanding how the time is categorized.

**5. Inferring Go Features:**

As I understand the code, I'd identify the Go features being used:

* **Structs and Methods:**  Fundamental Go concepts for data organization and behavior.
* **Maps and Slices:** Essential data structures for storing collections of data.
* **Time Package:** Used for handling timestamps and durations.
* **String Manipulation:**  Used in `IsSystemGoroutine`.
* **Comparators (`cmp` package):** Used for sorting regions.

**6. Developing Examples and Scenarios:**

Based on the understanding of the code, I'd create examples:

* **Goroutine Creation and Execution:** A simple goroutine that runs and finishes.
* **User-Defined Regions:**  Code with `trace.Region` calls to illustrate region tracking.
* **Tasks:** Code using the `trace.NewTask` API.
* **Syscalls:**  An example of a goroutine making a syscall.

**7. Identifying Potential Pitfalls:**

I'd consider how a user might misuse the API or misunderstand the output:

* **Not ending regions:**  Forgetting to call `trace.EndRegion`.
* **Assuming perfect attribution of P-bound ranges:**  Understanding the limitations of attributing processor-level ranges to goroutines.

**8. Addressing Command-Line Arguments (or Lack Thereof):**

The code itself doesn't seem to directly process command-line arguments. This is likely handled by a higher-level tool that consumes the trace data and uses this `summary` package.

**9. Structuring the Answer:**

Finally, I'd organize the information logically, starting with a high-level summary of the file's purpose, then diving into the details of the data structures and the `Summarizer`, providing Go code examples, explaining the underlying Go features, and highlighting potential issues. Using clear headings and bullet points helps with readability. The request to answer in Chinese is addressed at the output stage.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption Check:**  I might initially assume the code directly interacts with trace files. However, seeing the `Event` method suggests a more event-driven processing model, where events are fed in.
* **Clarifying Ambiguities:** If I'm unsure about a specific piece of logic (e.g., the `rangesP` map), I'd re-read the comments and the surrounding code to deduce its purpose.
* **Ensuring Code Examples are Relevant:**  The examples should directly illustrate the functionality of the `summary.go` code, focusing on the APIs it would interact with (like `trace.Region`, `trace.NewTask`).

By following this structured thought process, combining code analysis with understanding of tracing concepts, and iteratively refining my understanding, I can arrive at a comprehensive and accurate explanation of the provided Go code.
这段代码是Go语言运行时跟踪（runtime tracing）系统的一部分，位于 `go/src/internal/trace/summary.go` 文件中。它的主要功能是**对Go程序的运行时跟踪数据进行分析和汇总，生成一个包含 Goroutine、任务（Task）和用户自定义区域（Region）统计信息的摘要（Summary）**。

更具体地说，它的功能可以细分为：

1. **数据结构定义:** 定义了用于存储分析结果的各种数据结构，例如：
    *   `Summary`: 最终的分析结果，包含 Goroutine 和 Task 的摘要信息。
    *   `GoroutineSummary`:  单个 Goroutine 的统计和执行细节，例如 ID、名称、创建/开始/结束时间、执行时间、调度等待时间、阻塞时间、系统调用时间以及包含的用户自定义区域列表。
    *   `UserTaskSummary`: 用户定义的任务的摘要信息，包括 ID、名称、父子关系、开始/结束事件、关联的日志、包含的用户自定义区域以及与该任务关联的 Goroutine。
    *   `UserRegionSummary`: 用户在代码中定义的区域的摘要信息，包含所属的任务 ID、名称、开始/结束事件以及该区域内的 Goroutine 执行统计信息。
    *   `GoroutineExecStats`: Goroutine 在一段时间内的执行统计信息，包括执行时间、调度等待时间、各种原因的阻塞时间、系统调用时间等。

2. **`Summarizer` 结构体和方法:**  `Summarizer` 结构体是执行分析的核心组件。
    *   **`NewSummarizer()`:** 创建一个新的 `Summarizer` 实例，初始化内部的 Goroutine 和 Task 映射。
    *   **`Event(ev *Event)`:**  接收一个跟踪事件 `Event`，并根据事件类型更新内部的 Goroutine 和 Task 状态及统计信息。这是分析的核心方法，它处理各种事件，如 Goroutine 状态转换、用户自定义区域的开始和结束、任务的开始和结束、日志事件等。
    *   **`Finalize()`:**  在所有事件处理完成后调用，用于清理剩余状态，计算最终的统计信息，并返回一个 `Summary` 结构体。

3. **辅助功能:**
    *   **`RelatedGoroutinesV2(events []Event, goid GoID) map[GoID]struct{}`:**  根据 Goroutine 之间的同步关系（例如，一个 Goroutine 解除了另一个 Goroutine 的阻塞），找到与指定 Goroutine `goid` 相关的 Goroutine 集合。
    *   **`IsSystemGoroutine(entryFn string) bool`:** 判断一个 Goroutine 是否是系统 Goroutine（例如，runtime 包内部的 Goroutine）。

**可以推理出这是 Go 语言运行时跟踪功能的实现。**

**Go 代码举例说明:**

假设我们有以下简单的 Go 代码，其中使用了 `runtime/trace` 包来定义用户自定义区域和任务：

```go
package main

import (
	"fmt"
	"runtime/trace"
	"time"
)

func main() {
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	trace.Start(f)
	defer trace.Stop()

	task1 := trace.NewTask(nil, "ParentTask")
	defer task1.End()

	trace.WithRegion(task1, "RegionInParent", func() {
		time.Sleep(10 * time.Millisecond)
		fmt.Println("Inside RegionInParent")

		task2 := trace.NewTask(task1, "ChildTask")
		defer task2.End()

		trace.WithRegion(task2, "RegionInChild", func() {
			time.Sleep(5 * time.Millisecond)
			fmt.Println("Inside RegionInChild")
		})
	})

	time.Sleep(5 * time.Millisecond)
}
```

**假设的输入与输出:**

1. **输入:**  通过运行上述代码生成的 `trace.out` 文件，该文件包含了程序运行时的各种跟踪事件。

2. **处理:**  一个使用 `internal/trace` 包的工具（例如 `go tool trace`）会读取 `trace.out` 文件，并将解析出的 `Event` 逐个传递给 `Summarizer` 的 `Event` 方法。

3. **输出:**  `Summarizer` 的 `Finalize()` 方法会返回一个 `Summary` 结构体，其中可能包含类似以下的摘要信息（简化表示）：

```
Summary{
    Goroutines: map[GoID]*GoroutineSummary{
        1: &GoroutineSummary{
            ID:           1,
            Name:         "runtime.main",
            // ... 其他 Goroutine 的信息
            Regions: []*UserRegionSummary{
                {
                    TaskID: 1, // ParentTask 的 ID
                    Name:   "RegionInParent",
                    // ... 该区域的开始和结束事件，以及 Goroutine 执行统计信息
                },
            },
        },
        // ... 其他 Goroutine 的摘要
    },
    Tasks: map[TaskID]*UserTaskSummary{
        1: &UserTaskSummary{
            ID:       1,
            Name:     "ParentTask",
            Children: []*UserTaskSummary{
                {
                    ID:   2,
                    Name: "ChildTask",
                    // ...
                    Regions: []*UserRegionSummary{
                        {
                            TaskID: 2, // ChildTask 的 ID
                            Name:   "RegionInChild",
                            // ...
                        },
                    },
                    // ...
                },
            },
            Regions: []*UserRegionSummary{
                // ...
            },
            // ...
        },
        2: &UserTaskSummary{
            ID:   2,
            Name: "ChildTask",
            // ...
        },
    },
}
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是一个内部的分析库。通常，会有一个更上层的工具（例如 `go tool trace`）负责处理命令行参数，例如指定跟踪文件的路径，然后使用这个 `summary` 包来分析该文件。

`go tool trace` 工具的使用方式大致如下：

```bash
go tool trace trace.out
```

这里 `trace.out` 就是一个命令行参数，指定了要分析的跟踪文件。`go tool trace` 会读取这个文件，解析其中的事件，并可能使用 `internal/trace/summary.go` 中的代码来生成各种分析结果，例如 Goroutine 的执行时间线、火焰图、以及这里定义的摘要信息。

**使用者易犯错的点:**

虽然这个文件是内部实现，但使用者（通常是 Go 开发者在使用 `runtime/trace` 包时）容易犯的错误会影响到这里生成的摘要信息的准确性：

1. **Region 或 Task 没有正确结束:** 如果使用了 `trace.StartRegion` 或 `trace.NewTask`，但忘记调用相应的 `trace.EndRegion` 或 `task.End()`，会导致 `UserRegionSummary` 或 `UserTaskSummary` 的 `End` 字段为 `nil`，`Complete()` 方法返回 `false`，并且相关的执行统计信息可能不完整或不准确。

    **示例:**

    ```go
    func myFunc() {
        trace.StartRegion(nil, "MyRegion")
        // ... 执行一些操作，但忘记调用 trace.EndRegion()
    }
    ```

    在这种情况下，`Summarizer` 在处理到跟踪结束时，可能会将该 Region 的 `End` 设置为跟踪结束时间，但这可能不是预期的。

2. **对系统 Goroutine 的理解偏差:**  `IsSystemGoroutine` 函数用于区分用户代码创建的 Goroutine 和 Go 运行时内部的 Goroutine。在分析跟踪数据时，了解哪些 Goroutine 是系统 Goroutine，哪些是用户 Goroutine 很重要。错误地将系统 Goroutine 视为用户 Goroutine 可能会导致对程序性能的误判。

这段代码是 Go 运行时跟踪分析的核心部分，它将原始的跟踪事件转化为更易于理解和分析的摘要信息，帮助开发者理解程序的执行行为和性能瓶颈。

### 提示词
```
这是路径为go/src/internal/trace/summary.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmp"
	"slices"
	"strings"
	"time"
)

// Summary is the analysis result produced by the summarizer.
type Summary struct {
	Goroutines map[GoID]*GoroutineSummary
	Tasks      map[TaskID]*UserTaskSummary
}

// GoroutineSummary contains statistics and execution details of a single goroutine.
// (For v2 traces.)
type GoroutineSummary struct {
	ID           GoID
	Name         string // A non-unique human-friendly identifier for the goroutine.
	PC           uint64 // The first PC we saw for the entry function of the goroutine
	CreationTime Time   // Timestamp of the first appearance in the trace.
	StartTime    Time   // Timestamp of the first time it started running. 0 if the goroutine never ran.
	EndTime      Time   // Timestamp of when the goroutine exited. 0 if the goroutine never exited.

	// List of regions in the goroutine, sorted based on the start time.
	Regions []*UserRegionSummary

	// Statistics of execution time during the goroutine execution.
	GoroutineExecStats

	// goroutineSummary is state used just for computing this structure.
	// It's dropped before being returned to the caller.
	//
	// More specifically, if it's nil, it indicates that this summary has
	// already been finalized.
	*goroutineSummary
}

// UserTaskSummary represents a task in the trace.
type UserTaskSummary struct {
	ID       TaskID
	Name     string
	Parent   *UserTaskSummary // nil if the parent is unknown.
	Children []*UserTaskSummary

	// Task begin event. An EventTaskBegin event or nil.
	Start *Event

	// End end event. Normally EventTaskEnd event or nil.
	End *Event

	// Logs is a list of EventLog events associated with the task.
	Logs []*Event

	// List of regions in the task, sorted based on the start time.
	Regions []*UserRegionSummary

	// Goroutines is the set of goroutines associated with this task.
	Goroutines map[GoID]*GoroutineSummary
}

// Complete returns true if we have complete information about the task
// from the trace: both a start and an end.
func (s *UserTaskSummary) Complete() bool {
	return s.Start != nil && s.End != nil
}

// Descendents returns a slice consisting of itself (always the first task returned),
// and the transitive closure of all of its children.
func (s *UserTaskSummary) Descendents() []*UserTaskSummary {
	descendents := []*UserTaskSummary{s}
	for _, child := range s.Children {
		descendents = append(descendents, child.Descendents()...)
	}
	return descendents
}

// UserRegionSummary represents a region and goroutine execution stats
// while the region was active. (For v2 traces.)
type UserRegionSummary struct {
	TaskID TaskID
	Name   string

	// Region start event. Normally EventRegionBegin event or nil,
	// but can be a state transition event from NotExist or Undetermined
	// if the region is a synthetic region representing task inheritance
	// from the parent goroutine.
	Start *Event

	// Region end event. Normally EventRegionEnd event or nil,
	// but can be a state transition event to NotExist if the goroutine
	// terminated without explicitly ending the region.
	End *Event

	GoroutineExecStats
}

// GoroutineExecStats contains statistics about a goroutine's execution
// during a period of time.
type GoroutineExecStats struct {
	// These stats are all non-overlapping.
	ExecTime          time.Duration
	SchedWaitTime     time.Duration
	BlockTimeByReason map[string]time.Duration
	SyscallTime       time.Duration
	SyscallBlockTime  time.Duration

	// TotalTime is the duration of the goroutine's presence in the trace.
	// Necessarily overlaps with other stats.
	TotalTime time.Duration

	// Total time the goroutine spent in certain ranges; may overlap
	// with other stats.
	RangeTime map[string]time.Duration
}

func (s GoroutineExecStats) NonOverlappingStats() map[string]time.Duration {
	stats := map[string]time.Duration{
		"Execution time":         s.ExecTime,
		"Sched wait time":        s.SchedWaitTime,
		"Syscall execution time": s.SyscallTime,
		"Block time (syscall)":   s.SyscallBlockTime,
		"Unknown time":           s.UnknownTime(),
	}
	for reason, dt := range s.BlockTimeByReason {
		stats["Block time ("+reason+")"] += dt
	}
	// N.B. Don't include RangeTime or TotalTime; they overlap with these other
	// stats.
	return stats
}

// UnknownTime returns whatever isn't accounted for in TotalTime.
func (s GoroutineExecStats) UnknownTime() time.Duration {
	sum := s.ExecTime + s.SchedWaitTime + s.SyscallTime +
		s.SyscallBlockTime
	for _, dt := range s.BlockTimeByReason {
		sum += dt
	}
	// N.B. Don't include range time. Ranges overlap with
	// other stats, whereas these stats are non-overlapping.
	if sum < s.TotalTime {
		return s.TotalTime - sum
	}
	return 0
}

// sub returns the stats v-s.
func (s GoroutineExecStats) sub(v GoroutineExecStats) (r GoroutineExecStats) {
	r = s.clone()
	r.ExecTime -= v.ExecTime
	r.SchedWaitTime -= v.SchedWaitTime
	for reason := range s.BlockTimeByReason {
		r.BlockTimeByReason[reason] -= v.BlockTimeByReason[reason]
	}
	r.SyscallTime -= v.SyscallTime
	r.SyscallBlockTime -= v.SyscallBlockTime
	r.TotalTime -= v.TotalTime
	for name := range s.RangeTime {
		r.RangeTime[name] -= v.RangeTime[name]
	}
	return r
}

func (s GoroutineExecStats) clone() (r GoroutineExecStats) {
	r = s
	r.BlockTimeByReason = make(map[string]time.Duration)
	for reason, dt := range s.BlockTimeByReason {
		r.BlockTimeByReason[reason] = dt
	}
	r.RangeTime = make(map[string]time.Duration)
	for name, dt := range s.RangeTime {
		r.RangeTime[name] = dt
	}
	return r
}

// snapshotStat returns the snapshot of the goroutine execution statistics.
// This is called as we process the ordered trace event stream. lastTs is used
// to process pending statistics if this is called before any goroutine end event.
func (g *GoroutineSummary) snapshotStat(lastTs Time) (ret GoroutineExecStats) {
	ret = g.GoroutineExecStats.clone()

	if g.goroutineSummary == nil {
		return ret // Already finalized; no pending state.
	}

	// Set the total time if necessary.
	if g.TotalTime == 0 {
		ret.TotalTime = lastTs.Sub(g.CreationTime)
	}

	// Add in time since lastTs.
	if g.lastStartTime != 0 {
		ret.ExecTime += lastTs.Sub(g.lastStartTime)
	}
	if g.lastRunnableTime != 0 {
		ret.SchedWaitTime += lastTs.Sub(g.lastRunnableTime)
	}
	if g.lastBlockTime != 0 {
		ret.BlockTimeByReason[g.lastBlockReason] += lastTs.Sub(g.lastBlockTime)
	}
	if g.lastSyscallTime != 0 {
		ret.SyscallTime += lastTs.Sub(g.lastSyscallTime)
	}
	if g.lastSyscallBlockTime != 0 {
		ret.SchedWaitTime += lastTs.Sub(g.lastSyscallBlockTime)
	}
	for name, ts := range g.lastRangeTime {
		ret.RangeTime[name] += lastTs.Sub(ts)
	}
	return ret
}

// finalize is called when processing a goroutine end event or at
// the end of trace processing. This finalizes the execution stat
// and any active regions in the goroutine, in which case trigger is nil.
func (g *GoroutineSummary) finalize(lastTs Time, trigger *Event) {
	if trigger != nil {
		g.EndTime = trigger.Time()
	}
	finalStat := g.snapshotStat(lastTs)

	g.GoroutineExecStats = finalStat

	// System goroutines are never part of regions, even though they
	// "inherit" a task due to creation (EvGoCreate) from within a region.
	// This may happen e.g. if the first GC is triggered within a region,
	// starting the GC worker goroutines.
	if !IsSystemGoroutine(g.Name) {
		for _, s := range g.activeRegions {
			s.End = trigger
			s.GoroutineExecStats = finalStat.sub(s.GoroutineExecStats)
			g.Regions = append(g.Regions, s)
		}
	}
	*(g.goroutineSummary) = goroutineSummary{}
}

// goroutineSummary is a private part of GoroutineSummary that is required only during analysis.
type goroutineSummary struct {
	lastStartTime        Time
	lastRunnableTime     Time
	lastBlockTime        Time
	lastBlockReason      string
	lastSyscallTime      Time
	lastSyscallBlockTime Time
	lastRangeTime        map[string]Time
	activeRegions        []*UserRegionSummary // stack of active regions
}

// Summarizer constructs per-goroutine time statistics for v2 traces.
type Summarizer struct {
	// gs contains the map of goroutine summaries we're building up to return to the caller.
	gs map[GoID]*GoroutineSummary

	// tasks contains the map of task summaries we're building up to return to the caller.
	tasks map[TaskID]*UserTaskSummary

	// syscallingP and syscallingG represent a binding between a P and G in a syscall.
	// Used to correctly identify and clean up after syscalls (blocking or otherwise).
	syscallingP map[ProcID]GoID
	syscallingG map[GoID]ProcID

	// rangesP is used for optimistic tracking of P-based ranges for goroutines.
	//
	// It's a best-effort mapping of an active range on a P to the goroutine we think
	// is associated with it.
	rangesP map[rangeP]GoID

	lastTs Time // timestamp of the last event processed.
	syncTs Time // timestamp of the last sync event processed (or the first timestamp in the trace).
}

// NewSummarizer creates a new struct to build goroutine stats from a trace.
func NewSummarizer() *Summarizer {
	return &Summarizer{
		gs:          make(map[GoID]*GoroutineSummary),
		tasks:       make(map[TaskID]*UserTaskSummary),
		syscallingP: make(map[ProcID]GoID),
		syscallingG: make(map[GoID]ProcID),
		rangesP:     make(map[rangeP]GoID),
	}
}

type rangeP struct {
	id   ProcID
	name string
}

// Event feeds a single event into the stats summarizer.
func (s *Summarizer) Event(ev *Event) {
	if s.syncTs == 0 {
		s.syncTs = ev.Time()
	}
	s.lastTs = ev.Time()

	switch ev.Kind() {
	// Record sync time for the RangeActive events.
	case EventSync:
		s.syncTs = ev.Time()

	// Handle state transitions.
	case EventStateTransition:
		st := ev.StateTransition()
		switch st.Resource.Kind {
		// Handle goroutine transitions, which are the meat of this computation.
		case ResourceGoroutine:
			id := st.Resource.Goroutine()
			old, new := st.Goroutine()
			if old == new {
				// Skip these events; they're not telling us anything new.
				break
			}

			// Handle transition out.
			g := s.gs[id]
			switch old {
			case GoUndetermined, GoNotExist:
				g = &GoroutineSummary{ID: id, goroutineSummary: &goroutineSummary{}}
				// If we're coming out of GoUndetermined, then the creation time is the
				// time of the last sync.
				if old == GoUndetermined {
					g.CreationTime = s.syncTs
				} else {
					g.CreationTime = ev.Time()
				}
				// The goroutine is being created, or it's being named for the first time.
				g.lastRangeTime = make(map[string]Time)
				g.BlockTimeByReason = make(map[string]time.Duration)
				g.RangeTime = make(map[string]time.Duration)

				// When a goroutine is newly created, inherit the task
				// of the active region. For ease handling of this
				// case, we create a fake region description with the
				// task id. This isn't strictly necessary as this
				// goroutine may not be associated with the task, but
				// it can be convenient to see all children created
				// during a region.
				//
				// N.B. ev.Goroutine() will always be NoGoroutine for the
				// Undetermined case, so this is will simply not fire.
				if creatorG := s.gs[ev.Goroutine()]; creatorG != nil && len(creatorG.activeRegions) > 0 {
					regions := creatorG.activeRegions
					s := regions[len(regions)-1]
					g.activeRegions = []*UserRegionSummary{{TaskID: s.TaskID, Start: ev}}
				}
				s.gs[g.ID] = g
			case GoRunning:
				// Record execution time as we transition out of running
				g.ExecTime += ev.Time().Sub(g.lastStartTime)
				g.lastStartTime = 0
			case GoWaiting:
				// Record block time as we transition out of waiting.
				if g.lastBlockTime != 0 {
					g.BlockTimeByReason[g.lastBlockReason] += ev.Time().Sub(g.lastBlockTime)
					g.lastBlockTime = 0
				}
			case GoRunnable:
				// Record sched latency time as we transition out of runnable.
				if g.lastRunnableTime != 0 {
					g.SchedWaitTime += ev.Time().Sub(g.lastRunnableTime)
					g.lastRunnableTime = 0
				}
			case GoSyscall:
				// Record syscall execution time and syscall block time as we transition out of syscall.
				if g.lastSyscallTime != 0 {
					if g.lastSyscallBlockTime != 0 {
						g.SyscallBlockTime += ev.Time().Sub(g.lastSyscallBlockTime)
						g.SyscallTime += g.lastSyscallBlockTime.Sub(g.lastSyscallTime)
					} else {
						g.SyscallTime += ev.Time().Sub(g.lastSyscallTime)
					}
					g.lastSyscallTime = 0
					g.lastSyscallBlockTime = 0

					// Clear the syscall map.
					delete(s.syscallingP, s.syscallingG[id])
					delete(s.syscallingG, id)
				}
			}

			// The goroutine hasn't been identified yet. Take the transition stack
			// and identify the goroutine by the root frame of that stack.
			// This root frame will be identical for all transitions on this
			// goroutine, because it represents its immutable start point.
			if g.Name == "" {
				for frame := range st.Stack.Frames() {
					// NB: this PC won't actually be consistent for
					// goroutines which existed at the start of the
					// trace. The UI doesn't use it directly; this
					// mainly serves as an indication that we
					// actually saw a call stack for the goroutine
					g.PC = frame.PC
					g.Name = frame.Func
				}
			}

			// Handle transition in.
			switch new {
			case GoRunning:
				// We started running. Record it.
				g.lastStartTime = ev.Time()
				if g.StartTime == 0 {
					g.StartTime = ev.Time()
				}
			case GoRunnable:
				g.lastRunnableTime = ev.Time()
			case GoWaiting:
				if st.Reason != "forever" {
					g.lastBlockTime = ev.Time()
					g.lastBlockReason = st.Reason
					break
				}
				// "Forever" is like goroutine death.
				fallthrough
			case GoNotExist:
				g.finalize(ev.Time(), ev)
			case GoSyscall:
				s.syscallingP[ev.Proc()] = id
				s.syscallingG[id] = ev.Proc()
				g.lastSyscallTime = ev.Time()
			}

		// Handle procs to detect syscall blocking, which si identifiable as a
		// proc going idle while the goroutine it was attached to is in a syscall.
		case ResourceProc:
			id := st.Resource.Proc()
			old, new := st.Proc()
			if old != new && new == ProcIdle {
				if goid, ok := s.syscallingP[id]; ok {
					g := s.gs[goid]
					g.lastSyscallBlockTime = ev.Time()
					delete(s.syscallingP, id)
				}
			}
		}

	// Handle ranges of all kinds.
	case EventRangeBegin, EventRangeActive:
		r := ev.Range()
		var g *GoroutineSummary
		switch r.Scope.Kind {
		case ResourceGoroutine:
			// Simple goroutine range. We attribute the entire range regardless of
			// goroutine stats. Lots of situations are still identifiable, e.g. a
			// goroutine blocked often in mark assist will have both high mark assist
			// and high block times. Those interested in a deeper view can look at the
			// trace viewer.
			g = s.gs[r.Scope.Goroutine()]
		case ResourceProc:
			// N.B. These ranges are not actually bound to the goroutine, they're
			// bound to the P. But if we happen to be on the P the whole time, let's
			// try to attribute it to the goroutine. (e.g. GC sweeps are here.)
			g = s.gs[ev.Goroutine()]
			if g != nil {
				s.rangesP[rangeP{id: r.Scope.Proc(), name: r.Name}] = ev.Goroutine()
			}
		}
		if g == nil {
			break
		}
		if ev.Kind() == EventRangeActive {
			if ts := g.lastRangeTime[r.Name]; ts != 0 {
				g.RangeTime[r.Name] += s.syncTs.Sub(ts)
			}
			g.lastRangeTime[r.Name] = s.syncTs
		} else {
			g.lastRangeTime[r.Name] = ev.Time()
		}
	case EventRangeEnd:
		r := ev.Range()
		var g *GoroutineSummary
		switch r.Scope.Kind {
		case ResourceGoroutine:
			g = s.gs[r.Scope.Goroutine()]
		case ResourceProc:
			rp := rangeP{id: r.Scope.Proc(), name: r.Name}
			if goid, ok := s.rangesP[rp]; ok {
				if goid == ev.Goroutine() {
					// As the comment in the RangeBegin case states, this is only OK
					// if we finish on the same goroutine we started on.
					g = s.gs[goid]
				}
				delete(s.rangesP, rp)
			}
		}
		if g == nil {
			break
		}
		ts := g.lastRangeTime[r.Name]
		if ts == 0 {
			break
		}
		g.RangeTime[r.Name] += ev.Time().Sub(ts)
		delete(g.lastRangeTime, r.Name)

	// Handle user-defined regions.
	case EventRegionBegin:
		g := s.gs[ev.Goroutine()]
		r := ev.Region()
		region := &UserRegionSummary{
			Name:               r.Type,
			TaskID:             r.Task,
			Start:              ev,
			GoroutineExecStats: g.snapshotStat(ev.Time()),
		}
		g.activeRegions = append(g.activeRegions, region)
		// Associate the region and current goroutine to the task.
		task := s.getOrAddTask(r.Task)
		task.Regions = append(task.Regions, region)
		task.Goroutines[g.ID] = g
	case EventRegionEnd:
		g := s.gs[ev.Goroutine()]
		r := ev.Region()
		var sd *UserRegionSummary
		if regionStk := g.activeRegions; len(regionStk) > 0 {
			// Pop the top region from the stack since that's what must have ended.
			n := len(regionStk)
			sd = regionStk[n-1]
			regionStk = regionStk[:n-1]
			g.activeRegions = regionStk
			// N.B. No need to add the region to a task; the EventRegionBegin already handled it.
		} else {
			// This is an "end" without a start. Just fabricate the region now.
			sd = &UserRegionSummary{Name: r.Type, TaskID: r.Task}
			// Associate the region and current goroutine to the task.
			task := s.getOrAddTask(r.Task)
			task.Goroutines[g.ID] = g
			task.Regions = append(task.Regions, sd)
		}
		sd.GoroutineExecStats = g.snapshotStat(ev.Time()).sub(sd.GoroutineExecStats)
		sd.End = ev
		g.Regions = append(g.Regions, sd)

	// Handle tasks and logs.
	case EventTaskBegin, EventTaskEnd:
		// Initialize the task.
		t := ev.Task()
		task := s.getOrAddTask(t.ID)
		task.Name = t.Type
		task.Goroutines[ev.Goroutine()] = s.gs[ev.Goroutine()]
		if ev.Kind() == EventTaskBegin {
			task.Start = ev
		} else {
			task.End = ev
		}
		// Initialize the parent, if one exists and it hasn't been done yet.
		// We need to avoid doing it twice, otherwise we could appear twice
		// in the parent's Children list.
		if t.Parent != NoTask && task.Parent == nil {
			parent := s.getOrAddTask(t.Parent)
			task.Parent = parent
			parent.Children = append(parent.Children, task)
		}
	case EventLog:
		log := ev.Log()
		// Just add the log to the task. We'll create the task if it
		// doesn't exist (it's just been mentioned now).
		task := s.getOrAddTask(log.Task)
		task.Goroutines[ev.Goroutine()] = s.gs[ev.Goroutine()]
		task.Logs = append(task.Logs, ev)
	}
}

func (s *Summarizer) getOrAddTask(id TaskID) *UserTaskSummary {
	task := s.tasks[id]
	if task == nil {
		task = &UserTaskSummary{ID: id, Goroutines: make(map[GoID]*GoroutineSummary)}
		s.tasks[id] = task
	}
	return task
}

// Finalize indicates to the summarizer that we're done processing the trace.
// It cleans up any remaining state and returns the full summary.
func (s *Summarizer) Finalize() *Summary {
	for _, g := range s.gs {
		g.finalize(s.lastTs, nil)

		// Sort based on region start time.
		slices.SortFunc(g.Regions, func(a, b *UserRegionSummary) int {
			x := a.Start
			y := b.Start
			if x == nil {
				if y == nil {
					return 0
				}
				return -1
			}
			if y == nil {
				return +1
			}
			return cmp.Compare(x.Time(), y.Time())
		})
		g.goroutineSummary = nil
	}
	return &Summary{
		Goroutines: s.gs,
		Tasks:      s.tasks,
	}
}

// RelatedGoroutinesV2 finds a set of goroutines related to goroutine goid for v2 traces.
// The association is based on whether they have synchronized with each other in the Go
// scheduler (one has unblocked another).
func RelatedGoroutinesV2(events []Event, goid GoID) map[GoID]struct{} {
	// Process all the events, looking for transitions of goroutines
	// out of GoWaiting. If there was an active goroutine when this
	// happened, then we know that active goroutine unblocked another.
	// Scribble all these down so we can process them.
	type unblockEdge struct {
		operator GoID
		operand  GoID
	}
	var unblockEdges []unblockEdge
	for _, ev := range events {
		if ev.Goroutine() == NoGoroutine {
			continue
		}
		if ev.Kind() != EventStateTransition {
			continue
		}
		st := ev.StateTransition()
		if st.Resource.Kind != ResourceGoroutine {
			continue
		}
		id := st.Resource.Goroutine()
		old, new := st.Goroutine()
		if old == new || old != GoWaiting {
			continue
		}
		unblockEdges = append(unblockEdges, unblockEdge{
			operator: ev.Goroutine(),
			operand:  id,
		})
	}
	// Compute the transitive closure of depth 2 of goroutines that have unblocked each other
	// (starting from goid).
	gmap := make(map[GoID]struct{})
	gmap[goid] = struct{}{}
	for i := 0; i < 2; i++ {
		// Copy the map.
		gmap1 := make(map[GoID]struct{})
		for g := range gmap {
			gmap1[g] = struct{}{}
		}
		for _, edge := range unblockEdges {
			if _, ok := gmap[edge.operand]; ok {
				gmap1[edge.operator] = struct{}{}
			}
		}
		gmap = gmap1
	}
	return gmap
}

func IsSystemGoroutine(entryFn string) bool {
	// This mimics runtime.isSystemGoroutine as closely as
	// possible.
	// Also, locked g in extra M (with empty entryFn) is system goroutine.
	return entryFn == "" || entryFn != "runtime.main" && strings.HasPrefix(entryFn, "runtime.")
}
```