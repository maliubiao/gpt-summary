Response:
Let's break down the thought process for analyzing this Go test file.

1. **Understand the Goal:** The core goal is to understand what this specific Go file (`summary_test.go`) in the `internal/trace` package is doing. The "test" in the filename is a strong clue: it's likely testing some functionality.

2. **Identify Key Components:**  Scan the file for recognizable Go testing patterns. The presence of `import "testing"` and functions starting with `Test...` immediately flags this as a standard Go test file. The other imports (`internal/trace`, `internal/trace/testtrace`, `io`) tell us what this test file is interacting with.

3. **Analyze Individual Test Functions:** Go through each `Test...` function one by one.

    * **`TestSummarizeGoroutinesTrace`:**
        * **Function Call:** `summarizeTraceTest(t, "testdata/tests/go122-gc-stress.test")`. This suggests the core functionality being tested involves summarizing a trace file. The file name "gc-stress" hints that it might be related to garbage collection.
        * **Assertions:** `assertContainsGoroutine`, `basicGoroutineSummaryChecks`. These helper functions indicate that the test is verifying the presence and properties of goroutine summaries.
        * **Flags:** `hasSchedWaitTime`, `hasSyncBlockTime`, `hasGCMarkAssistTime`. These suggest the test is specifically looking for these time metrics in the goroutine summaries.
        * **Inference:** This test seems to verify that the trace summarization correctly captures information about goroutines, including scheduling wait time, synchronization blocking time, and GC mark assist time.

    * **`TestSummarizeGoroutinesRegionsTrace`:**
        * **Function Call:**  Similar to the previous test, but with a different trace file: "go122-annotations.test". The name "annotations" suggests it's testing how regions within goroutines are handled.
        * **Data Structure:** `wantRegions`. This map defines the expected start and end event kinds for different named regions.
        * **Assertions:** `basicGoroutineSummaryChecks`, `checkRegionEvents`. This confirms it's checking general goroutine summary properties and specifically the start and end events of regions.
        * **Inference:**  This test focuses on verifying that user-defined regions within goroutines are correctly identified and their start and end events are of the expected types.

    * **`TestSummarizeTasksTrace`:**
        * **Function Call:**  Uses "go122-annotations-stress.test". The name "Tasks" in the function name is a key indicator.
        * **Data Structure:** `wantTasks`. This complex map defines expected properties of tasks, including their parent, children, logs, and associated goroutines.
        * **Assertions:**  The test iterates through the summarized tasks and compares their properties (parent, children, logs, goroutines) with the expected values in `wantTasks`.
        * **Inference:** This test is about verifying the correct summarization of tasks within a trace, including their hierarchical relationships, logged messages, and the goroutines that executed within them.

    * **`TestRelatedGoroutinesV2Trace`:**
        * **Function Call:**  Calls `trace.RelatedGoroutinesV2`. This is a direct call to a function within the `internal/trace` package.
        * **Input:** Takes a slice of `trace.Event` and a `trace.GoID`.
        * **Assertion:** Checks if the returned set of related goroutines matches the expected set.
        * **Inference:**  This test verifies the functionality of a function that identifies goroutines related to a given target goroutine based on the events in the trace.

4. **Analyze Helper Functions:**  Examine the utility functions used within the tests.

    * **`assertContainsGoroutine`:**  Simple helper to check if a goroutine with a specific name exists in the summaries.
    * **`basicGoroutineSummaryChecks`:** Performs general consistency checks on a `GoroutineSummary` struct (e.g., start/end times, name/PC).
    * **`summarizeTraceTest`:**  The core function for loading and summarizing a trace file. It uses `testtrace.ParseFile` to parse the trace and `trace.NewSummarizer` to perform the summarization.
    * **`checkRegionEvents`:**  Verifies the start and end events of a user region have the expected kinds.
    * **`basicGoroutineExecStatsChecks`:** Checks for negative values in the execution statistics of a goroutine or region.

5. **Identify the Core Functionality Under Test:** Based on the analysis of the test functions and helper functions, the main functionality being tested is the trace summarization logic within the `internal/trace` package. Specifically, it tests the ability to:

    * Summarize goroutine information (name, execution stats, blocking times).
    * Summarize user-defined regions within goroutines.
    * Summarize tasks and their relationships, logs, and associated goroutines.
    * Identify related goroutines.

6. **Infer Go Language Features:** The code heavily uses Go's standard testing library (`testing`). It also demonstrates:

    * **Structs:**  `GoroutineSummary`, `UserRegionSummary`, `Task`, etc.
    * **Maps:**  Used extensively for storing and retrieving summaries and expected values.
    * **Slices:** Used for storing lists of summaries, events, etc.
    * **Error Handling:**  Uses `t.Error`, `t.Errorf`, and `t.Fatalf` for reporting test failures.
    * **File I/O:** Reads trace files using `testtrace.ParseFile` and `trace.NewReader`.

7. **Consider Potential User Errors:** Analyze the test logic for areas where a user of the `internal/trace` package might make mistakes. In this case, since it's mostly testing internal functionality, the potential user errors are more related to *understanding* the trace data rather than direct usage of the functions being tested. The test code highlights the importance of correct event ordering and the potential loss of parent information for tasks started before tracing began.

8. **Structure the Answer:** Organize the findings into the requested categories: functionality, Go feature examples, code reasoning, command-line arguments (if any), and potential errors. Use clear and concise language. Provide code examples where requested, making sure they are illustrative and easy to understand.

This systematic approach helps in dissecting the code and understanding its purpose and implications. The key is to look for patterns, understand the purpose of each function and data structure, and connect the dots to the overall functionality being tested.
这个Go语言文件 `go/src/internal/trace/summary_test.go` 是 Go 语言运行时追踪 (runtime tracing) 功能的一部分，专门用于测试 **trace summary** 的生成和正确性。

**功能列举:**

1. **测试 Goroutine 摘要生成:**  `TestSummarizeGoroutinesTrace` 函数测试了从一个追踪文件中提取和汇总 Goroutine 信息的功能。它断言了生成的摘要中包含了特定的 Goroutine (例如 `runtime.gcBgMarkWorker`, `main.main.func1`)，并验证了摘要中是否包含了如调度等待时间 (`SchedWaitTime`)、同步阻塞时间 (`sync` 导致的阻塞) 以及 GC 辅助标记时间 (`GC mark assist`) 等关键指标。

2. **测试 Goroutine 区域 (Regions) 摘要生成:** `TestSummarizeGoroutinesRegionsTrace` 函数测试了对 Goroutine 中用户自定义的区域 (Regions) 进行摘要的功能。它验证了从追踪文件中提取的区域信息是否符合预期，包括区域的名称以及起始和结束事件的类型 (`trace.EventRegionBegin`, `trace.EventRegionEnd`, `trace.EventStateTransition`)。

3. **测试任务 (Tasks) 摘要生成:** `TestSummarizeTasksTrace` 函数测试了从追踪文件中提取和汇总任务信息的功能。它验证了生成的任务摘要中是否包含了任务的父任务、子任务、日志信息以及关联的 Goroutine。

4. **测试相关 Goroutine 的查找:** `TestRelatedGoroutinesV2Trace` 函数测试了 `trace.RelatedGoroutinesV2` 函数，该函数用于从一系列追踪事件中找到与指定 Goroutine 相关的其他 Goroutine。

**推断的 Go 语言功能实现及代码示例:**

这个文件主要测试的是 `internal/trace` 包中的 **追踪摘要 (trace summarization)** 功能。这个功能的目标是从原始的运行时追踪数据中提取出有用的统计和结构化信息，方便用户理解程序的执行情况。

我们可以推断出 `internal/trace` 包中存在一个类似 `Summarizer` 的结构体，负责处理追踪事件并生成摘要。

以下是一个简化的示例，说明如何使用 `internal/trace` 包中的相关功能（请注意，这只是一个概念性的示例，可能与实际 `internal/trace` 的 API 略有不同）：

```go
package main

import (
	"fmt"
	"internal/trace"
	"io"
	"os"
	"runtime/trace"
)

func main() {
	// 启动追踪
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	trace.Start(f)
	defer trace.Stop()

	// 你的程序代码
	fmt.Println("Hello, trace!")

	// ... 更多代码 ...
}
```

**假设的输入与输出 (基于 `TestSummarizeGoroutinesTrace`):**

**假设输入:**  一个包含 Goroutine 调度、同步以及 GC 事件的追踪文件 `testdata/tests/go122-gc-stress.test`。

**预期输出 (部分):**  `summarizeTraceTest` 函数会返回一个 `trace.Summary` 类型的结构体，其中 `Goroutines` 字段是一个 `map[trace.GoID]*trace.GoroutineSummary`。对于 `runtime.gcBgMarkWorker` 这个 Goroutine，其 `GoroutineSummary` 结构体可能包含类似以下的信息：

```go
&trace.GoroutineSummary{
    ID:            10, // 假设的 Goroutine ID
    Name:          "runtime.gcBgMarkWorker",
    CreationTime:  1678886400000000000, // 假设的创建时间
    StartTime:     1678886400000100000, // 假设的开始时间
    EndTime:       1678886400000500000, // 假设的结束时间
    SchedWaitTime: 100000,            // 假设的调度等待时间
    BlockTimeByReason: map[string]int64{
        "sync": 50000, // 假设的同步阻塞时间
    },
    RangeTime: map[string]int64{
        "GC mark assist": 200000, // 假设的 GC 辅助标记时间
    },
    // ... 其他字段 ...
}
```

**命令行参数的具体处理:**

在这个测试文件中，并没有直接涉及命令行参数的处理。`summarizeTraceTest` 函数接收的是一个追踪文件的路径作为输入。实际的 `go tool trace` 命令会处理命令行参数，例如指定要分析的追踪文件。

**使用者易犯错的点 (未在代码中直接体现，但与 trace 功能相关):**

虽然这个测试文件本身不涉及用户直接使用 `internal/trace` 的 API，但使用 Go 语言的追踪功能时，开发者容易犯以下错误：

1. **忘记停止追踪:**  如果在程序结束前没有调用 `trace.Stop()`，追踪数据可能不完整或无法正确写入文件。

   ```go
   f, _ := os.Create("trace.out")
   trace.Start(f)
   // ... 程序代码 ...
   // 容易忘记添加:
   // trace.Stop()
   // f.Close()
   ```

2. **在高负载下追踪所有事件:**  追踪会引入一定的性能开销。在高负载的应用中，追踪所有事件可能会导致明显的性能下降。应该根据需要选择性地追踪关键部分。

3. **不理解追踪事件的含义:**  Go 语言的追踪包含多种事件类型。不理解这些事件的含义可能会导致对追踪数据的错误解读。例如，`GCSweepStart` 和 `GCSweepDone` 事件表示垃圾回收的清扫阶段，理解这些事件有助于分析 GC 性能。

4. **在生产环境长时间开启追踪:**  持续的追踪会产生大量的追踪数据，占用磁盘空间并可能影响性能。生产环境的追踪应该谨慎使用，并设置合适的采样率或时间窗口。

总而言之，`go/src/internal/trace/summary_test.go` 文件是 Go 语言运行时追踪功能中至关重要的一部分，它通过一系列的测试用例，保证了追踪摘要功能的正确性和可靠性，为开发者分析 Go 程序的性能提供了坚实的基础。

Prompt: 
```
这是路径为go/src/internal/trace/summary_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace_test

import (
	"internal/trace"
	"internal/trace/testtrace"
	"io"
	"testing"
)

func TestSummarizeGoroutinesTrace(t *testing.T) {
	summaries := summarizeTraceTest(t, "testdata/tests/go122-gc-stress.test").Goroutines
	var (
		hasSchedWaitTime    bool
		hasSyncBlockTime    bool
		hasGCMarkAssistTime bool
	)

	assertContainsGoroutine(t, summaries, "runtime.gcBgMarkWorker")
	assertContainsGoroutine(t, summaries, "main.main.func1")

	for _, summary := range summaries {
		basicGoroutineSummaryChecks(t, summary)
		hasSchedWaitTime = hasSchedWaitTime || summary.SchedWaitTime > 0
		if dt, ok := summary.BlockTimeByReason["sync"]; ok && dt > 0 {
			hasSyncBlockTime = true
		}
		if dt, ok := summary.RangeTime["GC mark assist"]; ok && dt > 0 {
			hasGCMarkAssistTime = true
		}
	}
	if !hasSchedWaitTime {
		t.Error("missing sched wait time")
	}
	if !hasSyncBlockTime {
		t.Error("missing sync block time")
	}
	if !hasGCMarkAssistTime {
		t.Error("missing GC mark assist time")
	}
}

func TestSummarizeGoroutinesRegionsTrace(t *testing.T) {
	summaries := summarizeTraceTest(t, "testdata/tests/go122-annotations.test").Goroutines
	type region struct {
		startKind trace.EventKind
		endKind   trace.EventKind
	}
	wantRegions := map[string]region{
		// N.B. "pre-existing region" never even makes it into the trace.
		//
		// TODO(mknyszek): Add test case for end-without-a-start, which can happen at
		// a generation split only.
		"":                     {trace.EventStateTransition, trace.EventStateTransition}, // Task inheritance marker.
		"task0 region":         {trace.EventRegionBegin, trace.EventBad},
		"region0":              {trace.EventRegionBegin, trace.EventRegionEnd},
		"region1":              {trace.EventRegionBegin, trace.EventRegionEnd},
		"unended region":       {trace.EventRegionBegin, trace.EventStateTransition},
		"post-existing region": {trace.EventRegionBegin, trace.EventBad},
	}
	for _, summary := range summaries {
		basicGoroutineSummaryChecks(t, summary)
		for _, region := range summary.Regions {
			want, ok := wantRegions[region.Name]
			if !ok {
				continue
			}
			checkRegionEvents(t, want.startKind, want.endKind, summary.ID, region)
			delete(wantRegions, region.Name)
		}
	}
	if len(wantRegions) != 0 {
		t.Errorf("failed to find regions: %#v", wantRegions)
	}
}

func TestSummarizeTasksTrace(t *testing.T) {
	summaries := summarizeTraceTest(t, "testdata/tests/go122-annotations-stress.test").Tasks
	type task struct {
		name       string
		parent     *trace.TaskID
		children   []trace.TaskID
		logs       []trace.Log
		goroutines []trace.GoID
	}
	parent := func(id trace.TaskID) *trace.TaskID {
		p := new(trace.TaskID)
		*p = id
		return p
	}
	wantTasks := map[trace.TaskID]task{
		trace.BackgroundTask: {
			// The background task (0) is never any task's parent.
			logs: []trace.Log{
				{Task: trace.BackgroundTask, Category: "log", Message: "before do"},
				{Task: trace.BackgroundTask, Category: "log", Message: "before do"},
			},
			goroutines: []trace.GoID{1},
		},
		1: {
			// This started before tracing started and has no parents.
			// Task 2 is technically a child, but we lost that information.
			children: []trace.TaskID{3, 7, 16},
			logs: []trace.Log{
				{Task: 1, Category: "log", Message: "before do"},
				{Task: 1, Category: "log", Message: "before do"},
			},
			goroutines: []trace.GoID{1},
		},
		2: {
			// This started before tracing started and its parent is technically (1), but that information was lost.
			children: []trace.TaskID{8, 17},
			logs: []trace.Log{
				{Task: 2, Category: "log", Message: "before do"},
				{Task: 2, Category: "log", Message: "before do"},
			},
			goroutines: []trace.GoID{1},
		},
		3: {
			parent:   parent(1),
			children: []trace.TaskID{10, 19},
			logs: []trace.Log{
				{Task: 3, Category: "log", Message: "before do"},
				{Task: 3, Category: "log", Message: "before do"},
			},
			goroutines: []trace.GoID{1},
		},
		4: {
			// Explicitly, no parent.
			children: []trace.TaskID{12, 21},
			logs: []trace.Log{
				{Task: 4, Category: "log", Message: "before do"},
				{Task: 4, Category: "log", Message: "before do"},
			},
			goroutines: []trace.GoID{1},
		},
		12: {
			parent:   parent(4),
			children: []trace.TaskID{13},
			logs: []trace.Log{
				// TODO(mknyszek): This is computed asynchronously in the trace,
				// which makes regenerating this test very annoying, since it will
				// likely break this test. Resolve this by making the order not matter.
				{Task: 12, Category: "log2", Message: "do"},
				{Task: 12, Category: "log", Message: "fanout region4"},
				{Task: 12, Category: "log", Message: "fanout region0"},
				{Task: 12, Category: "log", Message: "fanout region1"},
				{Task: 12, Category: "log", Message: "fanout region2"},
				{Task: 12, Category: "log", Message: "before do"},
				{Task: 12, Category: "log", Message: "fanout region3"},
			},
			goroutines: []trace.GoID{1, 5, 6, 7, 8, 9},
		},
		13: {
			// Explicitly, no children.
			parent: parent(12),
			logs: []trace.Log{
				{Task: 13, Category: "log2", Message: "do"},
			},
			goroutines: []trace.GoID{7},
		},
	}
	for id, summary := range summaries {
		want, ok := wantTasks[id]
		if !ok {
			continue
		}
		if id != summary.ID {
			t.Errorf("ambiguous task %d (or %d?): field likely set incorrectly", id, summary.ID)
		}

		// Check parent.
		if want.parent != nil {
			if summary.Parent == nil {
				t.Errorf("expected parent %d for task %d without a parent", *want.parent, id)
			} else if summary.Parent.ID != *want.parent {
				t.Errorf("bad parent for task %d: want %d, got %d", id, *want.parent, summary.Parent.ID)
			}
		} else if summary.Parent != nil {
			t.Errorf("unexpected parent %d for task %d", summary.Parent.ID, id)
		}

		// Check children.
		gotChildren := make(map[trace.TaskID]struct{})
		for _, child := range summary.Children {
			gotChildren[child.ID] = struct{}{}
		}
		for _, wantChild := range want.children {
			if _, ok := gotChildren[wantChild]; ok {
				delete(gotChildren, wantChild)
			} else {
				t.Errorf("expected child task %d for task %d not found", wantChild, id)
			}
		}
		if len(gotChildren) != 0 {
			for child := range gotChildren {
				t.Errorf("unexpected child task %d for task %d", child, id)
			}
		}

		// Check logs.
		if len(want.logs) != len(summary.Logs) {
			t.Errorf("wanted %d logs for task %d, got %d logs instead", len(want.logs), id, len(summary.Logs))
		} else {
			for i := range want.logs {
				if want.logs[i] != summary.Logs[i].Log() {
					t.Errorf("log mismatch: want %#v, got %#v", want.logs[i], summary.Logs[i].Log())
				}
			}
		}

		// Check goroutines.
		if len(want.goroutines) != len(summary.Goroutines) {
			t.Errorf("wanted %d goroutines for task %d, got %d goroutines instead", len(want.goroutines), id, len(summary.Goroutines))
		} else {
			for _, goid := range want.goroutines {
				g, ok := summary.Goroutines[goid]
				if !ok {
					t.Errorf("want goroutine %d for task %d, not found", goid, id)
					continue
				}
				if g.ID != goid {
					t.Errorf("goroutine summary for %d does not match task %d listing of %d", g.ID, id, goid)
				}
			}
		}

		// Marked as seen.
		delete(wantTasks, id)
	}
	if len(wantTasks) != 0 {
		t.Errorf("failed to find tasks: %#v", wantTasks)
	}
}

func assertContainsGoroutine(t *testing.T, summaries map[trace.GoID]*trace.GoroutineSummary, name string) {
	for _, summary := range summaries {
		if summary.Name == name {
			return
		}
	}
	t.Errorf("missing goroutine %s", name)
}

func basicGoroutineSummaryChecks(t *testing.T, summary *trace.GoroutineSummary) {
	if summary.ID == trace.NoGoroutine {
		t.Error("summary found for no goroutine")
		return
	}
	if (summary.StartTime != 0 && summary.CreationTime > summary.StartTime) ||
		(summary.StartTime != 0 && summary.EndTime != 0 && summary.StartTime > summary.EndTime) {
		t.Errorf("bad summary creation/start/end times for G %d: creation=%d start=%d end=%d", summary.ID, summary.CreationTime, summary.StartTime, summary.EndTime)
	}
	if (summary.PC != 0 && summary.Name == "") || (summary.PC == 0 && summary.Name != "") {
		t.Errorf("bad name and/or PC for G %d: pc=0x%x name=%q", summary.ID, summary.PC, summary.Name)
	}
	basicGoroutineExecStatsChecks(t, &summary.GoroutineExecStats)
	for _, region := range summary.Regions {
		basicGoroutineExecStatsChecks(t, &region.GoroutineExecStats)
	}
}

func summarizeTraceTest(t *testing.T, testPath string) *trace.Summary {
	trc, _, err := testtrace.ParseFile(testPath)
	if err != nil {
		t.Fatalf("malformed test %s: bad trace file: %v", testPath, err)
	}
	// Create the analysis state.
	s := trace.NewSummarizer()

	// Create a reader.
	r, err := trace.NewReader(trc)
	if err != nil {
		t.Fatalf("failed to create trace reader for %s: %v", testPath, err)
	}
	// Process the trace.
	for {
		ev, err := r.ReadEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to process trace %s: %v", testPath, err)
		}
		s.Event(&ev)
	}
	return s.Finalize()
}

func checkRegionEvents(t *testing.T, wantStart, wantEnd trace.EventKind, goid trace.GoID, region *trace.UserRegionSummary) {
	switch wantStart {
	case trace.EventBad:
		if region.Start != nil {
			t.Errorf("expected nil region start event, got\n%s", region.Start.String())
		}
	case trace.EventStateTransition, trace.EventRegionBegin:
		if region.Start == nil {
			t.Error("expected non-nil region start event, got nil")
		}
		kind := region.Start.Kind()
		if kind != wantStart {
			t.Errorf("wanted region start event %s, got %s", wantStart, kind)
		}
		if kind == trace.EventRegionBegin {
			if region.Start.Region().Type != region.Name {
				t.Errorf("region name mismatch: event has %s, summary has %s", region.Start.Region().Type, region.Name)
			}
		} else {
			st := region.Start.StateTransition()
			if st.Resource.Kind != trace.ResourceGoroutine {
				t.Errorf("found region start event for the wrong resource: %s", st.Resource)
			}
			if st.Resource.Goroutine() != goid {
				t.Errorf("found region start event for the wrong resource: wanted goroutine %d, got %s", goid, st.Resource)
			}
			if old, _ := st.Goroutine(); old != trace.GoNotExist && old != trace.GoUndetermined {
				t.Errorf("expected transition from GoNotExist or GoUndetermined, got transition from %s instead", old)
			}
		}
	default:
		t.Errorf("unexpected want start event type: %s", wantStart)
	}

	switch wantEnd {
	case trace.EventBad:
		if region.End != nil {
			t.Errorf("expected nil region end event, got\n%s", region.End.String())
		}
	case trace.EventStateTransition, trace.EventRegionEnd:
		if region.End == nil {
			t.Error("expected non-nil region end event, got nil")
		}
		kind := region.End.Kind()
		if kind != wantEnd {
			t.Errorf("wanted region end event %s, got %s", wantEnd, kind)
		}
		if kind == trace.EventRegionEnd {
			if region.End.Region().Type != region.Name {
				t.Errorf("region name mismatch: event has %s, summary has %s", region.End.Region().Type, region.Name)
			}
		} else {
			st := region.End.StateTransition()
			if st.Resource.Kind != trace.ResourceGoroutine {
				t.Errorf("found region end event for the wrong resource: %s", st.Resource)
			}
			if st.Resource.Goroutine() != goid {
				t.Errorf("found region end event for the wrong resource: wanted goroutine %d, got %s", goid, st.Resource)
			}
			if _, new := st.Goroutine(); new != trace.GoNotExist {
				t.Errorf("expected transition to GoNotExist, got transition to %s instead", new)
			}
		}
	default:
		t.Errorf("unexpected want end event type: %s", wantEnd)
	}
}

func basicGoroutineExecStatsChecks(t *testing.T, stats *trace.GoroutineExecStats) {
	if stats.ExecTime < 0 {
		t.Error("found negative ExecTime")
	}
	if stats.SchedWaitTime < 0 {
		t.Error("found negative SchedWaitTime")
	}
	if stats.SyscallTime < 0 {
		t.Error("found negative SyscallTime")
	}
	if stats.SyscallBlockTime < 0 {
		t.Error("found negative SyscallBlockTime")
	}
	if stats.TotalTime < 0 {
		t.Error("found negative TotalTime")
	}
	for reason, dt := range stats.BlockTimeByReason {
		if dt < 0 {
			t.Errorf("found negative BlockTimeByReason for %s", reason)
		}
	}
	for name, dt := range stats.RangeTime {
		if dt < 0 {
			t.Errorf("found negative RangeTime for range %s", name)
		}
	}
}

func TestRelatedGoroutinesV2Trace(t *testing.T) {
	testPath := "testdata/tests/go122-gc-stress.test"
	trc, _, err := testtrace.ParseFile(testPath)
	if err != nil {
		t.Fatalf("malformed test %s: bad trace file: %v", testPath, err)
	}

	// Create a reader.
	r, err := trace.NewReader(trc)
	if err != nil {
		t.Fatalf("failed to create trace reader for %s: %v", testPath, err)
	}

	// Collect all the events.
	var events []trace.Event
	for {
		ev, err := r.ReadEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to process trace %s: %v", testPath, err)
		}
		events = append(events, ev)
	}

	// Test the function.
	targetg := trace.GoID(86)
	got := trace.RelatedGoroutinesV2(events, targetg)
	want := map[trace.GoID]struct{}{
		trace.GoID(86):  struct{}{}, // N.B. Result includes target.
		trace.GoID(71):  struct{}{},
		trace.GoID(25):  struct{}{},
		trace.GoID(122): struct{}{},
	}
	for goid := range got {
		if _, ok := want[goid]; ok {
			delete(want, goid)
		} else {
			t.Errorf("unexpected goroutine %d found in related goroutines for %d in test %s", goid, targetg, testPath)
		}
	}
	if len(want) != 0 {
		for goid := range want {
			t.Errorf("failed to find related goroutine %d for goroutine %d in test %s", goid, targetg, testPath)
		}
	}
}

"""



```