Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding of the Goal:**

The first thing I notice is the filename: `jsontrace.go`. This immediately suggests the code is involved in generating a JSON representation of some kind of trace data. The package name `main` tells me this is likely an executable program, or at least a component of one. The import of `net/http` and the function `JSONTraceHandler` strongly indicate this is part of a web service or a tool that serves trace data over HTTP.

**2. Deconstructing the `JSONTraceHandler` Function:**

This is the core of the provided code, so I'll analyze it step-by-step:

* **`func JSONTraceHandler(parsed *parsedTrace) http.Handler`:**  This confirms the HTTP handler nature. It takes a `parsedTrace` as input, implying some prior processing of raw trace data. The return type `http.Handler` is standard for HTTP handlers in Go.
* **`http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ... })`:** This is the standard way to define an HTTP handler inline in Go. The inner function receives the `ResponseWriter` (for sending the response) and the `Request` (containing incoming request data).
* **`opts := defaultGenOpts()`:** This suggests a configuration structure (`genOpts`) for how the JSON trace will be generated, initialized with default values.
* **`switch r.FormValue("view") { ... }`:**  This checks for a query parameter named "view". The "thread" case indicates different output modes.
* **`if goids := r.FormValue("goid"); goids != ""`:** This checks for a "goid" parameter. The name strongly suggests it's related to Go goroutine IDs. The code parses this ID and attempts to focus the trace on a specific goroutine.
* **`else if taskids := r.FormValue("focustask"); taskids != ""`:** Similar to "goid", this checks for a "focustask" parameter, likely related to user-defined tasks within the trace.
* **`else if taskids := r.FormValue("taskid"); taskids != ""`:** Another parameter related to tasks, but the handling is different, suggesting potentially different ways to view or filter tasks.
* **Parsing "start" and "end":** The code handles "start" and "end" query parameters to filter the time range of the trace.
* **`c := traceviewer.ViewerDataTraceConsumer(w, start, end)`:** This looks like the core of the JSON generation. It creates a `TraceConsumer` that writes to the HTTP response writer (`w`), likely formatting the trace data as JSON.
* **`if err := generateTrace(parsed, opts, c); err != nil { ... }`:**  This delegates the actual trace generation to another function, `generateTrace`.

**3. Analyzing `generateTrace` and Related Structures:**

* **`type traceContext struct { ... }`:** This structure holds the `traceviewer.Emitter` (likely responsible for the low-level JSON emission) and start/end times of the trace.
* **`type genOpts struct { ... }`:**  This structure stores the various options for trace generation, such as the viewing mode, time range, focused goroutine, and focused task. The `setTask` method is important for understanding how task focus is handled.
* **`func generateTrace(parsed *parsedTrace, opts *genOpts, c traceviewer.TraceConsumer) error`:** This function orchestrates the trace generation. It creates a `traceContext`, chooses a generator based on the `opts.mode`, and then calls `runGenerator`.
* **Generator Interface:** The code uses an interface `generator` with implementations like `goroutineGenerator`, `threadGenerator`, and `procGenerator`. This indicates different strategies for organizing the trace data.

**4. Inferring Functionality and Go Concepts:**

Based on the code structure and naming, I can infer the following:

* **Go's `net/http` package:**  The code uses `http.Handler` and `http.ResponseWriter`, which are fundamental to building web services in Go.
* **Goroutine Tracing:** The "goid" parameter and the `trace.GoID` type strongly indicate this code deals with tracing the execution of Go goroutines.
* **User Tasks:** The "focustask" and "taskid" parameters, along with `trace.UserTaskSummary`, suggest the ability to define and track user-level tasks within the trace.
* **Trace Viewer:** The `traceviewer` package is central, and it likely provides the core logic for formatting and rendering the trace data in a web browser.
* **Query Parameters:** The code extensively uses `r.FormValue()` to retrieve query parameters from the HTTP request, enabling users to customize the trace view.

**5. Constructing Examples and Identifying Potential Issues:**

Now, with a good understanding of the code, I can start thinking about how to illustrate its functionality and potential pitfalls.

* **Example:** I'll choose the "goid" parameter to demonstrate focusing on a specific goroutine. I need to simulate how the `parsedTrace` might look (though I don't have the full structure) and the expected JSON output (again, a simplification).
* **Command-line Arguments:** While the code itself doesn't directly handle command-line arguments, the context (being part of `cmd/trace`) implies that this handler would be used by a larger tool that *does* take command-line arguments to load the trace data. I'll focus on the HTTP request parameters since that's what the code directly processes.
* **Common Mistakes:** I'll consider scenarios where a user might provide incorrect input, such as invalid "goid" or "taskid" values, or inconsistent "start" and "end" times.

**6. Refinement and Iteration:**

As I write the explanation, I might go back and reread parts of the code to ensure my understanding is correct. For example, I might double-check how the `setTask` function works or how the different viewing modes are selected. I'll also make sure my examples are clear and concise.

This systematic approach of understanding the overall goal, deconstructing the code, inferring functionality, constructing examples, and refining the explanation helps to create a comprehensive and accurate analysis of the provided Go code snippet.
这段Go语言代码是 `go tool trace` 工具中用于处理和展示 trace 数据的 HTTP 处理函数 `JSONTraceHandler` 的一部分。它的主要功能是将解析后的 Go trace 数据转换成 JSON 格式，以便前端的 trace viewer (通常是网页应用) 可以加载和渲染这些数据。

更具体地说，`JSONTraceHandler` 接收一个 `parsedTrace` 类型的参数，这个参数包含了从 trace 文件中解析出来的所有事件和元数据。然后，它根据 HTTP 请求中的查询参数来定制生成的 JSON 数据，以满足不同的查看需求。

**功能列表:**

1. **处理 HTTP 请求:**  它是一个 `http.Handler`，因此能够处理来自 web 浏览器的请求。
2. **根据查询参数设置查看选项:**  它会解析请求 URL 中的查询参数，例如 `view`, `goid`, `focustask`, `taskid`, `start`, `end`，并据此调整 trace 数据的生成方式。
3. **支持不同的视图模式:**
    * **线程导向视图 (`view=thread`)**: 虽然代码中仅有 `opts.mode = traceviewer.ModeThreadOriented` 的设置，但可以推断其目的是生成适合按线程查看的 JSON 数据。
    * **Goroutine 导向视图 (`goid=...` 或 `taskid=...`)**:  允许用户聚焦于特定的 goroutine 或与特定任务相关的 goroutine。
    * **任务导向视图 (`focustask=...` 或 `taskid=...`)**: 允许用户聚焦于特定的用户任务及其相关的 goroutine。
4. **支持按 Goroutine 过滤:** 通过 `goid` 参数，可以只显示与特定 goroutine 相关的事件。
5. **支持按用户任务过滤:** 通过 `focustask` 和 `taskid` 参数，可以只显示与特定用户任务相关的事件。
6. **支持时间范围过滤:** 通过 `start` 和 `end` 参数，可以限制生成的 JSON 数据的时间范围。
7. **生成 JSON 数据并写入 HTTP 响应:**  最终，它会调用 `generateTrace` 函数，将根据选项过滤和处理后的 trace 数据以 JSON 格式写入 HTTP 响应，发送给客户端。

**它是什么 Go 语言功能的实现：**

这段代码是 Go 语言 `net/http` 包中处理 HTTP 请求的功能的实现。它利用了 `http.Handler` 接口和 `http.ResponseWriter` 以及 `http.Request` 对象来构建一个 Web 服务端点，用于提供 trace 数据。 同时，它也用到了 Go 的并发模型中的 goroutine 的 tracing 功能，这体现在对 `goid` 参数的处理上。

**Go 代码举例说明:**

假设我们有一个已经解析好的 trace 数据 `parsed`。现在我们想要创建一个 HTTP 服务器，当访问 `/trace` 路径时，能够根据查询参数返回 JSON 格式的 trace 数据。

```go
package main

import (
	"fmt"
	"net/http"

	"internal/trace" // 假设这里是 trace 相关的内部包
	"internal/trace/traceviewer" // 假设这里是 trace viewer 相关的内部包
)

// 假设的 parsedTrace 结构
type parsedTrace struct {
	summary *trace.TraceSummary
	events  []*trace.Event
}

// 假设的 trace.TraceSummary 和 trace.Event 的简化定义
type TraceSummary struct {
	Goroutines map[trace.GoID]*GoroutineInfo
	Tasks      map[trace.TaskID]*UserTaskSummary
}

type GoroutineInfo struct {
	ID        trace.GoID
	StartTime trace.Time
	EndTime   trace.Time
}

type UserTaskSummary struct {
	ID         trace.TaskID
	Start      *trace.Event
	End        *trace.Event
	DescendentsFunc func() []*UserTaskSummary
	Goroutines map[trace.GoID]struct{}
	Logs       []*trace.Event // 假设的 Log 事件
}

func (t *UserTaskSummary) Descendents() []*UserTaskSummary {
	if t.DescendentsFunc != nil {
		return t.DescendentsFunc()
	}
	return nil
}

func main() {
	// 模拟解析好的 trace 数据
	parsed := &parsedTrace{
		summary: &trace.TraceSummary{
			Goroutines: map[trace.GoID]*GoroutineInfo{
				1: {ID: 1, StartTime: 10, EndTime: 100},
				2: {ID: 2, StartTime: 20, EndTime: 90},
			},
			Tasks: map[trace.TaskID]*UserTaskSummary{
				100: {
					ID: 100,
					Start: &trace.Event{P: 0, Time_: 30, G: 1},
					End:   &trace.Event{P: 0, Time_: 80, G: 1},
					Goroutines: map[trace.GoID]struct{}{1: {}},
					Logs: []*trace.Event{{P: 0, Time_: 40, G: 1}},
				},
			},
		},
		events: []*trace.Event{
			{P: 0, Time_: 10, G: 1, Type: trace.EvGoCreate},
			{P: 0, Time_: 20, G: 2, Type: trace.EvGoCreate},
			{P: 0, Time_: 30, G: 1, Type: trace.EvUserTaskCreate},
			{P: 0, Time_: 40, G: 1, Type: trace.EvUserLog},
			{P: 0, Time_: 80, G: 1, Type: trace.EvUserTaskEnd},
			{P: 0, Time_: 90, G: 2, Type: trace.EvGoEnd},
			{P: 0, Time_: 100, G: 1, Type: trace.EvGoEnd},
		},
	}

	// 创建处理函数
	handler := JSONTraceHandler(parsed)

	// 注册处理函数到 /trace 路径
	http.Handle("/trace", handler)

	fmt.Println("Server listening on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

// 这里需要提供 generateTrace 函数的实现，为了简化，我们只打印 opts
func generateTrace(parsed *parsedTrace, opts *genOpts, c traceviewer.TraceConsumer) error {
	fmt.Println("Generating trace with options:", opts)
	// 实际实现会调用 c.WriteEvent 等方法将数据写入
	return nil
}

// 假设的 defaultGenOpts 函数
func defaultGenOpts() *genOpts {
	return &genOpts{
		startTime: 0,
		endTime:   99999999999, // 很大的值
	}
}

// 假设的 genOpts 结构
type genOpts struct {
	mode      traceviewer.Mode
	startTime int64
	endTime   int64
	focusGoroutine trace.GoID
	goroutines map[trace.GoID]struct{}
	tasks []*trace.UserTaskSummary
}

// 假设的 traceviewer.Mode 类型
type Mode int

const (
	ModeThreadOriented Mode = 1 << 0
	ModeGoroutineOriented Mode = 1 << 1
	ModeTaskOriented Mode = 1 << 2
)

// 假设的 traceviewer.TraceConsumer 接口
type TraceConsumer interface {
	WriteEvent(event interface{}) error
}

// 假设的 traceviewer.ViewerDataTraceConsumer 函数
func ViewerDataTraceConsumer(w http.ResponseWriter, start, end int64) TraceConsumer {
	return &dummyTraceConsumer{writer: w}
}

type dummyTraceConsumer struct {
	writer http.ResponseWriter
}

func (d *dummyTraceConsumer) WriteEvent(event interface{}) error {
	fmt.Fprintf(d.writer, "%v\n", event)
	return nil
}

// 假设的 trace 包中的类型定义
type Time int64
type GoID uint64
type TaskID uint64

type EventType int

const (
	EvGoCreate EventType = iota
	EvGoStart
	EvGoEnd
	EvUserTaskCreate
	EvUserTaskEnd
	EvUserLog
	// ... 更多事件类型
)

type Event struct {
	P    int
	Time_ Time
	G    GoID
	Type EventType
	// ... 更多字段
}

func (e *Event) Time() Time {
	return e.Time_
}

func (e *Event) Goroutine() GoID {
	return e.G
}

// 假设的 trace.RelatedGoroutinesV2 函数
func RelatedGoroutinesV2(events []*trace.Event, goid trace.GoID) map[trace.GoID]struct{} {
	related := make(map[trace.GoID]struct{})
	related[goid] = struct{}{}
	return related
}

func (opts *genOpts) setTask(parsed *parsedTrace, task *trace.UserTaskSummary) {
	opts.mode |= traceviewer.ModeTaskOriented
	var startTime Time
	if task.Start != nil {
		startTime = task.Start.Time()
	}
	opts.startTime = int64(startTime) // 简化时间处理
	var endTime Time
	if task.End != nil {
		endTime = task.End.Time()
	} else {
		endTime = Time(99999999999) // 简化处理
	}
	opts.endTime = int64(endTime)
	opts.tasks = task.Descendents()
	// 简化排序
}
```

现在，你可以运行这个程序，然后在浏览器中访问 `http://localhost:8080/trace` 或 `http://localhost:8080/trace?goid=1` 等 URL 来查看不同过滤条件的 JSON 输出（实际上上面的简化代码只是打印了 `opts`）。

**代码推理与假设的输入输出:**

**假设输入:**

一个包含以下事件的 `parsedTrace` 结构:

```go
parsed := &parsedTrace{
    summary: &trace.TraceSummary{
        Goroutines: map[trace.GoID]*GoroutineInfo{
            1: {ID: 1, StartTime: 10, EndTime: 100},
        },
        Tasks: map[trace.TaskID]*UserTaskSummary{
            100: {
                ID: 100,
                Start: &trace.Event{P: 0, Time_: 30, G: 1},
                End:   &trace.Event{P: 0, Time_: 80, G: 1},
				Goroutines: map[trace.GoID]struct{}{1: {}},
            },
        },
    },
    events: []*trace.Event{
        {P: 0, Time_: 10, G: 1, Type: trace.EvGoCreate},
        {P: 0, Time_: 30, G: 1, Type: trace.EvUserTaskCreate},
        {P: 0, Time_: 80, G: 1, Type: trace.EvUserTaskEnd},
        {P: 0, Time_: 100, G: 1, Type: trace.EvGoEnd},
    },
}
```

**场景 1:  无查询参数**

**HTTP 请求:** `GET /trace HTTP/1.1`

**推理:** `defaultGenOpts` 会被使用，生成包含所有事件的 JSON 数据。

**假设输出 (JSON 结构示意):**

```json
[
  {"type": "event", "time": 10, "goid": 1, "name": "GoCreate"},
  {"type": "event", "time": 30, "goid": 1, "name": "UserTaskCreate"},
  {"type": "event", "time": 80, "goid": 1, "name": "UserTaskEnd"},
  {"type": "event", "time": 100, "goid": 1, "name": "GoEnd"}
]
```

**场景 2:  指定 `goid`**

**HTTP 请求:** `GET /trace?goid=1 HTTP/1.1`

**推理:**  会聚焦于 goroutine ID 为 1 的事件。

**假设输出 (JSON 结构示意):**

```json
[
  {"type": "event", "time": 10, "goid": 1, "name": "GoCreate"},
  {"type": "event", "time": 30, "goid": 1, "name": "UserTaskCreate"},
  {"type": "event", "time": 80, "goid": 1, "name": "UserTaskEnd"},
  {"type": "event", "time": 100, "goid": 1, "name": "GoEnd"}
]
```

**场景 3: 指定 `taskid`**

**HTTP 请求:** `GET /trace?taskid=100 HTTP/1.1`

**推理:** 会聚焦于 task ID 为 100 的事件以及相关的 goroutine 事件。

**假设输出 (JSON 结构示意):**

```json
[
  {"type": "event", "time": 30, "goid": 1, "name": "UserTaskCreate"},
  {"type": "event", "time": 80, "goid": 1, "name": "UserTaskEnd"}
]
```

**命令行参数的具体处理:**

该代码段本身并不直接处理命令行参数。它是一个 HTTP 处理函数，处理的是 HTTP 请求中的查询参数。

具体的命令行参数处理通常发生在 `go tool trace` 工具的主程序中，用于指定要分析的 trace 文件。  `JSONTraceHandler` 函数接收的 `parsed *parsedTrace` 参数，其数据来源就是通过命令行指定的 trace 文件，并经过解析后得到的。

**使用者易犯错的点:**

1. **错误的 `goid` 或 `taskid`:** 如果用户提供的 `goid` 或 `taskid` 在 trace 数据中不存在，服务器会记录错误日志，但可能不会返回友好的错误信息到客户端，导致前端无法正确展示。

   **例如:**  如果 trace 中只存在 `goid=1`，但用户访问 `GET /trace?goid=2`，控制台会输出 `failed to find goroutine 2`。

2. **不匹配的 `start` 和 `end` 参数:**  代码要求 `start` 和 `end` 参数同时存在或同时不存在。如果只提供其中一个，会导致日志输出错误信息。

   **例如:** 访问 `GET /trace?start=10` 会导致控制台输出 `failed to parse end parameter ""`.

3. **时间参数格式错误:** `start` 和 `end` 参数需要是能够被 `strconv.ParseInt` 解析为整数的字符串。如果提供非数字字符串，会导致解析错误。

   **例如:** 访问 `GET /trace?start=abc&end=def` 会导致控制台输出解析错误。

总的来说，`jsontrace.go` 文件中的 `JSONTraceHandler` 函数是 `go tool trace` 工具中一个关键的组成部分，它负责将后端的 trace 数据以 JSON 格式暴露给前端，使得用户可以通过 web 界面来交互式地查看和分析 Go 程序的执行轨迹。

Prompt: 
```
这是路径为go/src/cmd/trace/jsontrace.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"cmp"
	"log"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"internal/trace"
	"internal/trace/traceviewer"
)

func JSONTraceHandler(parsed *parsedTrace) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opts := defaultGenOpts()

		switch r.FormValue("view") {
		case "thread":
			opts.mode = traceviewer.ModeThreadOriented
		}
		if goids := r.FormValue("goid"); goids != "" {
			// Render trace focused on a particular goroutine.

			id, err := strconv.ParseUint(goids, 10, 64)
			if err != nil {
				log.Printf("failed to parse goid parameter %q: %v", goids, err)
				return
			}
			goid := trace.GoID(id)
			g, ok := parsed.summary.Goroutines[goid]
			if !ok {
				log.Printf("failed to find goroutine %d", goid)
				return
			}
			opts.mode = traceviewer.ModeGoroutineOriented
			if g.StartTime != 0 {
				opts.startTime = g.StartTime.Sub(parsed.startTime())
			} else {
				opts.startTime = 0
			}
			if g.EndTime != 0 {
				opts.endTime = g.EndTime.Sub(parsed.startTime())
			} else { // The goroutine didn't end.
				opts.endTime = parsed.endTime().Sub(parsed.startTime())
			}
			opts.focusGoroutine = goid
			opts.goroutines = trace.RelatedGoroutinesV2(parsed.events, goid)
		} else if taskids := r.FormValue("focustask"); taskids != "" {
			taskid, err := strconv.ParseUint(taskids, 10, 64)
			if err != nil {
				log.Printf("failed to parse focustask parameter %q: %v", taskids, err)
				return
			}
			task, ok := parsed.summary.Tasks[trace.TaskID(taskid)]
			if !ok || (task.Start == nil && task.End == nil) {
				log.Printf("failed to find task with id %d", taskid)
				return
			}
			opts.setTask(parsed, task)
		} else if taskids := r.FormValue("taskid"); taskids != "" {
			taskid, err := strconv.ParseUint(taskids, 10, 64)
			if err != nil {
				log.Printf("failed to parse taskid parameter %q: %v", taskids, err)
				return
			}
			task, ok := parsed.summary.Tasks[trace.TaskID(taskid)]
			if !ok {
				log.Printf("failed to find task with id %d", taskid)
				return
			}
			// This mode is goroutine-oriented.
			opts.mode = traceviewer.ModeGoroutineOriented
			opts.setTask(parsed, task)

			// Pick the goroutine to orient ourselves around by just
			// trying to pick the earliest event in the task that makes
			// any sense. Though, we always want the start if that's there.
			var firstEv *trace.Event
			if task.Start != nil {
				firstEv = task.Start
			} else {
				for _, logEv := range task.Logs {
					if firstEv == nil || logEv.Time() < firstEv.Time() {
						firstEv = logEv
					}
				}
				if task.End != nil && (firstEv == nil || task.End.Time() < firstEv.Time()) {
					firstEv = task.End
				}
			}
			if firstEv == nil || firstEv.Goroutine() == trace.NoGoroutine {
				log.Printf("failed to find task with id %d", taskid)
				return
			}

			// Set the goroutine filtering options.
			goid := firstEv.Goroutine()
			opts.focusGoroutine = goid
			goroutines := make(map[trace.GoID]struct{})
			for _, task := range opts.tasks {
				// Find only directly involved goroutines.
				for id := range task.Goroutines {
					goroutines[id] = struct{}{}
				}
			}
			opts.goroutines = goroutines
		}

		// Parse start and end options. Both or none must be present.
		start := int64(0)
		end := int64(math.MaxInt64)
		if startStr, endStr := r.FormValue("start"), r.FormValue("end"); startStr != "" && endStr != "" {
			var err error
			start, err = strconv.ParseInt(startStr, 10, 64)
			if err != nil {
				log.Printf("failed to parse start parameter %q: %v", startStr, err)
				return
			}

			end, err = strconv.ParseInt(endStr, 10, 64)
			if err != nil {
				log.Printf("failed to parse end parameter %q: %v", endStr, err)
				return
			}
		}

		c := traceviewer.ViewerDataTraceConsumer(w, start, end)
		if err := generateTrace(parsed, opts, c); err != nil {
			log.Printf("failed to generate trace: %v", err)
		}
	})
}

// traceContext is a wrapper around a traceviewer.Emitter with some additional
// information that's useful to most parts of trace viewer JSON emission.
type traceContext struct {
	*traceviewer.Emitter
	startTime trace.Time
	endTime   trace.Time
}

// elapsed returns the elapsed time between the trace time and the start time
// of the trace.
func (ctx *traceContext) elapsed(now trace.Time) time.Duration {
	return now.Sub(ctx.startTime)
}

type genOpts struct {
	mode      traceviewer.Mode
	startTime time.Duration
	endTime   time.Duration

	// Used if mode != 0.
	focusGoroutine trace.GoID
	goroutines     map[trace.GoID]struct{} // Goroutines to be displayed for goroutine-oriented or task-oriented view. goroutines[0] is the main goroutine.
	tasks          []*trace.UserTaskSummary
}

// setTask sets a task to focus on.
func (opts *genOpts) setTask(parsed *parsedTrace, task *trace.UserTaskSummary) {
	opts.mode |= traceviewer.ModeTaskOriented
	if task.Start != nil {
		opts.startTime = task.Start.Time().Sub(parsed.startTime())
	} else { // The task started before the trace did.
		opts.startTime = 0
	}
	if task.End != nil {
		opts.endTime = task.End.Time().Sub(parsed.startTime())
	} else { // The task didn't end.
		opts.endTime = parsed.endTime().Sub(parsed.startTime())
	}
	opts.tasks = task.Descendents()
	slices.SortStableFunc(opts.tasks, func(a, b *trace.UserTaskSummary) int {
		aStart, bStart := parsed.startTime(), parsed.startTime()
		if a.Start != nil {
			aStart = a.Start.Time()
		}
		if b.Start != nil {
			bStart = b.Start.Time()
		}
		if a.Start != b.Start {
			return cmp.Compare(aStart, bStart)
		}
		// Break ties with the end time.
		aEnd, bEnd := parsed.endTime(), parsed.endTime()
		if a.End != nil {
			aEnd = a.End.Time()
		}
		if b.End != nil {
			bEnd = b.End.Time()
		}
		return cmp.Compare(aEnd, bEnd)
	})
}

func defaultGenOpts() *genOpts {
	return &genOpts{
		startTime: time.Duration(0),
		endTime:   time.Duration(math.MaxInt64),
	}
}

func generateTrace(parsed *parsedTrace, opts *genOpts, c traceviewer.TraceConsumer) error {
	ctx := &traceContext{
		Emitter:   traceviewer.NewEmitter(c, opts.startTime, opts.endTime),
		startTime: parsed.events[0].Time(),
		endTime:   parsed.events[len(parsed.events)-1].Time(),
	}
	defer ctx.Flush()

	var g generator
	if opts.mode&traceviewer.ModeGoroutineOriented != 0 {
		g = newGoroutineGenerator(ctx, opts.focusGoroutine, opts.goroutines)
	} else if opts.mode&traceviewer.ModeThreadOriented != 0 {
		g = newThreadGenerator()
	} else {
		g = newProcGenerator()
	}
	runGenerator(ctx, g, parsed, opts)
	return nil
}

"""



```