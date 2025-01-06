Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding: The Big Picture**

The first thing I notice is the import path `go/src/cmd/trace/tasks.go`. This immediately tells me this code is part of the `trace` command in the Go toolchain. The filename `tasks.go` strongly suggests it deals with the concept of "tasks" within a trace. The package name `main` confirms this is an executable program's code.

**2. Identifying Key Functions and Data Structures**

I start by looking for the main entry points or significant functions. The names `UserTasksHandlerFunc` and `UserTaskHandlerFunc` stand out. The `HandlerFunc` suffix strongly implies they are HTTP handler functions used to serve web pages. This means the `trace` command likely has a web interface for visualizing traces.

Next, I examine the data structures. `taskStats` appears to be a summary of task information, holding the task type, count, and a histogram of durations. The `task` struct in `UserTaskHandlerFunc` looks like a detailed representation of an individual task, including events, timings, and IDs. `taskFilter` is clearly used for filtering tasks based on user input.

**3. Analyzing `UserTasksHandlerFunc`**

* **Purpose:** The name strongly suggests it handles requests for a summary of user tasks.
* **Input:** It takes a `parsedTrace` as input. This likely contains the parsed data from a trace file.
* **Processing:**
    * It iterates through `t.summary.Tasks`, which I assume is a slice of individual task details.
    * It creates a `summary` map to group tasks by name (task type).
    * It populates the `summary` map with `taskStats`, accumulating counts and histogram data for each task type.
    * It sorts the summarized tasks by type.
    * It executes a template (`templUserTaskTypes`) to generate HTML output.
* **Output:**  It writes HTML to the `http.ResponseWriter`, displaying a table of task types, their counts, and duration distributions.
* **Inference:** This function provides a high-level overview of the different types of tasks present in the trace and their performance characteristics.

**4. Analyzing `UserTaskHandlerFunc`**

* **Purpose:** The name suggests it handles requests for details of specific user tasks.
* **Input:** It also takes a `parsedTrace`. It receives HTTP request parameters to filter tasks.
* **Processing:**
    * It creates a `taskFilter` based on the URL parameters.
    * It iterates through the tasks in the trace.
    * For each matching task:
        * It collects relevant events (start, end, logs, regions).
        * It sorts the events by time.
        * It creates an `event` struct for each event, including timestamps and descriptions.
        * It creates a `task` struct with details like start/end times, duration, events, and completeness.
    * It sorts the filtered tasks by duration.
    * It executes a template (`templUserTaskType`) to generate detailed HTML output for the filtered tasks.
* **Output:** It writes HTML to the `http.ResponseWriter`, displaying a detailed view of the selected tasks and their associated events.
* **Inference:** This function allows users to drill down into the details of specific tasks, examining their execution flow and timing.

**5. Analyzing `taskFilter` and `newTaskFilter`**

* **Purpose:** To filter tasks based on user-specified criteria.
* **Mechanism:** `newTaskFilter` parses URL parameters (like `type`, `complete`, `latmin`, `latmax`, `logtext`) and creates a `taskFilter` object. The `taskFilter` holds a slice of predicate functions (`cond`). The `match` method checks if a task satisfies all the filter conditions.
* **Inference:** This provides the filtering logic for the detailed task view.

**6. Analyzing Helper Functions**

I briefly look at functions like `taskInterval`, `taskMatches`, `describeEvent`, `primaryGoroutine`, `elapsed`, and `asMillisecond`. These appear to be utility functions for calculating durations, matching text, formatting output, and extracting information from trace events.

**7. Template Analysis**

I skim the template definitions (`templUserTaskTypes` and `templUserTaskType`). I notice the HTML structure for tables, links, and basic styling. This confirms the web interface nature of the code. The template logic (using `{{range}}`, `{{.Type}}`, etc.) indicates how the Go data is rendered into HTML.

**8. Putting It All Together (Inferring Functionality)**

Based on the above analysis, I can infer the overall functionality:

* The code is part of the `go tool trace` command.
* It provides a web interface for analyzing Go execution traces.
* The `tasks.go` file specifically deals with visualizing user-defined tasks within the trace.
* It allows users to view a summary of task types and their performance.
* It enables users to drill down into the details of individual tasks, examining their event timelines and durations.
* It supports filtering tasks based on various criteria like type, completeness, latency, and log message content.

**9. Considering Edge Cases and Potential Issues (Error Analysis)**

While analyzing, I consider potential issues:

* **Error Handling:**  The code includes checks for errors during template execution and parameter parsing.
* **Data Dependency:** The code relies on the `parsedTrace` data being correctly populated. Issues in the trace parsing logic could lead to incorrect results.
* **User Input:**  The code uses `template.URLQueryEscaper` to prevent potential injection vulnerabilities when constructing URLs with user-provided data.

**10. Code Examples and Command-Line Interaction (Illustrative)**

Finally, I construct illustrative code examples and command-line scenarios to demonstrate how this code might be used in practice. This helps solidify the understanding and provides concrete use cases. I also think about how the command-line flags of `go tool trace` might influence the behavior (though this specific file doesn't parse those flags directly).

This systematic approach, moving from the general to the specific, allows for a comprehensive understanding of the code's functionality and its role within the larger `trace` tool.
这段代码是 Go 语言 `trace` 工具的一部分，位于 `go/src/cmd/trace/tasks.go` 文件中。它的主要功能是 **处理和展示 Go 程序执行跟踪 (trace) 中用户自定义的任务 (User Tasks) 信息**。

更具体地说，它实现了以下功能：

1. **汇总用户任务类型:**  `UserTasksHandlerFunc` 函数负责接收 HTTP 请求，并汇总跟踪数据中所有用户任务的类型、数量以及执行时长分布。它将同名的任务归为一类，并计算它们的统计信息。

2. **展示用户任务类型列表:**  `UserTasksHandlerFunc` 使用 HTML 模板 `templUserTaskTypes` 将汇总的任务类型信息渲染成一个 HTML 表格，表格包含任务类型、数量以及完成任务的执行时长分布直方图。

3. **展示特定用户任务的详细信息:** `UserTaskHandlerFunc` 函数处理针对特定用户任务类型的请求。它根据 URL 参数（例如任务类型、完成状态、延迟范围、日志文本等）过滤任务，并展示匹配的任务的详细信息，包括时间戳、执行时长、发生的事件（例如任务开始、结束、日志记录、region 的开始和结束等）。

4. **用户任务过滤:** `newTaskFilter` 函数根据 HTTP 请求的 URL 参数创建一个 `taskFilter` 对象。这个过滤器可以根据任务类型、完成状态、执行延迟范围和日志内容等条件来筛选用户任务。

5. **事件展示:**  代码中定义了 `describeEvent` 函数，用于将跟踪事件转换为易于理解的文本描述。这使得用户更容易理解任务执行过程中发生的具体事件。

**它可以推理出它是什么 go 语言功能的实现：**

这段代码是 `go tool trace` 命令的一部分，用于分析 Go 程序的运行时跟踪数据。Go 语言内置了 `runtime/trace` 包，允许开发者在程序中插入自定义的任务和事件，以便在事后进行分析。这段代码正是利用了这些跟踪数据，通过 Web 界面将用户自定义的任务信息可视化展示出来。

**Go 代码示例 (假设的输入与输出):**

假设我们有一个 Go 程序，其中使用了 `runtime/trace` 包记录了一些用户任务：

```go
package main

import (
	"context"
	"fmt"
	"os"
	"runtime/trace"
	"time"
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

	ctx := context.Background()

	// 记录一个完整的任务
	task1 := trace.NewTask(ctx, "ProcessData")
	defer task1.End()
	time.Sleep(100 * time.Millisecond)
	trace.Logf(ctx, "ProcessData", "Data processed successfully")

	// 记录另一个完整的任务
	task2 := trace.NewTask(ctx, "SendData")
	defer task2.End()
	time.Sleep(50 * time.Millisecond)
	trace.Logf(ctx, "SendData", "Data sent")

	// 记录一个未完成的任务
	_ = trace.NewTask(ctx, "WaitForInput")
	time.Sleep(200 * time.Millisecond) // 假设程序在这里退出
}
```

**命令行参数的具体处理:**

这段代码本身是 HTTP 处理函数，它处理的是 Web 界面上的请求，而不是直接处理命令行参数。  `UserTasksHandlerFunc` 和 `UserTaskHandlerFunc` 从 `http.Request` 对象中获取 URL 查询参数，例如：

* **`UserTasksHandlerFunc` (没有特定的 URL 参数):**  该处理函数主要用于展示所有任务类型的汇总信息，通常没有特定的 URL 参数。

* **`UserTaskHandlerFunc`:** 该处理函数会处理以下可能的 URL 参数，并通过 `newTaskFilter` 函数解析这些参数来过滤任务:
    * **`type`:**  指定要查看的任务类型。例如：`/usertask?type=ProcessData`
    * **`complete`:**  指定是否只查看已完成的任务 (`complete=1`) 或未完成的任务 (`complete=0`)。例如：`/usertask?type=ProcessData&complete=1`
    * **`latmin`:**  指定最小执行延迟。例如：`/usertask?type=ProcessData&latmin=50ms`
    * **`latmax`:**  指定最大执行延迟。例如：`/usertask?type=ProcessData&latmax=150ms`
    * **`logtext`:**  指定日志文本包含的字符串。例如：`/usertask?logtext=processed`

**假设的输出 (访问 `/tasks` 路径，由 `UserTasksHandlerFunc` 处理):**

访问 `/tasks` 路径后，可能会看到类似以下的 HTML 表格：

```html
<!DOCTYPE html>
<title>Tasks</title>
<style>/* ... CSS 样式 ... */</style>
<body>
Search log text: <form action="/usertask"><input name="logtext" type="text"><input type="submit"></form><br>
<table border="1" sortable="1">
<tr>
<th>Task type</th>
<th>Count</th>
<th>Duration distribution (complete tasks)</th>
</tr>
  <tr>
    <td>ProcessData</td>
    <td><a href="/usertask?type=ProcessData">1</a></td>
    <td><div class="histoTime">0.000100s</div></td>
  </tr>
  <tr>
    <td>SendData</td>
    <td><a href="/usertask?type=SendData">1</a></td>
    <td><div class="histoTime">0.000050s</div></td>
  </tr>
  <tr>
    <td>WaitForInput</td>
    <td><a href="/usertask?type=WaitForInput">1</a></td>
    <td></td>
  </tr>
</table>
</body>
</html>
```

**假设的输出 (访问 `/usertask?type=ProcessData` 路径，由 `UserTaskHandlerFunc` 处理):**

访问 `/usertask?type=ProcessData` 路径后，可能会看到类似以下的 HTML 页面：

```html
<!DOCTYPE html>
<title>Tasks: ProcessData</title>
<style>/* ... CSS 样式 ... */</style>
<body>

<h2>User Task: ProcessData</h2>

Search log text: <form onsubmit="window.location.search+='&logtext='+window.logtextinput.value; return false">
<input name="logtext" id="logtextinput" type="text"><input type="submit">
</form><br>

<table id="reqs">
	<tr>
		<th>When</th>
		<th>Elapsed</th>
		<th>Goroutine</th>
		<th>Events</th>
	</tr>
	<tr class="first">
		<td class="when">0.000000000s</td>
		<td class="elapsed">0.000000s</td>
		<td></td>
		<td>
			<a href="/trace?focustask=1#0:100">Task 1</a>
			<a href="/trace?taskid=1#0:100">(goroutine view)</a>
			(complete)
		</td>
	</tr>
	<tr>
		<td class="when">         .000000000</td>
		<td class="elapsed">         .000100000</td>
		<td class="goid">14</td>
		<td>log "Data processed successfully"</td>
	</tr>
    </tbody>
</table>
</body>
</html>
```

**使用者易犯错的点:**

1. **URL 参数拼写错误:**  用户在通过 URL 过滤任务时，可能会拼错参数名（例如 `tpye` 而不是 `type`）或参数值，导致过滤条件失效，看不到预期的结果。

   **例如:**  用户想查看 "ProcessData" 类型的任务，但错误地输入了 `/usertask?tpye=ProcessData`，这将不会返回任何结果。

2. **对时间单位的理解不准确:** 在使用 `latmin` 和 `latmax` 参数时，用户需要理解时间单位是 Go 的 `time.Duration` 格式。如果输入了错误的单位，例如 `/usertask?latmin=100`（缺少时间单位），则会导致解析错误。

3. **期望实时更新:** 用户可能会误认为在程序运行过程中刷新 `/tasks` 或 `/usertask` 页面就能看到最新的任务信息。实际上，`go tool trace` 处理的是一个已经完成的跟踪文件，页面展示的是该文件的静态快照。需要重新生成跟踪文件并重新加载才能看到最新的数据。

4. **混淆任务 ID 和任务类型:** 用户可能会混淆任务的唯一 ID 和任务的类型名称。URL 中使用 `type` 参数来筛选任务类型，而任务 ID 通常用于在更详细的跟踪视图中定位特定的任务实例。

总而言之，`go/src/cmd/trace/tasks.go` 文件中的代码为 `go tool trace` 提供了核心的用户任务分析和展示功能，帮助开发者理解其 Go 程序中自定义任务的执行情况。

Prompt: 
```
这是路径为go/src/cmd/trace/tasks.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"bytes"
	"cmp"
	"fmt"
	"html/template"
	"internal/trace"
	"internal/trace/traceviewer"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
)

// UserTasksHandlerFunc returns a HandlerFunc that reports all tasks found in the trace.
func UserTasksHandlerFunc(t *parsedTrace) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tasks := t.summary.Tasks

		// Summarize groups of tasks with the same name.
		summary := make(map[string]taskStats)
		for _, task := range tasks {
			stats, ok := summary[task.Name]
			if !ok {
				stats.Type = task.Name
			}
			stats.add(task)
			summary[task.Name] = stats
		}

		// Sort tasks by type.
		userTasks := make([]taskStats, 0, len(summary))
		for _, stats := range summary {
			userTasks = append(userTasks, stats)
		}
		slices.SortFunc(userTasks, func(a, b taskStats) int {
			return cmp.Compare(a.Type, b.Type)
		})

		// Emit table.
		err := templUserTaskTypes.Execute(w, userTasks)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
			return
		}
	}
}

type taskStats struct {
	Type      string
	Count     int                       // Complete + incomplete tasks
	Histogram traceviewer.TimeHistogram // Complete tasks only
}

func (s *taskStats) UserTaskURL(complete bool) func(min, max time.Duration) string {
	return func(min, max time.Duration) string {
		return fmt.Sprintf("/usertask?type=%s&complete=%v&latmin=%v&latmax=%v", template.URLQueryEscaper(s.Type), template.URLQueryEscaper(complete), template.URLQueryEscaper(min), template.URLQueryEscaper(max))
	}
}

func (s *taskStats) add(task *trace.UserTaskSummary) {
	s.Count++
	if task.Complete() {
		s.Histogram.Add(task.End.Time().Sub(task.Start.Time()))
	}
}

var templUserTaskTypes = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<title>Tasks</title>
<style>` + traceviewer.CommonStyle + `
.histoTime {
  width: 20%;
  white-space:nowrap;
}
th {
  background-color: #050505;
  color: #fff;
}
table {
  border-collapse: collapse;
}
td,
th {
  padding-left: 8px;
  padding-right: 8px;
  padding-top: 4px;
  padding-bottom: 4px;
}
</style>
<body>
Search log text: <form action="/usertask"><input name="logtext" type="text"><input type="submit"></form><br>
<table border="1" sortable="1">
<tr>
<th>Task type</th>
<th>Count</th>
<th>Duration distribution (complete tasks)</th>
</tr>
{{range $}}
  <tr>
    <td>{{.Type}}</td>
    <td><a href="/usertask?type={{.Type}}">{{.Count}}</a></td>
    <td>{{.Histogram.ToHTML (.UserTaskURL true)}}</td>
  </tr>
{{end}}
</table>
</body>
</html>
`))

// UserTaskHandlerFunc returns a HandlerFunc that presents the details of the selected tasks.
func UserTaskHandlerFunc(t *parsedTrace) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter, err := newTaskFilter(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type event struct {
			WhenString string
			Elapsed    time.Duration
			Goroutine  trace.GoID
			What       string
			// TODO: include stack trace of creation time
		}
		type task struct {
			WhenString string
			ID         trace.TaskID
			Duration   time.Duration
			Complete   bool
			Events     []event
			Start, End time.Duration // Time since the beginning of the trace
			GCTime     time.Duration
		}
		var tasks []task
		for _, summary := range t.summary.Tasks {
			if !filter.match(t, summary) {
				continue
			}

			// Collect all the events for the task.
			var rawEvents []*trace.Event
			if summary.Start != nil {
				rawEvents = append(rawEvents, summary.Start)
			}
			if summary.End != nil {
				rawEvents = append(rawEvents, summary.End)
			}
			rawEvents = append(rawEvents, summary.Logs...)
			for _, r := range summary.Regions {
				if r.Start != nil {
					rawEvents = append(rawEvents, r.Start)
				}
				if r.End != nil {
					rawEvents = append(rawEvents, r.End)
				}
			}

			// Sort them.
			slices.SortStableFunc(rawEvents, func(a, b *trace.Event) int {
				return cmp.Compare(a.Time(), b.Time())
			})

			// Summarize them.
			var events []event
			last := t.startTime()
			for _, ev := range rawEvents {
				what := describeEvent(ev)
				if what == "" {
					continue
				}
				sinceStart := ev.Time().Sub(t.startTime())
				events = append(events, event{
					WhenString: fmt.Sprintf("%2.9f", sinceStart.Seconds()),
					Elapsed:    ev.Time().Sub(last),
					What:       what,
					Goroutine:  primaryGoroutine(ev),
				})
				last = ev.Time()
			}
			taskSpan := taskInterval(t, summary)
			taskStart := taskSpan.start.Sub(t.startTime())

			// Produce the task summary.
			tasks = append(tasks, task{
				WhenString: fmt.Sprintf("%2.9fs", taskStart.Seconds()),
				Duration:   taskSpan.duration(),
				ID:         summary.ID,
				Complete:   summary.Complete(),
				Events:     events,
				Start:      taskStart,
				End:        taskStart + taskSpan.duration(),
			})
		}
		// Sort the tasks by duration.
		slices.SortFunc(tasks, func(a, b task) int {
			return cmp.Compare(a.Duration, b.Duration)
		})

		// Emit table.
		err = templUserTaskType.Execute(w, struct {
			Name  string
			Tasks []task
		}{
			Name:  filter.name,
			Tasks: tasks,
		})
		if err != nil {
			log.Printf("failed to execute template: %v", err)
			http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
			return
		}
	}
}

var templUserTaskType = template.Must(template.New("userTask").Funcs(template.FuncMap{
	"elapsed":       elapsed,
	"asMillisecond": asMillisecond,
	"trimSpace":     strings.TrimSpace,
}).Parse(`
<!DOCTYPE html>
<title>Tasks: {{.Name}}</title>
<style>` + traceviewer.CommonStyle + `
body {
  font-family: sans-serif;
}
table#req-status td.family {
  padding-right: 2em;
}
table#req-status td.active {
  padding-right: 1em;
}
table#req-status td.empty {
  color: #aaa;
}
table#reqs {
  margin-top: 1em;
  border-collapse: collapse;
}
table#reqs tr.first {
  font-weight: bold;
}
table#reqs td {
  font-family: monospace;
}
table#reqs td.when {
  text-align: right;
  white-space: nowrap;
}
table#reqs td.elapsed {
  padding: 0 0.5em;
  text-align: right;
  white-space: pre;
  width: 10em;
}
address {
  font-size: smaller;
  margin-top: 5em;
}
</style>
<body>

<h2>User Task: {{.Name}}</h2>

Search log text: <form onsubmit="window.location.search+='&logtext='+window.logtextinput.value; return false">
<input name="logtext" id="logtextinput" type="text"><input type="submit">
</form><br>

<table id="reqs">
	<tr>
		<th>When</th>
		<th>Elapsed</th>
		<th>Goroutine</th>
		<th>Events</th>
	</tr>
	{{range $el := $.Tasks}}
	<tr class="first">
		<td class="when">{{$el.WhenString}}</td>
		<td class="elapsed">{{$el.Duration}}</td>
		<td></td>
		<td>
			<a href="/trace?focustask={{$el.ID}}#{{asMillisecond $el.Start}}:{{asMillisecond $el.End}}">Task {{$el.ID}}</a>
			<a href="/trace?taskid={{$el.ID}}#{{asMillisecond $el.Start}}:{{asMillisecond $el.End}}">(goroutine view)</a>
			({{if .Complete}}complete{{else}}incomplete{{end}})
		</td>
	</tr>
	{{range $el.Events}}
	<tr>
		<td class="when">{{.WhenString}}</td>
		<td class="elapsed">{{elapsed .Elapsed}}</td>
		<td class="goid">{{.Goroutine}}</td>
		<td>{{.What}}</td>
	</tr>
	{{end}}
    {{end}}
</body>
</html>
`))

// taskFilter represents a task filter specified by a user of cmd/trace.
type taskFilter struct {
	name string
	cond []func(*parsedTrace, *trace.UserTaskSummary) bool
}

// match returns true if a task, described by its ID and summary, matches
// the filter.
func (f *taskFilter) match(t *parsedTrace, task *trace.UserTaskSummary) bool {
	if t == nil {
		return false
	}
	for _, c := range f.cond {
		if !c(t, task) {
			return false
		}
	}
	return true
}

// newTaskFilter creates a new task filter from URL query variables.
func newTaskFilter(r *http.Request) (*taskFilter, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	var name []string
	var conditions []func(*parsedTrace, *trace.UserTaskSummary) bool

	param := r.Form
	if typ, ok := param["type"]; ok && len(typ) > 0 {
		name = append(name, fmt.Sprintf("%q", typ[0]))
		conditions = append(conditions, func(_ *parsedTrace, task *trace.UserTaskSummary) bool {
			return task.Name == typ[0]
		})
	}
	if complete := r.FormValue("complete"); complete == "1" {
		name = append(name, "complete")
		conditions = append(conditions, func(_ *parsedTrace, task *trace.UserTaskSummary) bool {
			return task.Complete()
		})
	} else if complete == "0" {
		name = append(name, "incomplete")
		conditions = append(conditions, func(_ *parsedTrace, task *trace.UserTaskSummary) bool {
			return !task.Complete()
		})
	}
	if lat, err := time.ParseDuration(r.FormValue("latmin")); err == nil {
		name = append(name, fmt.Sprintf("latency >= %s", lat))
		conditions = append(conditions, func(t *parsedTrace, task *trace.UserTaskSummary) bool {
			return task.Complete() && taskInterval(t, task).duration() >= lat
		})
	}
	if lat, err := time.ParseDuration(r.FormValue("latmax")); err == nil {
		name = append(name, fmt.Sprintf("latency <= %s", lat))
		conditions = append(conditions, func(t *parsedTrace, task *trace.UserTaskSummary) bool {
			return task.Complete() && taskInterval(t, task).duration() <= lat
		})
	}
	if text := r.FormValue("logtext"); text != "" {
		name = append(name, fmt.Sprintf("log contains %q", text))
		conditions = append(conditions, func(_ *parsedTrace, task *trace.UserTaskSummary) bool {
			return taskMatches(task, text)
		})
	}

	return &taskFilter{name: strings.Join(name, ","), cond: conditions}, nil
}

func taskInterval(t *parsedTrace, s *trace.UserTaskSummary) interval {
	var i interval
	if s.Start != nil {
		i.start = s.Start.Time()
	} else {
		i.start = t.startTime()
	}
	if s.End != nil {
		i.end = s.End.Time()
	} else {
		i.end = t.endTime()
	}
	return i
}

func taskMatches(t *trace.UserTaskSummary, text string) bool {
	matches := func(s string) bool {
		return strings.Contains(s, text)
	}
	if matches(t.Name) {
		return true
	}
	for _, r := range t.Regions {
		if matches(r.Name) {
			return true
		}
	}
	for _, ev := range t.Logs {
		log := ev.Log()
		if matches(log.Category) {
			return true
		}
		if matches(log.Message) {
			return true
		}
	}
	return false
}

func describeEvent(ev *trace.Event) string {
	switch ev.Kind() {
	case trace.EventStateTransition:
		st := ev.StateTransition()
		if st.Resource.Kind != trace.ResourceGoroutine {
			return ""
		}
		old, new := st.Goroutine()
		return fmt.Sprintf("%s -> %s", old, new)
	case trace.EventRegionBegin:
		return fmt.Sprintf("region %q begin", ev.Region().Type)
	case trace.EventRegionEnd:
		return fmt.Sprintf("region %q end", ev.Region().Type)
	case trace.EventTaskBegin:
		t := ev.Task()
		return fmt.Sprintf("task %q (D %d, parent %d) begin", t.Type, t.ID, t.Parent)
	case trace.EventTaskEnd:
		return "task end"
	case trace.EventLog:
		log := ev.Log()
		if log.Category != "" {
			return fmt.Sprintf("log %q", log.Message)
		}
		return fmt.Sprintf("log (category: %s): %q", log.Category, log.Message)
	}
	return ""
}

func primaryGoroutine(ev *trace.Event) trace.GoID {
	if ev.Kind() != trace.EventStateTransition {
		return ev.Goroutine()
	}
	st := ev.StateTransition()
	if st.Resource.Kind != trace.ResourceGoroutine {
		return trace.NoGoroutine
	}
	return st.Resource.Goroutine()
}

func elapsed(d time.Duration) string {
	b := fmt.Appendf(nil, "%.9f", d.Seconds())

	// For subsecond durations, blank all zeros before decimal point,
	// and all zeros between the decimal point and the first non-zero digit.
	if d < time.Second {
		dot := bytes.IndexByte(b, '.')
		for i := 0; i < dot; i++ {
			b[i] = ' '
		}
		for i := dot + 1; i < len(b); i++ {
			if b[i] == '0' {
				b[i] = ' '
			} else {
				break
			}
		}
	}
	return string(b)
}

func asMillisecond(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / float64(time.Millisecond)
}

"""



```