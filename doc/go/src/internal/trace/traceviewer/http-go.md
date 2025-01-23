Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Goal Identification:**

The first step is to quickly read through the code, paying attention to package names, function names, and key data structures. We see `package traceviewer`, `import`, `func MainHandler`, `const CommonStyle`, `var templMain`, `type View`, `func TraceHandler`, `var templTrace`, and `func StaticHandler`. The file path `go/src/internal/trace/traceviewer/http.go` strongly suggests this code is related to displaying trace data via HTTP.

**Goal:**  The core goal is to understand what this code *does* in the context of Go tracing and how it presents that information to a user.

**2. Analyzing `MainHandler`:**

* **Signature:** `func MainHandler(views []View) http.Handler` immediately tells us this function takes a slice of `View` structs and returns an `http.Handler`. This means it's responsible for handling HTTP requests.
* **Implementation:** It creates an `http.HandlerFunc`. Inside, it executes the `templMain` template, passing the `views` slice as data. If there's an error, it serves a 500 error.
* **Key Deduction:** `MainHandler` is likely the entry point for the main trace viewer page. It takes structured `View` data and renders it into HTML using a template.

**3. Analyzing `templMain`:**

* **Content:** It's a large HTML string with `<style>` and `<body>` tags. It includes headings, paragraphs, lists, and links. Notice the `{{range}}` directives – this confirms it's a Go HTML template.
* **Data Binding:**  The template iterates over the `views` slice and displays information based on the `View` struct's fields (`Type`, `Ranges`, `URL`).
* **Key Deduction:**  `templMain` defines the structure and content of the main trace viewer page. It dynamically generates links based on the `View` data. It also provides helpful explanations about Go tracing.

**4. Analyzing `View` and `Range`:**

* **Structure:**  `View` has `Type` (string) and `Ranges` (slice of `Range`). `Range` has details about start and end points, likely related to segments of the trace.
* **`URL()` methods:**  These methods generate URLs, suggesting different ways to view the trace data.
* **Key Deduction:** These structs represent the data model for organizing and presenting different views of the trace. The `Ranges` indicate the ability to split large traces into smaller, manageable chunks.

**5. Analyzing `TraceHandler`:**

* **Signature:**  `func TraceHandler() http.Handler`. Another HTTP handler.
* **Implementation:** Parses form data from the request, then replaces `{{PARAMS}}` in `templTrace` with the encoded form data. Writes the result to the response.
* **Key Deduction:** This handler likely renders a more detailed trace view. The `{{PARAMS}}` suggests it receives parameters (like `view`, `start`, `end`) to specify what part of the trace to display.

**6. Analyzing `templTrace`:**

* **Content:**  HTML with `<script>` and `<link>` tags that load external resources (`/static/webcomponents.min.js`, `/static/trace_viewer_full.html`). A lot of JavaScript code within `<script>` tags.
* **JavaScript Functionality:** The JavaScript fetches data from `/jsontrace?{{PARAMS}}`, then uses a `tr.Model` and `tr.importer.Import` (suggesting a library for trace visualization) to load and display the data. It seems to be using a web component (`<tr-ui-timeline-view>`).
* **Key Deduction:**  `templTrace` embeds a rich, interactive trace viewer, likely based on Chromium's Trace Event Profiling Tool. It fetches the actual trace data as JSON.

**7. Analyzing `StaticHandler`:**

* **Signature:** `func StaticHandler() http.Handler`. Another HTTP handler.
* **Implementation:** Uses `embed.FS` to serve files from the `staticContent` variable.
* **Key Deduction:** This handler serves static files like JavaScript libraries and HTML needed by the trace viewer.

**8. Putting it all together (Inferring the bigger picture):**

* The code defines two main views: a main overview (`MainHandler`, `templMain`) and a detailed trace view (`TraceHandler`, `templTrace`).
* The main overview lists different ways to view the trace (by proc, by thread). It provides links to the detailed trace view with specific parameters.
* The detailed trace view uses a sophisticated JavaScript-based viewer to display the trace data interactively.
* The `static` directory provides the necessary front-end assets.

**9. Answering the specific questions:**

Now that we have a good understanding of the code, we can directly address the prompt's questions. This involves summarizing the deductions made in the previous steps.

**10. Example Code and Reasoning:**

For the Go code example, we need to illustrate how `MainHandler` might be used. This involves:

* Defining the `View` struct with some sample data.
* Setting up a basic HTTP server using `net/http`.
* Registering the `MainHandler` for a specific route.
* Accessing the server in a browser to see the output.

The reasoning connects the code back to the overall goal: how does this handler actually *show* the information to a user?

**11. Command-line Arguments and Error Points:**

The code itself doesn't explicitly handle command-line arguments. This is important to note. The most likely error point is a missing or incorrectly configured `static` directory, preventing the JavaScript viewer from loading.

**Self-Correction/Refinement:**

During the process, I might realize I'm focusing too much on the HTML details and not enough on the *purpose* of each handler. I'd then step back and ask: "What is the responsibility of `MainHandler`? What data does it need? Where does that data come from (even if it's not shown in this snippet)?"  This helps ensure a high-level understanding. I also double-check that my code examples are concise and directly demonstrate the functionality in question.
这段Go语言代码是 `go tool trace` 工具中用于展示 trace 数据的 Web 界面的 HTTP 处理逻辑的一部分。它定义了处理主页面和详细 trace 页面的 HTTP 处理器，并包含了渲染这些页面的 HTML 模板。

**功能列表:**

1. **提供主页面 (MainHandler):**
   - 接收一个 `View` 类型的切片作为输入，这些 `View` 描述了不同的 trace 查看方式（例如，按处理器、按线程）。
   - 使用 `templMain` 模板渲染主 HTML 页面。
   - 在主页面上列出可用的 trace 视图链接，允许用户选择不同的视角查看 trace 数据。
   - 提供对 `runtime/trace` 包的简要介绍和使用说明。
   - 提供其他分析页面的链接，例如 goroutine 分析、性能 profile 以及用户定义的任务和区域。

2. **提供详细 Trace 页面 (TraceHandler):**
   - 处理对 `/trace` 路径的请求。
   - 解析请求中的表单参数（例如，`view`, `start`, `end`），用于指定要查看的 trace 数据的范围和类型。
   - 使用 `templTrace` 模板渲染详细的 trace 查看器页面。
   - `templTrace` 嵌入了 Chromium 的 Trace Event Profiling Tool，用于交互式地可视化 trace 数据。
   - 通过 JavaScript 从 `/jsontrace` 路径获取实际的 trace 数据。

3. **提供静态资源服务 (StaticHandler):**
   - 使用 `embed.FS` 嵌入的文件系统 `staticContent`，用于提供 trace 查看器所需的静态资源，例如 JavaScript 文件 (`webcomponents.min.js`) 和 HTML 文件 (`trace_viewer_full.html`)。

**推断的 Go 语言功能实现 (示例):**

这段代码是 `go tool trace` 工具的一部分，该工具用于分析 Go 程序运行时生成的 trace 数据。 `runtime/trace` 包允许 Go 程序在运行时记录各种事件，例如 goroutine 的创建和阻塞、系统调用、垃圾回收等。`go tool trace` 工具读取这些 trace 数据，并提供一个 Web 界面来可视化分析这些数据。

**Go 代码示例 (假设):**

假设 `go tool trace` 工具在处理 trace 文件时，根据 trace 数据生成了不同的视图信息，并传递给 `MainHandler`。

```go
package main

import (
	"fmt"
	"net/http"
	"internal/trace/traceviewer" // 假设这个包的路径
)

func main() {
	// 假设从 trace 文件中解析出的视图信息
	views := []traceviewer.View{
		{
			Type: traceviewer.ViewProc,
			Ranges: []traceviewer.Range{
				{Name: "0-1000", Start: 0, End: 1000, StartTime: 0, EndTime: 100},
				{Name: "1001-2000", Start: 1001, End: 2000, StartTime: 101, EndTime: 200},
			},
		},
		{
			Type: traceviewer.ViewThread,
		},
	}

	// 注册主页面处理器
	http.Handle("/", traceviewer.MainHandler(views))

	// 注册详细 trace 页面处理器
	http.Handle("/trace", traceviewer.TraceHandler())

	// 注册静态资源处理器
	http.Handle("/static/", http.StripPrefix("/static/", traceviewer.StaticHandler()))

	fmt.Println("启动服务器，访问 http://localhost:8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("服务器启动失败:", err)
	}
}
```

**假设的输入与输出:**

- **输入 (MainHandler):**
  ```go
  views := []traceviewer.View{
      {
          Type: traceviewer.ViewProc,
          Ranges: []traceviewer.Range{
              {Name: "0-1000", Start: 0, End: 1000, StartTime: 0, EndTime: 100},
              {Name: "1001-2000", Start: 1001, End: 2000, StartTime: 101, EndTime: 200},
          },
      },
      {
          Type: traceviewer.ViewThread,
      },
  }
  ```
- **输出 (MainHandler - 部分生成的 HTML):**
  ```html
  <html>
  <style> /* ... CommonStyle ... */ </style>
  <body>
  <h1>cmd/trace: the Go trace event viewer</h1>
  <p>...</p>

  <h2>Event timelines for running goroutines</h2>
  <p>
    Large traces are split into multiple sections of equal data size
    (not duration) to avoid overwhelming the visualizer.
  </p>
  <ul>
      <li><a href="/trace?view=proc&start=0&end=1000">View trace by proc (0-1000)</a></li>
      <li><a href="/trace?view=proc&start=1001&end=2000">View trace by proc (1001-2000)</a></li>
  </ul>
  <ul>
      <li><a href="/trace?view=thread">View trace by thread</a></li>
  </ul>
  <p>...</p>
  </body>
  </html>
  ```

- **输入 (TraceHandler - HTTP 请求):**
  `GET /trace?view=proc&start=0&end=1000 HTTP/1.1`
- **输出 (TraceHandler - 部分生成的 HTML):**
  ```html
  <html>
  <head>
  <script src="/static/webcomponents.min.js"></script>
  <script>
  'use strict';
  // ... JavaScript 代码 ...
  </script>
  <link rel="import" href="/static/trace_viewer_full.html"
        onerror="onTraceViewerImportFail(event)">
  <style type="text/css">
    html, body { /* ... */ }
    #trace-viewer { /* ... */ }
  </style>
  <script>
  'use strict';
  // ... JavaScript 代码，包含加载 /jsontrace?view=proc&start=0&end=1000 的逻辑 ...
  </script>
  </head>
  <body>
  </body>
  </html>
  ```

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。通常，`go tool trace` 工具会在命令行中接收 trace 文件路径作为参数。工具会解析该文件，生成 `View` 结构体的数据，然后将这些数据传递给 `MainHandler`。

例如，用户可能会这样运行 `go tool trace`:

```bash
go tool trace mytrace.out
```

`go tool trace` 工具会读取 `mytrace.out` 文件，解析 trace 数据，并启动一个本地 HTTP 服务器，然后打开浏览器显示主页面。

**使用者易犯错的点:**

1. **缺少或路径不正确的静态资源:** `templTrace` 依赖于 `/static/webcomponents.min.js` 和 `/static/trace_viewer_full.html`。如果这些文件不存在于正确的路径下（相对于 Web 服务器的根目录），或者 `embed.FS` 的配置不正确，会导致详细 trace 页面无法正常加载或显示。  用户可能会看到 JavaScript 错误或者页面显示不完整。

   **例如:** 如果 `static` 文件夹没有和编译后的 `go tool trace` 程序放在一起，或者 `embed` 的路径配置错误，就会出现这个问题。

2. **Trace 数据格式不正确:** 虽然这段代码没有直接处理 trace 数据的解析，但如果传递给 `go tool trace` 的 trace 文件格式不正确或损坏，可能会导致工具解析失败，从而影响 `View` 数据的生成，最终导致主页面显示不正确或者详细 trace 页面无法加载数据。

3. **浏览器兼容性问题:** `templTrace` 中嵌入的 Chromium Trace Event Profiling Tool 可能在某些旧版本的浏览器上显示不正常。虽然代码中没有直接处理浏览器兼容性，但用户可能会遇到显示问题。

总的来说，这段代码的核心功能是搭建一个 Web 服务器，用于可视化 Go 程序的 trace 数据。它通过 Go 的 `net/http` 包处理 HTTP 请求，并使用 `html/template` 包渲染 HTML 页面。详细的 trace 可视化依赖于嵌入的 Chromium Trace Event Profiling Tool 及其相关的静态资源。

### 提示词
```
这是路径为go/src/internal/trace/traceviewer/http.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package traceviewer

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

func MainHandler(views []View) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := templMain.Execute(w, views); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
}

const CommonStyle = `
/* See https://github.com/golang/pkgsite/blob/master/static/shared/typography/typography.css */
body {
  font-family:	-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji';
  font-size:	1rem;
  line-height:	normal;
  max-width:	9in;
  margin:	1em;
}
h1 { font-size: 1.5rem; }
h2 { font-size: 1.375rem; }
h1,h2 {
  font-weight: 600;
  line-height: 1.25em;
  word-break: break-word;
}
p  { color: grey85; font-size:85%; }
code,
pre,
textarea.code {
  font-family: SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 0.875rem;
  line-height: 1.5em;
}

pre,
textarea.code {
  background-color: var(--color-background-accented);
  border: var(--border);
  border-radius: var(--border-radius);
  color: var(--color-text);
  overflow-x: auto;
  padding: 0.625rem;
  tab-size: 4;
  white-space: pre;
}
`

var templMain = template.Must(template.New("").Parse(`
<html>
<style>` + CommonStyle + `</style>
<body>
<h1>cmd/trace: the Go trace event viewer</h1>
<p>
  This web server provides various visualizations of an event log gathered during
  the execution of a Go program that uses the <a href='https://pkg.go.dev/runtime/trace'>runtime/trace</a> package.
</p>

<h2>Event timelines for running goroutines</h2>
{{range $i, $view := $}}
{{if $view.Ranges}}
{{if eq $i 0}}
<p>
  Large traces are split into multiple sections of equal data size
  (not duration) to avoid overwhelming the visualizer.
</p>
{{end}}
<ul>
	{{range $index, $e := $view.Ranges}}
		<li><a href="{{$view.URL $index}}">View trace by {{$view.Type}} ({{$e.Name}})</a></li>
	{{end}}
</ul>
{{else}}
<ul>
	<li><a href="{{$view.URL -1}}">View trace by {{$view.Type}}</a></li>
</ul>
{{end}}
{{end}}
<p>
  This view displays a series of timelines for a type of resource.
  The "by proc" view consists of a timeline for each of the GOMAXPROCS
  logical processors, showing which goroutine (if any) was running on that
  logical processor at each moment.
  The "by thread" view (if available) consists of a similar timeline for each
  OS thread.

  Each goroutine has an identifying number (e.g. G123), main function,
  and color.

  A colored bar represents an uninterrupted span of execution.

  Execution of a goroutine may migrate from one logical processor to another,
  causing a single colored bar to be horizontally continuous but
  vertically displaced.
</p>
<p>
  Clicking on a span reveals information about it, such as its
  duration, its causal predecessors and successors, and the stack trace
  at the final moment when it yielded the logical processor, for example
  because it made a system call or tried to acquire a mutex.

  Directly underneath each bar, a smaller bar or more commonly a fine
  vertical line indicates an event occurring during its execution.
  Some of these are related to garbage collection; most indicate that
  a goroutine yielded its logical processor but then immediately resumed execution
  on the same logical processor. Clicking on the event displays the stack trace
  at the moment it occurred.
</p>
<p>
  The causal relationships between spans of goroutine execution
  can be displayed by clicking the Flow Events button at the top.
</p>
<p>
  At the top ("STATS"), there are three additional timelines that
  display statistical information.

  "Goroutines" is a time series of the count of existing goroutines;
  clicking on it displays their breakdown by state at that moment:
  running, runnable, or waiting.

  "Heap" is a time series of the amount of heap memory allocated (in orange)
  and (in green) the allocation limit at which the next GC cycle will begin.

  "Threads" shows the number of kernel threads in existence: there is
  always one kernel thread per logical processor, and additional threads
  are created for calls to non-Go code such as a system call or a
  function written in C.
</p>
<p>
  Above the event trace for the first logical processor are
  traces for various runtime-internal events.

  The "GC" bar shows when the garbage collector is running, and in which stage.
  Garbage collection may temporarily affect all the logical processors
  and the other metrics.

  The "Network", "Timers", and "Syscalls" traces indicate events in
  the runtime that cause goroutines to wake up.
</p>
<p>
  The visualization allows you to navigate events at scales ranging from several
  seconds to a handful of nanoseconds.

  Consult the documentation for the Chromium <a href='https://www.chromium.org/developers/how-tos/trace-event-profiling-tool/'>Trace Event Profiling Tool<a/>
  for help navigating the view.
</p>

<ul>
<li><a href="/goroutines">Goroutine analysis</a></li>
</ul>
<p>
  This view displays information about each set of goroutines that
  shares the same main function.

  Clicking on a main function shows links to the four types of
  blocking profile (see below) applied to that subset of goroutines.

  It also shows a table of specific goroutine instances, with various
  execution statistics and a link to the event timeline for each one.

  The timeline displays only the selected goroutine and any others it
  interacts with via block/unblock events. (The timeline is
  goroutine-oriented rather than logical processor-oriented.)
</p>

<h2>Profiles</h2>
<p>
  Each link below displays a global profile in zoomable graph form as
  produced by <a href='https://go.dev/blog/pprof'>pprof</a>'s "web" command.

  In addition there is a link to download the profile for offline
  analysis with pprof.

  All four profiles represent causes of delay that prevent a goroutine
  from running on a logical processor: because it was waiting for the network,
  for a synchronization operation on a mutex or channel, for a system call,
  or for a logical processor to become available.
</p>
<ul>
<li><a href="/io">Network blocking profile</a> (<a href="/io?raw=1" download="io.profile">⬇</a>)</li>
<li><a href="/block">Synchronization blocking profile</a> (<a href="/block?raw=1" download="block.profile">⬇</a>)</li>
<li><a href="/syscall">Syscall profile</a> (<a href="/syscall?raw=1" download="syscall.profile">⬇</a>)</li>
<li><a href="/sched">Scheduler latency profile</a> (<a href="/sched?raw=1" download="sched.profile">⬇</a>)</li>
</ul>

<h2>User-defined tasks and regions</h2>
<p>
  The trace API allows a target program to annotate a <a
  href='https://pkg.go.dev/runtime/trace#Region'>region</a> of code
  within a goroutine, such as a key function, so that its performance
  can be analyzed.

  <a href='https://pkg.go.dev/runtime/trace#Log'>Log events</a> may be
  associated with a region to record progress and relevant values.

  The API also allows annotation of higher-level
  <a href='https://pkg.go.dev/runtime/trace#Task'>tasks</a>,
  which may involve work across many goroutines.
</p>
<p>
  The links below display, for each region and task, a histogram of its execution times.

  Each histogram bucket contains a sample trace that records the
  sequence of events such as goroutine creations, log events, and
  subregion start/end times.

  For each task, you can click through to a logical-processor or
  goroutine-oriented view showing the tasks and regions on the
  timeline.

  Such information may help uncover which steps in a region are
  unexpectedly slow, or reveal relationships between the data values
  logged in a request and its running time.
</p>
<ul>
<li><a href="/usertasks">User-defined tasks</a></li>
<li><a href="/userregions">User-defined regions</a></li>
</ul>

<h2>Garbage collection metrics</h2>
<ul>
<li><a href="/mmu">Minimum mutator utilization</a></li>
</ul>
<p>
  This chart indicates the maximum GC pause time (the largest x value
  for which y is zero), and more generally, the fraction of time that
  the processors are available to application goroutines ("mutators"),
  for any time window of a specified size, in the worst case.
</p>
</body>
</html>
`))

type View struct {
	Type   ViewType
	Ranges []Range
}

type ViewType string

const (
	ViewProc   ViewType = "proc"
	ViewThread ViewType = "thread"
)

func (v View) URL(rangeIdx int) string {
	if rangeIdx < 0 {
		return fmt.Sprintf("/trace?view=%s", v.Type)
	}
	return v.Ranges[rangeIdx].URL(v.Type)
}

type Range struct {
	Name      string
	Start     int
	End       int
	StartTime int64
	EndTime   int64
}

func (r Range) URL(viewType ViewType) string {
	return fmt.Sprintf("/trace?view=%s&start=%d&end=%d", viewType, r.Start, r.End)
}

func TraceHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		html := strings.ReplaceAll(templTrace, "{{PARAMS}}", r.Form.Encode())
		w.Write([]byte(html))
	})
}

// https://chromium.googlesource.com/catapult/+/9508452e18f130c98499cb4c4f1e1efaedee8962/tracing/docs/embedding-trace-viewer.md
// This is almost verbatim copy of https://chromium-review.googlesource.com/c/catapult/+/2062938/2/tracing/bin/index.html
var templTrace = `
<html>
<head>
<script src="/static/webcomponents.min.js"></script>
<script>
'use strict';

function onTraceViewerImportFail() {
  document.addEventListener('DOMContentLoaded', function() {
    document.body.textContent =
    '/static/trace_viewer_full.html is missing. File a bug in https://golang.org/issue';
  });
}
</script>

<link rel="import" href="/static/trace_viewer_full.html"
      onerror="onTraceViewerImportFail(event)">

<style type="text/css">
  html, body {
    box-sizing: border-box;
    overflow: hidden;
    margin: 0px;
    padding: 0;
    width: 100%;
    height: 100%;
  }
  #trace-viewer {
    width: 100%;
    height: 100%;
  }
  #trace-viewer:focus {
    outline: none;
  }
</style>
<script>
'use strict';
(function() {
  var viewer;
  var url;
  var model;

  function load() {
    var req = new XMLHttpRequest();
    var isBinary = /[.]gz$/.test(url) || /[.]zip$/.test(url);
    req.overrideMimeType('text/plain; charset=x-user-defined');
    req.open('GET', url, true);
    if (isBinary)
      req.responseType = 'arraybuffer';

    req.onreadystatechange = function(event) {
      if (req.readyState !== 4)
        return;

      window.setTimeout(function() {
        if (req.status === 200)
          onResult(isBinary ? req.response : req.responseText);
        else
          onResultFail(req.status);
      }, 0);
    };
    req.send(null);
  }

  function onResultFail(err) {
    var overlay = new tr.ui.b.Overlay();
    overlay.textContent = err + ': ' + url + ' could not be loaded';
    overlay.title = 'Failed to fetch data';
    overlay.visible = true;
  }

  function onResult(result) {
    model = new tr.Model();
    var opts = new tr.importer.ImportOptions();
    opts.shiftWorldToZero = false;
    var i = new tr.importer.Import(model, opts);
    var p = i.importTracesWithProgressDialog([result]);
    p.then(onModelLoaded, onImportFail);
  }

  function onModelLoaded() {
    viewer.model = model;
    viewer.viewTitle = "trace";

    if (!model || model.bounds.isEmpty)
      return;
    var sel = window.location.hash.substr(1);
    if (sel === '')
      return;
    var parts = sel.split(':');
    var range = new (tr.b.Range || tr.b.math.Range)();
    range.addValue(parseFloat(parts[0]));
    range.addValue(parseFloat(parts[1]));
    viewer.trackView.viewport.interestRange.set(range);
  }

  function onImportFail(err) {
    var overlay = new tr.ui.b.Overlay();
    overlay.textContent = tr.b.normalizeException(err).message;
    overlay.title = 'Import error';
    overlay.visible = true;
  }

  document.addEventListener('WebComponentsReady', function() {
    var container = document.createElement('track-view-container');
    container.id = 'track_view_container';

    viewer = document.createElement('tr-ui-timeline-view');
    viewer.track_view_container = container;
    Polymer.dom(viewer).appendChild(container);

    viewer.id = 'trace-viewer';
    viewer.globalMode = true;
    Polymer.dom(document.body).appendChild(viewer);

    url = '/jsontrace?{{PARAMS}}';
    load();
  });
}());
</script>
</head>
<body>
</body>
</html>
`

//go:embed static/trace_viewer_full.html static/webcomponents.min.js
var staticContent embed.FS

func StaticHandler() http.Handler {
	return http.FileServer(http.FS(staticContent))
}
```