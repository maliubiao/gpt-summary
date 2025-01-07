Response: Let's break down the thought process for analyzing the Go code and fulfilling the request.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly read through the code, looking for keywords and structures that give hints about its functionality. I see:

* `package main`: Indicates this is an executable program, likely part of a larger tool.
* `import`:  Mentions packages like `net/http`, `html/template`, `internal/trace`, `internal/trace/traceviewer`, etc. These suggest it's involved in web serving and processing trace data.
* Function names like `UserRegionsHandlerFunc`, `fingerprintRegion`, `regionTopStackFrame`, `newRegionFilter`:  These clearly point to handling user-defined regions within a trace.
* Template usage (`template.Must(template.New("").Parse(...))`), especially the HTML content within the templates, strongly suggests generating web pages.
* Data structures like `regionFingerprint`, `regionStats`, and the use of `map` and `slices`:  Indicates data aggregation and manipulation.
* The presence of URL query parameters (`r.FormValue("type")`, `r.FormValue("pc")`, etc.) and URL construction (`fmt.Sprintf("/userregion?...")`):  Confirms web-based interaction and filtering.

**2. Focusing on the Core Functionality:**

The name `UserRegionsHandlerFunc` appears twice, suggesting there are two distinct handlers for dealing with user regions. The first one seems to *summarize* regions, while the second one presents *details* of selected regions.

**3. Analyzing `UserRegionsHandlerFunc` (Summary):**

* It iterates through goroutines and their regions (`t.summary.Goroutines`).
* It uses `fingerprintRegion` to group regions based on their type and starting stack frame.
* It aggregates statistics (`regionStats`) for each group, including a latency histogram.
* It sorts the regions.
* Crucially, it executes the `templUserRegionTypes` template to generate HTML.

**4. Analyzing `UserRegionsHandlerFunc` (Details):**

* It extracts filtering parameters from the request (`newRegionFilter`).
* It iterates through regions, applying the filter.
* It collects detailed information about each matching region, including non-overlapping statistics and range times.
* It sorts the regions based on user-specified criteria.
* It executes the `templUserRegionType` template to generate HTML, providing a more detailed view.

**5. Inferring the Go Tool's Purpose:**

Based on the imports and the functionality of the handlers, the most logical conclusion is that this code is part of a tool that *analyzes Go execution traces*. The "user regions" likely refer to custom instrumentation points added by developers in their Go code using something like `runtime/trace.WithRegion`.

**6. Constructing the Go Example:**

To demonstrate the "user region" functionality, I need to show how these regions are created in user code. The `runtime/trace` package is the obvious candidate. I'd think about:

* Importing `runtime/trace`.
* Using `trace.StartRegion` and `region.End()`.
* Providing a meaningful name for the region.
* Running the code and generating a trace (likely using the `-trace` flag when running the Go program).

**7. Analyzing Command-Line Arguments and Web Interaction:**

The code directly handles HTTP requests and parses URL parameters. There are no explicit command-line arguments handled *within this specific code snippet*. However, the context suggests that the larger `cmd/trace` tool likely has command-line arguments to specify the trace file to analyze. The web interface allows filtering by `type`, `pc`, `latmin`, and `latmax`.

**8. Identifying Potential User Errors:**

The key error point comes from misunderstanding how "user regions" are defined and how the trace is generated. Users might:

* Forget to import `runtime/trace`.
* Misspell the region name.
* Not generate a trace file when running their application.
* Misinterpret the latency histogram (as noted in the HTML comments).

**9. Structuring the Answer:**

Finally, organize the findings into the requested sections: functionality, Go example, inferred Go feature, command-line arguments (with the caveat), and common mistakes. Use clear and concise language, and provide illustrative code examples and input/output scenarios where applicable. Emphasize the web-based nature of the tool based on the HTTP handlers and template usage.
The code snippet you provided is a part of the `go tool trace` command, specifically the functionality related to analyzing **user-defined regions** within a Go execution trace.

Here's a breakdown of its functionality:

**1. Summarizing User Regions (`UserRegionsHandlerFunc`):**

* **Purpose:** This function handles an HTTP request to display a summary of all unique user-defined regions found in the provided Go execution trace.
* **Data Aggregation:** It iterates through all goroutines in the trace summary and collects information about the `Regions` associated with each goroutine.
* **Region Grouping:** It groups regions based on their "fingerprint," which consists of the region's `Type` (name) and the stack frame where the region started (`fingerprintRegion`). This helps identify logically similar regions even if they occur in different goroutines.
* **Statistics Calculation:** For each unique region fingerprint, it calculates statistics using the `regionStats` struct, which includes a latency histogram (`traceviewer.TimeHistogram`) of the region's duration.
* **Sorting:**  It sorts the summarized regions first by `Type` and then by the Program Counter (`PC`) of the starting stack frame. This ensures a consistent and organized presentation.
* **HTML Rendering:** It uses an HTML template (`templUserRegionTypes`) to display the summarized information in a table format. The table includes the region type, the count of occurrences, and a histogram visualizing the duration of completed instances of that region.

**2. Displaying Details of Selected Regions (`UserRegionHandlerFunc`):**

* **Purpose:** This function handles HTTP requests to display detailed information about specific user-defined regions, allowing users to drill down based on filters.
* **Filtering:** It parses URL query parameters to create a `regionFilter`. This filter allows users to select regions based on their type, the PC of their starting frame, and minimum/maximum latency.
* **Region Collection:** It iterates through all goroutines and their regions, applying the `regionFilter` to select only the matching regions. It also gathers non-overlapping statistics (e.g., execution time, time spent in GC) and range-specific times (e.g., time spent in GC assist) for each region.
* **Sorting:** It allows sorting the detailed region list based on different criteria (e.g., total time, non-overlapping stats) using the `sortby` query parameter. It defaults to sorting by total time.
* **HTML Rendering:** It uses another HTML template (`templUserRegionType`) to present the detailed information in a table. This table includes the goroutine ID, task ID (if any), total time spent in the region, and a breakdown of time spent in different non-overlapping states and special ranges.

**3. Helper Functions:**

* **`fingerprintRegion(r *trace.UserRegionSummary) regionFingerprint`:**  Creates a unique identifier for a region based on its type (name) and the top stack frame where it started.
* **`regionTopStackFrame(r *trace.UserRegionSummary) trace.StackFrame`:**  Extracts the top stack frame information from the region's start event.
* **`regionInterval(t *parsedTrace, s *trace.UserRegionSummary) interval`:**  Calculates the interval (start and end times) of a user region.
* **`newRegionFilter(r *http.Request) (*regionFilter, error)`:**  Parses the HTTP request parameters to create a filter for selecting specific regions.
* **`regionFilter.match(t *parsedTrace, s *trace.UserRegionSummary) bool`:**  Checks if a given region matches the filter criteria.

**Inferred Go Language Feature:**

This code implements the visualization and analysis of user-defined regions, which are a feature of the `runtime/trace` package in Go. This allows developers to instrument their code with custom regions to measure the performance and behavior of specific code sections.

**Go Code Example Illustrating User Regions:**

```go
package main

import (
	"fmt"
	"runtime/trace"
	"time"
)

func main() {
	f, err := trace.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	trace.Start(f)
	defer trace.Stop()

	// Start a user-defined region named "MyOperation"
	region := trace.StartRegion(nil, "MyOperation")
	time.Sleep(100 * time.Millisecond) // Simulate some work

	// Start a nested region
	nestedRegion := trace.StartRegion(nil, "SubTask")
	time.Sleep(50 * time.Millisecond)
	nestedRegion.End()

	region.End()

	// Another instance of the same region
	region2 := trace.StartRegion(nil, "MyOperation")
	time.Sleep(150 * time.Millisecond)
	region2.End()

	fmt.Println("Trace generated: trace.out")
}
```

**Assumptions and Input/Output for Code Reasoning:**

**Assumption:**  We have a trace file named `trace.out` generated by the example above.

**Input (for `UserRegionsHandlerFunc`):** An HTTP request to `/regions`.

**Output (for `UserRegionsHandlerFunc`):** An HTML page containing a table similar to this:

```html
<!DOCTYPE html>
<title>Regions</title>
<style>/* ... CSS styles ... */</style>
<body>
<h1>Regions</h1>

Below is a table containing a summary of all the user-defined regions in the trace.
Regions are grouped by the region type and the point at which the region started.
...
<table border="1" sortable="1">
<tr>
<th>Region type</th>
<th>Count</th>
<th>Duration distribution (complete tasks)</th>
</tr>
  <tr>
    <td><pre>"MyOperation"<br>main.main @ 0x...<br>/path/to/your/file.go:14</pre></td>
    <td><a href="/userregion?type=MyOperation&pc=...">2</a></td>
    <td><div class="histoTime">0s</div><div class="histoBar" style="width:50.00%;">&nbsp;</div><div class="histoTime">100ms</div><div class="histoBar" style="width:0.00%;">&nbsp;</div><div class="histoTime">200ms</div></td>
  </tr>
  <tr>
    <td><pre>"SubTask"<br>main.main @ 0x...<br>/path/to/your/file.go:19</pre></td>
    <td><a href="/userregion?type=SubTask&pc=...">1</a></td>
    <td><div class="histoTime">0s</div><div class="histoBar" style="width:100.00%;">&nbsp;</div><div class="histoTime">100ms</div></td>
  </tr>
</table>
</body>
</html>
```

**Input (for `UserRegionHandlerFunc`):** An HTTP request to `/userregion?type=MyOperation`.

**Output (for `UserRegionHandlerFunc`):** An HTML page containing a table detailing the instances of the "MyOperation" region:

```html
<!DOCTYPE html>
<title>Regions: "MyOperation"</title>
<style>/* ... CSS styles ... */</style>
<body>
<h1>Regions: "MyOperation"</h1>

Table of contents
<ul>
	<li><a href="#summary">Summary</a></li>
	<li><a href="#breakdown">Breakdown</a></li>
	<li><a href="#ranges">Special ranges</a></li>
</ul>

<h3 id="summary">Summary</h3>
...

<h3 id="breakdown">Breakdown</h3>

The table below breaks down where each goroutine is spent its time during the
traced period.
...

<table class="details">
<tr>
<th> Goroutine </th>
<th> Task </th>
<th class="link" onclick="reloadTable('sortby', 'Total time')"> Total</th>
<th></th>
</tr>
	<tr>
		<td> <a href="/trace?goid=1">1</a> </td>
		<td>  </td>
		<td> 100ms </td>
		<td>
			<div class="stacked-bar-graph">
				<span style="width: 100.00%; background-color: #8FBC8F;">&nbsp;</span>
			</div>
		</td>
	</tr>
	<tr>
		<td> <a href="/trace?goid=1">1</a> </td>
		<td>  </td>
		<td> 150ms </td>
		<td>
			<div class="stacked-bar-graph">
				<span style="width: 100.00%; background-color: #8FBC8F;">&nbsp;</span>
			</div>
		</td>
	</tr>
</table>

<h3 id="ranges">Special ranges</h3>
...
</body>
</html>
```

**Command-Line Argument Handling:**

This specific code snippet doesn't directly handle command-line arguments. However, the `go tool trace` command itself takes command-line arguments. The typical usage involves:

```bash
go tool trace trace.out
```

Where `trace.out` is the path to the Go execution trace file. The `go tool trace` then starts an HTTP server, and the handlers in this `regions.go` file are used to respond to requests at specific paths like `/regions` and `/userregion`.

The `UserRegionHandlerFunc` itself processes URL query parameters:

* **`/regions`**: No specific parameters for the summary view.
* **`/userregion`**:
    * `type`: Filters regions by their name (e.g., `?type=MyOperation`).
    * `pc`: Filters regions by the program counter of their starting frame (e.g., `?pc=4a80b0`).
    * `latmin`: Filters regions with a duration greater than or equal to the specified duration (e.g., `?latmin=100ms`).
    * `latmax`: Filters regions with a duration less than or equal to the specified duration (e.g., `?latmax=200ms`).
    * `sortby`: Specifies the field to sort the detailed region table by (e.g., `?sortby=Execution time`).

**User Mistakes:**

One potential mistake users might make is **forgetting to generate the trace file**. If they run their Go program without the `-trace` flag, there will be no `trace.out` file for `go tool trace` to analyze, and they won't see any user regions.

**Example of User Mistake:**

1. User runs their Go code: `go run main.go` (without `-trace`).
2. User then tries to analyze the trace: `go tool trace trace.out`.
3. The `go tool trace` will likely show no user-defined regions because the `trace.out` file doesn't contain the necessary information.

To fix this, the user needs to run their Go program like this:

```bash
go run main.go -trace=trace.out
```

This will generate the `trace.out` file that `go tool trace` can then process.

Prompt: 
```
这是路径为go/src/cmd/trace/regions.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"fmt"
	"html/template"
	"internal/trace"
	"internal/trace/traceviewer"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// UserRegionsHandlerFunc returns a HandlerFunc that reports all regions found in the trace.
func UserRegionsHandlerFunc(t *parsedTrace) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Summarize all the regions.
		summary := make(map[regionFingerprint]regionStats)
		for _, g := range t.summary.Goroutines {
			for _, r := range g.Regions {
				id := fingerprintRegion(r)
				stats, ok := summary[id]
				if !ok {
					stats.regionFingerprint = id
				}
				stats.add(t, r)
				summary[id] = stats
			}
		}
		// Sort regions by PC and name.
		userRegions := make([]regionStats, 0, len(summary))
		for _, stats := range summary {
			userRegions = append(userRegions, stats)
		}
		slices.SortFunc(userRegions, func(a, b regionStats) int {
			if c := cmp.Compare(a.Type, b.Type); c != 0 {
				return c
			}
			return cmp.Compare(a.Frame.PC, b.Frame.PC)
		})
		// Emit table.
		err := templUserRegionTypes.Execute(w, userRegions)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
			return
		}
	}
}

// regionFingerprint is a way to categorize regions that goes just one step beyond the region's Type
// by including the top stack frame.
type regionFingerprint struct {
	Frame trace.StackFrame
	Type  string
}

func fingerprintRegion(r *trace.UserRegionSummary) regionFingerprint {
	return regionFingerprint{
		Frame: regionTopStackFrame(r),
		Type:  r.Name,
	}
}

func regionTopStackFrame(r *trace.UserRegionSummary) trace.StackFrame {
	var frame trace.StackFrame
	if r.Start != nil && r.Start.Stack() != trace.NoStack {
		for f := range r.Start.Stack().Frames() {
			frame = f
		}
	}
	return frame
}

type regionStats struct {
	regionFingerprint
	Histogram traceviewer.TimeHistogram
}

func (s *regionStats) UserRegionURL() func(min, max time.Duration) string {
	return func(min, max time.Duration) string {
		return fmt.Sprintf("/userregion?type=%s&pc=%x&latmin=%v&latmax=%v", template.URLQueryEscaper(s.Type), s.Frame.PC, template.URLQueryEscaper(min), template.URLQueryEscaper(max))
	}
}

func (s *regionStats) add(t *parsedTrace, region *trace.UserRegionSummary) {
	s.Histogram.Add(regionInterval(t, region).duration())
}

var templUserRegionTypes = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<title>Regions</title>
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
<h1>Regions</h1>

Below is a table containing a summary of all the user-defined regions in the trace.
Regions are grouped by the region type and the point at which the region started.
The rightmost column of the table contains a latency histogram for each region group.
Note that this histogram only counts regions that began and ended within the traced
period.
However, the "Count" column includes all regions, including those that only started
or ended during the traced period.
Regions that were active through the trace period were not recorded, and so are not
accounted for at all.
Click on the links to explore a breakdown of time spent for each region by goroutine
and user-defined task.
<br>
<br>

<table border="1" sortable="1">
<tr>
<th>Region type</th>
<th>Count</th>
<th>Duration distribution (complete tasks)</th>
</tr>
{{range $}}
  <tr>
    <td><pre>{{printf "%q" .Type}}<br>{{.Frame.Func}} @ {{printf "0x%x" .Frame.PC}}<br>{{.Frame.File}}:{{.Frame.Line}}</pre></td>
    <td><a href="/userregion?type={{.Type}}&pc={{.Frame.PC | printf "%x"}}">{{.Histogram.Count}}</a></td>
    <td>{{.Histogram.ToHTML (.UserRegionURL)}}</td>
  </tr>
{{end}}
</table>
</body>
</html>
`))

// UserRegionHandlerFunc returns a HandlerFunc that presents the details of the selected regions.
func UserRegionHandlerFunc(t *parsedTrace) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Construct the filter from the request.
		filter, err := newRegionFilter(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Collect all the regions with their goroutines.
		type region struct {
			*trace.UserRegionSummary
			Goroutine           trace.GoID
			NonOverlappingStats map[string]time.Duration
			HasRangeTime        bool
		}
		var regions []region
		var maxTotal time.Duration
		validNonOverlappingStats := make(map[string]struct{})
		validRangeStats := make(map[string]struct{})
		for _, g := range t.summary.Goroutines {
			for _, r := range g.Regions {
				if !filter.match(t, r) {
					continue
				}
				nonOverlappingStats := r.NonOverlappingStats()
				for name := range nonOverlappingStats {
					validNonOverlappingStats[name] = struct{}{}
				}
				var totalRangeTime time.Duration
				for name, dt := range r.RangeTime {
					validRangeStats[name] = struct{}{}
					totalRangeTime += dt
				}
				regions = append(regions, region{
					UserRegionSummary:   r,
					Goroutine:           g.ID,
					NonOverlappingStats: nonOverlappingStats,
					HasRangeTime:        totalRangeTime != 0,
				})
				if maxTotal < r.TotalTime {
					maxTotal = r.TotalTime
				}
			}
		}

		// Sort.
		sortBy := r.FormValue("sortby")
		if _, ok := validNonOverlappingStats[sortBy]; ok {
			slices.SortFunc(regions, func(a, b region) int {
				return cmp.Compare(b.NonOverlappingStats[sortBy], a.NonOverlappingStats[sortBy])
			})
		} else {
			// Sort by total time by default.
			slices.SortFunc(regions, func(a, b region) int {
				return cmp.Compare(b.TotalTime, a.TotalTime)
			})
		}

		// Write down all the non-overlapping stats and sort them.
		allNonOverlappingStats := make([]string, 0, len(validNonOverlappingStats))
		for name := range validNonOverlappingStats {
			allNonOverlappingStats = append(allNonOverlappingStats, name)
		}
		slices.SortFunc(allNonOverlappingStats, func(a, b string) int {
			if a == b {
				return 0
			}
			if a == "Execution time" {
				return -1
			}
			if b == "Execution time" {
				return 1
			}
			return cmp.Compare(a, b)
		})

		// Write down all the range stats and sort them.
		allRangeStats := make([]string, 0, len(validRangeStats))
		for name := range validRangeStats {
			allRangeStats = append(allRangeStats, name)
		}
		sort.Strings(allRangeStats)

		err = templUserRegionType.Execute(w, struct {
			MaxTotal            time.Duration
			Regions             []region
			Name                string
			Filter              *regionFilter
			NonOverlappingStats []string
			RangeStats          []string
		}{
			MaxTotal:            maxTotal,
			Regions:             regions,
			Name:                filter.name,
			Filter:              filter,
			NonOverlappingStats: allNonOverlappingStats,
			RangeStats:          allRangeStats,
		})
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
			return
		}
	}
}

var templUserRegionType = template.Must(template.New("").Funcs(template.FuncMap{
	"headerStyle": func(statName string) template.HTMLAttr {
		return template.HTMLAttr(fmt.Sprintf("style=\"background-color: %s;\"", stat2Color(statName)))
	},
	"barStyle": func(statName string, dividend, divisor time.Duration) template.HTMLAttr {
		width := "0"
		if divisor != 0 {
			width = fmt.Sprintf("%.2f%%", float64(dividend)/float64(divisor)*100)
		}
		return template.HTMLAttr(fmt.Sprintf("style=\"width: %s; background-color: %s;\"", width, stat2Color(statName)))
	},
	"filterParams": func(f *regionFilter) template.URL {
		return template.URL(f.params.Encode())
	},
}).Parse(`
<!DOCTYPE html>
<title>Regions: {{.Name}}</title>
<style>` + traceviewer.CommonStyle + `
th {
  background-color: #050505;
  color: #fff;
}
th.link {
  cursor: pointer;
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
.details tr:hover {
  background-color: #f2f2f2;
}
.details td {
  text-align: right;
  border: 1px solid #000;
}
.details td.id {
  text-align: left;
}
.stacked-bar-graph {
  width: 300px;
  height: 10px;
  color: #414042;
  white-space: nowrap;
  font-size: 5px;
}
.stacked-bar-graph span {
  display: inline-block;
  width: 100%;
  height: 100%;
  box-sizing: border-box;
  float: left;
  padding: 0;
}
</style>

<script>
function reloadTable(key, value) {
  let params = new URLSearchParams(window.location.search);
  params.set(key, value);
  window.location.search = params.toString();
}
</script>

<h1>Regions: {{.Name}}</h1>

Table of contents
<ul>
	<li><a href="#summary">Summary</a></li>
	<li><a href="#breakdown">Breakdown</a></li>
	<li><a href="#ranges">Special ranges</a></li>
</ul>

<h3 id="summary">Summary</h3>

{{ with $p := filterParams .Filter}}
<table class="summary">
	<tr>
		<td>Network wait profile:</td>
		<td> <a href="/regionio?{{$p}}">graph</a> <a href="/regionio?{{$p}}&raw=1" download="io.profile">(download)</a></td>
	</tr>
	<tr>
		<td>Sync block profile:</td>
		<td> <a href="/regionblock?{{$p}}">graph</a> <a href="/regionblock?{{$p}}&raw=1" download="block.profile">(download)</a></td>
	</tr>
	<tr>
		<td>Syscall profile:</td>
		<td> <a href="/regionsyscall?{{$p}}">graph</a> <a href="/regionsyscall?{{$p}}&raw=1" download="syscall.profile">(download)</a></td>
	</tr>
	<tr>
		<td>Scheduler wait profile:</td>
		<td> <a href="/regionsched?{{$p}}">graph</a> <a href="/regionsched?{{$p}}&raw=1" download="sched.profile">(download)</a></td>
	</tr>
</table>
{{ end }}

<h3 id="breakdown">Breakdown</h3>

The table below breaks down where each goroutine is spent its time during the
traced period.
All of the columns except total time are non-overlapping.
<br>
<br>

<table class="details">
<tr>
<th> Goroutine </th>
<th> Task </th>
<th class="link" onclick="reloadTable('sortby', 'Total time')"> Total</th>
<th></th>
{{range $.NonOverlappingStats}}
<th class="link" onclick="reloadTable('sortby', '{{.}}')" {{headerStyle .}}> {{.}}</th>
{{end}}
</tr>
{{range .Regions}}
	<tr>
		<td> <a href="/trace?goid={{.Goroutine}}">{{.Goroutine}}</a> </td>
		<td> {{if .TaskID}}<a href="/trace?focustask={{.TaskID}}">{{.TaskID}}</a>{{end}} </td>
		<td> {{ .TotalTime.String }} </td>
		<td>
			<div class="stacked-bar-graph">
			{{$Region := .}}
			{{range $.NonOverlappingStats}}
				{{$Time := index $Region.NonOverlappingStats .}}
				{{if $Time}}
					<span {{barStyle . $Time $.MaxTotal}}>&nbsp;</span>
				{{end}}
			{{end}}
			</div>
		</td>
		{{$Region := .}}
		{{range $.NonOverlappingStats}}
			{{$Time := index $Region.NonOverlappingStats .}}
			<td> {{$Time.String}}</td>
		{{end}}
	</tr>
{{end}}
</table>

<h3 id="ranges">Special ranges</h3>

The table below describes how much of the traced period each goroutine spent in
certain special time ranges.
If a goroutine has spent no time in any special time ranges, it is excluded from
the table.
For example, how much time it spent helping the GC. Note that these times do
overlap with the times from the first table.
In general the goroutine may not be executing in these special time ranges.
For example, it may have blocked while trying to help the GC.
This must be taken into account when interpreting the data.
<br>
<br>

<table class="details">
<tr>
<th> Goroutine</th>
<th> Task </th>
<th> Total</th>
{{range $.RangeStats}}
<th {{headerStyle .}}> {{.}}</th>
{{end}}
</tr>
{{range .Regions}}
	{{if .HasRangeTime}}
		<tr>
			<td> <a href="/trace?goid={{.Goroutine}}">{{.Goroutine}}</a> </td>
			<td> {{if .TaskID}}<a href="/trace?focustask={{.TaskID}}">{{.TaskID}}</a>{{end}} </td>
			<td> {{ .TotalTime.String }} </td>
			{{$Region := .}}
			{{range $.RangeStats}}
				{{$Time := index $Region.RangeTime .}}
				<td> {{$Time.String}}</td>
			{{end}}
		</tr>
	{{end}}
{{end}}
</table>
`))

// regionFilter represents a region filter specified by a user of cmd/trace.
type regionFilter struct {
	name   string
	params url.Values
	cond   []func(*parsedTrace, *trace.UserRegionSummary) bool
}

// match returns true if a region, described by its ID and summary, matches
// the filter.
func (f *regionFilter) match(t *parsedTrace, s *trace.UserRegionSummary) bool {
	for _, c := range f.cond {
		if !c(t, s) {
			return false
		}
	}
	return true
}

// newRegionFilter creates a new region filter from URL query variables.
func newRegionFilter(r *http.Request) (*regionFilter, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	var name []string
	var conditions []func(*parsedTrace, *trace.UserRegionSummary) bool
	filterParams := make(url.Values)

	param := r.Form
	if typ, ok := param["type"]; ok && len(typ) > 0 {
		name = append(name, fmt.Sprintf("%q", typ[0]))
		conditions = append(conditions, func(_ *parsedTrace, r *trace.UserRegionSummary) bool {
			return r.Name == typ[0]
		})
		filterParams.Add("type", typ[0])
	}
	if pc, err := strconv.ParseUint(r.FormValue("pc"), 16, 64); err == nil {
		encPC := fmt.Sprintf("0x%x", pc)
		name = append(name, "@ "+encPC)
		conditions = append(conditions, func(_ *parsedTrace, r *trace.UserRegionSummary) bool {
			return regionTopStackFrame(r).PC == pc
		})
		filterParams.Add("pc", encPC)
	}

	if lat, err := time.ParseDuration(r.FormValue("latmin")); err == nil {
		name = append(name, fmt.Sprintf("(latency >= %s)", lat))
		conditions = append(conditions, func(t *parsedTrace, r *trace.UserRegionSummary) bool {
			return regionInterval(t, r).duration() >= lat
		})
		filterParams.Add("latmin", lat.String())
	}
	if lat, err := time.ParseDuration(r.FormValue("latmax")); err == nil {
		name = append(name, fmt.Sprintf("(latency <= %s)", lat))
		conditions = append(conditions, func(t *parsedTrace, r *trace.UserRegionSummary) bool {
			return regionInterval(t, r).duration() <= lat
		})
		filterParams.Add("latmax", lat.String())
	}

	return &regionFilter{
		name:   strings.Join(name, " "),
		cond:   conditions,
		params: filterParams,
	}, nil
}

func regionInterval(t *parsedTrace, s *trace.UserRegionSummary) interval {
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

"""



```