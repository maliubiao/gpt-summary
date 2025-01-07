Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Big Picture:**

The comments at the top clearly state this code is for "Minimum mutator utilization (MMU) graphing."  This immediately tells us it's about visualizing how much the application's "mutator" (the part of the Go runtime that executes user code) is able to run without being interrupted by the garbage collector (GC). The "minimum" part suggests it's looking at the *worst* case over some time window.

**2. Identifying Key Components and Structures:**

I start by scanning the code for type definitions and global variables. This helps identify the core data and operations.

*   `MutatorUtilFunc`: This is a function type, suggesting a pluggable way to get mutator utilization data.
*   `MMUHandlerFunc`:  The name strongly hints at this being an HTTP handler function. It takes `ranges` and `MutatorUtilFunc` as input, suggesting it's tied to specific time ranges in the trace data.
*   `utilFlagNames`:  A map associating string names with `trace.UtilFlags`. This looks like a way to filter or categorize the utilization data.
*   `requestUtilFlags`: A function that extracts these flags from an HTTP request.
*   `mmuCacheEntry`:  This likely holds cached results of calculations, improving performance. The `sync.Once` confirms this.
*   `mmu`: The main struct, containing the cache, the utilization function, and the time ranges.
*   `linkedUtilWindow`: A struct for linking utilization data to specific points in the trace viewer.

**3. Tracing the HTTP Request Flow:**

The `MMUHandlerFunc` is the entry point for HTTP requests. The `switch r.FormValue("mode")` block is crucial:

*   `"plot"`: Calls `mmu.HandlePlot`. This suggests generating the main MMU graph data.
*   `"details"`: Calls `mmu.HandleDetails`. Likely for fetching details about a specific point on the graph.
*   Default: Serves the `templMMU`, which looks like the HTML for the MMU viewer.

**4. Analyzing `HandlePlot`:**

This function is responsible for generating the data for the main MMU plot. I focus on the key steps:

*   `m.get(requestUtilFlags(r))`: Fetches the mutator utilization data, potentially from the cache.
*   Quantile Calculation: The code checks for the "mut" flag and calculates quantiles. This indicates the ability to show percentile-based MMU.
*   Window Size Calculation (`xMin`, `xMax`): It dynamically determines a suitable range of window sizes for the x-axis of the plot. It starts small and increases, but is limited by the trace duration.
*   MMU Curve Calculation: The `for` loop iterates through different window sizes and calculates the MMU (or MUD for quantiles) using `mmuCurve.MMU` and `mmuCurve.MUD`.
*   JSON Encoding: The result is encoded as JSON for the frontend.

**5. Analyzing `HandleDetails`:**

This function provides details for a selected point on the graph.

*   `m.get(requestUtilFlags(r))`: Again, fetches utilization data.
*   Window Parameter Parsing:  It extracts the `window` parameter from the request.
*   `mmuCurve.Examples`: This is the key part. It uses the provided window size to find the *worst* (lowest utilization) windows.
*   Linking to Trace: The `m.newLinkedUtilWindow` function creates links back to specific locations in the trace viewer.
*   JSON Encoding:  The details are sent as JSON.

**6. Examining `templMMU` (The HTML):**

This provides crucial context about the user interface. I look for:

*   JavaScript libraries: Google Charts and jQuery are used for rendering the plot and handling AJAX requests.
*   AJAX calls: The JavaScript makes requests to `?mode=plot` and `?mode=details`.
*   User interface elements: Checkboxes for selecting flags (`stw`, `background`, `assist`, `sweep`), radio buttons for "System" vs. "Per-goroutine" view.
*   Tooltips: The `<span class="help">` elements provide helpful explanations for the different options.

**7. Inferring Go Functionality:**

Based on the code and the overall purpose, I can infer this implements part of a **Go trace analysis tool**. It specifically focuses on visualizing the impact of the GC on application performance by showing how often the mutator is blocked.

**8. Developing the Example:**

The example needs to demonstrate how this code integrates into a larger tracing system. I consider:

*   How the `MutatorUtilFunc` would be implemented (using `trace.Parse`).
*   How the ranges are determined (likely based on the trace file).
*   How the HTTP handler is registered (using `http.HandleFunc`).
*   A simple trace file example to feed into the system.

**9. Identifying Potential User Errors:**

This involves thinking about how a user might interact with the UI and what could go wrong:

*   Misinterpreting the flags (the tooltips help mitigate this).
*   Not understanding the difference between "System" and "Per-goroutine" views.
*   Being confused by the logarithmic scale of the x-axis.
*   Assuming the "Sweep" option is always fast (the comment warns about this).

**10. Structuring the Answer:**

Finally, I organize the information into clear sections: Functionality, Go Feature Implementation, Code Example, Command-line Arguments (none apparent in this snippet), and Potential User Errors. I use clear and concise language, explaining technical terms as needed. The use of bolding and bullet points helps with readability.
这段代码是 Go 语言 traceviewer 工具的一部分，专门用于**展示和分析 Minimum Mutator Utilization (MMU)**，即最小化器利用率。  它通过图形化的方式，帮助开发者理解垃圾回收 (GC) 对程序性能的影响。

以下是其主要功能点的详细说明：

**1. MMU 数据获取和缓存:**

*   `MutatorUtilFunc` 是一个函数类型，代表获取 MMU 数据的函数。这个函数接收 `trace.UtilFlags` 作为参数，返回 `[][]trace.MutatorUtil`（多组 MutatorUtil 数据）和一个 error。
*   `mmu` 结构体维护了一个缓存 `cache`，用于存储不同 `trace.UtilFlags` 下计算得到的 MMU 数据，避免重复计算，提高性能。
*   `mmu.get()` 方法负责从缓存中获取数据，如果缓存中没有，则调用 `MutatorUtilFunc` 计算并存入缓存。使用了 `sync.Once` 保证数据只被计算一次。

**2. HTTP Handler 处理:**

*   `MMUHandlerFunc` 是一个 HTTP 处理函数，接收一个 `Range` 切片和一个 `MutatorUtilFunc` 作为参数。 `Range` 可能是指 trace 数据的时间范围划分。
*   该 handler 根据 `r.FormValue("mode")` 参数的不同，执行不同的操作：
    *   `mode="plot"`: 调用 `mmu.HandlePlot` 生成 MMU 图表的 JSON 数据。
    *   `mode="details"`: 调用 `mmu.HandleDetails` 生成特定窗口下 MMU 详细信息的 JSON 数据。
    *   默认情况：返回包含 MMU 图表界面的 HTML 模板 (`templMMU`)。

**3. MMU 图表数据生成 (`HandlePlot`):**

*   根据 HTTP 请求中的 `flags` 参数 (`r.FormValue("flags")`)，使用 `requestUtilFlags` 函数解析出需要计算的 `trace.UtilFlags`。这些 flags 可以控制包含哪些类型的 GC 活动 (例如 STW, Background, Assist, Sweep)。
*   调用 `m.get()` 获取对应的 MMU 数据。
*   如果请求中包含 `flags="mut"`，则计算 MMU 的分位数 (quantiles)，例如 99.9%, 99%, 95% 的最小值。
*   动态计算图表的 X 轴范围 (窗口大小)，从一个较小的值开始，逐步增大，直到覆盖 trace 的整个时间范围。
*   循环遍历不同的窗口大小，调用 `mmuCurve.MMU()` (或 `mmuCurve.MUD()` 对于分位数) 计算在该窗口大小下的最小 Mutator Utilization。
*   将计算结果 (窗口大小和对应的 MMU 值) 组织成二维切片 `plot`。
*   将图表数据 (包括 X 轴范围和 `plot` 数据) 编码成 JSON 响应发送给客户端。

**4. MMU 详细信息生成 (`HandleDetails`):**

*   根据 HTTP 请求中的 `flags` 参数解析出 `trace.UtilFlags`。
*   调用 `m.get()` 获取对应的 MMU 数据。
*   从请求中解析出 `window` 参数，表示要查看的窗口大小。
*   调用 `mmuCurve.Examples(time.Duration(window), 10)` 获取在该窗口大小下，Mutator Utilization 最低的 10 个时间窗口的详细信息。
*   将这些详细信息 (包括时间、MutatorUtil 值以及指向 trace 具体位置的 URL) 编码成 JSON 响应发送给客户端。

**5. 客户端 HTML 模板 (`templMMU`):**

*   使用了 Google Charts 库来渲染 MMU 图表。
*   使用 jQuery 发送 AJAX 请求获取图表数据和详细信息。
*   提供了用户界面元素 (复选框和单选框) 来选择要包含的 GC 活动类型和视图模式 (System 或 Per-goroutine)。
*   定义了 JavaScript 函数 `refreshChart` 和 `drawChart` 来获取和渲染图表。
*   定义了 `selectHandler` 函数，当用户在图表上选择一个点时，发送请求获取详细信息并显示。

**推理其实现的 Go 语言功能:**

基于以上分析，可以推断出这段代码是 Go 语言 trace 包提供的 **trace viewer** 的一部分，用于可视化 Go 程序的运行时 trace 数据。  它专注于 **垃圾回收的性能分析**，特别是通过 MMU 图表来展示 GC 如何影响程序执行用户代码的能力。

**Go 代码举例说明:**

假设我们有一个名为 `main.go` 的 Go 程序，我们想分析其 MMU。

```go
// main.go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	// 启用 trace
	// f, err := os.Create("trace.out")
	// if err != nil {
	// 	panic(err)
	// }
	// defer f.Close()
	// if err := trace.Start(f); err != nil {
	// 	panic(err)
	// }
	// defer trace.Stop()

	// 模拟一些工作负载
	for i := 0; i < 100000; i++ {
		_ = make([]byte, 1024)
	}
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 50000; i++ {
		_ = make([]byte, 2048)
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC() // 手动触发 GC
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 200000; i++ {
		_ = make([]byte, 512)
	}
}
```

要分析这个程序的 MMU，通常需要先生成 trace 文件，然后使用 `go tool trace` 命令打开 trace viewer。

**假设的输入与输出 (基于 `HandlePlot`):**

**假设输入 (HTTP 请求):**

```
GET /mmu?mode=plot&flags=stw|background
```

*   `mode=plot`:  请求生成 MMU 图表数据。
*   `flags=stw|background`:  要求计算包含 STW (Stop-The-World) 和 Background GC 活动的 MMU。

**假设 `MutatorUtilFunc` 的输出 (简化):**

假设 `MutatorUtilFunc`  （对应代码中的 `f` 字段）根据 `trace.UtilSTW | trace.UtilBackground` 计算出的 MMU 数据如下 (每条数据代表一个时间点的 Mutator Utilization)：

```
[][]trace.MutatorUtil{
    {
        {Time: 1 * time.Second, MutatorUtil: 0.95},
        {Time: 1.1 * time.Second, MutatorUtil: 0.80}, // 受到 Background GC 的影响
        {Time: 1.2 * time.Second, MutatorUtil: 0.98},
    },
    {
        {Time: 2 * time.Second, MutatorUtil: 0.60}, // 受到 STW 的影响
        {Time: 2.05 * time.Second, MutatorUtil: 0.60},
        {Time: 2.1 * time.Second, MutatorUtil: 0.99},
    },
}
```

**假设输出 (JSON 响应):**

```json
{
  "xMin": 1000000,
  "xMax": 2000000000,
  "quantiles": null,
  "curve": [
    [1000000, 0.60], // 窗口大小 1ms，最小 MutatorUtil
    [10000000, 0.60], // 窗口大小 10ms，最小 MutatorUtil
    [100000000, 0.80], // 窗口大小 100ms，最小 MutatorUtil
    // ... 更多数据点
  ]
}
```

*   `xMin`:  图表 X 轴的最小值 (1ms)。
*   `xMax`:  图表 X 轴的最大值 (2s，假设 trace 总时长为 2s)。
*   `quantiles`: `null`，因为请求中没有 `flags=mut`。
*   `curve`:  MMU 曲线数据，每个元素是一个数组 `[窗口大小 (纳秒), 最小 MutatorUtil]`。

**假设的输入与输出 (基于 `HandleDetails`):**

**假设输入 (HTTP 请求):**

```
GET /mmu?mode=details&window=10000000&flags=stw|background
```

*   `mode=details`: 请求获取详细信息。
*   `window=10000000`:  指定窗口大小为 10ms (10,000,000 纳秒)。
*   `flags=stw|background`:  与图表请求的 flags 相同。

**假设 `mmuCurve.Examples` 的输出 (简化):**

假设在 10ms 的窗口下，`mmuCurve.Examples` 返回了以下 Mutator Utilization 最低的两个窗口：

```
[]trace.UtilWindow{
    {Time: 2000000000, MutatorUtil: 0.60}, // 时间 2 秒
    {Time: 1050000000, MutatorUtil: 0.80}, // 时间 1.05 秒
}
```

**假设输出 (JSON 响应):**

```json
[
  {
    "Time": 2000000000,
    "End": 2010000000,
    "MutatorUtil": 0.60,
    "URL": "/trace#2000.000:2010.000"
  },
  {
    "Time": 1050000000,
    "End": 1060000000,
    "MutatorUtil": 0.80,
    "URL": "/trace#1050.000:1060.000"
  }
]
```

*   包含了 Mutator Utilization 最低的两个窗口的 `Time`、`End` 时间戳和 `MutatorUtil` 值。
*   `URL` 提供了指向 trace viewer 中对应时间段的链接。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个 HTTP handler，用于响应来自 trace viewer 前端的请求。  trace viewer 的主程序 (通常在 `go/src/cmd/trace/`) 负责处理命令行参数，例如指定 trace 文件路径等。

**使用者易犯错的点:**

*   **不理解 "System" 和 "Per-goroutine" 视图的区别:**  用户可能会混淆这两种视图的含义，导致对 MMU 的解读出现偏差。
    *   **System:**  考虑整个系统的 Mutator 利用率。如果在一个四核 CPU 上，只有一个核在运行用户代码，其他核在进行 GC，则 Mutator 利用率会低于 1。
    *   **Per-goroutine:**  只要有一个 goroutine 被 GC 中断，Mutator 利用率就为 0。这种视图更强调单个 goroutine 的中断情况。
*   **不理解各个 GC 活动类型 (STW, Background, Assist, Sweep) 的含义:** 用户可能不清楚勾选不同的 "Include" 选项会对 MMU 图表产生什么影响，从而难以根据图表进行有效的性能分析。 例如，忽略 "STW" 可能无法识别由 Stop-The-World 引起的性能下降。
*   **误解 MMU 图表的含义:** 用户可能认为 MMU 值越高越好，但实际上，MMU 图表主要是帮助理解 GC 对程序执行的影响。一个完全没有 GC 的程序可能 MMU 接近 1，但这通常不是实际情况。 关键是要理解在不同的时间窗口下，Mutator 的利用率是多少。
*   **忽略 "Sweep" 选项的性能影响:**  代码中注释提到 "Enabling this may be very slow."，用户可能没有注意到这一点，导致在分析大型 trace 文件时加载时间过长。

总而言之，这段代码是 Go trace viewer 中用于可视化 MMU 的核心组件，通过 HTTP 接口提供数据给前端，帮助开发者深入理解 Go 程序的垃圾回收行为以及对程序性能的影响。

Prompt: 
```
这是路径为go/src/internal/trace/traceviewer/mmu.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Minimum mutator utilization (MMU) graphing.

// TODO:
//
// In worst window list, show break-down of GC utilization sources
// (STW, assist, etc). Probably requires a different MutatorUtil
// representation.
//
// When a window size is selected, show a second plot of the mutator
// utilization distribution for that window size.
//
// Render plot progressively so rough outline is visible quickly even
// for very complex MUTs. Start by computing just a few window sizes
// and then add more window sizes.
//
// Consider using sampling to compute an approximate MUT. This would
// work by sampling the mutator utilization at randomly selected
// points in time in the trace to build an empirical distribution. We
// could potentially put confidence intervals on these estimates and
// render this progressively as we refine the distributions.

package traceviewer

import (
	"encoding/json"
	"fmt"
	"internal/trace"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MutatorUtilFunc func(trace.UtilFlags) ([][]trace.MutatorUtil, error)

func MMUHandlerFunc(ranges []Range, f MutatorUtilFunc) http.HandlerFunc {
	mmu := &mmu{
		cache:  make(map[trace.UtilFlags]*mmuCacheEntry),
		f:      f,
		ranges: ranges,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.FormValue("mode") {
		case "plot":
			mmu.HandlePlot(w, r)
			return
		case "details":
			mmu.HandleDetails(w, r)
			return
		}
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader(templMMU))
	}
}

var utilFlagNames = map[string]trace.UtilFlags{
	"perProc":    trace.UtilPerProc,
	"stw":        trace.UtilSTW,
	"background": trace.UtilBackground,
	"assist":     trace.UtilAssist,
	"sweep":      trace.UtilSweep,
}

func requestUtilFlags(r *http.Request) trace.UtilFlags {
	var flags trace.UtilFlags
	for _, flagStr := range strings.Split(r.FormValue("flags"), "|") {
		flags |= utilFlagNames[flagStr]
	}
	return flags
}

type mmuCacheEntry struct {
	init     sync.Once
	util     [][]trace.MutatorUtil
	mmuCurve *trace.MMUCurve
	err      error
}

type mmu struct {
	mu     sync.Mutex
	cache  map[trace.UtilFlags]*mmuCacheEntry
	f      MutatorUtilFunc
	ranges []Range
}

func (m *mmu) get(flags trace.UtilFlags) ([][]trace.MutatorUtil, *trace.MMUCurve, error) {
	m.mu.Lock()
	entry := m.cache[flags]
	if entry == nil {
		entry = new(mmuCacheEntry)
		m.cache[flags] = entry
	}
	m.mu.Unlock()

	entry.init.Do(func() {
		util, err := m.f(flags)
		if err != nil {
			entry.err = err
		} else {
			entry.util = util
			entry.mmuCurve = trace.NewMMUCurve(util)
		}
	})
	return entry.util, entry.mmuCurve, entry.err
}

// HandlePlot serves the JSON data for the MMU plot.
func (m *mmu) HandlePlot(w http.ResponseWriter, r *http.Request) {
	mu, mmuCurve, err := m.get(requestUtilFlags(r))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to produce MMU data: %v", err), http.StatusInternalServerError)
		return
	}

	var quantiles []float64
	for _, flagStr := range strings.Split(r.FormValue("flags"), "|") {
		if flagStr == "mut" {
			quantiles = []float64{0, 1 - .999, 1 - .99, 1 - .95}
			break
		}
	}

	// Find a nice starting point for the plot.
	xMin := time.Second
	for xMin > 1 {
		if mmu := mmuCurve.MMU(xMin); mmu < 0.0001 {
			break
		}
		xMin /= 1000
	}
	// Cover six orders of magnitude.
	xMax := xMin * 1e6
	// But no more than the length of the trace.
	minEvent, maxEvent := mu[0][0].Time, mu[0][len(mu[0])-1].Time
	for _, mu1 := range mu[1:] {
		if mu1[0].Time < minEvent {
			minEvent = mu1[0].Time
		}
		if mu1[len(mu1)-1].Time > maxEvent {
			maxEvent = mu1[len(mu1)-1].Time
		}
	}
	if maxMax := time.Duration(maxEvent - minEvent); xMax > maxMax {
		xMax = maxMax
	}
	// Compute MMU curve.
	logMin, logMax := math.Log(float64(xMin)), math.Log(float64(xMax))
	const samples = 100
	plot := make([][]float64, samples)
	for i := 0; i < samples; i++ {
		window := time.Duration(math.Exp(float64(i)/(samples-1)*(logMax-logMin) + logMin))
		if quantiles == nil {
			plot[i] = make([]float64, 2)
			plot[i][1] = mmuCurve.MMU(window)
		} else {
			plot[i] = make([]float64, 1+len(quantiles))
			copy(plot[i][1:], mmuCurve.MUD(window, quantiles))
		}
		plot[i][0] = float64(window)
	}

	// Create JSON response.
	err = json.NewEncoder(w).Encode(map[string]any{"xMin": int64(xMin), "xMax": int64(xMax), "quantiles": quantiles, "curve": plot})
	if err != nil {
		log.Printf("failed to serialize response: %v", err)
		return
	}
}

var templMMU = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
    <script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
    <script type="text/javascript">
      google.charts.load('current', {'packages':['corechart']});
      var chartsReady = false;
      google.charts.setOnLoadCallback(function() { chartsReady = true; refreshChart(); });

      var chart;
      var curve;

      function niceDuration(ns) {
          if (ns < 1e3) { return ns + 'ns'; }
          else if (ns < 1e6) { return ns / 1e3 + 'µs'; }
          else if (ns < 1e9) { return ns / 1e6 + 'ms'; }
          else { return ns / 1e9 + 's'; }
      }

      function niceQuantile(q) {
        return 'p' + q*100;
      }

      function mmuFlags() {
        var flags = "";
        $("#options input").each(function(i, elt) {
          if (elt.checked)
            flags += "|" + elt.id;
        });
        return flags.substr(1);
      }

      function refreshChart() {
        if (!chartsReady) return;
        var container = $('#mmu_chart');
        container.css('opacity', '.5');
        refreshChart.count++;
        var seq = refreshChart.count;
        $.getJSON('?mode=plot&flags=' + mmuFlags())
         .fail(function(xhr, status, error) {
           alert('failed to load plot: ' + status);
         })
         .done(function(result) {
           if (refreshChart.count === seq)
             drawChart(result);
         });
      }
      refreshChart.count = 0;

      function drawChart(plotData) {
        curve = plotData.curve;
        var data = new google.visualization.DataTable();
        data.addColumn('number', 'Window duration');
        data.addColumn('number', 'Minimum mutator utilization');
        if (plotData.quantiles) {
          for (var i = 1; i < plotData.quantiles.length; i++) {
            data.addColumn('number', niceQuantile(1 - plotData.quantiles[i]) + ' MU');
          }
        }
        data.addRows(curve);
        for (var i = 0; i < curve.length; i++) {
          data.setFormattedValue(i, 0, niceDuration(curve[i][0]));
        }

        var options = {
          chart: {
            title: 'Minimum mutator utilization',
          },
          hAxis: {
            title: 'Window duration',
            scaleType: 'log',
            ticks: [],
          },
          vAxis: {
            title: 'Minimum mutator utilization',
            minValue: 0.0,
            maxValue: 1.0,
          },
          legend: { position: 'none' },
          focusTarget: 'category',
          width: 900,
          height: 500,
          chartArea: { width: '80%', height: '80%' },
        };
        for (var v = plotData.xMin; v <= plotData.xMax; v *= 10) {
          options.hAxis.ticks.push({v:v, f:niceDuration(v)});
        }
        if (plotData.quantiles) {
          options.vAxis.title = 'Mutator utilization';
          options.legend.position = 'in';
        }

        var container = $('#mmu_chart');
        container.empty();
        container.css('opacity', '');
        chart = new google.visualization.LineChart(container[0]);
        chart = new google.visualization.LineChart(document.getElementById('mmu_chart'));
        chart.draw(data, options);

        google.visualization.events.addListener(chart, 'select', selectHandler);
        $('#details').empty();
      }

      function selectHandler() {
        var items = chart.getSelection();
        if (items.length === 0) {
          return;
        }
        var details = $('#details');
        details.empty();
        var windowNS = curve[items[0].row][0];
        var url = '?mode=details&window=' + windowNS + '&flags=' + mmuFlags();
        $.getJSON(url)
         .fail(function(xhr, status, error) {
            details.text(status + ': ' + url + ' could not be loaded');
         })
         .done(function(worst) {
            details.text('Lowest mutator utilization in ' + niceDuration(windowNS) + ' windows:');
            for (var i = 0; i < worst.length; i++) {
              details.append($('<br>'));
              var text = worst[i].MutatorUtil.toFixed(3) + ' at time ' + niceDuration(worst[i].Time);
              details.append($('<a/>').text(text).attr('href', worst[i].URL));
            }
         });
      }

      $.when($.ready).then(function() {
        $("#options input").click(refreshChart);
      });
    </script>
    <style>
      .help {
        display: inline-block;
        position: relative;
        width: 1em;
        height: 1em;
        border-radius: 50%;
        color: #fff;
        background: #555;
        text-align: center;
        cursor: help;
      }
      .help > span {
        display: none;
      }
      .help:hover > span {
        display: block;
        position: absolute;
        left: 1.1em;
        top: 1.1em;
        background: #555;
        text-align: left;
        width: 20em;
        padding: 0.5em;
        border-radius: 0.5em;
        z-index: 5;
      }
    </style>
  </head>
  <body>
    <div style="position: relative">
      <div id="mmu_chart" style="width: 900px; height: 500px; display: inline-block; vertical-align: top">Loading plot...</div>
      <div id="options" style="display: inline-block; vertical-align: top">
        <p>
          <b>View</b><br>
          <input type="radio" name="view" id="system" checked><label for="system">System</label>
          <span class="help">?<span>Consider whole system utilization. For example, if one of four procs is available to the mutator, mutator utilization will be 0.25. This is the standard definition of an MMU.</span></span><br>
          <input type="radio" name="view" id="perProc"><label for="perProc">Per-goroutine</label>
          <span class="help">?<span>Consider per-goroutine utilization. When even one goroutine is interrupted by GC, mutator utilization is 0.</span></span><br>
        </p>
        <p>
          <b>Include</b><br>
          <input type="checkbox" id="stw" checked><label for="stw">STW</label>
          <span class="help">?<span>Stop-the-world stops all goroutines simultaneously.</span></span><br>
          <input type="checkbox" id="background" checked><label for="background">Background workers</label>
          <span class="help">?<span>Background workers are GC-specific goroutines. 25% of the CPU is dedicated to background workers during GC.</span></span><br>
          <input type="checkbox" id="assist" checked><label for="assist">Mark assist</label>
          <span class="help">?<span>Mark assists are performed by allocation to prevent the mutator from outpacing GC.</span></span><br>
          <input type="checkbox" id="sweep"><label for="sweep">Sweep</label>
          <span class="help">?<span>Sweep reclaims unused memory between GCs. (Enabling this may be very slow.).</span></span><br>
        </p>
        <p>
          <b>Display</b><br>
          <input type="checkbox" id="mut"><label for="mut">Show percentiles</label>
          <span class="help">?<span>Display percentile mutator utilization in addition to minimum. E.g., p99 MU drops the worst 1% of windows.</span></span><br>
        </p>
      </div>
    </div>
    <div id="details">Select a point for details.</div>
  </body>
</html>
`

// HandleDetails serves details of an MMU graph at a particular window.
func (m *mmu) HandleDetails(w http.ResponseWriter, r *http.Request) {
	_, mmuCurve, err := m.get(requestUtilFlags(r))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to produce MMU data: %v", err), http.StatusInternalServerError)
		return
	}

	windowStr := r.FormValue("window")
	window, err := strconv.ParseUint(windowStr, 10, 64)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse window parameter %q: %v", windowStr, err), http.StatusBadRequest)
		return
	}
	worst := mmuCurve.Examples(time.Duration(window), 10)

	// Construct a link for each window.
	var links []linkedUtilWindow
	for _, ui := range worst {
		links = append(links, m.newLinkedUtilWindow(ui, time.Duration(window)))
	}

	err = json.NewEncoder(w).Encode(links)
	if err != nil {
		log.Printf("failed to serialize trace: %v", err)
		return
	}
}

type linkedUtilWindow struct {
	trace.UtilWindow
	URL string
}

func (m *mmu) newLinkedUtilWindow(ui trace.UtilWindow, window time.Duration) linkedUtilWindow {
	// Find the range containing this window.
	var r Range
	for _, r = range m.ranges {
		if r.EndTime > ui.Time {
			break
		}
	}
	return linkedUtilWindow{ui, fmt.Sprintf("%s#%v:%v", r.URL(ViewProc), float64(ui.Time)/1e6, float64(ui.Time+int64(window))/1e6)}
}

"""



```