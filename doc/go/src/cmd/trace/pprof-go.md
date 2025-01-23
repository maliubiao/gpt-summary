Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding - Context is King:**

The very first line, `// This is path go/src/cmd/trace/pprof.go`, is crucial. It immediately tells us this code is part of the Go `trace` tool, specifically handling pprof-like profile generation. This context guides our interpretation. We know it's not general-purpose code but rather a tool for analyzing Go execution traces.

**2. High-Level Structure Scan:**

I'd quickly scan the `import` statements and the defined functions. The imports (`cmp`, `fmt`, `internal/trace`, `internal/trace/traceviewer`, `net/http`, `slices`, `strings`, `time`) give hints about the functionality: sorting, formatting, interacting with the trace data structures, handling HTTP requests, string manipulation, and time calculations.

The function names themselves are very descriptive: `pprofByGoroutine`, `pprofByRegion`, `pprofMatchingGoroutines`, `pprofMatchingRegions`, `computePprofIO`, `computePprofBlock`, `computePprofSyscall`, `computePprofSched`, `makeComputePprofFunc`, `pprofOverlappingDuration`. These names strongly suggest the core functionalities: generating pprof profiles based on goroutines and regions, filtering these, and computing specific types of profiles (IO, block, syscall, sched).

**3. Function-by-Function Analysis (Top-Down):**

I'd go through each function, trying to understand its purpose and how it fits into the larger picture.

* **`pprofByGoroutine` and `pprofByRegion`:**  These seem to be HTTP handler functions. They take a `computePprofFunc` and a `parsedTrace` as input. They extract information from the HTTP request (goroutine name or region filter) and then call the appropriate matching function (`pprofMatchingGoroutines` or `pprofMatchingRegions`) to get relevant time intervals. Finally, they use the `computePprofFunc` to generate the profile data. The `traceviewer.ProfileFunc` return type reinforces the idea that these are generating profile data for a viewer.

* **`pprofMatchingGoroutines`:** This function clearly filters goroutines based on a name provided in the HTTP request. It iterates through the `t.summary.Goroutines` and returns a map of Goroutine IDs to their start and end times. The error handling for no matching goroutines is important.

* **`pprofMatchingRegions`:** This is similar to the goroutine version but filters based on regions. The nested loop structure iterating through goroutines and their regions is apparent. The sorting and filtering logic to keep only the outermost, non-overlapping regions is a key detail. I would pay close attention to the sorting criteria and the loop condition (`lastTimestamp <= i.start`).

* **`computePprofFunc`:** This is a function type, a common Go pattern for defining reusable logic. It takes the filtered goroutine intervals and the raw trace events and returns profile records.

* **`computePprofIO`, `computePprofBlock`, `computePprofSyscall`, `computePprofSched`:** These functions return concrete implementations of `computePprofFunc`. They use `makeComputePprofFunc` with different arguments to specialize the profile generation for IO wait, blocking, syscalls, and scheduler latency. The lambda functions passed to `makeComputePprofFunc` define the specific conditions for each profile type.

* **`makeComputePprofFunc`:** This is a factory function. It takes a `trace.GoState` and a `trackReason` function. The core logic involves iterating through the trace events, filtering for state transitions, and tracking goroutines that enter the desired state for the specified reasons. The `stacks` map and `tracking` map are used to collect stack information and manage the tracking of goroutines. The `pprofOverlappingDuration` call is critical for calculating the time spent in the desired state within the filtered intervals.

* **`pprofOverlappingDuration`:** This utility function calculates the overlap between a given interval and a set of intervals associated with a goroutine. The case where `gToIntervals` is nil is handled as a no-filter scenario.

* **`interval`:**  A simple struct to represent a time interval with helper methods for calculating duration and overlap.

* **`stackMap`:** This struct is designed for efficient deduplication of stacks. The `stacks` map provides quick access if exact matches exist, while the `pcs` map, using an array of program counters, handles cases where stacks are semantically equivalent but not pointer-equal. The `pprofMaxStack` constant is a limitation of this deduplication approach.

* **Helper functions within `stackMap` (`getOrAdd`, `profile`, `pcsForStack`):** These implement the logic for adding stacks, retrieving or creating profile records, and extracting program counters from stacks.

**4. Inferring the Go Feature:**

Based on the function names and the way the code processes trace events, it's clear that this code implements the logic for generating pprof-like profiles from Go execution traces. This allows users to analyze different aspects of their program's performance, such as time spent waiting on IO, blocked on synchronization primitives, in syscalls, or waiting to be scheduled.

**5. Code Examples and Assumptions:**

When providing code examples, it's crucial to make realistic assumptions about the input. For example, when demonstrating `pprofMatchingGoroutines`, assuming a `parsedTrace` with a few goroutines having specific names makes the example concrete. Similarly, for `pprofMatchingRegions`, constructing a sample `regionFilter` and a `parsedTrace` with regions allows for a clear demonstration.

**6. Command-Line Argument Handling:**

Since the code interacts with HTTP requests (`r *http.Request`), the relevant command-line arguments would be those that configure the trace tool to serve these pprof endpoints. This would involve specifying the trace file and potentially the port on which to serve the HTTP endpoints.

**7. Common Mistakes:**

Identifying potential user errors requires thinking about how someone might misuse or misunderstand the tool. The example of filtering by goroutine name highlights a common pitfall: expecting results when the provided name doesn't exist in the trace.

**8. Refinement and Clarity:**

After the initial analysis, I'd review the explanation for clarity and accuracy. Using bullet points, clear headings, and code formatting helps to organize the information effectively. Ensuring that the explanation aligns with the code's behavior and the context of the `trace` tool is essential.
这段代码是 Go 语言 `trace` 工具中用于生成类似 pprof 性能分析文件的功能实现。它允许用户根据不同的条件（例如，特定的 Goroutine 名称或代码区域）来分析 Go 程序的执行情况。

**功能列表:**

1. **按 Goroutine 生成 Pprof:**  `pprofByGoroutine` 函数接收一个 `computePprofFunc` 和一个解析后的 trace 数据 `t`，并返回一个 `traceviewer.ProfileFunc`。这个返回的函数会根据 HTTP 请求中提供的 Goroutine 名称（`name` 参数）过滤 Goroutine，并使用 `computePprofFunc` 计算这些 Goroutine 的性能 profile 数据。
2. **按代码区域生成 Pprof:** `pprofByRegion` 函数与 `pprofByGoroutine` 类似，但它根据 HTTP 请求中提供的区域过滤器（通过 `newRegionFilter(r)` 创建）来过滤代码执行区域，并使用 `computePprofFunc` 计算这些区域的性能 profile 数据。
3. **查找匹配的 Goroutine:** `pprofMatchingGoroutines` 函数根据给定的 Goroutine 名称，在解析后的 trace 数据中查找匹配的 Goroutine，并返回一个映射，其中键是 Goroutine 的 ID，值是 Goroutine 的生命周期时间段。
4. **查找匹配的代码区域:** `pprofMatchingRegions` 函数根据提供的区域过滤器，在解析后的 trace 数据中查找匹配的代码执行区域，并返回一个映射，其中键是 Goroutine 的 ID，值是该 Goroutine 中匹配区域的时间段列表。它还会去除嵌套的区域，只保留最外层的区域。
5. **定义 Pprof 计算函数类型:** `computePprofFunc` 定义了一个函数类型，该函数接收 Goroutine 的时间段映射和所有事件列表，并返回 `traceviewer.ProfileRecord` 类型的切片，用于表示性能 profile 数据。
6. **预定义的 Pprof 计算函数:** 提供了几个预定义的 `computePprofFunc` 实现：
    * `computePprofIO`: 计算 Goroutine 在 IO 等待上花费的时间（目前只考虑网络阻塞事件）。
    * `computePprofBlock`: 计算 Goroutine 在同步原语上阻塞的时间（例如，channel、sync 包、select）。
    * `computePprofSyscall`: 计算 Goroutine 在系统调用上花费的时间。
    * `computePprofSched`: 计算 Goroutine 从变为可运行状态到真正被调度执行之间的延迟。
7. **创建自定义 Pprof 计算函数:** `makeComputePprofFunc` 函数是一个工厂函数，用于创建自定义的 `computePprofFunc`。它接收一个 `trace.GoState`（例如，等待、可运行）和一个用于判断事件原因的函数 `trackReason`。
8. **计算时间段的重叠部分:** `pprofOverlappingDuration` 函数计算给定的时间段 `sample` 与一组 Goroutine 的时间段 `gToIntervals` 之间的重叠时长。
9. **表示时间段:** `interval` 结构体用于表示一个时间段，并提供了计算时长和与其他时间段重叠部分的方法。
10. **管理和去重调用栈:** `stackMap` 结构体用于存储和去重调用栈信息。由于 `trace.Stack` 的相等性判断是乐观的，`stackMap` 使用了两个 map 来确保准确的去重：一个存储 `trace.Stack` 到 `traceviewer.ProfileRecord` 的映射，另一个存储调用栈的程序计数器（PC）数组到 `trace.Stack` 的映射。

**推理 Go 语言功能的实现:**

这段代码是 Go 语言 `trace` 工具的一部分，用于生成 **性能分析 (Profiling)** 数据，特别是类似于 `pprof` 工具生成的 profile 文件。`pprof` 是 Go 语言标准库提供的用于分析程序性能的工具，它可以生成 CPU、内存、阻塞等各种类型的 profile。

这段代码的功能是，在已经通过 `go tool trace` 命令收集到的 trace 数据的基础上，进一步分析，并生成特定类型的 profile 数据，以便用户更细粒度地了解程序的性能瓶颈。

**Go 代码举例说明:**

假设我们已经通过 `go tool trace` 命令生成了一个 trace 文件 `trace.out`。现在，我们想要分析 Goroutine 在网络 IO 上花费的时间。`pprof.go` 中的 `computePprofIO` 函数正是为此设计的。

在 `trace` 工具的上下文中，这段代码会被用来处理 HTTP 请求。假设 `trace` 工具启动了一个 HTTP 服务，并且我们访问了类似以下的 URL：

```
http://localhost:<port>/pprof/io?name=myGoroutine
```

这里的 `<port>` 是 `trace` 工具监听的端口，`pprof/io` 指示我们想要生成 IO 相关的 profile，`name=myGoroutine` 是一个可选参数，用于指定我们只关注名为 "myGoroutine" 的 Goroutine。

`pprofByGoroutine` 函数会处理这个请求，调用 `pprofMatchingGoroutines` 找到名为 "myGoroutine" 的 Goroutine 的时间段，然后调用 `computePprofIO()` 返回的函数来计算这些 Goroutine 在网络 IO 上花费的时间。

`computePprofIO` 的内部实现（通过 `makeComputePprofFunc` 创建）会遍历 trace 事件，查找 `trace.GoWaiting` 状态且原因是 "network" 的事件，并记录相关调用栈和持续时间。

**假设的输入与输出:**

**假设输入:**

* **trace 数据 (`t *parsedTrace`)**: 包含 Goroutine 的创建、状态转换、代码区域等事件信息。假设其中包含一个名为 "myGoroutine" 的 Goroutine，其 ID 为 10，并在某个时间段内因为网络 IO 进入等待状态。
* **HTTP 请求 (`r *http.Request`)**:  如上例所示，请求 `/pprof/io?name=myGoroutine`。

**假设输出 (`[]traceviewer.ProfileRecord`):**

输出将是一个 `traceviewer.ProfileRecord` 的切片，每个元素代表一个调用栈以及在该调用栈上花费的总时间。例如：

```go
[]traceviewer.ProfileRecord{
    {
        Count: 5, // 该调用栈出现的次数
        Time:  time.Second * 2, // 在该调用栈上花费的总时间
        Stack: []*trace.Frame{
            {PC: 0x12345, Fn: "net/http.(*conn).readLoop", File: "/usr/local/go/src/net/http/server.go", Line: 1800},
            {PC: 0x54321, Fn: "net/http.(*conn).serve", File: "/usr/local/go/src/net/http/server.go", Line: 1700},
            // ... 更多调用栈帧
        },
    },
    // ... 更多 ProfileRecord，如果还有其他调用栈在 IO 等待上花费了时间
}
```

这个输出表明，调用栈中包含 `net/http.(*conn).readLoop` 和 `net/http.(*conn).serve` 的部分在网络 IO 上总共花费了 2 秒，并且出现了 5 次。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理通常发生在 `main` 包的其他文件中，用于配置 `trace` 工具的行为，例如指定 trace 文件路径、监听端口等。

然而，这段代码会间接地受到命令行参数的影响。例如，用户通过命令行参数指定了要分析的 trace 文件，那么 `pprof.go` 中的函数就会基于这个 trace 文件的数据进行分析。

对于 `pprofByGoroutine` 和 `pprofByRegion` 这两个函数，它们会从 HTTP 请求中获取参数，例如：

* **`name`**:  通过 `r.FormValue("name")` 获取，用于 `pprofByGoroutine`，指定要筛选的 Goroutine 名称。
* **Region 相关的参数**: `pprofByRegion` 使用 `newRegionFilter(r)` 来创建区域过滤器，这个过滤器可能会根据 HTTP 请求中的参数（例如，区域类型、函数名等）进行配置。具体的参数取决于 `newRegionFilter` 的实现。

**使用者易犯错的点:**

1. **Goroutine 名称拼写错误:**  在使用 `pprofByGoroutine` 时，如果提供的 Goroutine 名称在 trace 数据中不存在，`pprofMatchingGoroutines` 函数会返回一个错误。使用者可能会因为拼写错误或对 Goroutine 名称不熟悉而无法获取到预期的 profile 数据。

   **例如:**  如果 trace 中有一个 Goroutine 名为 "processRequest"，但用户在请求中使用了 `name=processrequest`（缺少一个 'R'），则会得到 "failed to find matching goroutines for name: processrequest" 的错误。

2. **对代码区域过滤器的理解不足:** `pprofByRegion` 的功能强大，但也更容易出错。使用者需要理解区域过滤器的配置方式和参数含义。如果过滤器配置不当，可能无法匹配到想要分析的代码区域，或者匹配到过多的区域，导致分析结果不准确。

   **例如:** 用户可能希望分析所有 "net/http" 包中的函数，但如果过滤器配置错误，只匹配了 "net/http." 开头的函数（缺少通配符），则可能遗漏了 "net/http/server.go" 等子目录下的函数。具体的过滤器参数和语法取决于 `newRegionFilter` 的实现，如果文档不清晰，则容易出错。

总而言之，这段代码是 Go `trace` 工具中用于生成各种 pprof 风格性能分析数据的核心部分，它通过 HTTP 接口接收请求，根据 Goroutine 或代码区域进行过滤，并利用不同的计算函数生成特定的 profile 信息，帮助开发者深入了解程序的性能特征。

### 提示词
```
这是路径为go/src/cmd/trace/pprof.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Serving of pprof-like profiles.

package main

import (
	"cmp"
	"fmt"
	"internal/trace"
	"internal/trace/traceviewer"
	"net/http"
	"slices"
	"strings"
	"time"
)

func pprofByGoroutine(compute computePprofFunc, t *parsedTrace) traceviewer.ProfileFunc {
	return func(r *http.Request) ([]traceviewer.ProfileRecord, error) {
		name := r.FormValue("name")
		gToIntervals, err := pprofMatchingGoroutines(name, t)
		if err != nil {
			return nil, err
		}
		return compute(gToIntervals, t.events)
	}
}

func pprofByRegion(compute computePprofFunc, t *parsedTrace) traceviewer.ProfileFunc {
	return func(r *http.Request) ([]traceviewer.ProfileRecord, error) {
		filter, err := newRegionFilter(r)
		if err != nil {
			return nil, err
		}
		gToIntervals, err := pprofMatchingRegions(filter, t)
		if err != nil {
			return nil, err
		}
		return compute(gToIntervals, t.events)
	}
}

// pprofMatchingGoroutines returns the ids of goroutines of the matching name and its interval.
// If the id string is empty, returns nil without an error.
func pprofMatchingGoroutines(name string, t *parsedTrace) (map[trace.GoID][]interval, error) {
	res := make(map[trace.GoID][]interval)
	for _, g := range t.summary.Goroutines {
		if name != "" && g.Name != name {
			continue
		}
		endTime := g.EndTime
		if g.EndTime == 0 {
			endTime = t.endTime() // Use the trace end time, since the goroutine is still live then.
		}
		res[g.ID] = []interval{{start: g.StartTime, end: endTime}}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("failed to find matching goroutines for name: %s", name)
	}
	return res, nil
}

// pprofMatchingRegions returns the time intervals of matching regions
// grouped by the goroutine id. If the filter is nil, returns nil without an error.
func pprofMatchingRegions(filter *regionFilter, t *parsedTrace) (map[trace.GoID][]interval, error) {
	if filter == nil {
		return nil, nil
	}

	gToIntervals := make(map[trace.GoID][]interval)
	for _, g := range t.summary.Goroutines {
		for _, r := range g.Regions {
			if !filter.match(t, r) {
				continue
			}
			gToIntervals[g.ID] = append(gToIntervals[g.ID], regionInterval(t, r))
		}
	}

	for g, intervals := range gToIntervals {
		// In order to remove nested regions and
		// consider only the outermost regions,
		// first, we sort based on the start time
		// and then scan through to select only the outermost regions.
		slices.SortFunc(intervals, func(a, b interval) int {
			if c := cmp.Compare(a.start, b.start); c != 0 {
				return c
			}
			return cmp.Compare(a.end, b.end)
		})
		var lastTimestamp trace.Time
		var n int
		// Select only the outermost regions.
		for _, i := range intervals {
			if lastTimestamp <= i.start {
				intervals[n] = i // new non-overlapping region starts.
				lastTimestamp = i.end
				n++
			}
			// Otherwise, skip because this region overlaps with a previous region.
		}
		gToIntervals[g] = intervals[:n]
	}
	return gToIntervals, nil
}

type computePprofFunc func(gToIntervals map[trace.GoID][]interval, events []trace.Event) ([]traceviewer.ProfileRecord, error)

// computePprofIO returns a computePprofFunc that generates IO pprof-like profile (time spent in
// IO wait, currently only network blocking event).
func computePprofIO() computePprofFunc {
	return makeComputePprofFunc(trace.GoWaiting, func(reason string) bool {
		return reason == "network"
	})
}

// computePprofBlock returns a computePprofFunc that generates blocking pprof-like profile
// (time spent blocked on synchronization primitives).
func computePprofBlock() computePprofFunc {
	return makeComputePprofFunc(trace.GoWaiting, func(reason string) bool {
		return strings.Contains(reason, "chan") || strings.Contains(reason, "sync") || strings.Contains(reason, "select")
	})
}

// computePprofSyscall returns a computePprofFunc that generates a syscall pprof-like
// profile (time spent in syscalls).
func computePprofSyscall() computePprofFunc {
	return makeComputePprofFunc(trace.GoSyscall, func(_ string) bool {
		return true
	})
}

// computePprofSched returns a computePprofFunc that generates a scheduler latency pprof-like profile
// (time between a goroutine become runnable and actually scheduled for execution).
func computePprofSched() computePprofFunc {
	return makeComputePprofFunc(trace.GoRunnable, func(_ string) bool {
		return true
	})
}

// makeComputePprofFunc returns a computePprofFunc that generates a profile of time goroutines spend
// in a particular state for the specified reasons.
func makeComputePprofFunc(state trace.GoState, trackReason func(string) bool) computePprofFunc {
	return func(gToIntervals map[trace.GoID][]interval, events []trace.Event) ([]traceviewer.ProfileRecord, error) {
		stacks := newStackMap()
		tracking := make(map[trace.GoID]*trace.Event)
		for i := range events {
			ev := &events[i]

			// Filter out any non-state-transitions and events without stacks.
			if ev.Kind() != trace.EventStateTransition {
				continue
			}
			stack := ev.Stack()
			if stack == trace.NoStack {
				continue
			}

			// The state transition has to apply to a goroutine.
			st := ev.StateTransition()
			if st.Resource.Kind != trace.ResourceGoroutine {
				continue
			}
			id := st.Resource.Goroutine()
			_, new := st.Goroutine()

			// Check if we're tracking this goroutine.
			startEv := tracking[id]
			if startEv == nil {
				// We're not. Start tracking if the new state
				// matches what we want and the transition is
				// for one of the reasons we care about.
				if new == state && trackReason(st.Reason) {
					tracking[id] = ev
				}
				continue
			}
			// We're tracking this goroutine.
			if new == state {
				// We're tracking this goroutine, but it's just transitioning
				// to the same state (this is a no-ip
				continue
			}
			// The goroutine has transitioned out of the state we care about,
			// so remove it from tracking and record the stack.
			delete(tracking, id)

			overlapping := pprofOverlappingDuration(gToIntervals, id, interval{startEv.Time(), ev.Time()})
			if overlapping > 0 {
				rec := stacks.getOrAdd(startEv.Stack())
				rec.Count++
				rec.Time += overlapping
			}
		}
		return stacks.profile(), nil
	}
}

// pprofOverlappingDuration returns the overlapping duration between
// the time intervals in gToIntervals and the specified event.
// If gToIntervals is nil, this simply returns the event's duration.
func pprofOverlappingDuration(gToIntervals map[trace.GoID][]interval, id trace.GoID, sample interval) time.Duration {
	if gToIntervals == nil { // No filtering.
		return sample.duration()
	}
	intervals := gToIntervals[id]
	if len(intervals) == 0 {
		return 0
	}

	var overlapping time.Duration
	for _, i := range intervals {
		if o := i.overlap(sample); o > 0 {
			overlapping += o
		}
	}
	return overlapping
}

// interval represents a time interval in the trace.
type interval struct {
	start, end trace.Time
}

func (i interval) duration() time.Duration {
	return i.end.Sub(i.start)
}

func (i1 interval) overlap(i2 interval) time.Duration {
	// Assume start1 <= end1 and start2 <= end2
	if i1.end < i2.start || i2.end < i1.start {
		return 0
	}
	if i1.start < i2.start { // choose the later one
		i1.start = i2.start
	}
	if i1.end > i2.end { // choose the earlier one
		i1.end = i2.end
	}
	return i1.duration()
}

// pprofMaxStack is the extent of the deduplication we're willing to do.
//
// Because slices aren't comparable and we want to leverage maps for deduplication,
// we have to choose a fixed constant upper bound on the amount of frames we want
// to support. In practice this is fine because there's a maximum depth to these
// stacks anyway.
const pprofMaxStack = 128

// stackMap is a map of trace.Stack to some value V.
type stackMap struct {
	// stacks contains the full list of stacks in the set, however
	// it is insufficient for deduplication because trace.Stack
	// equality is only optimistic. If two trace.Stacks are equal,
	// then they are guaranteed to be equal in content. If they are
	// not equal, then they might still be equal in content.
	stacks map[trace.Stack]*traceviewer.ProfileRecord

	// pcs is the source-of-truth for deduplication. It is a map of
	// the actual PCs in the stack to a trace.Stack.
	pcs map[[pprofMaxStack]uint64]trace.Stack
}

func newStackMap() *stackMap {
	return &stackMap{
		stacks: make(map[trace.Stack]*traceviewer.ProfileRecord),
		pcs:    make(map[[pprofMaxStack]uint64]trace.Stack),
	}
}

func (m *stackMap) getOrAdd(stack trace.Stack) *traceviewer.ProfileRecord {
	// Fast path: check to see if this exact stack is already in the map.
	if rec, ok := m.stacks[stack]; ok {
		return rec
	}
	// Slow path: the stack may still be in the map.

	// Grab the stack's PCs as the source-of-truth.
	var pcs [pprofMaxStack]uint64
	pcsForStack(stack, &pcs)

	// Check the source-of-truth.
	var rec *traceviewer.ProfileRecord
	if existing, ok := m.pcs[pcs]; ok {
		// In the map.
		rec = m.stacks[existing]
		delete(m.stacks, existing)
	} else {
		// Not in the map.
		rec = new(traceviewer.ProfileRecord)
	}
	// Insert regardless of whether we have a match in m.pcs.
	// Even if we have a match, we want to keep the newest version
	// of that stack, since we're much more likely tos see it again
	// as we iterate through the trace linearly. Simultaneously, we
	// are likely to never see the old stack again.
	m.pcs[pcs] = stack
	m.stacks[stack] = rec
	return rec
}

func (m *stackMap) profile() []traceviewer.ProfileRecord {
	prof := make([]traceviewer.ProfileRecord, 0, len(m.stacks))
	for stack, record := range m.stacks {
		rec := *record
		for i, frame := range slices.Collect(stack.Frames()) {
			rec.Stack = append(rec.Stack, &trace.Frame{
				PC:   frame.PC,
				Fn:   frame.Func,
				File: frame.File,
				Line: int(frame.Line),
			})
			// Cut this off at pprofMaxStack because that's as far
			// as our deduplication goes.
			if i >= pprofMaxStack {
				break
			}
		}
		prof = append(prof, rec)
	}
	return prof
}

// pcsForStack extracts the first pprofMaxStack PCs from stack into pcs.
func pcsForStack(stack trace.Stack, pcs *[pprofMaxStack]uint64) {
	for i, frame := range slices.Collect(stack.Frames()) {
		pcs[i] = frame.PC
		if i >= len(pcs) {
			break
		}
	}
}
```