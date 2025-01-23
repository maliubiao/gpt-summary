Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of `gc.go` within the `internal/trace` package. It also asks for examples, related Go features, command-line implications, and potential pitfalls.

2. **Initial Scan and Keywords:**  A quick skim reveals important keywords and data structures: `MutatorUtil`, `UtilFlags`, `MutatorUtilizationV2`, `MMUCurve`, `accumulator`, `GC`, `STW`, `mark assist`, `sweep`. These provide clues about the code's purpose.

3. **High-Level Functionality Identification:** The function `MutatorUtilizationV2` stands out. Its name strongly suggests it calculates how effectively the Go program's "mutator" (the part of the program that's *not* the garbage collector) is utilizing CPU time. The `UtilFlags` enum hints at different aspects of GC activity that can be included or excluded from this calculation.

4. **Dissecting `MutatorUtilizationV2`:**
    * **Input:**  It takes `events []Event` (likely trace events) and `flags UtilFlags`. This confirms it's analyzing a trace.
    * **Core Logic (Iterating through Events):** The `for i := range events` loop is the heart of the function. It processes each event and updates internal state.
    * **Tracking GC State:** Variables like `gc`, `inGC`, `bgMark` clearly track the garbage collector's activity on different processors (Ps) and goroutines.
    * **Calculating Utilization:** The logic within the loop, especially the `if flags&UtilPerProc == 0` and `else` blocks, shows how mutator utilization is computed based on whether GC is active on a given P or globally.
    * **Output:** It returns `[][]MutatorUtil`, suggesting a time series of utilization values, potentially per processor.

5. **Connecting to Go GC:**  The terms "mutator," "GC," "STW," "mark assist," and "sweep" are fundamental to the Go garbage collector. This strongly indicates that this code is part of the tracing infrastructure specifically for analyzing the GC's impact on application performance.

6. **Inferring the Purpose of `MMUCurve` and Related Structures:**
    * **`MMUCurve`:** "Minimum Mutator Utilization Curve" suggests it's calculating the *lowest* mutator utilization over various time *windows*.
    * **`accumulator`:** This structure seems to be a helper for calculating the MMU, tracking the minimum utilization (`mmu`), worst windows, and potentially a distribution (`mud`).
    * **Windowing:** The concept of a "window" (of time) and calculations related to it (`window time.Duration`) are central to `MMUCurve`. This points to analyzing performance over different time scales.

7. **Formulating the "What Go Feature is This Implementing?" Hypothesis:** Based on the analysis, the code is clearly related to the **Go Garbage Collector (GC) and its performance analysis**. Specifically, it's about understanding how much time the application spends running versus how much time the GC is running.

8. **Creating a Go Code Example:**  To illustrate this, a simple Go program that could be traced and analyzed by this code is needed. The example should demonstrate some allocation to trigger the GC. The `go build` and `go tool trace` commands are essential for showing how the tracing mechanism works. The example output should be illustrative, even if the exact numbers depend on the execution environment.

9. **Identifying Command-Line Arguments:** The `go tool trace` command itself takes a trace file as input. This is the most direct command-line interaction. Mentioning environment variables like `GODEBUG=gctrace=1` is also relevant, although this specific code doesn't directly process them.

10. **Pinpointing Common Mistakes:**  Thinking about how developers might misuse this *analysis tool* (rather than the `gc.go` code itself):
    * **Incorrect Flags:**  Using the wrong `UtilFlags` in `MutatorUtilizationV2` will lead to different interpretations of the data.
    * **Misinterpreting MMU:**  Not understanding that MMU is the *minimum* over all windows can be a source of confusion.
    * **Ignoring Window Size:** The `window` parameter in `MMU` and `MUD` is crucial and affects the results significantly.
    * **Overlooking STW:** Not accounting for STW time can skew utilization metrics if that's important for the analysis.

11. **Structuring the Answer:** Organize the findings logically:
    * Functionality of `gc.go`.
    * The Go feature it implements (GC performance analysis).
    * Go code example with tracing instructions.
    * Explanation of the example's input and potential output.
    * Command-line arguments related to tracing.
    * Common mistakes users might make.

12. **Refining the Language:**  Ensure the explanation is clear, concise, and uses appropriate technical terminology. Translate code comments and variable names into understandable explanations.

By following this systematic approach, breaking down the code into smaller pieces, connecting it to known Go concepts, and anticipating user needs, a comprehensive and accurate answer can be generated.
这段代码是 Go 语言运行时追踪 (runtime trace) 功能的一部分，具体来说，它实现了与 **垃圾回收 (Garbage Collection, GC)** 相关的性能分析功能。

**主要功能:**

1. **计算 Mutator 利用率 (Mutator Utilization):**  这是该代码的核心功能。Mutator 指的是应用程序中执行非垃圾回收工作的 Goroutine。Mutator 利用率衡量的是 Mutator Goroutine 实际占用 CPU 时间的比例。代码提供了 `MutatorUtilizationV2` 函数来计算 Mutator 利用率。

2. **考虑不同的 GC 活动:**  `MutatorUtilizationV2` 函数使用 `UtilFlags` 来控制计算 Mutator 利用率时是否考虑不同的 GC 活动，例如：
   - `UtilSTW`:  是否将 Stop-The-World (STW) 事件计入。
   - `UtilBackground`: 是否将后台标记 (background mark) worker 的活动计入。
   - `UtilAssist`: 是否将 Mark Assist (当 Mutator 需要分配内存但 GC 正在进行时，Mutator 协助 GC 标记) 计入。
   - `UtilSweep`: 是否将清理 (sweep) 阶段计入。
   - `UtilPerProc`: 是否为每个 P (Processor) 单独计算利用率。

3. **计算最小 Mutator 利用率曲线 (Minimum Mutator Utilization Curve, MMUCurve):** `MMUCurve` 结构和相关的函数（如 `NewMMUCurve`, `MMU`, `Examples`, `MUD`) 用于分析在不同时间窗口大小下，Mutator 的最低利用率是多少。这有助于识别程序执行过程中 Mutator 性能瓶颈的时期。

4. **计算 Mutator 利用率分布 (Mutator Utilization Distribution, MUD):**  `MUD` 函数用于计算在给定的时间窗口大小下，Mutator 利用率的分布情况，包括分位数等信息。

**推断的 Go 语言功能实现:**

这段代码是 `go tool trace` 命令用来分析 Go 程序运行时 trace 数据的核心部分之一。通过解析 trace 数据，它可以生成关于 GC 行为和 Mutator 利用率的详细报告，帮助开发者理解和优化程序的性能。

**Go 代码举例说明:**

假设我们有一个简单的 Go 程序，它会进行一些内存分配：

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	fmt.Println("程序开始")
	var data []*int
	for i := 0; i < 1000000; i++ {
		num := new(int)
		*num = i
		data = append(data, num)
		if i%100000 == 0 {
			runtime.GC() // 显式调用 GC
			time.Sleep(10 * time.Millisecond)
		}
	}
	fmt.Println("程序结束")
}
```

要使用这段 `gc.go` 代码分析这个程序，我们需要先生成 trace 数据，然后使用 `go tool trace` 命令：

**步骤 1: 运行程序并生成 trace 文件**

```bash
go run -gcflags='-G -N' main.go  # 为了保证trace的完整性，建议禁用内联和边界检查
```

**或者更常用的方式，使用 `runtime/trace` 包：**

```go
package main

import (
	"fmt"
	"os"
	"runtime"
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

	fmt.Println("程序开始")
	var data []*int
	for i := 0; i < 1000000; i++ {
		num := new(int)
		*num = i
		data = append(data, num)
		if i%100000 == 0 {
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
	}
	fmt.Println("程序结束")
}
```

然后运行程序：

```bash
go run main.go
```

这会生成一个名为 `trace.out` 的 trace 文件。

**步骤 2: 使用 `go tool trace` 分析 trace 文件**

```bash
go tool trace trace.out
```

这会打开一个 Web 界面，其中包含各种分析工具，包括 "Heap profile", "Goroutine analysis", **"Mutator utilization"** 等。  `gc.go` 中的代码就是用来生成 "Mutator utilization" 相关数据的。

**假设的输入与输出 (代码推理):**

`MutatorUtilizationV2` 函数的输入是 `[]Event` (trace 事件) 和 `UtilFlags`。  假设我们生成的 `trace.out` 文件包含以下几个关键事件 (简化)：

```
[
  { "Time": 1000, "Type": "Sync" },
  { "Time": 1100, "Type": "Metric", "Name": "/sched/gomaxprocs:threads", "Value": 4 }, // GOMAXPROCS = 4
  { "Time": 1200, "Type": "RangeBegin", "Proc": 0, "Name": "GC mark assist" },
  { "Time": 1300, "Type": "StateTransition", "GoID": 1, "OldStatus": "Runnable", "NewStatus": "Executing", "Proc": 0 },
  { "Time": 1400, "Type": "RangeEnd", "Proc": 0, "Name": "GC mark assist" },
  { "Time": 1500, "Type": "StateTransition", "GoID": 1, "OldStatus": "Executing", "NewStatus": "Runnable", "Proc": 0 },
  { "Time": 1600, "Type": "RangeBegin", "Name": "stop-the-world (GC)" },
  { "Time": 1700, "Type": "RangeEnd", "Name": "stop-the-world (GC)" },
  { "Time": 1800, "Type": "StateTransition", "GoID": 2, "OldStatus": "Runnable", "NewStatus": "Executing", "Proc": 1 },
  // ... 更多的事件
]
```

如果我们调用 `MutatorUtilizationV2(events, 0)` (不设置任何 `UtilFlags`)，它会尝试计算纯粹的 Mutator 利用率，不考虑 GC 活动。输出可能类似于：

```
[
  [ // 如果 UtilPerProc 未设置，则只有一个元素
    { "Time": 1100, "Util": 1.0 }, // 初始化时，所有 P 都在运行 Mutator
    { "Time": 1200, "Util": 0.75 }, // Proc 0 进入 GC mark assist，假设只影响一个 P
    { "Time": 1400, "Util": 1.0 },  // Proc 0 退出 GC mark assist
    { "Time": 1600, "Util": 0.0 },  // 进入 STW
    { "Time": 1700, "Util": 1.0 },  // 退出 STW
    { "Time": 1800, "Util": ... },
    // ...
  ]
]
```

如果调用 `MutatorUtilizationV2(events, UtilSTW)`，则 STW 期间的利用率仍然是 0。

如果调用 `MutatorUtilizationV2(events, UtilAssist)`，则 `GC mark assist` 期间的利用率会受到影响。

如果调用 `MutatorUtilizationV2(events, UtilPerProc)`，输出会变成一个二维数组，每个元素代表一个 P 的利用率时间序列。

**命令行参数的具体处理:**

`gc.go` 本身是 Go 运行时的一部分，并不直接处理命令行参数。它的功能是通过 `go tool trace` 命令来触发和使用。

`go tool trace` 命令接收一个或多个 trace 文件作为参数：

```bash
go tool trace trace1.out trace2.out
```

`go tool trace` 内部会读取这些 trace 文件，并调用 `internal/trace` 包（包括 `gc.go`）中的函数来解析和分析 trace 数据。

在 `go tool trace` 的 Web 界面中，用户可以选择不同的分析工具和选项，这些选项可能会影响 `internal/trace` 包中函数的调用方式和参数。例如，选择查看 "Mutator utilization" 可能会调用 `MutatorUtilizationV2` 函数，并根据用户的选择传递不同的 `UtilFlags`。

**使用者易犯错的点:**

理解 `UtilFlags` 的含义非常重要。错误地设置 flags 会导致对 Mutator 利用率的错误解读。

例如：

- **没有包含 STW 时间:** 如果分析时没有设置 `UtilSTW` 标志，那么 STW 期间会被认为是 Mutator 没有工作的状态，这对于理解程序的整体暂停时间是不够的。
- **混淆不同类型的 GC 活动:**  不理解 `UtilBackground`, `UtilAssist`, `UtilSweep` 的区别，可能会错误地将某些 GC 活动的影响归咎于 Mutator 性能问题。
- **忽略 `UtilPerProc`:** 在多核环境下，如果只看全局的 Mutator 利用率，可能会忽略某些 P 上的瓶颈。使用 `UtilPerProc` 可以更细粒度地分析每个 P 的利用率。
- **不理解时间窗口 (for MMU/MUD):**  在使用 `MMU` 和 `MUD` 功能时，理解 `window` 参数的含义至关重要。不同的时间窗口会揭示不同时间尺度的性能问题。例如，很小的窗口可能显示短暂的性能下降，而较大的窗口则显示较长时间的平均性能。

总而言之，`go/src/internal/trace/gc.go` 是 Go 运行时追踪系统中用于分析垃圾回收对程序 Mutator 性能影响的关键组件。它通过解析 trace 事件，计算 Mutator 利用率，并提供不同维度和时间窗口的分析，帮助开发者深入了解程序的 GC 行为和性能瓶颈。

### 提示词
```
这是路径为go/src/internal/trace/gc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"container/heap"
	"math"
	"sort"
	"strings"
	"time"
)

// MutatorUtil is a change in mutator utilization at a particular
// time. Mutator utilization functions are represented as a
// time-ordered []MutatorUtil.
type MutatorUtil struct {
	Time int64
	// Util is the mean mutator utilization starting at Time. This
	// is in the range [0, 1].
	Util float64
}

// UtilFlags controls the behavior of MutatorUtilization.
type UtilFlags int

const (
	// UtilSTW means utilization should account for STW events.
	// This includes non-GC STW events, which are typically user-requested.
	UtilSTW UtilFlags = 1 << iota
	// UtilBackground means utilization should account for
	// background mark workers.
	UtilBackground
	// UtilAssist means utilization should account for mark
	// assists.
	UtilAssist
	// UtilSweep means utilization should account for sweeping.
	UtilSweep

	// UtilPerProc means each P should be given a separate
	// utilization function. Otherwise, there is a single function
	// and each P is given a fraction of the utilization.
	UtilPerProc
)

// MutatorUtilizationV2 returns a set of mutator utilization functions
// for the given v2 trace, passed as an io.Reader. Each function will
// always end with 0 utilization. The bounds of each function are implicit
// in the first and last event; outside of these bounds each function is
// undefined.
//
// If the UtilPerProc flag is not given, this always returns a single
// utilization function. Otherwise, it returns one function per P.
func MutatorUtilizationV2(events []Event, flags UtilFlags) [][]MutatorUtil {
	// Set up a bunch of analysis state.
	type perP struct {
		// gc > 0 indicates that GC is active on this P.
		gc int
		// series the logical series number for this P. This
		// is necessary because Ps may be removed and then
		// re-added, and then the new P needs a new series.
		series int
	}
	type procsCount struct {
		// time at which procs changed.
		time int64
		// n is the number of procs at that point.
		n int
	}
	out := [][]MutatorUtil{}
	stw := 0
	ps := []perP{}
	inGC := make(map[GoID]bool)
	states := make(map[GoID]GoState)
	bgMark := make(map[GoID]bool)
	procs := []procsCount{}
	seenSync := false

	// Helpers.
	handleSTW := func(r Range) bool {
		return flags&UtilSTW != 0 && isGCSTW(r)
	}
	handleMarkAssist := func(r Range) bool {
		return flags&UtilAssist != 0 && isGCMarkAssist(r)
	}
	handleSweep := func(r Range) bool {
		return flags&UtilSweep != 0 && isGCSweep(r)
	}

	// Iterate through the trace, tracking mutator utilization.
	var lastEv *Event
	for i := range events {
		ev := &events[i]
		lastEv = ev

		// Process the event.
		switch ev.Kind() {
		case EventSync:
			seenSync = true
		case EventMetric:
			m := ev.Metric()
			if m.Name != "/sched/gomaxprocs:threads" {
				break
			}
			gomaxprocs := int(m.Value.Uint64())
			if len(ps) > gomaxprocs {
				if flags&UtilPerProc != 0 {
					// End each P's series.
					for _, p := range ps[gomaxprocs:] {
						out[p.series] = addUtil(out[p.series], MutatorUtil{int64(ev.Time()), 0})
					}
				}
				ps = ps[:gomaxprocs]
			}
			for len(ps) < gomaxprocs {
				// Start new P's series.
				series := 0
				if flags&UtilPerProc != 0 || len(out) == 0 {
					series = len(out)
					out = append(out, []MutatorUtil{{int64(ev.Time()), 1}})
				}
				ps = append(ps, perP{series: series})
			}
			if len(procs) == 0 || gomaxprocs != procs[len(procs)-1].n {
				procs = append(procs, procsCount{time: int64(ev.Time()), n: gomaxprocs})
			}
		}
		if len(ps) == 0 {
			// We can't start doing any analysis until we see what GOMAXPROCS is.
			// It will show up very early in the trace, but we need to be robust to
			// something else being emitted beforehand.
			continue
		}

		switch ev.Kind() {
		case EventRangeActive:
			if seenSync {
				// If we've seen a sync, then we can be sure we're not finding out about
				// something late; we have complete information after that point, and these
				// active events will just be redundant.
				break
			}
			// This range is active back to the start of the trace. We're failing to account
			// for this since we just found out about it now. Fix up the mutator utilization.
			//
			// N.B. A trace can't start during a STW, so we don't handle it here.
			r := ev.Range()
			switch {
			case handleMarkAssist(r):
				if !states[ev.Goroutine()].Executing() {
					// If the goroutine isn't executing, then the fact that it was in mark
					// assist doesn't actually count.
					break
				}
				// This G has been in a mark assist *and running on its P* since the start
				// of the trace.
				fallthrough
			case handleSweep(r):
				// This P has been in sweep (or mark assist, from above) in the start of the trace.
				//
				// We don't need to do anything if UtilPerProc is set. If we get an event like
				// this for a running P, it must show up the first time a P is mentioned. Therefore,
				// this P won't actually have any MutatorUtils on its list yet.
				//
				// However, if UtilPerProc isn't set, then we probably have data from other procs
				// and from previous events. We need to fix that up.
				if flags&UtilPerProc != 0 {
					break
				}
				// Subtract out 1/gomaxprocs mutator utilization for all time periods
				// from the beginning of the trace until now.
				mi, pi := 0, 0
				for mi < len(out[0]) {
					if pi < len(procs)-1 && procs[pi+1].time < out[0][mi].Time {
						pi++
						continue
					}
					out[0][mi].Util -= float64(1) / float64(procs[pi].n)
					if out[0][mi].Util < 0 {
						out[0][mi].Util = 0
					}
					mi++
				}
			}
			// After accounting for the portion we missed, this just acts like the
			// beginning of a new range.
			fallthrough
		case EventRangeBegin:
			r := ev.Range()
			if handleSTW(r) {
				stw++
			} else if handleSweep(r) {
				ps[ev.Proc()].gc++
			} else if handleMarkAssist(r) {
				ps[ev.Proc()].gc++
				if g := r.Scope.Goroutine(); g != NoGoroutine {
					inGC[g] = true
				}
			}
		case EventRangeEnd:
			r := ev.Range()
			if handleSTW(r) {
				stw--
			} else if handleSweep(r) {
				ps[ev.Proc()].gc--
			} else if handleMarkAssist(r) {
				ps[ev.Proc()].gc--
				if g := r.Scope.Goroutine(); g != NoGoroutine {
					delete(inGC, g)
				}
			}
		case EventStateTransition:
			st := ev.StateTransition()
			if st.Resource.Kind != ResourceGoroutine {
				break
			}
			old, new := st.Goroutine()
			g := st.Resource.Goroutine()
			if inGC[g] || bgMark[g] {
				if !old.Executing() && new.Executing() {
					// Started running while doing GC things.
					ps[ev.Proc()].gc++
				} else if old.Executing() && !new.Executing() {
					// Stopped running while doing GC things.
					ps[ev.Proc()].gc--
				}
			}
			states[g] = new
		case EventLabel:
			l := ev.Label()
			if flags&UtilBackground != 0 && strings.HasPrefix(l.Label, "GC ") && l.Label != "GC (idle)" {
				// Background mark worker.
				//
				// If we're in per-proc mode, we don't
				// count dedicated workers because
				// they kick all of the goroutines off
				// that P, so don't directly
				// contribute to goroutine latency.
				if !(flags&UtilPerProc != 0 && l.Label == "GC (dedicated)") {
					bgMark[ev.Goroutine()] = true
					ps[ev.Proc()].gc++
				}
			}
		}

		if flags&UtilPerProc == 0 {
			// Compute the current average utilization.
			if len(ps) == 0 {
				continue
			}
			gcPs := 0
			if stw > 0 {
				gcPs = len(ps)
			} else {
				for i := range ps {
					if ps[i].gc > 0 {
						gcPs++
					}
				}
			}
			mu := MutatorUtil{int64(ev.Time()), 1 - float64(gcPs)/float64(len(ps))}

			// Record the utilization change. (Since
			// len(ps) == len(out), we know len(out) > 0.)
			out[0] = addUtil(out[0], mu)
		} else {
			// Check for per-P utilization changes.
			for i := range ps {
				p := &ps[i]
				util := 1.0
				if stw > 0 || p.gc > 0 {
					util = 0.0
				}
				out[p.series] = addUtil(out[p.series], MutatorUtil{int64(ev.Time()), util})
			}
		}
	}

	// No events in the stream.
	if lastEv == nil {
		return nil
	}

	// Add final 0 utilization event to any remaining series. This
	// is important to mark the end of the trace. The exact value
	// shouldn't matter since no window should extend beyond this,
	// but using 0 is symmetric with the start of the trace.
	mu := MutatorUtil{int64(lastEv.Time()), 0}
	for i := range ps {
		out[ps[i].series] = addUtil(out[ps[i].series], mu)
	}
	return out
}

func addUtil(util []MutatorUtil, mu MutatorUtil) []MutatorUtil {
	if len(util) > 0 {
		if mu.Util == util[len(util)-1].Util {
			// No change.
			return util
		}
		if mu.Time == util[len(util)-1].Time {
			// Take the lowest utilization at a time stamp.
			if mu.Util < util[len(util)-1].Util {
				util[len(util)-1] = mu
			}
			return util
		}
	}
	return append(util, mu)
}

// totalUtil is total utilization, measured in nanoseconds. This is a
// separate type primarily to distinguish it from mean utilization,
// which is also a float64.
type totalUtil float64

func totalUtilOf(meanUtil float64, dur int64) totalUtil {
	return totalUtil(meanUtil * float64(dur))
}

// mean returns the mean utilization over dur.
func (u totalUtil) mean(dur time.Duration) float64 {
	return float64(u) / float64(dur)
}

// An MMUCurve is the minimum mutator utilization curve across
// multiple window sizes.
type MMUCurve struct {
	series []mmuSeries
}

type mmuSeries struct {
	util []MutatorUtil
	// sums[j] is the cumulative sum of util[:j].
	sums []totalUtil
	// bands summarizes util in non-overlapping bands of duration
	// bandDur.
	bands []mmuBand
	// bandDur is the duration of each band.
	bandDur int64
}

type mmuBand struct {
	// minUtil is the minimum instantaneous mutator utilization in
	// this band.
	minUtil float64
	// cumUtil is the cumulative total mutator utilization between
	// time 0 and the left edge of this band.
	cumUtil totalUtil

	// integrator is the integrator for the left edge of this
	// band.
	integrator integrator
}

// NewMMUCurve returns an MMU curve for the given mutator utilization
// function.
func NewMMUCurve(utils [][]MutatorUtil) *MMUCurve {
	series := make([]mmuSeries, len(utils))
	for i, util := range utils {
		series[i] = newMMUSeries(util)
	}
	return &MMUCurve{series}
}

// bandsPerSeries is the number of bands to divide each series into.
// This is only changed by tests.
var bandsPerSeries = 1000

func newMMUSeries(util []MutatorUtil) mmuSeries {
	// Compute cumulative sum.
	sums := make([]totalUtil, len(util))
	var prev MutatorUtil
	var sum totalUtil
	for j, u := range util {
		sum += totalUtilOf(prev.Util, u.Time-prev.Time)
		sums[j] = sum
		prev = u
	}

	// Divide the utilization curve up into equal size
	// non-overlapping "bands" and compute a summary for each of
	// these bands.
	//
	// Compute the duration of each band.
	numBands := bandsPerSeries
	if numBands > len(util) {
		// There's no point in having lots of bands if there
		// aren't many events.
		numBands = len(util)
	}
	dur := util[len(util)-1].Time - util[0].Time
	bandDur := (dur + int64(numBands) - 1) / int64(numBands)
	if bandDur < 1 {
		bandDur = 1
	}
	// Compute the bands. There are numBands+1 bands in order to
	// record the final cumulative sum.
	bands := make([]mmuBand, numBands+1)
	s := mmuSeries{util, sums, bands, bandDur}
	leftSum := integrator{&s, 0}
	for i := range bands {
		startTime, endTime := s.bandTime(i)
		cumUtil := leftSum.advance(startTime)
		predIdx := leftSum.pos
		minUtil := 1.0
		for i := predIdx; i < len(util) && util[i].Time < endTime; i++ {
			minUtil = math.Min(minUtil, util[i].Util)
		}
		bands[i] = mmuBand{minUtil, cumUtil, leftSum}
	}

	return s
}

func (s *mmuSeries) bandTime(i int) (start, end int64) {
	start = int64(i)*s.bandDur + s.util[0].Time
	end = start + s.bandDur
	return
}

type bandUtil struct {
	// Utilization series index
	series int
	// Band index
	i int
	// Lower bound of mutator utilization for all windows
	// with a left edge in this band.
	utilBound float64
}

type bandUtilHeap []bandUtil

func (h bandUtilHeap) Len() int {
	return len(h)
}

func (h bandUtilHeap) Less(i, j int) bool {
	return h[i].utilBound < h[j].utilBound
}

func (h bandUtilHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *bandUtilHeap) Push(x any) {
	*h = append(*h, x.(bandUtil))
}

func (h *bandUtilHeap) Pop() any {
	x := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return x
}

// UtilWindow is a specific window at Time.
type UtilWindow struct {
	Time int64
	// MutatorUtil is the mean mutator utilization in this window.
	MutatorUtil float64
}

type utilHeap []UtilWindow

func (h utilHeap) Len() int {
	return len(h)
}

func (h utilHeap) Less(i, j int) bool {
	if h[i].MutatorUtil != h[j].MutatorUtil {
		return h[i].MutatorUtil > h[j].MutatorUtil
	}
	return h[i].Time > h[j].Time
}

func (h utilHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *utilHeap) Push(x any) {
	*h = append(*h, x.(UtilWindow))
}

func (h *utilHeap) Pop() any {
	x := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return x
}

// An accumulator takes a windowed mutator utilization function and
// tracks various statistics for that function.
type accumulator struct {
	mmu float64

	// bound is the mutator utilization bound where adding any
	// mutator utilization above this bound cannot affect the
	// accumulated statistics.
	bound float64

	// Worst N window tracking
	nWorst int
	wHeap  utilHeap

	// Mutator utilization distribution tracking
	mud *mud
	// preciseMass is the distribution mass that must be precise
	// before accumulation is stopped.
	preciseMass float64
	// lastTime and lastMU are the previous point added to the
	// windowed mutator utilization function.
	lastTime int64
	lastMU   float64
}

// resetTime declares a discontinuity in the windowed mutator
// utilization function by resetting the current time.
func (acc *accumulator) resetTime() {
	// This only matters for distribution collection, since that's
	// the only thing that depends on the progression of the
	// windowed mutator utilization function.
	acc.lastTime = math.MaxInt64
}

// addMU adds a point to the windowed mutator utilization function at
// (time, mu). This must be called for monotonically increasing values
// of time.
//
// It returns true if further calls to addMU would be pointless.
func (acc *accumulator) addMU(time int64, mu float64, window time.Duration) bool {
	if mu < acc.mmu {
		acc.mmu = mu
	}
	acc.bound = acc.mmu

	if acc.nWorst == 0 {
		// If the minimum has reached zero, it can't go any
		// lower, so we can stop early.
		return mu == 0
	}

	// Consider adding this window to the n worst.
	if len(acc.wHeap) < acc.nWorst || mu < acc.wHeap[0].MutatorUtil {
		// This window is lower than the K'th worst window.
		//
		// Check if there's any overlapping window
		// already in the heap and keep whichever is
		// worse.
		for i, ui := range acc.wHeap {
			if time+int64(window) > ui.Time && ui.Time+int64(window) > time {
				if ui.MutatorUtil <= mu {
					// Keep the first window.
					goto keep
				} else {
					// Replace it with this window.
					heap.Remove(&acc.wHeap, i)
					break
				}
			}
		}

		heap.Push(&acc.wHeap, UtilWindow{time, mu})
		if len(acc.wHeap) > acc.nWorst {
			heap.Pop(&acc.wHeap)
		}
	keep:
	}

	if len(acc.wHeap) < acc.nWorst {
		// We don't have N windows yet, so keep accumulating.
		acc.bound = 1.0
	} else {
		// Anything above the least worst window has no effect.
		acc.bound = math.Max(acc.bound, acc.wHeap[0].MutatorUtil)
	}

	if acc.mud != nil {
		if acc.lastTime != math.MaxInt64 {
			// Update distribution.
			acc.mud.add(acc.lastMU, mu, float64(time-acc.lastTime))
		}
		acc.lastTime, acc.lastMU = time, mu
		if _, mudBound, ok := acc.mud.approxInvCumulativeSum(); ok {
			acc.bound = math.Max(acc.bound, mudBound)
		} else {
			// We haven't accumulated enough total precise
			// mass yet to even reach our goal, so keep
			// accumulating.
			acc.bound = 1
		}
		// It's not worth checking percentiles every time, so
		// just keep accumulating this band.
		return false
	}

	// If we've found enough 0 utilizations, we can stop immediately.
	return len(acc.wHeap) == acc.nWorst && acc.wHeap[0].MutatorUtil == 0
}

// MMU returns the minimum mutator utilization for the given time
// window. This is the minimum utilization for all windows of this
// duration across the execution. The returned value is in the range
// [0, 1].
func (c *MMUCurve) MMU(window time.Duration) (mmu float64) {
	acc := accumulator{mmu: 1.0, bound: 1.0}
	c.mmu(window, &acc)
	return acc.mmu
}

// Examples returns n specific examples of the lowest mutator
// utilization for the given window size. The returned windows will be
// disjoint (otherwise there would be a huge number of
// mostly-overlapping windows at the single lowest point). There are
// no guarantees on which set of disjoint windows this returns.
func (c *MMUCurve) Examples(window time.Duration, n int) (worst []UtilWindow) {
	acc := accumulator{mmu: 1.0, bound: 1.0, nWorst: n}
	c.mmu(window, &acc)
	sort.Sort(sort.Reverse(acc.wHeap))
	return ([]UtilWindow)(acc.wHeap)
}

// MUD returns mutator utilization distribution quantiles for the
// given window size.
//
// The mutator utilization distribution is the distribution of mean
// mutator utilization across all windows of the given window size in
// the trace.
//
// The minimum mutator utilization is the minimum (0th percentile) of
// this distribution. (However, if only the minimum is desired, it's
// more efficient to use the MMU method.)
func (c *MMUCurve) MUD(window time.Duration, quantiles []float64) []float64 {
	if len(quantiles) == 0 {
		return []float64{}
	}

	// Each unrefined band contributes a known total mass to the
	// distribution (bandDur except at the end), but in an unknown
	// way. However, we know that all the mass it contributes must
	// be at or above its worst-case mean mutator utilization.
	//
	// Hence, we refine bands until the highest desired
	// distribution quantile is less than the next worst-case mean
	// mutator utilization. At this point, all further
	// contributions to the distribution must be beyond the
	// desired quantile and hence cannot affect it.
	//
	// First, find the highest desired distribution quantile.
	maxQ := quantiles[0]
	for _, q := range quantiles {
		if q > maxQ {
			maxQ = q
		}
	}
	// The distribution's mass is in units of time (it's not
	// normalized because this would make it more annoying to
	// account for future contributions of unrefined bands). The
	// total final mass will be the duration of the trace itself
	// minus the window size. Using this, we can compute the mass
	// corresponding to quantile maxQ.
	var duration int64
	for _, s := range c.series {
		duration1 := s.util[len(s.util)-1].Time - s.util[0].Time
		if duration1 >= int64(window) {
			duration += duration1 - int64(window)
		}
	}
	qMass := float64(duration) * maxQ

	// Accumulate the MUD until we have precise information for
	// everything to the left of qMass.
	acc := accumulator{mmu: 1.0, bound: 1.0, preciseMass: qMass, mud: new(mud)}
	acc.mud.setTrackMass(qMass)
	c.mmu(window, &acc)

	// Evaluate the quantiles on the accumulated MUD.
	out := make([]float64, len(quantiles))
	for i := range out {
		mu, _ := acc.mud.invCumulativeSum(float64(duration) * quantiles[i])
		if math.IsNaN(mu) {
			// There are a few legitimate ways this can
			// happen:
			//
			// 1. If the window is the full trace
			// duration, then the windowed MU function is
			// only defined at a single point, so the MU
			// distribution is not well-defined.
			//
			// 2. If there are no events, then the MU
			// distribution has no mass.
			//
			// Either way, all of the quantiles will have
			// converged toward the MMU at this point.
			mu = acc.mmu
		}
		out[i] = mu
	}
	return out
}

func (c *MMUCurve) mmu(window time.Duration, acc *accumulator) {
	if window <= 0 {
		acc.mmu = 0
		return
	}

	var bandU bandUtilHeap
	windows := make([]time.Duration, len(c.series))
	for i, s := range c.series {
		windows[i] = window
		if max := time.Duration(s.util[len(s.util)-1].Time - s.util[0].Time); window > max {
			windows[i] = max
		}

		bandU1 := bandUtilHeap(s.mkBandUtil(i, windows[i]))
		if bandU == nil {
			bandU = bandU1
		} else {
			bandU = append(bandU, bandU1...)
		}
	}

	// Process bands from lowest utilization bound to highest.
	heap.Init(&bandU)

	// Refine each band into a precise window and MMU until
	// refining the next lowest band can no longer affect the MMU
	// or windows.
	for len(bandU) > 0 && bandU[0].utilBound < acc.bound {
		i := bandU[0].series
		c.series[i].bandMMU(bandU[0].i, windows[i], acc)
		heap.Pop(&bandU)
	}
}

func (c *mmuSeries) mkBandUtil(series int, window time.Duration) []bandUtil {
	// For each band, compute the worst-possible total mutator
	// utilization for all windows that start in that band.

	// minBands is the minimum number of bands a window can span
	// and maxBands is the maximum number of bands a window can
	// span in any alignment.
	minBands := int((int64(window) + c.bandDur - 1) / c.bandDur)
	maxBands := int((int64(window) + 2*(c.bandDur-1)) / c.bandDur)
	if window > 1 && maxBands < 2 {
		panic("maxBands < 2")
	}
	tailDur := int64(window) % c.bandDur
	nUtil := len(c.bands) - maxBands + 1
	if nUtil < 0 {
		nUtil = 0
	}
	bandU := make([]bandUtil, nUtil)
	for i := range bandU {
		// To compute the worst-case MU, we assume the minimum
		// for any bands that are only partially overlapped by
		// some window and the mean for any bands that are
		// completely covered by all windows.
		var util totalUtil

		// Find the lowest and second lowest of the partial
		// bands.
		l := c.bands[i].minUtil
		r1 := c.bands[i+minBands-1].minUtil
		r2 := c.bands[i+maxBands-1].minUtil
		minBand := math.Min(l, math.Min(r1, r2))
		// Assume the worst window maximally overlaps the
		// worst minimum and then the rest overlaps the second
		// worst minimum.
		if minBands == 1 {
			util += totalUtilOf(minBand, int64(window))
		} else {
			util += totalUtilOf(minBand, c.bandDur)
			midBand := 0.0
			switch {
			case minBand == l:
				midBand = math.Min(r1, r2)
			case minBand == r1:
				midBand = math.Min(l, r2)
			case minBand == r2:
				midBand = math.Min(l, r1)
			}
			util += totalUtilOf(midBand, tailDur)
		}

		// Add the total mean MU of bands that are completely
		// overlapped by all windows.
		if minBands > 2 {
			util += c.bands[i+minBands-1].cumUtil - c.bands[i+1].cumUtil
		}

		bandU[i] = bandUtil{series, i, util.mean(window)}
	}

	return bandU
}

// bandMMU computes the precise minimum mutator utilization for
// windows with a left edge in band bandIdx.
func (c *mmuSeries) bandMMU(bandIdx int, window time.Duration, acc *accumulator) {
	util := c.util

	// We think of the mutator utilization over time as the
	// box-filtered utilization function, which we call the
	// "windowed mutator utilization function". The resulting
	// function is continuous and piecewise linear (unless
	// window==0, which we handle elsewhere), where the boundaries
	// between segments occur when either edge of the window
	// encounters a change in the instantaneous mutator
	// utilization function. Hence, the minimum of this function
	// will always occur when one of the edges of the window
	// aligns with a utilization change, so these are the only
	// points we need to consider.
	//
	// We compute the mutator utilization function incrementally
	// by tracking the integral from t=0 to the left edge of the
	// window and to the right edge of the window.
	left := c.bands[bandIdx].integrator
	right := left
	time, endTime := c.bandTime(bandIdx)
	if utilEnd := util[len(util)-1].Time - int64(window); utilEnd < endTime {
		endTime = utilEnd
	}
	acc.resetTime()
	for {
		// Advance edges to time and time+window.
		mu := (right.advance(time+int64(window)) - left.advance(time)).mean(window)
		if acc.addMU(time, mu, window) {
			break
		}
		if time == endTime {
			break
		}

		// The maximum slope of the windowed mutator
		// utilization function is 1/window, so we can always
		// advance the time by at least (mu - mmu) * window
		// without dropping below mmu.
		minTime := time + int64((mu-acc.bound)*float64(window))

		// Advance the window to the next time where either
		// the left or right edge of the window encounters a
		// change in the utilization curve.
		if t1, t2 := left.next(time), right.next(time+int64(window))-int64(window); t1 < t2 {
			time = t1
		} else {
			time = t2
		}
		if time < minTime {
			time = minTime
		}
		if time >= endTime {
			// For MMUs we could stop here, but for MUDs
			// it's important that we span the entire
			// band.
			time = endTime
		}
	}
}

// An integrator tracks a position in a utilization function and
// integrates it.
type integrator struct {
	u *mmuSeries
	// pos is the index in u.util of the current time's non-strict
	// predecessor.
	pos int
}

// advance returns the integral of the utilization function from 0 to
// time. advance must be called on monotonically increasing values of
// times.
func (in *integrator) advance(time int64) totalUtil {
	util, pos := in.u.util, in.pos
	// Advance pos until pos+1 is time's strict successor (making
	// pos time's non-strict predecessor).
	//
	// Very often, this will be nearby, so we optimize that case,
	// but it may be arbitrarily far away, so we handled that
	// efficiently, too.
	const maxSeq = 8
	if pos+maxSeq < len(util) && util[pos+maxSeq].Time > time {
		// Nearby. Use a linear scan.
		for pos+1 < len(util) && util[pos+1].Time <= time {
			pos++
		}
	} else {
		// Far. Binary search for time's strict successor.
		l, r := pos, len(util)
		for l < r {
			h := int(uint(l+r) >> 1)
			if util[h].Time <= time {
				l = h + 1
			} else {
				r = h
			}
		}
		pos = l - 1 // Non-strict predecessor.
	}
	in.pos = pos
	var partial totalUtil
	if time != util[pos].Time {
		partial = totalUtilOf(util[pos].Util, time-util[pos].Time)
	}
	return in.u.sums[pos] + partial
}

// next returns the smallest time t' > time of a change in the
// utilization function.
func (in *integrator) next(time int64) int64 {
	for _, u := range in.u.util[in.pos:] {
		if u.Time > time {
			return u.Time
		}
	}
	return 1<<63 - 1
}

func isGCSTW(r Range) bool {
	return strings.HasPrefix(r.Name, "stop-the-world") && strings.Contains(r.Name, "GC")
}

func isGCMarkAssist(r Range) bool {
	return r.Name == "GC mark assist"
}

func isGCSweep(r Range) bool {
	return r.Name == "GC incremental sweep"
}
```