Response:
Let's break down the thought process to analyze the provided Go code snippet for `runtime/metrics.go`.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the given Go code. This means identifying what it does, what Go feature it supports, how it works internally, potential issues, and how to use it.

**2. Initial Code Scan - Identifying Key Components:**

I'll start by skimming the code, looking for keywords, data structures, and function names that stand out.

* **Package `runtime`:** This immediately tells me it's a core part of the Go runtime, dealing with low-level operations.
* **Import `internal/godebugs`:** This suggests interaction with internal debugging or feature flags.
* **`metricsSema`:** A semaphore for controlling access, hinting at concurrency control and potential shared state.
* **`metricsInit`, `metrics`:**  Suggests a map holding metric data, initialized lazily.
* **`metricData` struct:** Contains `deps` (dependencies) and `compute` (a function to calculate the metric value). This looks like the core logic for each metric.
* **`metricsLock()`, `metricsUnlock()`:**  Functions for acquiring and releasing the semaphore, confirming the concurrency control.
* **`initMetrics()`:**  Initializes the `metrics` map, defining all the available metrics.
* **Long list of entries in `metrics = map[string]metricData{...}`:**  This is the meat of the functionality - defining specific metrics and how to calculate them. The keys look like metric names (e.g., "/cgo/go-to-c-calls:calls").
* **`statDep`, `statDepSet`:**  Mechanisms for tracking dependencies between metrics and underlying runtime statistics.
* **`heapStatsAggregate`, `sysStatsAggregate`, `cpuStatsAggregate`, `gcStatsAggregate`:** Structures for holding aggregated runtime statistics.
* **`readMetrics()`:**  A function that reads the metrics, suggesting an external interface for accessing them.
* **`//go:linkname`:**  Indicates that these functions are linked to internal runtime/metrics package functions.

**3. Inferring the Overall Functionality:**

Based on these observations, the primary functionality appears to be **exposing runtime metrics**. The code defines a set of named metrics, specifies how to calculate their values based on underlying runtime statistics, and provides a way to read these metrics.

**4. Identifying the Go Feature Implemented:**

The presence of `//go:linkname readMetrics runtime/metrics.runtime_readMetrics` strongly suggests this code implements the functionality of the `runtime/metrics` package. This package allows users to programmatically access various runtime statistics.

**5. Illustrating with Go Code Example:**

To demonstrate the `runtime/metrics` functionality, I need to use the public `runtime/metrics` package. The example should show how to get the available metric names and how to read their values.

```go
package main

import (
	"fmt"
	"runtime/metrics"
)

func main() {
	// Get all available metric descriptions.
	metricsDescriptions := metrics.All()
	fmt.Println("Available Metrics:")
	for _, desc := range metricsDescriptions {
		fmt.Println(desc.Name)
	}

	// Read the value of a specific metric.
	sample := make([]metrics.Sample, 1)
	sample[0].Name = "/gc/heap/allocs:bytes" // Example metric name
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindUint64 {
		fmt.Printf("\nValue of %s: %d bytes\n", sample[0].Name, sample[0].Value.Uint64())
	}
}
```

**6. Reasoning about Code Internals (and Assumptions):**

The `compute` functions within `metricData` are the core logic. I can pick a few examples and explain how they work:

* **`/cgo/go-to-c-calls:calls`:** Directly calls `NumCgoCall()`, indicating this metric tracks the number of CGO calls.
* **`/cpu/classes/gc/mark/assist:cpu-seconds`:**  Relies on `cpuStatsDep`, retrieves `GCAssistTime` from `in.cpuStats`, and converts nanoseconds to seconds. This shows a dependency on CPU statistics and a time conversion.
* **`/gc/heap/allocs-by-size:bytes`:**  Uses `heapStatsDep` and populates a histogram (`float64HistOrInit`) based on allocation sizes. This is more complex, involving bucket creation and distribution of allocation counts. The comment about skipping the first size class is an important detail.

**7. Considering Command-Line Arguments:**

The code itself doesn't directly process command-line arguments. However, it interacts with `internal/godebugs`, which *can* be influenced by environment variables or potentially command-line flags. The example of `GODEBUG` is relevant here.

**8. Identifying Potential Pitfalls:**

* **Incorrect Metric Names:**  Typos are easy to make. The example of trying to read a non-existent metric highlights this.
* **Assuming Metric Types:**  Users need to check the `Kind()` of the metric value before accessing it (e.g., `Uint64()`, `Float64()`). Trying to access it as the wrong type will lead to errors.

**9. Structuring the Answer:**

Finally, I organize the information into clear sections, addressing each part of the original prompt:

* **功能列举:**  List the high-level functionalities.
* **Go语言功能实现:** Identify `runtime/metrics` and provide a usage example.
* **代码推理:** Explain how specific metrics are calculated, providing input/output assumptions where relevant (though detailed input/output tracing isn't really feasible for this kind of runtime code).
* **命令行参数:** Discuss the indirect influence via `GODEBUG`.
* **易犯错的点:** Give concrete examples of common mistakes.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the low-level details of the locking mechanisms. While important for understanding the code's robustness, the primary goal is the *functionality* it provides to users. I need to balance the level of detail.
* When explaining the code, I should prioritize clarity over replicating the code's internal variable names. Explaining the *purpose* of the code is more important than a line-by-line translation.
* The `go:linkname` directive is a crucial clue for identifying the implemented feature. I should make sure to highlight its significance.
* The example code should be simple and directly demonstrate the core functionality of reading metrics.

By following this systematic approach, combining code observation, logical deduction, and knowledge of Go's runtime and standard library, I can arrive at a comprehensive and accurate explanation of the provided code snippet.
这段代码是 Go 语言运行时环境 `runtime` 包中 `metrics.go` 文件的一部分，它实现了 **runtime/metrics** 包提供的功能。简单来说，它的主要功能是：**收集和暴露 Go 程序的运行时指标 (metrics)**。

更具体地，它可以让你了解 Go 程序的各种内部状态，例如：

* **CPU 使用情况:**  不同类别的 CPU 时间消耗，例如 GC 辅助、GC 专用、空闲、用户等。
* **GC (垃圾回收) 统计:**  GC 周期、扫描的内存量、暂停时间等。
* **堆内存分配情况:**  按大小分类的分配和释放量、总分配和释放量、堆的目标大小等。
* **内存分类:**  堆、元数据、栈、操作系统等不同内存区域的使用情况。
* **调度器统计:**  GOMAXPROCS、Goroutine 数量、调度延迟、STW (Stop-The-World) 暂停时间等。
* **同步原语统计:**  Mutex 等待的总时间。
* **CGO 调用统计:**  Go 调用 C 的次数。
* **godebug 设置:**  非默认的 `godebug` 设置。

**以下是对其功能的详细解释和代码示例：**

**1. 指标的定义和存储:**

* 代码中定义了一个名为 `metrics` 的全局 `map[string]metricData`，用于存储所有可用的运行时指标。
* `metricData` 结构体定义了每个指标的元数据，包括：
    * `deps`:  该指标依赖的运行时统计数据集合 (`statDepSet`)。
    * `compute`:  一个函数，用于根据提供的运行时统计数据 (`statAggregate`) 计算指标的值 (`metricValue`)。

**2. 指标的初始化 (`initMetrics` 函数):**

* `initMetrics` 函数负责初始化 `metrics` map。它在首次需要访问指标时被调用。
* 它定义了各种各样的指标，并将它们添加到 `metrics` map 中。每个指标都关联着一个唯一的名称 (例如 `"/gc/heap/allocs:bytes"`) 和一个 `compute` 函数。
* 例如，对于指标 `"/cgo/go-to-c-calls:calls"`，其 `compute` 函数直接调用 `NumCgoCall()` 函数来获取 CGO 调用的次数。
* 对于更复杂的指标，例如 `"/cpu/classes/gc/mark/assist:cpu-seconds"`，其 `compute` 函数会从 `statAggregate` 中获取 CPU 统计信息，并提取 GC 辅助时间。

**3. 运行时统计数据的聚合 (`statAggregate` 结构体):**

* `statAggregate` 结构体用于存储从运行时收集的不同类别的统计数据，例如堆内存统计 (`heapStatsAggregate`)、系统内存统计 (`sysStatsAggregate`)、CPU 统计 (`cpuStatsAggregate`) 和 GC 统计 (`gcStatsAggregate`)。
* `ensure` 方法允许按需加载所需的统计数据。只有当某个指标依赖的统计数据尚未加载时，才会调用相应的 `compute` 方法来填充 `statAggregate`。

**4. 读取指标 (`readMetrics` 函数):**

* `readMetrics` 函数是 `runtime/metrics.Read` 函数的运行时实现。它负责读取指定的指标并将其值写入提供的 `metricSample` 切片中。
* 它首先获取 `metricsSema` 锁来保证并发安全。
* 然后，它遍历传入的 `metricSample` 切片，并根据每个样本的名称，从 `metrics` map 中找到对应的 `metricData`。
* 对于找到的指标，它调用 `agg.ensure(&data.deps)` 来确保该指标依赖的运行时统计数据已被加载。
* 最后，它调用 `data.compute(&agg, &sample.value)` 来计算指标的值，并将结果存储在 `sample.value` 中。

**5. 动态注册指标 (`godebug_registerMetric` 函数):**

* `godebug_registerMetric` 函数允许 `internal/godebug` 包动态地注册新的指标。
* 这通常用于暴露一些与调试或实验性功能相关的指标。

**Go 代码示例：**

虽然你无法直接调用 `runtime/metrics.go` 中的内部函数，但你可以使用 **`runtime/metrics`** 包来读取这些指标。

```go
package main

import (
	"fmt"
	"runtime/metrics"
)

func main() {
	// 获取所有可用的指标描述
	metricsDescriptions := metrics.All()
	fmt.Println("可用的指标:")
	for _, desc := range metricsDescriptions {
		fmt.Println(desc.Name)
	}

	// 读取特定指标的值
	samples := make([]metrics.Sample, 1)
	samples[0].Name = "/gc/heap/allocs:bytes" // 示例指标名称
	metrics.Read(samples)

	if samples[0].Value.Kind() == metrics.KindUint64 {
		fmt.Printf("\n指标 '%s' 的值为: %d 字节\n", samples[0].Name, samples[0].Value.Uint64())
	}
}
```

**假设的输入与输出：**

假设运行上述代码，并且堆内存分配了一些数据，则输出可能如下所示：

```
可用的指标:
/cgo/go-to-c-calls:calls
/cpu/classes/gc/mark/assist:cpu-seconds
/cpu/classes/gc/mark/dedicated:cpu-seconds
/cpu/classes/gc/mark/idle:cpu-seconds
/cpu/classes/gc/pause:cpu-seconds
/cpu/classes/gc/total:cpu-seconds
/cpu/classes/idle:cpu-seconds
/cpu/classes/scavenge/assist:cpu-seconds
/cpu/classes/scavenge/background:cpu-seconds
/cpu/classes/scavenge/total:cpu-seconds
/cpu/classes/total:cpu-seconds
/cpu/classes/user:cpu-seconds
/gc/cycles/automatic:gc-cycles
/gc/cycles/forced:gc-cycles
/gc/cycles/total:gc-cycles
/gc/scan/globals:bytes
/gc/scan/heap:bytes
/gc/scan/stack:bytes
/gc/scan/total:bytes
/gc/heap/allocs-by-size:bytes
/gc/heap/allocs:bytes
/gc/heap/allocs:objects
/gc/heap/frees-by-size:bytes
/gc/heap/frees:bytes
/gc/heap/frees:objects
/gc/heap/goal:bytes
/gc/gomemlimit:bytes
/gc/gogc:percent
/gc/heap/live:bytes
/gc/heap/objects:objects
/gc/heap/tiny/allocs:objects
/gc/limiter/last-enabled:gc-cycle
/gc/pauses:seconds
/gc/stack/starting-size:bytes
/memory/classes/heap/free:bytes
/memory/classes/heap/objects:bytes
/memory/classes/heap/released:bytes
/memory/classes/heap/stacks:bytes
/memory/classes/heap/unused:bytes
/memory/classes/metadata/mcache/free:bytes
/memory/classes/metadata/mcache/inuse:bytes
/memory/classes/metadata/mspan/free:bytes
/memory/classes/metadata/mspan/inuse:bytes
/memory/classes/metadata/other:bytes
/memory/classes/os-stacks:bytes
/memory/classes/other:bytes
/memory/classes/profiling/buckets:bytes
/memory/classes/total:bytes
/sched/gomaxprocs:threads
/sched/goroutines:goroutines
/sched/latencies:seconds
/sched/pauses/stopping/gc:seconds
/sched/pauses/stopping/other:seconds
/sched/pauses/total/gc:seconds
/sched/pauses/total/other:seconds
/sync/mutex/wait/total:seconds
/godebug/non-default-behavior/cgocheck:events

指标 '/gc/heap/allocs:bytes' 的值为: 12345678 字节
```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。但是，它与 `internal/godebugs` 包交互，而 `godebugs` 包会读取环境变量（通常是 `GODEBUG`）来影响 Go 运行时的行为。

例如，你可以使用 `GODEBUG` 环境变量来启用或禁用某些调试功能，这可能会影响某些指标的值，或者导致新的指标被暴露出来（通过 `godebug_registerMetric`）。

**例如：**

你可以设置 `GODEBUG=cgocheck=1` 来启用 CGO 指针检查，这可能会影响与 CGO 相关的指标。虽然 `metrics.go` 本身不解析 `GODEBUG`，但 `internal/godebugs` 会解析，并且 `metrics.go` 会通过 `godebug_registerMetric` 暴露与这些调试设置相关的指标。

**使用者易犯错的点：**

* **不了解指标的含义:** 错误地理解指标的含义会导致错误的性能分析和优化。例如，混淆“分配的内存”和“正在使用的内存”。
* **假设指标的类型:**  在读取指标值之前，应该检查其类型 (`Value.Kind()`)，以避免类型断言错误。例如，假设某个指标是 `uint64` 但实际上是 `float64`。
* **频繁读取大量指标:**  频繁地读取大量的运行时指标可能会带来一定的性能开销，尤其是在高负载的应用程序中。应该谨慎选择需要监控的指标。
* **直接访问内部指标名称:** 开发者应该使用 `runtime/metrics` 包提供的 API 来访问指标，而不是尝试硬编码或假设内部的指标名称，因为这些名称可能会在 Go 的未来版本中发生变化。
* **忽略指标的时间属性:** 某些指标是瞬时值，而另一些是累积值。理解指标的时间属性对于正确分析数据至关重要。例如，`/gc/pauses:seconds` 是一个累积值，表示总的 GC 暂停时间。

总而言之，`go/src/runtime/metrics.go` 是 Go 运行时环境的关键组成部分，它负责收集和暴露程序运行时的各种内部状态，为开发者提供了强大的监控和诊断工具。理解其功能对于进行有效的 Go 程序性能分析和优化至关重要。

### 提示词
```
这是路径为go/src/runtime/metrics.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

// Metrics implementation exported to runtime/metrics.

import (
	"internal/godebugs"
	"unsafe"
)

var (
	// metrics is a map of runtime/metrics keys to data used by the runtime
	// to sample each metric's value. metricsInit indicates it has been
	// initialized.
	//
	// These fields are protected by metricsSema which should be
	// locked/unlocked with metricsLock() / metricsUnlock().
	metricsSema uint32 = 1
	metricsInit bool
	metrics     map[string]metricData

	sizeClassBuckets []float64
	timeHistBuckets  []float64
)

type metricData struct {
	// deps is the set of runtime statistics that this metric
	// depends on. Before compute is called, the statAggregate
	// which will be passed must ensure() these dependencies.
	deps statDepSet

	// compute is a function that populates a metricValue
	// given a populated statAggregate structure.
	compute func(in *statAggregate, out *metricValue)
}

func metricsLock() {
	// Acquire the metricsSema but with handoff. Operations are typically
	// expensive enough that queueing up goroutines and handing off between
	// them will be noticeably better-behaved.
	semacquire1(&metricsSema, true, 0, 0, waitReasonSemacquire)
	if raceenabled {
		raceacquire(unsafe.Pointer(&metricsSema))
	}
}

func metricsUnlock() {
	if raceenabled {
		racerelease(unsafe.Pointer(&metricsSema))
	}
	semrelease(&metricsSema)
}

// initMetrics initializes the metrics map if it hasn't been yet.
//
// metricsSema must be held.
func initMetrics() {
	if metricsInit {
		return
	}

	sizeClassBuckets = make([]float64, _NumSizeClasses, _NumSizeClasses+1)
	// Skip size class 0 which is a stand-in for large objects, but large
	// objects are tracked separately (and they actually get placed in
	// the last bucket, not the first).
	sizeClassBuckets[0] = 1 // The smallest allocation is 1 byte in size.
	for i := 1; i < _NumSizeClasses; i++ {
		// Size classes have an inclusive upper-bound
		// and exclusive lower bound (e.g. 48-byte size class is
		// (32, 48]) whereas we want and inclusive lower-bound
		// and exclusive upper-bound (e.g. 48-byte size class is
		// [33, 49)). We can achieve this by shifting all bucket
		// boundaries up by 1.
		//
		// Also, a float64 can precisely represent integers with
		// value up to 2^53 and size classes are relatively small
		// (nowhere near 2^48 even) so this will give us exact
		// boundaries.
		sizeClassBuckets[i] = float64(class_to_size[i] + 1)
	}
	sizeClassBuckets = append(sizeClassBuckets, float64Inf())

	timeHistBuckets = timeHistogramMetricsBuckets()
	metrics = map[string]metricData{
		"/cgo/go-to-c-calls:calls": {
			compute: func(_ *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(NumCgoCall())
			},
		},
		"/cpu/classes/gc/mark/assist:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.GCAssistTime))
			},
		},
		"/cpu/classes/gc/mark/dedicated:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.GCDedicatedTime))
			},
		},
		"/cpu/classes/gc/mark/idle:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.GCIdleTime))
			},
		},
		"/cpu/classes/gc/pause:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.GCPauseTime))
			},
		},
		"/cpu/classes/gc/total:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.GCTotalTime))
			},
		},
		"/cpu/classes/idle:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.IdleTime))
			},
		},
		"/cpu/classes/scavenge/assist:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.ScavengeAssistTime))
			},
		},
		"/cpu/classes/scavenge/background:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.ScavengeBgTime))
			},
		},
		"/cpu/classes/scavenge/total:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.ScavengeTotalTime))
			},
		},
		"/cpu/classes/total:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.TotalTime))
			},
		},
		"/cpu/classes/user:cpu-seconds": {
			deps: makeStatDepSet(cpuStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(in.cpuStats.UserTime))
			},
		},
		"/gc/cycles/automatic:gc-cycles": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.gcCyclesDone - in.sysStats.gcCyclesForced
			},
		},
		"/gc/cycles/forced:gc-cycles": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.gcCyclesForced
			},
		},
		"/gc/cycles/total:gc-cycles": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.gcCyclesDone
			},
		},
		"/gc/scan/globals:bytes": {
			deps: makeStatDepSet(gcStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.gcStats.globalsScan
			},
		},
		"/gc/scan/heap:bytes": {
			deps: makeStatDepSet(gcStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.gcStats.heapScan
			},
		},
		"/gc/scan/stack:bytes": {
			deps: makeStatDepSet(gcStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.gcStats.stackScan
			},
		},
		"/gc/scan/total:bytes": {
			deps: makeStatDepSet(gcStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.gcStats.totalScan
			},
		},
		"/gc/heap/allocs-by-size:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				hist := out.float64HistOrInit(sizeClassBuckets)
				hist.counts[len(hist.counts)-1] = in.heapStats.largeAllocCount
				// Cut off the first index which is ostensibly for size class 0,
				// but large objects are tracked separately so it's actually unused.
				for i, count := range in.heapStats.smallAllocCount[1:] {
					hist.counts[i] = count
				}
			},
		},
		"/gc/heap/allocs:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.totalAllocated
			},
		},
		"/gc/heap/allocs:objects": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.totalAllocs
			},
		},
		"/gc/heap/frees-by-size:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				hist := out.float64HistOrInit(sizeClassBuckets)
				hist.counts[len(hist.counts)-1] = in.heapStats.largeFreeCount
				// Cut off the first index which is ostensibly for size class 0,
				// but large objects are tracked separately so it's actually unused.
				for i, count := range in.heapStats.smallFreeCount[1:] {
					hist.counts[i] = count
				}
			},
		},
		"/gc/heap/frees:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.totalFreed
			},
		},
		"/gc/heap/frees:objects": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.totalFrees
			},
		},
		"/gc/heap/goal:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.heapGoal
			},
		},
		"/gc/gomemlimit:bytes": {
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(gcController.memoryLimit.Load())
			},
		},
		"/gc/gogc:percent": {
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(gcController.gcPercent.Load())
			},
		},
		"/gc/heap/live:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = gcController.heapMarked
			},
		},
		"/gc/heap/objects:objects": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.numObjects
			},
		},
		"/gc/heap/tiny/allocs:objects": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.tinyAllocCount
			},
		},
		"/gc/limiter/last-enabled:gc-cycle": {
			compute: func(_ *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(gcCPULimiter.lastEnabledCycle.Load())
			},
		},
		"/gc/pauses:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				// N.B. this is identical to /sched/pauses/total/gc:seconds.
				sched.stwTotalTimeGC.write(out)
			},
		},
		"/gc/stack/starting-size:bytes": {
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(startingStackSize)
			},
		},
		"/memory/classes/heap/free:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(in.heapStats.committed - in.heapStats.inHeap -
					in.heapStats.inStacks - in.heapStats.inWorkBufs -
					in.heapStats.inPtrScalarBits)
			},
		},
		"/memory/classes/heap/objects:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.heapStats.inObjects
			},
		},
		"/memory/classes/heap/released:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(in.heapStats.released)
			},
		},
		"/memory/classes/heap/stacks:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(in.heapStats.inStacks)
			},
		},
		"/memory/classes/heap/unused:bytes": {
			deps: makeStatDepSet(heapStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(in.heapStats.inHeap) - in.heapStats.inObjects
			},
		},
		"/memory/classes/metadata/mcache/free:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.mCacheSys - in.sysStats.mCacheInUse
			},
		},
		"/memory/classes/metadata/mcache/inuse:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.mCacheInUse
			},
		},
		"/memory/classes/metadata/mspan/free:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.mSpanSys - in.sysStats.mSpanInUse
			},
		},
		"/memory/classes/metadata/mspan/inuse:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.mSpanInUse
			},
		},
		"/memory/classes/metadata/other:bytes": {
			deps: makeStatDepSet(heapStatsDep, sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(in.heapStats.inWorkBufs+in.heapStats.inPtrScalarBits) + in.sysStats.gcMiscSys
			},
		},
		"/memory/classes/os-stacks:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.stacksSys
			},
		},
		"/memory/classes/other:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.otherSys
			},
		},
		"/memory/classes/profiling/buckets:bytes": {
			deps: makeStatDepSet(sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = in.sysStats.buckHashSys
			},
		},
		"/memory/classes/total:bytes": {
			deps: makeStatDepSet(heapStatsDep, sysStatsDep),
			compute: func(in *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(in.heapStats.committed+in.heapStats.released) +
					in.sysStats.stacksSys + in.sysStats.mSpanSys +
					in.sysStats.mCacheSys + in.sysStats.buckHashSys +
					in.sysStats.gcMiscSys + in.sysStats.otherSys
			},
		},
		"/sched/gomaxprocs:threads": {
			compute: func(_ *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(gomaxprocs)
			},
		},
		"/sched/goroutines:goroutines": {
			compute: func(_ *statAggregate, out *metricValue) {
				out.kind = metricKindUint64
				out.scalar = uint64(gcount())
			},
		},
		"/sched/latencies:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				sched.timeToRun.write(out)
			},
		},
		"/sched/pauses/stopping/gc:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				sched.stwStoppingTimeGC.write(out)
			},
		},
		"/sched/pauses/stopping/other:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				sched.stwStoppingTimeOther.write(out)
			},
		},
		"/sched/pauses/total/gc:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				sched.stwTotalTimeGC.write(out)
			},
		},
		"/sched/pauses/total/other:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				sched.stwTotalTimeOther.write(out)
			},
		},
		"/sync/mutex/wait/total:seconds": {
			compute: func(_ *statAggregate, out *metricValue) {
				out.kind = metricKindFloat64
				out.scalar = float64bits(nsToSec(totalMutexWaitTimeNanos()))
			},
		},
	}

	for _, info := range godebugs.All {
		if !info.Opaque {
			metrics["/godebug/non-default-behavior/"+info.Name+":events"] = metricData{compute: compute0}
		}
	}

	metricsInit = true
}

func compute0(_ *statAggregate, out *metricValue) {
	out.kind = metricKindUint64
	out.scalar = 0
}

type metricReader func() uint64

func (f metricReader) compute(_ *statAggregate, out *metricValue) {
	out.kind = metricKindUint64
	out.scalar = f()
}

//go:linkname godebug_registerMetric internal/godebug.registerMetric
func godebug_registerMetric(name string, read func() uint64) {
	metricsLock()
	initMetrics()
	d, ok := metrics[name]
	if !ok {
		throw("runtime: unexpected metric registration for " + name)
	}
	d.compute = metricReader(read).compute
	metrics[name] = d
	metricsUnlock()
}

// statDep is a dependency on a group of statistics
// that a metric might have.
type statDep uint

const (
	heapStatsDep statDep = iota // corresponds to heapStatsAggregate
	sysStatsDep                 // corresponds to sysStatsAggregate
	cpuStatsDep                 // corresponds to cpuStatsAggregate
	gcStatsDep                  // corresponds to gcStatsAggregate
	numStatsDeps
)

// statDepSet represents a set of statDeps.
//
// Under the hood, it's a bitmap.
type statDepSet [1]uint64

// makeStatDepSet creates a new statDepSet from a list of statDeps.
func makeStatDepSet(deps ...statDep) statDepSet {
	var s statDepSet
	for _, d := range deps {
		s[d/64] |= 1 << (d % 64)
	}
	return s
}

// difference returns set difference of s from b as a new set.
func (s statDepSet) difference(b statDepSet) statDepSet {
	var c statDepSet
	for i := range s {
		c[i] = s[i] &^ b[i]
	}
	return c
}

// union returns the union of the two sets as a new set.
func (s statDepSet) union(b statDepSet) statDepSet {
	var c statDepSet
	for i := range s {
		c[i] = s[i] | b[i]
	}
	return c
}

// empty returns true if there are no dependencies in the set.
func (s *statDepSet) empty() bool {
	for _, c := range s {
		if c != 0 {
			return false
		}
	}
	return true
}

// has returns true if the set contains a given statDep.
func (s *statDepSet) has(d statDep) bool {
	return s[d/64]&(1<<(d%64)) != 0
}

// heapStatsAggregate represents memory stats obtained from the
// runtime. This set of stats is grouped together because they
// depend on each other in some way to make sense of the runtime's
// current heap memory use. They're also sharded across Ps, so it
// makes sense to grab them all at once.
type heapStatsAggregate struct {
	heapStatsDelta

	// Derived from values in heapStatsDelta.

	// inObjects is the bytes of memory occupied by objects,
	inObjects uint64

	// numObjects is the number of live objects in the heap.
	numObjects uint64

	// totalAllocated is the total bytes of heap objects allocated
	// over the lifetime of the program.
	totalAllocated uint64

	// totalFreed is the total bytes of heap objects freed
	// over the lifetime of the program.
	totalFreed uint64

	// totalAllocs is the number of heap objects allocated over
	// the lifetime of the program.
	totalAllocs uint64

	// totalFrees is the number of heap objects freed over
	// the lifetime of the program.
	totalFrees uint64
}

// compute populates the heapStatsAggregate with values from the runtime.
func (a *heapStatsAggregate) compute() {
	memstats.heapStats.read(&a.heapStatsDelta)

	// Calculate derived stats.
	a.totalAllocs = a.largeAllocCount
	a.totalFrees = a.largeFreeCount
	a.totalAllocated = a.largeAlloc
	a.totalFreed = a.largeFree
	for i := range a.smallAllocCount {
		na := a.smallAllocCount[i]
		nf := a.smallFreeCount[i]
		a.totalAllocs += na
		a.totalFrees += nf
		a.totalAllocated += na * uint64(class_to_size[i])
		a.totalFreed += nf * uint64(class_to_size[i])
	}
	a.inObjects = a.totalAllocated - a.totalFreed
	a.numObjects = a.totalAllocs - a.totalFrees
}

// sysStatsAggregate represents system memory stats obtained
// from the runtime. This set of stats is grouped together because
// they're all relatively cheap to acquire and generally independent
// of one another and other runtime memory stats. The fact that they
// may be acquired at different times, especially with respect to
// heapStatsAggregate, means there could be some skew, but because of
// these stats are independent, there's no real consistency issue here.
type sysStatsAggregate struct {
	stacksSys      uint64
	mSpanSys       uint64
	mSpanInUse     uint64
	mCacheSys      uint64
	mCacheInUse    uint64
	buckHashSys    uint64
	gcMiscSys      uint64
	otherSys       uint64
	heapGoal       uint64
	gcCyclesDone   uint64
	gcCyclesForced uint64
}

// compute populates the sysStatsAggregate with values from the runtime.
func (a *sysStatsAggregate) compute() {
	a.stacksSys = memstats.stacks_sys.load()
	a.buckHashSys = memstats.buckhash_sys.load()
	a.gcMiscSys = memstats.gcMiscSys.load()
	a.otherSys = memstats.other_sys.load()
	a.heapGoal = gcController.heapGoal()
	a.gcCyclesDone = uint64(memstats.numgc)
	a.gcCyclesForced = uint64(memstats.numforcedgc)

	systemstack(func() {
		lock(&mheap_.lock)
		a.mSpanSys = memstats.mspan_sys.load()
		a.mSpanInUse = uint64(mheap_.spanalloc.inuse)
		a.mCacheSys = memstats.mcache_sys.load()
		a.mCacheInUse = uint64(mheap_.cachealloc.inuse)
		unlock(&mheap_.lock)
	})
}

// cpuStatsAggregate represents CPU stats obtained from the runtime
// acquired together to avoid skew and inconsistencies.
type cpuStatsAggregate struct {
	cpuStats
}

// compute populates the cpuStatsAggregate with values from the runtime.
func (a *cpuStatsAggregate) compute() {
	a.cpuStats = work.cpuStats
	// TODO(mknyszek): Update the CPU stats again so that we're not
	// just relying on the STW snapshot. The issue here is that currently
	// this will cause non-monotonicity in the "user" CPU time metric.
	//
	// a.cpuStats.accumulate(nanotime(), gcphase == _GCmark)
}

// gcStatsAggregate represents various GC stats obtained from the runtime
// acquired together to avoid skew and inconsistencies.
type gcStatsAggregate struct {
	heapScan    uint64
	stackScan   uint64
	globalsScan uint64
	totalScan   uint64
}

// compute populates the gcStatsAggregate with values from the runtime.
func (a *gcStatsAggregate) compute() {
	a.heapScan = gcController.heapScan.Load()
	a.stackScan = gcController.lastStackScan.Load()
	a.globalsScan = gcController.globalsScan.Load()
	a.totalScan = a.heapScan + a.stackScan + a.globalsScan
}

// nsToSec takes a duration in nanoseconds and converts it to seconds as
// a float64.
func nsToSec(ns int64) float64 {
	return float64(ns) / 1e9
}

// statAggregate is the main driver of the metrics implementation.
//
// It contains multiple aggregates of runtime statistics, as well
// as a set of these aggregates that it has populated. The aggregates
// are populated lazily by its ensure method.
type statAggregate struct {
	ensured   statDepSet
	heapStats heapStatsAggregate
	sysStats  sysStatsAggregate
	cpuStats  cpuStatsAggregate
	gcStats   gcStatsAggregate
}

// ensure populates statistics aggregates determined by deps if they
// haven't yet been populated.
func (a *statAggregate) ensure(deps *statDepSet) {
	missing := deps.difference(a.ensured)
	if missing.empty() {
		return
	}
	for i := statDep(0); i < numStatsDeps; i++ {
		if !missing.has(i) {
			continue
		}
		switch i {
		case heapStatsDep:
			a.heapStats.compute()
		case sysStatsDep:
			a.sysStats.compute()
		case cpuStatsDep:
			a.cpuStats.compute()
		case gcStatsDep:
			a.gcStats.compute()
		}
	}
	a.ensured = a.ensured.union(missing)
}

// metricKind is a runtime copy of runtime/metrics.ValueKind and
// must be kept structurally identical to that type.
type metricKind int

const (
	// These values must be kept identical to their corresponding Kind* values
	// in the runtime/metrics package.
	metricKindBad metricKind = iota
	metricKindUint64
	metricKindFloat64
	metricKindFloat64Histogram
)

// metricSample is a runtime copy of runtime/metrics.Sample and
// must be kept structurally identical to that type.
type metricSample struct {
	name  string
	value metricValue
}

// metricValue is a runtime copy of runtime/metrics.Sample and
// must be kept structurally identical to that type.
type metricValue struct {
	kind    metricKind
	scalar  uint64         // contains scalar values for scalar Kinds.
	pointer unsafe.Pointer // contains non-scalar values.
}

// float64HistOrInit tries to pull out an existing float64Histogram
// from the value, but if none exists, then it allocates one with
// the given buckets.
func (v *metricValue) float64HistOrInit(buckets []float64) *metricFloat64Histogram {
	var hist *metricFloat64Histogram
	if v.kind == metricKindFloat64Histogram && v.pointer != nil {
		hist = (*metricFloat64Histogram)(v.pointer)
	} else {
		v.kind = metricKindFloat64Histogram
		hist = new(metricFloat64Histogram)
		v.pointer = unsafe.Pointer(hist)
	}
	hist.buckets = buckets
	if len(hist.counts) != len(hist.buckets)-1 {
		hist.counts = make([]uint64, len(buckets)-1)
	}
	return hist
}

// metricFloat64Histogram is a runtime copy of runtime/metrics.Float64Histogram
// and must be kept structurally identical to that type.
type metricFloat64Histogram struct {
	counts  []uint64
	buckets []float64
}

// agg is used by readMetrics, and is protected by metricsSema.
//
// Managed as a global variable because its pointer will be
// an argument to a dynamically-defined function, and we'd
// like to avoid it escaping to the heap.
var agg statAggregate

type metricName struct {
	name string
	kind metricKind
}

// readMetricNames is the implementation of runtime/metrics.readMetricNames,
// used by the runtime/metrics test and otherwise unreferenced.
//
//go:linkname readMetricNames runtime/metrics_test.runtime_readMetricNames
func readMetricNames() []string {
	metricsLock()
	initMetrics()
	n := len(metrics)
	metricsUnlock()

	list := make([]string, 0, n)

	metricsLock()
	for name := range metrics {
		list = append(list, name)
	}
	metricsUnlock()

	return list
}

// readMetrics is the implementation of runtime/metrics.Read.
//
//go:linkname readMetrics runtime/metrics.runtime_readMetrics
func readMetrics(samplesp unsafe.Pointer, len int, cap int) {
	metricsLock()

	// Ensure the map is initialized.
	initMetrics()

	// Read the metrics.
	readMetricsLocked(samplesp, len, cap)
	metricsUnlock()
}

// readMetricsLocked is the internal, locked portion of readMetrics.
//
// Broken out for more robust testing. metricsLock must be held and
// initMetrics must have been called already.
func readMetricsLocked(samplesp unsafe.Pointer, len int, cap int) {
	// Construct a slice from the args.
	sl := slice{samplesp, len, cap}
	samples := *(*[]metricSample)(unsafe.Pointer(&sl))

	// Clear agg defensively.
	agg = statAggregate{}

	// Sample.
	for i := range samples {
		sample := &samples[i]
		data, ok := metrics[sample.name]
		if !ok {
			sample.value.kind = metricKindBad
			continue
		}
		// Ensure we have all the stats we need.
		// agg is populated lazily.
		agg.ensure(&data.deps)

		// Compute the value based on the stats we have.
		data.compute(&agg, &sample.value)
	}
}
```