Response:
Let's break down the thought process for answering the request about `description.go`.

**1. Understanding the Core Request:**

The primary goal is to understand the *functionality* of the provided Go code snippet. The request also asks for specific elaborations: Go feature implementation, code examples, command-line arguments (if applicable), and common mistakes. It emphasizes answering in Chinese.

**2. Initial Code Scan and Interpretation:**

* **Package and Imports:** The code belongs to the `runtime/metrics` package and imports `internal/godebugs`. This immediately suggests it's related to gathering and describing runtime performance or diagnostic data. The `godebugs` import hints at integration with the `GODEBUG` environment variable.
* **`Description` struct:** This is the central data structure. Its fields (`Name`, `Description`, `Kind`, `Cumulative`) clearly define the attributes of a runtime metric. The comments within the `Name` field provide a crucial understanding of the metric naming convention.
* **`allDesc` variable:** This is a slice of `Description` structs. It's populated with many concrete metric descriptions. This confirms the suspicion that the file defines the available runtime metrics.
* **`init()` function:** This function modifies `allDesc`. It iterates through `godebugs.All` and adds descriptions for non-default `GODEBUG` settings. This reinforces the connection to runtime configuration.
* **`All()` function:** This simple function returns the `allDesc` slice, making the metric descriptions accessible.

**3. Identifying Key Functionalities:**

Based on the code and initial interpretations, the core functionalities are:

* **Defining Metric Structure:** The `Description` struct provides a standardized way to represent runtime metrics.
* **Listing Available Metrics:** The `allDesc` variable and `All()` function provide a catalog of supported metrics.
* **Describing Metrics:** The `Description` struct includes a human-readable description for each metric.
* **Categorizing Metric Types:** The `Kind` field indicates the data type of the metric.
* **Specifying Metric Behavior:** The `Cumulative` field distinguishes between metrics that accumulate and those that represent a point-in-time value.
* **Integrating with `GODEBUG`:** The `init()` function dynamically adds metrics related to non-default `GODEBUG` settings.

**4. Reasoning about Go Feature Implementation:**

The code directly implements the concept of **runtime metrics**. This is a built-in feature of Go that allows applications to monitor the performance and behavior of the Go runtime itself. This implementation focuses on *describing* these metrics, which is a crucial part of a metrics system.

**5. Crafting the Code Example:**

To illustrate the usage, a simple example demonstrating how to access and print the metric descriptions is necessary. The `metrics.All()` function is the obvious entry point. The example should iterate through the returned slice and print relevant fields of the `Description` struct.

**6. Considering Command-Line Arguments:**

While the code itself doesn't directly process command-line arguments, the `init()` function interacts with the `GODEBUG` *environment variable*. This is a key aspect of runtime configuration. The answer needs to explain how `GODEBUG` influences the available metrics.

**7. Identifying Potential Mistakes:**

The most likely mistake users might make is misunderstanding the metric names and units. The defined format is specific, and incorrect parsing could lead to misinterpretations. The example provided in the `Name` field's comments should be highlighted as the correct format. Another point is the `Cumulative` flag and how it impacts interpretation (whether to calculate rates or not).

**8. Structuring the Answer in Chinese:**

The final step is to present the information clearly and concisely in Chinese, adhering to the request's formatting. This involves translating the identified functionalities, code examples, and explanations. Key terms like "运行时指标" (runtime metrics), "累积的" (cumulative), and "直方图" (histogram) need to be used accurately.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the code *collects* the metrics. **Correction:**  Closer reading reveals it only *describes* them. The actual collection happens elsewhere in the `runtime` package.
* **Initial thought:**  Focus heavily on the `GODEBUG` integration. **Refinement:** While important, it's a secondary function. The core is describing the base set of runtime metrics. The `GODEBUG` part should be explained but not overemphasized.
* **Initial thought:** Provide very complex code examples. **Refinement:**  A simple example showing how to access the descriptions is more effective for demonstrating the core functionality.

By following this systematic approach, combining code analysis with understanding of the request's nuances, and using self-correction, a comprehensive and accurate answer in Chinese can be generated.
这段 `go/src/runtime/metrics/description.go` 文件是 Go 运行时环境 (runtime) 中负责 **描述和定义运行时指标 (metrics)** 的一部分。它定义了 `Description` 结构体，用于存储每个指标的元数据，并提供了一个包含所有支持指标描述的列表。

**主要功能:**

1. **定义指标描述结构体 (`Description`):**  该文件定义了一个 `Description` 结构体，它包含了描述一个运行时指标所需的关键信息：
   - `Name` (指标名称): 指标的完整名称，包括单元。它遵循特定的格式，例如 `/memory/heap/free:bytes`。
   - `Description` (指标描述):  用英文描述指标含义的句子。
   - `Kind` (指标类型):  表示指标值的类型，例如 `KindUint64` (无符号 64 位整数), `KindFloat64` (64 位浮点数), `KindFloat64Histogram` (浮点数直方图)。
   - `Cumulative` (是否累积):  布尔值，指示指标是否是累积的。累积指标通常会随着时间的推移而单调递增。

2. **维护所有指标的描述列表 (`allDesc`):**  该文件声明并初始化了一个名为 `allDesc` 的 `Description` 结构体切片，其中包含了 Go 运行时提供的所有内置指标的描述。  这个列表中的每个元素都详细描述了一个特定的运行时指标，例如 `/cgo/go-to-c-calls:calls` 或 `/memory/heap/allocs:bytes`。

3. **动态添加 `GODEBUG` 相关的指标:** `init()` 函数负责在启动时将与非默认 `GODEBUG` 设置相关的指标添加到 `allDesc` 列表中。 这允许在启用特定的调试选项时，运行时能够报告额外的指标。

4. **提供获取所有指标描述的函数 (`All()`):**  `All()` 函数简单地返回 `allDesc` 切片，允许其他 Go 代码访问所有已定义的运行时指标的描述信息。

**它是什么 Go 语言功能的实现？**

这个文件是 Go **运行时指标 (runtime metrics)** 功能的核心组成部分。Go 的运行时指标功能允许程序监控 Go 运行时的内部状态，例如内存使用、垃圾回收统计、调度器延迟等。 这些指标对于性能分析、监控和故障排除非常有用。

**Go 代码示例：**

以下代码示例展示了如何使用 `metrics` 包来获取和打印所有运行时指标的名称和描述：

```go
package main

import (
	"fmt"
	"runtime/metrics"
)

func main() {
	allMetrics := metrics.All()
	for _, desc := range allMetrics {
		fmt.Printf("Name: %s\n", desc.Name)
		fmt.Printf("Description: %s\n", desc.Description)
		fmt.Println("---")
	}
}
```

**假设的输入与输出：**

该代码没有直接的输入。它的输出将是 Go 运行时支持的所有指标的名称和描述。 输出的一部分可能如下所示：

```
Name: /cgo/go-to-c-calls:calls
Description: Count of calls made from Go to C by the current process.
---
Name: /cpu/classes/gc/mark/assist:cpu-seconds
Description: Estimated total CPU time goroutines spent performing GC tasks to assist the GC and prevent it from falling behind the application. This metric is an overestimate, and not directly comparable to system CPU time measurements. Compare only with other /cpu/classes metrics.
---
Name: /memory/heap/allocs:bytes
Description: Cumulative sum of memory allocated to the heap by the application.
---
... 更多指标 ...
```

**命令行参数的具体处理：**

该文件本身不直接处理命令行参数。但是，它通过 `init()` 函数与 **`GODEBUG` 环境变量** 间接相关。

`GODEBUG` 是一个 Go 运行时环境变量，用于启用或修改某些运行时行为以进行调试或实验。 `description.go` 中的 `init()` 函数会检查 `internal/godebugs` 包中定义的非默认 `GODEBUG` 设置，并为这些设置对应的事件添加额外的运行时指标。

例如，如果用户设置了 `GODEBUG=http2debug=1`，运行时可能会暴露一些与 HTTP/2 相关的调试指标。`description.go` 会动态地将这些指标的描述添加到 `allDesc` 列表中。

**使用者易犯错的点：**

一个潜在的易错点是**错误地解析指标名称的格式**。 指标名称由两部分组成，用冒号分隔：路径和单元。  路径以 `/` 开头，单元描述指标的计量单位。

**示例：**  对于指标名称 `/memory/heap/free:bytes`， 用户可能会错误地认为整个字符串都是指标的名称，而忽略了 `:bytes` 部分表示该指标的单位是字节。

在处理直方图指标时，更容易混淆。例如，`/gc/heap/allocs-by-size:bytes` 是一个直方图，它的 buckets 的单位是 `bytes`，而 count 的单位是 `samples`。 理解这种多重单位的概念很重要。

另一个潜在的错误是**不理解 `Cumulative` 标志的含义**。  对于累积指标，直接读取其值通常意义不大。 需要计算一段时间内的变化率才能获得有用的信息。  例如，`/gc/heap/allocs:bytes` 是一个累积指标，表示已分配的总字节数。 要知道分配速率，需要定期采样并计算差值。

总而言之，`go/src/runtime/metrics/description.go` 是 Go 运行时指标系统的基础，它定义了指标的结构和提供了所有可用指标的详细描述，为开发者理解和监控 Go 应用程序的运行时行为提供了重要的元数据。

Prompt: 
```
这是路径为go/src/runtime/metrics/description.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package metrics

import "internal/godebugs"

// Description describes a runtime metric.
type Description struct {
	// Name is the full name of the metric which includes the unit.
	//
	// The format of the metric may be described by the following regular expression.
	//
	// 	^(?P<name>/[^:]+):(?P<unit>[^:*/]+(?:[*/][^:*/]+)*)$
	//
	// The format splits the name into two components, separated by a colon: a path which always
	// starts with a /, and a machine-parseable unit. The name may contain any valid Unicode
	// codepoint in between / characters, but by convention will try to stick to lowercase
	// characters and hyphens. An example of such a path might be "/memory/heap/free".
	//
	// The unit is by convention a series of lowercase English unit names (singular or plural)
	// without prefixes delimited by '*' or '/'. The unit names may contain any valid Unicode
	// codepoint that is not a delimiter.
	// Examples of units might be "seconds", "bytes", "bytes/second", "cpu-seconds",
	// "byte*cpu-seconds", and "bytes/second/second".
	//
	// For histograms, multiple units may apply. For instance, the units of the buckets and
	// the count. By convention, for histograms, the units of the count are always "samples"
	// with the type of sample evident by the metric's name, while the unit in the name
	// specifies the buckets' unit.
	//
	// A complete name might look like "/memory/heap/free:bytes".
	Name string

	// Description is an English language sentence describing the metric.
	Description string

	// Kind is the kind of value for this metric.
	//
	// The purpose of this field is to allow users to filter out metrics whose values are
	// types which their application may not understand.
	Kind ValueKind

	// Cumulative is whether or not the metric is cumulative. If a cumulative metric is just
	// a single number, then it increases monotonically. If the metric is a distribution,
	// then each bucket count increases monotonically.
	//
	// This flag thus indicates whether or not it's useful to compute a rate from this value.
	Cumulative bool
}

// The English language descriptions below must be kept in sync with the
// descriptions of each metric in doc.go by running 'go generate'.
var allDesc = []Description{
	{
		Name:        "/cgo/go-to-c-calls:calls",
		Description: "Count of calls made from Go to C by the current process.",
		Kind:        KindUint64,
		Cumulative:  true,
	},
	{
		Name: "/cpu/classes/gc/mark/assist:cpu-seconds",
		Description: "Estimated total CPU time goroutines spent performing GC tasks " +
			"to assist the GC and prevent it from falling behind the application. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/gc/mark/dedicated:cpu-seconds",
		Description: "Estimated total CPU time spent performing GC tasks on " +
			"processors (as defined by GOMAXPROCS) dedicated to those tasks. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/gc/mark/idle:cpu-seconds",
		Description: "Estimated total CPU time spent performing GC tasks on " +
			"spare CPU resources that the Go scheduler could not otherwise find " +
			"a use for. This should be subtracted from the total GC CPU time to " +
			"obtain a measure of compulsory GC CPU time. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/gc/pause:cpu-seconds",
		Description: "Estimated total CPU time spent with the application paused by " +
			"the GC. Even if only one thread is running during the pause, this is " +
			"computed as GOMAXPROCS times the pause latency because nothing else " +
			"can be executing. This is the exact sum of samples in " +
			"/sched/pauses/total/gc:seconds if each sample is multiplied by " +
			"GOMAXPROCS at the time it is taken. This metric is an overestimate, " +
			"and not directly comparable to system CPU time measurements. Compare " +
			"only with other /cpu/classes metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/gc/total:cpu-seconds",
		Description: "Estimated total CPU time spent performing GC tasks. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics. Sum of all metrics in /cpu/classes/gc.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/idle:cpu-seconds",
		Description: "Estimated total available CPU time not spent executing any Go or Go runtime code. " +
			"In other words, the part of /cpu/classes/total:cpu-seconds that was unused. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/scavenge/assist:cpu-seconds",
		Description: "Estimated total CPU time spent returning unused memory to the " +
			"underlying platform in response eagerly in response to memory pressure. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/scavenge/background:cpu-seconds",
		Description: "Estimated total CPU time spent performing background tasks " +
			"to return unused memory to the underlying platform. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/scavenge/total:cpu-seconds",
		Description: "Estimated total CPU time spent performing tasks that return " +
			"unused memory to the underlying platform. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics. Sum of all metrics in /cpu/classes/scavenge.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/total:cpu-seconds",
		Description: "Estimated total available CPU time for user Go code " +
			"or the Go runtime, as defined by GOMAXPROCS. In other words, GOMAXPROCS " +
			"integrated over the wall-clock duration this process has been executing for. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics. Sum of all metrics in /cpu/classes.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name: "/cpu/classes/user:cpu-seconds",
		Description: "Estimated total CPU time spent running user Go code. This may " +
			"also include some small amount of time spent in the Go runtime. " +
			"This metric is an overestimate, and not directly comparable to " +
			"system CPU time measurements. Compare only with other /cpu/classes " +
			"metrics.",
		Kind:       KindFloat64,
		Cumulative: true,
	},
	{
		Name:        "/gc/cycles/automatic:gc-cycles",
		Description: "Count of completed GC cycles generated by the Go runtime.",
		Kind:        KindUint64,
		Cumulative:  true,
	},
	{
		Name:        "/gc/cycles/forced:gc-cycles",
		Description: "Count of completed GC cycles forced by the application.",
		Kind:        KindUint64,
		Cumulative:  true,
	},
	{
		Name:        "/gc/cycles/total:gc-cycles",
		Description: "Count of all completed GC cycles.",
		Kind:        KindUint64,
		Cumulative:  true,
	},
	{
		Name: "/gc/gogc:percent",
		Description: "Heap size target percentage configured by the user, otherwise 100. This " +
			"value is set by the GOGC environment variable, and the runtime/debug.SetGCPercent " +
			"function.",
		Kind: KindUint64,
	},
	{
		Name: "/gc/gomemlimit:bytes",
		Description: "Go runtime memory limit configured by the user, otherwise " +
			"math.MaxInt64. This value is set by the GOMEMLIMIT environment variable, and " +
			"the runtime/debug.SetMemoryLimit function.",
		Kind: KindUint64,
	},
	{
		Name: "/gc/heap/allocs-by-size:bytes",
		Description: "Distribution of heap allocations by approximate size. " +
			"Bucket counts increase monotonically. " +
			"Note that this does not include tiny objects as defined by " +
			"/gc/heap/tiny/allocs:objects, only tiny blocks.",
		Kind:       KindFloat64Histogram,
		Cumulative: true,
	},
	{
		Name:        "/gc/heap/allocs:bytes",
		Description: "Cumulative sum of memory allocated to the heap by the application.",
		Kind:        KindUint64,
		Cumulative:  true,
	},
	{
		Name: "/gc/heap/allocs:objects",
		Description: "Cumulative count of heap allocations triggered by the application. " +
			"Note that this does not include tiny objects as defined by " +
			"/gc/heap/tiny/allocs:objects, only tiny blocks.",
		Kind:       KindUint64,
		Cumulative: true,
	},
	{
		Name: "/gc/heap/frees-by-size:bytes",
		Description: "Distribution of freed heap allocations by approximate size. " +
			"Bucket counts increase monotonically. " +
			"Note that this does not include tiny objects as defined by " +
			"/gc/heap/tiny/allocs:objects, only tiny blocks.",
		Kind:       KindFloat64Histogram,
		Cumulative: true,
	},
	{
		Name:        "/gc/heap/frees:bytes",
		Description: "Cumulative sum of heap memory freed by the garbage collector.",
		Kind:        KindUint64,
		Cumulative:  true,
	},
	{
		Name: "/gc/heap/frees:objects",
		Description: "Cumulative count of heap allocations whose storage was freed " +
			"by the garbage collector. " +
			"Note that this does not include tiny objects as defined by " +
			"/gc/heap/tiny/allocs:objects, only tiny blocks.",
		Kind:       KindUint64,
		Cumulative: true,
	},
	{
		Name:        "/gc/heap/goal:bytes",
		Description: "Heap size target for the end of the GC cycle.",
		Kind:        KindUint64,
	},
	{
		Name:        "/gc/heap/live:bytes",
		Description: "Heap memory occupied by live objects that were marked by the previous GC.",
		Kind:        KindUint64,
	},
	{
		Name:        "/gc/heap/objects:objects",
		Description: "Number of objects, live or unswept, occupying heap memory.",
		Kind:        KindUint64,
	},
	{
		Name: "/gc/heap/tiny/allocs:objects",
		Description: "Count of small allocations that are packed together into blocks. " +
			"These allocations are counted separately from other allocations " +
			"because each individual allocation is not tracked by the runtime, " +
			"only their block. Each block is already accounted for in " +
			"allocs-by-size and frees-by-size.",
		Kind:       KindUint64,
		Cumulative: true,
	},
	{
		Name: "/gc/limiter/last-enabled:gc-cycle",
		Description: "GC cycle the last time the GC CPU limiter was enabled. " +
			"This metric is useful for diagnosing the root cause of an out-of-memory " +
			"error, because the limiter trades memory for CPU time when the GC's CPU " +
			"time gets too high. This is most likely to occur with use of SetMemoryLimit. " +
			"The first GC cycle is cycle 1, so a value of 0 indicates that it was never enabled.",
		Kind: KindUint64,
	},
	{
		Name:        "/gc/pauses:seconds",
		Description: "Deprecated. Prefer the identical /sched/pauses/total/gc:seconds.",
		Kind:        KindFloat64Histogram,
		Cumulative:  true,
	},
	{
		Name:        "/gc/scan/globals:bytes",
		Description: "The total amount of global variable space that is scannable.",
		Kind:        KindUint64,
	},
	{
		Name:        "/gc/scan/heap:bytes",
		Description: "The total amount of heap space that is scannable.",
		Kind:        KindUint64,
	},
	{
		Name:        "/gc/scan/stack:bytes",
		Description: "The number of bytes of stack that were scanned last GC cycle.",
		Kind:        KindUint64,
	},
	{
		Name:        "/gc/scan/total:bytes",
		Description: "The total amount space that is scannable. Sum of all metrics in /gc/scan.",
		Kind:        KindUint64,
	},
	{
		Name:        "/gc/stack/starting-size:bytes",
		Description: "The stack size of new goroutines.",
		Kind:        KindUint64,
		Cumulative:  false,
	},
	{
		Name: "/memory/classes/heap/free:bytes",
		Description: "Memory that is completely free and eligible to be returned to the underlying system, " +
			"but has not been. This metric is the runtime's estimate of free address space that is backed by " +
			"physical memory.",
		Kind: KindUint64,
	},
	{
		Name:        "/memory/classes/heap/objects:bytes",
		Description: "Memory occupied by live objects and dead objects that have not yet been marked free by the garbage collector.",
		Kind:        KindUint64,
	},
	{
		Name: "/memory/classes/heap/released:bytes",
		Description: "Memory that is completely free and has been returned to the underlying system. This " +
			"metric is the runtime's estimate of free address space that is still mapped into the process, " +
			"but is not backed by physical memory.",
		Kind: KindUint64,
	},
	{
		Name: "/memory/classes/heap/stacks:bytes",
		Description: "Memory allocated from the heap that is reserved for stack space, whether or not it is currently in-use. " +
			"Currently, this represents all stack memory for goroutines. It also includes all OS thread stacks in non-cgo programs. " +
			"Note that stacks may be allocated differently in the future, and this may change.",
		Kind: KindUint64,
	},
	{
		Name:        "/memory/classes/heap/unused:bytes",
		Description: "Memory that is reserved for heap objects but is not currently used to hold heap objects.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/metadata/mcache/free:bytes",
		Description: "Memory that is reserved for runtime mcache structures, but not in-use.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/metadata/mcache/inuse:bytes",
		Description: "Memory that is occupied by runtime mcache structures that are currently being used.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/metadata/mspan/free:bytes",
		Description: "Memory that is reserved for runtime mspan structures, but not in-use.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/metadata/mspan/inuse:bytes",
		Description: "Memory that is occupied by runtime mspan structures that are currently being used.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/metadata/other:bytes",
		Description: "Memory that is reserved for or used to hold runtime metadata.",
		Kind:        KindUint64,
	},
	{
		Name: "/memory/classes/os-stacks:bytes",
		Description: "Stack memory allocated by the underlying operating system. " +
			"In non-cgo programs this metric is currently zero. This may change in the future." +
			"In cgo programs this metric includes OS thread stacks allocated directly from the OS. " +
			"Currently, this only accounts for one stack in c-shared and c-archive build modes, " +
			"and other sources of stacks from the OS are not measured. This too may change in the future.",
		Kind: KindUint64,
	},
	{
		Name:        "/memory/classes/other:bytes",
		Description: "Memory used by execution trace buffers, structures for debugging the runtime, finalizer and profiler specials, and more.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/profiling/buckets:bytes",
		Description: "Memory that is used by the stack trace hash map used for profiling.",
		Kind:        KindUint64,
	},
	{
		Name:        "/memory/classes/total:bytes",
		Description: "All memory mapped by the Go runtime into the current process as read-write. Note that this does not include memory mapped by code called via cgo or via the syscall package. Sum of all metrics in /memory/classes.",
		Kind:        KindUint64,
	},
	{
		Name:        "/sched/gomaxprocs:threads",
		Description: "The current runtime.GOMAXPROCS setting, or the number of operating system threads that can execute user-level Go code simultaneously.",
		Kind:        KindUint64,
	},
	{
		Name:        "/sched/goroutines:goroutines",
		Description: "Count of live goroutines.",
		Kind:        KindUint64,
	},
	{
		Name:        "/sched/latencies:seconds",
		Description: "Distribution of the time goroutines have spent in the scheduler in a runnable state before actually running. Bucket counts increase monotonically.",
		Kind:        KindFloat64Histogram,
		Cumulative:  true,
	},
	{
		Name:        "/sched/pauses/stopping/gc:seconds",
		Description: "Distribution of individual GC-related stop-the-world stopping latencies. This is the time it takes from deciding to stop the world until all Ps are stopped. This is a subset of the total GC-related stop-the-world time (/sched/pauses/total/gc:seconds). During this time, some threads may be executing. Bucket counts increase monotonically.",
		Kind:        KindFloat64Histogram,
		Cumulative:  true,
	},
	{
		Name:        "/sched/pauses/stopping/other:seconds",
		Description: "Distribution of individual non-GC-related stop-the-world stopping latencies. This is the time it takes from deciding to stop the world until all Ps are stopped. This is a subset of the total non-GC-related stop-the-world time (/sched/pauses/total/other:seconds). During this time, some threads may be executing. Bucket counts increase monotonically.",
		Kind:        KindFloat64Histogram,
		Cumulative:  true,
	},
	{
		Name:        "/sched/pauses/total/gc:seconds",
		Description: "Distribution of individual GC-related stop-the-world pause latencies. This is the time from deciding to stop the world until the world is started again. Some of this time is spent getting all threads to stop (this is measured directly in /sched/pauses/stopping/gc:seconds), during which some threads may still be running. Bucket counts increase monotonically.",
		Kind:        KindFloat64Histogram,
		Cumulative:  true,
	},
	{
		Name:        "/sched/pauses/total/other:seconds",
		Description: "Distribution of individual non-GC-related stop-the-world pause latencies. This is the time from deciding to stop the world until the world is started again. Some of this time is spent getting all threads to stop (measured directly in /sched/pauses/stopping/other:seconds). Bucket counts increase monotonically.",
		Kind:        KindFloat64Histogram,
		Cumulative:  true,
	},
	{
		Name:        "/sync/mutex/wait/total:seconds",
		Description: "Approximate cumulative time goroutines have spent blocked on a sync.Mutex, sync.RWMutex, or runtime-internal lock. This metric is useful for identifying global changes in lock contention. Collect a mutex or block profile using the runtime/pprof package for more detailed contention data.",
		Kind:        KindFloat64,
		Cumulative:  true,
	},
}

func init() {
	// Insert all the non-default-reporting GODEBUGs into the table,
	// preserving the overall sort order.
	i := 0
	for i < len(allDesc) && allDesc[i].Name < "/godebug/" {
		i++
	}
	more := make([]Description, i, len(allDesc)+len(godebugs.All))
	copy(more, allDesc)
	for _, info := range godebugs.All {
		if !info.Opaque {
			more = append(more, Description{
				Name: "/godebug/non-default-behavior/" + info.Name + ":events",
				Description: "The number of non-default behaviors executed by the " +
					info.Package + " package " + "due to a non-default " +
					"GODEBUG=" + info.Name + "=... setting.",
				Kind:       KindUint64,
				Cumulative: true,
			})
		}
	}
	allDesc = append(more, allDesc[i:]...)
}

// All returns a slice of containing metric descriptions for all supported metrics.
func All() []Description {
	return allDesc
}

"""



```