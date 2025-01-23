Response:
My thinking process to answer the request about `go/src/runtime/metrics/doc.go` goes like this:

1. **Understand the Core Request:** The primary goal is to explain the *functionality* of the `metrics` package based on its documentation. The secondary goal is to provide illustrative Go code, explain potential pitfalls, and detail command-line interaction (if any).

2. **Initial Scan and Keyword Identification:** I'll read through the documentation, looking for keywords and phrases that indicate the package's purpose and how it works. Keywords like "stable interface," "implementation-defined metrics," "exported by the Go runtime," "similar to `runtime.ReadMemStats`," "general," "string key," `All` function, `Description` struct, "kind," "metric key format,"  "GODEBUG," and mentions of specific metrics jump out.

3. **Identify the Main Purpose:** The first paragraph clearly states the core function: providing a *stable interface* to access *implementation-defined metrics* exported by the Go runtime. This immediately tells me it's about monitoring and understanding the runtime's internal behavior. The comparison to `runtime.ReadMemStats` helps contextualize it as a more generalized approach.

4. **Break Down Functionality by Section:** The documentation is well-structured, so I can process it section by section:

    * **"Interface":**  This section highlights the key aspects of interacting with the package:
        * Metrics are identified by *string keys*.
        * The `All()` function returns a slice of `Description` structs.
        * `Description` provides metadata about each metric.
        * Users should use `All()` for compatibility.
        * Metrics have a `kind` that won't change.
    * **"Metric key format":** This explains the structure of the metric keys (path:unit) and the rationale behind it (compatibility).
    * **"A note about floats":** This is a specific guarantee about the format of floating-point values.
    * **"Supported metrics":** This is a long, but essential, list of all available metrics, categorized by their purpose (cgo, CPU, GC, etc.). This provides concrete examples of what the package monitors.

5. **Infer Go Language Features:** Based on the functionality, I can deduce the underlying Go features involved:
    * **Reflection:**  While not explicitly stated, the ability to access metrics by string keys suggests some internal mechanism for mapping strings to runtime data, which might involve reflection or a similar technique.
    * **Data Structures:** The `Description` struct is explicitly mentioned, indicating the use of structs to organize metric metadata.
    * **Functions and Methods:** The `All()` function is central to retrieving the metric information.
    * **Constants/Enums:** The `ValueKind` likely represents an enumeration of possible data types for the metrics.

6. **Construct Go Code Examples:**  To illustrate the usage, I'll focus on the core functionality: getting the list of metrics and accessing a specific metric.

    * **Example 1 (Listing all metrics):**  This directly uses the `All()` function and iterates through the results, printing the name and kind.
    * **Example 2 (Accessing a specific metric):** This demonstrates filtering the results of `All()` to find a metric by its name. I'll include a check for the metric's existence. *Initially, I considered showing how to read the *value* of a metric, but realized the documentation doesn't provide the mechanism for doing so. This highlights a limitation of the `doc.go` file itself – it describes the interface but not the actual data retrieval.*

7. **Address Command-Line Arguments:** The documentation mentions `go generate` and `go test -run=Docs -generate`. This is about *generating* the documentation itself, not about how a user would interact with the `metrics` package at runtime. Therefore, I'll explain this aspect clearly and distinguish it from runtime usage. The `GODEBUG` environment variables are mentioned in the context of *non-default behaviors*, which are also worth explaining.

8. **Identify Potential Pitfalls:**  The documentation itself points out some common issues:
    * **Relying on specific metrics:**  The recommendation to use `All()` is a direct warning against hardcoding metric names, as they might change.
    * **Interpreting `/cpu/classes` metrics:** The documentation explicitly states these are "overestimates" and should only be compared to other `/cpu/classes` metrics. This is a crucial point for correct interpretation.
    * **Deprecated metrics:** The example of `/gc/pauses:seconds` being deprecated is a good illustration of potential changes.

9. **Structure the Answer:** I'll organize the answer logically using headings to address each part of the request: Functionality, Go Language Features, Code Examples, Command-Line Arguments, and Potential Pitfalls. Using bullet points and code blocks will improve readability.

10. **Review and Refine:**  Finally, I'll review my answer for accuracy, clarity, and completeness. I'll ensure the Go code examples are valid and the explanations are easy to understand. I'll double-check that I've addressed all aspects of the original request. For instance, I need to make sure the explanation of `go generate` is clear that it's for documentation *generation*, not runtime metric retrieval. I also need to emphasize that the `metrics` package provides *descriptions* of metrics, and another mechanism is needed to get their actual values (which isn't covered in this `doc.go`).

By following these steps, I can systematically analyze the documentation and produce a comprehensive and accurate answer to the user's request.
## 对 `go/src/runtime/metrics/doc.go` 的功能分析

这个 `doc.go` 文件是 Go 语言 `runtime/metrics` 包的文档说明。它的主要功能是：

1. **定义并解释 `metrics` 包的功能和目标:**  它阐述了该包提供了一个稳定的接口，用于访问 Go 运行时导出的、由实现定义的性能指标。这类似于 `runtime.ReadMemStats` 和 `runtime/debug.ReadGCStats`，但更加通用。

2. **说明指标的动态性:**  强调了随着 Go 运行时的发展，以及不同 Go 实现之间的差异，该包定义的指标集可能会发生变化。

3. **描述 `metrics` 包的接口:**
    * 指标通过**字符串键**来标识，而不是结构体字段。
    * 可以通过 `All()` 函数获取一个 `Description` 切片，其中包含了所有支持的指标及其详细信息。
    * 建议用户使用 `All()` 返回的指标列表进行采样，以保持跨 Go 版本的兼容性。
    * 对于必须读取特定指标的情况，建议使用构建标签来处理可能的指标弃用或删除。
    * 每个指标键都有一个 `kind` (参见 `ValueKind`)，描述了指标值的格式，且保证不会更改。

4. **定义指标键的格式:**  指标键是字符串，由**根路径**和**单位**两部分组成，用冒号分隔。将单位包含在键中是为了兼容性考虑，因为单位的改变通常意味着语义的改变，应该引入新的键。

5. **声明关于浮点数的约定:**  承诺不会产生 NaN 和无穷大这两种浮点数值。

6. **列出所有支持的指标:**  详细列出了当前 Go 版本运行时支持的所有性能指标，并对每个指标的含义和用途进行了说明。这些指标涵盖了 CGO 调用、CPU 使用情况分类、GC 周期、堆内存分配、GODEBUG 标志的影响、内存分类、调度器延迟等多个方面。

**可以推理出它是什么 Go 语言功能的实现:**

`go/src/runtime/metrics/doc.go` 实际上是 `runtime/metrics` 包的文档，它描述了 Go 语言**运行时指标监控**功能的实现。这个功能允许开发者以编程方式获取 Go 运行时内部的各种性能数据，用于监控、分析和优化 Go 程序的行为。

**Go 代码举例说明:**

以下代码演示了如何使用 `runtime/metrics` 包获取和打印所有支持的指标的名称和类型：

```go
package main

import (
	"fmt"
	"runtime/metrics"
)

func main() {
	allMetrics := metrics.All()
	fmt.Println("Supported Metrics:")
	for _, m := range allMetrics {
		fmt.Printf("  %s (%s)\n", m.Name, m.Kind.String())
	}
}
```

**假设的输入与输出:**

由于这段代码不接受任何外部输入，并且其输出取决于 Go 运行时的内部状态和版本，因此很难预测确切的输出。但是，运行上述代码会打印出一个类似下面这样的列表（实际输出可能因 Go 版本而异）：

```
Supported Metrics:
  /cgo/go-to-c-calls:calls (Counter)
  /cpu/classes/gc/mark/assist:cpu-seconds (Counter)
  /cpu/classes/gc/mark/dedicated:cpu-seconds (Counter)
  /cpu/classes/gc/mark/idle:cpu-seconds (Counter)
  /cpu/classes/gc/pause:cpu-seconds (Counter)
  /cpu/classes/gc/total:cpu-seconds (Counter)
  /cpu/classes/idle:cpu-seconds (Counter)
  ... (更多指标)
```

**涉及命令行参数的具体处理:**

`doc.go` 文件本身不处理命令行参数。但是，文档开头的注释提到了 `go generate` 命令：

```
// Note: run 'go generate' (which will run 'go test -generate') to update the "Supported metrics" list.
//go:generate go test -run=Docs -generate
```

这意味着，为了保持文档中 "Supported metrics" 列表的最新状态，需要运行 `go generate` 命令。

* **`go generate`:**  这是一个 Go 语言提供的工具，用于执行源代码中由 `//go:generate` 注释指定的命令。
* **`go test -run=Docs -generate`:** 这是 `go generate` 实际执行的命令。
    * **`go test`:**  运行 Go 测试的命令。
    * **`-run=Docs`:** 指定要运行的测试函数或正则表达式。在这里，它运行名为 `Docs` 的测试函数。
    * **`-generate`:**  一个自定义的标志，很可能是在 `metrics` 包的测试文件中定义的。这个标志告诉测试函数生成最新的指标列表并更新 `doc.go` 文件。

**使用者易犯错的点:**

1. **硬编码指标名称:**  文档强调不要硬编码特定的指标名称，因为指标可能会被添加、删除或重命名。依赖于 `All()` 函数返回的列表，或者使用构建标签来处理特定版本的指标，是更安全的方法。

   **错误示例:**

   ```go
   package main

   import (
       "fmt"
       "runtime/metrics"
   )

   func main() {
       allMetrics := metrics.All()
       for _, m := range allMetrics {
           if m.Name == "/gc/heap/allocs:bytes" { // 硬编码指标名称
               // ... 处理该指标
               fmt.Println("Found allocs metric!")
               break
           }
       }
   }
   ```

   如果 `/gc/heap/allocs:bytes` 这个指标在未来的 Go 版本中被重命名或删除，这段代码就会失效。

2. **不理解 `/cpu/classes` 指标的含义:**  文档多次强调 `/cpu/classes` 下的指标是**估计值**，并且不能直接与系统 CPU 时间测量值进行比较。 开发者可能会错误地将这些指标当作精确的系统 CPU 使用情况。

   **错误理解:**  认为 `/cpu/classes/user:cpu-seconds` 的值可以直接用来计算进程的精确用户态 CPU 时间百分比。实际上，应该将其与其他 `/cpu/classes` 指标进行比较，以了解 CPU 时间的相对分配。

总而言之，`go/src/runtime/metrics/doc.go` 是 `runtime/metrics` 包的重要组成部分，它清晰地定义了该包的功能、使用方法和注意事项，帮助开发者正确地利用 Go 运行时提供的性能监控能力。

### 提示词
```
这是路径为go/src/runtime/metrics/doc.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Note: run 'go generate' (which will run 'go test -generate') to update the "Supported metrics" list.
//go:generate go test -run=Docs -generate

/*
Package metrics provides a stable interface to access implementation-defined
metrics exported by the Go runtime. This package is similar to existing functions
like [runtime.ReadMemStats] and [runtime/debug.ReadGCStats], but significantly more general.

The set of metrics defined by this package may evolve as the runtime itself
evolves, and also enables variation across Go implementations, whose relevant
metric sets may not intersect.

# Interface

Metrics are designated by a string key, rather than, for example, a field name in
a struct. The full list of supported metrics is always available in the slice of
Descriptions returned by [All]. Each [Description] also includes useful information
about the metric.

Thus, users of this API are encouraged to sample supported metrics defined by the
slice returned by All to remain compatible across Go versions. Of course, situations
arise where reading specific metrics is critical. For these cases, users are
encouraged to use build tags, and although metrics may be deprecated and removed,
users should consider this to be an exceptional and rare event, coinciding with a
very large change in a particular Go implementation.

Each metric key also has a "kind" (see [ValueKind]) that describes the format of the
metric's value.
In the interest of not breaking users of this package, the "kind" for a given metric
is guaranteed not to change. If it must change, then a new metric will be introduced
with a new key and a new "kind."

# Metric key format

As mentioned earlier, metric keys are strings. Their format is simple and well-defined,
designed to be both human and machine readable. It is split into two components,
separated by a colon: a rooted path and a unit. The choice to include the unit in
the key is motivated by compatibility: if a metric's unit changes, its semantics likely
did also, and a new key should be introduced.

For more details on the precise definition of the metric key's path and unit formats, see
the documentation of the Name field of the Description struct.

# A note about floats

This package supports metrics whose values have a floating-point representation. In
order to improve ease-of-use, this package promises to never produce the following
classes of floating-point values: NaN, infinity.

# Supported metrics

Below is the full list of supported metrics, ordered lexicographically.

	/cgo/go-to-c-calls:calls
		Count of calls made from Go to C by the current process.

	/cpu/classes/gc/mark/assist:cpu-seconds
		Estimated total CPU time goroutines spent performing GC
		tasks to assist the GC and prevent it from falling behind the
		application. This metric is an overestimate, and not directly
		comparable to system CPU time measurements. Compare only with
		other /cpu/classes metrics.

	/cpu/classes/gc/mark/dedicated:cpu-seconds
		Estimated total CPU time spent performing GC tasks on processors
		(as defined by GOMAXPROCS) dedicated to those tasks. This metric
		is an overestimate, and not directly comparable to system CPU
		time measurements. Compare only with other /cpu/classes metrics.

	/cpu/classes/gc/mark/idle:cpu-seconds
		Estimated total CPU time spent performing GC tasks on spare CPU
		resources that the Go scheduler could not otherwise find a use
		for. This should be subtracted from the total GC CPU time to
		obtain a measure of compulsory GC CPU time. This metric is an
		overestimate, and not directly comparable to system CPU time
		measurements. Compare only with other /cpu/classes metrics.

	/cpu/classes/gc/pause:cpu-seconds
		Estimated total CPU time spent with the application paused by
		the GC. Even if only one thread is running during the pause,
		this is computed as GOMAXPROCS times the pause latency because
		nothing else can be executing. This is the exact sum of samples
		in /sched/pauses/total/gc:seconds if each sample is multiplied
		by GOMAXPROCS at the time it is taken. This metric is an
		overestimate, and not directly comparable to system CPU time
		measurements. Compare only with other /cpu/classes metrics.

	/cpu/classes/gc/total:cpu-seconds
		Estimated total CPU time spent performing GC tasks. This metric
		is an overestimate, and not directly comparable to system CPU
		time measurements. Compare only with other /cpu/classes metrics.
		Sum of all metrics in /cpu/classes/gc.

	/cpu/classes/idle:cpu-seconds
		Estimated total available CPU time not spent executing
		any Go or Go runtime code. In other words, the part of
		/cpu/classes/total:cpu-seconds that was unused. This metric is
		an overestimate, and not directly comparable to system CPU time
		measurements. Compare only with other /cpu/classes metrics.

	/cpu/classes/scavenge/assist:cpu-seconds
		Estimated total CPU time spent returning unused memory to the
		underlying platform in response eagerly in response to memory
		pressure. This metric is an overestimate, and not directly
		comparable to system CPU time measurements. Compare only with
		other /cpu/classes metrics.

	/cpu/classes/scavenge/background:cpu-seconds
		Estimated total CPU time spent performing background tasks to
		return unused memory to the underlying platform. This metric is
		an overestimate, and not directly comparable to system CPU time
		measurements. Compare only with other /cpu/classes metrics.

	/cpu/classes/scavenge/total:cpu-seconds
		Estimated total CPU time spent performing tasks that return
		unused memory to the underlying platform. This metric is an
		overestimate, and not directly comparable to system CPU time
		measurements. Compare only with other /cpu/classes metrics.
		Sum of all metrics in /cpu/classes/scavenge.

	/cpu/classes/total:cpu-seconds
		Estimated total available CPU time for user Go code or the Go
		runtime, as defined by GOMAXPROCS. In other words, GOMAXPROCS
		integrated over the wall-clock duration this process has been
		executing for. This metric is an overestimate, and not directly
		comparable to system CPU time measurements. Compare only with
		other /cpu/classes metrics. Sum of all metrics in /cpu/classes.

	/cpu/classes/user:cpu-seconds
		Estimated total CPU time spent running user Go code. This may
		also include some small amount of time spent in the Go runtime.
		This metric is an overestimate, and not directly comparable
		to system CPU time measurements. Compare only with other
		/cpu/classes metrics.

	/gc/cycles/automatic:gc-cycles
		Count of completed GC cycles generated by the Go runtime.

	/gc/cycles/forced:gc-cycles
		Count of completed GC cycles forced by the application.

	/gc/cycles/total:gc-cycles
		Count of all completed GC cycles.

	/gc/gogc:percent
		Heap size target percentage configured by the user, otherwise
		100. This value is set by the GOGC environment variable, and the
		runtime/debug.SetGCPercent function.

	/gc/gomemlimit:bytes
		Go runtime memory limit configured by the user, otherwise
		math.MaxInt64. This value is set by the GOMEMLIMIT environment
		variable, and the runtime/debug.SetMemoryLimit function.

	/gc/heap/allocs-by-size:bytes
		Distribution of heap allocations by approximate size.
		Bucket counts increase monotonically. Note that this does not
		include tiny objects as defined by /gc/heap/tiny/allocs:objects,
		only tiny blocks.

	/gc/heap/allocs:bytes
		Cumulative sum of memory allocated to the heap by the
		application.

	/gc/heap/allocs:objects
		Cumulative count of heap allocations triggered by the
		application. Note that this does not include tiny objects as
		defined by /gc/heap/tiny/allocs:objects, only tiny blocks.

	/gc/heap/frees-by-size:bytes
		Distribution of freed heap allocations by approximate size.
		Bucket counts increase monotonically. Note that this does not
		include tiny objects as defined by /gc/heap/tiny/allocs:objects,
		only tiny blocks.

	/gc/heap/frees:bytes
		Cumulative sum of heap memory freed by the garbage collector.

	/gc/heap/frees:objects
		Cumulative count of heap allocations whose storage was freed
		by the garbage collector. Note that this does not include tiny
		objects as defined by /gc/heap/tiny/allocs:objects, only tiny
		blocks.

	/gc/heap/goal:bytes
		Heap size target for the end of the GC cycle.

	/gc/heap/live:bytes
		Heap memory occupied by live objects that were marked by the
		previous GC.

	/gc/heap/objects:objects
		Number of objects, live or unswept, occupying heap memory.

	/gc/heap/tiny/allocs:objects
		Count of small allocations that are packed together into blocks.
		These allocations are counted separately from other allocations
		because each individual allocation is not tracked by the
		runtime, only their block. Each block is already accounted for
		in allocs-by-size and frees-by-size.

	/gc/limiter/last-enabled:gc-cycle
		GC cycle the last time the GC CPU limiter was enabled.
		This metric is useful for diagnosing the root cause of an
		out-of-memory error, because the limiter trades memory for CPU
		time when the GC's CPU time gets too high. This is most likely
		to occur with use of SetMemoryLimit. The first GC cycle is cycle
		1, so a value of 0 indicates that it was never enabled.

	/gc/pauses:seconds
		Deprecated. Prefer the identical /sched/pauses/total/gc:seconds.

	/gc/scan/globals:bytes
		The total amount of global variable space that is scannable.

	/gc/scan/heap:bytes
		The total amount of heap space that is scannable.

	/gc/scan/stack:bytes
		The number of bytes of stack that were scanned last GC cycle.

	/gc/scan/total:bytes
		The total amount space that is scannable. Sum of all metrics in
		/gc/scan.

	/gc/stack/starting-size:bytes
		The stack size of new goroutines.

	/godebug/non-default-behavior/asynctimerchan:events
		The number of non-default behaviors executed by the time package
		due to a non-default GODEBUG=asynctimerchan=... setting.

	/godebug/non-default-behavior/execerrdot:events
		The number of non-default behaviors executed by the os/exec
		package due to a non-default GODEBUG=execerrdot=... setting.

	/godebug/non-default-behavior/gocachehash:events
		The number of non-default behaviors executed by the cmd/go
		package due to a non-default GODEBUG=gocachehash=... setting.

	/godebug/non-default-behavior/gocachetest:events
		The number of non-default behaviors executed by the cmd/go
		package due to a non-default GODEBUG=gocachetest=... setting.

	/godebug/non-default-behavior/gocacheverify:events
		The number of non-default behaviors executed by the cmd/go
		package due to a non-default GODEBUG=gocacheverify=... setting.

	/godebug/non-default-behavior/gotestjsonbuildtext:events
		The number of non-default behaviors executed by the cmd/go
		package due to a non-default GODEBUG=gotestjsonbuildtext=...
		setting.

	/godebug/non-default-behavior/gotypesalias:events
		The number of non-default behaviors executed by the go/types
		package due to a non-default GODEBUG=gotypesalias=... setting.

	/godebug/non-default-behavior/http2client:events
		The number of non-default behaviors executed by the net/http
		package due to a non-default GODEBUG=http2client=... setting.

	/godebug/non-default-behavior/http2server:events
		The number of non-default behaviors executed by the net/http
		package due to a non-default GODEBUG=http2server=... setting.

	/godebug/non-default-behavior/httplaxcontentlength:events
		The number of non-default behaviors executed by the net/http
		package due to a non-default GODEBUG=httplaxcontentlength=...
		setting.

	/godebug/non-default-behavior/httpmuxgo121:events
		The number of non-default behaviors executed by the net/http
		package due to a non-default GODEBUG=httpmuxgo121=... setting.

	/godebug/non-default-behavior/httpservecontentkeepheaders:events
		The number of non-default behaviors executed
		by the net/http package due to a non-default
		GODEBUG=httpservecontentkeepheaders=... setting.

	/godebug/non-default-behavior/installgoroot:events
		The number of non-default behaviors executed by the go/build
		package due to a non-default GODEBUG=installgoroot=... setting.

	/godebug/non-default-behavior/multipartmaxheaders:events
		The number of non-default behaviors executed by
		the mime/multipart package due to a non-default
		GODEBUG=multipartmaxheaders=... setting.

	/godebug/non-default-behavior/multipartmaxparts:events
		The number of non-default behaviors executed by
		the mime/multipart package due to a non-default
		GODEBUG=multipartmaxparts=... setting.

	/godebug/non-default-behavior/multipathtcp:events
		The number of non-default behaviors executed by the net package
		due to a non-default GODEBUG=multipathtcp=... setting.

	/godebug/non-default-behavior/netedns0:events
		The number of non-default behaviors executed by the net package
		due to a non-default GODEBUG=netedns0=... setting.

	/godebug/non-default-behavior/panicnil:events
		The number of non-default behaviors executed by the runtime
		package due to a non-default GODEBUG=panicnil=... setting.

	/godebug/non-default-behavior/randautoseed:events
		The number of non-default behaviors executed by the math/rand
		package due to a non-default GODEBUG=randautoseed=... setting.

	/godebug/non-default-behavior/randseednop:events
		The number of non-default behaviors executed by the math/rand
		package due to a non-default GODEBUG=randseednop=... setting.

	/godebug/non-default-behavior/rsa1024min:events
		The number of non-default behaviors executed by the crypto/rsa
		package due to a non-default GODEBUG=rsa1024min=... setting.

	/godebug/non-default-behavior/tarinsecurepath:events
		The number of non-default behaviors executed by the archive/tar
		package due to a non-default GODEBUG=tarinsecurepath=...
		setting.

	/godebug/non-default-behavior/tls10server:events
		The number of non-default behaviors executed by the crypto/tls
		package due to a non-default GODEBUG=tls10server=... setting.

	/godebug/non-default-behavior/tls3des:events
		The number of non-default behaviors executed by the crypto/tls
		package due to a non-default GODEBUG=tls3des=... setting.

	/godebug/non-default-behavior/tlsmaxrsasize:events
		The number of non-default behaviors executed by the crypto/tls
		package due to a non-default GODEBUG=tlsmaxrsasize=... setting.

	/godebug/non-default-behavior/tlsrsakex:events
		The number of non-default behaviors executed by the crypto/tls
		package due to a non-default GODEBUG=tlsrsakex=... setting.

	/godebug/non-default-behavior/tlsunsafeekm:events
		The number of non-default behaviors executed by the crypto/tls
		package due to a non-default GODEBUG=tlsunsafeekm=... setting.

	/godebug/non-default-behavior/winreadlinkvolume:events
		The number of non-default behaviors executed by the os package
		due to a non-default GODEBUG=winreadlinkvolume=... setting.

	/godebug/non-default-behavior/winsymlink:events
		The number of non-default behaviors executed by the os package
		due to a non-default GODEBUG=winsymlink=... setting.

	/godebug/non-default-behavior/x509keypairleaf:events
		The number of non-default behaviors executed by the crypto/tls
		package due to a non-default GODEBUG=x509keypairleaf=...
		setting.

	/godebug/non-default-behavior/x509negativeserial:events
		The number of non-default behaviors executed by the crypto/x509
		package due to a non-default GODEBUG=x509negativeserial=...
		setting.

	/godebug/non-default-behavior/x509rsacrt:events
		The number of non-default behaviors executed by the crypto/x509
		package due to a non-default GODEBUG=x509rsacrt=... setting.

	/godebug/non-default-behavior/x509usefallbackroots:events
		The number of non-default behaviors executed by the crypto/x509
		package due to a non-default GODEBUG=x509usefallbackroots=...
		setting.

	/godebug/non-default-behavior/x509usepolicies:events
		The number of non-default behaviors executed by the crypto/x509
		package due to a non-default GODEBUG=x509usepolicies=...
		setting.

	/godebug/non-default-behavior/zipinsecurepath:events
		The number of non-default behaviors executed by the archive/zip
		package due to a non-default GODEBUG=zipinsecurepath=...
		setting.

	/memory/classes/heap/free:bytes
		Memory that is completely free and eligible to be returned to
		the underlying system, but has not been. This metric is the
		runtime's estimate of free address space that is backed by
		physical memory.

	/memory/classes/heap/objects:bytes
		Memory occupied by live objects and dead objects that have not
		yet been marked free by the garbage collector.

	/memory/classes/heap/released:bytes
		Memory that is completely free and has been returned to the
		underlying system. This metric is the runtime's estimate of free
		address space that is still mapped into the process, but is not
		backed by physical memory.

	/memory/classes/heap/stacks:bytes
		Memory allocated from the heap that is reserved for stack space,
		whether or not it is currently in-use. Currently, this
		represents all stack memory for goroutines. It also includes all
		OS thread stacks in non-cgo programs. Note that stacks may be
		allocated differently in the future, and this may change.

	/memory/classes/heap/unused:bytes
		Memory that is reserved for heap objects but is not currently
		used to hold heap objects.

	/memory/classes/metadata/mcache/free:bytes
		Memory that is reserved for runtime mcache structures, but not
		in-use.

	/memory/classes/metadata/mcache/inuse:bytes
		Memory that is occupied by runtime mcache structures that are
		currently being used.

	/memory/classes/metadata/mspan/free:bytes
		Memory that is reserved for runtime mspan structures, but not
		in-use.

	/memory/classes/metadata/mspan/inuse:bytes
		Memory that is occupied by runtime mspan structures that are
		currently being used.

	/memory/classes/metadata/other:bytes
		Memory that is reserved for or used to hold runtime metadata.

	/memory/classes/os-stacks:bytes
		Stack memory allocated by the underlying operating system.
		In non-cgo programs this metric is currently zero. This may
		change in the future.In cgo programs this metric includes
		OS thread stacks allocated directly from the OS. Currently,
		this only accounts for one stack in c-shared and c-archive build
		modes, and other sources of stacks from the OS are not measured.
		This too may change in the future.

	/memory/classes/other:bytes
		Memory used by execution trace buffers, structures for debugging
		the runtime, finalizer and profiler specials, and more.

	/memory/classes/profiling/buckets:bytes
		Memory that is used by the stack trace hash map used for
		profiling.

	/memory/classes/total:bytes
		All memory mapped by the Go runtime into the current process
		as read-write. Note that this does not include memory mapped
		by code called via cgo or via the syscall package. Sum of all
		metrics in /memory/classes.

	/sched/gomaxprocs:threads
		The current runtime.GOMAXPROCS setting, or the number of
		operating system threads that can execute user-level Go code
		simultaneously.

	/sched/goroutines:goroutines
		Count of live goroutines.

	/sched/latencies:seconds
		Distribution of the time goroutines have spent in the scheduler
		in a runnable state before actually running. Bucket counts
		increase monotonically.

	/sched/pauses/stopping/gc:seconds
		Distribution of individual GC-related stop-the-world stopping
		latencies. This is the time it takes from deciding to stop the
		world until all Ps are stopped. This is a subset of the total
		GC-related stop-the-world time (/sched/pauses/total/gc:seconds).
		During this time, some threads may be executing. Bucket counts
		increase monotonically.

	/sched/pauses/stopping/other:seconds
		Distribution of individual non-GC-related stop-the-world
		stopping latencies. This is the time it takes from deciding
		to stop the world until all Ps are stopped. This is a
		subset of the total non-GC-related stop-the-world time
		(/sched/pauses/total/other:seconds). During this time, some
		threads may be executing. Bucket counts increase monotonically.

	/sched/pauses/total/gc:seconds
		Distribution of individual GC-related stop-the-world pause
		latencies. This is the time from deciding to stop the world
		until the world is started again. Some of this time is spent
		getting all threads to stop (this is measured directly in
		/sched/pauses/stopping/gc:seconds), during which some threads
		may still be running. Bucket counts increase monotonically.

	/sched/pauses/total/other:seconds
		Distribution of individual non-GC-related stop-the-world
		pause latencies. This is the time from deciding to stop the
		world until the world is started again. Some of this time
		is spent getting all threads to stop (measured directly in
		/sched/pauses/stopping/other:seconds). Bucket counts increase
		monotonically.

	/sync/mutex/wait/total:seconds
		Approximate cumulative time goroutines have spent blocked on a
		sync.Mutex, sync.RWMutex, or runtime-internal lock. This metric
		is useful for identifying global changes in lock contention.
		Collect a mutex or block profile using the runtime/pprof package
		for more detailed contention data.
*/
package metrics
```