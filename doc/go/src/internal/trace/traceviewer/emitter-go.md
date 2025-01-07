Response:
Let's break down the thought process for analyzing this Go code and generating the answer.

1. **Understand the Goal:** The request asks for the functionality of the provided Go code, its purpose within the broader Go ecosystem (specifically related to tracing), examples of its usage, how it handles command-line arguments, and potential pitfalls for users.

2. **Initial Code Scan - Identify Key Structures:**  The first step is to quickly scan the code to identify the major data structures and functions. I see:

    * `TraceConsumer`: An interface-like struct with function fields, suggesting it defines a contract for consuming trace data.
    * `ViewerDataTraceConsumer`: A function returning a `TraceConsumer`. This is likely a concrete implementation for a specific output format.
    * `SplittingTraceConsumer`: Another function returning a `TraceConsumer`, hinting at a different strategy for handling trace data (splitting).
    * `Emitter`: A central struct with methods like `Slice`, `AsyncSlice`, `Instant`, `Arrow`, etc. This looks like the core component responsible for *generating* trace events.
    * Helper functions like `WalkStackFrames`, `viewerTime`, `pickTaskColor`, etc.

3. **Focus on Core Functionality - `TraceConsumer` and its Implementations:** The `TraceConsumer` struct is crucial. Its fields (`ConsumeTimeUnit`, `ConsumeViewerEvent`, `ConsumeViewerFrame`, `Flush`) clearly define the actions needed to process trace data.

    * **`ViewerDataTraceConsumer`**:  The name strongly suggests it's for outputting data viewable by a trace viewer. The presence of `json.NewEncoder` confirms this, as trace viewers often consume JSON. The `startIdx` and `endIdx` parameters point to a mechanism for splitting large traces. The logic inside the `ConsumeViewerEvent` function confirms this splitting behavior. It checks if the current event index falls within the specified range. The use of `requiredFrames` suggests it's optimizing by only including necessary stack frame information.

    * **`SplittingTraceConsumer`**:  The name itself indicates its purpose. The `max` parameter likely sets a maximum size for each split. The internal `splitter` struct and `Range` type confirm this. It seems to buffer events and then create ranges based on the `max` size.

4. **Understand the `Emitter`:** The `Emitter` struct and its methods are responsible for transforming lower-level trace data (likely from `internal/trace`) into the format consumed by a `TraceConsumer`.

    * **Event Methods (`Slice`, `AsyncSlice`, `Instant`, `Arrow`):** These methods correspond to different types of trace events. They take specific parameters and likely format them into `format.Event` structs. The `tsWithinRange` check suggests filtering based on time.
    * **Metadata Methods (`Gomaxprocs`, `Resource`, `Task`, `SetResourceType`, `SetResourceFilter`):** These methods provide contextual information about the trace.
    * **State Tracking (`GoroutineTransition`, `IncThreadStateCount`, `HeapGoal`):** These methods track changes in the runtime state and emit corresponding counter events.
    * **Stack Handling (`Stack`, `buildBranch`):** This is responsible for managing and deduplicating stack frame information. The `frameTree` structure suggests an optimization to avoid redundant storage of stack frames.
    * **`Flush`**:  The `Flush` method is responsible for sending the accumulated metadata and finalizing the trace output.

5. **Infer the "What" - Go Tracing:** Based on the package name (`internal/trace/traceviewer`), the structures (`TraceConsumer`, `Emitter`), and the types of events being emitted (goroutine state, heap allocation, slices, arrows), it's highly probable that this code is part of Go's built-in tracing functionality. Specifically, it seems to be the part that formats and outputs trace data for visualization.

6. **Construct Examples:**  Now that I have a good understanding, I can create illustrative examples.

    * **`ViewerDataTraceConsumer`**: A simple example would be writing to `os.Stdout`. I need to show how to create the consumer and then feed it some basic data (time unit and a simple event). Showing the JSON output helps clarify its purpose. Demonstrating the splitting with `startIdx` and `endIdx` is also important.
    * **`SplittingTraceConsumer`**: This example should show how it divides the trace into multiple ranges. I need to simulate a series of events and then show the resulting `Ranges`.
    * **`Emitter`**: This requires demonstrating how to create an `Emitter` and use its methods to generate different types of trace events. Showing the connection to the `TraceConsumer` is also important.

7. **Identify Command-Line Arguments:**  Scanning the code, I don't see any direct parsing of command-line arguments. The `startIdx`, `endIdx`, and `max` parameters are passed directly to the constructor functions. This implies that the *calling code* is responsible for handling command-line arguments and providing these values.

8. **Identify Potential Pitfalls:**  Consider how a user might misuse the code or encounter unexpected behavior.

    * **Incorrect `startIdx`/`endIdx`:**  Providing an invalid range will result in missing events.
    * **Confusing `SplittingTraceConsumer` without understanding ranges:** Users might not realize the output is split and only look at the first part.
    * **Forgetting to call `Flush`:**  Metadata and the final part of the trace might be missing.

9. **Structure the Answer:** Organize the findings into a clear and logical structure, addressing each part of the request:

    * Functionality Overview
    * Go Feature Realization (Tracing)
    * Code Examples (with assumptions, inputs, and outputs)
    * Command-Line Argument Handling
    * Potential Mistakes

10. **Refine and Review:**  Read through the generated answer, ensuring accuracy, clarity, and completeness. Double-check code examples for correctness. Make sure the language is natural and easy to understand. For example, initially, I might just say "it splits the trace," but refining it to explain *why* (for large traces) and *how* (based on event indices or size) makes it much clearer. Similarly, for pitfalls, simply stating "incorrect indices" isn't as helpful as showing an example of what happens.
这段代码是 Go 语言 `internal/trace` 包中 `traceviewer` 子包的一部分，主要负责将 Go 程序运行时的 trace 数据转换成 trace viewer (如 Chrome 的 `chrome://tracing`) 可以理解的 JSON 格式。

**功能列表:**

1. **数据消费接口 (TraceConsumer):**  定义了一组用于接收和处理 trace 数据的回调函数。这些回调函数包括：
    * `ConsumeTimeUnit`: 接收时间单位。
    * `ConsumeViewerEvent`: 接收并处理单个 trace 事件。
    * `ConsumeViewerFrame`: 接收并处理堆栈帧信息。
    * `Flush`:  完成数据处理，进行最后的写入操作。

2. **`ViewerDataTraceConsumer` 函数:**  创建并返回一个 `TraceConsumer` 的具体实现，该实现将 trace 数据写入 `io.Writer`。
    * **分片处理:** 支持处理大型 trace 数据，可以通过 `startIdx` 和 `endIdx` 参数指定要输出的事件范围（基于 `traceEvents` 数组的索引）。
    * **JSON 输出:** 将 trace 数据格式化为 JSON 对象，包含 `displayTimeUnit`（时间单位）、`traceEvents`（事件数组）和 `stackFrames`（堆栈帧信息）。
    * **按需输出堆栈帧:**  只输出 `traceEvents` 中实际引用的堆栈帧，避免输出冗余信息。

3. **`SplittingTraceConsumer` 函数:**  创建并返回另一个 `TraceConsumer` 的实现，用于将大型 trace 数据分割成多个较小的片段。
    * **大小限制:**  通过 `max` 参数指定每个片段的最大大小。
    * **片段信息:**  生成一个 `splitter` 结构，其中包含 `Ranges` 字段，记录了每个片段的起始和结束事件索引以及时间范围。
    * **优化的堆栈帧处理:** 在分割时，会考虑每个事件及其关联的堆栈帧的大小，以更精确地控制片段的大小。

4. **`Emitter` 结构体和方法:**  `Emitter` 是一个核心结构体，负责接收 Go trace 数据并将其转换为 `TraceConsumer` 可以处理的格式。
    * **事件发射:**  提供了 `Slice`, `AsyncSlice`, `Instant`, `Arrow` 等方法，用于发射不同类型的 trace 事件。
    * **元数据处理:**  可以记录和发射诸如 goroutine 状态、线程状态、堆内存信息、资源名称、任务信息等元数据。
    * **堆栈管理:**  `Stack` 方法用于记录和复用堆栈信息，避免重复存储。
    * **过滤:** 支持根据资源 ID 进行事件过滤。
    * **时间范围限制:** 可以设置要输出的 trace 事件的时间范围 (`rangeStart`, `rangeEnd`)。

5. **辅助函数:**
    * `WalkStackFrames`: 遍历堆栈帧，执行指定的回调函数。
    * `stackFrameEncodedSize`: 计算单个堆栈帧编码后的近似大小，用于 `SplittingTraceConsumer` 中更精确的分割。
    * `viewerTime`: 将 `time.Duration` 转换为 trace viewer 需要的浮点数（秒或毫秒）。
    * `pickTaskColor`: 为任务选择预定义的颜色。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 **trace 功能的输出部分** 的实现。Go 的 `runtime/trace` 包负责收集程序运行时的各种事件，而 `internal/trace/traceviewer` 则负责将这些原始事件数据转换成用户友好的格式，以便使用 trace viewer 工具进行可视化分析。

**Go 代码举例说明:**

假设我们有一个简单的 Go 程序，我们想要收集它的 trace 数据并使用 `ViewerDataTraceConsumer` 将其输出到标准输出。

```go
package main

import (
	"fmt"
	"internal/trace"
	"internal/trace/traceviewer"
	"os"
	"time"
)

func main() {
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	trace.Start(f)
	defer trace.Stop()

	consumer := traceviewer.ViewerDataTraceConsumer(f, 0, 100) // 输出前 100 个事件
	emitter := traceviewer.NewEmitter(consumer, 0, 10*time.Second)

	emitter.Gomaxprocs(2)
	emitter.Resource(1, "goroutine 1")
	emitter.Slice(traceviewer.SliceEvent{
		Name:     "My Function",
		Ts:       0 * time.Second,
		Dur:      5 * time.Second,
		Resource: 1,
		Stack:    0, // 假设 Stack ID 为 0
		EndStack: 0,
		Arg:      map[string]interface{}{"value": 123},
	})

	emitter.Flush()
	fmt.Println("Trace data written to trace.out")
}
```

**假设的输入与输出:**

* **输入:**  Go 程序运行时产生的 trace 事件数据（通过 `trace.Start` 收集）。
* **输出 (trace.out):**  一个 JSON 文件，内容类似如下（简化版）：

```json
{
  "displayTimeUnit": "ns",
  "traceEvents": [
    {
      "name": "thread_name",
      "ph": "M",
      "pid": 0,
      "tid": 1,
      "args": {
        "name": "goroutine 1"
      }
    },
    {
      "name": "My Function",
      "ph": "X",
      "ts": 0,
      "dur": 5000000,
      "pid": 0,
      "tid": 1,
      "args": {
        "value": 123
      }
    }
  ],
  "stackFrames": {}
}
```

**命令行参数的具体处理:**

这段代码本身 **不直接处理命令行参数**。`ViewerDataTraceConsumer` 和 `SplittingTraceConsumer` 函数接收的 `startIdx`, `endIdx`, 和 `max` 参数需要在调用这些函数的地方提供。通常，使用 Go trace 功能的工具（例如 `go tool trace`) 会负责解析命令行参数，然后根据参数值来调用这些消费者创建函数。

例如，`go tool trace` 命令可能会有类似 `--start-index` 和 `--end-index` 的参数，这些参数的值会被传递给 `ViewerDataTraceConsumer`。对于 `SplittingTraceConsumer`，可能有一个 `--split-max` 参数来指定最大大小。

**使用者易犯错的点:**

1. **忘记调用 `Flush()`:** `Emitter` 在接收到事件后并不会立即写入，很多元数据和最终的输出操作在 `Flush()` 方法中完成。如果忘记调用 `Flush()`，可能会导致 trace 数据不完整。

   ```go
   // 错误示例：
   consumer := traceviewer.ViewerDataTraceConsumer(os.Stdout, 0, -1)
   emitter := traceviewer.NewEmitter(consumer, 0, 10*time.Second)
   emitter.Resource(1, "goroutine 1")
   // 缺少 emitter.Flush()
   ```

2. **`ViewerDataTraceConsumer` 的 `startIdx` 和 `endIdx` 理解错误:** 这两个索引是基于 `traceEvents` **输出数组** 的索引，而不是原始 trace 事件的顺序。如果在 trace 过程中有事件被过滤掉，输出数组的索引可能与原始事件的顺序不一致。因此，直接使用原始事件的序号作为 `startIdx` 和 `endIdx` 可能会导致意料之外的结果。

   假设原始 trace 有 5 个事件，但由于某些原因（例如时间范围过滤），只有 3 个事件被 `ConsumeViewerEvent` 处理并添加到 `traceEvents` 数组中。如果用户想查看原始的第 2 和第 3 个事件，他们需要理解这两个事件在输出数组中的实际索引（可能是 0 和 1，取决于过滤情况）。

3. **`SplittingTraceConsumer` 的 `max` 参数设置不当:** 如果 `max` 设置得太小，会导致 trace 被分割成过多的片段，分析起来比较麻烦。如果设置得太大，可能无法达到分割的目的，或者导致内存占用过高。用户需要根据实际的 trace 大小和分析需求来合理设置 `max` 值。

总而言之，这段代码是 Go trace 功能的重要组成部分，负责将 trace 数据转换为可供可视化工具使用的格式，并提供了灵活的分片机制来处理大型 trace 数据。使用者需要理解其工作原理和参数含义，才能正确地使用和分析 Go 程序的 trace 信息。

Prompt: 
```
这是路径为go/src/internal/trace/traceviewer/emitter.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package traceviewer

import (
	"encoding/json"
	"fmt"
	"internal/trace"
	"internal/trace/traceviewer/format"
	"io"
	"strconv"
	"time"
)

type TraceConsumer struct {
	ConsumeTimeUnit    func(unit string)
	ConsumeViewerEvent func(v *format.Event, required bool)
	ConsumeViewerFrame func(key string, f format.Frame)
	Flush              func()
}

// ViewerDataTraceConsumer returns a TraceConsumer that writes to w. The
// startIdx and endIdx are used for splitting large traces. They refer to
// indexes in the traceEvents output array, not the events in the trace input.
func ViewerDataTraceConsumer(w io.Writer, startIdx, endIdx int64) TraceConsumer {
	allFrames := make(map[string]format.Frame)
	requiredFrames := make(map[string]format.Frame)
	enc := json.NewEncoder(w)
	written := 0
	index := int64(-1)

	io.WriteString(w, "{")
	return TraceConsumer{
		ConsumeTimeUnit: func(unit string) {
			io.WriteString(w, `"displayTimeUnit":`)
			enc.Encode(unit)
			io.WriteString(w, ",")
		},
		ConsumeViewerEvent: func(v *format.Event, required bool) {
			index++
			if !required && (index < startIdx || index > endIdx) {
				// not in the range. Skip!
				return
			}
			WalkStackFrames(allFrames, v.Stack, func(id int) {
				s := strconv.Itoa(id)
				requiredFrames[s] = allFrames[s]
			})
			WalkStackFrames(allFrames, v.EndStack, func(id int) {
				s := strconv.Itoa(id)
				requiredFrames[s] = allFrames[s]
			})
			if written == 0 {
				io.WriteString(w, `"traceEvents": [`)
			}
			if written > 0 {
				io.WriteString(w, ",")
			}
			enc.Encode(v)
			// TODO(mknyszek): get rid of the extra \n inserted by enc.Encode.
			// Same should be applied to splittingTraceConsumer.
			written++
		},
		ConsumeViewerFrame: func(k string, v format.Frame) {
			allFrames[k] = v
		},
		Flush: func() {
			io.WriteString(w, `], "stackFrames":`)
			enc.Encode(requiredFrames)
			io.WriteString(w, `}`)
		},
	}
}

func SplittingTraceConsumer(max int) (*splitter, TraceConsumer) {
	type eventSz struct {
		Time   float64
		Sz     int
		Frames []int
	}

	var (
		// data.Frames contains only the frames for required events.
		data = format.Data{Frames: make(map[string]format.Frame)}

		allFrames = make(map[string]format.Frame)

		sizes []eventSz
		cw    countingWriter
	)

	s := new(splitter)

	return s, TraceConsumer{
		ConsumeTimeUnit: func(unit string) {
			data.TimeUnit = unit
		},
		ConsumeViewerEvent: func(v *format.Event, required bool) {
			if required {
				// Store required events inside data so flush
				// can include them in the required part of the
				// trace.
				data.Events = append(data.Events, v)
				WalkStackFrames(allFrames, v.Stack, func(id int) {
					s := strconv.Itoa(id)
					data.Frames[s] = allFrames[s]
				})
				WalkStackFrames(allFrames, v.EndStack, func(id int) {
					s := strconv.Itoa(id)
					data.Frames[s] = allFrames[s]
				})
				return
			}
			enc := json.NewEncoder(&cw)
			enc.Encode(v)
			size := eventSz{Time: v.Time, Sz: cw.size + 1} // +1 for ",".
			// Add referenced stack frames. Their size is computed
			// in flush, where we can dedup across events.
			WalkStackFrames(allFrames, v.Stack, func(id int) {
				size.Frames = append(size.Frames, id)
			})
			WalkStackFrames(allFrames, v.EndStack, func(id int) {
				size.Frames = append(size.Frames, id) // This may add duplicates. We'll dedup later.
			})
			sizes = append(sizes, size)
			cw.size = 0
		},
		ConsumeViewerFrame: func(k string, v format.Frame) {
			allFrames[k] = v
		},
		Flush: func() {
			// Calculate size of the mandatory part of the trace.
			// This includes thread names and stack frames for
			// required events.
			cw.size = 0
			enc := json.NewEncoder(&cw)
			enc.Encode(data)
			requiredSize := cw.size

			// Then calculate size of each individual event and
			// their stack frames, grouping them into ranges. We
			// only include stack frames relevant to the events in
			// the range to reduce overhead.

			var (
				start = 0

				eventsSize = 0

				frames     = make(map[string]format.Frame)
				framesSize = 0
			)
			for i, ev := range sizes {
				eventsSize += ev.Sz

				// Add required stack frames. Note that they
				// may already be in the map.
				for _, id := range ev.Frames {
					s := strconv.Itoa(id)
					_, ok := frames[s]
					if ok {
						continue
					}
					f := allFrames[s]
					frames[s] = f
					framesSize += stackFrameEncodedSize(uint(id), f)
				}

				total := requiredSize + framesSize + eventsSize
				if total < max {
					continue
				}

				// Reached max size, commit this range and
				// start a new range.
				startTime := time.Duration(sizes[start].Time * 1000)
				endTime := time.Duration(ev.Time * 1000)
				s.Ranges = append(s.Ranges, Range{
					Name:      fmt.Sprintf("%v-%v", startTime, endTime),
					Start:     start,
					End:       i + 1,
					StartTime: int64(startTime),
					EndTime:   int64(endTime),
				})
				start = i + 1
				frames = make(map[string]format.Frame)
				framesSize = 0
				eventsSize = 0
			}
			if len(s.Ranges) <= 1 {
				s.Ranges = nil
				return
			}

			if end := len(sizes) - 1; start < end {
				s.Ranges = append(s.Ranges, Range{
					Name:      fmt.Sprintf("%v-%v", time.Duration(sizes[start].Time*1000), time.Duration(sizes[end].Time*1000)),
					Start:     start,
					End:       end,
					StartTime: int64(sizes[start].Time * 1000),
					EndTime:   int64(sizes[end].Time * 1000),
				})
			}
		},
	}
}

type splitter struct {
	Ranges []Range
}

type countingWriter struct {
	size int
}

func (cw *countingWriter) Write(data []byte) (int, error) {
	cw.size += len(data)
	return len(data), nil
}

func stackFrameEncodedSize(id uint, f format.Frame) int {
	// We want to know the marginal size of traceviewer.Data.Frames for
	// each event. Running full JSON encoding of the map for each event is
	// far too slow.
	//
	// Since the format is fixed, we can easily compute the size without
	// encoding.
	//
	// A single entry looks like one of the following:
	//
	//   "1":{"name":"main.main:30"},
	//   "10":{"name":"pkg.NewSession:173","parent":9},
	//
	// The parent is omitted if 0. The trailing comma is omitted from the
	// last entry, but we don't need that much precision.
	const (
		baseSize = len(`"`) + len(`":{"name":"`) + len(`"},`)

		// Don't count the trailing quote on the name, as that is
		// counted in baseSize.
		parentBaseSize = len(`,"parent":`)
	)

	size := baseSize

	size += len(f.Name)

	// Bytes for id (always positive).
	for id > 0 {
		size += 1
		id /= 10
	}

	if f.Parent > 0 {
		size += parentBaseSize
		// Bytes for parent (always positive).
		for f.Parent > 0 {
			size += 1
			f.Parent /= 10
		}
	}

	return size
}

// WalkStackFrames calls fn for id and all of its parent frames from allFrames.
func WalkStackFrames(allFrames map[string]format.Frame, id int, fn func(id int)) {
	for id != 0 {
		f, ok := allFrames[strconv.Itoa(id)]
		if !ok {
			break
		}
		fn(id)
		id = f.Parent
	}
}

type Mode int

const (
	ModeGoroutineOriented Mode = 1 << iota
	ModeTaskOriented
	ModeThreadOriented // Mutually exclusive with ModeGoroutineOriented.
)

// NewEmitter returns a new Emitter that writes to c. The rangeStart and
// rangeEnd args are used for splitting large traces.
func NewEmitter(c TraceConsumer, rangeStart, rangeEnd time.Duration) *Emitter {
	c.ConsumeTimeUnit("ns")

	return &Emitter{
		c:          c,
		rangeStart: rangeStart,
		rangeEnd:   rangeEnd,
		frameTree:  frameNode{children: make(map[uint64]frameNode)},
		resources:  make(map[uint64]string),
		tasks:      make(map[uint64]task),
	}
}

type Emitter struct {
	c          TraceConsumer
	rangeStart time.Duration
	rangeEnd   time.Duration

	heapStats, prevHeapStats     heapStats
	gstates, prevGstates         [gStateCount]int64
	threadStats, prevThreadStats [threadStateCount]int64
	gomaxprocs                   uint64
	frameTree                    frameNode
	frameSeq                     int
	arrowSeq                     uint64
	filter                       func(uint64) bool
	resourceType                 string
	resources                    map[uint64]string
	focusResource                uint64
	tasks                        map[uint64]task
	asyncSliceSeq                uint64
}

type task struct {
	name      string
	sortIndex int
}

func (e *Emitter) Gomaxprocs(v uint64) {
	if v > e.gomaxprocs {
		e.gomaxprocs = v
	}
}

func (e *Emitter) Resource(id uint64, name string) {
	if e.filter != nil && !e.filter(id) {
		return
	}
	e.resources[id] = name
}

func (e *Emitter) SetResourceType(name string) {
	e.resourceType = name
}

func (e *Emitter) SetResourceFilter(filter func(uint64) bool) {
	e.filter = filter
}

func (e *Emitter) Task(id uint64, name string, sortIndex int) {
	e.tasks[id] = task{name, sortIndex}
}

func (e *Emitter) Slice(s SliceEvent) {
	if e.filter != nil && !e.filter(s.Resource) {
		return
	}
	e.slice(s, format.ProcsSection, "")
}

func (e *Emitter) TaskSlice(s SliceEvent) {
	e.slice(s, format.TasksSection, pickTaskColor(s.Resource))
}

func (e *Emitter) slice(s SliceEvent, sectionID uint64, cname string) {
	if !e.tsWithinRange(s.Ts) && !e.tsWithinRange(s.Ts+s.Dur) {
		return
	}
	e.OptionalEvent(&format.Event{
		Name:     s.Name,
		Phase:    "X",
		Time:     viewerTime(s.Ts),
		Dur:      viewerTime(s.Dur),
		PID:      sectionID,
		TID:      s.Resource,
		Stack:    s.Stack,
		EndStack: s.EndStack,
		Arg:      s.Arg,
		Cname:    cname,
	})
}

type SliceEvent struct {
	Name     string
	Ts       time.Duration
	Dur      time.Duration
	Resource uint64
	Stack    int
	EndStack int
	Arg      any
}

func (e *Emitter) AsyncSlice(s AsyncSliceEvent) {
	if !e.tsWithinRange(s.Ts) && !e.tsWithinRange(s.Ts+s.Dur) {
		return
	}
	if e.filter != nil && !e.filter(s.Resource) {
		return
	}
	cname := ""
	if s.TaskColorIndex != 0 {
		cname = pickTaskColor(s.TaskColorIndex)
	}
	e.asyncSliceSeq++
	e.OptionalEvent(&format.Event{
		Category: s.Category,
		Name:     s.Name,
		Phase:    "b",
		Time:     viewerTime(s.Ts),
		TID:      s.Resource,
		ID:       e.asyncSliceSeq,
		Scope:    s.Scope,
		Stack:    s.Stack,
		Cname:    cname,
	})
	e.OptionalEvent(&format.Event{
		Category: s.Category,
		Name:     s.Name,
		Phase:    "e",
		Time:     viewerTime(s.Ts + s.Dur),
		TID:      s.Resource,
		ID:       e.asyncSliceSeq,
		Scope:    s.Scope,
		Stack:    s.EndStack,
		Arg:      s.Arg,
		Cname:    cname,
	})
}

type AsyncSliceEvent struct {
	SliceEvent
	Category       string
	Scope          string
	TaskColorIndex uint64 // Take on the same color as the task with this ID.
}

func (e *Emitter) Instant(i InstantEvent) {
	if !e.tsWithinRange(i.Ts) {
		return
	}
	if e.filter != nil && !e.filter(i.Resource) {
		return
	}
	cname := ""
	e.OptionalEvent(&format.Event{
		Name:     i.Name,
		Category: i.Category,
		Phase:    "I",
		Scope:    "t",
		Time:     viewerTime(i.Ts),
		PID:      format.ProcsSection,
		TID:      i.Resource,
		Stack:    i.Stack,
		Cname:    cname,
		Arg:      i.Arg,
	})
}

type InstantEvent struct {
	Ts       time.Duration
	Name     string
	Category string
	Resource uint64
	Stack    int
	Arg      any
}

func (e *Emitter) Arrow(a ArrowEvent) {
	if e.filter != nil && (!e.filter(a.FromResource) || !e.filter(a.ToResource)) {
		return
	}
	e.arrow(a, format.ProcsSection)
}

func (e *Emitter) TaskArrow(a ArrowEvent) {
	e.arrow(a, format.TasksSection)
}

func (e *Emitter) arrow(a ArrowEvent, sectionID uint64) {
	if !e.tsWithinRange(a.Start) || !e.tsWithinRange(a.End) {
		return
	}
	e.arrowSeq++
	e.OptionalEvent(&format.Event{
		Name:  a.Name,
		Phase: "s",
		TID:   a.FromResource,
		PID:   sectionID,
		ID:    e.arrowSeq,
		Time:  viewerTime(a.Start),
		Stack: a.FromStack,
	})
	e.OptionalEvent(&format.Event{
		Name:  a.Name,
		Phase: "t",
		TID:   a.ToResource,
		PID:   sectionID,
		ID:    e.arrowSeq,
		Time:  viewerTime(a.End),
	})
}

type ArrowEvent struct {
	Name         string
	Start        time.Duration
	End          time.Duration
	FromResource uint64
	FromStack    int
	ToResource   uint64
}

func (e *Emitter) Event(ev *format.Event) {
	e.c.ConsumeViewerEvent(ev, true)
}

func (e *Emitter) HeapAlloc(ts time.Duration, v uint64) {
	e.heapStats.heapAlloc = v
	e.emitHeapCounters(ts)
}

func (e *Emitter) Focus(id uint64) {
	e.focusResource = id
}

func (e *Emitter) GoroutineTransition(ts time.Duration, from, to GState) {
	e.gstates[from]--
	e.gstates[to]++
	if e.prevGstates == e.gstates {
		return
	}
	if e.tsWithinRange(ts) {
		e.OptionalEvent(&format.Event{
			Name:  "Goroutines",
			Phase: "C",
			Time:  viewerTime(ts),
			PID:   1,
			Arg: &format.GoroutineCountersArg{
				Running:   uint64(e.gstates[GRunning]),
				Runnable:  uint64(e.gstates[GRunnable]),
				GCWaiting: uint64(e.gstates[GWaitingGC]),
			},
		})
	}
	e.prevGstates = e.gstates
}

func (e *Emitter) IncThreadStateCount(ts time.Duration, state ThreadState, delta int64) {
	e.threadStats[state] += delta
	if e.prevThreadStats == e.threadStats {
		return
	}
	if e.tsWithinRange(ts) {
		e.OptionalEvent(&format.Event{
			Name:  "Threads",
			Phase: "C",
			Time:  viewerTime(ts),
			PID:   1,
			Arg: &format.ThreadCountersArg{
				Running:   int64(e.threadStats[ThreadStateRunning]),
				InSyscall: int64(e.threadStats[ThreadStateInSyscall]),
				// TODO(mknyszek): Why is InSyscallRuntime not included here?
			},
		})
	}
	e.prevThreadStats = e.threadStats
}

func (e *Emitter) HeapGoal(ts time.Duration, v uint64) {
	// This cutoff at 1 PiB is a Workaround for https://github.com/golang/go/issues/63864.
	//
	// TODO(mknyszek): Remove this once the problem has been fixed.
	const PB = 1 << 50
	if v > PB {
		v = 0
	}
	e.heapStats.nextGC = v
	e.emitHeapCounters(ts)
}

func (e *Emitter) emitHeapCounters(ts time.Duration) {
	if e.prevHeapStats == e.heapStats {
		return
	}
	diff := uint64(0)
	if e.heapStats.nextGC > e.heapStats.heapAlloc {
		diff = e.heapStats.nextGC - e.heapStats.heapAlloc
	}
	if e.tsWithinRange(ts) {
		e.OptionalEvent(&format.Event{
			Name:  "Heap",
			Phase: "C",
			Time:  viewerTime(ts),
			PID:   1,
			Arg:   &format.HeapCountersArg{Allocated: e.heapStats.heapAlloc, NextGC: diff},
		})
	}
	e.prevHeapStats = e.heapStats
}

// Err returns an error if the emitter is in an invalid state.
func (e *Emitter) Err() error {
	if e.gstates[GRunnable] < 0 || e.gstates[GRunning] < 0 || e.threadStats[ThreadStateInSyscall] < 0 || e.threadStats[ThreadStateInSyscallRuntime] < 0 {
		return fmt.Errorf(
			"runnable=%d running=%d insyscall=%d insyscallRuntime=%d",
			e.gstates[GRunnable],
			e.gstates[GRunning],
			e.threadStats[ThreadStateInSyscall],
			e.threadStats[ThreadStateInSyscallRuntime],
		)
	}
	return nil
}

func (e *Emitter) tsWithinRange(ts time.Duration) bool {
	return e.rangeStart <= ts && ts <= e.rangeEnd
}

// OptionalEvent emits ev if it's within the time range of the consumer, i.e.
// the selected trace split range.
func (e *Emitter) OptionalEvent(ev *format.Event) {
	e.c.ConsumeViewerEvent(ev, false)
}

func (e *Emitter) Flush() {
	e.processMeta(format.StatsSection, "STATS", 0)

	if len(e.tasks) != 0 {
		e.processMeta(format.TasksSection, "TASKS", 1)
	}
	for id, task := range e.tasks {
		e.threadMeta(format.TasksSection, id, task.name, task.sortIndex)
	}

	e.processMeta(format.ProcsSection, e.resourceType, 2)

	e.threadMeta(format.ProcsSection, trace.GCP, "GC", -6)
	e.threadMeta(format.ProcsSection, trace.NetpollP, "Network", -5)
	e.threadMeta(format.ProcsSection, trace.TimerP, "Timers", -4)
	e.threadMeta(format.ProcsSection, trace.SyscallP, "Syscalls", -3)

	for id, name := range e.resources {
		priority := int(id)
		if e.focusResource != 0 && id == e.focusResource {
			// Put the focus goroutine on top.
			priority = -2
		}
		e.threadMeta(format.ProcsSection, id, name, priority)
	}

	e.c.Flush()
}

func (e *Emitter) threadMeta(sectionID, tid uint64, name string, priority int) {
	e.Event(&format.Event{
		Name:  "thread_name",
		Phase: "M",
		PID:   sectionID,
		TID:   tid,
		Arg:   &format.NameArg{Name: name},
	})
	e.Event(&format.Event{
		Name:  "thread_sort_index",
		Phase: "M",
		PID:   sectionID,
		TID:   tid,
		Arg:   &format.SortIndexArg{Index: priority},
	})
}

func (e *Emitter) processMeta(sectionID uint64, name string, priority int) {
	e.Event(&format.Event{
		Name:  "process_name",
		Phase: "M",
		PID:   sectionID,
		Arg:   &format.NameArg{Name: name},
	})
	e.Event(&format.Event{
		Name:  "process_sort_index",
		Phase: "M",
		PID:   sectionID,
		Arg:   &format.SortIndexArg{Index: priority},
	})
}

// Stack emits the given frames and returns a unique id for the stack. No
// pointers to the given data are being retained beyond the call to Stack.
func (e *Emitter) Stack(stk []*trace.Frame) int {
	return e.buildBranch(e.frameTree, stk)
}

// buildBranch builds one branch in the prefix tree rooted at ctx.frameTree.
func (e *Emitter) buildBranch(parent frameNode, stk []*trace.Frame) int {
	if len(stk) == 0 {
		return parent.id
	}
	last := len(stk) - 1
	frame := stk[last]
	stk = stk[:last]

	node, ok := parent.children[frame.PC]
	if !ok {
		e.frameSeq++
		node.id = e.frameSeq
		node.children = make(map[uint64]frameNode)
		parent.children[frame.PC] = node
		e.c.ConsumeViewerFrame(strconv.Itoa(node.id), format.Frame{Name: fmt.Sprintf("%v:%v", frame.Fn, frame.Line), Parent: parent.id})
	}
	return e.buildBranch(node, stk)
}

type heapStats struct {
	heapAlloc uint64
	nextGC    uint64
}

func viewerTime(t time.Duration) float64 {
	return float64(t) / float64(time.Microsecond)
}

type GState int

const (
	GDead GState = iota
	GRunnable
	GRunning
	GWaiting
	GWaitingGC

	gStateCount
)

type ThreadState int

const (
	ThreadStateInSyscall ThreadState = iota
	ThreadStateInSyscallRuntime
	ThreadStateRunning

	threadStateCount
)

type frameNode struct {
	id       int
	children map[uint64]frameNode
}

// Mapping from more reasonable color names to the reserved color names in
// https://github.com/catapult-project/catapult/blob/master/tracing/tracing/base/color_scheme.html#L50
// The chrome trace viewer allows only those as cname values.
const (
	colorLightMauve     = "thread_state_uninterruptible" // 182, 125, 143
	colorOrange         = "thread_state_iowait"          // 255, 140, 0
	colorSeafoamGreen   = "thread_state_running"         // 126, 200, 148
	colorVistaBlue      = "thread_state_runnable"        // 133, 160, 210
	colorTan            = "thread_state_unknown"         // 199, 155, 125
	colorIrisBlue       = "background_memory_dump"       // 0, 180, 180
	colorMidnightBlue   = "light_memory_dump"            // 0, 0, 180
	colorDeepMagenta    = "detailed_memory_dump"         // 180, 0, 180
	colorBlue           = "vsync_highlight_color"        // 0, 0, 255
	colorGrey           = "generic_work"                 // 125, 125, 125
	colorGreen          = "good"                         // 0, 125, 0
	colorDarkGoldenrod  = "bad"                          // 180, 125, 0
	colorPeach          = "terrible"                     // 180, 0, 0
	colorBlack          = "black"                        // 0, 0, 0
	colorLightGrey      = "grey"                         // 221, 221, 221
	colorWhite          = "white"                        // 255, 255, 255
	colorYellow         = "yellow"                       // 255, 255, 0
	colorOlive          = "olive"                        // 100, 100, 0
	colorCornflowerBlue = "rail_response"                // 67, 135, 253
	colorSunsetOrange   = "rail_animation"               // 244, 74, 63
	colorTangerine      = "rail_idle"                    // 238, 142, 0
	colorShamrockGreen  = "rail_load"                    // 13, 168, 97
	colorGreenishYellow = "startup"                      // 230, 230, 0
	colorDarkGrey       = "heap_dump_stack_frame"        // 128, 128, 128
	colorTawny          = "heap_dump_child_node_arrow"   // 204, 102, 0
	colorLemon          = "cq_build_running"             // 255, 255, 119
	colorLime           = "cq_build_passed"              // 153, 238, 102
	colorPink           = "cq_build_failed"              // 238, 136, 136
	colorSilver         = "cq_build_abandoned"           // 187, 187, 187
	colorManzGreen      = "cq_build_attempt_runnig"      // 222, 222, 75
	colorKellyGreen     = "cq_build_attempt_passed"      // 108, 218, 35
	colorAnotherGrey    = "cq_build_attempt_failed"      // 187, 187, 187
)

var colorForTask = []string{
	colorLightMauve,
	colorOrange,
	colorSeafoamGreen,
	colorVistaBlue,
	colorTan,
	colorMidnightBlue,
	colorIrisBlue,
	colorDeepMagenta,
	colorGreen,
	colorDarkGoldenrod,
	colorPeach,
	colorOlive,
	colorCornflowerBlue,
	colorSunsetOrange,
	colorTangerine,
	colorShamrockGreen,
	colorTawny,
	colorLemon,
	colorLime,
	colorPink,
	colorSilver,
	colorManzGreen,
	colorKellyGreen,
}

func pickTaskColor(id uint64) string {
	idx := id % uint64(len(colorForTask))
	return colorForTask[idx]
}

"""



```