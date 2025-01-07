Response:
The user wants to understand the functionality of the provided Go code snippet. The code defines constants and types related to tracing events in Go version 1.22.

Here's a plan to address the user's request:

1. **List the functionalities:** Analyze the defined constants and types to identify the different kinds of events and data structures they represent.
2. **Infer the Go language feature:** Based on the event types, deduce that this code is part of Go's tracing mechanism.
3. **Provide Go code examples:** Demonstrate how these events might be generated using the `runtime/trace` package (or similar).
4. **Address code inference with assumptions:** For each example, specify the assumptions made about the program's behavior to generate a particular event. Show potential input and output if applicable (though tracing doesn't have direct output in the conventional sense, the output would be the trace data itself).
5. **Explain command-line parameters (if applicable):** Since the code doesn't directly handle command-line arguments, this part might be brief, focusing on how tracing is generally enabled.
6. **Highlight potential pitfalls:** Identify common mistakes users might make when working with Go's tracing features.
7. **Answer in Chinese:** Ensure the entire response is in Chinese.
这段代码是 Go 语言运行时追踪 (runtime tracing) 功能的一部分，具体来说，它定义了 Go 1.22 版本中追踪事件的类型和结构。

**它的主要功能包括：**

1. **定义追踪事件类型 (EvNone, EvEventBatch, EvGoCreate, 等等):**  代码中定义了大量的常量，每个常量都代表一个特定的追踪事件。这些事件涵盖了 Go 程序的各个方面，例如 goroutine 的创建、启动和停止，系统调用的开始和结束，垃圾回收的各个阶段，以及用户自定义的事件。

2. **定义结构化事件 (EvEventBatch, EvStacks, EvStrings, EvCPUSamples):** 这些事件用于组织和描述追踪数据的结构，例如事件批次、调用栈信息、字符串字典和 CPU 采样数据。

3. **定义进程 (Procs) 相关事件 (EvProcsChange, EvProcStart, EvProcStop, 等等):**  这些事件记录了 Go 调度器中 P（processor）的状态变化，例如 GOMAXPROCS 的改变、P 的启动和停止、以及 P 被窃取等。

4. **定义 Goroutine 相关事件 (EvGoCreate, EvGoStart, EvGoBlock, 等等):** 这些事件记录了 Goroutine 的生命周期和状态变化，例如创建、启动、阻塞、解除阻塞、进入和退出系统调用等。

5. **定义 STW (Stop-The-World) 相关事件 (EvSTWBegin, EvSTWEnd):**  这些事件标记了 STW 阶段的开始和结束，这通常与垃圾回收有关。

6. **定义垃圾回收 (GC) 相关事件 (EvGCActive, EvGCBegin, EvGCEnd, 等等):** 这些事件详细记录了垃圾回收的各个阶段，例如标记、清除等。

7. **定义注解 (Annotations) 相关事件 (EvGoLabel, EvUserTaskBegin, EvUserRegionBegin, EvUserLog):** 这些事件允许用户在追踪信息中添加自定义的标签、任务和区域信息，方便分析程序的行为。

8. **定义协程 (Coroutines) 相关事件 (EvGoSwitch, EvGoSwitchDestroy, EvGoCreateBlocked):** 这些是 Go 1.23 版本新增的关于协程切换和创建的事件。

9. **定义带有堆栈信息的 Goroutine 状态事件 (EvGoStatusStack):** 这是 Go 1.23 版本新增的，用于在记录 Goroutine 状态时包含调用栈信息。

10. **定义实验性批处理事件 (EvExperimentalBatch):**  允许记录具有自定义格式的实验性数据批次。

11. **定义实验性事件和实验 (Experiments) 常量:**  例如 `AllocFree` 实验及其相关的 `EvSpan`, `EvHeapObject`, `EvGoroutineStack` 等事件，用于追踪更细粒度的内存分配释放信息。

12. **提供事件名称和规范 (EventString, Specs):**  `EventString` 函数用于获取事件类型的名称，`Specs` 函数返回一个包含所有事件规范的切片，其中定义了每个事件的参数名称和类型等信息。

13. **定义状态类型 (GoStatus, ProcStatus):** 定义了 Goroutine 和 Processor 的状态枚举类型，并提供了将其转换为字符串的方法。

14. **定义常量 (MaxBatchSize, MaxFramesPerStack, MaxStringSize):** 定义了一些与追踪数据格式相关的常量，例如最大批次大小、每个调用栈的最大帧数、最大字符串大小。

**推理出的 Go 语言功能实现：**

这段代码是 Go 语言的**运行时追踪 (runtime tracing)** 功能的实现基础。Go 的运行时追踪允许开发者收集程序运行时的各种事件信息，用于性能分析、故障排查等。

**Go 代码示例：**

要触发这些事件，通常需要在运行 Go 程序时启用追踪，并使用 `runtime/trace` 包提供的函数。

```go
package main

import (
	"fmt"
	"os"
	"runtime/trace"
	"time"
)

func main() {
	// 创建追踪文件
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// 启动追踪
	if err := trace.Start(f); err != nil {
		panic(err)
	}
	defer trace.Stop()

	fmt.Println("Hello, tracing!")

	// 模拟一些操作，触发不同的事件
	go func() {
		time.Sleep(100 * time.Millisecond)
		fmt.Println("Goroutine finished")
	}()

	time.Sleep(200 * time.Millisecond)
}
```

**假设的输入与输出：**

* **输入:** 运行上述 Go 代码。
* **输出:** 会生成一个名为 `trace.out` 的追踪文件。这个文件是二进制格式，包含了程序运行期间发生的各种事件记录，例如 `EvGoCreate` (goroutine 创建), `EvGoStart` (goroutine 启动), `EvGoStop` (goroutine 停止) 等。要查看这些事件，需要使用 `go tool trace trace.out` 命令。

**涉及命令行参数的具体处理：**

Go 的运行时追踪通常通过以下方式启用：

1. **通过 `runtime/trace` 包的 API:**  如上面的代码示例所示，使用 `trace.Start()` 和 `trace.Stop()` 函数来控制追踪的开始和结束。

2. **通过 `testing` 包的标志:** 在运行测试时，可以使用 `-trace=file.out` 标志来启用追踪并将结果保存到指定的文件。例如：`go test -trace=trace.out ./...`

3. **通过 HTTP 接口:**  对于正在运行的服务，可以使用 `net/http/pprof` 包提供的 `/debug/trace` 接口来触发追踪，并获取追踪数据。

**使用者易犯错的点：**

1. **忘记停止追踪:** 如果使用 `trace.Start()` 启动了追踪，但忘记调用 `trace.Stop()`，可能会导致资源泄漏和性能问题。 应该始终使用 `defer trace.Stop()` 来确保追踪在函数退出时被停止。

   ```go
   func someFunction() {
       f, _ := os.Create("trace.out")
       trace.Start(f) // 容易忘记对应的 trace.Stop()
       // ... 一些代码 ...
   }
   ```

   **正确做法:**

   ```go
   func someFunction() {
       f, _ := os.Create("trace.out")
       defer f.Close()
       trace.Start(f)
       defer trace.Stop() // 确保追踪被停止
       // ... 一些代码 ...
   }
   ```

2. **在性能敏感的代码中过度使用用户自定义事件:**  虽然用户自定义事件 (例如 `EvUserTaskBegin`, `EvUserRegionBegin`) 可以提供有价值的信息，但在高频调用的代码路径中过度使用可能会引入显著的性能开销。应该谨慎地选择需要追踪的关键代码段。

3. **不了解追踪数据的分析工具:**  生成了追踪文件后，需要使用 `go tool trace` 命令来分析这些数据。  不熟悉这个工具可能会导致无法有效地利用追踪信息。应该学习如何使用 `go tool trace` 来查看事件、火焰图、goroutine 分析等。

4. **在生产环境中长时间开启追踪:**  虽然追踪对于问题排查很有用，但在生产环境中长时间开启追踪会显著增加 CPU 和内存开销，影响服务性能。应该仅在需要分析问题时临时启用追踪。

Prompt: 
```
这是路径为go/src/internal/trace/event/go122/event.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package go122

import (
	"fmt"
	"internal/trace/event"
)

const (
	EvNone event.Type = iota // unused

	// Structural events.
	EvEventBatch // start of per-M batch of events [generation, M ID, timestamp, batch length]
	EvStacks     // start of a section of the stack table [...EvStack]
	EvStack      // stack table entry [ID, ...{PC, func string ID, file string ID, line #}]
	EvStrings    // start of a section of the string dictionary [...EvString]
	EvString     // string dictionary entry [ID, length, string]
	EvCPUSamples // start of a section of CPU samples [...EvCPUSample]
	EvCPUSample  // CPU profiling sample [timestamp, M ID, P ID, goroutine ID, stack ID]
	EvFrequency  // timestamp units per sec [freq]

	// Procs.
	EvProcsChange // current value of GOMAXPROCS [timestamp, GOMAXPROCS, stack ID]
	EvProcStart   // start of P [timestamp, P ID, P seq]
	EvProcStop    // stop of P [timestamp]
	EvProcSteal   // P was stolen [timestamp, P ID, P seq, M ID]
	EvProcStatus  // P status at the start of a generation [timestamp, P ID, status]

	// Goroutines.
	EvGoCreate            // goroutine creation [timestamp, new goroutine ID, new stack ID, stack ID]
	EvGoCreateSyscall     // goroutine appears in syscall (cgo callback) [timestamp, new goroutine ID]
	EvGoStart             // goroutine starts running [timestamp, goroutine ID, goroutine seq]
	EvGoDestroy           // goroutine ends [timestamp]
	EvGoDestroySyscall    // goroutine ends in syscall (cgo callback) [timestamp]
	EvGoStop              // goroutine yields its time, but is runnable [timestamp, reason, stack ID]
	EvGoBlock             // goroutine blocks [timestamp, reason, stack ID]
	EvGoUnblock           // goroutine is unblocked [timestamp, goroutine ID, goroutine seq, stack ID]
	EvGoSyscallBegin      // syscall enter [timestamp, P seq, stack ID]
	EvGoSyscallEnd        // syscall exit [timestamp]
	EvGoSyscallEndBlocked // syscall exit and it blocked at some point [timestamp]
	EvGoStatus            // goroutine status at the start of a generation [timestamp, goroutine ID, thread ID, status]

	// STW.
	EvSTWBegin // STW start [timestamp, kind]
	EvSTWEnd   // STW done [timestamp]

	// GC events.
	EvGCActive           // GC active [timestamp, seq]
	EvGCBegin            // GC start [timestamp, seq, stack ID]
	EvGCEnd              // GC done [timestamp, seq]
	EvGCSweepActive      // GC sweep active [timestamp, P ID]
	EvGCSweepBegin       // GC sweep start [timestamp, stack ID]
	EvGCSweepEnd         // GC sweep done [timestamp, swept bytes, reclaimed bytes]
	EvGCMarkAssistActive // GC mark assist active [timestamp, goroutine ID]
	EvGCMarkAssistBegin  // GC mark assist start [timestamp, stack ID]
	EvGCMarkAssistEnd    // GC mark assist done [timestamp]
	EvHeapAlloc          // gcController.heapLive change [timestamp, heap alloc in bytes]
	EvHeapGoal           // gcController.heapGoal() change [timestamp, heap goal in bytes]

	// Annotations.
	EvGoLabel         // apply string label to current running goroutine [timestamp, label string ID]
	EvUserTaskBegin   // trace.NewTask [timestamp, internal task ID, internal parent task ID, name string ID, stack ID]
	EvUserTaskEnd     // end of a task [timestamp, internal task ID, stack ID]
	EvUserRegionBegin // trace.{Start,With}Region [timestamp, internal task ID, name string ID, stack ID]
	EvUserRegionEnd   // trace.{End,With}Region [timestamp, internal task ID, name string ID, stack ID]
	EvUserLog         // trace.Log [timestamp, internal task ID, key string ID, value string ID, stack]

	// Coroutines. Added in Go 1.23.
	EvGoSwitch        // goroutine switch (coroswitch) [timestamp, goroutine ID, goroutine seq]
	EvGoSwitchDestroy // goroutine switch and destroy [timestamp, goroutine ID, goroutine seq]
	EvGoCreateBlocked // goroutine creation (starts blocked) [timestamp, new goroutine ID, new stack ID, stack ID]

	// GoStatus with stack. Added in Go 1.23.
	EvGoStatusStack // goroutine status at the start of a generation, with a stack [timestamp, goroutine ID, M ID, status, stack ID]

	// Batch event for an experimental batch with a custom format. Added in Go 1.23.
	EvExperimentalBatch // start of extra data [experiment ID, generation, M ID, timestamp, batch length, batch data...]
)

// Experiments.
const (
	// AllocFree is the alloc-free events experiment.
	AllocFree event.Experiment = 1 + iota
)

// Experimental events.
const (
	_ event.Type = 127 + iota

	// Experimental events for AllocFree.

	// Experimental heap span events. Added in Go 1.23.
	EvSpan      // heap span exists [timestamp, id, npages, type/class]
	EvSpanAlloc // heap span alloc [timestamp, id, npages, type/class]
	EvSpanFree  // heap span free [timestamp, id]

	// Experimental heap object events. Added in Go 1.23.
	EvHeapObject      // heap object exists [timestamp, id, type]
	EvHeapObjectAlloc // heap object alloc [timestamp, id, type]
	EvHeapObjectFree  // heap object free [timestamp, id]

	// Experimental goroutine stack events. Added in Go 1.23.
	EvGoroutineStack      // stack exists [timestamp, id, order]
	EvGoroutineStackAlloc // stack alloc [timestamp, id, order]
	EvGoroutineStackFree  // stack free [timestamp, id]
)

// EventString returns the name of a Go 1.22 event.
func EventString(typ event.Type) string {
	if int(typ) < len(specs) {
		return specs[typ].Name
	}
	return fmt.Sprintf("Invalid(%d)", typ)
}

func Specs() []event.Spec {
	return specs[:]
}

var specs = [...]event.Spec{
	// "Structural" Events.
	EvEventBatch: event.Spec{
		Name: "EventBatch",
		Args: []string{"gen", "m", "time", "size"},
	},
	EvStacks: event.Spec{
		Name: "Stacks",
	},
	EvStack: event.Spec{
		Name:    "Stack",
		Args:    []string{"id", "nframes"},
		IsStack: true,
	},
	EvStrings: event.Spec{
		Name: "Strings",
	},
	EvString: event.Spec{
		Name:    "String",
		Args:    []string{"id"},
		HasData: true,
	},
	EvCPUSamples: event.Spec{
		Name: "CPUSamples",
	},
	EvCPUSample: event.Spec{
		Name: "CPUSample",
		Args: []string{"time", "m", "p", "g", "stack"},
		// N.B. There's clearly a timestamp here, but these Events
		// are special in that they don't appear in the regular
		// M streams.
	},
	EvFrequency: event.Spec{
		Name: "Frequency",
		Args: []string{"freq"},
	},
	EvExperimentalBatch: event.Spec{
		Name:    "ExperimentalBatch",
		Args:    []string{"exp", "gen", "m", "time"},
		HasData: true, // Easier to represent for raw readers.
	},

	// "Timed" Events.
	EvProcsChange: event.Spec{
		Name:         "ProcsChange",
		Args:         []string{"dt", "procs_value", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
	},
	EvProcStart: event.Spec{
		Name:         "ProcStart",
		Args:         []string{"dt", "p", "p_seq"},
		IsTimedEvent: true,
	},
	EvProcStop: event.Spec{
		Name:         "ProcStop",
		Args:         []string{"dt"},
		IsTimedEvent: true,
	},
	EvProcSteal: event.Spec{
		Name:         "ProcSteal",
		Args:         []string{"dt", "p", "p_seq", "m"},
		IsTimedEvent: true,
	},
	EvProcStatus: event.Spec{
		Name:         "ProcStatus",
		Args:         []string{"dt", "p", "pstatus"},
		IsTimedEvent: true,
	},
	EvGoCreate: event.Spec{
		Name:         "GoCreate",
		Args:         []string{"dt", "new_g", "new_stack", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{3, 2},
	},
	EvGoCreateSyscall: event.Spec{
		Name:         "GoCreateSyscall",
		Args:         []string{"dt", "new_g"},
		IsTimedEvent: true,
	},
	EvGoStart: event.Spec{
		Name:         "GoStart",
		Args:         []string{"dt", "g", "g_seq"},
		IsTimedEvent: true,
	},
	EvGoDestroy: event.Spec{
		Name:         "GoDestroy",
		Args:         []string{"dt"},
		IsTimedEvent: true,
	},
	EvGoDestroySyscall: event.Spec{
		Name:         "GoDestroySyscall",
		Args:         []string{"dt"},
		IsTimedEvent: true,
	},
	EvGoStop: event.Spec{
		Name:         "GoStop",
		Args:         []string{"dt", "reason_string", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
		StringIDs:    []int{1},
	},
	EvGoBlock: event.Spec{
		Name:         "GoBlock",
		Args:         []string{"dt", "reason_string", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
		StringIDs:    []int{1},
	},
	EvGoUnblock: event.Spec{
		Name:         "GoUnblock",
		Args:         []string{"dt", "g", "g_seq", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{3},
	},
	EvGoSyscallBegin: event.Spec{
		Name:         "GoSyscallBegin",
		Args:         []string{"dt", "p_seq", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
	},
	EvGoSyscallEnd: event.Spec{
		Name:         "GoSyscallEnd",
		Args:         []string{"dt"},
		StartEv:      EvGoSyscallBegin,
		IsTimedEvent: true,
	},
	EvGoSyscallEndBlocked: event.Spec{
		Name:         "GoSyscallEndBlocked",
		Args:         []string{"dt"},
		StartEv:      EvGoSyscallBegin,
		IsTimedEvent: true,
	},
	EvGoStatus: event.Spec{
		Name:         "GoStatus",
		Args:         []string{"dt", "g", "m", "gstatus"},
		IsTimedEvent: true,
	},
	EvSTWBegin: event.Spec{
		Name:         "STWBegin",
		Args:         []string{"dt", "kind_string", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
		StringIDs:    []int{1},
	},
	EvSTWEnd: event.Spec{
		Name:         "STWEnd",
		Args:         []string{"dt"},
		StartEv:      EvSTWBegin,
		IsTimedEvent: true,
	},
	EvGCActive: event.Spec{
		Name:         "GCActive",
		Args:         []string{"dt", "gc_seq"},
		IsTimedEvent: true,
		StartEv:      EvGCBegin,
	},
	EvGCBegin: event.Spec{
		Name:         "GCBegin",
		Args:         []string{"dt", "gc_seq", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
	},
	EvGCEnd: event.Spec{
		Name:         "GCEnd",
		Args:         []string{"dt", "gc_seq"},
		StartEv:      EvGCBegin,
		IsTimedEvent: true,
	},
	EvGCSweepActive: event.Spec{
		Name:         "GCSweepActive",
		Args:         []string{"dt", "p"},
		StartEv:      EvGCSweepBegin,
		IsTimedEvent: true,
	},
	EvGCSweepBegin: event.Spec{
		Name:         "GCSweepBegin",
		Args:         []string{"dt", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{1},
	},
	EvGCSweepEnd: event.Spec{
		Name:         "GCSweepEnd",
		Args:         []string{"dt", "swept_value", "reclaimed_value"},
		StartEv:      EvGCSweepBegin,
		IsTimedEvent: true,
	},
	EvGCMarkAssistActive: event.Spec{
		Name:         "GCMarkAssistActive",
		Args:         []string{"dt", "g"},
		StartEv:      EvGCMarkAssistBegin,
		IsTimedEvent: true,
	},
	EvGCMarkAssistBegin: event.Spec{
		Name:         "GCMarkAssistBegin",
		Args:         []string{"dt", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{1},
	},
	EvGCMarkAssistEnd: event.Spec{
		Name:         "GCMarkAssistEnd",
		Args:         []string{"dt"},
		StartEv:      EvGCMarkAssistBegin,
		IsTimedEvent: true,
	},
	EvHeapAlloc: event.Spec{
		Name:         "HeapAlloc",
		Args:         []string{"dt", "heapalloc_value"},
		IsTimedEvent: true,
	},
	EvHeapGoal: event.Spec{
		Name:         "HeapGoal",
		Args:         []string{"dt", "heapgoal_value"},
		IsTimedEvent: true,
	},
	EvGoLabel: event.Spec{
		Name:         "GoLabel",
		Args:         []string{"dt", "label_string"},
		IsTimedEvent: true,
		StringIDs:    []int{1},
	},
	EvUserTaskBegin: event.Spec{
		Name:         "UserTaskBegin",
		Args:         []string{"dt", "task", "parent_task", "name_string", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{4},
		StringIDs:    []int{3},
	},
	EvUserTaskEnd: event.Spec{
		Name:         "UserTaskEnd",
		Args:         []string{"dt", "task", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{2},
	},
	EvUserRegionBegin: event.Spec{
		Name:         "UserRegionBegin",
		Args:         []string{"dt", "task", "name_string", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{3},
		StringIDs:    []int{2},
	},
	EvUserRegionEnd: event.Spec{
		Name:         "UserRegionEnd",
		Args:         []string{"dt", "task", "name_string", "stack"},
		StartEv:      EvUserRegionBegin,
		IsTimedEvent: true,
		StackIDs:     []int{3},
		StringIDs:    []int{2},
	},
	EvUserLog: event.Spec{
		Name:         "UserLog",
		Args:         []string{"dt", "task", "key_string", "value_string", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{4},
		StringIDs:    []int{2, 3},
	},
	EvGoSwitch: event.Spec{
		Name:         "GoSwitch",
		Args:         []string{"dt", "g", "g_seq"},
		IsTimedEvent: true,
	},
	EvGoSwitchDestroy: event.Spec{
		Name:         "GoSwitchDestroy",
		Args:         []string{"dt", "g", "g_seq"},
		IsTimedEvent: true,
	},
	EvGoCreateBlocked: event.Spec{
		Name:         "GoCreateBlocked",
		Args:         []string{"dt", "new_g", "new_stack", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{3, 2},
	},
	EvGoStatusStack: event.Spec{
		Name:         "GoStatusStack",
		Args:         []string{"dt", "g", "m", "gstatus", "stack"},
		IsTimedEvent: true,
		StackIDs:     []int{4},
	},

	// Experimental events.

	EvSpan: event.Spec{
		Name:         "Span",
		Args:         []string{"dt", "id", "npages_value", "kindclass"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvSpanAlloc: event.Spec{
		Name:         "SpanAlloc",
		Args:         []string{"dt", "id", "npages_value", "kindclass"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvSpanFree: event.Spec{
		Name:         "SpanFree",
		Args:         []string{"dt", "id"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvHeapObject: event.Spec{
		Name:         "HeapObject",
		Args:         []string{"dt", "id", "type"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvHeapObjectAlloc: event.Spec{
		Name:         "HeapObjectAlloc",
		Args:         []string{"dt", "id", "type"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvHeapObjectFree: event.Spec{
		Name:         "HeapObjectFree",
		Args:         []string{"dt", "id"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvGoroutineStack: event.Spec{
		Name:         "GoroutineStack",
		Args:         []string{"dt", "id", "order"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvGoroutineStackAlloc: event.Spec{
		Name:         "GoroutineStackAlloc",
		Args:         []string{"dt", "id", "order"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
	EvGoroutineStackFree: event.Spec{
		Name:         "GoroutineStackFree",
		Args:         []string{"dt", "id"},
		IsTimedEvent: true,
		Experiment:   AllocFree,
	},
}

type GoStatus uint8

const (
	GoBad GoStatus = iota
	GoRunnable
	GoRunning
	GoSyscall
	GoWaiting
)

func (s GoStatus) String() string {
	switch s {
	case GoRunnable:
		return "Runnable"
	case GoRunning:
		return "Running"
	case GoSyscall:
		return "Syscall"
	case GoWaiting:
		return "Waiting"
	}
	return "Bad"
}

type ProcStatus uint8

const (
	ProcBad ProcStatus = iota
	ProcRunning
	ProcIdle
	ProcSyscall
	ProcSyscallAbandoned
)

func (s ProcStatus) String() string {
	switch s {
	case ProcRunning:
		return "Running"
	case ProcIdle:
		return "Idle"
	case ProcSyscall:
		return "Syscall"
	}
	return "Bad"
}

const (
	// Various format-specific constants.
	MaxBatchSize      = 64 << 10
	MaxFramesPerStack = 128
	MaxStringSize     = 1 << 10
)

"""



```