Response:
The user wants to understand the functionality of the Go code snippet provided, which is a test file for the `internal/trace` package. I need to analyze the test functions and their purposes.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The file `trace_test.go` is clearly a test suite for the `internal/trace` package. This means it tests the functionalities of tracing in Go.

2. **Examine individual test functions:**  Each function starting with `TestTrace...` is a specific test case. I need to analyze what each test is trying to verify.

3. **Analyze the `testTraceProg` helper function:** This function seems to be a common setup for running a test program and capturing its trace output. It takes a program name and an optional function `extra` for further validation. This suggests the tests work by running external Go programs and analyzing the generated trace data.

4. **Break down each test case:**
    * `TestTraceAnnotations`:  Focuses on verifying the recording of trace annotations like tasks, regions, and logs.
    * `TestTraceAnnotationsStress`: Likely a stress test for the annotation functionality.
    * `TestTraceCgoCallback`: Tests tracing in scenarios involving CGO callbacks.
    * `TestTraceCPUProfile`:  Examines the interaction between execution tracing and CPU profiling.
    * `TestTraceFutileWakeup`: Checks for a specific type of inefficiency related to goroutine blocking and unblocking.
    * `TestTraceGCStress`:  Likely a stress test related to tracing during garbage collection.
    * `TestTraceGOMAXPROCS`: Verifies that changes to `GOMAXPROCS` are correctly recorded in the trace.
    * `TestTraceStacks`:  Tests the capture and correctness of stack traces in various tracing events.
    * `TestTraceStress`: A general stress test for the tracing mechanism.
    * `TestTraceStressStartStop`: Tests starting and stopping the tracer under stress.
    * `TestTraceManyStartStop`: Tests rapidly starting and stopping the tracer.
    * `TestTraceWaitOnPipe`: Tests tracing when goroutines are waiting on pipes.
    * `TestTraceIterPull`: The purpose isn't immediately clear from the name. It likely tests a specific interaction related to iteration or pulling trace data.
    * `checkReaderDeterminism`: This function checks if reading the same trace data multiple times yields the same events.

5. **Infer the functionality of `internal/trace`:** Based on the tests, the `internal/trace` package likely provides functionality for:
    * Recording events with different kinds (task begin/end, region begin/end, log, state transition, stack sample, etc.).
    * Annotating events with tasks, regions, and log messages.
    * Integrating with CPU profiling.
    * Capturing goroutine state transitions and stack traces.
    * Handling CGO callbacks.
    * Providing a reader for parsing trace data.

6. **Provide Go code examples:** For each inferred functionality, create a simple illustrative example. This involves using the `runtime/trace` package (the user-facing interface) to generate trace data that the tests in `trace_test.go` would be designed to analyze.

7. **Address specific requests:**
    * **Function listing:**  Explicitly list the functionalities.
    * **Code examples:**  Provide the `runtime/trace` examples.
    * **Code inference (with assumptions):** Explain how the tests validate the trace data by comparing it to expected outputs.
    * **Command-line arguments:**  Explain how the tests use `go run` and environment variables like `GODEBUG`.
    * **Common mistakes:** Identify potential errors users might make when using the `runtime/trace` package.

8. **Structure the answer:** Organize the information logically with clear headings and explanations.

9. **Review and refine:** Check for accuracy, clarity, and completeness. Ensure the code examples are correct and the explanations are easy to understand. For instance, initially, I might focus too much on the internal details of `internal/trace`. The refined approach is to explain the functionality from the perspective of a user interacting with the `runtime/trace` package. Also, ensure all specific requests in the prompt are addressed.
这段代码是 Go 语言 `internal/trace` 包的测试文件 `trace_test.go` 的一部分。它的主要功能是**测试 Go 语言运行时追踪 (runtime tracing) 的各种特性和功能**。

让我们分解一下它测试的各种功能，并用 `runtime/trace` 包（用户使用的接口）的代码示例进行说明。

**测试功能列表:**

1. **追踪注解 (Trace Annotations):** 测试记录用户自定义的任务 (Task)、区域 (Region) 和日志 (Log) 事件。
2. **追踪注解压力测试 (Trace Annotations Stress):**  对追踪注解功能进行高并发压力测试。
3. **追踪 CGO 回调 (Trace Cgo Callback):** 测试在涉及 CGO (C 语言互操作) 回调时的追踪行为。
4. **追踪 CPU Profile (Trace CPU Profile):** 测试运行时追踪与 CPU 性能分析的集成，验证追踪数据中是否包含了 CPU profile 的信息。
5. **追踪无效唤醒 (Trace Futile Wakeup):**  检测 Goroutine 的无效唤醒情况，即 Goroutine 被唤醒后又立即进入阻塞状态。
6. **追踪 GC 压力测试 (Trace GC Stress):** 对垃圾回收 (Garbage Collection) 期间的追踪行为进行压力测试。
7. **追踪 GOMAXPROCS (Trace GOMAXPROCS):** 测试当 `GOMAXPROCS` (设置并发执行的操作系统线程数) 改变时，追踪是否能正确记录。
8. **追踪堆栈信息 (Trace Stacks):** 测试各种运行时事件是否能正确记录 Goroutine 的堆栈信息。
9. **追踪压力测试 (Trace Stress):** 对整个追踪机制进行综合压力测试。
10. **追踪频繁启停 (Trace Stress Start Stop 和 Trace Many Start Stop):** 测试频繁启动和停止追踪对系统行为的影响。
11. **追踪等待管道 (Trace Wait On Pipe):** 测试 Goroutine 在等待管道操作时的追踪情况。
12. **追踪迭代拉取 (Trace Iter Pull):**  这个测试的具体目的从名称上不太明确，可能测试的是一种特定的追踪数据迭代或拉取方式。
13. **追踪数据读取的确定性 (checkReaderDeterminism):**  验证多次读取相同的追踪数据是否会得到相同的结果。

**Go 语言功能实现示例 (使用 `runtime/trace` 包):**

为了理解这些测试验证的功能，我们需要了解如何使用 Go 的 `runtime/trace` 包来生成追踪数据。

```go
package main

import (
	"fmt"
	"os"
	"runtime/trace"
	"sync"
	"time"
)

func main() {
	// 创建一个追踪文件
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

	// 模拟一些工作，并添加注解
	trace.WithRegion(nil, "task0", func() {
		trace.WithRegion(nil, "region0", func() {
			trace.Log("region0", "key0", "0123456789abcdef")
			time.Sleep(10 * time.Millisecond)
		})
		trace.WithRegion(nil, "region1", func() {
			time.Sleep(5 * time.Millisecond)
		})
	})

	// 模拟 CPU 密集型工作，用于 CPU Profile 测试
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		trace.WithRegion(nil, "cpuHogger", func() {
			for i := 0; i < 1000000; i++ {
				_ = i * i
			}
		})
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500000; i++ {
			_ = i * 2
		}
	}()
	wg.Wait()

	// 模拟 Goroutine 状态变化，用于堆栈信息和无效唤醒测试
	ch := make(chan int)
	go func() {
		trace.WithRegion(nil, "special", func() {
			time.Sleep(time.Millisecond)
			ch <- 1 // 发送数据到 channel，可能会导致其他 Goroutine 从等待状态变为可运行
			time.Sleep(time.Millisecond)
		})
	}()
	<-ch

	// 模拟 GOMAXPROCS 的变化
	trace.Log("main", "/sched/gomaxprocs", fmt.Sprintf("%d", runtime.GOMAXPROCS(2)))
	trace.Log("main", "/sched/gomaxprocs", fmt.Sprintf("%d", runtime.GOMAXPROCS(1)))

	// ... 更多模拟各种场景的代码 ...
}
```

**代码推理 (带假设的输入与输出):**

以 `TestTraceAnnotations` 为例，它测试了注解功能。

**假设的输入 (对应 `annotations.go` 测试程序):**

`annotations.go` 测试程序会调用 `runtime/trace` 包的 API 来创建 Task、Region 和 Log 事件。例如，它可能会包含类似以下的调用：

```go
import "runtime/trace"

func main() {
	trace.WithTask(nil, "task0", func() {
		trace.WithRegion(nil, "region0", func() {
			trace.WithRegion(nil, "region1", func() {
				trace.Log("region1", "key0", "0123456789abcdef")
			})
		})
	})
	trace.NewRegion(nil, "post-existing region") // 后续可能没有显式结束
}
```

**推理的输出 (基于 `TestTraceAnnotations` 中的 `want` 变量):**

`TestTraceAnnotations` 会解析生成的追踪数据，并期望看到以下顺序的事件 (部分):

* `EventTaskBegin` (任务开始), TaskID=1, Args=["task0"]
* `EventRegionBegin` (区域开始), TaskID=1, Args=["region0"]
* `EventRegionBegin` (区域开始), TaskID=1, Args=["region1"]
* `EventLog` (日志), TaskID=1, Args=["key0", "0123456789abcdef"]
* `EventRegionEnd` (区域结束), TaskID=1, Args=["region1"]
* `EventRegionEnd` (区域结束), TaskID=1, Args=["region0"]
* `EventTaskEnd` (任务结束), TaskID=1, Args=["task0"]
* `EventRegionBegin` (区域开始), TaskID=BackgroundTask, Args=["post-existing region"] (后台任务)

`TestTraceAnnotations` 通过读取追踪数据，检查每个事件的类型、所属任务 ID 和参数是否与期望值一致，从而验证注解功能是否正常工作。

**命令行参数的具体处理:**

`testTraceProg` 函数是用来运行测试程序的辅助函数。它使用了 `go run` 命令来执行位于 `testdata/testprog` 目录下的 Go 程序。

* `cmd := testenv.Command(t, testenv.GoToolPath(t), "run")`:  构造 `go run` 命令。
* `cmd.Args = append(cmd.Args, testPath)`: 将要运行的测试程序路径添加到 `go run` 的参数中。
* `cmd.Env = append(os.Environ(), "GOEXPERIMENT=rangefunc")`:  设置环境变量 `GOEXPERIMENT=rangefunc`，这可能用于启用或禁用 Go 的实验性特性。
* `godebug := "tracecheckstackownership=1"`: 设置 `GODEBUG` 环境变量，用于控制 Go 运行时的调试选项，这里启用了堆栈所有权检查。
* 如果 `stress` 为 true，则会添加 `traceadvanceperiod=0` 到 `GODEBUG`，这会强制追踪器持续推进，用于压力测试。
* `cmd.Env = append(cmd.Env, "GODEBUG="+godebug)`: 将构建好的 `GODEBUG` 环境变量添加到命令的环境中。

简而言之，这些测试通过运行独立的 Go 程序，并设置特定的环境变量 (特别是 `GODEBUG`) 来控制追踪行为，然后分析这些程序生成的追踪数据。

**使用者易犯错的点 (基于 `runtime/trace` 包的使用):**

虽然这段代码是测试代码，但我们可以从它测试的内容推断出用户在使用 `runtime/trace` 包时可能犯的错误：

1. **忘记停止追踪:**  如果在程序结束前没有调用 `trace.Stop()`，追踪数据可能不会被完整写入文件。
   ```go
   f, _ := os.Create("trace.out")
   trace.Start(f)
   // ... 运行代码 ...
   // 忘记调用 trace.Stop()
   ```

2. **在错误的时间点启动或停止追踪:** 例如，在需要追踪的代码执行之前没有启动追踪，或者过早地停止了追踪。

3. **在高并发场景下过度使用注解:**  过多的 `trace.WithRegion` 或 `trace.Log` 调用可能会引入额外的开销，影响程序性能。应该谨慎地选择需要追踪的关键路径。

4. **误解追踪数据的含义:**  需要仔细理解不同事件类型的含义，以及如何使用 `go tool trace` 工具来分析追踪数据。

5. **在生产环境中无限制地启用追踪:**  长时间或无限制地启用追踪会产生大量的追踪数据，占用磁盘空间，并可能对性能产生影响。通常只在需要诊断问题时才启用追踪。

这段测试代码非常详尽地覆盖了 Go 运行时追踪的各种功能和边界情况，确保了 `internal/trace` 包的正确性和稳定性。理解这些测试用例有助于我们更好地理解 Go 语言的追踪机制以及如何有效地使用它。

### 提示词
```
这是路径为go/src/internal/trace/trace_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package trace_test

import (
	"bufio"
	"bytes"
	"fmt"
	"internal/race"
	"internal/testenv"
	"internal/trace"
	"internal/trace/testtrace"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestTraceAnnotations(t *testing.T) {
	testTraceProg(t, "annotations.go", func(t *testing.T, tb, _ []byte, _ bool) {
		type evDesc struct {
			kind trace.EventKind
			task trace.TaskID
			args []string
		}
		want := []evDesc{
			{trace.EventTaskBegin, trace.TaskID(1), []string{"task0"}},
			{trace.EventRegionBegin, trace.TaskID(1), []string{"region0"}},
			{trace.EventRegionBegin, trace.TaskID(1), []string{"region1"}},
			{trace.EventLog, trace.TaskID(1), []string{"key0", "0123456789abcdef"}},
			{trace.EventRegionEnd, trace.TaskID(1), []string{"region1"}},
			{trace.EventRegionEnd, trace.TaskID(1), []string{"region0"}},
			{trace.EventTaskEnd, trace.TaskID(1), []string{"task0"}},
			//  Currently, pre-existing region is not recorded to avoid allocations.
			{trace.EventRegionBegin, trace.BackgroundTask, []string{"post-existing region"}},
		}
		r, err := trace.NewReader(bytes.NewReader(tb))
		if err != nil {
			t.Error(err)
		}
		for {
			ev, err := r.ReadEvent()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, wantEv := range want {
				if wantEv.kind != ev.Kind() {
					continue
				}
				match := false
				switch ev.Kind() {
				case trace.EventTaskBegin, trace.EventTaskEnd:
					task := ev.Task()
					match = task.ID == wantEv.task && task.Type == wantEv.args[0]
				case trace.EventRegionBegin, trace.EventRegionEnd:
					reg := ev.Region()
					match = reg.Task == wantEv.task && reg.Type == wantEv.args[0]
				case trace.EventLog:
					log := ev.Log()
					match = log.Task == wantEv.task && log.Category == wantEv.args[0] && log.Message == wantEv.args[1]
				}
				if match {
					want[i] = want[len(want)-1]
					want = want[:len(want)-1]
					break
				}
			}
		}
		if len(want) != 0 {
			for _, ev := range want {
				t.Errorf("no match for %s TaskID=%d Args=%#v", ev.kind, ev.task, ev.args)
			}
		}
	})
}

func TestTraceAnnotationsStress(t *testing.T) {
	testTraceProg(t, "annotations-stress.go", nil)
}

func TestTraceCgoCallback(t *testing.T) {
	testenv.MustHaveCGO(t)

	switch runtime.GOOS {
	case "plan9", "windows":
		t.Skipf("cgo callback test requires pthreads and is not supported on %s", runtime.GOOS)
	}
	testTraceProg(t, "cgo-callback.go", nil)
}

func TestTraceCPUProfile(t *testing.T) {
	testTraceProg(t, "cpu-profile.go", func(t *testing.T, tb, stderr []byte, _ bool) {
		// Parse stderr which has a CPU profile summary, if everything went well.
		// (If it didn't, we shouldn't even make it here.)
		scanner := bufio.NewScanner(bytes.NewReader(stderr))
		pprofSamples := 0
		pprofStacks := make(map[string]int)
		for scanner.Scan() {
			var stack string
			var samples int
			_, err := fmt.Sscanf(scanner.Text(), "%s\t%d", &stack, &samples)
			if err != nil {
				t.Fatalf("failed to parse CPU profile summary in stderr: %s\n\tfull:\n%s", scanner.Text(), stderr)
			}
			pprofStacks[stack] = samples
			pprofSamples += samples
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("failed to parse CPU profile summary in stderr: %v", err)
		}
		if pprofSamples == 0 {
			t.Skip("CPU profile did not include any samples while tracing was active")
		}

		// Examine the execution tracer's view of the CPU profile samples. Filter it
		// to only include samples from the single test goroutine. Use the goroutine
		// ID that was recorded in the events: that should reflect getg().m.curg,
		// same as the profiler's labels (even when the M is using its g0 stack).
		totalTraceSamples := 0
		traceSamples := 0
		traceStacks := make(map[string]int)
		r, err := trace.NewReader(bytes.NewReader(tb))
		if err != nil {
			t.Error(err)
		}
		var hogRegion *trace.Event
		var hogRegionClosed bool
		for {
			ev, err := r.ReadEvent()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if ev.Kind() == trace.EventRegionBegin && ev.Region().Type == "cpuHogger" {
				hogRegion = &ev
			}
			if ev.Kind() == trace.EventStackSample {
				totalTraceSamples++
				if hogRegion != nil && ev.Goroutine() == hogRegion.Goroutine() {
					traceSamples++
					var fns []string
					for frame := range ev.Stack().Frames() {
						if frame.Func != "runtime.goexit" {
							fns = append(fns, fmt.Sprintf("%s:%d", frame.Func, frame.Line))
						}
					}
					stack := strings.Join(fns, "|")
					traceStacks[stack]++
				}
			}
			if ev.Kind() == trace.EventRegionEnd && ev.Region().Type == "cpuHogger" {
				hogRegionClosed = true
			}
		}
		if hogRegion == nil {
			t.Fatalf("execution trace did not identify cpuHogger goroutine")
		} else if !hogRegionClosed {
			t.Fatalf("execution trace did not close cpuHogger region")
		}

		// The execution trace may drop CPU profile samples if the profiling buffer
		// overflows. Based on the size of profBufWordCount, that takes a bit over
		// 1900 CPU samples or 19 thread-seconds at a 100 Hz sample rate. If we've
		// hit that case, then we definitely have at least one full buffer's worth
		// of CPU samples, so we'll call that success.
		overflowed := totalTraceSamples >= 1900
		if traceSamples < pprofSamples {
			t.Logf("execution trace did not include all CPU profile samples; %d in profile, %d in trace", pprofSamples, traceSamples)
			if !overflowed {
				t.Fail()
			}
		}

		for stack, traceSamples := range traceStacks {
			pprofSamples := pprofStacks[stack]
			delete(pprofStacks, stack)
			if traceSamples < pprofSamples {
				t.Logf("execution trace did not include all CPU profile samples for stack %q; %d in profile, %d in trace",
					stack, pprofSamples, traceSamples)
				if !overflowed {
					t.Fail()
				}
			}
		}
		for stack, pprofSamples := range pprofStacks {
			t.Logf("CPU profile included %d samples at stack %q not present in execution trace", pprofSamples, stack)
			if !overflowed {
				t.Fail()
			}
		}

		if t.Failed() {
			t.Logf("execution trace CPU samples:")
			for stack, samples := range traceStacks {
				t.Logf("%d: %q", samples, stack)
			}
			t.Logf("CPU profile:\n%s", stderr)
		}
	})
}

func TestTraceFutileWakeup(t *testing.T) {
	testTraceProg(t, "futile-wakeup.go", func(t *testing.T, tb, _ []byte, _ bool) {
		// Check to make sure that no goroutine in the "special" trace region
		// ends up blocking, unblocking, then immediately blocking again.
		//
		// The goroutines are careful to call runtime.Gosched in between blocking,
		// so there should never be a clean block/unblock on the goroutine unless
		// the runtime was generating extraneous events.
		const (
			entered = iota
			blocked
			runnable
			running
		)
		gs := make(map[trace.GoID]int)
		seenSpecialGoroutines := false
		r, err := trace.NewReader(bytes.NewReader(tb))
		if err != nil {
			t.Error(err)
		}
		for {
			ev, err := r.ReadEvent()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			// Only track goroutines in the special region we control, so runtime
			// goroutines don't interfere (it's totally valid in traces for a
			// goroutine to block, run, and block again; that's not what we care about).
			if ev.Kind() == trace.EventRegionBegin && ev.Region().Type == "special" {
				seenSpecialGoroutines = true
				gs[ev.Goroutine()] = entered
			}
			if ev.Kind() == trace.EventRegionEnd && ev.Region().Type == "special" {
				delete(gs, ev.Goroutine())
			}
			// Track state transitions for goroutines we care about.
			//
			// The goroutines we care about will advance through the state machine
			// of entered -> blocked -> runnable -> running. If in the running state
			// we block, then we have a futile wakeup. Because of the runtime.Gosched
			// on these specially marked goroutines, we should end up back in runnable
			// first. If at any point we go to a different state, switch back to entered
			// and wait for the next time the goroutine blocks.
			if ev.Kind() != trace.EventStateTransition {
				continue
			}
			st := ev.StateTransition()
			if st.Resource.Kind != trace.ResourceGoroutine {
				continue
			}
			id := st.Resource.Goroutine()
			state, ok := gs[id]
			if !ok {
				continue
			}
			_, new := st.Goroutine()
			switch state {
			case entered:
				if new == trace.GoWaiting {
					state = blocked
				} else {
					state = entered
				}
			case blocked:
				if new == trace.GoRunnable {
					state = runnable
				} else {
					state = entered
				}
			case runnable:
				if new == trace.GoRunning {
					state = running
				} else {
					state = entered
				}
			case running:
				if new == trace.GoWaiting {
					t.Fatalf("found futile wakeup on goroutine %d", id)
				} else {
					state = entered
				}
			}
			gs[id] = state
		}
		if !seenSpecialGoroutines {
			t.Fatal("did not see a goroutine in a the region 'special'")
		}
	})
}

func TestTraceGCStress(t *testing.T) {
	testTraceProg(t, "gc-stress.go", nil)
}

func TestTraceGOMAXPROCS(t *testing.T) {
	testTraceProg(t, "gomaxprocs.go", nil)
}

func TestTraceStacks(t *testing.T) {
	testTraceProg(t, "stacks.go", func(t *testing.T, tb, _ []byte, stress bool) {
		type frame struct {
			fn   string
			line int
		}
		type evDesc struct {
			kind   trace.EventKind
			match  string
			frames []frame
		}
		// mainLine is the line number of `func main()` in testprog/stacks.go.
		const mainLine = 21
		want := []evDesc{
			{trace.EventStateTransition, "Goroutine Running->Runnable", []frame{
				{"main.main", mainLine + 82},
			}},
			{trace.EventStateTransition, "Goroutine NotExist->Runnable", []frame{
				{"main.main", mainLine + 11},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"runtime.block", 0},
				{"main.main.func1", 0},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"runtime.chansend1", 0},
				{"main.main.func2", 0},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"runtime.chanrecv1", 0},
				{"main.main.func3", 0},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"runtime.chanrecv1", 0},
				{"main.main.func4", 0},
			}},
			{trace.EventStateTransition, "Goroutine Waiting->Runnable", []frame{
				{"runtime.chansend1", 0},
				{"main.main", mainLine + 84},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"runtime.chansend1", 0},
				{"main.main.func5", 0},
			}},
			{trace.EventStateTransition, "Goroutine Waiting->Runnable", []frame{
				{"runtime.chanrecv1", 0},
				{"main.main", mainLine + 85},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"runtime.selectgo", 0},
				{"main.main.func6", 0},
			}},
			{trace.EventStateTransition, "Goroutine Waiting->Runnable", []frame{
				{"runtime.selectgo", 0},
				{"main.main", mainLine + 86},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"sync.(*Mutex).Lock", 0},
				{"main.main.func7", 0},
			}},
			{trace.EventStateTransition, "Goroutine Waiting->Runnable", []frame{
				{"sync.(*Mutex).Unlock", 0},
				{"main.main", 0},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"sync.(*WaitGroup).Wait", 0},
				{"main.main.func8", 0},
			}},
			{trace.EventStateTransition, "Goroutine Waiting->Runnable", []frame{
				{"sync.(*WaitGroup).Add", 0},
				{"sync.(*WaitGroup).Done", 0},
				{"main.main", mainLine + 91},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"sync.(*Cond).Wait", 0},
				{"main.main.func9", 0},
			}},
			{trace.EventStateTransition, "Goroutine Waiting->Runnable", []frame{
				{"sync.(*Cond).Signal", 0},
				{"main.main", 0},
			}},
			{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
				{"time.Sleep", 0},
				{"main.main", 0},
			}},
			{trace.EventMetric, "/sched/gomaxprocs:threads", []frame{
				{"runtime.startTheWorld", 0}, // this is when the current gomaxprocs is logged.
				{"runtime.startTheWorldGC", 0},
				{"runtime.GOMAXPROCS", 0},
				{"main.main", 0},
			}},
		}
		if !stress {
			// Only check for this stack if !stress because traceAdvance alone could
			// allocate enough memory to trigger a GC if called frequently enough.
			// This might cause the runtime.GC call we're trying to match against to
			// coalesce with an active GC triggered this by traceAdvance. In that case
			// we won't have an EventRangeBegin event that matches the stace trace we're
			// looking for, since runtime.GC will not have triggered the GC.
			gcEv := evDesc{trace.EventRangeBegin, "GC concurrent mark phase", []frame{
				{"runtime.GC", 0},
				{"main.main", 0},
			}}
			want = append(want, gcEv)
		}
		if runtime.GOOS != "windows" && runtime.GOOS != "plan9" {
			want = append(want, []evDesc{
				{trace.EventStateTransition, "Goroutine Running->Waiting", []frame{
					{"internal/poll.(*FD).Accept", 0},
					{"net.(*netFD).accept", 0},
					{"net.(*TCPListener).accept", 0},
					{"net.(*TCPListener).Accept", 0},
					{"main.main.func10", 0},
				}},
				{trace.EventStateTransition, "Goroutine Running->Syscall", []frame{
					{"syscall.read", 0},
					{"syscall.Read", 0},
					{"internal/poll.ignoringEINTRIO", 0},
					{"internal/poll.(*FD).Read", 0},
					{"os.(*File).read", 0},
					{"os.(*File).Read", 0},
					{"main.main.func11", 0},
				}},
			}...)
		}
		stackMatches := func(stk trace.Stack, frames []frame) bool {
			for i, f := range slices.Collect(stk.Frames()) {
				if f.Func != frames[i].fn {
					return false
				}
				if line := uint64(frames[i].line); line != 0 && line != f.Line {
					return false
				}
			}
			return true
		}
		r, err := trace.NewReader(bytes.NewReader(tb))
		if err != nil {
			t.Error(err)
		}
		for {
			ev, err := r.ReadEvent()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, wantEv := range want {
				if wantEv.kind != ev.Kind() {
					continue
				}
				match := false
				switch ev.Kind() {
				case trace.EventStateTransition:
					st := ev.StateTransition()
					str := ""
					switch st.Resource.Kind {
					case trace.ResourceGoroutine:
						old, new := st.Goroutine()
						str = fmt.Sprintf("%s %s->%s", st.Resource.Kind, old, new)
					}
					match = str == wantEv.match
				case trace.EventRangeBegin:
					rng := ev.Range()
					match = rng.Name == wantEv.match
				case trace.EventMetric:
					metric := ev.Metric()
					match = metric.Name == wantEv.match
				}
				match = match && stackMatches(ev.Stack(), wantEv.frames)
				if match {
					want[i] = want[len(want)-1]
					want = want[:len(want)-1]
					break
				}
			}
		}
		if len(want) != 0 {
			for _, ev := range want {
				t.Errorf("no match for %s Match=%s Stack=%#v", ev.kind, ev.match, ev.frames)
			}
		}
	})
}

func TestTraceStress(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skip("no os.Pipe on " + runtime.GOOS)
	}
	testTraceProg(t, "stress.go", checkReaderDeterminism)
}

func TestTraceStressStartStop(t *testing.T) {
	switch runtime.GOOS {
	case "js", "wasip1":
		t.Skip("no os.Pipe on " + runtime.GOOS)
	}
	testTraceProg(t, "stress-start-stop.go", nil)
}

func TestTraceManyStartStop(t *testing.T) {
	testTraceProg(t, "many-start-stop.go", nil)
}

func TestTraceWaitOnPipe(t *testing.T) {
	switch runtime.GOOS {
	case "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris":
		testTraceProg(t, "wait-on-pipe.go", nil)
		return
	}
	t.Skip("no applicable syscall.Pipe on " + runtime.GOOS)
}

func TestTraceIterPull(t *testing.T) {
	testTraceProg(t, "iter-pull.go", nil)
}

func checkReaderDeterminism(t *testing.T, tb, _ []byte, _ bool) {
	events := func() []trace.Event {
		var evs []trace.Event

		r, err := trace.NewReader(bytes.NewReader(tb))
		if err != nil {
			t.Error(err)
		}
		for {
			ev, err := r.ReadEvent()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			evs = append(evs, ev)
		}

		return evs
	}

	evs1 := events()
	evs2 := events()

	if l1, l2 := len(evs1), len(evs2); l1 != l2 {
		t.Fatalf("re-reading trace gives different event count (%d != %d)", l1, l2)
	}
	for i, ev1 := range evs1 {
		ev2 := evs2[i]
		if s1, s2 := ev1.String(), ev2.String(); s1 != s2 {
			t.Errorf("re-reading trace gives different event %d:\n%s\n%s\n", i, s1, s2)
			break
		}
	}
}

func testTraceProg(t *testing.T, progName string, extra func(t *testing.T, trace, stderr []byte, stress bool)) {
	testenv.MustHaveGoRun(t)

	// Check if we're on a builder.
	onBuilder := testenv.Builder() != ""
	onOldBuilder := !strings.Contains(testenv.Builder(), "gotip") && !strings.Contains(testenv.Builder(), "go1")

	testPath := filepath.Join("./testdata/testprog", progName)
	testName := progName
	runTest := func(t *testing.T, stress bool, extraGODEBUG string) {
		// Run the program and capture the trace, which is always written to stdout.
		cmd := testenv.Command(t, testenv.GoToolPath(t), "run")
		if race.Enabled {
			cmd.Args = append(cmd.Args, "-race")
		}
		cmd.Args = append(cmd.Args, testPath)
		cmd.Env = append(os.Environ(), "GOEXPERIMENT=rangefunc")
		// Add a stack ownership check. This is cheap enough for testing.
		godebug := "tracecheckstackownership=1"
		if stress {
			// Advance a generation constantly to stress the tracer.
			godebug += ",traceadvanceperiod=0"
		}
		if extraGODEBUG != "" {
			// Add extra GODEBUG flags.
			godebug += "," + extraGODEBUG
		}
		cmd.Env = append(cmd.Env, "GODEBUG="+godebug)

		// Capture stdout and stderr.
		//
		// The protocol for these programs is that stdout contains the trace data
		// and stderr is an expectation in string format.
		var traceBuf, errBuf bytes.Buffer
		cmd.Stdout = &traceBuf
		cmd.Stderr = &errBuf
		// Run the program.
		if err := cmd.Run(); err != nil {
			if errBuf.Len() != 0 {
				t.Logf("stderr: %s", string(errBuf.Bytes()))
			}
			t.Fatal(err)
		}
		tb := traceBuf.Bytes()

		// Test the trace and the parser.
		testReader(t, bytes.NewReader(tb), testtrace.ExpectSuccess())

		// Run some extra validation.
		if !t.Failed() && extra != nil {
			extra(t, tb, errBuf.Bytes(), stress)
		}

		// Dump some more information on failure.
		if t.Failed() && onBuilder {
			// Dump directly to the test log on the builder, since this
			// data is critical for debugging and this is the only way
			// we can currently make sure it's retained.
			t.Log("found bad trace; dumping to test log...")
			s := dumpTraceToText(t, tb)
			if onOldBuilder && len(s) > 1<<20+512<<10 {
				// The old build infrastructure truncates logs at ~2 MiB.
				// Let's assume we're the only failure and give ourselves
				// up to 1.5 MiB to dump the trace.
				//
				// TODO(mknyszek): Remove this when we've migrated off of
				// the old infrastructure.
				t.Logf("text trace too large to dump (%d bytes)", len(s))
			} else {
				t.Log(s)
			}
		} else if t.Failed() || *dumpTraces {
			// We asked to dump the trace or failed. Write the trace to a file.
			t.Logf("wrote trace to file: %s", dumpTraceToFile(t, testName, stress, tb))
		}
	}
	t.Run("Default", func(t *testing.T) {
		runTest(t, false, "")
	})
	t.Run("Stress", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping trace stress tests in short mode")
		}
		runTest(t, true, "")
	})
	t.Run("AllocFree", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping trace alloc/free tests in short mode")
		}
		runTest(t, false, "traceallocfree=1")
	})
}
```