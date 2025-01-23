Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file name `mgcpacer_test.go` and the presence of `TestGcPacer` immediately suggest this code is testing the garbage collector (GC) pacing mechanism. The `runtime_test` package further reinforces this.

2. **High-Level Structure:** Observe the `TestGcPacer` function. It iterates through a slice of `gcExecTest` structs. This hints at a test-driven approach with multiple test cases. Each `gcExecTest` likely represents a different scenario for the GC pacer.

3. **`gcExecTest` Structure:**  Examine the fields of `gcExecTest`. They define parameters for a simulated GC environment:
    * `name`:  Clearly for identification.
    * `gcPercent`:  Relates to the `GOGC` environment variable, a crucial GC setting.
    * `memoryLimit`: Introduces memory constraints.
    * `globalsBytes`, `nCores`:  System configuration.
    * `allocRate`, `scanRate`, `growthRate`, `scannableFrac`, `stackBytes`:  These seem to describe the behavior of the simulated application (how much it allocates, how much data needs scanning, etc.). The `float64Stream` type suggests dynamic changes over time.
    * `length`:  The duration of the simulation (number of GC cycles).
    * `checker`: A function to verify the GC pacer's behavior in this scenario.

4. **Individual Test Cases:**  Scan through the different `gcExecTest` instances. Notice the descriptive names: "Steady", "SteadyBigStacks", "StepAlloc", "HighGOGC", "MemoryLimit", etc. Each name gives a clue about what aspect of the pacer is being tested. For example, "Steady" likely checks the pacer in a stable environment, while "StepAlloc" introduces a sudden change in allocation rate.

5. **`checker` Functions:** Focus on the `checker` functions within each test case. They use assertions (`assertInEpsilon`, `assertInRange`) to verify specific conditions related to GC behavior (e.g., "GC utilization", "goal ratio", "heap goal"). These assertions are key to understanding the expected behavior of the pacer.

6. **Simulation Logic:**  Analyze the core loop within the `TestGcPacer` function.
    * `NewGCController`:  This instantiates the GC pacer under test.
    * The loop iterates `e.length` times, simulating GC cycles.
    * `e.next()`:  This likely fetches the parameters for the current cycle from the `float64Stream` values.
    * `c.StartCycle(...)`:  Initializes the GC cycle in the pacer.
    * The inner loop simulates the GC process itself, incrementing scan work and calling `c.Revise()` to update the pacer with progress. The complexity here suggests a detailed simulation of GC mechanics, including assist pacing.
    * `c.EndCycle(...)`:  Finalizes the GC cycle in the pacer.
    * The `gcCycleResult` struct captures important metrics for each cycle.

7. **Key Concepts:** Identify the core GC pacing concepts being tested:
    * **GC Utilization:** The percentage of CPU time spent on garbage collection. The pacer aims to keep this within a target range.
    * **Heap Goal:** The target heap size after the current GC cycle.
    * **Trigger Ratio/Runway:** Metrics used to determine when to start the next GC cycle.
    * **`GOGC`:**  The percentage of "live" heap data to keep after a GC cycle.
    * **Memory Limit:**  A hard limit on the heap size.
    * **GC Assist:**  A mechanism to slow down allocation when GC needs more resources.

8. **Inference and Examples:** Based on the test names and assertions, infer the functionality being tested and create illustrative examples. For instance, the "StepAlloc" test clearly tests how the pacer reacts to a change in allocation rate. A simple code example demonstrating changing allocation patterns would be relevant.

9. **Command-line Arguments:**  Since this is a unit test file, it doesn't directly handle command-line arguments for the *tested code*. However, it uses the `testing` package, which *does* have command-line flags (like `-test.run`). Mentioning this distinction is important.

10. **Common Mistakes:**  Think about potential pitfalls for users of the GC pacer or the related concepts. Misunderstanding `GOGC` or memory limits are common issues.

11. **Structure the Answer:** Organize the findings logically, starting with a high-level summary and then delving into details. Use clear headings and bullet points for readability.

12. **Review and Refine:**  Read through the generated answer, checking for accuracy, clarity, and completeness. Ensure that the examples are correct and relevant.

By following these steps, we can systematically analyze the provided Go code and extract its key functionalities and the underlying GC concepts it tests.
这个Go语言文件的主要功能是 **测试 Go 运行时环境中的垃圾回收 (GC) 调步器 (pacer)**。

更具体地说，它通过模拟各种内存分配、扫描和增长模式，来验证 GC 调步器是否能够按照预期工作，例如：

* **在稳定状态下保持目标 GC 利用率。**
* **对分配速率、可扫描堆比例等变化做出合理响应。**
* **在高 GOGC 值下维持稳定的 GC 利用率。**
* **在内存受限的情况下正确调整 GC 行为。**

**它可以被认为是 Go 运行时 GC 机制的一部分，特别是负责动态调整 GC 的触发时机和强度，以平衡内存使用和 CPU 开销。**

**以下是用 Go 代码举例说明其功能的推理：**

假设我们有一个 Go 程序，它在运行过程中不断分配内存。GC 调步器的目标是在内存使用量达到一定阈值时触发垃圾回收，以回收不再使用的内存。

**假设的输入：**

* **程序开始运行，分配了少量内存。**
* **随着时间推移，程序以一定的速率持续分配新的内存。**
* **可能存在全局变量和栈上的数据也需要被扫描。**
* **模拟运行时环境设置了 `GOGC=100`，表示目标是在 GC 完成后，堆内存大小是上一次 GC 后存活对象大小的两倍 (100%)。**

**mgcpacer_test.go 的模拟过程（简化）：**

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	// 设置 GOGC (实际测试中是通过 runtime 包的内部机制设置)
	// runtime/mgcpacer_test.go 模拟了 GOGC 的行为

	// 模拟内存分配
	allocate := func(size int) {
		_ = make([]byte, size)
	}

	// 模拟全局变量 (影响扫描)
	var globalData [1024]byte

	// 模拟栈上的数据 (影响扫描)
	var stackData [512]byte
	_ = stackData

	startTime := time.Now()
	allocatedBytes := 0

	for i := 0; i < 100; i++ { // 模拟一段时间的运行
		// 模拟持续的内存分配
		allocSize := 1024 * (i % 10 + 1) // 分配速率有变化
		allocate(allocSize)
		allocatedBytes += allocSize

		// 在实际的 Go 运行时中，GC 调步器会根据内存使用情况和分配速率来决定是否触发 GC
		// mgcpacer_test.go 模拟了这个决策过程

		// 简单地打印当前的内存使用情况 (实际测试中会进行更细致的检查)
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		fmt.Printf("Time: %s, Allocated: %d KB, HeapAlloc: %d KB, NextGC: %d KB\n",
			time.Since(startTime), allocatedBytes/1024, m.HeapAlloc/1024, m.NextGC/1024)

		time.Sleep(10 * time.Millisecond)
	}
}
```

**假设的输出：**

你会看到 `NextGC` 的值会随着分配的内存增加而增长。 当 `HeapAlloc` 接近 `NextGC` 时，Go 运行时会触发垃圾回收。 `mgcpacer_test.go` 中的测试用例会精确地验证 `NextGC` 的计算是否符合预期，例如是否接近目标堆大小。

**代码推理：**

`mgcpacer_test.go` 中的 `gcExecTest` 结构体定义了各种测试场景，包括：

* **`allocRate` (分配速率):**  模拟程序分配内存的速度。可以是恒定的，也可以是变化的（例如阶跃式增长、振荡或随机）。
* **`scanRate` (扫描速率):** 模拟 GC 扫描内存的速度。
* **`growthRate` (增长速率):** 模拟堆内存的增长速度。
* **`scannableFrac` (可扫描比例):**  模拟堆内存中需要被扫描的部分比例。
* **`stackBytes` (栈大小):** 模拟 goroutine 栈的大小，影响扫描工作量。
* **`globalsBytes` (全局变量大小):** 模拟全局变量的大小，影响扫描工作量。
* **`gcPercent` (GOGC 值):**  模拟 `GOGC` 环境变量的影响。
* **`memoryLimit` (内存限制):** 模拟程序运行时的内存限制。

每个测试用例都会运行一段时间（`length`），并在每个模拟的 GC 周期后，通过 `checker` 函数来断言 GC 调步器的行为是否符合预期。例如，断言 `GC utilization` (GC 利用率) 是否接近目标值，`goal ratio` (目标比例) 是否在合理范围内，等等。

**命令行参数的具体处理：**

`mgcpacer_test.go` 本身是一个测试文件，它不直接处理用户提供的命令行参数来改变被测试代码的行为。 然而，Go 的测试框架 `go test` 接受一些标准的命令行参数，例如：

* **`-test.run <regexp>`:**  运行名称匹配正则表达式的测试用例。例如，`go test -test.run Steady` 只运行名字包含 "Steady" 的测试用例。
* **`-test.v`:** 启用详细输出，显示所有测试的运行结果，包括成功的测试。
* **`-test.count n`:** 运行每个测试用例 n 次。
* **`-test.cpuprofile <file>`:** 将 CPU 性能分析数据写入指定文件。
* **`-test.memprofile <file>`:** 将内存性能分析数据写入指定文件。

这些参数控制的是测试的执行方式，而不是被测试的 GC 调步器的行为。 `mgcpacer_test.go` 内部通过 `gcExecTest` 结构体和其字段来模拟不同的输入和场景，从而测试 GC 调步器的各种情况。

**功能归纳（第 1 部分）：**

这部分代码定义了一系列集成测试，用于验证 Go 运行时环境中的 GC 调步器 (pacer) 的功能。 它通过模拟不同的内存分配、扫描、增长模式以及配置参数（如 `GOGC` 和内存限制），来检查调步器是否能够根据预期调整垃圾回收行为，例如维持目标 GC 利用率，并对各种运行条件做出合理响应。  它使用 `gcExecTest` 结构体来定义测试用例，并使用 `checker` 函数来断言每个测试周期后的 GC 行为是否正确。

### 提示词
```
这是路径为go/src/runtime/mgcpacer_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"fmt"
	"math"
	"math/rand"
	. "runtime"
	"testing"
	"time"
)

func TestGcPacer(t *testing.T) {
	t.Parallel()

	const initialHeapBytes = 256 << 10
	for _, e := range []*gcExecTest{
		{
			// The most basic test case: a steady-state heap.
			// Growth to an O(MiB) heap, then constant heap size, alloc/scan rates.
			name:          "Steady",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n >= 25 {
					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// Same as the steady-state case, but lots of stacks to scan relative to the heap size.
			name:          "SteadyBigStacks",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(132.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(2048).sum(ramp(128<<20, 8)),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				// Check the same conditions as the steady-state case, except the old pacer can't
				// really handle this well, so don't check the goal ratio for it.
				n := len(c)
				if n >= 25 {
					// For the pacer redesign, assert something even stronger: at this alloc/scan rate,
					// it should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
				}
			},
		},
		{
			// Same as the steady-state case, but lots of globals to scan relative to the heap size.
			name:          "SteadyBigGlobals",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  128 << 20,
			nCores:        8,
			allocRate:     constant(132.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				// Check the same conditions as the steady-state case, except the old pacer can't
				// really handle this well, so don't check the goal ratio for it.
				n := len(c)
				if n >= 25 {
					// For the pacer redesign, assert something even stronger: at this alloc/scan rate,
					// it should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
				}
			},
		},
		{
			// This tests the GC pacer's response to a small change in allocation rate.
			name:          "StepAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0).sum(ramp(66.0, 1).delay(50)),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        100,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if (n >= 25 && n < 50) || n >= 75 {
					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles
					// and then is able to settle again after a significant jump in allocation rate.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// This tests the GC pacer's response to a large change in allocation rate.
			name:          "HeavyStepAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33).sum(ramp(330, 1).delay(50)),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        100,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if (n >= 25 && n < 50) || n >= 75 {
					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles
					// and then is able to settle again after a significant jump in allocation rate.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// This tests the GC pacer's response to a change in the fraction of the scannable heap.
			name:          "StepScannableFrac",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(128.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(0.2).sum(unit(0.5).delay(50)),
			stackBytes:    constant(8192),
			length:        100,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if (n >= 25 && n < 50) || n >= 75 {
					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles
					// and then is able to settle again after a significant jump in allocation rate.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// Tests the pacer for a high GOGC value with a large heap growth happening
			// in the middle. The purpose of the large heap growth is to check if GC
			// utilization ends up sensitive
			name:          "HighGOGC",
			gcPercent:     1500,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     random(7, 0x53).offset(165),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12), random(0.01, 0x1), unit(14).delay(25)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 12 {
					if n == 26 {
						// In the 26th cycle there's a heap growth. Overshoot is expected to maintain
						// a stable utilization, but we should *never* overshoot more than GOGC of
						// the next cycle.
						assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.90, 15)
					} else {
						// Give a wider goal range here. With such a high GOGC value we're going to be
						// forced to undershoot.
						//
						// TODO(mknyszek): Instead of placing a 0.95 limit on the trigger, make the limit
						// based on absolute bytes, that's based somewhat in how the minimum heap size
						// is determined.
						assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.90, 1.05)
					}

					// Ensure utilization remains stable despite a growth in live heap size
					// at GC #25. This test fails prior to the GC pacer redesign.
					//
					// Because GOGC is so large, we should also be really close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, GCGoalUtilization+0.03)
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.03)
				}
			},
		},
		{
			// This test makes sure that in the face of a varying (in this case, oscillating) allocation
			// rate, the pacer does a reasonably good job of staying abreast of the changes.
			name:          "OscAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     oscillate(13, 0, 8).offset(67),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 12 {
					// After the 12th GC, the heap will stop growing. Now, just make sure that:
					// 1. Utilization isn't varying _too_ much, and
					// 2. The pacer is mostly keeping up with the goal.
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
					assertInRange(t, "GC utilization", c[n-1].gcUtilization, 0.25, 0.3)
				}
			},
		},
		{
			// This test is the same as OscAlloc, but instead of oscillating, the allocation rate is jittery.
			name:          "JitterAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     random(13, 0xf).offset(132),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12), random(0.01, 0xe)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 12 {
					// After the 12th GC, the heap will stop growing. Now, just make sure that:
					// 1. Utilization isn't varying _too_ much, and
					// 2. The pacer is mostly keeping up with the goal.
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.025)
					assertInRange(t, "GC utilization", c[n-1].gcUtilization, 0.25, 0.275)
				}
			},
		},
		{
			// This test is the same as JitterAlloc, but with a much higher allocation rate.
			// The jitter is proportionally the same.
			name:          "HeavyJitterAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     random(33.0, 0x0).offset(330),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12), random(0.01, 0x152)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 13 {
					// After the 12th GC, the heap will stop growing. Now, just make sure that:
					// 1. Utilization isn't varying _too_ much, and
					// 2. The pacer is mostly keeping up with the goal.
					// We start at the 13th here because we want to use the 12th as a reference.
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
					// Unlike the other tests, GC utilization here will vary more and tend higher.
					// Just make sure it's not going too crazy.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.05)
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[11].gcUtilization, 0.05)
				}
			},
		},
		{
			// This test sets a slow allocation rate and a small heap (close to the minimum heap size)
			// to try to minimize the difference between the trigger and the goal.
			name:          "SmallHeapSlowAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(1.0),
			scanRate:      constant(2048.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 3)),
			scannableFrac: constant(0.01),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 4 {
					// After the 4th GC, the heap will stop growing.
					// First, let's make sure we're finishing near the goal, with some extra
					// room because we're probably going to be triggering early.
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.925, 1.025)
					// Next, let's make sure there's some minimum distance between the goal
					// and the trigger. It should be proportional to the runway (hence the
					// trigger ratio check, instead of a check against the runway).
					assertInRange(t, "trigger ratio", c[n-1].triggerRatio(), 0.925, 0.975)
				}
				if n > 25 {
					// Double-check that GC utilization looks OK.

					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)
					// Make sure GC utilization has mostly levelled off.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.05)
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[11].gcUtilization, 0.05)
				}
			},
		},
		{
			// This test sets a slow allocation rate and a medium heap (around 10x the min heap size)
			// to try to minimize the difference between the trigger and the goal.
			name:          "MediumHeapSlowAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(1.0),
			scanRate:      constant(2048.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 8)),
			scannableFrac: constant(0.01),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 9 {
					// After the 4th GC, the heap will stop growing.
					// First, let's make sure we're finishing near the goal, with some extra
					// room because we're probably going to be triggering early.
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.925, 1.025)
					// Next, let's make sure there's some minimum distance between the goal
					// and the trigger. It should be proportional to the runway (hence the
					// trigger ratio check, instead of a check against the runway).
					assertInRange(t, "trigger ratio", c[n-1].triggerRatio(), 0.925, 0.975)
				}
				if n > 25 {
					// Double-check that GC utilization looks OK.

					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)
					// Make sure GC utilization has mostly levelled off.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.05)
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[11].gcUtilization, 0.05)
				}
			},
		},
		{
			// This test sets a slow allocation rate and a large heap to try to minimize the
			// difference between the trigger and the goal.
			name:          "LargeHeapSlowAlloc",
			gcPercent:     100,
			memoryLimit:   math.MaxInt64,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(1.0),
			scanRate:      constant(2048.0),
			growthRate:    constant(4.0).sum(ramp(-3.0, 12)),
			scannableFrac: constant(0.01),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 13 {
					// After the 4th GC, the heap will stop growing.
					// First, let's make sure we're finishing near the goal.
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
					// Next, let's make sure there's some minimum distance between the goal
					// and the trigger. It should be around the default minimum heap size.
					assertInRange(t, "runway", c[n-1].runway(), DefaultHeapMinimum-64<<10, DefaultHeapMinimum+64<<10)
				}
				if n > 25 {
					// Double-check that GC utilization looks OK.

					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)
					// Make sure GC utilization has mostly levelled off.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.05)
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[11].gcUtilization, 0.05)
				}
			},
		},
		{
			// The most basic test case with a memory limit: a steady-state heap.
			// Growth to an O(MiB) heap, then constant heap size, alloc/scan rates.
			// Provide a lot of room for the limit. Essentially, this should behave just like
			// the "Steady" test. Note that we don't simulate non-heap overheads, so the
			// memory limit and the heap limit are identical.
			name:          "SteadyMemoryLimit",
			gcPercent:     100,
			memoryLimit:   512 << 20,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if peak := c[n-1].heapPeak; peak >= applyMemoryLimitHeapGoalHeadroom(512<<20) {
					t.Errorf("peak heap size reaches heap limit: %d", peak)
				}
				if n >= 25 {
					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// This is the same as the previous test, but gcPercent = -1, so the heap *should* grow
			// all the way to the peak.
			name:          "SteadyMemoryLimitNoGCPercent",
			gcPercent:     -1,
			memoryLimit:   512 << 20,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(2.0).sum(ramp(-1.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if goal := c[n-1].heapGoal; goal != applyMemoryLimitHeapGoalHeadroom(512<<20) {
					t.Errorf("heap goal is not the heap limit: %d", goal)
				}
				if n >= 25 {
					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// This test ensures that the pacer doesn't fall over even when the live heap exceeds
			// the memory limit. It also makes sure GC utilization actually rises to push back.
			name:          "ExceedMemoryLimit",
			gcPercent:     100,
			memoryLimit:   512 << 20,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(3.5).sum(ramp(-2.5, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 12 {
					// We're way over the memory limit, so we want to make sure our goal is set
					// as low as it possibly can be.
					if goal, live := c[n-1].heapGoal, c[n-1].heapLive; goal != live {
						t.Errorf("heap goal is not equal to live heap: %d != %d", goal, live)
					}
				}
				if n >= 25 {
					// Due to memory pressure, we should scale to 100% GC CPU utilization.
					// Note that in practice this won't actually happen because of the CPU limiter,
					// but it's not the pacer's job to limit CPU usage.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, 1.0, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					// In this case, that just means it's not wavering around a whole bunch.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
				}
			},
		},
		{
			// Same as the previous test, but with gcPercent = -1.
			name:          "ExceedMemoryLimitNoGCPercent",
			gcPercent:     -1,
			memoryLimit:   512 << 20,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(3.5).sum(ramp(-2.5, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n < 10 {
					if goal := c[n-1].heapGoal; goal != applyMemoryLimitHeapGoalHeadroom(512<<20) {
						t.Errorf("heap goal is not the heap limit: %d", goal)
					}
				}
				if n > 12 {
					// We're way over the memory limit, so we want to make sure our goal is set
					// as low as it possibly can be.
					if goal, live := c[n-1].heapGoal, c[n-1].heapLive; goal != live {
						t.Errorf("heap goal is not equal to live heap: %d != %d", goal, live)
					}
				}
				if n >= 25 {
					// Due to memory pressure, we should scale to 100% GC CPU utilization.
					// Note that in practice this won't actually happen because of the CPU limiter,
					// but it's not the pacer's job to limit CPU usage.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, 1.0, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles.
					// In this case, that just means it's not wavering around a whole bunch.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
				}
			},
		},
		{
			// This test ensures that the pacer maintains the memory limit as the heap grows.
			name:          "MaintainMemoryLimit",
			gcPercent:     100,
			memoryLimit:   512 << 20,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(3.0).sum(ramp(-2.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if n > 12 {
					// We're trying to saturate the memory limit.
					if goal := c[n-1].heapGoal; goal != applyMemoryLimitHeapGoalHeadroom(512<<20) {
						t.Errorf("heap goal is not the heap limit: %d", goal)
					}
				}
				if n >= 25 {
					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization,
					// even with the additional memory pressure.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles and
					// that it's meeting its goal.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		{
			// Same as the previous test, but with gcPercent = -1.
			name:          "MaintainMemoryLimitNoGCPercent",
			gcPercent:     -1,
			memoryLimit:   512 << 20,
			globalsBytes:  32 << 10,
			nCores:        8,
			allocRate:     constant(33.0),
			scanRate:      constant(1024.0),
			growthRate:    constant(3.0).sum(ramp(-2.0, 12)),
			scannableFrac: constant(1.0),
			stackBytes:    constant(8192),
			length:        50,
			checker: func(t *testing.T, c []gcCycleResult) {
				n := len(c)
				if goal := c[n-1].heapGoal; goal != applyMemoryLimitHeapGoalHeadroom(512<<20) {
					t.Errorf("heap goal is not the heap limit: %d", goal)
				}
				if n >= 25 {
					// At this alloc/scan rate, the pacer should be extremely close to the goal utilization,
					// even with the additional memory pressure.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, GCGoalUtilization, 0.005)

					// Make sure the pacer settles into a non-degenerate state in at least 25 GC cycles and
					// that it's meeting its goal.
					assertInEpsilon(t, "GC utilization", c[n-1].gcUtilization, c[n-2].gcUtilization, 0.005)
					assertInRange(t, "goal ratio", c[n-1].goalRatio(), 0.95, 1.05)
				}
			},
		},
		// TODO(mknyszek): Write a test that exercises the pacer's hard goal.
		// This is difficult in the idealized model this testing framework places
		// the pacer in, because the calculated overshoot is directly proportional
		// to the runway for the case of the expected work.
		// However, it is still possible to trigger this case if something exceptional
		// happens between calls to revise; the framework just doesn't support this yet.
	} {
		e := e
		t.Run(e.name, func(t *testing.T) {
			t.Parallel()

			c := NewGCController(e.gcPercent, e.memoryLimit)
			var bytesAllocatedBlackLast int64
			results := make([]gcCycleResult, 0, e.length)
			for i := 0; i < e.length; i++ {
				cycle := e.next()
				c.StartCycle(cycle.stackBytes, e.globalsBytes, cycle.scannableFrac, e.nCores)

				// Update pacer incrementally as we complete scan work.
				const (
					revisePeriod = 500 * time.Microsecond
					rateConv     = 1024 * float64(revisePeriod) / float64(time.Millisecond)
				)
				var nextHeapMarked int64
				if i == 0 {
					nextHeapMarked = initialHeapBytes
				} else {
					nextHeapMarked = int64(float64(int64(c.HeapMarked())-bytesAllocatedBlackLast) * cycle.growthRate)
				}
				globalsScanWorkLeft := int64(e.globalsBytes)
				stackScanWorkLeft := int64(cycle.stackBytes)
				heapScanWorkLeft := int64(float64(nextHeapMarked) * cycle.scannableFrac)
				doWork := func(work int64) (int64, int64, int64) {
					var deltas [3]int64

					// Do globals work first, then stacks, then heap.
					for i, workLeft := range []*int64{&globalsScanWorkLeft, &stackScanWorkLeft, &heapScanWorkLeft} {
						if *workLeft == 0 {
							continue
						}
						if *workLeft > work {
							deltas[i] += work
							*workLeft -= work
							work = 0
							break
						} else {
							deltas[i] += *workLeft
							work -= *workLeft
							*workLeft = 0
						}
					}
					return deltas[0], deltas[1], deltas[2]
				}
				var (
					gcDuration          int64
					assistTime          int64
					bytesAllocatedBlack int64
				)
				for heapScanWorkLeft+stackScanWorkLeft+globalsScanWorkLeft > 0 {
					// Simulate GC assist pacing.
					//
					// Note that this is an idealized view of the GC assist pacing
					// mechanism.

					// From the assist ratio and the alloc and scan rates, we can idealize what
					// the GC CPU utilization looks like.
					//
					// We start with assistRatio = (bytes of scan work) / (bytes of runway) (by definition).
					//
					// Over revisePeriod, we can also calculate how many bytes are scanned and
					// allocated, given some GC CPU utilization u:
					//
					//     bytesScanned   = scanRate  * rateConv * nCores * u
					//     bytesAllocated = allocRate * rateConv * nCores * (1 - u)
					//
					// During revisePeriod, assistRatio is kept constant, and GC assists kick in to
					// maintain it. Specifically, they act to prevent too many bytes being allocated
					// compared to how many bytes are scanned. It directly defines the ratio of
					// bytesScanned to bytesAllocated over this period, hence:
					//
					//     assistRatio = bytesScanned / bytesAllocated
					//
					// From this, we can solve for utilization, because everything else has already
					// been determined:
					//
					//     assistRatio = (scanRate * rateConv * nCores * u) / (allocRate * rateConv * nCores * (1 - u))
					//     assistRatio = (scanRate * u) / (allocRate * (1 - u))
					//     assistRatio * allocRate * (1-u) = scanRate * u
					//     assistRatio * allocRate - assistRatio * allocRate * u = scanRate * u
					//     assistRatio * allocRate = assistRatio * allocRate * u + scanRate * u
					//     assistRatio * allocRate = (assistRatio * allocRate + scanRate) * u
					//     u = (assistRatio * allocRate) / (assistRatio * allocRate + scanRate)
					//
					// Note that this may give a utilization that is _less_ than GCBackgroundUtilization,
					// which isn't possible in practice because of dedicated workers. Thus, this case
					// must be interpreted as GC assists not kicking in at all, and just round up. All
					// downstream values will then have this accounted for.
					assistRatio := c.AssistWorkPerByte()
					utilization := assistRatio * cycle.allocRate / (assistRatio*cycle.allocRate + cycle.scanRate)
					if utilization < GCBackgroundUtilization {
						utilization = GCBackgroundUtilization
					}

					// Knowing the utilization, calculate bytesScanned and bytesAllocated.
					bytesScanned := int64(cycle.scanRate * rateConv * float64(e.nCores) * utilization)
					bytesAllocated := int64(cycle.allocRate * rateConv * float64(e.nCores) * (1 - utilization))

					// Subtract work from our model.
					globalsScanned, stackScanned, heapScanned := doWork(bytesScanned)

					// doWork may not use all of bytesScanned.
					// In this case, the GC actually ends sometime in this period.
					// Let's figure out when, exactly, and adjust bytesAllocated too.
					actualElapsed := revisePeriod
					actualAllocated := bytesAllocated
					if actualScanned := globalsScanned + stackScanned + heapScanned; actualScanned < bytesScanned {
						// actualScanned = scanRate * rateConv * (t / revisePeriod) * nCores * u
						// => t = actualScanned * revisePeriod / (scanRate * rateConv * nCores * u)
						actualElapsed = time.Duration(float64(actualScanned) * float64(revisePeriod) / (cycle.scanRate * rateConv * float64(e.nCores) * utilization))
						actualAllocated = int64(cycle.allocRate * rateConv * float64(actualElapsed) / float64(revisePeriod) * float64(e.nCores) * (1 - utilization))
					}

					// Ask the pacer to revise.
					c.Revise(GCControllerReviseDelta{
						HeapLive:        actualAllocated,
						HeapScan:        int64(float64(actualAllocated) * cycle.scannableFrac),
						HeapScanWork:    heapScanned,
						StackScanWork:   stackScanned,
						GlobalsScanWork: globalsScanned,
					})

					// Accumulate variables.
					assistTime += int64(float64(actualElapsed) * float64(e.nCores) * (utilization - GCBackgroundUtilization))
					gcDuration += int64(actualElapsed)
					bytesAllocatedBlack += actualAllocated
				}

				// Put together the results, log them, and concatenate them.
				result := gcCycleResult{
					cycle:         i + 1,
					heapLive:      c.HeapMarked(),
					heapScannable: int64(float64(int64(c.HeapMarked())-bytesAllocatedBlackLast) * cycle.scannableFrac),
					heapTrigger:   c.Triggered(),
					heapPeak:      c.HeapLive(),
					heapGoal:      c.HeapGoal(),
					gcUtilization: float64(assistTime)/(float64(gcDuration)*float64(e.nCores)) + GCBackgroundUtilization,
				}
				t.Log("GC", result.String())
				results = append(results, result)

				// Run the checker for this test.
				e.check(t, results)

				c.EndCycle(uint64(nextHeapMarked+bytesAllocatedBlack), assistTime, gcDuration, e.nCores)

				bytesAllocatedBlackLast = bytesAllocatedBlack
			}
		})
	}
}

type gcExecTest struct {
	name string

	gcPercent    int
	memoryLimit  int64
	globalsBytes uint64
	nCores       int

	allocRate     float64Stream // > 0, KiB / cpu-ms
	scanRate      float64Stream // > 0, KiB / cpu-ms
	growthRate    float64Stream // > 0
	scannableFrac float64Stream // Clamped to [0, 1]
	stackBytes    float64Stream // Multiple of 2048.
	length        int

	checker func(*testing.T, []gcCycleResult)
}

// minRate is an arbitrary minimum for allocRate, scanRate, and growthRate.
// These values just cannot be zero.
const minRate = 0.0001

func (e *gcExecTest) next() gcCycle {
	return gcCycle{
		allocRate:     e.allocRate.min(minRate)(),
		scanRate:      e.scanRate.min(minRate)(),
		growthRate:    e.growthRate.min(minRate)(),
		scannableFrac: e.scannableFrac.limit(0, 1)(),
		stackBytes:    uint64(e.stackBytes.quantize(2048).min(0)()),
	}
}

func (e *gcExecTest) check(t *testing.T, results []gcCycleResult) {
	t.Helper()

	// Do some basic general checks first.
	n := len(results)
	switch n {
	case 0:
		t.Fatal("no results passed to check")
		return
	case 1:
		if results[0].cycle != 1 {
			t.Error("first cycle has incorrect number")
		}
	default:
		if results[n-1].cycle != results[n-2].cycle+1 {
			t.E
```