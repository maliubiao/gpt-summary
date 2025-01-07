Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code snippet, which is part of `go/src/runtime/pprof/pprof_test.go`. It also asks for specifics like the Go features being tested, code examples, command-line arguments (if any), and common pitfalls. This is just the *first* part of a larger file.

2. **Initial Scan and Keywords:** I'll quickly scan the code for recognizable patterns and keywords:
    * `package pprof`:  This confirms it's part of the `pprof` package, which deals with profiling.
    * `import`: Lists various standard library packages used, hinting at the functionality (testing, time, sync, runtime, etc.). The presence of `internal/profile` is significant as it directly relates to the profile data format.
    * Function names starting with `Test`:  Indicates this is a test file.
    * Function names like `TestCPUProfile`, `TestBlockProfile`: Suggests specific types of profiling being tested.
    * Helper functions like `cpuHogger`, `cpuHog1`, `cpuHog2`: Likely used to generate CPU load for testing CPU profiling.
    * Calls to `StartCPUProfile`, `StopCPUProfile`: Directly related to initiating and stopping CPU profiling.
    * Use of `runtime.GOMAXPROCS`: Related to testing concurrency aspects of profiling.
    * Mentions of "inlining": Suggests tests related to how inlined function calls are handled in profiles.
    * Mentions of "recursion":  Suggests tests related to recursive function calls in profiles.
    * `parseProfile`:  A function to parse the profile data.
    * `cpuProfilingBroken`:  Indicates handling of platforms where CPU profiling might be unreliable.
    * `diffCPUTime`:  A function likely used to measure CPU time for comparison.
    * `blockevent`, `runtime.SetBlockProfileRate`: Related to block profiling.

3. **Identify Core Functionality:** Based on the initial scan, the primary function of this code snippet is to **test the CPU and Block profiling features of the `pprof` package**. It aims to verify the correctness and robustness of these profiling mechanisms.

4. **Group Tests by Feature:** I can group the tests based on the profiling type they are targeting:
    * **CPU Profiling:** `TestCPUProfile`, `TestCPUProfileMultithreaded`, `TestCPUProfileMultithreadMagnitude`, `TestCPUProfileInlining`, `TestCPUProfileRecursion`, `TestCPUProfileWithFork`, `TestGoroutineSwitch`, `TestMathBigDivide`, `TestMorestack`.
    * **Block Profiling:** `TestBlockProfile`, `TestBlockProfileBias`.

5. **Infer Specific Test Scenarios:**  For each group, I'll try to understand the specific scenarios being tested:
    * **CPU Profiling:**
        * Basic functionality (capturing samples during CPU-intensive work).
        * Multithreading scenarios (ensuring profiles capture activity from multiple goroutines).
        * Accuracy of CPU time measurement (comparing against OS-reported usage).
        * Handling of inlined function calls.
        * Handling of recursive function calls.
        * Interaction of profiling with `fork` system calls.
        * Correctness when goroutines switch contexts.
        * Profiling specific operations like division in `math/big`.
        * Profiling stack growth (`morestack`).
    * **Block Profiling:**
        * Basic functionality (capturing blocking events on channels, mutexes, and conditions).
        * Testing the output format (both text and protocol buffer).
        * Testing for bias in reporting blocking times for frequent short vs. infrequent long blocking events.

6. **Look for Code Examples:** The request asks for code examples. The test functions themselves serve as excellent examples of how to use the profiling APIs (`StartCPUProfile`, `StopCPUProfile`, `runtime.SetBlockProfileRate`). I can extract the core parts of these tests as examples.

7. **Consider Command-Line Arguments:**  I'll check if any tests directly process command-line arguments. In this snippet, the tests themselves are run by the `go test` command, which has its own set of arguments. However, the *code being tested* doesn't seem to directly handle command-line arguments within this snippet.

8. **Identify Potential Pitfalls:** I'll look for areas where users might make mistakes when using the profiling features based on the test scenarios:
    * Not running the profiler long enough to capture meaningful data.
    * Issues with profiling on specific operating systems or architectures (as indicated by `cpuProfilingBroken`).
    * Misinterpreting the profile data, especially when dealing with inlined or recursive functions.

9. **Structure the Answer:** I'll organize the answer logically, starting with a general summary of the functionality and then diving into specifics for CPU and Block profiling. I will include code examples, discuss command-line arguments (if applicable), and highlight potential pitfalls.

10. **Refine and Review:** Finally, I'll review the answer for accuracy, clarity, and completeness, ensuring it addresses all parts of the request. Since this is part 1 of 3, I will explicitly state that this summary covers only the functionality present in the *provided* code snippet.

By following this thought process, I can systematically analyze the code and generate a comprehensive and accurate answer to the request. The iterative nature of scanning, identifying, grouping, and refining helps ensure all aspects are considered.
这个Go语言代码片段是 `go/src/runtime/pprof/pprof_test.go` 文件的一部分，其主要功能是**测试 Go 语言的 CPU 性能剖析（Profiling）功能**。

**功能归纳:**

这段代码主要通过编写各种测试用例来验证 `runtime/pprof` 包中关于 CPU 性能剖析的实现是否正确。它覆盖了以下几个核心方面：

1. **基本的 CPU 性能剖析功能:**  测试能否正确启动和停止 CPU 性能剖析，并生成包含 CPU 使用信息的 profile 数据。
2. **多线程环境下的 CPU 性能剖析:**  测试在并发执行的 Goroutine 中，CPU 性能剖析是否能正确记录各个 Goroutine 的 CPU 使用情况。
3. **CPU 性能剖析的精度:**  通过与操作系统报告的 CPU 使用情况进行比较，来验证 Go 语言的 CPU 性能剖析的准确性。
4. **内联函数对 CPU 性能剖析的影响:** 测试 CPU 性能剖析是否能正确处理内联函数，并能在 profile 数据中体现内联函数的调用关系。
5. **递归函数对 CPU 性能剖析的影响:** 测试 CPU 性能剖析是否能正确处理递归函数调用，并能在 profile 数据中清晰地展示递归调用栈。
6. **与其他 Go 运行时机制的交互:**  例如，测试 CPU 性能剖析在进行系统调用 `fork` 时是否会产生问题，以及在 Goroutine 切换时是否会记录不一致的状态。
7. **特定场景下的 CPU 性能剖析:**  例如，测试对 `math/big` 包中的大数除法操作进行性能剖析是否正常。
8. **测试由于栈增长 (`morestack`) 导致的性能开销:**  验证性能剖析是否能捕捉到由于 Goroutine 栈增长而产生的 CPU 使用。
9. **测试阻塞性能剖析 (Block Profiling):**  虽然这部分内容在提供的代码片段中也有涉及，但主要集中在 CPU 剖析的测试上。代码中测试了在各种阻塞场景下，例如通道的发送和接收、互斥锁的竞争、条件变量的等待等，是否能正确记录阻塞事件。

**以下是用 Go 代码举例说明 CPU 性能剖析功能的实现:**

假设我们有一个需要进行性能分析的函数 `myFunction`:

```go
package main

import (
	"fmt"
	"os"
	"runtime/pprof"
	"time"
)

func myFunction() {
	// 模拟一些 CPU 密集型操作
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i * i
	}
	fmt.Println(sum)
}

func main() {
	// 创建一个文件用于保存 CPU profile 数据
	f, err := os.Create("cpu.prof")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// 启动 CPU 性能剖析
	if err := pprof.StartCPUProfile(f); err != nil {
		panic(err)
	}
	defer pprof.StopCPUProfile()

	// 执行需要分析的代码
	myFunction()

	fmt.Println("CPU profiling finished. Check cpu.prof")
}
```

**假设的输入与输出:**

* **输入:**  运行上述 Go 代码。
* **输出:**
    * 终端会打印出 `myFunction` 计算的结果。
    * 终端会打印出 "CPU profiling finished. Check cpu.prof"。
    * 当前目录下会生成一个名为 `cpu.prof` 的文件，该文件包含了 CPU 性能剖析的数据。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。但是，`runtime/pprof` 包提供的功能通常与 `go tool pprof` 命令行工具结合使用。用户可以通过以下命令来分析生成的 `cpu.prof` 文件：

```bash
go tool pprof cpu.prof
```

`go tool pprof` 提供了丰富的交互式命令，用于查看和分析 profile 数据，例如：

* `top`: 显示占用 CPU 时间最多的函数。
* `web`:  以图形化的方式展示调用关系和 CPU 耗时。
* `list <function_name>`: 显示特定函数的源代码以及 CPU 耗时信息。

**使用者易犯错的点:**

一个常见的错误是**在性能分析期间执行的代码量不足**，导致 profile 数据中样本过少，无法准确反映性能瓶颈。例如：

```go
package main

import (
	"fmt"
	"os"
	"runtime/pprof"
)

func shortFunction() {
	fmt.Println("This function runs quickly")
}

func main() {
	f, err := os.Create("cpu.prof")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	shortFunction() // 执行时间很短
}
```

在这种情况下，由于 `shortFunction` 执行得太快，可能无法采集到足够的 CPU profile 样本，导致分析结果不具有代表性。

**总结这段代码的功能:**

总而言之，这段代码片段是 Go 语言 `runtime/pprof` 包中关于 CPU 性能剖析功能的测试代码。它通过各种测试用例，验证了 CPU 性能剖析在不同场景下的正确性和可靠性，包括单线程、多线程、涉及内联函数、递归函数以及与其他运行时机制交互的情况。 这段代码为确保 Go 语言的 CPU 性能剖析功能能够准确地帮助开发者定位性能瓶颈起着至关重要的作用。

Prompt: 
```
这是路径为go/src/runtime/pprof/pprof_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js

package pprof

import (
	"bytes"
	"context"
	"fmt"
	"internal/abi"
	"internal/profile"
	"internal/syscall/unix"
	"internal/testenv"
	"io"
	"iter"
	"math"
	"math/big"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	_ "unsafe"
)

func cpuHogger(f func(x int) int, y *int, dur time.Duration) {
	// We only need to get one 100 Hz clock tick, so we've got
	// a large safety buffer.
	// But do at least 500 iterations (which should take about 100ms),
	// otherwise TestCPUProfileMultithreaded can fail if only one
	// thread is scheduled during the testing period.
	t0 := time.Now()
	accum := *y
	for i := 0; i < 500 || time.Since(t0) < dur; i++ {
		accum = f(accum)
	}
	*y = accum
}

var (
	salt1 = 0
	salt2 = 0
)

// The actual CPU hogging function.
// Must not call other functions nor access heap/globals in the loop,
// otherwise under race detector the samples will be in the race runtime.
func cpuHog1(x int) int {
	return cpuHog0(x, 1e5)
}

func cpuHog0(x, n int) int {
	foo := x
	for i := 0; i < n; i++ {
		if foo > 0 {
			foo *= foo
		} else {
			foo *= foo + 1
		}
	}
	return foo
}

func cpuHog2(x int) int {
	foo := x
	for i := 0; i < 1e5; i++ {
		if foo > 0 {
			foo *= foo
		} else {
			foo *= foo + 2
		}
	}
	return foo
}

// Return a list of functions that we don't want to ever appear in CPU
// profiles. For gccgo, that list includes the sigprof handler itself.
func avoidFunctions() []string {
	if runtime.Compiler == "gccgo" {
		return []string{"runtime.sigprof"}
	}
	return nil
}

func TestCPUProfile(t *testing.T) {
	matches := matchAndAvoidStacks(stackContains, []string{"runtime/pprof.cpuHog1"}, avoidFunctions())
	testCPUProfile(t, matches, func(dur time.Duration) {
		cpuHogger(cpuHog1, &salt1, dur)
	})
}

func TestCPUProfileMultithreaded(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	matches := matchAndAvoidStacks(stackContains, []string{"runtime/pprof.cpuHog1", "runtime/pprof.cpuHog2"}, avoidFunctions())
	testCPUProfile(t, matches, func(dur time.Duration) {
		c := make(chan int)
		go func() {
			cpuHogger(cpuHog1, &salt1, dur)
			c <- 1
		}()
		cpuHogger(cpuHog2, &salt2, dur)
		<-c
	})
}

func TestCPUProfileMultithreadMagnitude(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("issue 35057 is only confirmed on Linux")
	}

	// Linux [5.9,5.16) has a kernel bug that can break CPU timers on newly
	// created threads, breaking our CPU accounting.
	major, minor := unix.KernelVersion()
	t.Logf("Running on Linux %d.%d", major, minor)
	defer func() {
		if t.Failed() {
			t.Logf("Failure of this test may indicate that your system suffers from a known Linux kernel bug fixed on newer kernels. See https://golang.org/issue/49065.")
		}
	}()

	// Disable on affected builders to avoid flakiness, but otherwise keep
	// it enabled to potentially warn users that they are on a broken
	// kernel.
	if testenv.Builder() != "" && (runtime.GOARCH == "386" || runtime.GOARCH == "amd64") {
		have59 := major > 5 || (major == 5 && minor >= 9)
		have516 := major > 5 || (major == 5 && minor >= 16)
		if have59 && !have516 {
			testenv.SkipFlaky(t, 49065)
		}
	}

	// Run a workload in a single goroutine, then run copies of the same
	// workload in several goroutines. For both the serial and parallel cases,
	// the CPU time the process measures with its own profiler should match the
	// total CPU usage that the OS reports.
	//
	// We could also check that increases in parallelism (GOMAXPROCS) lead to a
	// linear increase in the CPU usage reported by both the OS and the
	// profiler, but without a guarantee of exclusive access to CPU resources
	// that is likely to be a flaky test.

	// Require the smaller value to be within 10%, or 40% in short mode.
	maxDiff := 0.10
	if testing.Short() {
		maxDiff = 0.40
	}

	compare := func(a, b time.Duration, maxDiff float64) error {
		if a <= 0 || b <= 0 {
			return fmt.Errorf("Expected both time reports to be positive")
		}

		if a < b {
			a, b = b, a
		}

		diff := float64(a-b) / float64(a)
		if diff > maxDiff {
			return fmt.Errorf("CPU usage reports are too different (limit -%.1f%%, got -%.1f%%)", maxDiff*100, diff*100)
		}

		return nil
	}

	for _, tc := range []struct {
		name    string
		workers int
	}{
		{
			name:    "serial",
			workers: 1,
		},
		{
			name:    "parallel",
			workers: runtime.GOMAXPROCS(0),
		},
	} {
		// check that the OS's perspective matches what the Go runtime measures.
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Running with %d workers", tc.workers)

			var userTime, systemTime time.Duration
			matches := matchAndAvoidStacks(stackContains, []string{"runtime/pprof.cpuHog1"}, avoidFunctions())
			acceptProfile := func(t *testing.T, p *profile.Profile) bool {
				if !matches(t, p) {
					return false
				}

				ok := true
				for i, unit := range []string{"count", "nanoseconds"} {
					if have, want := p.SampleType[i].Unit, unit; have != want {
						t.Logf("pN SampleType[%d]; %q != %q", i, have, want)
						ok = false
					}
				}

				// cpuHog1 called below is the primary source of CPU
				// load, but there may be some background work by the
				// runtime. Since the OS rusage measurement will
				// include all work done by the process, also compare
				// against all samples in our profile.
				var value time.Duration
				for _, sample := range p.Sample {
					value += time.Duration(sample.Value[1]) * time.Nanosecond
				}

				totalTime := userTime + systemTime
				t.Logf("compare %s user + %s system = %s vs %s", userTime, systemTime, totalTime, value)
				if err := compare(totalTime, value, maxDiff); err != nil {
					t.Logf("compare got %v want nil", err)
					ok = false
				}

				return ok
			}

			testCPUProfile(t, acceptProfile, func(dur time.Duration) {
				userTime, systemTime = diffCPUTime(t, func() {
					var wg sync.WaitGroup
					var once sync.Once
					for i := 0; i < tc.workers; i++ {
						wg.Add(1)
						go func() {
							defer wg.Done()
							var salt = 0
							cpuHogger(cpuHog1, &salt, dur)
							once.Do(func() { salt1 = salt })
						}()
					}
					wg.Wait()
				})
			})
		})
	}
}

// containsInlinedCall reports whether the function body for the function f is
// known to contain an inlined function call within the first maxBytes bytes.
func containsInlinedCall(f any, maxBytes int) bool {
	_, found := findInlinedCall(f, maxBytes)
	return found
}

// findInlinedCall returns the PC of an inlined function call within
// the function body for the function f if any.
func findInlinedCall(f any, maxBytes int) (pc uint64, found bool) {
	fFunc := runtime.FuncForPC(uintptr(abi.FuncPCABIInternal(f)))
	if fFunc == nil || fFunc.Entry() == 0 {
		panic("failed to locate function entry")
	}

	for offset := 0; offset < maxBytes; offset++ {
		innerPC := fFunc.Entry() + uintptr(offset)
		inner := runtime.FuncForPC(innerPC)
		if inner == nil {
			// No function known for this PC value.
			// It might simply be misaligned, so keep searching.
			continue
		}
		if inner.Entry() != fFunc.Entry() {
			// Scanned past f and didn't find any inlined functions.
			break
		}
		if inner.Name() != fFunc.Name() {
			// This PC has f as its entry-point, but is not f. Therefore, it must be a
			// function inlined into f.
			return uint64(innerPC), true
		}
	}

	return 0, false
}

func TestCPUProfileInlining(t *testing.T) {
	if !containsInlinedCall(inlinedCaller, 4<<10) {
		t.Skip("Can't determine whether inlinedCallee was inlined into inlinedCaller.")
	}

	matches := matchAndAvoidStacks(stackContains, []string{"runtime/pprof.inlinedCallee", "runtime/pprof.inlinedCaller"}, avoidFunctions())
	p := testCPUProfile(t, matches, func(dur time.Duration) {
		cpuHogger(inlinedCaller, &salt1, dur)
	})

	// Check if inlined function locations are encoded correctly. The inlinedCalee and inlinedCaller should be in one location.
	for _, loc := range p.Location {
		hasInlinedCallerAfterInlinedCallee, hasInlinedCallee := false, false
		for _, line := range loc.Line {
			if line.Function.Name == "runtime/pprof.inlinedCallee" {
				hasInlinedCallee = true
			}
			if hasInlinedCallee && line.Function.Name == "runtime/pprof.inlinedCaller" {
				hasInlinedCallerAfterInlinedCallee = true
			}
		}
		if hasInlinedCallee != hasInlinedCallerAfterInlinedCallee {
			t.Fatalf("want inlinedCallee followed by inlinedCaller, got separate Location entries:\n%v", p)
		}
	}
}

func inlinedCaller(x int) int {
	x = inlinedCallee(x, 1e5)
	return x
}

func inlinedCallee(x, n int) int {
	return cpuHog0(x, n)
}

//go:noinline
func dumpCallers(pcs []uintptr) {
	if pcs == nil {
		return
	}

	skip := 2 // Callers and dumpCallers
	runtime.Callers(skip, pcs)
}

//go:noinline
func inlinedCallerDump(pcs []uintptr) {
	inlinedCalleeDump(pcs)
}

func inlinedCalleeDump(pcs []uintptr) {
	dumpCallers(pcs)
}

type inlineWrapperInterface interface {
	dump(stack []uintptr)
}

type inlineWrapper struct {
}

func (h inlineWrapper) dump(pcs []uintptr) {
	dumpCallers(pcs)
}

func inlinedWrapperCallerDump(pcs []uintptr) {
	var h inlineWrapperInterface
	h = &inlineWrapper{}
	h.dump(pcs)
}

func TestCPUProfileRecursion(t *testing.T) {
	matches := matchAndAvoidStacks(stackContains, []string{"runtime/pprof.inlinedCallee", "runtime/pprof.recursionCallee", "runtime/pprof.recursionCaller"}, avoidFunctions())
	p := testCPUProfile(t, matches, func(dur time.Duration) {
		cpuHogger(recursionCaller, &salt1, dur)
	})

	// check the Location encoding was not confused by recursive calls.
	for i, loc := range p.Location {
		recursionFunc := 0
		for _, line := range loc.Line {
			if name := line.Function.Name; name == "runtime/pprof.recursionCaller" || name == "runtime/pprof.recursionCallee" {
				recursionFunc++
			}
		}
		if recursionFunc > 1 {
			t.Fatalf("want at most one recursionCaller or recursionCallee in one Location, got a violating Location (index: %d):\n%v", i, p)
		}
	}
}

func recursionCaller(x int) int {
	y := recursionCallee(3, x)
	return y
}

func recursionCallee(n, x int) int {
	if n == 0 {
		return 1
	}
	y := inlinedCallee(x, 1e4)
	return y * recursionCallee(n-1, x)
}

func recursionChainTop(x int, pcs []uintptr) {
	if x < 0 {
		return
	}
	recursionChainMiddle(x, pcs)
}

func recursionChainMiddle(x int, pcs []uintptr) {
	recursionChainBottom(x, pcs)
}

func recursionChainBottom(x int, pcs []uintptr) {
	// This will be called each time, we only care about the last. We
	// can't make this conditional or this function won't be inlined.
	dumpCallers(pcs)

	recursionChainTop(x-1, pcs)
}

func parseProfile(t *testing.T, valBytes []byte, f func(uintptr, []*profile.Location, map[string][]string)) *profile.Profile {
	p, err := profile.Parse(bytes.NewReader(valBytes))
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range p.Sample {
		count := uintptr(sample.Value[0])
		f(count, sample.Location, sample.Label)
	}
	return p
}

func cpuProfilingBroken() bool {
	switch runtime.GOOS {
	case "plan9":
		// Profiling unimplemented.
		return true
	case "aix":
		// See https://golang.org/issue/45170.
		return true
	case "ios", "dragonfly", "netbsd", "illumos", "solaris":
		// See https://golang.org/issue/13841.
		return true
	case "openbsd":
		if runtime.GOARCH == "arm" || runtime.GOARCH == "arm64" {
			// See https://golang.org/issue/13841.
			return true
		}
	}

	return false
}

// testCPUProfile runs f under the CPU profiler, checking for some conditions specified by need,
// as interpreted by matches, and returns the parsed profile.
func testCPUProfile(t *testing.T, matches profileMatchFunc, f func(dur time.Duration)) *profile.Profile {
	switch runtime.GOOS {
	case "darwin":
		out, err := testenv.Command(t, "uname", "-a").CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		vers := string(out)
		t.Logf("uname -a: %v", vers)
	case "plan9":
		t.Skip("skipping on plan9")
	case "wasip1":
		t.Skip("skipping on wasip1")
	}

	broken := cpuProfilingBroken()

	deadline, ok := t.Deadline()
	if broken || !ok {
		if broken && testing.Short() {
			// If it's expected to be broken, no point waiting around.
			deadline = time.Now().Add(1 * time.Second)
		} else {
			deadline = time.Now().Add(10 * time.Second)
		}
	}

	// If we're running a long test, start with a long duration
	// for tests that try to make sure something *doesn't* happen.
	duration := 5 * time.Second
	if testing.Short() {
		duration = 100 * time.Millisecond
	}

	// Profiling tests are inherently flaky, especially on a
	// loaded system, such as when this test is running with
	// several others under go test std. If a test fails in a way
	// that could mean it just didn't run long enough, try with a
	// longer duration.
	for {
		var prof bytes.Buffer
		if err := StartCPUProfile(&prof); err != nil {
			t.Fatal(err)
		}
		f(duration)
		StopCPUProfile()

		if p, ok := profileOk(t, matches, prof, duration); ok {
			return p
		}

		duration *= 2
		if time.Until(deadline) < duration {
			break
		}
		t.Logf("retrying with %s duration", duration)
	}

	if broken {
		t.Skipf("ignoring failure on %s/%s; see golang.org/issue/13841", runtime.GOOS, runtime.GOARCH)
	}

	// Ignore the failure if the tests are running in a QEMU-based emulator,
	// QEMU is not perfect at emulating everything.
	// IN_QEMU environmental variable is set by some of the Go builders.
	// IN_QEMU=1 indicates that the tests are running in QEMU. See issue 9605.
	if os.Getenv("IN_QEMU") == "1" {
		t.Skip("ignore the failure in QEMU; see golang.org/issue/9605")
	}
	t.FailNow()
	return nil
}

var diffCPUTimeImpl func(f func()) (user, system time.Duration)

func diffCPUTime(t *testing.T, f func()) (user, system time.Duration) {
	if fn := diffCPUTimeImpl; fn != nil {
		return fn(f)
	}
	t.Fatalf("cannot measure CPU time on GOOS=%s GOARCH=%s", runtime.GOOS, runtime.GOARCH)
	return 0, 0
}

// stackContains matches if a function named spec appears anywhere in the stack trace.
func stackContains(spec string, count uintptr, stk []*profile.Location, labels map[string][]string) bool {
	for _, loc := range stk {
		for _, line := range loc.Line {
			if strings.Contains(line.Function.Name, spec) {
				return true
			}
		}
	}
	return false
}

type sampleMatchFunc func(spec string, count uintptr, stk []*profile.Location, labels map[string][]string) bool

func profileOk(t *testing.T, matches profileMatchFunc, prof bytes.Buffer, duration time.Duration) (_ *profile.Profile, ok bool) {
	ok = true

	var samples uintptr
	var buf strings.Builder
	p := parseProfile(t, prof.Bytes(), func(count uintptr, stk []*profile.Location, labels map[string][]string) {
		fmt.Fprintf(&buf, "%d:", count)
		fprintStack(&buf, stk)
		fmt.Fprintf(&buf, " labels: %v\n", labels)
		samples += count
		fmt.Fprintf(&buf, "\n")
	})
	t.Logf("total %d CPU profile samples collected:\n%s", samples, buf.String())

	if samples < 10 && runtime.GOOS == "windows" {
		// On some windows machines we end up with
		// not enough samples due to coarse timer
		// resolution. Let it go.
		t.Log("too few samples on Windows (golang.org/issue/10842)")
		return p, false
	}

	// Check that we got a reasonable number of samples.
	// We used to always require at least ideal/4 samples,
	// but that is too hard to guarantee on a loaded system.
	// Now we accept 10 or more samples, which we take to be
	// enough to show that at least some profiling is occurring.
	if ideal := uintptr(duration * 100 / time.Second); samples == 0 || (samples < ideal/4 && samples < 10) {
		t.Logf("too few samples; got %d, want at least %d, ideally %d", samples, ideal/4, ideal)
		ok = false
	}

	if matches != nil && !matches(t, p) {
		ok = false
	}

	return p, ok
}

type profileMatchFunc func(*testing.T, *profile.Profile) bool

func matchAndAvoidStacks(matches sampleMatchFunc, need []string, avoid []string) profileMatchFunc {
	return func(t *testing.T, p *profile.Profile) (ok bool) {
		ok = true

		// Check that profile is well formed, contains 'need', and does not contain
		// anything from 'avoid'.
		have := make([]uintptr, len(need))
		avoidSamples := make([]uintptr, len(avoid))

		for _, sample := range p.Sample {
			count := uintptr(sample.Value[0])
			for i, spec := range need {
				if matches(spec, count, sample.Location, sample.Label) {
					have[i] += count
				}
			}
			for i, name := range avoid {
				for _, loc := range sample.Location {
					for _, line := range loc.Line {
						if strings.Contains(line.Function.Name, name) {
							avoidSamples[i] += count
						}
					}
				}
			}
		}

		for i, name := range avoid {
			bad := avoidSamples[i]
			if bad != 0 {
				t.Logf("found %d samples in avoid-function %s\n", bad, name)
				ok = false
			}
		}

		if len(need) == 0 {
			return
		}

		var total uintptr
		for i, name := range need {
			total += have[i]
			t.Logf("found %d samples in expected function %s\n", have[i], name)
		}
		if total == 0 {
			t.Logf("no samples in expected functions")
			ok = false
		}

		// We'd like to check a reasonable minimum, like
		// total / len(have) / smallconstant, but this test is
		// pretty flaky (see bug 7095).  So we'll just test to
		// make sure we got at least one sample.
		min := uintptr(1)
		for i, name := range need {
			if have[i] < min {
				t.Logf("%s has %d samples out of %d, want at least %d, ideally %d", name, have[i], total, min, total/uintptr(len(have)))
				ok = false
			}
		}
		return
	}
}

// Fork can hang if preempted with signals frequently enough (see issue 5517).
// Ensure that we do not do this.
func TestCPUProfileWithFork(t *testing.T) {
	testenv.MustHaveExec(t)

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	heap := 1 << 30
	if runtime.GOOS == "android" {
		// Use smaller size for Android to avoid crash.
		heap = 100 << 20
	}
	if runtime.GOOS == "windows" && runtime.GOARCH == "arm" {
		// Use smaller heap for Windows/ARM to avoid crash.
		heap = 100 << 20
	}
	if testing.Short() {
		heap = 100 << 20
	}
	// This makes fork slower.
	garbage := make([]byte, heap)
	// Need to touch the slice, otherwise it won't be paged in.
	done := make(chan bool)
	go func() {
		for i := range garbage {
			garbage[i] = 42
		}
		done <- true
	}()
	<-done

	var prof bytes.Buffer
	if err := StartCPUProfile(&prof); err != nil {
		t.Fatal(err)
	}
	defer StopCPUProfile()

	for i := 0; i < 10; i++ {
		testenv.Command(t, exe, "-h").CombinedOutput()
	}
}

// Test that profiler does not observe runtime.gogo as "user" goroutine execution.
// If it did, it would see inconsistent state and would either record an incorrect stack
// or crash because the stack was malformed.
func TestGoroutineSwitch(t *testing.T) {
	if runtime.Compiler == "gccgo" {
		t.Skip("not applicable for gccgo")
	}
	// How much to try. These defaults take about 1 seconds
	// on a 2012 MacBook Pro. The ones in short mode take
	// about 0.1 seconds.
	tries := 10
	count := 1000000
	if testing.Short() {
		tries = 1
	}
	for try := 0; try < tries; try++ {
		var prof bytes.Buffer
		if err := StartCPUProfile(&prof); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			runtime.Gosched()
		}
		StopCPUProfile()

		// Read profile to look for entries for gogo with an attempt at a traceback.
		// "runtime.gogo" is OK, because that's the part of the context switch
		// before the actual switch begins. But we should not see "gogo",
		// aka "gogo<>(SB)", which does the actual switch and is marked SPWRITE.
		parseProfile(t, prof.Bytes(), func(count uintptr, stk []*profile.Location, _ map[string][]string) {
			// An entry with two frames with 'System' in its top frame
			// exists to record a PC without a traceback. Those are okay.
			if len(stk) == 2 {
				name := stk[1].Line[0].Function.Name
				if name == "runtime._System" || name == "runtime._ExternalCode" || name == "runtime._GC" {
					return
				}
			}

			// An entry with just one frame is OK too:
			// it knew to stop at gogo.
			if len(stk) == 1 {
				return
			}

			// Otherwise, should not see gogo.
			// The place we'd see it would be the inner most frame.
			name := stk[0].Line[0].Function.Name
			if name == "gogo" {
				var buf strings.Builder
				fprintStack(&buf, stk)
				t.Fatalf("found profile entry for gogo:\n%s", buf.String())
			}
		})
	}
}

func fprintStack(w io.Writer, stk []*profile.Location) {
	if len(stk) == 0 {
		fmt.Fprintf(w, " (stack empty)")
	}
	for _, loc := range stk {
		fmt.Fprintf(w, " %#x", loc.Address)
		fmt.Fprintf(w, " (")
		for i, line := range loc.Line {
			if i > 0 {
				fmt.Fprintf(w, " ")
			}
			fmt.Fprintf(w, "%s:%d", line.Function.Name, line.Line)
		}
		fmt.Fprintf(w, ")")
	}
}

// Test that profiling of division operations is okay, especially on ARM. See issue 6681.
func TestMathBigDivide(t *testing.T) {
	testCPUProfile(t, nil, func(duration time.Duration) {
		t := time.After(duration)
		pi := new(big.Int)
		for {
			for i := 0; i < 100; i++ {
				n := big.NewInt(2646693125139304345)
				d := big.NewInt(842468587426513207)
				pi.Div(n, d)
			}
			select {
			case <-t:
				return
			default:
			}
		}
	})
}

// stackContainsAll matches if all functions in spec (comma-separated) appear somewhere in the stack trace.
func stackContainsAll(spec string, count uintptr, stk []*profile.Location, labels map[string][]string) bool {
	for _, f := range strings.Split(spec, ",") {
		if !stackContains(f, count, stk, labels) {
			return false
		}
	}
	return true
}

func TestMorestack(t *testing.T) {
	matches := matchAndAvoidStacks(stackContainsAll, []string{"runtime.newstack,runtime/pprof.growstack"}, avoidFunctions())
	testCPUProfile(t, matches, func(duration time.Duration) {
		t := time.After(duration)
		c := make(chan bool)
		for {
			go func() {
				growstack1()
				c <- true
			}()
			select {
			case <-t:
				return
			case <-c:
			}
		}
	})
}

//go:noinline
func growstack1() {
	growstack(10)
}

//go:noinline
func growstack(n int) {
	var buf [8 << 18]byte
	use(buf)
	if n > 0 {
		growstack(n - 1)
	}
}

//go:noinline
func use(x [8 << 18]byte) {}

func TestBlockProfile(t *testing.T) {
	type TestCase struct {
		name string
		f    func(*testing.T)
		stk  []string
		re   string
	}
	tests := [...]TestCase{
		{
			name: "chan recv",
			f:    blockChanRecv,
			stk: []string{
				"runtime.chanrecv1",
				"runtime/pprof.blockChanRecv",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	runtime\.chanrecv1\+0x[0-9a-f]+	.*runtime/chan.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockChanRecv\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
		{
			name: "chan send",
			f:    blockChanSend,
			stk: []string{
				"runtime.chansend1",
				"runtime/pprof.blockChanSend",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	runtime\.chansend1\+0x[0-9a-f]+	.*runtime/chan.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockChanSend\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
		{
			name: "chan close",
			f:    blockChanClose,
			stk: []string{
				"runtime.chanrecv1",
				"runtime/pprof.blockChanClose",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	runtime\.chanrecv1\+0x[0-9a-f]+	.*runtime/chan.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockChanClose\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
		{
			name: "select recv async",
			f:    blockSelectRecvAsync,
			stk: []string{
				"runtime.selectgo",
				"runtime/pprof.blockSelectRecvAsync",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	runtime\.selectgo\+0x[0-9a-f]+	.*runtime/select.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockSelectRecvAsync\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
		{
			name: "select send sync",
			f:    blockSelectSendSync,
			stk: []string{
				"runtime.selectgo",
				"runtime/pprof.blockSelectSendSync",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	runtime\.selectgo\+0x[0-9a-f]+	.*runtime/select.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockSelectSendSync\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
		{
			name: "mutex",
			f:    blockMutex,
			stk: []string{
				"sync.(*Mutex).Lock",
				"runtime/pprof.blockMutex",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	sync\.\(\*Mutex\)\.Lock\+0x[0-9a-f]+	.*sync/mutex\.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockMutex\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
		{
			name: "cond",
			f:    blockCond,
			stk: []string{
				"sync.(*Cond).Wait",
				"runtime/pprof.blockCond",
				"runtime/pprof.TestBlockProfile",
			},
			re: `
[0-9]+ [0-9]+ @( 0x[[:xdigit:]]+)+
#	0x[0-9a-f]+	sync\.\(\*Cond\)\.Wait\+0x[0-9a-f]+	.*sync/cond\.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.blockCond\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
#	0x[0-9a-f]+	runtime/pprof\.TestBlockProfile\+0x[0-9a-f]+	.*runtime/pprof/pprof_test.go:[0-9]+
`},
	}

	// Generate block profile
	runtime.SetBlockProfileRate(1)
	defer runtime.SetBlockProfileRate(0)
	for _, test := range tests {
		test.f(t)
	}

	t.Run("debug=1", func(t *testing.T) {
		var w strings.Builder
		Lookup("block").WriteTo(&w, 1)
		prof := w.String()

		if !strings.HasPrefix(prof, "--- contention:\ncycles/second=") {
			t.Fatalf("Bad profile header:\n%v", prof)
		}

		if strings.HasSuffix(prof, "#\t0x0\n\n") {
			t.Errorf("Useless 0 suffix:\n%v", prof)
		}

		for _, test := range tests {
			if !regexp.MustCompile(strings.ReplaceAll(test.re, "\t", "\t+")).MatchString(prof) {
				t.Errorf("Bad %v entry, expect:\n%v\ngot:\n%v", test.name, test.re, prof)
			}
		}
	})

	t.Run("proto", func(t *testing.T) {
		// proto format
		var w bytes.Buffer
		Lookup("block").WriteTo(&w, 0)
		p, err := profile.Parse(&w)
		if err != nil {
			t.Fatalf("failed to parse profile: %v", err)
		}
		t.Logf("parsed proto: %s", p)
		if err := p.CheckValid(); err != nil {
			t.Fatalf("invalid profile: %v", err)
		}

		stks := profileStacks(p)
		for _, test := range tests {
			if !containsStack(stks, test.stk) {
				t.Errorf("No matching stack entry for %v, want %+v", test.name, test.stk)
			}
		}
	})

}

func profileStacks(p *profile.Profile) (res [][]string) {
	for _, s := range p.Sample {
		var stk []string
		for _, l := range s.Location {
			for _, line := range l.Line {
				stk = append(stk, line.Function.Name)
			}
		}
		res = append(res, stk)
	}
	return res
}

func blockRecordStacks(records []runtime.BlockProfileRecord) (res [][]string) {
	for _, record := range records {
		frames := runtime.CallersFrames(record.Stack())
		var stk []string
		for {
			frame, more := frames.Next()
			stk = append(stk, frame.Function)
			if !more {
				break
			}
		}
		res = append(res, stk)
	}
	return res
}

func containsStack(got [][]string, want []string) bool {
	for _, stk := range got {
		if len(stk) < len(want) {
			continue
		}
		for i, f := range want {
			if f != stk[i] {
				break
			}
			if i == len(want)-1 {
				return true
			}
		}
	}
	return false
}

// awaitBlockedGoroutine spins on runtime.Gosched until a runtime stack dump
// shows a goroutine in the given state with a stack frame in
// runtime/pprof.<fName>.
func awaitBlockedGoroutine(t *testing.T, state, fName string, count int) {
	re := fmt.Sprintf(`(?m)^goroutine \d+ \[%s\]:\n(?:.+\n\t.+\n)*runtime/pprof\.%s`, regexp.QuoteMeta(state), fName)
	r := regexp.MustCompile(re)

	if deadline, ok := t.Deadline(); ok {
		if d := time.Until(deadline); d > 1*time.Second {
			timer := time.AfterFunc(d-1*time.Second, func() {
				debug.SetTraceback("all")
				panic(fmt.Sprintf("timed out waiting for %#q", re))
			})
			defer timer.Stop()
		}
	}

	buf := make([]byte, 64<<10)
	for {
		runtime.Gosched()
		n := runtime.Stack(buf, true)
		if n == len(buf) {
			// Buffer wasn't large enough for a full goroutine dump.
			// Resize it and try again.
			buf = make([]byte, 2*len(buf))
			continue
		}
		if len(r.FindAll(buf[:n], -1)) >= count {
			return
		}
	}
}

func blockChanRecv(t *testing.T) {
	c := make(chan bool)
	go func() {
		awaitBlockedGoroutine(t, "chan receive", "blockChanRecv", 1)
		c <- true
	}()
	<-c
}

func blockChanSend(t *testing.T) {
	c := make(chan bool)
	go func() {
		awaitBlockedGoroutine(t, "chan send", "blockChanSend", 1)
		<-c
	}()
	c <- true
}

func blockChanClose(t *testing.T) {
	c := make(chan bool)
	go func() {
		awaitBlockedGoroutine(t, "chan receive", "blockChanClose", 1)
		close(c)
	}()
	<-c
}

func blockSelectRecvAsync(t *testing.T) {
	const numTries = 3
	c := make(chan bool, 1)
	c2 := make(chan bool, 1)
	go func() {
		for i := 0; i < numTries; i++ {
			awaitBlockedGoroutine(t, "select", "blockSelectRecvAsync", 1)
			c <- true
		}
	}()
	for i := 0; i < numTries; i++ {
		select {
		case <-c:
		case <-c2:
		}
	}
}

func blockSelectSendSync(t *testing.T) {
	c := make(chan bool)
	c2 := make(chan bool)
	go func() {
		awaitBlockedGoroutine(t, "select", "blockSelectSendSync", 1)
		<-c
	}()
	select {
	case c <- true:
	case c2 <- true:
	}
}

func blockMutex(t *testing.T) {
	var mu sync.Mutex
	mu.Lock()
	go func() {
		awaitBlockedGoroutine(t, "sync.Mutex.Lock", "blockMutex", 1)
		mu.Unlock()
	}()
	// Note: Unlock releases mu before recording the mutex event,
	// so it's theoretically possible for this to proceed and
	// capture the profile before the event is recorded. As long
	// as this is blocked before the unlock happens, it's okay.
	mu.Lock()
}

func blockMutexN(t *testing.T, n int, d time.Duration) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	mu.Lock()
	go func() {
		awaitBlockedGoroutine(t, "sync.Mutex.Lock", "blockMutex", n)
		time.Sleep(d)
		mu.Unlock()
	}()
	// Note: Unlock releases mu before recording the mutex event,
	// so it's theoretically possible for this to proceed and
	// capture the profile before the event is recorded. As long
	// as this is blocked before the unlock happens, it's okay.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			mu.Unlock()
		}()
	}
	wg.Wait()
}

func blockCond(t *testing.T) {
	var mu sync.Mutex
	c := sync.NewCond(&mu)
	mu.Lock()
	go func() {
		awaitBlockedGoroutine(t, "sync.Cond.Wait", "blockCond", 1)
		mu.Lock()
		c.Signal()
		mu.Unlock()
	}()
	c.Wait()
	mu.Unlock()
}

// See http://golang.org/cl/299991.
func TestBlockProfileBias(t *testing.T) {
	rate := int(1000) // arbitrary value
	runtime.SetBlockProfileRate(rate)
	defer runtime.SetBlockProfileRate(0)

	// simulate blocking events
	blockFrequentShort(rate)
	blockInfrequentLong(rate)

	var w bytes.Buffer
	Lookup("block").WriteTo(&w, 0)
	p, err := profile.Parse(&w)
	if err != nil {
		t.Fatalf("failed to parse profile: %v", err)
	}
	t.Logf("parsed proto: %s", p)

	il := float64(-1) // blockInfrequentLong duration
	fs := float64(-1) // blockFrequentShort duration
	for _, s := range p.Sample {
		for _, l := range s.Location {
			for _, line := range l.Line {
				if len(s.Value) < 2 {
					t.Fatal("block profile has less than 2 sample types")
				}

				if line.Function.Name == "runtime/pprof.blockInfrequentLong" {
					il = float64(s.Value[1])
				} else if line.Function.Name == "runtime/pprof.blockFrequentShort" {
					fs = float64(s.Value[1])
				}
			}
		}
	}
	if il == -1 || fs == -1 {
		t.Fatal("block profile is missing expected functions")
	}

	// stddev of bias from 100 runs on local machine multiplied by 10x
	const threshold = 0.2
	if bias := (il - fs) / il; math.Abs(bias) > threshold {
		t.Fatalf("bias: abs(%f) > %f", bias, threshold)
	} else {
		t.Logf("bias: abs(%f) < %f", bias, threshold)
	}
}

// blockFrequentShort produces 100000 block events with an average duration of
// rate / 10.
func blockFrequentShort(rate int) {
	for i := 0; i < 100000; i++ {
		blockevent(int64(rate/10), 1)
	}
}

// blockInfrequentLong produces 10000 block events with an average duration of
// rate.
func blockInfrequentLong(rate int) {
	for i := 0; i < 10000; i++ {
		blockevent(int64(rate), 1)
	}
}

// Used by TestBlockProfileBias.
//
//go:linkname blockevent runtime.blockevent
func blockevent(cycles int
"""




```