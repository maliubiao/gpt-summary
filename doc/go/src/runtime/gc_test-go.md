Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Spotting:**

The first step is a quick skim of the code, looking for recognizable Go keywords and package names. I see:

* `package runtime_test`:  Immediately suggests this is a testing file for the `runtime` package.
* `import`: Lists several important packages: `fmt`, `internal/asan`, `internal/testenv`, `math/bits`, `math/rand`, `os`, `reflect`, `runtime`, `runtime/debug`, `slices`, `strings`, `sync`, `sync/atomic`, `testing`, `time`, `unsafe`, `weak`. This gives a strong hint about the areas being tested. For example, `runtime`, `runtime/debug`, `sync`, and `unsafe` are all related to low-level runtime functionalities.
* `func Test...`:  Confirms this is a testing file with standard Go test functions.
* `runtime.GC()`, `runtime.ReadMemStats()`, `runtime.GOMAXPROCS()`, `runtime.GCTestMoveStackOnNextCall()`, `runtime.GCTestIsReachable()`, `runtime.GCTestPointerClass()`, `runtime.ForceGCPeriod`, `runtime.MemStats`, `runtime.DoubleCheckReadMemStats`, `runtime.AllocMSpan()`, `runtime.FreeMSpan()`, `runtime.Usleep()`, `runtime.GCMarkDoneResetRestartFlag()`, `runtime.SetSpinInGCMarkDone()`, `runtime.GCMarkDoneRestarted()`. These are all explicit calls to `runtime` package functions, indicating the core functionality being tested is related to the Go runtime, especially the garbage collector (GC).
* `debug.SetGCPercent()`: Suggests testing configurations related to the GC.
* `weak.Pointer`: Hints at testing weak pointers and their interaction with the GC.
* `asan.Enabled`: Points to Address Sanitizer integration in some tests.

**2. Grouping Tests by Functionality:**

As I read through the individual test functions (`TestGcSys`, `TestGcDeepNesting`, etc.), I start to group them based on the `runtime` functionality they seem to be exercising:

* **Core GC Functionality:** `TestGcSys`, `TestGcDeepNesting`, `TestGcMapIndirection`, `TestGcArraySlice`, `TestGcRescan`, `TestGcLastTime`, `TestPeriodicGC`, `TestUserForcedGC`. These tests are directly calling `runtime.GC()` and checking its effects on various data structures and timing.
* **Stack Management:** `TestGCTestMoveStackOnNextCall`, `TestGCTestMoveStackRepeatedly`. These clearly involve testing how the Go runtime manages and potentially moves goroutine stacks.
* **Reachability and Pointer Classification:** `TestGCTestIsReachable`, `TestGCTestPointerClass`. These directly use functions for inspecting the reachability of objects and classifying pointers (stack, heap, etc.).
* **Memory Statistics:** `TestReadMemStats`, `BenchmarkReadMemStats`, `BenchmarkReadMemStatsLatency`, `TestPageAccounting`. These focus on retrieving and validating memory usage information via `runtime.ReadMemStats`.
* **Write Barrier:** `BenchmarkWriteBarrier`, `BenchmarkBulkWriteBarrier`. These benchmarks specifically target the performance of the write barrier, a crucial component of the concurrent GC.
* **Memory Limits:** `TestMemoryLimit`, `TestMemoryLimitNoGCPercent`. These tests deal with setting and enforcing memory limits for the Go runtime.
* **Weak Pointers and GC Interaction:** `TestWeakToStrongMarkTermination`. This test focuses on the interplay between weak pointers and the GC's mark termination phase.
* **Other:**  `TestGcZombieReporting` (detecting pointers to freed objects), `TestHugeGCInfo` (handling large types), `TestPrintGC` (interaction with `print`),  `BenchmarkAllocation` (basic allocation performance), `BenchmarkMSpanCountAlloc` (internal GC data structure benchmark).

**3. Detailed Analysis of Key Tests (with internal monologue examples):**

For some of the more complex or illustrative tests, I'd do a deeper dive:

* **`TestGcDeepNesting`:** "Okay, it's creating a deeply nested array of pointers. The `t.Logf("%p", a)` is a classic trick to defeat escape analysis. The core idea is to make sure the GC can handle pointers within deeply nested structures."  *Potential Example:*  Imagine the GC wasn't correctly traversing nested structures. This test would likely fail because after the GC, the pointer within the nested array might be considered dead and collected, leading to a value other than 13.

* **`TestGCTestMoveStackOnNextCall`:** "This one uses `runtime.GCTestMoveStackOnNextCall()`. That name strongly suggests it's testing the ability of the runtime to move a goroutine's stack. The `moveStackCheck` function then verifies if the stack pointer has changed. The `//go:noinline` is crucial to prevent the compiler from optimizing away the function call, which is needed to trigger the stack move." *Potential Issue:* If the stack wasn't moved, `new2 == old` would be true, and the test would fail.

* **`BenchmarkWriteBarrier`:** "This benchmark seems to be simulating a scenario with lots of pointer updates. The code reverses a tree structure, which involves modifying pointers. The `writeBarrierBenchmark` function likely sets up a continuous GC to ensure the write barrier is active. This helps measure the overhead of the write barrier."

* **`TestWeakToStrongMarkTermination`:** "This is about weak pointers and the GC's mark termination phase. The test intentionally stalls mark termination (`runtime.SetSpinInGCMarkDone(true)`) while simultaneously trying to convert weak pointers to strong pointers (`wp.Value()`). The goal is to check for race conditions or incorrect synchronization during this critical phase. The `runtime.GCMarkDoneRestarted()` check is a key indicator of a potential issue."

**4. Identifying Common Themes and Overall Purpose:**

After analyzing the individual tests, I start to see overarching themes:

* **Correctness of Garbage Collection:**  Many tests verify that the GC correctly identifies and reclaims unused memory without prematurely collecting live objects.
* **Performance of Garbage Collection:** Benchmarks measure the performance of various GC components (write barrier, `ReadMemStats`).
* **Robustness and Edge Cases:** Tests like `TestGcDeepNesting` and those involving weak pointers explore less common scenarios and potential edge cases.
* **Internal Runtime Mechanics:** Some tests (e.g., `TestGCTestMoveStackOnNextCall`, `BenchmarkMSpanCountAlloc`) delve into the internal workings of the Go runtime.

**5. Structuring the Answer:**

Finally, I organize the information into a clear and comprehensive answer, addressing each part of the prompt:

* **Functionality:** List the general areas covered by the tests.
* **Go Feature Illustration (with code examples):** Choose key tests that demonstrate important Go features (like GC, stack management, weak pointers) and provide simplified code examples to illustrate the underlying concepts. Include assumptions about inputs and expected outputs.
* **Command Line Arguments:**  Mention any tests that use environment variables (like `GOGC` or `GODEBUG`).
* **Common Mistakes:**  Highlight potential pitfalls for users based on the test cases (e.g., relying on finalizers for critical cleanup).
* **Language:**  Present the answer in clear and concise Chinese.

This iterative process of scanning, grouping, analyzing, and synthesizing allows me to understand the purpose of the code snippet and provide a detailed and informative response.
这段Go语言代码是 `go/src/runtime/gc_test.go` 文件的一部分，它包含了大量的测试用例，用于验证 Go 语言运行时（runtime）中垃圾回收（Garbage Collection，GC）机制的正确性和性能。

以下是它主要的功能和涉及的 Go 语言特性：

**1. 核心垃圾回收功能测试:**

* **`TestGcSys`:**  测试 `runtime.GC()` 的基本功能，确保在调用后能够触发垃圾回收。它通过运行一个外部程序 `testprog` 并检查其输出来验证 GC 是否正常工作。
* **`TestGcDeepNesting`:** 测试 GC 处理深层嵌套数据结构的能力，防止在复杂的对象图中出现误回收的情况。它创建了一个深度嵌套的数组，并在 GC 后验证数据是否仍然存在。
* **`TestGcMapIndirection`:** 测试 GC 处理包含 map 类型的数据结构的能力。
* **`TestGcArraySlice`:** 测试 GC 处理包含数组和切片的数据结构的能力，特别关注切片底层的数组是否被正确管理。
* **`TestGcRescan`:** 测试 GC 在扫描过程中遇到新的指针时的处理能力，特别是涉及 channel 和指针的场景。
* **`TestGcLastTime`:** 测试 `runtime.MemStats` 中记录的上次 GC 时间是否准确。
* **`TestPeriodicGC`:** 测试 Go 运行时是否会按照预定的频率执行周期性的垃圾回收。它修改了 `runtime.ForceGCPeriod` 来强制执行周期性 GC，并检查 `runtime.MemStats` 中 `NumGC` 的增长。
* **`TestUserForcedGC`:**  即使设置了 `GOGC=off`，`runtime.GC()` 也应该能够强制触发垃圾回收。
* **`TestGcZombieReporting`:** 测试 GC 的 zombie reporting 机制，用于检测指向已被回收对象的指针。这通常与调试工具有关。

**2. 栈管理测试:**

* **`TestGCTestMoveStackOnNextCall`:**  测试 Go 运行时在下次函数调用时移动 goroutine 栈的能力。这涉及到栈的增长和收缩。
* **`TestGCTestMoveStackRepeatedly`:**  重复移动栈，确保栈的移动机制不会导致问题（例如，栈大小翻倍）。

**3. 对象可达性与指针类型测试:**

* **`TestGCTestIsReachable`:** 测试 `runtime.GCTestIsReachable` 函数，该函数可以判断一组指针指向的对象是否可达（live）。
* **`TestGCTestPointerClass`:** 测试 `runtime.GCTestPointerClass` 函数，该函数可以返回给定指针的类型（例如，栈、堆、bss 段、数据段）。

**4. 内存统计测试:**

* **`TestReadMemStats`:** 验证 `runtime.ReadMemStats` 函数返回的内存统计信息是否准确。它通过调用 `runtime.ReadMemStatsSlow()` 进行双重检查。
* **`BenchmarkReadMemStats`:**  基准测试 `runtime.ReadMemStats` 的性能。
* **`BenchmarkReadMemStatsLatency`:**  基准测试在高负载下 `runtime.ReadMemStats` 的延迟。
* **`TestPageAccounting`:**  测试内存页面的统计是否正确，防止出现页面计数错误。

**5. 写屏障（Write Barrier）测试:**

* **`BenchmarkWriteBarrier`:**  基准测试写屏障的性能。写屏障是并发垃圾回收的关键机制，用于在 GC 运行时跟踪对象之间的指针更新。
* **`BenchmarkBulkWriteBarrier`:**  基准测试批量写屏障的性能。

**6. 内存限制测试:**

* **`TestMemoryLimit`:** 测试 Go 运行时设置内存限制 (`GOMEMLIMIT`) 的功能。
* **`TestMemoryLimitNoGCPercent`:** 测试当没有设置 `GOGC` 时，内存限制的功能。

**7. 弱引用测试:**

* **`TestWeakToStrongMarkTermination`:** 测试弱引用 (`weak.Pointer`) 在 GC 标记终止阶段的行为。这涉及到弱引用如何与并发 GC 协同工作。

**8. 其他测试:**

* **`TestHugeGCInfo`:**  测试编译器处理大型数据类型的能力，即使这些类型在运行时没有实际分配。
* **`TestPrintGC`:**  一个压力测试，可能会触发 GC 并检查 `print` 函数的行为。
* **`BenchmarkAllocation`:**  一个简单的内存分配基准测试。
* **`BenchmarkMSpanCountAlloc`:**  基准测试 `runtime.MSpanCountAlloc` 函数，该函数用于统计 mspan 中已分配的对象。

**Go 语言功能示例 (基于 `TestGcDeepNesting`):**

```go
package main

import (
	"fmt"
	"runtime"
)

type NestedArray [2][2][2][2][2][2][2][2][2][2]*int

func main() {
	a := new(NestedArray)

	// 打印指针，防止编译器进行逃逸分析
	fmt.Printf("%p\n", a)

	a[0][0][0][0][0][0][0][0][0][0] = new(int)
	*a[0][0][0][0][0][0][0][0][0][0] = 123

	runtime.GC() // 显式触发垃圾回收

	// 垃圾回收后，数据应该仍然存在
	fmt.Println(*a[0][0][0][0][0][0][0][0][0][0])
}
```

**假设的输入与输出:**

* **输入:** 运行上述 `main.go` 程序。
* **输出:**
   ```
   0xc00008e000  // 指针地址 (每次运行可能不同)
   123
   ```

**代码推理:**

`TestGcDeepNesting` 的核心思想是创建一个在堆上分配的深层嵌套的数据结构。通过在 GC 前后访问最内层的值，可以验证 GC 是否正确地识别并保留了被引用的对象，即使对象嵌套很深。`fmt.Printf("%p\n", a)` 的作用是防止编译器将 `a` 分配在栈上，因为我们希望测试堆上的对象回收。

**命令行参数的具体处理:**

在这些测试中，命令行参数主要通过环境变量来控制 Go 运行时的行为：

* **`GOGC`:**  控制垃圾回收的触发百分比。例如，`GOGC=off` 会禁用基于堆大小增长的垃圾回收，但仍然可以通过 `runtime.GC()` 手动触发。在 `TestGcSys` 和 `TestUserForcedGC` 中，会检查在 `GOGC=off` 的情况下 `runtime.GC()` 的行为。
* **`GODEBUG`:**  用于启用或禁用各种运行时调试选项。在 `TestGcZombieReporting` 中，使用了 `GODEBUG=invalidptr=0` 来避免由于地址空间布局随机化导致的问题。
* **`GOMAXPROCS`:** 设置用于并行执行 Go 代码的最大 CPU 核心数。在 `TestPrintGC`, `TestWeakToStrongMarkTermination`, `BenchmarkWriteBarrier`, `BenchmarkBulkWriteBarrier` 中使用了 `runtime.GOMAXPROCS` 来控制并发度。
* **`GOMEMLIMIT`:** 设置 Go 程序的内存使用硬限制。 `TestMemoryLimit` 和 `TestMemoryLimitNoGCPercent` 就是测试这个环境变量的影响。

**使用者易犯错的点 (基于测试内容):**

* **过度依赖 Finalizer:** 虽然 Go 提供了 `runtime.SetFinalizer` 来注册对象的终结器，但不应将其用于释放关键资源，因为终结器的执行时间不确定，并且可能会在程序退出时才执行。从 GC 测试的角度来看，测试用例不会显式地测试 finalizer 的行为，因为其执行是非确定性的。
* **误解 `runtime.GC()` 的作用:**  开发者可能会认为频繁调用 `runtime.GC()` 可以提高性能，但实际上这通常是适得其反的。Go 的 GC 是自动的，手动调用应该仅在极少数需要精确控制 GC 时机的情况下使用。测试用例通过 `TestUserForcedGC` 强调了 `runtime.GC()` 的强制触发作用，即使在 `GOGC` 被禁用的情况下。
* **不理解栈和堆的区别以及逃逸分析:** 在编写低级代码或进行性能优化时，理解对象是在栈上还是堆上分配非常重要。`TestGcDeepNesting` 中使用了 `t.Logf("%p", a)` 来阻止逃逸分析，确保对象分配在堆上，这在实际编程中也需要注意。
* **对弱引用的使用不当:** 弱引用不会阻止对象被垃圾回收。`TestWeakToStrongMarkTermination` 测试了弱引用在 GC 过程中的行为，使用者需要理解弱引用的生命周期和适用场景。

总而言之，这个测试文件是 Go 运行时 GC 机制的严格验证，涵盖了 GC 的核心功能、性能、内存管理以及与其他运行时组件的交互。通过这些测试，可以确保 Go 语言的内存管理是安全可靠的。

### 提示词
```
这是路径为go/src/runtime/gc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"fmt"
	"internal/asan"
	"internal/testenv"
	"math/bits"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
	"weak"
)

func TestGcSys(t *testing.T) {
	t.Skip("skipping known-flaky test; golang.org/issue/37331")
	if os.Getenv("GOGC") == "off" {
		t.Skip("skipping test; GOGC=off in environment")
	}
	got := runTestProg(t, "testprog", "GCSys")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got %q", want, got)
	}
}

func TestGcDeepNesting(t *testing.T) {
	type T [2][2][2][2][2][2][2][2][2][2]*int
	a := new(T)

	// Prevent the compiler from applying escape analysis.
	// This makes sure new(T) is allocated on heap, not on the stack.
	t.Logf("%p", a)

	a[0][0][0][0][0][0][0][0][0][0] = new(int)
	*a[0][0][0][0][0][0][0][0][0][0] = 13
	runtime.GC()
	if *a[0][0][0][0][0][0][0][0][0][0] != 13 {
		t.Fail()
	}
}

func TestGcMapIndirection(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(1))
	runtime.GC()
	type T struct {
		a [256]int
	}
	m := make(map[T]T)
	for i := 0; i < 2000; i++ {
		var a T
		a.a[0] = i
		m[a] = T{}
	}
}

func TestGcArraySlice(t *testing.T) {
	type X struct {
		buf     [1]byte
		nextbuf []byte
		next    *X
	}
	var head *X
	for i := 0; i < 10; i++ {
		p := &X{}
		p.buf[0] = 42
		p.next = head
		if head != nil {
			p.nextbuf = head.buf[:]
		}
		head = p
		runtime.GC()
	}
	for p := head; p != nil; p = p.next {
		if p.buf[0] != 42 {
			t.Fatal("corrupted heap")
		}
	}
}

func TestGcRescan(t *testing.T) {
	type X struct {
		c     chan error
		nextx *X
	}
	type Y struct {
		X
		nexty *Y
		p     *int
	}
	var head *Y
	for i := 0; i < 10; i++ {
		p := &Y{}
		p.c = make(chan error)
		if head != nil {
			p.nextx = &head.X
		}
		p.nexty = head
		p.p = new(int)
		*p.p = 42
		head = p
		runtime.GC()
	}
	for p := head; p != nil; p = p.nexty {
		if *p.p != 42 {
			t.Fatal("corrupted heap")
		}
	}
}

func TestGcLastTime(t *testing.T) {
	ms := new(runtime.MemStats)
	t0 := time.Now().UnixNano()
	runtime.GC()
	t1 := time.Now().UnixNano()
	runtime.ReadMemStats(ms)
	last := int64(ms.LastGC)
	if t0 > last || last > t1 {
		t.Fatalf("bad last GC time: got %v, want [%v, %v]", last, t0, t1)
	}
	pause := ms.PauseNs[(ms.NumGC+255)%256]
	// Due to timer granularity, pause can actually be 0 on windows
	// or on virtualized environments.
	if pause == 0 {
		t.Logf("last GC pause was 0")
	} else if pause > 10e9 {
		t.Logf("bad last GC pause: got %v, want [0, 10e9]", pause)
	}
}

var hugeSink any

func TestHugeGCInfo(t *testing.T) {
	// The test ensures that compiler can chew these huge types even on weakest machines.
	// The types are not allocated at runtime.
	if hugeSink != nil {
		// 400MB on 32 bots, 4TB on 64-bits.
		const n = (400 << 20) + (unsafe.Sizeof(uintptr(0))-4)<<40
		hugeSink = new([n]*byte)
		hugeSink = new([n]uintptr)
		hugeSink = new(struct {
			x float64
			y [n]*byte
			z []string
		})
		hugeSink = new(struct {
			x float64
			y [n]uintptr
			z []string
		})
	}
}

func TestPeriodicGC(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no sysmon on wasm yet")
	}

	// Make sure we're not in the middle of a GC.
	runtime.GC()

	var ms1, ms2 runtime.MemStats
	runtime.ReadMemStats(&ms1)

	// Make periodic GC run continuously.
	orig := *runtime.ForceGCPeriod
	*runtime.ForceGCPeriod = 0

	// Let some periodic GCs happen. In a heavily loaded system,
	// it's possible these will be delayed, so this is designed to
	// succeed quickly if things are working, but to give it some
	// slack if things are slow.
	var numGCs uint32
	const want = 2
	for i := 0; i < 200 && numGCs < want; i++ {
		time.Sleep(5 * time.Millisecond)

		// Test that periodic GC actually happened.
		runtime.ReadMemStats(&ms2)
		numGCs = ms2.NumGC - ms1.NumGC
	}
	*runtime.ForceGCPeriod = orig

	if numGCs < want {
		t.Fatalf("no periodic GC: got %v GCs, want >= 2", numGCs)
	}
}

func TestGcZombieReporting(t *testing.T) {
	// This test is somewhat sensitive to how the allocator works.
	// Pointers in zombies slice may cross-span, thus we
	// add invalidptr=0 for avoiding the badPointer check.
	// See issue https://golang.org/issues/49613/
	got := runTestProg(t, "testprog", "GCZombie", "GODEBUG=invalidptr=0")
	want := "found pointer to free object"
	if !strings.Contains(got, want) {
		t.Fatalf("expected %q in output, but got %q", want, got)
	}
}

func TestGCTestMoveStackOnNextCall(t *testing.T) {
	if asan.Enabled {
		t.Skip("extra allocations with -asan causes this to fail; see #70079")
	}
	t.Parallel()
	var onStack int
	// GCTestMoveStackOnNextCall can fail in rare cases if there's
	// a preemption. This won't happen many times in quick
	// succession, so just retry a few times.
	for retry := 0; retry < 5; retry++ {
		runtime.GCTestMoveStackOnNextCall()
		if moveStackCheck(t, &onStack, uintptr(unsafe.Pointer(&onStack))) {
			// Passed.
			return
		}
	}
	t.Fatal("stack did not move")
}

// This must not be inlined because the point is to force a stack
// growth check and move the stack.
//
//go:noinline
func moveStackCheck(t *testing.T, new *int, old uintptr) bool {
	// new should have been updated by the stack move;
	// old should not have.

	// Capture new's value before doing anything that could
	// further move the stack.
	new2 := uintptr(unsafe.Pointer(new))

	t.Logf("old stack pointer %x, new stack pointer %x", old, new2)
	if new2 == old {
		// Check that we didn't screw up the test's escape analysis.
		if cls := runtime.GCTestPointerClass(unsafe.Pointer(new)); cls != "stack" {
			t.Fatalf("test bug: new (%#x) should be a stack pointer, not %s", new2, cls)
		}
		// This was a real failure.
		return false
	}
	return true
}

func TestGCTestMoveStackRepeatedly(t *testing.T) {
	// Move the stack repeatedly to make sure we're not doubling
	// it each time.
	for i := 0; i < 100; i++ {
		runtime.GCTestMoveStackOnNextCall()
		moveStack1(false)
	}
}

//go:noinline
func moveStack1(x bool) {
	// Make sure this function doesn't get auto-nosplit.
	if x {
		println("x")
	}
}

func TestGCTestIsReachable(t *testing.T) {
	var all, half []unsafe.Pointer
	var want uint64
	for i := 0; i < 16; i++ {
		// The tiny allocator muddies things, so we use a
		// scannable type.
		p := unsafe.Pointer(new(*int))
		all = append(all, p)
		if i%2 == 0 {
			half = append(half, p)
			want |= 1 << i
		}
	}

	got := runtime.GCTestIsReachable(all...)
	if got&want != want {
		// This is a serious bug - an object is live (due to the KeepAlive
		// call below), but isn't reported as such.
		t.Fatalf("live object not in reachable set; want %b, got %b", want, got)
	}
	if bits.OnesCount64(got&^want) > 1 {
		// Note: we can occasionally have a value that is retained even though
		// it isn't live, due to conservative scanning of stack frames.
		// See issue 67204. For now, we allow a "slop" of 1 unintentionally
		// retained object.
		t.Fatalf("dead object in reachable set; want %b, got %b", want, got)
	}
	runtime.KeepAlive(half)
}

var pointerClassBSS *int
var pointerClassData = 42

func TestGCTestPointerClass(t *testing.T) {
	if asan.Enabled {
		t.Skip("extra allocations cause this test to fail; see #70079")
	}
	t.Parallel()
	check := func(p unsafe.Pointer, want string) {
		t.Helper()
		got := runtime.GCTestPointerClass(p)
		if got != want {
			// Convert the pointer to a uintptr to avoid
			// escaping it.
			t.Errorf("for %#x, want class %s, got %s", uintptr(p), want, got)
		}
	}
	var onStack int
	var notOnStack int
	check(unsafe.Pointer(&onStack), "stack")
	check(unsafe.Pointer(runtime.Escape(&notOnStack)), "heap")
	check(unsafe.Pointer(&pointerClassBSS), "bss")
	check(unsafe.Pointer(&pointerClassData), "data")
	check(nil, "other")
}

func BenchmarkAllocation(b *testing.B) {
	type T struct {
		x, y *byte
	}
	ngo := runtime.GOMAXPROCS(0)
	work := make(chan bool, b.N+ngo)
	result := make(chan *T)
	for i := 0; i < b.N; i++ {
		work <- true
	}
	for i := 0; i < ngo; i++ {
		work <- false
	}
	for i := 0; i < ngo; i++ {
		go func() {
			var x *T
			for <-work {
				for i := 0; i < 1000; i++ {
					x = &T{}
				}
			}
			result <- x
		}()
	}
	for i := 0; i < ngo; i++ {
		<-result
	}
}

func TestPrintGC(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				runtime.GC()
			}
		}
	}()
	for i := 0; i < 1e4; i++ {
		func() {
			defer print("")
		}()
	}
	close(done)
}

func testTypeSwitch(x any) error {
	switch y := x.(type) {
	case nil:
		// ok
	case error:
		return y
	}
	return nil
}

func testAssert(x any) error {
	if y, ok := x.(error); ok {
		return y
	}
	return nil
}

func testAssertVar(x any) error {
	var y, ok = x.(error)
	if ok {
		return y
	}
	return nil
}

var a bool

//go:noinline
func testIfaceEqual(x any) {
	if x == "abc" {
		a = true
	}
}

func TestPageAccounting(t *testing.T) {
	// Grow the heap in small increments. This used to drop the
	// pages-in-use count below zero because of a rounding
	// mismatch (golang.org/issue/15022).
	const blockSize = 64 << 10
	blocks := make([]*[blockSize]byte, (64<<20)/blockSize)
	for i := range blocks {
		blocks[i] = new([blockSize]byte)
	}

	// Check that the running page count matches reality.
	pagesInUse, counted := runtime.CountPagesInUse()
	if pagesInUse != counted {
		t.Fatalf("mheap_.pagesInUse is %d, but direct count is %d", pagesInUse, counted)
	}
}

func init() {
	// Enable ReadMemStats' double-check mode.
	*runtime.DoubleCheckReadMemStats = true
}

func TestReadMemStats(t *testing.T) {
	base, slow := runtime.ReadMemStatsSlow()
	if base != slow {
		logDiff(t, "MemStats", reflect.ValueOf(base), reflect.ValueOf(slow))
		t.Fatal("memstats mismatch")
	}
}

func logDiff(t *testing.T, prefix string, got, want reflect.Value) {
	typ := got.Type()
	switch typ.Kind() {
	case reflect.Array, reflect.Slice:
		if got.Len() != want.Len() {
			t.Logf("len(%s): got %v, want %v", prefix, got, want)
			return
		}
		for i := 0; i < got.Len(); i++ {
			logDiff(t, fmt.Sprintf("%s[%d]", prefix, i), got.Index(i), want.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			gf, wf := got.Field(i), want.Field(i)
			logDiff(t, prefix+"."+typ.Field(i).Name, gf, wf)
		}
	case reflect.Map:
		t.Fatal("not implemented: logDiff for map")
	default:
		if got.Interface() != want.Interface() {
			t.Logf("%s: got %v, want %v", prefix, got, want)
		}
	}
}

func BenchmarkReadMemStats(b *testing.B) {
	var ms runtime.MemStats
	const heapSize = 100 << 20
	x := make([]*[1024]byte, heapSize/1024)
	for i := range x {
		x[i] = new([1024]byte)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runtime.ReadMemStats(&ms)
	}

	runtime.KeepAlive(x)
}

func applyGCLoad(b *testing.B) func() {
	// We’ll apply load to the runtime with maxProcs-1 goroutines
	// and use one more to actually benchmark. It doesn't make sense
	// to try to run this test with only 1 P (that's what
	// BenchmarkReadMemStats is for).
	maxProcs := runtime.GOMAXPROCS(-1)
	if maxProcs == 1 {
		b.Skip("This benchmark can only be run with GOMAXPROCS > 1")
	}

	// Code to build a big tree with lots of pointers.
	type node struct {
		children [16]*node
	}
	var buildTree func(depth int) *node
	buildTree = func(depth int) *node {
		tree := new(node)
		if depth != 0 {
			for i := range tree.children {
				tree.children[i] = buildTree(depth - 1)
			}
		}
		return tree
	}

	// Keep the GC busy by continuously generating large trees.
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < maxProcs-1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var hold *node
		loop:
			for {
				hold = buildTree(5)
				select {
				case <-done:
					break loop
				default:
				}
			}
			runtime.KeepAlive(hold)
		}()
	}
	return func() {
		close(done)
		wg.Wait()
	}
}

func BenchmarkReadMemStatsLatency(b *testing.B) {
	stop := applyGCLoad(b)

	// Spend this much time measuring latencies.
	latencies := make([]time.Duration, 0, 1024)

	// Run for timeToBench hitting ReadMemStats continuously
	// and measuring the latency.
	b.ResetTimer()
	var ms runtime.MemStats
	for i := 0; i < b.N; i++ {
		// Sleep for a bit, otherwise we're just going to keep
		// stopping the world and no one will get to do anything.
		time.Sleep(100 * time.Millisecond)
		start := time.Now()
		runtime.ReadMemStats(&ms)
		latencies = append(latencies, time.Since(start))
	}
	// Make sure to stop the timer before we wait! The load created above
	// is very heavy-weight and not easy to stop, so we could end up
	// confusing the benchmarking framework for small b.N.
	b.StopTimer()
	stop()

	// Disable the default */op metrics.
	// ns/op doesn't mean anything because it's an average, but we
	// have a sleep in our b.N loop above which skews this significantly.
	b.ReportMetric(0, "ns/op")
	b.ReportMetric(0, "B/op")
	b.ReportMetric(0, "allocs/op")

	// Sort latencies then report percentiles.
	slices.Sort(latencies)
	b.ReportMetric(float64(latencies[len(latencies)*50/100]), "p50-ns")
	b.ReportMetric(float64(latencies[len(latencies)*90/100]), "p90-ns")
	b.ReportMetric(float64(latencies[len(latencies)*99/100]), "p99-ns")
}

func TestUserForcedGC(t *testing.T) {
	// Test that runtime.GC() triggers a GC even if GOGC=off.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	var ms1, ms2 runtime.MemStats
	runtime.ReadMemStats(&ms1)
	runtime.GC()
	runtime.ReadMemStats(&ms2)
	if ms1.NumGC == ms2.NumGC {
		t.Fatalf("runtime.GC() did not trigger GC")
	}
	if ms1.NumForcedGC == ms2.NumForcedGC {
		t.Fatalf("runtime.GC() was not accounted in NumForcedGC")
	}
}

func writeBarrierBenchmark(b *testing.B, f func()) {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	//b.Logf("heap size: %d MB", ms.HeapAlloc>>20)

	// Keep GC running continuously during the benchmark, which in
	// turn keeps the write barrier on continuously.
	var stop uint32
	done := make(chan bool)
	go func() {
		for atomic.LoadUint32(&stop) == 0 {
			runtime.GC()
		}
		close(done)
	}()
	defer func() {
		atomic.StoreUint32(&stop, 1)
		<-done
	}()

	b.ResetTimer()
	f()
	b.StopTimer()
}

func BenchmarkWriteBarrier(b *testing.B) {
	if runtime.GOMAXPROCS(-1) < 2 {
		// We don't want GC to take our time.
		b.Skip("need GOMAXPROCS >= 2")
	}

	// Construct a large tree both so the GC runs for a while and
	// so we have a data structure to manipulate the pointers of.
	type node struct {
		l, r *node
	}
	var wbRoots []*node
	var mkTree func(level int) *node
	mkTree = func(level int) *node {
		if level == 0 {
			return nil
		}
		n := &node{mkTree(level - 1), mkTree(level - 1)}
		if level == 10 {
			// Seed GC with enough early pointers so it
			// doesn't start termination barriers when it
			// only has the top of the tree.
			wbRoots = append(wbRoots, n)
		}
		return n
	}
	const depth = 22 // 64 MB
	root := mkTree(22)

	writeBarrierBenchmark(b, func() {
		var stack [depth]*node
		tos := -1

		// There are two write barriers per iteration, so i+=2.
		for i := 0; i < b.N; i += 2 {
			if tos == -1 {
				stack[0] = root
				tos = 0
			}

			// Perform one step of reversing the tree.
			n := stack[tos]
			if n.l == nil {
				tos--
			} else {
				n.l, n.r = n.r, n.l
				stack[tos] = n.l
				stack[tos+1] = n.r
				tos++
			}

			if i%(1<<12) == 0 {
				// Avoid non-preemptible loops (see issue #10958).
				runtime.Gosched()
			}
		}
	})

	runtime.KeepAlive(wbRoots)
}

func BenchmarkBulkWriteBarrier(b *testing.B) {
	if runtime.GOMAXPROCS(-1) < 2 {
		// We don't want GC to take our time.
		b.Skip("need GOMAXPROCS >= 2")
	}

	// Construct a large set of objects we can copy around.
	const heapSize = 64 << 20
	type obj [16]*byte
	ptrs := make([]*obj, heapSize/unsafe.Sizeof(obj{}))
	for i := range ptrs {
		ptrs[i] = new(obj)
	}

	writeBarrierBenchmark(b, func() {
		const blockSize = 1024
		var pos int
		for i := 0; i < b.N; i += blockSize {
			// Rotate block.
			block := ptrs[pos : pos+blockSize]
			first := block[0]
			copy(block, block[1:])
			block[blockSize-1] = first

			pos += blockSize
			if pos+blockSize > len(ptrs) {
				pos = 0
			}

			runtime.Gosched()
		}
	})

	runtime.KeepAlive(ptrs)
}

func BenchmarkScanStackNoLocals(b *testing.B) {
	var ready sync.WaitGroup
	teardown := make(chan bool)
	for j := 0; j < 10; j++ {
		ready.Add(1)
		go func() {
			x := 100000
			countpwg(&x, &ready, teardown)
		}()
	}
	ready.Wait()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		runtime.GC()
		runtime.GC()
		b.StopTimer()
	}
	close(teardown)
}

func BenchmarkMSpanCountAlloc(b *testing.B) {
	// Allocate one dummy mspan for the whole benchmark.
	s := runtime.AllocMSpan()
	defer runtime.FreeMSpan(s)

	// n is the number of bytes to benchmark against.
	// n must always be a multiple of 8, since gcBits is
	// always rounded up 8 bytes.
	for _, n := range []int{8, 16, 32, 64, 128} {
		b.Run(fmt.Sprintf("bits=%d", n*8), func(b *testing.B) {
			// Initialize a new byte slice with pseudo-random data.
			bits := make([]byte, n)
			rand.Read(bits)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				runtime.MSpanCountAlloc(s, bits)
			}
		})
	}
}

func countpwg(n *int, ready *sync.WaitGroup, teardown chan bool) {
	if *n == 0 {
		ready.Done()
		<-teardown
		return
	}
	*n--
	countpwg(n, ready, teardown)
}

func TestMemoryLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test that takes time to run")
	}
	if runtime.NumCPU() < 4 {
		t.Skip("want at least 4 CPUs for this test")
	}
	got := runTestProg(t, "testprog", "GCMemoryLimit")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got %q", want, got)
	}
}

func TestMemoryLimitNoGCPercent(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test that takes time to run")
	}
	if runtime.NumCPU() < 4 {
		t.Skip("want at least 4 CPUs for this test")
	}
	got := runTestProg(t, "testprog", "GCMemoryLimitNoGCPercent")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got %q", want, got)
	}
}

func TestMyGenericFunc(t *testing.T) {
	runtime.MyGenericFunc[int]()
}

func TestWeakToStrongMarkTermination(t *testing.T) {
	testenv.MustHaveParallelism(t)

	type T struct {
		a *int
		b int
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	w := make([]weak.Pointer[T], 2048)

	// Make sure there's no out-standing GC from a previous test.
	runtime.GC()

	// Create many objects with a weak pointers to them.
	for i := range w {
		x := new(T)
		x.a = new(int)
		w[i] = weak.Make(x)
	}

	// Reset the restart flag.
	runtime.GCMarkDoneResetRestartFlag()

	// Prevent mark termination from completing.
	runtime.SetSpinInGCMarkDone(true)

	// Start a GC, and wait a little bit to get something spinning in mark termination.
	// Simultaneously, fire off another goroutine to disable spinning. If everything's
	// working correctly, then weak.Value will block, so we need to make sure something
	// prevents the GC from continuing to spin.
	done := make(chan struct{})
	go func() {
		runtime.GC()
		done <- struct{}{}
	}()
	go func() {
		// Usleep here instead of time.Sleep. time.Sleep
		// can allocate, and if we get unlucky, then it
		// can end up stuck in gcMarkDone with nothing to
		// wake it.
		runtime.Usleep(100000) // 100ms

		// Let mark termination continue.
		runtime.SetSpinInGCMarkDone(false)
	}()
	time.Sleep(10 * time.Millisecond)

	// Perform many weak->strong conversions in the critical window.
	var wg sync.WaitGroup
	for _, wp := range w {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wp.Value()
		}()
	}

	// Make sure the GC completes.
	<-done

	// Make sure all the weak->strong conversions finish.
	wg.Wait()

	// The bug is triggered if there's still mark work after gcMarkDone stops the world.
	//
	// This can manifest in one of two ways today:
	// - An exceedingly rare crash in mark termination.
	// - gcMarkDone restarts, as if issue #27993 is at play.
	//
	// Check for the latter. This is a fairly controlled environment, so #27993 is very
	// unlikely to happen (it's already rare to begin with) but we'll always _appear_ to
	// trigger the same bug if weak->strong conversions aren't properly coordinated with
	// mark termination.
	if runtime.GCMarkDoneRestarted() {
		t.Errorf("gcMarkDone restarted")
	}
}
```