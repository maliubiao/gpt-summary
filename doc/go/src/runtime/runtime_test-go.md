Response:
Let's break down the thought process for analyzing this Go test file.

1. **Identify the Core Purpose:** The filename `runtime_test.go` and the package declaration `package runtime_test` immediately suggest this file contains tests for the `runtime` package in Go. This means it's testing fundamental aspects of Go's execution environment.

2. **Scan for Top-Level Declarations:** Quickly read through the file, paying attention to:
    * `import` statements:  These reveal dependencies and hints about the tested functionalities (e.g., `flag`, `fmt`, `runtime`, `sync`, `testing`).
    * Global variables:  Variables like `flagQuick`, `errf`, `faultAddrs`, `One` indicate test setup or data. The comment about `flagQuick` is important.
    * Function declarations: The names of the functions (`Benchmark...`, `Test...`) are strong indicators of their purpose – benchmarks measure performance, and tests verify correctness.

3. **Categorize Tests and Benchmarks:**  Group the functions based on their prefixes:
    * **Benchmarks:** `BenchmarkIfaceCmp...`, `BenchmarkDefer...`, `BenchmarkPanicRecover`, `BenchmarkGoroutineProfile`, `BenchmarkProcYield`, `BenchmarkOSYield`, `BenchmarkMutex...`. These are about measuring the performance of various runtime features.
    * **Tests:** `TestStopCPUProfilingWithProfilerOff`, `TestSetPanicOnFault`, `TestEqString`, `TestTrailingZero`, `TestAppendGrowth`, `TestAppendSliceGrowth`, `TestGoroutineProfileTrivial`, `TestVersion`, `TestTimediv`. These are about verifying the correct behavior of runtime features.

4. **Analyze Individual Tests/Benchmarks (Iterative Approach):**  Choose a few representative examples and analyze them in detail. Look for:
    * **Setup:** How is the test environment prepared? (e.g., setting `errf`, initializing `faultAddrs`, defining structs like `T1`).
    * **Action:** What is the core operation being tested or benchmarked? (e.g., comparing interfaces, using `defer`, triggering a panic, calling `GoroutineProfile`, manipulating mutexes).
    * **Assertions/Measurements:** How is the correctness or performance measured? (e.g., `if errfn() == io.EOF { b.Fatal(...) }`, `if recover() == nil { panic(...) }`, checking `unsafe.Sizeof`, comparing `cap(x)` with expected values, calling `GoroutineProfile` and checking return values, using `b.ReportMetric`).
    * **Edge Cases/Specific Scenarios:** Are there any interesting or unusual scenarios being tested? (e.g., testing equality of strings created differently, checking trailing zero-sized fields in structs, testing fault handling with specific memory addresses).

5. **Infer Functionality from Tests:** Based on the analyzed tests and benchmarks, start to infer the Go language features being tested. For example:
    * `BenchmarkIfaceCmp`: Interface comparison.
    * `BenchmarkDefer`: The `defer` keyword and `recover`.
    * `TestSetPanicOnFault`:  The `debug.SetPanicOnFault` function and fault handling.
    * `TestAppendGrowth`: The growth behavior of slices when using `append`.
    * `BenchmarkMutex...`: Mutex locking and unlocking behavior (contention, capture, handoff).
    * `BenchmarkGoroutineProfile`:  The `runtime.GoroutineProfile` function.

6. **Look for Command-Line Flag Handling:**  Notice the `flag` package import and the `flagQuick` variable. The comment clearly explains its purpose related to skipping slow tests in the `cmd/dist` build process.

7. **Identify Potential Pitfalls:** Consider common errors developers might make when using the tested features. For example:
    * Misunderstanding interface comparison (especially with `nil`).
    * Incorrectly using `defer` and `recover`.
    * Being unaware of slice growth behavior.
    * Potential issues with concurrency and mutex usage (deadlocks, starvation). While the benchmarks *test* mutex behavior, they indirectly highlight the complexities involved.

8. **Structure the Answer:** Organize the findings logically:
    * Start with a general summary of the file's purpose.
    * List the functionalities being tested.
    * Provide code examples for key features, including assumptions and expected outputs.
    * Explain the command-line flag.
    * Discuss potential pitfalls with examples.

9. **Refine and Elaborate:**  Review the answer for clarity, accuracy, and completeness. Add details where necessary and ensure the language is clear and concise. For instance, when giving code examples, make sure the imports are included and the example is self-contained.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This file just tests random runtime stuff."  **Correction:**  Realize the tests are structured and focus on specific aspects like memory management, concurrency primitives, and debugging tools.
* **When analyzing `TestSetPanicOnFault`:**  Initially might just think it tests `SetPanicOnFault`. **Refinement:**  Recognize the indirect testing of OS-level fault handling and the reason for the `faultAddrs` array. The `//go:nocheckptr` comment also provides important context.
* **While looking at `BenchmarkMutexCapture`:** Notice the histograms and percentile calculations, and understand this is about measuring fairness, not just raw performance.
* **Realizing the importance of comments:** Pay close attention to the comments in the code, as they often explain the *why* behind the tests (e.g., the comment about `flagQuick`, the comments in `TestEqString`, the explanation in `BenchmarkMutexContention`).

By following this structured approach, combining code reading with understanding the purpose of tests and benchmarks, and iteratively refining the analysis, a comprehensive and accurate answer can be generated.
这个文件 `go/src/runtime/runtime_test.go` 是 Go 语言运行时（runtime）包的测试文件。它包含了大量的测试用例和基准测试，用于验证 `runtime` 包的各种功能和性能。

以下是该文件主要功能的详细列表：

**1. 测试运行时核心功能:**

* **接口比较 (Interface Comparison):** 测试接口值的比较，包括与 `nil` 的比较。例如 `BenchmarkIfaceCmp100` 和 `BenchmarkIfaceCmpNil100` 测试了不同情况下的接口比较性能。
* **Defer 和 Recover 机制:**  测试 `defer` 语句的执行顺序和 `recover` 函数捕获 panic 的能力。例如 `BenchmarkDefer`, `BenchmarkDefer10`, `BenchmarkDeferMany`, `BenchmarkPanicRecover` 等测试了不同场景下 `defer` 的性能和 `recover` 的正确性。
* **Panic 处理:**  测试当发生 panic 时，运行时的行为，例如 `TestSetPanicOnFault` 测试了 `debug.SetPanicOnFault` 函数的功能，使其在发生内存访问错误时触发 panic。
* **字符串比较:**  测试字符串的相等性比较 (`==`) 的实现细节，并通过 `eqstring_generic` 函数进行了对比。`TestEqString` 验证了内置字符串比较运算符的行为。
* **结构体内存布局:** 测试结构体在内存中的布局，特别是尾部零大小字段的填充情况。`TestTrailingZero` 确保了编译器在处理此类结构体时会添加正确的填充。
* **切片 (Slice) 的增长:** 测试 `append` 函数在向切片添加元素时的扩容策略。`TestAppendGrowth` 和 `TestAppendSliceGrowth` 验证了切片的容量增长是否符合预期。
* **Goroutine Profile:** 测试获取当前所有 Goroutine 堆栈信息的功能。`TestGoroutineProfileTrivial` 和 `BenchmarkGoroutineProfile` 验证了 `runtime.GoroutineProfile` 函数的正确性和性能。
* **版本信息:** 测试获取 Go 版本信息的功能。`TestVersion` 确保了 `runtime.Version()` 返回的字符串不包含换行符。
* **时间除法:** 测试自定义的时间除法函数 `Timediv`，处理溢出情况。`TestTimediv` 验证了该函数在不同输入下的返回值和余数。
* **处理器让步 (Processor Yield):** 测试主动让出处理器时间片的功能。`BenchmarkProcYield` 测量了 `runtime.ProcYield` 的性能。
* **操作系统让步 (OS Yield):** 测试主动让出操作系统时间片的功能。`BenchmarkOSYield` 测量了 `runtime.OSYield` 的性能。

**2. 测试同步原语 (Synchronization Primitives):**

* **Mutex 互斥锁:** 包含多个基准测试来评估互斥锁的性能，包括在多线程竞争下的吞吐量、锁的公平性以及锁的交接延迟。
    * `BenchmarkMutexContention`: 测试多 Goroutine 竞争同一个 Mutex 的性能。
    * `BenchmarkMutexCapture`:  测试 Mutex 的公平性，衡量单个 Goroutine 获取锁的 "streak" 时间以及其他 Goroutine 等待的时间。
    * `BenchmarkMutexHandoff`: 测试在两个 Goroutine 之间传递 Mutex 的延迟。

**3. 测试辅助功能:**

* **CPU Profile 控制:** `TestStopCPUProfilingWithProfilerOff` 测试了在 CPU Profiler 关闭状态下停止 Profiling 的行为，确保不会出错。
* **设置 PanicOnFault:** `TestSetPanicOnFault` 测试了 `debug.SetPanicOnFault` 函数，用于在发生内存访问错误时触发 panic，方便调试。

**可以推理出的 Go 语言功能实现并用代码举例说明:**

**功能:**  **切片 (Slice) 的动态扩容**

**代码示例:**

```go
package main

import (
	"fmt"
)

func main() {
	var s []int
	fmt.Printf("len=%d cap=%d slice=%v\n", len(s), cap(s), s) // 假设输出: len=0 cap=0 slice=[]

	s = append(s, 1)
	fmt.Printf("len=%d cap=%d slice=%v\n", len(s), cap(s), s) // 假设输出: len=1 cap=1 slice=[1]

	s = append(s, 2)
	fmt.Printf("len=%d cap=%d slice=%v\n", len(s), cap(s), s) // 假设输出: len=2 cap=2 slice=[1 2]

	s = append(s, 3)
	fmt.Printf("len=%d cap=%d slice=%v\n", len(s), cap(s), s) // 假设输出: len=3 cap=4 slice=[1 2 3]

	s = append(s, 4, 5)
	fmt.Printf("len=%d cap=%d slice=%v\n", len(s), cap(s), s) // 假设输出: len=5 cap=8 slice=[1 2 3 4 5]
}
```

**假设的输入与输出:**  如代码注释所示。

**推理:** `TestAppendGrowth` 和 `TestAppendSliceGrowth` 通过不断向切片追加元素，并检查切片的容量 (`cap`) 是否按照一定的规律增长，来验证 Go 运行时中切片的动态扩容机制的实现。这个机制确保了在向切片添加元素时，如果当前容量不足，会自动分配更大的内存空间。

**命令行参数的具体处理:**

文件中处理了一个命令行参数 `-quick`:

```go
var flagQuick = flag.Bool("quick", false, "skip slow tests, for cmd/dist test runtime:cpu124")

func init() {
	// ...
}
```

* **`flag.Bool("quick", false, "skip slow tests, for cmd/dist test runtime:cpu124")`**:  这行代码使用 `flag` 包定义了一个名为 `quick` 的布尔类型的命令行参数。
    * `"quick"`:  是命令行参数的名称，用户可以通过 `-quick` 或 `-quick=true` 来设置。
    * `false`: 是该参数的默认值，如果没有在命令行中指定，则默认为 `false`。
    * `"skip slow tests, for cmd/dist test runtime:cpu124"`: 是该参数的描述信息，当用户使用 `-help` 查看帮助信息时会显示出来。

**作用:**  当在运行测试时，如果指定了 `-quick` 命令行参数（例如：`go test -quick ./runtime`），则 `flagQuick` 变量的值会被设置为 `true`。测试代码中可以使用 `*flagQuick` 的值来决定是否跳过一些比较耗时的测试用例。这通常用于快速构建和测试 Go 语言本身。

**使用者易犯错的点 (基于代码推断):**

* **接口比较的陷阱:**  使用者可能会错误地认为两个包含相同值的接口变量总是相等的，但实际上，只有当接口的动态类型和动态值都相同时，接口才相等。与 `nil` 的比较也需要注意，只有当接口的动态类型和动态值都为 `nil` 时，接口才与 `nil` 相等。`BenchmarkIfaceCmp100` 和 `BenchmarkIfaceCmpNil100`  强调了这些比较的不同场景。

   **易错示例:**

   ```go
   package main

   import "fmt"

   func main() {
       var err1 error = nil
       var err2 error = (*error)(nil) // 动态类型不为 nil

       fmt.Println(err1 == nil) // 输出: true
       fmt.Println(err2 == nil) // 输出: false

       var i interface{} = 5
       var j interface{} = 5
       fmt.Println(i == j)     // 输出: true

       var p1 *int = new(int)
       *p1 = 5
       var p2 *int = new(int)
       *p2 = 5
       var k interface{} = p1
       var l interface{} = p2
       fmt.Println(k == l)     // 输出: false (虽然指向的值相同，但指针地址不同)
   }
   ```

* **对 `defer` 和 `recover` 的误用:**  使用者可能不清楚 `defer` 语句的执行时机（函数返回前）以及 `recover` 只能在 `defer` 函数中调用才能捕获 panic。 `BenchmarkDefer` 系列的测试和 `BenchmarkPanicRecover` 旨在验证这些机制的正确性。

   **易错示例:**

   ```go
   package main

   import "fmt"

   func main() {
       defer fmt.Println("This will be printed")

       if r := recover(); r != nil {
           fmt.Println("Recovered:", r) // 这段代码不会执行，因为 recover 不在 defer 函数中
       }

       panic("Something went wrong")
   }
   ```

总而言之，`go/src/runtime/runtime_test.go` 是一个非常重要的文件，它通过大量的测试用例保障了 Go 语言运行时的稳定性和可靠性。通过阅读和分析这些测试代码，开发者可以更深入地理解 Go 语言的内部机制和潜在的陷阱。

Prompt: 
```
这是路径为go/src/runtime/runtime_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"flag"
	"fmt"
	"internal/cpu"
	"internal/runtime/atomic"
	"io"
	"math/bits"
	. "runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// flagQuick is set by the -quick option to skip some relatively slow tests.
// This is used by the cmd/dist test runtime:cpu124.
// The cmd/dist test passes both -test.short and -quick;
// there are tests that only check testing.Short, and those tests will
// not be skipped if only -quick is used.
var flagQuick = flag.Bool("quick", false, "skip slow tests, for cmd/dist test runtime:cpu124")

func init() {
	// We're testing the runtime, so make tracebacks show things
	// in the runtime. This only raises the level, so it won't
	// override GOTRACEBACK=crash from the user.
	SetTracebackEnv("system")
}

var errf error

func errfn() error {
	return errf
}

func errfn1() error {
	return io.EOF
}

func BenchmarkIfaceCmp100(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			if errfn() == io.EOF {
				b.Fatal("bad comparison")
			}
		}
	}
}

func BenchmarkIfaceCmpNil100(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			if errfn1() == nil {
				b.Fatal("bad comparison")
			}
		}
	}
}

var efaceCmp1 any
var efaceCmp2 any

func BenchmarkEfaceCmpDiff(b *testing.B) {
	x := 5
	efaceCmp1 = &x
	y := 6
	efaceCmp2 = &y
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			if efaceCmp1 == efaceCmp2 {
				b.Fatal("bad comparison")
			}
		}
	}
}

func BenchmarkEfaceCmpDiffIndirect(b *testing.B) {
	efaceCmp1 = [2]int{1, 2}
	efaceCmp2 = [2]int{1, 2}
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			if efaceCmp1 != efaceCmp2 {
				b.Fatal("bad comparison")
			}
		}
	}
}

func BenchmarkDefer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		defer1()
	}
}

func defer1() {
	defer func(x, y, z int) {
		if recover() != nil || x != 1 || y != 2 || z != 3 {
			panic("bad recover")
		}
	}(1, 2, 3)
}

func BenchmarkDefer10(b *testing.B) {
	for i := 0; i < b.N/10; i++ {
		defer2()
	}
}

func defer2() {
	for i := 0; i < 10; i++ {
		defer func(x, y, z int) {
			if recover() != nil || x != 1 || y != 2 || z != 3 {
				panic("bad recover")
			}
		}(1, 2, 3)
	}
}

func BenchmarkDeferMany(b *testing.B) {
	for i := 0; i < b.N; i++ {
		defer func(x, y, z int) {
			if recover() != nil || x != 1 || y != 2 || z != 3 {
				panic("bad recover")
			}
		}(1, 2, 3)
	}
}

func BenchmarkPanicRecover(b *testing.B) {
	for i := 0; i < b.N; i++ {
		defer3()
	}
}

func defer3() {
	defer func(x, y, z int) {
		if recover() == nil {
			panic("failed recover")
		}
	}(1, 2, 3)
	panic("hi")
}

// golang.org/issue/7063
func TestStopCPUProfilingWithProfilerOff(t *testing.T) {
	SetCPUProfileRate(0)
}

// Addresses to test for faulting behavior.
// This is less a test of SetPanicOnFault and more a check that
// the operating system and the runtime can process these faults
// correctly. That is, we're indirectly testing that without SetPanicOnFault
// these would manage to turn into ordinary crashes.
// Note that these are truncated on 32-bit systems, so the bottom 32 bits
// of the larger addresses must themselves be invalid addresses.
// We might get unlucky and the OS might have mapped one of these
// addresses, but probably not: they're all in the first page, very high
// addresses that normally an OS would reserve for itself, or malformed
// addresses. Even so, we might have to remove one or two on different
// systems. We will see.

var faultAddrs = []uint64{
	// low addresses
	0,
	1,
	0xfff,
	// high (kernel) addresses
	// or else malformed.
	0xffffffffffffffff,
	0xfffffffffffff001,
	0xffffffffffff0001,
	0xfffffffffff00001,
	0xffffffffff000001,
	0xfffffffff0000001,
	0xffffffff00000001,
	0xfffffff000000001,
	0xffffff0000000001,
	0xfffff00000000001,
	0xffff000000000001,
	0xfff0000000000001,
	0xff00000000000001,
	0xf000000000000001,
	0x8000000000000001,
}

func TestSetPanicOnFault(t *testing.T) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)

	nfault := 0
	for _, addr := range faultAddrs {
		testSetPanicOnFault(t, uintptr(addr), &nfault)
	}
	if nfault == 0 {
		t.Fatalf("none of the addresses faulted")
	}
}

// testSetPanicOnFault tests one potentially faulting address.
// It deliberately constructs and uses an invalid pointer,
// so mark it as nocheckptr.
//
//go:nocheckptr
func testSetPanicOnFault(t *testing.T, addr uintptr, nfault *int) {
	if GOOS == "js" || GOOS == "wasip1" {
		t.Skip(GOOS + " does not support catching faults")
	}

	defer func() {
		if err := recover(); err != nil {
			*nfault++
		}
	}()

	// The read should fault, except that sometimes we hit
	// addresses that have had C or kernel pages mapped there
	// readable by user code. So just log the content.
	// If no addresses fault, we'll fail the test.
	v := *(*byte)(unsafe.Pointer(addr))
	t.Logf("addr %#x: %#x\n", addr, v)
}

func eqstring_generic(s1, s2 string) bool {
	if len(s1) != len(s2) {
		return false
	}
	// optimization in assembly versions:
	// if s1.str == s2.str { return true }
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

func TestEqString(t *testing.T) {
	// This isn't really an exhaustive test of == on strings, it's
	// just a convenient way of documenting (via eqstring_generic)
	// what == does.
	s := []string{
		"",
		"a",
		"c",
		"aaa",
		"ccc",
		"cccc"[:3], // same contents, different string
		"1234567890",
	}
	for _, s1 := range s {
		for _, s2 := range s {
			x := s1 == s2
			y := eqstring_generic(s1, s2)
			if x != y {
				t.Errorf(`("%s" == "%s") = %t, want %t`, s1, s2, x, y)
			}
		}
	}
}

func TestTrailingZero(t *testing.T) {
	// make sure we add padding for structs with trailing zero-sized fields
	type T1 struct {
		n int32
		z [0]byte
	}
	if unsafe.Sizeof(T1{}) != 8 {
		t.Errorf("sizeof(%#v)==%d, want 8", T1{}, unsafe.Sizeof(T1{}))
	}
	type T2 struct {
		n int64
		z struct{}
	}
	if unsafe.Sizeof(T2{}) != 8+unsafe.Sizeof(uintptr(0)) {
		t.Errorf("sizeof(%#v)==%d, want %d", T2{}, unsafe.Sizeof(T2{}), 8+unsafe.Sizeof(uintptr(0)))
	}
	type T3 struct {
		n byte
		z [4]struct{}
	}
	if unsafe.Sizeof(T3{}) != 2 {
		t.Errorf("sizeof(%#v)==%d, want 2", T3{}, unsafe.Sizeof(T3{}))
	}
	// make sure padding can double for both zerosize and alignment
	type T4 struct {
		a int32
		b int16
		c int8
		z struct{}
	}
	if unsafe.Sizeof(T4{}) != 8 {
		t.Errorf("sizeof(%#v)==%d, want 8", T4{}, unsafe.Sizeof(T4{}))
	}
	// make sure we don't pad a zero-sized thing
	type T5 struct {
	}
	if unsafe.Sizeof(T5{}) != 0 {
		t.Errorf("sizeof(%#v)==%d, want 0", T5{}, unsafe.Sizeof(T5{}))
	}
}

func TestAppendGrowth(t *testing.T) {
	var x []int64
	check := func(want int) {
		if cap(x) != want {
			t.Errorf("len=%d, cap=%d, want cap=%d", len(x), cap(x), want)
		}
	}

	check(0)
	want := 1
	for i := 1; i <= 100; i++ {
		x = append(x, 1)
		check(want)
		if i&(i-1) == 0 {
			want = 2 * i
		}
	}
}

var One = []int64{1}

func TestAppendSliceGrowth(t *testing.T) {
	var x []int64
	check := func(want int) {
		if cap(x) != want {
			t.Errorf("len=%d, cap=%d, want cap=%d", len(x), cap(x), want)
		}
	}

	check(0)
	want := 1
	for i := 1; i <= 100; i++ {
		x = append(x, One...)
		check(want)
		if i&(i-1) == 0 {
			want = 2 * i
		}
	}
}

func TestGoroutineProfileTrivial(t *testing.T) {
	// Calling GoroutineProfile twice in a row should find the same number of goroutines,
	// but it's possible there are goroutines just about to exit, so we might end up
	// with fewer in the second call. Try a few times; it should converge once those
	// zombies are gone.
	for i := 0; ; i++ {
		n1, ok := GoroutineProfile(nil) // should fail, there's at least 1 goroutine
		if n1 < 1 || ok {
			t.Fatalf("GoroutineProfile(nil) = %d, %v, want >0, false", n1, ok)
		}
		n2, ok := GoroutineProfile(make([]StackRecord, n1))
		if n2 == n1 && ok {
			break
		}
		t.Logf("GoroutineProfile(%d) = %d, %v, want %d, true", n1, n2, ok, n1)
		if i >= 10 {
			t.Fatalf("GoroutineProfile not converging")
		}
	}
}

func BenchmarkGoroutineProfile(b *testing.B) {
	run := func(fn func() bool) func(b *testing.B) {
		runOne := func(b *testing.B) {
			latencies := make([]time.Duration, 0, b.N)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				start := time.Now()
				ok := fn()
				if !ok {
					b.Fatal("goroutine profile failed")
				}
				latencies = append(latencies, time.Since(start))
			}
			b.StopTimer()

			// Sort latencies then report percentiles.
			slices.Sort(latencies)
			b.ReportMetric(float64(latencies[len(latencies)*50/100]), "p50-ns")
			b.ReportMetric(float64(latencies[len(latencies)*90/100]), "p90-ns")
			b.ReportMetric(float64(latencies[len(latencies)*99/100]), "p99-ns")
		}
		return func(b *testing.B) {
			b.Run("idle", runOne)

			b.Run("loaded", func(b *testing.B) {
				stop := applyGCLoad(b)
				runOne(b)
				// Make sure to stop the timer before we wait! The load created above
				// is very heavy-weight and not easy to stop, so we could end up
				// confusing the benchmarking framework for small b.N.
				b.StopTimer()
				stop()
			})
		}
	}

	// Measure the cost of counting goroutines
	b.Run("small-nil", run(func() bool {
		GoroutineProfile(nil)
		return true
	}))

	// Measure the cost with a small set of goroutines
	n := NumGoroutine()
	p := make([]StackRecord, 2*n+2*GOMAXPROCS(0))
	b.Run("small", run(func() bool {
		_, ok := GoroutineProfile(p)
		return ok
	}))

	// Measure the cost with a large set of goroutines
	ch := make(chan int)
	var ready, done sync.WaitGroup
	for i := 0; i < 5000; i++ {
		ready.Add(1)
		done.Add(1)
		go func() { ready.Done(); <-ch; done.Done() }()
	}
	ready.Wait()

	// Count goroutines with a large allgs list
	b.Run("large-nil", run(func() bool {
		GoroutineProfile(nil)
		return true
	}))

	n = NumGoroutine()
	p = make([]StackRecord, 2*n+2*GOMAXPROCS(0))
	b.Run("large", run(func() bool {
		_, ok := GoroutineProfile(p)
		return ok
	}))

	close(ch)
	done.Wait()

	// Count goroutines with a large (but unused) allgs list
	b.Run("sparse-nil", run(func() bool {
		GoroutineProfile(nil)
		return true
	}))

	// Measure the cost of a large (but unused) allgs list
	n = NumGoroutine()
	p = make([]StackRecord, 2*n+2*GOMAXPROCS(0))
	b.Run("sparse", run(func() bool {
		_, ok := GoroutineProfile(p)
		return ok
	}))
}

func TestVersion(t *testing.T) {
	// Test that version does not contain \r or \n.
	vers := Version()
	if strings.Contains(vers, "\r") || strings.Contains(vers, "\n") {
		t.Fatalf("cr/nl in version: %q", vers)
	}
}

func TestTimediv(t *testing.T) {
	for _, tc := range []struct {
		num int64
		div int32
		ret int32
		rem int32
	}{
		{
			num: 8,
			div: 2,
			ret: 4,
			rem: 0,
		},
		{
			num: 9,
			div: 2,
			ret: 4,
			rem: 1,
		},
		{
			// Used by runtime.check.
			num: 12345*1000000000 + 54321,
			div: 1000000000,
			ret: 12345,
			rem: 54321,
		},
		{
			num: 1<<32 - 1,
			div: 2,
			ret: 1<<31 - 1, // no overflow.
			rem: 1,
		},
		{
			num: 1 << 32,
			div: 2,
			ret: 1<<31 - 1, // overflow.
			rem: 0,
		},
		{
			num: 1 << 40,
			div: 2,
			ret: 1<<31 - 1, // overflow.
			rem: 0,
		},
		{
			num: 1<<40 + 1,
			div: 1 << 10,
			ret: 1 << 30,
			rem: 1,
		},
	} {
		name := fmt.Sprintf("%d div %d", tc.num, tc.div)
		t.Run(name, func(t *testing.T) {
			// Double check that the inputs make sense using
			// standard 64-bit division.
			ret64 := tc.num / int64(tc.div)
			rem64 := tc.num % int64(tc.div)
			if ret64 != int64(int32(ret64)) {
				// Simulate timediv overflow value.
				ret64 = 1<<31 - 1
				rem64 = 0
			}
			if ret64 != int64(tc.ret) {
				t.Errorf("%d / %d got ret %d rem %d want ret %d rem %d", tc.num, tc.div, ret64, rem64, tc.ret, tc.rem)
			}

			var rem int32
			ret := Timediv(tc.num, tc.div, &rem)
			if ret != tc.ret || rem != tc.rem {
				t.Errorf("timediv %d / %d got ret %d rem %d want ret %d rem %d", tc.num, tc.div, ret, rem, tc.ret, tc.rem)
			}
		})
	}
}

func BenchmarkProcYield(b *testing.B) {
	benchN := func(n uint32) func(*testing.B) {
		return func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ProcYield(n)
			}
		}
	}

	b.Run("1", benchN(1))
	b.Run("10", benchN(10))
	b.Run("30", benchN(30)) // active_spin_cnt in lock_sema.go and lock_futex.go
	b.Run("100", benchN(100))
	b.Run("1000", benchN(1000))
}

func BenchmarkOSYield(b *testing.B) {
	for i := 0; i < b.N; i++ {
		OSYield()
	}
}

func BenchmarkMutexContention(b *testing.B) {
	// Measure throughput of a single mutex with all threads contending
	//
	// Share a single counter across all threads. Progress from any thread is
	// progress for the benchmark as a whole. We don't measure or give points
	// for fairness here, arbitrary delay to any given thread's progress is
	// invisible and allowed.
	//
	// The cache line that holds the count value will need to move between
	// processors, but not as often as the cache line that holds the mutex. The
	// mutex protects access to the count value, which limits contention on that
	// cache line. This is a simple design, but it helps to make the behavior of
	// the benchmark clear. Most real uses of mutex will protect some number of
	// cache lines anyway.

	var state struct {
		_     cpu.CacheLinePad
		lock  Mutex
		_     cpu.CacheLinePad
		count atomic.Int64
		_     cpu.CacheLinePad
	}

	procs := GOMAXPROCS(0)
	var wg sync.WaitGroup
	for range procs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				Lock(&state.lock)
				ours := state.count.Add(1)
				Unlock(&state.lock)
				if ours >= int64(b.N) {
					return
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkMutexCapture(b *testing.B) {

	// Measure mutex fairness.
	//
	// Have several threads contend for a single mutex value. Measure how
	// effectively a single thread is able to capture the lock and report the
	// duration of those "streak" events. Measure how long other individual
	// threads need to wait between their turns with the lock. Report the
	// duration of those "starve" events.
	//
	// Report in terms of wall clock time (assuming a constant time per
	// lock/unlock pair) rather than number of locks/unlocks. This keeps
	// timekeeping overhead out of the critical path, and avoids giving an
	// advantage to lock/unlock implementations that take less time per
	// operation.

	var state struct {
		_     cpu.CacheLinePad
		lock  Mutex
		_     cpu.CacheLinePad
		count atomic.Int64
		_     cpu.CacheLinePad
	}

	procs := GOMAXPROCS(0)
	var wg sync.WaitGroup
	histograms := make(chan [2][65]int)
	for range procs {
		wg.Add(1)
		go func() {
			var (
				prev      int64
				streak    int64
				histogram [2][65]int
			)
			for {
				Lock(&state.lock)
				ours := state.count.Add(1)
				Unlock(&state.lock)
				delta := ours - prev - 1
				prev = ours
				if delta == 0 {
					streak++
				} else {
					histogram[0][bits.LeadingZeros64(uint64(streak))]++
					histogram[1][bits.LeadingZeros64(uint64(delta))]++
					streak = 1
				}
				if ours >= int64(b.N) {
					wg.Done()
					if delta == 0 {
						histogram[0][bits.LeadingZeros64(uint64(streak))]++
						histogram[1][bits.LeadingZeros64(uint64(delta))]++
					}
					histograms <- histogram
					return
				}
			}
		}()
	}

	wg.Wait()
	b.StopTimer()

	var histogram [2][65]int
	for range procs {
		h := <-histograms
		for i := range h {
			for j := range h[i] {
				histogram[i][j] += h[i][j]
			}
		}
	}

	percentile := func(h [65]int, p float64) int {
		sum := 0
		for i, v := range h {
			bound := uint64(1<<63) >> i
			sum += int(bound) * v
		}

		// Imagine that the longest streak / starvation events were instead half
		// as long but twice in number. (Note that we've pre-multiplied by the
		// [lower] "bound" value.) Continue those splits until we meet the
		// percentile target.
		part := 0
		for i, v := range h {
			bound := uint64(1<<63) >> i
			part += int(bound) * v
			// have we trimmed off enough at the head to dip below the percentile goal
			if float64(sum-part) < float64(sum)*p {
				return int(bound)
			}
		}

		return 0
	}

	perOp := float64(b.Elapsed().Nanoseconds()) / float64(b.N)
	b.ReportMetric(perOp*float64(percentile(histogram[0], 1.0)), "ns/streak-p100")
	b.ReportMetric(perOp*float64(percentile(histogram[0], 0.9)), "ns/streak-p90")
	b.ReportMetric(perOp*float64(percentile(histogram[1], 1.0)), "ns/starve-p100")
	b.ReportMetric(perOp*float64(percentile(histogram[1], 0.9)), "ns/starve-p90")
}

func BenchmarkMutexHandoff(b *testing.B) {
	testcase := func(delay func(l *Mutex)) func(b *testing.B) {
		return func(b *testing.B) {
			if workers := 2; GOMAXPROCS(0) < workers {
				b.Skipf("requires GOMAXPROCS >= %d", workers)
			}

			// Measure latency of mutex handoff between threads.
			//
			// Hand off a runtime.mutex between two threads, one running a
			// "coordinator" goroutine and the other running a "worker"
			// goroutine. We don't override the runtime's typical
			// goroutine/thread mapping behavior.
			//
			// Measure the latency, starting when the coordinator enters a call
			// to runtime.unlock and ending when the worker's call to
			// runtime.lock returns. The benchmark can specify a "delay"
			// function to simulate the length of the mutex-holder's critical
			// section, including to arrange for the worker's thread to be in
			// either the "spinning" or "sleeping" portions of the runtime.lock2
			// implementation. Measurement starts after any such "delay".
			//
			// The two threads' goroutines communicate their current position to
			// each other in a non-blocking way via the "turn" state.

			var state struct {
				_    cpu.CacheLinePad
				lock Mutex
				_    cpu.CacheLinePad
				turn atomic.Int64
				_    cpu.CacheLinePad
			}

			var delta atomic.Int64
			var wg sync.WaitGroup

			// coordinator:
			//  - acquire the mutex
			//  - set the turn to 2 mod 4, instructing the worker to begin its Lock call
			//  - wait until the mutex is contended
			//  - wait a bit more so the worker can commit to its sleep
			//  - release the mutex and wait for it to be our turn (0 mod 4) again
			wg.Add(1)
			go func() {
				defer wg.Done()
				var t int64
				for range b.N {
					Lock(&state.lock)
					state.turn.Add(2)
					delay(&state.lock)
					t -= Nanotime() // start the timer
					Unlock(&state.lock)
					for state.turn.Load()&0x2 != 0 {
					}
				}
				state.turn.Add(1)
				delta.Add(t)
			}()

			// worker:
			//  - wait until its our turn (2 mod 4)
			//  - acquire and release the mutex
			//  - switch the turn counter back to the coordinator (0 mod 4)
			wg.Add(1)
			go func() {
				defer wg.Done()
				var t int64
				for {
					switch state.turn.Load() & 0x3 {
					case 0:
					case 1, 3:
						delta.Add(t)
						return
					case 2:
						Lock(&state.lock)
						t += Nanotime() // stop the timer
						Unlock(&state.lock)
						state.turn.Add(2)
					}
				}
			}()

			wg.Wait()
			b.ReportMetric(float64(delta.Load())/float64(b.N), "ns/op")
		}
	}

	b.Run("Solo", func(b *testing.B) {
		var lock Mutex
		for range b.N {
			Lock(&lock)
			Unlock(&lock)
		}
	})

	b.Run("FastPingPong", testcase(func(l *Mutex) {}))
	b.Run("SlowPingPong", testcase(func(l *Mutex) {
		// Wait for the worker to stop spinning and prepare to sleep
		for !MutexContended(l) {
		}
		// Wait a bit longer so the OS can finish committing the worker to its
		// sleep. Balance consistency against getting enough iterations.
		const extraNs = 10e3
		for t0 := Nanotime(); Nanotime()-t0 < extraNs; {
		}
	}))
}

"""



```