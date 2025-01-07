Response:
Let's break down the thought process for analyzing the provided Go code snippet from `malloc_test.go`.

1. **Understand the Goal:** The primary goal is to figure out what this code *does*. Since it's in a `_test.go` file within the `runtime` package, the immediate assumption is that it's testing some aspect of Go's runtime, specifically related to memory allocation (`malloc`).

2. **Initial Scan and Keyword Recognition:**  Read through the code, looking for familiar Go constructs and keywords that hint at functionality. Keywords like `func Test...`, `Benchmark...`, `GC()`, `ReadMemStats()`, `new()`, `make()`, `unsafe.Pointer`, `atomic.StoreUint64`, `flag`, `os/exec`, etc., jump out. These provide strong clues.

3. **Categorize the Tests:** Notice the pattern of functions starting with `Test` and `Benchmark`. This signals unit tests and benchmarks, respectively. Grouping them helps organize the analysis.

4. **Analyze Individual Tests (The `Test` functions):**
   * **`TestMemStats`:** The name strongly suggests it's testing the `MemStats` struct. The code calls `ReadMemStats` and then performs a series of checks on the fields of the `MemStats` struct. The checks involve comparisons to zero, upper bounds, and equality. This clearly tests the correctness and sanity of the memory statistics reported by the runtime.
   * **`TestStringConcatenationAllocs`:**  This uses `testing.AllocsPerRun`, which is a function for measuring the number of allocations during a specific operation (string concatenation in this case). The assertion `n != 1` confirms that string concatenation allocates (specifically, only once in this scenario).
   * **`TestTinyAlloc`:** The name suggests testing "tiny allocations." The code allocates several single bytes and then checks if they are allocated within the same 8-byte chunk. This points to testing Go's tiny allocation optimization. The `Raceenabled` and `asan.Enabled` checks indicate that this optimization might be suppressed under race detection or address sanitizer.
   * **`TestTinyAllocIssue37262`:**  The name and the comment within the function clearly link it to a specific issue. The code attempts to trigger an alignment issue when accessing a field in a tiny-allocated object. The use of `atomic.StoreUint64` highlights a potential problem with atomic operations on misaligned memory. The `runtime.Acquirem()` and `runtime.Releasem()` suggest the test is trying to isolate execution to a single OS thread to control the tiny allocator behavior.
   * **`TestPageCacheLeak`:** The name and the function `PageCachePagesLeaked()` indicate a test for memory leaks in the page cache.
   * **`TestPhysicalMemoryUtilization`:** This runs an external program (`testprog`) with a specific argument (`GCPhys`) and checks its output. This is likely an integration test verifying how the runtime interacts with the OS's memory management.
   * **`TestScavengedBitsCleared`:**  The name and the `CheckScavengedBitsCleared` function suggest this tests whether the garbage collector correctly clears the "scavenged" bits in memory.
   * **`TestArenaCollision`:** This test is more complex and uses environment variables and `os/exec`. It appears to be testing the runtime's ability to handle address space collisions when allocating memory. The logic involves reserving memory regions and then trying to allocate to force collisions.

5. **Analyze Benchmarks (The `Benchmark` functions):**
   * **`BenchmarkMalloc8`, `BenchmarkMalloc16`, `BenchmarkMallocTypeInfo8`, `BenchmarkMallocTypeInfo16`, `BenchmarkMallocLargeStruct`:** These are standard benchmarks measuring the performance of `new` and `make` for different sizes and types. The `Escape` function is used to prevent the compiler from optimizing away the allocations.
   * **`BenchmarkGoroutineSelect`, `BenchmarkGoroutineBlocking`, `BenchmarkGoroutineForRange`, `BenchmarkGoroutineIdle`:** These benchmarks focus on goroutine and channel performance, specifically testing `select`, blocking reads, `for...range` on channels, and the overhead of idle goroutines. The use of `flag.Int` indicates that the number of goroutines can be controlled via a command-line flag.

6. **Infer Go Feature Implementation (Based on Tests):**
   * **Memory Management:**  The core theme is memory management. `TestMemStats` directly checks the runtime's accounting. `TestTinyAlloc` and `TestTinyAllocIssue37262` focus on a specific optimization. `TestPageCacheLeak` and `TestArenaCollision` test robustness in memory allocation.
   * **Garbage Collection:**  `GC()` is called frequently, and `TestScavengedBitsCleared` specifically tests a GC-related aspect.
   * **Goroutines and Channels:** The benchmark section heavily features goroutines and channels, indicating this file also tests the performance of these concurrency primitives.
   * **String Handling:** `TestStringConcatenationAllocs` briefly touches on string allocation.

7. **Code Examples (Illustrating the Features):** Based on the inferred features, construct simple Go code snippets that demonstrate their usage. For `MemStats`, show how to retrieve and print the stats. For tiny allocation, demonstrate allocating small objects. For arena collision, illustrate how memory mapping can conflict.

8. **Command-Line Arguments:**  The `flag.Int("n", ...)` in the benchmark section clearly indicates a command-line argument `-n` to control the number of goroutines. Explain how to use it.

9. **Common Mistakes:** Focus on potential errors a user might make *when using the features being tested*. For example, misunderstanding the meaning of `MemStats` fields or assuming tiny allocations always behave the same way under different conditions (like race detection).

10. **Structure and Refine the Answer:** Organize the findings logically. Start with a summary of the file's purpose, then detail the functionality of each test and benchmark. Provide clear code examples, explain command-line arguments, and highlight potential pitfalls. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe this just tests the `new` keyword."  **Correction:** Realize it's much broader, covering various aspects of memory management and concurrency.
* **Initially overlooked:** The significance of `runtime.Escape`. **Correction:** Understand its role in preventing compiler optimizations in benchmarks.
* **Vague understanding:** "Arena collision seems complex." **Correction:** Carefully analyze the code with the environment variable and `MapNextArenaHint` calls to grasp the testing strategy.
* **Too technical:**  Initially focusing on low-level memory details. **Correction:**  Shift focus to the user-observable behavior and the Go features being tested.

By following this iterative process of scanning, categorizing, analyzing, inferring, illustrating, and refining, you can effectively understand and explain the functionality of a complex piece of code like the provided `malloc_test.go` snippet.
这个 `go/src/runtime/malloc_test.go` 文件是 Go 语言运行时环境的一部分，专门用于测试内存分配器（malloc）的各种功能和特性。 它的主要功能可以概括为：

**1. 测试 `runtime.MemStats` 结构体及其相关功能:**

   * **功能:**  `TestMemStats` 函数测试了 `runtime.MemStats` 结构体中各种内存统计指标的正确性。 `runtime.MemStats` 提供了关于 Go 程序内存使用情况的详细信息，例如已分配的堆内存、系统使用的内存、GC 的次数和耗时等等。
   * **代码举例:**
     ```go
     package main

     import (
         "fmt"
         "runtime"
         "time"
     )

     func main() {
         var m runtime.MemStats
         runtime.ReadMemStats(&m)

         fmt.Printf("Allocated heap objects: %d\n", m.HeapObjects)
         fmt.Printf("Total memory allocated (cumulative): %d bytes\n", m.TotalAlloc)

         // 进行一些内存分配
         s := make([]int, 100000)
         for i := 0; i < len(s); i++ {
             s[i] = i
         }

         runtime.GC() // 触发一次垃圾回收

         runtime.ReadMemStats(&m)
         fmt.Printf("Allocated heap objects after GC: %d\n", m.HeapObjects)
         fmt.Printf("HeapAlloc after GC: %d bytes\n", m.HeapAlloc)
         fmt.Printf("Number of GC cycles: %d\n", m.NumGC)
         fmt.Printf("Total GC pause duration: %s\n", time.Duration(m.PauseTotalNs))
     }
     ```
     **假设输入:**  运行上述代码。
     **预期输出:**  会打印出程序启动时和进行内存分配并进行一次垃圾回收后的内存统计信息，包括堆对象数量、总分配内存、垃圾回收次数和暂停时间等。  输出的具体数值会根据运行环境和分配情况有所不同，但会反映内存使用的变化。

**2. 测试小对象分配器 (Tiny Allocator):**

   * **功能:**  `TestTinyAlloc` 和 `TestTinyAllocIssue37262` 函数测试了运行时环境中的小对象分配器。  Go 语言为了优化小对象的分配，会将多个小对象分配在同一个内存块中。 这些测试旨在验证这种优化的正确性和潜在的对齐问题。
   * **代码举例 (基于推断):** 虽然无法直接调用底层的 tiny allocator，但可以通过连续分配小对象来观察其行为。
     ```go
     package main

     import "fmt"

     func main() {
         var pointers [16]*byte
         for i := 0; i < len(pointers); i++ {
             b := new(byte)
             pointers[i] = b
             fmt.Printf("Pointer %d: %p\n", i, b)
         }
     }
     ```
     **假设输入:** 运行上述代码。
     **预期输出:**  打印出的多个指针地址，如果 tiny allocator 工作正常，可能会观察到部分指针的低几位是相同的，因为它们被分配在同一个 8 字节的 chunk 中。 这不是绝对保证的，因为 tiny allocator 的行为还受到其他因素影响。

**3. 测试字符串连接的内存分配:**

   * **功能:** `TestStringConcatenationAllocs` 函数使用 `testing.AllocsPerRun` 来精确地计算字符串连接操作会分配多少次内存。 这有助于验证 Go 编译器和运行时在字符串连接上的优化。
   * **代码举例:**  已经在 `TestStringConcatenationAllocs` 函数中展示。

**4. 测试页缓存泄漏:**

   * **功能:** `TestPageCacheLeak` 函数调用 `PageCachePagesLeaked()` 来检查是否存在页缓存泄漏。 页缓存是 Go 运行时用于管理内存页的机制，如果存在泄漏会导致内存占用持续增长。

**5. 测试物理内存利用率:**

   * **功能:** `TestPhysicalMemoryUtilization` 函数通过运行一个外部程序并检查其输出来测试 Go 运行时在物理内存利用方面的行为。  这可能涉及到测试 GC 在释放内存方面的能力。
   * **命令行参数:** 该测试通过 `runTestProg` 函数运行名为 `testprog` 的外部程序，并传递参数 `"GCPhys"`。  这意味着在运行测试之前，需要存在一个名为 `testprog` 的可执行文件，并且该程序能够处理 `"GCPhys"` 参数，并输出 `"OK\n"` 表示测试通过。

**6. 测试已回收内存的标记位是否被清除:**

   * **功能:** `TestScavengedBitsCleared` 函数调用 `CheckScavengedBitsCleared` 来验证垃圾回收器是否正确地清除了已回收内存上的标记位。 这是确保内存安全和避免错误的关键步骤。

**7. 测试内存区域冲突处理 (Arena Collision):**

   * **功能:** `TestArenaCollision` 函数旨在测试当 Go 运行时尝试分配内存时，如果遇到与其他内存映射冲突的情况，是否能够正确处理。 这通常涉及到操作系统层面的内存管理。
   * **代码推理与命令行参数:**
     * 该测试首先检查环境变量 `TEST_ARENA_COLLISION` 是否为 "1"。
     * 如果不是 "1"，它会创建一个新的进程来运行自身，并将环境变量设置为 "1"。 这意味着测试会分两个阶段运行。
     * 在子进程中（`TEST_ARENA_COLLISION=1`），测试会调用 `KeepNArenaHints(3)` 来限制内存分配器的 hint 数量。
     * 接着，它会循环调用 `MapNextArenaHint()` 来预留一些内存区域，模拟与其他内存映射的冲突。
     * 然后，在这些预留的区域附近进行内存分配 (`new(acLink)`)，并断言分配的内存没有落入预留的区域。
     * 这种机制是为了触发内存分配器在 hint 用完后，尝试在其他地址空间分配内存，并验证其处理冲突的能力。

**8. 基准测试 (Benchmarks):**

   * **功能:**  `BenchmarkMalloc*` 系列函数测试了不同大小对象分配的性能。
   * **功能:** `BenchmarkGoroutineSelect`, `BenchmarkGoroutineBlocking`, `BenchmarkGoroutineForRange`, `BenchmarkGoroutineIdle` 测试了 goroutine 和 channel 相关的性能，例如 `select` 语句的性能、阻塞 channel 的性能以及空闲 goroutine 的开销。
   * **命令行参数:**  `BenchmarkGoroutine*` 系列的测试使用了 `flag` 包定义了一个名为 `n` 的命令行参数，用于指定 goroutine 的数量。
     * **使用方法:**  在运行基准测试时，可以使用 `-n` 参数来指定 goroutine 的数量。 例如：
       ```bash
       go test -bench=. -n=10000  # 运行所有基准测试，并设置 goroutine 数量为 10000
       ```
     * **详细介绍:**
       * `-bench=.`:  表示运行当前目录下的所有基准测试。
       * `-n=10000`:  设置 `n` 标志的值为 10000，这将影响 `BenchmarkGoroutine*` 系列测试中创建的 goroutine 数量。

**使用者易犯错的点 (基于代码推理):**

* **误解 `MemStats` 的含义:**  使用者可能会错误地解释 `MemStats` 中的某些指标，例如将 `Sys` 理解为当前进程占用的所有系统内存，而实际上它指的是 Go 运行时向操作系统申请的总内存。
* **假设 tiny allocator 的行为是绝对的:**  使用者可能会认为小对象总是会被分配在同一个 chunk 中，但实际上 tiny allocator 的行为受到多种因素影响，例如并发、GC 等。 因此，不应该依赖于 tiny allocator 的特定行为。
* **在没有理解 arena collision 测试机制的情况下运行它:**  如果直接运行 `TestArenaCollision`，可能会因为没有设置正确的环境变量而无法执行完整的测试逻辑。 正确的方式是通过 `go test` 命令运行，它会自动处理子进程的创建和环境变量的设置。

总而言之，`go/src/runtime/malloc_test.go` 是一个非常重要的测试文件，它覆盖了 Go 语言内存分配器的核心功能，包括内存统计、小对象分配、字符串连接、页缓存管理、物理内存利用以及内存区域冲突处理等。 通过这些测试，可以确保 Go 运行时的内存管理机制的正确性和性能。

Prompt: 
```
这是路径为go/src/runtime/malloc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"flag"
	"fmt"
	"internal/asan"
	"internal/race"
	"internal/testenv"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	. "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

var testMemStatsCount int

func TestMemStats(t *testing.T) {
	testMemStatsCount++

	// Make sure there's at least one forced GC.
	GC()

	// Test that MemStats has sane values.
	st := new(MemStats)
	ReadMemStats(st)

	nz := func(x any) error {
		if x != reflect.Zero(reflect.TypeOf(x)).Interface() {
			return nil
		}
		return fmt.Errorf("zero value")
	}
	le := func(thresh float64) func(any) error {
		return func(x any) error {
			// These sanity tests aren't necessarily valid
			// with high -test.count values, so only run
			// them once.
			if testMemStatsCount > 1 {
				return nil
			}

			if reflect.ValueOf(x).Convert(reflect.TypeOf(thresh)).Float() < thresh {
				return nil
			}
			return fmt.Errorf("insanely high value (overflow?); want <= %v", thresh)
		}
	}
	eq := func(x any) func(any) error {
		return func(y any) error {
			if x == y {
				return nil
			}
			return fmt.Errorf("want %v", x)
		}
	}
	// Of the uint fields, HeapReleased, HeapIdle can be 0.
	// PauseTotalNs can be 0 if timer resolution is poor.
	fields := map[string][]func(any) error{
		"Alloc": {nz, le(1e10)}, "TotalAlloc": {nz, le(1e11)}, "Sys": {nz, le(1e10)},
		"Lookups": {eq(uint64(0))}, "Mallocs": {nz, le(1e10)}, "Frees": {nz, le(1e10)},
		"HeapAlloc": {nz, le(1e10)}, "HeapSys": {nz, le(1e10)}, "HeapIdle": {le(1e10)},
		"HeapInuse": {nz, le(1e10)}, "HeapReleased": {le(1e10)}, "HeapObjects": {nz, le(1e10)},
		"StackInuse": {nz, le(1e10)}, "StackSys": {nz, le(1e10)},
		"MSpanInuse": {nz, le(1e10)}, "MSpanSys": {nz, le(1e10)},
		"MCacheInuse": {nz, le(1e10)}, "MCacheSys": {nz, le(1e10)},
		"BuckHashSys": {nz, le(1e10)}, "GCSys": {nz, le(1e10)}, "OtherSys": {nz, le(1e10)},
		"NextGC": {nz, le(1e10)}, "LastGC": {nz},
		"PauseTotalNs": {le(1e11)}, "PauseNs": nil, "PauseEnd": nil,
		"NumGC": {nz, le(1e9)}, "NumForcedGC": {nz, le(1e9)},
		"GCCPUFraction": {le(0.99)}, "EnableGC": {eq(true)}, "DebugGC": {eq(false)},
		"BySize": nil,
	}

	rst := reflect.ValueOf(st).Elem()
	for i := 0; i < rst.Type().NumField(); i++ {
		name, val := rst.Type().Field(i).Name, rst.Field(i).Interface()
		checks, ok := fields[name]
		if !ok {
			t.Errorf("unknown MemStats field %s", name)
			continue
		}
		for _, check := range checks {
			if err := check(val); err != nil {
				t.Errorf("%s = %v: %s", name, val, err)
			}
		}
	}

	if st.Sys != st.HeapSys+st.StackSys+st.MSpanSys+st.MCacheSys+
		st.BuckHashSys+st.GCSys+st.OtherSys {
		t.Fatalf("Bad sys value: %+v", *st)
	}

	if st.HeapIdle+st.HeapInuse != st.HeapSys {
		t.Fatalf("HeapIdle(%d) + HeapInuse(%d) should be equal to HeapSys(%d), but isn't.", st.HeapIdle, st.HeapInuse, st.HeapSys)
	}

	if lpe := st.PauseEnd[int(st.NumGC+255)%len(st.PauseEnd)]; st.LastGC != lpe {
		t.Fatalf("LastGC(%d) != last PauseEnd(%d)", st.LastGC, lpe)
	}

	var pauseTotal uint64
	for _, pause := range st.PauseNs {
		pauseTotal += pause
	}
	if int(st.NumGC) < len(st.PauseNs) {
		// We have all pauses, so this should be exact.
		if st.PauseTotalNs != pauseTotal {
			t.Fatalf("PauseTotalNs(%d) != sum PauseNs(%d)", st.PauseTotalNs, pauseTotal)
		}
		for i := int(st.NumGC); i < len(st.PauseNs); i++ {
			if st.PauseNs[i] != 0 {
				t.Fatalf("Non-zero PauseNs[%d]: %+v", i, st)
			}
			if st.PauseEnd[i] != 0 {
				t.Fatalf("Non-zero PauseEnd[%d]: %+v", i, st)
			}
		}
	} else {
		if st.PauseTotalNs < pauseTotal {
			t.Fatalf("PauseTotalNs(%d) < sum PauseNs(%d)", st.PauseTotalNs, pauseTotal)
		}
	}

	if st.NumForcedGC > st.NumGC {
		t.Fatalf("NumForcedGC(%d) > NumGC(%d)", st.NumForcedGC, st.NumGC)
	}
}

func TestStringConcatenationAllocs(t *testing.T) {
	n := testing.AllocsPerRun(1e3, func() {
		b := make([]byte, 10)
		for i := 0; i < 10; i++ {
			b[i] = byte(i) + '0'
		}
		s := "foo" + string(b)
		if want := "foo0123456789"; s != want {
			t.Fatalf("want %v, got %v", want, s)
		}
	})
	// Only string concatenation allocates.
	if n != 1 {
		t.Fatalf("want 1 allocation, got %v", n)
	}
}

func TestTinyAlloc(t *testing.T) {
	if runtime.Raceenabled {
		t.Skip("tinyalloc suppressed when running in race mode")
	}
	if asan.Enabled {
		t.Skip("tinyalloc suppressed when running in asan mode due to redzone")
	}
	const N = 16
	var v [N]unsafe.Pointer
	for i := range v {
		v[i] = unsafe.Pointer(new(byte))
	}

	chunks := make(map[uintptr]bool, N)
	for _, p := range v {
		chunks[uintptr(p)&^7] = true
	}

	if len(chunks) == N {
		t.Fatal("no bytes allocated within the same 8-byte chunk")
	}
}

type obj12 struct {
	a uint64
	b uint32
}

func TestTinyAllocIssue37262(t *testing.T) {
	if runtime.Raceenabled {
		t.Skip("tinyalloc suppressed when running in race mode")
	}
	if asan.Enabled {
		t.Skip("tinyalloc suppressed when running in asan mode due to redzone")
	}
	// Try to cause an alignment access fault
	// by atomically accessing the first 64-bit
	// value of a tiny-allocated object.
	// See issue 37262 for details.

	// GC twice, once to reach a stable heap state
	// and again to make sure we finish the sweep phase.
	runtime.GC()
	runtime.GC()

	// Disable preemption so we stay on one P's tiny allocator and
	// nothing else allocates from it.
	runtime.Acquirem()

	// Make 1-byte allocations until we get a fresh tiny slot.
	aligned := false
	for i := 0; i < 16; i++ {
		x := runtime.Escape(new(byte))
		if uintptr(unsafe.Pointer(x))&0xf == 0xf {
			aligned = true
			break
		}
	}
	if !aligned {
		runtime.Releasem()
		t.Fatal("unable to get a fresh tiny slot")
	}

	// Create a 4-byte object so that the current
	// tiny slot is partially filled.
	runtime.Escape(new(uint32))

	// Create a 12-byte object, which fits into the
	// tiny slot. If it actually gets place there,
	// then the field "a" will be improperly aligned
	// for atomic access on 32-bit architectures.
	// This won't be true if issue 36606 gets resolved.
	tinyObj12 := runtime.Escape(new(obj12))

	// Try to atomically access "x.a".
	atomic.StoreUint64(&tinyObj12.a, 10)

	runtime.Releasem()
}

func TestPageCacheLeak(t *testing.T) {
	defer GOMAXPROCS(GOMAXPROCS(1))
	leaked := PageCachePagesLeaked()
	if leaked != 0 {
		t.Fatalf("found %d leaked pages in page caches", leaked)
	}
}

func TestPhysicalMemoryUtilization(t *testing.T) {
	got := runTestProg(t, "testprog", "GCPhys")
	want := "OK\n"
	if got != want {
		t.Fatalf("expected %q, but got %q", want, got)
	}
}

func TestScavengedBitsCleared(t *testing.T) {
	var mismatches [128]BitsMismatch
	if n, ok := CheckScavengedBitsCleared(mismatches[:]); !ok {
		t.Errorf("uncleared scavenged bits")
		for _, m := range mismatches[:n] {
			t.Logf("\t@ address 0x%x", m.Base)
			t.Logf("\t|  got: %064b", m.Got)
			t.Logf("\t| want: %064b", m.Want)
		}
		t.FailNow()
	}
}

type acLink struct {
	x [1 << 20]byte
}

var arenaCollisionSink []*acLink

func TestArenaCollision(t *testing.T) {
	testenv.MustHaveExec(t)

	// Test that mheap.sysAlloc handles collisions with other
	// memory mappings.
	if os.Getenv("TEST_ARENA_COLLISION") != "1" {
		cmd := testenv.CleanCmdEnv(exec.Command(os.Args[0], "-test.run=^TestArenaCollision$", "-test.v"))
		cmd.Env = append(cmd.Env, "TEST_ARENA_COLLISION=1")
		out, err := cmd.CombinedOutput()
		if race.Enabled {
			// This test runs the runtime out of hint
			// addresses, so it will start mapping the
			// heap wherever it can. The race detector
			// doesn't support this, so look for the
			// expected failure.
			if want := "too many address space collisions"; !strings.Contains(string(out), want) {
				t.Fatalf("want %q, got:\n%s", want, string(out))
			}
		} else if !strings.Contains(string(out), "PASS\n") || err != nil {
			t.Fatalf("%s\n(exit status %v)", string(out), err)
		}
		return
	}
	disallowed := [][2]uintptr{}
	// Drop all but the next 3 hints. 64-bit has a lot of hints,
	// so it would take a lot of memory to go through all of them.
	KeepNArenaHints(3)
	// Consume these 3 hints and force the runtime to find some
	// fallback hints.
	for i := 0; i < 5; i++ {
		// Reserve memory at the next hint so it can't be used
		// for the heap.
		start, end, ok := MapNextArenaHint()
		if !ok {
			t.Skipf("failed to reserve memory at next arena hint [%#x, %#x)", start, end)
		}
		t.Logf("reserved [%#x, %#x)", start, end)
		disallowed = append(disallowed, [2]uintptr{start, end})
		// Allocate until the runtime tries to use the hint we
		// just mapped over.
		hint := GetNextArenaHint()
		for GetNextArenaHint() == hint {
			ac := new(acLink)
			arenaCollisionSink = append(arenaCollisionSink, ac)
			// The allocation must not have fallen into
			// one of the reserved regions.
			p := uintptr(unsafe.Pointer(ac))
			for _, d := range disallowed {
				if d[0] <= p && p < d[1] {
					t.Fatalf("allocation %#x in reserved region [%#x, %#x)", p, d[0], d[1])
				}
			}
		}
	}
}

func BenchmarkMalloc8(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := new(int64)
		Escape(p)
	}
}

func BenchmarkMalloc16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := new([2]int64)
		Escape(p)
	}
}

func BenchmarkMallocTypeInfo8(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := new(struct {
			p [8 / unsafe.Sizeof(uintptr(0))]*int
		})
		Escape(p)
	}
}

func BenchmarkMallocTypeInfo16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := new(struct {
			p [16 / unsafe.Sizeof(uintptr(0))]*int
		})
		Escape(p)
	}
}

type LargeStruct struct {
	x [16][]byte
}

func BenchmarkMallocLargeStruct(b *testing.B) {
	for i := 0; i < b.N; i++ {
		p := make([]LargeStruct, 2)
		Escape(p)
	}
}

var n = flag.Int("n", 1000, "number of goroutines")

func BenchmarkGoroutineSelect(b *testing.B) {
	quit := make(chan struct{})
	read := func(ch chan struct{}) {
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			case <-quit:
				return
			}
		}
	}
	benchHelper(b, *n, read)
}

func BenchmarkGoroutineBlocking(b *testing.B) {
	read := func(ch chan struct{}) {
		for {
			if _, ok := <-ch; !ok {
				return
			}
		}
	}
	benchHelper(b, *n, read)
}

func BenchmarkGoroutineForRange(b *testing.B) {
	read := func(ch chan struct{}) {
		for range ch {
		}
	}
	benchHelper(b, *n, read)
}

func benchHelper(b *testing.B, n int, read func(chan struct{})) {
	m := make([]chan struct{}, n)
	for i := range m {
		m[i] = make(chan struct{}, 1)
		go read(m[i])
	}
	b.StopTimer()
	b.ResetTimer()
	GC()

	for i := 0; i < b.N; i++ {
		for _, ch := range m {
			if ch != nil {
				ch <- struct{}{}
			}
		}
		time.Sleep(10 * time.Millisecond)
		b.StartTimer()
		GC()
		b.StopTimer()
	}

	for _, ch := range m {
		close(ch)
	}
	time.Sleep(10 * time.Millisecond)
}

func BenchmarkGoroutineIdle(b *testing.B) {
	quit := make(chan struct{})
	fn := func() {
		<-quit
	}
	for i := 0; i < *n; i++ {
		go fn()
	}

	GC()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		GC()
	}

	b.StopTimer()
	close(quit)
	time.Sleep(10 * time.Millisecond)
}

"""



```