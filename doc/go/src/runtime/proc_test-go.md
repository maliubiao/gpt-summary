Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding: Context is Key**

The first thing to notice is the `//go:build` line (even though it's not directly in the provided snippet, the file path `go/src/runtime/proc_test.go` tells us it's part of the Go runtime). This immediately signals that the code is testing internal aspects of the Go runtime, specifically the scheduler and process management (`proc`). The `_test` suffix reinforces that it's a testing file.

**2. High-Level Scan for Functionality:**

I'll quickly read through the function names and some of the core logic to get a general sense of what's being tested. Keywords like `Test`, `Benchmark`, `runtime.`, `atomic.`, `time.Sleep`, `chan`, `sync.WaitGroup`, `net.Listen` jump out. This suggests testing things like:

* **Concurrency primitives:** Goroutines, channels, mutexes (implicitly through `sync.WaitGroup`).
* **Scheduler behavior:** Preemption, yielding, parallelism.
* **Garbage Collection (GC):**  Disabling and potentially observing its interaction with goroutines.
* **System calls:** Locking OS threads, potentially interacting with network polling.
* **Performance:** Benchmarking goroutine creation, context switching, and potentially CPU-bound tasks.

**3. Categorizing Tests by Functionality:**

I start grouping the tests based on their names and what they seem to be doing:

* **Stopping the world:** `TestStopTheWorldDeadlock` likely tests scenarios that could lead to deadlocks during GC or scheduler operations.
* **Yielding:** `TestYieldProgress`, `TestYieldLockedProgress`, `TestYieldLocked` focus on the `runtime.Gosched()` function and its behavior with OS threads.
* **Parallelism:** `TestGoroutineParallelism`, `TestGoroutineParallelism2` aim to verify that multiple goroutines can run concurrently on different processors.
* **OS Thread Locking:** `TestBlockLocked`, `TestLockOSThreadNesting`, `TestLockOSThreadExit`, `TestLockOSThreadAvoidsStatePropagation`, `TestLockOSThreadTemplateThreadRace` deal with the `runtime.LockOSThread()` functionality and its implications.
* **Timer Fairness:** `TestTimerFairness`, `TestTimerFairness2` check the fairness of Go's timers when multiple goroutines are involved.
* **Preemption:** `TestPreemption`, `TestPreemptionGC`, `TestAsyncPreempt`, `TestPreemptSplitBig`, `TestPreemptionAfterSyscall` test various aspects of goroutine preemption, including at function calls, during GC, and after system calls.
* **Garbage Collection Fairness:** `TestGCFairness`, `TestGCFairness2` are likely related to ensuring fair scheduling of GC processes.
* **Goroutine Counting and Stacks:** `TestNumGoroutine` checks the accuracy of `runtime.NumGoroutine()` and `runtime.Stack()`.
* **Scheduler Queues:** `TestSchedLocalQueue`, `TestSchedLocalQueueSteal`, `TestSchedLocalQueueEmpty` test the behavior of the scheduler's local run queues.
* **Benchmarking:** The `Benchmark...` functions measure the performance of different operations.
* **Netpoll:** `TestNetpollBreak` tests the ability to interrupt network polling.
* **GOMAXPROCS:** `TestBigGOMAXPROCS` likely tests handling of a large number of processors.

**4. Deep Dive into Selected Tests (for Code Examples and Reasoning):**

For a few key tests, I'll examine the code more closely to understand the testing logic and potential use cases:

* **`TestStopTheWorldDeadlock`:** The name suggests it's looking for deadlocks during "stop-the-world" events (like GC). It uses `runtime.GC()` and `runtime.GOMAXPROCS()` in separate goroutines, which can sometimes interact in unexpected ways. The `perpetuumMobile()` function creates a continuously running goroutine, adding to the complexity. *Hypothesis: This tests whether repeatedly triggering GC and changing `GOMAXPROCS` concurrently can cause a deadlock.*

* **`TestYieldProgress`:**  This test uses `runtime.Gosched()` to explicitly yield the processor. The `locked` parameter suggests testing this both with and without the goroutine being bound to an OS thread. *Hypothesis:  This verifies that `runtime.Gosched()` allows other goroutines to make progress.*

* **`TestGoroutineParallelism`:** The use of `atomic.LoadUint32` and `atomic.StoreUint32` hints at trying to coordinate the execution of multiple goroutines simultaneously. The loops and the `expected` value calculation suggest checking if goroutines are indeed running in parallel and incrementing a shared counter in a predictable order. *Hypothesis: This tests if the scheduler can effectively run multiple goroutines in parallel when there's work to be done.*

* **`TestLockOSThread` tests:** These are quite specific. They use `runtime.LockOSThread()` which binds a goroutine to a specific OS thread. The tests seem to cover nesting of these calls, behavior on exit, and potential side effects. *Hypothesis: These tests ensure the correct behavior of the OS thread locking mechanism.*

**5. Identifying Potential User Errors:**

Based on my understanding of the tests, I can think about common mistakes users might make:

* **Incorrect use of `runtime.Gosched()`:** Users might think `Gosched()` guarantees immediate execution of other goroutines, but it only yields the current time slice.
* **Misunderstanding `runtime.LockOSThread()`:**  Forgetting to call `runtime.UnlockOSThread()` can lead to resource leaks (threads not being returned to the pool). Over-reliance on `LockOSThread` can reduce concurrency.
* **Deadlocks with `GOMAXPROCS` and GC:** While rare in typical application code, the `TestStopTheWorldDeadlock` highlights that manipulating `GOMAXPROCS` concurrently with GC can be problematic in certain scenarios.

**6. Structuring the Answer:**

Finally, I organize the information in the requested format:

* **功能:** List the general functionalities being tested.
* **Go语言功能实现推理和代码举例:** Pick a few interesting tests, explain the underlying Go feature being tested, provide a simplified code example demonstrating that feature, and explain the assumptions, inputs, and expected outputs.
* **命令行参数处理:**  Since the provided code snippet doesn't directly handle command-line arguments, I'd note this and mention that `testing` package handles flags like `-short`.
* **使用者易犯错的点:**  List common pitfalls based on the tested functionalities.

This structured approach helps to systematically analyze the code and provide a comprehensive answer.
这段代码是 Go 语言运行时（runtime）的一部分，位于 `go/src/runtime/proc_test.go`，它主要用于测试 Go 语言的**调度器（scheduler）**和**进程管理（process management）**相关的核心功能。

以下是它的一些主要功能和测试点：

**1. 测试防止“停止世界”（Stop-The-World）时的死锁：**

* **功能:** `TestStopTheWorldDeadlock` 函数测试在高并发场景下，当垃圾回收（GC）或者其他需要暂停所有 goroutine 的操作发生时，是否会发生死锁。它通过并发地执行 GC 和修改 `GOMAXPROCS` 来模拟高压场景。
* **Go语言功能:** 这测试了 Go 运行时在执行需要 STW 的操作时的同步机制和锁的正确性。
* **代码举例:**
```go
package main

import (
	"runtime"
	"time"
)

func main() {
	runtime.GOMAXPROCS(3) // 设置 GOMAXPROCS
	stop := make(chan bool)

	// 一个无限循环的 goroutine
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				// 执行一些操作
			}
		}
	}()

	// 并发地触发 GC 和修改 GOMAXPROCS
	go func() {
		for i := 0; i < 1000; i++ {
			runtime.GC()
		}
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			runtime.GOMAXPROCS(3)
		}
	}()

	time.Sleep(time.Second) // 运行一段时间
	stop <- true
}
```
* **假设输入与输出:** 此测试没有直接的输入输出，它的目的是验证在并发操作下不会发生死锁导致程序无法正常结束。如果发生死锁，测试会超时或卡住。

**2. 测试 `runtime.Gosched()` 的作用：**

* **功能:** `TestYieldProgress` 和 `TestYieldLockedProgress` 测试 `runtime.Gosched()` 函数，该函数用于让出当前 goroutine 的 CPU 时间片，让其他 runnable 的 goroutine 运行。`TestYieldLockedProgress` 特别测试了当 goroutine 锁定操作系统线程时的 `Gosched()` 行为。
* **Go语言功能:** 测试了 goroutine 的协作式调度。
* **代码举例:**
```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	c := make(chan bool)
	go func() {
		fmt.Println("Goroutine 1 starting")
		runtime.Gosched() // 让出 CPU
		fmt.Println("Goroutine 1 continuing")
		c <- true
	}()

	time.Sleep(time.Millisecond) // 确保 Goroutine 1 先运行
	fmt.Println("Main goroutine")
	<-c // 等待 Goroutine 1 完成
}
```
* **假设输入与输出:**
    * 输出可能为:
    ```
    Goroutine 1 starting
    Main goroutine
    Goroutine 1 continuing
    ```
    或者
    ```
    Main goroutine
    Goroutine 1 starting
    Goroutine 1 continuing
    ```
    这取决于调度器的具体行为，但 `runtime.Gosched()` 的作用是允许主 goroutine 在 Goroutine 1 让出 CPU 后有机会运行。

**3. 测试 goroutine 的并行性：**

* **功能:** `TestGoroutineParallelism` 和 `TestGoroutineParallelism2` 测试在多核 CPU 环境下，多个 goroutine 是否能够真正并行执行。它们通过原子操作来同步多个 goroutine，确保它们同时被调度执行。
* **Go语言功能:** 测试了 Go 语言的并发模型和调度器在多核环境下的效率。
* **代码举例:**
```go
package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"time"
)

func main() {
	if runtime.NumCPU() < 2 {
		fmt.Println("Skipping test on single-core CPU")
		return
	}

	runtime.GOMAXPROCS(2) // 确保至少有两个 P

	var counter uint32
	done := make(chan bool)

	for i := 0; i < 2; i++ {
		go func(id int) {
			for j := 0; j < 1000; j++ {
				atomic.AddUint32(&counter, 1)
			}
			done <- true
		}(i)
	}

	<-done
	<-done

	fmt.Println("Counter:", counter) // 期望 counter 接近 2000
}
```
* **假设输入与输出:** 在双核 CPU 上，期望 `counter` 的值接近 2000，因为两个 goroutine 并行地增加计数器。

**4. 测试锁定操作系统线程的行为：**

* **功能:** `TestYieldLocked`, `TestBlockLocked`, `TestLockOSThreadNesting` 等测试了 `runtime.LockOSThread()` 和 `runtime.UnlockOSThread()` 函数，这两个函数用于将 goroutine 绑定到特定的操作系统线程。
* **Go语言功能:** 测试了与操作系统线程的交互和绑定。
* **代码举例:**
```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func main() {
	runtime.LockOSThread()
	fmt.Println("Goroutine locked to OS thread")
	time.Sleep(time.Second) // 执行一些操作
	runtime.UnlockOSThread()
	fmt.Println("Goroutine unlocked from OS thread")
}
```
* **假设输入与输出:** 程序会输出 "Goroutine locked to OS thread"，然后等待一秒，最后输出 "Goroutine unlocked from OS thread"。这展示了 goroutine 和 OS 线程的绑定关系。

**5. 测试定时器的公平性：**

* **功能:** `TestTimerFairness` 和 `TestTimerFairness2` 检查 Go 语言的定时器（`time.After`）在多个 goroutine 竞争时的公平性，确保没有 goroutine 会一直被饿死。
* **Go语言功能:** 测试了调度器对定时器的处理和 goroutine 的唤醒机制。

**6. 测试抢占式调度：**

* **功能:** `TestPreemption`, `TestPreemptionGC`, `TestAsyncPreempt`, `TestPreemptSplitBig`, `TestPreemptionAfterSyscall` 等测试了 Go 语言的抢占式调度机制，确保长时间运行或阻塞的 goroutine 会被抢占，让其他 goroutine 能够运行。
* **Go语言功能:** 测试了 Go 语言如何保证公平的 CPU 资源分配。
* **`TestAsyncPreempt` 和 `TestPreemptionAfterSyscall` 涉及到更底层的机制:**
    * `TestAsyncPreempt` 测试异步抢占，这是一种更激进的抢占方式，可以在安全点之外进行抢占。
    * `TestPreemptionAfterSyscall` 测试 goroutine 在系统调用返回后是否能被及时抢占。

**7. 测试垃圾回收的公平性：**

* **功能:** `TestGCFairness` 和 `TestGCFairness2` 测试垃圾回收器在多 goroutine 并发执行时的公平性，确保 GC 不会过度影响某些 goroutine 的执行。

**8. 测试 `runtime.NumGoroutine()` 的准确性：**

* **功能:** `TestNumGoroutine` 检查 `runtime.NumGoroutine()` 函数返回的当前 goroutine 数量是否准确，并与 `runtime.Stack()` 输出的 goroutine 信息进行对比。

**9. 测试调度器的本地队列和工作窃取机制：**

* **功能:** `TestSchedLocalQueue`, `TestSchedLocalQueueSteal`, `TestSchedLocalQueueEmpty` 等测试调度器的本地运行队列以及工作窃取机制，确保 goroutine 能够高效地在不同的 P（processor）之间迁移和调度。

**10. 性能基准测试：**

* 诸如 `BenchmarkStackGrowth`, `BenchmarkCreateGoroutines`, `BenchmarkPingPongHog`, `BenchmarkMatmult` 等 `Benchmark` 开头的函数用于衡量不同操作的性能，例如栈增长、goroutine 创建、上下文切换以及计算密集型任务的性能。

**命令行参数处理：**

该测试文件本身并不直接处理命令行参数。但是，它使用 `testing` 包进行测试，而 `testing` 包会处理一些标准的测试标志，例如：

* `-test.short`:  运行时间较短的测试。
* `-test.v`:  显示更详细的测试输出。
* `-test.run <regexp>`:  只运行匹配正则表达式的测试。
* `-test.cpu <n>`:  设置 `GOMAXPROCS` 的值。

例如，你可以使用 `go test -test.short ./proc_test.go` 来运行该文件中标记为短时间的测试。

**使用者易犯错的点 (与测试覆盖的功能相关):**

* **过度依赖 `runtime.Gosched()` 来控制执行顺序:**  `Gosched()` 只是建议让出 CPU，并不能保证其他特定的 goroutine 会立即运行。依赖 `Gosched()` 来实现精确的同步通常是不可靠的。
* **误解 `runtime.LockOSThread()` 的作用和副作用:**  过度使用 `LockOSThread()` 会限制 Go 语言的并发能力，因为它将 goroutine 绑定到单个操作系统线程，无法利用多核 CPU 的优势。忘记调用 `runtime.UnlockOSThread()` 会导致操作系统线程泄漏。
* **在高并发场景下修改 `GOMAXPROCS`:** 虽然在某些特定场景下可能需要动态调整 `GOMAXPROCS`，但在高并发环境下频繁修改可能会导致意想不到的调度行为，甚至引发问题（如 `TestStopTheWorldDeadlock` 尝试模拟的情况）。
* **不理解抢占式调度的行为:**  开发者不应该依赖于特定的 goroutine 运行时间或执行顺序，因为抢占式调度会根据系统负载和 goroutine 的行为动态调整。

总的来说，`go/src/runtime/proc_test.go` 是一个非常重要的测试文件，它深入测试了 Go 语言并发模型的核心，确保调度器和进程管理机制的正确性、效率和公平性。理解这些测试的功能有助于更深入地理解 Go 语言的并发原理。

Prompt: 
```
这是路径为go/src/runtime/proc_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime_test

import (
	"fmt"
	"internal/race"
	"internal/testenv"
	"math"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var stop = make(chan bool, 1)

func perpetuumMobile() {
	select {
	case <-stop:
	default:
		go perpetuumMobile()
	}
}

func TestStopTheWorldDeadlock(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}
	if testing.Short() {
		t.Skip("skipping during short test")
	}
	maxprocs := runtime.GOMAXPROCS(3)
	compl := make(chan bool, 2)
	go func() {
		for i := 0; i != 1000; i += 1 {
			runtime.GC()
		}
		compl <- true
	}()
	go func() {
		for i := 0; i != 1000; i += 1 {
			runtime.GOMAXPROCS(3)
		}
		compl <- true
	}()
	go perpetuumMobile()
	<-compl
	<-compl
	stop <- true
	runtime.GOMAXPROCS(maxprocs)
}

func TestYieldProgress(t *testing.T) {
	testYieldProgress(false)
}

func TestYieldLockedProgress(t *testing.T) {
	testYieldProgress(true)
}

func testYieldProgress(locked bool) {
	c := make(chan bool)
	cack := make(chan bool)
	go func() {
		if locked {
			runtime.LockOSThread()
		}
		for {
			select {
			case <-c:
				cack <- true
				return
			default:
				runtime.Gosched()
			}
		}
	}()
	time.Sleep(10 * time.Millisecond)
	c <- true
	<-cack
}

func TestYieldLocked(t *testing.T) {
	const N = 10
	c := make(chan bool)
	go func() {
		runtime.LockOSThread()
		for i := 0; i < N; i++ {
			runtime.Gosched()
			time.Sleep(time.Millisecond)
		}
		c <- true
		// runtime.UnlockOSThread() is deliberately omitted
	}()
	<-c
}

func TestGoroutineParallelism(t *testing.T) {
	if runtime.NumCPU() == 1 {
		// Takes too long, too easy to deadlock, etc.
		t.Skip("skipping on uniprocessor")
	}
	P := 4
	N := 10
	if testing.Short() {
		P = 3
		N = 3
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(P))
	// If runtime triggers a forced GC during this test then it will deadlock,
	// since the goroutines can't be stopped/preempted.
	// Disable GC for this test (see issue #10958).
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	// SetGCPercent waits until the mark phase is over, but the runtime
	// also preempts at the start of the sweep phase, so make sure that's
	// done too. See #45867.
	runtime.GC()
	for try := 0; try < N; try++ {
		done := make(chan bool)
		x := uint32(0)
		for p := 0; p < P; p++ {
			// Test that all P goroutines are scheduled at the same time
			go func(p int) {
				for i := 0; i < 3; i++ {
					expected := uint32(P*i + p)
					for atomic.LoadUint32(&x) != expected {
					}
					atomic.StoreUint32(&x, expected+1)
				}
				done <- true
			}(p)
		}
		for p := 0; p < P; p++ {
			<-done
		}
	}
}

// Test that all runnable goroutines are scheduled at the same time.
func TestGoroutineParallelism2(t *testing.T) {
	//testGoroutineParallelism2(t, false, false)
	testGoroutineParallelism2(t, true, false)
	testGoroutineParallelism2(t, false, true)
	testGoroutineParallelism2(t, true, true)
}

func testGoroutineParallelism2(t *testing.T, load, netpoll bool) {
	if runtime.NumCPU() == 1 {
		// Takes too long, too easy to deadlock, etc.
		t.Skip("skipping on uniprocessor")
	}
	P := 4
	N := 10
	if testing.Short() {
		N = 3
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(P))
	// If runtime triggers a forced GC during this test then it will deadlock,
	// since the goroutines can't be stopped/preempted.
	// Disable GC for this test (see issue #10958).
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	// SetGCPercent waits until the mark phase is over, but the runtime
	// also preempts at the start of the sweep phase, so make sure that's
	// done too. See #45867.
	runtime.GC()
	for try := 0; try < N; try++ {
		if load {
			// Create P goroutines and wait until they all run.
			// When we run the actual test below, worker threads
			// running the goroutines will start parking.
			done := make(chan bool)
			x := uint32(0)
			for p := 0; p < P; p++ {
				go func() {
					if atomic.AddUint32(&x, 1) == uint32(P) {
						done <- true
						return
					}
					for atomic.LoadUint32(&x) != uint32(P) {
					}
				}()
			}
			<-done
		}
		if netpoll {
			// Enable netpoller, affects schedler behavior.
			laddr := "localhost:0"
			if runtime.GOOS == "android" {
				// On some Android devices, there are no records for localhost,
				// see https://golang.org/issues/14486.
				// Don't use 127.0.0.1 for every case, it won't work on IPv6-only systems.
				laddr = "127.0.0.1:0"
			}
			ln, err := net.Listen("tcp", laddr)
			if err == nil {
				defer ln.Close() // yup, defer in a loop
			}
		}
		done := make(chan bool)
		x := uint32(0)
		// Spawn P goroutines in a nested fashion just to differ from TestGoroutineParallelism.
		for p := 0; p < P/2; p++ {
			go func(p int) {
				for p2 := 0; p2 < 2; p2++ {
					go func(p2 int) {
						for i := 0; i < 3; i++ {
							expected := uint32(P*i + p*2 + p2)
							for atomic.LoadUint32(&x) != expected {
							}
							atomic.StoreUint32(&x, expected+1)
						}
						done <- true
					}(p2)
				}
			}(p)
		}
		for p := 0; p < P; p++ {
			<-done
		}
	}
}

func TestBlockLocked(t *testing.T) {
	const N = 10
	c := make(chan bool)
	go func() {
		runtime.LockOSThread()
		for i := 0; i < N; i++ {
			c <- true
		}
		runtime.UnlockOSThread()
	}()
	for i := 0; i < N; i++ {
		<-c
	}
}

func TestTimerFairness(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}

	done := make(chan bool)
	c := make(chan bool)
	for i := 0; i < 2; i++ {
		go func() {
			for {
				select {
				case c <- true:
				case <-done:
					return
				}
			}
		}()
	}

	timer := time.After(20 * time.Millisecond)
	for {
		select {
		case <-c:
		case <-timer:
			close(done)
			return
		}
	}
}

func TestTimerFairness2(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}

	done := make(chan bool)
	c := make(chan bool)
	for i := 0; i < 2; i++ {
		go func() {
			timer := time.After(20 * time.Millisecond)
			var buf [1]byte
			for {
				syscall.Read(0, buf[0:0])
				select {
				case c <- true:
				case <-c:
				case <-timer:
					done <- true
					return
				}
			}
		}()
	}
	<-done
	<-done
}

// The function is used to test preemption at split stack checks.
// Declaring a var avoids inlining at the call site.
var preempt = func() int {
	var a [128]int
	sum := 0
	for _, v := range a {
		sum += v
	}
	return sum
}

func TestPreemption(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}

	// Test that goroutines are preempted at function calls.
	N := 5
	if testing.Short() {
		N = 2
	}
	c := make(chan bool)
	var x uint32
	for g := 0; g < 2; g++ {
		go func(g int) {
			for i := 0; i < N; i++ {
				for atomic.LoadUint32(&x) != uint32(g) {
					preempt()
				}
				atomic.StoreUint32(&x, uint32(1-g))
			}
			c <- true
		}(g)
	}
	<-c
	<-c
}

func TestPreemptionGC(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}

	// Test that pending GC preempts running goroutines.
	P := 5
	N := 10
	if testing.Short() {
		P = 3
		N = 2
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(P + 1))
	var stop uint32
	for i := 0; i < P; i++ {
		go func() {
			for atomic.LoadUint32(&stop) == 0 {
				preempt()
			}
		}()
	}
	for i := 0; i < N; i++ {
		runtime.Gosched()
		runtime.GC()
	}
	atomic.StoreUint32(&stop, 1)
}

func TestAsyncPreempt(t *testing.T) {
	if !runtime.PreemptMSupported {
		t.Skip("asynchronous preemption not supported on this platform")
	}
	output := runTestProg(t, "testprog", "AsyncPreempt")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestGCFairness(t *testing.T) {
	output := runTestProg(t, "testprog", "GCFairness")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestGCFairness2(t *testing.T) {
	output := runTestProg(t, "testprog", "GCFairness2")
	want := "OK\n"
	if output != want {
		t.Fatalf("want %s, got %s\n", want, output)
	}
}

func TestNumGoroutine(t *testing.T) {
	output := runTestProg(t, "testprog", "NumGoroutine")
	want := "1\n"
	if output != want {
		t.Fatalf("want %q, got %q", want, output)
	}

	buf := make([]byte, 1<<20)

	// Try up to 10 times for a match before giving up.
	// This is a fundamentally racy check but it's important
	// to notice if NumGoroutine and Stack are _always_ out of sync.
	for i := 0; ; i++ {
		// Give goroutines about to exit a chance to exit.
		// The NumGoroutine and Stack below need to see
		// the same state of the world, so anything we can do
		// to keep it quiet is good.
		runtime.Gosched()

		n := runtime.NumGoroutine()
		buf = buf[:runtime.Stack(buf, true)]

		// To avoid double-counting "goroutine" in "goroutine $m [running]:"
		// and "created by $func in goroutine $n", remove the latter
		output := strings.ReplaceAll(string(buf), "in goroutine", "")
		nstk := strings.Count(output, "goroutine ")
		if n == nstk {
			break
		}
		if i >= 10 {
			t.Fatalf("NumGoroutine=%d, but found %d goroutines in stack dump: %s", n, nstk, buf)
		}
	}
}

func TestPingPongHog(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	if race.Enabled {
		// The race detector randomizes the scheduler,
		// which causes this test to fail (#38266).
		t.Skip("skipping in -race mode")
	}

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	done := make(chan bool)
	hogChan, lightChan := make(chan bool), make(chan bool)
	hogCount, lightCount := 0, 0

	run := func(limit int, counter *int, wake chan bool) {
		for {
			select {
			case <-done:
				return

			case <-wake:
				for i := 0; i < limit; i++ {
					*counter++
				}
				wake <- true
			}
		}
	}

	// Start two co-scheduled hog goroutines.
	for i := 0; i < 2; i++ {
		go run(1e6, &hogCount, hogChan)
	}

	// Start two co-scheduled light goroutines.
	for i := 0; i < 2; i++ {
		go run(1e3, &lightCount, lightChan)
	}

	// Start goroutine pairs and wait for a few preemption rounds.
	hogChan <- true
	lightChan <- true
	time.Sleep(100 * time.Millisecond)
	close(done)
	<-hogChan
	<-lightChan

	// Check that hogCount and lightCount are within a factor of
	// 20, which indicates that both pairs of goroutines handed off
	// the P within a time-slice to their buddy. We can use a
	// fairly large factor here to make this robust: if the
	// scheduler isn't working right, the gap should be ~1000X
	// (was 5, increased to 20, see issue 52207).
	const factor = 20
	if hogCount/factor > lightCount || lightCount/factor > hogCount {
		t.Fatalf("want hogCount/lightCount in [%v, %v]; got %d/%d = %g", 1.0/factor, factor, hogCount, lightCount, float64(hogCount)/float64(lightCount))
	}
}

func BenchmarkPingPongHog(b *testing.B) {
	if b.N == 0 {
		return
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))

	// Create a CPU hog
	stop, done := make(chan bool), make(chan bool)
	go func() {
		for {
			select {
			case <-stop:
				done <- true
				return
			default:
			}
		}
	}()

	// Ping-pong b.N times
	ping, pong := make(chan bool), make(chan bool)
	go func() {
		for j := 0; j < b.N; j++ {
			pong <- <-ping
		}
		close(stop)
		done <- true
	}()
	go func() {
		for i := 0; i < b.N; i++ {
			ping <- <-pong
		}
		done <- true
	}()
	b.ResetTimer()
	ping <- true // Start ping-pong
	<-stop
	b.StopTimer()
	<-ping // Let last ponger exit
	<-done // Make sure goroutines exit
	<-done
	<-done
}

var padData [128]uint64

func stackGrowthRecursive(i int) {
	var pad [128]uint64
	pad = padData
	for j := range pad {
		if pad[j] != 0 {
			return
		}
	}
	if i != 0 {
		stackGrowthRecursive(i - 1)
	}
}

func TestPreemptSplitBig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	stop := make(chan int)
	go big(stop)
	for i := 0; i < 3; i++ {
		time.Sleep(10 * time.Microsecond) // let big start running
		runtime.GC()
	}
	close(stop)
}

func big(stop chan int) int {
	n := 0
	for {
		// delay so that gc is sure to have asked for a preemption
		for i := 0; i < 1e9; i++ {
			n++
		}

		// call bigframe, which used to miss the preemption in its prologue.
		bigframe(stop)

		// check if we've been asked to stop.
		select {
		case <-stop:
			return n
		}
	}
}

func bigframe(stop chan int) int {
	// not splitting the stack will overflow.
	// small will notice that it needs a stack split and will
	// catch the overflow.
	var x [8192]byte
	return small(stop, &x)
}

func small(stop chan int, x *[8192]byte) int {
	for i := range x {
		x[i] = byte(i)
	}
	sum := 0
	for i := range x {
		sum += int(x[i])
	}

	// keep small from being a leaf function, which might
	// make it not do any stack check at all.
	nonleaf(stop)

	return sum
}

func nonleaf(stop chan int) bool {
	// do something that won't be inlined:
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func TestSchedLocalQueue(t *testing.T) {
	runtime.RunSchedLocalQueueTest()
}

func TestSchedLocalQueueSteal(t *testing.T) {
	runtime.RunSchedLocalQueueStealTest()
}

func TestSchedLocalQueueEmpty(t *testing.T) {
	if runtime.NumCPU() == 1 {
		// Takes too long and does not trigger the race.
		t.Skip("skipping on uniprocessor")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))

	// If runtime triggers a forced GC during this test then it will deadlock,
	// since the goroutines can't be stopped/preempted during spin wait.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	// SetGCPercent waits until the mark phase is over, but the runtime
	// also preempts at the start of the sweep phase, so make sure that's
	// done too. See #45867.
	runtime.GC()

	iters := int(1e5)
	if testing.Short() {
		iters = 1e2
	}
	runtime.RunSchedLocalQueueEmptyTest(iters)
}

func benchmarkStackGrowth(b *testing.B, rec int) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			stackGrowthRecursive(rec)
		}
	})
}

func BenchmarkStackGrowth(b *testing.B) {
	benchmarkStackGrowth(b, 10)
}

func BenchmarkStackGrowthDeep(b *testing.B) {
	benchmarkStackGrowth(b, 1024)
}

func BenchmarkCreateGoroutines(b *testing.B) {
	benchmarkCreateGoroutines(b, 1)
}

func BenchmarkCreateGoroutinesParallel(b *testing.B) {
	benchmarkCreateGoroutines(b, runtime.GOMAXPROCS(-1))
}

func benchmarkCreateGoroutines(b *testing.B, procs int) {
	c := make(chan bool)
	var f func(n int)
	f = func(n int) {
		if n == 0 {
			c <- true
			return
		}
		go f(n - 1)
	}
	for i := 0; i < procs; i++ {
		go f(b.N / procs)
	}
	for i := 0; i < procs; i++ {
		<-c
	}
}

func BenchmarkCreateGoroutinesCapture(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		const N = 4
		var wg sync.WaitGroup
		wg.Add(N)
		for i := 0; i < N; i++ {
			i := i
			go func() {
				if i >= N {
					b.Logf("bad") // just to capture b
				}
				wg.Done()
			}()
		}
		wg.Wait()
	}
}

// warmupScheduler ensures the scheduler has at least targetThreadCount threads
// in its thread pool.
func warmupScheduler(targetThreadCount int) {
	var wg sync.WaitGroup
	var count int32
	for i := 0; i < targetThreadCount; i++ {
		wg.Add(1)
		go func() {
			atomic.AddInt32(&count, 1)
			for atomic.LoadInt32(&count) < int32(targetThreadCount) {
				// spin until all threads started
			}

			// spin a bit more to ensure they are all running on separate CPUs.
			doWork(time.Millisecond)
			wg.Done()
		}()
	}
	wg.Wait()
}

func doWork(dur time.Duration) {
	start := time.Now()
	for time.Since(start) < dur {
	}
}

// BenchmarkCreateGoroutinesSingle creates many goroutines, all from a single
// producer (the main benchmark goroutine).
//
// Compared to BenchmarkCreateGoroutines, this causes different behavior in the
// scheduler because Ms are much more likely to need to steal work from the
// main P rather than having work in the local run queue.
func BenchmarkCreateGoroutinesSingle(b *testing.B) {
	// Since we are interested in stealing behavior, warm the scheduler to
	// get all the Ps running first.
	warmupScheduler(runtime.GOMAXPROCS(0))
	b.ResetTimer()

	var wg sync.WaitGroup
	wg.Add(b.N)
	for i := 0; i < b.N; i++ {
		go func() {
			wg.Done()
		}()
	}
	wg.Wait()
}

func BenchmarkClosureCall(b *testing.B) {
	sum := 0
	off1 := 1
	for i := 0; i < b.N; i++ {
		off2 := 2
		func() {
			sum += i + off1 + off2
		}()
	}
	_ = sum
}

func benchmarkWakeupParallel(b *testing.B, spin func(time.Duration)) {
	if runtime.GOMAXPROCS(0) == 1 {
		b.Skip("skipping: GOMAXPROCS=1")
	}

	wakeDelay := 5 * time.Microsecond
	for _, delay := range []time.Duration{
		0,
		1 * time.Microsecond,
		2 * time.Microsecond,
		5 * time.Microsecond,
		10 * time.Microsecond,
		20 * time.Microsecond,
		50 * time.Microsecond,
		100 * time.Microsecond,
	} {
		b.Run(delay.String(), func(b *testing.B) {
			if b.N == 0 {
				return
			}
			// Start two goroutines, which alternate between being
			// sender and receiver in the following protocol:
			//
			// - The receiver spins for `delay` and then does a
			// blocking receive on a channel.
			//
			// - The sender spins for `delay+wakeDelay` and then
			// sends to the same channel. (The addition of
			// `wakeDelay` improves the probability that the
			// receiver will be blocking when the send occurs when
			// the goroutines execute in parallel.)
			//
			// In each iteration of the benchmark, each goroutine
			// acts once as sender and once as receiver, so each
			// goroutine spins for delay twice.
			//
			// BenchmarkWakeupParallel is used to estimate how
			// efficiently the scheduler parallelizes goroutines in
			// the presence of blocking:
			//
			// - If both goroutines are executed on the same core,
			// an increase in delay by N will increase the time per
			// iteration by 4*N, because all 4 delays are
			// serialized.
			//
			// - Otherwise, an increase in delay by N will increase
			// the time per iteration by 2*N, and the time per
			// iteration is 2 * (runtime overhead + chan
			// send/receive pair + delay + wakeDelay). This allows
			// the runtime overhead, including the time it takes
			// for the unblocked goroutine to be scheduled, to be
			// estimated.
			ping, pong := make(chan struct{}), make(chan struct{})
			start := make(chan struct{})
			done := make(chan struct{})
			go func() {
				<-start
				for i := 0; i < b.N; i++ {
					// sender
					spin(delay + wakeDelay)
					ping <- struct{}{}
					// receiver
					spin(delay)
					<-pong
				}
				done <- struct{}{}
			}()
			go func() {
				for i := 0; i < b.N; i++ {
					// receiver
					spin(delay)
					<-ping
					// sender
					spin(delay + wakeDelay)
					pong <- struct{}{}
				}
				done <- struct{}{}
			}()
			b.ResetTimer()
			start <- struct{}{}
			<-done
			<-done
		})
	}
}

func BenchmarkWakeupParallelSpinning(b *testing.B) {
	benchmarkWakeupParallel(b, func(d time.Duration) {
		end := time.Now().Add(d)
		for time.Now().Before(end) {
			// do nothing
		}
	})
}

// sysNanosleep is defined by OS-specific files (such as runtime_linux_test.go)
// to sleep for the given duration. If nil, dependent tests are skipped.
// The implementation should invoke a blocking system call and not
// call time.Sleep, which would deschedule the goroutine.
var sysNanosleep func(d time.Duration)

func BenchmarkWakeupParallelSyscall(b *testing.B) {
	if sysNanosleep == nil {
		b.Skipf("skipping on %v; sysNanosleep not defined", runtime.GOOS)
	}
	benchmarkWakeupParallel(b, func(d time.Duration) {
		sysNanosleep(d)
	})
}

type Matrix [][]float64

func BenchmarkMatmult(b *testing.B) {
	b.StopTimer()
	// matmult is O(N**3) but testing expects O(b.N),
	// so we need to take cube root of b.N
	n := int(math.Cbrt(float64(b.N))) + 1
	A := makeMatrix(n)
	B := makeMatrix(n)
	C := makeMatrix(n)
	b.StartTimer()
	matmult(nil, A, B, C, 0, n, 0, n, 0, n, 8)
}

func makeMatrix(n int) Matrix {
	m := make(Matrix, n)
	for i := 0; i < n; i++ {
		m[i] = make([]float64, n)
		for j := 0; j < n; j++ {
			m[i][j] = float64(i*n + j)
		}
	}
	return m
}

func matmult(done chan<- struct{}, A, B, C Matrix, i0, i1, j0, j1, k0, k1, threshold int) {
	di := i1 - i0
	dj := j1 - j0
	dk := k1 - k0
	if di >= dj && di >= dk && di >= threshold {
		// divide in two by y axis
		mi := i0 + di/2
		done1 := make(chan struct{}, 1)
		go matmult(done1, A, B, C, i0, mi, j0, j1, k0, k1, threshold)
		matmult(nil, A, B, C, mi, i1, j0, j1, k0, k1, threshold)
		<-done1
	} else if dj >= dk && dj >= threshold {
		// divide in two by x axis
		mj := j0 + dj/2
		done1 := make(chan struct{}, 1)
		go matmult(done1, A, B, C, i0, i1, j0, mj, k0, k1, threshold)
		matmult(nil, A, B, C, i0, i1, mj, j1, k0, k1, threshold)
		<-done1
	} else if dk >= threshold {
		// divide in two by "k" axis
		// deliberately not parallel because of data races
		mk := k0 + dk/2
		matmult(nil, A, B, C, i0, i1, j0, j1, k0, mk, threshold)
		matmult(nil, A, B, C, i0, i1, j0, j1, mk, k1, threshold)
	} else {
		// the matrices are small enough, compute directly
		for i := i0; i < i1; i++ {
			for j := j0; j < j1; j++ {
				for k := k0; k < k1; k++ {
					C[i][j] += A[i][k] * B[k][j]
				}
			}
		}
	}
	if done != nil {
		done <- struct{}{}
	}
}

func TestStealOrder(t *testing.T) {
	runtime.RunStealOrderTest()
}

func TestLockOSThreadNesting(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no threads on wasm yet")
	}

	go func() {
		e, i := runtime.LockOSCounts()
		if e != 0 || i != 0 {
			t.Errorf("want locked counts 0, 0; got %d, %d", e, i)
			return
		}
		runtime.LockOSThread()
		runtime.LockOSThread()
		runtime.UnlockOSThread()
		e, i = runtime.LockOSCounts()
		if e != 1 || i != 0 {
			t.Errorf("want locked counts 1, 0; got %d, %d", e, i)
			return
		}
		runtime.UnlockOSThread()
		e, i = runtime.LockOSCounts()
		if e != 0 || i != 0 {
			t.Errorf("want locked counts 0, 0; got %d, %d", e, i)
			return
		}
	}()
}

func TestLockOSThreadExit(t *testing.T) {
	testLockOSThreadExit(t, "testprog")
}

func testLockOSThreadExit(t *testing.T, prog string) {
	output := runTestProg(t, prog, "LockOSThreadMain", "GOMAXPROCS=1")
	want := "OK\n"
	if output != want {
		t.Errorf("want %q, got %q", want, output)
	}

	output = runTestProg(t, prog, "LockOSThreadAlt")
	if output != want {
		t.Errorf("want %q, got %q", want, output)
	}
}

func TestLockOSThreadAvoidsStatePropagation(t *testing.T) {
	want := "OK\n"
	skip := "unshare not permitted\n"
	output := runTestProg(t, "testprog", "LockOSThreadAvoidsStatePropagation", "GOMAXPROCS=1")
	if output == skip {
		t.Skip("unshare syscall not permitted on this system")
	} else if output != want {
		t.Errorf("want %q, got %q", want, output)
	}
}

func TestLockOSThreadTemplateThreadRace(t *testing.T) {
	testenv.MustHaveGoRun(t)

	exe, err := buildTestProg(t, "testprog")
	if err != nil {
		t.Fatal(err)
	}

	iterations := 100
	if testing.Short() {
		// Reduce run time to ~100ms, with much lower probability of
		// catching issues.
		iterations = 5
	}
	for i := 0; i < iterations; i++ {
		want := "OK\n"
		output := runBuiltTestProg(t, exe, "LockOSThreadTemplateThreadRace")
		if output != want {
			t.Fatalf("run %d: want %q, got %q", i, want, output)
		}
	}
}

// fakeSyscall emulates a system call.
//
//go:nosplit
func fakeSyscall(duration time.Duration) {
	runtime.Entersyscall()
	for start := runtime.Nanotime(); runtime.Nanotime()-start < int64(duration); {
	}
	runtime.Exitsyscall()
}

// Check that a goroutine will be preempted if it is calling short system calls.
func testPreemptionAfterSyscall(t *testing.T, syscallDuration time.Duration) {
	if runtime.GOARCH == "wasm" {
		t.Skip("no preemption on wasm yet")
	}

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))

	iterations := 10
	if testing.Short() {
		iterations = 1
	}
	const (
		maxDuration = 5 * time.Second
		nroutines   = 8
	)

	for i := 0; i < iterations; i++ {
		c := make(chan bool, nroutines)
		stop := uint32(0)

		start := time.Now()
		for g := 0; g < nroutines; g++ {
			go func(stop *uint32) {
				c <- true
				for atomic.LoadUint32(stop) == 0 {
					fakeSyscall(syscallDuration)
				}
				c <- true
			}(&stop)
		}
		// wait until all goroutines have started.
		for g := 0; g < nroutines; g++ {
			<-c
		}
		atomic.StoreUint32(&stop, 1)
		// wait until all goroutines have finished.
		for g := 0; g < nroutines; g++ {
			<-c
		}
		duration := time.Since(start)

		if duration > maxDuration {
			t.Errorf("timeout exceeded: %v (%v)", duration, maxDuration)
		}
	}
}

func TestPreemptionAfterSyscall(t *testing.T) {
	if runtime.GOOS == "plan9" {
		testenv.SkipFlaky(t, 41015)
	}

	for _, i := range []time.Duration{10, 100, 1000} {
		d := i * time.Microsecond
		t.Run(fmt.Sprint(d), func(t *testing.T) {
			testPreemptionAfterSyscall(t, d)
		})
	}
}

func TestGetgThreadSwitch(t *testing.T) {
	runtime.RunGetgThreadSwitchTest()
}

// TestNetpollBreak tests that netpollBreak can break a netpoll.
// This test is not particularly safe since the call to netpoll
// will pick up any stray files that are ready, but it should work
// OK as long it is not run in parallel.
func TestNetpollBreak(t *testing.T) {
	if runtime.GOMAXPROCS(0) == 1 {
		t.Skip("skipping: GOMAXPROCS=1")
	}

	// Make sure that netpoll is initialized.
	runtime.NetpollGenericInit()

	start := time.Now()
	c := make(chan bool, 2)
	go func() {
		c <- true
		runtime.Netpoll(10 * time.Second.Nanoseconds())
		c <- true
	}()
	<-c
	// Loop because the break might get eaten by the scheduler.
	// Break twice to break both the netpoll we started and the
	// scheduler netpoll.
loop:
	for {
		runtime.Usleep(100)
		runtime.NetpollBreak()
		runtime.NetpollBreak()
		select {
		case <-c:
			break loop
		default:
		}
	}
	if dur := time.Since(start); dur > 5*time.Second {
		t.Errorf("netpollBreak did not interrupt netpoll: slept for: %v", dur)
	}
}

// TestBigGOMAXPROCS tests that setting GOMAXPROCS to a large value
// doesn't cause a crash at startup. See issue 38474.
func TestBigGOMAXPROCS(t *testing.T) {
	t.Parallel()
	output := runTestProg(t, "testprog", "NonexistentTest", "GOMAXPROCS=1024")
	// Ignore error conditions on small machines.
	for _, errstr := range []string{
		"failed to create new OS thread",
		"cannot allocate memory",
	} {
		if strings.Contains(output, errstr) {
			t.Skipf("failed to create 1024 threads")
		}
	}
	if !strings.Contains(output, "unknown function: NonexistentTest") {
		t.Errorf("output:\n%s\nwanted:\nunknown function: NonexistentTest", output)
	}
}

"""



```