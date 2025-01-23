Response:
Let's break down the thought process for analyzing this Go runtime code snippet.

**1. Initial Understanding - Context is Key:**

The first thing I notice is the file path: `go/src/runtime/proc.go`. The `runtime` package is core to Go's execution, and `proc.go` strongly suggests process and thread management, particularly related to the scheduler. The initial comments confirm this, mentioning Goroutines (G), Machines/worker threads (M), and Processors (P). The design doc link (`https://golang.org/s/go11sched`) is a treasure trove for deeper understanding, although we need to analyze the provided code itself.

**2. High-Level Feature Identification (Skimming and Keywords):**

I quickly skim the code, looking for key data structures and function names. Terms like `Goroutine scheduler`, `worker thread`, `processor`, `parking/unparking`, `run queue`, `timers`, `GC`, `m`, `g`, `p`, `sched`, `mutex`, `atomic`, `main`, `init`, `Gosched`, `gopark`, `goready`, etc., jump out. This confirms the initial suspicion about the code's purpose.

**3. Categorizing Functionality - The "Mental Buckets":**

Based on the keywords and comments, I start mentally grouping the functionalities:

* **Scheduler Core:**  This is the most prominent theme. It involves managing Gs, Ms, and Ps, including putting Goroutines onto run queues, waking up threads, and managing the spinning thread logic.
* **Initialization:**  The `main` and `init` functions, along with `schedinit`, clearly deal with setting up the runtime environment.
* **Goroutine Lifecycle:** Functions like `gopark` and `goready` directly manage the state transitions of Goroutines.
* **Thread Management:**  The parking/unparking logic and the `m` structure relate to managing OS threads.
* **Synchronization Primitives:** The presence of `mutex` and `atomic` operations indicates mechanisms for protecting shared state.
* **Memory Management (Indirectly):** While `proc.go` isn't the core memory allocator, its interaction with the GC and the allocation of stacks (`stackalloc`) is evident.
* **System Interaction:**  The `syscall` mention and `lockOSThread` point to interaction with the underlying operating system.
* **Debugging and Tracing:**  The `debug` package usage and `inittrace` suggest features for observing and understanding runtime behavior.

**4. Drilling Down - Specific Function Analysis:**

Now, I examine specific blocks of code and functions more closely:

* **Scheduler Logic (Wakep, Spinning):** The comments explaining the spinning thread logic are crucial. I identify the conditions under which new threads are unparked (`wakep`), and the roles of `m.spinning` and `sched.nmspinning`. The described general patterns for submission and spinning->non-spinning transitions are important to note.
* **`main` function:** I analyze the steps within `main`, including locking the OS thread, calling `doInit`, enabling GC, handling CGO, and finally calling `main_main`. This provides a high-level overview of the program's startup.
* **`init` functions:** I see multiple `init` functions, indicating setup for various runtime components like the garbage collector (`forcegchelper`).
* **`Gosched` family:** I understand that `Gosched`, `goschedguarded`, and `goschedIfBusy` are different ways for a Goroutine to yield the processor.
* **`gopark` and `goready`:**  These are fundamental for Goroutine synchronization and waiting/waking. The comments highlight their external usage via `linkname`.
* **`acquireSudog` and `releaseSudog`:** The comments reveal these are related to a semaphore implementation and their careful handling to avoid deadlocks with the GC.
* **`schedinit`:** This function is responsible for initializing various runtime locks and subsystems.

**5. Inferring Go Features and Providing Examples:**

Based on the identified functionalities, I start inferring the Go language features being implemented:

* **Goroutines and the Scheduler:**  This is the most obvious one. I can provide a simple example of launching multiple Goroutines and observing their concurrent execution.
* **`runtime.Gosched()`:**  The code clearly implements this function. I provide an example of how it can be used to manually yield the processor.
* **`runtime.LockOSThread()`:** The `lockOSThread` call in `main` shows the implementation of this feature. I provide an example demonstrating its use, highlighting the scenario where it's necessary (e.g., interacting with C libraries).
* **Internal Synchronization (Mutexes, Atomicity):** While not directly exposed as a high-level Go feature *in this specific snippet*, the presence of mutexes and atomic operations is fundamental to Go's concurrency model and the implementation of features like channels and wait groups (which are related to `gopark`/`goready`). I could mention this as a related, though not directly shown, aspect.

**6. Code Reasoning and Assumptions:**

When reasoning about the code, I make certain assumptions based on my knowledge of Go and operating systems. For example, I assume that `newm` creates a new OS thread, `runqput` adds a Goroutine to a run queue, and `wakep` wakes up a processor. If the request asked for deep code tracing, I would need to examine the implementation of these called functions as well.

**7. Identifying Potential Pitfalls:**

I look for common mistakes users might make when interacting with the features implemented by this code:

* **Misunderstanding `Gosched()`:** Users might think `Gosched()` suspends the Goroutine, leading to unexpected behavior if they rely on immediate continuation.
* **Overusing `runtime.LockOSThread()`:**  Locking the OS thread can limit concurrency and should be done sparingly. I provide an example where it's unnecessary to illustrate the pitfall.

**8. Structuring the Answer:**

Finally, I organize the information logically, starting with a summary, then detailing the functionalities, providing code examples, explaining reasoning, and highlighting potential pitfalls. I use clear and concise language, explaining technical terms where necessary. Since the prompt specified Chinese, I ensured the entire response was in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis:** I might initially focus too heavily on one aspect, like the spinning thread logic. I need to broaden my perspective and ensure I cover all significant functionalities.
* **Clarity of Examples:** My initial code examples might be too complex. I need to simplify them to clearly demonstrate the specific feature.
* **Addressing the "Why":**  It's not enough to just describe *what* the code does. I need to explain *why* it's designed this way (e.g., the rationale behind the spinning thread logic).
* **Checking for Completeness:** I review the prompt to ensure I've addressed all its points, including the specific request to summarize the first part.

By following this iterative process of understanding, categorizing, analyzing, inferring, and refining, I can effectively analyze and explain the functionality of the given Go runtime code snippet.
这段Go语言代码是 Go 运行时环境（runtime）中 `proc.go` 文件的一部分，主要负责 **Goroutine 调度器** 的实现。

**它的核心功能是管理和调度 Goroutine 在操作系统线程上的执行。**

**更具体地说，它包含了以下关键功能：**

1. **定义核心数据结构：**  定义了 Goroutine (G)、工作线程/机器 (M) 和处理器 (P) 这些核心概念的结构体。这些结构体是 Go 并发模型的基础。

2. **工作线程的停放与唤醒 (Parking/Unparking)：**  实现了智能的工作线程管理机制，平衡硬件并行性的利用和 CPU 资源的节约。  其中核心逻辑围绕着 "spinning" 状态的 worker thread。

3. **Goroutine 的状态管理：** 维护 Goroutine 的各种状态，例如运行中、等待中、可运行等，并通过原子操作来保证状态切换的线程安全。

4. **运行队列 (Run Queue) 管理：**  虽然这段代码本身没有直接显示运行队列的实现，但它描述了如何将 Goroutine 放入本地或全局运行队列，以及 worker thread 如何从这些队列中获取 Goroutine 执行。

5. **初始化 (Initialization)：**  包含了 `main` 和 `schedinit` 函数，负责运行时环境的初始化，包括创建初始的 Goroutine (`g0`) 和工作线程 (`m0`)，初始化调度器锁等。

6. **`Gosched()` 的实现：**  实现了让当前 Goroutine 主动让出 CPU 的功能。

7. **`gopark()` 和 `goready()` 的实现：**  实现了 Goroutine 进入等待状态和被唤醒的功能，这是实现 Go 语言中各种同步原语（如 `sync.Mutex`, `sync.WaitGroup`, channels）的基础。

8. **`forcegchelper()` 的实现：** 启动一个辅助 Goroutine 来触发垃圾回收。

9. **CPU 特性检测和初始化 (`cpuinit`)：**  检测当前 CPU 的特性，以便在运行时选择最优的指令。

10. **获取和设置环境变量 (`getGodebugEarly`, `goargs`, `goenvs`)：**  处理与环境变量相关的操作。

11. **Panic 和死锁检测 (间接)：** 虽然代码中没有直接的死锁检测逻辑，但包含了 `deadlock` 锁的初始化，暗示了运行时有相关的机制来处理死锁。

**可以推理出它是什么 Go 语言功能的实现：**

这段代码是 **Go 语言并发模型的核心实现**，特别是 **Goroutine 的调度**。它确保了多个 Goroutine 能够高效地并发执行在少量的操作系统线程上，并提供了 Goroutine 协作的基础机制。

**Go 代码举例说明 (Goroutine 调度)：**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func task(id int, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("Goroutine %d started\n", id)
	time.Sleep(time.Millisecond * 100) // 模拟一些工作
	fmt.Printf("Goroutine %d finished\n", id)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU()) // 设置使用的 CPU 核心数
	fmt.Printf("Number of CPUs: %d\n", runtime.NumCPU())

	var wg sync.WaitGroup
	numTasks := 5

	for i := 0; i < numTasks; i++ {
		wg.Add(1)
		go task(i, &wg) // 启动多个 Goroutine
	}

	wg.Wait() // 等待所有 Goroutine 完成
	fmt.Println("All Goroutines finished")
}
```

**假设的输入与输出：**

* **输入：**  启动上述 Go 程序。
* **输出：**  程序会并发地执行多个 `task` 函数，输出类似以下内容（顺序可能不同，因为是并发执行）：

```
Number of CPUs: ... (取决于你的系统)
Goroutine 0 started
Goroutine 1 started
Goroutine 2 started
Goroutine 3 started
Goroutine 4 started
Goroutine 1 finished
Goroutine 0 finished
Goroutine 3 finished
Goroutine 2 finished
Goroutine 4 finished
All Goroutines finished
```

**代码推理：**

* `runtime.GOMAXPROCS(runtime.NumCPU())`  会调用运行时相关的函数来设置可用于执行 Go 代码的处理器数量。这段代码会影响调度器的行为，决定了最多有多少个 P 可以同时运行 M。
* `go task(i, &wg)`  关键字 `go` 会创建一个新的 Goroutine 来执行 `task` 函数。运行时调度器会将这些 Goroutine 放入队列，并分配给可用的 M 和 P 执行。
* `wg.Wait()` 会阻塞 `main` Goroutine，直到所有通过 `wg.Add()` 添加的 Goroutine 都调用了 `wg.Done()`。  这涉及到 Goroutine 的等待和唤醒机制，`gopark` 和 `goready` 在底层起作用。

**命令行参数的具体处理：**

这段代码本身没有直接处理命令行参数的逻辑。命令行参数的处理通常发生在 `os` 包和 `flag` 包中。  `proc.go` 中涉及的可能是通过环境变量来影响运行时的行为，例如 `GOMAXPROCS` 环境变量会影响 `schedinit` 函数中对处理器数量的设置。

**使用者易犯错的点 (与 Goroutine 调度相关)：**

1. **误解 `runtime.Gosched()` 的作用：**  新手可能会认为 `Gosched()` 会暂停当前 Goroutine，然后在之后某个时间点恢复执行。实际上，`Gosched()` 只是让当前 Goroutine 暂时放弃 CPU，调度器会选择其他可运行的 Goroutine 来执行，当前 Goroutine 仍然是可运行的，很可能在很短的时间后再次被调度执行。

   **错误示例：**

   ```go
   package main

   import (
       "fmt"
       "runtime"
       "time"
   )

   func main() {
       go func() {
           fmt.Println("Goroutine 1: Start")
           runtime.Gosched()
           fmt.Println("Goroutine 1: End") // 期望在 Goroutine 2 之后执行
       }()

       go func() {
           fmt.Println("Goroutine 2: Start")
           // 做一些耗时操作，但很快
           fmt.Println("Goroutine 2: End")
       }()

       time.Sleep(time.Second) // 期望等待两个 Goroutine 完成
   }
   ```

   **可能输出：**

   ```
   Goroutine 1: Start
   Goroutine 2: Start
   Goroutine 1: End  // 很可能在 Goroutine 2 结束之前
   Goroutine 2: End
   ```

2. **过度依赖 `runtime.LockOSThread()`：**  在某些需要与特定操作系统线程绑定的场景下（例如调用某些 C 库），可以使用 `runtime.LockOSThread()`。但是，过度使用会导致 Goroutine 无法在其他线程上执行，降低程序的并发性能。

   **错误示例：**

   ```go
   package main

   import (
       "fmt"
       "runtime"
       "sync"
   )

   func processData(id int, wg *sync.WaitGroup) {
       defer wg.Done()
       runtime.LockOSThread() // 不必要的锁定
       defer runtime.UnlockOSThread()
       fmt.Printf("Processing data %d on OS thread %v\n", id, getThreadID())
       // ... 一些数据处理 ...
   }

   func getThreadID() int {
       // 平台相关的获取线程 ID 的方法 (这里只是一个占位符)
       return 0
   }

   func main() {
       runtime.GOMAXPROCS(runtime.NumCPU())
       var wg sync.WaitGroup
       for i := 0; i < 5; i++ {
           wg.Add(1)
           go processData(i, &wg)
       }
       wg.Wait()
   }
   ```

   在这个例子中，如果没有特别的原因需要将 `processData` 绑定到特定的操作系统线程，`runtime.LockOSThread()` 就是不必要的，会限制 Goroutine 的调度灵活性。

**总结一下它的功能 (第 1 部分)：**

这段 `proc.go` 的第一部分主要 **介绍了 Goroutine 调度器的基本概念和设计思想**，定义了核心的数据结构 (G, M, P)，并着重阐述了 **工作线程的停放与唤醒机制**，特别是 "spinning" 状态的处理方式。它为理解 Go 语言的并发模型和调度策略奠定了基础。

### 提示词
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/cpu"
	"internal/goarch"
	"internal/goos"
	"internal/runtime/atomic"
	"internal/runtime/exithook"
	"internal/runtime/sys"
	"internal/stringslite"
	"unsafe"
)

// set using cmd/go/internal/modload.ModInfoProg
var modinfo string

// Goroutine scheduler
// The scheduler's job is to distribute ready-to-run goroutines over worker threads.
//
// The main concepts are:
// G - goroutine.
// M - worker thread, or machine.
// P - processor, a resource that is required to execute Go code.
//     M must have an associated P to execute Go code, however it can be
//     blocked or in a syscall w/o an associated P.
//
// Design doc at https://golang.org/s/go11sched.

// Worker thread parking/unparking.
// We need to balance between keeping enough running worker threads to utilize
// available hardware parallelism and parking excessive running worker threads
// to conserve CPU resources and power. This is not simple for two reasons:
// (1) scheduler state is intentionally distributed (in particular, per-P work
// queues), so it is not possible to compute global predicates on fast paths;
// (2) for optimal thread management we would need to know the future (don't park
// a worker thread when a new goroutine will be readied in near future).
//
// Three rejected approaches that would work badly:
// 1. Centralize all scheduler state (would inhibit scalability).
// 2. Direct goroutine handoff. That is, when we ready a new goroutine and there
//    is a spare P, unpark a thread and handoff it the thread and the goroutine.
//    This would lead to thread state thrashing, as the thread that readied the
//    goroutine can be out of work the very next moment, we will need to park it.
//    Also, it would destroy locality of computation as we want to preserve
//    dependent goroutines on the same thread; and introduce additional latency.
// 3. Unpark an additional thread whenever we ready a goroutine and there is an
//    idle P, but don't do handoff. This would lead to excessive thread parking/
//    unparking as the additional threads will instantly park without discovering
//    any work to do.
//
// The current approach:
//
// This approach applies to three primary sources of potential work: readying a
// goroutine, new/modified-earlier timers, and idle-priority GC. See below for
// additional details.
//
// We unpark an additional thread when we submit work if (this is wakep()):
// 1. There is an idle P, and
// 2. There are no "spinning" worker threads.
//
// A worker thread is considered spinning if it is out of local work and did
// not find work in the global run queue or netpoller; the spinning state is
// denoted in m.spinning and in sched.nmspinning. Threads unparked this way are
// also considered spinning; we don't do goroutine handoff so such threads are
// out of work initially. Spinning threads spin on looking for work in per-P
// run queues and timer heaps or from the GC before parking. If a spinning
// thread finds work it takes itself out of the spinning state and proceeds to
// execution. If it does not find work it takes itself out of the spinning
// state and then parks.
//
// If there is at least one spinning thread (sched.nmspinning>1), we don't
// unpark new threads when submitting work. To compensate for that, if the last
// spinning thread finds work and stops spinning, it must unpark a new spinning
// thread. This approach smooths out unjustified spikes of thread unparking,
// but at the same time guarantees eventual maximal CPU parallelism
// utilization.
//
// The main implementation complication is that we need to be very careful
// during spinning->non-spinning thread transition. This transition can race
// with submission of new work, and either one part or another needs to unpark
// another worker thread. If they both fail to do that, we can end up with
// semi-persistent CPU underutilization.
//
// The general pattern for submission is:
// 1. Submit work to the local or global run queue, timer heap, or GC state.
// 2. #StoreLoad-style memory barrier.
// 3. Check sched.nmspinning.
//
// The general pattern for spinning->non-spinning transition is:
// 1. Decrement nmspinning.
// 2. #StoreLoad-style memory barrier.
// 3. Check all per-P work queues and GC for new work.
//
// Note that all this complexity does not apply to global run queue as we are
// not sloppy about thread unparking when submitting to global queue. Also see
// comments for nmspinning manipulation.
//
// How these different sources of work behave varies, though it doesn't affect
// the synchronization approach:
// * Ready goroutine: this is an obvious source of work; the goroutine is
//   immediately ready and must run on some thread eventually.
// * New/modified-earlier timer: The current timer implementation (see time.go)
//   uses netpoll in a thread with no work available to wait for the soonest
//   timer. If there is no thread waiting, we want a new spinning thread to go
//   wait.
// * Idle-priority GC: The GC wakes a stopped idle thread to contribute to
//   background GC work (note: currently disabled per golang.org/issue/19112).
//   Also see golang.org/issue/44313, as this should be extended to all GC
//   workers.

var (
	m0           m
	g0           g
	mcache0      *mcache
	raceprocctx0 uintptr
	raceFiniLock mutex
)

// This slice records the initializing tasks that need to be
// done to start up the runtime. It is built by the linker.
var runtime_inittasks []*initTask

// main_init_done is a signal used by cgocallbackg that initialization
// has been completed. It is made before _cgo_notify_runtime_init_done,
// so all cgo calls can rely on it existing. When main_init is complete,
// it is closed, meaning cgocallbackg can reliably receive from it.
var main_init_done chan bool

//go:linkname main_main main.main
func main_main()

// mainStarted indicates that the main M has started.
var mainStarted bool

// runtimeInitTime is the nanotime() at which the runtime started.
var runtimeInitTime int64

// Value to use for signal mask for newly created M's.
var initSigmask sigset

// The main goroutine.
func main() {
	mp := getg().m

	// Racectx of m0->g0 is used only as the parent of the main goroutine.
	// It must not be used for anything else.
	mp.g0.racectx = 0

	// Max stack size is 1 GB on 64-bit, 250 MB on 32-bit.
	// Using decimal instead of binary GB and MB because
	// they look nicer in the stack overflow failure message.
	if goarch.PtrSize == 8 {
		maxstacksize = 1000000000
	} else {
		maxstacksize = 250000000
	}

	// An upper limit for max stack size. Used to avoid random crashes
	// after calling SetMaxStack and trying to allocate a stack that is too big,
	// since stackalloc works with 32-bit sizes.
	maxstackceiling = 2 * maxstacksize

	// Allow newproc to start new Ms.
	mainStarted = true

	if haveSysmon {
		systemstack(func() {
			newm(sysmon, nil, -1)
		})
	}

	// Lock the main goroutine onto this, the main OS thread,
	// during initialization. Most programs won't care, but a few
	// do require certain calls to be made by the main thread.
	// Those can arrange for main.main to run in the main thread
	// by calling runtime.LockOSThread during initialization
	// to preserve the lock.
	lockOSThread()

	if mp != &m0 {
		throw("runtime.main not on m0")
	}

	// Record when the world started.
	// Must be before doInit for tracing init.
	runtimeInitTime = nanotime()
	if runtimeInitTime == 0 {
		throw("nanotime returning zero")
	}

	if debug.inittrace != 0 {
		inittrace.id = getg().goid
		inittrace.active = true
	}

	doInit(runtime_inittasks) // Must be before defer.

	// Defer unlock so that runtime.Goexit during init does the unlock too.
	needUnlock := true
	defer func() {
		if needUnlock {
			unlockOSThread()
		}
	}()

	gcenable()

	main_init_done = make(chan bool)
	if iscgo {
		if _cgo_pthread_key_created == nil {
			throw("_cgo_pthread_key_created missing")
		}

		if _cgo_thread_start == nil {
			throw("_cgo_thread_start missing")
		}
		if GOOS != "windows" {
			if _cgo_setenv == nil {
				throw("_cgo_setenv missing")
			}
			if _cgo_unsetenv == nil {
				throw("_cgo_unsetenv missing")
			}
		}
		if _cgo_notify_runtime_init_done == nil {
			throw("_cgo_notify_runtime_init_done missing")
		}

		// Set the x_crosscall2_ptr C function pointer variable point to crosscall2.
		if set_crosscall2 == nil {
			throw("set_crosscall2 missing")
		}
		set_crosscall2()

		// Start the template thread in case we enter Go from
		// a C-created thread and need to create a new thread.
		startTemplateThread()
		cgocall(_cgo_notify_runtime_init_done, nil)
	}

	// Run the initializing tasks. Depending on build mode this
	// list can arrive a few different ways, but it will always
	// contain the init tasks computed by the linker for all the
	// packages in the program (excluding those added at runtime
	// by package plugin). Run through the modules in dependency
	// order (the order they are initialized by the dynamic
	// loader, i.e. they are added to the moduledata linked list).
	for m := &firstmoduledata; m != nil; m = m.next {
		doInit(m.inittasks)
	}

	// Disable init tracing after main init done to avoid overhead
	// of collecting statistics in malloc and newproc
	inittrace.active = false

	close(main_init_done)

	needUnlock = false
	unlockOSThread()

	if isarchive || islibrary {
		// A program compiled with -buildmode=c-archive or c-shared
		// has a main, but it is not executed.
		if GOARCH == "wasm" {
			// On Wasm, pause makes it return to the host.
			// Unlike cgo callbacks where Ms are created on demand,
			// on Wasm we have only one M. So we keep this M (and this
			// G) for callbacks.
			// Using the caller's SP unwinds this frame and backs to
			// goexit. The -16 is: 8 for goexit's (fake) return PC,
			// and pause's epilogue pops 8.
			pause(sys.GetCallerSP() - 16) // should not return
			panic("unreachable")
		}
		return
	}
	fn := main_main // make an indirect call, as the linker doesn't know the address of the main package when laying down the runtime
	fn()
	if raceenabled {
		runExitHooks(0) // run hooks now, since racefini does not return
		racefini()
	}

	// Make racy client program work: if panicking on
	// another goroutine at the same time as main returns,
	// let the other goroutine finish printing the panic trace.
	// Once it does, it will exit. See issues 3934 and 20018.
	if runningPanicDefers.Load() != 0 {
		// Running deferred functions should not take long.
		for c := 0; c < 1000; c++ {
			if runningPanicDefers.Load() == 0 {
				break
			}
			Gosched()
		}
	}
	if panicking.Load() != 0 {
		gopark(nil, nil, waitReasonPanicWait, traceBlockForever, 1)
	}
	runExitHooks(0)

	exit(0)
	for {
		var x *int32
		*x = 0
	}
}

// os_beforeExit is called from os.Exit(0).
//
//go:linkname os_beforeExit os.runtime_beforeExit
func os_beforeExit(exitCode int) {
	runExitHooks(exitCode)
	if exitCode == 0 && raceenabled {
		racefini()
	}
}

func init() {
	exithook.Gosched = Gosched
	exithook.Goid = func() uint64 { return getg().goid }
	exithook.Throw = throw
}

func runExitHooks(code int) {
	exithook.Run(code)
}

// start forcegc helper goroutine
func init() {
	go forcegchelper()
}

func forcegchelper() {
	forcegc.g = getg()
	lockInit(&forcegc.lock, lockRankForcegc)
	for {
		lock(&forcegc.lock)
		if forcegc.idle.Load() {
			throw("forcegc: phase error")
		}
		forcegc.idle.Store(true)
		goparkunlock(&forcegc.lock, waitReasonForceGCIdle, traceBlockSystemGoroutine, 1)
		// this goroutine is explicitly resumed by sysmon
		if debug.gctrace > 0 {
			println("GC forced")
		}
		// Time-triggered, fully concurrent.
		gcStart(gcTrigger{kind: gcTriggerTime, now: nanotime()})
	}
}

// Gosched yields the processor, allowing other goroutines to run. It does not
// suspend the current goroutine, so execution resumes automatically.
//
//go:nosplit
func Gosched() {
	checkTimeouts()
	mcall(gosched_m)
}

// goschedguarded yields the processor like gosched, but also checks
// for forbidden states and opts out of the yield in those cases.
//
//go:nosplit
func goschedguarded() {
	mcall(goschedguarded_m)
}

// goschedIfBusy yields the processor like gosched, but only does so if
// there are no idle Ps or if we're on the only P and there's nothing in
// the run queue. In both cases, there is freely available idle time.
//
//go:nosplit
func goschedIfBusy() {
	gp := getg()
	// Call gosched if gp.preempt is set; we may be in a tight loop that
	// doesn't otherwise yield.
	if !gp.preempt && sched.npidle.Load() > 0 {
		return
	}
	mcall(gosched_m)
}

// Puts the current goroutine into a waiting state and calls unlockf on the
// system stack.
//
// If unlockf returns false, the goroutine is resumed.
//
// unlockf must not access this G's stack, as it may be moved between
// the call to gopark and the call to unlockf.
//
// Note that because unlockf is called after putting the G into a waiting
// state, the G may have already been readied by the time unlockf is called
// unless there is external synchronization preventing the G from being
// readied. If unlockf returns false, it must guarantee that the G cannot be
// externally readied.
//
// Reason explains why the goroutine has been parked. It is displayed in stack
// traces and heap dumps. Reasons should be unique and descriptive. Do not
// re-use reasons, add new ones.
//
// gopark should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//   - github.com/sagernet/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname gopark
func gopark(unlockf func(*g, unsafe.Pointer) bool, lock unsafe.Pointer, reason waitReason, traceReason traceBlockReason, traceskip int) {
	if reason != waitReasonSleep {
		checkTimeouts() // timeouts may expire while two goroutines keep the scheduler busy
	}
	mp := acquirem()
	gp := mp.curg
	status := readgstatus(gp)
	if status != _Grunning && status != _Gscanrunning {
		throw("gopark: bad g status")
	}
	mp.waitlock = lock
	mp.waitunlockf = unlockf
	gp.waitreason = reason
	mp.waitTraceBlockReason = traceReason
	mp.waitTraceSkip = traceskip
	releasem(mp)
	// can't do anything that might move the G between Ms here.
	mcall(park_m)
}

// Puts the current goroutine into a waiting state and unlocks the lock.
// The goroutine can be made runnable again by calling goready(gp).
func goparkunlock(lock *mutex, reason waitReason, traceReason traceBlockReason, traceskip int) {
	gopark(parkunlock_c, unsafe.Pointer(lock), reason, traceReason, traceskip)
}

// goready should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//   - github.com/sagernet/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname goready
func goready(gp *g, traceskip int) {
	systemstack(func() {
		ready(gp, traceskip, true)
	})
}

//go:nosplit
func acquireSudog() *sudog {
	// Delicate dance: the semaphore implementation calls
	// acquireSudog, acquireSudog calls new(sudog),
	// new calls malloc, malloc can call the garbage collector,
	// and the garbage collector calls the semaphore implementation
	// in stopTheWorld.
	// Break the cycle by doing acquirem/releasem around new(sudog).
	// The acquirem/releasem increments m.locks during new(sudog),
	// which keeps the garbage collector from being invoked.
	mp := acquirem()
	pp := mp.p.ptr()
	if len(pp.sudogcache) == 0 {
		lock(&sched.sudoglock)
		// First, try to grab a batch from central cache.
		for len(pp.sudogcache) < cap(pp.sudogcache)/2 && sched.sudogcache != nil {
			s := sched.sudogcache
			sched.sudogcache = s.next
			s.next = nil
			pp.sudogcache = append(pp.sudogcache, s)
		}
		unlock(&sched.sudoglock)
		// If the central cache is empty, allocate a new one.
		if len(pp.sudogcache) == 0 {
			pp.sudogcache = append(pp.sudogcache, new(sudog))
		}
	}
	n := len(pp.sudogcache)
	s := pp.sudogcache[n-1]
	pp.sudogcache[n-1] = nil
	pp.sudogcache = pp.sudogcache[:n-1]
	if s.elem != nil {
		throw("acquireSudog: found s.elem != nil in cache")
	}
	releasem(mp)
	return s
}

//go:nosplit
func releaseSudog(s *sudog) {
	if s.elem != nil {
		throw("runtime: sudog with non-nil elem")
	}
	if s.isSelect {
		throw("runtime: sudog with non-false isSelect")
	}
	if s.next != nil {
		throw("runtime: sudog with non-nil next")
	}
	if s.prev != nil {
		throw("runtime: sudog with non-nil prev")
	}
	if s.waitlink != nil {
		throw("runtime: sudog with non-nil waitlink")
	}
	if s.c != nil {
		throw("runtime: sudog with non-nil c")
	}
	gp := getg()
	if gp.param != nil {
		throw("runtime: releaseSudog with non-nil gp.param")
	}
	mp := acquirem() // avoid rescheduling to another P
	pp := mp.p.ptr()
	if len(pp.sudogcache) == cap(pp.sudogcache) {
		// Transfer half of local cache to the central cache.
		var first, last *sudog
		for len(pp.sudogcache) > cap(pp.sudogcache)/2 {
			n := len(pp.sudogcache)
			p := pp.sudogcache[n-1]
			pp.sudogcache[n-1] = nil
			pp.sudogcache = pp.sudogcache[:n-1]
			if first == nil {
				first = p
			} else {
				last.next = p
			}
			last = p
		}
		lock(&sched.sudoglock)
		last.next = sched.sudogcache
		sched.sudogcache = first
		unlock(&sched.sudoglock)
	}
	pp.sudogcache = append(pp.sudogcache, s)
	releasem(mp)
}

// called from assembly.
func badmcall(fn func(*g)) {
	throw("runtime: mcall called on m->g0 stack")
}

func badmcall2(fn func(*g)) {
	throw("runtime: mcall function returned")
}

func badreflectcall() {
	panic(plainError("arg size to reflect.call more than 1GB"))
}

//go:nosplit
//go:nowritebarrierrec
func badmorestackg0() {
	if !crashStackImplemented {
		writeErrStr("fatal: morestack on g0\n")
		return
	}

	g := getg()
	switchToCrashStack(func() {
		print("runtime: morestack on g0, stack [", hex(g.stack.lo), " ", hex(g.stack.hi), "], sp=", hex(g.sched.sp), ", called from\n")
		g.m.traceback = 2 // include pc and sp in stack trace
		traceback1(g.sched.pc, g.sched.sp, g.sched.lr, g, 0)
		print("\n")

		throw("morestack on g0")
	})
}

//go:nosplit
//go:nowritebarrierrec
func badmorestackgsignal() {
	writeErrStr("fatal: morestack on gsignal\n")
}

//go:nosplit
func badctxt() {
	throw("ctxt != 0")
}

// gcrash is a fake g that can be used when crashing due to bad
// stack conditions.
var gcrash g

var crashingG atomic.Pointer[g]

// Switch to crashstack and call fn, with special handling of
// concurrent and recursive cases.
//
// Nosplit as it is called in a bad stack condition (we know
// morestack would fail).
//
//go:nosplit
//go:nowritebarrierrec
func switchToCrashStack(fn func()) {
	me := getg()
	if crashingG.CompareAndSwapNoWB(nil, me) {
		switchToCrashStack0(fn) // should never return
		abort()
	}
	if crashingG.Load() == me {
		// recursive crashing. too bad.
		writeErrStr("fatal: recursive switchToCrashStack\n")
		abort()
	}
	// Another g is crashing. Give it some time, hopefully it will finish traceback.
	usleep_no_g(100)
	writeErrStr("fatal: concurrent switchToCrashStack\n")
	abort()
}

// Disable crash stack on Windows for now. Apparently, throwing an exception
// on a non-system-allocated crash stack causes EXCEPTION_STACK_OVERFLOW and
// hangs the process (see issue 63938).
const crashStackImplemented = GOOS != "windows"

//go:noescape
func switchToCrashStack0(fn func()) // in assembly

func lockedOSThread() bool {
	gp := getg()
	return gp.lockedm != 0 && gp.m.lockedg != 0
}

var (
	// allgs contains all Gs ever created (including dead Gs), and thus
	// never shrinks.
	//
	// Access via the slice is protected by allglock or stop-the-world.
	// Readers that cannot take the lock may (carefully!) use the atomic
	// variables below.
	allglock mutex
	allgs    []*g

	// allglen and allgptr are atomic variables that contain len(allgs) and
	// &allgs[0] respectively. Proper ordering depends on totally-ordered
	// loads and stores. Writes are protected by allglock.
	//
	// allgptr is updated before allglen. Readers should read allglen
	// before allgptr to ensure that allglen is always <= len(allgptr). New
	// Gs appended during the race can be missed. For a consistent view of
	// all Gs, allglock must be held.
	//
	// allgptr copies should always be stored as a concrete type or
	// unsafe.Pointer, not uintptr, to ensure that GC can still reach it
	// even if it points to a stale array.
	allglen uintptr
	allgptr **g
)

func allgadd(gp *g) {
	if readgstatus(gp) == _Gidle {
		throw("allgadd: bad status Gidle")
	}

	lock(&allglock)
	allgs = append(allgs, gp)
	if &allgs[0] != allgptr {
		atomicstorep(unsafe.Pointer(&allgptr), unsafe.Pointer(&allgs[0]))
	}
	atomic.Storeuintptr(&allglen, uintptr(len(allgs)))
	unlock(&allglock)
}

// allGsSnapshot returns a snapshot of the slice of all Gs.
//
// The world must be stopped or allglock must be held.
func allGsSnapshot() []*g {
	assertWorldStoppedOrLockHeld(&allglock)

	// Because the world is stopped or allglock is held, allgadd
	// cannot happen concurrently with this. allgs grows
	// monotonically and existing entries never change, so we can
	// simply return a copy of the slice header. For added safety,
	// we trim everything past len because that can still change.
	return allgs[:len(allgs):len(allgs)]
}

// atomicAllG returns &allgs[0] and len(allgs) for use with atomicAllGIndex.
func atomicAllG() (**g, uintptr) {
	length := atomic.Loaduintptr(&allglen)
	ptr := (**g)(atomic.Loadp(unsafe.Pointer(&allgptr)))
	return ptr, length
}

// atomicAllGIndex returns ptr[i] with the allgptr returned from atomicAllG.
func atomicAllGIndex(ptr **g, i uintptr) *g {
	return *(**g)(add(unsafe.Pointer(ptr), i*goarch.PtrSize))
}

// forEachG calls fn on every G from allgs.
//
// forEachG takes a lock to exclude concurrent addition of new Gs.
func forEachG(fn func(gp *g)) {
	lock(&allglock)
	for _, gp := range allgs {
		fn(gp)
	}
	unlock(&allglock)
}

// forEachGRace calls fn on every G from allgs.
//
// forEachGRace avoids locking, but does not exclude addition of new Gs during
// execution, which may be missed.
func forEachGRace(fn func(gp *g)) {
	ptr, length := atomicAllG()
	for i := uintptr(0); i < length; i++ {
		gp := atomicAllGIndex(ptr, i)
		fn(gp)
	}
	return
}

const (
	// Number of goroutine ids to grab from sched.goidgen to local per-P cache at once.
	// 16 seems to provide enough amortization, but other than that it's mostly arbitrary number.
	_GoidCacheBatch = 16
)

// cpuinit sets up CPU feature flags and calls internal/cpu.Initialize. env should be the complete
// value of the GODEBUG environment variable.
func cpuinit(env string) {
	switch GOOS {
	case "aix", "darwin", "ios", "dragonfly", "freebsd", "netbsd", "openbsd", "illumos", "solaris", "linux":
		cpu.DebugOptions = true
	}
	cpu.Initialize(env)

	// Support cpu feature variables are used in code generated by the compiler
	// to guard execution of instructions that can not be assumed to be always supported.
	switch GOARCH {
	case "386", "amd64":
		x86HasPOPCNT = cpu.X86.HasPOPCNT
		x86HasSSE41 = cpu.X86.HasSSE41
		x86HasFMA = cpu.X86.HasFMA

	case "arm":
		armHasVFPv4 = cpu.ARM.HasVFPv4

	case "arm64":
		arm64HasATOMICS = cpu.ARM64.HasATOMICS

	case "loong64":
		loong64HasLAMCAS = cpu.Loong64.HasLAMCAS
		loong64HasLAM_BH = cpu.Loong64.HasLAM_BH
		loong64HasLSX = cpu.Loong64.HasLSX
	}
}

// getGodebugEarly extracts the environment variable GODEBUG from the environment on
// Unix-like operating systems and returns it. This function exists to extract GODEBUG
// early before much of the runtime is initialized.
func getGodebugEarly() string {
	const prefix = "GODEBUG="
	var env string
	switch GOOS {
	case "aix", "darwin", "ios", "dragonfly", "freebsd", "netbsd", "openbsd", "illumos", "solaris", "linux":
		// Similar to goenv_unix but extracts the environment value for
		// GODEBUG directly.
		// TODO(moehrmann): remove when general goenvs() can be called before cpuinit()
		n := int32(0)
		for argv_index(argv, argc+1+n) != nil {
			n++
		}

		for i := int32(0); i < n; i++ {
			p := argv_index(argv, argc+1+i)
			s := unsafe.String(p, findnull(p))

			if stringslite.HasPrefix(s, prefix) {
				env = gostring(p)[len(prefix):]
				break
			}
		}
	}
	return env
}

// The bootstrap sequence is:
//
//	call osinit
//	call schedinit
//	make & queue new G
//	call runtime·mstart
//
// The new G calls runtime·main.
func schedinit() {
	lockInit(&sched.lock, lockRankSched)
	lockInit(&sched.sysmonlock, lockRankSysmon)
	lockInit(&sched.deferlock, lockRankDefer)
	lockInit(&sched.sudoglock, lockRankSudog)
	lockInit(&deadlock, lockRankDeadlock)
	lockInit(&paniclk, lockRankPanic)
	lockInit(&allglock, lockRankAllg)
	lockInit(&allpLock, lockRankAllp)
	lockInit(&reflectOffs.lock, lockRankReflectOffs)
	lockInit(&finlock, lockRankFin)
	lockInit(&cpuprof.lock, lockRankCpuprof)
	allocmLock.init(lockRankAllocmR, lockRankAllocmRInternal, lockRankAllocmW)
	execLock.init(lockRankExecR, lockRankExecRInternal, lockRankExecW)
	traceLockInit()
	// Enforce that this lock is always a leaf lock.
	// All of this lock's critical sections should be
	// extremely short.
	lockInit(&memstats.heapStats.noPLock, lockRankLeafRank)

	lockVerifyMSize()

	// raceinit must be the first call to race detector.
	// In particular, it must be done before mallocinit below calls racemapshadow.
	gp := getg()
	if raceenabled {
		gp.racectx, raceprocctx0 = raceinit()
	}

	sched.maxmcount = 10000
	crashFD.Store(^uintptr(0))

	// The world starts stopped.
	worldStopped()

	ticks.init() // run as early as possible
	moduledataverify()
	stackinit()
	mallocinit()
	godebug := getGodebugEarly()
	cpuinit(godebug) // must run before alginit
	randinit()       // must run before alginit, mcommoninit
	alginit()        // maps, hash, rand must not be used before this call
	mcommoninit(gp.m, -1)
	modulesinit()   // provides activeModules
	typelinksinit() // uses maps, activeModules
	itabsinit()     // uses activeModules
	stkobjinit()    // must run before GC starts

	sigsave(&gp.m.sigmask)
	initSigmask = gp.m.sigmask

	goargs()
	goenvs()
	secure()
	checkfds()
	parsedebugvars()
	gcinit()

	// Allocate stack space that can be used when crashing due to bad stack
	// conditions, e.g. morestack on g0.
	gcrash.stack = stackalloc(16384)
	gcrash.stackguard0 = gcrash.stack.lo + 1000
	gcrash.stackguard1 = gcrash.stack.lo + 1000

	// if disableMemoryProfiling is set, update MemProfileRate to 0 to turn off memprofile.
	// Note: parsedebugvars may update MemProfileRate, but when disableMemoryProfiling is
	// set to true by the linker, it means that nothing is consuming the profile, it is
	// safe to set MemProfileRate to 0.
	if disableMemoryProfiling {
		MemProfileRate = 0
	}

	// mcommoninit runs before parsedebugvars, so init profstacks again.
	mProfStackInit(gp.m)

	lock(&sched.lock)
	sched.lastpoll.Store(nanotime())
	procs := ncpu
	if n, ok := atoi32(gogetenv("GOMAXPROCS")); ok && n > 0 {
		procs = n
	}
	if procresize(procs) != nil {
		throw("unknown runnable goroutine during bootstrap")
	}
	unlock(&sched.lock)

	// World is effectively started now, as P's can run.
	worldStarted()

	if buildVersion == "" {
		// Condition should never trigger. This code just serves
		// to ensure runtime·buildVersion is kept in the resulting binary.
		buildVersion = "unknown"
	}
	if len(modinfo) == 1 {
		// Condition should never trigger. This code just serves
		// to ensure runtime·modinfo is kept in the resulting binary.
		modinfo = ""
	}
}

func dumpgstatus(gp *g) {
	thisg := getg()
	print("runtime:   gp: gp=", gp, ", goid=", gp.goid, ", gp->atomicstatus=", readgstatus(gp), "\n")
	print("runtime: getg:  g=", thisg, ", goid=", thisg.goid, ",  g->atomicstatus=", readgstatus(thisg), "\n")
}

// sched.lock must be held.
func checkmcount() {
	assertLockHeld(&sched.lock)

	// Exclude extra M's, which are used for cgocallback from threads
	// created in C.
	//
	// The purpose of the SetMaxThreads limit is to avoid accidental fork
	// bomb from something like millions of goroutines blocking on system
	// calls, causing the runtime to create millions of threads. By
	// definition, this isn't a problem for threads created in C, so we
	// exclude them from the limit. See https://go.dev/issue/60004.
	count := mcount() - int32(extraMInUse.Load()) - int32(extraMLength.Load())
	if count > sched.maxmcount {
		print("runtime: program exceeds ", sched.maxmcount, "-thread limit\n")
		throw("thread exhaustion")
	}
}

// mReserveID returns the next ID to use for a new m. This new m is immediately
// considered 'running' by checkdead.
//
// sched.lock must be held.
func mReserveID() int64 {
	assertLockHeld(&sched.lock)

	if sched.mnext+1 < sched.mnext {
		throw("runtime: thread ID overflow")
	}
	id := sched.mnext
	sched.mnext++
	checkmcount()
	return id
}

// Pre-allocated ID may be passed as 'id', or omitted by passing -1.
func mcommoninit(mp *m, id int64) {
	gp := getg()

	// g0 stack won't make sense for user (and is not necessary unwindable).
	if gp != gp.m.g0 {
		callers(1, mp.createstack[:])
	}

	lock(&sched.lock)

	if id >= 0 {
		mp.id = id
	} else {
		mp.id = mReserveID()
	}

	mrandinit(mp)

	mpreinit(mp)
	if mp.gsignal != nil {
		mp.gsignal.stackguard1 = mp.gsignal.stack.lo + stackGuard
	}

	// Add to allm so garbage collector doesn't free g->m
	// when it is just in a register or thread-local storage.
	mp.alllink = allm

	// NumCgoCall() and others iterate over allm w/o schedlock,
	// so we need to publish it safely.
	atomicstorep(unsafe.Pointer(&allm), unsafe.Pointer(mp))
	unlock(&sched.lock)

	// Allocate memory to hold a cgo traceback if the cgo call crashes.
	if iscgo || GOOS == "solaris" || GOOS == "illumos" || GOOS == "windows" {
		mp.cgoCallers = new(cgoCallers)
	}
	mProfStackInit(mp)
}

// mProfStackInit is used to eagerly initialize stack trace buffers for
// profiling. Lazy allocation would have to deal with reentrancy issues in
// malloc and runtime locks for mLockProfile.
// TODO(mknyszek): Implement lazy allocation if this becomes a problem.
func mProfStackInit(mp *m) {
	if debug.profstackdepth == 0 {
		// debug.profstack is set to 0 by the user, or we're being called from
		// schedinit before parsedebugvars.
		return
	}
	mp.profStack = makeProfStackFP()
	mp.mLockProfile.stack = makeProfStackFP()
}

// makeProfStackFP creates a buffer large enough to hold a maximum-sized stack
// trace as well as any additional frames needed for frame pointer unwinding
// with delayed inline expansion.
func makeProfStackFP() []uintptr {
	// The "1" term is to account for the first stack entry being
	// taken up by a "skip" sentinel value for profilers which
	// defer inline frame expansion until the profile is reported.
	// The "maxSkip" term is for frame pointer unwinding, where we
	// want to end up with debug.profstackdebth frames but will discard
	// some "physical" frames to account for skipping.
	return make([]uintptr, 1+maxSkip+debug.profstackdepth)
}

// makeProfStack returns a buffer large enough to hold a maximum-sized stack
// trace.
func makeProfStack() []uintptr { return make([]uintptr, debug.profstackdepth) }

//go:linkname pprof_makeProfStack
func pprof_makeProfStack() []uintptr { return makeProfStack() }

func (mp *m) becomeSpinning() {
	mp.spinning = true
	sched.nmspinning.Add(1)
	sched.needspinning.Store(0)
}

func (mp *m) hasCgoOnStack() bool {
	return mp.ncgo > 0 || mp.isextra
}

const (
	// osHasLowResTimer indicates that the platform's internal timer system has a low resolution,
	// typically on the order of 1 ms or more.
	osHasLowResTimer = GOOS == "windows" || GOOS == "openbsd" || GOOS == "netbsd"

	// osHasLowResClockInt is osHasLowResClock but in integer form, so it can be used to create
	// constants conditionally.
	osHasLowResClockInt = goos.IsWindows

	// osHasLowResClock indicates that timestamps produced by nanotime on the platform have a
	// low resolution, typically on the order of 1 ms or more.
	osHasLowResClock = osHasLowResClockInt > 0
)

// Mark gp ready to run.
func ready(gp *g, traceskip int, next bool) {
	status := readgstatus(gp)

	// Mark runnable.
	mp := acquirem() // disable preemption because it can be holding p in a local var
	if status&^_Gscan != _Gwaiting {
		dumpgstatus(gp)
		throw("bad g->status in ready")
	}

	// status is Gwaiting or Gscanwaiting, make Grunnable and put on runq
	trace := traceAcquire()
	casgstatus(gp, _Gwaiting, _Grunnable)
	if trace.ok() {
		trace.GoUnpark(gp, traceskip)
		traceRelease(trace)
	}
	runqput(mp.p.ptr(), gp, next)
	wakep()
	releasem
```