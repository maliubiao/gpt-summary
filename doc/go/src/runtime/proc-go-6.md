Response:
Let's break down the thought process for analyzing this Go code snippet and generating the response.

**1. Understanding the Request:**

The core request is to analyze a specific section of `runtime/proc.go` and explain its functionality, relate it to Go features, provide code examples, discuss potential pitfalls, and summarize its purpose within the larger context. The "part 7 of 7" indicates this is the final piece, hinting at the need for a comprehensive summary.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and structures. This helps to get a general idea of what it's doing. Keywords that jump out include:

* **`p` (processor), `g` (goroutine):**  This immediately suggests this code deals with Go's scheduling mechanisms.
* **`runq`, `runnext`:**  These are clearly related to runnable goroutine queues.
* **`atomic.Load`, `atomic.Store`, `atomic.Cas`:**  Indicates concurrency control and safe access to shared data.
* **`gQueue`, `gList`:** Data structures for managing goroutines.
* **`runqput`, `runqget`, `runqsteal`, `runqdrain`:** Functions for manipulating the run queues.
* **`setMaxThreads`, `procPin`, `procUnpin`:** Functions related to thread management and processor affinity.
* **`sync_runtime_canSpin`, `sync_runtime_doSpin`:**  Spinning logic for synchronization primitives.
* **`randomOrder`, `randomEnum`:**  Randomization for scheduling decisions (likely for testing/robustness).
* **`initTask`, `doInit`:** Initialization routines for packages.

**3. Grouping Functionality and Identifying Core Concepts:**

Based on the keywords, I start grouping related functions and identifying the underlying concepts:

* **Goroutine Run Queues:** `runqput`, `runqget`, `runqempty`, `runqsteal`, `runqdrain`, `gQueue`, `gList`. This is the central theme of this code block. It's about managing which goroutines are ready to run on a processor.
* **Processor Management:**  The `p` structure and functions like `newproc1` (from the beginning of the snippet, though not fully shown) hint at managing the lifecycle of processors.
* **Concurrency Control:** The atomic operations are crucial for ensuring thread-safe access to the run queues.
* **Work Stealing:** `runqsteal` explicitly deals with this concept, where a processor tries to take work from another's queue.
* **Randomization:**  The `randomizeScheduler` constant and related code indicate deliberate introduction of randomness for testing and revealing potential race conditions.
* **Initialization:** `initTask` and `doInit` are about running package initialization functions.
* **Thread Limits:** `setMaxThreads` directly relates to controlling the number of OS threads.
* **Processor Pinning:** `procPin` and `procUnpin` deal with associating goroutines/locks with specific processors.
* **Spinning:** The `sync_runtime_canSpin` and `sync_runtime_doSpin` functions are about short busy-waiting to avoid immediately blocking on mutexes.

**4. Relating to Go Features:**

Now, connect the identified concepts to higher-level Go features:

* **Goroutine Scheduling:** The entire run queue mechanism is the core of Go's lightweight concurrency model.
* **`go` keyword:**  The functions here are the low-level implementation of how a new goroutine created with `go` gets scheduled.
* **Concurrency Primitives (sync package):** The spinning logic is used internally by `sync.Mutex` to optimize performance in certain scenarios.
* **Package Initialization (`init()` functions):**  The `initTask` and `doInit` functions are the runtime support for executing `init()` functions in packages.
* **`runtime.GOMAXPROCS()`:** The `setMaxThreads` function is related to the `runtime.GOMAXPROCS()` function, which controls the number of concurrently executing OS threads.
* **Processor Affinity (less common):** While not a primary Go feature exposed directly to most users, `procPin` and `procUnpin` allow for finer-grained control over where goroutines execute.

**5. Crafting Examples:**

For each key feature, create simple, illustrative Go code examples. Focus on demonstrating the *effect* of the underlying mechanism without getting bogged down in complex details. For example:

* For run queues, show how multiple goroutines are created and conceptually placed on these queues.
* For work stealing, create a scenario where one goroutine might steal work from another.
* For initialization, show a basic `init()` function.

**6. Identifying Potential Pitfalls:**

Think about common mistakes developers might make that relate to these low-level details, even if they don't directly interact with these functions:

* **Assuming Deterministic Scheduling:** The `randomizeScheduler` and work-stealing mechanisms mean you can't rely on a specific execution order.
* **Over-reliance on Processor Pinning:**  Misusing `procPin` and `procUnpin` can lead to performance problems if not done carefully.
* **Misunderstanding `GOMAXPROCS`:** Developers sometimes misunderstand how `GOMAXPROCS` affects concurrency vs. parallelism.

**7. Summarizing the Functionality:**

Finally, synthesize the analysis into a concise summary that highlights the main responsibilities of this code block within the Go runtime. Emphasize its role in managing goroutines, scheduling, and overall concurrency.

**Self-Correction/Refinement during the process:**

* **Initial Overemphasis:**  I might initially focus too much on one specific function. The "part 7 of 7" instruction reminds me to look at the bigger picture.
* **Technical Jargon:** I need to ensure the explanation is understandable to a broader audience, not just runtime developers. Explain concepts like "atomic operations" briefly.
* **Code Example Clarity:** Make sure the code examples are easy to understand and directly relate to the concept being illustrated. Avoid unnecessary complexity.
* **Addressing All Parts of the Request:**  Double-check that I've addressed all the points in the prompt, including code examples, command-line arguments (if applicable), pitfalls, and the final summary. In this case, no specific command-line arguments were directly handled in the provided code, so that part of the analysis would reflect that.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive and informative response that addresses all aspects of the user's request.
这段 `go/src/runtime/proc.go` 代码是 Go 语言运行时系统 **处理器 (Processor, P)** 管理和 **可运行 Goroutine 队列 (Run Queue)** 实现的核心部分。它负责将待执行的 Goroutine 分配到操作系统线程上运行，是 Go 并发模型的重要组成部分。

以下是这段代码的主要功能：

**1. P 的创建和获取:**

* `acquirep()`:  尝试获取一个空闲的 P 或者创建一个新的 P。这是 Goroutine 能够被调度执行的前提。
* `releasep()`: 释放当前 G 占用的 P，通常在 G 进入休眠状态或者需要让出 CPU 时调用。

**2. 可运行 Goroutine 队列的管理:**

* **本地队列 (`pp.runq`):** 每个 P 都有一个本地的 Goroutine 队列，用于存放分配给该 P 运行的 Goroutine。
    * `runqempty(pp *p) bool`: 检查 P 的本地运行队列是否为空。
    * `runqput(pp *p, gp *g, next bool)`: 将 Goroutine `gp` 放入 P 的本地运行队列。`next` 参数决定是否将 `gp` 放在队列头部（`pp.runnext` 槽位）。
    * `runqputslow(pp *p, gp *g, h, t uint32) bool`: 当本地队列已满时，将部分 Goroutine 转移到全局队列。
    * `runqputbatch(pp *p, q *gQueue, qsize int)`: 将一批 Goroutine 从 `gQueue` 放入 P 的本地队列。
    * `runqget(pp *p) (gp *g, inheritTime bool)`: 从 P 的本地运行队列中获取一个待执行的 Goroutine。
    * `runqdrain(pp *p) (drainQ gQueue, n uint32)`: 将 P 的本地运行队列中的所有 Goroutine 移动到一个 `gQueue` 中。
    * `runqgrab(pp *p, batch *[256]guintptr, batchHead uint32, stealRunNextG bool) uint32`: 从 P 的本地队列抓取一部分 Goroutine 到 `batch` 中，用于 work stealing。
    * `runqsteal(pp, p2 *p, stealRunNextG bool) *g`: 从另一个 P (`p2`) 的本地队列中窃取 Goroutine 到当前 P (`pp`) 的本地队列。

* **全局队列 (`sched.runq`)**:  当本地队列满或需要跨 P 调度时使用。虽然这段代码没有直接操作全局队列，但 `runqputslow` 和 `runqputbatch` 会在必要时将 Goroutine 放入全局队列。

* **`pp.runnext`**:  每个 P 都有一个 `runnext` 槽位，用于存放即将运行的 Goroutine。这提供了一种优化，允许当前 Goroutine 立即调度另一个 Goroutine 而无需进入队列。

**3. Goroutine 队列的数据结构:**

* `gQueue`: 一个使用链表实现的双端队列，用于存放 Goroutine。
    * `empty() bool`: 检查队列是否为空。
    * `push(gp *g)`: 将 Goroutine 添加到队列头部。
    * `pushBack(gp *g)`: 将 Goroutine 添加到队列尾部。
    * `pushBackAll(q2 gQueue)`: 将另一个队列的所有 Goroutine 添加到当前队列尾部。
    * `pop() *g`: 从队列头部移除并返回一个 Goroutine。
    * `popList() gList`: 将队列中的所有 Goroutine 转换为一个 `gList`。

* `gList`: 一个使用链表实现的单向列表，用于存放 Goroutine。

**4. 调度相关的辅助功能:**

* `randomizeScheduler`: 一个常量，当启用 race detector 时为 true，用于在调度决策中引入随机性，以帮助检测潜在的竞态条件。
* `stealOrder`, `randomOrder`, `randomEnum`:  用于实现随机化的工作窃取顺序，确保 P 尝试从其他 P 窃取 Goroutine 时不会总是按照相同的顺序。
* `gcd(a, b uint32) uint32`:  计算最大公约数，用于 `randomOrder` 的计算。

**5. 线程管理和处理器绑定:**

* `setMaxThreads(in int) (out int)`:  设置 Go 程序可以使用的最大操作系统线程数 (M 的最大数量)。这与 `runtime.GOMAXPROCS()` 函数相关联。
* `procPin() int`:  将当前 Goroutine 绑定到当前的 P 上，并返回 P 的 ID。这会阻止当前 Goroutine 在绑定期间被迁移到其他 P。
* `procUnpin()`:  解除当前 Goroutine 与 P 的绑定。
* `sync_runtime_procPin()`, `sync_runtime_procUnpin()`, `sync_atomic_runtime_procPin()`, `sync_atomic_runtime_procUnpin()`:  提供给 `sync` 和 `sync/atomic` 包使用的内部链接函数，用于实现基于 P 绑定的自旋锁优化。

**6. 自旋锁优化:**

* `internal_sync_runtime_canSpin(i int) bool`:  判断当前 Goroutine 是否可以进行自旋等待，以避免立即进入阻塞状态。这是一种性能优化，用于减少上下文切换的开销。
* `internal_sync_runtime_doSpin()`:  执行自旋等待。
* `sync_runtime_canSpin(i int) bool`, `sync_runtime_doSpin()`:  提供给 `sync` 包使用的内部链接函数，用于实现自旋锁。

**7. 包初始化:**

* `initTask`: 表示一个包的初始化任务，包含需要执行的初始化函数。
* `doInit(ts []*initTask)`:  执行给定的包初始化任务。
* `doInit1(t *initTask)`:  执行单个包的初始化任务。

**推理出的 Go 语言功能实现:**

这段代码是 Go 语言 **调度器 (Scheduler)** 的核心实现之一，特别是关于 **本地运行队列 (Local Run Queue)** 和 **工作窃取 (Work Stealing)** 的部分。

**Go 代码示例 (演示 `runqput` 和 `runqget`):**

```go
package main

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

func myGoroutine(id int) {
	fmt.Println("Goroutine", id, "is running on P", runtime_procPin())
	runtime_procUnpin()
}

func main() {
	runtime.GOMAXPROCS(2) // 设置使用 2 个 P

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			myGoroutine(id)
		}(i)
	}

	wg.Wait()
}

//go:linkname runtime_procPin runtime.procPin
func runtime_procPin() int

//go:linkname runtime_procUnpin runtime.procUnpin
func runtime_procUnpin()
```

**假设的输入与输出:**

在这个例子中，我们创建了 5 个 Goroutine。由于 `GOMAXPROCS` 设置为 2，所以理论上会有两个 P 参与调度。`runqput` 会将这些 Goroutine 放入 P 的本地运行队列（或 `runnext` 槽位），而 `runqget` 会从这些队列中取出 Goroutine 来执行。

**可能的输出:** (输出顺序可能不同，因为调度是非确定的)

```
Goroutine 0 is running on P 0
Goroutine 1 is running on P 1
Goroutine 2 is running on P 0
Goroutine 3 is running on P 1
Goroutine 4 is running on P 0
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。但是，与它相关的 `runtime.GOMAXPROCS()` 函数可以通过设置环境变量 `GOMAXPROCS` 来影响。例如，在运行 Go 程序时，可以使用 `GOMAXPROCS=4 go run your_program.go` 来设置最大 P 数量为 4。

**使用者易犯错的点:**

这段代码是 Go 运行时的内部实现，普通 Go 开发者通常不会直接调用或操作这些函数。然而，理解其背后的原理对于避免一些常见的并发错误很有帮助。

一个潜在的误解是 **假设 Goroutine 会在创建它的 P 上立即运行**。实际上，Goroutine 会被放入 P 的运行队列，等待调度器选择执行。工作窃取机制也意味着 Goroutine 可能会被其他 P 执行。这对于理解为什么不能依赖特定的 Goroutine 执行顺序非常重要。

**归纳一下它的功能:**

这段 `go/src/runtime/proc.go` 的代码主要负责以下功能：

1. **管理 Go 语言的处理器 (P)：**  包括创建、获取和释放 P，它们是 Goroutine 执行的上下文。
2. **管理每个 P 的本地可运行 Goroutine 队列：**  提供添加、获取、检查队列状态以及批量操作 Goroutine 的功能。
3. **实现工作窃取机制：**  允许空闲的 P 从其他 P 的本地队列中窃取 Goroutine 来执行，以提高 CPU 利用率和调度效率。
4. **提供处理器绑定的能力：** 允许将 Goroutine 绑定到特定的 P 上，这在某些特定场景下可以用于性能优化。
5. **支持自旋锁优化：**  为 `sync` 包提供内部支持，通过短时间的自旋等待来避免不必要的阻塞和上下文切换。
6. **执行包的初始化任务：**  负责运行每个包的 `init()` 函数。

总而言之，这段代码是 Go 运行时调度器的核心组件，负责 Goroutine 的调度和执行，是 Go 并发模型高效运行的关键。它通过精巧的队列管理、原子操作和工作窃取等机制，实现了高效的并发执行。

Prompt: 
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共7部分，请归纳一下它的功能

"""

	return pp, now
}

// runqempty reports whether pp has no Gs on its local run queue.
// It never returns true spuriously.
func runqempty(pp *p) bool {
	// Defend against a race where 1) pp has G1 in runqnext but runqhead == runqtail,
	// 2) runqput on pp kicks G1 to the runq, 3) runqget on pp empties runqnext.
	// Simply observing that runqhead == runqtail and then observing that runqnext == nil
	// does not mean the queue is empty.
	for {
		head := atomic.Load(&pp.runqhead)
		tail := atomic.Load(&pp.runqtail)
		runnext := atomic.Loaduintptr((*uintptr)(unsafe.Pointer(&pp.runnext)))
		if tail == atomic.Load(&pp.runqtail) {
			return head == tail && runnext == 0
		}
	}
}

// To shake out latent assumptions about scheduling order,
// we introduce some randomness into scheduling decisions
// when running with the race detector.
// The need for this was made obvious by changing the
// (deterministic) scheduling order in Go 1.5 and breaking
// many poorly-written tests.
// With the randomness here, as long as the tests pass
// consistently with -race, they shouldn't have latent scheduling
// assumptions.
const randomizeScheduler = raceenabled

// runqput tries to put g on the local runnable queue.
// If next is false, runqput adds g to the tail of the runnable queue.
// If next is true, runqput puts g in the pp.runnext slot.
// If the run queue is full, runnext puts g on the global queue.
// Executed only by the owner P.
func runqput(pp *p, gp *g, next bool) {
	if !haveSysmon && next {
		// A runnext goroutine shares the same time slice as the
		// current goroutine (inheritTime from runqget). To prevent a
		// ping-pong pair of goroutines from starving all others, we
		// depend on sysmon to preempt "long-running goroutines". That
		// is, any set of goroutines sharing the same time slice.
		//
		// If there is no sysmon, we must avoid runnext entirely or
		// risk starvation.
		next = false
	}
	if randomizeScheduler && next && randn(2) == 0 {
		next = false
	}

	if next {
	retryNext:
		oldnext := pp.runnext
		if !pp.runnext.cas(oldnext, guintptr(unsafe.Pointer(gp))) {
			goto retryNext
		}
		if oldnext == 0 {
			return
		}
		// Kick the old runnext out to the regular run queue.
		gp = oldnext.ptr()
	}

retry:
	h := atomic.LoadAcq(&pp.runqhead) // load-acquire, synchronize with consumers
	t := pp.runqtail
	if t-h < uint32(len(pp.runq)) {
		pp.runq[t%uint32(len(pp.runq))].set(gp)
		atomic.StoreRel(&pp.runqtail, t+1) // store-release, makes the item available for consumption
		return
	}
	if runqputslow(pp, gp, h, t) {
		return
	}
	// the queue is not full, now the put above must succeed
	goto retry
}

// Put g and a batch of work from local runnable queue on global queue.
// Executed only by the owner P.
func runqputslow(pp *p, gp *g, h, t uint32) bool {
	var batch [len(pp.runq)/2 + 1]*g

	// First, grab a batch from local queue.
	n := t - h
	n = n / 2
	if n != uint32(len(pp.runq)/2) {
		throw("runqputslow: queue is not full")
	}
	for i := uint32(0); i < n; i++ {
		batch[i] = pp.runq[(h+i)%uint32(len(pp.runq))].ptr()
	}
	if !atomic.CasRel(&pp.runqhead, h, h+n) { // cas-release, commits consume
		return false
	}
	batch[n] = gp

	if randomizeScheduler {
		for i := uint32(1); i <= n; i++ {
			j := cheaprandn(i + 1)
			batch[i], batch[j] = batch[j], batch[i]
		}
	}

	// Link the goroutines.
	for i := uint32(0); i < n; i++ {
		batch[i].schedlink.set(batch[i+1])
	}
	var q gQueue
	q.head.set(batch[0])
	q.tail.set(batch[n])

	// Now put the batch on global queue.
	lock(&sched.lock)
	globrunqputbatch(&q, int32(n+1))
	unlock(&sched.lock)
	return true
}

// runqputbatch tries to put all the G's on q on the local runnable queue.
// If the queue is full, they are put on the global queue; in that case
// this will temporarily acquire the scheduler lock.
// Executed only by the owner P.
func runqputbatch(pp *p, q *gQueue, qsize int) {
	h := atomic.LoadAcq(&pp.runqhead)
	t := pp.runqtail
	n := uint32(0)
	for !q.empty() && t-h < uint32(len(pp.runq)) {
		gp := q.pop()
		pp.runq[t%uint32(len(pp.runq))].set(gp)
		t++
		n++
	}
	qsize -= int(n)

	if randomizeScheduler {
		off := func(o uint32) uint32 {
			return (pp.runqtail + o) % uint32(len(pp.runq))
		}
		for i := uint32(1); i < n; i++ {
			j := cheaprandn(i + 1)
			pp.runq[off(i)], pp.runq[off(j)] = pp.runq[off(j)], pp.runq[off(i)]
		}
	}

	atomic.StoreRel(&pp.runqtail, t)
	if !q.empty() {
		lock(&sched.lock)
		globrunqputbatch(q, int32(qsize))
		unlock(&sched.lock)
	}
}

// Get g from local runnable queue.
// If inheritTime is true, gp should inherit the remaining time in the
// current time slice. Otherwise, it should start a new time slice.
// Executed only by the owner P.
func runqget(pp *p) (gp *g, inheritTime bool) {
	// If there's a runnext, it's the next G to run.
	next := pp.runnext
	// If the runnext is non-0 and the CAS fails, it could only have been stolen by another P,
	// because other Ps can race to set runnext to 0, but only the current P can set it to non-0.
	// Hence, there's no need to retry this CAS if it fails.
	if next != 0 && pp.runnext.cas(next, 0) {
		return next.ptr(), true
	}

	for {
		h := atomic.LoadAcq(&pp.runqhead) // load-acquire, synchronize with other consumers
		t := pp.runqtail
		if t == h {
			return nil, false
		}
		gp := pp.runq[h%uint32(len(pp.runq))].ptr()
		if atomic.CasRel(&pp.runqhead, h, h+1) { // cas-release, commits consume
			return gp, false
		}
	}
}

// runqdrain drains the local runnable queue of pp and returns all goroutines in it.
// Executed only by the owner P.
func runqdrain(pp *p) (drainQ gQueue, n uint32) {
	oldNext := pp.runnext
	if oldNext != 0 && pp.runnext.cas(oldNext, 0) {
		drainQ.pushBack(oldNext.ptr())
		n++
	}

retry:
	h := atomic.LoadAcq(&pp.runqhead) // load-acquire, synchronize with other consumers
	t := pp.runqtail
	qn := t - h
	if qn == 0 {
		return
	}
	if qn > uint32(len(pp.runq)) { // read inconsistent h and t
		goto retry
	}

	if !atomic.CasRel(&pp.runqhead, h, h+qn) { // cas-release, commits consume
		goto retry
	}

	// We've inverted the order in which it gets G's from the local P's runnable queue
	// and then advances the head pointer because we don't want to mess up the statuses of G's
	// while runqdrain() and runqsteal() are running in parallel.
	// Thus we should advance the head pointer before draining the local P into a gQueue,
	// so that we can update any gp.schedlink only after we take the full ownership of G,
	// meanwhile, other P's can't access to all G's in local P's runnable queue and steal them.
	// See https://groups.google.com/g/golang-dev/c/0pTKxEKhHSc/m/6Q85QjdVBQAJ for more details.
	for i := uint32(0); i < qn; i++ {
		gp := pp.runq[(h+i)%uint32(len(pp.runq))].ptr()
		drainQ.pushBack(gp)
		n++
	}
	return
}

// Grabs a batch of goroutines from pp's runnable queue into batch.
// Batch is a ring buffer starting at batchHead.
// Returns number of grabbed goroutines.
// Can be executed by any P.
func runqgrab(pp *p, batch *[256]guintptr, batchHead uint32, stealRunNextG bool) uint32 {
	for {
		h := atomic.LoadAcq(&pp.runqhead) // load-acquire, synchronize with other consumers
		t := atomic.LoadAcq(&pp.runqtail) // load-acquire, synchronize with the producer
		n := t - h
		n = n - n/2
		if n == 0 {
			if stealRunNextG {
				// Try to steal from pp.runnext.
				if next := pp.runnext; next != 0 {
					if pp.status == _Prunning {
						// Sleep to ensure that pp isn't about to run the g
						// we are about to steal.
						// The important use case here is when the g running
						// on pp ready()s another g and then almost
						// immediately blocks. Instead of stealing runnext
						// in this window, back off to give pp a chance to
						// schedule runnext. This will avoid thrashing gs
						// between different Ps.
						// A sync chan send/recv takes ~50ns as of time of
						// writing, so 3us gives ~50x overshoot.
						if !osHasLowResTimer {
							usleep(3)
						} else {
							// On some platforms system timer granularity is
							// 1-15ms, which is way too much for this
							// optimization. So just yield.
							osyield()
						}
					}
					if !pp.runnext.cas(next, 0) {
						continue
					}
					batch[batchHead%uint32(len(batch))] = next
					return 1
				}
			}
			return 0
		}
		if n > uint32(len(pp.runq)/2) { // read inconsistent h and t
			continue
		}
		for i := uint32(0); i < n; i++ {
			g := pp.runq[(h+i)%uint32(len(pp.runq))]
			batch[(batchHead+i)%uint32(len(batch))] = g
		}
		if atomic.CasRel(&pp.runqhead, h, h+n) { // cas-release, commits consume
			return n
		}
	}
}

// Steal half of elements from local runnable queue of p2
// and put onto local runnable queue of p.
// Returns one of the stolen elements (or nil if failed).
func runqsteal(pp, p2 *p, stealRunNextG bool) *g {
	t := pp.runqtail
	n := runqgrab(p2, &pp.runq, t, stealRunNextG)
	if n == 0 {
		return nil
	}
	n--
	gp := pp.runq[(t+n)%uint32(len(pp.runq))].ptr()
	if n == 0 {
		return gp
	}
	h := atomic.LoadAcq(&pp.runqhead) // load-acquire, synchronize with consumers
	if t-h+n >= uint32(len(pp.runq)) {
		throw("runqsteal: runq overflow")
	}
	atomic.StoreRel(&pp.runqtail, t+n) // store-release, makes the item available for consumption
	return gp
}

// A gQueue is a dequeue of Gs linked through g.schedlink. A G can only
// be on one gQueue or gList at a time.
type gQueue struct {
	head guintptr
	tail guintptr
}

// empty reports whether q is empty.
func (q *gQueue) empty() bool {
	return q.head == 0
}

// push adds gp to the head of q.
func (q *gQueue) push(gp *g) {
	gp.schedlink = q.head
	q.head.set(gp)
	if q.tail == 0 {
		q.tail.set(gp)
	}
}

// pushBack adds gp to the tail of q.
func (q *gQueue) pushBack(gp *g) {
	gp.schedlink = 0
	if q.tail != 0 {
		q.tail.ptr().schedlink.set(gp)
	} else {
		q.head.set(gp)
	}
	q.tail.set(gp)
}

// pushBackAll adds all Gs in q2 to the tail of q. After this q2 must
// not be used.
func (q *gQueue) pushBackAll(q2 gQueue) {
	if q2.tail == 0 {
		return
	}
	q2.tail.ptr().schedlink = 0
	if q.tail != 0 {
		q.tail.ptr().schedlink = q2.head
	} else {
		q.head = q2.head
	}
	q.tail = q2.tail
}

// pop removes and returns the head of queue q. It returns nil if
// q is empty.
func (q *gQueue) pop() *g {
	gp := q.head.ptr()
	if gp != nil {
		q.head = gp.schedlink
		if q.head == 0 {
			q.tail = 0
		}
	}
	return gp
}

// popList takes all Gs in q and returns them as a gList.
func (q *gQueue) popList() gList {
	stack := gList{q.head}
	*q = gQueue{}
	return stack
}

// A gList is a list of Gs linked through g.schedlink. A G can only be
// on one gQueue or gList at a time.
type gList struct {
	head guintptr
}

// empty reports whether l is empty.
func (l *gList) empty() bool {
	return l.head == 0
}

// push adds gp to the head of l.
func (l *gList) push(gp *g) {
	gp.schedlink = l.head
	l.head.set(gp)
}

// pushAll prepends all Gs in q to l.
func (l *gList) pushAll(q gQueue) {
	if !q.empty() {
		q.tail.ptr().schedlink = l.head
		l.head = q.head
	}
}

// pop removes and returns the head of l. If l is empty, it returns nil.
func (l *gList) pop() *g {
	gp := l.head.ptr()
	if gp != nil {
		l.head = gp.schedlink
	}
	return gp
}

//go:linkname setMaxThreads runtime/debug.setMaxThreads
func setMaxThreads(in int) (out int) {
	lock(&sched.lock)
	out = int(sched.maxmcount)
	if in > 0x7fffffff { // MaxInt32
		sched.maxmcount = 0x7fffffff
	} else {
		sched.maxmcount = int32(in)
	}
	checkmcount()
	unlock(&sched.lock)
	return
}

// procPin should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/gopkg
//   - github.com/choleraehyq/pid
//   - github.com/songzhibin97/gkit
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname procPin
//go:nosplit
func procPin() int {
	gp := getg()
	mp := gp.m

	mp.locks++
	return int(mp.p.ptr().id)
}

// procUnpin should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/gopkg
//   - github.com/choleraehyq/pid
//   - github.com/songzhibin97/gkit
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname procUnpin
//go:nosplit
func procUnpin() {
	gp := getg()
	gp.m.locks--
}

//go:linkname sync_runtime_procPin sync.runtime_procPin
//go:nosplit
func sync_runtime_procPin() int {
	return procPin()
}

//go:linkname sync_runtime_procUnpin sync.runtime_procUnpin
//go:nosplit
func sync_runtime_procUnpin() {
	procUnpin()
}

//go:linkname sync_atomic_runtime_procPin sync/atomic.runtime_procPin
//go:nosplit
func sync_atomic_runtime_procPin() int {
	return procPin()
}

//go:linkname sync_atomic_runtime_procUnpin sync/atomic.runtime_procUnpin
//go:nosplit
func sync_atomic_runtime_procUnpin() {
	procUnpin()
}

// Active spinning for sync.Mutex.
//
//go:linkname internal_sync_runtime_canSpin internal/sync.runtime_canSpin
//go:nosplit
func internal_sync_runtime_canSpin(i int) bool {
	// sync.Mutex is cooperative, so we are conservative with spinning.
	// Spin only few times and only if running on a multicore machine and
	// GOMAXPROCS>1 and there is at least one other running P and local runq is empty.
	// As opposed to runtime mutex we don't do passive spinning here,
	// because there can be work on global runq or on other Ps.
	if i >= active_spin || ncpu <= 1 || gomaxprocs <= sched.npidle.Load()+sched.nmspinning.Load()+1 {
		return false
	}
	if p := getg().m.p.ptr(); !runqempty(p) {
		return false
	}
	return true
}

//go:linkname internal_sync_runtime_doSpin internal/sync.runtime_doSpin
//go:nosplit
func internal_sync_runtime_doSpin() {
	procyield(active_spin_cnt)
}

// Active spinning for sync.Mutex.
//
// sync_runtime_canSpin should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/livekit/protocol
//   - github.com/sagernet/gvisor
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname sync_runtime_canSpin sync.runtime_canSpin
//go:nosplit
func sync_runtime_canSpin(i int) bool {
	return internal_sync_runtime_canSpin(i)
}

// sync_runtime_doSpin should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/livekit/protocol
//   - github.com/sagernet/gvisor
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname sync_runtime_doSpin sync.runtime_doSpin
//go:nosplit
func sync_runtime_doSpin() {
	internal_sync_runtime_doSpin()
}

var stealOrder randomOrder

// randomOrder/randomEnum are helper types for randomized work stealing.
// They allow to enumerate all Ps in different pseudo-random orders without repetitions.
// The algorithm is based on the fact that if we have X such that X and GOMAXPROCS
// are coprime, then a sequences of (i + X) % GOMAXPROCS gives the required enumeration.
type randomOrder struct {
	count    uint32
	coprimes []uint32
}

type randomEnum struct {
	i     uint32
	count uint32
	pos   uint32
	inc   uint32
}

func (ord *randomOrder) reset(count uint32) {
	ord.count = count
	ord.coprimes = ord.coprimes[:0]
	for i := uint32(1); i <= count; i++ {
		if gcd(i, count) == 1 {
			ord.coprimes = append(ord.coprimes, i)
		}
	}
}

func (ord *randomOrder) start(i uint32) randomEnum {
	return randomEnum{
		count: ord.count,
		pos:   i % ord.count,
		inc:   ord.coprimes[i/ord.count%uint32(len(ord.coprimes))],
	}
}

func (enum *randomEnum) done() bool {
	return enum.i == enum.count
}

func (enum *randomEnum) next() {
	enum.i++
	enum.pos = (enum.pos + enum.inc) % enum.count
}

func (enum *randomEnum) position() uint32 {
	return enum.pos
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// An initTask represents the set of initializations that need to be done for a package.
// Keep in sync with ../../test/noinit.go:initTask
type initTask struct {
	state uint32 // 0 = uninitialized, 1 = in progress, 2 = done
	nfns  uint32
	// followed by nfns pcs, uintptr sized, one per init function to run
}

// inittrace stores statistics for init functions which are
// updated by malloc and newproc when active is true.
var inittrace tracestat

type tracestat struct {
	active bool   // init tracing activation status
	id     uint64 // init goroutine id
	allocs uint64 // heap allocations
	bytes  uint64 // heap allocated bytes
}

func doInit(ts []*initTask) {
	for _, t := range ts {
		doInit1(t)
	}
}

func doInit1(t *initTask) {
	switch t.state {
	case 2: // fully initialized
		return
	case 1: // initialization in progress
		throw("recursive call during initialization - linker skew")
	default: // not initialized yet
		t.state = 1 // initialization in progress

		var (
			start  int64
			before tracestat
		)

		if inittrace.active {
			start = nanotime()
			// Load stats non-atomically since tracinit is updated only by this init goroutine.
			before = inittrace
		}

		if t.nfns == 0 {
			// We should have pruned all of these in the linker.
			throw("inittask with no functions")
		}

		firstFunc := add(unsafe.Pointer(t), 8)
		for i := uint32(0); i < t.nfns; i++ {
			p := add(firstFunc, uintptr(i)*goarch.PtrSize)
			f := *(*func())(unsafe.Pointer(&p))
			f()
		}

		if inittrace.active {
			end := nanotime()
			// Load stats non-atomically since tracinit is updated only by this init goroutine.
			after := inittrace

			f := *(*func())(unsafe.Pointer(&firstFunc))
			pkg := funcpkgpath(findfunc(abi.FuncPCABIInternal(f)))

			var sbuf [24]byte
			print("init ", pkg, " @")
			print(string(fmtNSAsMS(sbuf[:], uint64(start-runtimeInitTime))), " ms, ")
			print(string(fmtNSAsMS(sbuf[:], uint64(end-start))), " ms clock, ")
			print(string(itoa(sbuf[:], after.bytes-before.bytes)), " bytes, ")
			print(string(itoa(sbuf[:], after.allocs-before.allocs)), " allocs")
			print("\n")
		}

		t.state = 2 // initialization done
	}
}

"""




```