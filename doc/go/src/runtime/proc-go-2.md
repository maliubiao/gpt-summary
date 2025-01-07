Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Recognition:**

*   Keywords like `safePoint`, `cgo`, `allocm`, `needm`, `dropm`, `startm`, `stopm`, `handoffp`, `wakep`, `stoplockedm`, `startlockedm` immediately jump out. These are strong indicators of the code's purpose.
*   Comments like "// When running with cgo..." and "// Allocate a new m unassociated with any thread." provide direct clues.
*   Variables like `sched`, `allp`, `freem`, `extraM`, `newmHandoff` hint at global state and management structures.

**2. Grouping by Functionality:**

Based on the keywords and comments, I started mentally grouping the functions:

*   **Safe Points:** `forEachP`, `runSafePointFn`. The names suggest a mechanism for executing code on all Ps, likely for synchronization or GC.
*   **M Management (General):** `allocm`. This seems to be the core function for creating new Ms.
*   **CGO Integration:** `needm`, `needAndBindM`, `newextram`, `oneNewExtraM`, `dropm`, `cgoBindM`. These are clearly related to handling calls between Go and C code.
*   **M Lifecycle and Scheduling:** `startm`, `stopm`, `mspinning`. These are fundamental to how Ms are started and stopped.
*   **P Handoff and Wakeup:** `handoffp`, `wakep`. These likely deal with moving work between Ps and waking up sleeping Ps.
*   **Locked Ms:** `stoplockedm`, `startlockedm`. These seem to handle a specific case where an M is tied to a G.
*   **Extra M Management:** `lockextra`, `unlockextra`, `getExtraM`, `putExtraM`, `addExtraM`. These functions manage the pool of Ms used for CGO.
*   **New M Handling (Deferred):** `newm`, `newm1`, `startTemplateThread`, `templateThread`. This suggests a way to create Ms in situations where it can't be done directly.

**3. Analyzing Individual Functions (Key Insights):**

For each function, I tried to understand:

*   **Purpose:** What problem does this function solve?  (e.g., `allocm` creates a new M, `needm` gets an M for a CGO call).
*   **Inputs and Outputs:** What data does it take and what does it return?
*   **Key Operations:** What are the main steps involved?  (e.g., locking, allocation, state changes, signaling).
*   **Relationship to Other Functions:** How does this function interact with other parts of the code?  (e.g., `needm` calls `getExtraM`, `startm` calls `newm`).
*   **Special Considerations:**  Are there any specific conditions or constraints? (e.g., `needm` is `nosplit`, `allocm` handles write barriers).

**4. Inferring Higher-Level Functionality:**

By connecting the individual function functionalities, I could infer the higher-level Go features being implemented:

*   **Goroutine Scheduling:** The functions related to starting, stopping, and handing off Ps are core to the Go scheduler.
*   **CGO (C Go Interaction):** The `needm`/`dropm` pattern is a classic way to manage resources when interacting with external code. The extra M pool is a specific optimization for this.
*   **Safe Points (for GC):** The `forEachP` and `runSafePointFn` strongly suggest a mechanism for synchronizing all processors for garbage collection or other global operations.
*   **Thread Management:** `allocm` and `newm` are fundamental to creating and managing OS threads for Go's concurrency model.

**5. Addressing Specific Questions (Mental Checklist):**

*   **List of Functions:** Simply iterate through the identified functions.
*   **Go Feature Implementation:**  Based on the analysis, I could link the code to goroutine scheduling, CGO, and safe points.
*   **Code Examples:** I thought about scenarios where these features would be used (e.g., calling a C function from Go, the Go runtime needing to stop the world for GC). Constructing concrete code examples required some imagination but was guided by the function names and purposes.
*   **Input/Output and Assumptions:** For the code examples, I considered basic inputs and what the expected outcome would be based on the function's supposed behavior.
*   **Command-line Arguments:**  I scanned the code for any direct processing of `os.Args` or flags but found none in this snippet. So, the answer was that it doesn't directly handle them.
*   **Common Mistakes:** I thought about common pitfalls, especially in CGO (memory management, thread safety) and concurrency (deadlocks, race conditions), and tried to relate them to potential misuse of the functions.
*   **Part Summary:**  This involved distilling the core functionalities identified into a concise summary.

**6. Iteration and Refinement:**

My initial analysis might not be perfectly accurate. I would mentally review the groupings and interpretations, looking for inconsistencies or missing pieces. For instance, understanding the purpose of the "template thread" required connecting it to the cases where directly creating a thread is unsafe.

**Example of Pre-computation/Pre-analysis for `needm`:**

*   **Keyword:** `needm`, `cgo`
*   **Comment:** "needm is called when a cgo callback happens on a thread without an m"
*   **Purpose:** Obtain an `m` structure for a CGO callback on a non-Go thread.
*   **Mechanism:** Steal an `m` from the `extraM` list using a spin-lock approach. Create a new `m` if the list is empty.
*   **Key Operations:** `sigsave`, `sigblock`, `getExtraM`, `setg`, `minit`, `asminit`.
*   **Implication:**  This is about bridging the gap between OS threads managed by C and Go's internal thread management.

By systematically going through these steps, I could arrive at a comprehensive understanding of the provided Go code snippet. The key is to combine direct observation of the code with knowledge of how the Go runtime generally works.
这段代码是 Go 运行时系统 `runtime` 包中 `proc.go` 文件的一部分，主要负责**管理和调度操作系统线程（M）**，特别是涉及到与 C 代码交互（CGO）时的线程管理，以及在安全点（safepoint）的协调。

以下是这段代码功能的详细列举和推理：

**1. 安全点（Safepoint）机制的支持：**

*   **`forEachP` 函数：**  遍历所有的 P（Processor，代表执行 Go 代码的上下文），并在每个 P 上执行一个给定的函数 `fn`。这是一个在需要全局同步的场景下非常有用的机制，例如垃圾回收的 STW (Stop The World) 阶段。
    *   代码中使用了 `sched.safePointFn` 来存储要执行的函数。
    *   `sched.safePointWait` 用于跟踪有多少 P 尚未执行该函数。
    *   `sched.safePointNote` 是一个信号量，用于等待所有 P 完成操作。
    *   `preemptall()` 被调用以确保所有 P 都进入安全点。
    *   **推理:** `forEachP` 是实现 Go 运行时安全点的核心部分，它允许在所有处理器上同步执行某些操作。

*   **`runSafePointFn` 函数：** 如果当前 P 有待执行的安全点函数，则执行它。
    *   使用原子操作 `atomic.Cas` 来避免多个线程同时执行同一个 P 的安全点函数。
    *   执行完成后会递减 `sched.safePointWait`，并在所有 P 完成时唤醒等待的线程。
    *   **推理:** `runSafePointFn` 是在每个 P 上实际执行安全点逻辑的函数。

**Go 代码示例（安全点）：**

假设我们需要在垃圾回收开始前，记录所有 Goroutine 的堆栈信息。

```go
package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

func recordStack(p *runtime.P) {
	// 模拟在 P 上执行的操作，例如记录堆栈信息
	fmt.Printf("记录 P %d 的堆栈信息\n", p.ID)
	time.Sleep(100 * time.Millisecond) // 模拟一些工作
}

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				fmt.Printf("Goroutine %d doing work %d\n", id, j)
				time.Sleep(50 * time.Millisecond)
			}
		}(i)
	}

	time.Sleep(500 * time.Millisecond) // 让 Goroutine 运行一段时间

	// 触发安全点执行 recordStack 函数
	runtime.LockOSThread()
	runtime_forEachP(recordStack)
	runtime.UnlockOSThread()

	fmt.Println("所有 P 的堆栈信息已记录")
	wg.Wait()
}

//go:linkname runtime_forEachP runtime.forEachP
func runtime_forEachP(fn func(*runtime.P))

```

**假设输入与输出：**

*   **输入：** 在 `main` 函数中调用 `runtime_forEachP(recordStack)`。
*   **输出：** 控制台会输出类似以下内容，表明 `recordStack` 函数在每个 P 上都被执行：
    ```
    Goroutine 0 doing work 0
    Goroutine 1 doing work 0
    Goroutine 2 doing work 0
    Goroutine 3 doing work 0
    Goroutine 4 doing work 0
    ... (其他 Goroutine 的输出)
    记录 P 0 的堆栈信息
    记录 P 1 的堆栈信息
    记录 P 2 的堆栈信息
    记录 P 3 的堆栈信息
    记录 P 4 的堆栈信息
    所有 P 的堆栈信息已记录
    ... (Goroutine 完成后的输出)
    ```

**2. 与 CGO 的集成：**

*   **`allocm` 函数：** 分配一个新的 M（操作系统线程），但它最初不与任何线程关联。
    *   可以指定一个预先分配的 M ID。
    *   处理空闲 M 列表 `sched.freem`，尝试复用空闲的 M 和栈。
    *   根据是否启用 CGO 或操作系统类型，决定如何分配 g0 栈（用于运行调度器代码）。
    *   **推理:** `allocm` 是创建新的操作系统线程结构的关键函数。

*   **`needm` 函数：** 当一个由 C 代码启动的线程回调 Go 代码时，并且该线程没有关联的 M 时被调用。
    *   尝试从 `extraM` 列表中“偷取”一个可用的 M。这个列表维护了预先创建的额外 M，用于处理 CGO 回调。
    *   使用原子操作模拟锁来保护 `extraM` 列表。
    *   如果 `extraM` 列表为空，则标记需要创建新的额外 M。
    *   初始化 M 和 G（Goroutine）以供 Go 代码使用。
    *   **推理:** `needm` 实现了在 CGO 回调场景下，为 C 线程提供运行 Go 代码所需上下文的关键机制。

*   **`needAndBindM` 函数：**  调用 `needm` 获取 M，并尝试将该 M 绑定到当前的 C 线程。绑定是通过 `cgoBindM` 实现的，它利用 pthread 键（thread-specific data）在线程退出时执行清理操作。

*   **`newextram` 函数：** 分配新的 M 并将它们添加到 `extraM` 列表中。这确保了在需要时总有可用的 M 来处理 CGO 回调。

*   **`oneNewExtraM` 函数：** 创建一个额外的 M，并将其关联到一个特殊的 Goroutine（用于执行 CGO 回调）。

*   **`dropm` 函数：**  当 CGO 回调完成，或者 C 线程即将退出时，将当前 M 放回 `extraM` 列表。
    *   在非 pthread 平台上，在每次 CGO 回调完成后调用。
    *   在 pthread 平台上，作为线程退出时的析构函数被调用。
    *   清理 M 和 G 的状态。

*   **`cgoBindM` 函数：**  使用 `_cgo_bindm` (CGO 提供的函数) 将当前的 g0 存储到线程特定的存储中。这允许在线程退出时执行 `dropm`。

**Go 代码示例（CGO）：**

假设有一个 C 函数，我们想从 Go 代码中调用，并且 C 函数会回调 Go 函数。

```go
// main.go
package main

//#include <stdio.h>
//#include <stdlib.h>
//
//typedef void (*go_callback_t)(int);
//
//extern void goCallback(int);
//
//void call_go_callback(go_callback_t cb, int value) {
//    printf("Calling Go callback from C with value: %d\n", value);
//    cb(value);
//}
import "C"
import "fmt"

//export goCallback
func goCallback(value C.int) {
	fmt.Printf("Go callback received value: %d\n", value)
}

func main() {
	C.call_go_callback(C.go_callback_t(C.goCallback), C.int(123))
}
```

**假设输入与输出：**

*   **输入：** 运行上面的 Go 代码。
*   **输出：**
    ```
    Calling Go callback from C with value: 123
    Go callback received value: 123
    ```
    当 C 代码调用 `goCallback` 时，如果当前 C 线程没有关联的 M，`needm` 会被调用来获取一个 M，使得 Go 代码 `goCallback` 可以在该 M 上执行。

**3. M 的启动和停止：**

*   **`startm` 函数：** 调度一个 M 来运行一个 P（如果必要会创建新的 M）。
    *   如果 `p` 为 nil，则尝试获取一个空闲的 P。
    *   如果 `spinning` 为 true，表示调用者已经增加了 `nmspinning` 计数器。
    *   会尝试复用空闲的 M，或者在必要时调用 `newm` 创建新的 M。
    *   **推理:** `startm` 负责将工作（P）分配给可用的线程（M）。

*   **`stopm` 函数：** 停止当前 M 的执行，直到有新的工作可用。它会将当前的 M 放入空闲 M 列表并进入休眠状态。

*   **`mspinning` 函数：**  设置当前 M 的 `spinning` 状态为 true。 Spinning M 会主动寻找可以执行的 Goroutine。

**4. P 的移交和唤醒：**

*   **`handoffp` 函数：** 从 syscall 或被锁定的 M 移交 P。它负责确保 P 上的工作能够继续执行。
    *   如果 P 上有本地工作或全局运行队列中有待执行的 Goroutine，会启动一个 M 来运行该 P。
    *   还会处理 GC 工作、安全点函数等。
    *   如果没有本地工作，并且没有自旋或空闲的 M，则可能会启动一个新的自旋 M。
    *   **推理:** `handoffp` 确保当一个 P 变得空闲时，其上的工作能够被其他 M 接管。

*   **`wakep` 函数：** 尝试添加一个额外的 P 来执行 Goroutine。当有新的 Goroutine 变为可运行状态时被调用。

**5. 锁定 M 的处理：**

*   **`stoplockedm` 函数：** 停止当前锁定到特定 G 的 M 的执行，直到该 G 再次变为可运行状态。

*   **`startlockedm` 函数：**  调度锁定的 M 来运行其锁定的 G。

**6. `extraM` 列表的管理：**

*   **`extraM` (atomic.Uintptr):**  原子地指向 `extraM` 列表的头部。
*   **`extraMLength` (atomic.Uint32):** 原子地记录 `extraM` 列表中 M 的数量。
*   **`extraMWaiters` (atomic.Uint32):** 原子地记录等待 `extraM` 的线程数量。
*   **`extraMInUse` (atomic.Uint32):** 原子地记录正在被使用的额外 M 的数量。
*   **`lockextra` 和 `unlockextra` 函数：** 用于安全地访问和修改 `extraM` 列表的自旋锁机制。
*   **`getExtraM` 函数：** 从 `extraM` 列表中获取一个 M。
*   **`putExtraM` 函数：** 将一个 M 放回 `extraM` 列表。
*   **`addExtraM` 函数：** 将一个新分配的 M 添加到 `extraM` 列表。

**7. 延迟的 M 创建 (`newmHandoff`)：**

*   **`newmHandoff` 结构体：** 用于在当前 M 无法安全地创建新 OS 线程时，将 M 的创建请求传递给一个“模板线程”。
*   **`newm` 函数：** 创建一个新的 M。如果当前 M 处于锁定状态或由 C 代码启动，则会将创建请求添加到 `newmHandoff` 列表。
*   **`newm1` 函数：**  实际执行创建新 OS 线程的操作，根据是否启用 CGO 调用 `asmcgocall` 或 `newosproc`。
*   **`startTemplateThread` 函数：** 启动模板线程（如果尚未运行）。
*   **`templateThread` 函数：**  一个运行在没有 P 的 M 上的线程，专门用于处理 `newmHandoff` 列表中的 M 创建请求。这解决了一些在特定情况下（如在持有锁的线程上）无法直接创建新线程的问题。

**命令行参数的处理：**

这段代码本身没有直接处理命令行参数。命令行参数的处理通常发生在 `os` 和 `flag` 等包中。`runtime` 包主要关注底层的运行时机制。

**使用者易犯错的点（与 CGO 相关）：**

1. **CGO 回调中的并发安全：**  在 Go 回调函数中访问共享的 Go 数据时，需要注意并发安全，因为回调可能发生在不同的 M 上。
2. **C 代码中的 Go 内存管理：**  从 C 代码中直接操作 Go 分配的内存是危险的，容易导致内存泄漏或崩溃。应该使用 CGO 提供的机制（如 `C.malloc`/`C.free` 与 Go 的内存交互）。
3. **线程局部存储 (TLS) 的理解：**  CGO 中线程局部存储的行为可能与纯 Go 代码不同，需要仔细理解其生命周期和作用域。
4. **`needm`/`dropm` 的不成对使用：**  在某些复杂的 CGO 场景下，手动管理 `needm` 和 `dropm` 的调用可能出错，导致 M 的泄漏或状态不一致。

**总结 - 第 3 部分的功能：**

这段代码主要负责以下功能：

*   **实现 Go 运行时的安全点机制，允许在所有处理器上同步执行特定函数，常用于垃圾回收等全局操作。**
*   **管理与 C 代码交互（CGO）过程中涉及的线程（M）的创建、获取和释放，特别是处理 C 代码回调 Go 代码的场景。**  通过维护一个额外的 M 列表 (`extraM`) 来高效处理 CGO 回调。
*   **提供 M 的启动和停止机制，以及 P 在不同 M 之间的移交，是 Go 调度器的核心组成部分。**
*   **处理锁定到特定 Goroutine 的 M 的特殊情况。**
*   **实现了一种延迟创建 M 的机制，用于解决在某些特定上下文（例如持有锁的线程）中无法直接创建新线程的问题。**

总而言之，这段代码是 Go 运行时系统中关于线程管理和与外部代码交互的关键组成部分，它确保了 Go 程序的正确执行和与 C 代码的有效集成。

Prompt: 
```
这是路径为go/src/runtime/proc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共7部分，请归纳一下它的功能

"""
r {
			// Wait for 100us, then try to re-preempt in
			// case of any races.
			//
			// Requires system stack.
			if notetsleep(&sched.safePointNote, 100*1000) {
				noteclear(&sched.safePointNote)
				break
			}
			preemptall()
		}
	}
	if sched.safePointWait != 0 {
		throw("forEachP: not done")
	}
	for _, p2 := range allp {
		if p2.runSafePointFn != 0 {
			throw("forEachP: P did not run fn")
		}
	}

	lock(&sched.lock)
	sched.safePointFn = nil
	unlock(&sched.lock)
	releasem(mp)
}

// runSafePointFn runs the safe point function, if any, for this P.
// This should be called like
//
//	if getg().m.p.runSafePointFn != 0 {
//	    runSafePointFn()
//	}
//
// runSafePointFn must be checked on any transition in to _Pidle or
// _Psyscall to avoid a race where forEachP sees that the P is running
// just before the P goes into _Pidle/_Psyscall and neither forEachP
// nor the P run the safe-point function.
func runSafePointFn() {
	p := getg().m.p.ptr()
	// Resolve the race between forEachP running the safe-point
	// function on this P's behalf and this P running the
	// safe-point function directly.
	if !atomic.Cas(&p.runSafePointFn, 1, 0) {
		return
	}
	sched.safePointFn(p)
	lock(&sched.lock)
	sched.safePointWait--
	if sched.safePointWait == 0 {
		notewakeup(&sched.safePointNote)
	}
	unlock(&sched.lock)
}

// When running with cgo, we call _cgo_thread_start
// to start threads for us so that we can play nicely with
// foreign code.
var cgoThreadStart unsafe.Pointer

type cgothreadstart struct {
	g   guintptr
	tls *uint64
	fn  unsafe.Pointer
}

// Allocate a new m unassociated with any thread.
// Can use p for allocation context if needed.
// fn is recorded as the new m's m.mstartfn.
// id is optional pre-allocated m ID. Omit by passing -1.
//
// This function is allowed to have write barriers even if the caller
// isn't because it borrows pp.
//
//go:yeswritebarrierrec
func allocm(pp *p, fn func(), id int64) *m {
	allocmLock.rlock()

	// The caller owns pp, but we may borrow (i.e., acquirep) it. We must
	// disable preemption to ensure it is not stolen, which would make the
	// caller lose ownership.
	acquirem()

	gp := getg()
	if gp.m.p == 0 {
		acquirep(pp) // temporarily borrow p for mallocs in this function
	}

	// Release the free M list. We need to do this somewhere and
	// this may free up a stack we can use.
	if sched.freem != nil {
		lock(&sched.lock)
		var newList *m
		for freem := sched.freem; freem != nil; {
			// Wait for freeWait to indicate that freem's stack is unused.
			wait := freem.freeWait.Load()
			if wait == freeMWait {
				next := freem.freelink
				freem.freelink = newList
				newList = freem
				freem = next
				continue
			}
			// Drop any remaining trace resources.
			// Ms can continue to emit events all the way until wait != freeMWait,
			// so it's only safe to call traceThreadDestroy at this point.
			if traceEnabled() || traceShuttingDown() {
				traceThreadDestroy(freem)
			}
			// Free the stack if needed. For freeMRef, there is
			// nothing to do except drop freem from the sched.freem
			// list.
			if wait == freeMStack {
				// stackfree must be on the system stack, but allocm is
				// reachable off the system stack transitively from
				// startm.
				systemstack(func() {
					stackfree(freem.g0.stack)
				})
			}
			freem = freem.freelink
		}
		sched.freem = newList
		unlock(&sched.lock)
	}

	mp := new(m)
	mp.mstartfn = fn
	mcommoninit(mp, id)

	// In case of cgo or Solaris or illumos or Darwin, pthread_create will make us a stack.
	// Windows and Plan 9 will layout sched stack on OS stack.
	if iscgo || mStackIsSystemAllocated() {
		mp.g0 = malg(-1)
	} else {
		mp.g0 = malg(16384 * sys.StackGuardMultiplier)
	}
	mp.g0.m = mp

	if pp == gp.m.p.ptr() {
		releasep()
	}

	releasem(gp.m)
	allocmLock.runlock()
	return mp
}

// needm is called when a cgo callback happens on a
// thread without an m (a thread not created by Go).
// In this case, needm is expected to find an m to use
// and return with m, g initialized correctly.
// Since m and g are not set now (likely nil, but see below)
// needm is limited in what routines it can call. In particular
// it can only call nosplit functions (textflag 7) and cannot
// do any scheduling that requires an m.
//
// In order to avoid needing heavy lifting here, we adopt
// the following strategy: there is a stack of available m's
// that can be stolen. Using compare-and-swap
// to pop from the stack has ABA races, so we simulate
// a lock by doing an exchange (via Casuintptr) to steal the stack
// head and replace the top pointer with MLOCKED (1).
// This serves as a simple spin lock that we can use even
// without an m. The thread that locks the stack in this way
// unlocks the stack by storing a valid stack head pointer.
//
// In order to make sure that there is always an m structure
// available to be stolen, we maintain the invariant that there
// is always one more than needed. At the beginning of the
// program (if cgo is in use) the list is seeded with a single m.
// If needm finds that it has taken the last m off the list, its job
// is - once it has installed its own m so that it can do things like
// allocate memory - to create a spare m and put it on the list.
//
// Each of these extra m's also has a g0 and a curg that are
// pressed into service as the scheduling stack and current
// goroutine for the duration of the cgo callback.
//
// It calls dropm to put the m back on the list,
// 1. when the callback is done with the m in non-pthread platforms,
// 2. or when the C thread exiting on pthread platforms.
//
// The signal argument indicates whether we're called from a signal
// handler.
//
//go:nosplit
func needm(signal bool) {
	if (iscgo || GOOS == "windows") && !cgoHasExtraM {
		// Can happen if C/C++ code calls Go from a global ctor.
		// Can also happen on Windows if a global ctor uses a
		// callback created by syscall.NewCallback. See issue #6751
		// for details.
		//
		// Can not throw, because scheduler is not initialized yet.
		writeErrStr("fatal error: cgo callback before cgo call\n")
		exit(1)
	}

	// Save and block signals before getting an M.
	// The signal handler may call needm itself,
	// and we must avoid a deadlock. Also, once g is installed,
	// any incoming signals will try to execute,
	// but we won't have the sigaltstack settings and other data
	// set up appropriately until the end of minit, which will
	// unblock the signals. This is the same dance as when
	// starting a new m to run Go code via newosproc.
	var sigmask sigset
	sigsave(&sigmask)
	sigblock(false)

	// getExtraM is safe here because of the invariant above,
	// that the extra list always contains or will soon contain
	// at least one m.
	mp, last := getExtraM()

	// Set needextram when we've just emptied the list,
	// so that the eventual call into cgocallbackg will
	// allocate a new m for the extra list. We delay the
	// allocation until then so that it can be done
	// after exitsyscall makes sure it is okay to be
	// running at all (that is, there's no garbage collection
	// running right now).
	mp.needextram = last

	// Store the original signal mask for use by minit.
	mp.sigmask = sigmask

	// Install TLS on some platforms (previously setg
	// would do this if necessary).
	osSetupTLS(mp)

	// Install g (= m->g0) and set the stack bounds
	// to match the current stack.
	setg(mp.g0)
	sp := sys.GetCallerSP()
	callbackUpdateSystemStack(mp, sp, signal)

	// Should mark we are already in Go now.
	// Otherwise, we may call needm again when we get a signal, before cgocallbackg1,
	// which means the extram list may be empty, that will cause a deadlock.
	mp.isExtraInC = false

	// Initialize this thread to use the m.
	asminit()
	minit()

	// Emit a trace event for this dead -> syscall transition,
	// but only if we're not in a signal handler.
	//
	// N.B. the tracer can run on a bare M just fine, we just have
	// to make sure to do this before setg(nil) and unminit.
	var trace traceLocker
	if !signal {
		trace = traceAcquire()
	}

	// mp.curg is now a real goroutine.
	casgstatus(mp.curg, _Gdead, _Gsyscall)
	sched.ngsys.Add(-1)

	if !signal {
		if trace.ok() {
			trace.GoCreateSyscall(mp.curg)
			traceRelease(trace)
		}
	}
	mp.isExtraInSig = signal
}

// Acquire an extra m and bind it to the C thread when a pthread key has been created.
//
//go:nosplit
func needAndBindM() {
	needm(false)

	if _cgo_pthread_key_created != nil && *(*uintptr)(_cgo_pthread_key_created) != 0 {
		cgoBindM()
	}
}

// newextram allocates m's and puts them on the extra list.
// It is called with a working local m, so that it can do things
// like call schedlock and allocate.
func newextram() {
	c := extraMWaiters.Swap(0)
	if c > 0 {
		for i := uint32(0); i < c; i++ {
			oneNewExtraM()
		}
	} else if extraMLength.Load() == 0 {
		// Make sure there is at least one extra M.
		oneNewExtraM()
	}
}

// oneNewExtraM allocates an m and puts it on the extra list.
func oneNewExtraM() {
	// Create extra goroutine locked to extra m.
	// The goroutine is the context in which the cgo callback will run.
	// The sched.pc will never be returned to, but setting it to
	// goexit makes clear to the traceback routines where
	// the goroutine stack ends.
	mp := allocm(nil, nil, -1)
	gp := malg(4096)
	gp.sched.pc = abi.FuncPCABI0(goexit) + sys.PCQuantum
	gp.sched.sp = gp.stack.hi
	gp.sched.sp -= 4 * goarch.PtrSize // extra space in case of reads slightly beyond frame
	gp.sched.lr = 0
	gp.sched.g = guintptr(unsafe.Pointer(gp))
	gp.syscallpc = gp.sched.pc
	gp.syscallsp = gp.sched.sp
	gp.stktopsp = gp.sched.sp
	// malg returns status as _Gidle. Change to _Gdead before
	// adding to allg where GC can see it. We use _Gdead to hide
	// this from tracebacks and stack scans since it isn't a
	// "real" goroutine until needm grabs it.
	casgstatus(gp, _Gidle, _Gdead)
	gp.m = mp
	mp.curg = gp
	mp.isextra = true
	// mark we are in C by default.
	mp.isExtraInC = true
	mp.lockedInt++
	mp.lockedg.set(gp)
	gp.lockedm.set(mp)
	gp.goid = sched.goidgen.Add(1)
	if raceenabled {
		gp.racectx = racegostart(abi.FuncPCABIInternal(newextram) + sys.PCQuantum)
	}
	// put on allg for garbage collector
	allgadd(gp)

	// gp is now on the allg list, but we don't want it to be
	// counted by gcount. It would be more "proper" to increment
	// sched.ngfree, but that requires locking. Incrementing ngsys
	// has the same effect.
	sched.ngsys.Add(1)

	// Add m to the extra list.
	addExtraM(mp)
}

// dropm puts the current m back onto the extra list.
//
// 1. On systems without pthreads, like Windows
// dropm is called when a cgo callback has called needm but is now
// done with the callback and returning back into the non-Go thread.
//
// The main expense here is the call to signalstack to release the
// m's signal stack, and then the call to needm on the next callback
// from this thread. It is tempting to try to save the m for next time,
// which would eliminate both these costs, but there might not be
// a next time: the current thread (which Go does not control) might exit.
// If we saved the m for that thread, there would be an m leak each time
// such a thread exited. Instead, we acquire and release an m on each
// call. These should typically not be scheduling operations, just a few
// atomics, so the cost should be small.
//
// 2. On systems with pthreads
// dropm is called while a non-Go thread is exiting.
// We allocate a pthread per-thread variable using pthread_key_create,
// to register a thread-exit-time destructor.
// And store the g into a thread-specific value associated with the pthread key,
// when first return back to C.
// So that the destructor would invoke dropm while the non-Go thread is exiting.
// This is much faster since it avoids expensive signal-related syscalls.
//
// This always runs without a P, so //go:nowritebarrierrec is required.
//
// This may run with a different stack than was recorded in g0 (there is no
// call to callbackUpdateSystemStack prior to dropm), so this must be
// //go:nosplit to avoid the stack bounds check.
//
//go:nowritebarrierrec
//go:nosplit
func dropm() {
	// Clear m and g, and return m to the extra list.
	// After the call to setg we can only call nosplit functions
	// with no pointer manipulation.
	mp := getg().m

	// Emit a trace event for this syscall -> dead transition.
	//
	// N.B. the tracer can run on a bare M just fine, we just have
	// to make sure to do this before setg(nil) and unminit.
	var trace traceLocker
	if !mp.isExtraInSig {
		trace = traceAcquire()
	}

	// Return mp.curg to dead state.
	casgstatus(mp.curg, _Gsyscall, _Gdead)
	mp.curg.preemptStop = false
	sched.ngsys.Add(1)

	if !mp.isExtraInSig {
		if trace.ok() {
			trace.GoDestroySyscall()
			traceRelease(trace)
		}
	}

	// Trash syscalltick so that it doesn't line up with mp.old.syscalltick anymore.
	//
	// In the new tracer, we model needm and dropm and a goroutine being created and
	// destroyed respectively. The m then might get reused with a different procid but
	// still with a reference to oldp, and still with the same syscalltick. The next
	// time a G is "created" in needm, it'll return and quietly reacquire its P from a
	// different m with a different procid, which will confuse the trace parser. By
	// trashing syscalltick, we ensure that it'll appear as if we lost the P to the
	// tracer parser and that we just reacquired it.
	//
	// Trash the value by decrementing because that gets us as far away from the value
	// the syscall exit code expects as possible. Setting to zero is risky because
	// syscalltick could already be zero (and in fact, is initialized to zero).
	mp.syscalltick--

	// Reset trace state unconditionally. This goroutine is being 'destroyed'
	// from the perspective of the tracer.
	mp.curg.trace.reset()

	// Flush all the M's buffers. This is necessary because the M might
	// be used on a different thread with a different procid, so we have
	// to make sure we don't write into the same buffer.
	if traceEnabled() || traceShuttingDown() {
		// Acquire sched.lock across thread destruction. One of the invariants of the tracer
		// is that a thread cannot disappear from the tracer's view (allm or freem) without
		// it noticing, so it requires that sched.lock be held over traceThreadDestroy.
		//
		// This isn't strictly necessary in this case, because this thread never leaves allm,
		// but the critical section is short and dropm is rare on pthread platforms, so just
		// take the lock and play it safe. traceThreadDestroy also asserts that the lock is held.
		lock(&sched.lock)
		traceThreadDestroy(mp)
		unlock(&sched.lock)
	}
	mp.isExtraInSig = false

	// Block signals before unminit.
	// Unminit unregisters the signal handling stack (but needs g on some systems).
	// Setg(nil) clears g, which is the signal handler's cue not to run Go handlers.
	// It's important not to try to handle a signal between those two steps.
	sigmask := mp.sigmask
	sigblock(false)
	unminit()

	setg(nil)

	// Clear g0 stack bounds to ensure that needm always refreshes the
	// bounds when reusing this M.
	g0 := mp.g0
	g0.stack.hi = 0
	g0.stack.lo = 0
	g0.stackguard0 = 0
	g0.stackguard1 = 0
	mp.g0StackAccurate = false

	putExtraM(mp)

	msigrestore(sigmask)
}

// bindm store the g0 of the current m into a thread-specific value.
//
// We allocate a pthread per-thread variable using pthread_key_create,
// to register a thread-exit-time destructor.
// We are here setting the thread-specific value of the pthread key, to enable the destructor.
// So that the pthread_key_destructor would dropm while the C thread is exiting.
//
// And the saved g will be used in pthread_key_destructor,
// since the g stored in the TLS by Go might be cleared in some platforms,
// before the destructor invoked, so, we restore g by the stored g, before dropm.
//
// We store g0 instead of m, to make the assembly code simpler,
// since we need to restore g0 in runtime.cgocallback.
//
// On systems without pthreads, like Windows, bindm shouldn't be used.
//
// NOTE: this always runs without a P, so, nowritebarrierrec required.
//
//go:nosplit
//go:nowritebarrierrec
func cgoBindM() {
	if GOOS == "windows" || GOOS == "plan9" {
		fatal("bindm in unexpected GOOS")
	}
	g := getg()
	if g.m.g0 != g {
		fatal("the current g is not g0")
	}
	if _cgo_bindm != nil {
		asmcgocall(_cgo_bindm, unsafe.Pointer(g))
	}
}

// A helper function for EnsureDropM.
//
// getm should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - fortio.org/log
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname getm
func getm() uintptr {
	return uintptr(unsafe.Pointer(getg().m))
}

var (
	// Locking linked list of extra M's, via mp.schedlink. Must be accessed
	// only via lockextra/unlockextra.
	//
	// Can't be atomic.Pointer[m] because we use an invalid pointer as a
	// "locked" sentinel value. M's on this list remain visible to the GC
	// because their mp.curg is on allgs.
	extraM atomic.Uintptr
	// Number of M's in the extraM list.
	extraMLength atomic.Uint32
	// Number of waiters in lockextra.
	extraMWaiters atomic.Uint32

	// Number of extra M's in use by threads.
	extraMInUse atomic.Uint32
)

// lockextra locks the extra list and returns the list head.
// The caller must unlock the list by storing a new list head
// to extram. If nilokay is true, then lockextra will
// return a nil list head if that's what it finds. If nilokay is false,
// lockextra will keep waiting until the list head is no longer nil.
//
//go:nosplit
func lockextra(nilokay bool) *m {
	const locked = 1

	incr := false
	for {
		old := extraM.Load()
		if old == locked {
			osyield_no_g()
			continue
		}
		if old == 0 && !nilokay {
			if !incr {
				// Add 1 to the number of threads
				// waiting for an M.
				// This is cleared by newextram.
				extraMWaiters.Add(1)
				incr = true
			}
			usleep_no_g(1)
			continue
		}
		if extraM.CompareAndSwap(old, locked) {
			return (*m)(unsafe.Pointer(old))
		}
		osyield_no_g()
		continue
	}
}

//go:nosplit
func unlockextra(mp *m, delta int32) {
	extraMLength.Add(delta)
	extraM.Store(uintptr(unsafe.Pointer(mp)))
}

// Return an M from the extra M list. Returns last == true if the list becomes
// empty because of this call.
//
// Spins waiting for an extra M, so caller must ensure that the list always
// contains or will soon contain at least one M.
//
//go:nosplit
func getExtraM() (mp *m, last bool) {
	mp = lockextra(false)
	extraMInUse.Add(1)
	unlockextra(mp.schedlink.ptr(), -1)
	return mp, mp.schedlink.ptr() == nil
}

// Returns an extra M back to the list. mp must be from getExtraM. Newly
// allocated M's should use addExtraM.
//
//go:nosplit
func putExtraM(mp *m) {
	extraMInUse.Add(-1)
	addExtraM(mp)
}

// Adds a newly allocated M to the extra M list.
//
//go:nosplit
func addExtraM(mp *m) {
	mnext := lockextra(true)
	mp.schedlink.set(mnext)
	unlockextra(mp, 1)
}

var (
	// allocmLock is locked for read when creating new Ms in allocm and their
	// addition to allm. Thus acquiring this lock for write blocks the
	// creation of new Ms.
	allocmLock rwmutex

	// execLock serializes exec and clone to avoid bugs or unspecified
	// behaviour around exec'ing while creating/destroying threads. See
	// issue #19546.
	execLock rwmutex
)

// These errors are reported (via writeErrStr) by some OS-specific
// versions of newosproc and newosproc0.
const (
	failthreadcreate  = "runtime: failed to create new OS thread\n"
	failallocatestack = "runtime: failed to allocate stack for the new OS thread\n"
)

// newmHandoff contains a list of m structures that need new OS threads.
// This is used by newm in situations where newm itself can't safely
// start an OS thread.
var newmHandoff struct {
	lock mutex

	// newm points to a list of M structures that need new OS
	// threads. The list is linked through m.schedlink.
	newm muintptr

	// waiting indicates that wake needs to be notified when an m
	// is put on the list.
	waiting bool
	wake    note

	// haveTemplateThread indicates that the templateThread has
	// been started. This is not protected by lock. Use cas to set
	// to 1.
	haveTemplateThread uint32
}

// Create a new m. It will start off with a call to fn, or else the scheduler.
// fn needs to be static and not a heap allocated closure.
// May run with m.p==nil, so write barriers are not allowed.
//
// id is optional pre-allocated m ID. Omit by passing -1.
//
//go:nowritebarrierrec
func newm(fn func(), pp *p, id int64) {
	// allocm adds a new M to allm, but they do not start until created by
	// the OS in newm1 or the template thread.
	//
	// doAllThreadsSyscall requires that every M in allm will eventually
	// start and be signal-able, even with a STW.
	//
	// Disable preemption here until we start the thread to ensure that
	// newm is not preempted between allocm and starting the new thread,
	// ensuring that anything added to allm is guaranteed to eventually
	// start.
	acquirem()

	mp := allocm(pp, fn, id)
	mp.nextp.set(pp)
	mp.sigmask = initSigmask
	if gp := getg(); gp != nil && gp.m != nil && (gp.m.lockedExt != 0 || gp.m.incgo) && GOOS != "plan9" {
		// We're on a locked M or a thread that may have been
		// started by C. The kernel state of this thread may
		// be strange (the user may have locked it for that
		// purpose). We don't want to clone that into another
		// thread. Instead, ask a known-good thread to create
		// the thread for us.
		//
		// This is disabled on Plan 9. See golang.org/issue/22227.
		//
		// TODO: This may be unnecessary on Windows, which
		// doesn't model thread creation off fork.
		lock(&newmHandoff.lock)
		if newmHandoff.haveTemplateThread == 0 {
			throw("on a locked thread with no template thread")
		}
		mp.schedlink = newmHandoff.newm
		newmHandoff.newm.set(mp)
		if newmHandoff.waiting {
			newmHandoff.waiting = false
			notewakeup(&newmHandoff.wake)
		}
		unlock(&newmHandoff.lock)
		// The M has not started yet, but the template thread does not
		// participate in STW, so it will always process queued Ms and
		// it is safe to releasem.
		releasem(getg().m)
		return
	}
	newm1(mp)
	releasem(getg().m)
}

func newm1(mp *m) {
	if iscgo {
		var ts cgothreadstart
		if _cgo_thread_start == nil {
			throw("_cgo_thread_start missing")
		}
		ts.g.set(mp.g0)
		ts.tls = (*uint64)(unsafe.Pointer(&mp.tls[0]))
		ts.fn = unsafe.Pointer(abi.FuncPCABI0(mstart))
		if msanenabled {
			msanwrite(unsafe.Pointer(&ts), unsafe.Sizeof(ts))
		}
		if asanenabled {
			asanwrite(unsafe.Pointer(&ts), unsafe.Sizeof(ts))
		}
		execLock.rlock() // Prevent process clone.
		asmcgocall(_cgo_thread_start, unsafe.Pointer(&ts))
		execLock.runlock()
		return
	}
	execLock.rlock() // Prevent process clone.
	newosproc(mp)
	execLock.runlock()
}

// startTemplateThread starts the template thread if it is not already
// running.
//
// The calling thread must itself be in a known-good state.
func startTemplateThread() {
	if GOARCH == "wasm" { // no threads on wasm yet
		return
	}

	// Disable preemption to guarantee that the template thread will be
	// created before a park once haveTemplateThread is set.
	mp := acquirem()
	if !atomic.Cas(&newmHandoff.haveTemplateThread, 0, 1) {
		releasem(mp)
		return
	}
	newm(templateThread, nil, -1)
	releasem(mp)
}

// templateThread is a thread in a known-good state that exists solely
// to start new threads in known-good states when the calling thread
// may not be in a good state.
//
// Many programs never need this, so templateThread is started lazily
// when we first enter a state that might lead to running on a thread
// in an unknown state.
//
// templateThread runs on an M without a P, so it must not have write
// barriers.
//
//go:nowritebarrierrec
func templateThread() {
	lock(&sched.lock)
	sched.nmsys++
	checkdead()
	unlock(&sched.lock)

	for {
		lock(&newmHandoff.lock)
		for newmHandoff.newm != 0 {
			newm := newmHandoff.newm.ptr()
			newmHandoff.newm = 0
			unlock(&newmHandoff.lock)
			for newm != nil {
				next := newm.schedlink.ptr()
				newm.schedlink = 0
				newm1(newm)
				newm = next
			}
			lock(&newmHandoff.lock)
		}
		newmHandoff.waiting = true
		noteclear(&newmHandoff.wake)
		unlock(&newmHandoff.lock)
		notesleep(&newmHandoff.wake)
	}
}

// Stops execution of the current m until new work is available.
// Returns with acquired P.
func stopm() {
	gp := getg()

	if gp.m.locks != 0 {
		throw("stopm holding locks")
	}
	if gp.m.p != 0 {
		throw("stopm holding p")
	}
	if gp.m.spinning {
		throw("stopm spinning")
	}

	lock(&sched.lock)
	mput(gp.m)
	unlock(&sched.lock)
	mPark()
	acquirep(gp.m.nextp.ptr())
	gp.m.nextp = 0
}

func mspinning() {
	// startm's caller incremented nmspinning. Set the new M's spinning.
	getg().m.spinning = true
}

// Schedules some M to run the p (creates an M if necessary).
// If p==nil, tries to get an idle P, if no idle P's does nothing.
// May run with m.p==nil, so write barriers are not allowed.
// If spinning is set, the caller has incremented nmspinning and must provide a
// P. startm will set m.spinning in the newly started M.
//
// Callers passing a non-nil P must call from a non-preemptible context. See
// comment on acquirem below.
//
// Argument lockheld indicates whether the caller already acquired the
// scheduler lock. Callers holding the lock when making the call must pass
// true. The lock might be temporarily dropped, but will be reacquired before
// returning.
//
// Must not have write barriers because this may be called without a P.
//
//go:nowritebarrierrec
func startm(pp *p, spinning, lockheld bool) {
	// Disable preemption.
	//
	// Every owned P must have an owner that will eventually stop it in the
	// event of a GC stop request. startm takes transient ownership of a P
	// (either from argument or pidleget below) and transfers ownership to
	// a started M, which will be responsible for performing the stop.
	//
	// Preemption must be disabled during this transient ownership,
	// otherwise the P this is running on may enter GC stop while still
	// holding the transient P, leaving that P in limbo and deadlocking the
	// STW.
	//
	// Callers passing a non-nil P must already be in non-preemptible
	// context, otherwise such preemption could occur on function entry to
	// startm. Callers passing a nil P may be preemptible, so we must
	// disable preemption before acquiring a P from pidleget below.
	mp := acquirem()
	if !lockheld {
		lock(&sched.lock)
	}
	if pp == nil {
		if spinning {
			// TODO(prattmic): All remaining calls to this function
			// with _p_ == nil could be cleaned up to find a P
			// before calling startm.
			throw("startm: P required for spinning=true")
		}
		pp, _ = pidleget(0)
		if pp == nil {
			if !lockheld {
				unlock(&sched.lock)
			}
			releasem(mp)
			return
		}
	}
	nmp := mget()
	if nmp == nil {
		// No M is available, we must drop sched.lock and call newm.
		// However, we already own a P to assign to the M.
		//
		// Once sched.lock is released, another G (e.g., in a syscall),
		// could find no idle P while checkdead finds a runnable G but
		// no running M's because this new M hasn't started yet, thus
		// throwing in an apparent deadlock.
		// This apparent deadlock is possible when startm is called
		// from sysmon, which doesn't count as a running M.
		//
		// Avoid this situation by pre-allocating the ID for the new M,
		// thus marking it as 'running' before we drop sched.lock. This
		// new M will eventually run the scheduler to execute any
		// queued G's.
		id := mReserveID()
		unlock(&sched.lock)

		var fn func()
		if spinning {
			// The caller incremented nmspinning, so set m.spinning in the new M.
			fn = mspinning
		}
		newm(fn, pp, id)

		if lockheld {
			lock(&sched.lock)
		}
		// Ownership transfer of pp committed by start in newm.
		// Preemption is now safe.
		releasem(mp)
		return
	}
	if !lockheld {
		unlock(&sched.lock)
	}
	if nmp.spinning {
		throw("startm: m is spinning")
	}
	if nmp.nextp != 0 {
		throw("startm: m has p")
	}
	if spinning && !runqempty(pp) {
		throw("startm: p has runnable gs")
	}
	// The caller incremented nmspinning, so set m.spinning in the new M.
	nmp.spinning = spinning
	nmp.nextp.set(pp)
	notewakeup(&nmp.park)
	// Ownership transfer of pp committed by wakeup. Preemption is now
	// safe.
	releasem(mp)
}

// Hands off P from syscall or locked M.
// Always runs without a P, so write barriers are not allowed.
//
//go:nowritebarrierrec
func handoffp(pp *p) {
	// handoffp must start an M in any situation where
	// findrunnable would return a G to run on pp.

	// if it has local work, start it straight away
	if !runqempty(pp) || sched.runqsize != 0 {
		startm(pp, false, false)
		return
	}
	// if there's trace work to do, start it straight away
	if (traceEnabled() || traceShuttingDown()) && traceReaderAvailable() != nil {
		startm(pp, false, false)
		return
	}
	// if it has GC work, start it straight away
	if gcBlackenEnabled != 0 && gcMarkWorkAvailable(pp) {
		startm(pp, false, false)
		return
	}
	// no local work, check that there are no spinning/idle M's,
	// otherwise our help is not required
	if sched.nmspinning.Load()+sched.npidle.Load() == 0 && sched.nmspinning.CompareAndSwap(0, 1) { // TODO: fast atomic
		sched.needspinning.Store(0)
		startm(pp, true, false)
		return
	}
	lock(&sched.lock)
	if sched.gcwaiting.Load() {
		pp.status = _Pgcstop
		pp.gcStopTime = nanotime()
		sched.stopwait--
		if sched.stopwait == 0 {
			notewakeup(&sched.stopnote)
		}
		unlock(&sched.lock)
		return
	}
	if pp.runSafePointFn != 0 && atomic.Cas(&pp.runSafePointFn, 1, 0) {
		sched.safePointFn(pp)
		sched.safePointWait--
		if sched.safePointWait == 0 {
			notewakeup(&sched.safePointNote)
		}
	}
	if sched.runqsize != 0 {
		unlock(&sched.lock)
		startm(pp, false, false)
		return
	}
	// If this is the last running P and nobody is polling network,
	// need to wakeup another M to poll network.
	if sched.npidle.Load() == gomaxprocs-1 && sched.lastpoll.Load() != 0 {
		unlock(&sched.lock)
		startm(pp, false, false)
		return
	}

	// The scheduler lock cannot be held when calling wakeNetPoller below
	// because wakeNetPoller may call wakep which may call startm.
	when := pp.timers.wakeTime()
	pidleput(pp, 0)
	unlock(&sched.lock)

	if when != 0 {
		wakeNetPoller(when)
	}
}

// Tries to add one more P to execute G's.
// Called when a G is made runnable (newproc, ready).
// Must be called with a P.
//
// wakep should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname wakep
func wakep() {
	// Be conservative about spinning threads, only start one if none exist
	// already.
	if sched.nmspinning.Load() != 0 || !sched.nmspinning.CompareAndSwap(0, 1) {
		return
	}

	// Disable preemption until ownership of pp transfers to the next M in
	// startm. Otherwise preemption here would leave pp stuck waiting to
	// enter _Pgcstop.
	//
	// See preemption comment on acquirem in startm for more details.
	mp := acquirem()

	var pp *p
	lock(&sched.lock)
	pp, _ = pidlegetSpinning(0)
	if pp == nil {
		if sched.nmspinning.Add(-1) < 0 {
			throw("wakep: negative nmspinning")
		}
		unlock(&sched.lock)
		releasem(mp)
		return
	}
	// Since we always have a P, the race in the "No M is available"
	// comment in startm doesn't apply during the small window between the
	// unlock here and lock in startm. A checkdead in between will always
	// see at least one running M (ours).
	unlock(&sched.lock)

	startm(pp, true, false)

	releasem(mp)
}

// Stops execution of the current m that is locked to a g until the g is runnable again.
// Returns with acquired P.
func stoplockedm() {
	gp := getg()

	if gp.m.lockedg == 0 || gp.m.lockedg.ptr().lockedm.ptr() != gp.m {
		throw("stoplockedm: inconsistent locking")
	}
	if gp.m.p != 0 {
		// Schedule another M to run this p.
		pp := releasep()
		handoffp(pp)
	}
	incidlelocked(1)
	// Wait until another thread schedules lockedg again.
	mPark()
	status := readgstatus(gp.m.lockedg.ptr())
	if status&^_Gscan != _Grunnable {
		print("runtime:stoplockedm: lockedg (atomicstatus=", status, ") is not Grunnable or Gscanrunnable\n")
		dumpgstatus(gp.m.lockedg.ptr())
		throw("stoplockedm: not runnable")
	}
	acquirep(gp.m.nextp.ptr())
	gp.m.nextp = 0
}

// Schedules the locked m to run the locked gp.
// May run during STW, so write barriers are not allowed.
//
//go:nowritebarrierrec
func startlockedm(gp *g) {
	mp := gp.lockedm.ptr()
	if mp == getg().m {
		throw("startlockedm: locked to me")
	}
	if mp.nextp != 0 {
		throw("startlockedm: m has p")
	}
	// directly handoff c
"""




```