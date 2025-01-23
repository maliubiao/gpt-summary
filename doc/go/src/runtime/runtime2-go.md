Response:
Let's break down the thought process for analyzing this Go runtime code snippet.

**1. Initial Understanding & Context:**

* **File Path:** The path `go/src/runtime/runtime2.go` immediately tells us this is a core part of the Go runtime. The `runtime` package is responsible for managing goroutines, memory, scheduling, and other fundamental aspects of the language.
* **"Part 1 of 2":** This signals that the provided code is incomplete and we should expect a continuation.
* **Copyright & License:** Standard Go boilerplate, confirming its source and licensing.
* **`package runtime` and `import (...)`:** This confirms it's the runtime package and lists its dependencies (internal packages mostly). We can infer that these imported packages provide lower-level functionalities used by `runtime2.go`.

**2. Scanning for Key Structures and Concepts:**

I'd start by visually scanning the code for the most prominent elements:

* **`const` blocks:**  These define important named constants. The names like `_Gidle`, `_Grunnable`, `_Prunning`, `_Pidle` immediately jump out as likely related to the states of goroutines (`G`) and processors (`P`). This hints at the scheduler's inner workings.
* **`type` declarations:** These define the core data structures. I'd pay close attention to:
    * `mutex`: Basic synchronization primitive.
    * `gobuf`:  Looks like it holds the context of a goroutine (SP, PC, etc.). Crucial for switching between goroutines.
    * `g`: The structure representing a goroutine. Its fields are packed with information about its state, stack, associated M, and more.
    * `m`: The structure representing a machine/OS thread. It manages the execution of goroutines.
    * `p`: The structure representing a processor, which acts as a local scheduler for goroutines.
    * `schedt`:  Likely the central scheduler data structure, holding global run queues, idle lists, and statistics.
    * `sudog`: Seems related to goroutines waiting on synchronization primitives (like channels).
* **Functions:**  I'd notice the small `go:nosplit` and `go:nowritebarrier` functions (`guintptr.ptr()`, `guintptr.set()`, etc.). These likely deal with low-level memory manipulation and bypassing Go's write barrier during garbage collection. The presence of `guintptr`, `muintptr`, and `puintptr` is a strong indicator of careful management of pointers to avoid issues with the GC.

**3. Connecting the Dots and Inferring Functionality:**

Based on the identified structures and constants, I'd start making inferences:

* **Goroutine States:** The `_G...` constants clearly define the different states a goroutine can be in (idle, runnable, running, waiting, etc.). This is fundamental to the Go scheduler.
* **Processor States:**  Similarly, the `_P...` constants define the states of processors.
* **Scheduling:** The interplay between `g`, `m`, and `p` becomes apparent. Goroutines run on processors (`p`), which are associated with OS threads (`m`). The scheduler moves goroutines between different states and assigns them to processors.
* **Synchronization:**  `mutex` and `sudog` point towards mechanisms for coordinating access to shared resources and handling blocking operations (channels, mutexes, etc.).
* **Garbage Collection:** The `_Gscan...` states and the discussion of `guintptr`, `muintptr`, `puintptr`, and write barriers strongly suggest that this code is deeply involved in how Go manages memory and performs garbage collection. The need to bypass write barriers in certain scenarios is a key detail.
* **Low-Level Operations:**  The `go:nosplit` and `go:nowritebarrier` pragmas indicate functions that need to be very efficient and avoid stack splitting or triggering write barriers, often for performance or correctness reasons in critical sections.

**4. Formulating the Summary (Based on Part 1):**

Given the above analysis, I'd formulate a summary like this:

* **Core Data Structures:** Defines the fundamental building blocks for Go's concurrency and execution model: goroutines (`g`), OS threads (`m`), and processors (`p`).
* **Goroutine and Processor States:** Enumerates the different states these entities can be in, crucial for scheduling and lifecycle management.
* **Synchronization Primitives:** Includes the definition of `mutex`, a basic locking mechanism.
* **Low-Level Pointer Management:** Introduces `guintptr`, `muintptr`, and `puintptr` as special pointer types used to bypass write barriers, essential for safe and efficient memory management during garbage collection.
* **Goroutine Context:** Defines `gobuf` to store the execution context of a goroutine, enabling context switching.
* **Waiting on Synchronization:** Defines `sudog` for representing goroutines waiting on synchronization objects.

**5. Anticipating Part 2:**

Knowing this is "Part 1 of 2," I'd anticipate that the next part will likely delve deeper into:

* **Scheduler Logic:** How goroutines are moved between run queues and assigned to processors.
* **Garbage Collection Details:**  More about how the GC interacts with goroutine states and memory management.
* **Synchronization Primitives Implementation:**  More complex synchronization mechanisms beyond basic mutexes (channels, wait groups, etc.).
* **System Calls:** How goroutines interact with the operating system.
* **Memory Allocation:**  Potentially, though `mcache` and `pageCache` are mentioned, this might be in a separate file.

This structured approach, starting with high-level observations and gradually digging deeper into the code's elements and their relationships, allows for a comprehensive understanding of the provided Go runtime snippet. The keywords, data structures, and pragmas act as strong clues to the code's purpose.
这段Go语言代码是 `go/src/runtime/runtime2.go` 文件的一部分，它定义了Go运行时系统的核心数据结构和常量。这些结构和常量是Go语言并发模型、内存管理、垃圾回收以及与操作系统交互的基础。

**功能归纳：**

这段代码主要定义了以下关键功能：

1. **定义了 Goroutine (G) 的状态：**  使用常量 `_Gidle` 到 `_Gscanpreempted` 定义了 Goroutine 的各种状态，例如：空闲、可运行、正在运行、系统调用中、等待中等等。这些状态用于 Goroutine 的调度和生命周期管理。
2. **定义了处理器 (P) 的状态：** 使用常量 `_Pidle` 到 `_Pdead` 定义了处理器 P 的各种状态，例如：空闲、运行中、系统调用中、GC停止等。P 是 Go 调度器的核心组件，负责执行 Goroutine。
3. **定义了互斥锁 (Mutex)：** 定义了 `mutex` 结构，这是 Go 中用于实现互斥访问共享资源的基本同步原语。
4. **定义了函数值 (funcval)：** 定义了 `funcval` 结构，用于表示闭包或其他包含函数指针和上下文信息的值。
5. **定义了接口类型 (iface, eface)：** 定义了 `iface` 和 `eface` 结构，用于表示 Go 的接口类型。`iface` 用于带有方法的接口，`eface` 用于 `interface{}` 类型的接口。
6. **定义了特殊的指针类型 (guintptr, muintptr, puintptr)：**  这些类型是 `uintptr` 的别名，但它们的存在是为了绕过 Go 的写屏障机制。这在运行时的一些底层操作中是必要的，以避免在不安全的时间点触发写屏障，例如在没有关联 P 的情况下修改 G 或 P 的指针。
7. **定义了 Goroutine 的上下文 (gobuf)：** 定义了 `gobuf` 结构，用于保存 Goroutine 的寄存器状态（例如栈指针 sp、程序计数器 pc 等），用于 Goroutine 的切换。
8. **定义了等待队列元素 (sudog)：** 定义了 `sudog` 结构，用于表示等待在某个同步对象（例如 Channel）上的 Goroutine。
9. **定义了系统调用信息 (libcall)：** 定义了 `libcall` 结构，用于存储进行系统调用时的一些参数和返回值。
10. **定义了栈信息 (stack)：** 定义了 `stack` 结构，用于描述 Goroutine 的栈的起始和结束地址。
11. **定义了持有的锁信息 (heldLockInfo)：**  定义了 `heldLockInfo` 结构，用于记录当前 M 持有的锁的地址和排名（用于死锁检测）。
12. **定义了 Machine (M) 的结构：** 定义了 `m` 结构，代表操作系统线程。M 负责执行 Goroutine，并关联一个 P。
13. **定义了 Processor (P) 的结构：** 定义了 `p` 结构，是 Go 调度器的核心组件，拥有可运行的 Goroutine 队列。
14. **定义了调度器 (schedt) 的结构：** 定义了 `schedt` 结构，包含了全局的 Goroutine 队列、空闲的 M 和 P 的列表，以及一些调度相关的统计信息。

**Go 语言功能的实现推理和代码举例：**

**推理：Goroutine 的状态管理和调度**

这段代码中 `_Gidle`，`_Grunnable`，`_Grunning` 等常量以及 `g` 结构体中的 `atomicstatus` 字段，明显是为了实现 Goroutine 的状态管理。结合 `p` 结构体中的 `runq` (可运行 Goroutine 队列) 和 `m` 结构体中关联的 `p`，可以推断出这是 Go 调度器的基础。

**代码示例：**

以下代码模拟了将一个 Goroutine 从 `_Gidle` 状态变为 `_Grunnable` 状态，并放入 P 的运行队列中：

```go
package main

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"unsafe"
)

// 模拟 runtime 中的部分结构
type guintptr uintptr
type p struct {
	runqhead uint32
	runqtail uint32
	runq     [256]guintptr
}
type g struct {
	atomicstatus atomic.Uint32
}

const (
	_Gidle     = 0
	_Grunnable = 1
)

func main() {
	// 模拟一个 P
	var pInstance p

	// 创建一个新的 Goroutine (模拟，实际的创建会更复杂)
	newG := &g{}
	newG.atomicstatus.Store(_Gidle)

	fmt.Printf("New G's initial status: %d (_Gidle: %d)\n", newG.atomicstatus.Load(), _Gidle)

	// 将 Goroutine 状态设置为可运行
	newG.atomicstatus.Store(_Grunnable)
	fmt.Printf("New G's status after setting to runnable: %d (_Grunnable: %d)\n", newG.atomicstatus.Load(), _Grunnable)

	// 模拟将 Goroutine 放入 P 的运行队列
	head := atomic.LoadUint32(&pInstance.runqhead)
	tail := atomic.LoadUint32(&pInstance.runqtail)

	if (tail+1)%uint32(len(pInstance.runq)) != head {
		pInstance.runq[tail] = guintptr(unsafe.Pointer(newG))
		atomic.StoreUint32(&pInstance.runqtail, (tail+1)%uint32(len(pInstance.runq)))
		fmt.Println("G added to P's run queue.")
	} else {
		fmt.Println("P's run queue is full.")
	}

	fmt.Printf("P's runqhead: %d, runqtail: %d\n", pInstance.runqhead, pInstance.runqtail)
}
```

**假设的输入与输出：**

运行上面的代码，输出可能如下：

```
New G's initial status: 0 (_Gidle: 0)
New G's status after setting to runnable: 1 (_Grunnable: 1)
G added to P's run queue.
P's runqhead: 0, runqtail: 1
```

**代码推理：特殊的指针类型 (guintptr, muintptr, puintptr)**

`guintptr`, `muintptr`, 和 `puintptr` 的存在是为了在某些特定的运行时操作中绕过 Go 的写屏障。写屏障是垃圾回收机制的一部分，用于跟踪对象之间的指针关系。但在某些底层操作中，例如在没有关联 P 的情况下修改 G 或 P 的指针，如果触发写屏障可能会导致不一致的状态或性能问题。

**代码示例：**

以下代码展示了如何使用 `guintptr` 来设置 `gobuf` 中的 `g` 字段，而无需触发写屏障（尽管在实际应用中，直接修改 `gobuf` 通常在汇编代码中完成）：

```go
package main

import (
	"fmt"
	"unsafe"
)

// 模拟 runtime 中的部分结构
type guintptr uintptr
type gobuf struct {
	sp uintptr
	pc uintptr
	g  guintptr
}
type g struct {
	id int
}

func main() {
	var gInstance g
	gInstance.id = 123

	var buf gobuf

	// 使用 guintptr 设置 gobuf 中的 g 字段
	buf.g = guintptr(unsafe.Pointer(&gInstance))

	// 从 gobuf 中取回 g
	gFromBuf := (*g)(unsafe.Pointer(buf.g))

	fmt.Printf("G's ID: %d\n", gFromBuf.id)
}
```

**假设的输入与输出：**

运行上面的代码，输出如下：

```
G's ID: 123
```

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常在 `os` 包和 `flag` 包中完成。然而，Go 运行时的一些行为可以通过环境变量来配置，例如 `GOMAXPROCS` 控制着 P 的数量，这会影响调度器的行为。这些环境变量在运行时启动时被读取，并影响这些数据结构的初始化。

**使用者易犯错的点：**

这段代码是 Go 运行时的核心部分，普通 Go 开发者通常不会直接与之交互。但是，理解这些结构对于深入理解 Go 的并发模型和性能调优至关重要。

一个与此相关的易错点是**不理解 `GOMAXPROCS` 的作用**。`GOMAXPROCS` 设置了可以同时执行用户 Go 代码的操作系统线程的最大数量。如果设置不当，可能会导致 CPU 资源利用率低下或过高的上下文切换开销。

**例子：**

假设在一个 8 核 CPU 的机器上，`GOMAXPROCS` 被设置为 1。这意味着只有一个 P 处于运行状态，即使有多个 Goroutine 处于可运行状态，也只有一个 Goroutine 能真正在某个时刻执行，这会限制并发性能。

**总结：**

这段 `go/src/runtime/runtime2.go` 的代码定义了 Go 运行时系统的核心数据结构，这些结构是 Goroutine 管理、调度、内存管理和同步的基础。它为理解 Go 语言的底层机制提供了重要的视角。虽然普通开发者不会直接修改这些代码，但理解这些概念对于编写高效、并发的 Go 程序至关重要。

### 提示词
```
这是路径为go/src/runtime/runtime2.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/chacha8rand"
	"internal/goarch"
	"internal/goexperiment"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

// defined constants
const (
	// G status
	//
	// Beyond indicating the general state of a G, the G status
	// acts like a lock on the goroutine's stack (and hence its
	// ability to execute user code).
	//
	// If you add to this list, add to the list
	// of "okay during garbage collection" status
	// in mgcmark.go too.
	//
	// TODO(austin): The _Gscan bit could be much lighter-weight.
	// For example, we could choose not to run _Gscanrunnable
	// goroutines found in the run queue, rather than CAS-looping
	// until they become _Grunnable. And transitions like
	// _Gscanwaiting -> _Gscanrunnable are actually okay because
	// they don't affect stack ownership.

	// _Gidle means this goroutine was just allocated and has not
	// yet been initialized.
	_Gidle = iota // 0

	// _Grunnable means this goroutine is on a run queue. It is
	// not currently executing user code. The stack is not owned.
	_Grunnable // 1

	// _Grunning means this goroutine may execute user code. The
	// stack is owned by this goroutine. It is not on a run queue.
	// It is assigned an M and a P (g.m and g.m.p are valid).
	_Grunning // 2

	// _Gsyscall means this goroutine is executing a system call.
	// It is not executing user code. The stack is owned by this
	// goroutine. It is not on a run queue. It is assigned an M.
	_Gsyscall // 3

	// _Gwaiting means this goroutine is blocked in the runtime.
	// It is not executing user code. It is not on a run queue,
	// but should be recorded somewhere (e.g., a channel wait
	// queue) so it can be ready()d when necessary. The stack is
	// not owned *except* that a channel operation may read or
	// write parts of the stack under the appropriate channel
	// lock. Otherwise, it is not safe to access the stack after a
	// goroutine enters _Gwaiting (e.g., it may get moved).
	_Gwaiting // 4

	// _Gmoribund_unused is currently unused, but hardcoded in gdb
	// scripts.
	_Gmoribund_unused // 5

	// _Gdead means this goroutine is currently unused. It may be
	// just exited, on a free list, or just being initialized. It
	// is not executing user code. It may or may not have a stack
	// allocated. The G and its stack (if any) are owned by the M
	// that is exiting the G or that obtained the G from the free
	// list.
	_Gdead // 6

	// _Genqueue_unused is currently unused.
	_Genqueue_unused // 7

	// _Gcopystack means this goroutine's stack is being moved. It
	// is not executing user code and is not on a run queue. The
	// stack is owned by the goroutine that put it in _Gcopystack.
	_Gcopystack // 8

	// _Gpreempted means this goroutine stopped itself for a
	// suspendG preemption. It is like _Gwaiting, but nothing is
	// yet responsible for ready()ing it. Some suspendG must CAS
	// the status to _Gwaiting to take responsibility for
	// ready()ing this G.
	_Gpreempted // 9

	// _Gscan combined with one of the above states other than
	// _Grunning indicates that GC is scanning the stack. The
	// goroutine is not executing user code and the stack is owned
	// by the goroutine that set the _Gscan bit.
	//
	// _Gscanrunning is different: it is used to briefly block
	// state transitions while GC signals the G to scan its own
	// stack. This is otherwise like _Grunning.
	//
	// atomicstatus&~Gscan gives the state the goroutine will
	// return to when the scan completes.
	_Gscan          = 0x1000
	_Gscanrunnable  = _Gscan + _Grunnable  // 0x1001
	_Gscanrunning   = _Gscan + _Grunning   // 0x1002
	_Gscansyscall   = _Gscan + _Gsyscall   // 0x1003
	_Gscanwaiting   = _Gscan + _Gwaiting   // 0x1004
	_Gscanpreempted = _Gscan + _Gpreempted // 0x1009
)

const (
	// P status

	// _Pidle means a P is not being used to run user code or the
	// scheduler. Typically, it's on the idle P list and available
	// to the scheduler, but it may just be transitioning between
	// other states.
	//
	// The P is owned by the idle list or by whatever is
	// transitioning its state. Its run queue is empty.
	_Pidle = iota

	// _Prunning means a P is owned by an M and is being used to
	// run user code or the scheduler. Only the M that owns this P
	// is allowed to change the P's status from _Prunning. The M
	// may transition the P to _Pidle (if it has no more work to
	// do), _Psyscall (when entering a syscall), or _Pgcstop (to
	// halt for the GC). The M may also hand ownership of the P
	// off directly to another M (e.g., to schedule a locked G).
	_Prunning

	// _Psyscall means a P is not running user code. It has
	// affinity to an M in a syscall but is not owned by it and
	// may be stolen by another M. This is similar to _Pidle but
	// uses lightweight transitions and maintains M affinity.
	//
	// Leaving _Psyscall must be done with a CAS, either to steal
	// or retake the P. Note that there's an ABA hazard: even if
	// an M successfully CASes its original P back to _Prunning
	// after a syscall, it must understand the P may have been
	// used by another M in the interim.
	_Psyscall

	// _Pgcstop means a P is halted for STW and owned by the M
	// that stopped the world. The M that stopped the world
	// continues to use its P, even in _Pgcstop. Transitioning
	// from _Prunning to _Pgcstop causes an M to release its P and
	// park.
	//
	// The P retains its run queue and startTheWorld will restart
	// the scheduler on Ps with non-empty run queues.
	_Pgcstop

	// _Pdead means a P is no longer used (GOMAXPROCS shrank). We
	// reuse Ps if GOMAXPROCS increases. A dead P is mostly
	// stripped of its resources, though a few things remain
	// (e.g., trace buffers).
	_Pdead
)

// Mutual exclusion locks.  In the uncontended case,
// as fast as spin locks (just a few user-level instructions),
// but on the contention path they sleep in the kernel.
// A zeroed Mutex is unlocked (no need to initialize each lock).
// Initialization is helpful for static lock ranking, but not required.
type mutex struct {
	// Empty struct if lock ranking is disabled, otherwise includes the lock rank
	lockRankStruct
	// Futex-based impl treats it as uint32 key,
	// while sema-based impl as M* waitm.
	// Used to be a union, but unions break precise GC.
	key uintptr
}

type funcval struct {
	fn uintptr
	// variable-size, fn-specific data here
}

type iface struct {
	tab  *itab
	data unsafe.Pointer
}

type eface struct {
	_type *_type
	data  unsafe.Pointer
}

func efaceOf(ep *any) *eface {
	return (*eface)(unsafe.Pointer(ep))
}

// The guintptr, muintptr, and puintptr are all used to bypass write barriers.
// It is particularly important to avoid write barriers when the current P has
// been released, because the GC thinks the world is stopped, and an
// unexpected write barrier would not be synchronized with the GC,
// which can lead to a half-executed write barrier that has marked the object
// but not queued it. If the GC skips the object and completes before the
// queuing can occur, it will incorrectly free the object.
//
// We tried using special assignment functions invoked only when not
// holding a running P, but then some updates to a particular memory
// word went through write barriers and some did not. This breaks the
// write barrier shadow checking mode, and it is also scary: better to have
// a word that is completely ignored by the GC than to have one for which
// only a few updates are ignored.
//
// Gs and Ps are always reachable via true pointers in the
// allgs and allp lists or (during allocation before they reach those lists)
// from stack variables.
//
// Ms are always reachable via true pointers either from allm or
// freem. Unlike Gs and Ps we do free Ms, so it's important that
// nothing ever hold an muintptr across a safe point.

// A guintptr holds a goroutine pointer, but typed as a uintptr
// to bypass write barriers. It is used in the Gobuf goroutine state
// and in scheduling lists that are manipulated without a P.
//
// The Gobuf.g goroutine pointer is almost always updated by assembly code.
// In one of the few places it is updated by Go code - func save - it must be
// treated as a uintptr to avoid a write barrier being emitted at a bad time.
// Instead of figuring out how to emit the write barriers missing in the
// assembly manipulation, we change the type of the field to uintptr,
// so that it does not require write barriers at all.
//
// Goroutine structs are published in the allg list and never freed.
// That will keep the goroutine structs from being collected.
// There is never a time that Gobuf.g's contain the only references
// to a goroutine: the publishing of the goroutine in allg comes first.
// Goroutine pointers are also kept in non-GC-visible places like TLS,
// so I can't see them ever moving. If we did want to start moving data
// in the GC, we'd need to allocate the goroutine structs from an
// alternate arena. Using guintptr doesn't make that problem any worse.
// Note that pollDesc.rg, pollDesc.wg also store g in uintptr form,
// so they would need to be updated too if g's start moving.
type guintptr uintptr

//go:nosplit
func (gp guintptr) ptr() *g { return (*g)(unsafe.Pointer(gp)) }

//go:nosplit
func (gp *guintptr) set(g *g) { *gp = guintptr(unsafe.Pointer(g)) }

//go:nosplit
func (gp *guintptr) cas(old, new guintptr) bool {
	return atomic.Casuintptr((*uintptr)(unsafe.Pointer(gp)), uintptr(old), uintptr(new))
}

//go:nosplit
func (gp *g) guintptr() guintptr {
	return guintptr(unsafe.Pointer(gp))
}

// setGNoWB performs *gp = new without a write barrier.
// For times when it's impractical to use a guintptr.
//
//go:nosplit
//go:nowritebarrier
func setGNoWB(gp **g, new *g) {
	(*guintptr)(unsafe.Pointer(gp)).set(new)
}

type puintptr uintptr

//go:nosplit
func (pp puintptr) ptr() *p { return (*p)(unsafe.Pointer(pp)) }

//go:nosplit
func (pp *puintptr) set(p *p) { *pp = puintptr(unsafe.Pointer(p)) }

// muintptr is a *m that is not tracked by the garbage collector.
//
// Because we do free Ms, there are some additional constrains on
// muintptrs:
//
//  1. Never hold an muintptr locally across a safe point.
//
//  2. Any muintptr in the heap must be owned by the M itself so it can
//     ensure it is not in use when the last true *m is released.
type muintptr uintptr

//go:nosplit
func (mp muintptr) ptr() *m { return (*m)(unsafe.Pointer(mp)) }

//go:nosplit
func (mp *muintptr) set(m *m) { *mp = muintptr(unsafe.Pointer(m)) }

// setMNoWB performs *mp = new without a write barrier.
// For times when it's impractical to use an muintptr.
//
//go:nosplit
//go:nowritebarrier
func setMNoWB(mp **m, new *m) {
	(*muintptr)(unsafe.Pointer(mp)).set(new)
}

type gobuf struct {
	// The offsets of sp, pc, and g are known to (hard-coded in) libmach.
	//
	// ctxt is unusual with respect to GC: it may be a
	// heap-allocated funcval, so GC needs to track it, but it
	// needs to be set and cleared from assembly, where it's
	// difficult to have write barriers. However, ctxt is really a
	// saved, live register, and we only ever exchange it between
	// the real register and the gobuf. Hence, we treat it as a
	// root during stack scanning, which means assembly that saves
	// and restores it doesn't need write barriers. It's still
	// typed as a pointer so that any other writes from Go get
	// write barriers.
	sp   uintptr
	pc   uintptr
	g    guintptr
	ctxt unsafe.Pointer
	ret  uintptr
	lr   uintptr
	bp   uintptr // for framepointer-enabled architectures
}

// sudog (pseudo-g) represents a g in a wait list, such as for sending/receiving
// on a channel.
//
// sudog is necessary because the g ↔ synchronization object relation
// is many-to-many. A g can be on many wait lists, so there may be
// many sudogs for one g; and many gs may be waiting on the same
// synchronization object, so there may be many sudogs for one object.
//
// sudogs are allocated from a special pool. Use acquireSudog and
// releaseSudog to allocate and free them.
type sudog struct {
	// The following fields are protected by the hchan.lock of the
	// channel this sudog is blocking on. shrinkstack depends on
	// this for sudogs involved in channel ops.

	g *g

	next *sudog
	prev *sudog
	elem unsafe.Pointer // data element (may point to stack)

	// The following fields are never accessed concurrently.
	// For channels, waitlink is only accessed by g.
	// For semaphores, all fields (including the ones above)
	// are only accessed when holding a semaRoot lock.

	acquiretime int64
	releasetime int64
	ticket      uint32

	// isSelect indicates g is participating in a select, so
	// g.selectDone must be CAS'd to win the wake-up race.
	isSelect bool

	// success indicates whether communication over channel c
	// succeeded. It is true if the goroutine was awoken because a
	// value was delivered over channel c, and false if awoken
	// because c was closed.
	success bool

	// waiters is a count of semaRoot waiting list other than head of list,
	// clamped to a uint16 to fit in unused space.
	// Only meaningful at the head of the list.
	// (If we wanted to be overly clever, we could store a high 16 bits
	// in the second entry in the list.)
	waiters uint16

	parent   *sudog // semaRoot binary tree
	waitlink *sudog // g.waiting list or semaRoot
	waittail *sudog // semaRoot
	c        *hchan // channel
}

type libcall struct {
	fn   uintptr
	n    uintptr // number of parameters
	args uintptr // parameters
	r1   uintptr // return values
	r2   uintptr
	err  uintptr // error number
}

// Stack describes a Go execution stack.
// The bounds of the stack are exactly [lo, hi),
// with no implicit data structures on either side.
type stack struct {
	lo uintptr
	hi uintptr
}

// heldLockInfo gives info on a held lock and the rank of that lock
type heldLockInfo struct {
	lockAddr uintptr
	rank     lockRank
}

type g struct {
	// Stack parameters.
	// stack describes the actual stack memory: [stack.lo, stack.hi).
	// stackguard0 is the stack pointer compared in the Go stack growth prologue.
	// It is stack.lo+StackGuard normally, but can be StackPreempt to trigger a preemption.
	// stackguard1 is the stack pointer compared in the //go:systemstack stack growth prologue.
	// It is stack.lo+StackGuard on g0 and gsignal stacks.
	// It is ~0 on other goroutine stacks, to trigger a call to morestackc (and crash).
	stack       stack   // offset known to runtime/cgo
	stackguard0 uintptr // offset known to liblink
	stackguard1 uintptr // offset known to liblink

	_panic    *_panic // innermost panic - offset known to liblink
	_defer    *_defer // innermost defer
	m         *m      // current m; offset known to arm liblink
	sched     gobuf
	syscallsp uintptr // if status==Gsyscall, syscallsp = sched.sp to use during gc
	syscallpc uintptr // if status==Gsyscall, syscallpc = sched.pc to use during gc
	syscallbp uintptr // if status==Gsyscall, syscallbp = sched.bp to use in fpTraceback
	stktopsp  uintptr // expected sp at top of stack, to check in traceback
	// param is a generic pointer parameter field used to pass
	// values in particular contexts where other storage for the
	// parameter would be difficult to find. It is currently used
	// in four ways:
	// 1. When a channel operation wakes up a blocked goroutine, it sets param to
	//    point to the sudog of the completed blocking operation.
	// 2. By gcAssistAlloc1 to signal back to its caller that the goroutine completed
	//    the GC cycle. It is unsafe to do so in any other way, because the goroutine's
	//    stack may have moved in the meantime.
	// 3. By debugCallWrap to pass parameters to a new goroutine because allocating a
	//    closure in the runtime is forbidden.
	// 4. When a panic is recovered and control returns to the respective frame,
	//    param may point to a savedOpenDeferState.
	param        unsafe.Pointer
	atomicstatus atomic.Uint32
	stackLock    uint32 // sigprof/scang lock; TODO: fold in to atomicstatus
	goid         uint64
	schedlink    guintptr
	waitsince    int64      // approx time when the g become blocked
	waitreason   waitReason // if status==Gwaiting

	preempt       bool // preemption signal, duplicates stackguard0 = stackpreempt
	preemptStop   bool // transition to _Gpreempted on preemption; otherwise, just deschedule
	preemptShrink bool // shrink stack at synchronous safe point

	// asyncSafePoint is set if g is stopped at an asynchronous
	// safe point. This means there are frames on the stack
	// without precise pointer information.
	asyncSafePoint bool

	paniconfault bool // panic (instead of crash) on unexpected fault address
	gcscandone   bool // g has scanned stack; protected by _Gscan bit in status
	throwsplit   bool // must not split stack
	// activeStackChans indicates that there are unlocked channels
	// pointing into this goroutine's stack. If true, stack
	// copying needs to acquire channel locks to protect these
	// areas of the stack.
	activeStackChans bool
	// parkingOnChan indicates that the goroutine is about to
	// park on a chansend or chanrecv. Used to signal an unsafe point
	// for stack shrinking.
	parkingOnChan atomic.Bool
	// inMarkAssist indicates whether the goroutine is in mark assist.
	// Used by the execution tracer.
	inMarkAssist bool
	coroexit     bool // argument to coroswitch_m

	raceignore    int8  // ignore race detection events
	nocgocallback bool  // whether disable callback from C
	tracking      bool  // whether we're tracking this G for sched latency statistics
	trackingSeq   uint8 // used to decide whether to track this G
	trackingStamp int64 // timestamp of when the G last started being tracked
	runnableTime  int64 // the amount of time spent runnable, cleared when running, only used when tracking
	lockedm       muintptr
	fipsIndicator uint8
	sig           uint32
	writebuf      []byte
	sigcode0      uintptr
	sigcode1      uintptr
	sigpc         uintptr
	parentGoid    uint64          // goid of goroutine that created this goroutine
	gopc          uintptr         // pc of go statement that created this goroutine
	ancestors     *[]ancestorInfo // ancestor information goroutine(s) that created this goroutine (only used if debug.tracebackancestors)
	startpc       uintptr         // pc of goroutine function
	racectx       uintptr
	waiting       *sudog         // sudog structures this g is waiting on (that have a valid elem ptr); in lock order
	cgoCtxt       []uintptr      // cgo traceback context
	labels        unsafe.Pointer // profiler labels
	timer         *timer         // cached timer for time.Sleep
	sleepWhen     int64          // when to sleep until
	selectDone    atomic.Uint32  // are we participating in a select and did someone win the race?

	// goroutineProfiled indicates the status of this goroutine's stack for the
	// current in-progress goroutine profile
	goroutineProfiled goroutineProfileStateHolder

	coroarg   *coro // argument during coroutine transfers
	syncGroup *synctestGroup

	// Per-G tracer state.
	trace gTraceState

	// Per-G GC state

	// gcAssistBytes is this G's GC assist credit in terms of
	// bytes allocated. If this is positive, then the G has credit
	// to allocate gcAssistBytes bytes without assisting. If this
	// is negative, then the G must correct this by performing
	// scan work. We track this in bytes to make it fast to update
	// and check for debt in the malloc hot path. The assist ratio
	// determines how this corresponds to scan work debt.
	gcAssistBytes int64
}

// gTrackingPeriod is the number of transitions out of _Grunning between
// latency tracking runs.
const gTrackingPeriod = 8

const (
	// tlsSlots is the number of pointer-sized slots reserved for TLS on some platforms,
	// like Windows.
	tlsSlots = 6
	tlsSize  = tlsSlots * goarch.PtrSize
)

// Values for m.freeWait.
const (
	freeMStack = 0 // M done, free stack and reference.
	freeMRef   = 1 // M done, free reference.
	freeMWait  = 2 // M still in use.
)

type m struct {
	g0      *g     // goroutine with scheduling stack
	morebuf gobuf  // gobuf arg to morestack
	divmod  uint32 // div/mod denominator for arm - known to liblink
	_       uint32 // align next field to 8 bytes

	// Fields not known to debuggers.
	procid          uint64            // for debuggers, but offset not hard-coded
	gsignal         *g                // signal-handling g
	goSigStack      gsignalStack      // Go-allocated signal handling stack
	sigmask         sigset            // storage for saved signal mask
	tls             [tlsSlots]uintptr // thread-local storage (for x86 extern register)
	mstartfn        func()
	curg            *g       // current running goroutine
	caughtsig       guintptr // goroutine running during fatal signal
	p               puintptr // attached p for executing go code (nil if not executing go code)
	nextp           puintptr
	oldp            puintptr // the p that was attached before executing a syscall
	id              int64
	mallocing       int32
	throwing        throwType
	preemptoff      string // if != "", keep curg running on this m
	locks           int32
	dying           int32
	profilehz       int32
	spinning        bool // m is out of work and is actively looking for work
	blocked         bool // m is blocked on a note
	newSigstack     bool // minit on C thread called sigaltstack
	printlock       int8
	incgo           bool          // m is executing a cgo call
	isextra         bool          // m is an extra m
	isExtraInC      bool          // m is an extra m that is not executing Go code
	isExtraInSig    bool          // m is an extra m in a signal handler
	freeWait        atomic.Uint32 // Whether it is safe to free g0 and delete m (one of freeMRef, freeMStack, freeMWait)
	needextram      bool
	g0StackAccurate bool // whether the g0 stack has accurate bounds
	traceback       uint8
	ncgocall        uint64        // number of cgo calls in total
	ncgo            int32         // number of cgo calls currently in progress
	cgoCallersUse   atomic.Uint32 // if non-zero, cgoCallers in use temporarily
	cgoCallers      *cgoCallers   // cgo traceback if crashing in cgo call
	park            note
	alllink         *m // on allm
	schedlink       muintptr
	lockedg         guintptr
	createstack     [32]uintptr // stack that created this thread, it's used for StackRecord.Stack0, so it must align with it.
	lockedExt       uint32      // tracking for external LockOSThread
	lockedInt       uint32      // tracking for internal lockOSThread
	mWaitList       mWaitList   // list of runtime lock waiters

	mLockProfile mLockProfile // fields relating to runtime.lock contention
	profStack    []uintptr    // used for memory/block/mutex stack traces

	// wait* are used to carry arguments from gopark into park_m, because
	// there's no stack to put them on. That is their sole purpose.
	waitunlockf          func(*g, unsafe.Pointer) bool
	waitlock             unsafe.Pointer
	waitTraceSkip        int
	waitTraceBlockReason traceBlockReason

	syscalltick uint32
	freelink    *m // on sched.freem
	trace       mTraceState

	// these are here because they are too large to be on the stack
	// of low-level NOSPLIT functions.
	libcall    libcall
	libcallpc  uintptr // for cpu profiler
	libcallsp  uintptr
	libcallg   guintptr
	winsyscall winlibcall // stores syscall parameters on windows

	vdsoSP uintptr // SP for traceback while in VDSO call (0 if not in call)
	vdsoPC uintptr // PC for traceback while in VDSO call

	// preemptGen counts the number of completed preemption
	// signals. This is used to detect when a preemption is
	// requested, but fails.
	preemptGen atomic.Uint32

	// Whether this is a pending preemption signal on this M.
	signalPending atomic.Uint32

	// pcvalue lookup cache
	pcvalueCache pcvalueCache

	dlogPerM

	mOS

	chacha8   chacha8rand.State
	cheaprand uint64

	// Up to 10 locks held by this m, maintained by the lock ranking code.
	locksHeldLen int
	locksHeld    [10]heldLockInfo

	// Size the runtime.m structure so it fits in the 2048-byte size class, and
	// not in the next-smallest (1792-byte) size class. That leaves the 11 low
	// bits of muintptr values available for flags, as required for
	// GOEXPERIMENT=spinbitmutex.
	_ [goexperiment.SpinbitMutexInt * 700 * (2 - goarch.PtrSize/4)]byte
}

type p struct {
	id          int32
	status      uint32 // one of pidle/prunning/...
	link        puintptr
	schedtick   uint32     // incremented on every scheduler call
	syscalltick uint32     // incremented on every system call
	sysmontick  sysmontick // last tick observed by sysmon
	m           muintptr   // back-link to associated m (nil if idle)
	mcache      *mcache
	pcache      pageCache
	raceprocctx uintptr

	deferpool    []*_defer // pool of available defer structs (see panic.go)
	deferpoolbuf [32]*_defer

	// Cache of goroutine ids, amortizes accesses to runtime·sched.goidgen.
	goidcache    uint64
	goidcacheend uint64

	// Queue of runnable goroutines. Accessed without lock.
	runqhead uint32
	runqtail uint32
	runq     [256]guintptr
	// runnext, if non-nil, is a runnable G that was ready'd by
	// the current G and should be run next instead of what's in
	// runq if there's time remaining in the running G's time
	// slice. It will inherit the time left in the current time
	// slice. If a set of goroutines is locked in a
	// communicate-and-wait pattern, this schedules that set as a
	// unit and eliminates the (potentially large) scheduling
	// latency that otherwise arises from adding the ready'd
	// goroutines to the end of the run queue.
	//
	// Note that while other P's may atomically CAS this to zero,
	// only the owner P can CAS it to a valid G.
	runnext guintptr

	// Available G's (status == Gdead)
	gFree struct {
		gList
		n int32
	}

	sudogcache []*sudog
	sudogbuf   [128]*sudog

	// Cache of mspan objects from the heap.
	mspancache struct {
		// We need an explicit length here because this field is used
		// in allocation codepaths where write barriers are not allowed,
		// and eliminating the write barrier/keeping it eliminated from
		// slice updates is tricky, more so than just managing the length
		// ourselves.
		len int
		buf [128]*mspan
	}

	// Cache of a single pinner object to reduce allocations from repeated
	// pinner creation.
	pinnerCache *pinner

	trace pTraceState

	palloc persistentAlloc // per-P to avoid mutex

	// Per-P GC state
	gcAssistTime         int64 // Nanoseconds in assistAlloc
	gcFractionalMarkTime int64 // Nanoseconds in fractional mark worker (atomic)

	// limiterEvent tracks events for the GC CPU limiter.
	limiterEvent limiterEvent

	// gcMarkWorkerMode is the mode for the next mark worker to run in.
	// That is, this is used to communicate with the worker goroutine
	// selected for immediate execution by
	// gcController.findRunnableGCWorker. When scheduling other goroutines,
	// this field must be set to gcMarkWorkerNotWorker.
	gcMarkWorkerMode gcMarkWorkerMode
	// gcMarkWorkerStartTime is the nanotime() at which the most recent
	// mark worker started.
	gcMarkWorkerStartTime int64

	// gcw is this P's GC work buffer cache. The work buffer is
	// filled by write barriers, drained by mutator assists, and
	// disposed on certain GC state transitions.
	gcw gcWork

	// wbBuf is this P's GC write barrier buffer.
	//
	// TODO: Consider caching this in the running G.
	wbBuf wbBuf

	runSafePointFn uint32 // if 1, run sched.safePointFn at next safe point

	// statsSeq is a counter indicating whether this P is currently
	// writing any stats. Its value is even when not, odd when it is.
	statsSeq atomic.Uint32

	// Timer heap.
	timers timers

	// maxStackScanDelta accumulates the amount of stack space held by
	// live goroutines (i.e. those eligible for stack scanning).
	// Flushed to gcController.maxStackScan once maxStackScanSlack
	// or -maxStackScanSlack is reached.
	maxStackScanDelta int64

	// gc-time statistics about current goroutines
	// Note that this differs from maxStackScan in that this
	// accumulates the actual stack observed to be used at GC time (hi - sp),
	// not an instantaneous measure of the total stack size that might need
	// to be scanned (hi - lo).
	scannedStackSize uint64 // stack size of goroutines scanned by this P
	scannedStacks    uint64 // number of goroutines scanned by this P

	// preempt is set to indicate that this P should be enter the
	// scheduler ASAP (regardless of what G is running on it).
	preempt bool

	// gcStopTime is the nanotime timestamp that this P last entered _Pgcstop.
	gcStopTime int64

	// Padding is no longer needed. False sharing is now not a worry because p is large enough
	// that its size class is an integer multiple of the cache line size (for any of our architectures).
}

type schedt struct {
	goidgen   atomic.Uint64
	lastpoll  atomic.Int64 // time of last network poll, 0 if currently polling
	pollUntil atomic.Int64 // time to which current poll is sleeping

	lock mutex

	// When increasing nmidle, nmidlelocked, nmsys, or nmfreed, be
	// sure to call checkdead().

	midle        muintptr // idle m's waiting for work
	nmidle       int32    // number of idle m's waiting for work
	nmidlelocked int32    // number of locked m's waiting for work
	mnext        int64    // number of m's that have been created and next M ID
	maxmcount    int32    // maximum number of m's allowed (or die)
	nmsys        int32    // number of system m's not counted for deadlock
	nmfreed      int64    // cumulative number of freed m's

	ngsys atomic.Int32 // number of system goroutines

	pidle        puintptr // idle p's
	npidle       atomic.Int32
	nmspinning   atomic.Int32  // See "Worker thread parking/unparking" comment in proc.go.
	needspinning atomic.Uint32 // See "Delicate dance" comment in proc.go. Boolean. Must hold sched.lock to set to 1.

	// Global runnable queue.
	runq     gQueue
	runqsize int32

	// disable controls selective disabling of the scheduler.
	//
	// Use schedEnableUser to control this.
	//
	// disable is protected by sched.lock.
	disable struct {
		// user disables scheduling of user goroutines.
		user     bool
		runnable gQueue // pending runnable Gs
		n        int32  // length of runnable
	}

	// Global cache of dead G's.
	gFree struct {
		lock    mutex
		stack   gList // Gs with stacks
		noStack gList // Gs without stacks
		n       int32
	}

	// Central cache of sudog structs.
	sudoglock  mutex
	sudogcache *sudog

	// Central pool of available defer structs.
	deferlock mutex
	deferpool *_defer

	// freem is the list of m's waiting to be freed when their
	// m.exited is set. Linked through m.freelink.
	freem *m

	gcwaiting  atomic.Bool // gc is waiting to run
	stopwait   int32
	stopnote   note
	sysmonwait atomic.Bool
	sysmonnote note

	// safePointFn should be called on each P at the next GC
	// safepoint if p.runSafePointFn is set.
	safePointFn   func(*p)
	safePointWait int32
	safePointNote note

	profilehz int32 // cpu profiling rate

	procresizetime int64 // nanotime() of last change to gomaxprocs
	totaltime      int64 // ∫gomaxprocs dt up to procresizetime

	// sysmonlock protects sysmon's actions on the runtime.
	//
	// Acquire and hold this mutex to block sysmon from interacting
	// with the rest of the runtime.
	sysmonlock mutex

	// timeToRun is a distribution of scheduling latencies, defined
	// as the sum of time a G spends in the _Grunnable state before
	// it transitions to _Grunning.
	timeToRun timeHistogram

	// idleTime is the total CPU time Ps have "spent" idle.
	//
	// Reset on each GC cycle.
	idleTime atomic.Int64

	// totalMutexWaitTime is the sum of time goroutines have spent in _Gwaiting
	// with a waitreason of the form waitReasonSync{RW,}Mutex{R,}Lock.
	totalMutexWaitTime atomic.Int64

	// stwStoppingTimeGC/Other are distributions of stop-the-world stopping
	// latencies, defined as the time taken by stopTheWorldWithSema to get
	// all Ps to stop. stwStoppingTimeGC covers all GC-related STWs,
	// stwStoppingTimeOther covers the others.
	stwStoppingTimeGC    timeHistogram
	stwStoppingTimeOther timeHistogram

	// stwTotalTimeGC/Other are distributions of stop-the-world total
	// latencies, defined as the total time from stopTheWorldWithSema to
	// startTheWorldWithSema. This is a superset of
	// stwStoppingTimeGC/Other. stwTotalTimeGC covers all GC-related STWs,
	// stwTotalTimeOther covers the others.
	stwTotalTimeGC    timeHistogram
	stwTotalTimeOther timeHistogram

	// totalRuntimeLockWaitTime (plus the value of lockWaitTime on each M in
	// allm) is the sum of time goroutines have spent in _Grunnable and with an
	// M, but waiting for locks within the runtime. This field stores the value
	//
```