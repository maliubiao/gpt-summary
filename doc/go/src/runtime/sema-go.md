Response:
Let's break down the thought process for analyzing the `sema.go` code.

1. **Understand the Core Purpose:** The initial comments are crucial. They explicitly state this isn't a general-purpose semaphore. Instead, it's a sleep/wakeup mechanism, similar in spirit to Linux futex but with simpler semantics. The key takeaway is the "paired sleep with single wakeup" guarantee, even with races. This immediately suggests it's a low-level building block for higher-level synchronization primitives.

2. **Identify Key Data Structures:** The code defines `semaRoot` and `semTable`. `semaRoot` contains the lock (`mutex`), a balanced tree (`treap`) of waiting goroutines (`sudog`), and a counter for waiters (`nwait`). The `treap` structure, with the comment about `golang.org/issue/17953`, hints at performance optimizations for cases with many goroutines waiting on the same address. `semTable` is an array of `semaRoot`, suggesting a sharded approach to reduce contention on a single lock. The `rootFor` method confirms this sharding based on the address being waited on.

3. **Analyze the Core Functions:** The functions `semacquire` and `semrelease` (and their variations with `1` suffix) are central.

    * **`semacquire` family:**  These functions are for acquiring (waiting). The logic involves a fast path (`cansemacquire`) and a slower path. The slower path involves creating a `sudog`, adding it to the `semaRoot`'s wait queue, and parking the goroutine. The `lifo` parameter in some variations suggests optimization for specific use cases like mutexes. The `profile` flags indicate integration with runtime profiling.

    * **`semrelease` family:** These are for releasing (waking up). The core logic is to increment the counter and, if there are waiters, dequeue one and wake it up. The `handoff` parameter suggests a performance optimization where the released goroutine directly hands off the processor to the woken goroutine.

4. **Trace Function Calls and Linknames:** The `//go:linkname` directives are extremely important. They expose these runtime functions to the `sync` and `internal/poll` packages. This confirms the initial hypothesis that this code implements low-level primitives used by higher-level synchronization. The listed "hall of shame" packages further underscores the unexpected external usage.

5. **Infer Functionality Based on Usage:**  The `//go:linkname` associations provide strong clues about what Go features are being implemented:

    * `sync_runtime_Semacquire`/`sync_runtime_Semrelease`: Implies a basic synchronization mechanism, likely the foundation for `sync.Mutex`.
    * `poll_runtime_Semacquire`/`poll_runtime_Semrelease`: Suggests this is also used for I/O multiplexing (like `select` or network polling).
    * `internal_sync_runtime_SemacquireMutex`: Strongly suggests the implementation of `sync.Mutex` itself.
    * `sync_runtime_SemacquireRWMutexR`/`sync_runtime_SemacquireRWMutex`: Points to the implementation of `sync.RWMutex` for both read and write locks.
    * `sync_runtime_SemacquireWaitGroup`:  Clearly indicates the implementation of `sync.WaitGroup`.

6. **Examine Supporting Functions:** Functions like `cansemacquire`, `queue`, `dequeue`, `readyWithTime`, and the rotation functions (`rotateLeft`, `rotateRight`) provide details about the implementation of the wait queue and the wakeup mechanism. The treap structure and its rotation functions indicate a balanced binary search tree for efficient management of waiters.

7. **Analyze `notifyList`:**  This distinct structure with its own set of functions (`notifyListAdd`, `notifyListWait`, `notifyListNotifyAll`, `notifyListNotifyOne`) clearly corresponds to the implementation of `sync.Cond`. The `wait` and `notify` ticket mechanism is key to its operation.

8. **Identify Potential Pitfalls:** The comments explicitly mention that these aren't traditional semaphores and shouldn't be used as such. The "paired sleep with single wakeup" constraint is crucial. The external usage via `linkname` also highlights a potential pitfall: changes to these internal functions can break external packages.

9. **Construct Examples:** Based on the inferred functionality, create simple Go code examples demonstrating the usage of `sync.Mutex`, `sync.RWMutex`, `sync.WaitGroup`, and `sync.Cond`. These examples should align with the identified `//go:linkname` associations.

10. **Address Specific Requirements:** Finally, ensure all parts of the prompt are addressed: listing functions, inferring Go features, providing code examples with input/output (even if the output is primarily about blocking), explaining command-line parameters (though none were directly in this code), and identifying common mistakes.

This systematic approach, moving from high-level understanding to detailed code analysis and then connecting it back to user-level features, allows for a comprehensive explanation of the `sema.go` file's functionality. The `//go:linkname` directives are the most direct and powerful clues in this particular case.
`go/src/runtime/sema.go` 文件是 Go 运行时系统中的一部分，它实现了用于 Goroutine 同步的底层原语，尤其是用于构建更高级同步机制的睡眠和唤醒功能。它并非传统意义上的信号量，而更像是一个优化的、针对特定 Go 并发场景的睡眠/唤醒机制。

以下是 `sema.go` 的主要功能：

1. **提供 Goroutine 的阻塞和唤醒机制:**  这是其核心功能。当 Goroutine 需要等待某个条件满足时，它可以调用 `semacquire` 来阻塞自己。当条件满足时，另一个 Goroutine 可以调用 `semrelease` 来唤醒等待的 Goroutine。

2. **实现基于地址的等待队列:**  `sema.go` 维护了一个全局的 `semtable`，它是一个哈希表，用于存储等待在特定内存地址上的 Goroutine。每个 `semtable` 的条目包含一个 `semaRoot`，它管理着等待在同一地址上的 Goroutine 队列。

3. **支持公平和非公平的唤醒策略:**  `semacquire1` 函数接受一个 `lifo` 参数，用于指定是否使用 LIFO (后进先出) 的方式添加到等待队列中。这影响了 `semrelease` 唤醒 Goroutine 的顺序。

4. **处理竞争条件下的唤醒:**  该实现考虑了唤醒操作可能在 Goroutine 进入睡眠之前发生的竞争情况。通过 `nwait` 计数器和 `cansemacquire` 函数的配合，确保即使唤醒先于睡眠，睡眠的 Goroutine 也能被正确唤醒或避免进入睡眠。

5. **用于构建更高级的同步原语:**  正如注释所说，`sema.go` 的目的是为其他同步原语（如 `sync.Mutex`, `sync.RWMutex`, `sync.Cond`, `sync.WaitGroup`）提供底层的睡眠和唤醒机制。

6. **提供性能优化:**  使用了两级列表结构（`semaRoot` 中的 `treap` 和每个 `sudog` 的 `waitlink`）来优化在高并发场景下，大量 Goroutine 等待在相同地址时的性能。`treap` 是一种平衡二叉搜索树，用于高效地查找和管理不同的等待地址。

7. **与运行时性能分析集成:**  `semacquire1` 函数接受 `semaProfileFlags` 参数，用于集成阻塞性能分析 (`semaBlockProfile`) 和互斥锁性能分析 (`semaMutexProfile`)。

8. **提供直接 Goroutine 交接 (Handoff) 优化:**  `semrelease1` 函数的 `handoff` 参数允许在唤醒 Goroutine 后，直接将当前 Goroutine 的时间片和运行权交给被唤醒的 Goroutine，从而减少调度开销，特别是在高度竞争的场景下。

**推理 Go 语言功能的实现:**

基于 `//go:linkname` 注释，我们可以推断出 `sema.go` 实现了以下 Go 语言功能：

* **`sync.Mutex`:** `internal_sync_runtime_SemacquireMutex` 函数被链接到 `internal/sync.runtime_SemacquireMutex`，这表明 `sema.go` 提供了 `sync.Mutex` 的底层实现，用于互斥锁的获取和释放。
* **`sync.RWMutex`:** `sync_runtime_SemacquireRWMutexR` 和 `sync_runtime_SemacquireRWMutex` 分别对应 `sync.RWMutex` 的读锁和写锁的获取。
* **`sync.WaitGroup`:** `sync_runtime_SemacquireWaitGroup` 用于 `sync.WaitGroup` 的等待操作。
* **`sync.Cond`:**  `notifyList` 结构体及其相关函数 (`notifyListAdd`, `notifyListWait`, `notifyListNotifyAll`, `notifyListNotifyOne`) 实现了 `sync.Cond` 的通知机制。
* **网络轮询 (Polling):** `poll_runtime_Semacquire` 和 `poll_runtime_Semrelease` 被链接到 `internal/poll` 包，说明 `sema.go` 也被用于网络 I/O 的多路复用机制中，例如 `select` 和网络连接的等待。

**Go 代码示例:**

以下示例演示了 `sync.Mutex` 的使用，其底层就可能使用了 `sema.go` 提供的功能。

```go
package main

import (
	"fmt"
	"sync"
	"time"
)

var (
	counter int
	mu      sync.Mutex
)

func increment() {
	mu.Lock()
	defer mu.Unlock()
	counter++
	fmt.Println("Counter incremented to:", counter)
}

func main() {
	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				increment()
				time.Sleep(time.Millisecond * 10)
			}
		}()
	}

	wg.Wait()
	fmt.Println("Final counter value:", counter)
}
```

**假设的输入与输出:**

在这个 `sync.Mutex` 的例子中，没有直接的
### 提示词
```
这是路径为go/src/runtime/sema.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Semaphore implementation exposed to Go.
// Intended use is provide a sleep and wakeup
// primitive that can be used in the contended case
// of other synchronization primitives.
// Thus it targets the same goal as Linux's futex,
// but it has much simpler semantics.
//
// That is, don't think of these as semaphores.
// Think of them as a way to implement sleep and wakeup
// such that every sleep is paired with a single wakeup,
// even if, due to races, the wakeup happens before the sleep.
//
// See Mullender and Cox, ``Semaphores in Plan 9,''
// https://swtch.com/semaphore.pdf

package runtime

import (
	"internal/cpu"
	"internal/runtime/atomic"
	"unsafe"
)

// Asynchronous semaphore for sync.Mutex.

// A semaRoot holds a balanced tree of sudog with distinct addresses (s.elem).
// Each of those sudog may in turn point (through s.waitlink) to a list
// of other sudogs waiting on the same address.
// The operations on the inner lists of sudogs with the same address
// are all O(1). The scanning of the top-level semaRoot list is O(log n),
// where n is the number of distinct addresses with goroutines blocked
// on them that hash to the given semaRoot.
// See golang.org/issue/17953 for a program that worked badly
// before we introduced the second level of list, and
// BenchmarkSemTable/OneAddrCollision/* for a benchmark that exercises this.
type semaRoot struct {
	lock  mutex
	treap *sudog        // root of balanced tree of unique waiters.
	nwait atomic.Uint32 // Number of waiters. Read w/o the lock.
}

var semtable semTable

// Prime to not correlate with any user patterns.
const semTabSize = 251

type semTable [semTabSize]struct {
	root semaRoot
	pad  [cpu.CacheLinePadSize - unsafe.Sizeof(semaRoot{})]byte
}

func (t *semTable) rootFor(addr *uint32) *semaRoot {
	return &t[(uintptr(unsafe.Pointer(addr))>>3)%semTabSize].root
}

// sync_runtime_Semacquire should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//   - github.com/sagernet/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname sync_runtime_Semacquire sync.runtime_Semacquire
func sync_runtime_Semacquire(addr *uint32) {
	semacquire1(addr, false, semaBlockProfile, 0, waitReasonSemacquire)
}

//go:linkname poll_runtime_Semacquire internal/poll.runtime_Semacquire
func poll_runtime_Semacquire(addr *uint32) {
	semacquire1(addr, false, semaBlockProfile, 0, waitReasonSemacquire)
}

// sync_runtime_Semrelease should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gvisor.dev/gvisor
//   - github.com/sagernet/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname sync_runtime_Semrelease sync.runtime_Semrelease
func sync_runtime_Semrelease(addr *uint32, handoff bool, skipframes int) {
	semrelease1(addr, handoff, skipframes)
}

//go:linkname internal_sync_runtime_SemacquireMutex internal/sync.runtime_SemacquireMutex
func internal_sync_runtime_SemacquireMutex(addr *uint32, lifo bool, skipframes int) {
	semacquire1(addr, lifo, semaBlockProfile|semaMutexProfile, skipframes, waitReasonSyncMutexLock)
}

//go:linkname sync_runtime_SemacquireRWMutexR sync.runtime_SemacquireRWMutexR
func sync_runtime_SemacquireRWMutexR(addr *uint32, lifo bool, skipframes int) {
	semacquire1(addr, lifo, semaBlockProfile|semaMutexProfile, skipframes, waitReasonSyncRWMutexRLock)
}

//go:linkname sync_runtime_SemacquireRWMutex sync.runtime_SemacquireRWMutex
func sync_runtime_SemacquireRWMutex(addr *uint32, lifo bool, skipframes int) {
	semacquire1(addr, lifo, semaBlockProfile|semaMutexProfile, skipframes, waitReasonSyncRWMutexLock)
}

//go:linkname sync_runtime_SemacquireWaitGroup sync.runtime_SemacquireWaitGroup
func sync_runtime_SemacquireWaitGroup(addr *uint32) {
	semacquire1(addr, false, semaBlockProfile, 0, waitReasonSyncWaitGroupWait)
}

//go:linkname poll_runtime_Semrelease internal/poll.runtime_Semrelease
func poll_runtime_Semrelease(addr *uint32) {
	semrelease(addr)
}

//go:linkname internal_sync_runtime_Semrelease internal/sync.runtime_Semrelease
func internal_sync_runtime_Semrelease(addr *uint32, handoff bool, skipframes int) {
	semrelease1(addr, handoff, skipframes)
}

func readyWithTime(s *sudog, traceskip int) {
	if s.releasetime != 0 {
		s.releasetime = cputicks()
	}
	goready(s.g, traceskip)
}

type semaProfileFlags int

const (
	semaBlockProfile semaProfileFlags = 1 << iota
	semaMutexProfile
)

// Called from runtime.
func semacquire(addr *uint32) {
	semacquire1(addr, false, 0, 0, waitReasonSemacquire)
}

func semacquire1(addr *uint32, lifo bool, profile semaProfileFlags, skipframes int, reason waitReason) {
	gp := getg()
	if gp != gp.m.curg {
		throw("semacquire not on the G stack")
	}

	// Easy case.
	if cansemacquire(addr) {
		return
	}

	// Harder case:
	//	increment waiter count
	//	try cansemacquire one more time, return if succeeded
	//	enqueue itself as a waiter
	//	sleep
	//	(waiter descriptor is dequeued by signaler)
	s := acquireSudog()
	root := semtable.rootFor(addr)
	t0 := int64(0)
	s.releasetime = 0
	s.acquiretime = 0
	s.ticket = 0
	if profile&semaBlockProfile != 0 && blockprofilerate > 0 {
		t0 = cputicks()
		s.releasetime = -1
	}
	if profile&semaMutexProfile != 0 && mutexprofilerate > 0 {
		if t0 == 0 {
			t0 = cputicks()
		}
		s.acquiretime = t0
	}
	for {
		lockWithRank(&root.lock, lockRankRoot)
		// Add ourselves to nwait to disable "easy case" in semrelease.
		root.nwait.Add(1)
		// Check cansemacquire to avoid missed wakeup.
		if cansemacquire(addr) {
			root.nwait.Add(-1)
			unlock(&root.lock)
			break
		}
		// Any semrelease after the cansemacquire knows we're waiting
		// (we set nwait above), so go to sleep.
		root.queue(addr, s, lifo)
		goparkunlock(&root.lock, reason, traceBlockSync, 4+skipframes)
		if s.ticket != 0 || cansemacquire(addr) {
			break
		}
	}
	if s.releasetime > 0 {
		blockevent(s.releasetime-t0, 3+skipframes)
	}
	releaseSudog(s)
}

func semrelease(addr *uint32) {
	semrelease1(addr, false, 0)
}

func semrelease1(addr *uint32, handoff bool, skipframes int) {
	root := semtable.rootFor(addr)
	atomic.Xadd(addr, 1)

	// Easy case: no waiters?
	// This check must happen after the xadd, to avoid a missed wakeup
	// (see loop in semacquire).
	if root.nwait.Load() == 0 {
		return
	}

	// Harder case: search for a waiter and wake it.
	lockWithRank(&root.lock, lockRankRoot)
	if root.nwait.Load() == 0 {
		// The count is already consumed by another goroutine,
		// so no need to wake up another goroutine.
		unlock(&root.lock)
		return
	}
	s, t0, tailtime := root.dequeue(addr)
	if s != nil {
		root.nwait.Add(-1)
	}
	unlock(&root.lock)
	if s != nil { // May be slow or even yield, so unlock first
		acquiretime := s.acquiretime
		if acquiretime != 0 {
			// Charge contention that this (delayed) unlock caused.
			// If there are N more goroutines waiting beyond the
			// one that's waking up, charge their delay as well, so that
			// contention holding up many goroutines shows up as
			// more costly than contention holding up a single goroutine.
			// It would take O(N) time to calculate how long each goroutine
			// has been waiting, so instead we charge avg(head-wait, tail-wait)*N.
			// head-wait is the longest wait and tail-wait is the shortest.
			// (When we do a lifo insertion, we preserve this property by
			// copying the old head's acquiretime into the inserted new head.
			// In that case the overall average may be slightly high, but that's fine:
			// the average of the ends is only an approximation to the actual
			// average anyway.)
			// The root.dequeue above changed the head and tail acquiretime
			// to the current time, so the next unlock will not re-count this contention.
			dt0 := t0 - acquiretime
			dt := dt0
			if s.waiters != 0 {
				dtail := t0 - tailtime
				dt += (dtail + dt0) / 2 * int64(s.waiters)
			}
			mutexevent(dt, 3+skipframes)
		}
		if s.ticket != 0 {
			throw("corrupted semaphore ticket")
		}
		if handoff && cansemacquire(addr) {
			s.ticket = 1
		}
		readyWithTime(s, 5+skipframes)
		if s.ticket == 1 && getg().m.locks == 0 {
			// Direct G handoff
			// readyWithTime has added the waiter G as runnext in the
			// current P; we now call the scheduler so that we start running
			// the waiter G immediately.
			// Note that waiter inherits our time slice: this is desirable
			// to avoid having a highly contended semaphore hog the P
			// indefinitely. goyield is like Gosched, but it emits a
			// "preempted" trace event instead and, more importantly, puts
			// the current G on the local runq instead of the global one.
			// We only do this in the starving regime (handoff=true), as in
			// the non-starving case it is possible for a different waiter
			// to acquire the semaphore while we are yielding/scheduling,
			// and this would be wasteful. We wait instead to enter starving
			// regime, and then we start to do direct handoffs of ticket and
			// P.
			// See issue 33747 for discussion.
			goyield()
		}
	}
}

func cansemacquire(addr *uint32) bool {
	for {
		v := atomic.Load(addr)
		if v == 0 {
			return false
		}
		if atomic.Cas(addr, v, v-1) {
			return true
		}
	}
}

// queue adds s to the blocked goroutines in semaRoot.
func (root *semaRoot) queue(addr *uint32, s *sudog, lifo bool) {
	s.g = getg()
	s.elem = unsafe.Pointer(addr)
	s.next = nil
	s.prev = nil
	s.waiters = 0

	var last *sudog
	pt := &root.treap
	for t := *pt; t != nil; t = *pt {
		if t.elem == unsafe.Pointer(addr) {
			// Already have addr in list.
			if lifo {
				// Substitute s in t's place in treap.
				*pt = s
				s.ticket = t.ticket
				s.acquiretime = t.acquiretime // preserve head acquiretime as oldest time
				s.parent = t.parent
				s.prev = t.prev
				s.next = t.next
				if s.prev != nil {
					s.prev.parent = s
				}
				if s.next != nil {
					s.next.parent = s
				}
				// Add t first in s's wait list.
				s.waitlink = t
				s.waittail = t.waittail
				if s.waittail == nil {
					s.waittail = t
				}
				s.waiters = t.waiters
				if s.waiters+1 != 0 {
					s.waiters++
				}
				t.parent = nil
				t.prev = nil
				t.next = nil
				t.waittail = nil
			} else {
				// Add s to end of t's wait list.
				if t.waittail == nil {
					t.waitlink = s
				} else {
					t.waittail.waitlink = s
				}
				t.waittail = s
				s.waitlink = nil
				if t.waiters+1 != 0 {
					t.waiters++
				}
			}
			return
		}
		last = t
		if uintptr(unsafe.Pointer(addr)) < uintptr(t.elem) {
			pt = &t.prev
		} else {
			pt = &t.next
		}
	}

	// Add s as new leaf in tree of unique addrs.
	// The balanced tree is a treap using ticket as the random heap priority.
	// That is, it is a binary tree ordered according to the elem addresses,
	// but then among the space of possible binary trees respecting those
	// addresses, it is kept balanced on average by maintaining a heap ordering
	// on the ticket: s.ticket <= both s.prev.ticket and s.next.ticket.
	// https://en.wikipedia.org/wiki/Treap
	// https://faculty.washington.edu/aragon/pubs/rst89.pdf
	//
	// s.ticket compared with zero in couple of places, therefore set lowest bit.
	// It will not affect treap's quality noticeably.
	s.ticket = cheaprand() | 1
	s.parent = last
	*pt = s

	// Rotate up into tree according to ticket (priority).
	for s.parent != nil && s.parent.ticket > s.ticket {
		if s.parent.prev == s {
			root.rotateRight(s.parent)
		} else {
			if s.parent.next != s {
				panic("semaRoot queue")
			}
			root.rotateLeft(s.parent)
		}
	}
}

// dequeue searches for and finds the first goroutine
// in semaRoot blocked on addr.
// If the sudog was being profiled, dequeue returns the time
// at which it was woken up as now. Otherwise now is 0.
// If there are additional entries in the wait list, dequeue
// returns tailtime set to the last entry's acquiretime.
// Otherwise tailtime is found.acquiretime.
func (root *semaRoot) dequeue(addr *uint32) (found *sudog, now, tailtime int64) {
	ps := &root.treap
	s := *ps
	for ; s != nil; s = *ps {
		if s.elem == unsafe.Pointer(addr) {
			goto Found
		}
		if uintptr(unsafe.Pointer(addr)) < uintptr(s.elem) {
			ps = &s.prev
		} else {
			ps = &s.next
		}
	}
	return nil, 0, 0

Found:
	now = int64(0)
	if s.acquiretime != 0 {
		now = cputicks()
	}
	if t := s.waitlink; t != nil {
		// Substitute t, also waiting on addr, for s in root tree of unique addrs.
		*ps = t
		t.ticket = s.ticket
		t.parent = s.parent
		t.prev = s.prev
		if t.prev != nil {
			t.prev.parent = t
		}
		t.next = s.next
		if t.next != nil {
			t.next.parent = t
		}
		if t.waitlink != nil {
			t.waittail = s.waittail
		} else {
			t.waittail = nil
		}
		t.waiters = s.waiters
		if t.waiters > 1 {
			t.waiters--
		}
		// Set head and tail acquire time to 'now',
		// because the caller will take care of charging
		// the delays before now for all entries in the list.
		t.acquiretime = now
		tailtime = s.waittail.acquiretime
		s.waittail.acquiretime = now
		s.waitlink = nil
		s.waittail = nil
	} else {
		// Rotate s down to be leaf of tree for removal, respecting priorities.
		for s.next != nil || s.prev != nil {
			if s.next == nil || s.prev != nil && s.prev.ticket < s.next.ticket {
				root.rotateRight(s)
			} else {
				root.rotateLeft(s)
			}
		}
		// Remove s, now a leaf.
		if s.parent != nil {
			if s.parent.prev == s {
				s.parent.prev = nil
			} else {
				s.parent.next = nil
			}
		} else {
			root.treap = nil
		}
		tailtime = s.acquiretime
	}
	s.parent = nil
	s.elem = nil
	s.next = nil
	s.prev = nil
	s.ticket = 0
	return s, now, tailtime
}

// rotateLeft rotates the tree rooted at node x.
// turning (x a (y b c)) into (y (x a b) c).
func (root *semaRoot) rotateLeft(x *sudog) {
	// p -> (x a (y b c))
	p := x.parent
	y := x.next
	b := y.prev

	y.prev = x
	x.parent = y
	x.next = b
	if b != nil {
		b.parent = x
	}

	y.parent = p
	if p == nil {
		root.treap = y
	} else if p.prev == x {
		p.prev = y
	} else {
		if p.next != x {
			throw("semaRoot rotateLeft")
		}
		p.next = y
	}
}

// rotateRight rotates the tree rooted at node y.
// turning (y (x a b) c) into (x a (y b c)).
func (root *semaRoot) rotateRight(y *sudog) {
	// p -> (y (x a b) c)
	p := y.parent
	x := y.prev
	b := x.next

	x.next = y
	y.parent = x
	y.prev = b
	if b != nil {
		b.parent = y
	}

	x.parent = p
	if p == nil {
		root.treap = x
	} else if p.prev == y {
		p.prev = x
	} else {
		if p.next != y {
			throw("semaRoot rotateRight")
		}
		p.next = x
	}
}

// notifyList is a ticket-based notification list used to implement sync.Cond.
//
// It must be kept in sync with the sync package.
type notifyList struct {
	// wait is the ticket number of the next waiter. It is atomically
	// incremented outside the lock.
	wait atomic.Uint32

	// notify is the ticket number of the next waiter to be notified. It can
	// be read outside the lock, but is only written to with lock held.
	//
	// Both wait & notify can wrap around, and such cases will be correctly
	// handled as long as their "unwrapped" difference is bounded by 2^31.
	// For this not to be the case, we'd need to have 2^31+ goroutines
	// blocked on the same condvar, which is currently not possible.
	notify uint32

	// List of parked waiters.
	lock mutex
	head *sudog
	tail *sudog
}

// less checks if a < b, considering a & b running counts that may overflow the
// 32-bit range, and that their "unwrapped" difference is always less than 2^31.
func less(a, b uint32) bool {
	return int32(a-b) < 0
}

// notifyListAdd adds the caller to a notify list such that it can receive
// notifications. The caller must eventually call notifyListWait to wait for
// such a notification, passing the returned ticket number.
//
//go:linkname notifyListAdd sync.runtime_notifyListAdd
func notifyListAdd(l *notifyList) uint32 {
	// This may be called concurrently, for example, when called from
	// sync.Cond.Wait while holding a RWMutex in read mode.
	return l.wait.Add(1) - 1
}

// notifyListWait waits for a notification. If one has been sent since
// notifyListAdd was called, it returns immediately. Otherwise, it blocks.
//
//go:linkname notifyListWait sync.runtime_notifyListWait
func notifyListWait(l *notifyList, t uint32) {
	lockWithRank(&l.lock, lockRankNotifyList)

	// Return right away if this ticket has already been notified.
	if less(t, l.notify) {
		unlock(&l.lock)
		return
	}

	// Enqueue itself.
	s := acquireSudog()
	s.g = getg()
	s.ticket = t
	s.releasetime = 0
	t0 := int64(0)
	if blockprofilerate > 0 {
		t0 = cputicks()
		s.releasetime = -1
	}
	if l.tail == nil {
		l.head = s
	} else {
		l.tail.next = s
	}
	l.tail = s
	goparkunlock(&l.lock, waitReasonSyncCondWait, traceBlockCondWait, 3)
	if t0 != 0 {
		blockevent(s.releasetime-t0, 2)
	}
	releaseSudog(s)
}

// notifyListNotifyAll notifies all entries in the list.
//
//go:linkname notifyListNotifyAll sync.runtime_notifyListNotifyAll
func notifyListNotifyAll(l *notifyList) {
	// Fast-path: if there are no new waiters since the last notification
	// we don't need to acquire the lock.
	if l.wait.Load() == atomic.Load(&l.notify) {
		return
	}

	// Pull the list out into a local variable, waiters will be readied
	// outside the lock.
	lockWithRank(&l.lock, lockRankNotifyList)
	s := l.head
	l.head = nil
	l.tail = nil

	// Update the next ticket to be notified. We can set it to the current
	// value of wait because any previous waiters are already in the list
	// or will notice that they have already been notified when trying to
	// add themselves to the list.
	atomic.Store(&l.notify, l.wait.Load())
	unlock(&l.lock)

	// Go through the local list and ready all waiters.
	for s != nil {
		next := s.next
		s.next = nil
		if s.g.syncGroup != nil && getg().syncGroup != s.g.syncGroup {
			println("semaphore wake of synctest goroutine", s.g.goid, "from outside bubble")
			panic("semaphore wake of synctest goroutine from outside bubble")
		}
		readyWithTime(s, 4)
		s = next
	}
}

// notifyListNotifyOne notifies one entry in the list.
//
//go:linkname notifyListNotifyOne sync.runtime_notifyListNotifyOne
func notifyListNotifyOne(l *notifyList) {
	// Fast-path: if there are no new waiters since the last notification
	// we don't need to acquire the lock at all.
	if l.wait.Load() == atomic.Load(&l.notify) {
		return
	}

	lockWithRank(&l.lock, lockRankNotifyList)

	// Re-check under the lock if we need to do anything.
	t := l.notify
	if t == l.wait.Load() {
		unlock(&l.lock)
		return
	}

	// Update the next notify ticket number.
	atomic.Store(&l.notify, t+1)

	// Try to find the g that needs to be notified.
	// If it hasn't made it to the list yet we won't find it,
	// but it won't park itself once it sees the new notify number.
	//
	// This scan looks linear but essentially always stops quickly.
	// Because g's queue separately from taking numbers,
	// there may be minor reorderings in the list, but we
	// expect the g we're looking for to be near the front.
	// The g has others in front of it on the list only to the
	// extent that it lost the race, so the iteration will not
	// be too long. This applies even when the g is missing:
	// it hasn't yet gotten to sleep and has lost the race to
	// the (few) other g's that we find on the list.
	for p, s := (*sudog)(nil), l.head; s != nil; p, s = s, s.next {
		if s.ticket == t {
			n := s.next
			if p != nil {
				p.next = n
			} else {
				l.head = n
			}
			if n == nil {
				l.tail = p
			}
			unlock(&l.lock)
			s.next = nil
			if s.g.syncGroup != nil && getg().syncGroup != s.g.syncGroup {
				println("semaphore wake of synctest goroutine", s.g.goid, "from outside bubble")
				panic("semaphore wake of synctest goroutine from outside bubble")
			}
			readyWithTime(s, 4)
			return
		}
	}
	unlock(&l.lock)
}

//go:linkname notifyListCheck sync.runtime_notifyListCheck
func notifyListCheck(sz uintptr) {
	if sz != unsafe.Sizeof(notifyList{}) {
		print("runtime: bad notifyList size - sync=", sz, " runtime=", unsafe.Sizeof(notifyList{}), "\n")
		throw("bad notifyList size")
	}
}

//go:linkname internal_sync_nanotime internal/sync.runtime_nanotime
func internal_sync_nanotime() int64 {
	return nanotime()
}
```