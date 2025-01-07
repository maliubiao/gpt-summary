Response:
Let's break down the thought process for analyzing this Go `select.go` code snippet.

**1. Understanding the Goal:**

The core request is to understand the functionality of this code, which is clearly related to Go's `select` statement. The prompt also asks for specific things like examples, potential errors, and command-line parameters.

**2. Initial Code Scan & Keywords:**

I'd first scan the code for keywords and structure. Things that immediately stand out are:

* `package runtime`:  This tells me it's a core part of the Go runtime, dealing with low-level operations.
* `// This file contains the implementation of Go select statements.` : This confirms the main purpose.
* `scase`: This struct likely represents a single case within a `select` statement. The comments mention the compiler knowing about it.
* `hchan`:  This is a well-known Go runtime type representing a channel. The interaction with `hchan` is central to `select`.
* `sellock`, `selunlock`:  These function names strongly suggest locking mechanisms related to `select`.
* `selectgo`: This function name screams "the core logic of `select`."
* `runtimeSelect`:  This seems to be a structure used when `select` is invoked through reflection.
* `debugSelect`:  A debugging flag.
* `raceenabled`, `msanenabled`, `asanenabled`: These are related to race detection and memory sanitizers, indicating this code needs to be thread-safe and memory-safe.

**3. Deconstructing `selectgo`:**

`selectgo` is clearly the heart of the implementation. I'd analyze its steps:

* **Initialization:** Setting up `scases`, `pollorder`, `lockorder`. The comments about stack allocation are important for understanding performance and potential limitations.
* **Permutation of Cases:** The `pollorder` shuffling using `cheaprandn` suggests a mechanism for fairness or preventing biases in selecting cases.
* **Sorting for Locking:** The heap sort on `lockorder` based on channel addresses (`c.sortkey()`) is crucial for preventing deadlocks when multiple channels are involved. Locking channels in a consistent order is a standard concurrency practice.
* **First Pass (Immediate Check):** Iterating through `pollorder` and checking for immediate send/receive opportunities (non-blocking cases).
* **Blocking Logic (if needed):** If no immediate case is ready and `block` is true:
    * Enqueueing the goroutine (`gp`) onto the wait queues of the involved channels. The `sudog` structure is key here, representing a waiting goroutine.
    * Parking the goroutine using `gopark`. The `selparkcommit` function looks like a cleanup/preparation step before parking.
* **Wake-up Handling:** When a channel operation makes the goroutine runnable again:
    * Dequeuing from unsuccessful channels.
    * Identifying the successful case.
* **Handling Successful Cases:**  Different logic for sends, receives (buffered and synchronous), and closed channels. The use of `typedmemmove` and `typedmemclr` suggests memory manipulation.
* **Unlocking:**  Crucially, unlocking the channels using `selunlock` after the operation.

**4. Identifying Key Concepts:**

From the `selectgo` analysis, several core concepts emerge:

* **Fairness:** The random permutation of `pollorder` aims for fairness.
* **Deadlock Prevention:** The sorted locking order is vital for preventing deadlocks.
* **Goroutine Waiting:** The `sudog` structure and the enqueueing/dequeueing mechanisms are how goroutines wait for channel operations.
* **Channel States:** The checks for `c.closed`, `c.qcount`, and `c.dataqsiz` show how `select` handles different channel states.
* **Memory Management:** The use of `typedmemmove` and related functions indicates careful handling of memory when sending/receiving data.

**5. Understanding Other Functions:**

* `sellock` and `selunlock`:  These implement the sorted locking and unlocking strategy. The comments in `selunlock` about potential race conditions after unlocking are important.
* `selparkcommit`: This seems to handle the transition of a goroutine to a parked state, managing stack shrinking and locking.
* `block`:  A simple function to put the goroutine into a permanent sleep.
* `reflect_rselect`: This is the entry point when `select` is used with reflection. It converts the reflection-based `runtimeSelect` structure into the internal `scase` format.

**6. Inferring Functionality and Examples:**

Based on the code, I can now deduce the core functionality: `select` allows a goroutine to wait on multiple channel operations and proceed with the first one that becomes ready.

I can then construct simple Go examples illustrating the key scenarios: sending, receiving, and the default case.

**7. Considering Error Points:**

The "send on closed channel" panic is explicitly handled in the code, making it a prime candidate for a common error. The subtle issue of potential data races if channels are not locked consistently (which the code addresses) is another important point.

**8. Command-Line Parameters:**

A quick search within the code reveals the `debugSelect`, `blockprofilerate`, `raceenabled`, `msanenabled`, and `asanenabled` constants/variables. While not strictly command-line *parameters* in the traditional sense for this specific file, they represent build-time or runtime configurations that affect `select`'s behavior, especially related to debugging and testing.

**9. Structuring the Answer:**

Finally, I organize the findings into a clear and structured answer, addressing each part of the prompt: functionality, examples, reasoning, potential errors, and command-line considerations. Using clear headings and code formatting improves readability.

**Self-Correction/Refinement:**

Initially, I might have focused too heavily on the individual functions without seeing the bigger picture of how they work together in the `selectgo` function. Realizing that `selectgo` is the central orchestrator is a key refinement. Also, paying attention to the comments, especially those explaining subtle concurrency details, is crucial for a deeper understanding. I might also initially miss the connection to reflection and then realize `reflect_rselect` provides that link.
这段代码是Go语言运行时（runtime）包中 `select.go` 文件的一部分，主要负责实现Go语言中的 `select` 语句。 `select` 语句允许一个 goroutine 同时等待多个 channel 操作，并在其中一个操作完成时继续执行。

**功能列举:**

1. **定义 `scase` 结构体:**  `scase` 结构体用于描述 `select` 语句中的一个 `case` 分支，包含关联的 channel (`c`) 和用于发送或接收的数据元素指针 (`elem`)。编译器会直接使用这个结构体的信息。
2. **定义常量 `debugSelect`:**  这是一个调试标志，用于在调试 `select` 语句时输出额外的日志信息。
3. **定义全局变量 `chansendpc` 和 `chanrecvpc`:** 这两个变量分别存储 `chansend` 和 `chanrecv` 函数的程序计数器 (PC)，用于在 race 检测中标记 channel 的发送和接收操作。
4. **`selectsetpc` 函数:**  用于设置程序计数器，通常在 race 检测启用时使用，记录 `select` 语句中每个 case 的调用位置。
5. **`sellock` 函数:**  负责对 `select` 语句中涉及的所有 channel 进行加锁。为了避免死锁，它会根据 channel 的地址顺序进行加锁。
6. **`selunlock` 函数:**  负责解锁 `sellock` 加锁的 channel。为了避免在解锁后访问可能被释放的内存，解锁顺序是加锁顺序的逆序，并且在解锁最后一个锁之后非常小心地避免访问与 `select` 操作相关的数据结构。
7. **`selparkcommit` 函数:**  在 goroutine 因为 `select` 语句而进入等待状态时被调用。它的作用是标记 goroutine 正在等待 channel 操作，并解锁 channel 上的锁。这个函数需要非常小心，不能访问 goroutine 的栈，因为它可能正在被其他线程收缩。
8. **`block` 函数:**  当 `select` 语句没有任何 `case` 或只有一个 `default` 分支时，会调用这个函数，使当前 goroutine 进入永久阻塞状态。
9. **`selectgo` 函数:**  这是实现 `select` 语句的核心函数。它接收一个 `scase` 数组，一个用于存储轮询顺序和锁定顺序的数组，以及发送和接收 case 的数量等参数。它会尝试执行其中一个可以立即完成的 channel 操作，或者将 goroutine 加入到相关 channel 的等待队列中，直到其中一个操作可以执行。
10. **`sortkey` 方法:**  为 `hchan` 类型定义了一个 `sortkey` 方法，返回 channel 的地址，用于 `sellock` 函数中的排序，以确保一致的加锁顺序。
11. **`runtimeSelect` 结构体和 `selectDir` 类型:**  这两个定义是为了支持通过反射 (reflection) 使用 `select` 语句。`runtimeSelect` 描述了一个反射的 `select` case，而 `selectDir` 枚举了 case 的类型（发送、接收、默认）。
12. **`reflect_rselect` 函数:**  当通过反射调用 `select` 时，会调用这个函数。它将 `runtimeSelect` 类型的 slice 转换为 `scase` 类型的 slice，然后调用 `selectgo` 执行 `select` 操作。
13. **`dequeueSudoG` 方法:**  为 `waitq` 类型定义了一个 `dequeueSudoG` 方法，用于从 channel 的等待队列中移除一个 `sudog` 结构体。

**`select` 语句的实现推理及代码示例:**

这段代码实现了 Go 语言的 `select` 语句，它允许 goroutine 同时等待多个 channel 操作。`select` 语句的行为如下：

1. **评估所有 case:**  `select` 语句会从上到下评估所有的 `case` 表达式。
2. **立即执行:** 如果其中一个 `case` 对应的 channel 操作可以立即执行（例如，从一个有数据的 channel 接收数据，或向一个有空位的 channel 发送数据），那么这个 `case` 就会被选中并执行。
3. **阻塞等待:** 如果没有 `case` 可以立即执行，并且没有 `default` 分支，那么 goroutine 将会阻塞，直到至少有一个 channel 操作可以执行。
4. **`default` 分支:** 如果有 `default` 分支，并且没有 `case` 可以立即执行，那么 `default` 分支会被选中并执行，goroutine 不会阻塞。
5. **随机选择:** 如果有多个 `case` 可以立即执行，Go 语言会随机选择一个执行。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	ch1 := make(chan string)
	ch2 := make(chan string)

	go func() {
		time.Sleep(1 * time.Second)
		ch1 <- "message from ch1"
	}()

	go func() {
		time.Sleep(2 * time.Second)
		ch2 <- "message from ch2"
	}()

	select {
	case msg1 := <-ch1:
		fmt.Println("received", msg1)
	case msg2 := <-ch2:
		fmt.Println("received", msg2)
	case <-time.After(3 * time.Second): // 超时处理
		fmt.Println("timeout")
	}

	fmt.Println("Done")
}
```

**假设输入与输出:**

在这个例子中，`ch1` 会在 1 秒后发送消息，`ch2` 会在 2 秒后发送消息。 `select` 语句会等待这两个 channel 上的接收操作，或者等待 3 秒超时。

**可能的输出：**

```
received message from ch1
Done
```

或者，如果运行环境负载较高，导致 goroutine 调度延迟，也可能输出：

```
received message from ch2
Done
```

如果两个 channel 几乎同时准备好，则输出结果是随机的。

如果将 `time.Sleep` 的时间都设置得超过 3 秒，则会输出：

```
timeout
Done
```

**代码推理:**

`selectgo` 函数会遍历 `scase` 数组，检查每个 channel 是否可以立即发送或接收。

* **第一阶段 (轮询):**  它会根据 `pollorder` 中随机排列的顺序检查 channel。如果发现一个 channel 可以立即操作（例如，接收 channel 有数据，发送 channel 有空位，或者 channel 已关闭），则会执行相应的操作并返回。
* **第二阶段 (加锁和等待):** 如果没有可以立即执行的 case，并且 `block` 参数为 `true`（通常 `select` 语句会阻塞），`selectgo` 会对所有涉及的 channel 加锁，并将当前的 goroutine (`gp`) 加入到不能立即操作的 channel 的等待队列中。然后调用 `gopark` 使 goroutine 进入休眠状态。
* **唤醒和处理:** 当某个 channel 上的操作变得可能时，等待在该 channel 上的 goroutine 会被唤醒。`selectgo` 会再次被调用，这次它会处理被选中的 `case`，并解锁所有 channel。

**使用者易犯错的点:**

1. **在 `select` 中使用 `nil` channel:**  尝试在 `select` 语句中使用 `nil` channel 会导致 goroutine 永久阻塞。 这是因为对 `nil` channel 的发送和接收操作会永远阻塞。

   ```go
   package main

   import "fmt"

   func main() {
       var ch chan int // ch is nil

       select {
       case <-ch: // 永远阻塞
           fmt.Println("received from nil channel")
       default:
           fmt.Println("default case")
       }
       fmt.Println("Done") // 如果没有 default，这行代码永远不会执行
   }
   ```

   **输出 (如果没有 `default`):** 程序会一直阻塞，没有输出。
   **输出 (如果有 `default`):**
   ```
   default case
   Done
   ```

2. **误以为 `select` 会并行处理所有 case:** `select` 语句只会执行第一个可以执行的 `case`，或者 `default` 分支。它不会并行处理所有的 `case`。

3. **在不需要阻塞的场景下使用 `select` 而不带 `default`:** 如果没有可以立即执行的 case，并且没有 `default` 分支，goroutine 会一直阻塞。在某些情况下，这可能不是期望的行为。

这段代码是 Go 语言并发模型的核心组成部分，理解它的实现原理对于编写高效且健壮的并发程序至关重要。

Prompt: 
```
这是路径为go/src/runtime/select.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

// This file contains the implementation of Go select statements.

import (
	"internal/abi"
	"internal/runtime/sys"
	"unsafe"
)

const debugSelect = false

// Select case descriptor.
// Known to compiler.
// Changes here must also be made in src/cmd/compile/internal/walk/select.go's scasetype.
type scase struct {
	c    *hchan         // chan
	elem unsafe.Pointer // data element
}

var (
	chansendpc = abi.FuncPCABIInternal(chansend)
	chanrecvpc = abi.FuncPCABIInternal(chanrecv)
)

func selectsetpc(pc *uintptr) {
	*pc = sys.GetCallerPC()
}

func sellock(scases []scase, lockorder []uint16) {
	var c *hchan
	for _, o := range lockorder {
		c0 := scases[o].c
		if c0 != c {
			c = c0
			lock(&c.lock)
		}
	}
}

func selunlock(scases []scase, lockorder []uint16) {
	// We must be very careful here to not touch sel after we have unlocked
	// the last lock, because sel can be freed right after the last unlock.
	// Consider the following situation.
	// First M calls runtime·park() in runtime·selectgo() passing the sel.
	// Once runtime·park() has unlocked the last lock, another M makes
	// the G that calls select runnable again and schedules it for execution.
	// When the G runs on another M, it locks all the locks and frees sel.
	// Now if the first M touches sel, it will access freed memory.
	for i := len(lockorder) - 1; i >= 0; i-- {
		c := scases[lockorder[i]].c
		if i > 0 && c == scases[lockorder[i-1]].c {
			continue // will unlock it on the next iteration
		}
		unlock(&c.lock)
	}
}

func selparkcommit(gp *g, _ unsafe.Pointer) bool {
	// There are unlocked sudogs that point into gp's stack. Stack
	// copying must lock the channels of those sudogs.
	// Set activeStackChans here instead of before we try parking
	// because we could self-deadlock in stack growth on a
	// channel lock.
	gp.activeStackChans = true
	// Mark that it's safe for stack shrinking to occur now,
	// because any thread acquiring this G's stack for shrinking
	// is guaranteed to observe activeStackChans after this store.
	gp.parkingOnChan.Store(false)
	// Make sure we unlock after setting activeStackChans and
	// unsetting parkingOnChan. The moment we unlock any of the
	// channel locks we risk gp getting readied by a channel operation
	// and so gp could continue running before everything before the
	// unlock is visible (even to gp itself).

	// This must not access gp's stack (see gopark). In
	// particular, it must not access the *hselect. That's okay,
	// because by the time this is called, gp.waiting has all
	// channels in lock order.
	var lastc *hchan
	for sg := gp.waiting; sg != nil; sg = sg.waitlink {
		if sg.c != lastc && lastc != nil {
			// As soon as we unlock the channel, fields in
			// any sudog with that channel may change,
			// including c and waitlink. Since multiple
			// sudogs may have the same channel, we unlock
			// only after we've passed the last instance
			// of a channel.
			unlock(&lastc.lock)
		}
		lastc = sg.c
	}
	if lastc != nil {
		unlock(&lastc.lock)
	}
	return true
}

func block() {
	gopark(nil, nil, waitReasonSelectNoCases, traceBlockForever, 1) // forever
}

// selectgo implements the select statement.
//
// cas0 points to an array of type [ncases]scase, and order0 points to
// an array of type [2*ncases]uint16 where ncases must be <= 65536.
// Both reside on the goroutine's stack (regardless of any escaping in
// selectgo).
//
// For race detector builds, pc0 points to an array of type
// [ncases]uintptr (also on the stack); for other builds, it's set to
// nil.
//
// selectgo returns the index of the chosen scase, which matches the
// ordinal position of its respective select{recv,send,default} call.
// Also, if the chosen scase was a receive operation, it reports whether
// a value was received.
func selectgo(cas0 *scase, order0 *uint16, pc0 *uintptr, nsends, nrecvs int, block bool) (int, bool) {
	gp := getg()
	if debugSelect {
		print("select: cas0=", cas0, "\n")
	}

	// NOTE: In order to maintain a lean stack size, the number of scases
	// is capped at 65536.
	cas1 := (*[1 << 16]scase)(unsafe.Pointer(cas0))
	order1 := (*[1 << 17]uint16)(unsafe.Pointer(order0))

	ncases := nsends + nrecvs
	scases := cas1[:ncases:ncases]
	pollorder := order1[:ncases:ncases]
	lockorder := order1[ncases:][:ncases:ncases]
	// NOTE: pollorder/lockorder's underlying array was not zero-initialized by compiler.

	// Even when raceenabled is true, there might be select
	// statements in packages compiled without -race (e.g.,
	// ensureSigM in runtime/signal_unix.go).
	var pcs []uintptr
	if raceenabled && pc0 != nil {
		pc1 := (*[1 << 16]uintptr)(unsafe.Pointer(pc0))
		pcs = pc1[:ncases:ncases]
	}
	casePC := func(casi int) uintptr {
		if pcs == nil {
			return 0
		}
		return pcs[casi]
	}

	var t0 int64
	if blockprofilerate > 0 {
		t0 = cputicks()
	}

	// The compiler rewrites selects that statically have
	// only 0 or 1 cases plus default into simpler constructs.
	// The only way we can end up with such small sel.ncase
	// values here is for a larger select in which most channels
	// have been nilled out. The general code handles those
	// cases correctly, and they are rare enough not to bother
	// optimizing (and needing to test).

	// generate permuted order
	norder := 0
	allSynctest := true
	for i := range scases {
		cas := &scases[i]

		// Omit cases without channels from the poll and lock orders.
		if cas.c == nil {
			cas.elem = nil // allow GC
			continue
		}

		if cas.c.synctest {
			if getg().syncGroup == nil {
				panic(plainError("select on synctest channel from outside bubble"))
			}
		} else {
			allSynctest = false
		}

		if cas.c.timer != nil {
			cas.c.timer.maybeRunChan()
		}

		j := cheaprandn(uint32(norder + 1))
		pollorder[norder] = pollorder[j]
		pollorder[j] = uint16(i)
		norder++
	}
	pollorder = pollorder[:norder]
	lockorder = lockorder[:norder]

	waitReason := waitReasonSelect
	if gp.syncGroup != nil && allSynctest {
		// Every channel selected on is in a synctest bubble,
		// so this goroutine will count as idle while selecting.
		waitReason = waitReasonSynctestSelect
	}

	// sort the cases by Hchan address to get the locking order.
	// simple heap sort, to guarantee n log n time and constant stack footprint.
	for i := range lockorder {
		j := i
		// Start with the pollorder to permute cases on the same channel.
		c := scases[pollorder[i]].c
		for j > 0 && scases[lockorder[(j-1)/2]].c.sortkey() < c.sortkey() {
			k := (j - 1) / 2
			lockorder[j] = lockorder[k]
			j = k
		}
		lockorder[j] = pollorder[i]
	}
	for i := len(lockorder) - 1; i >= 0; i-- {
		o := lockorder[i]
		c := scases[o].c
		lockorder[i] = lockorder[0]
		j := 0
		for {
			k := j*2 + 1
			if k >= i {
				break
			}
			if k+1 < i && scases[lockorder[k]].c.sortkey() < scases[lockorder[k+1]].c.sortkey() {
				k++
			}
			if c.sortkey() < scases[lockorder[k]].c.sortkey() {
				lockorder[j] = lockorder[k]
				j = k
				continue
			}
			break
		}
		lockorder[j] = o
	}

	if debugSelect {
		for i := 0; i+1 < len(lockorder); i++ {
			if scases[lockorder[i]].c.sortkey() > scases[lockorder[i+1]].c.sortkey() {
				print("i=", i, " x=", lockorder[i], " y=", lockorder[i+1], "\n")
				throw("select: broken sort")
			}
		}
	}

	// lock all the channels involved in the select
	sellock(scases, lockorder)

	var (
		sg     *sudog
		c      *hchan
		k      *scase
		sglist *sudog
		sgnext *sudog
		qp     unsafe.Pointer
		nextp  **sudog
	)

	// pass 1 - look for something already waiting
	var casi int
	var cas *scase
	var caseSuccess bool
	var caseReleaseTime int64 = -1
	var recvOK bool
	for _, casei := range pollorder {
		casi = int(casei)
		cas = &scases[casi]
		c = cas.c

		if casi >= nsends {
			sg = c.sendq.dequeue()
			if sg != nil {
				goto recv
			}
			if c.qcount > 0 {
				goto bufrecv
			}
			if c.closed != 0 {
				goto rclose
			}
		} else {
			if raceenabled {
				racereadpc(c.raceaddr(), casePC(casi), chansendpc)
			}
			if c.closed != 0 {
				goto sclose
			}
			sg = c.recvq.dequeue()
			if sg != nil {
				goto send
			}
			if c.qcount < c.dataqsiz {
				goto bufsend
			}
		}
	}

	if !block {
		selunlock(scases, lockorder)
		casi = -1
		goto retc
	}

	// pass 2 - enqueue on all chans
	if gp.waiting != nil {
		throw("gp.waiting != nil")
	}
	nextp = &gp.waiting
	for _, casei := range lockorder {
		casi = int(casei)
		cas = &scases[casi]
		c = cas.c
		sg := acquireSudog()
		sg.g = gp
		sg.isSelect = true
		// No stack splits between assigning elem and enqueuing
		// sg on gp.waiting where copystack can find it.
		sg.elem = cas.elem
		sg.releasetime = 0
		if t0 != 0 {
			sg.releasetime = -1
		}
		sg.c = c
		// Construct waiting list in lock order.
		*nextp = sg
		nextp = &sg.waitlink

		if casi < nsends {
			c.sendq.enqueue(sg)
		} else {
			c.recvq.enqueue(sg)
		}

		if c.timer != nil {
			blockTimerChan(c)
		}
	}

	// wait for someone to wake us up
	gp.param = nil
	// Signal to anyone trying to shrink our stack that we're about
	// to park on a channel. The window between when this G's status
	// changes and when we set gp.activeStackChans is not safe for
	// stack shrinking.
	gp.parkingOnChan.Store(true)
	gopark(selparkcommit, nil, waitReason, traceBlockSelect, 1)
	gp.activeStackChans = false

	sellock(scases, lockorder)

	gp.selectDone.Store(0)
	sg = (*sudog)(gp.param)
	gp.param = nil

	// pass 3 - dequeue from unsuccessful chans
	// otherwise they stack up on quiet channels
	// record the successful case, if any.
	// We singly-linked up the SudoGs in lock order.
	casi = -1
	cas = nil
	caseSuccess = false
	sglist = gp.waiting
	// Clear all elem before unlinking from gp.waiting.
	for sg1 := gp.waiting; sg1 != nil; sg1 = sg1.waitlink {
		sg1.isSelect = false
		sg1.elem = nil
		sg1.c = nil
	}
	gp.waiting = nil

	for _, casei := range lockorder {
		k = &scases[casei]
		if k.c.timer != nil {
			unblockTimerChan(k.c)
		}
		if sg == sglist {
			// sg has already been dequeued by the G that woke us up.
			casi = int(casei)
			cas = k
			caseSuccess = sglist.success
			if sglist.releasetime > 0 {
				caseReleaseTime = sglist.releasetime
			}
		} else {
			c = k.c
			if int(casei) < nsends {
				c.sendq.dequeueSudoG(sglist)
			} else {
				c.recvq.dequeueSudoG(sglist)
			}
		}
		sgnext = sglist.waitlink
		sglist.waitlink = nil
		releaseSudog(sglist)
		sglist = sgnext
	}

	if cas == nil {
		throw("selectgo: bad wakeup")
	}

	c = cas.c

	if debugSelect {
		print("wait-return: cas0=", cas0, " c=", c, " cas=", cas, " send=", casi < nsends, "\n")
	}

	if casi < nsends {
		if !caseSuccess {
			goto sclose
		}
	} else {
		recvOK = caseSuccess
	}

	if raceenabled {
		if casi < nsends {
			raceReadObjectPC(c.elemtype, cas.elem, casePC(casi), chansendpc)
		} else if cas.elem != nil {
			raceWriteObjectPC(c.elemtype, cas.elem, casePC(casi), chanrecvpc)
		}
	}
	if msanenabled {
		if casi < nsends {
			msanread(cas.elem, c.elemtype.Size_)
		} else if cas.elem != nil {
			msanwrite(cas.elem, c.elemtype.Size_)
		}
	}
	if asanenabled {
		if casi < nsends {
			asanread(cas.elem, c.elemtype.Size_)
		} else if cas.elem != nil {
			asanwrite(cas.elem, c.elemtype.Size_)
		}
	}

	selunlock(scases, lockorder)
	goto retc

bufrecv:
	// can receive from buffer
	if raceenabled {
		if cas.elem != nil {
			raceWriteObjectPC(c.elemtype, cas.elem, casePC(casi), chanrecvpc)
		}
		racenotify(c, c.recvx, nil)
	}
	if msanenabled && cas.elem != nil {
		msanwrite(cas.elem, c.elemtype.Size_)
	}
	if asanenabled && cas.elem != nil {
		asanwrite(cas.elem, c.elemtype.Size_)
	}
	recvOK = true
	qp = chanbuf(c, c.recvx)
	if cas.elem != nil {
		typedmemmove(c.elemtype, cas.elem, qp)
	}
	typedmemclr(c.elemtype, qp)
	c.recvx++
	if c.recvx == c.dataqsiz {
		c.recvx = 0
	}
	c.qcount--
	selunlock(scases, lockorder)
	goto retc

bufsend:
	// can send to buffer
	if raceenabled {
		racenotify(c, c.sendx, nil)
		raceReadObjectPC(c.elemtype, cas.elem, casePC(casi), chansendpc)
	}
	if msanenabled {
		msanread(cas.elem, c.elemtype.Size_)
	}
	if asanenabled {
		asanread(cas.elem, c.elemtype.Size_)
	}
	typedmemmove(c.elemtype, chanbuf(c, c.sendx), cas.elem)
	c.sendx++
	if c.sendx == c.dataqsiz {
		c.sendx = 0
	}
	c.qcount++
	selunlock(scases, lockorder)
	goto retc

recv:
	// can receive from sleeping sender (sg)
	recv(c, sg, cas.elem, func() { selunlock(scases, lockorder) }, 2)
	if debugSelect {
		print("syncrecv: cas0=", cas0, " c=", c, "\n")
	}
	recvOK = true
	goto retc

rclose:
	// read at end of closed channel
	selunlock(scases, lockorder)
	recvOK = false
	if cas.elem != nil {
		typedmemclr(c.elemtype, cas.elem)
	}
	if raceenabled {
		raceacquire(c.raceaddr())
	}
	goto retc

send:
	// can send to a sleeping receiver (sg)
	if raceenabled {
		raceReadObjectPC(c.elemtype, cas.elem, casePC(casi), chansendpc)
	}
	if msanenabled {
		msanread(cas.elem, c.elemtype.Size_)
	}
	if asanenabled {
		asanread(cas.elem, c.elemtype.Size_)
	}
	send(c, sg, cas.elem, func() { selunlock(scases, lockorder) }, 2)
	if debugSelect {
		print("syncsend: cas0=", cas0, " c=", c, "\n")
	}
	goto retc

retc:
	if caseReleaseTime > 0 {
		blockevent(caseReleaseTime-t0, 1)
	}
	return casi, recvOK

sclose:
	// send on closed channel
	selunlock(scases, lockorder)
	panic(plainError("send on closed channel"))
}

func (c *hchan) sortkey() uintptr {
	return uintptr(unsafe.Pointer(c))
}

// A runtimeSelect is a single case passed to rselect.
// This must match ../reflect/value.go:/runtimeSelect
type runtimeSelect struct {
	dir selectDir
	typ unsafe.Pointer // channel type (not used here)
	ch  *hchan         // channel
	val unsafe.Pointer // ptr to data (SendDir) or ptr to receive buffer (RecvDir)
}

// These values must match ../reflect/value.go:/SelectDir.
type selectDir int

const (
	_             selectDir = iota
	selectSend              // case Chan <- Send
	selectRecv              // case <-Chan:
	selectDefault           // default
)

//go:linkname reflect_rselect reflect.rselect
func reflect_rselect(cases []runtimeSelect) (int, bool) {
	if len(cases) == 0 {
		block()
	}
	sel := make([]scase, len(cases))
	orig := make([]int, len(cases))
	nsends, nrecvs := 0, 0
	dflt := -1
	for i, rc := range cases {
		var j int
		switch rc.dir {
		case selectDefault:
			dflt = i
			continue
		case selectSend:
			j = nsends
			nsends++
		case selectRecv:
			nrecvs++
			j = len(cases) - nrecvs
		}

		sel[j] = scase{c: rc.ch, elem: rc.val}
		orig[j] = i
	}

	// Only a default case.
	if nsends+nrecvs == 0 {
		return dflt, false
	}

	// Compact sel and orig if necessary.
	if nsends+nrecvs < len(cases) {
		copy(sel[nsends:], sel[len(cases)-nrecvs:])
		copy(orig[nsends:], orig[len(cases)-nrecvs:])
	}

	order := make([]uint16, 2*(nsends+nrecvs))
	var pc0 *uintptr
	if raceenabled {
		pcs := make([]uintptr, nsends+nrecvs)
		for i := range pcs {
			selectsetpc(&pcs[i])
		}
		pc0 = &pcs[0]
	}

	chosen, recvOK := selectgo(&sel[0], &order[0], pc0, nsends, nrecvs, dflt == -1)

	// Translate chosen back to caller's ordering.
	if chosen < 0 {
		chosen = dflt
	} else {
		chosen = orig[chosen]
	}
	return chosen, recvOK
}

func (q *waitq) dequeueSudoG(sgp *sudog) {
	x := sgp.prev
	y := sgp.next
	if x != nil {
		if y != nil {
			// middle of queue
			x.next = y
			y.prev = x
			sgp.next = nil
			sgp.prev = nil
			return
		}
		// end of queue
		x.next = nil
		q.last = x
		sgp.prev = nil
		return
	}
	if y != nil {
		// start of queue
		y.prev = nil
		q.first = y
		sgp.next = nil
		return
	}

	// x==y==nil. Either sgp is the only element in the queue,
	// or it has already been removed. Use q.first to disambiguate.
	if q.first == sgp {
		q.first = nil
		q.last = nil
	}
}

"""



```