Response:
Let's break down the thought process to generate the answer.

1. **Understanding the Request:** The core request is to analyze the provided Go code snippet from `runtime/chan.go` and explain its functionality. Specifically, it asks for:
    * Listing of functionalities.
    * Deduction of the broader Go feature it implements (with code examples).
    * Explanation of code reasoning (with input/output examples).
    * Details on command-line parameter handling (if applicable).
    * Common mistakes users might make.

2. **Initial Scan and Identification of Key Structures:**  The first step is to quickly scan the code and identify the central data structures and functions. The `hchan` struct is immediately prominent, along with the `chansend`, `chanrecv`, `makechan`, and `closechan` functions. The comments and variable names within `hchan` (like `qcount`, `dataqsiz`, `buf`, `sendq`, `recvq`) strongly suggest this code relates to Go's channels.

3. **Focusing on `hchan`:** The `hchan` struct is the heart of the implementation. Analyzing its fields provides a wealth of information about the channel's internal workings:
    * `qcount`, `dataqsiz`, `buf`:  These clearly relate to the channel's buffer and its size.
    * `elemsize`, `elemtype`:  These indicate the type and size of the data stored in the channel.
    * `sendx`, `recvx`:  These look like indices for a circular buffer.
    * `recvq`, `sendq`: These are `waitq` structures, suggesting queues for goroutines waiting to send or receive.
    * `closed`: A flag indicating the channel's closed state.
    * `lock`: A mutex for protecting the channel's state.

4. **Analyzing Key Functions:**  Next, examine the key functions:
    * `makechan`:  This function's name and parameters (`t *chantype`, `size int`) clearly indicate it's responsible for creating channels. The logic involving memory allocation for the buffer confirms this.
    * `chansend`:  The parameters (`c *hchan`, `elem unsafe.Pointer`, `block bool`) and the function's logic (checking for waiting receivers, buffer space, and blocking) point to the implementation of the send operation (`<-`).
    * `chanrecv`: Similar to `chansend`, the parameters and logic (checking for waiting senders, buffer data, and blocking) suggest the receive operation (`->`).
    * `closechan`: The name and logic clearly indicate it's for closing channels, and the code iterates through and wakes up waiting senders and receivers.

5. **Deducing the Go Feature:**  Based on the identified structures and functions, the deduction that this code implements Go channels is straightforward. The core functionalities of creating, sending to, receiving from, and closing channels are all present.

6. **Providing Code Examples:**  To illustrate the functionality, simple Go code snippets demonstrating channel creation, sending, and receiving are necessary. It's important to include both buffered and unbuffered channel examples to showcase different aspects. Examples of closing channels and handling closed channel behavior are also relevant.

7. **Reasoning about the Code (Input/Output):** For key functions like `chansend` and `chanrecv`, explain the control flow based on different channel states (empty, full, closed) and the `block` parameter. Providing hypothetical input and expected output for these scenarios makes the explanation clearer. For example:
    * `chansend` on a full buffered channel without `block`: Input: a channel and a value. Output: `false` (send failed).
    * `chanrecv` on an empty channel with `block`: Input: a channel. Output: The goroutine will block.

8. **Command-Line Parameters:**  A quick review of the code reveals no direct handling of command-line parameters within this specific snippet. Therefore, it's appropriate to state that there are no command-line parameters handled.

9. **Common Mistakes:** Think about how developers typically misuse channels. Common mistakes include:
    * Sending to a closed channel (panic).
    * Receiving from a closed channel (returns zero value).
    * Unbuffered channels and deadlock (where both sender and receiver are blocked indefinitely).

10. **Structuring the Answer:**  Organize the information logically using the headings provided in the prompt. Start with the functionalities, then the feature implementation, followed by code reasoning, command-line arguments, and finally, common mistakes. Use clear and concise language.

11. **Refinement and Review:** After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure that the code examples are correct and that the explanations are easy to understand. Double-check for any inconsistencies or omissions. For example, ensure to mention the role of the mutex in protecting the channel's state and preventing race conditions. Also, highlight the distinction between buffered and unbuffered channels in the explanations.
这段代码是 Go 语言运行时（runtime）中关于 **channel（通道）** 实现的核心部分。它定义了 channel 的数据结构和相关操作。

**功能列举:**

1. **定义 Channel 数据结构 (`hchan`)**:  定义了 `hchan` 结构体，用于表示一个 channel。这个结构体包含了 channel 的缓冲区、元素大小、等待队列、锁等关键信息。
2. **创建 Channel (`makechan`, `makechan64`, `reflect_makechan`)**: 提供了创建 channel 的函数，可以指定 channel 的元素类型和缓冲区大小。`makechan` 是内部使用的创建函数，`makechan64` 允许使用 `int64` 指定大小，`reflect_makechan` 用于反射创建 channel。
3. **发送数据到 Channel (`chansend`, `chansend1`, `selectnbsend`, `reflect_chansend`)**:  实现了向 channel 发送数据的操作。
    * `chansend`:  是发送操作的核心函数，处理阻塞和非阻塞的发送。
    * `chansend1`: 是编译后的 `ch <- value` 语句的入口。
    * `selectnbsend`: 用于 `select` 语句中的非阻塞发送。
    * `reflect_chansend`: 用于反射调用发送操作。
4. **从 Channel 接收数据 (`chanrecv`, `chanrecv1`, `chanrecv2`, `selectnbrecv`, `reflect_chanrecv`)**: 实现了从 channel 接收数据的操作。
    * `chanrecv`: 是接收操作的核心函数，处理阻塞和非阻塞的接收。
    * `chanrecv1`: 是编译后的 `value <- ch` 语句的入口（忽略接收状态）。
    * `chanrecv2`: 是编译后的 `value, ok <- ch` 语句的入口（包含接收状态）。
    * `selectnbrecv`: 用于 `select` 语句中的非阻塞接收。
    * `reflect_chanrecv`: 用于反射调用接收操作。
5. **关闭 Channel (`closechan`, `reflect_chanclose`)**:  提供了关闭 channel 的功能。关闭 channel 后，不能再向其发送数据，但仍然可以接收数据直到缓冲区为空。
6. **获取 Channel 长度和容量 (`chanlen`, `chancap`, `reflect_chanlen`, `reflectlite_chanlen`, `reflect_chancap`)**:  提供了获取 channel 当前已缓冲数据量和容量的函数。
7. **管理等待队列 (`waitq`, `enqueue`, `dequeue`)**:  定义了 `waitq` 结构体和相关方法，用于管理等待发送或接收的 Goroutine 队列。
8. **辅助函数**: 提供了一些辅助函数，如 `chanbuf` (获取缓冲区指定位置的指针), `full` (判断 channel 是否已满), `empty` (判断 channel 是否为空), `send` (执行发送操作), `recv` (执行接收操作), `sendDirect`, `recvDirect` (用于无缓冲 channel 的直接发送/接收), `timerchandrain` (清空定时器 channel 的缓冲区), `chanparkcommit` (用于 Goroutine 在 channel 上阻塞时的处理), `racesync`, `racenotify` (用于 race detector)。

**Go 语言功能实现：Channel**

这段代码是 Go 语言中 **goroutine 之间进行同步和通信** 的核心机制—— **channel** 的底层实现。

**Go 代码举例说明:**

```go
package main

import "fmt"

func main() {
	// 创建一个可以传递 int 类型的 channel，缓冲区大小为 0 (无缓冲)
	ch := make(chan int)

	// 启动一个 Goroutine 向 channel 发送数据
	go func() {
		fmt.Println("准备发送数据...")
		ch <- 10 // 发送数据到 channel，由于是无缓冲，会阻塞直到有接收者
		fmt.Println("数据已发送")
	}()

	// 从 channel 接收数据
	fmt.Println("准备接收数据...")
	receivedData := <-ch // 从 channel 接收数据，由于 channel 中没有数据，会阻塞直到有发送者
	fmt.Println("接收到的数据:", receivedData)
}
```

**假设的输入与输出:**

在这个例子中，没有直接的外部输入。输出是程序执行的结果。

* **输出:**
```
准备发送数据...
准备接收数据...
接收到的数据: 10
数据已发送
```

**代码推理:**

1. **`ch := make(chan int)`**:  调用 `makechan` 函数（通过 `reflect_makechan` 或直接调用）创建一个 `hchan` 结构体实例。由于没有指定缓冲区大小，或者指定大小为 0，所以创建的是一个无缓冲 channel。
2. **`ch <- 10`**:  调用 `chansend` 函数尝试向 channel 发送数据 `10`。
    * 由于是无缓冲 channel，并且当前没有 Goroutine 在等待接收，`chansend` 会将当前的 Goroutine 加入到 channel 的 `sendq` (发送等待队列) 并使其阻塞 (`gopark`)。
3. **`receivedData := <-ch`**: 调用 `chanrecv` 函数尝试从 channel 接收数据。
    * 由于 channel 中没有数据，`chanrecv` 会检查是否有 Goroutine 在 `sendq` 中等待发送。
    * 发现等待发送的 Goroutine (上面发送数据的 Goroutine)，`chanrecv` 会将发送者 Goroutine 从 `sendq` 中取出，并将发送的数据 (10) 直接传递给接收者 Goroutine。
    * 接收者 Goroutine 被唤醒 (`goready`)，并将接收到的数据赋值给 `receivedData`。
    * 发送者 Goroutine 也被唤醒。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。Go 语言处理命令行参数通常使用 `os` 包中的 `Args` 变量或 `flag` 包。

**使用者易犯错的点:**

1. **向已关闭的 Channel 发送数据:**

   ```go
   ch := make(chan int)
   close(ch)
   ch <- 10 // panic: send on closed channel
   ```
   **错误原因:**  一旦 channel 被关闭，就不能再向其发送数据。

2. **从已关闭的 Channel 接收数据，但未检查 Channel 是否已关闭:**

   ```go
   ch := make(chan int, 1)
   ch <- 10
   close(ch)
   data := <-ch // 接收到 10
   data = <-ch // 接收到 channel 元素类型的零值 (0 for int)
   data = <-ch // 接收到 channel 元素类型的零值 (0 for int)
   // ... 如果不检查 channel 是否关闭，可能会误认为接收到了有效数据
   data, ok := <-ch // 使用双返回值可以检查 channel 是否已关闭
   fmt.Println(data, ok) // 输出: 0 false
   ```
   **错误原因:** 从已关闭的 channel 接收数据会一直成功，直到缓冲区为空，之后会接收到 channel 元素类型的零值。如果不检查第二个返回值 `ok`，可能会误以为接收到了有效数据。

3. **死锁 (Deadlock) 在无缓冲 Channel 中:**

   ```go
   package main

   func main() {
       ch := make(chan int)
       ch <- 10 // 阻塞，因为没有接收者
       // 没有其他 Goroutine 从 ch 接收数据，导致程序死锁
   }
   ```

   ```go
   package main

   func main() {
       ch := make(chan int)
       go func() {
           received := <-ch // 阻塞等待接收
           println(received)
       }()
       ch <- 10 // 主 Goroutine 阻塞等待发送，但接收的 Goroutine 也在阻塞等待接收
       // 两个 Goroutine 都在等待对方，导致死锁
   }
   ```
   **错误原因:**  在无缓冲 channel 中，发送者必须等待接收者准备好接收，反之亦然。如果两个或多个 Goroutine 互相等待对方操作 channel，就会发生死锁。

4. **在 `select` 语句中使用 `nil` Channel:**

   ```go
   var ch chan int
   select {
   case <-ch: // 永远阻塞
       println("received")
   default:
       println("default")
   }
   ```
   **错误原因:**  对 `nil` channel 的发送和接收操作会永远阻塞。在 `select` 语句中，`nil` channel 的 case 会被忽略，除非所有其他 case 也都阻塞，此时会执行 `default` case（如果存在）。如果没有 `default` case，`select` 语句也会永远阻塞。

理解这些易犯的错误可以帮助开发者更安全有效地使用 Go 语言的 channel 进行并发编程。

Prompt: 
```
这是路径为go/src/runtime/chan.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

// This file contains the implementation of Go channels.

// Invariants:
//  At least one of c.sendq and c.recvq is empty,
//  except for the case of an unbuffered channel with a single goroutine
//  blocked on it for both sending and receiving using a select statement,
//  in which case the length of c.sendq and c.recvq is limited only by the
//  size of the select statement.
//
// For buffered channels, also:
//  c.qcount > 0 implies that c.recvq is empty.
//  c.qcount < c.dataqsiz implies that c.sendq is empty.

import (
	"internal/abi"
	"internal/runtime/atomic"
	"internal/runtime/math"
	"internal/runtime/sys"
	"unsafe"
)

const (
	maxAlign  = 8
	hchanSize = unsafe.Sizeof(hchan{}) + uintptr(-int(unsafe.Sizeof(hchan{}))&(maxAlign-1))
	debugChan = false
)

type hchan struct {
	qcount   uint           // total data in the queue
	dataqsiz uint           // size of the circular queue
	buf      unsafe.Pointer // points to an array of dataqsiz elements
	elemsize uint16
	synctest bool // true if created in a synctest bubble
	closed   uint32
	timer    *timer // timer feeding this chan
	elemtype *_type // element type
	sendx    uint   // send index
	recvx    uint   // receive index
	recvq    waitq  // list of recv waiters
	sendq    waitq  // list of send waiters

	// lock protects all fields in hchan, as well as several
	// fields in sudogs blocked on this channel.
	//
	// Do not change another G's status while holding this lock
	// (in particular, do not ready a G), as this can deadlock
	// with stack shrinking.
	lock mutex
}

type waitq struct {
	first *sudog
	last  *sudog
}

//go:linkname reflect_makechan reflect.makechan
func reflect_makechan(t *chantype, size int) *hchan {
	return makechan(t, size)
}

func makechan64(t *chantype, size int64) *hchan {
	if int64(int(size)) != size {
		panic(plainError("makechan: size out of range"))
	}

	return makechan(t, int(size))
}

func makechan(t *chantype, size int) *hchan {
	elem := t.Elem

	// compiler checks this but be safe.
	if elem.Size_ >= 1<<16 {
		throw("makechan: invalid channel element type")
	}
	if hchanSize%maxAlign != 0 || elem.Align_ > maxAlign {
		throw("makechan: bad alignment")
	}

	mem, overflow := math.MulUintptr(elem.Size_, uintptr(size))
	if overflow || mem > maxAlloc-hchanSize || size < 0 {
		panic(plainError("makechan: size out of range"))
	}

	// Hchan does not contain pointers interesting for GC when elements stored in buf do not contain pointers.
	// buf points into the same allocation, elemtype is persistent.
	// SudoG's are referenced from their owning thread so they can't be collected.
	// TODO(dvyukov,rlh): Rethink when collector can move allocated objects.
	var c *hchan
	switch {
	case mem == 0:
		// Queue or element size is zero.
		c = (*hchan)(mallocgc(hchanSize, nil, true))
		// Race detector uses this location for synchronization.
		c.buf = c.raceaddr()
	case !elem.Pointers():
		// Elements do not contain pointers.
		// Allocate hchan and buf in one call.
		c = (*hchan)(mallocgc(hchanSize+mem, nil, true))
		c.buf = add(unsafe.Pointer(c), hchanSize)
	default:
		// Elements contain pointers.
		c = new(hchan)
		c.buf = mallocgc(mem, elem, true)
	}

	c.elemsize = uint16(elem.Size_)
	c.elemtype = elem
	c.dataqsiz = uint(size)
	if getg().syncGroup != nil {
		c.synctest = true
	}
	lockInit(&c.lock, lockRankHchan)

	if debugChan {
		print("makechan: chan=", c, "; elemsize=", elem.Size_, "; dataqsiz=", size, "\n")
	}
	return c
}

// chanbuf(c, i) is pointer to the i'th slot in the buffer.
//
// chanbuf should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/fjl/memsize
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname chanbuf
func chanbuf(c *hchan, i uint) unsafe.Pointer {
	return add(c.buf, uintptr(i)*uintptr(c.elemsize))
}

// full reports whether a send on c would block (that is, the channel is full).
// It uses a single word-sized read of mutable state, so although
// the answer is instantaneously true, the correct answer may have changed
// by the time the calling function receives the return value.
func full(c *hchan) bool {
	// c.dataqsiz is immutable (never written after the channel is created)
	// so it is safe to read at any time during channel operation.
	if c.dataqsiz == 0 {
		// Assumes that a pointer read is relaxed-atomic.
		return c.recvq.first == nil
	}
	// Assumes that a uint read is relaxed-atomic.
	return c.qcount == c.dataqsiz
}

// entry point for c <- x from compiled code.
//
//go:nosplit
func chansend1(c *hchan, elem unsafe.Pointer) {
	chansend(c, elem, true, sys.GetCallerPC())
}

/*
 * generic single channel send/recv
 * If block is not nil,
 * then the protocol will not
 * sleep but return if it could
 * not complete.
 *
 * sleep can wake up with g.param == nil
 * when a channel involved in the sleep has
 * been closed.  it is easiest to loop and re-run
 * the operation; we'll see that it's now closed.
 */
func chansend(c *hchan, ep unsafe.Pointer, block bool, callerpc uintptr) bool {
	if c == nil {
		if !block {
			return false
		}
		gopark(nil, nil, waitReasonChanSendNilChan, traceBlockForever, 2)
		throw("unreachable")
	}

	if debugChan {
		print("chansend: chan=", c, "\n")
	}

	if raceenabled {
		racereadpc(c.raceaddr(), callerpc, abi.FuncPCABIInternal(chansend))
	}

	if c.synctest && getg().syncGroup == nil {
		panic(plainError("send on synctest channel from outside bubble"))
	}

	// Fast path: check for failed non-blocking operation without acquiring the lock.
	//
	// After observing that the channel is not closed, we observe that the channel is
	// not ready for sending. Each of these observations is a single word-sized read
	// (first c.closed and second full()).
	// Because a closed channel cannot transition from 'ready for sending' to
	// 'not ready for sending', even if the channel is closed between the two observations,
	// they imply a moment between the two when the channel was both not yet closed
	// and not ready for sending. We behave as if we observed the channel at that moment,
	// and report that the send cannot proceed.
	//
	// It is okay if the reads are reordered here: if we observe that the channel is not
	// ready for sending and then observe that it is not closed, that implies that the
	// channel wasn't closed during the first observation. However, nothing here
	// guarantees forward progress. We rely on the side effects of lock release in
	// chanrecv() and closechan() to update this thread's view of c.closed and full().
	if !block && c.closed == 0 && full(c) {
		return false
	}

	var t0 int64
	if blockprofilerate > 0 {
		t0 = cputicks()
	}

	lock(&c.lock)

	if c.closed != 0 {
		unlock(&c.lock)
		panic(plainError("send on closed channel"))
	}

	if sg := c.recvq.dequeue(); sg != nil {
		// Found a waiting receiver. We pass the value we want to send
		// directly to the receiver, bypassing the channel buffer (if any).
		send(c, sg, ep, func() { unlock(&c.lock) }, 3)
		return true
	}

	if c.qcount < c.dataqsiz {
		// Space is available in the channel buffer. Enqueue the element to send.
		qp := chanbuf(c, c.sendx)
		if raceenabled {
			racenotify(c, c.sendx, nil)
		}
		typedmemmove(c.elemtype, qp, ep)
		c.sendx++
		if c.sendx == c.dataqsiz {
			c.sendx = 0
		}
		c.qcount++
		unlock(&c.lock)
		return true
	}

	if !block {
		unlock(&c.lock)
		return false
	}

	// Block on the channel. Some receiver will complete our operation for us.
	gp := getg()
	mysg := acquireSudog()
	mysg.releasetime = 0
	if t0 != 0 {
		mysg.releasetime = -1
	}
	// No stack splits between assigning elem and enqueuing mysg
	// on gp.waiting where copystack can find it.
	mysg.elem = ep
	mysg.waitlink = nil
	mysg.g = gp
	mysg.isSelect = false
	mysg.c = c
	gp.waiting = mysg
	gp.param = nil
	c.sendq.enqueue(mysg)
	// Signal to anyone trying to shrink our stack that we're about
	// to park on a channel. The window between when this G's status
	// changes and when we set gp.activeStackChans is not safe for
	// stack shrinking.
	gp.parkingOnChan.Store(true)
	reason := waitReasonChanSend
	if c.synctest {
		reason = waitReasonSynctestChanSend
	}
	gopark(chanparkcommit, unsafe.Pointer(&c.lock), reason, traceBlockChanSend, 2)
	// Ensure the value being sent is kept alive until the
	// receiver copies it out. The sudog has a pointer to the
	// stack object, but sudogs aren't considered as roots of the
	// stack tracer.
	KeepAlive(ep)

	// someone woke us up.
	if mysg != gp.waiting {
		throw("G waiting list is corrupted")
	}
	gp.waiting = nil
	gp.activeStackChans = false
	closed := !mysg.success
	gp.param = nil
	if mysg.releasetime > 0 {
		blockevent(mysg.releasetime-t0, 2)
	}
	mysg.c = nil
	releaseSudog(mysg)
	if closed {
		if c.closed == 0 {
			throw("chansend: spurious wakeup")
		}
		panic(plainError("send on closed channel"))
	}
	return true
}

// send processes a send operation on an empty channel c.
// The value ep sent by the sender is copied to the receiver sg.
// The receiver is then woken up to go on its merry way.
// Channel c must be empty and locked.  send unlocks c with unlockf.
// sg must already be dequeued from c.
// ep must be non-nil and point to the heap or the caller's stack.
func send(c *hchan, sg *sudog, ep unsafe.Pointer, unlockf func(), skip int) {
	if c.synctest && sg.g.syncGroup != getg().syncGroup {
		unlockf()
		panic(plainError("send on synctest channel from outside bubble"))
	}
	if raceenabled {
		if c.dataqsiz == 0 {
			racesync(c, sg)
		} else {
			// Pretend we go through the buffer, even though
			// we copy directly. Note that we need to increment
			// the head/tail locations only when raceenabled.
			racenotify(c, c.recvx, nil)
			racenotify(c, c.recvx, sg)
			c.recvx++
			if c.recvx == c.dataqsiz {
				c.recvx = 0
			}
			c.sendx = c.recvx // c.sendx = (c.sendx+1) % c.dataqsiz
		}
	}
	if sg.elem != nil {
		sendDirect(c.elemtype, sg, ep)
		sg.elem = nil
	}
	gp := sg.g
	unlockf()
	gp.param = unsafe.Pointer(sg)
	sg.success = true
	if sg.releasetime != 0 {
		sg.releasetime = cputicks()
	}
	goready(gp, skip+1)
}

// timerchandrain removes all elements in channel c's buffer.
// It reports whether any elements were removed.
// Because it is only intended for timers, it does not
// handle waiting senders at all (all timer channels
// use non-blocking sends to fill the buffer).
func timerchandrain(c *hchan) bool {
	// Note: Cannot use empty(c) because we are called
	// while holding c.timer.sendLock, and empty(c) will
	// call c.timer.maybeRunChan, which will deadlock.
	// We are emptying the channel, so we only care about
	// the count, not about potentially filling it up.
	if atomic.Loaduint(&c.qcount) == 0 {
		return false
	}
	lock(&c.lock)
	any := false
	for c.qcount > 0 {
		any = true
		typedmemclr(c.elemtype, chanbuf(c, c.recvx))
		c.recvx++
		if c.recvx == c.dataqsiz {
			c.recvx = 0
		}
		c.qcount--
	}
	unlock(&c.lock)
	return any
}

// Sends and receives on unbuffered or empty-buffered channels are the
// only operations where one running goroutine writes to the stack of
// another running goroutine. The GC assumes that stack writes only
// happen when the goroutine is running and are only done by that
// goroutine. Using a write barrier is sufficient to make up for
// violating that assumption, but the write barrier has to work.
// typedmemmove will call bulkBarrierPreWrite, but the target bytes
// are not in the heap, so that will not help. We arrange to call
// memmove and typeBitsBulkBarrier instead.

func sendDirect(t *_type, sg *sudog, src unsafe.Pointer) {
	// src is on our stack, dst is a slot on another stack.

	// Once we read sg.elem out of sg, it will no longer
	// be updated if the destination's stack gets copied (shrunk).
	// So make sure that no preemption points can happen between read & use.
	dst := sg.elem
	typeBitsBulkBarrier(t, uintptr(dst), uintptr(src), t.Size_)
	// No need for cgo write barrier checks because dst is always
	// Go memory.
	memmove(dst, src, t.Size_)
}

func recvDirect(t *_type, sg *sudog, dst unsafe.Pointer) {
	// dst is on our stack or the heap, src is on another stack.
	// The channel is locked, so src will not move during this
	// operation.
	src := sg.elem
	typeBitsBulkBarrier(t, uintptr(dst), uintptr(src), t.Size_)
	memmove(dst, src, t.Size_)
}

func closechan(c *hchan) {
	if c == nil {
		panic(plainError("close of nil channel"))
	}

	lock(&c.lock)
	if c.closed != 0 {
		unlock(&c.lock)
		panic(plainError("close of closed channel"))
	}

	if raceenabled {
		callerpc := sys.GetCallerPC()
		racewritepc(c.raceaddr(), callerpc, abi.FuncPCABIInternal(closechan))
		racerelease(c.raceaddr())
	}

	c.closed = 1

	var glist gList

	// release all readers
	for {
		sg := c.recvq.dequeue()
		if sg == nil {
			break
		}
		if sg.elem != nil {
			typedmemclr(c.elemtype, sg.elem)
			sg.elem = nil
		}
		if sg.releasetime != 0 {
			sg.releasetime = cputicks()
		}
		gp := sg.g
		gp.param = unsafe.Pointer(sg)
		sg.success = false
		if raceenabled {
			raceacquireg(gp, c.raceaddr())
		}
		glist.push(gp)
	}

	// release all writers (they will panic)
	for {
		sg := c.sendq.dequeue()
		if sg == nil {
			break
		}
		sg.elem = nil
		if sg.releasetime != 0 {
			sg.releasetime = cputicks()
		}
		gp := sg.g
		gp.param = unsafe.Pointer(sg)
		sg.success = false
		if raceenabled {
			raceacquireg(gp, c.raceaddr())
		}
		glist.push(gp)
	}
	unlock(&c.lock)

	// Ready all Gs now that we've dropped the channel lock.
	for !glist.empty() {
		gp := glist.pop()
		gp.schedlink = 0
		goready(gp, 3)
	}
}

// empty reports whether a read from c would block (that is, the channel is
// empty).  It is atomically correct and sequentially consistent at the moment
// it returns, but since the channel is unlocked, the channel may become
// non-empty immediately afterward.
func empty(c *hchan) bool {
	// c.dataqsiz is immutable.
	if c.dataqsiz == 0 {
		return atomic.Loadp(unsafe.Pointer(&c.sendq.first)) == nil
	}
	// c.timer is also immutable (it is set after make(chan) but before any channel operations).
	// All timer channels have dataqsiz > 0.
	if c.timer != nil {
		c.timer.maybeRunChan()
	}
	return atomic.Loaduint(&c.qcount) == 0
}

// entry points for <- c from compiled code.
//
//go:nosplit
func chanrecv1(c *hchan, elem unsafe.Pointer) {
	chanrecv(c, elem, true)
}

//go:nosplit
func chanrecv2(c *hchan, elem unsafe.Pointer) (received bool) {
	_, received = chanrecv(c, elem, true)
	return
}

// chanrecv receives on channel c and writes the received data to ep.
// ep may be nil, in which case received data is ignored.
// If block == false and no elements are available, returns (false, false).
// Otherwise, if c is closed, zeros *ep and returns (true, false).
// Otherwise, fills in *ep with an element and returns (true, true).
// A non-nil ep must point to the heap or the caller's stack.
func chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected, received bool) {
	// raceenabled: don't need to check ep, as it is always on the stack
	// or is new memory allocated by reflect.

	if debugChan {
		print("chanrecv: chan=", c, "\n")
	}

	if c == nil {
		if !block {
			return
		}
		gopark(nil, nil, waitReasonChanReceiveNilChan, traceBlockForever, 2)
		throw("unreachable")
	}

	if c.synctest && getg().syncGroup == nil {
		panic(plainError("receive on synctest channel from outside bubble"))
	}

	if c.timer != nil {
		c.timer.maybeRunChan()
	}

	// Fast path: check for failed non-blocking operation without acquiring the lock.
	if !block && empty(c) {
		// After observing that the channel is not ready for receiving, we observe whether the
		// channel is closed.
		//
		// Reordering of these checks could lead to incorrect behavior when racing with a close.
		// For example, if the channel was open and not empty, was closed, and then drained,
		// reordered reads could incorrectly indicate "open and empty". To prevent reordering,
		// we use atomic loads for both checks, and rely on emptying and closing to happen in
		// separate critical sections under the same lock.  This assumption fails when closing
		// an unbuffered channel with a blocked send, but that is an error condition anyway.
		if atomic.Load(&c.closed) == 0 {
			// Because a channel cannot be reopened, the later observation of the channel
			// being not closed implies that it was also not closed at the moment of the
			// first observation. We behave as if we observed the channel at that moment
			// and report that the receive cannot proceed.
			return
		}
		// The channel is irreversibly closed. Re-check whether the channel has any pending data
		// to receive, which could have arrived between the empty and closed checks above.
		// Sequential consistency is also required here, when racing with such a send.
		if empty(c) {
			// The channel is irreversibly closed and empty.
			if raceenabled {
				raceacquire(c.raceaddr())
			}
			if ep != nil {
				typedmemclr(c.elemtype, ep)
			}
			return true, false
		}
	}

	var t0 int64
	if blockprofilerate > 0 {
		t0 = cputicks()
	}

	lock(&c.lock)

	if c.closed != 0 {
		if c.qcount == 0 {
			if raceenabled {
				raceacquire(c.raceaddr())
			}
			unlock(&c.lock)
			if ep != nil {
				typedmemclr(c.elemtype, ep)
			}
			return true, false
		}
		// The channel has been closed, but the channel's buffer have data.
	} else {
		// Just found waiting sender with not closed.
		if sg := c.sendq.dequeue(); sg != nil {
			// Found a waiting sender. If buffer is size 0, receive value
			// directly from sender. Otherwise, receive from head of queue
			// and add sender's value to the tail of the queue (both map to
			// the same buffer slot because the queue is full).
			recv(c, sg, ep, func() { unlock(&c.lock) }, 3)
			return true, true
		}
	}

	if c.qcount > 0 {
		// Receive directly from queue
		qp := chanbuf(c, c.recvx)
		if raceenabled {
			racenotify(c, c.recvx, nil)
		}
		if ep != nil {
			typedmemmove(c.elemtype, ep, qp)
		}
		typedmemclr(c.elemtype, qp)
		c.recvx++
		if c.recvx == c.dataqsiz {
			c.recvx = 0
		}
		c.qcount--
		unlock(&c.lock)
		return true, true
	}

	if !block {
		unlock(&c.lock)
		return false, false
	}

	// no sender available: block on this channel.
	gp := getg()
	mysg := acquireSudog()
	mysg.releasetime = 0
	if t0 != 0 {
		mysg.releasetime = -1
	}
	// No stack splits between assigning elem and enqueuing mysg
	// on gp.waiting where copystack can find it.
	mysg.elem = ep
	mysg.waitlink = nil
	gp.waiting = mysg

	mysg.g = gp
	mysg.isSelect = false
	mysg.c = c
	gp.param = nil
	c.recvq.enqueue(mysg)
	if c.timer != nil {
		blockTimerChan(c)
	}

	// Signal to anyone trying to shrink our stack that we're about
	// to park on a channel. The window between when this G's status
	// changes and when we set gp.activeStackChans is not safe for
	// stack shrinking.
	gp.parkingOnChan.Store(true)
	reason := waitReasonChanReceive
	if c.synctest {
		reason = waitReasonSynctestChanReceive
	}
	gopark(chanparkcommit, unsafe.Pointer(&c.lock), reason, traceBlockChanRecv, 2)

	// someone woke us up
	if mysg != gp.waiting {
		throw("G waiting list is corrupted")
	}
	if c.timer != nil {
		unblockTimerChan(c)
	}
	gp.waiting = nil
	gp.activeStackChans = false
	if mysg.releasetime > 0 {
		blockevent(mysg.releasetime-t0, 2)
	}
	success := mysg.success
	gp.param = nil
	mysg.c = nil
	releaseSudog(mysg)
	return true, success
}

// recv processes a receive operation on a full channel c.
// There are 2 parts:
//  1. The value sent by the sender sg is put into the channel
//     and the sender is woken up to go on its merry way.
//  2. The value received by the receiver (the current G) is
//     written to ep.
//
// For synchronous channels, both values are the same.
// For asynchronous channels, the receiver gets its data from
// the channel buffer and the sender's data is put in the
// channel buffer.
// Channel c must be full and locked. recv unlocks c with unlockf.
// sg must already be dequeued from c.
// A non-nil ep must point to the heap or the caller's stack.
func recv(c *hchan, sg *sudog, ep unsafe.Pointer, unlockf func(), skip int) {
	if c.synctest && sg.g.syncGroup != getg().syncGroup {
		unlockf()
		panic(plainError("receive on synctest channel from outside bubble"))
	}
	if c.dataqsiz == 0 {
		if raceenabled {
			racesync(c, sg)
		}
		if ep != nil {
			// copy data from sender
			recvDirect(c.elemtype, sg, ep)
		}
	} else {
		// Queue is full. Take the item at the
		// head of the queue. Make the sender enqueue
		// its item at the tail of the queue. Since the
		// queue is full, those are both the same slot.
		qp := chanbuf(c, c.recvx)
		if raceenabled {
			racenotify(c, c.recvx, nil)
			racenotify(c, c.recvx, sg)
		}
		// copy data from queue to receiver
		if ep != nil {
			typedmemmove(c.elemtype, ep, qp)
		}
		// copy data from sender to queue
		typedmemmove(c.elemtype, qp, sg.elem)
		c.recvx++
		if c.recvx == c.dataqsiz {
			c.recvx = 0
		}
		c.sendx = c.recvx // c.sendx = (c.sendx+1) % c.dataqsiz
	}
	sg.elem = nil
	gp := sg.g
	unlockf()
	gp.param = unsafe.Pointer(sg)
	sg.success = true
	if sg.releasetime != 0 {
		sg.releasetime = cputicks()
	}
	goready(gp, skip+1)
}

func chanparkcommit(gp *g, chanLock unsafe.Pointer) bool {
	// There are unlocked sudogs that point into gp's stack. Stack
	// copying must lock the channels of those sudogs.
	// Set activeStackChans here instead of before we try parking
	// because we could self-deadlock in stack growth on the
	// channel lock.
	gp.activeStackChans = true
	// Mark that it's safe for stack shrinking to occur now,
	// because any thread acquiring this G's stack for shrinking
	// is guaranteed to observe activeStackChans after this store.
	gp.parkingOnChan.Store(false)
	// Make sure we unlock after setting activeStackChans and
	// unsetting parkingOnChan. The moment we unlock chanLock
	// we risk gp getting readied by a channel operation and
	// so gp could continue running before everything before
	// the unlock is visible (even to gp itself).
	unlock((*mutex)(chanLock))
	return true
}

// compiler implements
//
//	select {
//	case c <- v:
//		... foo
//	default:
//		... bar
//	}
//
// as
//
//	if selectnbsend(c, v) {
//		... foo
//	} else {
//		... bar
//	}
func selectnbsend(c *hchan, elem unsafe.Pointer) (selected bool) {
	return chansend(c, elem, false, sys.GetCallerPC())
}

// compiler implements
//
//	select {
//	case v, ok = <-c:
//		... foo
//	default:
//		... bar
//	}
//
// as
//
//	if selected, ok = selectnbrecv(&v, c); selected {
//		... foo
//	} else {
//		... bar
//	}
func selectnbrecv(elem unsafe.Pointer, c *hchan) (selected, received bool) {
	return chanrecv(c, elem, false)
}

//go:linkname reflect_chansend reflect.chansend0
func reflect_chansend(c *hchan, elem unsafe.Pointer, nb bool) (selected bool) {
	return chansend(c, elem, !nb, sys.GetCallerPC())
}

//go:linkname reflect_chanrecv reflect.chanrecv
func reflect_chanrecv(c *hchan, nb bool, elem unsafe.Pointer) (selected bool, received bool) {
	return chanrecv(c, elem, !nb)
}

func chanlen(c *hchan) int {
	if c == nil {
		return 0
	}
	async := debug.asynctimerchan.Load() != 0
	if c.timer != nil && async {
		c.timer.maybeRunChan()
	}
	if c.timer != nil && !async {
		// timer channels have a buffered implementation
		// but present to users as unbuffered, so that we can
		// undo sends without users noticing.
		return 0
	}
	return int(c.qcount)
}

func chancap(c *hchan) int {
	if c == nil {
		return 0
	}
	if c.timer != nil {
		async := debug.asynctimerchan.Load() != 0
		if async {
			return int(c.dataqsiz)
		}
		// timer channels have a buffered implementation
		// but present to users as unbuffered, so that we can
		// undo sends without users noticing.
		return 0
	}
	return int(c.dataqsiz)
}

//go:linkname reflect_chanlen reflect.chanlen
func reflect_chanlen(c *hchan) int {
	return chanlen(c)
}

//go:linkname reflectlite_chanlen internal/reflectlite.chanlen
func reflectlite_chanlen(c *hchan) int {
	return chanlen(c)
}

//go:linkname reflect_chancap reflect.chancap
func reflect_chancap(c *hchan) int {
	return chancap(c)
}

//go:linkname reflect_chanclose reflect.chanclose
func reflect_chanclose(c *hchan) {
	closechan(c)
}

func (q *waitq) enqueue(sgp *sudog) {
	sgp.next = nil
	x := q.last
	if x == nil {
		sgp.prev = nil
		q.first = sgp
		q.last = sgp
		return
	}
	sgp.prev = x
	x.next = sgp
	q.last = sgp
}

func (q *waitq) dequeue() *sudog {
	for {
		sgp := q.first
		if sgp == nil {
			return nil
		}
		y := sgp.next
		if y == nil {
			q.first = nil
			q.last = nil
		} else {
			y.prev = nil
			q.first = y
			sgp.next = nil // mark as removed (see dequeueSudoG)
		}

		// if a goroutine was put on this queue because of a
		// select, there is a small window between the goroutine
		// being woken up by a different case and it grabbing the
		// channel locks. Once it has the lock
		// it removes itself from the queue, so we won't see it after that.
		// We use a flag in the G struct to tell us when someone
		// else has won the race to signal this goroutine but the goroutine
		// hasn't removed itself from the queue yet.
		if sgp.isSelect {
			if !sgp.g.selectDone.CompareAndSwap(0, 1) {
				// We lost the race to wake this goroutine.
				continue
			}
		}

		return sgp
	}
}

func (c *hchan) raceaddr() unsafe.Pointer {
	// Treat read-like and write-like operations on the channel to
	// happen at this address. Avoid using the address of qcount
	// or dataqsiz, because the len() and cap() builtins read
	// those addresses, and we don't want them racing with
	// operations like close().
	return unsafe.Pointer(&c.buf)
}

func racesync(c *hchan, sg *sudog) {
	racerelease(chanbuf(c, 0))
	raceacquireg(sg.g, chanbuf(c, 0))
	racereleaseg(sg.g, chanbuf(c, 0))
	raceacquire(chanbuf(c, 0))
}

// Notify the race detector of a send or receive involving buffer entry idx
// and a channel c or its communicating partner sg.
// This function handles the special case of c.elemsize==0.
func racenotify(c *hchan, idx uint, sg *sudog) {
	// We could have passed the unsafe.Pointer corresponding to entry idx
	// instead of idx itself.  However, in a future version of this function,
	// we can use idx to better handle the case of elemsize==0.
	// A future improvement to the detector is to call TSan with c and idx:
	// this way, Go will continue to not allocating buffer entries for channels
	// of elemsize==0, yet the race detector can be made to handle multiple
	// sync objects underneath the hood (one sync object per idx)
	qp := chanbuf(c, idx)
	// When elemsize==0, we don't allocate a full buffer for the channel.
	// Instead of individual buffer entries, the race detector uses the
	// c.buf as the only buffer entry.  This simplification prevents us from
	// following the memory model's happens-before rules (rules that are
	// implemented in racereleaseacquire).  Instead, we accumulate happens-before
	// information in the synchronization object associated with c.buf.
	if c.elemsize == 0 {
		if sg == nil {
			raceacquire(qp)
			racerelease(qp)
		} else {
			raceacquireg(sg.g, qp)
			racereleaseg(sg.g, qp)
		}
	} else {
		if sg == nil {
			racereleaseacquire(qp)
		} else {
			racereleaseacquireg(sg.g, qp)
		}
	}
}

"""



```