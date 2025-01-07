Response:
My thinking process to analyze the provided Go code and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to understand the functionality of the provided Go code snippet, which is a part of the `runtime` package dealing with time management. Specifically, they want a summary of its features, potential Go language features it implements, code examples, explanations of command-line arguments (if any), common mistakes, and a final summary of its function in this part.

2. **Initial Code Scan and Identification of Key Structures:** I started by quickly scanning the code to identify the major data structures and functions. I noticed:
    * `timer`: A struct representing a single timer.
    * `timers`: A struct representing a collection of timers, typically associated with a processor (`P`).
    * `time_runtimeNow`, `time_runtimeNano`: Functions for getting the current time.
    * Functions like `timeSleep`, `newTimer`, `stopTimer`, `resetTimer`: These clearly relate to the user-facing `time` package.
    * Functions with names like `addHeap`, `deleteMin`, `adjust`, `run`, `maybeAdd`: These seem to manage the internal timer heap.

3. **Focus on Core Functionality:** I recognized that the core functionality revolves around managing timers efficiently. This involves:
    * **Scheduling:** Determining when a timer should fire.
    * **Execution:** Running the function associated with a timer when it expires.
    * **Storage:** Keeping track of active timers, likely in a priority queue (heap).
    * **Manipulation:**  Creating, starting, stopping, and resetting timers.

4. **Inferring Go Language Features:** Based on the identified structures and functions, I could infer the following Go features being used:
    * **Goroutines:** The code mentions "client goroutine" and interacting with the scheduler, indicating goroutines are involved.
    * **Channels:** The `isChan` field in `timer` and the `hchan()` method strongly suggest that timers can be associated with channels.
    * **Mutexes:** The `mu` field in `timer` and `timers`, along with `lock` and `unlock` methods, indicate the use of mutexes for concurrent access protection.
    * **Atomic Operations:** The `atomic.Uint32` and `atomic.Int32` types show the use of atomic operations for thread-safe access to certain fields.
    * **Linkname:** The `//go:linkname` directives reveal that this runtime code provides the underlying implementation for functions in the `time` package.
    * **System Stack:** The `//go:systemstack` directive marks functions that need to run on a dedicated system stack.

5. **Developing Code Examples:** To illustrate the inferred Go features, I created basic examples using the `time` package. These examples aimed to showcase:
    * Creating and using a `time.Timer`.
    * Using `time.Sleep`.
    * Creating and using a `time.Ticker`.
    * Demonstrating the use of channels with timers.

6. **Reasoning about Inputs and Outputs (Where Applicable):** For functions like `time_runtimeNow` and `time_runtimeNano`, I considered the expected input (implicitly the system clock) and output (seconds, nanoseconds, and monotonic time). For internal functions like `addHeap`, I considered the input (a `timer` object) and the output (modifying the `timers` heap).

7. **Considering Command-Line Arguments:**  I scanned the code for any direct handling of command-line arguments. Finding none, I concluded that this specific code snippet doesn't directly process them. However, I noted that the `debug.asynctimerchan` variable might be influenced by build tags or internal settings.

8. **Identifying Common Mistakes:** I thought about how users might misuse the `time` package based on the underlying implementation. I focused on:
    * **Not draining channels associated with timers:** This can lead to goroutine leaks.
    * **Assuming immediate execution after `Reset`:** The timer is added to a heap and executed when its time arrives.

9. **Synthesizing the Summary:** Finally, I compiled my understanding into a concise summary of the code's functionality, focusing on its role as the runtime underpinning for Go's `time` package, managing timers, and providing accurate time information.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  I initially focused heavily on the heap data structure. While important, I realized the interaction with goroutines, channels, and the `time` package was equally crucial.
* **Clarifying `linkname`:** I initially understood `linkname` but refined my explanation to emphasize how it bridges the `runtime` and `time` packages.
* **Focusing on user-level interactions:**  While analyzing the internal mechanisms, I made sure to connect them back to how users interact with the `time` package. This helped in creating relevant code examples and identifying common mistakes.
* **Emphasizing concurrency:** The heavy use of mutexes and atomics highlighted the importance of concurrency management in this code. I made sure to emphasize this in my explanations.
```text
这是路径为go/src/runtime/time.go的go语言实现的一部分
```

这段 Go 语言代码是 `runtime` 包中关于时间管理的核心部分，它提供了底层的时间机制，并被上层的 `time` 标准库所使用。

**它的主要功能可以归纳为：**

1. **提供获取当前时间的基础能力：**
   - `time_runtimeNow()` 和 `time_runtimeNano()` 函数提供了获取当前时间和单调时间的底层实现。它们会尝试从当前 Goroutine 的同步组 (syncGroup) 获取时间，如果 Goroutine 不属于任何同步组，则调用更底层的 `time_now()` 或 `nanotime()`。

2. **实现计时器 (Timer) 的核心逻辑：**
   - 定义了 `timer` 结构体，用于表示一个计时器，包含了到期时间 (`when`)、触发间隔 (`period`)、回调函数 (`f`)、参数 (`arg`) 等信息。
   - 定义了 `timers` 结构体，用于管理一组计时器，通常与一个 P (Processor) 关联。它使用堆数据结构 (`heap`) 来高效地存储和查找最近到期的计时器。
   - 提供了计时器的创建 (`newTimer`)、启动（通过 `modify` 或 `reset` 添加到堆中）、停止 (`stop`)、重置 (`reset`) 和触发执行 (`unlockAndRun`) 等操作。

3. **支持与 Channel 关联的计时器：**
   - `timer` 结构体中的 `isChan` 字段表示计时器是否关联了一个 Channel。
   - 当计时器到期时，如果关联了 Channel，会将一个值发送到该 Channel。
   - 使用 `sendLock` 和 `isSending` 来保证向 Channel 发送的原子性和避免竞争条件。

4. **提供 `time.Sleep` 的底层实现：**
   - `timeSleep` 函数利用计时器将当前的 Goroutine 挂起指定的时间。

5. **管理计时器堆：**
   - `addHeap`、`deleteMin`、`siftUp`、`siftDown` 等函数用于维护 `timers` 结构体中的堆，确保计时器按照到期时间排序。
   - `adjust` 函数用于调整堆中已修改的计时器的位置，并移除已删除的计时器。
   - `cleanHead` 函数用于清理堆头部的过期或已停止的计时器，提高性能。

6. **处理 fake time (用于测试)：**
   - `isFake` 字段允许创建使用 fake time 的计时器，这主要用于测试目的，允许在不依赖系统真实时间的情况下模拟时间流逝。

7. **提供线程安全的访问：**
   - 使用 `mutex` (互斥锁) 来保护 `timer` 和 `timers` 结构体的并发访问，防止数据竞争。
   - 使用 `atomic` 包提供的原子操作来保证某些状态的原子更新。

8. **与网络轮询器 (netpoller) 集成：**
   - 代码中提到 `netpollInited`，表明计时器机制与 Go 语言的网络 I/O 模型集成，可以唤醒网络轮询器来处理到期的计时器。

**可以推理出它是什么 go 语言功能的实现：**

这段代码是 Go 语言 `time` 标准库中 `time.Timer` 和 `time.Sleep` 等时间相关功能的核心运行时实现。

**Go 代码举例说明：**

```go
package main

import (
	"fmt"
	"time"
)

func main() {
	// 使用 time.Sleep 让程序暂停 1 秒
	fmt.Println("开始休眠")
	time.Sleep(1 * time.Second)
	fmt.Println("休眠结束")

	// 创建一个 2 秒后触发的定时器
	timer := time.NewTimer(2 * time.Second)
	fmt.Println("创建定时器")

	// 等待定时器触发
	<-timer.C
	fmt.Println("定时器触发")

	// 创建一个周期性触发的定时器 (Ticker)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop() // 记得停止 Ticker

	fmt.Println("创建周期性定时器")
	for i := 0; i < 3; i++ {
		<-ticker.C
		fmt.Println("周期性定时器触发", i+1)
	}

	// 使用 AfterFunc 在指定时间后执行一个函数
	fmt.Println("设置 AfterFunc")
	time.AfterFunc(1*time.Second, func() {
		fmt.Println("AfterFunc 执行")
	})

	time.Sleep(2 * time.Second) // 等待 AfterFunc 执行
}
```

**假设的输入与输出 (针对 `time_runtimeNow`)：**

* **假设输入：**  当前系统时间为 `2023-10-27 10:00:00.123456789 UTC`，单调时钟的值为某个数字。
* **假设输出：**
   - `sec`: `1698381600` (Unix 时间戳，秒)
   - `nsec`: `123456789` (纳秒)
   - `mono`:  取决于具体的单调时钟实现，例如可能是从系统启动开始的纳秒数。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。与时间相关的命令行参数可能由上层的 `time` 标准库或者使用 `time` 库的应用程序来处理，例如设置超时时间等。

**使用者易犯错的点：**

1. **忘记停止 `time.Ticker`:**  `time.Ticker` 会持续发送时间事件到其 Channel，如果不调用 `Stop()`，会导致 Goroutine 和资源泄漏。

   ```go
   ticker := time.NewTicker(time.Second)
   // ... 使用 ticker.C

   // 忘记调用 ticker.Stop()
   ```

2. **混淆 `time.Timer` 和 `time.Ticker` 的用途:** `time.Timer` 触发一次后即失效，而 `time.Ticker` 会周期性触发。

3. **在 Channel 阻塞的情况下停止 Timer/Ticker 可能导致发送失败：** 如果与 Timer/Ticker 关联的 Channel 没有接收者，并且在 Timer/Ticker 到期后立即调用 `Stop()`，那么尝试发送到 Channel 的操作可能不会成功。

**功能归纳（第 1 部分）：**

这段 `go/src/runtime/time.go` 的代码是 Go 语言运行时环境中负责时间管理的基础设施。它实现了获取当前时间、管理计时器（包括单次触发和周期性触发）、支持与 Channel 关联的计时器，并为 `time.Sleep` 等上层时间相关功能提供了底层支撑。它使用了锁和原子操作来保证并发安全性，并与网络轮询器集成以实现高效的事件处理。此外，它还支持 fake time 用于测试目的。

Prompt: 
```
这是路径为go/src/runtime/time.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Time-related runtime and pieces of package time.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

//go:linkname time_runtimeNow time.runtimeNow
func time_runtimeNow() (sec int64, nsec int32, mono int64) {
	if sg := getg().syncGroup; sg != nil {
		sec = sg.now / (1000 * 1000 * 1000)
		nsec = int32(sg.now % (1000 * 1000 * 1000))
		return sec, nsec, sg.now
	}
	return time_now()
}

//go:linkname time_runtimeNano time.runtimeNano
func time_runtimeNano() int64 {
	gp := getg()
	if gp.syncGroup != nil {
		return gp.syncGroup.now
	}
	return nanotime()
}

// A timer is a potentially repeating trigger for calling t.f(t.arg, t.seq).
// Timers are allocated by client code, often as part of other data structures.
// Each P has a heap of pointers to timers that it manages.
//
// A timer is expected to be used by only one client goroutine at a time,
// but there will be concurrent access by the P managing that timer.
// Timer accesses are protected by the lock t.mu, with a snapshot of
// t's state bits published in t.astate to enable certain fast paths to make
// decisions about a timer without acquiring the lock.
type timer struct {
	// mu protects reads and writes to all fields, with exceptions noted below.
	mu mutex

	astate atomic.Uint8 // atomic copy of state bits at last unlock
	state  uint8        // state bits
	isChan bool         // timer has a channel; immutable; can be read without lock
	isFake bool         // timer is using fake time; immutable; can be read without lock

	blocked uint32 // number of goroutines blocked on timer's channel

	// Timer wakes up at when, and then at when+period, ... (period > 0 only)
	// each time calling f(arg, seq, delay) in the timer goroutine, so f must be
	// a well-behaved function and not block.
	//
	// The arg and seq are client-specified opaque arguments passed back to f.
	// When used from netpoll, arg and seq have meanings defined by netpoll
	// and are completely opaque to this code; in that context, seq is a sequence
	// number to recognize and squelch stale function invocations.
	// When used from package time, arg is a channel (for After, NewTicker)
	// or the function to call (for AfterFunc) and seq is unused (0).
	//
	// Package time does not know about seq, but if this is a channel timer (t.isChan == true),
	// this file uses t.seq as a sequence number to recognize and squelch
	// sends that correspond to an earlier (stale) timer configuration,
	// similar to its use in netpoll. In this usage (that is, when t.isChan == true),
	// writes to seq are protected by both t.mu and t.sendLock,
	// so reads are allowed when holding either of the two mutexes.
	//
	// The delay argument is nanotime() - t.when, meaning the delay in ns between
	// when the timer should have gone off and now. Normally that amount is
	// small enough not to matter, but for channel timers that are fed lazily,
	// the delay can be arbitrarily long; package time subtracts it out to make
	// it look like the send happened earlier than it actually did.
	// (No one looked at the channel since then, or the send would have
	// not happened so late, so no one can tell the difference.)
	when   int64
	period int64
	f      func(arg any, seq uintptr, delay int64)
	arg    any
	seq    uintptr

	// If non-nil, the timers containing t.
	ts *timers

	// sendLock protects sends on the timer's channel.
	// Not used for async (pre-Go 1.23) behavior when debug.asynctimerchan.Load() != 0.
	sendLock mutex

	// isSending is used to handle races between running a
	// channel timer and stopping or resetting the timer.
	// It is used only for channel timers (t.isChan == true).
	// It is not used for tickers.
	// The value is incremented when about to send a value on the channel,
	// and decremented after sending the value.
	// The stop/reset code uses this to detect whether it
	// stopped the channel send.
	//
	// isSending is incremented only when t.mu is held.
	// isSending is decremented only when t.sendLock is held.
	// isSending is read only when both t.mu and t.sendLock are held.
	isSending atomic.Int32
}

// init initializes a newly allocated timer t.
// Any code that allocates a timer must call t.init before using it.
// The arg and f can be set during init, or they can be nil in init
// and set by a future call to t.modify.
func (t *timer) init(f func(arg any, seq uintptr, delay int64), arg any) {
	lockInit(&t.mu, lockRankTimer)
	t.f = f
	t.arg = arg
}

// A timers is a per-P set of timers.
type timers struct {
	// mu protects timers; timers are per-P, but the scheduler can
	// access the timers of another P, so we have to lock.
	mu mutex

	// heap is the set of timers, ordered by heap[i].when.
	// Must hold lock to access.
	heap []timerWhen

	// len is an atomic copy of len(heap).
	len atomic.Uint32

	// zombies is the number of timers in the heap
	// that are marked for removal.
	zombies atomic.Int32

	// raceCtx is the race context used while executing timer functions.
	raceCtx uintptr

	// minWhenHeap is the minimum heap[i].when value (= heap[0].when).
	// The wakeTime method uses minWhenHeap and minWhenModified
	// to determine the next wake time.
	// If minWhenHeap = 0, it means there are no timers in the heap.
	minWhenHeap atomic.Int64

	// minWhenModified is a lower bound on the minimum
	// heap[i].when over timers with the timerModified bit set.
	// If minWhenModified = 0, it means there are no timerModified timers in the heap.
	minWhenModified atomic.Int64

	syncGroup *synctestGroup
}

type timerWhen struct {
	timer *timer
	when  int64
}

func (ts *timers) lock() {
	lock(&ts.mu)
}

func (ts *timers) unlock() {
	// Update atomic copy of len(ts.heap).
	// We only update at unlock so that the len is always
	// the most recent unlocked length, not an ephemeral length.
	// This matters if we lock ts, delete the only timer from the heap,
	// add it back, and unlock. We want ts.len.Load to return 1 the
	// entire time, never 0. This is important for pidleput deciding
	// whether ts is empty.
	ts.len.Store(uint32(len(ts.heap)))

	unlock(&ts.mu)
}

// Timer state field.
const (
	// timerHeaped is set when the timer is stored in some P's heap.
	timerHeaped uint8 = 1 << iota

	// timerModified is set when t.when has been modified
	// but the heap's heap[i].when entry still needs to be updated.
	// That change waits until the heap in which
	// the timer appears can be locked and rearranged.
	// timerModified is only set when timerHeaped is also set.
	timerModified

	// timerZombie is set when the timer has been stopped
	// but is still present in some P's heap.
	// Only set when timerHeaped is also set.
	// It is possible for timerModified and timerZombie to both
	// be set, meaning that the timer was modified and then stopped.
	// A timer sending to a channel may be placed in timerZombie
	// to take it out of the heap even though the timer is not stopped,
	// as long as nothing is reading from the channel.
	timerZombie
)

// timerDebug enables printing a textual debug trace of all timer operations to stderr.
const timerDebug = false

func (t *timer) trace(op string) {
	if timerDebug {
		t.trace1(op)
	}
}

func (t *timer) trace1(op string) {
	if !timerDebug {
		return
	}
	bits := [4]string{"h", "m", "z", "c"}
	for i := range 3 {
		if t.state&(1<<i) == 0 {
			bits[i] = "-"
		}
	}
	if !t.isChan {
		bits[3] = "-"
	}
	print("T ", t, " ", bits[0], bits[1], bits[2], bits[3], " b=", t.blocked, " ", op, "\n")
}

func (ts *timers) trace(op string) {
	if timerDebug {
		println("TS", ts, op)
	}
}

// lock locks the timer, allowing reading or writing any of the timer fields.
func (t *timer) lock() {
	lock(&t.mu)
	t.trace("lock")
}

// unlock updates t.astate and unlocks the timer.
func (t *timer) unlock() {
	t.trace("unlock")
	// Let heap fast paths know whether heap[i].when is accurate.
	// Also let maybeRunChan know whether channel is in heap.
	t.astate.Store(t.state)
	unlock(&t.mu)
}

// hchan returns the channel in t.arg.
// t must be a timer with a channel.
func (t *timer) hchan() *hchan {
	if !t.isChan {
		badTimer()
	}
	// Note: t.arg is a chan time.Time,
	// and runtime cannot refer to that type,
	// so we cannot use a type assertion.
	return (*hchan)(efaceOf(&t.arg).data)
}

// updateHeap updates t as directed by t.state, updating t.state
// and returning a bool indicating whether the state (and ts.heap[0].when) changed.
// The caller must hold t's lock, or the world can be stopped instead.
// The timer set t.ts must be non-nil and locked, t must be t.ts.heap[0], and updateHeap
// takes care of moving t within the timers heap to preserve the heap invariants.
// If ts == nil, then t must not be in a heap (or is in a heap that is
// temporarily not maintaining its invariant, such as during timers.adjust).
func (t *timer) updateHeap() (updated bool) {
	assertWorldStoppedOrLockHeld(&t.mu)
	t.trace("updateHeap")
	ts := t.ts
	if ts == nil || t != ts.heap[0].timer {
		badTimer()
	}
	assertLockHeld(&ts.mu)
	if t.state&timerZombie != 0 {
		// Take timer out of heap.
		t.state &^= timerHeaped | timerZombie | timerModified
		ts.zombies.Add(-1)
		ts.deleteMin()
		return true
	}

	if t.state&timerModified != 0 {
		// Update ts.heap[0].when and move within heap.
		t.state &^= timerModified
		ts.heap[0].when = t.when
		ts.siftDown(0)
		ts.updateMinWhenHeap()
		return true
	}

	return false
}

// maxWhen is the maximum value for timer's when field.
const maxWhen = 1<<63 - 1

// verifyTimers can be set to true to add debugging checks that the
// timer heaps are valid.
const verifyTimers = false

// Package time APIs.
// Godoc uses the comments in package time, not these.

// time.now is implemented in assembly.

// timeSleep puts the current goroutine to sleep for at least ns nanoseconds.
//
//go:linkname timeSleep time.Sleep
func timeSleep(ns int64) {
	if ns <= 0 {
		return
	}

	gp := getg()
	t := gp.timer
	if t == nil {
		t = new(timer)
		t.init(goroutineReady, gp)
		if gp.syncGroup != nil {
			t.isFake = true
		}
		gp.timer = t
	}
	var now int64
	if sg := gp.syncGroup; sg != nil {
		now = sg.now
	} else {
		now = nanotime()
	}
	when := now + ns
	if when < 0 { // check for overflow.
		when = maxWhen
	}
	gp.sleepWhen = when
	if t.isFake {
		// Call timer.reset in this goroutine, since it's the one in a syncGroup.
		// We don't need to worry about the timer function running before the goroutine
		// is parked, because time won't advance until we park.
		resetForSleep(gp, nil)
		gopark(nil, nil, waitReasonSleep, traceBlockSleep, 1)
	} else {
		gopark(resetForSleep, nil, waitReasonSleep, traceBlockSleep, 1)
	}
}

// resetForSleep is called after the goroutine is parked for timeSleep.
// We can't call timer.reset in timeSleep itself because if this is a short
// sleep and there are many goroutines then the P can wind up running the
// timer function, goroutineReady, before the goroutine has been parked.
func resetForSleep(gp *g, _ unsafe.Pointer) bool {
	gp.timer.reset(gp.sleepWhen, 0)
	return true
}

// A timeTimer is a runtime-allocated time.Timer or time.Ticker
// with the additional runtime state following it.
// The runtime state is inaccessible to package time.
type timeTimer struct {
	c    unsafe.Pointer // <-chan time.Time
	init bool
	timer
}

// newTimer allocates and returns a new time.Timer or time.Ticker (same layout)
// with the given parameters.
//
//go:linkname newTimer time.newTimer
func newTimer(when, period int64, f func(arg any, seq uintptr, delay int64), arg any, c *hchan) *timeTimer {
	t := new(timeTimer)
	t.timer.init(nil, nil)
	t.trace("new")
	if raceenabled {
		racerelease(unsafe.Pointer(&t.timer))
	}
	if c != nil {
		lockInit(&t.sendLock, lockRankTimerSend)
		t.isChan = true
		c.timer = &t.timer
		if c.dataqsiz == 0 {
			throw("invalid timer channel: no capacity")
		}
	}
	if gr := getg().syncGroup; gr != nil {
		t.isFake = true
	}
	t.modify(when, period, f, arg, 0)
	t.init = true
	return t
}

// stopTimer stops a timer.
// It reports whether t was stopped before being run.
//
//go:linkname stopTimer time.stopTimer
func stopTimer(t *timeTimer) bool {
	if t.isFake && getg().syncGroup == nil {
		panic("stop of synctest timer from outside bubble")
	}
	return t.stop()
}

// resetTimer resets an inactive timer, adding it to the timer heap.
//
// Reports whether the timer was modified before it was run.
//
//go:linkname resetTimer time.resetTimer
func resetTimer(t *timeTimer, when, period int64) bool {
	if raceenabled {
		racerelease(unsafe.Pointer(&t.timer))
	}
	if t.isFake && getg().syncGroup == nil {
		panic("reset of synctest timer from outside bubble")
	}
	return t.reset(when, period)
}

// Go runtime.

// Ready the goroutine arg.
func goroutineReady(arg any, _ uintptr, _ int64) {
	goready(arg.(*g), 0)
}

// addHeap adds t to the timers heap.
// The caller must hold ts.lock or the world must be stopped.
// The caller must also have checked that t belongs in the heap.
// Callers that are not sure can call t.maybeAdd instead,
// but note that maybeAdd has different locking requirements.
func (ts *timers) addHeap(t *timer) {
	assertWorldStoppedOrLockHeld(&ts.mu)
	// Timers rely on the network poller, so make sure the poller
	// has started.
	if netpollInited.Load() == 0 {
		netpollGenericInit()
	}

	if t.ts != nil {
		throw("ts set in timer")
	}
	t.ts = ts
	ts.heap = append(ts.heap, timerWhen{t, t.when})
	ts.siftUp(len(ts.heap) - 1)
	if t == ts.heap[0].timer {
		ts.updateMinWhenHeap()
	}
}

// maybeRunAsync checks whether t needs to be triggered and runs it if so.
// The caller is responsible for locking the timer and for checking that we
// are running timers in async mode. If the timer needs to be run,
// maybeRunAsync will unlock and re-lock it.
// The timer is always locked on return.
func (t *timer) maybeRunAsync() {
	assertLockHeld(&t.mu)
	if t.state&timerHeaped == 0 && t.isChan && t.when > 0 {
		// If timer should have triggered already (but nothing looked at it yet),
		// trigger now, so that a receive after the stop sees the "old" value
		// that should be there.
		// (It is possible to have t.blocked > 0 if there is a racing receive
		// in blockTimerChan, but timerHeaped not being set means
		// it hasn't run t.maybeAdd yet; in that case, running the
		// timer ourselves now is fine.)
		if now := nanotime(); t.when <= now {
			systemstack(func() {
				t.unlockAndRun(now) // resets t.when
			})
			t.lock()
		}
	}
}

// stop stops the timer t. It may be on some other P, so we can't
// actually remove it from the timers heap. We can only mark it as stopped.
// It will be removed in due course by the P whose heap it is on.
// Reports whether the timer was stopped before it was run.
func (t *timer) stop() bool {
	async := debug.asynctimerchan.Load() != 0
	if !async && t.isChan {
		lock(&t.sendLock)
	}

	t.lock()
	t.trace("stop")
	if async {
		t.maybeRunAsync()
	}
	if t.state&timerHeaped != 0 {
		t.state |= timerModified
		if t.state&timerZombie == 0 {
			t.state |= timerZombie
			t.ts.zombies.Add(1)
		}
	}
	pending := t.when > 0
	t.when = 0

	if !async && t.isChan {
		// Stop any future sends with stale values.
		// See timer.unlockAndRun.
		t.seq++

		// If there is currently a send in progress,
		// incrementing seq is going to prevent that
		// send from actually happening. That means
		// that we should return true: the timer was
		// stopped, even though t.when may be zero.
		if t.period == 0 && t.isSending.Load() > 0 {
			pending = true
		}
	}
	t.unlock()
	if !async && t.isChan {
		unlock(&t.sendLock)
		if timerchandrain(t.hchan()) {
			pending = true
		}
	}

	return pending
}

// deleteMin removes timer 0 from ts.
// ts must be locked.
func (ts *timers) deleteMin() {
	assertLockHeld(&ts.mu)
	t := ts.heap[0].timer
	if t.ts != ts {
		throw("wrong timers")
	}
	t.ts = nil
	last := len(ts.heap) - 1
	if last > 0 {
		ts.heap[0] = ts.heap[last]
	}
	ts.heap[last] = timerWhen{}
	ts.heap = ts.heap[:last]
	if last > 0 {
		ts.siftDown(0)
	}
	ts.updateMinWhenHeap()
	if last == 0 {
		// If there are no timers, then clearly there are no timerModified timers.
		ts.minWhenModified.Store(0)
	}
}

// modify modifies an existing timer.
// This is called by the netpoll code or time.Ticker.Reset or time.Timer.Reset.
// Reports whether the timer was modified before it was run.
// If f == nil, then t.f, t.arg, and t.seq are not modified.
func (t *timer) modify(when, period int64, f func(arg any, seq uintptr, delay int64), arg any, seq uintptr) bool {
	if when <= 0 {
		throw("timer when must be positive")
	}
	if period < 0 {
		throw("timer period must be non-negative")
	}
	async := debug.asynctimerchan.Load() != 0

	if !async && t.isChan {
		lock(&t.sendLock)
	}

	t.lock()
	if async {
		t.maybeRunAsync()
	}
	t.trace("modify")
	oldPeriod := t.period
	t.period = period
	if f != nil {
		t.f = f
		t.arg = arg
		t.seq = seq
	}

	wake := false
	pending := t.when > 0
	t.when = when
	if t.state&timerHeaped != 0 {
		t.state |= timerModified
		if t.state&timerZombie != 0 {
			// In the heap but marked for removal (by a Stop).
			// Unmark it, since it has been Reset and will be running again.
			t.ts.zombies.Add(-1)
			t.state &^= timerZombie
		}
		// The corresponding heap[i].when is updated later.
		// See comment in type timer above and in timers.adjust below.
		if min := t.ts.minWhenModified.Load(); min == 0 || when < min {
			wake = true
			// Force timerModified bit out to t.astate before updating t.minWhenModified,
			// to synchronize with t.ts.adjust. See comment in adjust.
			t.astate.Store(t.state)
			t.ts.updateMinWhenModified(when)
		}
	}

	add := t.needsAdd()

	if !async && t.isChan {
		// Stop any future sends with stale values.
		// See timer.unlockAndRun.
		t.seq++

		// If there is currently a send in progress,
		// incrementing seq is going to prevent that
		// send from actually happening. That means
		// that we should return true: the timer was
		// stopped, even though t.when may be zero.
		if oldPeriod == 0 && t.isSending.Load() > 0 {
			pending = true
		}
	}
	t.unlock()
	if !async && t.isChan {
		if timerchandrain(t.hchan()) {
			pending = true
		}
		unlock(&t.sendLock)
	}

	if add {
		t.maybeAdd()
	}
	if wake {
		wakeNetPoller(when)
	}

	return pending
}

// needsAdd reports whether t needs to be added to a timers heap.
// t must be locked.
func (t *timer) needsAdd() bool {
	assertLockHeld(&t.mu)
	need := t.state&timerHeaped == 0 && t.when > 0 && (!t.isChan || t.isFake || t.blocked > 0)
	if need {
		t.trace("needsAdd+")
	} else {
		t.trace("needsAdd-")
	}
	return need
}

// maybeAdd adds t to the local timers heap if it needs to be in a heap.
// The caller must not hold t's lock nor any timers heap lock.
// The caller probably just unlocked t, but that lock must be dropped
// in order to acquire a ts.lock, to avoid lock inversions.
// (timers.adjust holds ts.lock while acquiring each t's lock,
// so we cannot hold any t's lock while acquiring ts.lock).
//
// Strictly speaking it *might* be okay to hold t.lock and
// acquire ts.lock at the same time, because we know that
// t is not in any ts.heap, so nothing holding a ts.lock would
// be acquiring the t.lock at the same time, meaning there
// isn't a possible deadlock. But it is easier and safer not to be
// too clever and respect the static ordering.
// (If we don't, we have to change the static lock checking of t and ts.)
//
// Concurrent calls to time.Timer.Reset or blockTimerChan
// may result in concurrent calls to t.maybeAdd,
// so we cannot assume that t is not in a heap on entry to t.maybeAdd.
func (t *timer) maybeAdd() {
	// Note: Not holding any locks on entry to t.maybeAdd,
	// so the current g can be rescheduled to a different M and P
	// at any time, including between the ts := assignment and the
	// call to ts.lock. If a reschedule happened then, we would be
	// adding t to some other P's timers, perhaps even a P that the scheduler
	// has marked as idle with no timers, in which case the timer could
	// go unnoticed until long after t.when.
	// Calling acquirem instead of using getg().m makes sure that
	// we end up locking and inserting into the current P's timers.
	mp := acquirem()
	var ts *timers
	if t.isFake {
		sg := getg().syncGroup
		if sg == nil {
			throw("invalid timer: fake time but no syncgroup")
		}
		ts = &sg.timers
	} else {
		ts = &mp.p.ptr().timers
	}
	ts.lock()
	ts.cleanHead()
	t.lock()
	t.trace("maybeAdd")
	when := int64(0)
	wake := false
	if t.needsAdd() {
		t.state |= timerHeaped
		when = t.when
		wakeTime := ts.wakeTime()
		wake = wakeTime == 0 || when < wakeTime
		ts.addHeap(t)
	}
	t.unlock()
	ts.unlock()
	releasem(mp)
	if wake {
		wakeNetPoller(when)
	}
}

// reset resets the time when a timer should fire.
// If used for an inactive timer, the timer will become active.
// Reports whether the timer was active and was stopped.
func (t *timer) reset(when, period int64) bool {
	return t.modify(when, period, nil, nil, 0)
}

// cleanHead cleans up the head of the timer queue. This speeds up
// programs that create and delete timers; leaving them in the heap
// slows down heap operations.
// The caller must have locked ts.
func (ts *timers) cleanHead() {
	ts.trace("cleanHead")
	assertLockHeld(&ts.mu)
	gp := getg()
	for {
		if len(ts.heap) == 0 {
			return
		}

		// This loop can theoretically run for a while, and because
		// it is holding timersLock it cannot be preempted.
		// If someone is trying to preempt us, just return.
		// We can clean the timers later.
		if gp.preemptStop {
			return
		}

		// Delete zombies from tail of heap. It requires no heap adjustments at all,
		// and doing so increases the chances that when we swap out a zombie
		// in heap[0] for the tail of the heap, we'll get a non-zombie timer,
		// shortening this loop.
		n := len(ts.heap)
		if t := ts.heap[n-1].timer; t.astate.Load()&timerZombie != 0 {
			t.lock()
			if t.state&timerZombie != 0 {
				t.state &^= timerHeaped | timerZombie | timerModified
				t.ts = nil
				ts.zombies.Add(-1)
				ts.heap[n-1] = timerWhen{}
				ts.heap = ts.heap[:n-1]
			}
			t.unlock()
			continue
		}

		t := ts.heap[0].timer
		if t.ts != ts {
			throw("bad ts")
		}

		if t.astate.Load()&(timerModified|timerZombie) == 0 {
			// Fast path: head of timers does not need adjustment.
			return
		}

		t.lock()
		updated := t.updateHeap()
		t.unlock()
		if !updated {
			// Head of timers does not need adjustment.
			return
		}
	}
}

// take moves any timers from src into ts
// and then clears the timer state from src,
// because src is being destroyed.
// The caller must not have locked either timers.
// For now this is only called when the world is stopped.
func (ts *timers) take(src *timers) {
	ts.trace("take")
	assertWorldStopped()
	if len(src.heap) > 0 {
		// The world is stopped, so we ignore the locking of ts and src here.
		// That would introduce a sched < timers lock ordering,
		// which we'd rather avoid in the static ranking.
		for _, tw := range src.heap {
			t := tw.timer
			t.ts = nil
			if t.state&timerZombie != 0 {
				t.state &^= timerHeaped | timerZombie | timerModified
			} else {
				t.state &^= timerModified
				ts.addHeap(t)
			}
		}
		src.heap = nil
		src.zombies.Store(0)
		src.minWhenHeap.Store(0)
		src.minWhenModified.Store(0)
		src.len.Store(0)
		ts.len.Store(uint32(len(ts.heap)))
	}
}

// adjust looks through the timers in ts.heap for
// any timers that have been modified to run earlier, and puts them in
// the correct place in the heap. While looking for those timers,
// it also moves timers that have been modified to run later,
// and removes deleted timers. The caller must have locked ts.
func (ts *timers) adjust(now int64, force bool) {
	ts.trace("adjust")
	assertLockHeld(&ts.mu)
	// If we haven't yet reached the time of the earliest modified
	// timer, don't do anything. This speeds up programs that adjust
	// a lot of timers back and forth if the timers rarely expire.
	// We'll postpone looking through all the adjusted timers until
	// one would actually expire.
	if !force {
		first := ts.minWhenModified.Load()
		if first == 0 || first > now {
			if verifyTimers {
				ts.verify()
			}
			return
		}
	}

	// minWhenModified is a lower bound on the earliest t.when
	// among the timerModified timers. We want to make it more precise:
	// we are going to scan the heap and clean out all the timerModified bits,
	// at which point minWhenModified can be set to 0 (indicating none at all).
	//
	// Other P's can be calling ts.wakeTime concurrently, and we'd like to
	// keep ts.wakeTime returning an accurate value throughout this entire process.
	//
	// Setting minWhenModified = 0 *before* the scan could make wakeTime
	// return an incorrect value: if minWhenModified < minWhenHeap, then clearing
	// it to 0 will make wakeTime return minWhenHeap (too late) until the scan finishes.
	// To avoid that, we want to set minWhenModified to 0 *after* the scan.
	//
	// Setting minWhenModified = 0 *after* the scan could result in missing
	// concurrent timer modifications in other goroutines; those will lock
	// the specific timer, set the timerModified bit, and set t.when.
	// To avoid that, we want to set minWhenModified to 0 *before* the scan.
	//
	// The way out of this dilemma is to preserve wakeTime a different way.
	// wakeTime is min(minWhenHeap, minWhenModified), and minWhenHeap
	// is protected by ts.lock, which we hold, so we can modify it however we like
	// in service of keeping wakeTime accurate.
	//
	// So we can:
	//
	//	1. Set minWhenHeap = min(minWhenHeap, minWhenModified)
	//	2. Set minWhenModified = 0
	//	   (Other goroutines may modify timers and update minWhenModified now.)
	//	3. Scan timers
	//	4. Set minWhenHeap = heap[0].when
	//
	// That order preserves a correct value of wakeTime throughout the entire
	// operation:
	// Step 1 “locks in” an accurate wakeTime even with minWhenModified cleared.
	// Step 2 makes sure concurrent t.when updates are not lost during the scan.
	// Step 3 processes all modified timer values, justifying minWhenModified = 0.
	// Step 4 corrects minWhenHeap to a precise value.
	//
	// The wakeTime method implementation reads minWhenModified *before* minWhenHeap,
	// so that if the minWhenModified is observed to be 0, that means the minWhenHeap that
	// follows will include the information that was zeroed out of it.
	//
	// Originally Step 3 locked every timer, which made sure any timer update that was
	// already in progress during Steps 1+2 completed and was observed by Step 3.
	// All that locking was too expensive, so now we do an atomic load of t.astate to
	// decide whether we need to do a full lock. To make sure that we still observe any
	// timer update already in progress during Steps 1+2, t.modify sets timerModified
	// in t.astate *before* calling t.updateMinWhenModified. That ensures that the
	// overwrite in Step 2 cannot lose an update: if it does overwrite an update, Step 3
	// will see the timerModified and do a full lock.
	ts.minWhenHeap.Store(ts.wakeTime())
	ts.minWhenModified.Store(0)

	changed := false
	for i := 0; i < len(ts.heap); i++ {
		tw := &ts.heap[i]
		t := tw.timer
		if t.ts != ts {
			throw("bad ts")
		}

		if t.astate.Load()&(timerModified|timerZombie) == 0 {
			// Does not need adjustment.
			continue
		}

		t.lock()
		switch {
		case t.state&timerHeaped == 0:
			badTimer()

		case t.state&timerZombie != 0:
			ts.zombies.Add(-1)
			t.state &^= timerHeaped | timerZombie | timerModified
			n := len(ts.heap)
			ts.heap[i] = ts.heap[n-1]
			ts.heap[n-1] = timerWhen{}
			ts.heap = ts.heap[:n-1]
			t.ts = nil
			i--
			changed = true

		case t.state&timerModified != 0:
			tw.when = t.when
			t.state &^= timerModified
			changed = true
		}
		t.unlock()
	}

	if changed {
		ts.initHeap()
	}
	ts.updateMinWhenHeap()

	if verifyTimers {
		ts.verify()
	}
}

// wakeTime looks at ts's timers and returns the time when we
// should wake up the netpoller. It returns 0 if there are no timers.
// This function is invoked when dropping a P, so it must run without
// any write barriers.
//
//go:nowritebarrierrec
func (ts *timers) wakeTime() int64 {
	// Note that the order of these two loads matters:
	// adjust updates minWhen to make it safe to clear minNextWhen.
	// We read minWhen after reading minNextWhen so that
	// if we see a cleared minNextWhen, we are guaranteed to see
	// the updated minWhen.
	nextWhen := ts.minWhenModified.Load()
	when := ts.minWhenHeap.Load()
	if when == 0 || (nextWhen != 0 && nextWhen < when) {
		when = nextWhen
	}
	return when
}

// check runs any timers in ts that are ready.
// If now is not 0 it is the current time.
// It returns the passed time or the current time if now was passed as 0.
// and the time when the next timer should run or 0 if there is no next timer,
// and reports whether it ran any timers.
// If the time when the next timer should run is not 0,
// it is always larger than the returned time.
// We pass now in and out to avoid extra calls of nanotime.
//
//go:yeswritebarrierrec
func (ts *timers) check(now int64) (rnow, pollUntil int64, ran bool) {
	ts.trace("check")
	// If it's not yet time for the first timer, or the first adjusted
	// timer, then there is nothing to do.
	next := ts.wakeTime()
	if next == 0 {
		// No timers to run or adjust.
		return now, 0, false
	}

	if now == 0 {
		now = nanotime()
	}

	// If this is the local P, and there are a lot of deleted timers,
	// clear them out. We only do this for the local P to reduce
	// lock contention on timersLock.
	zombies := ts.zombies.Load()
	if zombies < 0 {
		badTimer()
	}
	force := ts == &getg().m.p.ptr().timers && int(zombies) > int(ts.len.Load())/4

	if now < next && !force {
		// Next timer is not ready to run, and we don't need to clear deleted timers.
		return now, next, false
	}

	ts.lock()
	if len(ts.heap) > 0 {
		ts.adjust(now, false)
		for len(ts.heap) > 0 {
			// Note that runtimer may temporarily unlock ts.
			if tw := ts.run(now); tw != 0 {
				if tw > 0 {
					pollUntil = tw
				}
				break
			}
			ran = true
		}

		// Note: Delaying the forced adjustment until after the ts.run
		// (as opposed to calling ts.adjust(now, force) above)
		// is significantly faster under contention, such as in
		// package time's BenchmarkTimerAdjust10000,
		// though we do not fully understand why.
		force = ts == &getg().m.p.ptr().timers && int(ts.zombies.Load()) > int(ts.len.Load())/4
		if force {
			ts.adjust(now, true)
		}
	}
	ts.unlock()

	return now, pollUntil, ran
}

// run examines the first timer in ts. If it is ready based on now,
// it runs the timer and removes or updates it.
// Returns 0 if it ran a timer, -1 if there are no more timers, or the time
// when the first timer should run.
// The caller must have locked ts.
// If a timer is run, this will temporarily unlock ts.
//
//go:systemstack
func (ts *timers) run(now int64) int64 {
	ts.trace("run")
	assertLockHeld(&ts.mu)
Redo:
	if len(ts.heap) == 0 {
		return -1
	}
	tw := ts.heap[0]
	t := tw.timer
	if t.ts != ts {
		throw("bad ts")
	}

	if t.astate.Load()&(timerModified|timerZombie) == 0 && tw.when > now {
		// Fast path: not ready to run.
		return tw.when
	}

	t.lock()
	if t.updateHeap() {
		t.unlock()
		goto Redo
	}

	if t.state&timerHeaped == 0 || t.state&timerModified != 0 {
		badTimer()
	}

	if t.when > now {
		// Not ready to run.
		t.unlock()
		return t.when
	}

	t.unlockAndRun(now)
	assertLockHeld(&ts.mu) // t is unlocked now, but not ts
	return 0
}

// unlockAndRun unlocks and runs the timer t (which must be locked).
// If t is in a timer set (t.ts != nil), the caller must also have locked the timer set,
// and this call will temporarily unlock the timer set while running the timer function.
// unlockAndRun returns with t unlocked and t.ts (re-)locked.
//
//go:systemstack
func (t *timer) unlockAndRun(now int64) {
	t.trace("unlockAndRun")
	assertLockHeld(&t.mu)
	if t.ts != nil {
		assertLockHeld(&t.ts.mu)
	}
	if raceenabled {
		// Note that we are running on a system stack,
		// so there is no chance of getg().m being reassigned
		// out from under us while this function executes.
		tsLocal := &getg().m.p.ptr().timers
		if tsLocal.raceCtx == 0 {
			tsLocal.raceCtx = racegostart(abi.FuncPCABIInternal((*timers).run) + sys.PCQuantum)
		}
		raceacquirectx(tsLocal.raceCtx, unsafe.Pointer(t))
	}

	if t.state&(timerModified|timerZombie) != 0 {
		badTimer()
	}

	f := t.f
	arg := t.arg
	seq := t.seq
	var next int64
	delay := now - t.when
	if t.period > 0 {
		// Leave in heap but adjust next time to fire.
		next = t.when + t.period*(1+delay/t.period)
		if next < 0 { /
"""




```