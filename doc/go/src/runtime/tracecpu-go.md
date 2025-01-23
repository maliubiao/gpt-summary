Response:
我的目标是理解并解释给定的 Go 代码片段 `go/src/runtime/tracecpu.go` 的功能。我的思考过程如下：

1. **通读代码，识别关键函数和数据结构：**  首先，我浏览了代码，注意到了一些重要的函数名，如 `traceInitReadCPU`, `traceStartReadCPU`, `traceStopReadCPU`, `traceReadCPU`, `traceCPUFlush`, `traceCPUSample`。这些函数名暗示了代码与 CPU 性能数据的读取、开始、停止、刷新和采样有关。  我还注意到了 `trace` 包以及 `profBuf` 结构体，它们似乎是核心组件。

2. **逐个函数分析，理解其目的和机制：**

   * **`traceInitReadCPU`:**  函数名中的 "InitReadCPU" 表明这是初始化读取 CPU 数据的过程。代码创建了两个 `profBuf` 实例 (`trace.cpuLogRead`) 用于存储 CPU 采样数据。  `trace.cpuLogWrite` 看起来是指向这两个缓冲区的指针，并且使用了原子操作 (`Store`)，这暗示了可能有并发访问。注释提到“CPU profile -> tracer state for tracing”，表明这是将 CPU 性能数据整合到 Go 的 tracing 系统中。

   * **`traceStartReadCPU`:**  "StartReadCPU" 表明这是启动读取 CPU 数据的过程。 代码创建了一个新的 goroutine 来持续读取 CPU 数据。  这个 goroutine 使用 `traceReadCPU` 函数读取数据，并且在循环中使用 `trace.cpuSleep.sleep` 来避免过于频繁的读取，这类似于 `runtime/pprof` 的行为。注释提到了 Darwin 平台的限制，以及避免频繁唤醒的需求。

   * **`traceStopReadCPU`:** "StopReadCPU" 表明这是停止读取 CPU 数据的过程。  它关闭了 `profBuf` 并唤醒了读取数据的 goroutine，确保该 goroutine 能够感知到停止信号并退出。 代码使用了 channel `trace.cpuLogDone` 来等待 goroutine 的退出。

   * **`traceReadCPU`:**  这是核心的读取函数。它从 `profBuf` 中读取数据，解析数据，并将其转换为 tracing 事件。  它处理了数据截断、格式错误和溢出记录的情况。  它将读取到的堆栈信息存储到 `trace.stackTab` 中，并使用 `unsafeTraceWriter` 将事件写入 trace buffer。

   * **`traceCPUFlush`:**  这个函数的作用是刷新 `trace.cpuBuf` 中的数据。它确保在某个 tracing generation 完成后，所有缓冲的数据都被写入。  使用了 `systemstack` 和锁来确保操作的安全性。

   * **`traceCPUSample`:**  这是从信号处理程序中调用的函数，用于记录 CPU 采样。 由于在信号处理程序中运行，它受到了限制。  它首先检查 tracing 是否启用，并尝试获取 `mp.trace.seqlock` 以确定当前的 tracing generation。  然后，它构建包含 goroutine、m 和 p 的信息的头部，并使用原子操作获取 `trace.signalLock` 来写入 `profBuf`。

3. **推断 Go 功能：**  通过对各个函数的分析，我得出结论，这段代码是 Go runtime 中用于将 CPU profile 数据集成到 execution trace 的实现。这意味着当启用 Go 的 tracing 功能时，可以捕获 CPU 采样的信息，并将这些信息作为事件包含在 trace 中。

4. **代码示例：**  为了说明这个功能，我需要展示如何启用 Go tracing 并生成包含 CPU 采样的 trace 数据。  我选择了使用 `runtime/trace` 包的标准方法，即在程序开始时调用 `trace.Start`，在程序结束时调用 `trace.Stop`。

5. **命令行参数：**  Go 的 tracing 功能主要通过 `go tool trace` 命令行工具来分析 trace 文件。  我需要解释如何生成 trace 文件，并提及 `go tool trace` 命令。

6. **易犯错误：**  我认为最容易犯的错误是在 tracing 启用时调用 `traceInitReadCPU`，因为这会导致 panic。  我还想到了在信号处理程序中使用锁的潜在问题，但这在代码中已经通过原子操作和自旋等待来处理了。  不过，我可以强调在信号处理程序中编程的限制，以及可能出现的死锁风险。

7. **组织答案，使用中文：**  最后，我将所有分析结果、代码示例、命令行参数和易犯错误整理成清晰的中文描述。  我尽量使用准确的术语，并解释关键概念，如 `profBuf` 和 tracing 的工作原理。  我添加了代码注释，使代码示例更易理解。

通过以上步骤，我构建了对给定 Go 代码片段的全面解释，涵盖了其功能、实现机制、使用方法和潜在的陷阱。
这段 Go 语言代码是 `runtime` 包中负责将 **CPU profile 数据集成到 Go execution trace** 的一部分。

简单来说，它的功能是：**当 Go 程序启用 execution trace 时，它能够将 CPU profiling 的采样数据也记录到 trace 中，以便用户可以分析程序在哪些函数上花费了多少 CPU 时间。**

下面我们来详细解释各个部分的功能：

**1. `traceInitReadCPU()`**

* **功能:** 初始化 CPU profile 到 trace 状态。
* **目的:** 在开始 tracing 之前，设置用于读取 CPU profile 数据的缓冲区。
* **机制:**
    * 创建两个 `profBuf` 实例 (`trace.cpuLogRead[0]` 和 `trace.cpuLogRead[1]`) 用于临时存储 CPU 采样数据。 每个 `profBuf` 都有固定数量的字 (`profBufWordCount`) 和标签 (`profBufTagCount`)。
    * `profBuf` 存储的格式是：时间戳之后，是头部信息 `[pp.id, gp.goid, mp.procid]`。
    * 将 `trace.cpuLogWrite` 指向 `trace.cpuLogRead`，`trace.cpuLogWrite` 用于在信号处理程序中写入数据，这里使用原子操作 `Store` 是因为写入可能发生在信号处理上下文中，需要避免数据竞争。
* **易犯错误:**  如果在 tracing 已经启用时调用 `traceInitReadCPU`，会导致程序 `throw` (panic)。

**2. `traceStartReadCPU()`**

* **功能:** 创建一个 goroutine 来开始将 CPU profile 数据读取到活跃的 trace 中。
* **目的:** 启动一个后台 goroutine，定期从 `profBuf` 中读取 CPU 采样数据，并将其转换为 trace 事件。
* **机制:**
    * 检查 tracing 是否已启用，如果未启用则抛出异常。
    * 创建一个 `wakeableSleep` 实例 `trace.cpuSleep`，用于控制读取 goroutine 的休眠和唤醒。
    * 启动一个新的 goroutine：
        * 在循环中，只要 tracing 启用，就会执行以下操作：
            * 休眠一段时间 (`trace.cpuSleep.sleep(100_000_000)`)，避免频繁读取。这模仿了 `runtime/pprof` 包的行为。
            * 获取 trace 锁 (`traceAcquire`)。
            * 调用 `traceReadCPU` 从 `profBuf` 读取数据并将其写入 trace。
            * 释放 trace 锁 (`traceRelease`).
            * 如果 `traceReadCPU` 返回 `false`，则退出循环（表示 `profBuf` 已关闭或应停止读取）。
    * 使用 channel `trace.cpuLogDone` 来通知主 goroutine 读取 goroutine 已退出。
* **与 `runtime/pprof` 的关联:**  注释中提到，这里的休眠和非阻塞读取策略与 `runtime/pprof` 包获取 CPU profile 数据的方式类似。这是因为 Darwin 平台（macOS）的限制，无法在信号处理程序中进行阻塞唤醒。

**3. `traceStopReadCPU()`**

* **功能:** 阻塞直到读取 CPU 数据的 goroutine 退出。
* **目的:** 在停止 tracing 时，确保读取 CPU 数据的 goroutine 已经安全退出。
* **机制:**
    * 检查 tracing 是否已禁用，如果未禁用则抛出异常。
    * 将 `trace.cpuLogWrite` 指向 `nil`，并关闭 `trace.cpuLogRead`，这会通知读取 goroutine 缓冲区已关闭。
    * 唤醒读取 goroutine (`trace.cpuSleep.wake()`)，以便它可以观察到缓冲区已关闭并退出。
    * 等待读取 goroutine 通过 `trace.cpuLogDone` channel 发送信号表示已退出。
    * 清理相关状态，为下一次 trace 做准备。

**4. `traceReadCPU(gen uintptr)`**

* **功能:** 尝试从提供的 `profBuf[gen%2]` 中读取数据并写入到 trace 中。
* **目的:**  实际执行从 `profBuf` 读取 CPU 采样数据并将其转换为 trace 事件的操作。
* **机制:**
    * 从 `trace.cpuLogRead[gen%2]` 中非阻塞地读取数据 (`profBufNonBlocking`)。
    * 循环处理读取到的数据：
        * 检查数据的完整性和格式。
        * 反序列化 profile 缓冲区中的数据，包括时间戳、ppid、goid、mpid 和堆栈信息。
        * 处理溢出记录 (overflow record)。
        * 构建堆栈信息 (`pcBuf`)。
        * 使用 `unsafeTraceWriter` 获取 trace buffer 的写入器。
        * 确保有足够的空间写入 trace 事件。
        * 将堆栈信息添加到堆栈表 (`trace.stackTab`).
        * 写入 `traceEvCPUSample` 事件，包含时间戳、mpid、ppid、goid 和 stackID。
    * 返回 `true` 如果可能还有更多数据要读取，否则返回 `false`。
* **重要约束:**
    * 调用者必须确保 `gen` 在调用期间不会改变，这通常通过持有 `traceAcquire/traceRelease` 锁或者 `traceAdvanceSema` 信号量来实现。
    * 同一个 `profBuf` 在同一时间只能有一个 goroutine 调用 `traceReadCPU`。
    * **不能在系统栈上运行**，因为 `profBuf.read` 执行了竞态操作 (race operations)。

**5. `traceCPUFlush(gen uintptr)`**

* **功能:** 刷新 `trace.cpuBuf[gen%2]`。
* **目的:** 确保所有缓冲的 CPU 采样数据都被写入到 trace 文件中。
* **机制:**
    * 检查对应的 CPU buffer (`trace.cpuBuf[gen%2]`) 是否存在。
    * 在系统栈上执行一个匿名函数：
        * 获取 trace 锁 (`trace.lock`).
        * 调用 `traceBufFlush` 将 buffer 中的数据刷新到 trace。
        * 释放 trace 锁。
        * 将 CPU buffer 设置为 `nil`.
* **使用场景:** 当某个 tracing generation 完成并且不再有写入者时调用。

**6. `traceCPUSample(gp *g, mp *m, pp *p, stk []uintptr)`**

* **功能:** 将 CPU profile 采样堆栈写入到 execution tracer 的 profiling 缓冲区。
* **目的:**  在发生 CPU 采样时，将采样到的堆栈信息记录到 `profBuf` 中。
* **机制:**
    * **在信号处理程序中调用，因此有严格的限制。**
    * 检查 tracing 是否启用，如果未启用则快速返回。
    * 如果 `mp` 为 `nil` (无法识别的线程)，则丢弃采样。
    * 尝试获取当前线程的 trace seqlock (`mp.trace.seqlock`)。如果未持有，则获取它并标记 `locked` 为 `true`。
    * 获取当前的 tracing generation (`trace.gen`).
    * 如果 tracing 已禁用，释放 seqlock (如果之前获取了) 并返回。
    * 获取当前时间戳 (`traceClockNow`).
    * 构建头部信息 `hdr`，包含 ppid、goid 和 mpid。
        * 如果 `pp` 不为 `nil`，则 `hdr[0]` 存储 `pp.id` 并设置最低位为 1。
        * 如果 `pp` 为 `nil`，则设置 `hdr[0]` 的最低两位为 10。
        * `hdr[1]` 存储 `gp.goid`。
        * `hdr[2]` 存储 `mp.procid`。
    * 使用自旋锁 (`trace.signalLock`) 确保只有一个写入者访问 `profBuf`。
    * 如果对应的 `trace.cpuLogWrite[gen%2]` 不为 `nil`，则调用 `log.write` 将采样数据写入 `profBuf`。
    * 释放 `trace.signalLock`。
    * 如果在函数开始时获取了 seqlock，则释放它。

**总结 Go 语言功能:**

这段代码实现了 Go 的 execution trace 功能中收集 CPU profile 数据的功能。当你在运行 Go 程序时启用了 tracing (例如，通过 `import _ "net/http/pprof"` 并访问 `/debug/pprof/trace` 或者使用 `go test -trace=trace.out`)，Go runtime 会定期进行 CPU 采样，并将这些采样数据记录到 trace 文件中。然后，你可以使用 `go tool trace` 命令来分析这个 trace 文件，查看程序在不同函数上的 CPU 耗时。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"os"
	"runtime/trace"
	"time"
)

func expensiveFunction() {
	// 模拟一个耗时的操作
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i
	}
}

func main() {
	f, err := os.Create("trace.out")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = trace.Start(f)
	if err != nil {
		panic(err)
	}
	defer trace.Stop()

	fmt.Println("Starting trace...")

	for i := 0; i < 10; i++ {
		expensiveFunction()
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("Trace finished.")
}
```

**假设的输入与输出 (对于 `traceReadCPU`)：**

**假设输入:**  `trace.cpuLogRead[0]` 中包含以下模拟的 CPU 采样数据：

```
data = [
  5,         // recordLen
  1678886400, // timestamp
  (1 << 1) | 1, // ppid = 1
  100,       // goid
  2,         // mpid
  0x400000,  // stack frame 1
  0x401000,  // stack frame 2
]
```

**预期输出 (部分 trace 事件):**

`traceReadCPU` 会将上述数据转换为一个 `traceEvCPUSample` 事件，并写入到 `trace.cpuBuf[0]`。这个事件会包含：

* 事件类型: `traceEvCPUSample`
* 时间戳: `1678886400`
* mpid: `2`
* ppid: `1`
* goid: `100`
* stackID:  指向包含 `0x400000` 和 `0x401000` 的堆栈信息的 ID。

**命令行参数的具体处理：**

这段代码本身不直接处理命令行参数。CPU profiling 和 tracing 的启用通常是通过以下方式：

* **`runtime/trace` 包：** 在你的 Go 代码中使用 `runtime/trace` 包的 `trace.Start()` 和 `trace.Stop()` 函数来控制 tracing 的开始和结束，并将 trace 数据写入指定的文件。
* **`go test` 命令：**  可以使用 `go test -trace=trace.out` 命令来运行测试并生成 trace 文件。
* **`net/http/pprof` 包：**  导入 `net/http/pprof` 包会在你的 HTTP 服务中注册 `/debug/pprof/trace` 接口，你可以通过访问这个接口来启动和下载 trace 文件。

**使用者易犯错的点：**

1. **在 tracing 启用时调用 `traceInitReadCPU`:**  如前所述，这会导致 panic。使用者需要确保在 tracing 启动前调用 `traceInitReadCPU`。

2. **在信号处理程序中进行复杂操作：** `traceCPUSample` 函数在信号处理程序中运行，因此必须非常小心，避免执行可能导致死锁或崩溃的操作。这段代码通过使用原子操作和自旋锁来尽量保证安全。

3. **忘记停止 trace：** 如果使用 `runtime/trace` 包手动启动了 tracing，务必记得在程序结束前调用 `trace.Stop()`，否则 trace 文件可能不完整。

4. **不理解 trace 数据的含义：**  生成的 trace 文件是二进制格式，需要使用 `go tool trace` 命令来解析和分析。不了解 trace 工具的使用方法可能导致无法有效利用 trace 数据。

总而言之，`go/src/runtime/tracecpu.go` 是 Go runtime 中一个关键的组成部分，它负责将底层的 CPU profiling 数据桥接到高级的 execution tracing 系统，为 Go 开发者提供了强大的性能分析工具。

### 提示词
```
这是路径为go/src/runtime/tracecpu.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// CPU profile -> trace

package runtime

// traceInitReadCPU initializes CPU profile -> tracer state for tracing.
//
// Returns a profBuf for reading from.
func traceInitReadCPU() {
	if traceEnabled() {
		throw("traceInitReadCPU called with trace enabled")
	}
	// Create new profBuf for CPU samples that will be emitted as events.
	// Format: after the timestamp, header is [pp.id, gp.goid, mp.procid].
	trace.cpuLogRead[0] = newProfBuf(3, profBufWordCount, profBufTagCount)
	trace.cpuLogRead[1] = newProfBuf(3, profBufWordCount, profBufTagCount)
	// We must not acquire trace.signalLock outside of a signal handler: a
	// profiling signal may arrive at any time and try to acquire it, leading to
	// deadlock. Because we can't use that lock to protect updates to
	// trace.cpuLogWrite (only use of the structure it references), reads and
	// writes of the pointer must be atomic. (And although this field is never
	// the sole pointer to the profBuf value, it's best to allow a write barrier
	// here.)
	trace.cpuLogWrite[0].Store(trace.cpuLogRead[0])
	trace.cpuLogWrite[1].Store(trace.cpuLogRead[1])
}

// traceStartReadCPU creates a goroutine to start reading CPU profile
// data into an active trace.
//
// traceAdvanceSema must be held.
func traceStartReadCPU() {
	if !traceEnabled() {
		throw("traceStartReadCPU called with trace disabled")
	}
	// Spin up the logger goroutine.
	trace.cpuSleep = newWakeableSleep()
	done := make(chan struct{}, 1)
	go func() {
		for traceEnabled() {
			// Sleep here because traceReadCPU is non-blocking. This mirrors
			// how the runtime/pprof package obtains CPU profile data.
			//
			// We can't do a blocking read here because Darwin can't do a
			// wakeup from a signal handler, so all CPU profiling is just
			// non-blocking. See #61768 for more details.
			//
			// Like the runtime/pprof package, even if that bug didn't exist
			// we would still want to do a goroutine-level sleep in between
			// reads to avoid frequent wakeups.
			trace.cpuSleep.sleep(100_000_000)

			tl := traceAcquire()
			if !tl.ok() {
				// Tracing disabled.
				break
			}
			keepGoing := traceReadCPU(tl.gen)
			traceRelease(tl)
			if !keepGoing {
				break
			}
		}
		done <- struct{}{}
	}()
	trace.cpuLogDone = done
}

// traceStopReadCPU blocks until the trace CPU reading goroutine exits.
//
// traceAdvanceSema must be held, and tracing must be disabled.
func traceStopReadCPU() {
	if traceEnabled() {
		throw("traceStopReadCPU called with trace enabled")
	}

	// Once we close the profbuf, we'll be in one of two situations:
	// - The logger goroutine has already exited because it observed
	//   that the trace is disabled.
	// - The logger goroutine is asleep.
	//
	// Wake the goroutine so it can observe that their the buffer is
	// closed an exit.
	trace.cpuLogWrite[0].Store(nil)
	trace.cpuLogWrite[1].Store(nil)
	trace.cpuLogRead[0].close()
	trace.cpuLogRead[1].close()
	trace.cpuSleep.wake()

	// Wait until the logger goroutine exits.
	<-trace.cpuLogDone

	// Clear state for the next trace.
	trace.cpuLogDone = nil
	trace.cpuLogRead[0] = nil
	trace.cpuLogRead[1] = nil
	trace.cpuSleep.close()
}

// traceReadCPU attempts to read from the provided profBuf[gen%2] and write
// into the trace. Returns true if there might be more to read or false
// if the profBuf is closed or the caller should otherwise stop reading.
//
// The caller is responsible for ensuring that gen does not change. Either
// the caller must be in a traceAcquire/traceRelease block, or must be calling
// with traceAdvanceSema held.
//
// No more than one goroutine may be in traceReadCPU for the same
// profBuf at a time.
//
// Must not run on the system stack because profBuf.read performs race
// operations.
func traceReadCPU(gen uintptr) bool {
	var pcBuf [traceStackSize]uintptr

	data, tags, eof := trace.cpuLogRead[gen%2].read(profBufNonBlocking)
	for len(data) > 0 {
		if len(data) < 4 || data[0] > uint64(len(data)) {
			break // truncated profile
		}
		if data[0] < 4 || tags != nil && len(tags) < 1 {
			break // malformed profile
		}
		if len(tags) < 1 {
			break // mismatched profile records and tags
		}

		// Deserialize the data in the profile buffer.
		recordLen := data[0]
		timestamp := data[1]
		ppid := data[2] >> 1
		if hasP := (data[2] & 0b1) != 0; !hasP {
			ppid = ^uint64(0)
		}
		goid := data[3]
		mpid := data[4]
		stk := data[5:recordLen]

		// Overflow records always have their headers contain
		// all zeroes.
		isOverflowRecord := len(stk) == 1 && data[2] == 0 && data[3] == 0 && data[4] == 0

		// Move the data iterator forward.
		data = data[recordLen:]
		// No support here for reporting goroutine tags at the moment; if
		// that information is to be part of the execution trace, we'd
		// probably want to see when the tags are applied and when they
		// change, instead of only seeing them when we get a CPU sample.
		tags = tags[1:]

		if isOverflowRecord {
			// Looks like an overflow record from the profBuf. Not much to
			// do here, we only want to report full records.
			continue
		}

		// Construct the stack for insertion to the stack table.
		nstk := 1
		pcBuf[0] = logicalStackSentinel
		for ; nstk < len(pcBuf) && nstk-1 < len(stk); nstk++ {
			pcBuf[nstk] = uintptr(stk[nstk-1])
		}

		// Write out a trace event.
		w := unsafeTraceWriter(gen, trace.cpuBuf[gen%2])

		// Ensure we have a place to write to.
		var flushed bool
		w, flushed = w.ensure(2 + 5*traceBytesPerNumber /* traceEvCPUSamples + traceEvCPUSample + timestamp + g + m + p + stack ID */)
		if flushed {
			// Annotate the batch as containing strings.
			w.byte(byte(traceEvCPUSamples))
		}

		// Add the stack to the table.
		stackID := trace.stackTab[gen%2].put(pcBuf[:nstk])

		// Write out the CPU sample.
		w.byte(byte(traceEvCPUSample))
		w.varint(timestamp)
		w.varint(mpid)
		w.varint(ppid)
		w.varint(goid)
		w.varint(stackID)

		trace.cpuBuf[gen%2] = w.traceBuf
	}
	return !eof
}

// traceCPUFlush flushes trace.cpuBuf[gen%2]. The caller must be certain that gen
// has completed and that there are no more writers to it.
func traceCPUFlush(gen uintptr) {
	// Flush any remaining trace buffers containing CPU samples.
	if buf := trace.cpuBuf[gen%2]; buf != nil {
		systemstack(func() {
			lock(&trace.lock)
			traceBufFlush(buf, gen)
			unlock(&trace.lock)
			trace.cpuBuf[gen%2] = nil
		})
	}
}

// traceCPUSample writes a CPU profile sample stack to the execution tracer's
// profiling buffer. It is called from a signal handler, so is limited in what
// it can do. mp must be the thread that is currently stopped in a signal.
func traceCPUSample(gp *g, mp *m, pp *p, stk []uintptr) {
	if !traceEnabled() {
		// Tracing is usually turned off; don't spend time acquiring the signal
		// lock unless it's active.
		return
	}
	if mp == nil {
		// Drop samples that don't have an identifiable thread. We can't render
		// this in any useful way anyway.
		return
	}

	// We're going to conditionally write to one of two buffers based on the
	// generation. To make sure we write to the correct one, we need to make
	// sure this thread's trace seqlock is held. If it already is, then we're
	// in the tracer and we can just take advantage of that. If it isn't, then
	// we need to acquire it and read the generation.
	locked := false
	if mp.trace.seqlock.Load()%2 == 0 {
		mp.trace.seqlock.Add(1)
		locked = true
	}
	gen := trace.gen.Load()
	if gen == 0 {
		// Tracing is disabled, as it turns out. Release the seqlock if necessary
		// and exit.
		if locked {
			mp.trace.seqlock.Add(1)
		}
		return
	}

	now := traceClockNow()
	// The "header" here is the ID of the M that was running the profiled code,
	// followed by the IDs of the P and goroutine. (For normal CPU profiling, it's
	// usually the number of samples with the given stack.) Near syscalls, pp
	// may be nil. Reporting goid of 0 is fine for either g0 or a nil gp.
	var hdr [3]uint64
	if pp != nil {
		// Overflow records in profBuf have all header values set to zero. Make
		// sure that real headers have at least one bit set.
		hdr[0] = uint64(pp.id)<<1 | 0b1
	} else {
		hdr[0] = 0b10
	}
	if gp != nil {
		hdr[1] = gp.goid
	}
	hdr[2] = uint64(mp.procid)

	// Allow only one writer at a time
	for !trace.signalLock.CompareAndSwap(0, 1) {
		// TODO: Is it safe to osyield here? https://go.dev/issue/52672
		osyield()
	}

	if log := trace.cpuLogWrite[gen%2].Load(); log != nil {
		// Note: we don't pass a tag pointer here (how should profiling tags
		// interact with the execution tracer?), but if we did we'd need to be
		// careful about write barriers. See the long comment in profBuf.write.
		log.write(nil, int64(now), hdr[:], stk)
	}

	trace.signalLock.Store(0)

	// Release the seqlock if we acquired it earlier.
	if locked {
		mp.trace.seqlock.Add(1)
	}
}
```