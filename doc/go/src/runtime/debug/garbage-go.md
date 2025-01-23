Response:
Let's break down the thought process for analyzing this Go code snippet and generating the answer.

**1. Understanding the Goal:**

The request asks for a functional breakdown of the provided Go code (`go/src/runtime/debug/garbage.go`). Specifically, it asks for:

* **Functionality listing:** What each function does.
* **Underlying Go feature:**  What core Go capability this code relates to.
* **Go code example:**  Demonstrating usage.
* **Input/Output (for code inference):** Showing how the functions behave with sample data.
* **Command-line arguments:** Details on how any parameters are handled.
* **Common mistakes:**  Potential pitfalls for users.
* **Language:**  The answer should be in Chinese.

**2. Initial Code Scan and Function Identification:**

The first step is to read through the code and identify the publicly exported functions. These are the ones that start with a capital letter:

* `GCStats` (struct)
* `ReadGCStats`
* `SetGCPercent`
* `FreeOSMemory`
* `SetMaxStack`
* `SetMaxThreads`
* `SetPanicOnFault`
* `WriteHeapDump`
* `SetTraceback`
* `SetMemoryLimit`

**3. Analyzing Each Function (and Struct):**

For each function, I considered the following:

* **Doc Comments:** The doc comments are invaluable. They provide a high-level description of the function's purpose, parameters, and return values. I relied heavily on these.
* **Function Signature:**  The parameters and return types offer clues about the data the function works with.
* **Internal Function Calls (with lowercase names):**  The calls to functions like `readGCStats`, `setGCPercent`, etc., indicate that this `debug` package is acting as a higher-level interface to lower-level runtime functionality. While I don't have the *implementation* of those functions, their names are suggestive.
* **Data Structures:**  The `GCStats` struct is clearly designed to hold garbage collection-related information. The fields within it (e.g., `LastGC`, `NumGC`, `Pause`) are strong indicators of what kind of data is being collected.

**4. Connecting to Core Go Features:**

Based on the function names and their descriptions, I started connecting them to core Go garbage collection and runtime management features:

* `GCStats` and `ReadGCStats`:  Clearly related to monitoring the garbage collector.
* `SetGCPercent`:  Likely controls the trigger point for garbage collection.
* `FreeOSMemory`:  Explicitly about reclaiming memory.
* `SetMaxStack`, `SetMaxThreads`: Related to resource limits.
* `SetPanicOnFault`:  Deals with error handling and debugging.
* `WriteHeapDump`:  A debugging tool for inspecting memory.
* `SetTraceback`: Configures error reporting.
* `SetMemoryLimit`:  A newer feature for controlling memory usage.

**5. Crafting the Go Code Examples:**

For each function (where it made sense), I tried to create a simple, illustrative Go code example. The goal was to demonstrate basic usage:

* `ReadGCStats`: Show how to create a `GCStats` struct and populate it.
* `SetGCPercent`: Demonstrate setting and getting the GC percentage.
* `FreeOSMemory`:  A simple call.
* `SetMaxStack`, `SetMaxThreads`, `SetMemoryLimit`:  Show setting the limits and retrieving the old values.
* `SetPanicOnFault`: Demonstrate enabling and disabling the panic behavior.
* `WriteHeapDump`: Briefly mention its usage with a file.
* `SetTraceback`: Show setting the traceback level.

**6. Reasoning About Input/Output (for Code Inference):**

This was more relevant for functions that retrieve information (`ReadGCStats`). I outlined the *types* of input (an empty `GCStats` struct) and output (the populated struct). For functions that set values, the "input" is the parameter passed, and the "output" is the previous setting.

**7. Handling Command-Line Arguments:**

The code mentions environment variables like `GOGC` and `GOMEMLIMIT`. I explained how these environment variables influence the initial settings of `SetGCPercent` and `SetMemoryLimit`.

**8. Identifying Potential Mistakes:**

This required some thought about how developers might misuse these functions:

* `ReadGCStats`:  Reusing the `Pause` slice without checking its length could lead to unexpected behavior or panics if the runtime needs to store more data.
* `WriteHeapDump`:  Piping the output back to the same process is a recipe for deadlock.
* `SetPanicOnFault`:  Misunderstanding its scope (goroutine-specific) could lead to incorrect assumptions about its effect.

**9. Structuring the Answer in Chinese:**

Finally, I translated the information into clear and concise Chinese, using appropriate technical terminology. I organized the answer by function, following the order in the code. I made sure to address all the specific points raised in the original request.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the internal `runtime` package details. I realized the request was about the *`debug` package* and its user-facing functionality.
* I considered whether to provide very complex examples. I opted for simplicity to make the core functionality clearer.
* I double-checked the doc comments to ensure my understanding of each function was accurate.
* I made sure the Chinese translation was natural and technically correct. For instance, using the correct terms for "garbage collection" (垃圾回收), "memory heap" (堆内存), etc.

By following this structured approach, I could systematically analyze the code, extract the relevant information, and present it in a clear and helpful manner, fulfilling all the requirements of the prompt.
这段代码是 Go 语言 `runtime/debug` 包中负责提供垃圾回收 (Garbage Collection, GC) 统计信息和控制 GC 行为的一部分。它提供了一些函数来获取 GC 的运行状态、手动触发 GC、设置 GC 的触发阈值等。

下面列举一下它的功能：

1. **`GCStats` 结构体:**  这是一个用于存储垃圾回收统计信息的结构体。它包含了最后一次 GC 的时间、GC 的次数、所有 GC 暂停的总时间、每次 GC 的暂停时间历史记录以及暂停结束时间历史记录。还可以存储暂停时间的百分位数。

2. **`ReadGCStats(stats *GCStats)` 函数:**  这个函数用于读取当前的垃圾回收统计信息并将结果填充到提供的 `GCStats` 结构体中。
    * 它会更新 `stats.LastGC` (最后一次 GC 的时间)。
    * 更新 `stats.NumGC` (GC 的次数)。
    * 更新 `stats.PauseTotal` (所有 GC 暂停的总时间)。
    * 更新 `stats.Pause` (最近的 GC 暂停时间历史记录)。
    * 更新 `stats.PauseEnd` (最近的 GC 暂停结束时间历史记录)。
    * 如果 `stats.PauseQuantiles` 非空，它会计算并填充暂停时间的百分位数。

3. **`SetGCPercent(percent int) int` 函数:**  这个函数用于设置垃圾回收的目标百分比。当新分配的数据量与上次 GC 后存活的数据量的比率达到这个百分比时，就会触发一次 GC。
    * 它返回之前的 GC 百分比设置。
    * 初始值由 `GOGC` 环境变量决定，如果没有设置则默认为 100。
    * 设置为负数会有效地禁用 GC，除非达到内存限制。

4. **`FreeOSMemory()` 函数:**  这个函数会强制执行一次垃圾回收，并尝试尽可能多地将内存返回给操作系统。即使不调用此函数，runtime 也会在后台逐渐将内存返回给操作系统。

5. **`SetMaxStack(bytes int) int` 函数:**  这个函数用于设置单个 goroutine 栈可以使用的最大内存量。如果任何 goroutine 在扩展其栈时超过此限制，程序将会崩溃。
    * 它返回之前的最大栈大小设置。
    * 初始值在 64 位系统上为 1GB，在 32 位系统上为 250MB。

6. **`SetMaxThreads(threads int) int` 函数:**  这个函数用于设置 Go 程序可以使用的操作系统线程的最大数量。如果尝试使用超过这个数量的线程，程序将会崩溃。
    * 它返回之前的最大线程数设置。
    * 初始值为 10,000 个线程。

7. **`SetPanicOnFault(enabled bool) bool` 函数:**  这个函数控制 runtime 在程序因意外（非 nil）地址发生错误时的行为。默认情况下，这通常表示运行时内存损坏等严重 bug，因此默认行为是崩溃程序。对于处理内存映射文件或不安全内存操作的程序，可以在不太严重的情况下遇到此类错误。`SetPanicOnFault` 允许这些程序请求 runtime 只触发 panic，而不是崩溃。
    * 它只对当前 goroutine 生效。
    * 它返回之前的设置。

8. **`WriteHeapDump(fd uintptr)` 函数:**  这个函数将堆的描述和其中的对象写入给定的文件描述符。
    * 在堆转储完成写入之前，它会暂停所有 goroutine 的执行。
    * 因此，文件描述符不应连接到管道或 socket，其另一端位于同一 Go 进程中。应该使用临时文件或网络 socket。

9. **`SetTraceback(level string)` 函数:**  这个函数设置 runtime 在因未恢复的 panic 或内部运行时错误而退出之前打印的回溯信息的详细程度。
    * `level` 参数的值与 `GOTRACEBACK` 环境变量相同。
    * 如果使用低于环境变量的级别调用 `SetTraceback`，则调用将被忽略。

10. **`SetMemoryLimit(limit int64) int64` 函数:** 这个函数为 runtime 提供了一个软内存限制。
    * runtime 会采取多种措施来遵守此内存限制，包括调整垃圾回收的频率和更积极地将内存返回给底层系统。即使 `GOGC=off` 或执行了 `SetGCPercent(-1)`，此限制也会生效。
    * 输入的 `limit` 以字节为单位，包括 Go runtime 映射、管理和未释放的所有内存。
    * 零限制或低于 Go runtime 已使用内存量的限制可能会导致垃圾回收几乎持续运行。
    * 可以将限制设置为 `math.MaxInt64` 来有效地禁用此行为。
    * 初始设置是 `math.MaxInt64`，除非设置了 `GOMEMLIMIT` 环境变量。
    * 它返回之前设置的内存限制。负数输入不会调整限制，但可以用于检索当前设置的内存限制。

**它是什么 Go 语言功能的实现？**

这段代码主要实现了 **Go 语言的垃圾回收机制的监控和控制** 以及一些 **资源限制和错误处理** 的功能。具体来说：

* **垃圾回收控制和监控:**  `GCStats`, `ReadGCStats`, `SetGCPercent`, `FreeOSMemory` 这几个函数直接关联到 Go 的垃圾回收器。它们允许用户了解 GC 的状态，并对 GC 的行为进行一定程度的干预。
* **资源限制:** `SetMaxStack`, `SetMaxThreads`, `SetMemoryLimit` 这些函数允许程序设置 goroutine 栈大小、操作系统线程数以及整个进程的内存使用上限，有助于防止资源耗尽。
* **错误处理和调试:** `SetPanicOnFault`, `WriteHeapDump`, `SetTraceback` 这些函数涉及到程序发生错误时的行为控制和调试信息的收集。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"runtime/debug"
	"time"
)

func main() {
	// 获取 GC 统计信息
	var stats debug.GCStats
	debug.ReadGCStats(&stats)
	fmt.Println("GC 次数:", stats.NumGC)
	fmt.Println("上次 GC 时间:", stats.LastGC)
	fmt.Println("GC 总暂停时间:", stats.PauseTotal)
	if len(stats.Pause) > 0 {
		fmt.Println("最近一次 GC 暂停时间:", stats.Pause[0])
	}

	// 设置 GC 目标百分比
	oldPercent := debug.SetGCPercent(50)
	fmt.Println("之前的 GC 百分比:", oldPercent)

	// 触发一次 GC 并释放内存
	debug.FreeOSMemory()

	// 设置最大栈大小
	oldStackSize := debug.SetMaxStack(1024 * 1024) // 1MB
	fmt.Println("之前的最大栈大小:", oldStackSize)

	// 设置内存限制 (假设限制为 100MB)
	limit := int64(100 * 1024 * 1024)
	oldMemoryLimit := debug.SetMemoryLimit(limit)
	fmt.Println("之前的内存限制:", oldMemoryLimit)

	// 获取当前的内存限制
	currentMemoryLimit := debug.SetMemoryLimit(-1)
	fmt.Println("当前的内存限制:", currentMemoryLimit)

	// 设置 panic on fault
	oldPanicOnFault := debug.SetPanicOnFault(true)
	fmt.Println("之前的 PanicOnFault 设置:", oldPanicOnFault)

	// 设置 traceback 级别
	debug.SetTraceback("all")

	// 假设我们想获取 GC 暂停时间的 25%, 50%, 75% 分位数
	stats.PauseQuantiles = make([]time.Duration, 3)
	debug.ReadGCStats(&stats)
	fmt.Println("GC 暂停时间分位数 (25%, 50%, 75%):", stats.PauseQuantiles)
}
```

**假设的输入与输出 (针对 `ReadGCStats`):**

**假设输入:**  一个空的 `debug.GCStats` 结构体。

```go
var stats debug.GCStats
```

**假设输出:**  `ReadGCStats(&stats)` 调用后，`stats` 的字段会被填充，例如：

```
GC 次数: 123
上次 GC 时间: 2023-10-27 10:00:00 +0000 UTC
GC 总暂停时间: 10ms
最近一次 GC 暂停时间: 1ms
```

具体的数值会根据程序的运行情况而变化。对于 `PauseQuantiles`，如果设置了，输出可能如下：

```
GC 暂停时间分位数 (25%, 50%, 75%): [500µs 750µs 900µs]
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数，但它会受到 **环境变量** 的影响：

* **`GOGC` 环境变量:**  影响 `SetGCPercent` 函数的初始值。如果启动程序时设置了 `GOGC=80`，那么在程序启动时，GC 的目标百分比会被设置为 80。
* **`GOMEMLIMIT` 环境变量:** 影响 `SetMemoryLimit` 函数的初始值。例如，如果启动程序时设置了 `GOMEMLIMIT=1GiB`，那么程序的初始内存限制将是 1GB。环境变量支持 `B`, `KiB`, `MiB`, `GiB`, `TiB` 这些单位后缀。
* **`GOTRACEBACK` 环境变量:** 影响 `SetTraceback` 函数的默认行为。虽然 `SetTraceback` 可以覆盖这个设置，但 `GOTRACEBACK` 决定了程序在没有调用 `SetTraceback` 时，panic 时的回溯信息详细程度。

**使用者易犯错的点:**

* **误解 `SetGCPercent` 的作用:**  `SetGCPercent` 设置的是一个目标，而不是强制立即执行 GC。GC 何时发生还受到其他因素的影响。
* **错误地使用 `WriteHeapDump`:**  将堆转储输出到与当前进程相关的管道或 socket 可能会导致死锁，因为 `WriteHeapDump` 会暂停所有 goroutine。应该使用临时文件或网络 socket。
* **认为 `SetPanicOnFault` 是全局的:**  `SetPanicOnFault` 只影响调用它的 **当前 goroutine**。其他 goroutine 的行为不受影响。
* **不理解 `SetMemoryLimit` 的限制范围:**  `SetMemoryLimit` 限制的是 Go runtime 管理的内存，不包括操作系统内核占用的内存、C 代码分配的内存或通过 `syscall.Mmap` 映射的内存。
* **频繁调用 `FreeOSMemory`:**  虽然 `FreeOSMemory` 可以立即回收内存，但频繁调用可能会导致性能下降，因为它会强制进行 GC。runtime 本身会在后台进行内存回收。
* **假设 `ReadGCStats` 返回的 `Pause` 切片总是有固定的大小:**  文档说明 `Pause` 切片的条目数量是系统相关的。用户应该检查切片的长度，而不是假设它总是包含特定数量的元素。

总而言之，这段代码提供了对 Go 语言垃圾回收机制和资源管理的一些重要控制和监控能力，但需要理解其背后的原理和潜在的副作用才能正确使用。

### 提示词
```
这是路径为go/src/runtime/debug/garbage.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"runtime"
	"slices"
	"time"
)

// GCStats collect information about recent garbage collections.
type GCStats struct {
	LastGC         time.Time       // time of last collection
	NumGC          int64           // number of garbage collections
	PauseTotal     time.Duration   // total pause for all collections
	Pause          []time.Duration // pause history, most recent first
	PauseEnd       []time.Time     // pause end times history, most recent first
	PauseQuantiles []time.Duration
}

// ReadGCStats reads statistics about garbage collection into stats.
// The number of entries in the pause history is system-dependent;
// stats.Pause slice will be reused if large enough, reallocated otherwise.
// ReadGCStats may use the full capacity of the stats.Pause slice.
// If stats.PauseQuantiles is non-empty, ReadGCStats fills it with quantiles
// summarizing the distribution of pause time. For example, if
// len(stats.PauseQuantiles) is 5, it will be filled with the minimum,
// 25%, 50%, 75%, and maximum pause times.
func ReadGCStats(stats *GCStats) {
	// Create a buffer with space for at least two copies of the
	// pause history tracked by the runtime. One will be returned
	// to the caller and the other will be used as transfer buffer
	// for end times history and as a temporary buffer for
	// computing quantiles.
	const maxPause = len(((*runtime.MemStats)(nil)).PauseNs)
	if cap(stats.Pause) < 2*maxPause+3 {
		stats.Pause = make([]time.Duration, 2*maxPause+3)
	}

	// readGCStats fills in the pause and end times histories (up to
	// maxPause entries) and then three more: Unix ns time of last GC,
	// number of GC, and total pause time in nanoseconds. Here we
	// depend on the fact that time.Duration's native unit is
	// nanoseconds, so the pauses and the total pause time do not need
	// any conversion.
	readGCStats(&stats.Pause)
	n := len(stats.Pause) - 3
	stats.LastGC = time.Unix(0, int64(stats.Pause[n]))
	stats.NumGC = int64(stats.Pause[n+1])
	stats.PauseTotal = stats.Pause[n+2]
	n /= 2 // buffer holds pauses and end times
	stats.Pause = stats.Pause[:n]

	if cap(stats.PauseEnd) < maxPause {
		stats.PauseEnd = make([]time.Time, 0, maxPause)
	}
	stats.PauseEnd = stats.PauseEnd[:0]
	for _, ns := range stats.Pause[n : n+n] {
		stats.PauseEnd = append(stats.PauseEnd, time.Unix(0, int64(ns)))
	}

	if len(stats.PauseQuantiles) > 0 {
		if n == 0 {
			clear(stats.PauseQuantiles)
		} else {
			// There's room for a second copy of the data in stats.Pause.
			// See the allocation at the top of the function.
			sorted := stats.Pause[n : n+n]
			copy(sorted, stats.Pause)
			slices.Sort(sorted)
			nq := len(stats.PauseQuantiles) - 1
			for i := 0; i < nq; i++ {
				stats.PauseQuantiles[i] = sorted[len(sorted)*i/nq]
			}
			stats.PauseQuantiles[nq] = sorted[len(sorted)-1]
		}
	}
}

// SetGCPercent sets the garbage collection target percentage:
// a collection is triggered when the ratio of freshly allocated data
// to live data remaining after the previous collection reaches this percentage.
// SetGCPercent returns the previous setting.
// The initial setting is the value of the GOGC environment variable
// at startup, or 100 if the variable is not set.
// This setting may be effectively reduced in order to maintain a memory
// limit.
// A negative percentage effectively disables garbage collection, unless
// the memory limit is reached.
// See SetMemoryLimit for more details.
func SetGCPercent(percent int) int {
	return int(setGCPercent(int32(percent)))
}

// FreeOSMemory forces a garbage collection followed by an
// attempt to return as much memory to the operating system
// as possible. (Even if this is not called, the runtime gradually
// returns memory to the operating system in a background task.)
func FreeOSMemory() {
	freeOSMemory()
}

// SetMaxStack sets the maximum amount of memory that
// can be used by a single goroutine stack.
// If any goroutine exceeds this limit while growing its stack,
// the program crashes.
// SetMaxStack returns the previous setting.
// The initial setting is 1 GB on 64-bit systems, 250 MB on 32-bit systems.
// There may be a system-imposed maximum stack limit regardless
// of the value provided to SetMaxStack.
//
// SetMaxStack is useful mainly for limiting the damage done by
// goroutines that enter an infinite recursion. It only limits future
// stack growth.
func SetMaxStack(bytes int) int {
	return setMaxStack(bytes)
}

// SetMaxThreads sets the maximum number of operating system
// threads that the Go program can use. If it attempts to use more than
// this many, the program crashes.
// SetMaxThreads returns the previous setting.
// The initial setting is 10,000 threads.
//
// The limit controls the number of operating system threads, not the number
// of goroutines. A Go program creates a new thread only when a goroutine
// is ready to run but all the existing threads are blocked in system calls, cgo calls,
// or are locked to other goroutines due to use of runtime.LockOSThread.
//
// SetMaxThreads is useful mainly for limiting the damage done by
// programs that create an unbounded number of threads. The idea is
// to take down the program before it takes down the operating system.
func SetMaxThreads(threads int) int {
	return setMaxThreads(threads)
}

// SetPanicOnFault controls the runtime's behavior when a program faults
// at an unexpected (non-nil) address. Such faults are typically caused by
// bugs such as runtime memory corruption, so the default response is to crash
// the program. Programs working with memory-mapped files or unsafe
// manipulation of memory may cause faults at non-nil addresses in less
// dramatic situations; SetPanicOnFault allows such programs to request
// that the runtime trigger only a panic, not a crash.
// The runtime.Error that the runtime panics with may have an additional method:
//
//	Addr() uintptr
//
// If that method exists, it returns the memory address which triggered the fault.
// The results of Addr are best-effort and the veracity of the result
// may depend on the platform.
// SetPanicOnFault applies only to the current goroutine.
// It returns the previous setting.
func SetPanicOnFault(enabled bool) bool {
	return setPanicOnFault(enabled)
}

// WriteHeapDump writes a description of the heap and the objects in
// it to the given file descriptor.
//
// WriteHeapDump suspends the execution of all goroutines until the heap
// dump is completely written.  Thus, the file descriptor must not be
// connected to a pipe or socket whose other end is in the same Go
// process; instead, use a temporary file or network socket.
//
// The heap dump format is defined at https://golang.org/s/go15heapdump.
func WriteHeapDump(fd uintptr)

// SetTraceback sets the amount of detail printed by the runtime in
// the traceback it prints before exiting due to an unrecovered panic
// or an internal runtime error.
// The level argument takes the same values as the GOTRACEBACK
// environment variable. For example, SetTraceback("all") ensure
// that the program prints all goroutines when it crashes.
// See the package runtime documentation for details.
// If SetTraceback is called with a level lower than that of the
// environment variable, the call is ignored.
func SetTraceback(level string)

// SetMemoryLimit provides the runtime with a soft memory limit.
//
// The runtime undertakes several processes to try to respect this
// memory limit, including adjustments to the frequency of garbage
// collections and returning memory to the underlying system more
// aggressively. This limit will be respected even if GOGC=off (or,
// if SetGCPercent(-1) is executed).
//
// The input limit is provided as bytes, and includes all memory
// mapped, managed, and not released by the Go runtime. Notably, it
// does not account for space used by the Go binary and memory
// external to Go, such as memory managed by the underlying system
// on behalf of the process, or memory managed by non-Go code inside
// the same process. Examples of excluded memory sources include: OS
// kernel memory held on behalf of the process, memory allocated by
// C code, and memory mapped by syscall.Mmap (because it is not
// managed by the Go runtime).
//
// More specifically, the following expression accurately reflects
// the value the runtime attempts to maintain as the limit:
//
//	runtime.MemStats.Sys - runtime.MemStats.HeapReleased
//
// or in terms of the runtime/metrics package:
//
//	/memory/classes/total:bytes - /memory/classes/heap/released:bytes
//
// A zero limit or a limit that's lower than the amount of memory
// used by the Go runtime may cause the garbage collector to run
// nearly continuously. However, the application may still make
// progress.
//
// The memory limit is always respected by the Go runtime, so to
// effectively disable this behavior, set the limit very high.
// [math.MaxInt64] is the canonical value for disabling the limit,
// but values much greater than the available memory on the underlying
// system work just as well.
//
// See https://go.dev/doc/gc-guide for a detailed guide explaining
// the soft memory limit in more detail, as well as a variety of common
// use-cases and scenarios.
//
// The initial setting is math.MaxInt64 unless the GOMEMLIMIT
// environment variable is set, in which case it provides the initial
// setting. GOMEMLIMIT is a numeric value in bytes with an optional
// unit suffix. The supported suffixes include B, KiB, MiB, GiB, and
// TiB. These suffixes represent quantities of bytes as defined by
// the IEC 80000-13 standard. That is, they are based on powers of
// two: KiB means 2^10 bytes, MiB means 2^20 bytes, and so on.
//
// SetMemoryLimit returns the previously set memory limit.
// A negative input does not adjust the limit, and allows for
// retrieval of the currently set memory limit.
func SetMemoryLimit(limit int64) int64 {
	return setMemoryLimit(limit)
}
```