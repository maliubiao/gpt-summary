Response:
Let's break down the thought process to answer the request about `go/src/runtime/race.go`.

**1. Understanding the Core Request:**

The request asks for the functionality of the provided Go code snippet, specifically focusing on `go/src/runtime/race.go`. It also asks to identify the Go feature it implements, provide a code example, explain command-line interaction, and highlight common mistakes.

**2. Initial Code Scan and Keywords:**

I first scanned the code for prominent keywords and patterns:

* `//go:build race`: This immediately signals that this code is only included when the `-race` flag is used during compilation. This is a crucial piece of information for understanding the code's purpose.
* `package runtime`: This indicates it's part of the Go runtime, suggesting low-level operations.
* `RaceRead`, `RaceWrite`, `RaceReadRange`, `RaceWriteRange`: These function names strongly suggest interaction with memory access. The "Race" prefix and the "Range" suffix hint at the purpose.
* `RaceAcquire`, `RaceRelease`, `RaceReleaseMerge`: These names relate to synchronization primitives and "happens-before" relationships, which are core concepts in concurrent programming.
* `RaceDisable`, `RaceEnable`: These clearly control the activation/deactivation of some functionality.
* `racecall`: This indicates interaction with external code, likely a C library. The `__tsan_` prefixes on the linked variables further confirm this (TSan likely refers to ThreadSanitizer).
* `symbolizeCodeContext`, `symbolizeDataContext`: These structures and the associated `raceSymbolizeCode` and `raceSymbolizeData` functions suggest a mechanism for obtaining debugging information related to code and data.
* The numerous `//go:linkname` directives point to internal packages, indicating the code is bridging the public `runtime` API with internal implementations.

**3. Deducing the Core Functionality (Race Detector):**

Based on the keywords and the conditional compilation (`//go:build race`), the primary function of this code is highly likely to be **implementing Go's race detector**. The function names related to reading, writing, and synchronization directly support this conclusion.

**4. Structuring the Answer:**

I decided to structure the answer based on the request's prompts:

* **功能列举 (List of Functions):**  Go through the public API functions (`RaceRead`, `RaceWrite`, etc.) and briefly explain what each one does based on its name and comments.
* **实现的 Go 语言功能 (Go Feature Implementation):**  State clearly that it implements the race detector and explain its purpose: detecting concurrent data access problems.
* **Go 代码举例说明 (Go Code Example):**  Create a simple, illustrative example demonstrating a data race *without* and *with* the `-race` flag. This makes the benefit of the race detector concrete. I needed to show how the race detector would report the issue. I also included an example of `RaceAcquire` and `RaceRelease` to illustrate their more advanced use.
* **代码推理 (Code Reasoning):** Explain how the `RaceRead`/`RaceWrite` functions likely work by instrumenting memory access. Mention the interaction with the external TSan library via `racecall`. Include assumptions about inputs and outputs for the core functions.
* **命令行参数处理 (Command-Line Argument Handling):** Explain the role of the `-race` flag during compilation.
* **使用者易犯错的点 (Common Mistakes):** Focus on the fact that the race detector needs the `-race` flag to be effective and that it only detects *runtime* races, not all concurrency issues. Mention the performance overhead.

**5. Crafting the Code Examples:**

For the data race example:

* **Without `-race`:** Show two goroutines accessing and modifying a shared variable concurrently without any synchronization. This will likely produce unexpected results.
* **With `-race`:** Compile and run the same code with the `-race` flag. The race detector should report the data race.
* For the `RaceAcquire`/`RaceRelease` example, I needed a scenario where the standard Go synchronization primitives were insufficient or where external synchronization mechanisms were used. Using a channel and manually signaling with `RaceRelease` and `RaceAcquire` provides a good demonstration.

**6. Explaining `racecall` and TSan:**

It's important to explain that `racecall` is the bridge to the underlying C implementation of the race detector (TSan). Mentioning the `__tsan_` prefixed variables reinforces this.

**7. Detailing Command-Line Usage:**

Emphasize the necessity of the `-race` flag for the race detector to function. Show the compilation and execution steps.

**8. Highlighting Common Mistakes:**

Focus on the most common misunderstandings:

* Forgetting to use the `-race` flag.
* Thinking the race detector finds *all* concurrency bugs.
* Not being aware of the performance impact.

**9. Review and Refinement:**

After drafting the answer, I reviewed it for clarity, accuracy, and completeness, ensuring all parts of the request were addressed. I made sure the code examples were runnable and the explanations were easy to understand. I also double-checked the function descriptions against the code to ensure accuracy.

This iterative process of understanding the core functionality, structuring the answer, creating examples, and refining the explanations allowed me to generate a comprehensive and accurate response to the request.
这段 `go/src/runtime/race.go` 文件是 Go 语言运行时环境的一部分，专门用于实现 **数据竞争检测器 (Race Detector)**。

**功能列举:**

这个文件定义了一系列函数，用于在启用了 `-race` 编译选项的情况下，在 Go 程序运行时监控内存访问和同步操作，以检测潜在的数据竞争。 这些函数可以大致分为以下几类：

1. **内存访问监控:**
   - `RaceRead(addr unsafe.Pointer)`: 标记对指定地址的读取操作。
   - `RaceWrite(addr unsafe.Pointer)`: 标记对指定地址的写入操作。
   - `RaceReadRange(addr unsafe.Pointer, len int)`: 标记对指定地址范围的读取操作。
   - `RaceWriteRange(addr unsafe.Pointer, len int)`: 标记对指定地址范围的写入操作。
   - `raceReadObjectPC(t *_type, addr unsafe.Pointer, callerpc, pc uintptr)`:  读取对象的监控，针对不同类型的对象（数组、结构体等）有不同的处理方式。
   - `raceWriteObjectPC(t *_type, addr unsafe.Pointer, callerpc, pc uintptr)`: 写入对象的监控，同样针对不同类型的对象有不同的处理方式。
   - `racereadpc(addr unsafe.Pointer, callpc, pc uintptr)`:  带有程序计数器的读取操作监控。
   - `racewritepc(addr unsafe.Pointer, callpc, pc uintptr)`: 带有程序计数器的写入操作监控。
   - `racereadrangepc(addr unsafe.Pointer, sz, callpc, pc uintptr)`: 带有程序计数器的范围读取操作监控。
   - `racewriterangepc(addr unsafe.Pointer, sz, callpc, pc uintptr)`: 带有程序计数器的范围写入操作监控。

2. **同步操作监控:**
   - `RaceAcquire(addr unsafe.Pointer)`: 标记获取锁或其他同步原语的操作，建立 "happens-before" 关系。
   - `RaceRelease(addr unsafe.Pointer)`: 标记释放锁或其他同步原语的操作，与 `RaceAcquire` 配合建立 "happens-before" 关系。
   - `RaceReleaseMerge(addr unsafe.Pointer)`: 类似 `RaceRelease`，但也会与之前的 `RaceRelease` 或 `RaceReleaseMerge` 建立 "happens-before" 关系。
   - `RaceDisable()`: 禁用当前 goroutine 中的竞争检测事件处理。
   - `RaceEnable()`: 重新启用当前 goroutine 中的竞争检测事件处理。

3. **错误报告:**
   - `RaceErrors() int`: 返回当前检测到的数据竞争错误数量。

4. **内部支持函数:**
   - `raceinit()`: 初始化数据竞争检测器。
   - `racefini()`: 清理数据竞争检测器。
   - `raceproccreate()`: 创建进程时调用，用于维护线程上下文。
   - `raceprocdestroy()`: 销毁进程时调用。
   - `racemapshadow(addr unsafe.Pointer, size uintptr)`: 映射内存阴影区域，用于跟踪内存访问。
   - `racemalloc(p unsafe.Pointer, sz uintptr)`: 监控内存分配。
   - `racefree(p unsafe.Pointer, sz uintptr)`: 监控内存释放。
   - `racegostart(pc uintptr)`: 在新的 goroutine 启动时调用。
   - `racegoend()`: 在 goroutine 结束时调用。
   - `racecall(fn *byte, arg0, arg1, arg2, arg3 uintptr)`: 用于调用 C 编写的 ThreadSanitizer (TSan) 库中的函数。
   - `racecallback(cmd uintptr, ctx unsafe.Pointer)`: 从 C 代码回调到 Go，处理一些命令，例如符号化代码和数据地址。
   - `racefuncenter(callpc uintptr)` / `racefuncexit()`: 监控函数入口和出口，用于更精确地定位竞争。

5. **符号化支持:**
   - `raceSymbolizeCode(ctx *symbolizeCodeContext)`:  将程序计数器 (PC) 转换为函数名、文件名和行号。
   - `raceSymbolizeData(ctx *symbolizeDataContext)`: 获取数据地址的堆信息，例如起始地址、大小等。

**实现的 Go 语言功能：数据竞争检测 (Race Detection)**

这个文件是 Go 语言数据竞争检测功能的核心实现。数据竞争是指在没有明确同步的情况下，多个 goroutine 并发地访问相同的内存地址，并且至少有一个 goroutine 尝试写入该地址。数据竞争会导致程序行为不可预测，难以调试。

Go 的数据竞争检测器通过在编译时插入额外的代码（当使用 `-race` 编译选项时），在运行时监控所有内存访问和同步操作。当检测到潜在的数据竞争时，它会打印出详细的错误信息，包括发生竞争的内存地址、访问的 goroutine 以及相关的代码位置。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"sync"
	"time"
)

var counter int

func increment() {
	for i := 0; i < 1000; i++ {
		counter++ // 潜在的数据竞争
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		increment()
	}()

	go func() {
		defer wg.Done()
		increment()
	}()

	wg.Wait()
	fmt.Println("Counter:", counter)
}
```

**假设的输入与输出:**

1. **不使用 `-race` 编译:**

   - **编译命令:** `go build main.go`
   - **运行命令:** `./main`
   - **输出:**  `Counter:` 加上一个接近 2000 的数字，但每次运行结果可能不同，因为存在数据竞争。

2. **使用 `-race` 编译:**

   - **编译命令:** `go build -race main.go`
   - **运行命令:** `./main`
   - **输出:** 除了 `Counter:` 加上一个数字之外，还会包含**数据竞争报告**，类似于：

     ```
     ==================
     WARNING: DATA RACE
     Write at 0x... by goroutine ...:
       main.increment()
           .../main.go:13 +0x...

     Previous write at 0x... by goroutine ...:
       main.increment()
           .../main.go:13 +0x...

     Goroutine ... (running) created at:
       main.main()
           .../main.go:21 +0x...

     Goroutine ... (running) created at:
       main.main()
           .../main.go:27 +0x...
     ==================
     Counter: ...
     ```

     这个报告会明确指出发生数据竞争的内存地址 (`0x...`)，以及参与竞争的 goroutine 和代码位置 (`main.increment()` at `.../main.go:13`).

**代码推理:**

当使用 `-race` 编译时，编译器会在 `counter++`  这样的内存访问前后插入对 `runtime.RaceRead` 或 `runtime.RaceWrite` 的调用。这些函数会将内存访问的地址、goroutine 的信息等传递给底层的 ThreadSanitizer 库。TSan 维护着一个影子内存 (shadow memory)，用于记录每个内存地址的访问历史 (哪个 goroutine 在何时进行了读写操作)。

当 TSan 检测到两个或多个 goroutine 在没有 intervening 的 "happens-before" 关系的情况下访问相同的内存地址，并且至少有一个是写入操作时，它就会报告数据竞争。

`RaceAcquire` 和 `RaceRelease` 等函数用于显式地告诉 TSan 哪些操作构成了同步，建立了 "happens-before" 关系。例如，在一个互斥锁的 `Lock()` 操作中会调用 `RaceAcquire`，在 `Unlock()` 操作中会调用 `RaceRelease`。

**命令行参数的具体处理:**

`-race` 是 `go build`, `go run`, `go test` 等 Go 工具的编译选项。当指定 `-race` 时，Go 编译器会将额外的代码注入到程序中，以便在运行时监控数据竞争。

- **`go build -race main.go`**:  编译 `main.go` 文件，并启用数据竞争检测。生成的可执行文件运行时会进行数据竞争检测。
- **`go run -race main.go`**:  编译并直接运行 `main.go` 文件，启用数据竞争检测。
- **`go test -race`**:  运行测试用例，并启用数据竞争检测。这对于发现并发代码中的竞态条件非常有用。

如果不使用 `-race` 选项编译程序，则 `runtime/race.go` 中的大部分代码将不会被激活，性能开销也会降低。

**使用者易犯错的点:**

1. **忘记使用 `-race` 编译选项:** 这是最常见的错误。如果没有使用 `-race` 编译，数据竞争检测器根本不会运行，也就无法发现潜在的并发问题。开发者可能会在没有检测的情况下部署有数据竞争的代码。

   **示例:**  开发者编写了并发代码，但只使用了 `go build main.go` 进行编译和测试。程序在某些情况下运行正常，但在高并发环境下可能会出现奇怪的错误。如果使用了 `go build -race main.go`，则很可能在测试阶段就能发现数据竞争。

2. **认为数据竞争检测器能捕捉所有并发问题:** 数据竞争检测器主要关注的是**数据竞争**，即并发地、无同步地访问共享内存。它不能检测到死锁、活锁或其他类型的并发错误。

   **示例:** 两个 goroutine 相互等待对方释放锁，导致死锁。即使使用了 `-race` 编译，数据竞争检测器也无法直接报告死锁，因为没有发生并发的、无同步的内存访问冲突。需要使用其他工具或方法来检测死锁。

3. **在生产环境中使用 `-race` 编译:**  虽然 `-race` 能有效地发现数据竞争，但它会显著增加程序的运行时开销 (通常会降低 5-10 倍的性能，并增加内存使用)。因此，**不建议在生产环境中使用 `-race` 编译的程序**。数据竞争检测主要用于开发和测试阶段。

**总结:**

`go/src/runtime/race.go` 是 Go 语言数据竞争检测功能的核心实现。它通过在运行时监控内存访问和同步操作，帮助开发者发现并发代码中的潜在问题。正确使用 `-race` 编译选项并在开发测试阶段进行充分的检测，是编写可靠并发 Go 程序的重要环节。

### 提示词
```
这是路径为go/src/runtime/race.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build race

package runtime

import (
	"internal/abi"
	"unsafe"
)

// Public race detection API, present iff build with -race.

func RaceRead(addr unsafe.Pointer)

//go:linkname race_Read internal/race.Read
//go:nosplit
func race_Read(addr unsafe.Pointer) {
	RaceRead(addr)
}

func RaceWrite(addr unsafe.Pointer)

//go:linkname race_Write internal/race.Write
//go:nosplit
func race_Write(addr unsafe.Pointer) {
	RaceWrite(addr)
}

func RaceReadRange(addr unsafe.Pointer, len int)

//go:linkname race_ReadRange internal/race.ReadRange
//go:nosplit
func race_ReadRange(addr unsafe.Pointer, len int) {
	RaceReadRange(addr, len)
}

func RaceWriteRange(addr unsafe.Pointer, len int)

//go:linkname race_WriteRange internal/race.WriteRange
//go:nosplit
func race_WriteRange(addr unsafe.Pointer, len int) {
	RaceWriteRange(addr, len)
}

func RaceErrors() int {
	var n uint64
	racecall(&__tsan_report_count, uintptr(unsafe.Pointer(&n)), 0, 0, 0)
	return int(n)
}

//go:linkname race_Errors internal/race.Errors
//go:nosplit
func race_Errors() int {
	return RaceErrors()
}

// RaceAcquire/RaceRelease/RaceReleaseMerge establish happens-before relations
// between goroutines. These inform the race detector about actual synchronization
// that it can't see for some reason (e.g. synchronization within RaceDisable/RaceEnable
// sections of code).
// RaceAcquire establishes a happens-before relation with the preceding
// RaceReleaseMerge on addr up to and including the last RaceRelease on addr.
// In terms of the C memory model (C11 §5.1.2.4, §7.17.3),
// RaceAcquire is equivalent to atomic_load(memory_order_acquire).
//
//go:nosplit
func RaceAcquire(addr unsafe.Pointer) {
	raceacquire(addr)
}

//go:linkname race_Acquire internal/race.Acquire
//go:nosplit
func race_Acquire(addr unsafe.Pointer) {
	RaceAcquire(addr)
}

// RaceRelease performs a release operation on addr that
// can synchronize with a later RaceAcquire on addr.
//
// In terms of the C memory model, RaceRelease is equivalent to
// atomic_store(memory_order_release).
//
//go:nosplit
func RaceRelease(addr unsafe.Pointer) {
	racerelease(addr)
}

//go:linkname race_Release internal/race.Release
//go:nosplit
func race_Release(addr unsafe.Pointer) {
	RaceRelease(addr)
}

// RaceReleaseMerge is like RaceRelease, but also establishes a happens-before
// relation with the preceding RaceRelease or RaceReleaseMerge on addr.
//
// In terms of the C memory model, RaceReleaseMerge is equivalent to
// atomic_exchange(memory_order_release).
//
//go:nosplit
func RaceReleaseMerge(addr unsafe.Pointer) {
	racereleasemerge(addr)
}

//go:linkname race_ReleaseMerge internal/race.ReleaseMerge
//go:nosplit
func race_ReleaseMerge(addr unsafe.Pointer) {
	RaceReleaseMerge(addr)
}

// RaceDisable disables handling of race synchronization events in the current goroutine.
// Handling is re-enabled with RaceEnable. RaceDisable/RaceEnable can be nested.
// Non-synchronization events (memory accesses, function entry/exit) still affect
// the race detector.
//
//go:nosplit
func RaceDisable() {
	gp := getg()
	if gp.raceignore == 0 {
		racecall(&__tsan_go_ignore_sync_begin, gp.racectx, 0, 0, 0)
	}
	gp.raceignore++
}

//go:linkname race_Disable internal/race.Disable
//go:nosplit
func race_Disable() {
	RaceDisable()
}

// RaceEnable re-enables handling of race events in the current goroutine.
//
//go:nosplit
func RaceEnable() {
	gp := getg()
	gp.raceignore--
	if gp.raceignore == 0 {
		racecall(&__tsan_go_ignore_sync_end, gp.racectx, 0, 0, 0)
	}
}

//go:linkname race_Enable internal/race.Enable
//go:nosplit
func race_Enable() {
	RaceEnable()
}

// Private interface for the runtime.

const raceenabled = true

// For all functions accepting callerpc and pc,
// callerpc is a return PC of the function that calls this function,
// pc is start PC of the function that calls this function.
func raceReadObjectPC(t *_type, addr unsafe.Pointer, callerpc, pc uintptr) {
	kind := t.Kind_ & abi.KindMask
	if kind == abi.Array || kind == abi.Struct {
		// for composite objects we have to read every address
		// because a write might happen to any subobject.
		racereadrangepc(addr, t.Size_, callerpc, pc)
	} else {
		// for non-composite objects we can read just the start
		// address, as any write must write the first byte.
		racereadpc(addr, callerpc, pc)
	}
}

//go:linkname race_ReadObjectPC internal/race.ReadObjectPC
func race_ReadObjectPC(t *abi.Type, addr unsafe.Pointer, callerpc, pc uintptr) {
	raceReadObjectPC(t, addr, callerpc, pc)
}

func raceWriteObjectPC(t *_type, addr unsafe.Pointer, callerpc, pc uintptr) {
	kind := t.Kind_ & abi.KindMask
	if kind == abi.Array || kind == abi.Struct {
		// for composite objects we have to write every address
		// because a write might happen to any subobject.
		racewriterangepc(addr, t.Size_, callerpc, pc)
	} else {
		// for non-composite objects we can write just the start
		// address, as any write must write the first byte.
		racewritepc(addr, callerpc, pc)
	}
}

//go:linkname race_WriteObjectPC internal/race.WriteObjectPC
func race_WriteObjectPC(t *abi.Type, addr unsafe.Pointer, callerpc, pc uintptr) {
	raceWriteObjectPC(t, addr, callerpc, pc)
}

//go:noescape
func racereadpc(addr unsafe.Pointer, callpc, pc uintptr)

//go:noescape
func racewritepc(addr unsafe.Pointer, callpc, pc uintptr)

//go:linkname race_ReadPC internal/race.ReadPC
func race_ReadPC(addr unsafe.Pointer, callerpc, pc uintptr) {
	racereadpc(addr, callerpc, pc)
}

//go:linkname race_WritePC internal/race.WritePC
func race_WritePC(addr unsafe.Pointer, callerpc, pc uintptr) {
	racewritepc(addr, callerpc, pc)
}

type symbolizeCodeContext struct {
	pc   uintptr
	fn   *byte
	file *byte
	line uintptr
	off  uintptr
	res  uintptr
}

var qq = [...]byte{'?', '?', 0}
var dash = [...]byte{'-', 0}

const (
	raceGetProcCmd = iota
	raceSymbolizeCodeCmd
	raceSymbolizeDataCmd
)

// Callback from C into Go, runs on g0.
func racecallback(cmd uintptr, ctx unsafe.Pointer) {
	switch cmd {
	case raceGetProcCmd:
		throw("should have been handled by racecallbackthunk")
	case raceSymbolizeCodeCmd:
		raceSymbolizeCode((*symbolizeCodeContext)(ctx))
	case raceSymbolizeDataCmd:
		raceSymbolizeData((*symbolizeDataContext)(ctx))
	default:
		throw("unknown command")
	}
}

// raceSymbolizeCode reads ctx.pc and populates the rest of *ctx with
// information about the code at that pc.
//
// The race detector has already subtracted 1 from pcs, so they point to the last
// byte of call instructions (including calls to runtime.racewrite and friends).
//
// If the incoming pc is part of an inlined function, *ctx is populated
// with information about the inlined function, and on return ctx.pc is set
// to a pc in the logically containing function. (The race detector should call this
// function again with that pc.)
//
// If the incoming pc is not part of an inlined function, the return pc is unchanged.
func raceSymbolizeCode(ctx *symbolizeCodeContext) {
	pc := ctx.pc
	fi := findfunc(pc)
	if fi.valid() {
		u, uf := newInlineUnwinder(fi, pc)
		for ; uf.valid(); uf = u.next(uf) {
			sf := u.srcFunc(uf)
			if sf.funcID == abi.FuncIDWrapper && u.isInlined(uf) {
				// Ignore wrappers, unless we're at the outermost frame of u.
				// A non-inlined wrapper frame always means we have a physical
				// frame consisting entirely of wrappers, in which case we'll
				// take an outermost wrapper over nothing.
				continue
			}

			name := sf.name()
			file, line := u.fileLine(uf)
			if line == 0 {
				// Failure to symbolize
				continue
			}
			ctx.fn = &bytes(name)[0] // assume NUL-terminated
			ctx.line = uintptr(line)
			ctx.file = &bytes(file)[0] // assume NUL-terminated
			ctx.off = pc - fi.entry()
			ctx.res = 1
			if u.isInlined(uf) {
				// Set ctx.pc to the "caller" so the race detector calls this again
				// to further unwind.
				uf = u.next(uf)
				ctx.pc = uf.pc
			}
			return
		}
	}
	ctx.fn = &qq[0]
	ctx.file = &dash[0]
	ctx.line = 0
	ctx.off = ctx.pc
	ctx.res = 1
}

type symbolizeDataContext struct {
	addr  uintptr
	heap  uintptr
	start uintptr
	size  uintptr
	name  *byte
	file  *byte
	line  uintptr
	res   uintptr
}

func raceSymbolizeData(ctx *symbolizeDataContext) {
	if base, span, _ := findObject(ctx.addr, 0, 0); base != 0 {
		// TODO: Does this need to handle malloc headers?
		ctx.heap = 1
		ctx.start = base
		ctx.size = span.elemsize
		ctx.res = 1
	}
}

// Race runtime functions called via runtime·racecall.
//
//go:linkname __tsan_init __tsan_init
var __tsan_init byte

//go:linkname __tsan_fini __tsan_fini
var __tsan_fini byte

//go:linkname __tsan_proc_create __tsan_proc_create
var __tsan_proc_create byte

//go:linkname __tsan_proc_destroy __tsan_proc_destroy
var __tsan_proc_destroy byte

//go:linkname __tsan_map_shadow __tsan_map_shadow
var __tsan_map_shadow byte

//go:linkname __tsan_finalizer_goroutine __tsan_finalizer_goroutine
var __tsan_finalizer_goroutine byte

//go:linkname __tsan_go_start __tsan_go_start
var __tsan_go_start byte

//go:linkname __tsan_go_end __tsan_go_end
var __tsan_go_end byte

//go:linkname __tsan_malloc __tsan_malloc
var __tsan_malloc byte

//go:linkname __tsan_free __tsan_free
var __tsan_free byte

//go:linkname __tsan_acquire __tsan_acquire
var __tsan_acquire byte

//go:linkname __tsan_release __tsan_release
var __tsan_release byte

//go:linkname __tsan_release_acquire __tsan_release_acquire
var __tsan_release_acquire byte

//go:linkname __tsan_release_merge __tsan_release_merge
var __tsan_release_merge byte

//go:linkname __tsan_go_ignore_sync_begin __tsan_go_ignore_sync_begin
var __tsan_go_ignore_sync_begin byte

//go:linkname __tsan_go_ignore_sync_end __tsan_go_ignore_sync_end
var __tsan_go_ignore_sync_end byte

//go:linkname __tsan_report_count __tsan_report_count
var __tsan_report_count byte

// Mimic what cmd/cgo would do.
//
//go:cgo_import_static __tsan_init
//go:cgo_import_static __tsan_fini
//go:cgo_import_static __tsan_proc_create
//go:cgo_import_static __tsan_proc_destroy
//go:cgo_import_static __tsan_map_shadow
//go:cgo_import_static __tsan_finalizer_goroutine
//go:cgo_import_static __tsan_go_start
//go:cgo_import_static __tsan_go_end
//go:cgo_import_static __tsan_malloc
//go:cgo_import_static __tsan_free
//go:cgo_import_static __tsan_acquire
//go:cgo_import_static __tsan_release
//go:cgo_import_static __tsan_release_acquire
//go:cgo_import_static __tsan_release_merge
//go:cgo_import_static __tsan_go_ignore_sync_begin
//go:cgo_import_static __tsan_go_ignore_sync_end
//go:cgo_import_static __tsan_report_count

// These are called from race_amd64.s.
//
//go:cgo_import_static __tsan_read
//go:cgo_import_static __tsan_read_pc
//go:cgo_import_static __tsan_read_range
//go:cgo_import_static __tsan_write
//go:cgo_import_static __tsan_write_pc
//go:cgo_import_static __tsan_write_range
//go:cgo_import_static __tsan_func_enter
//go:cgo_import_static __tsan_func_exit

//go:cgo_import_static __tsan_go_atomic32_load
//go:cgo_import_static __tsan_go_atomic64_load
//go:cgo_import_static __tsan_go_atomic32_store
//go:cgo_import_static __tsan_go_atomic64_store
//go:cgo_import_static __tsan_go_atomic32_exchange
//go:cgo_import_static __tsan_go_atomic64_exchange
//go:cgo_import_static __tsan_go_atomic32_fetch_add
//go:cgo_import_static __tsan_go_atomic64_fetch_add
//go:cgo_import_static __tsan_go_atomic32_fetch_and
//go:cgo_import_static __tsan_go_atomic64_fetch_and
//go:cgo_import_static __tsan_go_atomic32_fetch_or
//go:cgo_import_static __tsan_go_atomic64_fetch_or
//go:cgo_import_static __tsan_go_atomic32_compare_exchange
//go:cgo_import_static __tsan_go_atomic64_compare_exchange

// start/end of global data (data+bss).
var racedatastart uintptr
var racedataend uintptr

// start/end of heap for race_amd64.s
var racearenastart uintptr
var racearenaend uintptr

func racefuncenter(callpc uintptr)
func racefuncenterfp(fp uintptr)
func racefuncexit()
func raceread(addr uintptr)
func racewrite(addr uintptr)
func racereadrange(addr, size uintptr)
func racewriterange(addr, size uintptr)
func racereadrangepc1(addr, size, pc uintptr)
func racewriterangepc1(addr, size, pc uintptr)
func racecallbackthunk(uintptr)

// racecall allows calling an arbitrary function fn from C race runtime
// with up to 4 uintptr arguments.
func racecall(fn *byte, arg0, arg1, arg2, arg3 uintptr)

// checks if the address has shadow (i.e. heap or data/bss).
//
//go:nosplit
func isvalidaddr(addr unsafe.Pointer) bool {
	return racearenastart <= uintptr(addr) && uintptr(addr) < racearenaend ||
		racedatastart <= uintptr(addr) && uintptr(addr) < racedataend
}

//go:nosplit
func raceinit() (gctx, pctx uintptr) {
	lockInit(&raceFiniLock, lockRankRaceFini)

	// On most machines, cgo is required to initialize libc, which is used by race runtime.
	if !iscgo && GOOS != "darwin" {
		throw("raceinit: race build must use cgo")
	}

	racecall(&__tsan_init, uintptr(unsafe.Pointer(&gctx)), uintptr(unsafe.Pointer(&pctx)), abi.FuncPCABI0(racecallbackthunk), 0)

	// Round data segment to page boundaries, because it's used in mmap().
	start := ^uintptr(0)
	end := uintptr(0)
	if start > firstmoduledata.noptrdata {
		start = firstmoduledata.noptrdata
	}
	if start > firstmoduledata.data {
		start = firstmoduledata.data
	}
	if start > firstmoduledata.noptrbss {
		start = firstmoduledata.noptrbss
	}
	if start > firstmoduledata.bss {
		start = firstmoduledata.bss
	}
	if end < firstmoduledata.enoptrdata {
		end = firstmoduledata.enoptrdata
	}
	if end < firstmoduledata.edata {
		end = firstmoduledata.edata
	}
	if end < firstmoduledata.enoptrbss {
		end = firstmoduledata.enoptrbss
	}
	if end < firstmoduledata.ebss {
		end = firstmoduledata.ebss
	}
	size := alignUp(end-start, _PageSize)
	racecall(&__tsan_map_shadow, start, size, 0, 0)
	racedatastart = start
	racedataend = start + size

	return
}

//go:nosplit
func racefini() {
	// racefini() can only be called once to avoid races.
	// This eventually (via __tsan_fini) calls C.exit which has
	// undefined behavior if called more than once. If the lock is
	// already held it's assumed that the first caller exits the program
	// so other calls can hang forever without an issue.
	lock(&raceFiniLock)

	// __tsan_fini will run C atexit functions and C++ destructors,
	// which can theoretically call back into Go.
	// Tell the scheduler we entering external code.
	entersyscall()

	// We're entering external code that may call ExitProcess on
	// Windows.
	osPreemptExtEnter(getg().m)

	racecall(&__tsan_fini, 0, 0, 0, 0)
}

//go:nosplit
func raceproccreate() uintptr {
	var ctx uintptr
	racecall(&__tsan_proc_create, uintptr(unsafe.Pointer(&ctx)), 0, 0, 0)
	return ctx
}

//go:nosplit
func raceprocdestroy(ctx uintptr) {
	racecall(&__tsan_proc_destroy, ctx, 0, 0, 0)
}

//go:nosplit
func racemapshadow(addr unsafe.Pointer, size uintptr) {
	if racearenastart == 0 {
		racearenastart = uintptr(addr)
	}
	if racearenaend < uintptr(addr)+size {
		racearenaend = uintptr(addr) + size
	}
	racecall(&__tsan_map_shadow, uintptr(addr), size, 0, 0)
}

//go:nosplit
func racemalloc(p unsafe.Pointer, sz uintptr) {
	racecall(&__tsan_malloc, 0, 0, uintptr(p), sz)
}

//go:nosplit
func racefree(p unsafe.Pointer, sz uintptr) {
	racecall(&__tsan_free, uintptr(p), sz, 0, 0)
}

//go:nosplit
func racegostart(pc uintptr) uintptr {
	gp := getg()
	var spawng *g
	if gp.m.curg != nil {
		spawng = gp.m.curg
	} else {
		spawng = gp
	}

	var racectx uintptr
	racecall(&__tsan_go_start, spawng.racectx, uintptr(unsafe.Pointer(&racectx)), pc, 0)
	return racectx
}

//go:nosplit
func racegoend() {
	racecall(&__tsan_go_end, getg().racectx, 0, 0, 0)
}

//go:nosplit
func racectxend(racectx uintptr) {
	racecall(&__tsan_go_end, racectx, 0, 0, 0)
}

//go:nosplit
func racewriterangepc(addr unsafe.Pointer, sz, callpc, pc uintptr) {
	gp := getg()
	if gp != gp.m.curg {
		// The call is coming from manual instrumentation of Go code running on g0/gsignal.
		// Not interesting.
		return
	}
	if callpc != 0 {
		racefuncenter(callpc)
	}
	racewriterangepc1(uintptr(addr), sz, pc)
	if callpc != 0 {
		racefuncexit()
	}
}

//go:nosplit
func racereadrangepc(addr unsafe.Pointer, sz, callpc, pc uintptr) {
	gp := getg()
	if gp != gp.m.curg {
		// The call is coming from manual instrumentation of Go code running on g0/gsignal.
		// Not interesting.
		return
	}
	if callpc != 0 {
		racefuncenter(callpc)
	}
	racereadrangepc1(uintptr(addr), sz, pc)
	if callpc != 0 {
		racefuncexit()
	}
}

//go:nosplit
func raceacquire(addr unsafe.Pointer) {
	raceacquireg(getg(), addr)
}

//go:nosplit
func raceacquireg(gp *g, addr unsafe.Pointer) {
	if getg().raceignore != 0 || !isvalidaddr(addr) {
		return
	}
	racecall(&__tsan_acquire, gp.racectx, uintptr(addr), 0, 0)
}

//go:nosplit
func raceacquirectx(racectx uintptr, addr unsafe.Pointer) {
	if !isvalidaddr(addr) {
		return
	}
	racecall(&__tsan_acquire, racectx, uintptr(addr), 0, 0)
}

//go:nosplit
func racerelease(addr unsafe.Pointer) {
	racereleaseg(getg(), addr)
}

//go:nosplit
func racereleaseg(gp *g, addr unsafe.Pointer) {
	if getg().raceignore != 0 || !isvalidaddr(addr) {
		return
	}
	racecall(&__tsan_release, gp.racectx, uintptr(addr), 0, 0)
}

//go:nosplit
func racereleaseacquire(addr unsafe.Pointer) {
	racereleaseacquireg(getg(), addr)
}

//go:nosplit
func racereleaseacquireg(gp *g, addr unsafe.Pointer) {
	if getg().raceignore != 0 || !isvalidaddr(addr) {
		return
	}
	racecall(&__tsan_release_acquire, gp.racectx, uintptr(addr), 0, 0)
}

//go:nosplit
func racereleasemerge(addr unsafe.Pointer) {
	racereleasemergeg(getg(), addr)
}

//go:nosplit
func racereleasemergeg(gp *g, addr unsafe.Pointer) {
	if getg().raceignore != 0 || !isvalidaddr(addr) {
		return
	}
	racecall(&__tsan_release_merge, gp.racectx, uintptr(addr), 0, 0)
}

//go:nosplit
func racefingo() {
	racecall(&__tsan_finalizer_goroutine, getg().racectx, 0, 0, 0)
}

// The declarations below generate ABI wrappers for functions
// implemented in assembly in this package but declared in another
// package.

//go:linkname abigen_sync_atomic_LoadInt32 sync/atomic.LoadInt32
func abigen_sync_atomic_LoadInt32(addr *int32) (val int32)

//go:linkname abigen_sync_atomic_LoadInt64 sync/atomic.LoadInt64
func abigen_sync_atomic_LoadInt64(addr *int64) (val int64)

//go:linkname abigen_sync_atomic_LoadUint32 sync/atomic.LoadUint32
func abigen_sync_atomic_LoadUint32(addr *uint32) (val uint32)

//go:linkname abigen_sync_atomic_LoadUint64 sync/atomic.LoadUint64
func abigen_sync_atomic_LoadUint64(addr *uint64) (val uint64)

//go:linkname abigen_sync_atomic_LoadUintptr sync/atomic.LoadUintptr
func abigen_sync_atomic_LoadUintptr(addr *uintptr) (val uintptr)

//go:linkname abigen_sync_atomic_LoadPointer sync/atomic.LoadPointer
func abigen_sync_atomic_LoadPointer(addr *unsafe.Pointer) (val unsafe.Pointer)

//go:linkname abigen_sync_atomic_StoreInt32 sync/atomic.StoreInt32
func abigen_sync_atomic_StoreInt32(addr *int32, val int32)

//go:linkname abigen_sync_atomic_StoreInt64 sync/atomic.StoreInt64
func abigen_sync_atomic_StoreInt64(addr *int64, val int64)

//go:linkname abigen_sync_atomic_StoreUint32 sync/atomic.StoreUint32
func abigen_sync_atomic_StoreUint32(addr *uint32, val uint32)

//go:linkname abigen_sync_atomic_StoreUint64 sync/atomic.StoreUint64
func abigen_sync_atomic_StoreUint64(addr *uint64, val uint64)

//go:linkname abigen_sync_atomic_SwapInt32 sync/atomic.SwapInt32
func abigen_sync_atomic_SwapInt32(addr *int32, new int32) (old int32)

//go:linkname abigen_sync_atomic_SwapInt64 sync/atomic.SwapInt64
func abigen_sync_atomic_SwapInt64(addr *int64, new int64) (old int64)

//go:linkname abigen_sync_atomic_SwapUint32 sync/atomic.SwapUint32
func abigen_sync_atomic_SwapUint32(addr *uint32, new uint32) (old uint32)

//go:linkname abigen_sync_atomic_SwapUint64 sync/atomic.SwapUint64
func abigen_sync_atomic_SwapUint64(addr *uint64, new uint64) (old uint64)

//go:linkname abigen_sync_atomic_AddInt32 sync/atomic.AddInt32
func abigen_sync_atomic_AddInt32(addr *int32, delta int32) (new int32)

//go:linkname abigen_sync_atomic_AddUint32 sync/atomic.AddUint32
func abigen_sync_atomic_AddUint32(addr *uint32, delta uint32) (new uint32)

//go:linkname abigen_sync_atomic_AddInt64 sync/atomic.AddInt64
func abigen_sync_atomic_AddInt64(addr *int64, delta int64) (new int64)

//go:linkname abigen_sync_atomic_AddUint64 sync/atomic.AddUint64
func abigen_sync_atomic_AddUint64(addr *uint64, delta uint64) (new uint64)

//go:linkname abigen_sync_atomic_AddUintptr sync/atomic.AddUintptr
func abigen_sync_atomic_AddUintptr(addr *uintptr, delta uintptr) (new uintptr)

//go:linkname abigen_sync_atomic_AndInt32 sync/atomic.AndInt32
func abigen_sync_atomic_AndInt32(addr *int32, mask int32) (old int32)

//go:linkname abigen_sync_atomic_AndUint32 sync/atomic.AndUint32
func abigen_sync_atomic_AndUint32(addr *uint32, mask uint32) (old uint32)

//go:linkname abigen_sync_atomic_AndInt64 sync/atomic.AndInt64
func abigen_sync_atomic_AndInt64(addr *int64, mask int64) (old int64)

//go:linkname abigen_sync_atomic_AndUint64 sync/atomic.AndUint64
func abigen_sync_atomic_AndUint64(addr *uint64, mask uint64) (old uint64)

//go:linkname abigen_sync_atomic_AndUintptr sync/atomic.AndUintptr
func abigen_sync_atomic_AndUintptr(addr *uintptr, mask uintptr) (old uintptr)

//go:linkname abigen_sync_atomic_OrInt32 sync/atomic.OrInt32
func abigen_sync_atomic_OrInt32(addr *int32, mask int32) (old int32)

//go:linkname abigen_sync_atomic_OrUint32 sync/atomic.OrUint32
func abigen_sync_atomic_OrUint32(addr *uint32, mask uint32) (old uint32)

//go:linkname abigen_sync_atomic_OrInt64 sync/atomic.OrInt64
func abigen_sync_atomic_OrInt64(addr *int64, mask int64) (old int64)

//go:linkname abigen_sync_atomic_OrUint64 sync/atomic.OrUint64
func abigen_sync_atomic_OrUint64(addr *uint64, mask uint64) (old uint64)

//go:linkname abigen_sync_atomic_OrUintptr sync/atomic.OrUintptr
func abigen_sync_atomic_OrUintptr(addr *uintptr, mask uintptr) (old uintptr)

//go:linkname abigen_sync_atomic_CompareAndSwapInt32 sync/atomic.CompareAndSwapInt32
func abigen_sync_atomic_CompareAndSwapInt32(addr *int32, old, new int32) (swapped bool)

//go:linkname abigen_sync_atomic_CompareAndSwapInt64 sync/atomic.CompareAndSwapInt64
func abigen_sync_atomic_CompareAndSwapInt64(addr *int64, old, new int64) (swapped bool)

//go:linkname abigen_sync_atomic_CompareAndSwapUint32 sync/atomic.CompareAndSwapUint32
func abigen_sync_atomic_CompareAndSwapUint32(addr *uint32, old, new uint32) (swapped bool)

//go:linkname abigen_sync_atomic_CompareAndSwapUint64 sync/atomic.CompareAndSwapUint64
func abigen_sync_atomic_CompareAndSwapUint64(addr *uint64, old, new uint64) (swapped bool)
```