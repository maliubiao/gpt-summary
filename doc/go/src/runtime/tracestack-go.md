Response:
Let's break down the thought process for analyzing the Go code snippet and generating the response.

**1. Understanding the Request:**

The core request is to understand the functionality of the provided Go code, specifically the `go/src/runtime/tracestack.go` file. The request has several sub-components:

* **List Functionality:** Identify the key tasks performed by the code.
* **Infer Go Feature:**  Determine what broader Go capability this code supports.
* **Go Code Example:** Illustrate the feature's usage.
* **Code Inference (with examples):** If functionality involves complex logic, demonstrate it with input/output scenarios.
* **Command-line Arguments:** Explain relevant command-line flags.
* **Common Mistakes:**  Point out potential pitfalls for users.
* **Chinese Response:**  The entire response must be in Chinese.

**2. Initial Code Scan and Keyword Identification:**

The first step is to skim the code and identify key terms and data structures. This involves looking for:

* **Package Name:** `package runtime` immediately tells us this is part of Go's core runtime.
* **Function Names:** `traceStack`, `traceStackTable`, `put`, `dump`, `makeTraceFrames`, `fpTracebackPCs`, `fpunwindExpand`, `startPCForTrace`. These are the primary actions the code performs.
* **Constants:** `traceStackSize`, `logicalStackSentinel`. These define limits and special values.
* **Data Structures:** `traceStackTable`, `traceMap`, `traceFrame`. Understanding their purpose is crucial.
* **Imports:** `internal/abi`, `internal/goarch`, `unsafe`. These hint at low-level operations and architecture dependencies.
* **Comments:** Pay attention to the comments, especially those explaining the purpose of functions and constants. The comment at the beginning of `traceStack` is very helpful.

**3. Analyzing Key Functions:**

* **`traceStack`:** This is the central function. The comments clearly state it "captures a stack trace from a goroutine and registers it in the trace stack table." The `skip` parameter suggests it's used to filter out internal tracer details. The logic branches based on whether frame pointer unwinding is enabled (`tracefpunwindoff`) or if Cgo is involved. This points to different methods of obtaining the call stack.
* **`traceStackTable`:**  This structure seems to be a table for storing and retrieving stack traces using unique IDs. The `put` method likely adds new stack traces, and `dump` suggests a way to output the stored traces.
* **`put`:**  Confirms the table's purpose of associating a unique ID with a stack trace.
* **`dump`:**  Indicates the process of writing the stored stack traces to some output, likely for tracing or profiling purposes.
* **`makeTraceFrames`:** Converts a slice of program counters (PCs) into a slice of `traceFrame` structs, which contain more detailed information about each stack frame (function name, file, line number).
* **`fpTracebackPCs`:** The name strongly suggests this function is responsible for traversing the stack using frame pointers to collect return addresses (PCs).
* **`fpunwindExpand`:**  This function handles the expansion of stack frames, potentially dealing with inlined function calls. The `logicalStackSentinel` is a key indicator of the stack format.
* **`startPCForTrace`:**  Seems to handle cases where the initial PC points to a wrapper function and tries to get the PC of the actual wrapped function.

**4. Inferring the Go Feature:**

Based on the function names and the overall purpose of capturing and storing stack traces, the most likely Go feature being implemented is **Go's built-in tracing and profiling capabilities**. Specifically, this code seems to be involved in capturing stack traces during runtime for analysis with tools like `go tool trace`.

**5. Crafting the Go Code Example:**

To illustrate the tracing functionality, a simple program that performs some work and then uses the `runtime/trace` package to start and stop tracing is necessary. The `go tool trace` command is essential for analyzing the generated trace file.

**6. Code Inference Examples (Input/Output):**

The `fpunwindExpand` function has some interesting logic related to inlining. To illustrate this:

* **Input:** A hypothetical `pcBuf` representing a stack trace with an inlined function.
* **Output:** The expanded `dst` showing the individual frames, including the inlined ones.

**7. Command-line Arguments:**

The `tracefpunwindoff` function mentions `GODEBUG`. This immediately suggests that the `GODEBUG` environment variable is relevant. Specifically, `GODEBUG=tracefponly=0` disables frame pointer unwinding.

**8. Common Mistakes:**

The main potential mistake for users would be directly calling the internal `traceStack` function. The comments explicitly discourage this, emphasizing the need for synchronization with generations. This leads to the example of incorrect usage.

**9. Structuring the Response in Chinese:**

The final step is to organize all the gathered information into a clear and concise Chinese response, addressing each part of the original request. This involves:

* **Using clear and precise language.**
* **Translating technical terms accurately.**
* **Structuring the answer logically with headings and bullet points.**
* **Providing clear code examples with explanations.**

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is related to error handling or panic recovery.
* **Correction:** The emphasis on tracing, the `traceStackTable`, and the interaction with `go tool trace` strongly point to the tracing/profiling feature.
* **Initial thought:**  Focus heavily on the low-level details of frame pointer manipulation.
* **Refinement:** While important, it's more crucial to explain the *purpose* of these operations within the broader context of tracing. The high-level functionality is key for the request.
* **Ensuring all aspects of the request are addressed:** Double-check that the response covers functionality, feature identification, code examples, input/output for code inference, command-line arguments, and potential mistakes.
这段代码是 Go 语言运行时环境 `runtime` 包中 `tracestack.go` 文件的一部分，主要负责**收集和管理 goroutine 的堆栈跟踪信息，用于 Go 的追踪 (tracing) 功能**。

下面我们详细列举它的功能并进行解释：

**主要功能:**

1. **`traceStack(skip int, gp *g, gen uintptr) uint64`**:
   - **捕获 Goroutine 的堆栈信息:**  这个函数是核心，用于获取指定 goroutine (`gp`) 的当前堆栈信息。如果 `gp` 为 `nil`，则尝试获取当前执行的 goroutine 的堆栈。
   - **跳过指定帧:** `skip` 参数允许跳过堆栈顶部的若干帧，这通常用于隐藏追踪器内部的实现细节，让用户看到的堆栈更简洁。
   - **区分快速路径和慢速路径:**  根据是否启用帧指针展开 (`tracefpunwindoff`) 以及是否存在 CGO 调用，选择不同的堆栈展开方式。
     - **快速路径 (Frame Pointer Unwinding):**  利用帧指针快速遍历堆栈，效率较高。
     - **慢速路径 (Default Unwinder):** 使用更通用的 `callers` 或 `gcallers` 函数进行堆栈展开，可能涉及查找符号表等操作。
   - **处理不同 Goroutine 状态:**  能够处理当前正在运行的 goroutine 和不在运行但可能被锁定的 goroutine 的堆栈。
   - **注册堆栈到堆栈跟踪表:** 将捕获到的堆栈信息存储到 `traceStackTable` 中。
   - **返回唯一 ID:**  为每个不同的堆栈跟踪生成一个唯一的 64 位 ID。这个 ID 可以用来在追踪事件中引用这个堆栈，避免重复存储完整的堆栈信息，节省空间。

2. **`traceStackTable`**:
   - **存储堆栈跟踪:**  这个结构体包含一个 `traceMap`，用于存储堆栈跟踪信息及其对应的 ID。
   - **锁无关读取:**  设计为读取操作是无锁的，提高并发性能。

3. **`put(pcs []uintptr) uint64` (在 `traceStackTable` 中):**
   - **添加新的堆栈跟踪:**  接收一个表示堆栈帧的程序计数器 (PC) 切片 `pcs`。
   - **缓存堆栈:** 如果这个堆栈跟踪是第一次遇到，则将其添加到 `traceMap` 中，并返回一个新的唯一 ID。

4. **`dump(gen uintptr)` (在 `traceStackTable` 中):**
   - **转储缓存的堆栈:**  将之前缓存的所有堆栈跟踪信息写入到追踪缓冲区中。
   - **释放内存并重置状态:**  在转储完成后，释放 `traceStackTable` 占用的内存并重置其状态。
   - **保证没有写入者:**  这个函数只能在确保没有其他线程会向 `traceStackTable` 写入数据时调用。

5. **`dumpStacksRec(node *traceMapNode, w traceWriter, stackBuf []uintptr) traceWriter`**:
   - **递归转储堆栈:**  递归遍历 `traceMap` 中的节点，将每个堆栈跟踪写入到 `traceWriter`。
   - **展开内联函数:** 使用 `fpunwindExpand` 函数将物理堆栈帧展开为包含内联函数的逻辑堆栈帧。
   - **生成追踪事件:**  将堆栈信息编码为 `traceEvStack` 或 `traceEvStacks` 事件写入追踪缓冲区。

6. **`makeTraceFrames(gen uintptr, pcs []uintptr) []traceFrame`**:
   - **将 PC 转换为 `traceFrame`:**  将程序计数器 (PC) 切片转换为包含更详细信息的 `traceFrame` 结构体切片。
   - **获取函数和文件名:**  利用 `CallersFrames` 迭代器获取每个 PC 对应的函数名、文件名和行号。
   - **存储字符串到字符串表:** 将函数名和文件名存储到全局的字符串表 (`trace.stringTab`) 中，并使用其 ID，减少重复存储。

7. **`makeTraceFrame(gen uintptr, f Frame) traceFrame`**:
   - **创建单个 `traceFrame`:**  从 `runtime.Frame` 结构体中提取 PC、函数名、文件名和行号信息，并存储到 `traceFrame` 中。
   - **截断过长的字符串:**  如果函数名或文件名过长，则进行截断。

8. **`tracefpunwindoff() bool`**:
   - **判断是否禁用帧指针展开:**  检查环境变量 `GODEBUG` 中的 `tracefpunwindoff` 选项，以及当前架构是否支持帧指针展开。

9. **`fpTracebackPCs(fp unsafe.Pointer, pcBuf []uintptr) (i int)`**:
   - **使用帧指针展开获取 PC:**  通过帧指针 `fp` 遍历堆栈，将每个栈帧的返回地址 (PC) 存储到 `pcBuf` 中。

10. **`fpunwindExpand(dst, pcBuf []uintptr) int`**:
    - **展开堆栈帧:** 将 `pcBuf` 中的物理堆栈帧（可能由 `fpTracebackPCs` 获取）展开为包含内联函数的逻辑堆栈帧，并将结果存储到 `dst` 中。
    - **处理逻辑堆栈:** 如果 `pcBuf` 以 `logicalStackSentinel` 开头，则表示已经是逻辑堆栈，直接复制。
    - **应用跳过值:**  处理 `pcBuf[0]` 中存储的跳过值。

11. **`startPCForTrace(pc uintptr) uintptr`**:
    - **获取用于追踪的起始 PC:**  如果给定的 `pc` 属于一个包装函数（wrapper），则返回被包装函数的 PC，否则返回原始的 `pc`。这有助于追踪到实际执行的函数。

**实现的 Go 语言功能：Go 的追踪 (Tracing) 功能**

这段代码是 Go 语言追踪功能的核心组成部分。Go 的追踪功能允许开发者在运行时记录程序的各种事件，包括 goroutine 的创建、阻塞、解锁、调度，以及用户自定义的事件等。捕获堆栈跟踪是追踪功能中非常重要的一环，它可以帮助开发者理解程序在特定时刻的执行路径，从而进行性能分析、死锁检测、问题定位等。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"runtime"
	"runtime/trace"
	"os"
)

func foo() {
	bar()
}

func bar() {
	runtime.Gosched() // 让出 CPU
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

	go foo() // 启动一个 goroutine

	fmt.Println("Hello from main")
}
```

**假设的输入与输出 (涉及代码推理):**

假设我们运行上面的代码，并且在 `bar` 函数中 `runtime.Gosched()` 发生时，追踪器捕获了 goroutine 的堆栈。

**输入 (在 `traceStack` 函数中):**

- `skip`: 0 (假设不跳过任何帧)
- `gp`: 指向 `foo` goroutine 的 `g` 结构体的指针
- `gen`: 当前的追踪代数

**输出 (可能的 `pcBuf` 和 `nstk`):**

如果使用帧指针展开，`pcBuf` 可能会包含类似以下的程序计数器 (PC) 值，`nstk` 表示捕获到的帧数：

```
pcBuf = [
    地址_runtime_goexit,
    地址_main_bar,
    地址_main_foo,
    地址_runtime_goexit, // 实际中不会包含这个，这里只是为了示意
]
nstk = 3
```

如果使用默认展开器，`pcBuf` 的内容和 `nstk` 的值可能会略有不同，但最终会包含类似的调用栈信息。

**后续处理:**

`traceStack` 函数会调用 `trace.stackTab[gen%2].put(pcBuf[:nstk])`，将 `pcBuf` 中的堆栈信息存储到 `traceStackTable` 中，并返回一个唯一的 ID。这个 ID 会被记录到追踪事件中。

**命令行参数的具体处理:**

代码中提到了 `GODEBUG=tracefpunwindoff=1`。这是一个 Go 运行时环境变量，用于禁用追踪器的帧指针展开优化。

- **不设置或 `GODEBUG=tracefpunwindoff=0`:**  如果架构支持且没有其他原因禁用，追踪器会尝试使用更高效的帧指针展开来获取堆栈信息。
- **`GODEBUG=tracefpunwindoff=1`:**  强制追踪器使用较慢但更通用的堆栈展开方式，即使架构支持帧指针展开。这在某些情况下可能用于调试或解决帧指针展开引起的问题。

**使用者易犯错的点:**

用户不太可能直接与 `runtime/tracestack.go` 中的函数交互。这些是底层的运行时实现细节。

但如果开发者尝试**手动模拟或干预 Go 的追踪机制**，可能会犯错。例如：

1. **直接调用 `traceStack` 函数:**  `traceStack` 函数的注释中明确指出“避免直接调用此函数”。它需要与追踪代数同步，如果直接调用可能会导致数据不一致或其他问题。

   ```go
   // 错误示例：直接调用 traceStack
   // 这可能会导致追踪数据错误
   // runtime.traceStack(0, runtime.GetCurrentGo(), 0)
   ```

2. **错误地假设堆栈信息的格式或内容:**  堆栈信息的具体格式和内容是运行时内部实现，可能会随着 Go 版本的变化而改变。不应该依赖于特定的堆栈帧结构或 PC 值进行硬编码的判断。

总而言之，`go/src/runtime/tracestack.go` 中的代码是 Go 语言追踪功能的基础，它负责高效地捕获和管理 goroutine 的堆栈信息，为性能分析和问题诊断提供了重要的支撑。开发者通常通过 `runtime/trace` 包来使用 Go 的追踪功能，而无需直接关心 `tracestack.go` 的实现细节。

Prompt: 
```
这是路径为go/src/runtime/tracestack.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Trace stack table and acquisition.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"unsafe"
)

const (
	// Maximum number of PCs in a single stack trace.
	// Since events contain only stack id rather than whole stack trace,
	// we can allow quite large values here.
	traceStackSize = 128

	// logicalStackSentinel is a sentinel value at pcBuf[0] signifying that
	// pcBuf[1:] holds a logical stack requiring no further processing. Any other
	// value at pcBuf[0] represents a skip value to apply to the physical stack in
	// pcBuf[1:] after inline expansion.
	logicalStackSentinel = ^uintptr(0)
)

// traceStack captures a stack trace from a goroutine and registers it in the trace
// stack table. It then returns its unique ID. If gp == nil, then traceStack will
// attempt to use the current execution context.
//
// skip controls the number of leaf frames to omit in order to hide tracer internals
// from stack traces, see CL 5523.
//
// Avoid calling this function directly. gen needs to be the current generation
// that this stack trace is being written out for, which needs to be synchronized with
// generations moving forward. Prefer traceEventWriter.stack.
func traceStack(skip int, gp *g, gen uintptr) uint64 {
	var pcBuf [traceStackSize]uintptr

	// Figure out gp and mp for the backtrace.
	var mp *m
	if gp == nil {
		mp = getg().m
		gp = mp.curg
	}

	// Double-check that we own the stack we're about to trace.
	if debug.traceCheckStackOwnership != 0 && gp != nil {
		status := readgstatus(gp)
		// If the scan bit is set, assume we're the ones that acquired it.
		if status&_Gscan == 0 {
			// Use the trace status to check this. There are a number of cases
			// where a running goroutine might be in _Gwaiting, and these cases
			// are totally fine for taking a stack trace. They're captured
			// correctly in goStatusToTraceGoStatus.
			switch goStatusToTraceGoStatus(status, gp.waitreason) {
			case traceGoRunning, traceGoSyscall:
				if getg() == gp || mp.curg == gp {
					break
				}
				fallthrough
			default:
				print("runtime: gp=", unsafe.Pointer(gp), " gp.goid=", gp.goid, " status=", gStatusStrings[status], "\n")
				throw("attempted to trace stack of a goroutine this thread does not own")
			}
		}
	}

	if gp != nil && mp == nil {
		// We're getting the backtrace for a G that's not currently executing.
		// It may still have an M, if it's locked to some M.
		mp = gp.lockedm.ptr()
	}
	nstk := 1
	if tracefpunwindoff() || (mp != nil && mp.hasCgoOnStack()) {
		// Slow path: Unwind using default unwinder. Used when frame pointer
		// unwinding is unavailable or disabled (tracefpunwindoff), or might
		// produce incomplete results or crashes (hasCgoOnStack). Note that no
		// cgo callback related crashes have been observed yet. The main
		// motivation is to take advantage of a potentially registered cgo
		// symbolizer.
		pcBuf[0] = logicalStackSentinel
		if getg() == gp {
			nstk += callers(skip+1, pcBuf[1:])
		} else if gp != nil {
			nstk += gcallers(gp, skip, pcBuf[1:])
		}
	} else {
		// Fast path: Unwind using frame pointers.
		pcBuf[0] = uintptr(skip)
		if getg() == gp {
			nstk += fpTracebackPCs(unsafe.Pointer(getfp()), pcBuf[1:])
		} else if gp != nil {
			// Three cases:
			//
			// (1) We're called on the g0 stack through mcall(fn) or systemstack(fn). To
			// behave like gcallers above, we start unwinding from sched.bp, which
			// points to the caller frame of the leaf frame on g's stack. The return
			// address of the leaf frame is stored in sched.pc, which we manually
			// capture here.
			//
			// (2) We're called against a gp that we're not currently executing on, but that isn't
			// in a syscall, in which case it's currently not executing. gp.sched contains the most
			// up-to-date information about where it stopped, and like case (1), we match gcallers
			// here.
			//
			// (3) We're called against a gp that we're not currently executing on, but that is in
			// a syscall, in which case gp.syscallsp != 0. gp.syscall* contains the most up-to-date
			// information about where it stopped, and like case (1), we match gcallers here.
			if gp.syscallsp != 0 {
				pcBuf[1] = gp.syscallpc
				nstk += 1 + fpTracebackPCs(unsafe.Pointer(gp.syscallbp), pcBuf[2:])
			} else {
				pcBuf[1] = gp.sched.pc
				nstk += 1 + fpTracebackPCs(unsafe.Pointer(gp.sched.bp), pcBuf[2:])
			}
		}
	}
	if nstk > 0 {
		nstk-- // skip runtime.goexit
	}
	if nstk > 0 && gp.goid == 1 {
		nstk-- // skip runtime.main
	}
	id := trace.stackTab[gen%2].put(pcBuf[:nstk])
	return id
}

// traceStackTable maps stack traces (arrays of PC's) to unique uint32 ids.
// It is lock-free for reading.
type traceStackTable struct {
	tab traceMap
}

// put returns a unique id for the stack trace pcs and caches it in the table,
// if it sees the trace for the first time.
func (t *traceStackTable) put(pcs []uintptr) uint64 {
	if len(pcs) == 0 {
		return 0
	}
	id, _ := t.tab.put(noescape(unsafe.Pointer(&pcs[0])), uintptr(len(pcs))*unsafe.Sizeof(uintptr(0)))
	return id
}

// dump writes all previously cached stacks to trace buffers,
// releases all memory and resets state. It must only be called once the caller
// can guarantee that there are no more writers to the table.
func (t *traceStackTable) dump(gen uintptr) {
	stackBuf := make([]uintptr, traceStackSize)
	w := unsafeTraceWriter(gen, nil)
	if root := (*traceMapNode)(t.tab.root.Load()); root != nil {
		w = dumpStacksRec(root, w, stackBuf)
	}
	w.flush().end()
	t.tab.reset()
}

func dumpStacksRec(node *traceMapNode, w traceWriter, stackBuf []uintptr) traceWriter {
	stack := unsafe.Slice((*uintptr)(unsafe.Pointer(&node.data[0])), uintptr(len(node.data))/unsafe.Sizeof(uintptr(0)))

	// N.B. This might allocate, but that's OK because we're not writing to the M's buffer,
	// but one we're about to create (with ensure).
	n := fpunwindExpand(stackBuf, stack)
	frames := makeTraceFrames(w.gen, stackBuf[:n])

	// The maximum number of bytes required to hold the encoded stack, given that
	// it contains N frames.
	maxBytes := 1 + (2+4*len(frames))*traceBytesPerNumber

	// Estimate the size of this record. This
	// bound is pretty loose, but avoids counting
	// lots of varint sizes.
	//
	// Add 1 because we might also write traceEvStacks.
	var flushed bool
	w, flushed = w.ensure(1 + maxBytes)
	if flushed {
		w.byte(byte(traceEvStacks))
	}

	// Emit stack event.
	w.byte(byte(traceEvStack))
	w.varint(uint64(node.id))
	w.varint(uint64(len(frames)))
	for _, frame := range frames {
		w.varint(uint64(frame.PC))
		w.varint(frame.funcID)
		w.varint(frame.fileID)
		w.varint(frame.line)
	}

	// Recursively walk all child nodes.
	for i := range node.children {
		child := node.children[i].Load()
		if child == nil {
			continue
		}
		w = dumpStacksRec((*traceMapNode)(child), w, stackBuf)
	}
	return w
}

// makeTraceFrames returns the frames corresponding to pcs. It may
// allocate and may emit trace events.
func makeTraceFrames(gen uintptr, pcs []uintptr) []traceFrame {
	frames := make([]traceFrame, 0, len(pcs))
	ci := CallersFrames(pcs)
	for {
		f, more := ci.Next()
		frames = append(frames, makeTraceFrame(gen, f))
		if !more {
			return frames
		}
	}
}

type traceFrame struct {
	PC     uintptr
	funcID uint64
	fileID uint64
	line   uint64
}

// makeTraceFrame sets up a traceFrame for a frame.
func makeTraceFrame(gen uintptr, f Frame) traceFrame {
	var frame traceFrame
	frame.PC = f.PC

	fn := f.Function
	const maxLen = 1 << 10
	if len(fn) > maxLen {
		fn = fn[len(fn)-maxLen:]
	}
	frame.funcID = trace.stringTab[gen%2].put(gen, fn)
	frame.line = uint64(f.Line)
	file := f.File
	if len(file) > maxLen {
		file = file[len(file)-maxLen:]
	}
	frame.fileID = trace.stringTab[gen%2].put(gen, file)
	return frame
}

// tracefpunwindoff returns true if frame pointer unwinding for the tracer is
// disabled via GODEBUG or not supported by the architecture.
func tracefpunwindoff() bool {
	return debug.tracefpunwindoff != 0 || (goarch.ArchFamily != goarch.AMD64 && goarch.ArchFamily != goarch.ARM64)
}

// fpTracebackPCs populates pcBuf with the return addresses for each frame and
// returns the number of PCs written to pcBuf. The returned PCs correspond to
// "physical frames" rather than "logical frames"; that is if A is inlined into
// B, this will return a PC for only B.
func fpTracebackPCs(fp unsafe.Pointer, pcBuf []uintptr) (i int) {
	for i = 0; i < len(pcBuf) && fp != nil; i++ {
		// return addr sits one word above the frame pointer
		pcBuf[i] = *(*uintptr)(unsafe.Pointer(uintptr(fp) + goarch.PtrSize))
		// follow the frame pointer to the next one
		fp = unsafe.Pointer(*(*uintptr)(fp))
	}
	return i
}

//go:linkname pprof_fpunwindExpand
func pprof_fpunwindExpand(dst, src []uintptr) int {
	return fpunwindExpand(dst, src)
}

// fpunwindExpand expands a call stack from pcBuf into dst,
// returning the number of PCs written to dst.
// pcBuf and dst should not overlap.
//
// fpunwindExpand checks if pcBuf contains logical frames (which include inlined
// frames) or physical frames (produced by frame pointer unwinding) using a
// sentinel value in pcBuf[0]. Logical frames are simply returned without the
// sentinel. Physical frames are turned into logical frames via inline unwinding
// and by applying the skip value that's stored in pcBuf[0].
func fpunwindExpand(dst, pcBuf []uintptr) int {
	if len(pcBuf) == 0 {
		return 0
	} else if len(pcBuf) > 0 && pcBuf[0] == logicalStackSentinel {
		// pcBuf contains logical rather than inlined frames, skip has already been
		// applied, just return it without the sentinel value in pcBuf[0].
		return copy(dst, pcBuf[1:])
	}

	var (
		n          int
		lastFuncID = abi.FuncIDNormal
		skip       = pcBuf[0]
		// skipOrAdd skips or appends retPC to newPCBuf and returns true if more
		// pcs can be added.
		skipOrAdd = func(retPC uintptr) bool {
			if skip > 0 {
				skip--
			} else if n < len(dst) {
				dst[n] = retPC
				n++
			}
			return n < len(dst)
		}
	)

outer:
	for _, retPC := range pcBuf[1:] {
		callPC := retPC - 1
		fi := findfunc(callPC)
		if !fi.valid() {
			// There is no funcInfo if callPC belongs to a C function. In this case
			// we still keep the pc, but don't attempt to expand inlined frames.
			if more := skipOrAdd(retPC); !more {
				break outer
			}
			continue
		}

		u, uf := newInlineUnwinder(fi, callPC)
		for ; uf.valid(); uf = u.next(uf) {
			sf := u.srcFunc(uf)
			if sf.funcID == abi.FuncIDWrapper && elideWrapperCalling(lastFuncID) {
				// ignore wrappers
			} else if more := skipOrAdd(uf.pc + 1); !more {
				break outer
			}
			lastFuncID = sf.funcID
		}
	}
	return n
}

// startPCForTrace returns the start PC of a goroutine for tracing purposes.
// If pc is a wrapper, it returns the PC of the wrapped function. Otherwise it
// returns pc.
func startPCForTrace(pc uintptr) uintptr {
	f := findfunc(pc)
	if !f.valid() {
		return pc // may happen for locked g in extra M since its pc is 0.
	}
	w := funcdata(f, abi.FUNCDATA_WrapInfo)
	if w == nil {
		return pc // not a wrapper
	}
	return f.datap.textAddr(*(*uint32)(w))
}

"""



```