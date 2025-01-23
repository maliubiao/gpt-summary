Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file path `go/src/runtime/stubs.go` immediately suggests that this file contains low-level runtime functions. The name "stubs" implies that some of these functions might have platform-specific implementations elsewhere (likely in assembly files).

2. **Scan for Key Concepts and Annotations:**  Look for recurring patterns and keywords:
    * `unsafe.Pointer`:  This strongly indicates low-level memory manipulation.
    * `//go:linkname`: This is a crucial annotation. It means functions defined here are being accessed from other packages (even though they are intended to be internal). This explains the comments about the "hall of shame".
    * `//go:nosplit`: Indicates functions that must not have stack splits, often due to their involvement in very low-level operations where stack manipulation could be dangerous.
    * `getg()`, `mcall()`, `systemstack()`:  These are fundamental runtime primitives related to goroutine management and stack switching.
    * `memclrNoHeapPointers()`, `memmove()`, `memequal()`:  These point to basic memory operations.
    * `reflectcall()`: Suggests interaction with the reflection mechanism.
    * `goexit()`:  The function a goroutine returns to.
    * `publicationBarrier()`: Hints at memory synchronization.
    * `cgocallback()`: Involves interaction with C code.
    * `abi.RegArgs`:  Related to function calling conventions and register arguments.

3. **Categorize the Functions:**  Based on the identified keywords and concepts, group the functions by their apparent purpose:
    * **Low-level Memory Operations:** `add`, `memclrNoHeapPointers`, `memmove`, `memequal`.
    * **Goroutine and Stack Management:** `getg`, `mcall`, `systemstack`, `goexit`, `morestack`, `morestack_noctxt`.
    * **Function Calling and Reflection:** `reflectcall`, `call16`...`call1073741824`.
    * **C Interoperability:** `cgocallback`, `asmcgocall`.
    * **Synchronization:** `publicationBarrier`.
    * **Utilities/Helpers:** `noescape`, `noEscapePtr`, `alignUp`, `alignDown`, `divRoundUp`, `bool2int`.
    * **Internal Runtime Operations:** `badsystemstack`, `return0`, `asminit`, `setg`, `breakpoint`, `rt0_go`, `systemstack_switch`, `checkASM`, `memequal_varlen`, `abort`, `gcWriteBarrier...`, `duffzero`, `duffcopy`, `addmoduledata`, `sigpanic0`.

4. **Explain Individual Functions:** For each function, describe its role based on its name, parameters, return type, and any associated comments. Pay special attention to the `//go:linkname` annotations and the reasons behind them.

5. **Identify Key Go Features:**  Connect the functions to specific Go features. For example:
    * Goroutines: `getg`, `mcall`, `systemstack`, `goexit`.
    * Memory Management: `memclrNoHeapPointers`, `memmove`, `publicationBarrier`.
    * Reflection: `reflectcall`.
    * Cgo: `cgocallback`, `asmcgocall`.
    * Function Calls: The `call...` family of functions relates to calling functions with varying stack frame sizes, likely used in reflection or runtime internals.

6. **Provide Code Examples:**  Illustrate the usage of the more prominent functions with simple Go code. Focus on demonstrating the core functionality. For functions like `mcall` which are not directly callable, explain their internal use.

7. **Consider Edge Cases and Potential Mistakes:**  Think about how developers might misuse these functions, especially those marked with `//go:linkname`. The main error is directly calling or relying on the stability of these internal functions.

8. **Structure the Answer:** Organize the information logically with clear headings and bullet points for readability. Start with a high-level summary and then delve into the details.

9. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Make sure the language is precise and avoids jargon where possible. For instance, initially, I might just say "`getg` gets the current goroutine," but refining it to "returns a pointer to the current goroutine" is more precise. Similarly, explaining *why* `mcall` isn't directly callable is crucial.

**Self-Correction/Refinement Example During the Process:**

* **Initial thought:** "Oh, `add` just adds to a pointer."
* **Refinement:** "Wait, it's an `unsafe.Pointer`. This is low-level address arithmetic. The comments mention `//go:linkname` and issues with other packages using it. I need to emphasize that this is *not* the typical way to do pointer arithmetic in Go and highlight the risks."

* **Initial thought:** "The `call...` functions are probably just different ways to call functions."
* **Refinement:** "The names suggest different sizes. The `reflectcall` function calls them. This is likely related to how Go handles function calls with varying stack frame sizes, especially in reflection scenarios where the argument layout might not be known at compile time."

By following this structured approach, including careful reading of comments and annotations, and iteratively refining understanding, one can effectively analyze and explain the functionality of this Go runtime code snippet.
这段代码是 Go 语言运行时环境 `runtime` 包中 `stubs.go` 文件的一部分。它定义了一些关键的底层函数，这些函数通常直接与操作系统或硬件交互，并且是 Go 语言运行时实现各种核心功能的基础。

以下是这些函数的功能列表：

**1. 底层内存操作:**

* **`add(p unsafe.Pointer, x uintptr) unsafe.Pointer`:** 将指针 `p` 增加 `x` 个字节。尽管名为 `add`，但它本质上是进行指针的偏移。由于一些外部包通过 `//go:linkname` 引用了它，因此其签名和存在性需要保持稳定，即使它本应是内部实现细节。
* **`memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)`:** 将从 `ptr` 开始的 `n` 个字节的内存清零。这个函数假定这块内存不包含堆指针，或者正在被重新使用。它保证了如果 `ptr` 是指针对齐的，且 `n` 是指针大小的倍数，则任何指针大小的部分会被原子地清除。 同样由于 `//go:linkname` 被外部包引用，需要保持稳定。
* **`memmove(to, from unsafe.Pointer, n uintptr)`:** 将 `n` 个字节从 `from` 复制到 `to`。这个函数确保在复制包含指针的内存时，写入操作是不可分割的，以防止垃圾回收器观察到半写入的指针。出于同样的原因，需要保持稳定。
* **`memequal(a, b unsafe.Pointer, size uintptr) bool`:** 比较从 `a` 和 `b` 开始的 `size` 个字节的内存是否相等。同样需要保持稳定。

**2. Goroutine 和栈管理:**

* **`getg() *g`:** 返回当前 Goroutine 的 `g` 结构体的指针。编译器会将对此函数的调用重写为直接从线程本地存储（TLS）或专用寄存器中获取 `g`。
* **`mcall(fn func(*g))`:** 从当前 Goroutine 的栈切换到 `g0` 栈，并调用函数 `fn(g)`，其中 `g` 是发起调用的 Goroutine。`mcall` 会保存 `g` 的当前 PC/SP 到 `g->sched`，以便稍后恢复。`fn` 负责安排稍后的执行，通常是将 `g` 记录在一个数据结构中，导致某些操作稍后调用 `ready(g)`。`mcall` 会在 `g` 被重新调度后返回到原始 Goroutine。`fn` 不能返回，通常以调用 `schedule` 结束，以便让当前的 M (machine) 运行其他 Goroutine。`mcall` 只能从 Goroutine 栈（而不是 `g0` 或 `gsignal` 栈）调用。
* **`systemstack(fn func())`:** 在系统栈上运行函数 `fn`。如果 `systemstack` 是从 per-OS-thread (`g0`) 栈或信号处理 (`gsignal`) 栈调用的，它会直接调用 `fn` 并返回。否则，如果从普通 Goroutine 的有限栈调用，它会切换到 per-OS-thread 栈，调用 `fn`，然后切换回来。
* **`badsystemstack()`:** 在不期望的 Goroutine 上调用 `systemstack` 时触发的函数，会打印错误信息。
* **`goexit(neverCallThisFunction)`:** 每个 Goroutine 调用栈顶部的返回存根。每个 Goroutine 栈都被构造为好像 `goexit` 调用了 Goroutine 的入口点函数。当入口点函数返回时，它会返回到 `goexit`，然后 `goexit` 会调用 `goexit1` 来执行实际的退出操作。这个函数不应该被直接调用。

**3. 函数调用相关:**

* **`reflectcall(stackArgsType *_type, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)`:** 使用 `stackArgs`、`stackArgsSize`、`frameSize` 和 `regArgs` 描述的参数调用函数 `fn`。这主要用于 `reflect` 包进行反射调用。
* **`call16` - `call1073741824`:** 这些是一系列函数，它们都调用 `reflectcall`，但可能用于不同大小的栈帧。它们的存在主要是为了为回溯提供类型信息。

**4. 同步和原子操作:**

* **`publicationBarrier()`:** 执行一个 store/store 内存屏障（也称为“发布”或“导出”屏障）。这用于在初始化一个对象和使该对象对另一个处理器可见之间进行同步，防止重排序导致另一个处理器看到未初始化的对象。

**5. 与 C 代码交互:**

* **`cgocallback(fn, frame, ctxt uintptr)`:** 从 C 代码回调到 Go 代码的入口点。
* **`asmcgocall(fn, arg unsafe.Pointer) int32`:**  从 Go 代码调用 C 代码。

**6. 其他辅助函数:**

* **`noescape(p unsafe.Pointer) unsafe.Pointer`:**  一个身份函数，但逃逸分析不会认为输出依赖于输入。这用于阻止指针逃逸到堆上。同样需要保持稳定。
* **`noEscapePtr[T any](p *T) *T`:** `noescape` 的泛型版本。
* **`procyield(cycles uint32)`:**  让出当前处理器的执行时间片。同样需要保持稳定。
* **`asminit()`:**  汇编代码的初始化函数。
* **`setg(gg *g)`:** 设置当前的 Goroutine。
* **`breakpoint()`:**  用于调试的断点指令。
* **`return0()`:**  用于从 `deferproc` 返回 0 的存根。
* **`systemstack_switch()`:**  切换到系统栈。
* **`alignUp(n, a uintptr) uintptr`:** 将 `n` 向上舍入到 `a` 的倍数，`a` 必须是 2 的幂。
* **`alignDown(n, a uintptr) uintptr`:** 将 `n` 向下舍入到 `a` 的倍数，`a` 必须是 2 的幂。
* **`divRoundUp(n, a uintptr) uintptr`:** 返回 `ceil(n / a)`。
* **`checkASM() bool`:** 报告汇编运行时检查是否通过。
* **`memequal_varlen(a, b unsafe.Pointer) bool`:** 比较两个变长内存块是否相等。
* **`bool2int(x bool) int`:** 将布尔值转换为整数（true 为 1，false 为 0）。
* **`abort()`:**  使运行时崩溃，用于 `throw` 可能不起作用的情况。
* **`gcWriteBarrier1` - `gcWriteBarrier8`:**  垃圾回收的写屏障函数。 其中 `gcWriteBarrier2` 同样需要保持稳定。
* **`duffzero()` 和 `duffcopy()`:**  使用 Duff's device 优化的大块内存清零和复制函数。
* **`addmoduledata()`:**  由链接器生成的 `.initarray` 调用，用于添加模块数据。
* **`sigpanic0()`:**  由信号处理程序注入，用于处理 panic 信号。

### 功能实现举例 (使用 `systemstack`):

`systemstack` 用于在系统线程的栈上执行代码，这在执行某些需要与操作系统进行底层交互的操作时非常有用，例如进行系统调用。

```go
package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

func main() {
	var errno syscall.Errno
	runtime.Systemstack(func() {
		// 在系统栈上执行的系统调用
		_, _, errno = syscall.Syscall(syscall.SYS_GETPID, 0, 0, 0)
	})

	if errno != 0 {
		fmt.Println("系统调用失败:", errno)
	} else {
		fmt.Println("成功执行系统调用")
	}
}
```

**假设输入与输出:**

这个例子中没有直接的输入，它执行一个不需要额外输入的系统调用 `syscall.SYS_GETPID`。

**输出:**

如果系统调用成功，输出将会是:

```
成功执行系统调用
```

如果系统调用失败，输出将会包含错误信息，例如：

```
系统调用失败: [errno value]
```

### 功能实现举例 (使用 `memclrNoHeapPointers`):

虽然 `memclrNoHeapPointers` 通常不直接在用户代码中使用，但可以展示其基本功能。

```go
package main

import (
	"fmt"
	"runtime"
	"unsafe"
)

func main() {
	data := [10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ptr := unsafe.Pointer(&data[0])
	size := unsafe.Sizeof(data[0]) * uintptr(len(data))

	fmt.Println("清零前:", data)

	runtime.MemclrNoHeapPointers(ptr, size)

	fmt.Println("清零后:", data)
}
```

**假设输入与输出:**

**输入:** 数组 `data` 初始化为 `[1 2 3 4 5 6 7 8 9 10]`

**输出:**

```
清零前: [1 2 3 4 5 6 7 8 9 10]
清零后: [0 0 0 0 0 0 0 0 0 0]
```

### 易犯错的点 (对于 `//go:linkname` 引用的函数):

使用者最容易犯的错误是**直接调用或依赖这些通过 `//go:linkname` 暴露的运行时内部函数**。

**错误示例:**

```go
package main

import (
	_ "unsafe" // Required for go:linkname

	"fmt"
)

//go:linkname myAdd runtime.add
func myAdd(p unsafe.Pointer, x uintptr) unsafe.Pointer

func main() {
	var i int = 10
	ptr := unsafe.Pointer(&i)
	newPtr := myAdd(ptr, 8) // 假设 int 是 8 字节
	fmt.Println("原始指针:", ptr)
	fmt.Println("偏移后指针:", newPtr)
}
```

**问题:**

* **违反了 Go 的 API 稳定性原则:** 这些函数是运行时的内部实现细节，Go 官方不保证它们的签名、行为甚至存在性在未来的 Go 版本中保持不变。
* **潜在的兼容性问题:** 依赖这些函数可能导致代码在新版本的 Go 中无法编译或运行。
* **增加了代码的维护难度:**  如果这些内部函数的行为发生变化，依赖它们的代码可能需要进行大规模的修改。

**正确的做法是使用 Go 语言提供的公共 API 和标准库来实现所需的功能。**  `//go:linkname` 主要是为了某些特殊场景（例如需要极高性能的底层库）而存在的，普通开发者不应该依赖它。

总结来说，`stubs.go` 文件中的这些函数是 Go 运行时环境的基石，它们提供了底层的内存操作、Goroutine 管理、函数调用等核心功能。虽然其中一些函数通过 `//go:linkname` 被外部包引用，但这并不意味着开发者应该直接使用它们。直接使用这些内部函数会带来稳定性和兼容性的风险。

### 提示词
```
这是路径为go/src/runtime/stubs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"unsafe"
)

// Should be a built-in for unsafe.Pointer?
//
// add should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - fortio.org/log
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname add
//go:nosplit
func add(p unsafe.Pointer, x uintptr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + x)
}

// getg returns the pointer to the current g.
// The compiler rewrites calls to this function into instructions
// that fetch the g directly (from TLS or from the dedicated register).
func getg() *g

// mcall switches from the g to the g0 stack and invokes fn(g),
// where g is the goroutine that made the call.
// mcall saves g's current PC/SP in g->sched so that it can be restored later.
// It is up to fn to arrange for that later execution, typically by recording
// g in a data structure, causing something to call ready(g) later.
// mcall returns to the original goroutine g later, when g has been rescheduled.
// fn must not return at all; typically it ends by calling schedule, to let the m
// run other goroutines.
//
// mcall can only be called from g stacks (not g0, not gsignal).
//
// This must NOT be go:noescape: if fn is a stack-allocated closure,
// fn puts g on a run queue, and g executes before fn returns, the
// closure will be invalidated while it is still executing.
func mcall(fn func(*g))

// systemstack runs fn on a system stack.
// If systemstack is called from the per-OS-thread (g0) stack, or
// if systemstack is called from the signal handling (gsignal) stack,
// systemstack calls fn directly and returns.
// Otherwise, systemstack is being called from the limited stack
// of an ordinary goroutine. In this case, systemstack switches
// to the per-OS-thread stack, calls fn, and switches back.
// It is common to use a func literal as the argument, in order
// to share inputs and outputs with the code around the call
// to system stack:
//
//	... set up y ...
//	systemstack(func() {
//		x = bigcall(y)
//	})
//	... use x ...
//
//go:noescape
func systemstack(fn func())

//go:nosplit
//go:nowritebarrierrec
func badsystemstack() {
	writeErrStr("fatal: systemstack called from unexpected goroutine")
}

// memclrNoHeapPointers clears n bytes starting at ptr.
//
// Usually you should use typedmemclr. memclrNoHeapPointers should be
// used only when the caller knows that *ptr contains no heap pointers
// because either:
//
// *ptr is initialized memory and its type is pointer-free, or
//
// *ptr is uninitialized memory (e.g., memory that's being reused
// for a new allocation) and hence contains only "junk".
//
// memclrNoHeapPointers ensures that if ptr is pointer-aligned, and n
// is a multiple of the pointer size, then any pointer-aligned,
// pointer-sized portion is cleared atomically. Despite the function
// name, this is necessary because this function is the underlying
// implementation of typedmemclr and memclrHasPointers. See the doc of
// memmove for more details.
//
// The (CPU-specific) implementations of this function are in memclr_*.s.
//
// memclrNoHeapPointers should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/chenzhuoyu/iasm
//   - github.com/dgraph-io/ristretto
//   - github.com/outcaste-io/ristretto
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname memclrNoHeapPointers
//go:noescape
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

//go:linkname reflect_memclrNoHeapPointers reflect.memclrNoHeapPointers
func reflect_memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr) {
	memclrNoHeapPointers(ptr, n)
}

// memmove copies n bytes from "from" to "to".
//
// memmove ensures that any pointer in "from" is written to "to" with
// an indivisible write, so that racy reads cannot observe a
// half-written pointer. This is necessary to prevent the garbage
// collector from observing invalid pointers, and differs from memmove
// in unmanaged languages. However, memmove is only required to do
// this if "from" and "to" may contain pointers, which can only be the
// case if "from", "to", and "n" are all be word-aligned.
//
// Implementations are in memmove_*.s.
//
// Outside assembly calls memmove.
//
// memmove should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//   - github.com/cloudwego/dynamicgo
//   - github.com/ebitengine/purego
//   - github.com/tetratelabs/wazero
//   - github.com/ugorji/go/codec
//   - gvisor.dev/gvisor
//   - github.com/sagernet/gvisor
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname memmove
//go:noescape
func memmove(to, from unsafe.Pointer, n uintptr)

//go:linkname reflect_memmove reflect.memmove
func reflect_memmove(to, from unsafe.Pointer, n uintptr) {
	memmove(to, from, n)
}

// exported value for testing
const hashLoad = float32(loadFactorNum) / float32(loadFactorDen)

// in internal/bytealg/equal_*.s
//
// memequal should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname memequal
//go:noescape
func memequal(a, b unsafe.Pointer, size uintptr) bool

// noescape hides a pointer from escape analysis.  noescape is
// the identity function but escape analysis doesn't think the
// output depends on the input.  noescape is inlined and currently
// compiles down to zero instructions.
// USE CAREFULLY!
//
// noescape should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/gopkg
//   - github.com/ebitengine/purego
//   - github.com/hamba/avro/v2
//   - github.com/puzpuzpuz/xsync/v3
//   - github.com/songzhibin97/gkit
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname noescape
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

// noEscapePtr hides a pointer from escape analysis. See noescape.
// USE CAREFULLY!
//
//go:nosplit
func noEscapePtr[T any](p *T) *T {
	x := uintptr(unsafe.Pointer(p))
	return (*T)(unsafe.Pointer(x ^ 0))
}

// Not all cgocallback frames are actually cgocallback,
// so not all have these arguments. Mark them uintptr so that the GC
// does not misinterpret memory when the arguments are not present.
// cgocallback is not called from Go, only from crosscall2.
// This in turn calls cgocallbackg, which is where we'll find
// pointer-declared arguments.
//
// When fn is nil (frame is saved g), call dropm instead,
// this is used when the C thread is exiting.
func cgocallback(fn, frame, ctxt uintptr)

func gogo(buf *gobuf)

func asminit()
func setg(gg *g)
func breakpoint()

// reflectcall calls fn with arguments described by stackArgs, stackArgsSize,
// frameSize, and regArgs.
//
// Arguments passed on the stack and space for return values passed on the stack
// must be laid out at the space pointed to by stackArgs (with total length
// stackArgsSize) according to the ABI.
//
// stackRetOffset must be some value <= stackArgsSize that indicates the
// offset within stackArgs where the return value space begins.
//
// frameSize is the total size of the argument frame at stackArgs and must
// therefore be >= stackArgsSize. It must include additional space for spilling
// register arguments for stack growth and preemption.
//
// TODO(mknyszek): Once we don't need the additional spill space, remove frameSize,
// since frameSize will be redundant with stackArgsSize.
//
// Arguments passed in registers must be laid out in regArgs according to the ABI.
// regArgs will hold any return values passed in registers after the call.
//
// reflectcall copies stack arguments from stackArgs to the goroutine stack, and
// then copies back stackArgsSize-stackRetOffset bytes back to the return space
// in stackArgs once fn has completed. It also "unspills" argument registers from
// regArgs before calling fn, and spills them back into regArgs immediately
// following the call to fn. If there are results being returned on the stack,
// the caller should pass the argument frame type as stackArgsType so that
// reflectcall can execute appropriate write barriers during the copy.
//
// reflectcall expects regArgs.ReturnIsPtr to be populated indicating which
// registers on the return path will contain Go pointers. It will then store
// these pointers in regArgs.Ptrs such that they are visible to the GC.
//
// Package reflect passes a frame type. In package runtime, there is only
// one call that copies results back, in callbackWrap in syscall_windows.go, and it
// does NOT pass a frame type, meaning there are no write barriers invoked. See that
// call site for justification.
//
// Package reflect accesses this symbol through a linkname.
//
// Arguments passed through to reflectcall do not escape. The type is used
// only in a very limited callee of reflectcall, the stackArgs are copied, and
// regArgs is only used in the reflectcall frame.
//
//go:noescape
func reflectcall(stackArgsType *_type, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)

// procyield should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/sagernet/sing-tun
//   - github.com/slackhq/nebula
//   - golang.zx2c4.com/wireguard
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname procyield
func procyield(cycles uint32)

type neverCallThisFunction struct{}

// goexit is the return stub at the top of every goroutine call stack.
// Each goroutine stack is constructed as if goexit called the
// goroutine's entry point function, so that when the entry point
// function returns, it will return to goexit, which will call goexit1
// to perform the actual exit.
//
// This function must never be called directly. Call goexit1 instead.
// gentraceback assumes that goexit terminates the stack. A direct
// call on the stack will cause gentraceback to stop walking the stack
// prematurely and if there is leftover state it may panic.
func goexit(neverCallThisFunction)

// publicationBarrier performs a store/store barrier (a "publication"
// or "export" barrier). Some form of synchronization is required
// between initializing an object and making that object accessible to
// another processor. Without synchronization, the initialization
// writes and the "publication" write may be reordered, allowing the
// other processor to follow the pointer and observe an uninitialized
// object. In general, higher-level synchronization should be used,
// such as locking or an atomic pointer write. publicationBarrier is
// for when those aren't an option, such as in the implementation of
// the memory manager.
//
// There's no corresponding barrier for the read side because the read
// side naturally has a data dependency order. All architectures that
// Go supports or seems likely to ever support automatically enforce
// data dependency ordering.
func publicationBarrier()

//go:noescape
func asmcgocall(fn, arg unsafe.Pointer) int32

func morestack()

func morestack_noctxt()

func rt0_go()

// return0 is a stub used to return 0 from deferproc.
// It is called at the very end of deferproc to signal
// the calling Go function that it should not jump
// to deferreturn.
// in asm_*.s
func return0()

// in asm_*.s
// not called directly; definitions here supply type information for traceback.
// These must have the same signature (arg pointer map) as reflectcall.
func call16(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call32(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call64(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call128(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call256(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call512(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call1024(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call2048(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call4096(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call8192(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call16384(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call32768(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call65536(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call131072(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call262144(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call524288(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call1048576(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call2097152(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call4194304(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call8388608(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call16777216(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call33554432(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call67108864(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call134217728(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call268435456(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call536870912(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)
func call1073741824(typ, fn, stackArgs unsafe.Pointer, stackArgsSize, stackRetOffset, frameSize uint32, regArgs *abi.RegArgs)

func systemstack_switch()

// alignUp rounds n up to a multiple of a. a must be a power of 2.
//
//go:nosplit
func alignUp(n, a uintptr) uintptr {
	return (n + a - 1) &^ (a - 1)
}

// alignDown rounds n down to a multiple of a. a must be a power of 2.
//
//go:nosplit
func alignDown(n, a uintptr) uintptr {
	return n &^ (a - 1)
}

// divRoundUp returns ceil(n / a).
//
//go:nosplit
func divRoundUp(n, a uintptr) uintptr {
	// a is generally a power of two. This will get inlined and
	// the compiler will optimize the division.
	return (n + a - 1) / a
}

// checkASM reports whether assembly runtime checks have passed.
func checkASM() bool

func memequal_varlen(a, b unsafe.Pointer) bool

// bool2int returns 0 if x is false or 1 if x is true.
func bool2int(x bool) int {
	// Avoid branches. In the SSA compiler, this compiles to
	// exactly what you would want it to.
	return int(*(*uint8)(unsafe.Pointer(&x)))
}

// abort crashes the runtime in situations where even throw might not
// work. In general it should do something a debugger will recognize
// (e.g., an INT3 on x86). A crash in abort is recognized by the
// signal handler, which will attempt to tear down the runtime
// immediately.
func abort()

// Called from compiled code; declared for vet; do NOT call from Go.
func gcWriteBarrier1()

// gcWriteBarrier2 should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname gcWriteBarrier2
func gcWriteBarrier2()

func gcWriteBarrier3()
func gcWriteBarrier4()
func gcWriteBarrier5()
func gcWriteBarrier6()
func gcWriteBarrier7()
func gcWriteBarrier8()
func duffzero()
func duffcopy()

// Called from linker-generated .initarray; declared for go vet; do NOT call from Go.
func addmoduledata()

// Injected by the signal handler for panicking signals.
// Initializes any registers that have fixed meaning at calls but
// are scratch in bodies and calls sigpanic.
// On many platforms it just jumps to sigpanic.
func sigpanic0()

// intArgRegs is used by the various register assignment
// algorithm implementations in the runtime. These include:.
// - Finalizers (mfinal.go)
// - Windows callbacks (syscall_windows.go)
//
// Both are stripped-down versions of the algorithm since they
// only have to deal with a subset of cases (finalizers only
// take a pointer or interface argument, Go Windows callbacks
// don't support floating point).
//
// It should be modified with care and are generally only
// modified when testing this package.
//
// It should never be set higher than its internal/abi
// constant counterparts, because the system relies on a
// structure that is at least large enough to hold the
// registers the system supports.
//
// Protected by finlock.
var intArgRegs = abi.IntArgRegs
```