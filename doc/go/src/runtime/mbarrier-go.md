Response:
Let's break down the thought process for analyzing the `mbarrier.go` code.

**1. Understanding the Request:**

The request asks for the *functionality* of the given Go code snippet, specifically within the context of garbage collection. It also probes for deeper understanding, asking to infer the larger Go feature it supports, provide code examples, discuss command-line arguments (if applicable), and highlight common mistakes.

**2. Initial Scan and Keywords:**

The first step is to quickly scan the code for important keywords and concepts. I see:

* `"runtime"` package -  Signals core Go functionality.
* `"mbarrier.go"` in the path - Implies memory barriers.
* `"Garbage collector"`, `"write barriers"` - Key terms indicating the code's purpose.
* `gcWriteBarrier` -  Mentioned as the main assembly-level barrier.
* `typedmemmove`, `wbZero`, `wbMove`, `typedslicecopy`, `typedmemclr`, `memclrHasPointers` - These function names suggest bulk operations related to memory manipulation, especially moving, zeroing, and copying, likely involving types.
* `"shade"`, `"grey"`, `"black"` -  Garbage collection coloring terminology.
* `"Yuasa-style deletion barrier"`, `"Dijkstra insertion barrier"` - Specific GC barrier techniques.
* `"pre-publication"` -  Indicates when the barrier takes place relative to the pointer write.
* `bulkBarrierPreWrite` - A common function called before the memory operations.
* `writeBarrier.enabled` - A condition to check if write barriers are active.
* `memmove`, `memclrNoHeapPointers` - Underlying memory manipulation functions.
* `reflect`, `reflectlite`, `maps` in function names (with `linkname`) -  Indicates these functions are used by reflection and map implementations.
* `raceenabled`, `msanenabled`, `asanenabled`, `goexperiment.CgoCheck2` - Indicate conditional execution for race detection, memory sanitizer, address sanitizer, and CGO checks.
* `unsafe.Pointer` -  Direct memory manipulation, often related to lower-level operations.
* Comments explaining the write barrier logic and its interaction with mutators and the GC.

**3. Core Functionality Identification:**

Based on the keywords and the file name, the primary function is clearly implementing *write barriers* for the Go garbage collector. The comments explicitly state this. The code defines functions that are called *before* performing memory operations involving pointers.

**4. Inferring the Larger Go Feature:**

The purpose of write barriers is to ensure the garbage collector can correctly track live objects in a concurrent environment where the program (mutator) is modifying memory while the garbage collector is running. This allows for *concurrent garbage collection*, reducing pause times.

**5. Code Example - `typedmemmove`:**

The `typedmemmove` function is a good candidate for a code example because it demonstrates the core write barrier logic. I would construct an example that shows a pointer being moved from one location to another, triggering the write barrier.

* **Input:** Two pointers of the same type, one pointing to a live object, the other to an uninitialized location.
* **Process:** Call `typedmemmove` to copy the object.
* **Expected Output:** The destination pointer now points to the copied object, and the write barrier has been executed, potentially marking the original and/or the new object for the GC. *Crucially, the example doesn't directly *show* the marking, as that's internal to the GC. The output demonstrates the basic memory movement.*

**6. Code Example - `typedslicecopy`:**

Similar to `typedmemmove`, `typedslicecopy` showcases the write barrier for slice copying. The example should involve two slices with pointer elements.

* **Input:** Two slices of the same type, containing pointers.
* **Process:** Call `typedslicecopy` to copy elements from the source slice to the destination slice.
* **Expected Output:** The destination slice contains copies of the elements from the source slice, and the write barrier has been executed for each pointer copied.

**7. Reasoning about `bulkBarrierPreWrite`:**

The repeated calls to `bulkBarrierPreWrite` suggest it's the core function implementing the write barrier logic for bulk operations. The parameters (`dst`, `src`, `size`, `typ`) indicate it takes information about the destination, source, size of the memory region, and the type involved. The comments explain the optimization of passing `typ` when the operation involves a full value of that type.

**8. Command-Line Arguments:**

The code doesn't directly process command-line arguments. However, the presence of `goexperiment.CgoCheck2`, `raceenabled`, `msanenabled`, and `asanenabled` hints that these features (and their associated command-line flags like `-race`, `-msan`, `-asan`, and experiment settings) *influence* whether the write barriers are active or if additional checks are performed. I need to explain this indirect connection.

**9. Common Mistakes:**

The comments mention that the compiler sometimes needs to emit write barriers even for stack writes if the pointer has been passed down the call stack. This is a subtle point where a developer might incorrectly assume stack writes are always barrier-free. Another mistake could be manually manipulating memory with pointers without understanding the implications for the GC and potentially bypassing the write barrier if using `unsafe` operations incorrectly.

**10. Structuring the Answer:**

Finally, organize the information logically, starting with a concise summary of the functionality, then delving into details like the larger feature, code examples, command-line arguments, and potential pitfalls. Use clear and concise language, explaining technical terms where necessary. The request specified Chinese, so the entire response needs to be in Chinese.

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on the low-level details of the Yuasa and Dijkstra barriers.
* **Correction:** While important, the request asks for functionality and broader understanding. Emphasize the *purpose* of the barriers in the context of concurrent GC.
* **Initial thought:** Provide very detailed code examples showing the state of memory before and after.
* **Correction:**  The internal state of the GC isn't directly observable. Focus on the effect of the memory operations and acknowledge the write barrier's internal role.
* **Initial thought:** List every possible command-line flag related to GC.
* **Correction:** Focus on the flags directly related to the conditional logic within the provided code (race, msan, asan, experiments).

By following this structured thought process, breaking down the code into smaller parts, and focusing on the user's request, I can arrive at a comprehensive and accurate answer.
这段代码是 Go 语言运行时（runtime）包中关于**垃圾回收器（Garbage Collector, GC）的写屏障（Write Barrier）**的实现。

**功能列表:**

1. **实现并发垃圾回收的写屏障机制:**  这是代码的核心功能。它实现了 Yuasa 删除屏障和 Dijkstra 插入屏障的组合，用于在并发垃圾回收期间，保证垃圾回收器能够正确追踪对象引用，避免遗漏存活对象，也避免回收正在使用的对象。
2. **`typedmemmove` 函数:**  用于将指定类型的数据从 `src` 复制到 `dst`。在复制前，如果写屏障启用且类型包含指针，则会调用 `bulkBarrierPreWrite` 执行写屏障操作。这个函数被广泛用于各种内存移动的场景，包括反射。
3. **`wbZero` 函数:**  用于在将一块内存区域置零之前执行必要的写屏障操作。它不实际执行置零操作。
4. **`wbMove` 函数:**  用于在将一块内存区域从 `src` 复制到 `dst` 之前执行必要的写屏障操作。它不实际执行复制操作。
5. **`reflect_typedmemmove` 函数:**  `typedmemmove` 的反射版本，用于反射操作中的内存移动，同样包含写屏障逻辑，并且加入了对 race detection (竞争检测), msan (内存检查器) 和 asan (地址检查器) 的支持。
6. **`reflectlite_typedmemmove` 函数:**  `reflect_typedmemmove` 的一个轻量级版本。
7. **`maps_typedmemmove` 函数:**  用于 map 数据结构内部的内存移动。
8. **`reflectcallmove` 函数:**  用于在反射调用后，将返回值从栈拷贝到堆上时执行必要的写屏障。
9. **`typedslicecopy` 函数:**  用于复制 slice 的底层数据。在复制前，如果写屏障启用且元素类型包含指针，则会调用 `bulkBarrierPreWrite`。
10. **`reflect_typedslicecopy` 函数:**  `typedslicecopy` 的反射版本。
11. **`typedmemclr` 函数:**  用于将指定类型的内存区域清零。在清零前，如果写屏障启用且类型包含指针，则会调用 `bulkBarrierPreWrite`。
12. **`reflect_typedmemclr` 函数:**  `typedmemclr` 的反射版本。
13. **`maps_typedmemclr` 函数:**  用于 map 数据结构内部的内存清零。
14. **`reflect_typedmemclrpartial` 函数:**  用于清除类型内存的指定部分。
15. **`reflect_typedarrayclear` 函数:** 用于清除类型数组的内存。
16. **`memclrHasPointers` 函数:**  用于清除包含指针的内存区域。

**推理 Go 语言功能：并发垃圾回收**

这段代码的核心功能是实现垃圾回收器的写屏障，这直接服务于 Go 语言的**并发垃圾回收**机制。并发垃圾回收允许垃圾回收器在程序运行的同时进行垃圾回收，从而减少程序暂停的时间。

**Go 代码示例:**

```go
package main

import "fmt"

type MyStruct struct {
	Data *int
}

func main() {
	// 假设 GC 正在运行

	obj1 := &MyStruct{Data: new(int)}
	*obj1.Data = 10

	obj2 := &MyStruct{}

	// 执行一个可能触发写屏障的操作：将 obj1 的指针赋值给 obj2.Data
	obj2.Data = obj1.Data

	fmt.Println(*obj2.Data) // 输出: 10
}
```

**假设的输入与输出:**

在这个例子中，当执行 `obj2.Data = obj1.Data` 时，由于 `MyStruct` 包含指针，并且写屏障是启用的，runtime 会调用相应的写屏障函数（例如，内部会调用 `gcWriteBarrier` 或 `bulkBarrierPreWrite`）。

* **输入 (假设):**
    * `obj2.Data` 的内存地址
    * `obj1.Data` 的内存地址 (指向值为 10 的 int)
    * 当前 Goroutine 的状态 (例如，栈是否为灰色)

* **输出 (内部 GC 状态变化):**
    * 根据写屏障的逻辑，`obj1.Data` 指向的内存块会被标记为存活（灰色或黑色），即使在并发 GC 的标记阶段，垃圾回收器也能正确识别它为存活对象。
    * 如果当前 Goroutine 的栈是灰色的（意味着正在扫描），`obj1.Data` 指向的对象也会被标记。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。但是，Go 语言的垃圾回收行为可以通过一些环境变量或 runtime 包提供的函数进行配置，例如：

* **`GOGC` 环境变量:**  设置垃圾回收的目标百分比。
* **`GODEBUG` 环境变量:**  可以控制垃圾回收的详细输出信息，例如 `godebug=gctrace=1` 可以打印 GC 的跟踪信息。
* **`runtime.GC()` 函数:**  可以手动触发一次垃圾回收。

这些参数和函数会影响垃圾回收器的整体行为，从而间接地影响写屏障的执行时机和效果。例如，如果 `GOGC` 设置得非常低，垃圾回收更频繁，写屏障被调用的次数也可能更多。

**使用者易犯错的点:**

虽然这段代码是 runtime 内部的实现，普通 Go 开发者不会直接调用这些函数，但理解写屏障的概念对于避免一些与并发相关的内存问题至关重要。一个常见的误解是：

* **错误地认为对栈上的指针赋值不需要考虑并发问题。**  正如代码注释中提到的，如果栈指针被传递到更深的调用栈，编译器仍然会生成写屏障。

**示例说明易犯错的点:**

```go
package main

import "fmt"
import "time"

type Node struct {
	Value int
	Next  *Node
}

func modifyList(head **Node) {
	newNode := &Node{Value: 10}
	newNode.Next = *head
	*head = newNode // 这里可能会触发写屏障，即使 head 指向栈上的变量
}

func main() {
	head := &Node{Value: 5}

	go func() {
		for {
			modifyList(&head)
			time.Sleep(time.Millisecond)
		}
	}()

	for i := 0; i < 10; i++ {
		fmt.Println(head.Value)
		time.Sleep(time.Second)
	}
}
```

在这个例子中，`head` 变量在 `main` 函数的栈上，但在 `modifyList` 函数中，通过指针的指针 `**Node` 进行修改。尽管 `head` 本身在栈上，但对其指向的堆内存的修改仍然需要写屏障来保证并发 GC 的正确性。 初学者可能会认为直接修改栈上的变量不需要考虑 GC 的影响，但当涉及到指针以及指针指向的堆内存时，写屏障仍然起作用。

总而言之，`mbarrier.go` 文件是 Go 语言运行时中实现并发垃圾回收关键机制——写屏障的核心部分。它定义了在修改堆上对象指针时必须执行的操作，以确保垃圾回收器能够在并发执行的情况下正确地管理内存。

### 提示词
```
这是路径为go/src/runtime/mbarrier.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Garbage collector: write barriers.
//
// For the concurrent garbage collector, the Go compiler implements
// updates to pointer-valued fields that may be in heap objects by
// emitting calls to write barriers. The main write barrier for
// individual pointer writes is gcWriteBarrier and is implemented in
// assembly. This file contains write barrier entry points for bulk
// operations. See also mwbbuf.go.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/goexperiment"
	"internal/runtime/sys"
	"unsafe"
)

// Go uses a hybrid barrier that combines a Yuasa-style deletion
// barrier—which shades the object whose reference is being
// overwritten—with Dijkstra insertion barrier—which shades the object
// whose reference is being written. The insertion part of the barrier
// is necessary while the calling goroutine's stack is grey. In
// pseudocode, the barrier is:
//
//     writePointer(slot, ptr):
//         shade(*slot)
//         if current stack is grey:
//             shade(ptr)
//         *slot = ptr
//
// slot is the destination in Go code.
// ptr is the value that goes into the slot in Go code.
//
// Shade indicates that it has seen a white pointer by adding the referent
// to wbuf as well as marking it.
//
// The two shades and the condition work together to prevent a mutator
// from hiding an object from the garbage collector:
//
// 1. shade(*slot) prevents a mutator from hiding an object by moving
// the sole pointer to it from the heap to its stack. If it attempts
// to unlink an object from the heap, this will shade it.
//
// 2. shade(ptr) prevents a mutator from hiding an object by moving
// the sole pointer to it from its stack into a black object in the
// heap. If it attempts to install the pointer into a black object,
// this will shade it.
//
// 3. Once a goroutine's stack is black, the shade(ptr) becomes
// unnecessary. shade(ptr) prevents hiding an object by moving it from
// the stack to the heap, but this requires first having a pointer
// hidden on the stack. Immediately after a stack is scanned, it only
// points to shaded objects, so it's not hiding anything, and the
// shade(*slot) prevents it from hiding any other pointers on its
// stack.
//
// For a detailed description of this barrier and proof of
// correctness, see https://github.com/golang/proposal/blob/master/design/17503-eliminate-rescan.md
//
//
//
// Dealing with memory ordering:
//
// Both the Yuasa and Dijkstra barriers can be made conditional on the
// color of the object containing the slot. We chose not to make these
// conditional because the cost of ensuring that the object holding
// the slot doesn't concurrently change color without the mutator
// noticing seems prohibitive.
//
// Consider the following example where the mutator writes into
// a slot and then loads the slot's mark bit while the GC thread
// writes to the slot's mark bit and then as part of scanning reads
// the slot.
//
// Initially both [slot] and [slotmark] are 0 (nil)
// Mutator thread          GC thread
// st [slot], ptr          st [slotmark], 1
//
// ld r1, [slotmark]       ld r2, [slot]
//
// Without an expensive memory barrier between the st and the ld, the final
// result on most HW (including 386/amd64) can be r1==r2==0. This is a classic
// example of what can happen when loads are allowed to be reordered with older
// stores (avoiding such reorderings lies at the heart of the classic
// Peterson/Dekker algorithms for mutual exclusion). Rather than require memory
// barriers, which will slow down both the mutator and the GC, we always grey
// the ptr object regardless of the slot's color.
//
//
// Stack writes:
//
// The compiler omits write barriers for writes to the current frame,
// but if a stack pointer has been passed down the call stack, the
// compiler will generate a write barrier for writes through that
// pointer (because it doesn't know it's not a heap pointer).
//
//
// Global writes:
//
// The Go garbage collector requires write barriers when heap pointers
// are stored in globals. Many garbage collectors ignore writes to
// globals and instead pick up global -> heap pointers during
// termination. This increases pause time, so we instead rely on write
// barriers for writes to globals so that we don't have to rescan
// global during mark termination.
//
//
// Publication ordering:
//
// The write barrier is *pre-publication*, meaning that the write
// barrier happens prior to the *slot = ptr write that may make ptr
// reachable by some goroutine that currently cannot reach it.
//
//
// Signal handler pointer writes:
//
// In general, the signal handler cannot safely invoke the write
// barrier because it may run without a P or even during the write
// barrier.
//
// There is exactly one exception: profbuf.go omits a barrier during
// signal handler profile logging. That's safe only because of the
// deletion barrier. See profbuf.go for a detailed argument. If we
// remove the deletion barrier, we'll have to work out a new way to
// handle the profile logging.

// typedmemmove copies a value of type typ to dst from src.
// Must be nosplit, see #16026.
//
// TODO: Perfect for go:nosplitrec since we can't have a safe point
// anywhere in the bulk barrier or memmove.
//
// typedmemmove should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname typedmemmove
//go:nosplit
func typedmemmove(typ *abi.Type, dst, src unsafe.Pointer) {
	if dst == src {
		return
	}
	if writeBarrier.enabled && typ.Pointers() {
		// This always copies a full value of type typ so it's safe
		// to pass typ along as an optimization. See the comment on
		// bulkBarrierPreWrite.
		bulkBarrierPreWrite(uintptr(dst), uintptr(src), typ.PtrBytes, typ)
	}
	// There's a race here: if some other goroutine can write to
	// src, it may change some pointer in src after we've
	// performed the write barrier but before we perform the
	// memory copy. This safe because the write performed by that
	// other goroutine must also be accompanied by a write
	// barrier, so at worst we've unnecessarily greyed the old
	// pointer that was in src.
	memmove(dst, src, typ.Size_)
	if goexperiment.CgoCheck2 {
		cgoCheckMemmove2(typ, dst, src, 0, typ.Size_)
	}
}

// wbZero performs the write barrier operations necessary before
// zeroing a region of memory at address dst of type typ.
// Does not actually do the zeroing.
//
//go:nowritebarrierrec
//go:nosplit
func wbZero(typ *_type, dst unsafe.Pointer) {
	// This always copies a full value of type typ so it's safe
	// to pass typ along as an optimization. See the comment on
	// bulkBarrierPreWrite.
	bulkBarrierPreWrite(uintptr(dst), 0, typ.PtrBytes, typ)
}

// wbMove performs the write barrier operations necessary before
// copying a region of memory from src to dst of type typ.
// Does not actually do the copying.
//
//go:nowritebarrierrec
//go:nosplit
func wbMove(typ *_type, dst, src unsafe.Pointer) {
	// This always copies a full value of type typ so it's safe to
	// pass a type here.
	//
	// See the comment on bulkBarrierPreWrite.
	bulkBarrierPreWrite(uintptr(dst), uintptr(src), typ.PtrBytes, typ)
}

// reflect_typedmemmove is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/goccy/json
//   - github.com/modern-go/reflect2
//   - github.com/ugorji/go/codec
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_typedmemmove reflect.typedmemmove
func reflect_typedmemmove(typ *_type, dst, src unsafe.Pointer) {
	if raceenabled {
		raceWriteObjectPC(typ, dst, sys.GetCallerPC(), abi.FuncPCABIInternal(reflect_typedmemmove))
		raceReadObjectPC(typ, src, sys.GetCallerPC(), abi.FuncPCABIInternal(reflect_typedmemmove))
	}
	if msanenabled {
		msanwrite(dst, typ.Size_)
		msanread(src, typ.Size_)
	}
	if asanenabled {
		asanwrite(dst, typ.Size_)
		asanread(src, typ.Size_)
	}
	typedmemmove(typ, dst, src)
}

//go:linkname reflectlite_typedmemmove internal/reflectlite.typedmemmove
func reflectlite_typedmemmove(typ *_type, dst, src unsafe.Pointer) {
	reflect_typedmemmove(typ, dst, src)
}

//go:linkname maps_typedmemmove internal/runtime/maps.typedmemmove
func maps_typedmemmove(typ *_type, dst, src unsafe.Pointer) {
	typedmemmove(typ, dst, src)
}

// reflectcallmove is invoked by reflectcall to copy the return values
// out of the stack and into the heap, invoking the necessary write
// barriers. dst, src, and size describe the return value area to
// copy. typ describes the entire frame (not just the return values).
// typ may be nil, which indicates write barriers are not needed.
//
// It must be nosplit and must only call nosplit functions because the
// stack map of reflectcall is wrong.
//
//go:nosplit
func reflectcallmove(typ *_type, dst, src unsafe.Pointer, size uintptr, regs *abi.RegArgs) {
	if writeBarrier.enabled && typ != nil && typ.Pointers() && size >= goarch.PtrSize {
		// Pass nil for the type. dst does not point to value of type typ,
		// but rather points into one, so applying the optimization is not
		// safe. See the comment on this function.
		bulkBarrierPreWrite(uintptr(dst), uintptr(src), size, nil)
	}
	memmove(dst, src, size)

	// Move pointers returned in registers to a place where the GC can see them.
	for i := range regs.Ints {
		if regs.ReturnIsPtr.Get(i) {
			regs.Ptrs[i] = unsafe.Pointer(regs.Ints[i])
		}
	}
}

// typedslicecopy should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/segmentio/encoding
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname typedslicecopy
//go:nosplit
func typedslicecopy(typ *_type, dstPtr unsafe.Pointer, dstLen int, srcPtr unsafe.Pointer, srcLen int) int {
	n := dstLen
	if n > srcLen {
		n = srcLen
	}
	if n == 0 {
		return 0
	}

	// The compiler emits calls to typedslicecopy before
	// instrumentation runs, so unlike the other copying and
	// assignment operations, it's not instrumented in the calling
	// code and needs its own instrumentation.
	if raceenabled {
		callerpc := sys.GetCallerPC()
		pc := abi.FuncPCABIInternal(slicecopy)
		racewriterangepc(dstPtr, uintptr(n)*typ.Size_, callerpc, pc)
		racereadrangepc(srcPtr, uintptr(n)*typ.Size_, callerpc, pc)
	}
	if msanenabled {
		msanwrite(dstPtr, uintptr(n)*typ.Size_)
		msanread(srcPtr, uintptr(n)*typ.Size_)
	}
	if asanenabled {
		asanwrite(dstPtr, uintptr(n)*typ.Size_)
		asanread(srcPtr, uintptr(n)*typ.Size_)
	}

	if goexperiment.CgoCheck2 {
		cgoCheckSliceCopy(typ, dstPtr, srcPtr, n)
	}

	if dstPtr == srcPtr {
		return n
	}

	// Note: No point in checking typ.PtrBytes here:
	// compiler only emits calls to typedslicecopy for types with pointers,
	// and growslice and reflect_typedslicecopy check for pointers
	// before calling typedslicecopy.
	size := uintptr(n) * typ.Size_
	if writeBarrier.enabled {
		// This always copies one or more full values of type typ so
		// it's safe to pass typ along as an optimization. See the comment on
		// bulkBarrierPreWrite.
		pwsize := size - typ.Size_ + typ.PtrBytes
		bulkBarrierPreWrite(uintptr(dstPtr), uintptr(srcPtr), pwsize, typ)
	}
	// See typedmemmove for a discussion of the race between the
	// barrier and memmove.
	memmove(dstPtr, srcPtr, size)
	return n
}

// reflect_typedslicecopy is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - gitee.com/quant1x/gox
//   - github.com/modern-go/reflect2
//   - github.com/RomiChan/protobuf
//   - github.com/segmentio/encoding
//   - github.com/v2pro/plz
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_typedslicecopy reflect.typedslicecopy
func reflect_typedslicecopy(elemType *_type, dst, src slice) int {
	if !elemType.Pointers() {
		return slicecopy(dst.array, dst.len, src.array, src.len, elemType.Size_)
	}
	return typedslicecopy(elemType, dst.array, dst.len, src.array, src.len)
}

// typedmemclr clears the typed memory at ptr with type typ. The
// memory at ptr must already be initialized (and hence in type-safe
// state). If the memory is being initialized for the first time, see
// memclrNoHeapPointers.
//
// If the caller knows that typ has pointers, it can alternatively
// call memclrHasPointers.
//
// TODO: A "go:nosplitrec" annotation would be perfect for this.
//
//go:nosplit
func typedmemclr(typ *_type, ptr unsafe.Pointer) {
	if writeBarrier.enabled && typ.Pointers() {
		// This always clears a whole value of type typ, so it's
		// safe to pass a type here and apply the optimization.
		// See the comment on bulkBarrierPreWrite.
		bulkBarrierPreWrite(uintptr(ptr), 0, typ.PtrBytes, typ)
	}
	memclrNoHeapPointers(ptr, typ.Size_)
}

// reflect_typedmemclr is meant for package reflect,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/ugorji/go/codec
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname reflect_typedmemclr reflect.typedmemclr
func reflect_typedmemclr(typ *_type, ptr unsafe.Pointer) {
	typedmemclr(typ, ptr)
}

//go:linkname maps_typedmemclr internal/runtime/maps.typedmemclr
func maps_typedmemclr(typ *_type, ptr unsafe.Pointer) {
	typedmemclr(typ, ptr)
}

//go:linkname reflect_typedmemclrpartial reflect.typedmemclrpartial
func reflect_typedmemclrpartial(typ *_type, ptr unsafe.Pointer, off, size uintptr) {
	if writeBarrier.enabled && typ.Pointers() {
		// Pass nil for the type. ptr does not point to value of type typ,
		// but rather points into one so it's not safe to apply the optimization.
		// See the comment on this function in the reflect package and the
		// comment on bulkBarrierPreWrite.
		bulkBarrierPreWrite(uintptr(ptr), 0, size, nil)
	}
	memclrNoHeapPointers(ptr, size)
}

//go:linkname reflect_typedarrayclear reflect.typedarrayclear
func reflect_typedarrayclear(typ *_type, ptr unsafe.Pointer, len int) {
	size := typ.Size_ * uintptr(len)
	if writeBarrier.enabled && typ.Pointers() {
		// This always clears whole elements of an array, so it's
		// safe to pass a type here. See the comment on bulkBarrierPreWrite.
		bulkBarrierPreWrite(uintptr(ptr), 0, size, typ)
	}
	memclrNoHeapPointers(ptr, size)
}

// memclrHasPointers clears n bytes of typed memory starting at ptr.
// The caller must ensure that the type of the object at ptr has
// pointers, usually by checking typ.PtrBytes. However, ptr
// does not have to point to the start of the allocation.
//
// memclrHasPointers should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/bytedance/sonic
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname memclrHasPointers
//go:nosplit
func memclrHasPointers(ptr unsafe.Pointer, n uintptr) {
	// Pass nil for the type since we don't have one here anyway.
	bulkBarrierPreWrite(uintptr(ptr), 0, n, nil)
	memclrNoHeapPointers(ptr, n)
}
```