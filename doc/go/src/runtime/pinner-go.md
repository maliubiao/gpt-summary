Response:
Let's break down the thought process for analyzing the `pinner.go` code and generating the response.

**1. Understanding the Core Goal:**

The first step is to grasp the fundamental purpose of this code. The comments at the very beginning are key:  "A Pinner is a set of Go objects each pinned to a fixed location in memory." and the description of `Pin` and `Unpin`. This immediately tells us this is about controlling the garbage collector's (GC) behavior regarding specific objects. "Pinned" means the GC won't move or free these objects.

**2. Identifying Key Structures and Functions:**

Next, we look for the main data structures and functions:

* **`Pinner` struct:** This is the user-facing type. It holds a pointer to a `pinner` struct.
* **`pinner` struct:** This is the internal, low-level structure that manages the actual pinning. It contains `refs` (a slice of pinned pointers) and `refStore` (an inline array for initial storage).
* **`Pin` method:**  The function to pin an object.
* **`Unpin` method:** The function to unpin objects.
* **Helper functions:** `pinnerGetPtr`, `isPinned`, `setPinned`, `unpin` (method on `pinner`).

**3. Deconstructing the `Pin` Function:**

This is where the core pinning logic resides. We need to follow the steps:

* **Initialization:** Check if `p.pinner` is nil. If so, attempt to grab a cached `pinner` from the processor (`pp.pinnerCache`). If the cache is empty, create a new `pinner` and set a finalizer on it. The finalizer is crucial for detecting leaks.
* **Getting the raw pointer:** `pinnerGetPtr` extracts the `unsafe.Pointer` from the `any` input. This involves type checking to ensure it's a pointer.
* **Setting the pinned bit:** `setPinned` is the low-level function that actually marks the object as pinned in the memory management structures.
* **Tracking the pinned pointer:** Add the pointer to the `p.refs` slice.

**4. Deconstructing the `Unpin` Function:**

This is the counterpart to `Pin`:

* **Calling the internal unpin:** `p.pinner.unpin()` iterates through the stored pointers and calls `setPinned` with `false` to unmark them. It also clears the `refs` slice.
* **Caching the pinner:** After unpinning, the `pinner` might be returned to the processor's cache (`pp.pinnerCache`) for potential reuse. This optimization avoids repeated allocation and finalizer setup.

**5. Examining Helper Functions:**

* **`pinnerGetPtr`:** Focus on the type checking and the extraction of `unsafe.Pointer`. Note the panic conditions.
* **`isPinned`:** Understand how it checks the `mspan` (memory span) for the pinned status.
* **`setPinned`:** This is complex. It deals with `mspan`, `pinnerBits`, and potential multiple pins on the same object (using `specialPinCounter`). Pay attention to the locking (`span.speciallock`).
* **`unpin` (method on `pinner`):**  Simple iteration and calling `setPinned(ptr, false)`.

**6. Connecting to Go Concepts:**

Now, relate the code to broader Go features:

* **Garbage Collection:** The entire purpose is to interact with the GC.
* **`unsafe.Pointer`:** Essential for low-level memory manipulation and interacting with C code.
* **Finalizers:** Used here for leak detection.
* **`runtime` package:** This code lives within the core runtime, indicating its low-level nature.
* **`any` type:** Allows `Pin` to accept any pointer type.
* **`mspan`:** The fundamental unit of memory management in Go.
* **Atomic operations:** Used in `setPinned` for thread safety.

**7. Inferring the High-Level Go Feature:**

Based on the functionality, the most likely high-level feature is **interfacing with C code (Cgo)**. Pinning memory is crucial when you need to pass Go data to C functions that might hold onto pointers or access memory directly. The comments about storing pointers in C memory reinforce this.

**8. Crafting the Example:**

Create a simple Cgo example demonstrating the pinning and unpinning of a Go string being passed to a C function. Include necessary imports and C code block. Show the basic usage of `Pinner`.

**9. Identifying Potential Pitfalls:**

Think about what could go wrong when using this functionality:

* **Forgetting to `Unpin`:** This is the most obvious mistake, leading to memory leaks. The finalizer is designed to catch this.
* **Pinning non-pointer types:** The `Pin` function explicitly checks for this and panics.
* **Pinning stack allocated variables:** This is generally not necessary and might have unexpected consequences.
* **Incorrectly handling nested pointers:** If a pinned object contains pointers to other Go objects that need to be accessed from C, those also need pinning.

**10. Structuring the Response:**

Organize the findings logically, following the prompt's requirements:

* **功能列举:**  List the direct functionalities of `Pin` and `Unpin`.
* **Go 功能推断:** State the inferred high-level feature (Cgo) and provide the example.
* **代码推理:** Explain the example's input, output, and how the `Pinner` interacts.
* **命令行参数:**  Acknowledge the lack of command-line parameters.
* **易犯错的点:** List the potential pitfalls with illustrative examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Could this be related to some form of manual memory management in Go?  *Correction:*  No, Go is garbage collected. The pinning is about controlling the *interaction* with the GC, not bypassing it entirely.
* **Focusing too much on low-level details:**  While understanding `mspan` and `pinnerBits` is important, the response should prioritize the user-facing aspects and the high-level purpose.
* **Ensuring the example is clear and concise:** The Cgo example needs to be simple enough to demonstrate the pinning concept without unnecessary complexity.

By following these steps, combining close reading of the code with knowledge of Go's internals and common use cases, a comprehensive and accurate answer can be constructed.
这段 `go/src/runtime/pinner.go` 文件实现了一个用于**将 Go 对象固定在内存中特定位置**的功能。这通常用于与 C 代码进行互操作 (通过 Cgo)，或者在某些特定的性能优化场景中需要确保对象地址不变的情况。

以下是它的功能列表：

1. **`Pinner` 类型:**  定义了一个 `Pinner` 结构体，作为用户操作的入口点。它内部包含一个 `*pinner` 类型的指针。

2. **`Pin(pointer any)` 方法:**
   - 接受一个 `any` 类型的参数，但实际上它期望的是一个指针类型 (或 `unsafe.Pointer`)。
   - **防止 Go 对象被 GC 移动或回收:**  调用 `Pin` 会将指向的 Go 对象标记为“已固定”，从而阻止垃圾回收器在 `Unpin` 被调用之前移动或释放该对象。
   - **处理非 Go 指针:** 如果传入的不是 Go 指针，`Pin` 方法会静默地不做任何操作。
   - **使用缓存优化:**  它会尝试从当前 Goroutine 关联的 Processor (`P`) 的缓存中获取已有的 `pinner` 对象，以提高性能。
   - **延迟 finalizer 设置:**  `Pinner` 的 finalizer 只会被设置一次，并且会检查 `refs` 列表是否为空，以处理从缓存中重用的情况。finalizer 的作用是在 `Pinner` 对象被回收时检查是否还有未释放的 pin，如果有则会 panic，用于检测内存泄漏。
   - **存储被 pin 的指针:**  成功 pin 的指针会被添加到 `pinner` 结构体的 `refs` 切片中。

3. **`Unpin()` 方法:**
   - **释放所有被 pin 的对象:** 遍历 `pinner` 中 `refs` 切片存储的所有指针，并将它们标记为“未固定”，允许垃圾回收器像处理普通对象一样处理它们。
   - **缓存 `pinner` 对象:**  在 `Unpin` 后，如果当前 Goroutine 关联的 Processor 的缓存为空，则会将当前的 `pinner` 对象放回缓存中，以便后续 `Pin` 调用可以重用，提高效率。

4. **`pinner` 结构体:**
   - 内部结构体，存储了被 pin 的对象的指针切片 `refs` 和一个用于初始存储的小型固定大小的数组 `refStore`，用于避免在少量 pin 的情况下立即进行堆分配。

5. **`unpin()` 方法 (在 `pinner` 上):**
   - 实际执行解除 pin 操作的方法。遍历 `refs` 切片，调用 `setPinned(ptr, false)` 来取消每个指针的 pin 状态。
   - 清空 `refs` 切片，使其指向 `refStore` 的起始位置，有效地释放了对 pin 住的对象的引用。

6. **`pinnerGetPtr(i *any)` 函数:**
   - 从 `any` 类型的参数中提取 `unsafe.Pointer`。
   - **进行类型检查:**  确保参数是指针类型或 `unsafe.Pointer`，如果不是则会 panic。
   - **检查 Arena 分配:**  如果对象是在 Arena (一种特殊的内存分配区域，用于提升某些场景下的性能) 中分配的，则会 panic，因为 Arena 分配的对象不适合被 pin。

7. **`isPinned(ptr unsafe.Pointer) bool` 函数:**
   - 检查给定的 Go 指针是否被 pin。
   - 通过 `spanOfHeap` 获取指针所属的 `mspan` (内存 span)。
   - 检查 `mspan` 的 `pinnerBits` 中对应的位是否被设置。

8. **`setPinned(ptr unsafe.Pointer, pin bool) bool` 函数:**
   - **设置或取消 pin 状态:**  根据 `pin` 参数的值，将给定的 Go 指针标记为 pin 住或取消 pin。
   - **处理非 Go 指针:** 如果尝试 pin 非 Go 指针，会静默忽略。如果尝试 unpin 非 Go 指针，则会 panic。
   - **使用 `mspan` 和 `pinnerBits`:**  它使用 `mspan` 结构来管理内存页，并通过 `pinnerBits` 来存储每个对象是否被 pin 的状态。
   - **处理多次 pin 同一个对象:**  如果同一个对象被多次 `Pin`，它会设置一个 `multipin` 标志，并使用一个引用计数器来跟踪 pin 的次数。
   - **加锁保护:**  使用 `span.speciallock` 来防止并发调用 `setPinned` 导致的竞争条件。

9. **`pinState` 结构体:**
   - 表示一个对象的 pin 状态，包括是否被 pin 和是否被多次 pin。

10. **`pinnerBits` 类型:**
    - 类似于 `gcBits`，但用于存储 pin 的信息。

11. **`refreshPinnerBits()` 方法 (在 `mspan` 上):**
    - 在 GC 周期中更新 `mspan` 的 `pinnerBits`。如果 span 中没有被 pin 的对象，则会将 `pinnerBits` 设置为 nil。

12. **`incPinCounter()` 和 `decPinCounter()` 方法 (在 `mspan` 上):**
    - 用于管理同一个对象被多次 pin 时的计数器。

13. **`pinnerLeakPanic` 变量:**
    - 一个函数类型的变量，用于在检测到 pin 泄漏时触发 panic。这允许在测试中覆盖默认的 panic 行为。

**推断的 Go 语言功能：与 C 代码互操作 (Cgo)**

`Pinner` 的主要目的是为了支持 Go 程序与 C 代码进行安全的内存交互。当需要将 Go 对象的指针传递给 C 代码时，需要确保在该 C 代码操作期间，Go 对象不会被垃圾回收器移动或回收。`Pinner` 正是提供了这种能力。

**Go 代码示例 (Cgo 示例):**

```go
package main

/*
#include <stdlib.h>
#include <stdio.h>

void print_string(char* s) {
    printf("C code received: %s\n", s);
}
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

func main() {
	s := "Hello from Go!"
	pinner := &runtime.Pinner{}
	pinner.Pin(&s) // Pin the Go string

	// Pass the pointer to the C function
	cstr := C.CString(s)
	C.print_string(cstr)
	C.free(unsafe.Pointer(cstr)) // Remember to free the C string

	pinner.Unpin() // Unpin the Go string

	fmt.Println("Go program finished.")
}
```

**代码推理:**

**假设输入:**  Go 代码创建了一个字符串 `s := "Hello from Go!"`。

**输出:**

```
C code received: Hello from Go!
Go program finished.
```

**推理过程:**

1. `pinner.Pin(&s)`:  `Pin` 方法被调用，传入了字符串 `s` 的地址。这将阻止 Go 的垃圾回收器移动或回收 `s` 变量在内存中的位置。
2. `C.CString(s)`:  Go 的字符串被转换为 C 风格的字符串。由于 `s` 被 pin 住，即使 `C.CString` 可能涉及内存分配和复制，原始的 Go 字符串 `s` 的内存地址在 `Unpin` 之前是稳定的。
3. `C.print_string(cstr)`: C 函数 `print_string` 接收到指向 C 字符串的指针，并打印出来。
4. `pinner.Unpin()`:  `Unpin` 方法被调用，允许垃圾回收器像处理普通对象一样处理 `s`。

**涉及的代码推理细节:**

- `Pin(&s)` 调用 `setPinned`，最终会在 `s` 变量所在的内存 span 的 `pinnerBits` 中设置相应的位，标记该对象已被 pin。
- 在 `C.print_string` 执行期间，由于 `s` 被 pin 住，即使发生垃圾回收，`s` 的地址也不会改变，C 代码可以安全地访问该内存。
- `Unpin()` 调用 `unpin` 方法，遍历已 pin 的指针列表，并调用 `setPinned` 将 `pinnerBits` 中对应的位清除。

**命令行参数:**

这段代码本身不直接处理命令行参数。它属于 Go 运行时库的一部分，为其他 Go 代码提供服务。命令行参数的处理通常发生在 `main` 包的 `main` 函数中，可以使用 `os.Args` 或 `flag` 包来解析。

**使用者易犯错的点:**

1. **忘记调用 `Unpin()` 导致内存泄漏:** 这是最常见也是最严重的错误。如果对象被 `Pin` 但没有对应的 `Unpin`，那么即使该对象不再被使用，垃圾回收器也无法回收其占用的内存，从而导致内存泄漏。

   ```go
   package main

   import (
       "fmt"
       "runtime"
   )

   func main() {
       data := make([]byte, 1024*1024) // 1MB 的数据
       pinner := &runtime.Pinner{}
       pinner.Pin(&data)

       // ... 使用 data 的指针传递给 C 代码 ...

       // 忘记调用 pinner.Unpin()
       fmt.Println("Program finished, but memory is still pinned.")
   }
   ```

   在这个例子中，`data` 被 pin 住，但程序结束时忘记调用 `pinner.Unpin()`，这会导致 `data` 占用的 1MB 内存无法被回收，直到程序进程结束。

2. **Pin 非指针类型:** 虽然 `Pin` 方法接受 `any` 类型，但它内部会检查参数是否为指针。如果传入非指针类型，`pinnerGetPtr` 函数会 panic。

   ```go
   package main

   import "runtime"

   func main() {
       value := 10
       pinner := &runtime.Pinner{}
       // pinner.Pin(value) // 这会 panic: runtime.Pinner: argument is not a pointer: int
       pinner.Pin(&value) // 正确的做法
   }
   ```

3. **在不需要 pin 的情况下使用 `Pinner`:**  过度使用 `Pinner` 可能会降低程序的性能，因为它会限制垃圾回收器的灵活性。只有在与 C 代码互操作或有特定的内存地址固定需求时才应该使用。

4. **Pin 了栈上分配的变量:**  虽然可以 pin 栈上分配的变量，但这通常不是一个好的做法，并且可能引入难以追踪的错误。栈上的变量的生命周期由函数调用栈管理，超出其作用域后可能会失效，即使被 pin 住也可能导致问题。最好 pin 堆上分配的对象。

这段代码是 Go 运行时库中非常底层和关键的一部分，它为 Go 程序提供了与外部世界（特别是 C 代码）进行安全交互的能力。理解其功能和潜在的陷阱对于编写可靠的 Go Cgo 程序至关重要。

Prompt: 
```
这是路径为go/src/runtime/pinner.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

import (
	"internal/abi"
	"internal/runtime/atomic"
	"unsafe"
)

// A Pinner is a set of Go objects each pinned to a fixed location in memory. The
// [Pinner.Pin] method pins one object, while [Pinner.Unpin] unpins all pinned
// objects. See their comments for more information.
type Pinner struct {
	*pinner
}

// Pin pins a Go object, preventing it from being moved or freed by the garbage
// collector until the [Pinner.Unpin] method has been called.
//
// A pointer to a pinned object can be directly stored in C memory or can be
// contained in Go memory passed to C functions. If the pinned object itself
// contains pointers to Go objects, these objects must be pinned separately if they
// are going to be accessed from C code.
//
// The argument must be a pointer of any type or an [unsafe.Pointer].
// It's safe to call Pin on non-Go pointers, in which case Pin will do nothing.
func (p *Pinner) Pin(pointer any) {
	if p.pinner == nil {
		// Check the pinner cache first.
		mp := acquirem()
		if pp := mp.p.ptr(); pp != nil {
			p.pinner = pp.pinnerCache
			pp.pinnerCache = nil
		}
		releasem(mp)

		if p.pinner == nil {
			// Didn't get anything from the pinner cache.
			p.pinner = new(pinner)
			p.refs = p.refStore[:0]

			// We set this finalizer once and never clear it. Thus, if the
			// pinner gets cached, we'll reuse it, along with its finalizer.
			// This lets us avoid the relatively expensive SetFinalizer call
			// when reusing from the cache. The finalizer however has to be
			// resilient to an empty pinner being finalized, which is done
			// by checking p.refs' length.
			SetFinalizer(p.pinner, func(i *pinner) {
				if len(i.refs) != 0 {
					i.unpin() // only required to make the test idempotent
					pinnerLeakPanic()
				}
			})
		}
	}
	ptr := pinnerGetPtr(&pointer)
	if setPinned(ptr, true) {
		p.refs = append(p.refs, ptr)
	}
}

// Unpin unpins all pinned objects of the [Pinner].
func (p *Pinner) Unpin() {
	p.pinner.unpin()

	mp := acquirem()
	if pp := mp.p.ptr(); pp != nil && pp.pinnerCache == nil {
		// Put the pinner back in the cache, but only if the
		// cache is empty. If application code is reusing Pinners
		// on its own, we want to leave the backing store in place
		// so reuse is more efficient.
		pp.pinnerCache = p.pinner
		p.pinner = nil
	}
	releasem(mp)
}

const (
	pinnerSize         = 64
	pinnerRefStoreSize = (pinnerSize - unsafe.Sizeof([]unsafe.Pointer{})) / unsafe.Sizeof(unsafe.Pointer(nil))
)

type pinner struct {
	refs     []unsafe.Pointer
	refStore [pinnerRefStoreSize]unsafe.Pointer
}

func (p *pinner) unpin() {
	if p == nil || p.refs == nil {
		return
	}
	for i := range p.refs {
		setPinned(p.refs[i], false)
	}
	// The following two lines make all pointers to references
	// in p.refs unreachable, either by deleting them or dropping
	// p.refs' backing store (if it was not backed by refStore).
	p.refStore = [pinnerRefStoreSize]unsafe.Pointer{}
	p.refs = p.refStore[:0]
}

func pinnerGetPtr(i *any) unsafe.Pointer {
	e := efaceOf(i)
	etyp := e._type
	if etyp == nil {
		panic(errorString("runtime.Pinner: argument is nil"))
	}
	if kind := etyp.Kind_ & abi.KindMask; kind != abi.Pointer && kind != abi.UnsafePointer {
		panic(errorString("runtime.Pinner: argument is not a pointer: " + toRType(etyp).string()))
	}
	if inUserArenaChunk(uintptr(e.data)) {
		// Arena-allocated objects are not eligible for pinning.
		panic(errorString("runtime.Pinner: object was allocated into an arena"))
	}
	return e.data
}

// isPinned checks if a Go pointer is pinned.
// nosplit, because it's called from nosplit code in cgocheck.
//
//go:nosplit
func isPinned(ptr unsafe.Pointer) bool {
	span := spanOfHeap(uintptr(ptr))
	if span == nil {
		// this code is only called for Go pointer, so this must be a
		// linker-allocated global object.
		return true
	}
	pinnerBits := span.getPinnerBits()
	// these pinnerBits might get unlinked by a concurrently running sweep, but
	// that's OK because gcBits don't get cleared until the following GC cycle
	// (nextMarkBitArenaEpoch)
	if pinnerBits == nil {
		return false
	}
	objIndex := span.objIndex(uintptr(ptr))
	pinState := pinnerBits.ofObject(objIndex)
	KeepAlive(ptr) // make sure ptr is alive until we are done so the span can't be freed
	return pinState.isPinned()
}

// setPinned marks or unmarks a Go pointer as pinned, when the ptr is a Go pointer.
// It will be ignored while try to pin a non-Go pointer,
// and it will be panic while try to unpin a non-Go pointer,
// which should not happen in normal usage.
func setPinned(ptr unsafe.Pointer, pin bool) bool {
	span := spanOfHeap(uintptr(ptr))
	if span == nil {
		if !pin {
			panic(errorString("tried to unpin non-Go pointer"))
		}
		// This is a linker-allocated, zero size object or other object,
		// nothing to do, silently ignore it.
		return false
	}

	// ensure that the span is swept, b/c sweeping accesses the specials list
	// w/o locks.
	mp := acquirem()
	span.ensureSwept()
	KeepAlive(ptr) // make sure ptr is still alive after span is swept

	objIndex := span.objIndex(uintptr(ptr))

	lock(&span.speciallock) // guard against concurrent calls of setPinned on same span

	pinnerBits := span.getPinnerBits()
	if pinnerBits == nil {
		pinnerBits = span.newPinnerBits()
		span.setPinnerBits(pinnerBits)
	}
	pinState := pinnerBits.ofObject(objIndex)
	if pin {
		if pinState.isPinned() {
			// multiple pins on same object, set multipin bit
			pinState.setMultiPinned(true)
			// and increase the pin counter
			// TODO(mknyszek): investigate if systemstack is necessary here
			systemstack(func() {
				offset := objIndex * span.elemsize
				span.incPinCounter(offset)
			})
		} else {
			// set pin bit
			pinState.setPinned(true)
		}
	} else {
		// unpin
		if pinState.isPinned() {
			if pinState.isMultiPinned() {
				var exists bool
				// TODO(mknyszek): investigate if systemstack is necessary here
				systemstack(func() {
					offset := objIndex * span.elemsize
					exists = span.decPinCounter(offset)
				})
				if !exists {
					// counter is 0, clear multipin bit
					pinState.setMultiPinned(false)
				}
			} else {
				// no multipins recorded. unpin object.
				pinState.setPinned(false)
			}
		} else {
			// unpinning unpinned object, bail out
			throw("runtime.Pinner: object already unpinned")
		}
	}
	unlock(&span.speciallock)
	releasem(mp)
	return true
}

type pinState struct {
	bytep   *uint8
	byteVal uint8
	mask    uint8
}

// nosplit, because it's called by isPinned, which is nosplit
//
//go:nosplit
func (v *pinState) isPinned() bool {
	return (v.byteVal & v.mask) != 0
}

func (v *pinState) isMultiPinned() bool {
	return (v.byteVal & (v.mask << 1)) != 0
}

func (v *pinState) setPinned(val bool) {
	v.set(val, false)
}

func (v *pinState) setMultiPinned(val bool) {
	v.set(val, true)
}

// set sets the pin bit of the pinState to val. If multipin is true, it
// sets/unsets the multipin bit instead.
func (v *pinState) set(val bool, multipin bool) {
	mask := v.mask
	if multipin {
		mask <<= 1
	}
	if val {
		atomic.Or8(v.bytep, mask)
	} else {
		atomic.And8(v.bytep, ^mask)
	}
}

// pinnerBits is the same type as gcBits but has different methods.
type pinnerBits gcBits

// ofObject returns the pinState of the n'th object.
// nosplit, because it's called by isPinned, which is nosplit
//
//go:nosplit
func (p *pinnerBits) ofObject(n uintptr) pinState {
	bytep, mask := (*gcBits)(p).bitp(n * 2)
	byteVal := atomic.Load8(bytep)
	return pinState{bytep, byteVal, mask}
}

func (s *mspan) pinnerBitSize() uintptr {
	return divRoundUp(uintptr(s.nelems)*2, 8)
}

// newPinnerBits returns a pointer to 8 byte aligned bytes to be used for this
// span's pinner bits. newPinnerBits is used to mark objects that are pinned.
// They are copied when the span is swept.
func (s *mspan) newPinnerBits() *pinnerBits {
	return (*pinnerBits)(newMarkBits(uintptr(s.nelems) * 2))
}

// nosplit, because it's called by isPinned, which is nosplit
//
//go:nosplit
func (s *mspan) getPinnerBits() *pinnerBits {
	return (*pinnerBits)(atomic.Loadp(unsafe.Pointer(&s.pinnerBits)))
}

func (s *mspan) setPinnerBits(p *pinnerBits) {
	atomicstorep(unsafe.Pointer(&s.pinnerBits), unsafe.Pointer(p))
}

// refreshPinnerBits replaces pinnerBits with a fresh copy in the arenas for the
// next GC cycle. If it does not contain any pinned objects, pinnerBits of the
// span is set to nil.
func (s *mspan) refreshPinnerBits() {
	p := s.getPinnerBits()
	if p == nil {
		return
	}

	hasPins := false
	bytes := alignUp(s.pinnerBitSize(), 8)

	// Iterate over each 8-byte chunk and check for pins. Note that
	// newPinnerBits guarantees that pinnerBits will be 8-byte aligned, so we
	// don't have to worry about edge cases, irrelevant bits will simply be
	// zero.
	for _, x := range unsafe.Slice((*uint64)(unsafe.Pointer(&p.x)), bytes/8) {
		if x != 0 {
			hasPins = true
			break
		}
	}

	if hasPins {
		newPinnerBits := s.newPinnerBits()
		memmove(unsafe.Pointer(&newPinnerBits.x), unsafe.Pointer(&p.x), bytes)
		s.setPinnerBits(newPinnerBits)
	} else {
		s.setPinnerBits(nil)
	}
}

// incPinCounter is only called for multiple pins of the same object and records
// the _additional_ pins.
func (span *mspan) incPinCounter(offset uintptr) {
	var rec *specialPinCounter
	ref, exists := span.specialFindSplicePoint(offset, _KindSpecialPinCounter)
	if !exists {
		lock(&mheap_.speciallock)
		rec = (*specialPinCounter)(mheap_.specialPinCounterAlloc.alloc())
		unlock(&mheap_.speciallock)
		// splice in record, fill in offset.
		rec.special.offset = offset
		rec.special.kind = _KindSpecialPinCounter
		rec.special.next = *ref
		*ref = (*special)(unsafe.Pointer(rec))
		spanHasSpecials(span)
	} else {
		rec = (*specialPinCounter)(unsafe.Pointer(*ref))
	}
	rec.counter++
}

// decPinCounter decreases the counter. If the counter reaches 0, the counter
// special is deleted and false is returned. Otherwise true is returned.
func (span *mspan) decPinCounter(offset uintptr) bool {
	ref, exists := span.specialFindSplicePoint(offset, _KindSpecialPinCounter)
	if !exists {
		throw("runtime.Pinner: decreased non-existing pin counter")
	}
	counter := (*specialPinCounter)(unsafe.Pointer(*ref))
	counter.counter--
	if counter.counter == 0 {
		*ref = counter.special.next
		if span.specials == nil {
			spanHasNoSpecials(span)
		}
		lock(&mheap_.speciallock)
		mheap_.specialPinCounterAlloc.free(unsafe.Pointer(counter))
		unlock(&mheap_.speciallock)
		return false
	}
	return true
}

// only for tests
func pinnerGetPinCounter(addr unsafe.Pointer) *uintptr {
	_, span, objIndex := findObject(uintptr(addr), 0, 0)
	offset := objIndex * span.elemsize
	t, exists := span.specialFindSplicePoint(offset, _KindSpecialPinCounter)
	if !exists {
		return nil
	}
	counter := (*specialPinCounter)(unsafe.Pointer(*t))
	return &counter.counter
}

// to be able to test that the GC panics when a pinned pointer is leaking, this
// panic function is a variable, that can be overwritten by a test.
var pinnerLeakPanic = func() {
	panic(errorString("runtime.Pinner: found leaking pinned pointer; forgot to call Unpin()?"))
}

"""



```