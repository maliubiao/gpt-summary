Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided Go code snippet, focusing on its functionality, how it's used, assumptions, potential errors, and examples. It's explicitly marked as the first part of a two-part question.

2. **Identify the Core Topic:** The initial comments clearly state the code deals with "Garbage collector: type and heap bitmaps."  This is the central theme I need to address.

3. **Break Down the Functionality (Based on Comments and Code):** I'll go through the comments and the function names, grouping related concepts.

    * **Bitmaps for GC:** The code describes how bitmaps are used to track pointers for the garbage collector. I'll differentiate between stack/data/bss bitmaps and heap bitmaps.
    * **Heap Bitmap Details:** The code elaborates on how heap bitmaps are stored and accessed for small and large objects. The "tiling" concept for large objects is important.
    * **`typePointers` struct and Iteration:**  The `typePointers` struct and its `next` and `nextFast` methods are about iterating over pointers within objects. The "tiling algorithm" is relevant here.
    * **Span Management:**  Concepts like `mspan`, `heapBits`, and `heapBitsSmallForAddr` relate to how memory spans and their associated bitmaps are handled.
    * **Write Barriers:** Functions like `bulkBarrierPreWrite` and `bulkBarrierPreWriteSrcOnly` are explicitly identified as write barriers, used during memory operations.
    * **Setting Heap Types:** Functions like `heapSetTypeNoHeader`, `heapSetTypeSmallHeader`, and `heapSetTypeLarge` are responsible for recording the type information of newly allocated objects for the GC.

4. **Formulate Functionality Summary:** Based on the breakdown, I can summarize the main functionalities:

    * Representing pointer information using bitmaps for GC.
    * Different bitmap strategies for stack/globals and the heap.
    * Specialized heap bitmap handling for small and large objects, including the "tiling" method.
    * Iterating over pointers within objects using the `typePointers` structure.
    * Implementing write barriers for safe memory manipulation during GC.
    * Recording the type information of allocated objects in the heap.

5. **Address the Specific Questions (Part 1 Focus):**

    * **List Functionality:**  This is directly answered by the summary I formulated.
    * **Go Feature Implementation:** The code is clearly part of the Go garbage collector implementation.
    * **Go Code Example:**  Since it's an internal part of the GC, a *direct* user-level example is tricky. I'll opt for showing how the GC *indirectly* uses this by tracking pointers in a struct. This requires a simple struct with pointer fields. I need to mention that the *details* are internal and not directly accessible to users. *Initially, I considered trying to force a GC cycle and inspect memory, but that's too complex and unreliable for a clear example.*
    * **Code Reasoning (Input/Output):**  For `typePointers`, I can create a hypothetical scenario with a struct and show how the iterator would traverse the pointer fields. I need to make assumptions about the type metadata (which isn't directly exposed).
    * **Command-line Arguments:**  This code doesn't directly handle command-line arguments. I need to state this explicitly.
    * **User Errors:** Common errors might involve misunderstanding how write barriers work or attempting to manipulate memory without proper synchronization, potentially leading to data corruption. I can provide a simple example of a data race.
    * **Part 1 Summary:**  This is essentially the same as the initial functionality summary.

6. **Structure the Answer:** I'll organize the answer with clear headings for each part of the request. I'll use code blocks for examples and ensure the language is clear and concise.

7. **Refine and Review:** I'll reread my answer to make sure it's accurate, addresses all parts of the prompt, and is easy to understand. I'll double-check the code examples for correctness and clarity. I will ensure that I'm explicitly stating assumptions when needed (like in the `typePointers` example). I need to emphasize that this is an *internal* implementation detail of the GC.

By following these steps, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request regarding the provided Go code snippet. The key is to focus on the core functionality, break it down logically, and then synthesize the information into a clear and well-structured response.
这段代码是 Go 语言运行时环境（runtime）中 `mbitmap.go` 文件的一部分，主要负责 **管理和操作内存的位图 (bitmap)**，这些位图用于垃圾回收 (Garbage Collection, GC) 追踪内存中哪些位置包含指向其他对象的指针。

**它的主要功能可以归纳为以下几点：**

1. **定义了不同类型的位图:**
   - **栈、数据段和 BSS 段位图:** 用于描述栈帧和全局变量中哪些字是活跃的指针。
   - **堆位图:**  用于记录堆内存中每个字是否存储了一个指针。

2. **提供了访问和操作堆位图的方法:**
   - **`heapBits()`:**  对于小对象，返回包含整个 span 位图的切片。对于大对象，并不存储实际的位图，而是依赖类型元数据在运行时动态生成。
   - **`heapBitsSmallForAddr()`:**  加载存储在 span 末尾的小对象的堆位图。
   - **`writeHeapBitsSmall()`:**  写入小对象的堆位图。
   - **`initHeapBits()`:** 初始化 span 的堆位图。

3. **实现了迭代器 `typePointers` 用于遍历对象中的指针:**
   - 这个迭代器基于对象的类型信息（`_type`）和位图信息，按照“平铺”算法（tiling algorithm）来找到对象内部的指针。
   - 提供了 `nextFast()` 和 `next()` 方法来高效地获取下一个指针的地址。
   - 提供了 `typePointersOf()`，`typePointersOfUnchecked()`， `typePointersOfType()` 等方法来创建不同场景下的迭代器。

4. **实现了写入屏障 (Write Barrier) 相关的功能:**
   - **`bulkBarrierPreWrite()`:** 在 `memmove` 之前执行必要的写入屏障，用于确保 GC 能正确追踪移动后的指针。
   - **`bulkBarrierPreWriteSrcOnly()`:** 类似于 `bulkBarrierPreWrite`，但只处理源内存的写入屏障，假设目标内存已被清零。

5. **提供了设置堆对象类型信息的方法:**
   - **`heapSetTypeNoHeader()`， `heapSetTypeSmallHeader()`， `heapSetTypeLarge()`:**  在对象分配后，记录对象的类型信息，以便 GC 可以根据类型信息扫描对象内部的指针。

**它是什么 Go 语言功能的实现？**

这段代码是 **Go 语言垃圾回收机制 (Garbage Collection)** 的核心组成部分。它实现了 GC 需要的关键数据结构和算法，用于跟踪内存中的指针，从而识别哪些内存是活跃的，哪些可以被回收。

**Go 代码举例说明:**

虽然这段代码是 runtime 内部的实现，用户代码不会直接调用这些函数，但我们可以通过一个例子来说明 GC 如何利用这些位图来追踪指针。

```go
package main

import "fmt"
import "runtime"

type MyStruct struct {
	Ptr1 *int
	Value int
	Ptr2 *string
}

func main() {
	runtime.GC() // 手动触发一次 GC，方便观察

	num := 10
	str := "hello"
	s := &MyStruct{&num, 20, &str}

	// 在这里，GC 会使用 mbitmap.go 中的机制来标记 s 指向的内存中哪些是指针
	// 指向 num 和 str 的位置会被标记为指针

	fmt.Println(*s.Ptr1, s.Value, *s.Ptr2)

	runtime.KeepAlive(s) // 确保 s 在 GC 发生前不会被优化掉
	runtime.GC()
}
```

**假设的输入与输出 (对于 `typePointers`):**

假设我们有以下结构体和一个指向它的指针：

```go
package main

type MyData struct {
	A int
	B *int
	C string
	D *string
}

func main() {
	num := 10
	str := "world"
	data := &MyData{1, &num, "hello", &str}
	// ... 假设我们有指向 data 的地址 `addr` 和 span 信息 `span`
}
```

如果我们使用 `span.typePointersOf(addr, size)` 来创建一个 `typePointers` 迭代器，假设 `size` 是 `MyData` 结构体的大小，那么：

- **输入:**  `addr` (指向 `data` 的起始地址), `size` ( `MyData` 的大小), `span` (包含 `data` 的内存 span)
- **输出 (迭代过程):**
    - 第一次调用 `tp.next()` 可能返回 `data` 中字段 `B` 的地址 (因为 `B` 是一个 `*int`)。
    - 第二次调用 `tp.next()` 可能返回 `data` 中字段 `D` 的地址 (因为 `D` 是一个 `*string`)。
    - 后续调用 `tp.next()` 将返回 0，表示没有更多的指针。

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。Go 语言的 GC 行为可以通过一些环境变量来控制，例如 `GOGC` 和 `GODEBUG`，但这些参数的处理逻辑在 runtime 的其他部分。

**使用者易犯错的点:**

作为用户，我们通常不会直接与 `mbitmap.go` 中的代码交互。但是，理解其背后的概念有助于避免一些与内存管理和并发相关的错误：

1. **误解写入屏障的作用:**  不理解写入屏障可能导致在并发场景下，GC 无法正确追踪到被修改的指针，从而导致悬挂指针或内存泄漏。例如，在没有正确同步的情况下，一个 goroutine 修改了一个指针，而 GC 在修改完成前进行扫描，可能会认为该指针已经失效。

   ```go
   package main

   import (
   	"fmt"
   	"runtime"
   	"sync"
   )

   type Data struct {
   	Value *int
   }

   func main() {
   	runtime.GC()
   	var wg sync.WaitGroup
   	d := &Data{}

   	wg.Add(2)
   	go func() {
   		defer wg.Done()
   		num := 42
   		d.Value = &num // 潜在的 race condition，可能在 GC 扫描时发生
   	}()

   	go func() {
   		defer wg.Done()
   		runtime.GC() // 尝试在另一个 goroutine 修改指针时触发 GC
   		if d.Value != nil {
   			fmt.Println(*d.Value) // 如果 GC 没有正确追踪，可能导致访问无效内存
   		}
   	}()

   	wg.Wait()
   	runtime.KeepAlive(d)
   }
   ```

2. **不了解 Go 的内存模型:**  Go 的内存模型保证了在正确同步的情况下，对共享变量的写入操作对其他 goroutine 是可见的。理解这一点对于避免与 GC 相关的并发问题至关重要。

**总结一下它的功能 (Part 1):**

这段 `mbitmap.go` 代码的核心功能是为 Go 语言的垃圾回收机制提供了 **内存位图管理和指针追踪** 的基础。它定义了不同类型的位图，提供了访问和操作这些位图的方法，并实现了用于遍历对象内部指针的迭代器和写入屏障机制。这些功能共同协作，使得 GC 能够准确地识别和回收不再使用的内存，保证了 Go 程序的内存安全和效率。

### 提示词
```
这是路径为go/src/runtime/mbitmap.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Garbage collector: type and heap bitmaps.
//
// Stack, data, and bss bitmaps
//
// Stack frames and global variables in the data and bss sections are
// described by bitmaps with 1 bit per pointer-sized word. A "1" bit
// means the word is a live pointer to be visited by the GC (referred to
// as "pointer"). A "0" bit means the word should be ignored by GC
// (referred to as "scalar", though it could be a dead pointer value).
//
// Heap bitmaps
//
// The heap bitmap comprises 1 bit for each pointer-sized word in the heap,
// recording whether a pointer is stored in that word or not. This bitmap
// is stored at the end of a span for small objects and is unrolled at
// runtime from type metadata for all larger objects. Objects without
// pointers have neither a bitmap nor associated type metadata.
//
// Bits in all cases correspond to words in little-endian order.
//
// For small objects, if s is the mspan for the span starting at "start",
// then s.heapBits() returns a slice containing the bitmap for the whole span.
// That is, s.heapBits()[0] holds the goarch.PtrSize*8 bits for the first
// goarch.PtrSize*8 words from "start" through "start+63*ptrSize" in the span.
// On a related note, small objects are always small enough that their bitmap
// fits in goarch.PtrSize*8 bits, so writing out bitmap data takes two bitmap
// writes at most (because object boundaries don't generally lie on
// s.heapBits()[i] boundaries).
//
// For larger objects, if t is the type for the object starting at "start",
// within some span whose mspan is s, then the bitmap at t.GCData is "tiled"
// from "start" through "start+s.elemsize".
// Specifically, the first bit of t.GCData corresponds to the word at "start",
// the second to the word after "start", and so on up to t.PtrBytes. At t.PtrBytes,
// we skip to "start+t.Size_" and begin again from there. This process is
// repeated until we hit "start+s.elemsize".
// This tiling algorithm supports array data, since the type always refers to
// the element type of the array. Single objects are considered the same as
// single-element arrays.
// The tiling algorithm may scan data past the end of the compiler-recognized
// object, but any unused data within the allocation slot (i.e. within s.elemsize)
// is zeroed, so the GC just observes nil pointers.
// Note that this "tiled" bitmap isn't stored anywhere; it is generated on-the-fly.
//
// For objects without their own span, the type metadata is stored in the first
// word before the object at the beginning of the allocation slot. For objects
// with their own span, the type metadata is stored in the mspan.
//
// The bitmap for small unallocated objects in scannable spans is not maintained
// (can be junk).

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/sys"
	"unsafe"
)

const (
	// A malloc header is functionally a single type pointer, but
	// we need to use 8 here to ensure 8-byte alignment of allocations
	// on 32-bit platforms. It's wasteful, but a lot of code relies on
	// 8-byte alignment for 8-byte atomics.
	mallocHeaderSize = 8

	// The minimum object size that has a malloc header, exclusive.
	//
	// The size of this value controls overheads from the malloc header.
	// The minimum size is bound by writeHeapBitsSmall, which assumes that the
	// pointer bitmap for objects of a size smaller than this doesn't cross
	// more than one pointer-word boundary. This sets an upper-bound on this
	// value at the number of bits in a uintptr, multiplied by the pointer
	// size in bytes.
	//
	// We choose a value here that has a natural cutover point in terms of memory
	// overheads. This value just happens to be the maximum possible value this
	// can be.
	//
	// A span with heap bits in it will have 128 bytes of heap bits on 64-bit
	// platforms, and 256 bytes of heap bits on 32-bit platforms. The first size
	// class where malloc headers match this overhead for 64-bit platforms is
	// 512 bytes (8 KiB / 512 bytes * 8 bytes-per-header = 128 bytes of overhead).
	// On 32-bit platforms, this same point is the 256 byte size class
	// (8 KiB / 256 bytes * 8 bytes-per-header = 256 bytes of overhead).
	//
	// Guaranteed to be exactly at a size class boundary. The reason this value is
	// an exclusive minimum is subtle. Suppose we're allocating a 504-byte object
	// and its rounded up to 512 bytes for the size class. If minSizeForMallocHeader
	// is 512 and an inclusive minimum, then a comparison against minSizeForMallocHeader
	// by the two values would produce different results. In other words, the comparison
	// would not be invariant to size-class rounding. Eschewing this property means a
	// more complex check or possibly storing additional state to determine whether a
	// span has malloc headers.
	minSizeForMallocHeader = goarch.PtrSize * ptrBits
)

// heapBitsInSpan returns true if the size of an object implies its ptr/scalar
// data is stored at the end of the span, and is accessible via span.heapBits.
//
// Note: this works for both rounded-up sizes (span.elemsize) and unrounded
// type sizes because minSizeForMallocHeader is guaranteed to be at a size
// class boundary.
//
//go:nosplit
func heapBitsInSpan(userSize uintptr) bool {
	// N.B. minSizeForMallocHeader is an exclusive minimum so that this function is
	// invariant under size-class rounding on its input.
	return userSize <= minSizeForMallocHeader
}

// typePointers is an iterator over the pointers in a heap object.
//
// Iteration through this type implements the tiling algorithm described at the
// top of this file.
type typePointers struct {
	// elem is the address of the current array element of type typ being iterated over.
	// Objects that are not arrays are treated as single-element arrays, in which case
	// this value does not change.
	elem uintptr

	// addr is the address the iterator is currently working from and describes
	// the address of the first word referenced by mask.
	addr uintptr

	// mask is a bitmask where each bit corresponds to pointer-words after addr.
	// Bit 0 is the pointer-word at addr, Bit 1 is the next word, and so on.
	// If a bit is 1, then there is a pointer at that word.
	// nextFast and next mask out bits in this mask as their pointers are processed.
	mask uintptr

	// typ is a pointer to the type information for the heap object's type.
	// This may be nil if the object is in a span where heapBitsInSpan(span.elemsize) is true.
	typ *_type
}

// typePointersOf returns an iterator over all heap pointers in the range [addr, addr+size).
//
// addr and addr+size must be in the range [span.base(), span.limit).
//
// Note: addr+size must be passed as the limit argument to the iterator's next method on
// each iteration. This slightly awkward API is to allow typePointers to be destructured
// by the compiler.
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func (span *mspan) typePointersOf(addr, size uintptr) typePointers {
	base := span.objBase(addr)
	tp := span.typePointersOfUnchecked(base)
	if base == addr && size == span.elemsize {
		return tp
	}
	return tp.fastForward(addr-tp.addr, addr+size)
}

// typePointersOfUnchecked is like typePointersOf, but assumes addr is the base
// of an allocation slot in a span (the start of the object if no header, the
// header otherwise). It returns an iterator that generates all pointers
// in the range [addr, addr+span.elemsize).
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func (span *mspan) typePointersOfUnchecked(addr uintptr) typePointers {
	const doubleCheck = false
	if doubleCheck && span.objBase(addr) != addr {
		print("runtime: addr=", addr, " base=", span.objBase(addr), "\n")
		throw("typePointersOfUnchecked consisting of non-base-address for object")
	}

	spc := span.spanclass
	if spc.noscan() {
		return typePointers{}
	}
	if heapBitsInSpan(span.elemsize) {
		// Handle header-less objects.
		return typePointers{elem: addr, addr: addr, mask: span.heapBitsSmallForAddr(addr)}
	}

	// All of these objects have a header.
	var typ *_type
	if spc.sizeclass() != 0 {
		// Pull the allocation header from the first word of the object.
		typ = *(**_type)(unsafe.Pointer(addr))
		addr += mallocHeaderSize
	} else {
		typ = span.largeType
		if typ == nil {
			// Allow a nil type here for delayed zeroing. See mallocgc.
			return typePointers{}
		}
	}
	gcmask := getGCMask(typ)
	return typePointers{elem: addr, addr: addr, mask: readUintptr(gcmask), typ: typ}
}

// typePointersOfType is like typePointersOf, but assumes addr points to one or more
// contiguous instances of the provided type. The provided type must not be nil.
//
// It returns an iterator that tiles typ's gcmask starting from addr. It's the caller's
// responsibility to limit iteration.
//
// nosplit because its callers are nosplit and require all their callees to be nosplit.
//
//go:nosplit
func (span *mspan) typePointersOfType(typ *abi.Type, addr uintptr) typePointers {
	const doubleCheck = false
	if doubleCheck && typ == nil {
		throw("bad type passed to typePointersOfType")
	}
	if span.spanclass.noscan() {
		return typePointers{}
	}
	// Since we have the type, pretend we have a header.
	gcmask := getGCMask(typ)
	return typePointers{elem: addr, addr: addr, mask: readUintptr(gcmask), typ: typ}
}

// nextFast is the fast path of next. nextFast is written to be inlineable and,
// as the name implies, fast.
//
// Callers that are performance-critical should iterate using the following
// pattern:
//
//	for {
//		var addr uintptr
//		if tp, addr = tp.nextFast(); addr == 0 {
//			if tp, addr = tp.next(limit); addr == 0 {
//				break
//			}
//		}
//		// Use addr.
//		...
//	}
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func (tp typePointers) nextFast() (typePointers, uintptr) {
	// TESTQ/JEQ
	if tp.mask == 0 {
		return tp, 0
	}
	// BSFQ
	var i int
	if goarch.PtrSize == 8 {
		i = sys.TrailingZeros64(uint64(tp.mask))
	} else {
		i = sys.TrailingZeros32(uint32(tp.mask))
	}
	// BTCQ
	tp.mask ^= uintptr(1) << (i & (ptrBits - 1))
	// LEAQ (XX)(XX*8)
	return tp, tp.addr + uintptr(i)*goarch.PtrSize
}

// next advances the pointers iterator, returning the updated iterator and
// the address of the next pointer.
//
// limit must be the same each time it is passed to next.
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func (tp typePointers) next(limit uintptr) (typePointers, uintptr) {
	for {
		if tp.mask != 0 {
			return tp.nextFast()
		}

		// Stop if we don't actually have type information.
		if tp.typ == nil {
			return typePointers{}, 0
		}

		// Advance to the next element if necessary.
		if tp.addr+goarch.PtrSize*ptrBits >= tp.elem+tp.typ.PtrBytes {
			tp.elem += tp.typ.Size_
			tp.addr = tp.elem
		} else {
			tp.addr += ptrBits * goarch.PtrSize
		}

		// Check if we've exceeded the limit with the last update.
		if tp.addr >= limit {
			return typePointers{}, 0
		}

		// Grab more bits and try again.
		tp.mask = readUintptr(addb(getGCMask(tp.typ), (tp.addr-tp.elem)/goarch.PtrSize/8))
		if tp.addr+goarch.PtrSize*ptrBits > limit {
			bits := (tp.addr + goarch.PtrSize*ptrBits - limit) / goarch.PtrSize
			tp.mask &^= ((1 << (bits)) - 1) << (ptrBits - bits)
		}
	}
}

// fastForward moves the iterator forward by n bytes. n must be a multiple
// of goarch.PtrSize. limit must be the same limit passed to next for this
// iterator.
//
// nosplit because it is used during write barriers and must not be preempted.
//
//go:nosplit
func (tp typePointers) fastForward(n, limit uintptr) typePointers {
	// Basic bounds check.
	target := tp.addr + n
	if target >= limit {
		return typePointers{}
	}
	if tp.typ == nil {
		// Handle small objects.
		// Clear any bits before the target address.
		tp.mask &^= (1 << ((target - tp.addr) / goarch.PtrSize)) - 1
		// Clear any bits past the limit.
		if tp.addr+goarch.PtrSize*ptrBits > limit {
			bits := (tp.addr + goarch.PtrSize*ptrBits - limit) / goarch.PtrSize
			tp.mask &^= ((1 << (bits)) - 1) << (ptrBits - bits)
		}
		return tp
	}

	// Move up elem and addr.
	// Offsets within an element are always at a ptrBits*goarch.PtrSize boundary.
	if n >= tp.typ.Size_ {
		// elem needs to be moved to the element containing
		// tp.addr + n.
		oldelem := tp.elem
		tp.elem += (tp.addr - tp.elem + n) / tp.typ.Size_ * tp.typ.Size_
		tp.addr = tp.elem + alignDown(n-(tp.elem-oldelem), ptrBits*goarch.PtrSize)
	} else {
		tp.addr += alignDown(n, ptrBits*goarch.PtrSize)
	}

	if tp.addr-tp.elem >= tp.typ.PtrBytes {
		// We're starting in the non-pointer area of an array.
		// Move up to the next element.
		tp.elem += tp.typ.Size_
		tp.addr = tp.elem
		tp.mask = readUintptr(getGCMask(tp.typ))

		// We may have exceeded the limit after this. Bail just like next does.
		if tp.addr >= limit {
			return typePointers{}
		}
	} else {
		// Grab the mask, but then clear any bits before the target address and any
		// bits over the limit.
		tp.mask = readUintptr(addb(getGCMask(tp.typ), (tp.addr-tp.elem)/goarch.PtrSize/8))
		tp.mask &^= (1 << ((target - tp.addr) / goarch.PtrSize)) - 1
	}
	if tp.addr+goarch.PtrSize*ptrBits > limit {
		bits := (tp.addr + goarch.PtrSize*ptrBits - limit) / goarch.PtrSize
		tp.mask &^= ((1 << (bits)) - 1) << (ptrBits - bits)
	}
	return tp
}

// objBase returns the base pointer for the object containing addr in span.
//
// Assumes that addr points into a valid part of span (span.base() <= addr < span.limit).
//
//go:nosplit
func (span *mspan) objBase(addr uintptr) uintptr {
	return span.base() + span.objIndex(addr)*span.elemsize
}

// bulkBarrierPreWrite executes a write barrier
// for every pointer slot in the memory range [src, src+size),
// using pointer/scalar information from [dst, dst+size).
// This executes the write barriers necessary before a memmove.
// src, dst, and size must be pointer-aligned.
// The range [dst, dst+size) must lie within a single object.
// It does not perform the actual writes.
//
// As a special case, src == 0 indicates that this is being used for a
// memclr. bulkBarrierPreWrite will pass 0 for the src of each write
// barrier.
//
// Callers should call bulkBarrierPreWrite immediately before
// calling memmove(dst, src, size). This function is marked nosplit
// to avoid being preempted; the GC must not stop the goroutine
// between the memmove and the execution of the barriers.
// The caller is also responsible for cgo pointer checks if this
// may be writing Go pointers into non-Go memory.
//
// Pointer data is not maintained for allocations containing
// no pointers at all; any caller of bulkBarrierPreWrite must first
// make sure the underlying allocation contains pointers, usually
// by checking typ.PtrBytes.
//
// The typ argument is the type of the space at src and dst (and the
// element type if src and dst refer to arrays) and it is optional.
// If typ is nil, the barrier will still behave as expected and typ
// is used purely as an optimization. However, it must be used with
// care.
//
// If typ is not nil, then src and dst must point to one or more values
// of type typ. The caller must ensure that the ranges [src, src+size)
// and [dst, dst+size) refer to one or more whole values of type src and
// dst (leaving off the pointerless tail of the space is OK). If this
// precondition is not followed, this function will fail to scan the
// right pointers.
//
// When in doubt, pass nil for typ. That is safe and will always work.
//
// Callers must perform cgo checks if goexperiment.CgoCheck2.
//
//go:nosplit
func bulkBarrierPreWrite(dst, src, size uintptr, typ *abi.Type) {
	if (dst|src|size)&(goarch.PtrSize-1) != 0 {
		throw("bulkBarrierPreWrite: unaligned arguments")
	}
	if !writeBarrier.enabled {
		return
	}
	s := spanOf(dst)
	if s == nil {
		// If dst is a global, use the data or BSS bitmaps to
		// execute write barriers.
		for _, datap := range activeModules() {
			if datap.data <= dst && dst < datap.edata {
				bulkBarrierBitmap(dst, src, size, dst-datap.data, datap.gcdatamask.bytedata)
				return
			}
		}
		for _, datap := range activeModules() {
			if datap.bss <= dst && dst < datap.ebss {
				bulkBarrierBitmap(dst, src, size, dst-datap.bss, datap.gcbssmask.bytedata)
				return
			}
		}
		return
	} else if s.state.get() != mSpanInUse || dst < s.base() || s.limit <= dst {
		// dst was heap memory at some point, but isn't now.
		// It can't be a global. It must be either our stack,
		// or in the case of direct channel sends, it could be
		// another stack. Either way, no need for barriers.
		// This will also catch if dst is in a freed span,
		// though that should never have.
		return
	}
	buf := &getg().m.p.ptr().wbBuf

	// Double-check that the bitmaps generated in the two possible paths match.
	const doubleCheck = false
	if doubleCheck {
		doubleCheckTypePointersOfType(s, typ, dst, size)
	}

	var tp typePointers
	if typ != nil {
		tp = s.typePointersOfType(typ, dst)
	} else {
		tp = s.typePointersOf(dst, size)
	}
	if src == 0 {
		for {
			var addr uintptr
			if tp, addr = tp.next(dst + size); addr == 0 {
				break
			}
			dstx := (*uintptr)(unsafe.Pointer(addr))
			p := buf.get1()
			p[0] = *dstx
		}
	} else {
		for {
			var addr uintptr
			if tp, addr = tp.next(dst + size); addr == 0 {
				break
			}
			dstx := (*uintptr)(unsafe.Pointer(addr))
			srcx := (*uintptr)(unsafe.Pointer(src + (addr - dst)))
			p := buf.get2()
			p[0] = *dstx
			p[1] = *srcx
		}
	}
}

// bulkBarrierPreWriteSrcOnly is like bulkBarrierPreWrite but
// does not execute write barriers for [dst, dst+size).
//
// In addition to the requirements of bulkBarrierPreWrite
// callers need to ensure [dst, dst+size) is zeroed.
//
// This is used for special cases where e.g. dst was just
// created and zeroed with malloc.
//
// The type of the space can be provided purely as an optimization.
// See bulkBarrierPreWrite's comment for more details -- use this
// optimization with great care.
//
//go:nosplit
func bulkBarrierPreWriteSrcOnly(dst, src, size uintptr, typ *abi.Type) {
	if (dst|src|size)&(goarch.PtrSize-1) != 0 {
		throw("bulkBarrierPreWrite: unaligned arguments")
	}
	if !writeBarrier.enabled {
		return
	}
	buf := &getg().m.p.ptr().wbBuf
	s := spanOf(dst)

	// Double-check that the bitmaps generated in the two possible paths match.
	const doubleCheck = false
	if doubleCheck {
		doubleCheckTypePointersOfType(s, typ, dst, size)
	}

	var tp typePointers
	if typ != nil {
		tp = s.typePointersOfType(typ, dst)
	} else {
		tp = s.typePointersOf(dst, size)
	}
	for {
		var addr uintptr
		if tp, addr = tp.next(dst + size); addr == 0 {
			break
		}
		srcx := (*uintptr)(unsafe.Pointer(addr - dst + src))
		p := buf.get1()
		p[0] = *srcx
	}
}

// initHeapBits initializes the heap bitmap for a span.
func (s *mspan) initHeapBits() {
	if goarch.PtrSize == 8 && !s.spanclass.noscan() && s.spanclass.sizeclass() == 1 {
		b := s.heapBits()
		for i := range b {
			b[i] = ^uintptr(0)
		}
	} else if (!s.spanclass.noscan() && heapBitsInSpan(s.elemsize)) || s.isUserArenaChunk {
		b := s.heapBits()
		clear(b)
	}
}

// heapBits returns the heap ptr/scalar bits stored at the end of the span for
// small object spans and heap arena spans.
//
// Note that the uintptr of each element means something different for small object
// spans and for heap arena spans. Small object spans are easy: they're never interpreted
// as anything but uintptr, so they're immune to differences in endianness. However, the
// heapBits for user arena spans is exposed through a dummy type descriptor, so the byte
// ordering needs to match the same byte ordering the compiler would emit. The compiler always
// emits the bitmap data in little endian byte ordering, so on big endian platforms these
// uintptrs will have their byte orders swapped from what they normally would be.
//
// heapBitsInSpan(span.elemsize) or span.isUserArenaChunk must be true.
//
//go:nosplit
func (span *mspan) heapBits() []uintptr {
	const doubleCheck = false

	if doubleCheck && !span.isUserArenaChunk {
		if span.spanclass.noscan() {
			throw("heapBits called for noscan")
		}
		if span.elemsize > minSizeForMallocHeader {
			throw("heapBits called for span class that should have a malloc header")
		}
	}
	// Find the bitmap at the end of the span.
	//
	// Nearly every span with heap bits is exactly one page in size. Arenas are the only exception.
	if span.npages == 1 {
		// This will be inlined and constant-folded down.
		return heapBitsSlice(span.base(), pageSize)
	}
	return heapBitsSlice(span.base(), span.npages*pageSize)
}

// Helper for constructing a slice for the span's heap bits.
//
//go:nosplit
func heapBitsSlice(spanBase, spanSize uintptr) []uintptr {
	bitmapSize := spanSize / goarch.PtrSize / 8
	elems := int(bitmapSize / goarch.PtrSize)
	var sl notInHeapSlice
	sl = notInHeapSlice{(*notInHeap)(unsafe.Pointer(spanBase + spanSize - bitmapSize)), elems, elems}
	return *(*[]uintptr)(unsafe.Pointer(&sl))
}

// heapBitsSmallForAddr loads the heap bits for the object stored at addr from span.heapBits.
//
// addr must be the base pointer of an object in the span. heapBitsInSpan(span.elemsize)
// must be true.
//
//go:nosplit
func (span *mspan) heapBitsSmallForAddr(addr uintptr) uintptr {
	spanSize := span.npages * pageSize
	bitmapSize := spanSize / goarch.PtrSize / 8
	hbits := (*byte)(unsafe.Pointer(span.base() + spanSize - bitmapSize))

	// These objects are always small enough that their bitmaps
	// fit in a single word, so just load the word or two we need.
	//
	// Mirrors mspan.writeHeapBitsSmall.
	//
	// We should be using heapBits(), but unfortunately it introduces
	// both bounds checks panics and throw which causes us to exceed
	// the nosplit limit in quite a few cases.
	i := (addr - span.base()) / goarch.PtrSize / ptrBits
	j := (addr - span.base()) / goarch.PtrSize % ptrBits
	bits := span.elemsize / goarch.PtrSize
	word0 := (*uintptr)(unsafe.Pointer(addb(hbits, goarch.PtrSize*(i+0))))
	word1 := (*uintptr)(unsafe.Pointer(addb(hbits, goarch.PtrSize*(i+1))))

	var read uintptr
	if j+bits > ptrBits {
		// Two reads.
		bits0 := ptrBits - j
		bits1 := bits - bits0
		read = *word0 >> j
		read |= (*word1 & ((1 << bits1) - 1)) << bits0
	} else {
		// One read.
		read = (*word0 >> j) & ((1 << bits) - 1)
	}
	return read
}

// writeHeapBitsSmall writes the heap bits for small objects whose ptr/scalar data is
// stored as a bitmap at the end of the span.
//
// Assumes dataSize is <= ptrBits*goarch.PtrSize. x must be a pointer into the span.
// heapBitsInSpan(dataSize) must be true. dataSize must be >= typ.Size_.
//
//go:nosplit
func (span *mspan) writeHeapBitsSmall(x, dataSize uintptr, typ *_type) (scanSize uintptr) {
	// The objects here are always really small, so a single load is sufficient.
	src0 := readUintptr(getGCMask(typ))

	// Create repetitions of the bitmap if we have a small slice backing store.
	scanSize = typ.PtrBytes
	src := src0
	if typ.Size_ == goarch.PtrSize {
		src = (1 << (dataSize / goarch.PtrSize)) - 1
	} else {
		// N.B. We rely on dataSize being an exact multiple of the type size.
		// The alternative is to be defensive and mask out src to the length
		// of dataSize. The purpose is to save on one additional masking operation.
		if doubleCheckHeapSetType && !asanenabled && dataSize%typ.Size_ != 0 {
			throw("runtime: (*mspan).writeHeapBitsSmall: dataSize is not a multiple of typ.Size_")
		}
		for i := typ.Size_; i < dataSize; i += typ.Size_ {
			src |= src0 << (i / goarch.PtrSize)
			scanSize += typ.Size_
		}
		if asanenabled {
			// Mask src down to dataSize. dataSize is going to be a strange size because of
			// the redzone required for allocations when asan is enabled.
			src &= (1 << (dataSize / goarch.PtrSize)) - 1
		}
	}

	// Since we're never writing more than one uintptr's worth of bits, we're either going
	// to do one or two writes.
	dst := unsafe.Pointer(span.base() + pageSize - pageSize/goarch.PtrSize/8)
	o := (x - span.base()) / goarch.PtrSize
	i := o / ptrBits
	j := o % ptrBits
	bits := span.elemsize / goarch.PtrSize
	if j+bits > ptrBits {
		// Two writes.
		bits0 := ptrBits - j
		bits1 := bits - bits0
		dst0 := (*uintptr)(add(dst, (i+0)*goarch.PtrSize))
		dst1 := (*uintptr)(add(dst, (i+1)*goarch.PtrSize))
		*dst0 = (*dst0)&(^uintptr(0)>>bits0) | (src << j)
		*dst1 = (*dst1)&^((1<<bits1)-1) | (src >> bits0)
	} else {
		// One write.
		dst := (*uintptr)(add(dst, i*goarch.PtrSize))
		*dst = (*dst)&^(((1<<bits)-1)<<j) | (src << j)
	}

	const doubleCheck = false
	if doubleCheck {
		srcRead := span.heapBitsSmallForAddr(x)
		if srcRead != src {
			print("runtime: x=", hex(x), " i=", i, " j=", j, " bits=", bits, "\n")
			print("runtime: dataSize=", dataSize, " typ.Size_=", typ.Size_, " typ.PtrBytes=", typ.PtrBytes, "\n")
			print("runtime: src0=", hex(src0), " src=", hex(src), " srcRead=", hex(srcRead), "\n")
			throw("bad pointer bits written for small object")
		}
	}
	return
}

// heapSetType* functions record that the new allocation [x, x+size)
// holds in [x, x+dataSize) one or more values of type typ.
// (The number of values is given by dataSize / typ.Size.)
// If dataSize < size, the fragment [x+dataSize, x+size) is
// recorded as non-pointer data.
// It is known that the type has pointers somewhere;
// malloc does not call heapSetType* when there are no pointers.
//
// There can be read-write races between heapSetType* and things
// that read the heap metadata like scanobject. However, since
// heapSetType* is only used for objects that have not yet been
// made reachable, readers will ignore bits being modified by this
// function. This does mean this function cannot transiently modify
// shared memory that belongs to neighboring objects. Also, on weakly-ordered
// machines, callers must execute a store/store (publication) barrier
// between calling this function and making the object reachable.

const doubleCheckHeapSetType = doubleCheckMalloc

func heapSetTypeNoHeader(x, dataSize uintptr, typ *_type, span *mspan) uintptr {
	if doubleCheckHeapSetType && (!heapBitsInSpan(dataSize) || !heapBitsInSpan(span.elemsize)) {
		throw("tried to write heap bits, but no heap bits in span")
	}
	scanSize := span.writeHeapBitsSmall(x, dataSize, typ)
	if doubleCheckHeapSetType {
		doubleCheckHeapType(x, dataSize, typ, nil, span)
	}
	return scanSize
}

func heapSetTypeSmallHeader(x, dataSize uintptr, typ *_type, header **_type, span *mspan) uintptr {
	*header = typ
	if doubleCheckHeapSetType {
		doubleCheckHeapType(x, dataSize, typ, header, span)
	}
	return span.elemsize
}

func heapSetTypeLarge(x, dataSize uintptr, typ *_type, span *mspan) uintptr {
	gctyp := typ
	// Write out the header.
	span.largeType = gctyp
	if doubleCheckHeapSetType {
		doubleCheckHeapType(x, dataSize, typ, &span.largeType, span)
	}
	return span.elemsize
}

func doubleCheckHeapType(x, dataSize uintptr, gctyp *_type, header **_type, span *mspan) {
	doubleCheckHeapPointers(x, dataSize, gctyp, header, span)

	// To exercise the less common path more often, generate
	// a random interior pointer and make sure iterating from
	// that point works correctly too.
	maxIterBytes := span.elemsize
	if header == nil {
		maxIterBytes = dataSize
	}
	off := alignUp(uintptr(cheaprand())%dataSize, goarch.PtrSize)
	size := dataSize - off
	if size == 0 {
		off -= goarch.PtrSize
		size += goarch.PtrSize
	}
	interior := x + off
	size -= alignDown(uintptr(cheaprand())%size, goarch.PtrSize)
	if size == 0 {
		size = goarch.PtrSize
	}
	// Round up the type to the size of the type.
	size = (size + gctyp.Size_ - 1) / gctyp.Size_ * gctyp.Size_
	if interior+size > x+maxIterBytes {
		size = x + maxIterBytes - interior
	}
	doubleCheckHeapPointersInterior(x, interior, size, dataSize, gctyp, header, span)
}

func doubleCheckHeapPointers(x, dataSize uintptr, typ *_type, header **_type, span *mspan) {
	// Check that scanning the full object works.
	tp := span.typePointersOfUnchecked(span.objBase(x))
	maxIterBytes := span.elemsize
	if header == nil {
		maxIterBytes = dataSize
	}
	bad := false
	for i := uintptr(0); i < maxIterBytes; i += goarch.PtrSize {
		// Compute the pointer bit we want at offset i.
		want := false
		if i < span.elemsize {
			off := i % typ.Size_
			if off < typ.PtrBytes {
				j := off / goarch.PtrSize
				want = *addb(getGCMask(typ), j/8)>>(j%8)&1 != 0
			}
		}
		if want {
			var addr uintptr
			tp, addr = tp.next(x + span.elemsize)
			if addr == 0 {
				println("runtime: found bad iterator")
			}
			if addr != x+i {
				print("runtime: addr=", hex(addr), " x+i=", hex(x+i), "\n")
				bad = true
			}
		}
	}
	if !bad {
		var addr uintptr
		tp, addr = tp.next(x + span.elemsize)
		if addr == 0 {
			return
		}
		println("runtime: extra pointer:", hex(addr))
	}
	print("runtime: hasHeader=", header != nil, " typ.Size_=", typ.Size_, " TFlagGCMaskOnDemaind=", typ.TFlag&abi.TFlagGCMaskOnDemand != 0, "\n")
	print("runtime: x=", hex(x), " dataSize=", dataSize, " elemsize=", span.elemsize, "\n")
	print("runtime: typ=", unsafe.Pointer(typ), " typ.PtrBytes=", typ.PtrBytes, "\n")
	print("runtime: limit=", hex(x+span.elemsize), "\n")
	tp = span.typePointersOfUnchecked(x)
	dumpTypePointers(tp)
	for {
		var addr uintptr
		if tp, addr = tp.next(x + span.elemsize); addr == 0 {
			println("runtime: would've stopped here")
			dumpTypePointers(tp)
			break
		}
		print("runtime: addr=", hex(addr), "\n")
		dumpTypePointers(tp)
	}
	throw("heapSetType: pointer entry not correct")
}

func doubleCheckHeapPointersInterior(x, interior, size, dataSize uintptr, typ *_type, header **_type, span *mspan) {
	bad := false
	if interior < x {
		print("runtime: interior=", hex(interior), " x=", hex(x), "\n")
		throw("found bad interior pointer")
	}
	off := interior - x
	tp := span.typePointersOf(interior, size)
	for i := off; i < off+size; i += goarch.PtrSize {
		// Compute the pointer bit we want at offset i.
		want := false
		if i < span.elemsize {
			off := i % typ.Size_
			if off < typ.PtrBytes {
				j := off / goarch.PtrSize
				want = *addb(getGCMask(typ), j/8)>>(j%8)&1 != 0
			}
		}
		if want {
			var addr uintptr
			tp, addr = tp.next(interior + size)
			if addr == 0 {
				println("runtime: found bad iterator")
				bad = true
			}
			if addr != x+i {
				print("runtime: addr=", hex(addr), " x+i=", hex(x+i), "\n")
				bad = true
			}
		}
	}
	if !bad {
		var addr uintptr
		tp, addr = tp.next(interior + size)
		if addr == 0 {
			return
		}
		println("runtime: extra pointer:", hex(addr))
	}
	print("runtime: hasHeader=", header != nil, " typ.Size_=", typ.Size_, "\n")
	print("runtime: x=", hex(x), " dataSize=", dataSize, " elemsize=", span.elemsize, " interior=", hex(interior), " size=", size, "\n")
	print("runtime: limit=", hex(interior+size), "\n")
	tp = span.typePointersOf(interior, size)
	dumpTypePointers(tp)
	for {
		var addr uintptr
		if tp, addr = tp.next(interior + size); addr == 0 {
			println("runtime: would've stopped here")
			dumpTypePointers(tp)
			break
		}
		print("runtime: addr=", hex(addr), "\n")
		dumpTypePointers(tp)
	}

	print("runtime: want: ")
	for i := off; i < off+size; i += goarch.PtrSize {
		// Compute the pointer bit we want at offset i.
		want := false
		if i < dataSize {
			off := i % typ.Size_
			if off < typ.PtrBytes {
				j := off / goarch.PtrSize
				want = *addb(getGCMask(typ), j/8)>>(j%8)&1 != 0
			}
		}
		if want {
			print("1")
		} else {
			print("0")
		}
	}
	println()

	throw("heapSetType: pointer entry not correct")
}

//go:nosplit
func doubleCheckTypePointersOfType(s *mspan, typ *_type, addr, size uintptr) {
	if typ == nil {
		return
	}
	if typ.Kind_&abi.KindMask == abi.Interface {
		// Interfaces are unfortunately inconsistently handled
		// when it comes to the type pointer, so it's easy to
		// produce a lot of false positives here.
		return
	}
	tp0 := s.typePointersOfType(typ, addr)
	tp1 := s.typePointersOf(addr, size)
	failed := false
	for {
		var addr0, addr1 uintptr
		tp0, addr0 = tp0.next(addr + size)
		tp1, addr1 = tp1.next(addr + size)
		if addr0 != addr1 {
			failed = true
			break
		}
		if addr0 == 0 {
			break
		}
	}
	if failed {
		tp0 := s.typePointersOfType(typ, addr)
		tp1 := s.typePointersOf(addr, size)
		print("runtime: addr=", hex(addr), " size=", size, "\n")
		print("runtime: type=", toRType(typ).string(), "\n")
		dumpTypePointers(tp0)
		dumpTypePointers(tp1)
		for {
			var addr0, addr1 uintptr
			tp0, addr0 = tp0.next(addr + size)
			tp1, addr1 = tp1.next(addr + size)
			print("runtime: ", hex(addr0), " ", hex(a
```