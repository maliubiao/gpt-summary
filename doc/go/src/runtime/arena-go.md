Response:
My thought process for analyzing the provided Go code snippet and generating the summary involved several steps:

1. **Initial Reading and Keyword Identification:** I first read through the entire code, focusing on comments and function names. Keywords like "arena," "chunk," "allocate," "free," "GC," "mspan," "heap," "fault," and "quarantine" immediately stood out as being central to the functionality.

2. **Understanding the Core Concept:**  The comments clearly explain the purpose: implementing user-managed arenas for memory allocation. This allows for bulk allocation and freeing, potentially improving performance by reducing GC frequency. The "safe" aspect, despite manual freeing, is highlighted by the faulting mechanism upon access after freeing.

3. **Tracing the Lifecycle:** The comments and the `// In summary, there are 2 resources...` section provide a high-level lifecycle of arenas and chunks. I mentally mapped out the transitions between states (creation, allocation, freeing, quarantining, reuse). This lifecycle became a key element in my summary.

4. **Analyzing Key Data Structures:**  I identified the crucial data structures:
    * `userArena`: Represents the user-facing arena, containing lists of full and active chunks, and references.
    * `mspan`: Represents a chunk of memory, a fundamental building block managed by the Go runtime's memory management. The code emphasizes how arena chunks *are* `mspan`s, but reserved for arena usage.
    * `userArenaState`: Holds global state related to arena management (reuse and fault lists).

5. **Dissecting Function Responsibilities:** I examined the purpose of the exported (`arena_...`) and internal functions:
    * `arena_newArena`: Creates a new user arena.
    * `arena_arena_New`: Allocates a single object in an arena.
    * `arena_arena_Slice`: Allocates a slice backing store in an arena.
    * `arena_arena_Free`: Frees an arena.
    * `arena_heapify`: Moves data from an arena to the regular heap.
    * `newUserArena`: The internal implementation of arena creation.
    * `alloc`, `refill`: Internal allocation logic.
    * `freeUserArenaChunk`, `setUserArenaChunkToFault`: Mechanisms for releasing and faulting chunks.

6. **Identifying Safety Mechanisms:** I noted the explanations of the safety features:
    * Faulting on access after free.
    * Quarantining chunks to prevent reuse until the GC confirms no more pointers exist.
    * Finalizers to ensure arenas are freed even if the user forgets.
    * Checks for double-frees.

7. **Extracting Key Details and Constraints:**  I paid attention to specific details:
    * Chunk size and its relationship to `heapArenaBytes`.
    * The bump allocation strategy (pointerful from low to high, pointer-free from high to low).
    * Non-concurrency safety of arenas.
    * The maximum allocation size within an arena chunk.

8. **Synthesizing the Summary:**  Based on the above analysis, I began formulating the summary, aiming for clarity and conciseness. I focused on:
    * **Core Purpose:** The main goal of the code.
    * **Key Components:** The essential entities involved (arenas and chunks).
    * **Lifecycle Management:** How arenas and chunks are created, used, and destroyed.
    * **Safety Aspects:**  The mechanisms preventing memory corruption.
    * **Performance Implications:** The intended benefits.

9. **Refining the Language:** I used clear and straightforward Chinese, avoiding overly technical jargon where possible while still maintaining accuracy. I ensured the summary flowed logically and covered the most important aspects. I used terms like "用户级内存分配," "批量分配和释放," and "故障处理" to accurately reflect the code's functionality in Chinese.

Essentially, my approach was to read for understanding, identify the core concepts and entities, trace the flow of operations, and then synthesize the information into a concise and informative summary. The provided comments within the code were invaluable in this process.
这段Go语言代码实现了**用户级内存 Arena (User Arena)** 的功能。

**功能归纳:**

这段代码的核心目标是提供一种**用户可控的、批量分配和释放内存**的机制，与Go语言自带的垃圾回收机制形成补充。  其主要功能可以归纳为：

1. **创建和管理用户 Arena:**  允许用户创建一个独立的内存区域 (Arena)。
2. **在 Arena 中分配内存:**  提供 `new` 和 `slice` 方法，允许用户在指定的 Arena 中分配单个对象或切片的底层存储空间。
3. **批量释放 Arena 内存:**  提供 `free` 方法，允许用户一次性释放整个 Arena 中分配的所有内存。
4. **安全性保障:**  当 Arena 被释放后，如果程序尝试访问该 Arena 的内存，会触发程序错误，防止内存损坏。通过“隔离”机制，确保已释放的 Arena 内存不会被立即重用，直到没有指向它的指针为止。
5. **与 GC 的协作:**  Arena 的实现需要与 Go 的垃圾回收器协同工作，确保 Arena 中的对象能被正确扫描和管理。
6. **优化内存分配:**  Arena 内部使用了 Bump Allocation 的策略，对于指针类型和非指针类型的数据采用不同的分配方向，以利用 GC 的优化，并避免清零非指针类型数据的 Heap Bitmap。
7. **内存复用:**  当 Arena 被释放后，部分使用的 Chunk 会被放入重用列表，以便下次创建 Arena 时可以快速复用，减少内存分配的开销。

**更具体地拆解其功能:**

* **`arena_newArena()`:**  创建一个新的用户 Arena 对象。
* **`arena_arena_New(arena unsafe.Pointer, typ any)`:** 在指定的 Arena 中分配一个类型为 `typ` 的对象的内存，返回指向该对象的指针。
* **`arena_arena_Slice(arena unsafe.Pointer, slice any, cap int)`:** 在指定的 Arena 中为切片 `slice` 分配一个容量为 `cap` 的底层数组。
* **`arena_arena_Free(arena unsafe.Pointer)`:** 释放指定的 Arena 中分配的所有内存。
* **`arena_heapify(s any)`:** 将 Arena 中分配的值复制到 Go 的堆上。
* **内存块 (Chunk) 管理:**  Arena 的底层是将内存划分为固定大小的 Chunk 进行管理。代码中定义了 Chunk 的大小 `userArenaChunkBytes`。
* **Chunk 的分配与回收:**  从操作系统映射新的内存，或者重用之前释放的 Chunk。释放的 Chunk 会被标记为 “故障” (fault)，防止被意外访问，并进入 “隔离” 状态，等待 GC 确认没有指针指向它之后才能被重用。
* **`userArena` 结构体:**  表示一个用户 Arena，包含已满的 Chunk 列表、当前正在使用的 Chunk 以及指向这些 Chunk 的指针列表，以确保它们不会被 GC 回收。
* **Bump Allocation:**  在 Chunk 内部进行内存分配时，采用 Bump Allocation 策略，维护一个指向下一个空闲位置的指针。
* **与 GC 的交互:**  当 Arena 中的对象包含指针时，需要设置 Heap Bitmap，以便 GC 能够正确扫描这些指针。

**总结:**

这段代码提供了一套机制，允许 Go 程序员在某些特定场景下，手动管理一部分内存的生命周期。这可以用来优化内存分配，减少 GC 的压力，并提高程序性能，但同时也需要程序员更加谨慎地管理内存，避免出现 use-after-free 等问题。  其核心思想是在 Go 的自动内存管理之上，提供一种更精细的手动控制方式。

Prompt: 
```
这是路径为go/src/runtime/arena.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Implementation of (safe) user arenas.
//
// This file contains the implementation of user arenas wherein Go values can
// be manually allocated and freed in bulk. The act of manually freeing memory,
// potentially before a GC cycle, means that a garbage collection cycle can be
// delayed, improving efficiency by reducing GC cycle frequency. There are other
// potential efficiency benefits, such as improved locality and access to a more
// efficient allocation strategy.
//
// What makes the arenas here safe is that once they are freed, accessing the
// arena's memory will cause an explicit program fault, and the arena's address
// space will not be reused until no more pointers into it are found. There's one
// exception to this: if an arena allocated memory that isn't exhausted, it's placed
// back into a pool for reuse. This means that a crash is not always guaranteed.
//
// While this may seem unsafe, it still prevents memory corruption, and is in fact
// necessary in order to make new(T) a valid implementation of arenas. Such a property
// is desirable to allow for a trivial implementation. (It also avoids complexities
// that arise from synchronization with the GC when trying to set the arena chunks to
// fault while the GC is active.)
//
// The implementation works in layers. At the bottom, arenas are managed in chunks.
// Each chunk must be a multiple of the heap arena size, or the heap arena size must
// be divisible by the arena chunks. The address space for each chunk, and each
// corresponding heapArena for that address space, are eternally reserved for use as
// arena chunks. That is, they can never be used for the general heap. Each chunk
// is also represented by a single mspan, and is modeled as a single large heap
// allocation. It must be, because each chunk contains ordinary Go values that may
// point into the heap, so it must be scanned just like any other object. Any
// pointer into a chunk will therefore always cause the whole chunk to be scanned
// while its corresponding arena is still live.
//
// Chunks may be allocated either from new memory mapped by the OS on our behalf,
// or by reusing old freed chunks. When chunks are freed, their underlying memory
// is returned to the OS, set to fault on access, and may not be reused until the
// program doesn't point into the chunk anymore (the code refers to this state as
// "quarantined"), a property checked by the GC.
//
// The sweeper handles moving chunks out of this quarantine state to be ready for
// reuse. When the chunk is placed into the quarantine state, its corresponding
// span is marked as noscan so that the GC doesn't try to scan memory that would
// cause a fault.
//
// At the next layer are the user arenas themselves. They consist of a single
// active chunk which new Go values are bump-allocated into and a list of chunks
// that were exhausted when allocating into the arena. Once the arena is freed,
// it frees all full chunks it references, and places the active one onto a reuse
// list for a future arena to use. Each arena keeps its list of referenced chunks
// explicitly live until it is freed. Each user arena also maps to an object which
// has a finalizer attached that ensures the arena's chunks are all freed even if
// the arena itself is never explicitly freed.
//
// Pointer-ful memory is bump-allocated from low addresses to high addresses in each
// chunk, while pointer-free memory is bump-allocated from high address to low
// addresses. The reason for this is to take advantage of a GC optimization wherein
// the GC will stop scanning an object when there are no more pointers in it, which
// also allows us to elide clearing the heap bitmap for pointer-free Go values
// allocated into arenas.
//
// Note that arenas are not safe to use concurrently.
//
// In summary, there are 2 resources: arenas, and arena chunks. They exist in the
// following lifecycle:
//
// (1) A new arena is created via newArena.
// (2) Chunks are allocated to hold memory allocated into the arena with new or slice.
//    (a) Chunks are first allocated from the reuse list of partially-used chunks.
//    (b) If there are no such chunks, then chunks on the ready list are taken.
//    (c) Failing all the above, memory for a new chunk is mapped.
// (3) The arena is freed, or all references to it are dropped, triggering its finalizer.
//    (a) If the GC is not active, exhausted chunks are set to fault and placed on a
//        quarantine list.
//    (b) If the GC is active, exhausted chunks are placed on a fault list and will
//        go through step (a) at a later point in time.
//    (c) Any remaining partially-used chunk is placed on a reuse list.
// (4) Once no more pointers are found into quarantined arena chunks, the sweeper
//     takes these chunks out of quarantine and places them on the ready list.

package runtime

import (
	"internal/abi"
	"internal/goarch"
	"internal/runtime/atomic"
	"internal/runtime/math"
	"internal/runtime/sys"
	"unsafe"
)

// Functions starting with arena_ are meant to be exported to downstream users
// of arenas. They should wrap these functions in a higher-lever API.
//
// The underlying arena and its resources are managed through an opaque unsafe.Pointer.

// arena_newArena is a wrapper around newUserArena.
//
//go:linkname arena_newArena arena.runtime_arena_newArena
func arena_newArena() unsafe.Pointer {
	return unsafe.Pointer(newUserArena())
}

// arena_arena_New is a wrapper around (*userArena).new, except that typ
// is an any (must be a *_type, still) and typ must be a type descriptor
// for a pointer to the type to actually be allocated, i.e. pass a *T
// to allocate a T. This is necessary because this function returns a *T.
//
//go:linkname arena_arena_New arena.runtime_arena_arena_New
func arena_arena_New(arena unsafe.Pointer, typ any) any {
	t := (*_type)(efaceOf(&typ).data)
	if t.Kind_&abi.KindMask != abi.Pointer {
		throw("arena_New: non-pointer type")
	}
	te := (*ptrtype)(unsafe.Pointer(t)).Elem
	x := ((*userArena)(arena)).new(te)
	var result any
	e := efaceOf(&result)
	e._type = t
	e.data = x
	return result
}

// arena_arena_Slice is a wrapper around (*userArena).slice.
//
//go:linkname arena_arena_Slice arena.runtime_arena_arena_Slice
func arena_arena_Slice(arena unsafe.Pointer, slice any, cap int) {
	((*userArena)(arena)).slice(slice, cap)
}

// arena_arena_Free is a wrapper around (*userArena).free.
//
//go:linkname arena_arena_Free arena.runtime_arena_arena_Free
func arena_arena_Free(arena unsafe.Pointer) {
	((*userArena)(arena)).free()
}

// arena_heapify takes a value that lives in an arena and makes a copy
// of it on the heap. Values that don't live in an arena are returned unmodified.
//
//go:linkname arena_heapify arena.runtime_arena_heapify
func arena_heapify(s any) any {
	var v unsafe.Pointer
	e := efaceOf(&s)
	t := e._type
	switch t.Kind_ & abi.KindMask {
	case abi.String:
		v = stringStructOf((*string)(e.data)).str
	case abi.Slice:
		v = (*slice)(e.data).array
	case abi.Pointer:
		v = e.data
	default:
		panic("arena: Clone only supports pointers, slices, and strings")
	}
	span := spanOf(uintptr(v))
	if span == nil || !span.isUserArenaChunk {
		// Not stored in a user arena chunk.
		return s
	}
	// Heap-allocate storage for a copy.
	var x any
	switch t.Kind_ & abi.KindMask {
	case abi.String:
		s1 := s.(string)
		s2, b := rawstring(len(s1))
		copy(b, s1)
		x = s2
	case abi.Slice:
		len := (*slice)(e.data).len
		et := (*slicetype)(unsafe.Pointer(t)).Elem
		sl := new(slice)
		*sl = slice{makeslicecopy(et, len, len, (*slice)(e.data).array), len, len}
		xe := efaceOf(&x)
		xe._type = t
		xe.data = unsafe.Pointer(sl)
	case abi.Pointer:
		et := (*ptrtype)(unsafe.Pointer(t)).Elem
		e2 := newobject(et)
		typedmemmove(et, e2, e.data)
		xe := efaceOf(&x)
		xe._type = t
		xe.data = e2
	}
	return x
}

const (
	// userArenaChunkBytes is the size of a user arena chunk.
	userArenaChunkBytesMax = 8 << 20
	userArenaChunkBytes    = uintptr(int64(userArenaChunkBytesMax-heapArenaBytes)&(int64(userArenaChunkBytesMax-heapArenaBytes)>>63) + heapArenaBytes) // min(userArenaChunkBytesMax, heapArenaBytes)

	// userArenaChunkPages is the number of pages a user arena chunk uses.
	userArenaChunkPages = userArenaChunkBytes / pageSize

	// userArenaChunkMaxAllocBytes is the maximum size of an object that can
	// be allocated from an arena. This number is chosen to cap worst-case
	// fragmentation of user arenas to 25%. Larger allocations are redirected
	// to the heap.
	userArenaChunkMaxAllocBytes = userArenaChunkBytes / 4
)

func init() {
	if userArenaChunkPages*pageSize != userArenaChunkBytes {
		throw("user arena chunk size is not a multiple of the page size")
	}
	if userArenaChunkBytes%physPageSize != 0 {
		throw("user arena chunk size is not a multiple of the physical page size")
	}
	if userArenaChunkBytes < heapArenaBytes {
		if heapArenaBytes%userArenaChunkBytes != 0 {
			throw("user arena chunk size is smaller than a heap arena, but doesn't divide it")
		}
	} else {
		if userArenaChunkBytes%heapArenaBytes != 0 {
			throw("user arena chunks size is larger than a heap arena, but not a multiple")
		}
	}
	lockInit(&userArenaState.lock, lockRankUserArenaState)
}

// userArenaChunkReserveBytes returns the amount of additional bytes to reserve for
// heap metadata.
func userArenaChunkReserveBytes() uintptr {
	// In the allocation headers experiment, we reserve the end of the chunk for
	// a pointer/scalar bitmap. We also reserve space for a dummy _type that
	// refers to the bitmap. The PtrBytes field of the dummy _type indicates how
	// many of those bits are valid.
	return userArenaChunkBytes/goarch.PtrSize/8 + unsafe.Sizeof(_type{})
}

type userArena struct {
	// fullList is a list of full chunks that have not enough free memory left, and
	// that we'll free once this user arena is freed.
	//
	// Can't use mSpanList here because it's not-in-heap.
	fullList *mspan

	// active is the user arena chunk we're currently allocating into.
	active *mspan

	// refs is a set of references to the arena chunks so that they're kept alive.
	//
	// The last reference in the list always refers to active, while the rest of
	// them correspond to fullList. Specifically, the head of fullList is the
	// second-to-last one, fullList.next is the third-to-last, and so on.
	//
	// In other words, every time a new chunk becomes active, its appended to this
	// list.
	refs []unsafe.Pointer

	// defunct is true if free has been called on this arena.
	//
	// This is just a best-effort way to discover a concurrent allocation
	// and free. Also used to detect a double-free.
	defunct atomic.Bool
}

// newUserArena creates a new userArena ready to be used.
func newUserArena() *userArena {
	a := new(userArena)
	SetFinalizer(a, func(a *userArena) {
		// If arena handle is dropped without being freed, then call
		// free on the arena, so the arena chunks are never reclaimed
		// by the garbage collector.
		a.free()
	})
	a.refill()
	return a
}

// new allocates a new object of the provided type into the arena, and returns
// its pointer.
//
// This operation is not safe to call concurrently with other operations on the
// same arena.
func (a *userArena) new(typ *_type) unsafe.Pointer {
	return a.alloc(typ, -1)
}

// slice allocates a new slice backing store. slice must be a pointer to a slice
// (i.e. *[]T), because userArenaSlice will update the slice directly.
//
// cap determines the capacity of the slice backing store and must be non-negative.
//
// This operation is not safe to call concurrently with other operations on the
// same arena.
func (a *userArena) slice(sl any, cap int) {
	if cap < 0 {
		panic("userArena.slice: negative cap")
	}
	i := efaceOf(&sl)
	typ := i._type
	if typ.Kind_&abi.KindMask != abi.Pointer {
		panic("slice result of non-ptr type")
	}
	typ = (*ptrtype)(unsafe.Pointer(typ)).Elem
	if typ.Kind_&abi.KindMask != abi.Slice {
		panic("slice of non-ptr-to-slice type")
	}
	typ = (*slicetype)(unsafe.Pointer(typ)).Elem
	// t is now the element type of the slice we want to allocate.

	*((*slice)(i.data)) = slice{a.alloc(typ, cap), cap, cap}
}

// free returns the userArena's chunks back to mheap and marks it as defunct.
//
// Must be called at most once for any given arena.
//
// This operation is not safe to call concurrently with other operations on the
// same arena.
func (a *userArena) free() {
	// Check for a double-free.
	if a.defunct.Load() {
		panic("arena double free")
	}

	// Mark ourselves as defunct.
	a.defunct.Store(true)
	SetFinalizer(a, nil)

	// Free all the full arenas.
	//
	// The refs on this list are in reverse order from the second-to-last.
	s := a.fullList
	i := len(a.refs) - 2
	for s != nil {
		a.fullList = s.next
		s.next = nil
		freeUserArenaChunk(s, a.refs[i])
		s = a.fullList
		i--
	}
	if a.fullList != nil || i >= 0 {
		// There's still something left on the full list, or we
		// failed to actually iterate over the entire refs list.
		throw("full list doesn't match refs list in length")
	}

	// Put the active chunk onto the reuse list.
	//
	// Note that active's reference is always the last reference in refs.
	s = a.active
	if s != nil {
		if raceenabled || msanenabled || asanenabled {
			// Don't reuse arenas with sanitizers enabled. We want to catch
			// any use-after-free errors aggressively.
			freeUserArenaChunk(s, a.refs[len(a.refs)-1])
		} else {
			lock(&userArenaState.lock)
			userArenaState.reuse = append(userArenaState.reuse, liveUserArenaChunk{s, a.refs[len(a.refs)-1]})
			unlock(&userArenaState.lock)
		}
	}
	// nil out a.active so that a race with freeing will more likely cause a crash.
	a.active = nil
	a.refs = nil
}

// alloc reserves space in the current chunk or calls refill and reserves space
// in a new chunk. If cap is negative, the type will be taken literally, otherwise
// it will be considered as an element type for a slice backing store with capacity
// cap.
func (a *userArena) alloc(typ *_type, cap int) unsafe.Pointer {
	s := a.active
	var x unsafe.Pointer
	for {
		x = s.userArenaNextFree(typ, cap)
		if x != nil {
			break
		}
		s = a.refill()
	}
	return x
}

// refill inserts the current arena chunk onto the full list and obtains a new
// one, either from the partial list or allocating a new one, both from mheap.
func (a *userArena) refill() *mspan {
	// If there's an active chunk, assume it's full.
	s := a.active
	if s != nil {
		if s.userArenaChunkFree.size() > userArenaChunkMaxAllocBytes {
			// It's difficult to tell when we're actually out of memory
			// in a chunk because the allocation that failed may still leave
			// some free space available. However, that amount of free space
			// should never exceed the maximum allocation size.
			throw("wasted too much memory in an arena chunk")
		}
		s.next = a.fullList
		a.fullList = s
		a.active = nil
		s = nil
	}
	var x unsafe.Pointer

	// Check the partially-used list.
	lock(&userArenaState.lock)
	if len(userArenaState.reuse) > 0 {
		// Pick off the last arena chunk from the list.
		n := len(userArenaState.reuse) - 1
		x = userArenaState.reuse[n].x
		s = userArenaState.reuse[n].mspan
		userArenaState.reuse[n].x = nil
		userArenaState.reuse[n].mspan = nil
		userArenaState.reuse = userArenaState.reuse[:n]
	}
	unlock(&userArenaState.lock)
	if s == nil {
		// Allocate a new one.
		x, s = newUserArenaChunk()
		if s == nil {
			throw("out of memory")
		}
	}
	a.refs = append(a.refs, x)
	a.active = s
	return s
}

type liveUserArenaChunk struct {
	*mspan // Must represent a user arena chunk.

	// Reference to mspan.base() to keep the chunk alive.
	x unsafe.Pointer
}

var userArenaState struct {
	lock mutex

	// reuse contains a list of partially-used and already-live
	// user arena chunks that can be quickly reused for another
	// arena.
	//
	// Protected by lock.
	reuse []liveUserArenaChunk

	// fault contains full user arena chunks that need to be faulted.
	//
	// Protected by lock.
	fault []liveUserArenaChunk
}

// userArenaNextFree reserves space in the user arena for an item of the specified
// type. If cap is not -1, this is for an array of cap elements of type t.
func (s *mspan) userArenaNextFree(typ *_type, cap int) unsafe.Pointer {
	size := typ.Size_
	if cap > 0 {
		if size > ^uintptr(0)/uintptr(cap) {
			// Overflow.
			throw("out of memory")
		}
		size *= uintptr(cap)
	}
	if size == 0 || cap == 0 {
		return unsafe.Pointer(&zerobase)
	}
	if size > userArenaChunkMaxAllocBytes {
		// Redirect allocations that don't fit into a chunk well directly
		// from the heap.
		if cap >= 0 {
			return newarray(typ, cap)
		}
		return newobject(typ)
	}

	// Prevent preemption as we set up the space for a new object.
	//
	// Act like we're allocating.
	mp := acquirem()
	if mp.mallocing != 0 {
		throw("malloc deadlock")
	}
	if mp.gsignal == getg() {
		throw("malloc during signal")
	}
	mp.mallocing = 1

	var ptr unsafe.Pointer
	if !typ.Pointers() {
		// Allocate pointer-less objects from the tail end of the chunk.
		v, ok := s.userArenaChunkFree.takeFromBack(size, typ.Align_)
		if ok {
			ptr = unsafe.Pointer(v)
		}
	} else {
		v, ok := s.userArenaChunkFree.takeFromFront(size, typ.Align_)
		if ok {
			ptr = unsafe.Pointer(v)
		}
	}
	if ptr == nil {
		// Failed to allocate.
		mp.mallocing = 0
		releasem(mp)
		return nil
	}
	if s.needzero != 0 {
		throw("arena chunk needs zeroing, but should already be zeroed")
	}
	// Set up heap bitmap and do extra accounting.
	if typ.Pointers() {
		if cap >= 0 {
			userArenaHeapBitsSetSliceType(typ, cap, ptr, s)
		} else {
			userArenaHeapBitsSetType(typ, ptr, s)
		}
		c := getMCache(mp)
		if c == nil {
			throw("mallocgc called without a P or outside bootstrapping")
		}
		if cap > 0 {
			c.scanAlloc += size - (typ.Size_ - typ.PtrBytes)
		} else {
			c.scanAlloc += typ.PtrBytes
		}
	}

	// Ensure that the stores above that initialize x to
	// type-safe memory and set the heap bits occur before
	// the caller can make ptr observable to the garbage
	// collector. Otherwise, on weakly ordered machines,
	// the garbage collector could follow a pointer to x,
	// but see uninitialized memory or stale heap bits.
	publicationBarrier()

	mp.mallocing = 0
	releasem(mp)

	return ptr
}

// userArenaHeapBitsSetSliceType is the equivalent of heapBitsSetType but for
// Go slice backing store values allocated in a user arena chunk. It sets up the
// heap bitmap for n consecutive values with type typ allocated at address ptr.
func userArenaHeapBitsSetSliceType(typ *_type, n int, ptr unsafe.Pointer, s *mspan) {
	mem, overflow := math.MulUintptr(typ.Size_, uintptr(n))
	if overflow || n < 0 || mem > maxAlloc {
		panic(plainError("runtime: allocation size out of range"))
	}
	for i := 0; i < n; i++ {
		userArenaHeapBitsSetType(typ, add(ptr, uintptr(i)*typ.Size_), s)
	}
}

// userArenaHeapBitsSetType is the equivalent of heapSetType but for
// non-slice-backing-store Go values allocated in a user arena chunk. It
// sets up the type metadata for the value with type typ allocated at address ptr.
// base is the base address of the arena chunk.
func userArenaHeapBitsSetType(typ *_type, ptr unsafe.Pointer, s *mspan) {
	base := s.base()
	h := s.writeUserArenaHeapBits(uintptr(ptr))

	p := getGCMask(typ) // start of 1-bit pointer mask
	nb := typ.PtrBytes / goarch.PtrSize

	for i := uintptr(0); i < nb; i += ptrBits {
		k := nb - i
		if k > ptrBits {
			k = ptrBits
		}
		// N.B. On big endian platforms we byte swap the data that we
		// read from GCData, which is always stored in little-endian order
		// by the compiler. writeUserArenaHeapBits handles data in
		// a platform-ordered way for efficiency, but stores back the
		// data in little endian order, since we expose the bitmap through
		// a dummy type.
		h = h.write(s, readUintptr(addb(p, i/8)), k)
	}
	// Note: we call pad here to ensure we emit explicit 0 bits
	// for the pointerless tail of the object. This ensures that
	// there's only a single noMorePtrs mark for the next object
	// to clear. We don't need to do this to clear stale noMorePtrs
	// markers from previous uses because arena chunk pointer bitmaps
	// are always fully cleared when reused.
	h = h.pad(s, typ.Size_-typ.PtrBytes)
	h.flush(s, uintptr(ptr), typ.Size_)

	// Update the PtrBytes value in the type information. After this
	// point, the GC will observe the new bitmap.
	s.largeType.PtrBytes = uintptr(ptr) - base + typ.PtrBytes

	// Double-check that the bitmap was written out correctly.
	const doubleCheck = false
	if doubleCheck {
		doubleCheckHeapPointersInterior(uintptr(ptr), uintptr(ptr), typ.Size_, typ.Size_, typ, &s.largeType, s)
	}
}

type writeUserArenaHeapBits struct {
	offset uintptr // offset in span that the low bit of mask represents the pointer state of.
	mask   uintptr // some pointer bits starting at the address addr.
	valid  uintptr // number of bits in buf that are valid (including low)
	low    uintptr // number of low-order bits to not overwrite
}

func (s *mspan) writeUserArenaHeapBits(addr uintptr) (h writeUserArenaHeapBits) {
	offset := addr - s.base()

	// We start writing bits maybe in the middle of a heap bitmap word.
	// Remember how many bits into the word we started, so we can be sure
	// not to overwrite the previous bits.
	h.low = offset / goarch.PtrSize % ptrBits

	// round down to heap word that starts the bitmap word.
	h.offset = offset - h.low*goarch.PtrSize

	// We don't have any bits yet.
	h.mask = 0
	h.valid = h.low

	return
}

// write appends the pointerness of the next valid pointer slots
// using the low valid bits of bits. 1=pointer, 0=scalar.
func (h writeUserArenaHeapBits) write(s *mspan, bits, valid uintptr) writeUserArenaHeapBits {
	if h.valid+valid <= ptrBits {
		// Fast path - just accumulate the bits.
		h.mask |= bits << h.valid
		h.valid += valid
		return h
	}
	// Too many bits to fit in this word. Write the current word
	// out and move on to the next word.

	data := h.mask | bits<<h.valid       // mask for this word
	h.mask = bits >> (ptrBits - h.valid) // leftover for next word
	h.valid += valid - ptrBits           // have h.valid+valid bits, writing ptrBits of them

	// Flush mask to the memory bitmap.
	idx := h.offset / (ptrBits * goarch.PtrSize)
	m := uintptr(1)<<h.low - 1
	bitmap := s.heapBits()
	bitmap[idx] = bswapIfBigEndian(bswapIfBigEndian(bitmap[idx])&m | data)
	// Note: no synchronization required for this write because
	// the allocator has exclusive access to the page, and the bitmap
	// entries are all for a single page. Also, visibility of these
	// writes is guaranteed by the publication barrier in mallocgc.

	// Move to next word of bitmap.
	h.offset += ptrBits * goarch.PtrSize
	h.low = 0
	return h
}

// Add padding of size bytes.
func (h writeUserArenaHeapBits) pad(s *mspan, size uintptr) writeUserArenaHeapBits {
	if size == 0 {
		return h
	}
	words := size / goarch.PtrSize
	for words > ptrBits {
		h = h.write(s, 0, ptrBits)
		words -= ptrBits
	}
	return h.write(s, 0, words)
}

// Flush the bits that have been written, and add zeros as needed
// to cover the full object [addr, addr+size).
func (h writeUserArenaHeapBits) flush(s *mspan, addr, size uintptr) {
	offset := addr - s.base()

	// zeros counts the number of bits needed to represent the object minus the
	// number of bits we've already written. This is the number of 0 bits
	// that need to be added.
	zeros := (offset+size-h.offset)/goarch.PtrSize - h.valid

	// Add zero bits up to the bitmap word boundary
	if zeros > 0 {
		z := ptrBits - h.valid
		if z > zeros {
			z = zeros
		}
		h.valid += z
		zeros -= z
	}

	// Find word in bitmap that we're going to write.
	bitmap := s.heapBits()
	idx := h.offset / (ptrBits * goarch.PtrSize)

	// Write remaining bits.
	if h.valid != h.low {
		m := uintptr(1)<<h.low - 1      // don't clear existing bits below "low"
		m |= ^(uintptr(1)<<h.valid - 1) // don't clear existing bits above "valid"
		bitmap[idx] = bswapIfBigEndian(bswapIfBigEndian(bitmap[idx])&m | h.mask)
	}
	if zeros == 0 {
		return
	}

	// Advance to next bitmap word.
	h.offset += ptrBits * goarch.PtrSize

	// Continue on writing zeros for the rest of the object.
	// For standard use of the ptr bits this is not required, as
	// the bits are read from the beginning of the object. Some uses,
	// like noscan spans, oblets, bulk write barriers, and cgocheck, might
	// start mid-object, so these writes are still required.
	for {
		// Write zero bits.
		idx := h.offset / (ptrBits * goarch.PtrSize)
		if zeros < ptrBits {
			bitmap[idx] = bswapIfBigEndian(bswapIfBigEndian(bitmap[idx]) &^ (uintptr(1)<<zeros - 1))
			break
		} else if zeros == ptrBits {
			bitmap[idx] = 0
			break
		} else {
			bitmap[idx] = 0
			zeros -= ptrBits
		}
		h.offset += ptrBits * goarch.PtrSize
	}
}

// bswapIfBigEndian swaps the byte order of the uintptr on goarch.BigEndian platforms,
// and leaves it alone elsewhere.
func bswapIfBigEndian(x uintptr) uintptr {
	if goarch.BigEndian {
		if goarch.PtrSize == 8 {
			return uintptr(sys.Bswap64(uint64(x)))
		}
		return uintptr(sys.Bswap32(uint32(x)))
	}
	return x
}

// newUserArenaChunk allocates a user arena chunk, which maps to a single
// heap arena and single span. Returns a pointer to the base of the chunk
// (this is really important: we need to keep the chunk alive) and the span.
func newUserArenaChunk() (unsafe.Pointer, *mspan) {
	if gcphase == _GCmarktermination {
		throw("newUserArenaChunk called with gcphase == _GCmarktermination")
	}

	// Deduct assist credit. Because user arena chunks are modeled as one
	// giant heap object which counts toward heapLive, we're obligated to
	// assist the GC proportionally (and it's worth noting that the arena
	// does represent additional work for the GC, but we also have no idea
	// what that looks like until we actually allocate things into the
	// arena).
	deductAssistCredit(userArenaChunkBytes)

	// Set mp.mallocing to keep from being preempted by GC.
	mp := acquirem()
	if mp.mallocing != 0 {
		throw("malloc deadlock")
	}
	if mp.gsignal == getg() {
		throw("malloc during signal")
	}
	mp.mallocing = 1

	// Allocate a new user arena.
	var span *mspan
	systemstack(func() {
		span = mheap_.allocUserArenaChunk()
	})
	if span == nil {
		throw("out of memory")
	}
	x := unsafe.Pointer(span.base())

	// Allocate black during GC.
	// All slots hold nil so no scanning is needed.
	// This may be racing with GC so do it atomically if there can be
	// a race marking the bit.
	if gcphase != _GCoff {
		gcmarknewobject(span, span.base())
	}

	if raceenabled {
		// TODO(mknyszek): Track individual objects.
		racemalloc(unsafe.Pointer(span.base()), span.elemsize)
	}

	if msanenabled {
		// TODO(mknyszek): Track individual objects.
		msanmalloc(unsafe.Pointer(span.base()), span.elemsize)
	}

	if asanenabled {
		// TODO(mknyszek): Track individual objects.
		// N.B. span.elemsize includes a redzone already.
		rzStart := span.base() + span.elemsize
		asanpoison(unsafe.Pointer(rzStart), span.limit-rzStart)
		asanunpoison(unsafe.Pointer(span.base()), span.elemsize)
	}

	if rate := MemProfileRate; rate > 0 {
		c := getMCache(mp)
		if c == nil {
			throw("newUserArenaChunk called without a P or outside bootstrapping")
		}
		// Note cache c only valid while m acquired; see #47302
		if rate != 1 && int64(userArenaChunkBytes) < c.nextSample {
			c.nextSample -= int64(userArenaChunkBytes)
		} else {
			profilealloc(mp, unsafe.Pointer(span.base()), userArenaChunkBytes)
		}
	}
	mp.mallocing = 0
	releasem(mp)

	// Again, because this chunk counts toward heapLive, potentially trigger a GC.
	if t := (gcTrigger{kind: gcTriggerHeap}); t.test() {
		gcStart(t)
	}

	if debug.malloc {
		if inittrace.active && inittrace.id == getg().goid {
			// Init functions are executed sequentially in a single goroutine.
			inittrace.bytes += uint64(userArenaChunkBytes)
		}
	}

	// Double-check it's aligned to the physical page size. Based on the current
	// implementation this is trivially true, but it need not be in the future.
	// However, if it's not aligned to the physical page size then we can't properly
	// set it to fault later.
	if uintptr(x)%physPageSize != 0 {
		throw("user arena chunk is not aligned to the physical page size")
	}

	return x, span
}

// isUnusedUserArenaChunk indicates that the arena chunk has been set to fault
// and doesn't contain any scannable memory anymore. However, it might still be
// mSpanInUse as it sits on the quarantine list, since it needs to be swept.
//
// This is not safe to execute unless the caller has ownership of the mspan or
// the world is stopped (preemption is prevented while the relevant state changes).
//
// This is really only meant to be used by accounting tests in the runtime to
// distinguish when a span shouldn't be counted (since mSpanInUse might not be
// enough).
func (s *mspan) isUnusedUserArenaChunk() bool {
	return s.isUserArenaChunk && s.spanclass == makeSpanClass(0, true)
}

// setUserArenaChunkToFault sets the address space for the user arena chunk to fault
// and releases any underlying memory resources.
//
// Must be in a non-preemptible state to ensure the consistency of statistics
// exported to MemStats.
func (s *mspan) setUserArenaChunkToFault() {
	if !s.isUserArenaChunk {
		throw("invalid span in heapArena for user arena")
	}
	if s.npages*pageSize != userArenaChunkBytes {
		throw("span on userArena.faultList has invalid size")
	}

	// Update the span class to be noscan. What we want to happen is that
	// any pointer into the span keeps it from getting recycled, so we want
	// the mark bit to get set, but we're about to set the address space to fault,
	// so we have to prevent the GC from scanning this memory.
	//
	// It's OK to set it here because (1) a GC isn't in progress, so the scanning code
	// won't make a bad decision, (2) we're currently non-preemptible and in the runtime,
	// so a GC is blocked from starting. We might race with sweeping, which could
	// put it on the "wrong" sweep list, but really don't care because the chunk is
	// treated as a large object span and there's no meaningful difference between scan
	// and noscan large objects in the sweeper. The STW at the start of the GC acts as a
	// barrier for this update.
	s.spanclass = makeSpanClass(0, true)

	// Actually set the arena chunk to fault, so we'll get dangling pointer errors.
	// sysFault currently uses a method on each OS that forces it to evacuate all
	// memory backing the chunk.
	sysFault(unsafe.Pointer(s.base()), s.npages*pageSize)

	// Everything on the list is counted as in-use, however sysFault transitions to
	// Reserved, not Prepared, so we skip updating heapFree or heapReleased and just
	// remove the memory from the total altogether; it's just address space now.
	gcController.heapInUse.add(-int64(s.npages * pageSize))

	// Count this as a free of an object right now as opposed to when
	// the span gets off the quarantine list. The main reason is so that the
	// amount of bytes allocated doesn't exceed how much is counted as
	// "mapped ready," which could cause a deadlock in the pacer.
	gcController.totalFree.Add(int64(s.elemsize))

	// Update consistent stats to match.
	//
	// We're non-preemptible, so it's safe to update consistent stats (our P
	// won't change out from under us).
	stats := memstats.heapStats.acquire()
	atomic.Xaddint64(&stats.committed, -int64(s.npages*pageSize))
	atomic.Xaddint64(&stats.inHeap, -int64(s.npages*pageSize))
	atomic.Xadd64(&stats.largeFreeCount, 1)
	atomic.Xadd64(&stats.largeFree, int64(s.elemsize))
	memstats.heapStats.release()

	// This counts as a free, so update heapLive.
	gcController.update(-int64(s.elemsize), 0)

	// Mark it as free for the race detector.
	if raceenabled {
		racefree(unsafe.Pointer(s.base()), s.elemsize)
	}

	systemstack(func() {
		// Add the user arena to the quarantine list.
		lock(&mheap_.lock)
		mheap_.userArena.quarantineList.insert(s)
		unlock(&mheap_.lock)
	})
}

// inUserArenaChunk returns true if p points to a user arena chunk.
func inUserArenaChunk(p uintptr) bool {
	s := spanOf(p)
	if s == nil {
		return false
	}
	return s.isUserArenaChunk
}

// freeUserArenaChunk releases the user arena represented by s back to the runtime.
//
// x must be a live pointer within s.
//
// The runtime will set the user arena to fault once it's safe (the GC is no longer running)
// and then once the user arena is no longer referenced by the application, will allow it to
// be reused.
func freeUserArenaChunk(s *mspan, x unsafe.Pointer) {
	if !s.isUserArenaChunk {
		throw("span is not for a user arena")
	}
	if s.npages*pageSize != userArenaChu
"""




```